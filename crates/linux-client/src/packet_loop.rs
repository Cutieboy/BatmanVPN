use std::{
    collections::VecDeque,
    io,
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{Receiver, Sender, TryRecvError},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use mousevpn_client_wire::ClientWire;
use mousevpn_config::ValidatedClientConfig;
use mousevpn_data_plane::{Decoded, PacketDevice, TunnelReceiver, TunnelSender};
use mousevpn_linux_platform::{DnsGuard, LinuxTun, RouteGuard};
use mousevpn_protocol::{Datagram, SessionParameters};
use mousevpn_transport::{DatagramTransport, UdpBatch, UdpTransport};

use crate::{
    error::is_peer_unavailable,
    handshake::connect,
    liveness::{Action, Liveness},
    metrics::RuntimeMetrics,
    ClientError,
};

const PACKET_BUFFER_LEN: usize = 65_535;
const BATCH_SIZE: usize = 32;
const MIGRATION_ATTEMPTS: usize = 3;
const MIGRATION_POLL: Duration = Duration::from_millis(500);
pub(crate) const POLL_INTERVAL: Duration = Duration::from_millis(500);
const ROUTE_REFRESH_INTERVAL: Duration = Duration::from_secs(30);
const METRICS_INTERVAL: Duration = Duration::from_secs(10);
const KEEPALIVE_RESPONSE_TIMEOUT: Duration = Duration::from_secs(20);

enum ReceiveEvent {
    Packets,
    Idle,
    PeerUnavailable,
}

pub(crate) struct PacketLoop<'a> {
    pub(crate) config: &'a ValidatedClientConfig,
    pub(crate) transport: UdpTransport,
    pub(crate) parameters: SessionParameters,
    pub(crate) tun: Arc<LinuxTun>,
    /// Owned outright: the receive direction shares no state with the sender,
    /// so decryption needs no lock at all.
    pub(crate) receiver: TunnelReceiver,
    pub(crate) sender: Arc<Mutex<TunnelSender>>,
    pub(crate) stopping: Arc<AtomicBool>,
    pub(crate) reconnecting: Arc<AtomicBool>,
    /// Raised by the send thread when it consumes the peer's ICMP error, which
    /// the receive path would otherwise never observe.
    pub(crate) reconnect_requested: Arc<AtomicU64>,
    /// Identifies the data-plane generation that an outgoing error belongs to.
    pub(crate) session_generation: Arc<AtomicU64>,
    pub(crate) worker: Receiver<Result<(), ClientError>>,
    pub(crate) outgoing_transport: Sender<UdpTransport>,
    pub(crate) wire: ClientWire,
    pub(crate) metrics: Arc<RuntimeMetrics>,
    pub(crate) routes: Option<&'a mut RouteGuard>,
    pub(crate) dns: Option<&'a mut DnsGuard>,
}

impl PacketLoop<'_> {
    pub(crate) fn run(mut self) -> Result<(), ClientError> {
        let mut datagrams: Vec<Vec<u8>> = (0..BATCH_SIZE)
            .map(|_| vec![0_u8; PACKET_BUFFER_LEN])
            .collect();
        let mut lengths = Vec::with_capacity(BATCH_SIZE);
        // Reused across packets: the receive path allocates nothing in steady state.
        let mut plaintext = Vec::with_capacity(PACKET_BUFFER_LEN);
        let mut wire_payload = Vec::with_capacity(PACKET_BUFFER_LEN);
        let mut keepalive = Vec::with_capacity(128);
        let mut wire_keepalive = Vec::with_capacity(256);
        let mut liveness = Liveness::new(Instant::now());
        let started = Instant::now();
        let mut next_route_refresh = Instant::now() + ROUTE_REFRESH_INTERVAL;
        let mut next_metrics = Instant::now() + METRICS_INTERVAL;
        let mut pending_keepalives = VecDeque::new();
        let mut udp_batch = UdpBatch::default();

        while !self.stopping.load(Ordering::Relaxed) {
            check_worker(&self.worker, &self.stopping)?;
            match self.receive(&mut datagrams, &mut lengths, &mut udp_batch)? {
                ReceiveEvent::Packets => {
                    for (datagram, &length) in datagrams.iter().zip(&lengths) {
                        let Ok(true) = self.wire.decode(&datagram[..length], &mut wire_payload)
                        else {
                            continue;
                        };
                        if let Ok(parsed) = Datagram::decode(&wire_payload) {
                            match self.receiver.decode_into(parsed, &mut plaintext) {
                                Ok(Decoded::Ip(packet)) => {
                                    liveness.packet_received(Instant::now());
                                    self.metrics.record_incoming_packet();
                                    // A failed TUN write costs one packet; the
                                    // tunnel itself stays up.
                                    if let Err(error) = self.tun.send(packet) {
                                        if !is_recoverable(&error) {
                                            return Err(error.into());
                                        }
                                    }
                                }
                                Ok(Decoded::Keepalive) => {
                                    let now = Instant::now();
                                    liveness.packet_received(now);
                                    // Keepalive payloads do not carry request
                                    // IDs. Match a reply to the newest probe:
                                    // on ordinary links its RTT is far below
                                    // the ten-second send interval, while an
                                    // older unanswered probe must remain in the
                                    // queue so it can be counted as lost.
                                    if let Some(sent) = pending_keepalives.pop_back() {
                                        self.metrics.record_keepalive_response(
                                            now.saturating_duration_since(sent),
                                        );
                                    }
                                }
                                Err(_) => {}
                            }
                        }
                    }
                }
                ReceiveEvent::Idle => {}
                ReceiveEvent::PeerUnavailable => {
                    if liveness.connection_lost(Instant::now()) {
                        self.metrics.record_peer_unreachable();
                    }
                }
            }
            if self.stopping.load(Ordering::Relaxed) {
                break;
            }
            if take_reconnect_request(&self.reconnect_requested, &self.session_generation)
                && liveness.connection_lost(Instant::now())
            {
                self.metrics.record_peer_unreachable();
            }
            let now = Instant::now();
            expire_keepalives(&self.metrics, &mut pending_keepalives, now);
            if now >= next_route_refresh {
                if let Some(routes) = self.routes.as_deref_mut() {
                    if let Err(error) = routes.refresh_server_route() {
                        eprintln!("MOUSEVPN_POLICY_WARNING=refreshing server route: {error}");
                    }
                }
                next_route_refresh = Instant::now() + ROUTE_REFRESH_INTERVAL;
            }
            self.maintain_liveness(
                &mut liveness,
                &mut keepalive,
                &mut wire_keepalive,
                &mut pending_keepalives,
            )?;
            if now >= next_metrics {
                self.metrics.emit(started.elapsed());
                next_metrics = now + METRICS_INTERVAL;
            }
        }
        self.metrics.emit(started.elapsed());
        Ok(())
    }

    fn receive(
        &mut self,
        datagrams: &mut [Vec<u8>],
        lengths: &mut Vec<usize>,
        batch: &mut UdpBatch,
    ) -> Result<ReceiveEvent, ClientError> {
        match self.transport.receive_batch_with(datagrams, lengths, batch) {
            Ok(()) => Ok(ReceiveEvent::Packets),
            Err(error)
                if error.kind() == io::ErrorKind::Interrupted
                    && self.stopping.load(Ordering::Relaxed) =>
            {
                Ok(ReceiveEvent::Idle)
            }
            Err(error) if is_timeout(&error) => {
                check_worker(&self.worker, &self.stopping)?;
                Ok(ReceiveEvent::Idle)
            }
            Err(error) if is_peer_unavailable(&error) => Ok(ReceiveEvent::PeerUnavailable),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => Ok(ReceiveEvent::Idle),
            Err(error) => Err(error.into()),
        }
    }

    fn maintain_liveness(
        &mut self,
        liveness: &mut Liveness,
        keepalive: &mut Vec<u8>,
        wire_keepalive: &mut Vec<u8>,
        pending_keepalives: &mut VecDeque<Instant>,
    ) -> Result<(), ClientError> {
        let now = Instant::now();
        match liveness.action(now) {
            Action::None => Ok(()),
            Action::Keepalive => {
                match self.send_keepalive(keepalive, wire_keepalive) {
                    Ok(()) => {
                        liveness.keepalive_sent(now);
                        pending_keepalives.push_back(now);
                        self.metrics.record_keepalive_sent();
                    }
                    Err(ClientError::Io(error)) if is_peer_unavailable(&error) => {
                        if liveness.connection_lost(now) {
                            self.metrics.record_peer_unreachable();
                        }
                    }
                    Err(error) => return Err(error),
                }
                Ok(())
            }
            Action::Reconnect => {
                self.reconnect(liveness, pending_keepalives, now);
                Ok(())
            }
        }
    }

    fn send_keepalive(
        &mut self,
        buffer: &mut Vec<u8>,
        wire_buffer: &mut Vec<u8>,
    ) -> Result<(), ClientError> {
        self.sender
            .lock()
            .map_err(|_| ClientError::WorkerStopped)?
            .encode_keepalive_into(buffer)?;
        self.wire.encode(buffer, wire_buffer)?;
        self.transport.send(wire_buffer)?;
        Ok(())
    }

    fn reconnect(
        &mut self,
        liveness: &mut Liveness,
        pending_keepalives: &mut VecDeque<Instant>,
        now: Instant,
    ) {
        self.metrics.record_reconnect();
        self.metrics
            .record_keepalive_timeouts(pending_keepalives.len());
        pending_keepalives.clear();
        self.reconnecting.store(true, Ordering::Relaxed);
        eprintln!("MOUSEVPN_STATE=reconnecting");
        eprintln!("MouseVPN session timed out; reconnecting");
        if let Some(routes) = self.routes.as_deref_mut() {
            if let Err(error) = routes.refresh_server_route() {
                liveness.network_unavailable(now);
                self.metrics.record_reconnect_failure();
                self.reconnecting.store(false, Ordering::Relaxed);
                eprintln!("MOUSEVPN_RECONNECT_ERROR=refreshing server route: {error}");
                return;
            }
        }
        liveness.reconnect_attempted(now);
        match self.try_migrate().or_else(|migration_error| {
            eprintln!("MOUSEVPN_MIGRATION_WARNING={migration_error}");
            self.establish_replacement()
        }) {
            Ok(()) => {
                liveness.reconnected(Instant::now());
                eprintln!("MOUSEVPN_STATE=reconnected");
                eprintln!("MouseVPN reconnected");
            }
            Err(error) => {
                self.metrics.record_reconnect_failure();
                eprintln!("MOUSEVPN_RECONNECT_ERROR={error}");
            }
        }
        self.reconnecting.store(false, Ordering::Relaxed);
    }

    fn establish_replacement(&mut self) -> Result<(), ClientError> {
        // Do not reuse the connected socket across suspend or a gateway
        // change. Linux may keep its old source address and cached route even
        // after the server host route has been repaired.
        let (replacement_transport, replacement, parameters) = connect(self.config, &self.wire)?;
        replacement_transport.set_read_timeout(Some(POLL_INTERVAL))?;
        let outgoing_transport = replacement_transport.try_clone()?;
        self.apply_session_parameters(parameters)?;
        let (sender, receiver) = replacement.split();
        self.receiver = receiver;
        *self.sender.lock().map_err(|_| ClientError::WorkerStopped)? = sender;
        self.outgoing_transport
            .send(outgoing_transport)
            .map_err(|_| ClientError::WorkerStopped)?;
        self.transport = replacement_transport;
        // Advance the data-plane generation before clearing requests. An old
        // send() completing after this point retains its old generation and
        // cannot tear down the replacement session.
        self.session_generation.fetch_add(1, Ordering::Relaxed);
        self.reconnect_requested.store(0, Ordering::Relaxed);
        Ok(())
    }

    fn try_migrate(&mut self) -> Result<(), ClientError> {
        let local = match self.config.server {
            SocketAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], 0)),
            SocketAddr::V6(_) => SocketAddr::from(([0_u16; 8], 0)),
        };
        let mut replacement = UdpTransport::bind(local, self.config.server)?;
        replacement.set_read_timeout(Some(MIGRATION_POLL))?;
        let mut keepalive = Vec::with_capacity(128);
        let mut wire_keepalive = Vec::with_capacity(256);
        let mut datagram = vec![0_u8; PACKET_BUFFER_LEN];
        let mut wire_payload = Vec::with_capacity(PACKET_BUFFER_LEN);
        let mut plaintext = Vec::with_capacity(PACKET_BUFFER_LEN);

        for _ in 0..MIGRATION_ATTEMPTS {
            self.sender
                .lock()
                .map_err(|_| ClientError::WorkerStopped)?
                .encode_keepalive_into(&mut keepalive)?;
            self.wire.encode(&keepalive, &mut wire_keepalive)?;
            replacement.send(&wire_keepalive)?;
            match replacement.receive(&mut datagram) {
                Ok(length) => {
                    if !self.wire.decode(&datagram[..length], &mut wire_payload)? {
                        continue;
                    }
                    let parsed = Datagram::decode(&wire_payload)
                        .map_err(|_| io::Error::other("invalid migration response"))?;
                    match self.receiver.decode_into(parsed, &mut plaintext) {
                        Ok(Decoded::Keepalive) => {}
                        Ok(Decoded::Ip(packet)) => {
                            if let Err(error) = self.tun.send(packet) {
                                if !is_recoverable(&error) {
                                    return Err(error.into());
                                }
                            }
                        }
                        Err(error) => return Err(error.into()),
                    }
                    replacement.set_read_timeout(Some(POLL_INTERVAL))?;
                    let outgoing = replacement.try_clone()?;
                    self.outgoing_transport
                        .send(outgoing)
                        .map_err(|_| ClientError::WorkerStopped)?;
                    self.transport = replacement;
                    self.session_generation.fetch_add(1, Ordering::Relaxed);
                    self.reconnect_requested.store(0, Ordering::Relaxed);
                    self.metrics.record_migration();
                    eprintln!("MOUSEVPN_STATE=migrated");
                    return Ok(());
                }
                Err(error) if is_timeout(&error) || is_peer_unavailable(&error) => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err(io::Error::new(io::ErrorKind::TimedOut, "fast migration timed out").into())
    }

    fn apply_session_parameters(
        &mut self,
        parameters: SessionParameters,
    ) -> Result<(), ClientError> {
        if parameters == self.parameters {
            return Ok(());
        }
        let Some(dns) = self.dns.as_deref_mut() else {
            return Err(ClientError::SessionParametersChanged);
        };
        let previous = self.parameters;
        self.tun.reconfigure(
            parameters.client_address,
            parameters.prefix_len,
            parameters.mtu,
        )?;
        if let Err(error) = dns.update(parameters.dns) {
            let rollback =
                self.tun
                    .reconfigure(previous.client_address, previous.prefix_len, previous.mtu);
            return match rollback {
                Ok(()) => Err(error.into()),
                Err(rollback) => Err(io::Error::other(format!(
                    "updating tunnel DNS failed: {error}; TUN rollback failed: {rollback}"
                ))
                .into()),
            };
        }
        self.parameters = parameters;
        eprintln!("MOUSEVPN_STATE=parameters_updated");
        Ok(())
    }
}

fn expire_keepalives(metrics: &RuntimeMetrics, pending: &mut VecDeque<Instant>, now: Instant) {
    let mut expired = 0;
    while pending
        .front()
        .is_some_and(|sent| now.saturating_duration_since(*sent) >= KEEPALIVE_RESPONSE_TIMEOUT)
    {
        pending.pop_front();
        expired += 1;
    }
    metrics.record_keepalive_timeouts(expired);
}

fn check_worker(
    receiver: &Receiver<Result<(), ClientError>>,
    stopping: &AtomicBool,
) -> Result<(), ClientError> {
    match receiver.try_recv() {
        Ok(Err(error)) => Err(error),
        // A worker that finished because we asked it to is not a failure: the
        // main loop exits on the same flag one iteration later.
        Ok(Ok(())) | Err(TryRecvError::Disconnected) if stopping.load(Ordering::Relaxed) => Ok(()),
        Ok(Ok(())) | Err(TryRecvError::Disconnected) => Err(ClientError::WorkerStopped),
        Err(TryRecvError::Empty) => Ok(()),
    }
}

fn take_reconnect_request(requested: &AtomicU64, generation: &AtomicU64) -> bool {
    let requested = requested.swap(0, Ordering::Relaxed);
    requested != 0 && requested == generation.load(Ordering::Relaxed)
}

fn is_timeout(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

fn is_recoverable(error: &io::Error) -> bool {
    is_timeout(error) || error.kind() == io::ErrorKind::Interrupted
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        sync::{
            atomic::{AtomicBool, AtomicU64, Ordering},
            mpsc,
        },
        time::{Duration, Instant},
    };

    use super::{check_worker, expire_keepalives, take_reconnect_request};
    use crate::{metrics::RuntimeMetrics, ClientError};

    #[test]
    fn a_clean_worker_exit_is_normal_during_shutdown() {
        let (sender, receiver) = mpsc::channel();
        sender.send(Ok(())).unwrap();
        assert!(check_worker(&receiver, &AtomicBool::new(true)).is_ok());
    }

    #[test]
    fn an_unexpected_clean_worker_exit_is_an_error() {
        let (sender, receiver) = mpsc::channel();
        sender.send(Ok(())).unwrap();
        assert!(matches!(
            check_worker(&receiver, &AtomicBool::new(false)),
            Err(ClientError::WorkerStopped)
        ));
    }

    #[test]
    fn ignores_a_reconnect_request_from_an_old_session() {
        let requested = AtomicU64::new(3);
        let generation = AtomicU64::new(4);
        assert!(!take_reconnect_request(&requested, &generation));
        assert_eq!(requested.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn accepts_a_reconnect_request_from_the_current_session() {
        assert!(take_reconnect_request(
            &AtomicU64::new(4),
            &AtomicU64::new(4)
        ));
    }

    #[test]
    fn expires_only_keepalives_past_the_response_budget() {
        let now = Instant::now();
        let mut pending = VecDeque::from([
            now.checked_sub(Duration::from_secs(21)).unwrap(),
            now.checked_sub(Duration::from_secs(19)).unwrap(),
        ]);
        let metrics = RuntimeMetrics::default();

        expire_keepalives(&metrics, &mut pending, now);

        assert_eq!(pending.len(), 1);
        assert_eq!(metrics.keepalive_timeouts(), 1);
    }
}
