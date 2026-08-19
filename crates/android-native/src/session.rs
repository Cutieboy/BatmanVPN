use std::{
    fs::File,
    io::{self, Read, Write},
    os::fd::{AsFd, FromRawFd, RawFd},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context, Result};
use mousevpn_client_wire::{ClientWire, MAX_WIRE_DATAGRAM_LEN};
use mousevpn_config::ValidatedClientConfig;
use mousevpn_data_plane::{Decoded, TunnelDataPlane, TunnelReceiver, TunnelSender};
use mousevpn_protocol::Datagram;
use mousevpn_protocol::SessionParameters;
use mousevpn_transport::{DatagramTransport, UdpBatch, UdpTransport};
use nix::fcntl::{fcntl, FcntlArg, OFlag};
use nix::{
    poll::{poll, PollFd, PollFlags},
    sys::eventfd::{EfdFlags, EventFd},
};

use crate::socket_protector::SocketProtector;

const POLL: Duration = Duration::from_millis(250);
const KEEPALIVE: Duration = Duration::from_secs(10);
/// Silence after which the session is treated as dead.
///
/// Keepalives go out every 10 s. The old 90 s budget meant a phone that changed
/// network kept a dead tunnel for a minute and a half before even trying.
const SESSION_TIMEOUT: Duration = Duration::from_secs(20);
/// Delay before the first retry, doubling up to [`MAX_RECONNECT_RETRY`].
const MIN_RECONNECT_RETRY: Duration = Duration::from_secs(1);
const MAX_RECONNECT_RETRY: Duration = Duration::from_secs(16);
const UDP_BATCH_SIZE: usize = 32;

struct OutboundState {
    transport: UdpTransport,
    sender: TunnelSender,
}

#[derive(Default)]
pub(crate) struct SessionMetrics {
    pub(crate) packets_sent: AtomicU64,
    pub(crate) bytes_sent: AtomicU64,
    pub(crate) packets_received: AtomicU64,
    pub(crate) bytes_received: AtomicU64,
    pub(crate) tun_drops: AtomicU64,
    pub(crate) udp_send_drops: AtomicU64,
    pub(crate) reconnects: AtomicU64,
    pub(crate) last_reconnect_ms: AtomicU64,
    pub(crate) network_changes: AtomicU64,
    pub(crate) session_timeouts: AtomicU64,
    pub(crate) peer_unreachable: AtomicU64,
    pub(crate) reconnect_failures: AtomicU64,
    pub(crate) migration_receive_failures: AtomicU64,
    pub(crate) migration_wire_failures: AtomicU64,
    pub(crate) migration_datagram_failures: AtomicU64,
    pub(crate) migration_inner_failures: AtomicU64,
    pub(crate) migration_successes: AtomicU64,
    pub(crate) invalid_datagrams: AtomicU64,
    pub(crate) keepalives_sent: AtomicU64,
    pub(crate) keepalive_responses: AtomicU64,
    pub(crate) last_keepalive_rtt_ms: AtomicU64,
    pub(crate) max_keepalive_rtt_ms: AtomicU64,
}

pub(crate) struct SpawnedSession {
    pub(crate) stopping: Arc<AtomicBool>,
    pub(crate) alive: Arc<AtomicBool>,
    pub(crate) reconnecting: Arc<AtomicBool>,
    pub(crate) reconnect_requested: Arc<AtomicBool>,
    pub(crate) parameters_changed: Arc<AtomicBool>,
    pub(crate) wake: Arc<EventFd>,
    pub(crate) metrics: Arc<SessionMetrics>,
    pub(crate) worker: thread::JoinHandle<()>,
}

struct RunContext {
    config: ValidatedClientConfig,
    wire: ClientWire,
    parameters: SessionParameters,
    protector: SocketProtector,
    stopping: Arc<AtomicBool>,
    reconnecting: Arc<AtomicBool>,
    reconnect_requested: Arc<AtomicBool>,
    parameters_changed: Arc<AtomicBool>,
    wake: Arc<EventFd>,
    metrics: Arc<SessionMetrics>,
}

struct IncomingLoop<'a> {
    tun: &'a mut File,
    transport: UdpTransport,
    receiver: TunnelReceiver,
    outbound: Arc<Mutex<OutboundState>>,
    context: &'a RunContext,
    reconnecting: Arc<AtomicBool>,
    last_sent: Instant,
    keepalive_sent_at: Option<Instant>,
    last_received: Instant,
    next_reconnect: Instant,
    reconnect_backoff: Duration,
    reconnect_needed: bool,
}

struct OutgoingContext<'a> {
    outbound: &'a Mutex<OutboundState>,
    wire: &'a ClientWire,
    stopping: &'a AtomicBool,
    reconnecting: &'a AtomicBool,
    reconnect_requested: &'a AtomicBool,
    session_stopping: &'a AtomicBool,
    wake: &'a EventFd,
    metrics: &'a SessionMetrics,
}

pub(crate) fn spawn(
    tun_fd: RawFd,
    transport: UdpTransport,
    plane: TunnelDataPlane,
    wire: ClientWire,
    config: ValidatedClientConfig,
    parameters: SessionParameters,
    protector: SocketProtector,
) -> Result<SpawnedSession> {
    // Android's ParcelFileDescriptor.detachFd() explicitly transfers ownership to native code.
    let tun = unsafe { File::from_raw_fd(tun_fd) };
    fcntl(&tun, FcntlArg::F_SETFL(OFlag::O_NONBLOCK)).context("failed to configure TUN")?;
    let stopping = Arc::new(AtomicBool::new(false));
    let alive = Arc::new(AtomicBool::new(true));
    let thread_alive = Arc::clone(&alive);
    let reconnecting = Arc::new(AtomicBool::new(false));
    let reconnect_requested = Arc::new(AtomicBool::new(false));
    let parameters_changed = Arc::new(AtomicBool::new(false));
    let wake = Arc::new(
        EventFd::from_flags(EfdFlags::EFD_CLOEXEC | EfdFlags::EFD_NONBLOCK)
            .context("failed to create session wake event")?,
    );
    let metrics = Arc::new(SessionMetrics::default());
    let context = RunContext {
        config,
        wire,
        parameters,
        protector,
        stopping: Arc::clone(&stopping),
        reconnecting: Arc::clone(&reconnecting),
        reconnect_requested: Arc::clone(&reconnect_requested),
        parameters_changed: Arc::clone(&parameters_changed),
        wake: Arc::clone(&wake),
        metrics: Arc::clone(&metrics),
    };
    let worker = thread::Builder::new()
        .name("mousevpn-android".to_owned())
        .spawn(move || {
            let _ = run(tun, transport, plane, &context);
            thread_alive.store(false, Ordering::Relaxed);
        })?;
    Ok(SpawnedSession {
        stopping,
        alive,
        reconnecting,
        reconnect_requested,
        parameters_changed,
        wake,
        metrics,
        worker,
    })
}

fn run(
    mut tun: File,
    transport: UdpTransport,
    plane: TunnelDataPlane,
    context: &RunContext,
) -> Result<()> {
    transport.set_read_timeout(Some(POLL))?;
    let sending_tun = tun.try_clone()?;
    // The two directions share no mutable state; only reconnect swaps the
    // sender, so the send path is uncontended and the receive path is lock-free.
    let (sender, receiver) = plane.split();
    let outbound = Arc::new(Mutex::new(OutboundState {
        transport: transport.try_clone()?,
        sender,
    }));
    let outgoing_state = Arc::clone(&outbound);
    let outgoing_stopping = Arc::new(AtomicBool::new(false));
    let outgoing_flag = Arc::clone(&outgoing_stopping);
    let reconnecting = Arc::clone(&context.reconnecting);
    let outgoing_reconnecting = Arc::clone(&reconnecting);
    let outgoing_reconnect_requested = Arc::clone(&context.reconnect_requested);
    let outgoing_wake = Arc::clone(&context.wake);
    let session_stopping = Arc::clone(&context.stopping);
    let packet_capacity = usize::from(context.parameters.mtu) + 128;
    let outgoing_metrics = Arc::clone(&context.metrics);
    let outgoing_wire = context.wire.clone();
    let outgoing = thread::spawn(move || {
        let result = send_outgoing(
            sending_tun,
            &OutgoingContext {
                outbound: &outgoing_state,
                wire: &outgoing_wire,
                stopping: &outgoing_flag,
                reconnecting: &outgoing_reconnecting,
                reconnect_requested: &outgoing_reconnect_requested,
                session_stopping: &session_stopping,
                wake: &outgoing_wake,
                metrics: &outgoing_metrics,
            },
            packet_capacity,
        );
        // The receive direction owns the public session state. If this worker
        // exits on its own (including a TUN EOF), wake that direction so the
        // session cannot remain "running" with uploads silently dead.
        if !session_stopping.load(Ordering::Relaxed) && !outgoing_flag.load(Ordering::Relaxed) {
            session_stopping.store(true, Ordering::Release);
            signal(&outgoing_wake);
        }
        result
    });
    let receive_result = IncomingLoop {
        tun: &mut tun,
        transport,
        receiver,
        outbound,
        context,
        reconnecting,
        last_sent: Instant::now(),
        keepalive_sent_at: None,
        last_received: Instant::now(),
        next_reconnect: Instant::now(),
        reconnect_backoff: MIN_RECONNECT_RETRY,
        reconnect_needed: false,
    }
    .run();
    outgoing_stopping.store(true, Ordering::Relaxed);
    signal(&context.wake);
    let outgoing_result = outgoing
        .join()
        .map_err(|_| anyhow!("outgoing packet thread panicked"))?;
    receive_result?;
    outgoing_result?;
    Ok(())
}

impl IncomingLoop<'_> {
    fn run(&mut self) -> Result<()> {
        let packet_capacity = usize::from(self.context.parameters.mtu) + 128;
        let mut packets: Vec<Vec<u8>> = (0..UDP_BATCH_SIZE)
            .map(|_| vec![0_u8; MAX_WIRE_DATAGRAM_LEN])
            .collect();
        let mut lengths = Vec::with_capacity(UDP_BATCH_SIZE);
        let mut wire_payload = Vec::with_capacity(MAX_WIRE_DATAGRAM_LEN);
        let mut plaintext = Vec::with_capacity(packet_capacity);
        let mut keepalive = Vec::with_capacity(128);
        let mut wire_keepalive = Vec::with_capacity(MAX_WIRE_DATAGRAM_LEN);
        let mut udp_batch = UdpBatch::default();
        while !self.context.stopping.load(Ordering::Relaxed) {
            match self
                .transport
                .receive_batch_with(&mut packets, &mut lengths, &mut udp_batch)
            {
                Ok(()) => {
                    for (packet, length) in packets.iter().zip(lengths.iter().copied()) {
                        self.process_received(
                            &packet[..length],
                            &mut wire_payload,
                            &mut plaintext,
                        )?;
                    }
                }
                Err(error) if is_poll_event(&error) => {}
                Err(error) if is_peer_unavailable(&error) => {
                    if !self.reconnect_needed {
                        self.context
                            .metrics
                            .peer_unreachable
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    self.reconnect_needed = true;
                }
                Err(error) => return Err(error.into()),
            }
            if self.last_sent.elapsed() >= KEEPALIVE {
                self.send_keepalive(&mut keepalive, &mut wire_keepalive)?;
            }
            self.update_reconnect_state();
            if self.reconnect_needed && Instant::now() >= self.next_reconnect {
                self.try_reconnect()?;
            }
        }
        Ok(())
    }

    fn process_received(
        &mut self,
        packet: &[u8],
        wire_payload: &mut Vec<u8>,
        plaintext: &mut Vec<u8>,
    ) -> Result<()> {
        let decoded = self
            .context
            .wire
            .decode(packet, wire_payload)
            .ok()
            .filter(|decoded| *decoded)
            .and_then(|_| Datagram::decode(wire_payload).ok())
            .map(|datagram| self.receiver.decode_into(datagram, plaintext));
        match decoded {
            Some(Ok(Decoded::Ip(ip))) => {
                self.last_received = Instant::now();
                self.context
                    .metrics
                    .packets_received
                    .fetch_add(1, Ordering::Relaxed);
                self.context
                    .metrics
                    .bytes_received
                    .fetch_add(ip.len() as u64, Ordering::Relaxed);
                if !write_packet_nonblocking(self.tun, ip)? {
                    self.context
                        .metrics
                        .tun_drops
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
            Some(Ok(Decoded::Keepalive)) => {
                self.last_received = Instant::now();
                if let Some(sent_at) = self.keepalive_sent_at.take() {
                    let rtt_ms = sent_at.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
                    self.context
                        .metrics
                        .keepalive_responses
                        .fetch_add(1, Ordering::Relaxed);
                    self.context
                        .metrics
                        .last_keepalive_rtt_ms
                        .store(rtt_ms, Ordering::Relaxed);
                    self.context
                        .metrics
                        .max_keepalive_rtt_ms
                        .fetch_max(rtt_ms, Ordering::Relaxed);
                }
            }
            Some(Err(_)) | None => {
                self.context
                    .metrics
                    .invalid_datagrams
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
        Ok(())
    }

    fn send_keepalive(&mut self, buffer: &mut Vec<u8>, wire_buffer: &mut Vec<u8>) -> Result<()> {
        encode_keepalive(&self.outbound, buffer)?;
        self.context.wire.encode(buffer, wire_buffer)?;
        match self.transport.send(wire_buffer) {
            Ok(()) => {
                self.last_sent = Instant::now();
                self.keepalive_sent_at = Some(self.last_sent);
                self.context
                    .metrics
                    .keepalives_sent
                    .fetch_add(1, Ordering::Relaxed);
            }
            Err(error) if is_peer_unavailable(&error) => {
                if !self.reconnect_needed {
                    self.context
                        .metrics
                        .peer_unreachable
                        .fetch_add(1, Ordering::Relaxed);
                }
                self.reconnect_needed = true;
                self.last_sent = Instant::now();
                self.keepalive_sent_at = None;
            }
            Err(error) if is_transient_send(&error) => {
                self.last_sent = Instant::now();
                self.keepalive_sent_at = None;
            }
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }

    fn update_reconnect_state(&mut self) {
        let now = Instant::now();
        if self
            .context
            .reconnect_requested
            .swap(false, Ordering::AcqRel)
        {
            self.reconnect_needed = true;
            self.next_reconnect = now;
        }
        if self.last_received.elapsed() >= SESSION_TIMEOUT && !self.reconnect_needed {
            self.context
                .metrics
                .session_timeouts
                .fetch_add(1, Ordering::Relaxed);
            self.reconnect_needed = true;
        }
        if self.reconnect_needed && !self.reconnecting.swap(true, Ordering::AcqRel) {
            signal(&self.context.wake);
        }
    }

    fn try_reconnect(&mut self) -> Result<()> {
        let started = Instant::now();
        self.context
            .metrics
            .reconnects
            .fetch_add(1, Ordering::Relaxed);
        // A keepalive-only migration can be a false positive on mobile carriers: the
        // small authenticated probe is echoed through the new NAT mapping while the
        // existing data-plane session remains unable to carry IP packets. Establish a
        // fresh Noise session for every Android reconnect so Wi-Fi/cellular roaming is
        // confirmed by the same handshake that will protect subsequent user traffic.
        let result = reconnect(
            &self.context.protector,
            &self.context.config,
            &self.context.wire,
            &self.context.stopping,
        );
        if let Ok((replacement_transport, replacement, parameters)) = result {
            if parameters == self.context.parameters {
                let installed = self.install_replacement(replacement_transport, replacement);
                self.finish_reconnect(started);
                return installed;
            }
            self.context
                .parameters_changed
                .store(true, Ordering::Release);
            self.context.stopping.store(true, Ordering::Release);
            self.finish_reconnect(started);
            return Ok(());
        }
        self.context
            .metrics
            .reconnect_failures
            .fetch_add(1, Ordering::Relaxed);
        self.next_reconnect = Instant::now() + self.reconnect_backoff;
        self.reconnect_backoff = (self.reconnect_backoff * 2).min(MAX_RECONNECT_RETRY);
        self.record_reconnect_duration(started);
        Ok(())
    }

    fn finish_reconnect(&self, started: Instant) {
        self.record_reconnect_duration(started);
        self.reconnecting.store(false, Ordering::Release);
        signal(&self.context.wake);
    }

    fn record_reconnect_duration(&self, started: Instant) {
        self.context.metrics.last_reconnect_ms.store(
            started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
    }

    fn install_replacement(
        &mut self,
        transport: UdpTransport,
        plane: TunnelDataPlane,
    ) -> Result<()> {
        transport.set_read_timeout(Some(POLL))?;
        let (sender, receiver) = plane.split();
        self.receiver = receiver;
        *self
            .outbound
            .lock()
            .map_err(|_| anyhow!("outbound lock poisoned"))? = OutboundState {
            transport: transport.try_clone()?,
            sender,
        };
        self.transport = transport;
        self.last_received = Instant::now();
        self.last_sent = self.last_received;
        self.keepalive_sent_at = None;
        self.reconnect_needed = false;
        self.reconnect_backoff = MIN_RECONNECT_RETRY;
        Ok(())
    }
}

fn send_outgoing(
    mut tun: File,
    context: &OutgoingContext<'_>,
    packet_capacity: usize,
) -> Result<()> {
    let mut packets: Vec<Vec<u8>> = (0..UDP_BATCH_SIZE)
        .map(|_| vec![0_u8; packet_capacity])
        .collect();
    let mut datagrams: Vec<Vec<u8>> = (0..UDP_BATCH_SIZE)
        .map(|_| Vec::with_capacity(packet_capacity + 128))
        .collect();
    let mut wire_datagrams: Vec<Vec<u8>> = (0..UDP_BATCH_SIZE)
        .map(|_| Vec::with_capacity(MAX_WIRE_DATAGRAM_LEN))
        .collect();
    let mut packet_lengths = [0_usize; UDP_BATCH_SIZE];
    let mut datagram_bytes = [0_u64; UDP_BATCH_SIZE];
    let mut udp_batch = UdpBatch::default();
    while !context.stopping.load(Ordering::Relaxed)
        && !context.session_stopping.load(Ordering::Relaxed)
    {
        let tun_ready = wait_for_tun(
            &tun,
            context.wake,
            !context.reconnecting.load(Ordering::Acquire),
        )?;
        if !tun_ready {
            continue;
        }
        let mut packet_count = 0;
        while packet_count < UDP_BATCH_SIZE {
            match tun.read(&mut packets[packet_count]) {
                Ok(0) => return Ok(()),
                Ok(length) => {
                    packet_lengths[packet_count] = length;
                    packet_count += 1;
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) =>
                {
                    break
                }
                Err(error) => return Err(error.into()),
            }
        }
        let mut outbound = context
            .outbound
            .lock()
            .map_err(|_| anyhow!("outbound lock poisoned"))?;
        let mut datagram_count = 0;
        for index in 0..packet_count {
            let packet = &packets[index][..packet_lengths[index]];
            if packet.first().is_some_and(|first| first >> 4 == 6) {
                continue;
            }
            if outbound
                .sender
                .encode_ip_into(packet, &mut datagrams[datagram_count])
                .is_ok()
            {
                datagram_bytes[datagram_count] = packet.len() as u64;
                datagram_count += 1;
            }
        }
        for index in 0..datagram_count {
            context
                .wire
                .encode(&datagrams[index], &mut wire_datagrams[index])?;
        }
        let sent = outbound
            .transport
            .send_batch_with(&wire_datagrams[..datagram_count], &mut udp_batch);
        drop(outbound);
        record_outgoing_result(sent, datagram_count, &datagram_bytes, context)?;
    }
    Ok(())
}

fn record_outgoing_result(
    sent: io::Result<usize>,
    datagram_count: usize,
    datagram_bytes: &[u64; UDP_BATCH_SIZE],
    context: &OutgoingContext<'_>,
) -> Result<()> {
    match sent {
        Ok(sent_count) => {
            let sent_bytes = datagram_bytes[..sent_count].iter().copied().sum::<u64>();
            context
                .metrics
                .packets_sent
                .fetch_add(sent_count as u64, Ordering::Relaxed);
            context
                .metrics
                .bytes_sent
                .fetch_add(sent_bytes, Ordering::Relaxed);
            context.metrics.udp_send_drops.fetch_add(
                datagram_count.saturating_sub(sent_count) as u64,
                Ordering::Relaxed,
            );
        }
        Err(error) if is_peer_unavailable(&error) => {
            if !context.reconnect_requested.swap(true, Ordering::AcqRel) {
                context
                    .metrics
                    .peer_unreachable
                    .fetch_add(1, Ordering::Relaxed);
                signal(context.wake);
            }
        }
        Err(error) if is_transient_send(&error) => {
            context
                .metrics
                .udp_send_drops
                .fetch_add(datagram_count as u64, Ordering::Relaxed);
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn wait_for_tun(tun: &File, wake: &EventFd, include_tun: bool) -> Result<bool> {
    let tun_events = if include_tun {
        PollFlags::POLLIN
    } else {
        PollFlags::empty()
    };
    let mut descriptors = [
        PollFd::new(tun.as_fd(), tun_events),
        PollFd::new(wake.as_fd(), PollFlags::POLLIN),
    ];
    poll(&mut descriptors, 250_u16).context("failed to poll TUN")?;
    let wake_ready = descriptors[1]
        .revents()
        .is_some_and(|events| events.contains(PollFlags::POLLIN));
    if wake_ready {
        let _ = wake.read();
    }
    Ok(descriptors[0]
        .revents()
        .is_some_and(|events| events.contains(PollFlags::POLLIN)))
}

pub(crate) fn signal(wake: &EventFd) {
    let _ = wake.write(1);
}

fn encode_keepalive(outbound: &Mutex<OutboundState>, buffer: &mut Vec<u8>) -> Result<()> {
    outbound
        .lock()
        .map_err(|_| anyhow!("outbound lock poisoned"))?
        .sender
        .encode_keepalive_into(buffer)?;
    Ok(())
}

fn reconnect(
    protector: &SocketProtector,
    config: &ValidatedClientConfig,
    wire: &ClientWire,
    stopping: &AtomicBool,
) -> Result<(UdpTransport, TunnelDataPlane, SessionParameters)> {
    let socket = crate::handshake::bind_socket(config.server)?;
    protector.protect(&socket)?;
    crate::handshake::negotiate_interruptible(socket, config, wire, stopping)
}

fn is_peer_unavailable(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::NotConnected
            | io::ErrorKind::NetworkUnreachable
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::AddrNotAvailable
    )
}

fn is_poll_event(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    )
}

fn is_transient_send(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    ) || matches!(
        error.raw_os_error(),
        Some(nix::libc::ENOBUFS | nix::libc::ENOMEM)
    )
}

fn write_packet_nonblocking(tun: &mut File, packet: &[u8]) -> Result<bool> {
    loop {
        match tun.write(packet) {
            Ok(0) => return Err(anyhow!("TUN write returned zero")),
            Ok(length) if length == packet.len() => return Ok(true),
            Ok(_) => return Err(anyhow!("partial TUN packet write")),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            // Keep draining UDP when Android's TUN queue is temporarily full. TCP and QUIC
            // recover an isolated dropped packet; blocking here instead stalls every flow.
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(error) => return Err(error.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::is_transient_send;

    #[test]
    fn treats_udp_queue_pressure_as_transient() {
        assert!(is_transient_send(&io::Error::from(
            io::ErrorKind::WouldBlock
        )));
        assert!(is_transient_send(&io::Error::from_raw_os_error(
            nix::libc::ENOBUFS
        )));
        assert!(is_transient_send(&io::Error::from_raw_os_error(
            nix::libc::ENOMEM
        )));
        assert!(!is_transient_send(&io::Error::from(
            io::ErrorKind::InvalidInput
        )));
    }
}
