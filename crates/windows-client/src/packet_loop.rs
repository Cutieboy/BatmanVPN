use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

use mousevpn_config::ValidatedClientConfig;
use mousevpn_data_plane::{Decoded, TunnelDataPlane, TunnelReceiver, TunnelSender};
use mousevpn_protocol::{Datagram, SessionParameters};
use mousevpn_transport::{DatagramTransport, UdpTransport};
use wintun::Session;

use crate::{
    handshake::negotiate,
    liveness::{Action, Liveness},
    network::NetworkGuard,
    ClientError,
};

pub(crate) const UDP_POLL: Duration = Duration::from_millis(250);
const POLICY_REFRESH_INTERVAL: Duration = Duration::from_secs(30);
const DATAGRAM_BUFFER_LEN: usize = 65_535;

#[allow(clippy::too_many_arguments)]
pub(crate) fn run(
    config: &ValidatedClientConfig,
    incoming: UdpTransport,
    outgoing: UdpTransport,
    plane: TunnelDataPlane,
    parameters: SessionParameters,
    session: Arc<Session>,
    stopping: &Arc<AtomicBool>,
    network: &NetworkGuard,
) -> Result<(), ClientError> {
    let (sender, receiver) = plane.split();
    let sender = Arc::new(Mutex::new(sender));
    let reconnecting = Arc::new(AtomicBool::new(false));
    let reconnect_requested = Arc::new(AtomicBool::new(false));
    let (result_tx, result_rx) = mpsc::sync_channel(1);
    spawn_outgoing(
        Arc::clone(&session),
        outgoing,
        Arc::clone(&sender),
        Arc::clone(stopping),
        Arc::clone(&reconnecting),
        Arc::clone(&reconnect_requested),
        result_tx,
    );
    let _policy_worker = PeriodicWorker::spawn(POLICY_REFRESH_INTERVAL, {
        let refresher = network.refresher();
        move || {
            if let Err(error) = refresher.refresh() {
                eprintln!("MOUSEVPN_POLICY_WARNING={error}");
            }
        }
    })?;

    eprintln!("MOUSEVPN_STATE=connected");
    IncomingLoop {
        config,
        transport: incoming,
        parameters,
        receiver,
        sender,
        session,
        stopping,
        reconnecting,
        reconnect_requested,
        worker: result_rx,
        network,
    }
    .run()
}

struct IncomingLoop<'a> {
    config: &'a ValidatedClientConfig,
    transport: UdpTransport,
    parameters: SessionParameters,
    receiver: TunnelReceiver,
    sender: Arc<Mutex<TunnelSender>>,
    session: Arc<Session>,
    stopping: &'a AtomicBool,
    reconnecting: Arc<AtomicBool>,
    reconnect_requested: Arc<AtomicBool>,
    worker: mpsc::Receiver<Result<(), ClientError>>,
    network: &'a NetworkGuard,
}

impl IncomingLoop<'_> {
    fn run(&mut self) -> Result<(), ClientError> {
        let mut encrypted = vec![0_u8; DATAGRAM_BUFFER_LEN];
        let mut plaintext = Vec::with_capacity(DATAGRAM_BUFFER_LEN);
        let mut keepalive = Vec::with_capacity(128);
        let mut liveness = Liveness::new(Instant::now());
        while !self.stopping.load(Ordering::Acquire) {
            self.check_worker()?;
            match self.transport.receive(&mut encrypted) {
                Ok(length) => {
                    let decoded = Datagram::decode(&encrypted[..length])
                        .ok()
                        .map(|datagram| self.receiver.decode_into(datagram, &mut plaintext));
                    match decoded {
                        Some(Ok(Decoded::Ip(packet))) => {
                            liveness.packet_received(Instant::now());
                            send_to_windows(&self.session, packet)?;
                        }
                        Some(Ok(Decoded::Keepalive)) => {
                            liveness.packet_received(Instant::now());
                        }
                        Some(Err(_)) | None => {}
                    }
                }
                Err(error) if is_timeout(&error) => {}
                Err(error) if is_peer_unavailable(&error) => {
                    liveness.connection_lost(Instant::now());
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error.into()),
            }
            if self.reconnect_requested.swap(false, Ordering::AcqRel) {
                liveness.connection_lost(Instant::now());
            }
            self.maintain_liveness(&mut liveness, &mut keepalive)?;
        }
        Ok(())
    }

    fn check_worker(&self) -> Result<(), ClientError> {
        match self.worker.try_recv() {
            Ok(result) => {
                result?;
                Err(ClientError::Platform(
                    "Wintun packet worker stopped unexpectedly".to_owned(),
                ))
            }
            Err(mpsc::TryRecvError::Disconnected) => Err(ClientError::Platform(
                "Wintun packet worker channel closed unexpectedly".to_owned(),
            )),
            Err(mpsc::TryRecvError::Empty) => Ok(()),
        }
    }

    fn maintain_liveness(
        &mut self,
        liveness: &mut Liveness,
        keepalive: &mut Vec<u8>,
    ) -> Result<(), ClientError> {
        let now = Instant::now();
        match liveness.action(now) {
            Action::None => Ok(()),
            Action::Keepalive => {
                let mut sender = self.sender.lock().map_err(|_| poisoned_sender())?;
                sender.encode_keepalive_into(keepalive)?;
                match self.transport.send(keepalive) {
                    Ok(()) => liveness.keepalive_sent(now),
                    Err(error) if is_peer_unavailable(&error) => liveness.connection_lost(now),
                    Err(error) => return Err(error.into()),
                }
                Ok(())
            }
            Action::Reconnect => self.reconnect(liveness, now),
        }
    }

    fn reconnect(&mut self, liveness: &mut Liveness, now: Instant) -> Result<(), ClientError> {
        liveness.reconnect_attempted(now);
        self.reconnecting.store(true, Ordering::Release);
        eprintln!("MOUSEVPN_STATE=reconnecting");
        if let Err(error) = self.network.refresh() {
            self.reconnecting.store(false, Ordering::Release);
            eprintln!("MOUSEVPN_RECONNECT_ERROR={error}");
            return Ok(());
        }
        let result = negotiate(&mut self.transport, self.config);
        let timeout_result = self.transport.set_read_timeout(Some(UDP_POLL));
        self.reconnecting.store(false, Ordering::Release);
        timeout_result?;
        match result {
            Ok((replacement, parameters)) => {
                if parameters != self.parameters {
                    return Err(ClientError::Platform(
                        "server changed tunnel parameters during reconnect".to_owned(),
                    ));
                }
                let (sender, receiver) = replacement.split();
                *self.sender.lock().map_err(|_| poisoned_sender())? = sender;
                self.receiver = receiver;
                liveness.reconnected(Instant::now());
                eprintln!("MOUSEVPN_STATE=reconnected");
            }
            Err(error) => eprintln!("MOUSEVPN_RECONNECT_ERROR={error}"),
        }
        Ok(())
    }
}

struct PeriodicWorker {
    stop: mpsc::Sender<()>,
    thread: Option<thread::JoinHandle<()>>,
}

impl PeriodicWorker {
    fn spawn(
        interval: Duration,
        mut task: impl FnMut() + Send + 'static,
    ) -> Result<Self, ClientError> {
        let (stop, receiver) = mpsc::channel();
        let thread = thread::Builder::new()
            .name("mousevpn-network-policy".to_owned())
            .spawn(move || loop {
                match receiver.recv_timeout(interval) {
                    Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => return,
                    Err(mpsc::RecvTimeoutError::Timeout) => task(),
                }
            })
            .map_err(|error| {
                ClientError::Platform(format!(
                    "failed to start Windows network policy worker: {error}"
                ))
            })?;
        Ok(Self {
            stop,
            thread: Some(thread),
        })
    }
}

impl Drop for PeriodicWorker {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_outgoing(
    session: Arc<Session>,
    mut transport: UdpTransport,
    sender: Arc<Mutex<TunnelSender>>,
    stopping: Arc<AtomicBool>,
    reconnecting: Arc<AtomicBool>,
    reconnect_requested: Arc<AtomicBool>,
    result_tx: mpsc::SyncSender<Result<(), ClientError>>,
) {
    thread::spawn(move || {
        let mut encrypted = Vec::new();
        let result = (|| {
            while !stopping.load(Ordering::Acquire) {
                let packet = session.receive_blocking().map_err(|error| {
                    ClientError::Platform(format!("failed to receive a Wintun packet: {error}"))
                })?;
                if reconnecting.load(Ordering::Acquire)
                    || packet.bytes().first().map(|byte| byte >> 4) != Some(4)
                {
                    continue;
                }
                let mut locked = sender.lock().map_err(|_| poisoned_sender())?;
                locked.encode_ip_into(packet.bytes(), &mut encrypted)?;
                match transport.send(&encrypted) {
                    Ok(()) => {}
                    Err(error) if is_peer_unavailable(&error) => {
                        reconnect_requested.store(true, Ordering::Release);
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            Ok(())
        })();
        let _ = result_tx.send(result);
    });
}

fn send_to_windows(session: &Arc<Session>, packet: &[u8]) -> Result<(), ClientError> {
    let length = u16::try_from(packet.len())
        .map_err(|_| ClientError::Platform("received IP packet is too large".to_owned()))?;
    let mut destination = session
        .allocate_send_packet(length)
        .map_err(|error| ClientError::Platform(format!("Wintun send queue failed: {error}")))?;
    destination.bytes_mut().copy_from_slice(packet);
    session.send_packet(destination);
    Ok(())
}

fn is_timeout(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    )
}

fn is_peer_unavailable(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::NotConnected
            | std::io::ErrorKind::HostUnreachable
            | std::io::ErrorKind::NetworkUnreachable
    )
}

fn poisoned_sender() -> ClientError {
    ClientError::Platform("packet sender lock was poisoned".to_owned())
}

#[cfg(test)]
mod tests {
    use super::PeriodicWorker;
    use std::{
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        time::Duration,
    };

    #[test]
    fn policy_worker_stops_without_waiting_for_its_interval() {
        let ran = Arc::new(AtomicBool::new(false));
        let task_ran = Arc::clone(&ran);
        let worker = PeriodicWorker::spawn(Duration::from_secs(60), move || {
            task_ran.store(true, Ordering::Release);
        })
        .expect("policy worker");
        drop(worker);
        assert!(!ran.load(Ordering::Acquire));
    }
}
