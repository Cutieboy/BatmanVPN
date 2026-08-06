use std::{
    fs::File,
    io::{self, Read, Write},
    os::fd::{FromRawFd, RawFd},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context, Result};
use mousevpn_config::ValidatedClientConfig;
use mousevpn_data_plane::{Decoded, TunnelDataPlane, TunnelReceiver, TunnelSender};
use mousevpn_protocol::Datagram;
use mousevpn_protocol::SessionParameters;
use mousevpn_transport::{DatagramTransport, UdpTransport};
use nix::fcntl::{fcntl, FcntlArg, OFlag};

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

struct OutboundState {
    transport: UdpTransport,
    sender: TunnelSender,
}

pub(crate) struct SpawnedSession {
    pub(crate) stopping: Arc<AtomicBool>,
    pub(crate) alive: Arc<AtomicBool>,
    pub(crate) reconnect_requested: Arc<AtomicBool>,
    pub(crate) worker: thread::JoinHandle<()>,
}

struct RunContext {
    config: ValidatedClientConfig,
    parameters: SessionParameters,
    protector: SocketProtector,
    stopping: Arc<AtomicBool>,
    reconnect_requested: Arc<AtomicBool>,
}

struct IncomingLoop<'a> {
    tun: &'a mut File,
    transport: UdpTransport,
    receiver: TunnelReceiver,
    outbound: Arc<Mutex<OutboundState>>,
    context: &'a RunContext,
    reconnecting: Arc<AtomicBool>,
    last_sent: Instant,
    last_received: Instant,
    next_reconnect: Instant,
    reconnect_backoff: Duration,
    reconnect_needed: bool,
}

enum ReceiveEvent {
    Packet,
    Idle,
    PeerUnavailable,
}

pub(crate) fn spawn(
    tun_fd: RawFd,
    transport: UdpTransport,
    plane: TunnelDataPlane,
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
    let reconnect_requested = Arc::new(AtomicBool::new(false));
    let context = RunContext {
        config,
        parameters,
        protector,
        stopping: Arc::clone(&stopping),
        reconnect_requested: Arc::clone(&reconnect_requested),
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
        reconnect_requested,
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
    let reconnecting = Arc::new(AtomicBool::new(false));
    let outgoing_reconnecting = Arc::clone(&reconnecting);
    let outgoing_reconnect_requested = Arc::clone(&context.reconnect_requested);
    let outgoing = thread::spawn(move || {
        send_outgoing(
            sending_tun,
            &outgoing_state,
            &outgoing_flag,
            &outgoing_reconnecting,
            &outgoing_reconnect_requested,
        )
    });
    let receive_result = IncomingLoop {
        tun: &mut tun,
        transport,
        receiver,
        outbound,
        context,
        reconnecting,
        last_sent: Instant::now(),
        last_received: Instant::now(),
        next_reconnect: Instant::now(),
        reconnect_backoff: MIN_RECONNECT_RETRY,
        reconnect_needed: false,
    }
    .run();
    outgoing_stopping.store(true, Ordering::Relaxed);
    let outgoing_result = outgoing
        .join()
        .map_err(|_| anyhow!("outgoing packet thread panicked"))?;
    receive_result?;
    outgoing_result?;
    Ok(())
}

impl IncomingLoop<'_> {
    fn run(&mut self) -> Result<()> {
        let mut packet = vec![0_u8; 65_535];
        let mut plaintext = Vec::with_capacity(65_535);
        let mut keepalive = Vec::with_capacity(128);
        while !self.context.stopping.load(Ordering::Relaxed) {
            if matches!(
                self.receive(&mut packet, &mut plaintext)?,
                ReceiveEvent::PeerUnavailable
            ) {
                self.reconnect_needed = true;
            }
            if self.last_sent.elapsed() >= KEEPALIVE {
                self.send_keepalive(&mut keepalive)?;
            }
            self.update_reconnect_state();
            if self.reconnect_needed && Instant::now() >= self.next_reconnect {
                self.try_reconnect()?;
            }
        }
        Ok(())
    }

    fn receive(&mut self, packet: &mut [u8], plaintext: &mut Vec<u8>) -> Result<ReceiveEvent> {
        let length = match self.transport.receive(packet) {
            Ok(length) => length,
            Err(error) if is_poll_event(&error) => return Ok(ReceiveEvent::Idle),
            Err(error) if is_peer_unavailable(&error) => {
                return Ok(ReceiveEvent::PeerUnavailable);
            }
            Err(error) => return Err(error.into()),
        };
        let decoded = Datagram::decode(&packet[..length])
            .ok()
            .map(|datagram| self.receiver.decode_into(datagram, plaintext));
        match decoded {
            Some(Ok(Decoded::Ip(ip))) => {
                self.last_received = Instant::now();
                write_packet_nonblocking(self.tun, ip)?;
            }
            Some(Ok(Decoded::Keepalive)) => self.last_received = Instant::now(),
            Some(Err(_)) | None => {}
        }
        Ok(ReceiveEvent::Packet)
    }

    fn send_keepalive(&mut self, buffer: &mut Vec<u8>) -> Result<()> {
        encode_keepalive(&self.outbound, buffer)?;
        match self.transport.send(buffer) {
            Ok(()) => {}
            Err(error) if is_peer_unavailable(&error) => self.reconnect_needed = true,
            Err(error) => return Err(error.into()),
        }
        self.last_sent = Instant::now();
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
        if self.last_received.elapsed() >= SESSION_TIMEOUT {
            self.reconnect_needed = true;
        }
    }

    fn try_reconnect(&mut self) -> Result<()> {
        self.reconnecting.store(true, Ordering::Relaxed);
        let result = reconnect(
            &self.context.protector,
            &self.context.config,
            &self.context.stopping,
        );
        if let Ok((replacement_transport, replacement, parameters)) = result {
            if parameters == self.context.parameters {
                self.install_replacement(replacement_transport, replacement)?;
                self.reconnecting.store(false, Ordering::Relaxed);
                return Ok(());
            }
        }
        self.next_reconnect = Instant::now() + self.reconnect_backoff;
        self.reconnect_backoff = (self.reconnect_backoff * 2).min(MAX_RECONNECT_RETRY);
        self.reconnecting.store(false, Ordering::Relaxed);
        Ok(())
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
        self.reconnect_needed = false;
        self.reconnect_backoff = MIN_RECONNECT_RETRY;
        Ok(())
    }
}

fn send_outgoing(
    mut tun: File,
    outbound: &Mutex<OutboundState>,
    stopping: &AtomicBool,
    reconnecting: &AtomicBool,
    reconnect_requested: &AtomicBool,
) -> Result<()> {
    let mut packet = vec![0_u8; 65_535];
    // Reused for every datagram: the send path allocates nothing in steady state.
    let mut datagram = Vec::with_capacity(65_535);
    while !stopping.load(Ordering::Relaxed) {
        while reconnecting.load(Ordering::Relaxed) && !stopping.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_millis(10));
        }
        match tun.read(&mut packet) {
            Ok(0) => return Ok(()),
            Ok(length) => {
                if packet[0] >> 4 != 6 {
                    let mut outbound = outbound
                        .lock()
                        .map_err(|_| anyhow!("outbound lock poisoned"))?;
                    let encoded = outbound
                        .sender
                        .encode_ip_into(&packet[..length], &mut datagram);
                    // One unencodable packet is a packet to drop, not a reason
                    // to tear the tunnel down.
                    if encoded.is_err() {
                        continue;
                    }
                    match outbound.transport.send(&datagram) {
                        Ok(()) => {}
                        Err(error) if is_peer_unavailable(&error) => {
                            reconnect_requested.store(true, Ordering::Release);
                        }
                        Err(error) => return Err(error.into()),
                    }
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
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
    stopping: &AtomicBool,
) -> Result<(UdpTransport, TunnelDataPlane, SessionParameters)> {
    let socket = crate::handshake::bind_socket(config.server)?;
    protector.protect(&socket)?;
    crate::handshake::negotiate_interruptible(socket, config, stopping)
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

fn write_packet_nonblocking(tun: &mut File, packet: &[u8]) -> Result<()> {
    loop {
        match tun.write(packet) {
            Ok(0) => return Err(anyhow!("TUN write returned zero")),
            Ok(length) if length == packet.len() => return Ok(()),
            Ok(_) => return Err(anyhow!("partial TUN packet write")),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            // Keep draining UDP when Android's TUN queue is temporarily full. TCP and QUIC
            // recover an isolated dropped packet; blocking here instead stalls every flow.
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) => return Err(error.into()),
        }
    }
}
