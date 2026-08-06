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
use mousevpn_data_plane::{Decoded, TunnelDataPlane, TunnelSender};
use mousevpn_protocol::Datagram;
use mousevpn_protocol::SessionParameters;
use mousevpn_transport::{DatagramTransport, UdpTransport};
use nix::fcntl::{fcntl, FcntlArg, OFlag};

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

pub(crate) fn spawn(
    tun_fd: RawFd,
    transport: UdpTransport,
    plane: TunnelDataPlane,
    config: ValidatedClientConfig,
    parameters: SessionParameters,
) -> Result<(Arc<AtomicBool>, Arc<AtomicBool>, thread::JoinHandle<()>)> {
    // Android's ParcelFileDescriptor.detachFd() explicitly transfers ownership to native code.
    let tun = unsafe { File::from_raw_fd(tun_fd) };
    fcntl(&tun, FcntlArg::F_SETFL(OFlag::O_NONBLOCK)).context("failed to configure TUN")?;
    let stopping = Arc::new(AtomicBool::new(false));
    let thread_stopping = Arc::clone(&stopping);
    let alive = Arc::new(AtomicBool::new(true));
    let thread_alive = Arc::clone(&alive);
    let worker = thread::Builder::new()
        .name("mousevpn-android".to_owned())
        .spawn(move || {
            let _ = run(tun, transport, plane, &config, parameters, &thread_stopping);
            thread_alive.store(false, Ordering::Relaxed);
        })?;
    Ok((stopping, alive, worker))
}

fn run(
    mut tun: File,
    mut transport: UdpTransport,
    plane: TunnelDataPlane,
    config: &ValidatedClientConfig,
    parameters: SessionParameters,
    stopping: &AtomicBool,
) -> Result<()> {
    transport.set_read_timeout(Some(POLL))?;
    let mut sending_transport = transport.try_clone()?;
    let sending_tun = tun.try_clone()?;
    // The two directions share no mutable state; only reconnect swaps the
    // sender, so the send path is uncontended and the receive path is lock-free.
    let (sender, mut receiver) = plane.split();
    let sender = Arc::new(Mutex::new(sender));
    let outgoing_sender = Arc::clone(&sender);
    let outgoing_stopping = Arc::new(AtomicBool::new(false));
    let outgoing_flag = Arc::clone(&outgoing_stopping);
    let reconnecting = Arc::new(AtomicBool::new(false));
    let outgoing_reconnecting = Arc::clone(&reconnecting);
    let outgoing = thread::spawn(move || {
        send_outgoing(
            sending_tun,
            &mut sending_transport,
            &outgoing_sender,
            &outgoing_flag,
            &outgoing_reconnecting,
        )
    });

    let receive_result = (|| -> Result<()> {
        let mut packet = vec![0_u8; 65_535];
        // Reused across packets: the receive path allocates nothing in steady state.
        let mut plaintext = Vec::with_capacity(65_535);
        let mut keepalive = Vec::with_capacity(128);
        let mut last_sent = Instant::now();
        let mut last_received = Instant::now();
        let mut next_reconnect = Instant::now();
        let mut reconnect_backoff = MIN_RECONNECT_RETRY;
        while !stopping.load(Ordering::Relaxed) {
            match transport.receive(&mut packet) {
                Ok(length) => {
                    let decoded = Datagram::decode(&packet[..length])
                        .ok()
                        .map(|datagram| receiver.decode_into(datagram, &mut plaintext));
                    match decoded {
                        Some(Ok(Decoded::Ip(ip))) => {
                            last_received = Instant::now();
                            write_packet_nonblocking(&mut tun, ip)?;
                        }
                        Some(Ok(Decoded::Keepalive)) => last_received = Instant::now(),
                        Some(Err(_)) | None => {}
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::TimedOut
                            | io::ErrorKind::WouldBlock
                            | io::ErrorKind::Interrupted
                    ) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::ConnectionRefused | io::ErrorKind::ConnectionReset
                    ) => {}
                Err(error) => return Err(error.into()),
            }
            if last_sent.elapsed() >= KEEPALIVE {
                send_keepalive(&mut transport, &sender, &mut keepalive)?;
                last_sent = Instant::now();
            }
            let now = Instant::now();
            if last_received.elapsed() >= SESSION_TIMEOUT && now >= next_reconnect {
                reconnecting.store(true, Ordering::Relaxed);
                let result = crate::handshake::renegotiate(&mut transport, config);
                transport.set_read_timeout(Some(POLL))?;
                match result {
                    Ok((replacement, replacement_parameters))
                        if replacement_parameters == parameters =>
                    {
                        let (replacement_sender, replacement_receiver) = replacement.split();
                        receiver = replacement_receiver;
                        *sender.lock().map_err(|_| anyhow!("crypto lock poisoned"))? =
                            replacement_sender;
                        last_received = Instant::now();
                        last_sent = last_received;
                        reconnect_backoff = MIN_RECONNECT_RETRY;
                    }
                    Ok(_) | Err(_) => {
                        next_reconnect = Instant::now() + reconnect_backoff;
                        reconnect_backoff = (reconnect_backoff * 2).min(MAX_RECONNECT_RETRY);
                    }
                }
                reconnecting.store(false, Ordering::Relaxed);
            }
        }
        Ok(())
    })();
    outgoing_stopping.store(true, Ordering::Relaxed);
    let outgoing_result = outgoing
        .join()
        .map_err(|_| anyhow!("outgoing packet thread panicked"))?;
    receive_result?;
    outgoing_result?;
    Ok(())
}

fn send_outgoing(
    mut tun: File,
    transport: &mut UdpTransport,
    sender: &Mutex<TunnelSender>,
    stopping: &AtomicBool,
    reconnecting: &AtomicBool,
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
                    let encoded = sender
                        .lock()
                        .map_err(|_| anyhow!("crypto lock poisoned"))?
                        .encode_ip_into(&packet[..length], &mut datagram);
                    // One unencodable packet is a packet to drop, not a reason
                    // to tear the tunnel down.
                    if encoded.is_err() {
                        continue;
                    }
                    match transport.send(&datagram) {
                        Ok(()) => {}
                        Err(error) if is_peer_unavailable(&error) => {}
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

fn send_keepalive(
    transport: &mut UdpTransport,
    sender: &Mutex<TunnelSender>,
    buffer: &mut Vec<u8>,
) -> Result<()> {
    sender
        .lock()
        .map_err(|_| anyhow!("crypto lock poisoned"))?
        .encode_keepalive_into(buffer)?;
    match transport.send(buffer) {
        Ok(()) => Ok(()),
        // The peer is unreachable right now; the reconnect path owns recovery.
        Err(error) if is_peer_unavailable(&error) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn is_peer_unavailable(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::NotConnected
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
