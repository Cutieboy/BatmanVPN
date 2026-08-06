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
use mousevpn_data_plane::{DecodedPacket, TunnelDataPlane};
use mousevpn_protocol::SessionParameters;
use mousevpn_transport::{DatagramTransport, UdpTransport};
use nix::fcntl::{fcntl, FcntlArg, OFlag};

const POLL: Duration = Duration::from_millis(250);
const KEEPALIVE: Duration = Duration::from_secs(10);
const SESSION_TIMEOUT: Duration = Duration::from_secs(90);
const RECONNECT_RETRY: Duration = Duration::from_secs(5);

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
    let plane = Arc::new(Mutex::new(plane));
    let outgoing_plane = Arc::clone(&plane);
    let outgoing_stopping = Arc::new(AtomicBool::new(false));
    let outgoing_flag = Arc::clone(&outgoing_stopping);
    let reconnecting = Arc::new(AtomicBool::new(false));
    let outgoing_reconnecting = Arc::clone(&reconnecting);
    let outgoing = thread::spawn(move || {
        send_outgoing(
            sending_tun,
            &mut sending_transport,
            &outgoing_plane,
            &outgoing_flag,
            &outgoing_reconnecting,
        )
    });

    let receive_result = (|| -> Result<()> {
        let mut packet = vec![0_u8; 65_535];
        let mut last_sent = Instant::now();
        let mut last_received = Instant::now();
        let mut next_reconnect = Instant::now();
        while !stopping.load(Ordering::Relaxed) {
            match transport.receive(&mut packet) {
                Ok(length) => {
                    match plane
                        .lock()
                        .map_err(|_| anyhow!("crypto lock poisoned"))?
                        .decode(&packet[..length])
                    {
                        Ok(DecodedPacket::Ip(ip)) => {
                            last_received = Instant::now();
                            write_packet_nonblocking(&mut tun, &ip)?;
                        }
                        Ok(DecodedPacket::Keepalive) => last_received = Instant::now(),
                        Err(_) => {}
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
                let keepalive = plane
                    .lock()
                    .map_err(|_| anyhow!("crypto lock poisoned"))?
                    .encode_keepalive()?;
                match transport.send(&keepalive) {
                    Ok(()) => {}
                    Err(error) if is_peer_unavailable(&error) => {}
                    Err(error) => return Err(error.into()),
                }
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
                        *plane.lock().map_err(|_| anyhow!("crypto lock poisoned"))? = replacement;
                        last_received = Instant::now();
                        last_sent = last_received;
                    }
                    Ok(_) | Err(_) => next_reconnect = Instant::now() + RECONNECT_RETRY,
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
    plane: &Mutex<TunnelDataPlane>,
    stopping: &AtomicBool,
    reconnecting: &AtomicBool,
) -> Result<()> {
    let mut packet = vec![0_u8; 65_535];
    while !stopping.load(Ordering::Relaxed) {
        while reconnecting.load(Ordering::Relaxed) && !stopping.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_millis(10));
        }
        match tun.read(&mut packet) {
            Ok(0) => return Ok(()),
            Ok(length) => {
                if packet[0] >> 4 != 6 {
                    let datagram = plane
                        .lock()
                        .map_err(|_| anyhow!("crypto lock poisoned"))?
                        .encode_ip(&packet[..length])?;
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
