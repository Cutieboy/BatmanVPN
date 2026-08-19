use std::{
    io,
    net::{SocketAddr, UdpSocket},
    sync::{atomic::AtomicBool, atomic::Ordering},
    thread,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context, Result};
use mousevpn_client_wire::ClientWire;
use mousevpn_config::ValidatedClientConfig;
use mousevpn_crypto::ClientHandshake;
use mousevpn_data_plane::TunnelDataPlane;
use mousevpn_protocol::{Datagram, Header, PacketKind, SessionParameters};
use mousevpn_transport::{DatagramTransport, UdpTransport};

/// Total time one connection attempt may spend before giving up.
const TIMEOUT: Duration = Duration::from_secs(10);
/// Gap between retransmissions of the initial message.
///
/// Mobile links drop handshake datagrams routinely, and sending the request
/// exactly once turned a single lost packet into a failed connect.
const RETRANSMIT: Duration = Duration::from_millis(700);

pub(crate) fn negotiate(
    socket: UdpSocket,
    config: &ValidatedClientConfig,
    wire: &ClientWire,
) -> Result<(UdpTransport, TunnelDataPlane, SessionParameters)> {
    negotiate_with_stop(socket, config, wire, None)
}

pub(crate) fn negotiate_interruptible(
    socket: UdpSocket,
    config: &ValidatedClientConfig,
    wire: &ClientWire,
    stopping: &AtomicBool,
) -> Result<(UdpTransport, TunnelDataPlane, SessionParameters)> {
    negotiate_with_stop(socket, config, wire, Some(stopping))
}

fn negotiate_with_stop(
    socket: UdpSocket,
    config: &ValidatedClientConfig,
    wire: &ClientWire,
    stopping: Option<&AtomicBool>,
) -> Result<(UdpTransport, TunnelDataPlane, SessionParameters)> {
    socket
        .connect(config.server)
        .context("UDP connect failed")?;
    let mut transport = UdpTransport::from_socket(socket, config.server)?;
    let (plane, parameters) = renegotiate(&mut transport, config, wire, stopping)?;
    Ok((transport, plane, parameters))
}

fn renegotiate(
    transport: &mut UdpTransport,
    config: &ValidatedClientConfig,
    wire: &ClientWire,
    stopping: Option<&AtomicBool>,
) -> Result<(TunnelDataPlane, SessionParameters)> {
    let mut session_bytes = [0_u8; 8];
    getrandom::fill(&mut session_bytes).context("random generator failed")?;
    let session_id = u64::from_be_bytes(session_bytes);
    let mut handshake = ClientHandshake::new(
        &config.client_private_key,
        &config.server_public_key,
        &config.context,
    )?;
    let initial = handshake.write_initial(&[])?;
    // Retransmissions repeat these exact bytes, which the server recognises as a
    // duplicate and answers without replacing an already established session.
    let request = Datagram::new(
        Header {
            kind: PacketKind::HandshakeInit,
            flags: 0,
            session_id,
            sequence: 0,
        },
        &initial,
    )
    .encode();

    let started = Instant::now();
    let deadline = started + TIMEOUT;
    send_prelude(transport, wire)?;
    let mut encoded_request = Vec::new();
    send_request(transport, wire, &request, &mut encoded_request)?;
    let mut next_retransmit = started + RETRANSMIT;

    let mut buffer = vec![0_u8; 65_535];
    let mut decoded = Vec::with_capacity(65_535);
    loop {
        if stopping.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
            return Err(anyhow!("handshake cancelled"));
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(anyhow!("handshake timed out"));
        }
        if now >= next_retransmit {
            send_request(transport, wire, &request, &mut encoded_request)?;
            next_retransmit = now + RETRANSMIT;
        }

        let wait = next_retransmit.min(deadline).saturating_duration_since(now);
        transport.set_read_timeout(Some(wait.max(Duration::from_millis(1))))?;
        let length = match transport.receive(&mut buffer) {
            Ok(length) => length,
            Err(error) if is_retryable(&error) => continue,
            Err(error) => return Err(error.into()),
        };
        let Ok(true) = wire.decode(&buffer[..length], &mut decoded) else {
            continue;
        };
        let Ok(response) = Datagram::decode(&decoded) else {
            continue;
        };
        if response.header.kind != PacketKind::HandshakeResponse
            || response.header.session_id != session_id
        {
            continue;
        }
        let (crypto, payload) = handshake.finish(response.payload)?;
        let parameters = SessionParameters::decode(&payload)?;
        return Ok((
            TunnelDataPlane::new(session_id, usize::from(parameters.mtu), crypto),
            parameters,
        ));
    }
}

fn send_request(
    transport: &mut UdpTransport,
    wire: &ClientWire,
    request: &[u8],
    encoded: &mut Vec<u8>,
) -> Result<()> {
    wire.encode(request, encoded)?;
    match transport.send(encoded) {
        // A refused or reset connection is a stale ICMP error from an earlier
        // datagram, not a reason to abandon this attempt.
        Ok(()) => Ok(()),
        Err(error) if is_retryable(&error) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn send_prelude(transport: &mut UdpTransport, wire: &ClientWire) -> Result<()> {
    let mut cover = Vec::new();
    for _ in 0..wire.cover_count()? {
        wire.encode_cover(&mut cover)?;
        transport.send(&cover)?;
        let jitter = wire.handshake_jitter_ms()?;
        if jitter != 0 {
            thread::sleep(Duration::from_millis(jitter));
        }
    }
    Ok(())
}

fn is_retryable(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::TimedOut
            | io::ErrorKind::WouldBlock
            | io::ErrorKind::Interrupted
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::NotConnected
    )
}

pub(crate) fn bind_socket(server: SocketAddr) -> Result<UdpSocket> {
    let local = match server {
        SocketAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], 0)),
        SocketAddr::V6(_) => SocketAddr::from(([0_u16; 8], 0)),
    };
    UdpSocket::bind(local).context("UDP bind failed")
}
