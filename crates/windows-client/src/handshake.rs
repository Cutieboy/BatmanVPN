use std::{
    io,
    net::SocketAddr,
    thread,
    time::{Duration, Instant},
};

use mousevpn_client_wire::ClientWire;
use mousevpn_config::ValidatedClientConfig;
use mousevpn_crypto::ClientHandshake;
use mousevpn_data_plane::TunnelDataPlane;
use mousevpn_protocol::{Datagram, Header, PacketKind, SessionParameters};
use mousevpn_transport::{DatagramTransport, UdpTransport};

use crate::ClientError;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const HANDSHAKE_RETRANSMIT: Duration = Duration::from_millis(700);
const DATAGRAM_BUFFER_LEN: usize = 65_535;

pub(crate) fn connect(
    config: &ValidatedClientConfig,
    wire: &ClientWire,
) -> Result<(UdpTransport, TunnelDataPlane, SessionParameters), ClientError> {
    let local = match config.server {
        SocketAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], 0)),
        SocketAddr::V6(_) => SocketAddr::from(([0_u16; 8], 0)),
    };
    let mut transport = UdpTransport::bind(local, config.server)?;
    let (plane, parameters) = negotiate(&mut transport, config, wire)?;
    Ok((transport, plane, parameters))
}

pub(crate) fn negotiate(
    transport: &mut UdpTransport,
    config: &ValidatedClientConfig,
    wire: &ClientWire,
) -> Result<(TunnelDataPlane, SessionParameters), ClientError> {
    let session_id = random_session_id()?;
    let mut handshake = ClientHandshake::new(
        &config.client_private_key,
        &config.server_public_key,
        &config.context,
    )?;
    let initial = handshake.write_initial(&[])?;
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
    let deadline = started + HANDSHAKE_TIMEOUT;
    send_prelude(transport, wire)?;
    let mut encoded_request = Vec::new();
    send_request(transport, wire, &request, &mut encoded_request)?;
    let mut next_retransmit = started + HANDSHAKE_RETRANSMIT;
    let mut buffer = vec![0_u8; DATAGRAM_BUFFER_LEN];
    let mut decoded = Vec::with_capacity(DATAGRAM_BUFFER_LEN);

    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(ClientError::HandshakeTimeout);
        }
        if now >= next_retransmit {
            send_request(transport, wire, &request, &mut encoded_request)?;
            next_retransmit = now + HANDSHAKE_RETRANSMIT;
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
        let Ok((crypto, payload)) = handshake.finish(response.payload) else {
            return Err(ClientError::HandshakeTimeout);
        };
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
) -> Result<(), ClientError> {
    wire.encode(request, encoded)?;
    match transport.send(encoded) {
        Ok(()) => Ok(()),
        Err(error) if is_retryable(&error) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn send_prelude(transport: &mut UdpTransport, wire: &ClientWire) -> Result<(), ClientError> {
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

fn random_session_id() -> Result<u64, ClientError> {
    let mut bytes = [0_u8; 8];
    getrandom::fill(&mut bytes)?;
    Ok(u64::from_be_bytes(bytes))
}
