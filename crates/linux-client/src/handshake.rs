use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};

use mousevpn_config::ValidatedClientConfig;
use mousevpn_crypto::ClientHandshake;
use mousevpn_data_plane::TunnelDataPlane;
use mousevpn_protocol::{Datagram, Header, PacketKind, SessionParameters};
use mousevpn_transport::{DatagramTransport, UdpTransport};

use crate::ClientError;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const DATAGRAM_BUFFER_LEN: usize = 65_535;

pub(crate) fn connect(
    config: &ValidatedClientConfig,
) -> Result<(UdpTransport, TunnelDataPlane, SessionParameters), ClientError> {
    let local = match config.server {
        SocketAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], 0)),
        SocketAddr::V6(_) => SocketAddr::from(([0_u16; 8], 0)),
    };
    let mut transport = UdpTransport::bind(local, config.server)?;
    let (plane, parameters) = negotiate(&mut transport, config)?;
    Ok((transport, plane, parameters))
}

pub(crate) fn negotiate(
    transport: &mut UdpTransport,
    config: &ValidatedClientConfig,
) -> Result<(TunnelDataPlane, SessionParameters), ClientError> {
    transport.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    let session_id = random_session_id()?;
    let mut handshake = ClientHandshake::new(
        &config.client_private_key,
        &config.server_public_key,
        &config.context,
    )?;
    let initial = handshake.write_initial(&[])?;
    let header = Header {
        kind: PacketKind::HandshakeInit,
        flags: 0,
        session_id,
        sequence: 0,
    };
    transport.send(&Datagram::new(header, &initial).encode())?;

    let mut buffer = vec![0_u8; DATAGRAM_BUFFER_LEN];
    let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(ClientError::HandshakeTimeout);
        }
        transport.set_read_timeout(Some(remaining))?;
        let length = match transport.receive(&mut buffer) {
            Ok(length) => length,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                return Err(ClientError::HandshakeTimeout);
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        };
        let Ok(response) = Datagram::decode(&buffer[..length]) else {
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

fn random_session_id() -> Result<u64, ClientError> {
    let mut bytes = [0_u8; 8];
    getrandom::fill(&mut bytes)?;
    Ok(u64::from_be_bytes(bytes))
}
