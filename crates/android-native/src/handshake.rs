use std::{
    io,
    net::{SocketAddr, UdpSocket},
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context, Result};
use mousevpn_config::ValidatedClientConfig;
use mousevpn_crypto::ClientHandshake;
use mousevpn_data_plane::TunnelDataPlane;
use mousevpn_protocol::{Datagram, Header, PacketKind, SessionParameters};
use mousevpn_transport::{DatagramTransport, UdpTransport};

const TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) fn negotiate(
    socket: UdpSocket,
    config: &ValidatedClientConfig,
) -> Result<(UdpTransport, TunnelDataPlane, SessionParameters)> {
    socket
        .connect(config.server)
        .context("UDP connect failed")?;
    let mut transport = UdpTransport::from_socket(socket, config.server)?;
    let (plane, parameters) = renegotiate(&mut transport, config)?;
    Ok((transport, plane, parameters))
}

pub(crate) fn renegotiate(
    transport: &mut UdpTransport,
    config: &ValidatedClientConfig,
) -> Result<(TunnelDataPlane, SessionParameters)> {
    transport.set_read_timeout(Some(TIMEOUT))?;
    let mut session_bytes = [0_u8; 8];
    getrandom::fill(&mut session_bytes).context("random generator failed")?;
    let session_id = u64::from_be_bytes(session_bytes);
    let mut handshake = ClientHandshake::new(
        &config.client_private_key,
        &config.server_public_key,
        &config.context,
    )?;
    let initial = handshake.write_initial(&[])?;
    transport.send(
        &Datagram::new(
            Header {
                kind: PacketKind::HandshakeInit,
                flags: 0,
                session_id,
                sequence: 0,
            },
            &initial,
        )
        .encode(),
    )?;

    let mut buffer = vec![0_u8; 65_535];
    let deadline = Instant::now() + TIMEOUT;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(anyhow!("handshake timed out"));
        }
        transport.set_read_timeout(Some(remaining))?;
        let length = match transport.receive(&mut buffer) {
            Ok(length) => length,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                return Err(anyhow!("handshake timed out"));
            }
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

pub(crate) fn bind_socket(server: SocketAddr) -> Result<UdpSocket> {
    let local = match server {
        SocketAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], 0)),
        SocketAddr::V6(_) => SocketAddr::from(([0_u16; 8], 0)),
    };
    UdpSocket::bind(local).context("UDP bind failed")
}
