use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddr, UdpSocket},
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use mousevpn_config::{ValidatedAuthorizedClient, ValidatedServerConfig};
use mousevpn_crypto::{PublicKey, ServerHandshake};
use mousevpn_data_plane::{DecodedPacket, Ipv4Packet, PacketDevice, TunnelDataPlane};
use mousevpn_linux_platform::{LinuxTun, LinuxTunConfig, DEFAULT_TX_QUEUE_LEN};
use mousevpn_protocol::{Datagram, Header, PacketKind, SessionParameters};
use socket2::SockRef;

use crate::{rate_limit::HandshakeLimiter, ServerDaemonError};

const DATAGRAM_BUFFER_LEN: usize = 65_535;
const SOCKET_BUFFER_LEN: usize = 8 * 1024 * 1024;

struct ClientLease {
    name: String,
    address: Ipv4Addr,
}

struct RuntimeSession {
    client_address: Ipv4Addr,
    state: Mutex<SessionState>,
}

struct SessionState {
    peer: SocketAddr,
    plane: TunnelDataPlane,
}

type SessionMap = Arc<Mutex<HashMap<u64, Arc<RuntimeSession>>>>;

/// Creates the server TUN/UDP endpoints and runs until a fatal I/O error.
///
/// # Errors
///
/// Returns an error when TUN creation, UDP binding or packet reception fails.
pub fn run(config: &ValidatedServerConfig) -> Result<(), ServerDaemonError> {
    let tun = Arc::new(LinuxTun::create(&LinuxTunConfig {
        name: config.tun.name.clone(),
        address: config.tun.address,
        prefix_len: config.tun.prefix_len,
        mtu: config.tun.mtu,
        tx_queue_len: DEFAULT_TX_QUEUE_LEN,
    })?);
    let socket = UdpSocket::bind(config.listen)?;
    configure_socket_buffers(&socket)?;
    let sessions = Arc::new(Mutex::new(HashMap::new()));
    let authorized = authorized_clients(&config.clients);
    let mut handshake_limiter = HandshakeLimiter::new(10, Duration::from_secs(60));

    start_tun_worker(Arc::clone(&tun), socket.try_clone()?, Arc::clone(&sessions));
    let mut buffer = vec![0_u8; DATAGRAM_BUFFER_LEN];
    loop {
        let (length, peer) = socket.recv_from(&mut buffer)?;
        let Ok(datagram) = Datagram::decode(&buffer[..length]) else {
            continue;
        };
        match datagram.header.kind {
            PacketKind::HandshakeInit if handshake_limiter.allow(peer.ip()) => {
                handle_handshake(&socket, peer, datagram, config, &authorized, &sessions);
            }
            PacketKind::Data => handle_client_data(peer, datagram, &sessions, &tun),
            PacketKind::Keepalive => handle_keepalive(&socket, peer, datagram, &sessions),
            _ => {}
        }
    }
}

fn configure_socket_buffers(socket: &UdpSocket) -> std::io::Result<()> {
    let socket = SockRef::from(socket);
    socket.set_recv_buffer_size(SOCKET_BUFFER_LEN)?;
    socket.set_send_buffer_size(SOCKET_BUFFER_LEN)
}

fn handle_keepalive(
    socket: &UdpSocket,
    peer: SocketAddr,
    datagram: Datagram<'_>,
    sessions: &SessionMap,
) {
    let response = {
        let Some(session) = find_session(sessions, datagram.header.session_id) else {
            return;
        };
        let Ok(mut state) = session.state.lock() else {
            return;
        };
        if state.peer != peer {
            return;
        }
        let encoded = datagram.encode();
        if !matches!(state.plane.decode(&encoded), Ok(DecodedPacket::Keepalive)) {
            return;
        }
        let Ok(response) = state.plane.encode_keepalive() else {
            return;
        };
        response
    };
    let _ = socket.send_to(&response, peer);
}

fn authorized_clients(clients: &[ValidatedAuthorizedClient]) -> HashMap<PublicKey, ClientLease> {
    clients
        .iter()
        .map(|client| {
            (
                client.public_key,
                ClientLease {
                    name: client.name.clone(),
                    address: client.address,
                },
            )
        })
        .collect()
}

fn handle_handshake(
    socket: &UdpSocket,
    peer: SocketAddr,
    datagram: Datagram<'_>,
    config: &ValidatedServerConfig,
    authorized: &HashMap<PublicKey, ClientLease>,
    sessions: &SessionMap,
) {
    let Ok(mut handshake) = ServerHandshake::new(&config.server_private_key, &config.context)
    else {
        return;
    };
    if handshake.read_initial(datagram.payload).is_err() {
        return;
    }
    let Some(public_key) = handshake.peer_static_key() else {
        return;
    };
    let Some(client) = authorized.get(&public_key) else {
        return;
    };
    let parameters = SessionParameters {
        client_address: client.address,
        prefix_len: config.tun.prefix_len,
        mtu: config.tun.mtu,
        dns: config.tun.dns,
    };
    let Ok((crypto, response)) = handshake.finish(&parameters.encode()) else {
        return;
    };
    let Ok(mut guard) = sessions.lock() else {
        return;
    };
    guard.retain(|_, session| session.client_address != client.address);
    if guard.contains_key(&datagram.header.session_id) {
        return;
    }
    guard.insert(
        datagram.header.session_id,
        Arc::new(RuntimeSession {
            client_address: client.address,
            state: Mutex::new(SessionState {
                peer,
                plane: TunnelDataPlane::new(
                    datagram.header.session_id,
                    usize::from(config.tun.mtu),
                    crypto,
                ),
            }),
        }),
    );
    drop(guard);

    let header = Header {
        kind: PacketKind::HandshakeResponse,
        flags: 0,
        session_id: datagram.header.session_id,
        sequence: 0,
    };
    let _ = socket.send_to(&Datagram::new(header, &response).encode(), peer);
    eprintln!("session established for {} from {peer}", client.name);
}

fn handle_client_data(
    peer: SocketAddr,
    datagram: Datagram<'_>,
    sessions: &SessionMap,
    tun: &LinuxTun,
) {
    let packet = {
        let Some(session) = find_session(sessions, datagram.header.session_id) else {
            return;
        };
        let Ok(mut state) = session.state.lock() else {
            return;
        };
        if state.peer != peer {
            return;
        }
        let encoded = datagram.encode();
        let Ok(packet) = state.plane.decode_ip(&encoded) else {
            return;
        };
        let Ok(ip) = Ipv4Packet::parse(&packet) else {
            return;
        };
        if ip.source() != session.client_address {
            return;
        }
        packet
    };
    let _ = tun.send(&packet);
}

fn start_tun_worker(tun: Arc<LinuxTun>, socket: UdpSocket, sessions: SessionMap) {
    thread::spawn(move || {
        let mut packet = vec![0_u8; DATAGRAM_BUFFER_LEN];
        while let Ok(length) = tun.receive(&mut packet) {
            let Ok(ip) = Ipv4Packet::parse(&packet[..length]) else {
                continue;
            };
            let session = {
                let Ok(guard) = sessions.lock() else {
                    break;
                };
                guard
                    .values()
                    .find(|session| session.client_address == ip.destination())
                    .cloned()
            };
            let Some(session) = session else {
                continue;
            };
            let encoded = {
                let Ok(mut state) = session.state.lock() else {
                    continue;
                };
                let Ok(datagram) = state.plane.encode_ip(ip.as_bytes()) else {
                    continue;
                };
                (datagram, state.peer)
            };
            let _ = socket.send_to(&encoded.0, encoded.1);
        }
    });
}

fn find_session(sessions: &SessionMap, session_id: u64) -> Option<Arc<RuntimeSession>> {
    sessions.lock().ok()?.get(&session_id).cloned()
}
