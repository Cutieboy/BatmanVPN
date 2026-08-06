use std::{
    collections::HashMap,
    env, fs,
    net::{Ipv4Addr, SocketAddr, UdpSocket},
    path::PathBuf,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use mousevpn_admin_api::{
    AdminSettings, AdminToken, DeviceAuthorization, SeedDevice, SharedDeviceRegistry,
};
use mousevpn_config::{encode_public_key, ValidatedServerConfig};
use mousevpn_crypto::ServerHandshake;
use mousevpn_data_plane::{DecodedPacket, Ipv4Packet, PacketDevice, TunnelDataPlane};
use mousevpn_linux_platform::{LinuxTun, LinuxTunConfig, DEFAULT_TX_QUEUE_LEN};
use mousevpn_protocol::{Datagram, Header, PacketKind, SessionParameters};
use socket2::SockRef;

use crate::{rate_limit::HandshakeLimiter, ServerDaemonError};

const DATAGRAM_BUFFER_LEN: usize = 65_535;
const SOCKET_BUFFER_LEN: usize = 8 * 1024 * 1024;

struct RuntimeSession {
    client_address: Ipv4Addr,
    authorization: DeviceAuthorization,
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
    let authorized = open_device_registry(config)?;
    start_admin_if_configured(config, &authorized)?;
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
            PacketKind::Data => {
                handle_client_data(peer, datagram, &sessions, &tun);
            }
            PacketKind::Keepalive => {
                handle_keepalive(&socket, peer, datagram, &sessions);
            }
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
        if !session.authorization.is_active() {
            return;
        }
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

fn handle_handshake(
    socket: &UdpSocket,
    peer: SocketAddr,
    datagram: Datagram<'_>,
    config: &ValidatedServerConfig,
    authorized: &SharedDeviceRegistry,
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
    let Some(client) = authorized.authorize(&public_key) else {
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
            authorization: client.authorization,
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
        if !session.authorization.is_active() {
            return;
        }
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
            if !session.authorization.is_active() {
                continue;
            }
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

fn open_device_registry(
    config: &ValidatedServerConfig,
) -> Result<SharedDeviceRegistry, ServerDaemonError> {
    let path = env::var_os("MOUSEVPN_DEVICE_STORE").map_or_else(
        || PathBuf::from("/var/lib/mousevpn/devices.toml"),
        PathBuf::from,
    );
    let seeds = config
        .clients
        .iter()
        .map(|client| SeedDevice {
            name: client.name.clone(),
            public_key: client.public_key,
            address: client.address,
        })
        .collect();
    SharedDeviceRegistry::open(path, seeds, config.tun.address, config.tun.prefix_len)
        .map_err(|error| ServerDaemonError::Configuration(error.to_string()))
}

fn start_admin_if_configured(
    config: &ValidatedServerConfig,
    registry: &SharedDeviceRegistry,
) -> Result<(), ServerDaemonError> {
    let Some(raw_token) = load_admin_token()? else {
        eprintln!("MouseVPN admin disabled: /etc/mousevpn/admin.token does not exist");
        return Ok(());
    };
    let token = AdminToken::new(raw_token.into_bytes())
        .map_err(|error| ServerDaemonError::Configuration(error.to_string()))?;
    let listen = env::var("MOUSEVPN_ADMIN_LISTEN")
        .unwrap_or_else(|_| format!("{}:9797", config.tun.address))
        .parse::<SocketAddr>()
        .map_err(|error| ServerDaemonError::Configuration(error.to_string()))?;
    if !listen.ip().is_loopback() && listen.ip() != config.tun.address {
        return Err(ServerDaemonError::Configuration(
            "admin listener must use the tunnel address or loopback".to_owned(),
        ));
    }
    let public_endpoint = config
        .public_endpoint
        .or_else(|| {
            env::var("MOUSEVPN_PUBLIC_ENDPOINT")
                .ok()
                .and_then(|value| value.parse().ok())
        })
        .ok_or_else(|| {
            ServerDaemonError::Configuration(
                "public_endpoint is required when admin is enabled".to_owned(),
            )
        })?;
    if public_endpoint.ip().is_unspecified() || public_endpoint.port() == 0 {
        return Err(ServerDaemonError::Configuration(
            "public_endpoint must contain a usable IP and port".to_owned(),
        ));
    }
    let settings = AdminSettings {
        public_endpoint,
        server_public_key: encode_public_key(&config.server_public_key),
        tun_name: config.tun.name.clone(),
    };
    mousevpn_admin_api::spawn(listen, registry.clone(), token, settings)?;
    Ok(())
}

fn load_admin_token() -> Result<Option<String>, ServerDaemonError> {
    if let Ok(token) = env::var("MOUSEVPN_ADMIN_TOKEN") {
        return Ok(Some(token));
    }
    let path = env::var_os("MOUSEVPN_ADMIN_TOKEN_FILE")
        .map_or_else(|| PathBuf::from("/etc/mousevpn/admin.token"), PathBuf::from);
    if !path.exists() {
        return Ok(None);
    }
    ensure_private_token_file(&path)?;
    let token = fs::read_to_string(path)?.trim().to_owned();
    Ok(Some(token))
}

#[cfg(unix)]
fn ensure_private_token_file(path: &std::path::Path) -> Result<(), ServerDaemonError> {
    use std::os::unix::fs::PermissionsExt;

    let mode = fs::metadata(path)?.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(ServerDaemonError::Configuration(format!(
            "admin token permissions are insecure: {mode:o}"
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_private_token_file(_path: &std::path::Path) -> Result<(), ServerDaemonError> {
    Ok(())
}

fn find_session(sessions: &SessionMap, session_id: u64) -> Option<Arc<RuntimeSession>> {
    sessions.lock().ok()?.get(&session_id).cloned()
}
