use std::{
    collections::HashMap,
    env, fs,
    io::{self, IoSlice, IoSliceMut},
    net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket},
    os::fd::AsRawFd,
    path::PathBuf,
    sync::{Arc, Mutex, RwLock},
    thread,
    time::{Duration, Instant},
};

use mousevpn_admin_api::{
    AdminSettings, AdminToken, DeviceAuthorization, SeedDevice, SharedDeviceRegistry,
};
use mousevpn_config::{
    encode_public_key, ValidatedServerConfig, DEFAULT_TUN_MTU, MAX_SAFE_TUN_MTU,
};
use mousevpn_crypto::{PublicKey, ServerHandshake};
use mousevpn_data_plane::{
    looks_like_protocol_datagram, Decoded, Ipv4Packet, PacketDevice, TunnelDataPlane,
    TunnelReceiver, TunnelSender, TUNNEL_OVERHEAD,
};
use mousevpn_linux_platform::{LinuxTun, LinuxTunConfig, DEFAULT_TX_QUEUE_LEN};
use mousevpn_protocol::{Datagram, Header, PacketKind, SessionParameters};
use nix::poll::{poll, PollFd, PollFlags};
use nix::sys::socket::{
    recvmmsg, sendmmsg, setsockopt, sockopt::RxqOvfl, ControlMessageOwned, MsgFlags, MultiHeaders,
    SockaddrStorage,
};
use socket2::SockRef;

use crate::{rate_limit::HandshakeLimiter, ServerDaemonError};

const DATAGRAM_BUFFER_LEN: usize = 65_535;
const UDP_BATCH_SIZE: usize = 32;
const SOCKET_BUFFER_LEN: usize = 8 * 1024 * 1024;
const PEER_LOG_INTERVAL: Duration = Duration::from_secs(10);
/// Outer IPv4 and UDP headers carried around every tunnel datagram.
const IPV4_UDP_OVERHEAD: usize = 28;

struct RuntimeSession {
    client_address: Ipv4Addr,
    authorization: DeviceAuthorization,
    /// Current client endpoint, replaced only after a packet authenticates.
    peer: RwLock<SocketAddr>,
    /// Client-to-server direction, driven by the UDP loop alone.
    inbound: Mutex<TunnelReceiver>,
    /// Server-to-client direction, driven by the TUN worker alone.
    outbound: Mutex<TunnelSender>,
    last_peer_log: Mutex<Option<Instant>>,
}

impl RuntimeSession {
    fn peer(&self) -> Option<SocketAddr> {
        self.peer.read().ok().map(|peer| *peer)
    }

    /// Adopts a new client endpoint after the packet has been authenticated.
    ///
    /// Clients behind NAT change source port on rebinding and change address
    /// entirely when roaming between networks. Without this the session stalls
    /// until the client's own idle timeout forces a fresh handshake.
    fn adopt_peer(&self, peer: SocketAddr) {
        if self.peer() == Some(peer) {
            return;
        }
        let previous = {
            let Ok(mut current) = self.peer.write() else {
                return;
            };
            if *current == peer {
                return;
            }
            let previous = *current;
            *current = peer;
            previous
        };
        let should_log = self.last_peer_log.lock().is_ok_and(|mut last| {
            if last.is_some_and(|last| last.elapsed() < PEER_LOG_INTERVAL) {
                return false;
            }
            *last = Some(Instant::now());
            true
        });
        if should_log {
            eprintln!(
                "session for {} moved from {previous} to {peer}",
                self.client_address
            );
        }
    }
}

/// Session lookup indexed for both hot paths.
///
/// The UDP loop looks sessions up by ID, the TUN worker by tunnel address; a
/// linear scan of either would cost O(sessions) on every single packet.
#[derive(Default)]
struct Sessions {
    by_id: HashMap<u64, Arc<RuntimeSession>>,
    by_address: HashMap<Ipv4Addr, Arc<RuntimeSession>>,
}

type SessionMap = Arc<RwLock<Sessions>>;

struct ReceivedDatagram {
    index: usize,
    length: usize,
    peer: SocketAddr,
    rx_overflow: Option<u32>,
}

/// Last handshake seen from a device, so duplicates stay harmless.
///
/// A `HandshakeInit` is replayable by design in Noise IK, and the client
/// retransmits it on a lossy link. Building a second session for a byte
/// identical message would silently strand the client on keys it never
/// derived, so an exact repeat is answered with the exact same response.
struct CachedHandshake {
    request: Vec<u8>,
    response: Vec<u8>,
}

/// Creates the server TUN/UDP endpoints and runs until a fatal I/O error.
///
/// # Errors
///
/// Returns an error when TUN creation, UDP binding or packet reception fails.
pub fn run(config: &ValidatedServerConfig) -> Result<(), ServerDaemonError> {
    warn_about_fragmenting_mtu(config.tun.mtu);
    let tun = Arc::new(LinuxTun::create(&LinuxTunConfig {
        name: config.tun.name.clone(),
        address: config.tun.address,
        prefix_len: config.tun.prefix_len,
        mtu: config.tun.mtu,
        tx_queue_len: DEFAULT_TX_QUEUE_LEN,
    })?);
    tun.set_nonblocking(true)?;
    let socket = UdpSocket::bind(config.listen)?;
    configure_socket_buffers(&socket)?;
    setsockopt(&socket, RxqOvfl, &1).map_err(io::Error::from)?;
    let sessions: SessionMap = Arc::new(RwLock::new(Sessions::default()));
    let authorized = open_device_registry(config)?;
    start_admin_if_configured(config, &authorized)?;
    let mut handshake_limiter = HandshakeLimiter::new(50, Duration::from_secs(60));
    let mut handshake_cache: HashMap<PublicKey, CachedHandshake> = HashMap::new();

    start_tun_worker(Arc::clone(&tun), socket.try_clone()?, Arc::clone(&sessions));
    let mut buffers: Vec<Vec<u8>> = (0..UDP_BATCH_SIZE)
        .map(|_| vec![0_u8; DATAGRAM_BUFFER_LEN])
        .collect();
    let mut headers =
        MultiHeaders::<SockaddrStorage>::preallocate(UDP_BATCH_SIZE, Some(nix::cmsg_space!(u32)));
    let mut received = Vec::with_capacity(UDP_BATCH_SIZE);
    let mut last_rx_overflow = 0_u32;
    // Reused across packets so the steady-state receive path never allocates.
    let mut plaintext = Vec::with_capacity(DATAGRAM_BUFFER_LEN);
    let mut response = Vec::with_capacity(usize::from(config.tun.mtu) + 128);
    loop {
        match receive_batch(&socket, &mut buffers, &mut headers, &mut received) {
            Ok(()) => {}
            Err(error) if is_recoverable(&error) => continue,
            Err(error) => return Err(error.into()),
        }
        for received in received.drain(..) {
            let ReceivedDatagram {
                index,
                length,
                peer,
                rx_overflow,
            } = received;
            if let Some(rx_overflow) = rx_overflow {
                if rx_overflow > last_rx_overflow {
                    eprintln!(
                        "MouseVPN UDP receive queue dropped {} datagrams (total {rx_overflow})",
                        rx_overflow - last_rx_overflow
                    );
                    last_rx_overflow = rx_overflow;
                }
            }
            let buffer = &buffers[index][..length];
            if !looks_like_protocol_datagram(buffer) {
                continue;
            }
            let Ok(datagram) = Datagram::decode(buffer) else {
                continue;
            };
            match datagram.header.kind {
                PacketKind::HandshakeInit if handshake_limiter.allow(peer.ip()) => {
                    handle_handshake(
                        &socket,
                        peer,
                        datagram,
                        config,
                        &authorized,
                        &sessions,
                        &mut handshake_cache,
                    );
                }
                PacketKind::Data => {
                    handle_client_data(peer, datagram, &sessions, &tun, &mut plaintext);
                }
                PacketKind::Keepalive => {
                    handle_keepalive(
                        &socket,
                        peer,
                        datagram,
                        &sessions,
                        &mut plaintext,
                        &mut response,
                    );
                }
                _ => {}
            }
        }
    }
}

fn receive_batch(
    socket: &UdpSocket,
    buffers: &mut [Vec<u8>],
    headers: &mut MultiHeaders<SockaddrStorage>,
    received: &mut Vec<ReceivedDatagram>,
) -> io::Result<()> {
    let mut slices: Vec<_> = buffers
        .iter_mut()
        .map(|buffer| [IoSliceMut::new(buffer)])
        .collect();
    let messages = recvmmsg(
        socket.as_raw_fd(),
        headers,
        slices.iter_mut(),
        MsgFlags::MSG_WAITFORONE,
        None,
    )
    .map_err(io::Error::from)?;
    received.clear();
    for (index, message) in messages.enumerate() {
        let Some(address) = message.address.and_then(socket_address) else {
            continue;
        };
        let overflow = message.cmsgs().ok().and_then(|mut messages| {
            messages.find_map(|message| match message {
                ControlMessageOwned::RxqOvfl(value) => Some(value),
                _ => None,
            })
        });
        received.push(ReceivedDatagram {
            index,
            length: message.bytes,
            peer: address,
            rx_overflow: overflow,
        });
    }
    Ok(())
}

fn socket_address(address: SockaddrStorage) -> Option<SocketAddr> {
    address
        .as_sockaddr_in()
        .copied()
        .map(SocketAddr::from)
        .or_else(|| address.as_sockaddr_in6().copied().map(SocketAddr::from))
}

/// Warns when the configured tunnel MTU cannot fit a 1500-byte path.
///
/// The symptom is not a clean failure: small packets work, large ones are
/// fragmented or silently dropped by middleboxes, and the tunnel looks merely
/// "slow" or "flaky" while TLS and video stall.
fn warn_about_fragmenting_mtu(mtu: u16) {
    if mtu > MAX_SAFE_TUN_MTU {
        eprintln!(
            "MouseVPN warning: tun.mtu = {mtu} produces {} byte datagrams on a \
             1500 byte path, which will be fragmented. Use {DEFAULT_TUN_MTU} \
             unless every path is known to carry more.",
            usize::from(mtu) + IPV4_UDP_OVERHEAD + TUNNEL_OVERHEAD
        );
    }
}

/// Transient receive errors that must not take the whole daemon down.
fn is_recoverable(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::Interrupted
            | io::ErrorKind::WouldBlock
            | io::ErrorKind::TimedOut
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
    )
}

fn configure_socket_buffers(socket: &UdpSocket) -> std::io::Result<()> {
    let socket = SockRef::from(socket);
    socket.set_recv_buffer_size(SOCKET_BUFFER_LEN)?;
    socket.set_send_buffer_size(SOCKET_BUFFER_LEN)?;
    let received = socket.recv_buffer_size()?;
    let sent = socket.send_buffer_size()?;
    eprintln!("MouseVPN UDP buffers: receive={received} send={sent} requested={SOCKET_BUFFER_LEN}");
    Ok(())
}

fn handle_keepalive(
    socket: &UdpSocket,
    peer: SocketAddr,
    datagram: Datagram<'_>,
    sessions: &SessionMap,
    plaintext: &mut Vec<u8>,
    response: &mut Vec<u8>,
) {
    let Some(session) = find_session_by_id(sessions, datagram.header.session_id) else {
        return;
    };
    if !session.authorization.is_active() {
        return;
    }
    {
        let Ok(mut inbound) = session.inbound.lock() else {
            return;
        };
        if !matches!(
            inbound.decode_into(datagram, plaintext),
            Ok(Decoded::Keepalive)
        ) {
            return;
        }
    }
    session.adopt_peer(peer);
    {
        let Ok(mut outbound) = session.outbound.lock() else {
            return;
        };
        if outbound.encode_keepalive_into(response).is_err() {
            return;
        }
    }
    let _ = socket.send_to(response, peer);
}

fn handle_handshake(
    socket: &UdpSocket,
    peer: SocketAddr,
    datagram: Datagram<'_>,
    config: &ValidatedServerConfig,
    authorized: &SharedDeviceRegistry,
    sessions: &SessionMap,
    cache: &mut HashMap<PublicKey, CachedHandshake>,
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

    // A repeat of the exact same request is a retransmission or a duplicate in
    // the network, never a new session. Answering it again keeps the client's
    // existing session alive instead of replacing it with unusable keys.
    if let Some(cached) = cache.get(&public_key) {
        if cached.request == datagram.payload {
            let _ = socket.send_to(&cached.response, peer);
            return;
        }
    }

    let parameters = SessionParameters {
        client_address: client.address,
        prefix_len: config.tun.prefix_len,
        mtu: config.tun.mtu,
        dns: config.tun.dns,
    };
    let Ok((crypto, response)) = handshake.finish(&parameters.encode()) else {
        return;
    };
    let (sender, receiver) = TunnelDataPlane::new(
        datagram.header.session_id,
        usize::from(config.tun.mtu),
        crypto,
    )
    .split();
    let session = Arc::new(RuntimeSession {
        client_address: client.address,
        authorization: client.authorization,
        peer: RwLock::new(peer),
        inbound: Mutex::new(receiver),
        outbound: Mutex::new(sender),
        last_peer_log: Mutex::new(None),
    });

    let Ok(mut guard) = sessions.write() else {
        return;
    };
    guard.replace_client(datagram.header.session_id, session);
    drop(guard);

    let header = Header {
        kind: PacketKind::HandshakeResponse,
        flags: 0,
        session_id: datagram.header.session_id,
        sequence: 0,
    };
    let encoded = Datagram::new(header, &response).encode();
    let _ = socket.send_to(&encoded, peer);
    cache.insert(
        public_key,
        CachedHandshake {
            request: datagram.payload.to_vec(),
            response: encoded,
        },
    );
    eprintln!("session established for {} from {peer}", client.name);
}

fn handle_client_data(
    peer: SocketAddr,
    datagram: Datagram<'_>,
    sessions: &SessionMap,
    tun: &LinuxTun,
    plaintext: &mut Vec<u8>,
) {
    let Some(session) = find_session_by_id(sessions, datagram.header.session_id) else {
        return;
    };
    if !session.authorization.is_active() {
        return;
    }
    let packet = {
        let Ok(mut inbound) = session.inbound.lock() else {
            return;
        };
        let Ok(Decoded::Ip(packet)) = inbound.decode_into(datagram, plaintext) else {
            return;
        };
        packet
    };
    let Ok(ip) = Ipv4Packet::parse(packet) else {
        return;
    };
    if ip.source() != session.client_address {
        return;
    }
    let _ = tun.send(packet);
    session.adopt_peer(peer);
}

fn start_tun_worker(tun: Arc<LinuxTun>, socket: UdpSocket, sessions: SessionMap) {
    thread::spawn(move || {
        let mut packets: Vec<Vec<u8>> = (0..UDP_BATCH_SIZE)
            .map(|_| vec![0_u8; DATAGRAM_BUFFER_LEN])
            .collect();
        let mut datagrams: Vec<Vec<u8>> = (0..UDP_BATCH_SIZE)
            .map(|_| Vec::with_capacity(DATAGRAM_BUFFER_LEN))
            .collect();
        let mut packet_lengths = [0_usize; UDP_BATCH_SIZE];
        let mut peers = Vec::with_capacity(UDP_BATCH_SIZE);
        let mut send_headers = MultiHeaders::preallocate(UDP_BATCH_SIZE, None);
        loop {
            let mut descriptor = [PollFd::new(tun.as_fd(), PollFlags::POLLIN)];
            if let Err(error) = poll(&mut descriptor, None::<u16>) {
                if error == nix::errno::Errno::EINTR {
                    continue;
                }
                eprintln!("MouseVPN TUN worker stopped: {error}");
                return;
            }
            let mut packet_count = 0;
            while packet_count < UDP_BATCH_SIZE {
                match tun.receive(&mut packets[packet_count]) {
                    Ok(length) => {
                        packet_lengths[packet_count] = length;
                        packet_count += 1;
                    }
                    Err(error) if is_recoverable(&error) => break,
                    Err(error) => {
                        eprintln!("MouseVPN TUN worker stopped: {error}");
                        return;
                    }
                }
            }

            peers.clear();
            let mut datagram_count = 0;
            for index in 0..packet_count {
                let packet = &packets[index][..packet_lengths[index]];
                let Ok(ip) = Ipv4Packet::parse(packet) else {
                    continue;
                };
                let Some(session) = find_session_by_address(&sessions, ip.destination()) else {
                    continue;
                };
                if !session.authorization.is_active() {
                    continue;
                }
                let Some(peer) = session.peer() else {
                    continue;
                };
                {
                    let Ok(mut outbound) = session.outbound.lock() else {
                        continue;
                    };
                    if outbound
                        .encode_ip_into(ip.as_bytes(), &mut datagrams[datagram_count])
                        .is_err()
                    {
                        continue;
                    }
                }
                peers.push(peer);
                datagram_count += 1;
            }
            if datagram_count == 0 {
                continue;
            }

            let slices: [[IoSlice<'_>; 1]; UDP_BATCH_SIZE] = std::array::from_fn(|index| {
                [IoSlice::new(
                    datagrams.get(index).map_or(&[], Vec::as_slice),
                )]
            });
            let addresses: [Option<SockaddrStorage>; UDP_BATCH_SIZE] =
                std::array::from_fn(|index| peers.get(index).copied().map(SockaddrStorage::from));
            let send_result = sendmmsg(
                socket.as_raw_fd(),
                &mut send_headers,
                &slices[..datagram_count],
                &addresses[..datagram_count],
                [],
                MsgFlags::empty(),
            );
            match send_result {
                Ok(results) => {
                    let _complete_batch = results.count() == datagram_count;
                }
                Err(error) if !is_recoverable(&io::Error::from(error)) => {
                    eprintln!("MouseVPN TUN worker stopped: {error}");
                    return;
                }
                Err(_) => {}
            }
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
    let allow_public = env::var("MOUSEVPN_ADMIN_ALLOW_PUBLIC")
        .is_ok_and(|value| matches!(value.as_str(), "1" | "true" | "yes"));
    if !admin_listener_allowed(listen.ip(), config.tun.address, allow_public) {
        return Err(ServerDaemonError::Configuration(
            "admin listener must use the tunnel address or loopback unless MOUSEVPN_ADMIN_ALLOW_PUBLIC=1"
                .to_owned(),
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

fn admin_listener_allowed(listen: IpAddr, tunnel: Ipv4Addr, allow_public: bool) -> bool {
    listen.is_loopback() || listen == IpAddr::V4(tunnel) || allow_public
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

fn find_session_by_id(sessions: &SessionMap, session_id: u64) -> Option<Arc<RuntimeSession>> {
    sessions.read().ok()?.by_id.get(&session_id).cloned()
}

fn find_session_by_address(
    sessions: &SessionMap,
    address: Ipv4Addr,
) -> Option<Arc<RuntimeSession>> {
    sessions.read().ok()?.by_address.get(&address).cloned()
}

impl Sessions {
    /// Installs a session, replacing any previous one for the same device.
    fn replace_client(&mut self, session_id: u64, session: Arc<RuntimeSession>) {
        let address = session.client_address;
        if let Some(previous) = self.by_address.insert(address, Arc::clone(&session)) {
            self.by_id
                .retain(|_, existing| !Arc::ptr_eq(existing, &previous));
        }
        self.by_id.insert(session_id, session);
    }
}

#[cfg(test)]
mod admin_listener_tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::admin_listener_allowed;

    #[test]
    fn public_admin_listener_requires_explicit_opt_in() {
        let tunnel = Ipv4Addr::new(10, 77, 0, 1);
        assert!(admin_listener_allowed(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            tunnel,
            false
        ));
        assert!(admin_listener_allowed(IpAddr::V4(tunnel), tunnel, false));
        assert!(!admin_listener_allowed(
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            tunnel,
            false
        ));
        assert!(admin_listener_allowed(
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            tunnel,
            true
        ));
    }
}
