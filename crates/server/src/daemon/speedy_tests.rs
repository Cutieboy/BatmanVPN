use mousevpn_client_wire::ClientWire;
use mousevpn_config::{ClientConfig, ClientProtocol, ServerTunConfig, ValidatedClientConfig};
use mousevpn_crypto::{ClientHandshake, KeyPair};

use super::*;

struct Fixture {
    _directory: tempfile::TempDir,
    config: ValidatedServerConfig,
    clients: Vec<KeyPair>,
    registry: SharedDeviceRegistry,
    traffic: TrafficStore,
    sessions: SessionMap,
    socket: UdpSocket,
    router: MorphRouter,
    cache: HashMap<PublicKey, CachedHandshake>,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let server = KeyPair::generate().unwrap();
        let clients: Vec<_> = (0..3).map(|_| KeyPair::generate().unwrap()).collect();
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let config = ValidatedServerConfig {
            listen: socket.local_addr().unwrap(),
            public_endpoint: None,
            server_public_key: server.public,
            server_private_key: server.secret,
            context: ProtocolContext::for_server(&server.public),
            tun: ServerTunConfig {
                name: "speedy-test".into(),
                address: "10.77.0.1".parse().unwrap(),
                prefix_len: 24,
                mtu: 1420,
                dns: "1.1.1.1".parse().unwrap(),
            },
            clients: Vec::new(),
        };
        let registry = SharedDeviceRegistry::open(
            directory.path().join("devices.toml"),
            clients
                .iter()
                .enumerate()
                .map(|(index, client)| SeedDevice {
                    name: format!("client-{index}"),
                    public_key: client.public,
                    address: Ipv4Addr::new(10, 77, 0, 2 + u8::try_from(index).unwrap()),
                })
                .collect(),
            config.tun.address,
            24,
        )
        .unwrap();
        let traffic = TrafficStore::open(directory.path().join("traffic.sqlite")).unwrap();
        Self {
            _directory: directory,
            config,
            clients,
            registry,
            traffic,
            sessions: Arc::new(RwLock::new(Sessions::default())),
            socket,
            router: MorphRouter::default(),
            cache: HashMap::new(),
        }
    }

    fn client_config(&self, index: usize, protocol: ClientProtocol) -> ValidatedClientConfig {
        ClientConfig {
            server: self.config.listen,
            server_public_key: encode_public_key(&self.config.server_public_key),
            client_private_key: mousevpn_config::encode_secret_key(&self.clients[index].secret),
            tun_name: "speedy-test".into(),
            protocol,
        }
        .validate()
        .unwrap()
    }

    fn handle(&mut self, peer: SocketAddr, request: &[u8]) -> Option<WireMode> {
        let mut decoded = Vec::new();
        let wire = decode_wire_into(
            request,
            &self.config,
            &self.registry,
            &mut self.router,
            &mut decoded,
        )?;
        let datagram = Datagram::decode(&decoded).ok()?;
        handle_handshake(
            &self.socket,
            peer,
            datagram,
            HandshakeServices {
                config: &self.config,
                authorized: &self.registry,
                traffic: &self.traffic,
                sessions: &self.sessions,
            },
            &wire,
            &mut self.cache,
        );
        Some(wire)
    }
}

fn receive(socket: &UdpSocket) -> Vec<u8> {
    let mut bytes = vec![0; 65_535];
    let length = socket.recv(&mut bytes).unwrap();
    bytes.truncate(length);
    bytes
}

fn assert_ip_roundtrip(
    fixture: &mut Fixture,
    wire: &ClientWire,
    plane: &mut TunnelDataPlane,
    socket: &UdpSocket,
    session: &RuntimeSession,
) {
    let mut packet = vec![42; 1280];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&1280_u16.to_be_bytes());
    packet[12..16].copy_from_slice(&session.client_address.octets());
    packet[16..20].copy_from_slice(&[1, 1, 1, 1]);
    let mut encoded = Vec::new();
    wire.encode(&plane.encode_ip(&packet).unwrap(), &mut encoded)
        .unwrap();
    socket.send_to(&encoded, fixture.config.listen).unwrap();
    let mut incoming = vec![0; 65_535];
    let (length, peer) = fixture.socket.recv_from(&mut incoming).unwrap();
    assert_eq!(peer, socket.local_addr().unwrap());
    let mut inner = Vec::new();
    let received_wire = decode_wire_into(
        &incoming[..length],
        &fixture.config,
        &fixture.registry,
        &mut fixture.router,
        &mut inner,
    )
    .unwrap();
    assert!(session.wire.matches(&received_wire));
    let mut plaintext = Vec::new();
    let mut inbound = session.inbound.lock().unwrap();
    assert_eq!(
        inbound
            .decode_into(Datagram::decode(&inner).unwrap(), &mut plaintext)
            .unwrap(),
        Decoded::Ip(packet.as_slice())
    );
    drop(inbound);
    session
        .outbound
        .lock()
        .unwrap()
        .encode_ip_into(&packet, &mut inner)
        .unwrap();
    session.wire.encode_server(&inner, &mut encoded).unwrap();
    fixture.socket.send_to(&encoded, peer).unwrap();
    wire.decode(&receive(socket), &mut inner).unwrap();
    assert_eq!(plane.decode_ip(&inner).unwrap(), packet);
}

#[test]
// Keep the handshake, retransmit and migration steps together so the shared
// socket/session invariants are visible in one end-to-end scenario.
#[allow(clippy::too_many_lines)]
fn legacy_morph_and_speedy_coexist_and_keepalive_migration_requires_fresh_authentication() {
    let mut fixture = Fixture::new();
    for (index, protocol) in [
        ClientProtocol::Legacy,
        ClientProtocol::MorphQuiet,
        ClientProtocol::Speedy,
    ]
    .into_iter()
    .enumerate()
    {
        let config = fixture.client_config(index, protocol);
        let wire = ClientWire::from_config(&config).unwrap();
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let peer = socket.local_addr().unwrap();
        let session_id = 10 + index as u64;
        let mut handshake = ClientHandshake::new(
            &config.client_private_key,
            &config.server_public_key,
            &config.context,
        )
        .unwrap();
        let initial = handshake.write_initial(&[]).unwrap();
        let header = Header {
            kind: PacketKind::HandshakeInit,
            flags: 0,
            session_id,
            sequence: 0,
        };
        let mut request = Vec::new();
        wire.encode(&Datagram::new(header, &initial).encode(), &mut request)
            .unwrap();
        let server_wire = fixture.handle(peer, &request).unwrap();
        let first_response = receive(&socket);
        let session = Arc::clone(&fixture.sessions.read().unwrap().by_id[&session_id]);
        fixture.handle(peer, &request).unwrap();
        let repeated = receive(&socket);
        assert!(Arc::ptr_eq(
            &fixture.sessions.read().unwrap().by_id[&session_id],
            &session
        ));
        let mut decoded = Vec::new();
        let mut decoded_repeat = Vec::new();
        assert!(wire.decode(&first_response, &mut decoded).unwrap());
        assert!(wire.decode(&repeated, &mut decoded_repeat).unwrap());
        assert_eq!(decoded, decoded_repeat);
        let response = Datagram::decode(&decoded).unwrap();
        let (crypto, parameters) = handshake.finish(response.payload).unwrap();
        let parameters = SessionParameters::decode(&parameters).unwrap();
        let expected_mtu = match protocol {
            ClientProtocol::Legacy => 1420,
            ClientProtocol::Speedy => mousevpn_speedy::SAFE_TUN_MTU,
            _ => SAFE_TUN_MTU,
        };
        assert_eq!(parameters.mtu, expected_mtu);
        let mut plane = TunnelDataPlane::new(session_id, usize::from(parameters.mtu), crypto);
        assert_ip_roundtrip(&mut fixture, &wire, &mut plane, &socket, &session);
        let keepalive = plane.encode_keepalive().unwrap();
        let mut frame = Vec::new();
        wire.encode(&keepalive, &mut frame).unwrap();
        let mut decoded = Vec::new();
        let received_wire = decode_wire_into(
            &frame,
            &fixture.config,
            &fixture.registry,
            &mut fixture.router,
            &mut decoded,
        )
        .unwrap();
        assert!(server_wire.matches(&received_wire));
        let mut buffers = KeepaliveBuffers {
            plaintext: Vec::new(),
            response: Vec::new(),
            wire_response: Vec::new(),
        };
        let migrated = UdpSocket::bind("127.0.0.1:0").unwrap();
        migrated
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let migrated_peer = migrated.local_addr().unwrap();
        // An altered Noise ciphertext cannot move an endpoint, even if the outer
        // frame came from an authorized masking key.
        let mut corrupt = decoded.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        handle_keepalive(
            &fixture.socket,
            migrated_peer,
            Datagram::decode(&corrupt).unwrap(),
            &received_wire,
            &fixture.sessions,
            &mut buffers,
        );
        assert_eq!(session.peer(), Some(peer));
        handle_keepalive(
            &fixture.socket,
            migrated_peer,
            Datagram::decode(&decoded).unwrap(),
            &received_wire,
            &fixture.sessions,
            &mut buffers,
        );
        assert_eq!(session.peer(), Some(migrated_peer));
        wire.decode(&receive(&migrated), &mut decoded_repeat)
            .unwrap();
        assert_eq!(
            plane.decode(&decoded_repeat).unwrap(),
            mousevpn_data_plane::DecodedPacket::Keepalive
        );
        // A captured keepalive cannot move the session back to an old endpoint.
        handle_keepalive(
            &fixture.socket,
            peer,
            Datagram::decode(&decoded).unwrap(),
            &received_wire,
            &fixture.sessions,
            &mut buffers,
        );
        assert_eq!(session.peer(), Some(migrated_peer));
    }
    assert_eq!(fixture.sessions.read().unwrap().by_id.len(), 3);
}

#[test]
fn linux_probe_retransmits_speedy_without_falling_back_to_legacy() {
    let mut fixture = Fixture::new();
    let config = fixture.client_config(0, ClientProtocol::Speedy);
    let server = thread::spawn(move || {
        let mut buffer = vec![0; 65_535];
        let (length, peer) = fixture.socket.recv_from(&mut buffer).unwrap();
        let first = buffer[..length].to_vec();
        // Lose the first request; exercise the real Linux handshake retransmit.
        let (length, second_peer) = fixture.socket.recv_from(&mut buffer).unwrap();
        assert_eq!(peer, second_peer);
        let mut first_inner = Vec::new();
        let mut second_inner = Vec::new();
        assert!(matches!(
            decode_wire_into(
                &first,
                &fixture.config,
                &fixture.registry,
                &mut fixture.router,
                &mut first_inner
            ),
            Some(WireMode::Speedy { .. })
        ));
        assert!(matches!(
            decode_wire_into(
                &buffer[..length],
                &fixture.config,
                &fixture.registry,
                &mut fixture.router,
                &mut second_inner
            ),
            Some(WireMode::Speedy { .. })
        ));
        assert_eq!(first_inner, second_inner);
        assert!(matches!(
            fixture.handle(peer, &buffer[..length]),
            Some(WireMode::Speedy { .. })
        ));
    });
    let parameters = mousevpn_linux_client::probe(&config).unwrap();
    assert_eq!(parameters.mtu, mousevpn_speedy::SAFE_TUN_MTU);
    server.join().unwrap();
}

#[test]
fn unknown_or_revoked_speedy_keys_have_no_route_and_cannot_create_sessions() {
    let mut fixture = Fixture::new();
    let config = fixture.client_config(0, ClientProtocol::Speedy);
    let wire = ClientWire::from_config(&config).unwrap();
    let mut handshake = ClientHandshake::new(
        &config.client_private_key,
        &config.server_public_key,
        &config.context,
    )
    .unwrap();
    let initial = handshake.write_initial(&[]).unwrap();
    let mut frame = Vec::new();
    wire.encode(
        &Datagram::new(
            Header {
                kind: PacketKind::HandshakeInit,
                flags: 0,
                session_id: 7,
                sequence: 0,
            },
            &initial,
        )
        .encode(),
        &mut frame,
    )
    .unwrap();
    let mut decoded = Vec::new();
    assert!(matches!(
        decode_wire_into(
            &frame,
            &fixture.config,
            &fixture.registry,
            &mut fixture.router,
            &mut decoded
        ),
        Some(WireMode::Speedy { .. })
    ));
    fixture
        .registry
        .revoke(&encode_public_key(&fixture.clients[0].public))
        .unwrap();
    fixture
        .router
        .refresh(0, &fixture.config, &fixture.registry)
        .unwrap();
    assert!(!fixture
        .router
        .speedy_codecs
        .contains_key(&fixture.clients[0].public));
    assert!(fixture
        .router
        .speedy_routes
        .values()
        .all(|(key, _)| *key != fixture.clients[0].public));
    fixture.handle("127.0.0.1:9999".parse().unwrap(), &frame);
    assert!(fixture.sessions.read().unwrap().by_id.is_empty());

    let mut unknown = fixture.client_config(1, ClientProtocol::Speedy);
    unknown.client_private_key = KeyPair::generate().unwrap().secret;
    let wire = ClientWire::from_config(&unknown).unwrap();
    let mut handshake = ClientHandshake::new(
        &unknown.client_private_key,
        &unknown.server_public_key,
        &unknown.context,
    )
    .unwrap();
    let initial = handshake.write_initial(&[]).unwrap();
    wire.encode(
        &Datagram::new(
            Header {
                kind: PacketKind::HandshakeInit,
                flags: 0,
                session_id: 8,
                sequence: 0,
            },
            &initial,
        )
        .encode(),
        &mut frame,
    )
    .unwrap();
    fixture.handle("127.0.0.1:9999".parse().unwrap(), &frame);
    assert!(fixture.sessions.read().unwrap().by_id.is_empty());
}

#[test]
fn speedy_does_not_accept_a_legacy_noise_handshake_inside_valid_masking() {
    let mut fixture = Fixture::new();
    let config = fixture.client_config(0, ClientProtocol::Speedy);
    let wire = ClientWire::from_config(&config).unwrap();
    let mut handshake = ClientHandshake::new(
        &config.client_private_key,
        &config.server_public_key,
        &fixture.config.context,
    )
    .unwrap();
    let initial = handshake.write_initial(&[]).unwrap();
    let mut frame = Vec::new();
    wire.encode(
        &Datagram::new(
            Header {
                kind: PacketKind::HandshakeInit,
                flags: 0,
                session_id: 9,
                sequence: 0,
            },
            &initial,
        )
        .encode(),
        &mut frame,
    )
    .unwrap();
    let resolved = fixture
        .handle("127.0.0.1:9999".parse().unwrap(), &frame)
        .unwrap();
    assert!(matches!(resolved, WireMode::Speedy { .. }));
    assert_eq!(resolved.session_mtu(1200), 1200);
    assert!(fixture.sessions.read().unwrap().by_id.is_empty());
}
