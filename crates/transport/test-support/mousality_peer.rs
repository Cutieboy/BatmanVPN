// Shared end-to-end fixture for the platform clients: real outer TCP auth,
// device Noise auth and bidirectional IP datagrams, without a system tunnel.
fn echo_peer(connections: usize) -> (mousevpn_config::ValidatedClientConfig, std::thread::JoinHandle<()>) {
    use mousevpn_config::{encode_public_key, encode_secret_key, ClientConfig, ClientProtocol, MousalityClientConfig};
    use mousevpn_crypto::{KeyPair, ServerHandshake};
    use mousevpn_mousality::{Accepted, ReplayCache, ServerSettings, ServerTemplate, StaticSecret};
    use mousevpn_transport::{DatagramTransport, MousalityTransport};
    let server = KeyPair::generate().unwrap();
    let client = KeyPair::generate().unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let config = ClientConfig {
        server: "127.0.0.1:51821".parse().unwrap(),
        server_public_key: encode_public_key(&server.public),
        client_private_key: encode_secret_key(&client.secret),
        tun_name: "mousality-test".into(), protocol: ClientProtocol::Mousality, bypass_russia: true,
        mousality: Some(MousalityClientConfig {
            endpoint: Some(listener.local_addr().unwrap()), server_name: String::new(),
            server_names: vec!["www.example.com".into()],
        }),
    }.validate().unwrap();
    let context = config.context;
    let worker = std::thread::spawn(move || {
        let settings = ServerSettings {
            server_static: StaticSecret::from(server.secret.expose_for_provisioning()),
            server_names: vec!["www.example.com".into()], template: ServerTemplate::default(),
        };
        let mut replay = ReplayCache::default();
        for _ in 0..connections {
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(std::time::Duration::from_secs(3))).unwrap();
            let Accepted::Tunnel(channel) = mousevpn_mousality::accept(&mut stream, &settings, &mut replay, mousevpn_transport::unix_seconds()).unwrap() else { panic!("expected authenticated camouflage"); };
            let mut transport = MousalityTransport::from_channel(stream, *channel).unwrap();
            transport.set_read_timeout(Some(std::time::Duration::from_secs(3)));
            let mut buffer = vec![0; 65_535];
            let length = transport.receive(&mut buffer).unwrap();
            let request = mousevpn_protocol::Datagram::decode(&buffer[..length]).unwrap();
            let mut handshake = ServerHandshake::new(&server.secret, &context).unwrap();
            handshake.read_initial(request.payload).unwrap();
            assert_eq!(handshake.peer_static_key(), Some(client.public));
            let parameters = mousevpn_protocol::SessionParameters {
                client_address: "10.83.0.2".parse().unwrap(), prefix_len: 24, mtu: 1400,
                dns: "1.1.1.1".parse().unwrap(),
            };
            let (crypto, response) = handshake.finish(&parameters.encode()).unwrap();
            let header = mousevpn_protocol::Header { kind: mousevpn_protocol::PacketKind::HandshakeResponse, ..request.header };
            transport.send(&mousevpn_protocol::Datagram::new(header, &response).encode()).unwrap();
            let plane = mousevpn_data_plane::TunnelDataPlane::new(header.session_id, 1400, crypto);
            let (mut sender, mut receiver) = plane.split();
            let mut encoded = Vec::new();
            let mut routes = Vec::new();
            mousevpn_protocol::DirectRoutes::encode(mousevpn_protocol::DirectRoutesPart::ListEnd,
                &[mousevpn_protocol::DirectRoute::new("77.88.0.0".parse().unwrap(), 18).unwrap()], &mut routes);
            sender.encode_direct_routes_into(&routes, &mut encoded).unwrap();
            transport.send(&encoded).unwrap();
            let length = transport.receive(&mut buffer).unwrap();
            let packet = match receiver.decode_into(mousevpn_protocol::Datagram::decode(&buffer[..length]).unwrap(), &mut encoded).unwrap() {
                mousevpn_data_plane::Decoded::Ip(packet) => packet.to_vec(),
                _ => panic!("expected IP datagram"),
            };
            assert_eq!(packet.len(), 20);
            sender.encode_ip_into(&packet, &mut encoded).unwrap();
            transport.send(&encoded).unwrap();
            let length = transport.receive(&mut buffer).unwrap();
            assert_eq!(&buffer[..length], b"done");
        }
    });
    (config, worker)
}

fn round_trip(mut transport: mousevpn_transport::ClientTransport, mut plane: mousevpn_data_plane::TunnelDataPlane) {
    use mousevpn_transport::DatagramTransport;
    assert!(transport.is_mousality());
    transport.set_read_timeout(Some(std::time::Duration::from_secs(3))).unwrap();
    let mut packet = vec![0; 20];
    packet[0] = 0x45;
    packet[3] = 20;
    transport.send(&plane.encode_ip(&packet).unwrap()).unwrap();
    let mut buffer = vec![0; 65_535];
    loop {
        let length = transport.receive(&mut buffer).unwrap();
        match plane.decode(&buffer[..length]).unwrap() {
            mousevpn_data_plane::DecodedPacket::DirectRoutes(_) => {},
            mousevpn_data_plane::DecodedPacket::Ip(actual) => { assert_eq!(actual, packet); break; },
            mousevpn_data_plane::DecodedPacket::Keepalive => panic!("unexpected datagram"),
        }
    }
    transport.send(b"done").unwrap();
    // Keep the queued final datagram alive until the peer closes the channel.
    assert!(transport.receive(&mut buffer).is_err());
}
