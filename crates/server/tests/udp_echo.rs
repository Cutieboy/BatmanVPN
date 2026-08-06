use std::{
    net::{SocketAddr, UdpSocket},
    thread,
    time::Duration,
};

use mousevpn_crypto::{ClientHandshake, KeyPair, ProtocolContext, ServerHandshake};
use mousevpn_protocol::{Datagram, Header, InnerPacket, InnerPacketKind, PacketKind};
use mousevpn_server::{ProvisionedDevice, ServerState};
use mousevpn_transport::{DatagramTransport, UdpTransport};

const CLIENT_COUNT: usize = 3;
const BUFFER_LEN: usize = 65_535;

#[test]
fn serves_three_authorized_udp_clients_and_ignores_unknown_key() {
    let server_keys = KeyPair::generate().expect("server keys");
    let server_public = server_keys.public;
    let context = ProtocolContext::for_server(&server_public);
    let mut state = ServerState::new(8);
    let mut devices = Vec::new();
    for index in 0..CLIENT_COUNT {
        let user = state
            .create_user(format!("friend-{index}"), 1)
            .expect("create user");
        devices.push(state.provision_device(user.id).expect("provision device"));
    }

    let socket = UdpSocket::bind("127.0.0.1:0").expect("server bind");
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("server timeout");
    let server_addr = socket.local_addr().expect("server address");
    let server_thread = thread::spawn(move || {
        run_server(&socket, &server_keys, context, state, CLIENT_COUNT);
    });

    assert_unknown_client_is_ignored(server_addr, server_public, context);
    for (index, device) in devices.iter().enumerate() {
        let message = format!("hello from friend {index}");
        let echoed = run_client(
            server_addr,
            server_public,
            context,
            100 + u64::try_from(index).expect("session index"),
            device,
            message.as_bytes(),
        );
        assert_eq!(echoed, message.as_bytes());
    }

    server_thread.join().expect("server thread");
}

fn run_server(
    socket: &UdpSocket,
    server_keys: &KeyPair,
    context: ProtocolContext,
    mut state: ServerState,
    expected_echoes: usize,
) {
    let mut buffer = vec![0_u8; BUFFER_LEN];
    let mut echoes = 0;
    while echoes < expected_echoes {
        let (length, peer) = socket.recv_from(&mut buffer).expect("server receive");
        let packet = Datagram::decode(&buffer[..length]).expect("outer packet");
        match packet.header.kind {
            PacketKind::HandshakeInit => {
                handle_handshake(socket, peer, packet, server_keys, &context, &mut state);
            }
            PacketKind::Data => {
                handle_data(socket, peer, packet, &mut state);
                echoes += 1;
            }
            _ => {}
        }
    }
}

fn handle_handshake(
    socket: &UdpSocket,
    peer: SocketAddr,
    packet: Datagram<'_>,
    server_keys: &KeyPair,
    context: &ProtocolContext,
    state: &mut ServerState,
) {
    let mut handshake = ServerHandshake::new(&server_keys.secret, context).expect("handshake");
    if handshake.read_initial(packet.payload).is_err() {
        return;
    }
    let Some(public_key) = handshake.peer_static_key() else {
        return;
    };
    let Some(user) = state.authorize(&public_key) else {
        return;
    };
    let (session, response) = handshake.finish(&[]).expect("finish handshake");
    state
        .insert_session(packet.header.session_id, &user, peer, session)
        .expect("insert session");
    let header = Header {
        kind: PacketKind::HandshakeResponse,
        flags: 0,
        session_id: packet.header.session_id,
        sequence: 0,
    };
    socket
        .send_to(&Datagram::new(header, &response).encode(), peer)
        .expect("send handshake response");
}

fn handle_data(
    socket: &UdpSocket,
    peer: SocketAddr,
    packet: Datagram<'_>,
    state: &mut ServerState,
) {
    let active = state
        .session_mut(packet.header.session_id, peer)
        .expect("authorized session");
    let plaintext = active
        .crypto_mut()
        .decrypt(packet.header.sequence, packet.payload)
        .expect("decrypt request");
    let inner = InnerPacket::decode(&plaintext).expect("inner request");
    assert_eq!(inner.kind, InnerPacketKind::Data);
    let response_plaintext = InnerPacket::new(InnerPacketKind::Data, inner.payload).encode();
    let ciphertext = active
        .crypto_mut()
        .encrypt(packet.header.sequence, &response_plaintext)
        .expect("encrypt response");
    socket
        .send_to(&Datagram::new(packet.header, &ciphertext).encode(), peer)
        .expect("send echo");
}

fn run_client(
    server_addr: SocketAddr,
    server_public: mousevpn_crypto::PublicKey,
    context: ProtocolContext,
    session_id: u64,
    device: &ProvisionedDevice,
    message: &[u8],
) -> Vec<u8> {
    let local = SocketAddr::from(([127, 0, 0, 1], 0));
    let mut transport = UdpTransport::bind(local, server_addr).expect("client UDP");
    transport
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("client timeout");
    let mut handshake = ClientHandshake::new(&device.secret_key, &server_public, &context)
        .expect("client handshake");
    let initial = handshake.write_initial(&[]).expect("initial message");
    send_packet(
        &mut transport,
        PacketKind::HandshakeInit,
        session_id,
        0,
        &initial,
    );
    let response = receive_packet(&mut transport);
    let (mut session, _) = handshake.finish(&response.payload).expect("finish client");

    let inner = InnerPacket::new(InnerPacketKind::Data, message).encode();
    let ciphertext = session.encrypt(0, &inner).expect("encrypt request");
    send_packet(&mut transport, PacketKind::Data, session_id, 0, &ciphertext);
    let response = receive_packet(&mut transport);
    let plaintext = session
        .decrypt(0, &response.payload)
        .expect("decrypt response");
    InnerPacket::decode(&plaintext)
        .expect("inner response")
        .payload
        .to_vec()
}

fn assert_unknown_client_is_ignored(
    server_addr: SocketAddr,
    server_public: mousevpn_crypto::PublicKey,
    context: ProtocolContext,
) {
    let unknown = KeyPair::generate().expect("unknown keys");
    let local = SocketAddr::from(([127, 0, 0, 1], 0));
    let mut transport = UdpTransport::bind(local, server_addr).expect("unknown UDP");
    transport
        .set_read_timeout(Some(Duration::from_millis(100)))
        .expect("unknown timeout");
    let mut handshake =
        ClientHandshake::new(&unknown.secret, &server_public, &context).expect("unknown handshake");
    let initial = handshake.write_initial(&[]).expect("unknown initial");
    send_packet(&mut transport, PacketKind::HandshakeInit, 99, 0, &initial);
    let mut buffer = vec![0_u8; BUFFER_LEN];
    assert!(transport.receive(&mut buffer).is_err());
}

fn send_packet(
    transport: &mut UdpTransport,
    kind: PacketKind,
    session_id: u64,
    sequence: u64,
    payload: &[u8],
) {
    let header = Header {
        kind,
        flags: 0,
        session_id,
        sequence,
    };
    transport
        .send(&Datagram::new(header, payload).encode())
        .expect("send packet");
}

struct ReceivedPacket {
    payload: Vec<u8>,
}

fn receive_packet(transport: &mut UdpTransport) -> ReceivedPacket {
    let mut buffer = vec![0_u8; BUFFER_LEN];
    let length = transport.receive(&mut buffer).expect("receive packet");
    buffer.truncate(length);
    let packet = Datagram::decode(&buffer).expect("decode packet");
    ReceivedPacket {
        payload: packet.payload.to_vec(),
    }
}
