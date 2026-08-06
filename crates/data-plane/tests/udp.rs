use std::{
    net::{SocketAddr, UdpSocket},
    thread,
    time::Duration,
};

use mousevpn_crypto::{ClientHandshake, KeyPair, ProtocolContext, ServerHandshake};
use mousevpn_data_plane::TunnelDataPlane;
use mousevpn_transport::{DatagramTransport, UdpTransport};

const SESSION_ID: u64 = 500;
const MTU: usize = 1_280;

#[test]
fn transports_ipv4_over_real_udp_socket() {
    let (client_crypto, server_crypto) = establish();
    let server_socket = UdpSocket::bind("127.0.0.1:0").expect("server bind");
    server_socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("server timeout");
    let server_addr = server_socket.local_addr().expect("server address");
    let server_thread = thread::spawn(move || {
        let mut buffer = vec![0_u8; 2_048];
        let (length, peer) = server_socket
            .recv_from(&mut buffer)
            .expect("server receive");
        let mut plane = TunnelDataPlane::new(SESSION_ID, MTU, server_crypto);
        let request = plane.decode_ip(&buffer[..length]).expect("decode request");
        let response = reverse_ipv4_addresses(request);
        let encrypted = plane.encode_ip(&response).expect("encode response");
        server_socket
            .send_to(&encrypted, peer)
            .expect("server response");
    });

    let local = SocketAddr::from(([127, 0, 0, 1], 0));
    let mut transport = UdpTransport::bind(local, server_addr).expect("client UDP");
    transport
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("client timeout");
    let mut plane = TunnelDataPlane::new(SESSION_ID, MTU, client_crypto);
    let request = ipv4_packet([10, 77, 0, 2], [9, 9, 9, 9]);
    transport
        .send(&plane.encode_ip(&request).expect("encode request"))
        .expect("send request");
    let mut buffer = vec![0_u8; 2_048];
    let length = transport.receive(&mut buffer).expect("receive response");
    let response = plane.decode_ip(&buffer[..length]).expect("decode response");
    assert_eq!(&response[12..16], &[9, 9, 9, 9]);
    assert_eq!(&response[16..20], &[10, 77, 0, 2]);
    server_thread.join().expect("server thread");
}

fn establish() -> (
    mousevpn_crypto::SecureSession,
    mousevpn_crypto::SecureSession,
) {
    let client_keys = KeyPair::generate().expect("client keys");
    let server_keys = KeyPair::generate().expect("server keys");
    let context = ProtocolContext::for_server(&server_keys.public);
    let mut client = ClientHandshake::new(&client_keys.secret, &server_keys.public, &context)
        .expect("client handshake");
    let initial = client.write_initial(&[]).expect("initial");
    let mut server = ServerHandshake::new(&server_keys.secret, &context).expect("server handshake");
    server.read_initial(&initial).expect("read initial");
    let (server_session, response) = server.finish(&[]).expect("response");
    let (client_session, _) = client.finish(&response).expect("finish");
    (client_session, server_session)
}

fn ipv4_packet(source: [u8; 4], destination: [u8; 4]) -> Vec<u8> {
    let mut packet = vec![0_u8; 20];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&20_u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 1;
    packet[12..16].copy_from_slice(&source);
    packet[16..20].copy_from_slice(&destination);
    packet
}

fn reverse_ipv4_addresses(mut packet: Vec<u8>) -> Vec<u8> {
    let source: [u8; 4] = packet[12..16].try_into().expect("source address");
    let destination: [u8; 4] = packet[16..20].try_into().expect("destination address");
    packet[12..16].copy_from_slice(&destination);
    packet[16..20].copy_from_slice(&source);
    packet
}
