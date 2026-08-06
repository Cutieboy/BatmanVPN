use mousevpn_crypto::{ClientHandshake, KeyPair, ProtocolContext, ServerHandshake};
use mousevpn_data_plane::{DecodedPacket, Ipv4Packet, TunnelDataPlane};

#[test]
fn carries_ipv4_packet_in_both_directions() {
    let (client_crypto, server_crypto) = establish();
    let mut client = TunnelDataPlane::new(77, 1_280, client_crypto);
    let mut server = TunnelDataPlane::new(77, 1_280, server_crypto);
    let request = ipv4_packet([10, 77, 0, 2], [1, 1, 1, 1], b"request");
    let response = ipv4_packet([1, 1, 1, 1], [10, 77, 0, 2], b"response");

    let encrypted = client.encode_ip(&request).expect("encode request");
    assert_eq!(
        server.decode_ip(&encrypted).expect("decode request"),
        request
    );
    let encrypted = server.encode_ip(&response).expect("encode response");
    assert_eq!(
        client.decode_ip(&encrypted).expect("decode response"),
        response
    );
}

#[test]
fn authenticates_keepalive_in_both_directions() {
    let (client_crypto, server_crypto) = establish();
    let mut client = TunnelDataPlane::new(78, 1_280, client_crypto);
    let mut server = TunnelDataPlane::new(78, 1_280, server_crypto);

    let packet = client.encode_keepalive().expect("client keepalive");
    assert_eq!(
        server.decode(&packet).expect("server decode"),
        DecodedPacket::Keepalive
    );
    let packet = server.encode_keepalive().expect("server keepalive");
    assert_eq!(
        client.decode(&packet).expect("client decode"),
        DecodedPacket::Keepalive
    );
}

#[test]
fn extracts_ipv4_addresses() {
    let bytes = ipv4_packet([10, 77, 0, 2], [8, 8, 8, 8], &[]);
    let packet = Ipv4Packet::parse(&bytes).expect("parse IPv4");
    assert_eq!(packet.source().octets(), [10, 77, 0, 2]);
    assert_eq!(packet.destination().octets(), [8, 8, 8, 8]);
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

fn ipv4_packet(source: [u8; 4], destination: [u8; 4], payload: &[u8]) -> Vec<u8> {
    let total_len = u16::try_from(20 + payload.len()).expect("test packet length");
    let mut packet = vec![0_u8; usize::from(total_len)];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&total_len.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&source);
    packet[16..20].copy_from_slice(&destination);
    packet[20..].copy_from_slice(payload);
    packet
}
