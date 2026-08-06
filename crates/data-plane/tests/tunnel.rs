use mousevpn_crypto::{ClientHandshake, KeyPair, ProtocolContext, ServerHandshake};
use mousevpn_data_plane::{
    looks_like_protocol_datagram, DataPlaneError, Decoded, DecodedPacket, Ipv4Packet,
    TunnelDataPlane,
};
use mousevpn_protocol::Datagram;

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
fn split_halves_carry_ipv4_in_both_directions() {
    let (client_crypto, server_crypto) = establish();
    let (mut client_sender, mut client_receiver) =
        TunnelDataPlane::new(79, 1_280, client_crypto).split();
    let (mut server_sender, mut server_receiver) =
        TunnelDataPlane::new(79, 1_280, server_crypto).split();
    let request = ipv4_packet([10, 77, 0, 2], [1, 1, 1, 1], b"request");
    let response = ipv4_packet([1, 1, 1, 1], [10, 77, 0, 2], b"response");
    let mut wire = Vec::new();
    let mut plaintext = Vec::new();

    client_sender
        .encode_ip_into(&request, &mut wire)
        .expect("encode request");
    assert!(looks_like_protocol_datagram(&wire));
    let decoded = server_receiver
        .decode_into(Datagram::decode(&wire).expect("frame"), &mut plaintext)
        .expect("decode request");
    assert_eq!(decoded, Decoded::Ip(&request));

    server_sender
        .encode_ip_into(&response, &mut wire)
        .expect("encode response");
    let decoded = client_receiver
        .decode_into(Datagram::decode(&wire).expect("frame"), &mut plaintext)
        .expect("decode response");
    assert_eq!(decoded, Decoded::Ip(&response));
}

#[test]
fn split_halves_authenticate_keepalives() {
    let (client_crypto, server_crypto) = establish();
    let (mut client_sender, _) = TunnelDataPlane::new(80, 1_280, client_crypto).split();
    let (_, mut server_receiver) = TunnelDataPlane::new(80, 1_280, server_crypto).split();
    let mut wire = Vec::new();
    let mut plaintext = Vec::new();

    client_sender
        .encode_keepalive_into(&mut wire)
        .expect("keepalive");
    let decoded = server_receiver
        .decode_into(Datagram::decode(&wire).expect("frame"), &mut plaintext)
        .expect("decode keepalive");
    assert_eq!(decoded, Decoded::Keepalive);
}

/// Buffers are reused across packets, so a short packet must never expose the
/// tail of a longer one, and a long packet must still fit.
#[test]
fn reused_buffers_do_not_leak_between_packets() {
    let (client_crypto, server_crypto) = establish();
    let (mut sender, _) = TunnelDataPlane::new(81, 1_280, client_crypto).split();
    let (_, mut receiver) = TunnelDataPlane::new(81, 1_280, server_crypto).split();
    let mut wire = Vec::new();
    let mut plaintext = Vec::new();

    for length in [1_200_usize, 4, 900, 0, 1_200] {
        let packet = ipv4_packet([10, 77, 0, 2], [1, 1, 1, 1], &vec![0xAB; length]);
        sender
            .encode_ip_into(&packet, &mut wire)
            .expect("encode packet");
        let decoded = receiver
            .decode_into(Datagram::decode(&wire).expect("frame"), &mut plaintext)
            .expect("decode packet");
        assert_eq!(decoded, Decoded::Ip(&packet));
    }
}

#[test]
fn split_halves_reject_replays_and_foreign_sessions() {
    let (client_crypto, server_crypto) = establish();
    let (mut sender, _) = TunnelDataPlane::new(82, 1_280, client_crypto).split();
    let (_, mut receiver) = TunnelDataPlane::new(82, 1_280, server_crypto).split();
    let (_, mut other_session) = TunnelDataPlane::new(83, 1_280, establish().1).split();
    let packet = ipv4_packet([10, 77, 0, 2], [1, 1, 1, 1], b"once");
    let mut wire = Vec::new();
    let mut plaintext = Vec::new();

    sender.encode_ip_into(&packet, &mut wire).expect("encode");
    receiver
        .decode_into(Datagram::decode(&wire).expect("frame"), &mut plaintext)
        .expect("first delivery");
    assert!(matches!(
        receiver.decode_into(Datagram::decode(&wire).expect("frame"), &mut plaintext),
        Err(DataPlaneError::Crypto(_))
    ));
    assert!(matches!(
        other_session.decode_into(Datagram::decode(&wire).expect("frame"), &mut plaintext),
        Err(DataPlaneError::SessionMismatch)
    ));
}

#[test]
fn split_halves_reject_packets_above_the_tunnel_mtu() {
    let (client_crypto, _) = establish();
    let (mut sender, _) = TunnelDataPlane::new(84, 600, client_crypto).split();
    let packet = ipv4_packet([10, 77, 0, 2], [1, 1, 1, 1], &vec![0_u8; 700]);
    let mut wire = Vec::new();

    assert!(matches!(
        sender.encode_ip_into(&packet, &mut wire),
        Err(DataPlaneError::PacketExceedsMtu { .. })
    ));
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
