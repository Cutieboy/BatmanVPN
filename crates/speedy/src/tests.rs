use mousevpn_crypto::{ClientHandshake, KeyPair, ProtocolContext, ServerHandshake};
use mousevpn_data_plane::{Decoded, TunnelDataPlane, TUNNEL_OVERHEAD};
use mousevpn_protocol::Header;

use super::*;

fn codec() -> SpeedyCodec {
    SpeedyCodec::new(SpeedyKey::from_bytes([7; 32]))
}

fn inner() -> Vec<u8> {
    Datagram::new(
        Header {
            kind: PacketKind::Data,
            flags: 0,
            session_id: 7,
            sequence: 9,
        },
        &(0..32).collect::<Vec<u8>>(),
    )
    .encode()
}

#[test]
fn wire_matches_independent_python_vector() {
    // Calculated with Python hmac and the Python BLAKE3 binding, independently
    // of this framing implementation. See tests/reference_vector.py.
    let expected = "3eeb98fb03c1e2d0c19bf22c5c5f0cebaa435946684ae6d96f4a3a50000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1ffdf734440e250c8284178b0f223fb937";
    let expected: Vec<u8> = expected
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();
    let mut frame = Vec::new();
    codec()
        .encode_at(&inner(), Direction::ClientToServer, 100, &mut frame)
        .unwrap();
    assert_eq!(frame, expected);
}

#[test]
fn rejects_tampering_at_every_byte_and_never_exposes_failed_output() {
    let codec = codec();
    let mut frame = Vec::new();
    let mut decoded = Vec::new();
    codec
        .encode_at(&inner(), Direction::ClientToServer, 100, &mut frame)
        .unwrap();
    for index in 0..frame.len() {
        frame[index] ^= 1;
        decoded.extend_from_slice(b"stale plaintext");
        assert!(
            codec
                .decode_at(&frame, Direction::ClientToServer, 100, &mut decoded)
                .is_err(),
            "byte {index}"
        );
        assert!(decoded.is_empty());
        frame[index] ^= 1;
    }
    codec
        .decode_at(&frame, Direction::ClientToServer, 100, &mut decoded)
        .unwrap();
    assert_eq!(decoded, inner());
    for length in 0..frame.len() {
        assert!(codec
            .decode_at(
                &frame[..length],
                Direction::ClientToServer,
                100,
                &mut decoded
            )
            .is_err());
        assert!(decoded.is_empty());
    }
    frame.push(0);
    assert!(codec
        .decode_at(&frame, Direction::ClientToServer, 100, &mut decoded)
        .is_err());
}

#[test]
fn directions_keys_and_epoch_windows_are_separate() {
    let codec = codec();
    let other = SpeedyCodec::new(SpeedyKey::from_bytes([8; 32]));
    let mut frame = Vec::new();
    let mut decoded = Vec::new();
    codec
        .encode_at(&inner(), Direction::ClientToServer, 100, &mut frame)
        .unwrap();
    for epoch in [99, 100, 101] {
        codec
            .decode_at(&frame, Direction::ClientToServer, epoch, &mut decoded)
            .unwrap();
        assert_eq!(decoded, inner());
    }
    for epoch in [98, 102, u64::MAX] {
        assert!(codec
            .decode_at(&frame, Direction::ClientToServer, epoch, &mut decoded)
            .is_err());
    }
    assert!(codec
        .decode_at(&frame, Direction::ServerToClient, 100, &mut decoded)
        .is_err());
    assert!(other
        .decode_at(&frame, Direction::ClientToServer, 100, &mut decoded)
        .is_err());
    let previous = frame.clone();
    codec
        .encode_at(&inner(), Direction::ClientToServer, 101, &mut frame)
        .unwrap();
    assert_ne!(&frame[..8], &previous[..8]);
    assert_ne!(&frame[8..28], &previous[8..28]);
    // The already encrypted payload is preserved; no second payload encryption.
    assert_eq!(&frame[28..frame.len() - 16], &inner()[20..]);
}

#[test]
fn enforces_mtu_header_flags_and_handshake_direction() {
    let codec = codec();
    let mut packet = inner();
    let mut frame = Vec::new();
    packet.resize(MAX_INNER_DATAGRAM_LEN, 42);
    codec
        .encode(&packet, Direction::ClientToServer, &mut frame)
        .unwrap();
    assert_eq!(frame.len(), MAX_DATAGRAM_LEN);
    assert_eq!(
        usize::from(SAFE_TUN_MTU) + TUNNEL_OVERHEAD + OVERHEAD,
        MAX_DATAGRAM_LEN
    );
    packet.push(0);
    assert!(codec
        .encode(&packet, Direction::ClientToServer, &mut frame)
        .is_err());
    assert!(frame.is_empty());
    let mut packet = inner();
    packet[2] = 1;
    assert!(codec
        .encode(&packet, Direction::ClientToServer, &mut frame)
        .is_err());
    packet[2] = 0;
    packet[1] = PacketKind::HandshakeResponse as u8;
    assert!(codec
        .encode(&packet, Direction::ClientToServer, &mut frame)
        .is_err());
    assert!(codec
        .encode(&packet, Direction::ServerToClient, &mut frame)
        .is_err());
    packet[12..20].fill(0);
    codec
        .encode(&packet, Direction::ServerToClient, &mut frame)
        .unwrap();
}

#[test]
fn noise_data_keepalive_reordering_and_replay_work_in_both_directions() {
    let client = KeyPair::generate().unwrap();
    let server = KeyPair::generate().unwrap();
    let context = ProtocolContext::for_speedy_server(&server.public);
    let mut initiator = ClientHandshake::new(&client.secret, &server.public, &context).unwrap();
    let mut responder = ServerHandshake::new(&server.secret, &context).unwrap();
    responder
        .read_initial(&initiator.write_initial(&[]).unwrap())
        .unwrap();
    let (server_crypto, response) = responder.finish(&[]).unwrap();
    let (client_crypto, _) = initiator.finish(&response).unwrap();
    let (client_send, client_receive) =
        TunnelDataPlane::new(7, usize::from(SAFE_TUN_MTU), client_crypto).split();
    let (server_send, server_receive) =
        TunnelDataPlane::new(7, usize::from(SAFE_TUN_MTU), server_crypto).split();
    let codec = codec();
    for (mut sender, mut receiver, direction) in [
        (client_send, server_receive, Direction::ClientToServer),
        (server_send, client_receive, Direction::ServerToClient),
    ] {
        let mut inner = Vec::new();
        let mut frames = Vec::new();
        let mut unmasked = Vec::new();
        let mut plaintext = Vec::new();
        for length in 20..=SAFE_TUN_MTU {
            let mut packet = vec![42; usize::from(length)];
            packet[0] = 0x45;
            packet[2..4].copy_from_slice(&length.to_be_bytes());
            sender.encode_ip_into(&packet, &mut inner).unwrap();
            let mut frame = Vec::new();
            codec.encode(&inner, direction, &mut frame).unwrap();
            frames.push((frame, packet));
        }
        for (frame, packet) in frames.iter().rev() {
            codec.decode(frame, direction, &mut unmasked).unwrap();
            assert_eq!(
                receiver
                    .decode_into(Datagram::decode(&unmasked).unwrap(), &mut plaintext)
                    .unwrap(),
                Decoded::Ip(packet)
            );
        }
        codec
            .decode(&frames[0].0, direction, &mut unmasked)
            .unwrap();
        assert!(receiver
            .decode_into(Datagram::decode(&unmasked).unwrap(), &mut plaintext)
            .is_err());
        sender.encode_keepalive_into(&mut inner).unwrap();
        let mut frame = Vec::new();
        codec.encode(&inner, direction, &mut frame).unwrap();
        codec.decode(&frame, direction, &mut unmasked).unwrap();
        assert_eq!(
            receiver
                .decode_into(Datagram::decode(&unmasked).unwrap(), &mut plaintext)
                .unwrap(),
            Decoded::Keepalive
        );
    }
}
