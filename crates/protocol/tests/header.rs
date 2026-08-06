use mousevpn_protocol::{DecodeError, Header, PacketKind, HEADER_LEN};

#[test]
fn header_round_trip() {
    let header = Header {
        kind: PacketKind::Data,
        flags: 0x0102,
        session_id: 42,
        sequence: 9001,
    };

    assert_eq!(Header::decode(&header.encode()), Ok(header));
}

#[test]
fn rejects_truncated_input() {
    assert_eq!(
        Header::decode(&[0_u8; HEADER_LEN - 1]),
        Err(DecodeError::Truncated {
            actual: HEADER_LEN - 1,
            minimum: HEADER_LEN,
        })
    );
}

#[test]
fn rejects_unknown_version() {
    let mut encoded = Header {
        kind: PacketKind::Keepalive,
        flags: 0,
        session_id: 1,
        sequence: 2,
    }
    .encode();
    encoded[0] = 99;

    assert_eq!(
        Header::decode(&encoded),
        Err(DecodeError::UnsupportedVersion(99))
    );
}
