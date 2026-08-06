use mousevpn_protocol::{InnerDecodeError, InnerPacket, InnerPacketKind};

#[test]
fn inner_packet_round_trip() {
    let encoded = InnerPacket::new(InnerPacketKind::Data, b"IP packet").encode();
    let decoded = InnerPacket::decode(&encoded).expect("decode inner packet");

    assert_eq!(decoded.kind, InnerPacketKind::Data);
    assert_eq!(decoded.payload, b"IP packet");
}

#[test]
fn rejects_empty_inner_packet() {
    assert_eq!(InnerPacket::decode(&[]), Err(InnerDecodeError::Empty));
}
