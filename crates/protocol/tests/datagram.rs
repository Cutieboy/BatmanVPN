use mousevpn_protocol::{Datagram, Header, PacketKind};

#[test]
fn datagram_round_trip() {
    let header = Header {
        kind: PacketKind::Data,
        flags: 0,
        session_id: 123,
        sequence: 456,
    };
    let encoded = Datagram::new(header, b"ciphertext").encode();
    let decoded = Datagram::decode(&encoded).expect("decode datagram");

    assert_eq!(decoded.header, header);
    assert_eq!(decoded.payload, b"ciphertext");
}
