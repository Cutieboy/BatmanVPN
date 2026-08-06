use mousevpn_client_core::{ClientSession, SessionState};
use mousevpn_protocol::PacketKind;

#[test]
fn starts_handshake() {
    let mut session = ClientSession::new(7);
    let header = session.begin_handshake();

    assert_eq!(session.state(), SessionState::Handshaking);
    assert_eq!(header.kind, PacketKind::HandshakeInit);
    assert_eq!(header.session_id, 7);
    assert_eq!(header.sequence, 0);
}
