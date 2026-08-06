use mousevpn_protocol::{Header, PacketKind};

use crate::SessionState;

#[derive(Debug)]
pub struct ClientSession {
    state: SessionState,
    session_id: u64,
    next_sequence: u64,
}

impl ClientSession {
    #[must_use]
    pub const fn new(session_id: u64) -> Self {
        Self {
            state: SessionState::Disconnected,
            session_id,
            next_sequence: 0,
        }
    }

    #[must_use]
    pub const fn state(&self) -> SessionState {
        self.state
    }

    pub fn begin_handshake(&mut self) -> Header {
        self.state = SessionState::Handshaking;
        self.next_header(PacketKind::HandshakeInit)
    }

    fn next_header(&mut self, kind: PacketKind) -> Header {
        let header = Header {
            kind,
            flags: 0,
            session_id: self.session_id,
            sequence: self.next_sequence,
        };
        self.next_sequence = self.next_sequence.saturating_add(1);
        header
    }
}
