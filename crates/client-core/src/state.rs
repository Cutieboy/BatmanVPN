#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionState {
    Disconnected,
    Handshaking,
    Established,
    Closing,
}
