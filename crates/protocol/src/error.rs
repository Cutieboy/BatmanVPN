use core::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeError {
    Truncated { actual: usize, minimum: usize },
    UnsupportedVersion(u8),
    UnknownPacketKind(u8),
    InvalidHeader,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { actual, minimum } => write!(
                formatter,
                "packet is truncated: {actual} bytes, need {minimum}"
            ),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported protocol version {version}")
            }
            Self::UnknownPacketKind(kind) => write!(formatter, "unknown packet kind {kind}"),
            Self::InvalidHeader => formatter.write_str("invalid packet header"),
        }
    }
}

impl std::error::Error for DecodeError {}
