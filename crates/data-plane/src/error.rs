use std::{error::Error, fmt};

use mousevpn_crypto::CryptoError;
use mousevpn_protocol::{DecodeError, InnerDecodeError, InnerPacketKind, PacketKind};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ipv4PacketError {
    Truncated,
    UnsupportedVersion(u8),
    InvalidHeaderLength,
    InvalidTotalLength,
}

impl fmt::Display for Ipv4PacketError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => formatter.write_str("IPv4 packet is truncated"),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "IP version {version} is not supported")
            }
            Self::InvalidHeaderLength => formatter.write_str("invalid IPv4 header length"),
            Self::InvalidTotalLength => formatter.write_str("invalid IPv4 total length"),
        }
    }
}

impl Error for Ipv4PacketError {}

#[derive(Debug)]
pub enum DataPlaneError {
    Crypto(CryptoError),
    Outer(DecodeError),
    Inner(InnerDecodeError),
    Ip(Ipv4PacketError),
    UnexpectedPacketKind(PacketKind),
    UnexpectedInnerPacketKind(InnerPacketKind),
    SessionMismatch,
    PacketExceedsMtu { actual: usize, mtu: usize },
    SequenceExhausted,
}

impl fmt::Display for DataPlaneError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Crypto(error) => write!(formatter, "cryptographic error: {error}"),
            Self::Outer(error) => write!(formatter, "outer packet error: {error}"),
            Self::Inner(error) => write!(formatter, "inner packet error: {error}"),
            Self::Ip(error) => write!(formatter, "IP packet error: {error}"),
            Self::UnexpectedPacketKind(kind) => {
                write!(formatter, "unexpected packet kind: {kind:?}")
            }
            Self::UnexpectedInnerPacketKind(kind) => {
                write!(formatter, "unexpected inner packet kind: {kind:?}")
            }
            Self::SessionMismatch => formatter.write_str("packet belongs to another session"),
            Self::PacketExceedsMtu { actual, mtu } => {
                write!(
                    formatter,
                    "IP packet has {actual} bytes; tunnel MTU is {mtu}"
                )
            }
            Self::SequenceExhausted => formatter.write_str("outgoing packet sequence exhausted"),
        }
    }
}

impl Error for DataPlaneError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Crypto(error) => Some(error),
            Self::Outer(error) => Some(error),
            Self::Inner(error) => Some(error),
            Self::Ip(error) => Some(error),
            Self::UnexpectedPacketKind(_)
            | Self::UnexpectedInnerPacketKind(_)
            | Self::SessionMismatch
            | Self::PacketExceedsMtu { .. }
            | Self::SequenceExhausted => None,
        }
    }
}

impl From<CryptoError> for DataPlaneError {
    fn from(error: CryptoError) -> Self {
        Self::Crypto(error)
    }
}

impl From<DecodeError> for DataPlaneError {
    fn from(error: DecodeError) -> Self {
        Self::Outer(error)
    }
}

impl From<InnerDecodeError> for DataPlaneError {
    fn from(error: InnerDecodeError) -> Self {
        Self::Inner(error)
    }
}

impl From<Ipv4PacketError> for DataPlaneError {
    fn from(error: Ipv4PacketError) -> Self {
        Self::Ip(error)
    }
}
