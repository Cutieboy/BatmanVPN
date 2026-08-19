use std::{error::Error, fmt};

use crate::ReplayError;

#[derive(Debug)]
pub enum CryptoError {
    Noise(snow::Error),
    InvalidKeyLength { actual: usize },
    MessageTooLarge { actual: usize, maximum: usize },
    InvalidSharedSecret,
    MissingPeerStaticKey,
    Replay(ReplayError),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Noise(error) => write!(formatter, "Noise protocol error: {error}"),
            Self::InvalidKeyLength { actual } => {
                write!(formatter, "invalid X25519 key length: {actual}")
            }
            Self::MessageTooLarge { actual, maximum } => {
                write!(
                    formatter,
                    "message is too large: {actual} bytes, maximum {maximum}"
                )
            }
            Self::InvalidSharedSecret => {
                formatter.write_str("X25519 peer key produces an invalid shared secret")
            }
            Self::MissingPeerStaticKey => formatter.write_str("peer static key is unavailable"),
            Self::Replay(error) => write!(formatter, "replay rejected: {error}"),
        }
    }
}

impl Error for CryptoError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Noise(error) => Some(error),
            Self::Replay(error) => Some(error),
            Self::InvalidKeyLength { .. }
            | Self::MessageTooLarge { .. }
            | Self::InvalidSharedSecret
            | Self::MissingPeerStaticKey => None,
        }
    }
}

impl From<snow::Error> for CryptoError {
    fn from(error: snow::Error) -> Self {
        Self::Noise(error)
    }
}

impl From<ReplayError> for CryptoError {
    fn from(error: ReplayError) -> Self {
        Self::Replay(error)
    }
}
