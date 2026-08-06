use std::{error::Error, fmt};

use mousevpn_crypto::CryptoError;
use mousevpn_data_plane::DataPlaneError;
use mousevpn_protocol::{DecodeError, SessionParametersError};

#[derive(Debug)]
pub enum ClientError {
    Io(std::io::Error),
    Crypto(CryptoError),
    Outer(DecodeError),
    Parameters(SessionParametersError),
    DataPlane(DataPlaneError),
    HandshakeTimeout,
    InvalidHandshakeResponse,
    SessionParametersChanged,
    Random(getrandom::Error),
    WorkerStopped,
}

impl fmt::Display for ClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "I/O error: {error}"),
            Self::Crypto(error) => write!(formatter, "cryptographic error: {error}"),
            Self::Outer(error) => write!(formatter, "protocol error: {error}"),
            Self::Parameters(error) => write!(formatter, "session parameters error: {error}"),
            Self::DataPlane(error) => write!(formatter, "data-plane error: {error}"),
            Self::HandshakeTimeout => formatter.write_str("VPN handshake timed out"),
            Self::InvalidHandshakeResponse => formatter.write_str("invalid handshake response"),
            Self::SessionParametersChanged => {
                formatter.write_str("server changed tunnel parameters; restart the client")
            }
            Self::Random(error) => write!(formatter, "random generator failed: {error}"),
            Self::WorkerStopped => formatter.write_str("packet worker stopped"),
        }
    }
}

impl Error for ClientError {}

impl From<std::io::Error> for ClientError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<CryptoError> for ClientError {
    fn from(error: CryptoError) -> Self {
        Self::Crypto(error)
    }
}

impl From<DecodeError> for ClientError {
    fn from(error: DecodeError) -> Self {
        Self::Outer(error)
    }
}

impl From<SessionParametersError> for ClientError {
    fn from(error: SessionParametersError) -> Self {
        Self::Parameters(error)
    }
}

impl From<DataPlaneError> for ClientError {
    fn from(error: DataPlaneError) -> Self {
        Self::DataPlane(error)
    }
}

impl From<getrandom::Error> for ClientError {
    fn from(error: getrandom::Error) -> Self {
        Self::Random(error)
    }
}
