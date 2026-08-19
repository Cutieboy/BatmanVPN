use std::{fmt, io};

use mousevpn_client_wire::ClientWireError;
use mousevpn_crypto::CryptoError;
use mousevpn_data_plane::DataPlaneError;
use mousevpn_protocol::SessionParametersError;

#[derive(Debug)]
pub enum ClientError {
    Crypto(CryptoError),
    DataPlane(DataPlaneError),
    HandshakeTimeout,
    Io(io::Error),
    Protocol(SessionParametersError),
    Wire(ClientWireError),
    Platform(String),
}

impl fmt::Display for ClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Crypto(error) => write!(formatter, "cryptographic operation failed: {error}"),
            Self::DataPlane(error) => write!(formatter, "packet processing failed: {error}"),
            Self::HandshakeTimeout => formatter.write_str("server handshake timed out"),
            Self::Io(error) => write!(formatter, "network I/O failed: {error}"),
            Self::Protocol(error) => write!(formatter, "invalid server parameters: {error}"),
            Self::Wire(error) => write!(formatter, "wire protocol failed: {error}"),
            Self::Platform(error) => formatter.write_str(error),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<CryptoError> for ClientError {
    fn from(error: CryptoError) -> Self {
        Self::Crypto(error)
    }
}

impl From<io::Error> for ClientError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<DataPlaneError> for ClientError {
    fn from(error: DataPlaneError) -> Self {
        Self::DataPlane(error)
    }
}

impl From<SessionParametersError> for ClientError {
    fn from(error: SessionParametersError) -> Self {
        Self::Protocol(error)
    }
}

impl From<ClientWireError> for ClientError {
    fn from(error: ClientWireError) -> Self {
        Self::Wire(error)
    }
}

impl From<getrandom::Error> for ClientError {
    fn from(error: getrandom::Error) -> Self {
        Self::Platform(format!("secure random generator failed: {error}"))
    }
}
