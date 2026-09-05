use std::{error::Error, fmt, io};

#[derive(Debug)]
pub struct AppleClientError {
    message: String,
}

impl AppleClientError {
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    #[must_use]
    pub fn context(self, context: &str) -> Self {
        Self::new(format!("{context}: {}", self.message))
    }
}

impl fmt::Display for AppleClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for AppleClientError {}

impl From<io::Error> for AppleClientError {
    fn from(error: io::Error) -> Self {
        Self::new(error.to_string())
    }
}

impl From<mousevpn_config::ConfigError> for AppleClientError {
    fn from(error: mousevpn_config::ConfigError) -> Self {
        Self::new(error.to_string())
    }
}

impl From<mousevpn_client_wire::ClientWireError> for AppleClientError {
    fn from(error: mousevpn_client_wire::ClientWireError) -> Self {
        Self::new(error.to_string())
    }
}

impl From<mousevpn_crypto::CryptoError> for AppleClientError {
    fn from(error: mousevpn_crypto::CryptoError) -> Self {
        Self::new(error.to_string())
    }
}

impl From<mousevpn_data_plane::DataPlaneError> for AppleClientError {
    fn from(error: mousevpn_data_plane::DataPlaneError) -> Self {
        Self::new(error.to_string())
    }
}

impl From<mousevpn_protocol::SessionParametersError> for AppleClientError {
    fn from(error: mousevpn_protocol::SessionParametersError) -> Self {
        Self::new(error.to_string())
    }
}

impl From<getrandom::Error> for AppleClientError {
    fn from(error: getrandom::Error) -> Self {
        Self::new(error.to_string())
    }
}
