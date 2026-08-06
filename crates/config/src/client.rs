use std::net::SocketAddr;

use mousevpn_crypto::{ProtocolContext, PublicKey, SecretKey};
use serde::Deserialize;

use crate::{decode_public_key, decode_secret_key, ConfigError};

#[derive(Debug, Deserialize)]
pub struct ClientConfig {
    pub server: SocketAddr,
    pub server_public_key: String,
    pub client_private_key: String,
    #[serde(default = "default_tun_name")]
    pub tun_name: String,
}

pub struct ValidatedClientConfig {
    pub server: SocketAddr,
    pub server_public_key: PublicKey,
    pub client_private_key: SecretKey,
    pub context: ProtocolContext,
    pub tun_name: String,
}

impl ClientConfig {
    /// Decodes cryptographic material and derives the deployment context.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid key encoding or length.
    pub fn validate(self) -> Result<ValidatedClientConfig, ConfigError> {
        let server_public_key = decode_public_key(&self.server_public_key)?;
        Ok(ValidatedClientConfig {
            server: self.server,
            client_private_key: decode_secret_key(&self.client_private_key)?,
            context: ProtocolContext::for_server(&server_public_key),
            server_public_key,
            tun_name: self.tun_name,
        })
    }
}

fn default_tun_name() -> String {
    "mousevpn0".to_owned()
}
