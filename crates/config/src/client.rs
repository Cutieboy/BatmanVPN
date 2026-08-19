use std::net::SocketAddr;

use mousevpn_crypto::{ProtocolContext, PublicKey, SecretKey};
use mousevpn_morph::Profile;
use serde::{Deserialize, Serialize};

use crate::{decode_public_key, decode_secret_key, ConfigError};

#[derive(Debug, Deserialize)]
pub struct ClientConfig {
    pub server: SocketAddr,
    pub server_public_key: String,
    pub client_private_key: String,
    #[serde(default = "default_tun_name")]
    pub tun_name: String,
    #[serde(default)]
    pub protocol: ClientProtocol,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientProtocol {
    #[default]
    Legacy,
    MorphQuiet,
    MorphBalanced,
    MorphParanoid,
}

impl ClientProtocol {
    #[must_use]
    pub const fn morph_profile(self) -> Option<Profile> {
        match self {
            Self::Legacy => None,
            Self::MorphQuiet => Some(Profile::Quiet),
            Self::MorphBalanced => Some(Profile::Balanced),
            Self::MorphParanoid => Some(Profile::Paranoid),
        }
    }
}

pub struct ValidatedClientConfig {
    pub server: SocketAddr,
    pub server_public_key: PublicKey,
    pub client_private_key: SecretKey,
    pub context: ProtocolContext,
    pub tun_name: String,
    pub protocol: ClientProtocol,
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
            protocol: self.protocol,
        })
    }
}

fn default_tun_name() -> String {
    "mousevpn0".to_owned()
}

#[cfg(test)]
mod tests {
    use super::{ClientConfig, ClientProtocol};

    const SERVER_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const CLIENT_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";

    #[test]
    fn legacy_is_the_backward_compatible_default() {
        let config: ClientConfig = toml::from_str(&format!(
            "server = '127.0.0.1:51820'\nserver_public_key = '{SERVER_KEY}'\nclient_private_key = '{CLIENT_KEY}'\n"
        ))
        .expect("config");
        assert_eq!(config.protocol, ClientProtocol::Legacy);
    }

    #[test]
    fn all_morph_profiles_are_selectable() {
        for (value, expected) in [
            ("morph_quiet", ClientProtocol::MorphQuiet),
            ("morph_balanced", ClientProtocol::MorphBalanced),
            ("morph_paranoid", ClientProtocol::MorphParanoid),
        ] {
            let config: ClientConfig = toml::from_str(&format!(
                "server = '127.0.0.1:51820'\nserver_public_key = '{SERVER_KEY}'\nclient_private_key = '{CLIENT_KEY}'\nprotocol = '{value}'\n"
            ))
            .expect("config");
            assert_eq!(config.protocol, expected);
            assert!(config.protocol.morph_profile().is_some());
        }
    }
}
