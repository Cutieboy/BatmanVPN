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
    #[serde(default)]
    pub mousality: Option<MousalityClientConfig>,
    /// Sends traffic for Russian networks over the physical link instead of
    /// the tunnel. Off unless a profile or client asks for it, so existing
    /// profiles keep routing everything through the VPN.
    #[serde(default)]
    pub bypass_russia: bool,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientProtocol {
    #[default]
    Legacy,
    MorphQuiet,
    MorphBalanced,
    MorphParanoid,
    Speedy,
    Mousality,
}

impl ClientProtocol {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Legacy => "legacy",
            Self::Speedy => "speedy",
            Self::Mousality => "mousality",
            Self::MorphQuiet => "morph_quiet",
            Self::MorphBalanced => "morph_balanced",
            Self::MorphParanoid => "morph_paranoid",
        }
    }

    #[must_use]
    pub const fn morph_profile(self) -> Option<Profile> {
        match self {
            Self::Legacy | Self::Speedy | Self::Mousality => None,
            Self::MorphQuiet => Some(Profile::Quiet),
            Self::MorphBalanced => Some(Profile::Balanced),
            Self::MorphParanoid => Some(Profile::Paranoid),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MousalityClientConfig {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub server_name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub server_names: Vec<String>,
    /// Separate TCP endpoint; defaults to the profile endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<SocketAddr>,
}

impl MousalityClientConfig {
    /// Returns all allowed SNI names, including legacy single-site profiles.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        (!self.server_name.is_empty())
            .then_some(self.server_name.as_str())
            .into_iter()
            .chain(self.server_names.iter().map(String::as_str))
    }
}

pub struct ValidatedClientConfig {
    pub server: SocketAddr,
    pub server_public_key: PublicKey,
    pub client_private_key: SecretKey,
    pub context: ProtocolContext,
    pub tun_name: String,
    pub protocol: ClientProtocol,
    pub mousality: Option<MousalityClientConfig>,
    pub bypass_russia: bool,
}

impl ClientConfig {
    /// Decodes cryptographic material and derives the deployment context.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid key encoding or length.
    pub fn validate(self) -> Result<ValidatedClientConfig, ConfigError> {
        if self.protocol == ClientProtocol::Mousality {
            let settings = self
                .mousality
                .as_ref()
                .ok_or(ConfigError::InvalidMousality)?;
            let names: Vec<_> = settings.names().collect();
            if names.is_empty()
                || names.len() > 16
                || !names.iter().all(|name| crate::valid_server_name(name))
                || settings
                    .endpoint
                    .is_some_and(|endpoint| endpoint.port() == 0)
            {
                return Err(ConfigError::InvalidMousality);
            }
        }
        let server_public_key = decode_public_key(&self.server_public_key)?;
        Ok(ValidatedClientConfig {
            server: if self.protocol == ClientProtocol::Mousality {
                self.mousality
                    .as_ref()
                    .and_then(|m| m.endpoint)
                    .unwrap_or(self.server)
            } else {
                self.server
            },
            client_private_key: decode_secret_key(&self.client_private_key)?,
            context: match self.protocol {
                ClientProtocol::Speedy => ProtocolContext::for_speedy_server(&server_public_key),
                _ => ProtocolContext::for_server(&server_public_key),
            },
            server_public_key,
            tun_name: self.tun_name,
            protocol: self.protocol,
            mousality: self.mousality,
            bypass_russia: self.bypass_russia,
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
        assert!(!config.bypass_russia);
    }

    #[test]
    fn russian_bypass_is_opt_in() {
        let config: ClientConfig = toml::from_str(&format!(
            "server = '127.0.0.1:51820'\nserver_public_key = '{SERVER_KEY}'\nclient_private_key = '{CLIENT_KEY}'\nbypass_russia = true\n"
        ))
        .expect("config");
        assert!(config.validate().unwrap().bypass_russia);
    }

    #[test]
    fn speedy_is_explicit_and_has_its_own_noise_context() {
        let config: ClientConfig = toml::from_str(&format!(
            "server = '127.0.0.1:51820'\nserver_public_key = '{SERVER_KEY}'\nclient_private_key = '{CLIENT_KEY}'\nprotocol = 'speedy'\n"
        )).unwrap();
        let validated = config.validate().unwrap();
        assert_eq!(validated.protocol, ClientProtocol::Speedy);
        assert_eq!(
            validated.context,
            mousevpn_crypto::ProtocolContext::for_speedy_server(&validated.server_public_key)
        );
        assert_ne!(
            validated.context,
            mousevpn_crypto::ProtocolContext::for_server(&validated.server_public_key)
        );
        assert_eq!(
            toml::Value::try_from(ClientProtocol::Speedy)
                .unwrap()
                .as_str(),
            Some("speedy")
        );
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

#[cfg(test)]
mod mousality_tests {
    use super::*;

    fn config(settings: &str) -> ClientConfig {
        toml::from_str(&format!(
            "server = '127.0.0.1:51821'\nserver_public_key = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'\nclient_private_key = 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE'\nprotocol = 'mousality'\n{settings}"
        )).unwrap()
    }

    #[test]
    fn mousality_requires_sni_and_selects_the_tcp_endpoint() {
        assert!(config("").validate().is_err());
        for name in [
            "",
            "bad/name",
            "-bad.example",
            "bad..example",
            "example.com\n",
        ] {
            let mut config = config("[mousality]\nserver_name = 'www.example.com'");
            config.mousality.as_mut().unwrap().server_name = name.into();
            assert!(config.validate().is_err(), "accepted {name:?}");
        }
        let validated =
            config("[mousality]\nserver_name = 'www.example.com'\nendpoint = '127.0.0.2:443'")
                .validate()
                .unwrap();
        assert_eq!(validated.server, "127.0.0.2:443".parse().unwrap());
        assert_eq!(
            validated.context,
            ProtocolContext::for_server(&validated.server_public_key)
        );
        assert_eq!(
            toml::Value::try_from(ClientProtocol::Mousality)
                .unwrap()
                .as_str(),
            Some("mousality")
        );
        let mut legacy =
            config("[mousality]\nserver_name = 'www.example.com'\nendpoint = '127.0.0.2:443'");
        legacy.protocol = ClientProtocol::Legacy;
        assert_eq!(legacy.validate().unwrap().server.port(), 51821);
    }
    #[test]
    fn automatic_pool_needs_no_manually_entered_name() {
        let validated = config("[mousality]\nserver_names = ['www.bing.com', 'www.apple.com']\nendpoint = '127.0.0.1:443'").validate().unwrap();
        assert_eq!(
            validated.mousality.unwrap().names().collect::<Vec<_>>(),
            vec!["www.bing.com", "www.apple.com"]
        );
        assert!(config("[mousality]\nserver_names = []").validate().is_err());
        assert!(config("[mousality]\nserver_names = ['bad/name']")
            .validate()
            .is_err());
    }
}
