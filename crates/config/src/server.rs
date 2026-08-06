use std::{
    collections::HashSet,
    net::{Ipv4Addr, SocketAddr},
};

use mousevpn_crypto::{ProtocolContext, PublicKey, SecretKey};
use serde::Deserialize;

use crate::{decode_public_key, decode_secret_key, ConfigError};

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    pub listen: SocketAddr,
    pub server_public_key: String,
    pub server_private_key: String,
    pub tun: ServerTunConfig,
    pub clients: Vec<AuthorizedClientConfig>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct ServerTunConfig {
    #[serde(default = "default_tun_name")]
    pub name: String,
    pub address: Ipv4Addr,
    pub prefix_len: u8,
    pub mtu: u16,
    pub dns: Ipv4Addr,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct AuthorizedClientConfig {
    pub name: String,
    pub public_key: String,
    pub address: Ipv4Addr,
}

pub struct ValidatedAuthorizedClient {
    pub name: String,
    pub public_key: PublicKey,
    pub address: Ipv4Addr,
}

pub struct ValidatedServerConfig {
    pub listen: SocketAddr,
    pub server_public_key: PublicKey,
    pub server_private_key: SecretKey,
    pub context: ProtocolContext,
    pub tun: ServerTunConfig,
    pub clients: Vec<ValidatedAuthorizedClient>,
}

impl ServerConfig {
    /// Validates network settings, uniqueness and cryptographic material.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid settings, duplicate clients or keys.
    pub fn validate(self) -> Result<ValidatedServerConfig, ConfigError> {
        if self.clients.is_empty() {
            return Err(ConfigError::EmptyClients);
        }
        if self.tun.prefix_len > 32 {
            return Err(ConfigError::InvalidPrefix(self.tun.prefix_len));
        }
        if !(576..=9_000).contains(&self.tun.mtu) {
            return Err(ConfigError::InvalidMtu(self.tun.mtu));
        }

        let server_public_key = decode_public_key(&self.server_public_key)?;
        let server_private_key = decode_secret_key(&self.server_private_key)?;
        if server_private_key.public_key() != server_public_key {
            return Err(ConfigError::ServerKeyPairMismatch);
        }
        let mut addresses = HashSet::new();
        let mut keys = HashSet::new();
        let mut clients = Vec::with_capacity(self.clients.len());
        for client in self.clients {
            if client.address == self.tun.address {
                return Err(ConfigError::ClientAddressMatchesServer);
            }
            if !same_subnet(client.address, self.tun.address, self.tun.prefix_len) {
                return Err(ConfigError::ClientOutsideTunnelSubnet);
            }
            if !addresses.insert(client.address) {
                return Err(ConfigError::DuplicateClientAddress);
            }
            let public_key = decode_public_key(&client.public_key)?;
            if !keys.insert(public_key) {
                return Err(ConfigError::DuplicateClientKey);
            }
            clients.push(ValidatedAuthorizedClient {
                name: client.name,
                public_key,
                address: client.address,
            });
        }

        Ok(ValidatedServerConfig {
            listen: self.listen,
            server_private_key,
            context: ProtocolContext::for_server(&server_public_key),
            server_public_key,
            tun: self.tun,
            clients,
        })
    }
}

fn default_tun_name() -> String {
    "mousevpn0".to_owned()
}

fn same_subnet(left: Ipv4Addr, right: Ipv4Addr, prefix_len: u8) -> bool {
    let mask = if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix_len))
    };
    u32::from(left) & mask == u32::from(right) & mask
}
