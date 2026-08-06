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
    #[serde(default)]
    pub public_endpoint: Option<SocketAddr>,
    pub server_public_key: String,
    pub server_private_key: String,
    pub tun: ServerTunConfig,
    pub clients: Vec<AuthorizedClientConfig>,
}

/// Tunnel MTU that still fits a 1500-byte path.
///
/// Every tunnelled packet costs 20 bytes of outer IP, 8 of UDP, 20 of protocol
/// header, 1 of inner framing and 16 of authentication tag: 65 in total. A
/// tunnel MTU above [`MAX_SAFE_TUN_MTU`] therefore produces outer datagrams
/// that a 1500-byte path has to fragment, which costs throughput and breaks
/// outright wherever fragments are filtered. The margin below the maximum
/// leaves room for `PPPoE` and similar encapsulation.
pub const DEFAULT_TUN_MTU: u16 = 1_420;

/// Largest tunnel MTU that never fragments on a 1500-byte path.
pub const MAX_SAFE_TUN_MTU: u16 = 1_435;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct ServerTunConfig {
    #[serde(default = "default_tun_name")]
    pub name: String,
    pub address: Ipv4Addr,
    pub prefix_len: u8,
    #[serde(default = "default_tun_mtu")]
    pub mtu: u16,
    pub dns: Ipv4Addr,
}

const fn default_tun_mtu() -> u16 {
    DEFAULT_TUN_MTU
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
    pub public_endpoint: Option<SocketAddr>,
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
            public_endpoint: self.public_endpoint,
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
