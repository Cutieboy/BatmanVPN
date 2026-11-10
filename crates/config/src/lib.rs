#![doc = "Validated TOML configuration for `MouseVPN` binaries."]

mod client;
mod error;
mod keys;
mod load;
mod server;

pub use client::{ClientConfig, ClientProtocol, MousalityClientConfig, ValidatedClientConfig};
pub use error::ConfigError;
pub use keys::{decode_public_key, decode_secret_key, encode_public_key, encode_secret_key};
pub use load::load_toml;
pub use server::{
    AuthorizedClientConfig, ServerConfig, ServerTunConfig, ValidatedAuthorizedClient,
    ValidatedServerConfig, DEFAULT_TUN_MTU, MAX_SAFE_TUN_MTU,
};

/// Returns whether the name is a valid ASCII hostname for camouflage TLS.
#[must_use]
pub fn valid_server_name(name: &str) -> bool {
    name.len() <= 253
        && name.contains('.')
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}
