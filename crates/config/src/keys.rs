use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use mousevpn_crypto::{PublicKey, SecretKey, KEY_LEN};
use zeroize::Zeroize;

use crate::ConfigError;

/// Decodes a URL-safe Base64 X25519 public key.
///
/// # Errors
///
/// Returns an error for invalid Base64 or a non-32-byte value.
pub fn decode_public_key(encoded: &str) -> Result<PublicKey, ConfigError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| ConfigError::InvalidKeyEncoding)?;
    let actual = bytes.len();
    let fixed: [u8; KEY_LEN] = bytes
        .try_into()
        .map_err(|_| ConfigError::InvalidKeyLength(actual))?;
    Ok(PublicKey::from_bytes(fixed))
}

/// Decodes a URL-safe Base64 X25519 secret key.
///
/// # Errors
///
/// Returns an error for invalid Base64 or a non-32-byte value.
pub fn decode_secret_key(encoded: &str) -> Result<SecretKey, ConfigError> {
    let mut bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| ConfigError::InvalidKeyEncoding)?;
    let actual = bytes.len();
    let fixed: [u8; KEY_LEN] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| ConfigError::InvalidKeyLength(actual))?;
    bytes.zeroize();
    Ok(SecretKey::from_bytes(fixed))
}

#[must_use]
pub fn encode_public_key(key: &PublicKey) -> String {
    URL_SAFE_NO_PAD.encode(key.as_bytes())
}

#[must_use]
pub fn encode_secret_key(key: &SecretKey) -> String {
    let mut bytes = key.expose_for_provisioning();
    let encoded = URL_SAFE_NO_PAD.encode(bytes);
    bytes.zeroize();
    encoded
}
