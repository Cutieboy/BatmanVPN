#![doc = "Encrypted portable `MouseVPN` profiles shared by CLI and admin UI."]

use std::{error::Error, fmt};

use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit, Nonce,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use pbkdf2::pbkdf2_hmac;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;
use zeroize::Zeroizing;

const ITERATIONS: u32 = 210_000;
const AAD: &[u8] = b"MouseVPN profile v1";

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PortableProfile {
    version: u8,
    id: String,
    name: String,
    endpoint: String,
    server_public_key: String,
    client_private_key: String,
}

impl PortableProfile {
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        endpoint: impl Into<String>,
        server_public_key: impl Into<String>,
        client_private_key: impl Into<String>,
    ) -> Self {
        Self {
            version: 1,
            id: Uuid::new_v4().to_string(),
            name: name.into(),
            endpoint: endpoint.into(),
            server_public_key: server_public_key.into(),
            client_private_key: client_private_key.into(),
        }
    }

    #[must_use]
    pub fn into_parts(self) -> (String, String, String, String, String) {
        (
            self.id,
            self.name,
            self.endpoint,
            self.server_public_key,
            self.client_private_key,
        )
    }
}

/// Encrypts a portable profile using the format understood by the Android app.
///
/// # Errors
///
/// Returns an error when randomness, serialization, or authenticated encryption fails.
pub fn encrypt_profile(profile: &PortableProfile, password: &[u8]) -> Result<String, ProfileError> {
    if password.len() < 8 {
        return Err(ProfileError::PasswordTooShort);
    }
    let mut salt = [0_u8; 16];
    let mut nonce = [0_u8; 12];
    getrandom::fill(&mut salt).map_err(|error| ProfileError::Random(error.to_string()))?;
    getrandom::fill(&mut nonce).map_err(|error| ProfileError::Random(error.to_string()))?;
    let mut key = Zeroizing::new([0_u8; 32]);
    pbkdf2_hmac::<Sha256>(password, &salt, ITERATIONS, key.as_mut());
    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| ProfileError::CipherInit)?;
    let plaintext = Zeroizing::new(serde_json::to_vec(profile)?);
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext.as_ref(),
                aad: AAD,
            },
        )
        .map_err(|_| ProfileError::Encryption)?;
    let mut packed = Vec::with_capacity(salt.len() + nonce.len() + ciphertext.len());
    packed.extend_from_slice(&salt);
    packed.extend_from_slice(&nonce);
    packed.extend_from_slice(&ciphertext);
    Ok(format!("MV1.{}", URL_SAFE_NO_PAD.encode(packed)))
}

/// Decrypts an `MV1.…` portable profile produced by the server or profile CLI.
///
/// # Errors
///
/// Returns an error for a short password, malformed token, authentication
/// failure, invalid JSON or an unsupported profile version.
pub fn decrypt_profile(encoded: &str, password: &[u8]) -> Result<PortableProfile, ProfileError> {
    if password.len() < 8 {
        return Err(ProfileError::PasswordTooShort);
    }
    let payload = encoded
        .trim()
        .strip_prefix("MV1.")
        .ok_or(ProfileError::InvalidFormat)?;
    let packed = URL_SAFE_NO_PAD.decode(payload)?;
    if packed.len() <= 16 + 12 + 16 {
        return Err(ProfileError::InvalidFormat);
    }
    let (salt, rest) = packed.split_at(16);
    let (nonce, ciphertext) = rest.split_at(12);
    let mut key = Zeroizing::new([0_u8; 32]);
    pbkdf2_hmac::<Sha256>(password, salt, ITERATIONS, key.as_mut());
    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| ProfileError::CipherInit)?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad: AAD,
                },
            )
            .map_err(|_| ProfileError::Decryption)?,
    );
    let profile: PortableProfile = serde_json::from_slice(plaintext.as_ref())?;
    if profile.version != 1 {
        return Err(ProfileError::UnsupportedVersion(profile.version));
    }
    Ok(profile)
}

#[derive(Debug)]
pub enum ProfileError {
    PasswordTooShort,
    Random(String),
    Serialization(serde_json::Error),
    CipherInit,
    Encryption,
    Decryption,
    InvalidFormat,
    UnsupportedVersion(u8),
    Base64(base64::DecodeError),
}

impl fmt::Display for ProfileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PasswordTooShort => {
                formatter.write_str("profile password must be at least 8 bytes")
            }
            Self::Random(error) => write!(formatter, "profile randomness failed: {error}"),
            Self::Serialization(error) => {
                write!(formatter, "profile serialization failed: {error}")
            }
            Self::CipherInit => formatter.write_str("profile cipher initialization failed"),
            Self::Encryption => formatter.write_str("profile encryption failed"),
            Self::Decryption => {
                formatter.write_str("profile password is wrong or token is damaged")
            }
            Self::InvalidFormat => formatter.write_str("invalid MouseVPN profile token"),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported MouseVPN profile version {version}")
            }
            Self::Base64(error) => write!(formatter, "invalid profile encoding: {error}"),
        }
    }
}

impl Error for ProfileError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Serialization(error) => Some(error),
            Self::Base64(error) => Some(error),
            _ => None,
        }
    }
}

impl From<base64::DecodeError> for ProfileError {
    fn from(error: base64::DecodeError) -> Self {
        Self::Base64(error)
    }
}

impl From<serde_json::Error> for ProfileError {
    fn from(error: serde_json::Error) -> Self {
        Self::Serialization(error)
    }
}

#[cfg(test)]
mod tests {
    use super::{decrypt_profile, encrypt_profile, PortableProfile};

    #[test]
    fn encrypted_profile_round_trips() {
        let profile =
            PortableProfile::new("Home", "198.51.100.7:51820", "server-key", "client-key");
        let token = encrypt_profile(&profile, b"long password").expect("encrypt profile");
        let decoded = decrypt_profile(&token, b"long password").expect("decrypt profile");
        let (_, name, endpoint, server_key, client_key) = decoded.into_parts();
        assert_eq!(name, "Home");
        assert_eq!(endpoint, "198.51.100.7:51820");
        assert_eq!(server_key, "server-key");
        assert_eq!(client_key, "client-key");
    }

    #[test]
    fn wrong_password_is_rejected() {
        let profile = PortableProfile::new("Home", "198.51.100.7:51820", "a", "b");
        let token = encrypt_profile(&profile, b"long password").expect("encrypt profile");
        assert!(decrypt_profile(&token, b"other password").is_err());
    }
}
