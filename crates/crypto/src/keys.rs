use std::fmt;

use hkdf::Hkdf;
use sha2::Sha256;
use snow::Builder;
use zeroize::Zeroize;

use crate::{handshake::noise_params, CryptoError};

pub const KEY_LEN: usize = 32;
const MORPH_KEY_LABEL: &[u8] = b"MouseVPN MouseMorph v2 key";

pub struct SecretKey(Box<[u8; KEY_LEN]>);

impl SecretKey {
    #[must_use]
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(Box::new(bytes))
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }

    /// Copies the secret for one-time device provisioning.
    ///
    /// Callers must avoid logs and erase the returned representation as soon as
    /// it has been delivered through an authenticated channel.
    #[must_use]
    pub fn expose_for_provisioning(&self) -> [u8; KEY_LEN] {
        *self.0
    }

    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        PublicKey::from_bytes(x25519_dalek::x25519(
            *self.0,
            x25519_dalek::X25519_BASEPOINT_BYTES,
        ))
    }

    fn from_vec(bytes: Vec<u8>) -> Result<Self, CryptoError> {
        let actual = bytes.len();
        let fixed = bytes
            .into_boxed_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyLength { actual })?;
        Ok(Self(fixed))
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretKey([REDACTED])")
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.as_mut().zeroize();
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PublicKey([u8; KEY_LEN]);

impl PublicKey {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    pub(crate) fn from_slice(bytes: &[u8]) -> Result<Self, CryptoError> {
        let value: [u8; KEY_LEN] = bytes
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyLength {
                actual: bytes.len(),
            })?;
        Ok(Self(value))
    }
}

#[derive(Debug)]
pub struct KeyPair {
    pub secret: SecretKey,
    pub public: PublicKey,
}

impl KeyPair {
    /// Generates a new `X25519` static key pair using the resolver's CSPRNG.
    ///
    /// # Errors
    ///
    /// Returns an error when the cryptographic resolver cannot generate a key.
    pub fn generate() -> Result<Self, CryptoError> {
        let generated = Builder::new(noise_params()?).generate_keypair()?;
        Ok(Self {
            secret: SecretKey::from_vec(generated.private)?,
            public: PublicKey::from_slice(&generated.public)?,
        })
    }
}

/// Derives the deployment- and device-specific key for the `MouseMorph` envelope.
///
/// `server_public_key` and `client_public_key` are always supplied in role
/// order so both sides construct identical HKDF info regardless of which side
/// calls this function.
///
/// # Errors
///
/// Returns an error for a low-order peer key or an impossible HKDF expansion
/// failure.
pub fn derive_morph_key(
    local_secret_key: &SecretKey,
    peer_public_key: &PublicKey,
    server_public_key: &PublicKey,
    client_public_key: &PublicKey,
) -> Result<[u8; KEY_LEN], CryptoError> {
    let mut shared = x25519_dalek::x25519(*local_secret_key.0, *peer_public_key.as_bytes());
    if shared == [0_u8; KEY_LEN] {
        return Err(CryptoError::InvalidSharedSecret);
    }
    let hkdf = Hkdf::<Sha256>::new(Some(MORPH_KEY_LABEL), &shared);
    let mut info = [0_u8; KEY_LEN * 2];
    info[..KEY_LEN].copy_from_slice(server_public_key.as_bytes());
    info[KEY_LEN..].copy_from_slice(client_public_key.as_bytes());
    let mut output = [0_u8; KEY_LEN];
    hkdf.expand(&info, &mut output)
        .map_err(|_| CryptoError::InvalidKeyLength { actual: KEY_LEN })?;
    shared.zeroize();
    info.zeroize();
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::{derive_morph_key, KeyPair};

    #[test]
    fn both_roles_derive_the_same_morph_key() {
        let server = KeyPair::generate().expect("server keys");
        let client = KeyPair::generate().expect("client keys");
        let from_client = derive_morph_key(
            &client.secret,
            &server.public,
            &server.public,
            &client.public,
        )
        .expect("client derivation");
        let from_server = derive_morph_key(
            &server.secret,
            &client.public,
            &server.public,
            &client.public,
        )
        .expect("server derivation");
        assert_eq!(from_client, from_server);
    }
}
