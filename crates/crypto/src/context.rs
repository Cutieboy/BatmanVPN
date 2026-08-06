use sha2::{Digest, Sha256};

use crate::PublicKey;

const CONTEXT_LABEL: &[u8] = b"MouseVPN deployment context v1\0";
const CONTEXT_LEN: usize = 32;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProtocolContext([u8; CONTEXT_LEN]);

impl ProtocolContext {
    /// Derives a deployment-specific Noise context from the pinned server key.
    #[must_use]
    pub fn for_server(server_public_key: &PublicKey) -> Self {
        let mut digest = Sha256::new();
        digest.update(CONTEXT_LABEL);
        digest.update(server_public_key.as_bytes());
        Self(digest.finalize().into())
    }

    #[must_use]
    pub const fn from_bytes(bytes: [u8; CONTEXT_LEN]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; CONTEXT_LEN] {
        &self.0
    }
}
