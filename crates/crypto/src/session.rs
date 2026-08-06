use snow::StatelessTransportState;

use crate::{replay::ReplayWindow, CryptoError, PublicKey, MAX_NOISE_MESSAGE_LEN};

const AUTH_TAG_LEN: usize = 16;
const MAX_PLAINTEXT_LEN: usize = MAX_NOISE_MESSAGE_LEN - AUTH_TAG_LEN;

pub struct SecureSession {
    transport: StatelessTransportState,
    receive_window: ReplayWindow,
    peer_static_key: PublicKey,
}

impl SecureSession {
    pub(crate) fn new(transport: StatelessTransportState, peer_static_key: PublicKey) -> Self {
        Self {
            transport,
            receive_window: ReplayWindow::default(),
            peer_static_key,
        }
    }

    #[must_use]
    pub const fn peer_static_key(&self) -> PublicKey {
        self.peer_static_key
    }

    /// Encrypts one datagram using `sequence` as the Noise nonce.
    ///
    /// The caller must never reuse a sequence number in this key direction.
    ///
    /// # Errors
    ///
    /// Returns an error when the plaintext exceeds the Noise message limit.
    pub fn encrypt(&self, sequence: u64, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if plaintext.len() > MAX_PLAINTEXT_LEN {
            return Err(CryptoError::MessageTooLarge {
                actual: plaintext.len(),
                maximum: MAX_PLAINTEXT_LEN,
            });
        }
        let mut ciphertext = vec![0_u8; plaintext.len() + AUTH_TAG_LEN];
        let length = self
            .transport
            .write_message(sequence, plaintext, &mut ciphertext)?;
        ciphertext.truncate(length);
        Ok(ciphertext)
    }

    /// Authenticates and decrypts one datagram.
    ///
    /// Sequence numbers are committed to the replay window only after successful
    /// authentication.
    ///
    /// # Errors
    ///
    /// Returns an error for duplicate, stale, oversized or unauthentic packets.
    pub fn decrypt(&mut self, sequence: u64, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if ciphertext.len() > MAX_NOISE_MESSAGE_LEN {
            return Err(CryptoError::MessageTooLarge {
                actual: ciphertext.len(),
                maximum: MAX_NOISE_MESSAGE_LEN,
            });
        }
        self.receive_window.ensure_acceptable(sequence)?;

        let mut plaintext = vec![0_u8; ciphertext.len()];
        let length = self
            .transport
            .read_message(sequence, ciphertext, &mut plaintext)?;
        plaintext.truncate(length);
        self.receive_window.mark_authenticated(sequence);
        Ok(plaintext)
    }
}
