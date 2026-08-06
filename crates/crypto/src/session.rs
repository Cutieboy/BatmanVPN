use std::sync::Arc;

use snow::StatelessTransportState;

use crate::{replay::ReplayWindow, CryptoError, PublicKey, MAX_NOISE_MESSAGE_LEN};

pub const AUTH_TAG_LEN: usize = 16;
const MAX_PLAINTEXT_LEN: usize = MAX_NOISE_MESSAGE_LEN - AUTH_TAG_LEN;

pub struct SecureSession {
    transport: Arc<StatelessTransportState>,
    receive_window: ReplayWindow,
    peer_static_key: PublicKey,
}

impl SecureSession {
    pub(crate) fn new(transport: StatelessTransportState, peer_static_key: PublicKey) -> Self {
        Self {
            transport: Arc::new(transport),
            receive_window: ReplayWindow::default(),
            peer_static_key,
        }
    }

    #[must_use]
    pub const fn peer_static_key(&self) -> PublicKey {
        self.peer_static_key
    }

    /// Splits the session into independently owned send and receive halves.
    ///
    /// Noise transport encryption needs no mutable state, so the two halves can
    /// live on different threads without a shared lock. Only the receiving half
    /// mutates, and only its own replay window.
    #[must_use]
    pub fn split(self) -> (SendHalf, ReceiveHalf) {
        let send = SendHalf {
            transport: Arc::clone(&self.transport),
            peer_static_key: self.peer_static_key,
        };
        let receive = ReceiveHalf {
            transport: self.transport,
            receive_window: self.receive_window,
            peer_static_key: self.peer_static_key,
        };
        (send, receive)
    }

    /// Encrypts one datagram using `sequence` as the Noise nonce.
    ///
    /// The caller must never reuse a sequence number in this key direction.
    ///
    /// # Errors
    ///
    /// Returns an error when the plaintext exceeds the Noise message limit.
    pub fn encrypt(&self, sequence: u64, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut ciphertext = vec![0_u8; plaintext.len() + AUTH_TAG_LEN];
        let length = encrypt_into(&self.transport, sequence, plaintext, &mut ciphertext)?;
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
        let mut plaintext = vec![0_u8; ciphertext.len()];
        let length = decrypt_into(
            &self.transport,
            &mut self.receive_window,
            sequence,
            ciphertext,
            &mut plaintext,
        )?;
        plaintext.truncate(length);
        Ok(plaintext)
    }
}

/// Encrypting half of an established session.
///
/// Cloning is deliberately unsupported: every clone would be a second sequence
/// number source for the same directional key.
pub struct SendHalf {
    transport: Arc<StatelessTransportState>,
    peer_static_key: PublicKey,
}

impl SendHalf {
    #[must_use]
    pub const fn peer_static_key(&self) -> PublicKey {
        self.peer_static_key
    }

    /// Encrypts `plaintext` into `output` and returns the ciphertext length.
    ///
    /// # Errors
    ///
    /// Returns an error when the plaintext exceeds the Noise message limit or
    /// `output` cannot hold the ciphertext and its authentication tag.
    pub fn encrypt_into(
        &self,
        sequence: u64,
        plaintext: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        encrypt_into(&self.transport, sequence, plaintext, output)
    }
}

/// Decrypting half of an established session, including its replay window.
pub struct ReceiveHalf {
    transport: Arc<StatelessTransportState>,
    receive_window: ReplayWindow,
    peer_static_key: PublicKey,
}

impl ReceiveHalf {
    #[must_use]
    pub const fn peer_static_key(&self) -> PublicKey {
        self.peer_static_key
    }

    /// Authenticates `ciphertext` into `output` and returns the plaintext length.
    ///
    /// The replay window advances only after successful authentication.
    ///
    /// # Errors
    ///
    /// Returns an error for duplicate, stale, oversized or unauthentic packets.
    pub fn decrypt_into(
        &mut self,
        sequence: u64,
        ciphertext: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        decrypt_into(
            &self.transport,
            &mut self.receive_window,
            sequence,
            ciphertext,
            output,
        )
    }
}

fn encrypt_into(
    transport: &StatelessTransportState,
    sequence: u64,
    plaintext: &[u8],
    output: &mut [u8],
) -> Result<usize, CryptoError> {
    if plaintext.len() > MAX_PLAINTEXT_LEN {
        return Err(CryptoError::MessageTooLarge {
            actual: plaintext.len(),
            maximum: MAX_PLAINTEXT_LEN,
        });
    }
    Ok(transport.write_message(sequence, plaintext, output)?)
}

fn decrypt_into(
    transport: &StatelessTransportState,
    window: &mut ReplayWindow,
    sequence: u64,
    ciphertext: &[u8],
    output: &mut [u8],
) -> Result<usize, CryptoError> {
    if ciphertext.len() > MAX_NOISE_MESSAGE_LEN {
        return Err(CryptoError::MessageTooLarge {
            actual: ciphertext.len(),
            maximum: MAX_NOISE_MESSAGE_LEN,
        });
    }
    window.ensure_acceptable(sequence)?;
    let length = transport.read_message(sequence, ciphertext, output)?;
    window.mark_authenticated(sequence);
    Ok(length)
}
