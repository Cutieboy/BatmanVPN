use snow::{params::NoiseParams, Builder, HandshakeState};

use crate::{
    CryptoError, ProtocolContext, PublicKey, SecretKey, SecureSession, MAX_NOISE_MESSAGE_LEN,
    NOISE_PATTERN,
};

pub(crate) fn noise_params() -> Result<NoiseParams, CryptoError> {
    Ok(NOISE_PATTERN.parse()?)
}

pub struct ClientHandshake {
    state: HandshakeState,
}

impl ClientHandshake {
    /// Creates an IK initiator pinned to `server_public_key`.
    ///
    /// # Errors
    ///
    /// Returns an error when keys or Noise parameters are invalid.
    pub fn new(
        client_secret_key: &SecretKey,
        server_public_key: &PublicKey,
        context: &ProtocolContext,
    ) -> Result<Self, CryptoError> {
        let state = Builder::new(noise_params()?)
            .local_private_key(client_secret_key.as_bytes())?
            .remote_public_key(server_public_key.as_bytes())?
            .prologue(context.as_bytes())?
            .build_initiator()?;
        Ok(Self { state })
    }

    /// Creates the first IK handshake message.
    ///
    /// # Errors
    ///
    /// Returns an error for an oversized payload or invalid state transition.
    pub fn write_initial(&mut self, payload: &[u8]) -> Result<Vec<u8>, CryptoError> {
        write_handshake_message(&mut self.state, payload)
    }

    /// Consumes the server response and enters stateless transport mode.
    ///
    /// # Errors
    ///
    /// Returns an error if authentication fails or the response is malformed.
    pub fn finish(mut self, response: &[u8]) -> Result<(SecureSession, Vec<u8>), CryptoError> {
        let payload = read_handshake_message(&mut self.state, response)?;
        let peer = peer_static_key(&self.state)?;
        let transport = self.state.into_stateless_transport_mode()?;
        Ok((SecureSession::new(transport, peer), payload))
    }
}

pub struct ServerHandshake {
    state: HandshakeState,
}

impl ServerHandshake {
    /// Creates an IK responder using the server static secret key.
    ///
    /// # Errors
    ///
    /// Returns an error when the key or Noise parameters are invalid.
    pub fn new(
        server_secret_key: &SecretKey,
        context: &ProtocolContext,
    ) -> Result<Self, CryptoError> {
        let state = Builder::new(noise_params()?)
            .local_private_key(server_secret_key.as_bytes())?
            .prologue(context.as_bytes())?
            .build_responder()?;
        Ok(Self { state })
    }

    /// Authenticates and decodes the client's initial handshake message.
    ///
    /// # Errors
    ///
    /// Returns an error if authentication fails or the message is malformed.
    pub fn read_initial(&mut self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        read_handshake_message(&mut self.state, message)
    }

    /// Returns the authenticated client static key after `read_initial` succeeds.
    #[must_use]
    pub fn peer_static_key(&self) -> Option<PublicKey> {
        self.state
            .get_remote_static()
            .and_then(|bytes| PublicKey::from_slice(bytes).ok())
    }

    /// Creates the server response and enters stateless transport mode.
    ///
    /// Authorization of `peer_static_key` must happen before calling this method.
    ///
    /// # Errors
    ///
    /// Returns an error for an oversized payload or invalid state transition.
    pub fn finish(mut self, payload: &[u8]) -> Result<(SecureSession, Vec<u8>), CryptoError> {
        let peer = peer_static_key(&self.state)?;
        let response = write_handshake_message(&mut self.state, payload)?;
        let transport = self.state.into_stateless_transport_mode()?;
        Ok((SecureSession::new(transport, peer), response))
    }
}

fn peer_static_key(state: &HandshakeState) -> Result<PublicKey, CryptoError> {
    state
        .get_remote_static()
        .ok_or(CryptoError::MissingPeerStaticKey)
        .and_then(PublicKey::from_slice)
}

fn write_handshake_message(
    state: &mut HandshakeState,
    payload: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let mut message = vec![0_u8; MAX_NOISE_MESSAGE_LEN];
    let length = state.write_message(payload, &mut message)?;
    message.truncate(length);
    Ok(message)
}

fn read_handshake_message(
    state: &mut HandshakeState,
    message: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if message.len() > MAX_NOISE_MESSAGE_LEN {
        return Err(CryptoError::MessageTooLarge {
            actual: message.len(),
            maximum: MAX_NOISE_MESSAGE_LEN,
        });
    }
    let mut payload = vec![0_u8; message.len()];
    let length = state.read_message(message, &mut payload)?;
    payload.truncate(length);
    Ok(payload)
}
