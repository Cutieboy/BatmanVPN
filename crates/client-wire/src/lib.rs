#![doc = "Shared client-side Legacy, `MouseMorph` and Speedy wire adapter."]

use std::{error::Error, fmt};

use mousevpn_config::ValidatedClientConfig;
use mousevpn_crypto::{derive_morph_key, derive_speedy_key, CryptoError};
use mousevpn_morph::{DecodedFrame, Direction, MorphCodec, MorphError, MorphKey, Profile};
use mousevpn_speedy::{Direction as SpeedyDirection, SpeedyCodec, SpeedyError, SpeedyKey};

pub const MAX_WIRE_DATAGRAM_LEN: usize = mousevpn_morph::MAX_DATAGRAM_LEN;

#[derive(Clone, Debug)]
pub enum ClientWire {
    Legacy,
    Morph(MorphCodec),
    Speedy(SpeedyCodec),
}

impl ClientWire {
    /// Builds the selected wire representation from already validated keys.
    ///
    /// # Errors
    ///
    /// Returns an error when the static X25519 shared secret is invalid.
    pub fn from_config(config: &ValidatedClientConfig) -> Result<Self, ClientWireError> {
        if config.protocol == mousevpn_config::ClientProtocol::Speedy {
            let key = derive_speedy_key(
                &config.client_private_key,
                &config.server_public_key,
                &config.server_public_key,
                &config.client_private_key.public_key(),
            )?;
            return Ok(Self::Speedy(SpeedyCodec::new(SpeedyKey::from_bytes(key))));
        }
        let Some(profile) = config.protocol.morph_profile() else {
            return Ok(Self::Legacy);
        };
        let client_public_key = config.client_private_key.public_key();
        let key = derive_morph_key(
            &config.client_private_key,
            &config.server_public_key,
            &config.server_public_key,
            &client_public_key,
        )?;
        Ok(Self::Morph(MorphCodec::new(
            MorphKey::from_bytes(key),
            profile,
        )))
    }

    #[must_use]
    pub const fn profile(&self) -> Option<Profile> {
        match self {
            Self::Legacy | Self::Speedy(_) => None,
            Self::Morph(codec) => Some(codec.profile()),
        }
    }

    /// Chooses how many authenticated cover frames precede a handshake.
    ///
    /// # Errors
    ///
    /// Returns an error when the operating-system random generator fails.
    pub fn cover_count(&self) -> Result<usize, ClientWireError> {
        match self {
            Self::Legacy | Self::Speedy(_) => Ok(0),
            Self::Morph(codec) => Ok(codec.profile().cover_count()?),
        }
    }

    /// Chooses the delay after a cover frame in milliseconds.
    ///
    /// # Errors
    ///
    /// Returns an error when the operating-system random generator fails.
    pub fn handshake_jitter_ms(&self) -> Result<u64, ClientWireError> {
        match self {
            Self::Legacy | Self::Speedy(_) => Ok(0),
            Self::Morph(codec) => Ok(codec.profile().handshake_jitter_ms()?),
        }
    }

    /// Encodes one complete legacy datagram for transport to the server.
    ///
    /// # Errors
    ///
    /// Returns an error when the selected masking format cannot encode the frame.
    pub fn encode(&self, inner: &[u8], output: &mut Vec<u8>) -> Result<(), ClientWireError> {
        match self {
            Self::Speedy(codec) => {
                codec.encode(inner, SpeedyDirection::ClientToServer, output)?;
                Ok(())
            }
            Self::Legacy => {
                output.clear();
                output.extend_from_slice(inner);
                Ok(())
            }
            Self::Morph(codec) => {
                codec.encode_payload(inner, Direction::ClientToServer, output)?;
                Ok(())
            }
        }
    }

    /// Decodes one server datagram, returning false for authenticated cover traffic.
    ///
    /// # Errors
    ///
    /// Returns an error when a masked frame is malformed or unauthenticated.
    pub fn decode(&self, outer: &[u8], output: &mut Vec<u8>) -> Result<bool, ClientWireError> {
        match self {
            Self::Speedy(codec) => {
                codec.decode(outer, SpeedyDirection::ServerToClient, output)?;
                Ok(true)
            }
            Self::Legacy => {
                output.clear();
                output.extend_from_slice(outer);
                Ok(true)
            }
            Self::Morph(codec) => Ok(matches!(
                codec.decode(outer, Direction::ServerToClient, output)?,
                DecodedFrame::Payload { .. }
            )),
        }
    }

    /// Produces one authenticated client-to-server cover frame.
    ///
    /// # Errors
    ///
    /// Returns an error when `MouseMorph` cannot encode the frame.
    pub fn encode_cover(&self, output: &mut Vec<u8>) -> Result<(), ClientWireError> {
        match self {
            Self::Legacy | Self::Speedy(_) => {
                output.clear();
                Ok(())
            }
            Self::Morph(codec) => {
                codec.encode_cover(Direction::ClientToServer, output)?;
                Ok(())
            }
        }
    }
}

#[derive(Debug)]
pub enum ClientWireError {
    Crypto(CryptoError),
    Morph(MorphError),
    Speedy(SpeedyError),
}

impl fmt::Display for ClientWireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Crypto(error) => write!(formatter, "wire key derivation failed: {error}"),
            Self::Morph(error) => write!(formatter, "MouseMorph frame failed: {error}"),
            Self::Speedy(error) => write!(formatter, "Speedy frame failed: {error}"),
        }
    }
}

impl Error for ClientWireError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Crypto(error) => Some(error),
            Self::Morph(error) => Some(error),
            Self::Speedy(error) => Some(error),
        }
    }
}

impl From<CryptoError> for ClientWireError {
    fn from(error: CryptoError) -> Self {
        Self::Crypto(error)
    }
}

impl From<MorphError> for ClientWireError {
    fn from(error: MorphError) -> Self {
        Self::Morph(error)
    }
}

impl From<SpeedyError> for ClientWireError {
    fn from(error: SpeedyError) -> Self {
        Self::Speedy(error)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use mousevpn_config::{ClientProtocol, ValidatedClientConfig};
    use mousevpn_crypto::{derive_morph_key, KeyPair, ProtocolContext};
    use mousevpn_morph::{DecodedFrame, Direction, MorphCodec, MorphKey, Profile};

    use super::ClientWire;

    #[test]
    fn legacy_keeps_datagrams_unchanged() {
        let wire = ClientWire::Legacy;
        let payload = b"legacy MouseVPN datagram";
        let mut encoded = Vec::new();
        let mut decoded = Vec::new();

        wire.encode(payload, &mut encoded).expect("encode");
        assert_eq!(encoded, payload);
        assert!(wire.decode(&encoded, &mut decoded).expect("decode"));
        assert_eq!(decoded, payload);
    }

    #[test]
    fn all_profiles_interoperate_with_the_server_codec() {
        for (protocol, profile) in [
            (ClientProtocol::MorphQuiet, Profile::Quiet),
            (ClientProtocol::MorphBalanced, Profile::Balanced),
            (ClientProtocol::MorphParanoid, Profile::Paranoid),
        ] {
            let server = KeyPair::generate().expect("server keypair");
            let client = KeyPair::generate().expect("client keypair");
            let server_codec = MorphCodec::new(
                MorphKey::from_bytes(
                    derive_morph_key(
                        &server.secret,
                        &client.public,
                        &server.public,
                        &client.public,
                    )
                    .expect("server key derivation"),
                ),
                profile,
            );
            let config = ValidatedClientConfig {
                server: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 51820),
                server_public_key: server.public,
                client_private_key: client.secret,
                context: ProtocolContext::for_server(&server.public),
                tun_name: "mousevpn-test".to_owned(),
                protocol,
            };
            let client_wire = ClientWire::from_config(&config).expect("client wire");

            let mut client_frame = Vec::new();
            let mut server_inner = Vec::new();
            client_wire
                .encode(b"handshake init", &mut client_frame)
                .expect("client encode");
            assert_eq!(
                server_codec
                    .decode(&client_frame, Direction::ClientToServer, &mut server_inner,)
                    .expect("server decode"),
                DecodedFrame::Payload { profile },
            );
            assert_eq!(server_inner, b"handshake init");

            let mut server_frame = Vec::new();
            let mut client_inner = Vec::new();
            server_codec
                .encode_payload(
                    b"handshake response",
                    Direction::ServerToClient,
                    &mut server_frame,
                )
                .expect("server encode");
            assert!(client_wire
                .decode(&server_frame, &mut client_inner)
                .expect("client decode"));
            assert_eq!(client_inner, b"handshake response");

            server_codec
                .encode_cover(Direction::ServerToClient, &mut server_frame)
                .expect("server cover");
            assert!(!client_wire
                .decode(&server_frame, &mut client_inner)
                .expect("client cover decode"));
        }
    }
}
