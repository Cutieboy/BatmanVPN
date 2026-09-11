//! Speedy v1: minimal header masking around authenticated Noise datagrams.
//!
//! The payload is encrypted only by Noise. This layer masks the header with a
//! keyed PRF and authenticates the entire wire frame before revealing that header.
//! It does not conceal lengths/timing or imitate a browser protocol. See SPEEDY.md.

use std::{
    error::Error,
    fmt,
    sync::{Arc, Mutex},
    time::SystemTime,
};

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use mousevpn_protocol::{Datagram, PacketKind, HEADER_LEN};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

pub const ROUTING_TAG_LEN: usize = 8;
const AUTH_TAG_LEN: usize = 16;
const SAMPLE_LEN: usize = 16;
pub const OVERHEAD: usize = ROUTING_TAG_LEN + AUTH_TAG_LEN;
/// Fits a 1500-byte outer path including IPv6 (40) and UDP (8).
pub const MAX_DATAGRAM_LEN: usize = 1_452;
pub const MAX_INNER_DATAGRAM_LEN: usize = MAX_DATAGRAM_LEN - OVERHEAD;
/// Outer Speedy (24), tunnel header (20), inner kind (1), Noise tag (16).
pub const SAFE_TUN_MTU: u16 = 1_391;
pub const EPOCH_SECONDS: u64 = 10;
const MIN_FRAME_LEN: usize = OVERHEAD + HEADER_LEN + SAMPLE_LEN;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Direction {
    ClientToServer = 0,
    ServerToClient = 1,
}

pub struct SpeedyKey([u8; 32]);

impl SpeedyKey {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl Drop for SpeedyKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

struct DirectionKeys {
    route: SpeedyKey,
    mask: SpeedyKey,
    auth: SpeedyKey,
}

struct Secrets {
    directions: [DirectionKeys; 2],
}

struct RouteCache {
    epoch: u64,
    // current, previous, next; both directions share one clock read/cache.
    tags: [[[u8; ROUTING_TAG_LEN]; 3]; 2],
}

#[derive(Clone)]
pub struct SpeedyCodec {
    secrets: Arc<Secrets>,
    routes: Arc<Mutex<Option<RouteCache>>>,
}

impl fmt::Debug for SpeedyCodec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SpeedyCodec([REDACTED])")
    }
}

impl SpeedyCodec {
    /// Builds the direction-specific masking, authentication and routing keys.
    ///
    /// # Panics
    /// Panics only if HKDF rejects a fixed 32-byte PRK or output length.
    #[must_use]
    pub fn new(key: SpeedyKey) -> Self {
        let hkdf = Hkdf::<Sha256>::from_prk(&key.0).expect("32-byte HKDF PRK");
        let directions = [Direction::ClientToServer, Direction::ServerToClient].map(|direction| {
            let derive = |purpose: u8| {
                let mut output = [0; 32];
                hkdf.expand(&[b'S', b'P', 1, direction as u8, purpose], &mut output)
                    .expect("32-byte HKDF output");
                SpeedyKey(output)
            };
            DirectionKeys {
                route: derive(0),
                mask: derive(1),
                auth: derive(2),
            }
        });
        // The master is no longer needed after deriving the six subkeys.
        drop(key);
        Self {
            secrets: Arc::new(Secrets { directions }),
            routes: Arc::new(Mutex::new(None)),
        }
    }

    /// Computes the server's device lookup tag without processing a packet.
    ///
    /// # Panics
    /// Panics only if a fixed-length digest slice cannot become an eight-byte tag.
    #[must_use]
    pub fn routing_tag_at(&self, direction: Direction, epoch: u64) -> [u8; ROUTING_TAG_LEN] {
        let mut mac = hmac(&self.keys(direction).route);
        mac.update(b"Speedy v1 route\0");
        mac.update(&epoch.to_be_bytes());
        mac.finalize().into_bytes()[..ROUTING_TAG_LEN]
            .try_into()
            .expect("fixed tag length")
    }

    /// Masks a complete Noise datagram. Reuses `output` without packet allocations.
    ///
    /// # Errors
    /// Returns an error for malformed/oversized datagrams or an unavailable clock.
    pub fn encode(
        &self,
        inner: &[u8],
        direction: Direction,
        output: &mut Vec<u8>,
    ) -> Result<(), SpeedyError> {
        output.clear();
        self.encode_at(inner, direction, current_epoch()?, output)
    }

    fn encode_at(
        &self,
        inner: &[u8],
        direction: Direction,
        epoch: u64,
        output: &mut Vec<u8>,
    ) -> Result<(), SpeedyError> {
        output.clear();
        validate_inner(inner, direction)?;
        let route = self.tags(direction, epoch)?[0];
        let mask = self.header_mask(direction, route, inner);
        output.reserve(inner.len() + OVERHEAD);
        output.extend_from_slice(&route);
        output.extend_from_slice(inner);
        for (byte, mask) in output[ROUTING_TAG_LEN..ROUTING_TAG_LEN + HEADER_LEN]
            .iter_mut()
            .zip(mask)
        {
            *byte ^= mask;
        }
        let mac = blake3::keyed_hash(&self.keys(direction).auth.0, output);
        output.extend_from_slice(&mac.as_bytes()[..AUTH_TAG_LEN]);
        Ok(())
    }

    /// Authenticates the complete frame before exposing its unmasked header.
    ///
    /// Noise authentication and replay checks MUST still run on the result.
    ///
    /// # Errors
    /// Returns an error for invalid lengths, stale tags, tampering or bad headers.
    pub fn decode(
        &self,
        input: &[u8],
        direction: Direction,
        output: &mut Vec<u8>,
    ) -> Result<(), SpeedyError> {
        output.clear();
        self.decode_at(input, direction, current_epoch()?, output)
    }

    fn decode_at(
        &self,
        input: &[u8],
        direction: Direction,
        epoch: u64,
        output: &mut Vec<u8>,
    ) -> Result<(), SpeedyError> {
        output.clear();
        if !(MIN_FRAME_LEN..=MAX_DATAGRAM_LEN).contains(&input.len()) {
            return Err(SpeedyError::InvalidLength);
        }
        let route = input[..ROUTING_TAG_LEN].try_into().expect("checked length");
        if !self.tags(direction, epoch)?.contains(&route) {
            return Err(SpeedyError::UnknownRoutingTag);
        }
        let end = input.len() - AUTH_TAG_LEN;
        let mac = blake3::keyed_hash(&self.keys(direction).auth.0, &input[..end]);
        if !bool::from(mac.as_bytes()[..AUTH_TAG_LEN].ct_eq(&input[end..])) {
            return Err(SpeedyError::Authentication);
        }
        let inner = &input[ROUTING_TAG_LEN..end];
        let mask = self.header_mask(direction, route, inner);
        output.extend_from_slice(inner);
        for (byte, mask) in output[..HEADER_LEN].iter_mut().zip(mask) {
            *byte ^= mask;
        }
        if let Err(error) = validate_inner(output, direction) {
            output.clear();
            return Err(error);
        }
        Ok(())
    }

    fn keys(&self, direction: Direction) -> &DirectionKeys {
        &self.secrets.directions[direction as usize]
    }

    fn header_mask(&self, direction: Direction, route: [u8; 8], inner: &[u8]) -> [u8; 32] {
        let mut sample = [0; ROUTING_TAG_LEN + SAMPLE_LEN];
        sample[..ROUTING_TAG_LEN].copy_from_slice(&route);
        // The last 16 bytes are the Noise authentication tag, including for
        // empty handshake payloads. Never sample a clear handshake ephemeral key.
        sample[ROUTING_TAG_LEN..].copy_from_slice(&inner[inner.len() - SAMPLE_LEN..]);
        *blake3::keyed_hash(&self.keys(direction).mask.0, &sample).as_bytes()
    }

    fn tags(&self, direction: Direction, epoch: u64) -> Result<[[u8; 8]; 3], SpeedyError> {
        let mut cache = self.routes.lock().map_err(|_| SpeedyError::Cache)?;
        if cache.as_ref().is_none_or(|cached| cached.epoch != epoch) {
            *cache = Some(RouteCache {
                epoch,
                tags: [Direction::ClientToServer, Direction::ServerToClient].map(|direction| {
                    accepted_epochs(epoch).map(|epoch| self.routing_tag_at(direction, epoch))
                }),
            });
        }
        Ok(cache.as_ref().expect("cache populated").tags[direction as usize])
    }
}

fn hmac(key: &SpeedyKey) -> Hmac<Sha256> {
    Hmac::<Sha256>::new_from_slice(&key.0).expect("HMAC accepts 32-byte keys")
}

fn validate_inner(inner: &[u8], direction: Direction) -> Result<(), SpeedyError> {
    if !(HEADER_LEN + SAMPLE_LEN..=MAX_INNER_DATAGRAM_LEN).contains(&inner.len()) {
        return Err(SpeedyError::InvalidLength);
    }
    let packet = Datagram::decode(inner).map_err(|_| SpeedyError::InvalidHeader)?;
    if packet.header.flags != 0 {
        return Err(SpeedyError::InvalidHeader);
    }
    match (packet.header.kind, direction) {
        (PacketKind::Data | PacketKind::Keepalive, _) => Ok(()),
        (PacketKind::HandshakeInit, Direction::ClientToServer)
        | (PacketKind::HandshakeResponse, Direction::ServerToClient)
            if packet.header.sequence == 0 =>
        {
            Ok(())
        }
        _ => Err(SpeedyError::InvalidHeader),
    }
}

#[must_use]
pub const fn accepted_epochs(epoch: u64) -> [u64; 3] {
    [epoch, epoch.saturating_sub(1), epoch.saturating_add(1)]
}

/// Returns the current ten-second routing epoch.
///
/// # Errors
/// Returns an error if the system clock precedes the Unix epoch.
pub fn current_epoch() -> Result<u64, SpeedyError> {
    Ok(SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| SpeedyError::Clock)?
        .as_secs()
        / EPOCH_SECONDS)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SpeedyError {
    InvalidLength,
    InvalidHeader,
    UnknownRoutingTag,
    Authentication,
    Clock,
    Cache,
}

impl fmt::Display for SpeedyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidLength => "invalid Speedy frame length",
            Self::InvalidHeader => "invalid Speedy header",
            Self::UnknownRoutingTag => "unknown Speedy routing tag",
            Self::Authentication => "Speedy authentication failed",
            Self::Clock => "system clock is before the Unix epoch",
            Self::Cache => "Speedy route cache is unavailable",
        })
    }
}

impl Error for SpeedyError {}

#[cfg(test)]
mod tests;
