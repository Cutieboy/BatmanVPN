#![doc = "Authenticated polymorphic UDP envelope for `MouseVPN`."]

use std::{error::Error, fmt, time::SystemTime};

use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    ChaCha20Poly1305, Nonce, Tag,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroize;

const FORMAT_VERSION: u8 = 2;
const ROUTING_TAG_LEN: usize = 8;
const NONCE_LEN: usize = 12;
const CLEAR_PREFIX_LEN: usize = ROUTING_TAG_LEN + NONCE_LEN;
const INNER_HEADER_LEN: usize = 6;
const AUTH_TAG_LEN: usize = 16;
const MIN_FRAME_LEN: usize = CLEAR_PREFIX_LEN + INNER_HEADER_LEN + AUTH_TAG_LEN;
const ROUTE_LABEL: &[u8] = b"MouseVPN MouseMorph v2 route";
pub const MAX_DATAGRAM_LEN: usize = 1_472;
pub const SAFE_TUN_MTU: u16 = 1_280;

const BALANCED_BUCKETS: &[usize] = &[192, 320, 512, 768, 1_024, 1_280, 1_408, 1_472];
const PARANOID_BUCKETS: &[usize] = &[256, 384, 576, 832, 1_088, 1_280, 1_408, 1_472];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Profile {
    Quiet = 1,
    Balanced = 2,
    Paranoid = 3,
}

impl Profile {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Quiet => "quiet",
            Self::Balanced => "balanced",
            Self::Paranoid => "paranoid",
        }
    }

    #[must_use]
    pub const fn epoch_seconds(self) -> u64 {
        match self {
            Self::Quiet => 30,
            Self::Balanced => 5,
            Self::Paranoid => 1,
        }
    }

    /// Chooses how many authenticated cover frames precede a handshake.
    ///
    /// # Errors
    ///
    /// Returns an error when the operating-system random generator fails.
    pub fn cover_count(self) -> Result<usize, MorphError> {
        match self {
            Self::Quiet => Ok(0),
            Self::Balanced => random_inclusive(1, 2),
            Self::Paranoid => random_inclusive(3, 5),
        }
    }

    /// Chooses the delay after a cover frame in milliseconds.
    ///
    /// # Errors
    ///
    /// Returns an error when the operating-system random generator fails.
    pub fn handshake_jitter_ms(self) -> Result<u64, MorphError> {
        match self {
            Self::Quiet => Ok(0),
            Self::Balanced => random_inclusive(1, 4).map(|value| value as u64),
            Self::Paranoid => random_inclusive(2, 12).map(|value| value as u64),
        }
    }

    fn from_id(value: u8) -> Result<Self, MorphError> {
        match value {
            1 => Ok(Self::Quiet),
            2 => Ok(Self::Balanced),
            3 => Ok(Self::Paranoid),
            _ => Err(MorphError::InvalidProfile(value)),
        }
    }

    fn target_len(self, minimum: usize) -> Result<usize, MorphError> {
        if minimum > MAX_DATAGRAM_LEN {
            return Err(MorphError::FrameTooLarge {
                actual: minimum,
                maximum: MAX_DATAGRAM_LEN,
            });
        }
        match self {
            Self::Quiet => {
                let extra = random_inclusive(0, 31)?;
                Ok(minimum.saturating_add(extra).min(MAX_DATAGRAM_LEN))
            }
            Self::Balanced => bucket_target(BALANCED_BUCKETS, minimum, 1),
            Self::Paranoid => bucket_target(PARANOID_BUCKETS, minimum, 2),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Direction {
    ClientToServer = 0,
    ServerToClient = 1,
}

pub struct MorphKey([u8; 32]);

impl MorphKey {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl Clone for MorphKey {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

impl fmt::Debug for MorphKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MorphKey([REDACTED])")
    }
}

impl Drop for MorphKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Clone, Debug)]
pub struct MorphCodec {
    key: MorphKey,
    profile: Profile,
}

impl MorphCodec {
    #[must_use]
    pub const fn new(key: MorphKey, profile: Profile) -> Self {
        Self { key, profile }
    }

    #[must_use]
    pub const fn profile(&self) -> Profile {
        self.profile
    }

    #[must_use]
    pub const fn key(&self) -> &MorphKey {
        &self.key
    }

    /// Wraps one complete legacy `MouseVPN` datagram.
    ///
    /// # Errors
    ///
    /// Returns an error for oversized input, clock failure, randomness failure,
    /// or authenticated-encryption failure.
    pub fn encode_payload(
        &self,
        inner: &[u8],
        direction: Direction,
        output: &mut Vec<u8>,
    ) -> Result<(), MorphError> {
        encode_frame(
            &self.key,
            self.profile,
            FrameKind::Payload,
            inner,
            direction,
            output,
        )
    }

    /// Produces one authenticated cover frame containing no protocol datagram.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::encode_payload`].
    pub fn encode_cover(
        &self,
        direction: Direction,
        output: &mut Vec<u8>,
    ) -> Result<(), MorphError> {
        encode_frame(
            &self.key,
            self.profile,
            FrameKind::Cover,
            &[],
            direction,
            output,
        )
    }

    /// Authenticates and unwraps one `MouseMorph` frame.
    ///
    /// Payload bytes are written to `output`. Cover frames leave it empty.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown epoch tag, malformed frame, or failed
    /// authentication.
    pub fn decode(
        &self,
        input: &[u8],
        direction: Direction,
        output: &mut Vec<u8>,
    ) -> Result<DecodedFrame, MorphError> {
        decode_frame(&self.key, self.profile, input, direction, output)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodedFrame {
    Cover { profile: Profile },
    Payload { profile: Profile },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum FrameKind {
    Cover = 0,
    Payload = 1,
}

fn encode_frame(
    key: &MorphKey,
    profile: Profile,
    kind: FrameKind,
    inner: &[u8],
    direction: Direction,
    output: &mut Vec<u8>,
) -> Result<(), MorphError> {
    let inner_len = u16::try_from(inner.len()).map_err(|_| MorphError::FrameTooLarge {
        actual: inner.len(),
        maximum: u16::MAX as usize,
    })?;
    let minimum = MIN_FRAME_LEN + inner.len();
    let target = profile.target_len(minimum)?;
    let padding_len = target - minimum;
    let epoch = current_epoch(profile)?;
    let route = routing_tag_at(key, profile, direction, epoch);
    let mut nonce = [0_u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|error| MorphError::Random(error.to_string()))?;

    output.clear();
    output.reserve(target);
    output.extend_from_slice(&route);
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&[
        FORMAT_VERSION,
        kind as u8,
        profile as u8,
        0,
        inner_len.to_be_bytes()[0],
        inner_len.to_be_bytes()[1],
    ]);
    output.extend_from_slice(inner);
    let padding_start = output.len();
    output.resize(padding_start + padding_len, 0);
    if padding_len != 0 {
        getrandom::fill(&mut output[padding_start..])
            .map_err(|error| MorphError::Random(error.to_string()))?;
    }

    let cipher = ChaCha20Poly1305::new_from_slice(&key.0).map_err(|_| MorphError::CipherInit)?;
    let aad = associated_data(route, direction);
    let authentication = cipher
        .encrypt_in_place_detached(
            Nonce::from_slice(&nonce),
            &aad,
            &mut output[CLEAR_PREFIX_LEN..],
        )
        .map_err(|_| MorphError::Encryption)?;
    output.extend_from_slice(&authentication);
    debug_assert_eq!(output.len(), target);
    Ok(())
}

fn decode_frame(
    key: &MorphKey,
    expected_profile: Profile,
    input: &[u8],
    direction: Direction,
    output: &mut Vec<u8>,
) -> Result<DecodedFrame, MorphError> {
    if input.len() < MIN_FRAME_LEN {
        return Err(MorphError::Truncated {
            actual: input.len(),
            minimum: MIN_FRAME_LEN,
        });
    }
    if input.len() > MAX_DATAGRAM_LEN {
        return Err(MorphError::FrameTooLarge {
            actual: input.len(),
            maximum: MAX_DATAGRAM_LEN,
        });
    }
    let route: [u8; ROUTING_TAG_LEN] = input[..ROUTING_TAG_LEN]
        .try_into()
        .map_err(|_| MorphError::InvalidFrame)?;
    let epoch = current_epoch(expected_profile)?;
    if !accepted_epochs(epoch)
        .into_iter()
        .any(|candidate| routing_tag_at(key, expected_profile, direction, candidate) == route)
    {
        return Err(MorphError::UnknownRoutingTag);
    }
    let nonce: [u8; NONCE_LEN] = input[ROUTING_TAG_LEN..CLEAR_PREFIX_LEN]
        .try_into()
        .map_err(|_| MorphError::InvalidFrame)?;
    let ciphertext_end = input.len() - AUTH_TAG_LEN;
    output.clear();
    output.extend_from_slice(&input[CLEAR_PREFIX_LEN..ciphertext_end]);
    let cipher = ChaCha20Poly1305::new_from_slice(&key.0).map_err(|_| MorphError::CipherInit)?;
    let aad = associated_data(route, direction);
    cipher
        .decrypt_in_place_detached(
            Nonce::from_slice(&nonce),
            &aad,
            output,
            Tag::from_slice(&input[ciphertext_end..]),
        )
        .map_err(|_| MorphError::Authentication)?;
    if output.len() < INNER_HEADER_LEN || output[0] != FORMAT_VERSION || output[3] != 0 {
        return Err(MorphError::InvalidFrame);
    }
    let profile = Profile::from_id(output[2])?;
    if profile != expected_profile {
        return Err(MorphError::InvalidFrame);
    }
    let inner_len = usize::from(u16::from_be_bytes([output[4], output[5]]));
    if INNER_HEADER_LEN + inner_len > output.len() {
        return Err(MorphError::InvalidFrame);
    }
    match output[1] {
        value if value == FrameKind::Cover as u8 && inner_len == 0 => {
            output.clear();
            Ok(DecodedFrame::Cover { profile })
        }
        value if value == FrameKind::Payload as u8 => {
            output.copy_within(INNER_HEADER_LEN..INNER_HEADER_LEN + inner_len, 0);
            output.truncate(inner_len);
            Ok(DecodedFrame::Payload { profile })
        }
        _ => Err(MorphError::InvalidFrame),
    }
}

#[must_use]
/// Derives one clear routing tag for an already selected profile and epoch.
///
/// # Panics
///
/// Panics only if HMAC rejects a fixed 32-byte key or a fixed-size digest slice
/// cannot be converted to eight bytes; both conditions are invariant violations.
pub fn routing_tag_at(
    key: &MorphKey,
    profile: Profile,
    direction: Direction,
    epoch: u64,
) -> [u8; 8] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&key.0)
        .expect("HMAC accepts every 32-byte MouseMorph key");
    mac.update(ROUTE_LABEL);
    mac.update(&[profile as u8]);
    mac.update(&[direction as u8]);
    mac.update(&epoch.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    digest[..ROUTING_TAG_LEN]
        .try_into()
        .expect("routing-tag slice has a fixed size")
}

/// Returns the previous, current and next accepted routing epochs.
#[must_use]
pub const fn accepted_epochs(epoch: u64) -> [u64; 3] {
    [epoch.saturating_sub(1), epoch, epoch.saturating_add(1)]
}

/// Returns the current profile-specific routing epoch.
///
/// # Errors
///
/// Returns an error when the system clock is earlier than the Unix epoch.
pub fn current_epoch(profile: Profile) -> Result<u64, MorphError> {
    let seconds = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| MorphError::Clock)?
        .as_secs();
    Ok(seconds / profile.epoch_seconds())
}

fn associated_data(route: [u8; ROUTING_TAG_LEN], direction: Direction) -> [u8; 9] {
    let mut aad = [0_u8; ROUTING_TAG_LEN + 1];
    aad[..ROUTING_TAG_LEN].copy_from_slice(&route);
    aad[ROUTING_TAG_LEN] = direction as u8;
    aad
}

fn bucket_target(
    buckets: &[usize],
    minimum: usize,
    alternatives: usize,
) -> Result<usize, MorphError> {
    let Some(first) = buckets.iter().position(|&bucket| bucket >= minimum) else {
        return Ok(MAX_DATAGRAM_LEN);
    };
    let last = (first + alternatives).min(buckets.len() - 1);
    let selected = random_inclusive(first, last)?;
    Ok(buckets[selected])
}

fn random_inclusive(minimum: usize, maximum: usize) -> Result<usize, MorphError> {
    debug_assert!(minimum <= maximum);
    if minimum == maximum {
        return Ok(minimum);
    }
    let mut random = [0_u8; 2];
    getrandom::fill(&mut random).map_err(|error| MorphError::Random(error.to_string()))?;
    let span = maximum - minimum + 1;
    Ok(minimum + (usize::from(u16::from_be_bytes(random)) % span))
}

#[derive(Debug, Eq, PartialEq)]
pub enum MorphError {
    Truncated { actual: usize, minimum: usize },
    FrameTooLarge { actual: usize, maximum: usize },
    InvalidFrame,
    InvalidProfile(u8),
    UnknownRoutingTag,
    Clock,
    Random(String),
    CipherInit,
    Encryption,
    Authentication,
}

impl fmt::Display for MorphError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { actual, minimum } => {
                write!(
                    formatter,
                    "MouseMorph frame has {actual} bytes; need {minimum}"
                )
            }
            Self::FrameTooLarge { actual, maximum } => {
                write!(
                    formatter,
                    "MouseMorph frame has {actual} bytes; maximum is {maximum}"
                )
            }
            Self::InvalidFrame => formatter.write_str("invalid MouseMorph frame"),
            Self::InvalidProfile(profile) => {
                write!(formatter, "invalid MouseMorph profile {profile}")
            }
            Self::UnknownRoutingTag => formatter.write_str("unknown MouseMorph routing tag"),
            Self::Clock => formatter.write_str("system clock is before the Unix epoch"),
            Self::Random(error) => write!(formatter, "MouseMorph randomness failed: {error}"),
            Self::CipherInit => formatter.write_str("MouseMorph cipher initialization failed"),
            Self::Encryption => formatter.write_str("MouseMorph encryption failed"),
            Self::Authentication => formatter.write_str("MouseMorph authentication failed"),
        }
    }
}

impl Error for MorphError {}

#[cfg(test)]
mod tests {
    use super::{
        accepted_epochs, routing_tag_at, DecodedFrame, Direction, MorphCodec, MorphKey, Profile,
        MAX_DATAGRAM_LEN,
    };

    fn codec(profile: Profile) -> MorphCodec {
        MorphCodec::new(MorphKey::from_bytes([7_u8; 32]), profile)
    }

    #[test]
    fn every_profile_round_trips_payloads() {
        for profile in [Profile::Quiet, Profile::Balanced, Profile::Paranoid] {
            let codec = codec(profile);
            let mut encoded = Vec::new();
            codec
                .encode_payload(b"legacy datagram", Direction::ClientToServer, &mut encoded)
                .expect("encode");
            assert!(encoded.len() <= MAX_DATAGRAM_LEN);
            assert_ne!(&encoded[..], b"legacy datagram");
            let mut decoded = Vec::new();
            assert_eq!(
                codec
                    .decode(&encoded, Direction::ClientToServer, &mut decoded)
                    .expect("decode"),
                DecodedFrame::Payload { profile }
            );
            assert_eq!(decoded, b"legacy datagram");
        }
    }

    #[test]
    fn cover_frames_are_authenticated_and_empty() {
        let codec = codec(Profile::Paranoid);
        let mut encoded = Vec::new();
        codec
            .encode_cover(Direction::ClientToServer, &mut encoded)
            .expect("encode cover");
        let mut decoded = Vec::new();
        assert_eq!(
            codec
                .decode(&encoded, Direction::ClientToServer, &mut decoded)
                .expect("decode cover"),
            DecodedFrame::Cover {
                profile: Profile::Paranoid
            }
        );
        assert!(decoded.is_empty());
    }

    #[test]
    fn tampering_and_wrong_direction_are_rejected() {
        let codec = codec(Profile::Balanced);
        let mut encoded = Vec::new();
        codec
            .encode_payload(b"secret", Direction::ClientToServer, &mut encoded)
            .expect("encode");
        let last = encoded.len() - 1;
        encoded[last] ^= 1;
        assert!(codec
            .decode(&encoded, Direction::ClientToServer, &mut Vec::new())
            .is_err());

        let mut valid = Vec::new();
        codec
            .encode_payload(b"secret", Direction::ClientToServer, &mut valid)
            .expect("encode");
        assert!(codec
            .decode(&valid, Direction::ServerToClient, &mut Vec::new())
            .is_err());
    }

    #[test]
    fn routing_tags_change_by_epoch_and_direction() {
        let key = MorphKey::from_bytes([11_u8; 32]);
        assert_ne!(
            routing_tag_at(&key, Profile::Quiet, Direction::ClientToServer, 10),
            routing_tag_at(&key, Profile::Quiet, Direction::ClientToServer, 11)
        );
        assert_ne!(
            routing_tag_at(&key, Profile::Quiet, Direction::ClientToServer, 10),
            routing_tag_at(&key, Profile::Quiet, Direction::ServerToClient, 10)
        );
        assert_ne!(
            routing_tag_at(&key, Profile::Quiet, Direction::ClientToServer, 10),
            routing_tag_at(&key, Profile::Paranoid, Direction::ClientToServer, 10)
        );
        assert_eq!(accepted_epochs(10), [9, 10, 11]);
    }
}
