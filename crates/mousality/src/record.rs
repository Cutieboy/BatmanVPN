//! Protected TLS 1.3-shaped application data records carrying tunnel datagrams.
//!
//! Each record is `17 03 03 <length>` followed by a ChaCha20-Poly1305
//! ciphertext under the direction's key, with the sequence number mixed into
//! the nonce as TLS 1.3 does. Inside, datagrams are framed by a 16-bit length;
//! a zero length ends the frames and the rest is padding. A record of pure
//! padding is how the server imitates the site's encrypted handshake flight.

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use zeroize::Zeroize;

use crate::{
    wire::{
        record_header, CONTENT_APPLICATION_DATA, MAX_PLAINTEXT_LEN, RECORD_HEADER_LEN, TLS_1_2,
    },
    MousalityError,
};

pub(crate) const TAG_LEN: usize = 16;
const FRAME_HEADER_LEN: usize = 2;
/// The largest datagram one record can carry.
pub const MAX_DATAGRAM_LEN: usize = MAX_PLAINTEXT_LEN - FRAME_HEADER_LEN;

/// One direction's record key, IV and sequence.
pub(crate) struct DirectionKey {
    key: LessSafeKey,
    iv: [u8; 12],
    sequence: u64,
}

impl DirectionKey {
    pub(crate) fn new(mut key: [u8; 32], iv: [u8; 12]) -> Result<Self, MousalityError> {
        let unbound =
            UnboundKey::new(&CHACHA20_POLY1305, &key).map_err(|_| MousalityError::InvalidKey);
        key.zeroize();
        Ok(Self {
            key: LessSafeKey::new(unbound?),
            iv,
            sequence: 0,
        })
    }

    fn next_nonce(&mut self) -> Result<Nonce, MousalityError> {
        let mut nonce = self.iv;
        for (byte, sequence) in nonce[4..].iter_mut().zip(self.sequence.to_be_bytes()) {
            *byte ^= sequence;
        }
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or(MousalityError::SequenceExhausted)?;
        Ok(Nonce::assume_unique_for_key(nonce))
    }
}

/// Seals datagrams into records.
pub struct RecordSealer {
    key: DirectionKey,
    plaintext: Vec<u8>,
}

impl RecordSealer {
    pub(crate) fn new(key: DirectionKey) -> Self {
        Self {
            key,
            plaintext: Vec::with_capacity(MAX_PLAINTEXT_LEN),
        }
    }

    /// Appends one record carrying `datagrams` to `output`, padded to at
    /// least `ciphertext_len` bytes of record body.
    ///
    /// # Errors
    ///
    /// Returns an error when the datagrams do not fit one record or the
    /// sequence is exhausted.
    pub fn seal(
        &mut self,
        datagrams: &[&[u8]],
        ciphertext_len: usize,
        output: &mut Vec<u8>,
    ) -> Result<(), MousalityError> {
        self.plaintext.clear();
        for datagram in datagrams {
            let length = u16::try_from(datagram.len())
                .ok()
                .filter(|length| *length > 0)
                .ok_or(MousalityError::TooLarge)?;
            self.plaintext.extend_from_slice(&length.to_be_bytes());
            self.plaintext.extend_from_slice(datagram);
        }
        let padded = ciphertext_len
            .saturating_sub(TAG_LEN)
            .max(self.plaintext.len())
            .min(MAX_PLAINTEXT_LEN);
        if self.plaintext.len() > padded {
            return Err(MousalityError::TooLarge);
        }
        // Zero padding reads as the end-of-frames marker.
        self.plaintext.resize(padded, 0);
        let header = record_header(CONTENT_APPLICATION_DATA, TLS_1_2, padded + TAG_LEN);
        let nonce = self.key.next_nonce()?;
        let tag = self
            .key
            .key
            .seal_in_place_separate_tag(nonce, Aad::from(header), &mut self.plaintext)
            .map_err(|_| MousalityError::InvalidKey)?;
        output.extend_from_slice(&header);
        output.extend_from_slice(&self.plaintext);
        output.extend_from_slice(tag.as_ref());
        Ok(())
    }
}

/// Opens records and yields the datagrams inside.
pub struct RecordOpener {
    key: DirectionKey,
}

impl RecordOpener {
    pub(crate) const fn new(key: DirectionKey) -> Self {
        Self { key }
    }

    /// Authenticates one application data record in place and returns its
    /// plaintext.
    ///
    /// # Errors
    ///
    /// Returns an error when the record fails authentication.
    pub fn open<'a>(
        &mut self,
        header: [u8; RECORD_HEADER_LEN],
        body: &'a mut [u8],
    ) -> Result<&'a [u8], MousalityError> {
        let nonce = self.key.next_nonce()?;
        self.key
            .key
            .open_in_place(nonce, Aad::from(header), body)
            .map(|plaintext| &*plaintext)
            .map_err(|_| MousalityError::Unauthenticated)
    }
}

/// Splits an opened record's plaintext into its datagrams.
pub(crate) fn frames(plaintext: &[u8]) -> impl Iterator<Item = Result<&[u8], MousalityError>> {
    let mut rest = plaintext;
    std::iter::from_fn(move || {
        if rest.len() < FRAME_HEADER_LEN {
            return None;
        }
        let length = usize::from(u16::from_be_bytes([rest[0], rest[1]]));
        if length == 0 {
            return None;
        }
        let Some(datagram) = rest.get(FRAME_HEADER_LEN..FRAME_HEADER_LEN + length) else {
            rest = &[];
            return Some(Err(MousalityError::Malformed));
        };
        rest = &rest[FRAME_HEADER_LEN + length..];
        Some(Ok(datagram))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (RecordSealer, RecordOpener) {
        (
            RecordSealer::new(DirectionKey::new([3; 32], [4; 12]).unwrap()),
            RecordOpener::new(DirectionKey::new([3; 32], [4; 12]).unwrap()),
        )
    }

    fn open_one(opener: &mut RecordOpener, record: &mut [u8]) -> Vec<Vec<u8>> {
        let header: [u8; 5] = record[..5].try_into().unwrap();
        let plaintext = opener.open(header, &mut record[5..]).unwrap();
        frames(plaintext)
            .map(|frame| frame.unwrap().to_vec())
            .collect()
    }

    #[test]
    fn datagrams_round_trip_and_padding_hides_their_length() {
        let (mut sealer, mut opener) = pair();
        let mut record = Vec::new();
        sealer
            .seal(&[b"first", b"second datagram"], 300, &mut record)
            .unwrap();
        assert_eq!(&record[..3], &[0x17, 3, 3]);
        assert_eq!(record.len(), 5 + 300);
        assert_eq!(
            open_one(&mut opener, &mut record),
            [b"first".to_vec(), b"second datagram".to_vec()]
        );

        let mut padding = Vec::new();
        sealer.seal(&[], 2_900, &mut padding).unwrap();
        assert_eq!(padding.len(), 5 + 2_900);
        assert!(open_one(&mut opener, &mut padding).is_empty());
    }

    #[test]
    fn reordered_tampered_or_oversized_records_are_rejected() {
        let (mut sealer, mut opener) = pair();
        let (mut first, mut second) = (Vec::new(), Vec::new());
        sealer.seal(&[b"one"], 0, &mut first).unwrap();
        sealer.seal(&[b"two"], 0, &mut second).unwrap();
        let header: [u8; 5] = second[..5].try_into().unwrap();
        assert!(opener.open(header, &mut second[5..]).is_err());

        let (mut sealer, mut opener) = pair();
        let mut record = Vec::new();
        sealer.seal(&[b"one"], 0, &mut record).unwrap();
        record[7] ^= 1;
        let header: [u8; 5] = record[..5].try_into().unwrap();
        assert!(opener.open(header, &mut record[5..]).is_err());

        let huge = vec![1_u8; MAX_PLAINTEXT_LEN];
        assert!(sealer.seal(&[&huge], 0, &mut Vec::new()).is_err());
    }
}
