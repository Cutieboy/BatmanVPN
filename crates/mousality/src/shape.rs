//! Mousality 2.0 record shaping.
//!
//! The tunnel carries other connections' TLS handshakes, and their record
//! sizes would show through the outer records: a classifier that knows how a
//! nested `ClientHello`, server flight and `Finished` look can find them.
//! Like XTLS Vision, the records most likely to hold such a handshake are
//! padded: the first ones of a connection and the first ones after a pause,
//! when a new inner connection usually starts. Short records grow into the
//! size range of a full packet, longer ones get a random tail. Steady traffic
//! in between stays unpadded, so bulk transfers pay nothing.

use std::time::{Duration, Instant};

use crate::{
    record::TAG_LEN,
    wire::{random_bytes, MAX_PLAINTEXT_LEN},
    MousalityError,
};

/// Records shaped when a connection opens and the first inner handshakes run.
const OPENING_RECORDS: u32 = 16;
/// Records shaped after a pause.
const BURST_RECORDS: u32 = 8;
/// A gap after which the next records count as a new burst.
const IDLE_GAP: Duration = Duration::from_millis(500);
/// Shorter plaintexts are padded to between this and `SHORT_PADDED + SHORT_SPREAD`.
const SHORT_PADDED: usize = 900;
const SHORT_SPREAD: usize = 500;
/// Longer plaintexts get up to this many random bytes on top.
const LONG_SPREAD: usize = 256;

/// One direction's padding decisions.
pub(crate) struct Shaper {
    remaining: u32,
    last: Option<Instant>,
}

impl Shaper {
    pub(crate) const fn new() -> Self {
        Self {
            remaining: OPENING_RECORDS,
            last: None,
        }
    }

    /// The record body length to pad `plaintext_len` bytes of frames to when
    /// sent at `now`; zero leaves the record unpadded.
    pub(crate) fn ciphertext_len(
        &mut self,
        plaintext_len: usize,
        now: Instant,
    ) -> Result<usize, MousalityError> {
        if self
            .last
            .is_some_and(|last| now.saturating_duration_since(last) >= IDLE_GAP)
        {
            self.remaining = self.remaining.max(BURST_RECORDS);
        }
        self.last = Some(now);
        if self.remaining == 0 {
            return Ok(0);
        }
        self.remaining -= 1;
        let draw = usize::from(u16::from_be_bytes(random_bytes::<2>()?));
        let padded = if plaintext_len < SHORT_PADDED {
            SHORT_PADDED + draw % SHORT_SPREAD
        } else {
            plaintext_len + draw % LONG_SPREAD
        };
        Ok(padded.min(MAX_PLAINTEXT_LEN) + TAG_LEN)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_connection_opens_with_padded_records_then_runs_unpadded() {
        let mut shaper = Shaper::new();
        let start = Instant::now();
        for index in 0..OPENING_RECORDS {
            let now = start + Duration::from_millis(u64::from(index));
            let length = shaper.ciphertext_len(60, now).unwrap();
            assert!(
                (SHORT_PADDED + TAG_LEN..SHORT_PADDED + SHORT_SPREAD + TAG_LEN).contains(&length),
                "{length}"
            );
        }
        let after = start + Duration::from_millis(u64::from(OPENING_RECORDS));
        assert_eq!(shaper.ciphertext_len(60, after).unwrap(), 0);
    }

    #[test]
    fn a_pause_starts_a_new_padded_burst() {
        let mut shaper = Shaper::new();
        let start = Instant::now();
        for index in 0..=OPENING_RECORDS {
            shaper
                .ciphertext_len(60, start + Duration::from_millis(u64::from(index)))
                .unwrap();
        }
        let resumed = start + Duration::from_secs(5);
        for index in 0..BURST_RECORDS {
            let now = resumed + Duration::from_millis(u64::from(index));
            assert_ne!(shaper.ciphertext_len(60, now).unwrap(), 0, "record {index}");
        }
        let later = resumed + Duration::from_millis(u64::from(BURST_RECORDS));
        assert_eq!(shaper.ciphertext_len(60, later).unwrap(), 0);
    }

    #[test]
    fn long_records_get_a_bounded_random_tail() {
        let mut shaper = Shaper::new();
        let now = Instant::now();
        let length = shaper.ciphertext_len(1_300, now).unwrap();
        assert!(
            (1_300 + TAG_LEN..1_300 + LONG_SPREAD + TAG_LEN).contains(&length),
            "{length}"
        );
        let full = shaper.ciphertext_len(MAX_PLAINTEXT_LEN, now).unwrap();
        assert_eq!(full, MAX_PLAINTEXT_LEN + TAG_LEN);
    }
}
