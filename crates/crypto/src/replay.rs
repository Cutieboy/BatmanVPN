use std::{error::Error, fmt};

/// Number of sequence numbers in the receive window, including the highest one.
///
/// A larger window tolerates bursts of reordered packets without changing the
/// wire protocol. Only successfully authenticated packets advance this window.
pub const REPLAY_WINDOW_SIZE: u64 = 8_192;

const WINDOW_SIZE: u64 = REPLAY_WINDOW_SIZE;
const WORD_BITS: u64 = u64::BITS as u64;
// The extra word preserves the oldest partial block when a new block opens.
// Without it, clearing a reused word could erase still-in-window replay bits.
const WORD_COUNT: usize = (WINDOW_SIZE / WORD_BITS) as usize + 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayError {
    Duplicate,
    TooOld,
}

impl fmt::Display for ReplayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Duplicate => formatter.write_str("duplicate sequence"),
            Self::TooOld => formatter.write_str("sequence is outside the receive window"),
        }
    }
}

impl Error for ReplayError {}

/// Sliding receive window backed by a circular bitmap (see RFC 6479).
///
/// Advancing into a new block clears only the newly occupied words. Large jumps
/// clear at most the complete bitmap. No shift, allocation or sequence sentinel
/// is needed on the packet path; the bitmap occupies 1032 bytes per receiver.
pub(crate) struct ReplayWindow {
    highest: Option<u64>,
    seen: Box<[u64]>,
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self {
            highest: None,
            seen: vec![0_u64; WORD_COUNT].into_boxed_slice(),
        }
    }
}

impl fmt::Debug for ReplayWindow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReplayWindow")
            .field("highest", &self.highest)
            .finish_non_exhaustive()
    }
}

impl ReplayWindow {
    pub(crate) fn ensure_acceptable(&self, sequence: u64) -> Result<(), ReplayError> {
        let Some(highest) = self.highest else {
            return Ok(());
        };
        if sequence > highest {
            return Ok(());
        }
        if highest - sequence >= WINDOW_SIZE {
            return Err(ReplayError::TooOld);
        }
        if self.seen[Self::index(sequence / WORD_BITS)] & Self::mask(sequence) != 0 {
            return Err(ReplayError::Duplicate);
        }
        Ok(())
    }

    pub(crate) fn mark_authenticated(&mut self, sequence: u64) {
        if let Some(highest) = self.highest {
            if sequence > highest {
                let previous_word = highest / WORD_BITS;
                let next_word = sequence / WORD_BITS;
                if next_word - previous_word >= WORD_COUNT as u64 {
                    self.seen.fill(0);
                } else {
                    for word in previous_word + 1..=next_word {
                        self.seen[Self::index(word)] = 0;
                    }
                }
            }
        }
        self.seen[Self::index(sequence / WORD_BITS)] |= Self::mask(sequence);
        if self.highest.is_none_or(|highest| sequence > highest) {
            self.highest = Some(sequence);
        }
    }

    fn mask(sequence: u64) -> u64 {
        1_u64 << (sequence % WORD_BITS)
    }

    fn index(word: u64) -> usize {
        usize::try_from(word % WORD_COUNT as u64).expect("bitmap index fits usize")
    }
}

#[cfg(test)]
mod tests {
    use super::{ReplayError, ReplayWindow, WINDOW_SIZE};

    #[test]
    fn accepts_fresh_and_reordered_sequences() {
        let mut window = ReplayWindow::default();
        window.mark_authenticated(0);
        window.mark_authenticated(5);
        assert_eq!(window.ensure_acceptable(3), Ok(()));
        window.mark_authenticated(3);
        assert_eq!(window.ensure_acceptable(3), Err(ReplayError::Duplicate));
        assert_eq!(window.ensure_acceptable(0), Err(ReplayError::Duplicate));
        assert_eq!(window.ensure_acceptable(6), Ok(()));
    }

    #[test]
    fn rejects_sequences_below_the_window() {
        let mut window = ReplayWindow::default();
        window.mark_authenticated(0);
        window.mark_authenticated(WINDOW_SIZE);
        assert_eq!(window.ensure_acceptable(0), Err(ReplayError::TooOld));
        assert_eq!(window.ensure_acceptable(1), Ok(()));
    }

    #[test]
    fn stale_ring_slots_do_not_reject_fresh_sequences() {
        let mut window = ReplayWindow::default();
        window.mark_authenticated(7);
        window.mark_authenticated(WINDOW_SIZE + 7);
        assert_eq!(
            window.ensure_acceptable(WINDOW_SIZE + 7),
            Err(ReplayError::Duplicate)
        );
        window.mark_authenticated(2 * WINDOW_SIZE);
        assert_eq!(window.ensure_acceptable(2 * WINDOW_SIZE - 1), Ok(()));
    }

    #[test]
    fn a_long_ordered_run_is_accepted_once_each() {
        let mut window = ReplayWindow::default();
        for sequence in 0..10_000 {
            assert_eq!(window.ensure_acceptable(sequence), Ok(()));
            window.mark_authenticated(sequence);
            assert_eq!(
                window.ensure_acceptable(sequence),
                Err(ReplayError::Duplicate)
            );
        }
    }

    #[test]
    fn advancing_preserves_the_oldest_partial_word() {
        let mut window = ReplayWindow::default();
        window.mark_authenticated(1);
        window.mark_authenticated(WINDOW_SIZE);
        assert_eq!(window.ensure_acceptable(1), Err(ReplayError::Duplicate));
        assert_eq!(window.ensure_acceptable(2), Ok(()));
        window.mark_authenticated(2);
        window.mark_authenticated(WINDOW_SIZE + 1);
        assert_eq!(window.ensure_acceptable(1), Err(ReplayError::TooOld));
        assert_eq!(window.ensure_acceptable(2), Err(ReplayError::Duplicate));
    }

    #[test]
    fn accepts_an_entire_reversed_window_once() {
        let mut window = ReplayWindow::default();
        for sequence in (0..WINDOW_SIZE).rev() {
            assert_eq!(window.ensure_acceptable(sequence), Ok(()));
            window.mark_authenticated(sequence);
        }
        for sequence in 0..WINDOW_SIZE {
            assert_eq!(
                window.ensure_acceptable(sequence),
                Err(ReplayError::Duplicate)
            );
        }
    }

    #[test]
    fn large_jumps_and_maximum_sequence_do_not_alias_empty_slots() {
        let mut window = ReplayWindow::default();
        window.mark_authenticated(0);
        window.mark_authenticated(3 * WINDOW_SIZE);
        assert_eq!(window.ensure_acceptable(0), Err(ReplayError::TooOld));
        assert_eq!(window.ensure_acceptable(3 * WINDOW_SIZE - 1), Ok(()));
        window.mark_authenticated(u64::MAX - 1);
        assert_eq!(window.ensure_acceptable(u64::MAX), Ok(()));
        window.mark_authenticated(u64::MAX);
        assert_eq!(
            window.ensure_acceptable(u64::MAX),
            Err(ReplayError::Duplicate)
        );
        assert_eq!(window.ensure_acceptable(u64::MAX - 2), Ok(()));
        assert_eq!(window.ensure_acceptable(u64::MAX - WINDOW_SIZE + 1), Ok(()));
        assert_eq!(
            window.ensure_acceptable(u64::MAX - WINDOW_SIZE),
            Err(ReplayError::TooOld)
        );
    }

    #[test]
    fn agrees_with_a_set_model_across_reordering_wraps_and_jumps() {
        use std::collections::BTreeSet;

        let mut window = ReplayWindow::default();
        let mut accepted = BTreeSet::new();
        let mut highest = 0_u64;
        let mut random = 123_456_789_u64;
        for step in 0..100_000 {
            random ^= random << 13;
            random ^= random >> 7;
            random ^= random << 17;
            let sequence = match step % 5 {
                0 => highest + random % (3 * WINDOW_SIZE),
                1 => highest + 1,
                _ => highest.saturating_sub(random % (WINDOW_SIZE + 128)),
            };
            let expected = if highest.saturating_sub(sequence) >= WINDOW_SIZE {
                Err(ReplayError::TooOld)
            } else if accepted.contains(&sequence) {
                Err(ReplayError::Duplicate)
            } else {
                Ok(())
            };
            assert_eq!(
                window.ensure_acceptable(sequence),
                expected,
                "step {step}, sequence {sequence}"
            );
            if expected.is_ok() {
                window.mark_authenticated(sequence);
                highest = highest.max(sequence);
                accepted = accepted.split_off(&highest.saturating_sub(WINDOW_SIZE - 1));
                accepted.insert(sequence);
            }
        }
    }
}
