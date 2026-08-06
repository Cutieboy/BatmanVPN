use std::{error::Error, fmt};

/// Number of sequence numbers accepted below the highest authenticated one.
///
/// The original 128-entry window was chosen for a single-threaded receiver.
/// Multi-queue receive paths and ordinary internet reordering under load can
/// exceed it, and every packet past the window edge is dropped even though it
/// authenticates. `WireGuard` uses 8192 counters for the same reason.
pub const REPLAY_WINDOW_SIZE: u64 = WINDOW_LEN as u64;

const WINDOW_LEN: usize = 1_024;
const WINDOW_SIZE: u64 = REPLAY_WINDOW_SIZE;

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

/// Sliding receive window backed by a ring of accepted sequence numbers.
///
/// Each slot stores `sequence + 1`, so `0` marks an unused slot. Two sequence
/// numbers share a slot only when they differ by a multiple of [`WINDOW_SIZE`],
/// which puts the older one outside the window, so a stale slot never hides a
/// fresh packet or accepts a duplicate.
pub(crate) struct ReplayWindow {
    highest: Option<u64>,
    seen: Box<[u64]>,
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self {
            highest: None,
            seen: vec![0_u64; WINDOW_LEN].into_boxed_slice(),
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
        if self.slot(sequence) == sequence.wrapping_add(1) {
            return Err(ReplayError::Duplicate);
        }
        Ok(())
    }

    pub(crate) fn mark_authenticated(&mut self, sequence: u64) {
        let index = Self::index(sequence);
        self.seen[index] = sequence.wrapping_add(1);
        if self.highest.is_none_or(|highest| sequence > highest) {
            self.highest = Some(sequence);
        }
    }

    fn slot(&self, sequence: u64) -> u64 {
        self.seen[Self::index(sequence)]
    }

    fn index(sequence: u64) -> usize {
        usize::try_from(sequence % WINDOW_SIZE).unwrap_or(0)
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
}
