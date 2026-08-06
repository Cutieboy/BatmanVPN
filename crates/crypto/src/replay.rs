use std::{error::Error, fmt};

const WINDOW_SIZE: u64 = 128;

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

#[derive(Debug, Default)]
pub(crate) struct ReplayWindow {
    highest: Option<u64>,
    bitmap: u128,
}

impl ReplayWindow {
    pub(crate) fn ensure_acceptable(&self, sequence: u64) -> Result<(), ReplayError> {
        let Some(highest) = self.highest else {
            return Ok(());
        };
        if sequence > highest {
            return Ok(());
        }

        let age = highest - sequence;
        if age >= WINDOW_SIZE {
            return Err(ReplayError::TooOld);
        }
        if self.bitmap & (1_u128 << age) != 0 {
            return Err(ReplayError::Duplicate);
        }
        Ok(())
    }

    pub(crate) fn mark_authenticated(&mut self, sequence: u64) {
        let Some(highest) = self.highest else {
            self.highest = Some(sequence);
            self.bitmap = 1;
            return;
        };

        if sequence > highest {
            let distance = sequence - highest;
            self.bitmap = if distance >= WINDOW_SIZE {
                1
            } else {
                (self.bitmap << distance) | 1
            };
            self.highest = Some(sequence);
        } else {
            self.bitmap |= 1_u128 << (highest - sequence);
        }
    }
}
