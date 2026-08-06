use crate::{DecodeError, PacketKind, VERSION};

pub const HEADER_LEN: usize = 20;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header {
    pub kind: PacketKind,
    pub flags: u16,
    pub session_id: u64,
    pub sequence: u64,
}

impl Header {
    #[must_use]
    pub fn encode(self) -> [u8; HEADER_LEN] {
        let mut output = [0_u8; HEADER_LEN];
        output[0] = VERSION;
        output[1] = self.kind as u8;
        output[2..4].copy_from_slice(&self.flags.to_be_bytes());
        output[4..12].copy_from_slice(&self.session_id.to_be_bytes());
        output[12..20].copy_from_slice(&self.sequence.to_be_bytes());
        output
    }

    /// Decodes a header from the beginning of `input`.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError`] when the input is too short, the protocol marker
    /// or version is unsupported, or the packet kind is unknown.
    pub fn decode(input: &[u8]) -> Result<Self, DecodeError> {
        if input.len() < HEADER_LEN {
            return Err(DecodeError::Truncated {
                actual: input.len(),
                minimum: HEADER_LEN,
            });
        }
        if input[0] != VERSION {
            return Err(DecodeError::UnsupportedVersion(input[0]));
        }

        Ok(Self {
            kind: PacketKind::try_from(input[1])?,
            flags: u16::from_be_bytes([input[2], input[3]]),
            session_id: u64::from_be_bytes(
                input[4..12]
                    .try_into()
                    .map_err(|_| DecodeError::InvalidHeader)?,
            ),
            sequence: u64::from_be_bytes(
                input[12..20]
                    .try_into()
                    .map_err(|_| DecodeError::InvalidHeader)?,
            ),
        })
    }
}
