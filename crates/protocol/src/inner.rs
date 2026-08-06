use core::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum InnerPacketKind {
    Data = 1,
    Keepalive = 2,
    Close = 3,
}

impl TryFrom<u8> for InnerPacketKind {
    type Error = InnerDecodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Data),
            2 => Ok(Self::Keepalive),
            3 => Ok(Self::Close),
            value => Err(InnerDecodeError::UnknownKind(value)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InnerPacket<'a> {
    pub kind: InnerPacketKind,
    pub payload: &'a [u8],
}

impl<'a> InnerPacket<'a> {
    #[must_use]
    pub const fn new(kind: InnerPacketKind, payload: &'a [u8]) -> Self {
        Self { kind, payload }
    }

    #[must_use]
    pub fn encode(self) -> Vec<u8> {
        let mut output = Vec::with_capacity(1 + self.payload.len());
        output.push(self.kind as u8);
        output.extend_from_slice(self.payload);
        output
    }

    /// Decodes authenticated inner framing.
    ///
    /// # Errors
    ///
    /// Returns [`InnerDecodeError`] for empty input or an unknown message kind.
    pub fn decode(input: &'a [u8]) -> Result<Self, InnerDecodeError> {
        let (&kind, payload) = input.split_first().ok_or(InnerDecodeError::Empty)?;
        Ok(Self {
            kind: InnerPacketKind::try_from(kind)?,
            payload,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InnerDecodeError {
    Empty,
    UnknownKind(u8),
}

impl fmt::Display for InnerDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("empty inner packet"),
            Self::UnknownKind(kind) => write!(formatter, "unknown inner packet kind {kind}"),
        }
    }
}

impl std::error::Error for InnerDecodeError {}
