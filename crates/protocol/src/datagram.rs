use crate::{DecodeError, Header, HEADER_LEN};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Datagram<'a> {
    pub header: Header,
    pub payload: &'a [u8],
}

impl<'a> Datagram<'a> {
    #[must_use]
    pub const fn new(header: Header, payload: &'a [u8]) -> Self {
        Self { header, payload }
    }

    #[must_use]
    pub fn encode(self) -> Vec<u8> {
        let mut output = Vec::with_capacity(HEADER_LEN + self.payload.len());
        output.extend_from_slice(&self.header.encode());
        output.extend_from_slice(self.payload);
        output
    }

    /// Decodes one complete transport datagram.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError`] when the outer header is malformed.
    pub fn decode(input: &'a [u8]) -> Result<Self, DecodeError> {
        let header = Header::decode(input)?;
        Ok(Self {
            header,
            payload: &input[HEADER_LEN..],
        })
    }
}
