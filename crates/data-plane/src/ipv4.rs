use std::net::Ipv4Addr;

use crate::Ipv4PacketError;

const MINIMUM_HEADER_LEN: usize = 20;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ipv4Packet<'a> {
    bytes: &'a [u8],
    source: Ipv4Addr,
    destination: Ipv4Addr,
}

impl<'a> Ipv4Packet<'a> {
    /// Parses the structural fields needed by the tunnel.
    ///
    /// # Errors
    ///
    /// Returns an error for truncated, non-IPv4 or inconsistent packets.
    pub fn parse(input: &'a [u8]) -> Result<Self, Ipv4PacketError> {
        if input.len() < MINIMUM_HEADER_LEN {
            return Err(Ipv4PacketError::Truncated);
        }
        let version = input[0] >> 4;
        if version != 4 {
            return Err(Ipv4PacketError::UnsupportedVersion(version));
        }
        let header_len = usize::from(input[0] & 0x0f) * 4;
        if header_len < MINIMUM_HEADER_LEN || header_len > input.len() {
            return Err(Ipv4PacketError::InvalidHeaderLength);
        }
        let total_len = usize::from(u16::from_be_bytes([input[2], input[3]]));
        if total_len < header_len || total_len > input.len() {
            return Err(Ipv4PacketError::InvalidTotalLength);
        }

        Ok(Self {
            bytes: &input[..total_len],
            source: Ipv4Addr::new(input[12], input[13], input[14], input[15]),
            destination: Ipv4Addr::new(input[16], input[17], input[18], input[19]),
        })
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    #[must_use]
    pub const fn source(&self) -> Ipv4Addr {
        self.source
    }

    #[must_use]
    pub const fn destination(&self) -> Ipv4Addr {
        self.destination
    }
}
