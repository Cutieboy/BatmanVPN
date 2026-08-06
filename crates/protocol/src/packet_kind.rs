use crate::DecodeError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PacketKind {
    HandshakeInit = 1,
    HandshakeResponse = 2,
    Data = 3,
    Keepalive = 4,
    Close = 5,
}

impl TryFrom<u8> for PacketKind {
    type Error = DecodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::HandshakeInit),
            2 => Ok(Self::HandshakeResponse),
            3 => Ok(Self::Data),
            4 => Ok(Self::Keepalive),
            5 => Ok(Self::Close),
            value => Err(DecodeError::UnknownPacketKind(value)),
        }
    }
}
