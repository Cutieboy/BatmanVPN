#![doc = "Versioned wire types shared by `MouseVPN` clients and servers."]

mod datagram;
mod error;
mod header;
mod inner;
mod packet_kind;
mod session_parameters;

pub use datagram::Datagram;
pub use error::DecodeError;
pub use header::{Header, HEADER_LEN};
pub use inner::{InnerDecodeError, InnerPacket, InnerPacketKind};
pub use packet_kind::PacketKind;
pub use session_parameters::{SessionParameters, SessionParametersError, SESSION_PARAMETERS_LEN};

pub const VERSION: u8 = 1;
