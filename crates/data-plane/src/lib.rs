#![doc = "Platform-independent encrypted IP packet data plane."]

mod device;
mod error;
mod ipv4;
mod tunnel;

pub use device::PacketDevice;
pub use error::{DataPlaneError, Ipv4PacketError};
pub use ipv4::Ipv4Packet;
pub use tunnel::{
    looks_like_protocol_datagram, Decoded, DecodedPacket, TunnelDataPlane, TunnelReceiver,
    TunnelSender, TUNNEL_OVERHEAD,
};
