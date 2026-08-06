#![doc = "Transport abstractions independent from the `MouseVPN` handshake."]

mod datagram;
mod udp;

pub use datagram::DatagramTransport;
pub use udp::UdpTransport;
