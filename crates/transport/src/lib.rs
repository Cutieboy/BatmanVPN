#![doc = "Transport abstractions independent from the `MouseVPN` handshake."]

mod datagram;
mod udp;

pub use datagram::DatagramTransport;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use udp::UdpBatch;
pub use udp::UdpTransport;
