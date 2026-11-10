#![doc = "Transport abstractions independent from the `MouseVPN` handshake."]

mod datagram;
mod udp;

pub use datagram::DatagramTransport;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use udp::UdpBatch;
pub use udp::UdpTransport;

mod mousality;
pub use mousality::{is_unauthenticated, mousality_io, unix_seconds, MousalityTransport};

mod mousality_pool;
pub use mousality_pool::connect_pooled;

mod client;
pub use client::ClientTransport;
