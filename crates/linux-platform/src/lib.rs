#![doc = "Shared Linux platform adapters for `MouseVPN`."]

mod dns;
mod firewall;
mod routes;
mod tun_device;

pub use dns::DnsGuard;
pub use firewall::FirewallGuard;
pub use routes::{ensure_no_competing_full_tunnel, RouteGuard};
pub use tun_device::{LinuxTun, LinuxTunConfig, DEFAULT_TX_QUEUE_LEN};
