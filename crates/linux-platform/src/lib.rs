#![doc = "Shared Linux platform adapters for `MouseVPN`."]

mod dns;
mod firewall;
mod proxy_routes;
mod routes;
mod tun_device;

use std::{io, net::Ipv4Addr};

pub use dns::DnsGuard;
pub use firewall::FirewallGuard;
pub use proxy_routes::{ProxyRouteGuard, PROXY_MARK};
pub use routes::{ensure_no_competing_full_tunnel, RouteGuard};
pub use tun_device::{LinuxTun, LinuxTunConfig, DEFAULT_TX_QUEUE_LEN};

/// Removes only crash leftovers owned by `MouseVPN`.
///
/// # Errors
///
/// Returns an error when nftables or the marked server route cannot be cleaned.
pub fn repair_stale_network(server: Ipv4Addr) -> io::Result<()> {
    firewall::remove_runtime_table()?;
    routes::remove_stale_server_routes(server)
}
