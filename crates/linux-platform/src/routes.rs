use std::{
    io,
    net::{IpAddr, Ipv4Addr},
};

use route_manager::{Route, RouteManager};

pub struct RouteGuard {
    manager: RouteManager,
    added: Vec<Route>,
}

/// Refuses the common split-default layout used by an existing full-tunnel VPN.
///
/// This is an early safety check. It does not claim to recognize every policy
/// routing setup, so callers should still require other VPNs to be disconnected.
///
/// # Errors
///
/// Returns an error when routes cannot be inspected or a split default exists.
pub fn ensure_no_competing_full_tunnel() -> io::Result<()> {
    let mut manager = RouteManager::new()?;
    reject_full_tunnel(&manager.list()?)
}

impl RouteGuard {
    /// Preserves the server path and installs split IPv4 defaults through TUN.
    ///
    /// Added routes are removed when the guard is dropped normally.
    ///
    /// # Errors
    ///
    /// Returns an error when the existing default cannot be found or a route
    /// cannot be installed.
    pub fn install(server: Ipv4Addr, tun_name: &str) -> io::Result<Self> {
        let mut manager = RouteManager::new()?;
        let routes = manager.list()?;
        reject_full_tunnel(&routes)?;
        let default = routes
            .into_iter()
            .filter(|route| {
                route.destination() == IpAddr::V4(Ipv4Addr::UNSPECIFIED) && route.prefix() == 0
            })
            .min_by_key(|route| route.metric().unwrap_or(u32::MAX))
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "IPv4 default route not found")
            })?;

        let mut server_route = Route::new(IpAddr::V4(server), 32);
        if let Some(gateway) = default.gateway() {
            server_route = server_route.with_gateway(gateway);
        }
        if let Some(index) = default.if_index() {
            server_route = server_route.with_if_index(index);
        } else if let Some(name) = default.if_name() {
            server_route = server_route.with_if_name(name.clone());
        }
        let first_half =
            Route::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 1).with_if_name(tun_name.to_owned());
        let second_half = Route::new(IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0)), 1)
            .with_if_name(tun_name.to_owned());

        let mut guard = Self {
            manager,
            added: Vec::new(),
        };
        guard.add(server_route)?;
        guard.add(first_half)?;
        guard.add(second_half)?;
        Ok(guard)
    }

    fn add(&mut self, route: Route) -> io::Result<()> {
        self.manager.add(&route)?;
        self.added.push(route);
        Ok(())
    }
}

fn reject_full_tunnel(routes: &[Route]) -> io::Result<()> {
    if has_full_tunnel(routes) {
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "another full-tunnel VPN appears to be active; disconnect it before starting MouseVPN",
        ))
    } else {
        Ok(())
    }
}

fn has_full_tunnel(routes: &[Route]) -> bool {
    routes.iter().any(|route| {
        route.prefix() == 1
            && matches!(
                route.destination(),
                IpAddr::V4(address)
                    if address == Ipv4Addr::UNSPECIFIED
                        || address == Ipv4Addr::new(128, 0, 0, 0)
            )
    })
}

impl Drop for RouteGuard {
    fn drop(&mut self) {
        for route in self.added.iter().rev() {
            let _ = self.manager.delete(route);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use route_manager::Route;

    use super::has_full_tunnel;

    #[test]
    fn detects_split_default_routes() {
        let normal = Route::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
        let split = Route::new(IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0)), 1);

        assert!(!has_full_tunnel(&[normal]));
        assert!(has_full_tunnel(&[split]));
    }
}
