use std::{
    io,
    net::{IpAddr, Ipv4Addr},
};

use route_manager::{Route, RouteManager};

const SERVER_ROUTE_METRIC: u32 = 4_242;

pub struct RouteGuard {
    manager: RouteManager,
    server_ip: Ipv4Addr,
    server_route: Option<Route>,
    tunnel_routes: Vec<Route>,
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
        let server_route = server_route(server, &routes)?;
        let first_half =
            Route::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 1).with_if_name(tun_name.to_owned());
        let second_half = Route::new(IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0)), 1)
            .with_if_name(tun_name.to_owned());

        let mut guard = Self {
            manager,
            server_ip: server,
            server_route: None,
            tunnel_routes: Vec::new(),
        };
        guard.manager.add(&server_route)?;
        guard.server_route = Some(server_route);
        guard.add_tunnel_route(first_half)?;
        guard.add_tunnel_route(second_half)?;
        Ok(guard)
    }

    /// Replaces the server host route when the physical default gateway changes.
    ///
    /// # Errors
    ///
    /// Returns an error when routes cannot be inspected or replaced.
    pub fn refresh_server_route(&mut self) -> io::Result<()> {
        let routes = self.manager.list()?;
        let replacement = server_route(self.server_ip, &routes)?;
        if self.server_route.as_ref() == Some(&replacement) {
            return Ok(());
        }

        let previous = self.server_route.take();
        if let Some(route) = previous.as_ref() {
            self.manager.delete(route)?;
        }
        if let Err(error) = self.manager.add(&replacement) {
            if let Some(route) = previous {
                if self.manager.add(&route).is_ok() {
                    self.server_route = Some(route);
                }
            }
            return Err(error);
        }
        self.server_route = Some(replacement);
        Ok(())
    }

    fn add_tunnel_route(&mut self, route: Route) -> io::Result<()> {
        self.manager.add(&route)?;
        self.tunnel_routes.push(route);
        Ok(())
    }
}

fn server_route(server: Ipv4Addr, routes: &[Route]) -> io::Result<Route> {
    let default = routes
        .iter()
        .filter(|route| {
            route.destination() == IpAddr::V4(Ipv4Addr::UNSPECIFIED) && route.prefix() == 0
        })
        .min_by_key(|route| route.metric().unwrap_or(u32::MAX))
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "IPv4 default route not found"))?;
    let mut route = Route::new(IpAddr::V4(server), 32).with_metric(SERVER_ROUTE_METRIC);
    if let Some(gateway) = default.gateway() {
        route = route.with_gateway(gateway);
    }
    if let Some(index) = default.if_index() {
        route = route.with_if_index(index);
    } else if let Some(name) = default.if_name() {
        route = route.with_if_name(name.clone());
    }
    Ok(route)
}

pub(crate) fn remove_stale_server_routes(server: Ipv4Addr) -> io::Result<()> {
    let mut manager = RouteManager::new()?;
    let stale = manager
        .list()?
        .into_iter()
        .filter(|route| is_owned_server_route(route, server))
        .collect::<Vec<_>>();
    for route in stale {
        manager.delete(&route)?;
    }
    Ok(())
}

fn is_owned_server_route(route: &Route, server: Ipv4Addr) -> bool {
    route.destination() == IpAddr::V4(server)
        && route.prefix() == 32
        && route.metric() == Some(SERVER_ROUTE_METRIC)
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
        for route in self.tunnel_routes.iter().rev() {
            let _ = self.manager.delete(route);
        }
        if let Some(route) = self.server_route.as_ref() {
            let _ = self.manager.delete(route);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use route_manager::Route;

    use super::{has_full_tunnel, is_owned_server_route, server_route};

    #[test]
    fn detects_split_default_routes() {
        let normal = Route::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
        let split = Route::new(IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0)), 1);

        assert!(!has_full_tunnel(&[normal]));
        assert!(has_full_tunnel(&[split]));
    }

    #[test]
    fn server_route_follows_the_best_physical_default() {
        let slower = Route::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
            .with_gateway(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
            .with_if_index(2)
            .with_metric(600);
        let faster = Route::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
            .with_gateway(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
            .with_if_index(3)
            .with_metric(100);
        let route = server_route(Ipv4Addr::new(203, 0, 113, 7), &[slower, faster]).unwrap();
        assert_eq!(
            route.gateway(),
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
        );
        assert_eq!(route.if_index(), Some(3));
    }

    #[test]
    fn crash_repair_only_owns_the_marked_server_route() {
        let server = Ipv4Addr::new(203, 0, 113, 7);
        let owned = Route::new(IpAddr::V4(server), 32).with_metric(4_242);
        let user = Route::new(IpAddr::V4(server), 32).with_metric(100);
        assert!(is_owned_server_route(&owned, server));
        assert!(!is_owned_server_route(&user, server));
    }
}
