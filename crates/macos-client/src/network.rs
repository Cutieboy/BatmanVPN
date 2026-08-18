use std::{io, net::Ipv4Addr, process::Command};

pub(crate) struct NetworkConfiguration {
    routes: RouteGuard,
    dns: Option<DnsGuard>,
}

impl NetworkConfiguration {
    pub(crate) fn install(
        tunnel: &str,
        server: Ipv4Addr,
        dns: Ipv4Addr,
    ) -> Result<Self, io::Error> {
        let default = default_route()?;
        let routes = RouteGuard::install(tunnel, server, &default)?;
        let dns = DnsGuard::install(&default.interface, dns)?;
        Ok(Self { routes, dns })
    }

    pub(crate) fn refresh_server_route(&mut self, server: Ipv4Addr) -> Result<(), io::Error> {
        self.routes.refresh_server(server)
    }
}

pub(crate) fn primary_ipv4() -> Result<Ipv4Addr, io::Error> {
    let default = default_route()?;
    let details = output("/sbin/ifconfig", &[&default.interface])?;
    details
        .lines()
        .find_map(|line| {
            let mut fields = line.split_whitespace();
            (fields.next() == Some("inet"))
                .then(|| fields.next())
                .flatten()
                .and_then(|value| value.parse().ok())
        })
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!(
                    "physical interface {} has no IPv4 address",
                    default.interface
                ),
            )
        })
}

impl Drop for NetworkConfiguration {
    fn drop(&mut self) {
        self.dns.take();
        self.routes.remove();
    }
}

struct DefaultRoute {
    gateway: Option<String>,
    interface: String,
}

struct RouteGuard {
    installed: Vec<InstalledRoute>,
}

enum InstalledRoute {
    Server(Ipv4Addr),
    Ipv4Network(&'static str),
    Ipv6Network(&'static str),
}

impl RouteGuard {
    fn install(tunnel: &str, server: Ipv4Addr, default: &DefaultRoute) -> Result<Self, io::Error> {
        let server_text = server.to_string();
        let mut guard = Self {
            installed: Vec::with_capacity(5),
        };
        if let Some(gateway) = &default.gateway {
            add_route(&["-host", &server_text, gateway])?;
        } else {
            add_route(&["-host", &server_text, "-interface", &default.interface])?;
        }
        guard.installed.push(InstalledRoute::Server(server));
        add_route(&["-net", "0.0.0.0/1", "-interface", tunnel])?;
        guard
            .installed
            .push(InstalledRoute::Ipv4Network("0.0.0.0/1"));
        add_route(&["-net", "128.0.0.0/1", "-interface", tunnel])?;
        guard
            .installed
            .push(InstalledRoute::Ipv4Network("128.0.0.0/1"));
        // Protocol v1 carries IPv4 only. More-specific IPv6 routes send IPv6
        // into utun where the packet loop deliberately drops it, preventing bypass.
        add_route(&["-inet6", "-net", "::/1", "-interface", tunnel])?;
        guard.installed.push(InstalledRoute::Ipv6Network("::/1"));
        add_route(&["-inet6", "-net", "8000::/1", "-interface", tunnel])?;
        guard
            .installed
            .push(InstalledRoute::Ipv6Network("8000::/1"));
        Ok(guard)
    }

    fn refresh_server(&mut self, server: Ipv4Addr) -> Result<(), io::Error> {
        if let Some(index) = self
            .installed
            .iter()
            .position(|route| matches!(route, InstalledRoute::Server(_)))
        {
            if let InstalledRoute::Server(previous) = self.installed.remove(index) {
                delete_route(&["-host", &previous.to_string()]);
            }
        }
        let default = default_route()?;
        let server_text = server.to_string();
        if let Some(gateway) = &default.gateway {
            add_route(&["-host", &server_text, gateway])?;
        } else {
            add_route(&["-host", &server_text, "-interface", &default.interface])?;
        }
        self.installed.insert(0, InstalledRoute::Server(server));
        Ok(())
    }

    fn remove(&mut self) {
        while let Some(route) = self.installed.pop() {
            match route {
                InstalledRoute::Server(server) => delete_route(&["-host", &server.to_string()]),
                InstalledRoute::Ipv4Network(network) => delete_route(&["-net", network]),
                InstalledRoute::Ipv6Network(network) => {
                    delete_route(&["-inet6", "-net", network]);
                }
            }
        }
    }
}

impl Drop for RouteGuard {
    fn drop(&mut self) {
        self.remove();
    }
}

struct DnsGuard {
    service: String,
    previous: Vec<String>,
}

impl DnsGuard {
    fn install(interface: &str, dns: Ipv4Addr) -> Result<Option<Self>, io::Error> {
        let Some(service) = service_for_interface(interface)? else {
            eprintln!(
                "MOUSEVPN_POLICY_WARNING=network service for {interface} was not found; DNS was not changed"
            );
            return Ok(None);
        };
        let current = output("/usr/sbin/networksetup", &["-getdnsservers", &service])?;
        let previous = if current.starts_with("There aren't any DNS Servers set on") {
            Vec::new()
        } else {
            current
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .map(str::to_owned)
                .collect()
        };
        run(
            "/usr/sbin/networksetup",
            &["-setdnsservers", &service, &dns.to_string()],
        )?;
        Ok(Some(Self { service, previous }))
    }
}

impl Drop for DnsGuard {
    fn drop(&mut self) {
        let mut arguments = vec!["-setdnsservers", self.service.as_str()];
        if self.previous.is_empty() {
            arguments.push("Empty");
        } else {
            arguments.extend(self.previous.iter().map(String::as_str));
        }
        if let Err(error) = run("/usr/sbin/networksetup", &arguments) {
            eprintln!("MOUSEVPN_POLICY_WARNING=restoring DNS failed: {error}");
        }
    }
}

fn default_route() -> Result<DefaultRoute, io::Error> {
    let route = output("/sbin/route", &["-n", "get", "default"])?;
    let gateway = field(&route, "gateway:");
    let interface = field(&route, "interface:").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "could not determine the default network interface",
        )
    })?;
    Ok(DefaultRoute { gateway, interface })
}

fn service_for_interface(interface: &str) -> Result<Option<String>, io::Error> {
    let order = output("/usr/sbin/networksetup", &["-listnetworkserviceorder"])?;
    let mut service = None;
    for line in order.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('(') && !trimmed.starts_with("(Hardware Port:") {
            service = trimmed
                .split_once(") ")
                .map(|(_, name)| name.trim_start_matches('*').trim().to_owned());
        } else if trimmed.contains(&format!("Device: {interface})")) {
            return Ok(service);
        }
    }
    Ok(None)
}

fn field(text: &str, name: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let line = line.trim();
        line.strip_prefix(name).map(str::trim).map(str::to_owned)
    })
}

fn add_route(arguments: &[&str]) -> Result<(), io::Error> {
    let mut full_arguments = vec!["-n", "add"];
    full_arguments.extend_from_slice(arguments);
    let result = Command::new("/sbin/route").args(&full_arguments).output()?;
    if result.status.success() {
        return Ok(());
    }
    let error = String::from_utf8_lossy(&result.stderr);
    if error.contains("File exists") {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "маршрут уже занят другим VPN: route {}",
                arguments.join(" ")
            ),
        ));
    }
    Err(command_error("/sbin/route", &full_arguments, &error))
}

fn delete_route(arguments: &[&str]) {
    let mut full_arguments = vec!["-n", "delete"];
    full_arguments.extend_from_slice(arguments);
    let _ = Command::new("/sbin/route").args(full_arguments).output();
}

fn output(program: &str, arguments: &[&str]) -> Result<String, io::Error> {
    let output = Command::new(program).args(arguments).output()?;
    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned());
    }
    Err(command_error(
        program,
        arguments,
        &String::from_utf8_lossy(&output.stderr),
    ))
}

fn run(program: &str, arguments: &[&str]) -> Result<(), io::Error> {
    output(program, arguments).map(drop)
}

fn command_error(program: &str, arguments: &[&str], error: &str) -> io::Error {
    io::Error::other(format!(
        "{} {} failed: {}",
        program,
        arguments.join(" "),
        error.trim()
    ))
}
