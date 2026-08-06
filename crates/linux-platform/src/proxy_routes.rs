use std::{io, process::Command};

pub const PROXY_MARK: u32 = 0x4d_56_50;
const PROXY_MARK_TEXT: &str = "0x4d5650";
const ROUTING_TABLE: &str = "51821";
const RULE_PRIORITY: &str = "10000";

pub struct ProxyRouteGuard {
    tun_name: String,
}

impl ProxyRouteGuard {
    /// Routes only sockets carrying the `MouseVPN` proxy mark through TUN.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsafe interface name or a failed `ip` command.
    pub fn install(tun_name: &str) -> io::Result<Self> {
        if !valid_interface_name(tun_name) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid TUN interface name",
            ));
        }
        run_ip(&[
            "-4",
            "route",
            "add",
            "default",
            "dev",
            tun_name,
            "table",
            ROUTING_TABLE,
        ])?;
        if let Err(error) = run_ip(&[
            "-4",
            "rule",
            "add",
            "priority",
            RULE_PRIORITY,
            "fwmark",
            PROXY_MARK_TEXT,
            "lookup",
            ROUTING_TABLE,
        ]) {
            let _ = delete_route(tun_name);
            return Err(error);
        }
        Ok(Self {
            tun_name: tun_name.to_owned(),
        })
    }
}

impl Drop for ProxyRouteGuard {
    fn drop(&mut self) {
        let _ = run_ip(&[
            "-4",
            "rule",
            "del",
            "priority",
            RULE_PRIORITY,
            "fwmark",
            PROXY_MARK_TEXT,
            "lookup",
            ROUTING_TABLE,
        ]);
        let _ = delete_route(&self.tun_name);
    }
}

fn delete_route(tun_name: &str) -> io::Result<()> {
    run_ip(&[
        "-4",
        "route",
        "del",
        "default",
        "dev",
        tun_name,
        "table",
        ROUTING_TABLE,
    ])
}

fn run_ip(arguments: &[&str]) -> io::Result<()> {
    let output = Command::new("ip").args(arguments).output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "ip {} failed: {}",
            arguments.join(" "),
            String::from_utf8_lossy(&output.stderr).trim(),
        )))
    }
}

fn valid_interface_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

#[cfg(test)]
mod tests {
    use super::valid_interface_name;

    #[test]
    fn validates_proxy_tun_names() {
        assert!(valid_interface_name("mousevpn0"));
        assert!(!valid_interface_name("bad/name"));
        assert!(!valid_interface_name("interface-name-is-too-long"));
    }
}
