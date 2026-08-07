use std::{
    io::{self, Write},
    net::Ipv4Addr,
    process::{Command, Stdio},
};

const TABLE_NAME: &str = "mousevpn_client_runtime";

pub struct FirewallGuard;

impl FirewallGuard {
    /// Installs a fail-closed nftables output policy for one VPN endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsafe interface name or failed nft invocation.
    pub fn install(server: Ipv4Addr, port: u16, tun_name: &str) -> io::Result<Self> {
        if !valid_interface_name(tun_name) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid TUN interface name",
            ));
        }
        let rules = format!(
            "table inet {TABLE_NAME} {{\n  chain output {{\n    type filter hook output priority -50; policy drop;\n    oifname \"lo\" accept\n    oifname \"{tun_name}\" accept\n    ip daddr {server} udp dport {port} accept\n  }}\n}}\n"
        );
        // A SIGKILL cannot run `Drop`, so only our isolated table may survive
        // an otherwise dead client. Removing it before the atomic recreation
        // makes the next connection self-healing without touching any other
        // firewall table or policy.
        remove_runtime_table()?;
        run_nft_script(&rules)?;
        Ok(Self)
    }
}

impl Drop for FirewallGuard {
    fn drop(&mut self) {
        let _ = remove_runtime_table();
    }
}

fn remove_runtime_table() -> io::Result<()> {
    let _status = Command::new("nft")
        .args(["delete", "table", "inet", TABLE_NAME])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    Ok(())
}

fn valid_interface_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn run_nft_script(rules: &str) -> io::Result<()> {
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("nft stdin is unavailable"))?
        .write_all(rules.as_bytes())?;
    let output = child.wait_with_output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "nft failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::valid_interface_name;

    #[test]
    fn validates_interface_names_before_rendering_rules() {
        assert!(valid_interface_name("mousevpn0"));
        assert!(!valid_interface_name("bad\"name"));
        assert!(!valid_interface_name("interface-name-is-too-long"));
    }
}
