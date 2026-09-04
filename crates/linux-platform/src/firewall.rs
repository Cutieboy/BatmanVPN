use std::{
    io::{self, Write},
    net::Ipv4Addr,
    process::{Command, Stdio},
};

const TABLE_NAME: &str = "mousevpn_client_runtime";

pub struct FirewallGuard;

impl FirewallGuard {
    /// Installs a fail-closed output policy with direct access to the server IP.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsafe interface name or failed nft invocation.
    pub fn install(server: Ipv4Addr, tun_name: &str) -> io::Result<Self> {
        if !valid_interface_name(tun_name) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid TUN interface name",
            ));
        }
        let rules = render_rules(server, tun_name);
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

/// Renders the fail-closed output policy.
///
/// The server's /32 route bypasses the tunnel. Allow all traffic to that one
/// address so websites and other services hosted there remain reachable too.
/// Other IPv4 destinations still require the tunnel (except DHCP renewal).
///
/// The tunnel carries IPv4 only, so global IPv6 must not leave the box. It is
/// rejected rather than dropped: a dropped SYN leaves every dual-stack client
/// hanging on its connect timeout, which reads as "the VPN is slow". Link-local
/// and multicast IPv6 stay allowed so neighbour discovery keeps working and the
/// network manager does not tear the physical link down under us.
///
/// IPv4 DHCP renewal is unicast UDP from a normal socket, so the output hook
/// sees it. Dropping it silently expired the lease on long sessions and killed
/// the tunnel from underneath.
fn render_rules(server: Ipv4Addr, tun_name: &str) -> String {
    format!(
        "table inet {TABLE_NAME} {{\n\
         \x20 chain output {{\n\
         \x20   type filter hook output priority -50; policy drop;\n\
         \x20   oifname \"lo\" accept\n\
         \x20   oifname \"{tun_name}\" accept\n\
         \x20   ip daddr {server} accept\n\
         \x20   meta nfproto ipv4 udp sport 68 udp dport 67 accept\n\
         \x20   ip6 daddr fe80::/10 accept\n\
         \x20   ip6 daddr ff02::/16 accept\n\
         \x20   meta nfproto ipv6 reject with icmpx type no-route\n\
         \x20 }}\n\
         }}\n"
    )
}

pub(crate) fn remove_runtime_table() -> io::Result<()> {
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
    use std::net::Ipv4Addr;

    use super::{render_rules, valid_interface_name};

    #[test]
    fn rejects_global_ipv6_but_keeps_discovery_and_dhcp() {
        let rules = render_rules(Ipv4Addr::new(203, 0, 113, 7), "mousevpn0");
        assert!(rules.contains("meta nfproto ipv6 reject with icmpx type no-route"));
        assert!(rules.contains("ip6 daddr fe80::/10 accept"));
        assert!(rules.contains("ip6 daddr ff02::/16 accept"));
        assert!(!rules.contains("ip6 daddr ff00::/8 accept"));
        assert!(rules.contains("meta nfproto ipv4 udp sport 68 udp dport 67 accept"));
        // The reject must not shadow loopback or the tunnel itself.
        let reject = rules.find("nfproto ipv6 reject").expect("reject rule");
        assert!(rules.find("oifname \"lo\" accept").expect("lo rule") < reject);
        assert!(
            rules
                .find("ip daddr 203.0.113.7 accept")
                .expect("server rule")
                < reject
        );
    }

    #[test]
    fn validates_interface_names_before_rendering_rules() {
        assert!(valid_interface_name("mousevpn0"));
        assert!(!valid_interface_name("bad\"name"));
        assert!(!valid_interface_name("interface-name-is-too-long"));
    }
}
