use std::{io, net::Ipv4Addr, process::Command};

pub struct DnsGuard {
    interface: String,
}

impl DnsGuard {
    /// Makes one TUN link the systemd-resolved default DNS route.
    ///
    /// The link-specific settings are reverted when the guard is dropped.
    ///
    /// # Errors
    ///
    /// Returns an error when `resolvectl` is unavailable or rejects a setting.
    pub fn install(interface: &str, dns: Ipv4Addr) -> io::Result<Self> {
        if !valid_interface_name(interface) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid DNS interface name",
            ));
        }

        let guard = Self {
            interface: interface.to_owned(),
        };
        Self::run(&["dns", interface, &dns.to_string()])?;
        if let Err(error) = Self::run(&["domain", interface, "~."]) {
            drop(guard);
            return Err(error);
        }
        if let Err(error) = Self::run(&["default-route", interface, "yes"]) {
            drop(guard);
            return Err(error);
        }
        Ok(guard)
    }

    fn run(arguments: &[&str]) -> io::Result<()> {
        let output = Command::new("resolvectl").args(arguments).output()?;
        if output.status.success() {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "resolvectl failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )))
        }
    }
}

impl Drop for DnsGuard {
    fn drop(&mut self) {
        let _ = Command::new("resolvectl")
            .args(["revert", &self.interface])
            .status();
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
    fn validates_dns_interface_names() {
        assert!(valid_interface_name("mousevpn0"));
        assert!(!valid_interface_name("bad/name"));
    }
}
