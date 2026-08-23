//! Prints live `WinDivert` flow events, to validate split tunnelling on a real
//! machine before any of it reaches the connection path.
//!
//! Requires Administrator: opening the first `WinDivert` handle installs and
//! starts the driver service. `WinDivert.dll` and `WinDivert64.sys` must sit
//! next to this executable.
//!
//! ```text
//! cargo build -p mousevpn-windows-client --example flow_probe
//! ```

fn main() {
    #[cfg(windows)]
    {
        let seconds = std::env::args()
            .nth(1)
            .and_then(|value| value.parse().ok())
            .unwrap_or(30);
        if let Err(error) = mousevpn_windows_client::probe_split_tunnel_flows(seconds) {
            eprintln!("flow probe failed: {error}");
            std::process::exit(1);
        }
    }

    #[cfg(not(windows))]
    eprintln!("the flow probe only runs on Windows");
}
