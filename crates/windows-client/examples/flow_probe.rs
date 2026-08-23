//! Prints live `WinDivert` flow events and the verdict the policy gives each
//! one, to tell a misrouted application apart from a broken tunnel.
//!
//! Requires Administrator: opening the first `WinDivert` handle installs and
//! starts the driver service. `WinDivert.dll` and `WinDivert64.sys` must sit
//! next to this executable. It only observes; nothing is tunnelled, so it is
//! safe to run beside a live session.
//!
//! ```text
//! flow_probe.exe 30 --include "C:\Users\me\AppData\Roaming\Telegram Desktop\Telegram.exe"
//! ```

fn main() {
    #[cfg(windows)]
    {
        match windows::arguments() {
            Ok((seconds, policy)) => {
                if let Err(error) =
                    mousevpn_windows_client::probe_split_tunnel_flows(seconds, &policy)
                {
                    eprintln!("flow probe failed: {error}");
                    std::process::exit(1);
                }
            }
            Err(usage) => {
                eprintln!("{usage}");
                std::process::exit(2);
            }
        }
    }

    #[cfg(not(windows))]
    eprintln!("the flow probe only runs on Windows");
}

#[cfg(windows)]
mod windows {
    use std::path::PathBuf;

    use mousevpn_windows_client::{AppRoutingMode, AppRoutingPolicy};

    /// Reads an optional duration followed by the policy to judge flows by.
    ///
    /// With no policy every flow reads `direct`, which still answers whether
    /// the flow layer sees an application at all.
    pub(super) fn arguments() -> Result<(u64, AppRoutingPolicy), String> {
        let values: Vec<String> = std::env::args().skip(1).collect();
        let mut seconds = 30;
        let mut policy = AppRoutingPolicy::default();
        let mut index = 0;
        if let Some(first) = values.first() {
            if let Ok(parsed) = first.parse() {
                seconds = parsed;
                index = 1;
            }
        }
        while index < values.len() {
            let mode = match values[index].as_str() {
                "--include" => AppRoutingMode::Include,
                "--exclude" => AppRoutingMode::Exclude,
                other => return Err(format!("unexpected argument {other}\n{}", usage())),
            };
            let Some(path) = values.get(index + 1) else {
                return Err(usage());
            };
            policy.mode = mode;
            policy.apps.push(PathBuf::from(path));
            index += 2;
        }
        Ok((seconds, policy))
    }

    fn usage() -> String {
        "usage: flow_probe [seconds] [(--include | --exclude) <app.exe>]...".to_owned()
    }
}
