#![doc = "Windows `MouseVPN` client runtime."]

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[cfg(windows)]
mod app_bypass;
#[cfg(not(windows))]
#[path = "app_bypass_stub.rs"]
mod app_bypass;
mod error;
#[cfg(windows)]
mod handshake;
mod liveness;
mod network;
#[cfg(windows)]
mod network_events;
#[cfg(windows)]
mod packet_loop;
#[cfg(windows)]
mod platform;

#[cfg(not(windows))]
mod platform_stub;
#[cfg(windows)]
mod runtime;

pub use error::ClientError;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AppRoutingMode {
    #[default]
    Exclude,
    Include,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AppRoutingPolicy {
    pub mode: AppRoutingMode,
    pub apps: Vec<PathBuf>,
}

/// Converts Rust's extended-length canonical Windows paths into the regular
/// DOS/UNC form expected by Windows Firewall and WFP application APIs.
#[must_use]
pub fn normalize_windows_path(path: &Path) -> PathBuf {
    let value = path.to_string_lossy().replace('/', "\\");
    if let Some(value) = value.strip_prefix(r"\\?\UNC\") {
        PathBuf::from(format!(r"\\{value}"))
    } else if let Some(value) = value.strip_prefix(r"\\?\") {
        PathBuf::from(value)
    } else {
        PathBuf::from(value)
    }
}

#[cfg(not(windows))]
pub use platform_stub::{
    diagnose, network_report, repair_network, run_with_stop, RuntimeDiagnostics,
};
#[cfg(windows)]
pub use runtime::{diagnose, network_report, repair_network, run_with_stop, RuntimeDiagnostics};

#[cfg(test)]
mod tests {
    use super::normalize_windows_path;
    use std::path::Path;

    #[test]
    fn removes_extended_drive_path_prefix() {
        assert_eq!(
            normalize_windows_path(Path::new(r"\\?\C:\Apps\Browser.exe")),
            Path::new(r"C:\Apps\Browser.exe")
        );
    }

    #[test]
    fn converts_extended_unc_path() {
        assert_eq!(
            normalize_windows_path(Path::new(r"\\?\UNC\server\share\Browser.exe")),
            Path::new(r"\\server\share\Browser.exe")
        );
    }
}
