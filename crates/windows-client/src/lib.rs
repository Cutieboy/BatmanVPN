#![doc = "Windows `MouseVPN` client runtime."]

use std::path::PathBuf;

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

#[cfg(not(windows))]
pub use platform_stub::{
    diagnose, network_report, repair_network, run_with_stop, RuntimeDiagnostics,
};
#[cfg(windows)]
pub use runtime::{diagnose, network_report, repair_network, run_with_stop, RuntimeDiagnostics};
