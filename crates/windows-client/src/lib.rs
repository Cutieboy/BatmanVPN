#![doc = "Windows `MouseVPN` client runtime."]

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

#[cfg(not(windows))]
pub use platform_stub::{
    diagnose, network_report, repair_network, run_with_stop, RuntimeDiagnostics,
};
#[cfg(windows)]
pub use runtime::{diagnose, network_report, repair_network, run_with_stop, RuntimeDiagnostics};
