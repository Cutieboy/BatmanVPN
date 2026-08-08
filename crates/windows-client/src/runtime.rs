use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use mousevpn_config::ValidatedClientConfig;
use wintun::Adapter;

use crate::{
    handshake::connect,
    network::{self, NetworkGuard, RuntimeLock, ADAPTER_NAME},
    packet_loop,
    platform::{ensure_supported_runtime, materialize_wintun},
    ClientError,
};

const ADAPTER_TUNNEL_TYPE: &str = "MouseVPN";

pub use crate::platform::{diagnose, RuntimeDiagnostics};

/// Starts a full Windows tunnel and runs until `stopping` is set.
///
/// # Errors
///
/// Returns an error when elevation, Wintun, handshake, firewall, routing, DNS,
/// UDP or packet processing fails.
pub fn run_with_stop(
    config: &ValidatedClientConfig,
    stopping: &Arc<AtomicBool>,
) -> Result<(), ClientError> {
    ensure_supported_runtime()?;
    let _runtime_lock = RuntimeLock::acquire()?;
    network::recover_stale_state()?;
    let server_ip = match config.server.ip() {
        std::net::IpAddr::V4(address) => address,
        std::net::IpAddr::V6(_) => {
            return Err(ClientError::Platform(
                "IPv6 server endpoints are not supported by the Windows client".to_owned(),
            ));
        }
    };

    let (incoming, plane, parameters) = connect(config)?;
    incoming.set_read_timeout(Some(packet_loop::UDP_POLL))?;
    let outgoing = incoming.try_clone()?;
    let wintun_path = materialize_wintun()?;
    let wintun = unsafe { wintun::load_from_path(&wintun_path) }
        .map_err(|error| ClientError::Platform(format!("failed to load wintun.dll: {error}")))?;
    let adapter = Adapter::open(&wintun, ADAPTER_NAME)
        .or_else(|_| Adapter::create(&wintun, ADAPTER_NAME, ADAPTER_TUNNEL_TYPE, None))
        .map_err(|error| {
            ClientError::Platform(format!("failed to create Wintun adapter: {error}"))
        })?;
    adapter
        .set_mtu(usize::from(parameters.mtu))
        .map_err(|error| ClientError::Platform(format!("failed to set Wintun MTU: {error}")))?;
    let session = Arc::new(
        adapter
            .start_session(wintun::MAX_RING_CAPACITY)
            .map_err(|error| ClientError::Platform(format!("failed to start Wintun: {error}")))?,
    );
    let network = NetworkGuard::install(server_ip, config.server.port(), parameters)?;
    let result = packet_loop::run(
        config,
        incoming,
        outgoing,
        plane,
        parameters,
        Arc::clone(&session),
        stopping,
        &network,
    );
    stopping.store(true, Ordering::Release);
    let _ = session.shutdown();
    result
}

/// Removes stale `MouseVPN` routes, DNS settings and firewall rules.
///
/// # Errors
///
/// Returns an error when elevation, locking or Windows network cleanup fails.
pub fn repair_network() -> Result<(), ClientError> {
    ensure_supported_runtime()?;
    let _runtime_lock = RuntimeLock::acquire()?;
    network::repair()
}

/// Returns a compact JSON snapshot of active `MouseVPN` network policy.
///
/// # Errors
///
/// Returns an error if PowerShell cannot query the Windows network state.
pub fn network_report() -> Result<String, ClientError> {
    ensure_supported_runtime()?;
    network::report()
}
