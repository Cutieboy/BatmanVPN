use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

use mousevpn_client_wire::ClientWire;
use mousevpn_config::ValidatedClientConfig;
use wintun::Adapter;

use crate::{
    app_bypass::AppBypassGuard,
    handshake::connect,
    network::{self, NetworkGuard, RuntimeLock, ADAPTER_GUID, ADAPTER_NAME},
    packet_loop,
    platform::{ensure_supported_runtime, materialize_wintun},
    AppRoutingPolicy, ClientError,
};

const ADAPTER_TUNNEL_TYPE: &str = "MouseVPN";
const RESTART_BACKOFF_MIN: Duration = Duration::from_secs(1);
const RESTART_BACKOFF_MAX: Duration = Duration::from_secs(16);
const STABLE_RUNTIME: Duration = Duration::from_secs(60);

pub use crate::platform::{diagnose, RuntimeDiagnostics};

/// Starts a full Windows tunnel and runs until `stopping` is set.
///
/// # Errors
///
/// Returns an error when elevation, Wintun, handshake, firewall, routing, DNS,
/// UDP or packet processing fails.
#[allow(clippy::too_many_lines)]
pub fn run_with_stop(
    config: &ValidatedClientConfig,
    stopping: &Arc<AtomicBool>,
    app_routing: &AppRoutingPolicy,
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

    let wire = ClientWire::from_config(config)?;
    // Materialising wintun.dll and creating the device is a second or more of
    // driver work that does not depend on the session, so let the handshake run
    // beside it rather than after it.
    let (handshake, device) = thread::scope(|scope| {
        let handshake = scope.spawn(|| connect(config, &wire));
        let device = (|| {
            let wintun_path = materialize_wintun()?;
            let wintun = unsafe { wintun::load_from_path(&wintun_path) }.map_err(|error| {
                ClientError::Platform(format!("failed to load wintun.dll: {error}"))
            })?;
            let adapter = Adapter::open(&wintun, ADAPTER_NAME)
                .or_else(|_| {
                    Adapter::create(
                        &wintun,
                        ADAPTER_NAME,
                        ADAPTER_TUNNEL_TYPE,
                        Some(ADAPTER_GUID),
                    )
                })
                .map_err(|error| {
                    ClientError::Platform(format!("failed to create Wintun adapter: {error}"))
                })?;
            Ok::<_, ClientError>((wintun, adapter))
        })();
        (handshake.join(), device)
    });
    let (incoming, plane, mut parameters) = handshake.map_err(|_| {
        ClientError::Platform("the MouseVPN handshake thread panicked".to_owned())
    })??;
    let (_wintun, adapter) = device?;
    incoming.set_read_timeout(Some(packet_loop::UDP_POLL))?;
    let outgoing = incoming.try_clone()?;
    adapter
        .set_mtu(usize::from(parameters.mtu))
        .map_err(|error| ClientError::Platform(format!("failed to set Wintun MTU: {error}")))?;
    let mut session = Arc::new(
        adapter
            .start_session(wintun::MAX_RING_CAPACITY)
            .map_err(|error| ClientError::Platform(format!("failed to start Wintun: {error}")))?,
    );
    let app_bypass = AppBypassGuard::install(app_routing)?;
    let mut network = NetworkGuard::install(
        server_ip,
        config.server.port(),
        parameters,
        app_routing,
        app_bypass,
    )?;
    let mut transports = (incoming, outgoing, plane);
    let mut restart_backoff = RESTART_BACKOFF_MIN;

    loop {
        let started = Instant::now();
        let result = packet_loop::run(
            config,
            transports.0,
            transports.1,
            transports.2,
            parameters,
            &session,
            stopping,
            &mut network,
            &wire,
        );
        let _ = session.shutdown();
        // `Session::shutdown` only signals blocking readers to stop; the driver
        // does not release the session (WintunEndSession) until every `Arc`
        // handle to it is dropped. `packet_loop::run` has already dropped its
        // own clones by the time it returns, so this is the last one. Drop it
        // now rather than waiting for a successful retry to overwrite it below
        // — otherwise every `adapter.start_session` attempt below races the
        // still-live old session and fails with WintunStartSession forever.
        drop(session);
        if stopping.load(Ordering::Acquire) {
            return Ok(());
        }

        let message = match result {
            Ok(()) => "packet loop stopped unexpectedly".to_owned(),
            Err(error) => error.to_string(),
        };
        eprintln!("MOUSEVPN_RUNTIME_WARNING={message}");
        eprintln!("MOUSEVPN_STATE=failed_closed");
        eprintln!("MOUSEVPN_STATE=restarting");
        if started.elapsed() >= STABLE_RUNTIME {
            restart_backoff = RESTART_BACKOFF_MIN;
        }

        loop {
            if wait_for_stop(stopping, restart_backoff) {
                return Ok(());
            }
            if let Err(error) = network.refresh() {
                eprintln!("MOUSEVPN_POLICY_WARNING={error}");
                restart_backoff = (restart_backoff * 2).min(RESTART_BACKOFF_MAX);
                continue;
            }

            let attempt: Result<_, ClientError> = (|| {
                let (next_incoming, next_plane, next_parameters) = connect(config, &wire)?;
                next_incoming.set_read_timeout(Some(packet_loop::UDP_POLL))?;
                let next_outgoing = next_incoming.try_clone()?;
                adapter
                    .set_mtu(usize::from(next_parameters.mtu))
                    .map_err(|error| {
                        ClientError::Platform(format!("failed to restore Wintun MTU: {error}"))
                    })?;
                let next_session =
                    Arc::new(adapter.start_session(wintun::MAX_RING_CAPACITY).map_err(
                        |error| ClientError::Platform(format!("failed to restart Wintun: {error}")),
                    )?);
                Ok((
                    next_incoming,
                    next_outgoing,
                    next_plane,
                    next_session,
                    next_parameters,
                ))
            })();

            match attempt {
                Ok((next_incoming, next_outgoing, next_plane, next_session, next_parameters)) => {
                    if next_parameters != parameters {
                        if let Err(error) = network.update_parameters(next_parameters) {
                            let _ = adapter.set_mtu(usize::from(parameters.mtu));
                            eprintln!("MOUSEVPN_RUNTIME_WARNING={error}");
                            restart_backoff = (restart_backoff * 2).min(RESTART_BACKOFF_MAX);
                            continue;
                        }
                        parameters = next_parameters;
                        eprintln!("MOUSEVPN_STATE=parameters_updated");
                    }
                    transports = (next_incoming, next_outgoing, next_plane);
                    session = next_session;
                    restart_backoff = RESTART_BACKOFF_MIN;
                    break;
                }
                Err(error) => {
                    eprintln!("MOUSEVPN_RUNTIME_WARNING={error}");
                    restart_backoff = (restart_backoff * 2).min(RESTART_BACKOFF_MAX);
                }
            }
        }
    }
}

fn wait_for_stop(stopping: &AtomicBool, duration: Duration) -> bool {
    let deadline = Instant::now() + duration;
    while !stopping.load(Ordering::Acquire) {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return false;
        }
        thread::sleep(remaining.min(Duration::from_millis(100)));
    }
    true
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
