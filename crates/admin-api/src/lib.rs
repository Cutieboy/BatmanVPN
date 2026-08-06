#![doc = "Authenticated localhost administration API for `MouseVPN`."]

mod auth;
mod error;
mod handlers;
mod models;
mod registry;
mod registry_store;
mod state;
mod ui;

use std::{io, net::SocketAddr, thread};

use axum::{
    routing::{delete, get},
    Router,
};

pub use auth::{AdminToken, TokenError};
use handlers::{health, list_devices, provision_device, revoke_device};
pub use registry::{
    DeviceAuthorization, DeviceLease, DevicePlatform, DeviceRecord, ProvisionedDevice, SeedDevice,
    SharedDeviceRegistry,
};
pub use registry_store::RegistryError;
pub use state::AdminSettings;
use state::ApiState;
use ui::admin_page;

pub fn router(
    registry: SharedDeviceRegistry,
    token: AdminToken,
    settings: AdminSettings,
) -> Router {
    let state = ApiState::new(registry, token, settings);
    Router::new()
        .route("/", get(admin_page))
        .route("/v1/health", get(health))
        .route("/v1/devices", get(list_devices).post(provision_device))
        .route("/v1/devices/{public_key}", delete(revoke_device))
        .with_state(state)
}

/// Starts the admin HTTP listener in a dedicated runtime thread.
///
/// # Errors
///
/// Returns an error if the private listener cannot be bound or configured.
pub fn spawn(
    address: SocketAddr,
    registry: SharedDeviceRegistry,
    token: AdminToken,
    settings: AdminSettings,
) -> io::Result<thread::JoinHandle<()>> {
    let listener = std::net::TcpListener::bind(address)?;
    listener.set_nonblocking(true)?;
    Ok(thread::spawn(move || {
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(error) => {
                eprintln!("MouseVPN admin runtime failed: {error}");
                return;
            }
        };
        runtime.block_on(async move {
            let listener = match tokio::net::TcpListener::from_std(listener) {
                Ok(listener) => listener,
                Err(error) => {
                    eprintln!("MouseVPN admin listener failed: {error}");
                    return;
                }
            };
            eprintln!("MouseVPN admin listening on http://{address}");
            if let Err(error) = axum::serve(listener, router(registry, token, settings)).await {
                eprintln!("MouseVPN admin stopped: {error}");
            }
        });
    }))
}
