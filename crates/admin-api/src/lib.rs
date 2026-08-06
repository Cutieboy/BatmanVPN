#![doc = "Authenticated localhost administration API for `MouseVPN`."]

mod auth;
mod error;
mod handlers;
mod models;
mod state;

use std::sync::{Arc, Mutex};

use axum::{
    routing::{delete, post},
    Router,
};
use mousevpn_server::ServerState;

pub use auth::{AdminToken, TokenError};
use handlers::{create_user, provision_device, revoke_device, revoke_user};
use state::ApiState;

pub fn router(server: Arc<Mutex<ServerState>>, token: AdminToken) -> Router {
    let state = ApiState::new(server, token);
    Router::new()
        .route("/v1/users", post(create_user))
        .route("/v1/users/{user_id}/devices", post(provision_device))
        .route("/v1/users/{user_id}", delete(revoke_user))
        .route("/v1/devices/{public_key}", delete(revoke_device))
        .with_state(state)
}
