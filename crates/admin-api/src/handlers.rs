use axum::{
    extract::{Path, State},
    http::{header::AUTHORIZATION, HeaderMap},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use mousevpn_crypto::{PublicKey, KEY_LEN};
use mousevpn_server::UserId;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::{
    error::ApiError,
    models::{CreateUserRequest, DeviceResponse, RevokeResponse, UserResponse},
    state::ApiState,
};

pub(crate) async fn create_user(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(request): Json<CreateUserRequest>,
) -> Result<Json<UserResponse>, ApiError> {
    authenticate(&headers, &state)?;
    let mut server = state.server.lock().map_err(|_| ApiError::internal())?;
    let user = server
        .create_user(request.name, request.max_sessions)
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    Ok(Json(UserResponse {
        id: user.id.0,
        name: user.name,
        max_sessions: user.max_sessions,
    }))
}

pub(crate) async fn provision_device(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(user_id): Path<u64>,
) -> Result<Json<DeviceResponse>, ApiError> {
    authenticate(&headers, &state)?;
    let mut server = state.server.lock().map_err(|_| ApiError::internal())?;
    let device = server
        .provision_device(UserId(user_id))
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    let mut secret = device.secret_key.expose_for_provisioning();
    let response = DeviceResponse {
        public_key: URL_SAFE_NO_PAD.encode(device.public_key.as_bytes()),
        secret_key: URL_SAFE_NO_PAD.encode(secret),
    };
    secret.zeroize();
    Ok(Json(response))
}

pub(crate) async fn revoke_user(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(user_id): Path<u64>,
) -> Result<Json<RevokeResponse>, ApiError> {
    authenticate(&headers, &state)?;
    let mut server = state.server.lock().map_err(|_| ApiError::internal())?;
    let result = server.revoke_user(UserId(user_id));
    if !result.revoked {
        return Err(ApiError::not_found("user not found"));
    }
    Ok(Json(RevokeResponse {
        revoked: result.revoked,
        closed_sessions: result.closed_sessions,
    }))
}

pub(crate) async fn revoke_device(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(encoded_key): Path<String>,
) -> Result<Json<RevokeResponse>, ApiError> {
    authenticate(&headers, &state)?;
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded_key)
        .map_err(|_| ApiError::bad_request("invalid public key encoding"))?;
    let key_bytes: [u8; KEY_LEN] = decoded
        .try_into()
        .map_err(|_| ApiError::bad_request("invalid public key length"))?;
    let mut server = state.server.lock().map_err(|_| ApiError::internal())?;
    let result = server.revoke_device(&PublicKey::from_bytes(key_bytes));
    if !result.revoked {
        return Err(ApiError::not_found("device key not found"));
    }
    Ok(Json(RevokeResponse {
        revoked: result.revoked,
        closed_sessions: result.closed_sessions,
    }))
}

fn authenticate(headers: &HeaderMap, state: &ApiState) -> Result<(), ApiError> {
    let candidate = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or_else(ApiError::unauthorized)?;
    if bool::from(candidate.as_bytes().ct_eq(state.token.as_ref())) {
        Ok(())
    } else {
        Err(ApiError::unauthorized())
    }
}
