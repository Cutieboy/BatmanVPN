use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    Json,
};
use mousevpn_config::encode_secret_key;
use mousevpn_profile_cli::{encrypt_profile, PortableProfile};
use serde::Deserialize;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::{
    error::ApiError,
    models::{
        CreateDeviceRequest, DeviceSummary, HealthResponse, ProvisionDeviceResponse, RevokeResponse,
    },
    state::ApiState,
    traffic::{TrafficReport, MAX_QUERY_HOURS},
};

#[derive(Debug, Default, Deserialize)]
pub(crate) struct TrafficQuery {
    hours: Option<u64>,
}

pub(crate) async fn health(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Result<Json<HealthResponse>, ApiError> {
    authenticate(&headers, &state)?;
    Ok(Json(HealthResponse { status: "ok" }))
}

pub(crate) async fn list_devices(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Result<Json<Vec<DeviceSummary>>, ApiError> {
    authenticate(&headers, &state)?;
    let devices = state
        .registry
        .list()
        .map_err(ApiError::internal_with)?
        .into_iter()
        .map(DeviceSummary::from)
        .collect();
    Ok(Json(devices))
}

pub(crate) async fn traffic(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(query): Query<TrafficQuery>,
) -> Result<Json<TrafficReport>, ApiError> {
    authenticate(&headers, &state)?;
    let hours = query.hours.unwrap_or(24);
    if hours == 0 || hours > MAX_QUERY_HOURS {
        return Err(ApiError::bad_request(format!(
            "hours must be between 1 and {MAX_QUERY_HOURS}"
        )));
    }
    state
        .traffic
        .report(hours)
        .map(Json)
        .map_err(ApiError::internal_with)
}

pub(crate) async fn provision_device(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(mut request): Json<CreateDeviceRequest>,
) -> Result<Json<ProvisionDeviceResponse>, ApiError> {
    authenticate(&headers, &state)?;
    if matches!(request.platform, crate::DevicePlatform::Android)
        && request.profile_password.is_none()
    {
        return Err(ApiError::bad_request(
            "Android profile requires a password of at least 8 characters",
        ));
    }
    if request
        .profile_password
        .as_ref()
        .is_some_and(|password| password.len() < 8)
    {
        return Err(ApiError::bad_request(
            "profile password must contain at least 8 characters",
        ));
    }
    let provisioned = state
        .registry
        .provision(&request.name, request.platform)
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    let client_private_key = encode_secret_key(&provisioned.private_key);
    let client_config = format!(
        "server = \"{}\"\nserver_public_key = \"{}\"\nclient_private_key = \"{}\"\ntun_name = \"{}\"\n# legacy | morph_quiet | morph_balanced | morph_paranoid\nprotocol = \"legacy\"\n",
        state.settings.public_endpoint,
        state.settings.server_public_key,
        client_private_key,
        state.settings.tun_name,
    );
    let profile = PortableProfile::new(
        &provisioned.record.name,
        state.settings.public_endpoint.to_string(),
        &state.settings.server_public_key,
        &client_private_key,
    );
    let profile_token = if let Some(mut password) = request.profile_password.take() {
        let result = encrypt_profile(&profile, password.as_bytes());
        password.zeroize();
        Some(result.map_err(ApiError::internal_with)?)
    } else {
        None
    };
    Ok(Json(ProvisionDeviceResponse {
        device: DeviceSummary::from(provisioned.record),
        client_config,
        profile_token,
    }))
}

pub(crate) async fn revoke_device(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(public_key): Path<String>,
) -> Result<Json<RevokeResponse>, ApiError> {
    authenticate(&headers, &state)?;
    let revoked = state
        .registry
        .revoke(&public_key)
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    if !revoked {
        return Err(ApiError::not_found("device key not found"));
    }
    Ok(Json(RevokeResponse { revoked }))
}

fn authenticate(headers: &HeaderMap, state: &ApiState) -> Result<(), ApiError> {
    let candidate = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or_else(ApiError::unauthorized)?;
    if bool::from(candidate.as_bytes().ct_eq(state.token.as_ref())) {
        Ok(())
    } else {
        Err(ApiError::unauthorized())
    }
}
