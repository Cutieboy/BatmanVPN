use std::sync::{Arc, Mutex};

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use http_body_util::BodyExt;
use mousevpn_admin_api::{router, AdminToken};
use mousevpn_server::ServerState;
use serde_json::Value;
use tower::ServiceExt;

const TOKEN: &str = "0123456789abcdef0123456789abcdef";

#[tokio::test]
async fn requires_admin_token() {
    let state = Arc::new(Mutex::new(ServerState::new(8)));
    let app = router(state, AdminToken::new(TOKEN).expect("admin token"));
    let request = Request::builder()
        .method(Method::POST)
        .uri("/v1/users")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"name":"friend","max_sessions":1}"#))
        .expect("request");

    let response = app.oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn provisions_and_revokes_device_and_user() {
    let state = Arc::new(Mutex::new(ServerState::new(8)));
    let app = router(
        Arc::clone(&state),
        AdminToken::new(TOKEN).expect("admin token"),
    );

    let user = send_json(
        &app,
        Method::POST,
        "/v1/users",
        Some(r#"{"name":"alice","max_sessions":2}"#),
    )
    .await;
    assert_eq!(user["name"], "alice");
    let user_id = user["id"].as_u64().expect("user ID");

    let device = send_json(
        &app,
        Method::POST,
        &format!("/v1/users/{user_id}/devices"),
        None,
    )
    .await;
    let public_key = device["public_key"].as_str().expect("public key");
    let secret_key = device["secret_key"].as_str().expect("secret key");
    assert_eq!(
        URL_SAFE_NO_PAD
            .decode(public_key)
            .expect("public key")
            .len(),
        32
    );
    assert_eq!(
        URL_SAFE_NO_PAD
            .decode(secret_key)
            .expect("secret key")
            .len(),
        32
    );

    let revoked_device = send_json(
        &app,
        Method::DELETE,
        &format!("/v1/devices/{public_key}"),
        None,
    )
    .await;
    assert_eq!(revoked_device["revoked"], true);

    let revoked_user = send_json(&app, Method::DELETE, &format!("/v1/users/{user_id}"), None).await;
    assert_eq!(revoked_user["revoked"], true);
    let state = state.lock().expect("server state");
    assert_eq!(state.user_count(), 0);
    assert_eq!(state.device_count(), 0);
}

async fn send_json(app: &axum::Router, method: Method, uri: &str, body: Option<&str>) -> Value {
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.unwrap_or_default().to_owned()))
        .expect("request");
    let response = app.clone().oneshot(request).await.expect("response");
    assert!(
        response.status().is_success(),
        "status: {}",
        response.status()
    );
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    serde_json::from_slice(&bytes).expect("JSON response")
}
