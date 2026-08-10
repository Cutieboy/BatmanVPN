use std::{net::SocketAddr, path::Path};

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
};
use http_body_util::BodyExt;
use mousevpn_admin_api::{
    router, AdminSettings, AdminToken, DevicePlatform, SeedDevice, SharedDeviceRegistry,
    TrafficStore,
};
use mousevpn_config::decode_public_key;
use mousevpn_crypto::KeyPair;
use serde_json::Value;
use tempfile::TempDir;
use tower::ServiceExt;

const TOKEN: &str = "0123456789abcdef0123456789abcdef";

#[tokio::test]
async fn requires_admin_token() {
    let temporary = TempDir::new().expect("temporary directory");
    let app = test_router(&temporary);
    let request = Request::builder()
        .method(Method::GET)
        .uri("/v1/devices")
        .body(Body::empty())
        .expect("request");

    let response = app.oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn provisions_lists_and_revokes_persistent_devices() {
    let temporary = TempDir::new().expect("temporary directory");
    let app = test_router(&temporary);

    let device = send_json(
        &app,
        Method::POST,
        "/v1/devices",
        Some(r#"{"name":"Alice phone","platform":"android","profile_password":"correct horse"}"#),
    )
    .await;
    assert_eq!(device["device"]["name"], "Alice phone");
    assert_eq!(device["device"]["address"], "10.77.0.3");
    assert!(device["profile_token"]
        .as_str()
        .expect("profile token")
        .starts_with("MV1."));
    assert!(device["client_config"]
        .as_str()
        .expect("client config")
        .contains("198.51.100.10:51820"));

    let devices = send_json(&app, Method::GET, "/v1/devices", None).await;
    assert_eq!(devices.as_array().expect("devices").len(), 2);
    let public_key = device["device"]["public_key"].as_str().expect("public key");
    let revoked = send_json(
        &app,
        Method::DELETE,
        &format!("/v1/devices/{public_key}"),
        None,
    )
    .await;
    assert_eq!(revoked["revoked"], true);

    let registry = SharedDeviceRegistry::open(
        temporary.path().join("devices.toml"),
        Vec::new(),
        "10.77.0.1".parse().expect("tunnel address"),
        24,
    )
    .expect("reopened registry");
    assert_eq!(registry.list().expect("device list").len(), 1);
}

#[test]
fn revocation_disables_an_existing_session_flag() {
    let temporary = TempDir::new().expect("temporary directory");
    let registry = registry(temporary.path());
    let provisioned = registry
        .provision("phone", DevicePlatform::Android)
        .expect("provisioned device");
    let public_key = decode_public_key(&provisioned.record.public_key).expect("public key");
    let lease = registry.authorize(&public_key).expect("device lease");
    assert!(lease.authorization.is_active());

    assert!(registry
        .revoke(&provisioned.record.public_key)
        .expect("revoked device"));
    assert!(!lease.authorization.is_active());
}

fn test_router(temporary: &TempDir) -> axum::Router {
    router(
        registry(temporary.path()),
        TrafficStore::open(temporary.path().join("traffic.sqlite")).expect("traffic store"),
        AdminToken::new(TOKEN).expect("admin token"),
        AdminSettings {
            public_endpoint: "198.51.100.10:51820"
                .parse::<SocketAddr>()
                .expect("endpoint"),
            server_public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            tun_name: "mousevpn0".to_owned(),
        },
    )
}

#[tokio::test]
async fn returns_authenticated_traffic_report() {
    let temporary = TempDir::new().expect("temporary directory");
    let traffic =
        TrafficStore::open(temporary.path().join("traffic.sqlite")).expect("traffic store");
    let counter = traffic.counter("phone-key", "Alice phone");
    counter.add_upload(1_024);
    counter.add_download(2_048);
    let app = router(
        registry(temporary.path()),
        traffic,
        AdminToken::new(TOKEN).expect("admin token"),
        AdminSettings {
            public_endpoint: "198.51.100.10:51820".parse().expect("endpoint"),
            server_public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            tun_name: "mousevpn0".to_owned(),
        },
    );

    let report = send_json(&app, Method::GET, "/v1/traffic?hours=24", None).await;
    assert_eq!(report["totals"]["hour"]["upload_bytes"], 1_024);
    assert_eq!(report["totals"]["day"]["download_bytes"], 2_048);
    assert_eq!(report["hourly"].as_array().expect("hourly").len(), 24);
    assert_eq!(report["devices"][0]["name"], "Alice phone");
}

fn registry(directory: &Path) -> SharedDeviceRegistry {
    let owner = KeyPair::generate().expect("owner keys");
    SharedDeviceRegistry::open(
        directory.join("devices.toml"),
        vec![SeedDevice {
            name: "owner".to_owned(),
            public_key: owner.public,
            address: "10.77.0.2".parse().expect("owner address"),
        }],
        "10.77.0.1".parse().expect("tunnel address"),
        24,
    )
    .expect("device registry")
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
