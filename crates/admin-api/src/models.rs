use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub name: String,
    pub max_sessions: usize,
}

#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: u64,
    pub name: String,
    pub max_sessions: usize,
}

#[derive(Debug, Serialize)]
pub struct DeviceResponse {
    pub public_key: String,
    pub secret_key: String,
}

#[derive(Debug, Serialize)]
pub struct RevokeResponse {
    pub revoked: bool,
    pub closed_sessions: usize,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}
