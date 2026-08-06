use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use crate::{DevicePlatform, DeviceRecord};

#[derive(Debug, Deserialize)]
pub struct CreateDeviceRequest {
    pub name: String,
    pub platform: DevicePlatform,
    pub profile_password: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DeviceSummary {
    pub name: String,
    pub platform: DevicePlatform,
    pub public_key: String,
    pub address: Ipv4Addr,
}

impl From<DeviceRecord> for DeviceSummary {
    fn from(record: DeviceRecord) -> Self {
        Self {
            name: record.name,
            platform: record.platform,
            public_key: record.public_key,
            address: record.address,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ProvisionDeviceResponse {
    pub device: DeviceSummary,
    pub client_config: String,
    pub profile_token: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RevokeResponse {
    pub revoked: bool,
}

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}
