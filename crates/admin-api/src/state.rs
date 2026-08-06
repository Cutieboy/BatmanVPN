use std::{net::SocketAddr, sync::Arc};

use crate::{AdminToken, SharedDeviceRegistry};

#[derive(Clone)]
pub struct AdminSettings {
    pub public_endpoint: SocketAddr,
    pub server_public_key: String,
    pub tun_name: String,
}

#[derive(Clone)]
pub(crate) struct ApiState {
    pub registry: SharedDeviceRegistry,
    pub token: Arc<[u8]>,
    pub settings: Arc<AdminSettings>,
}

impl ApiState {
    pub fn new(registry: SharedDeviceRegistry, token: AdminToken, settings: AdminSettings) -> Self {
        Self {
            registry,
            token: token.into_bytes().into(),
            settings: Arc::new(settings),
        }
    }
}
