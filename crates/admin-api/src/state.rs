use std::sync::{Arc, Mutex};

use mousevpn_server::ServerState;

use crate::AdminToken;

#[derive(Clone)]
pub(crate) struct ApiState {
    pub server: Arc<Mutex<ServerState>>,
    pub token: Arc<[u8]>,
}

impl ApiState {
    pub fn new(server: Arc<Mutex<ServerState>>, token: AdminToken) -> Self {
        Self {
            server,
            token: token.into_bytes().into(),
        }
    }
}
