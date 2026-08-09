use crate::{AppRoutingMode, AppRoutingPolicy, ClientError};

pub(crate) struct AppBypassGuard;
#[derive(Clone)]
pub(crate) struct AppBypassRefresher;

impl AppBypassGuard {
    pub(crate) fn install(policy: &AppRoutingPolicy) -> Result<Option<Self>, ClientError> {
        if policy.apps.is_empty() && policy.mode == AppRoutingMode::Exclude {
            Ok(None)
        } else {
            Err(ClientError::Platform(
                "application bypass is only available on Windows".to_owned(),
            ))
        }
    }

    #[allow(clippy::unused_self)]
    pub(crate) fn refresher(&self) -> AppBypassRefresher {
        AppBypassRefresher
    }
}

impl AppBypassRefresher {
    #[allow(clippy::unused_self, clippy::unnecessary_wraps)]
    pub(crate) fn refresh(&self) -> Result<(), ClientError> {
        Ok(())
    }
}
