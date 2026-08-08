use std::sync::{atomic::AtomicBool, Arc};

use mousevpn_config::ValidatedClientConfig;

use crate::ClientError;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeDiagnostics {
    pub platform: &'static str,
    pub running_under_wine: bool,
    pub wintun_available: bool,
    pub elevated: bool,
    pub message: String,
}

#[must_use]
pub fn diagnose() -> RuntimeDiagnostics {
    RuntimeDiagnostics {
        platform: std::env::consts::OS,
        running_under_wine: false,
        wintun_available: false,
        elevated: false,
        message: "Windows runtime is not available on this operating system; UI-only Wine smoke tests remain possible".to_owned(),
    }
}

/// Returns an unsupported-platform error without changing networking state.
///
/// # Errors
///
/// Always returns [`ClientError::Platform`] outside Windows.
pub fn run_with_stop(
    _config: &ValidatedClientConfig,
    _stopping: &Arc<AtomicBool>,
) -> Result<(), ClientError> {
    Err(ClientError::Platform(
        "the MouseVPN Windows networking backend can only run on Windows".to_owned(),
    ))
}

/// Returns an unsupported-platform error without changing networking state.
///
/// # Errors
///
/// Always returns [`ClientError::Platform`] outside Windows.
pub fn repair_network() -> Result<(), ClientError> {
    Err(ClientError::Platform(
        "Windows network repair can only run on Windows".to_owned(),
    ))
}

/// Returns an unsupported-platform error without querying networking state.
///
/// # Errors
///
/// Always returns [`ClientError::Platform`] outside Windows.
pub fn network_report() -> Result<String, ClientError> {
    Err(ClientError::Platform(
        "Windows network diagnostics can only run on Windows".to_owned(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_non_windows_runtime() {
        let diagnostics = diagnose();
        assert!(!diagnostics.wintun_available);
        assert!(!diagnostics.elevated);
    }
}
