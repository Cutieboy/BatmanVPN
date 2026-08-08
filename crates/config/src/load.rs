use std::{fs, path::Path};

use serde::de::DeserializeOwned;

use crate::ConfigError;

/// Loads a private TOML file after checking Unix permissions.
///
/// # Errors
///
/// Returns an error for insecure permissions, I/O failure or invalid TOML.
pub fn load_toml<T: DeserializeOwned>(path: &Path) -> Result<T, ConfigError> {
    ensure_private_permissions(path)?;
    let contents = fs::read_to_string(path)?;
    Ok(toml::from_str(&contents)?)
}

#[cfg(unix)]
fn ensure_private_permissions(path: &Path) -> Result<(), ConfigError> {
    use std::os::unix::fs::PermissionsExt;

    let mode = fs::metadata(path)?.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(ConfigError::InsecurePermissions {
            path: path.to_path_buf(),
            mode,
        });
    }
    Ok(())
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)] // Keeps the platform checks behind one fallible interface.
fn ensure_private_permissions(_path: &Path) -> Result<(), ConfigError> {
    Ok(())
}
