use std::{fs, io, path::PathBuf};

use serde::{Deserialize, Serialize};

use crate::profiles::write_atomic;

/// Device-wide routing choices that apply to every profile.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct RoutingSettings {
    /// Russian networks bypass the tunnel. On unless the user turned it off.
    #[serde(default = "enabled")]
    pub(crate) bypass_russia: bool,
}

impl Default for RoutingSettings {
    fn default() -> Self {
        Self {
            bypass_russia: true,
        }
    }
}

const fn enabled() -> bool {
    true
}

pub(crate) fn load() -> Result<RoutingSettings, String> {
    match fs::read_to_string(settings_path()?) {
        Ok(contents) => toml::from_str(&contents).map_err(display_error),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(RoutingSettings::default()),
        Err(error) => Err(display_error(error)),
    }
}

pub(crate) fn set_bypass_russia(enabled: bool) -> Result<RoutingSettings, String> {
    let settings = RoutingSettings {
        bypass_russia: enabled,
    };
    let path = settings_path()?;
    if let Some(directory) = path.parent() {
        fs::create_dir_all(directory).map_err(display_error)?;
    }
    write_atomic(
        &path,
        toml::to_string_pretty(&settings)
            .map_err(display_error)?
            .as_bytes(),
    )?;
    Ok(settings)
}

fn settings_path() -> Result<PathBuf, String> {
    dirs::config_dir()
        .map(|directory| directory.join("MouseVPN").join("routing.toml"))
        .ok_or_else(|| "Не удалось определить каталог конфигурации пользователя".to_owned())
}

fn display_error(error: impl std::fmt::Display) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests {
    use super::RoutingSettings;

    #[test]
    fn russian_bypass_defaults_to_on() {
        assert!(RoutingSettings::default().bypass_russia);
        let empty: RoutingSettings = toml::from_str("").unwrap();
        assert!(empty.bypass_russia);
        let off: RoutingSettings = toml::from_str("bypass_russia = false").unwrap();
        assert!(!off.bypass_russia);
    }
}
