use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use mousevpn_windows_client::AppRoutingMode;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[cfg(windows)]
use std::os::windows::process::CommandExt;
#[cfg(windows)]
use std::process::Command;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const SETTINGS_VERSION: u8 = 2;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AppEntry {
    path: String,
    name: String,
    available: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AppRoutingSettings {
    mode: AppRoutingMode,
    apps: Vec<AppEntry>,
}

#[derive(Deserialize, Serialize)]
struct StoredSettings {
    #[serde(default = "settings_version")]
    version: u8,
    #[serde(default)]
    mode: AppRoutingMode,
    #[serde(default)]
    apps: Vec<PathBuf>,
    // Version 1 stored only exclusions. Keep this field for seamless migration.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    excluded_apps: Vec<PathBuf>,
}

pub(crate) fn get() -> Result<AppRoutingSettings, String> {
    let mut settings = load()?;
    normalize(&mut settings);
    Ok(AppRoutingSettings {
        mode: settings.mode,
        apps: settings
            .apps
            .iter()
            .map(|path| AppEntry::from_path(path))
            .collect(),
    })
}

pub(crate) fn policy() -> Result<(AppRoutingMode, Vec<PathBuf>), String> {
    let mut settings = load()?;
    normalize(&mut settings);
    Ok((settings.mode, settings.apps))
}

pub(crate) fn set_mode(mode: AppRoutingMode) -> Result<AppRoutingSettings, String> {
    let mut settings = load()?;
    normalize(&mut settings);
    settings.mode = mode;
    save(&settings)?;
    get()
}

pub(crate) fn add(path: String) -> Result<AppRoutingSettings, String> {
    let path = validate_executable(Path::new(path.trim()))?;
    let mut settings = load()?;
    normalize(&mut settings);
    settings.apps.push(path);
    sort_and_deduplicate(&mut settings.apps);
    save(&settings)?;
    get()
}

pub(crate) fn remove(path: String) -> Result<AppRoutingSettings, String> {
    let requested = normalized_key(Path::new(path.trim()));
    let mut settings = load()?;
    normalize(&mut settings);
    settings
        .apps
        .retain(|candidate| normalized_key(candidate) != requested);
    save(&settings)?;
    get()
}

pub(crate) fn clear() -> Result<AppRoutingSettings, String> {
    let mut settings = load()?;
    normalize(&mut settings);
    settings.apps.clear();
    save(&settings)?;
    get()
}

pub(crate) fn choose_executable() -> Result<Option<String>, String> {
    #[cfg(windows)]
    {
        let script = "$ErrorActionPreference='Stop'; Add-Type -AssemblyName System.Windows.Forms; \
            $dialog=New-Object System.Windows.Forms.OpenFileDialog; \
            $dialog.Title='Выберите приложение'; \
            $dialog.Filter='Приложения (*.exe)|*.exe'; \
            $dialog.CheckFileExists=$true; $dialog.Multiselect=$false; \
            if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) \
            {[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); Write-Output $dialog.FileName}";
        let mut command = Command::new("powershell.exe");
        command.creation_flags(CREATE_NO_WINDOW);
        let output = command
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .output()
            .map_err(display_error)?;
        if !output.status.success() {
            return Err(format!(
                "Не удалось открыть выбор приложения: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        let path = String::from_utf8(output.stdout)
            .map_err(display_error)?
            .trim()
            .to_owned();
        Ok((!path.is_empty()).then_some(path))
    }

    #[cfg(not(windows))]
    {
        Err("Выбор Windows-приложения доступен только в Windows".to_owned())
    }
}

impl AppEntry {
    fn from_path(path: &Path) -> Self {
        Self {
            path: path.display().to_string(),
            name: path
                .file_stem()
                .and_then(|name| name.to_str())
                .unwrap_or("Приложение")
                .to_owned(),
            available: path.is_file(),
        }
    }
}

fn validate_executable(path: &Path) -> Result<PathBuf, String> {
    if !path.is_absolute() {
        return Err("Выберите приложение по полному пути".to_owned());
    }
    if !path
        .extension()
        .and_then(|value| value.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("exe"))
    {
        return Err("Можно добавить только Windows-приложение (*.exe)".to_owned());
    }
    if !path.is_file() {
        return Err("Файл приложения не найден".to_owned());
    }
    path.canonicalize().map_err(display_error)
}

fn load() -> Result<StoredSettings, String> {
    let path = settings_path()?;
    let backup = path.with_extension("bak");
    let contents = match fs::read_to_string(&path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            match fs::read_to_string(backup) {
                Ok(contents) => contents,
                Err(backup_error) if backup_error.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(StoredSettings {
                        version: SETTINGS_VERSION,
                        mode: AppRoutingMode::Exclude,
                        apps: Vec::new(),
                        excluded_apps: Vec::new(),
                    });
                }
                Err(backup_error) => return Err(display_error(backup_error)),
            }
        }
        Err(error) => return Err(display_error(error)),
    };
    let settings: StoredSettings = toml::from_str(&contents).map_err(display_error)?;
    migrate(settings)
}

fn migrate(mut settings: StoredSettings) -> Result<StoredSettings, String> {
    match settings.version {
        1 => {
            settings.version = SETTINGS_VERSION;
            settings.mode = AppRoutingMode::Exclude;
            settings.apps.append(&mut settings.excluded_apps);
        }
        SETTINGS_VERSION => {}
        version => {
            return Err(format!(
                "Неподдерживаемая версия настроек MouseVPN: {version}"
            ))
        }
    }
    normalize(&mut settings);
    Ok(settings)
}

fn save(settings: &StoredSettings) -> Result<(), String> {
    let path = settings_path()?;
    let directory = path
        .parent()
        .ok_or_else(|| "Не удалось определить каталог настроек".to_owned())?;
    fs::create_dir_all(directory).map_err(display_error)?;
    let temporary = path.with_extension(format!("tmp-{}", Uuid::new_v4()));
    let contents = toml::to_string_pretty(settings).map_err(display_error)?;
    let result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .map_err(display_error)?;
        file.write_all(contents.as_bytes()).map_err(display_error)?;
        file.sync_all().map_err(display_error)?;
        replace_file(&temporary, &path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

fn replace_file(source: &Path, destination: &Path) -> Result<(), String> {
    if !destination.exists() {
        return fs::rename(source, destination).map_err(display_error);
    }
    let backup = destination.with_extension("bak");
    if backup.exists() {
        fs::remove_file(&backup).map_err(display_error)?;
    }
    fs::rename(destination, &backup).map_err(display_error)?;
    match fs::rename(source, destination) {
        Ok(()) => {
            let _ = fs::remove_file(backup);
            Ok(())
        }
        Err(error) => {
            let _ = fs::rename(backup, destination);
            Err(display_error(error))
        }
    }
}

fn settings_path() -> Result<PathBuf, String> {
    dirs::config_dir()
        .map(|directory| directory.join("MouseVPN").join("settings.toml"))
        .ok_or_else(|| "Не удалось определить каталог настроек".to_owned())
}

fn normalize(settings: &mut StoredSettings) {
    settings.version = SETTINGS_VERSION;
    settings.excluded_apps.clear();
    sort_and_deduplicate(&mut settings.apps);
}

fn sort_and_deduplicate(paths: &mut Vec<PathBuf>) {
    paths.sort_by_key(|path| normalized_key(path));
    paths.dedup_by(|left, right| normalized_key(left) == normalized_key(right));
}

fn normalized_key(path: &Path) -> String {
    path.to_string_lossy().replace('/', "\\").to_lowercase()
}

const fn settings_version() -> u8 {
    SETTINGS_VERSION
}

fn display_error(error: impl std::fmt::Display) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{migrate, normalized_key, sort_and_deduplicate, StoredSettings};
    use mousevpn_windows_client::AppRoutingMode;

    #[test]
    fn windows_paths_are_deduplicated_case_insensitively() {
        let mut paths = vec![
            PathBuf::from(r"C:\Games\Mouse.exe"),
            PathBuf::from(r"c:/games/mouse.EXE"),
        ];
        sort_and_deduplicate(&mut paths);
        assert_eq!(paths.len(), 1);
    }

    #[test]
    fn normalized_keys_use_windows_separators() {
        assert_eq!(
            normalized_key(PathBuf::from("C:/Apps/Game.exe").as_path()),
            r"c:\apps\game.exe"
        );
    }

    #[test]
    fn version_one_exclusions_migrate_to_denylist() {
        let settings: StoredSettings = toml::from_str(
            r"version = 1
excluded_apps = ['C:\Apps\Browser.exe']
",
        )
        .unwrap();
        let settings = migrate(settings).unwrap();
        assert_eq!(settings.version, 2);
        assert_eq!(settings.mode, AppRoutingMode::Exclude);
        assert_eq!(settings.apps, [PathBuf::from(r"C:\Apps\Browser.exe")]);
        assert!(settings.excluded_apps.is_empty());
    }
}
