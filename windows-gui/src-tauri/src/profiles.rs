use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

const LAST_USED_PROFILE_FILE: &str = "last-profile";

use mousevpn_config::{ClientConfig, ClientProtocol};
use mousevpn_profile_cli::decrypt_profile;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroize;

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ProfileSummary {
    id: String,
    name: String,
    endpoint: String,
    protocol: ClientProtocol,
}

impl ProfileSummary {
    pub(crate) fn id(&self) -> &str {
        &self.id
    }
}

#[derive(Deserialize, Serialize)]
struct StoredProfile {
    id: String,
    name: String,
    server: String,
    server_public_key: String,
    client_private_key: String,
    tun_name: String,
    #[serde(default)]
    protocol: ClientProtocol,
}

impl StoredProfile {
    fn summary(&self) -> ProfileSummary {
        ProfileSummary {
            id: self.id.clone(),
            name: self.name.clone(),
            endpoint: self.server.clone(),
            protocol: self.protocol,
        }
    }

    fn client_config(&self) -> Result<ClientConfig, String> {
        Ok(ClientConfig {
            server: self
                .server
                .parse()
                .map_err(|error| format!("Неверный адрес сервера: {error}"))?,
            server_public_key: self.server_public_key.clone(),
            client_private_key: self.client_private_key.clone(),
            tun_name: self.tun_name.clone(),
            protocol: self.protocol,
        })
    }
}

pub(crate) fn list() -> Result<Vec<ProfileSummary>, String> {
    let directory = profiles_dir()?;
    if !directory.exists() {
        return Ok(Vec::new());
    }
    let mut profiles = Vec::new();
    for entry in fs::read_dir(directory).map_err(display_error)? {
        let path = entry.map_err(display_error)?.path();
        if path.extension().and_then(|value| value.to_str()) != Some("toml") {
            continue;
        }
        let contents = fs::read_to_string(path).map_err(display_error)?;
        let stored: StoredProfile = toml::from_str(&contents).map_err(display_error)?;
        profiles.push(stored.summary());
    }
    profiles.sort_by_key(|profile| profile.name.to_lowercase());
    Ok(profiles)
}

pub(crate) fn import(token: String, mut password: String) -> Result<ProfileSummary, String> {
    let decrypted = decrypt_profile(token.trim(), password.as_bytes()).map_err(display_error);
    password.zeroize();
    let (portable_id, name, endpoint, server_public_key, client_private_key) =
        decrypted?.into_parts();
    let id = Uuid::parse_str(&portable_id)
        .unwrap_or_else(|_| Uuid::new_v4())
        .to_string();
    let profile = StoredProfile {
        id,
        name: name.trim().to_owned(),
        server: endpoint.trim().to_owned(),
        server_public_key,
        client_private_key,
        tun_name: "MouseVPN".to_owned(),
        protocol: ClientProtocol::Legacy,
    };
    if profile.name.is_empty() {
        return Err("В конфигурации отсутствует название".to_owned());
    }
    profile.client_config()?.validate().map_err(display_error)?;
    let directory = profiles_dir()?;
    fs::create_dir_all(&directory).map_err(display_error)?;
    write_atomic(
        &profile_path(&profile.id)?,
        toml::to_string_pretty(&profile)
            .map_err(display_error)?
            .as_bytes(),
    )?;
    Ok(profile.summary())
}

pub(crate) fn set_protocol(id: &str, protocol: ClientProtocol) -> Result<ProfileSummary, String> {
    let path = profile_path(id)?;
    let contents = fs::read_to_string(&path).map_err(display_error)?;
    let mut profile: StoredProfile = toml::from_str(&contents).map_err(display_error)?;
    profile.protocol = protocol;
    profile.client_config()?.validate().map_err(display_error)?;
    write_atomic(
        &path,
        toml::to_string_pretty(&profile)
            .map_err(display_error)?
            .as_bytes(),
    )?;
    Ok(profile.summary())
}

pub(crate) fn remove(id: &str) -> Result<(), String> {
    match fs::remove_file(profile_path(id)?) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(display_error(error)),
    }
}

pub(crate) fn profile_path(id: &str) -> Result<PathBuf, String> {
    Ok(profiles_dir()?.join(format!("{}.toml", normalized_id(id)?)))
}


#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BackupProfile {
    pub(crate) version: u32,
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) endpoint: String,
    pub(crate) server_public_key: String,
    pub(crate) client_private_key: String,
    pub(crate) protocol: ClientProtocol,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct BackupProfiles {
    pub(crate) profiles: Vec<BackupProfile>,
    pub(crate) selected: Option<String>,
}

pub(crate) fn export_json() -> Result<serde_json::Value, String> {
    let directory = profiles_dir()?;
    let mut exported = Vec::new();
    if directory.exists() {
        for entry in fs::read_dir(&directory).map_err(display_error)? {
            let path = entry.map_err(display_error)?.path();
            if path.extension().and_then(|value| value.to_str()) != Some("toml") {
                continue;
            }
            let contents = fs::read_to_string(path).map_err(display_error)?;
            let profile: StoredProfile = toml::from_str(&contents).map_err(display_error)?;
            exported.push(BackupProfile {
                version: 1,
                id: normalized_id(&profile.id)?,
                name: profile.name,
                endpoint: profile.server,
                server_public_key: profile.server_public_key,
                client_private_key: profile.client_private_key,
                protocol: profile.protocol,
            });
        }
    }
    exported.sort_by(|left, right| left.name.to_lowercase().cmp(&right.name.to_lowercase()));
    let backup = BackupProfiles {
        profiles: exported,
        selected: last_used_id()?,
    };
    serde_json::to_value(backup).map_err(display_error)
}

pub(crate) fn validate_json(value: &serde_json::Value) -> Result<BackupProfiles, String> {
    let backup: BackupProfiles = serde_json::from_value(value.clone()).map_err(display_error)?;
    let mut ids = std::collections::HashSet::new();
    for profile in &backup.profiles {
        if profile.version != 1 {
            return Err("Неподдерживаемая версия профиля в резервной копии".to_owned());
        }
        let id = normalized_id(&profile.id)?;
        if !ids.insert(id.clone()) {
            return Err("В резервной копии обнаружены дублирующиеся профили".to_owned());
        }
        let stored = StoredProfile {
            id,
            name: profile.name.trim().to_owned(),
            server: profile.endpoint.trim().to_owned(),
            server_public_key: profile.server_public_key.clone(),
            client_private_key: profile.client_private_key.clone(),
            tun_name: "MouseVPN".to_owned(),
            protocol: profile.protocol,
        };
        if stored.name.is_empty() {
            return Err("В резервной копии есть профиль без названия".to_owned());
        }
        stored.client_config()?.validate().map_err(display_error)?;
    }

    let selected = backup.selected.as_deref().map(normalized_id).transpose()?;
    if let Some(selected) = selected {
        if !ids.contains(&selected) {
            return Err("Выбранный профиль отсутствует в резервной копии".to_owned());
        }
    }
    Ok(backup)
}

pub(crate) fn import_validated(backup: BackupProfiles) -> Result<(), String> {
    let directory = profiles_dir()?;
    fs::create_dir_all(&directory).map_err(display_error)?;

    let current_files = fs::read_dir(&directory)
        .map_err(display_error)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("toml"))
        .collect::<Vec<_>>();

    for path in current_files {
        fs::remove_file(path).map_err(display_error)?;
    }

    for profile in backup.profiles {
        let id = normalized_id(&profile.id)?;
        let stored = StoredProfile {
            id: id.clone(),
            name: profile.name.trim().to_owned(),
            server: profile.endpoint.trim().to_owned(),
            server_public_key: profile.server_public_key,
            client_private_key: profile.client_private_key,
            tun_name: "MouseVPN".to_owned(),
            protocol: profile.protocol,
        };
        let path = profile_path(&id)?;
        let contents = toml::to_string_pretty(&stored).map_err(display_error)?;
        write_atomic(&path, contents.as_bytes())?;
    }

    let selected_path = directory.join(LAST_USED_PROFILE_FILE);
    match backup.selected {
        Some(id) => write_atomic(&selected_path, normalized_id(&id)?.as_bytes())?,
        None => {
            let _ = fs::remove_file(selected_path);
        }
    }
    Ok(())
}

pub(crate) fn last_used_id() -> Result<Option<String>, String> {
    let path = profiles_dir()?.join(LAST_USED_PROFILE_FILE);
    match fs::read_to_string(path) {
        Ok(contents) => {
            let id = contents.trim();
            if id.is_empty() {
                Ok(None)
            } else {
                Ok(Some(normalized_id(id)?))
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(display_error(error)),
    }
}

pub(crate) fn mark_last_used(id: &str) -> Result<(), String> {
    let id = normalized_id(id)?;
    let path = profiles_dir()?.join(LAST_USED_PROFILE_FILE);
    write_atomic(&path, id.as_bytes())
}

pub(crate) fn normalized_id(id: &str) -> Result<String, String> {
    Uuid::parse_str(id)
        .map(|value| value.to_string())
        .map_err(|_| "Неверный идентификатор профиля".to_owned())
}

fn profiles_dir() -> Result<PathBuf, String> {
    dirs::config_dir()
        .map(|directory| directory.join("MouseVPN").join("profiles"))
        .ok_or_else(|| "Не удалось определить каталог конфигурации пользователя".to_owned())
}

fn write_atomic(path: &Path, contents: &[u8]) -> Result<(), String> {
    let temporary = path.with_extension(format!("tmp-{}", Uuid::new_v4()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .map_err(display_error)?;
        file.write_all(contents).map_err(display_error)?;
        file.sync_all().map_err(display_error)?;
        fs::rename(&temporary, path).map_err(display_error)
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

fn display_error(error: impl std::fmt::Display) -> String {
    error.to_string()
}
