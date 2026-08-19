use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

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
