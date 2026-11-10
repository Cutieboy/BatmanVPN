use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use mousevpn_config::{ClientConfig, ClientProtocol, MousalityClientConfig};
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    allowed_protocols: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mousality: Option<MousalityClientConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    managed_user: Option<String>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    selected_protocol: Option<ClientProtocol>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    allowed_protocols: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mousality: Option<MousalityClientConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    managed_user: Option<String>,
}

impl StoredProfile {
    fn summary(&self) -> ProfileSummary {
        ProfileSummary {
            id: self.id.clone(),
            name: self.name.clone(),
            endpoint: self
                .mousality
                .as_ref()
                .filter(|_| self.protocol == ClientProtocol::Mousality)
                .and_then(|settings| settings.endpoint)
                .map_or_else(|| self.server.clone(), |endpoint| endpoint.to_string()),
            protocol: self.protocol,
            allowed_protocols: self.allowed_protocols.clone(),
            mousality: self.mousality.clone(),
            managed_user: self.managed_user.clone(),
        }
    }

    fn client_config(&self) -> Result<ClientConfig, String> {
        Ok(ClientConfig {
            mousality: self.mousality.clone(),
            server: self
                .server
                .parse()
                .map_err(|error| format!("Неверный адрес сервера: {error}"))?,
            server_public_key: self.server_public_key.clone(),
            client_private_key: if let Some(user) = &self.managed_user {
                super::account::private_key(user, &self.id)?
            } else {
                self.client_private_key.clone()
            },
            tun_name: self.tun_name.clone(),
            protocol: self.protocol,
            bypass_russia: false,
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
        selected_protocol: None,
        allowed_protocols: None,
        mousality: None,
        managed_user: None,
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

fn central_mousality(
    settings: &mousevpn_account_client::MousalityEndpoint,
) -> Result<MousalityClientConfig, String> {
    let endpoint = settings
        .endpoint
        .parse()
        .map_err(|_| "Центр выдал неверный TCP-адрес Mousality".to_owned())?;
    Ok(MousalityClientConfig {
        server_name: String::new(),
        server_names: settings.server_names.clone(),
        endpoint: Some(endpoint),
    })
}

fn read_stored(path: &Path) -> Result<StoredProfile, String> {
    toml::from_str(&fs::read_to_string(path).map_err(display_error)?).map_err(display_error)
}
fn store(path: &Path, profile: &StoredProfile) -> Result<(), String> {
    profile.client_config()?.validate().map_err(display_error)?;
    write_atomic(
        path,
        toml::to_string_pretty(profile)
            .map_err(display_error)?
            .as_bytes(),
    )
}
fn configure_cached(
    profile: &mut StoredProfile,
    server: &mousevpn_account_client::Server,
) -> Result<(), String> {
    if server
        .allowed_protocols
        .as_ref()
        .is_some_and(|list| !list.iter().any(|name| name == profile.protocol.name()))
    {
        return Err("Этот протокол отключён администратором на выбранном сервере".into());
    }
    profile
        .allowed_protocols
        .clone_from(&server.allowed_protocols);
    profile.mousality = server
        .mousality
        .as_ref()
        .map(central_mousality)
        .transpose()?;
    if profile.protocol == ClientProtocol::Mousality && profile.mousality.is_none() {
        return Err("Параметры Mousality ещё не загружены. Обновите данные аккаунта при доступном командном центре.".into());
    }
    Ok(())
}
fn save_protocol(
    path: &Path,
    protocol: ClientProtocol,
    server: Option<&mousevpn_account_client::Server>,
) -> Result<ProfileSummary, String> {
    let mut profile = read_stored(path)?;
    profile.protocol = protocol;
    profile.selected_protocol = Some(protocol);
    if let Some(server) = server {
        configure_cached(&mut profile, server)?;
    }
    store(path, &profile)?;
    Ok(profile.summary())
}
pub(crate) fn set_protocol(id: &str, protocol: ClientProtocol) -> Result<ProfileSummary, String> {
    let path = profile_path(id)?;
    let profile = read_stored(&path)?;
    if let Some(user) = &profile.managed_user {
        super::account::with_server(user, id, |server| {
            save_protocol(&path, protocol, Some(server))
        })
    } else {
        save_protocol(&path, protocol, None)
    }
}
pub(crate) fn remove(id: &str) -> Result<(), String> {
    match fs::remove_file(profile_path(id)?) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(display_error(error)),
    }
}


const LAST_USED_PROFILE_FILE: &str = "last-profile";

pub(crate) fn last_used_id() -> Result<Option<String>, String> {
    let path = profiles_dir()?.join(LAST_USED_PROFILE_FILE);
    match fs::read_to_string(path) {
        Ok(contents) => Ok(Some(normalized_id(contents.trim())?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
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

pub(crate) fn write_atomic(path: &Path, contents: &[u8]) -> Result<(), String> {
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

pub(crate) fn load_config(path: &Path) -> Result<ClientConfig, String> {
    let contents = fs::read_to_string(path).map_err(display_error)?;
    if let Ok(profile) = toml::from_str::<StoredProfile>(&contents) {
        if let Some(user) = &profile.managed_user {
            return super::account::with_server(user, &profile.id, |server| {
                let mut configured = read_stored(path)?;
                configure_cached(&mut configured, server)?;
                configured.client_config()
            });
        }
        return profile.client_config();
    }
    toml::from_str(&contents).map_err(display_error)
}

pub(crate) fn is_managed(id: &str) -> Result<bool, String> {
    let value: StoredProfile =
        toml::from_str(&fs::read_to_string(profile_path(id)?).map_err(display_error)?)
            .map_err(display_error)?;
    Ok(value.managed_user.is_some())
}

pub(crate) fn connection_config(id: &str) -> Result<(ClientConfig, bool), String> {
    let path = profile_path(id)?;
    let profile = read_stored(&path)?;
    if let Some(user) = &profile.managed_user {
        super::account::with_server(user, id, |server| {
            let mut profile = read_stored(&path)?;
            configure_cached(&mut profile, server)?;
            store(&path, &profile)?;
            Ok((profile.client_config()?, true))
        })
    } else {
        Ok((profile.client_config()?, false))
    }
}
pub(crate) fn replace_managed(
    account: Option<&mousevpn_account_client::Account>,
) -> Result<(), String> {
    let directory = profiles_dir()?;
    fs::create_dir_all(&directory).map_err(display_error)?;
    for entry in fs::read_dir(&directory).map_err(display_error)? {
        let path = entry.map_err(display_error)?.path();
        if path.extension().and_then(|value| value.to_str()) != Some("toml") {
            continue;
        }
        let previous: StoredProfile =
            toml::from_str(&fs::read_to_string(&path).map_err(display_error)?)
                .map_err(display_error)?;
        if previous.managed_user.is_some()
            && !account.is_some_and(|account| {
                previous.managed_user.as_deref() == Some(&account.id)
                    && account
                        .servers
                        .iter()
                        .any(|server| server.id == previous.id)
            })
        {
            fs::remove_file(path).map_err(display_error)?;
        }
    }
    if let Some(account) = account {
        for server in &account.servers {
            let path = profile_path(&server.id)?;
            let previous = fs::read_to_string(&path)
                .ok()
                .and_then(|value| toml::from_str::<StoredProfile>(&value).ok());
            if previous
                .as_ref()
                .is_some_and(|profile| profile.managed_user.is_none())
            {
                return Err("Профиль сервера совпал с существующим личным профилем".to_owned());
            }
            let preferred = previous
                .as_ref()
                .filter(|profile| profile.managed_user.as_deref() == Some(&account.id))
                .map_or_else(
                    || match server.protocol.as_str() {
                        "morph_quiet" => ClientProtocol::MorphQuiet,
                        "morph_balanced" => ClientProtocol::MorphBalanced,
                        "morph_paranoid" => ClientProtocol::MorphParanoid,
                        _ => ClientProtocol::Legacy,
                    },
                    |profile| profile.selected_protocol.unwrap_or(profile.protocol),
                );
            let mousality = server
                .mousality
                .as_ref()
                .map(central_mousality)
                .transpose()?;
            let usable = |candidate: ClientProtocol| {
                (candidate != ClientProtocol::Mousality || mousality.is_some())
                    && server
                        .allowed_protocols
                        .as_ref()
                        .is_none_or(|names| names.iter().any(|name| name == candidate.name()))
            };
            let protocol = if usable(preferred) {
                preferred
            } else {
                [
                    ClientProtocol::Mousality,
                    ClientProtocol::MorphBalanced,
                    ClientProtocol::Speedy,
                    ClientProtocol::MorphQuiet,
                    ClientProtocol::MorphParanoid,
                    ClientProtocol::Legacy,
                ]
                .into_iter()
                .find(|mode| usable(*mode))
                .unwrap_or(ClientProtocol::Legacy)
            };
            let profile = StoredProfile {
                id: server.id.clone(),
                name: server.name.clone(),
                server: server.endpoint.clone(),
                server_public_key: server.public_key.clone(),
                client_private_key: String::new(),
                tun_name: "MouseVPN".to_owned(),
                protocol,
                selected_protocol: previous
                    .as_ref()
                    .and_then(|profile| profile.selected_protocol),
                allowed_protocols: server.allowed_protocols.clone(),
                mousality,
                managed_user: Some(account.id.clone()),
            };
            profile.client_config()?.validate().map_err(display_error)?;
            write_atomic(
                &path,
                toml::to_string_pretty(&profile)
                    .map_err(display_error)?
                    .as_bytes(),
            )?;
        }
    }
    Ok(())
}

fn display_error(error: impl std::fmt::Display) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use mousevpn_account_client::{MousalityEndpoint, Server};
    use mousevpn_config::{encode_public_key, encode_secret_key};
    use mousevpn_crypto::KeyPair;

    #[test]
    fn cached_center_policy_controls_tcp_endpoint_and_forbidden_modes() {
        let server_keys = KeyPair::generate().unwrap();
        let client_keys = KeyPair::generate().unwrap();
        let mut profile = StoredProfile {
            id: Uuid::new_v4().to_string(),
            name: "cached".into(),
            server: "127.0.0.1:51821".into(),
            server_public_key: encode_public_key(&server_keys.public),
            client_private_key: encode_secret_key(&client_keys.secret),
            tun_name: "MouseVPN".into(),
            protocol: ClientProtocol::Mousality,
            selected_protocol: Some(ClientProtocol::Mousality),
            allowed_protocols: None,
            mousality: None,
            managed_user: None,
        };
        let mut node = Server {
            id: profile.id.clone(),
            name: profile.name.clone(),
            endpoint: profile.server.clone(),
            public_key: profile.server_public_key.clone(),
            protocol: "legacy".into(),
            allowed_protocols: Some(vec!["mousality".into()]),
            supports_protocol_policy: true,
            online_devices: None,
            online_updated_at: None,
            mousality: Some(MousalityEndpoint {
                endpoint: "127.0.0.1:443".into(),
                server_names: vec!["www.bing.com".into()],
            }),
        };
        configure_cached(&mut profile, &node).unwrap();
        assert_eq!(
            profile
                .client_config()
                .unwrap()
                .validate()
                .unwrap()
                .server
                .port(),
            443
        );
        assert_eq!(profile.summary().endpoint, "127.0.0.1:443");
        profile.protocol = ClientProtocol::Speedy;
        assert!(configure_cached(&mut profile, &node).is_err());
        profile.protocol = ClientProtocol::Mousality;
        node.mousality = None;
        assert!(configure_cached(&mut profile, &node)
            .unwrap_err()
            .contains("ещё не загружены"));
        node.allowed_protocols = Some(Vec::new());
        profile.protocol = ClientProtocol::Legacy;
        assert!(configure_cached(&mut profile, &node).is_err());
    }
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
            // Only export unmanaged (manual) profiles
            if profile.managed_user.is_some() {
                continue;
            }
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
    exported.sort_by_key(|profile| profile.name.to_lowercase());
    serde_json::to_value(BackupProfiles {
        profiles: exported,
        selected: last_used_id()?,
    }).map_err(display_error)
}

pub(crate) fn validate_json(value: &serde_json::Value) -> Result<BackupProfiles, String> {
    let backup: BackupProfiles = serde_json::from_value(value.clone()).map_err(display_error)?;
    let mut ids = std::collections::HashSet::new();
    for profile in &backup.profiles {
        if profile.version != 1 {
            return Err("В резервной копии найдена неподдерживаемая версия профиля".to_owned());
        }
        let id = normalized_id(&profile.id)?;
        if !ids.insert(id.clone()) {
            return Err("В резервной копии найдены дубликаты профилей".to_owned());
        }
        let stored = StoredProfile {
            id,
            name: profile.name.trim().to_owned(),
            server: profile.endpoint.trim().to_owned(),
            server_public_key: profile.server_public_key.clone(),
            client_private_key: profile.client_private_key.clone(),
            tun_name: "MouseVPN".to_owned(),
            protocol: profile.protocol,
            selected_protocol: None,
            allowed_protocols: None,
            mousality: None,
            managed_user: None,
        };
        if stored.name.is_empty() {
            return Err("В резервной копии есть профиль без имени".to_owned());
        }
        stored.client_config()?.validate().map_err(display_error)?;
    }

    if let Some(selected) = backup.selected.as_deref().map(normalized_id).transpose()? {
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
        // Preserve managed profiles during manual backup import!
        if let Ok(contents) = fs::read_to_string(&path) {
            if let Ok(stored) = toml::from_str::<StoredProfile>(&contents) {
                if stored.managed_user.is_some() {
                    continue;
                }
            }
        }
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
            selected_protocol: None,
            allowed_protocols: None,
            mousality: None,
            managed_user: None,
        };
        let path = profile_path(&id)?;
        let contents = toml::to_string_pretty(&stored).map_err(display_error)?;
        write_atomic(&path, contents.as_bytes())?;
    }

    let selected_path = directory.join(LAST_USED_PROFILE_FILE);
    match backup.selected {
        Some(id) => write_atomic(&selected_path, normalized_id(&id)?.as_bytes())?,
        None => { let _ = fs::remove_file(selected_path); }
    }
    Ok(())
}
