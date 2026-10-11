use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
};

use mousevpn_windows_client::domain_routing::{normalize_domain, DomainRoute, DomainRule};
use serde::{Deserialize, Serialize};

const SETTINGS_VERSION: u8 = 1;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DomainRoutingSettings {
    pub(crate) rules: Vec<DomainRule>,
}

#[derive(Deserialize, Serialize)]
struct StoredRules {
    #[serde(default = "version")]
    version: u8,
    #[serde(default)]
    rules: Vec<DomainRule>,
}

fn version() -> u8 { SETTINGS_VERSION }

pub(crate) fn get() -> Result<DomainRoutingSettings, String> {
    Ok(DomainRoutingSettings { rules: load()?.rules })
}

pub(crate) fn add(domain: String, route: DomainRoute) -> Result<DomainRoutingSettings, String> {
    let domain = normalize_domain(&domain)?;
    let mut stored = load()?;
    stored.rules.retain(|rule| rule.domain != domain);
    stored.rules.push(DomainRule { domain, route });
    stored.rules.sort_by(|a, b| a.domain.cmp(&b.domain));
    save(&stored)?;
    get()
}

pub(crate) fn remove(domain: String) -> Result<DomainRoutingSettings, String> {
    let domain = normalize_domain(&domain)?;
    let mut stored = load()?;
    stored.rules.retain(|rule| rule.domain != domain);
    save(&stored)?;
    get()
}

pub(crate) fn clear() -> Result<DomainRoutingSettings, String> {
    let mut stored = load()?;
    stored.rules.clear();
    save(&stored)?;
    get()
}

pub(crate) fn policy() -> Result<Vec<DomainRule>, String> {
    Ok(load()?.rules)
}

fn settings_path() -> Result<PathBuf, String> {
    let base = dirs::config_dir().ok_or_else(|| "Не удалось определить каталог настроек".to_owned())?;
    Ok(base.join("MouseVPN").join("domain-rules.json"))
}

fn load() -> Result<StoredRules, String> {
    let path = settings_path()?;
    if !path.exists() {
        return Ok(StoredRules { version: SETTINGS_VERSION, rules: Vec::new() });
    }
    let bytes = fs::read(&path).map_err(|error| format!("Не удалось прочитать правила доменов: {error}"))?;
    let mut stored: StoredRules = serde_json::from_slice(&bytes)
        .map_err(|error| format!("Файл правил доменов повреждён: {error}"))?;
    if stored.version != SETTINGS_VERSION {
        return Err("Неподдерживаемая версия файла доменных правил".to_owned());
    }
    let normalized = mousevpn_windows_client::domain_routing::DomainRouting::new(stored.rules.clone())?;
    stored.rules = normalized.rules();
    Ok(stored)
}

fn save(stored: &StoredRules) -> Result<(), String> {
    let path = settings_path()?;
    let parent = path.parent().ok_or_else(|| "Некорректный путь настроек".to_owned())?;
    fs::create_dir_all(parent).map_err(|error| format!("Не удалось создать каталог настроек: {error}"))?;
    let mut bytes = serde_json::to_vec_pretty(stored).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    let temporary = path.with_extension("json.tmp");
    {
        let mut file = OpenOptions::new().create(true).truncate(true).write(true).open(&temporary)
            .map_err(|error| format!("Не удалось создать временный файл правил: {error}"))?;
        file.write_all(&bytes).map_err(|error| format!("Не удалось записать правила: {error}"))?;
        file.sync_all().map_err(|error| format!("Не удалось сохранить правила: {error}"))?;
    }
    fs::rename(&temporary, &path).map_err(|error| format!("Не удалось заменить правила доменов: {error}"))?;
    Ok(())
}
