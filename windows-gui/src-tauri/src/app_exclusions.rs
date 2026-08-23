use std::{
    collections::HashSet,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use mousevpn_windows_client::{normalize_windows_path, AppRoutingMode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[cfg(windows)]
use std::os::windows::process::CommandExt;
#[cfg(windows)]
use std::process::Command;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const SETTINGS_VERSION: u8 = 2;

#[cfg(windows)]
const INSTALLED_APPS_SCRIPT: &str = r#"
$ErrorActionPreference='SilentlyContinue'
$ProgressPreference='SilentlyContinue'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$apps=[System.Collections.Generic.List[object]]::new()
$startNames=@{}
Get-StartApps | ForEach-Object {$startNames[[string]$_.AppID]=[string]$_.Name}

function Add-DesktopApp([string]$name,[string]$path) {
  if ([string]::IsNullOrWhiteSpace($name) -or [string]::IsNullOrWhiteSpace($path)) { return }
  $path=[Environment]::ExpandEnvironmentVariables($path.Trim().Trim('"'))
  if (-not $path.EndsWith('.exe',[StringComparison]::OrdinalIgnoreCase)) { return }
  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return }
  $stem=[IO.Path]::GetFileNameWithoutExtension($path)
  if ($stem -match '^(unins\d*|uninstall)$' -or $stem -ieq 'mousevpn-windows-gui') { return }
  if ($name -match '^(Uninstall|Деинсталлировать)\b') { return }
  $desktopPaths=[System.Collections.Generic.List[string]]::new()
  $desktopPaths.Add($path)
  $fileName=[IO.Path]::GetFileName($path)
  $parent=[IO.Path]::GetDirectoryName($path)
  $squirrelRoot=$null
  if (Test-Path -LiteralPath (Join-Path $parent 'Update.exe') -PathType Leaf) {
    $squirrelRoot=$parent
  } elseif ([IO.Path]::GetFileName($parent).StartsWith('app-',[StringComparison]::OrdinalIgnoreCase)) {
    $candidateRoot=[IO.Path]::GetDirectoryName($parent)
    if (Test-Path -LiteralPath (Join-Path $candidateRoot 'Update.exe') -PathType Leaf) {$squirrelRoot=$candidateRoot}
  }
  if ($squirrelRoot) {
    $stable=Join-Path $squirrelRoot $fileName
    if (Test-Path -LiteralPath $stable -PathType Leaf) {$desktopPaths.Add($stable)}
    Get-ChildItem -LiteralPath $squirrelRoot -Directory -Filter 'app-*' | ForEach-Object {
      $versioned=Join-Path $_.FullName $fileName
      if (Test-Path -LiteralPath $versioned -PathType Leaf) {$desktopPaths.Add($versioned)}
    }
  }
  [string[]]$paths=@($desktopPaths | Select-Object -Unique)
  $apps.Add([pscustomobject]@{id=('desktop:'+$path);name=$name;path=$path;paths=$paths;source='desktop';packageName=$null;relativePaths=@()})
}

Get-AppxPackage | Where-Object {-not $_.IsFramework -and $_.InstallLocation} | ForEach-Object {
  $pkg=$_
  $manifest=Get-AppxPackageManifest -Package $pkg.PackageFullName
  foreach($application in @($manifest.Package.Applications.Application)) {
    $exe=[string]$application.Executable
    if (-not $exe -or -not $exe.EndsWith('.exe',[StringComparison]::OrdinalIgnoreCase)) { continue }
    $primary=Join-Path $pkg.InstallLocation $exe
    if (-not (Test-Path -LiteralPath $primary -PathType Leaf)) { continue }
    $aumid="$($pkg.PackageFamilyName)!$($application.Id)"
    $name=$startNames[$aumid]
    if ([string]::IsNullOrWhiteSpace($name) -or $name.StartsWith('ms-resource:')) {$name=[string]$pkg.Name}
    $packageToken=([string]$pkg.Name -split '\.')[-1]
    $primaryStem=[IO.Path]::GetFileNameWithoutExtension($exe)
    $packagePaths=[System.Collections.Generic.List[string]]::new()
    $packagePaths.Add($primary)
    Get-ChildItem -LiteralPath $pkg.InstallLocation -Filter *.exe -File -Recurse | Where-Object {
      $_.BaseName -ieq $primaryStem -or $_.BaseName -ieq $packageToken
    } | ForEach-Object {$packagePaths.Add($_.FullName)}
    [string[]]$packageOnlyPaths=@($packagePaths | Select-Object -Unique)
    [string[]]$relativePaths=@($packageOnlyPaths | ForEach-Object {$_.Substring($pkg.InstallLocation.Length).TrimStart('\')})
    if ([string]$pkg.Name -ieq 'Claude' -or $primaryStem -ieq 'Claude') {
      $claudeCodeRoot=Join-Path $env:APPDATA 'Claude\claude-code'
      if (Test-Path -LiteralPath $claudeCodeRoot -PathType Container) {
        Get-ChildItem -LiteralPath $claudeCodeRoot -Directory | ForEach-Object {
          $helper=Join-Path $_.FullName 'claude.exe'
          if (Test-Path -LiteralPath $helper -PathType Leaf) {$packagePaths.Add($helper)}
        }
      }
    }
    [string[]]$paths=@($packagePaths | Select-Object -Unique)
    $apps.Add([pscustomobject]@{id=('store:'+$aumid);name=$name;path=$primary;paths=$paths;source='store';packageName=[string]$pkg.Name;relativePaths=$relativePaths})
  }
}

$shell=New-Object -ComObject WScript.Shell
$startRoots=@([Environment]::GetFolderPath('StartMenu'),[Environment]::GetFolderPath('CommonStartMenu'))
foreach($root in $startRoots) {
  if ([string]::IsNullOrWhiteSpace($root)) { continue }
  Get-ChildItem -LiteralPath $root -Filter *.lnk -File -Recurse | ForEach-Object {
    $shortcut=$shell.CreateShortcut($_.FullName)
    Add-DesktopApp $_.BaseName ([string]$shortcut.TargetPath)
  }
}

$uninstallKeys=@(
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
  'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
Get-ItemProperty $uninstallKeys | ForEach-Object {
  $icon=[Environment]::ExpandEnvironmentVariables(([string]$_.DisplayIcon).Trim().Trim('"'))
  if ($icon -match '^(.*?\.exe)(?:,\s*-?\d+)?$') { Add-DesktopApp ([string]$_.DisplayName) $Matches[1] }
}

ConvertTo-Json -InputObject @($apps) -Depth 4 -Compress
"#;

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
    let mut settings = load_resolved()?;
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct InstalledApp {
    id: String,
    name: String,
    path: String,
    paths: Vec<String>,
    source: String,
    #[serde(default)]
    package_name: Option<String>,
    #[serde(default)]
    relative_paths: Vec<String>,
}

pub(crate) fn policy() -> Result<mousevpn_windows_client::AppRoutingPolicy, String> {
    let mut settings = load_resolved()?;
    normalize(&mut settings);
    // An uninstalled or updating application cannot produce traffic. Keep its
    // entry visible in the UI, but do not let it block the entire VPN session.
    settings
        .apps
        .retain(|path| path.is_absolute() && path.is_file());
    let mut package_families = settings
        .apps
        .iter()
        .filter_map(|path| windowsapps_package_family(path))
        .collect::<Vec<_>>();
    package_families.sort_by_key(|family| family.to_lowercase());
    package_families.dedup_by(|left, right| left.eq_ignore_ascii_case(right));
    let package_sids = package_families
        .iter()
        .map(|family| {
            mousevpn_windows_client::app_container_sid_string(family).map_err(|error| {
                format!("Не удалось определить пакет Microsoft Store {family}: {error}")
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(mousevpn_windows_client::AppRoutingPolicy {
        mode: settings.mode,
        apps: settings.apps,
        package_sids,
    })
}

pub(crate) fn installed_apps() -> Result<Vec<InstalledApp>, String> {
    discover_installed_apps()
}

pub(crate) fn set_installed_selection(
    selected_paths: Vec<String>,
    discovered_paths: Vec<String>,
) -> Result<AppRoutingSettings, String> {
    let selected = selected_paths
        .iter()
        .map(|path| validate_executable(Path::new(path.trim())))
        .collect::<Result<Vec<_>, _>>()?;
    let selected_keys = selected
        .iter()
        .map(|path| normalized_key(path))
        .collect::<HashSet<_>>();
    let discovered_keys = discovered_paths
        .iter()
        .map(|path| normalized_key(Path::new(path.trim())))
        .collect::<HashSet<_>>();
    let mut settings = load_resolved()?;
    settings.apps.retain(|path| {
        let key = normalized_key(path);
        !discovered_keys.contains(&key) || selected_keys.contains(&key)
    });
    settings.apps.extend(selected);
    sort_and_deduplicate(&mut settings.apps);
    save(&settings)?;
    get()
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
    path.canonicalize()
        .map(|path| normalize_windows_path(&path))
        .map_err(display_error)
}

fn load_resolved() -> Result<StoredSettings, String> {
    let mut settings = load()?;
    let mut changed = resolve_squirrel_paths(&mut settings.apps);
    if resolve_claude_code_paths(&mut settings.apps) {
        changed = true;
    }
    if settings
        .apps
        .iter()
        .any(|path| !path.is_file() && windowsapps_identity(path).is_some())
    {
        // Discovery is a repair aid, not a connection prerequisite. A damaged
        // AppX registration must not prevent MouseVPN from opening.
        if let Ok(installed) = discover_installed_apps() {
            if resolve_packaged_paths(&mut settings.apps, &installed) {
                changed = true;
            }
        }
    }
    if changed {
        sort_and_deduplicate(&mut settings.apps);
        save(&settings)?;
    }
    Ok(settings)
}

fn resolve_claude_code_paths(paths: &mut Vec<PathBuf>) -> bool {
    dirs::config_dir().is_some_and(|directory| {
        resolve_claude_code_paths_at(paths, &directory.join("Claude").join("claude-code"))
    })
}

fn resolve_claude_code_paths_at(paths: &mut Vec<PathBuf>, root: &Path) -> bool {
    let selected = paths.iter().any(|path| {
        windowsapps_identity(path)
            .is_some_and(|(package_name, _)| package_name.eq_ignore_ascii_case("Claude"))
            || is_claude_code_helper(path, root)
    });
    if !selected {
        return false;
    }

    let original_keys = paths
        .iter()
        .map(|path| normalized_key(path))
        .collect::<Vec<_>>();

    // Claude's Store UI launches a separately updated Claude Code helper from
    // %APPDATA%. Both processes perform network requests, so one Claude card
    // must route both identities through the same policy.
    if let Ok(entries) = fs::read_dir(root) {
        for entry in entries.flatten() {
            let helper = entry.path().join("claude.exe");
            if entry.path().is_dir() && helper.is_file() {
                paths.push(normalize_windows_path(&helper));
            }
        }
    }

    // Claude removes old version directories during its own update. Discard
    // only stale helpers under this exact installation root.
    paths.retain(|path| !is_claude_code_helper(path, root) || path.is_file());
    sort_and_deduplicate(paths);
    let resolved_keys = paths
        .iter()
        .map(|path| normalized_key(path))
        .collect::<Vec<_>>();
    original_keys != resolved_keys
}

fn is_claude_code_helper(path: &Path, root: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.eq_ignore_ascii_case("claude.exe"))
        && path
            .parent()
            .and_then(Path::parent)
            .is_some_and(|parent| normalized_key(parent) == normalized_key(root))
}

fn resolve_squirrel_paths(paths: &mut Vec<PathBuf>) -> bool {
    let original_keys = paths
        .iter()
        .map(|path| normalized_key(path))
        .collect::<Vec<_>>();
    let mut identities = Vec::new();
    let mut seen = HashSet::new();
    for path in paths.iter() {
        let Some((root, file_name)) = squirrel_identity(path) else {
            continue;
        };
        let key = format!(
            "{}|{}",
            normalized_key(&root),
            file_name.to_string_lossy().to_lowercase()
        );
        if seen.insert(key) {
            identities.push((root, file_name));
        }
    }

    for (root, file_name) in &identities {
        let stable = root.join(file_name);
        if stable.is_file() {
            paths.push(normalize_windows_path(&stable));
        }
        if let Ok(entries) = fs::read_dir(root) {
            for entry in entries.flatten() {
                let directory = entry.path();
                let is_version = entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.to_ascii_lowercase().starts_with("app-"));
                if is_version && directory.is_dir() {
                    let versioned = directory.join(file_name);
                    if versioned.is_file() {
                        paths.push(normalize_windows_path(&versioned));
                    }
                }
            }
        }
    }

    // Squirrel removes old app-* directories during updates. Once a stable
    // launcher identifies the installation, stale versioned paths are safe to
    // discard and the currently installed version above replaces them.
    paths.retain(|path| {
        if path.is_file() {
            return true;
        }
        !identities.iter().any(|(root, file_name)| {
            path.file_name()
                .is_some_and(|candidate| candidate.eq_ignore_ascii_case(file_name))
                && path
                    .parent()
                    .and_then(Path::file_name)
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.to_ascii_lowercase().starts_with("app-"))
                && path.parent().and_then(Path::parent) == Some(root.as_path())
        })
    });
    sort_and_deduplicate(paths);
    let resolved_keys = paths
        .iter()
        .map(|path| normalized_key(path))
        .collect::<Vec<_>>();
    original_keys != resolved_keys
}

fn squirrel_identity(path: &Path) -> Option<(PathBuf, std::ffi::OsString)> {
    let file_name = path.file_name()?.to_owned();
    let parent = path.parent()?;
    if parent.join("Update.exe").is_file() {
        return Some((parent.to_owned(), file_name));
    }
    let is_version = parent
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.to_ascii_lowercase().starts_with("app-"));
    let root = parent.parent()?;
    (is_version && root.join("Update.exe").is_file()).then(|| (root.to_owned(), file_name))
}

fn discover_installed_apps() -> Result<Vec<InstalledApp>, String> {
    #[cfg(windows)]
    {
        let mut command = Command::new("powershell.exe");
        command.creation_flags(CREATE_NO_WINDOW);
        let output = command
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                INSTALLED_APPS_SCRIPT,
            ])
            .output()
            .map_err(display_error)?;
        if !output.status.success() {
            return Err(format!(
                "Не удалось получить список установленных приложений: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        let json = String::from_utf8(output.stdout).map_err(display_error)?;
        let json = json.trim().trim_start_matches('\u{feff}');
        let mut apps: Vec<InstalledApp> = serde_json::from_str(json).map_err(display_error)?;
        let mut seen = HashSet::new();
        for app in &mut apps {
            app.path = normalize_windows_path(Path::new(&app.path))
                .display()
                .to_string();
            let original_paths = std::mem::take(&mut app.paths);
            let original_relative_paths = std::mem::take(&mut app.relative_paths);
            let mut seen_paths = HashSet::new();
            for (index, path) in original_paths.iter().enumerate() {
                let path = normalize_windows_path(Path::new(path))
                    .display()
                    .to_string();
                if Path::new(&path).is_file() && seen_paths.insert(normalized_key(Path::new(&path)))
                {
                    app.paths.push(path);
                    if let Some(relative) = original_relative_paths.get(index) {
                        app.relative_paths.push(relative.clone());
                    }
                }
            }
        }
        apps.retain(|app| {
            !app.name.trim().is_empty()
                && !app.paths.is_empty()
                && seen.insert(app.id.to_lowercase())
        });
        apps.sort_by(|left, right| {
            left.name
                .to_lowercase()
                .cmp(&right.name.to_lowercase())
                .then_with(|| left.path.to_lowercase().cmp(&right.path.to_lowercase()))
        });
        Ok(apps)
    }

    #[cfg(not(windows))]
    {
        Err("Список установленных приложений доступен только в Windows".to_owned())
    }
}

fn resolve_packaged_paths(paths: &mut [PathBuf], installed: &[InstalledApp]) -> bool {
    let mut changed = false;
    for path in paths {
        let Some((package_name, relative_path)) = windowsapps_identity(path) else {
            continue;
        };
        let replacement = installed.iter().find_map(|app| {
            if app.source != "store"
                || !app
                    .package_name
                    .as_deref()
                    .is_some_and(|name| name.eq_ignore_ascii_case(&package_name))
            {
                return None;
            }
            app.relative_paths
                .iter()
                .zip(&app.paths)
                .find(|(relative, _)| normalized_relative_path(relative) == relative_path)
                .map(|(_, path)| PathBuf::from(path))
        });
        if let Some(replacement) = replacement {
            if normalized_key(path) != normalized_key(&replacement) {
                *path = replacement;
                changed = true;
            }
        }
    }
    changed
}

fn windowsapps_identity(path: &Path) -> Option<(String, String)> {
    let value = normalize_windows_path(path)
        .to_string_lossy()
        .replace('/', "\\");
    let lowercase = value.to_lowercase();
    let marker = r"\windowsapps\";
    let start = lowercase.find(marker)? + marker.len();
    let (package_directory, relative_path) = value[start..].split_once('\\')?;
    let parts = package_directory.split('_').collect::<Vec<_>>();
    if parts.len() < 5 {
        return None;
    }
    let package_name = parts[..parts.len() - 4].join("_");
    (!package_name.is_empty() && !relative_path.is_empty())
        .then(|| (package_name, normalized_relative_path(relative_path)))
}

fn windowsapps_package_family(path: &Path) -> Option<String> {
    let value = normalize_windows_path(path)
        .to_string_lossy()
        .replace('/', "\\");
    let lowercase = value.to_lowercase();
    let marker = r"\windowsapps\";
    let start = lowercase.find(marker)? + marker.len();
    let package_directory = value[start..].split_once('\\')?.0;
    let parts = package_directory.split('_').collect::<Vec<_>>();
    if parts.len() < 5 {
        return None;
    }
    let package_name = parts[..parts.len() - 4].join("_");
    let publisher_id = parts.last()?;
    (!package_name.is_empty() && !publisher_id.is_empty())
        .then(|| format!("{package_name}_{publisher_id}"))
}

fn normalized_relative_path(path: &str) -> String {
    path.replace('/', "\\")
        .trim_start_matches('\\')
        .to_lowercase()
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
    // A preview build has to be able to keep its application list away from
    // the installed client's. The two disagree about how routing is enforced,
    // and a list written by one of them stops the other from connecting.
    if let Some(directory) = std::env::var_os("MOUSEVPN_SETTINGS_DIR") {
        return Ok(PathBuf::from(directory).join("settings.toml"));
    }
    dirs::config_dir()
        .map(|directory| directory.join("MouseVPN").join("settings.toml"))
        .ok_or_else(|| "Не удалось определить каталог настроек".to_owned())
}

fn normalize(settings: &mut StoredSettings) {
    settings.version = SETTINGS_VERSION;
    settings.excluded_apps.clear();
    for path in &mut settings.apps {
        *path = normalize_windows_path(path);
    }
    sort_and_deduplicate(&mut settings.apps);
}

fn sort_and_deduplicate(paths: &mut Vec<PathBuf>) {
    paths.sort_by_key(|path| normalized_key(path));
    paths.dedup_by(|left, right| normalized_key(left) == normalized_key(right));
}

fn normalized_key(path: &Path) -> String {
    normalize_windows_path(path)
        .to_string_lossy()
        .to_lowercase()
}

const fn settings_version() -> u8 {
    SETTINGS_VERSION
}

fn display_error(error: impl std::fmt::Display) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use super::{
        migrate, normalize, normalized_key, resolve_claude_code_paths_at, resolve_packaged_paths,
        resolve_squirrel_paths, sort_and_deduplicate, windowsapps_identity,
        windowsapps_package_family, InstalledApp, StoredSettings,
    };
    use mousevpn_windows_client::AppRoutingMode;
    use uuid::Uuid;

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
    fn normalizing_settings_removes_extended_path_prefixes() {
        let mut settings = StoredSettings {
            version: 2,
            mode: AppRoutingMode::Include,
            apps: vec![PathBuf::from(r"\\?\C:\Apps\Browser.exe")],
            excluded_apps: Vec::new(),
        };
        normalize(&mut settings);
        assert_eq!(settings.apps, [PathBuf::from(r"C:\Apps\Browser.exe")]);
    }

    #[test]
    fn extracts_stable_identity_from_windowsapps_path() {
        assert_eq!(
            windowsapps_identity(
                PathBuf::from(r"D:\WindowsApps\Vendor_App_1.2.3.0_x64__publisher\app\Client.exe")
                    .as_path()
            ),
            Some(("Vendor_App".to_owned(), r"app\client.exe".to_owned()))
        );
    }

    #[test]
    fn extracts_package_family_from_windowsapps_path() {
        assert_eq!(
            windowsapps_package_family(PathBuf::from(
                r"C:\Program Files\WindowsApps\Claude_1.30096.5.0_x64__pz87srrgttv7p\app\claude.exe"
            ).as_path()),
            Some("Claude_pz87srrgttv7p".to_owned())
        );
    }

    #[test]
    fn refreshes_a_store_path_after_package_update() {
        let mut paths = [PathBuf::from(
            r"C:\Program Files\WindowsApps\OpenAI.Codex_1.0.0.0_x64__publisher\app\ChatGPT.exe",
        )];
        let installed = [InstalledApp {
            id: "store:OpenAI.Codex_publisher!App".to_owned(),
            name: "ChatGPT".to_owned(),
            path:
                r"C:\Program Files\WindowsApps\OpenAI.Codex_2.0.0.0_x64__publisher\app\ChatGPT.exe"
                    .to_owned(),
            paths: vec![
                r"C:\Program Files\WindowsApps\OpenAI.Codex_2.0.0.0_x64__publisher\app\ChatGPT.exe"
                    .to_owned(),
            ],
            source: "store".to_owned(),
            package_name: Some("OpenAI.Codex".to_owned()),
            relative_paths: vec![r"app\ChatGPT.exe".to_owned()],
        }];
        assert!(resolve_packaged_paths(&mut paths, &installed));
        assert_eq!(
            paths[0],
            PathBuf::from(
                r"C:\Program Files\WindowsApps\OpenAI.Codex_2.0.0.0_x64__publisher\app\ChatGPT.exe"
            )
        );
    }

    #[test]
    fn expands_and_refreshes_squirrel_application_paths() {
        let root = std::env::temp_dir().join(format!("mousevpn-squirrel-{}", Uuid::new_v4()));
        let current = root.join("app-2.0.0");
        fs::create_dir_all(&current).unwrap();
        fs::write(root.join("Update.exe"), []).unwrap();
        fs::write(root.join("Claude.exe"), []).unwrap();
        fs::write(current.join("Claude.exe"), []).unwrap();

        let stale_version_path = root.join("app-1.0.0").join("Claude.exe");
        let launcher_path = root.join("Claude.exe");
        let current_executable = current.join("Claude.exe");
        let mut paths = vec![launcher_path.clone(), stale_version_path];
        assert!(resolve_squirrel_paths(&mut paths));
        assert_eq!(paths.len(), 2);
        assert!(paths.contains(&launcher_path));
        assert!(paths.contains(&current_executable));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn groups_and_refreshes_store_claude_with_its_code_helper() {
        let root = std::env::temp_dir().join(format!("mousevpn-claude-code-{}", Uuid::new_v4()));
        let current = root.join("2.1.230").join("claude.exe");
        fs::create_dir_all(current.parent().unwrap()).unwrap();
        fs::write(&current, []).unwrap();

        let store = PathBuf::from(
            r"C:\Program Files\WindowsApps\Claude_1.30096.5.0_x64__publisher\app\Claude.exe",
        );
        let stale = root.join("2.1.229").join("claude.exe");
        let mut paths = vec![store.clone(), stale];
        assert!(resolve_claude_code_paths_at(&mut paths, &root));
        assert_eq!(paths.len(), 2);
        assert!(paths.contains(&store));
        assert!(paths.contains(&current));

        fs::remove_dir_all(root).unwrap();
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
