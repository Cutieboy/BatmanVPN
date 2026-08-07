#![allow(clippy::needless_pass_by_value)] // Tauri IPC commands deserialize owned arguments.

use std::{
    fs::{self, DirBuilder, OpenOptions},
    io::{BufRead, BufReader, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex, OnceLock},
    thread,
};

use mousevpn_config::{load_toml, ClientConfig};
use mousevpn_profile_cli::decrypt_profile;
use serde::{Deserialize, Serialize};
use tauri::{Manager, State, WindowEvent};
use uuid::Uuid;
use zeroize::Zeroize;

mod helper_runtime;

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProfileSummary {
    id: String,
    name: String,
    endpoint: String,
}

#[derive(Deserialize, Serialize)]
struct StoredProfile {
    id: String,
    name: String,
    server: String,
    server_public_key: String,
    client_private_key: String,
    tun_name: String,
}

impl StoredProfile {
    fn summary(&self) -> ProfileSummary {
        ProfileSummary {
            id: self.id.clone(),
            name: self.name.clone(),
            endpoint: self.server.clone(),
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
        })
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ConnectionSnapshot {
    state: String,
    message: String,
    profile_id: Option<String>,
}

impl Default for ConnectionSnapshot {
    fn default() -> Self {
        Self {
            state: "disconnected".to_owned(),
            message: "VPN выключен".to_owned(),
            profile_id: None,
        }
    }
}

#[derive(Default)]
struct AppState {
    child: Mutex<Option<Child>>,
    snapshot: Arc<Mutex<ConnectionSnapshot>>,
}

#[tauri::command]
fn list_profiles() -> Result<Vec<ProfileSummary>, String> {
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
        let contents = fs::read_to_string(&path).map_err(display_error)?;
        let stored: StoredProfile = toml::from_str(&contents).map_err(display_error)?;
        profiles.push(stored.summary());
    }
    profiles.sort_by_key(|profile| profile.name.to_lowercase());
    Ok(profiles)
}

#[tauri::command]
fn import_profile(token: String, mut password: String) -> Result<ProfileSummary, String> {
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
        tun_name: "mousevpn0".to_owned(),
    };
    if profile.name.is_empty() {
        return Err("В конфигурации отсутствует название".to_owned());
    }
    profile.client_config()?.validate().map_err(display_error)?;
    let directory = profiles_dir()?;
    create_private_dir(&directory)?;
    let path = profile_path(&profile.id)?;
    write_private_atomic(
        &path,
        toml::to_string_pretty(&profile)
            .map_err(display_error)?
            .as_bytes(),
    )?;
    Ok(profile.summary())
}

#[tauri::command]
fn delete_profile(id: String, state: State<'_, AppState>) -> Result<(), String> {
    let id = normalized_id(&id)?;
    let snapshot = lock(&state.snapshot)?.clone();
    if snapshot.profile_id.as_deref() == Some(id.as_str()) && snapshot.state != "disconnected" {
        return Err("Сначала отключите активный профиль".to_owned());
    }
    let path = profile_path(&id)?;
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(display_error(error)),
    }
}

#[tauri::command]
fn connect_profile(id: String, state: State<'_, AppState>) -> Result<ConnectionSnapshot, String> {
    let id = normalized_id(&id)?;
    let path = profile_path(&id)?;
    let config: ClientConfig = load_toml(&path).map_err(display_error)?;
    config.validate().map_err(display_error)?;

    let mut child_slot = lock(&state.child)?;
    if let Some(child) = child_slot.as_mut() {
        if child.try_wait().map_err(display_error)?.is_none() {
            return Err("VPN уже запущен".to_owned());
        }
        *child_slot = None;
    }

    let (executable, is_standalone_helper) = privileged_helper_executable()?;
    let mut command = Command::new("pkexec");
    command.arg(executable);
    if !is_standalone_helper {
        command.arg("--helper");
    }
    let mut child = command
        .arg("--config")
        .arg(&path)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("Не удалось открыть PolicyKit: {error}"))?;

    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "Не удалось открыть журнал helper-процесса".to_owned())?;
    let snapshot = ConnectionSnapshot {
        state: "connecting".to_owned(),
        message: "Ожидание разрешения PolicyKit…".to_owned(),
        profile_id: Some(id),
    };
    *lock(&state.snapshot)? = snapshot.clone();
    let shared_snapshot = Arc::clone(&state.snapshot);
    thread::spawn(move || read_helper_status(stderr, &shared_snapshot));
    *child_slot = Some(child);
    Ok(snapshot)
}

fn privileged_helper_executable() -> Result<(PathBuf, bool), String> {
    let Some(appdir) = std::env::var_os("APPDIR") else {
        return std::env::current_exe()
            .map(|path| (path, false))
            .map_err(display_error);
    };
    let bundled = PathBuf::from(appdir).join("usr/lib/mousevpn/mousevpn-helper");
    if !bundled.is_file() {
        return Err("В AppImage отсутствует привилегированный MouseVPN helper".to_owned());
    }
    let directory = dirs::cache_dir()
        .ok_or_else(|| "Не удалось определить каталог кэша пользователя".to_owned())?
        .join("mousevpn");
    create_private_dir(&directory)?;
    let destination = directory.join("mousevpn-helper");
    let temporary = directory.join(format!("mousevpn-helper.tmp-{}", Uuid::new_v4()));
    let result = (|| {
        fs::copy(&bundled, &temporary).map_err(display_error)?;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o700))
            .map_err(display_error)?;
        fs::rename(&temporary, &destination).map_err(display_error)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result?;
    Ok((destination, true))
}

#[tauri::command]
fn disconnect(state: State<'_, AppState>) -> Result<ConnectionSnapshot, String> {
    disconnect_inner(&state)
}

fn disconnect_inner(state: &AppState) -> Result<ConnectionSnapshot, String> {
    let mut child_slot = lock(&state.child)?;
    let child = child_slot
        .as_mut()
        .ok_or_else(|| "VPN уже выключен".to_owned())?;
    let stdin = child
        .stdin
        .as_mut()
        .ok_or_else(|| "Канал управления VPN закрыт".to_owned())?;
    stdin.write_all(b"stop\n").map_err(display_error)?;
    stdin.flush().map_err(display_error)?;
    let mut snapshot = lock(&state.snapshot)?;
    "disconnecting".clone_into(&mut snapshot.state);
    "Безопасно отключаем VPN…".clone_into(&mut snapshot.message);
    Ok(snapshot.clone())
}

#[tauri::command]
fn connection_status(state: State<'_, AppState>) -> Result<ConnectionSnapshot, String> {
    let mut child_slot = lock(&state.child)?;
    if let Some(child) = child_slot.as_mut() {
        if let Some(exit) = child.try_wait().map_err(display_error)? {
            *child_slot = None;
            let mut snapshot = lock(&state.snapshot)?;
            if snapshot.state == "disconnecting" || exit.success() {
                *snapshot = ConnectionSnapshot::default();
            } else if snapshot.state != "error" {
                "error".clone_into(&mut snapshot.state);
                "VPN-процесс неожиданно завершился".clone_into(&mut snapshot.message);
            }
        }
    }
    Ok(lock(&state.snapshot)?.clone())
}

fn read_helper_status(stderr: impl std::io::Read, snapshot: &Arc<Mutex<ConnectionSnapshot>>) {
    for line in BufReader::new(stderr).lines().map_while(Result::ok) {
        let Ok(mut current) = snapshot.lock() else {
            return;
        };
        if line == "MOUSEVPN_STATE=connected" || line.contains("MouseVPN connected") {
            "connected".clone_into(&mut current.state);
            "Защищённое соединение установлено".clone_into(&mut current.message);
        } else if let Some(message) = line.strip_prefix("MOUSEVPN_ERROR=") {
            "error".clone_into(&mut current.state);
            message.clone_into(&mut current.message);
        }
    }
}

fn profiles_dir() -> Result<PathBuf, String> {
    dirs::config_dir()
        .map(|directory| directory.join("mousevpn").join("profiles"))
        .ok_or_else(|| "Не удалось определить каталог конфигурации пользователя".to_owned())
}

fn profile_path(id: &str) -> Result<PathBuf, String> {
    Ok(profiles_dir()?.join(format!("{}.toml", normalized_id(id)?)))
}

fn normalized_id(id: &str) -> Result<String, String> {
    Uuid::parse_str(id)
        .map(|value| value.to_string())
        .map_err(|_| "Неверный идентификатор профиля".to_owned())
}

fn create_private_dir(path: &Path) -> Result<(), String> {
    if path.exists() {
        return Ok(());
    }
    let mut builder = DirBuilder::new();
    builder.recursive(true).mode(0o700);
    builder.create(path).map_err(display_error)
}

fn write_private_atomic(path: &Path, contents: &[u8]) -> Result<(), String> {
    let temporary = path.with_extension(format!("tmp-{}", Uuid::new_v4()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(display_error)?;
        file.write_all(contents).map_err(display_error)?;
        file.sync_all().map_err(display_error)?;
        fs::rename(&temporary, path).map_err(display_error)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn lock<T>(mutex: &Mutex<T>) -> Result<std::sync::MutexGuard<'_, T>, String> {
    mutex
        .lock()
        .map_err(|_| "Внутренняя блокировка повреждена".to_owned())
}

fn display_error(error: impl std::fmt::Display) -> String {
    error.to_string()
}

struct MouseVpnTray {
    app: tauri::AppHandle,
}

impl ksni::Tray for MouseVpnTray {
    fn id(&self) -> String {
        "mousevpn".to_owned()
    }

    fn title(&self) -> String {
        let state = self.app.state::<AppState>();
        let label = state.snapshot.lock().ok().map_or(
            "состояние неизвестно",
            |snapshot| match snapshot.state.as_str() {
                "connected" => "подключено",
                "connecting" => "подключение",
                "disconnecting" => "отключение",
                "error" => "ошибка",
                _ => "отключено",
            },
        );
        format!("MouseVPN — {label}")
    }

    fn icon_name(&self) -> String {
        "network-vpn".to_owned()
    }

    fn icon_pixmap(&self) -> Vec<ksni::Icon> {
        static ICON: OnceLock<ksni::Icon> = OnceLock::new();
        vec![ICON
            .get_or_init(|| {
                let image = image::load_from_memory_with_format(
                    include_bytes!("../icons/icon.png"),
                    image::ImageFormat::Png,
                )
                .expect("embedded tray icon is valid")
                .into_rgba8();
                let (width, height) = image.dimensions();
                let mut data = image.into_raw();
                for pixel in data.chunks_exact_mut(4) {
                    pixel.rotate_right(1);
                }
                ksni::Icon {
                    width: i32::try_from(width).expect("tray icon width fits i32"),
                    height: i32::try_from(height).expect("tray icon height fits i32"),
                    data,
                }
            })
            .clone()]
    }

    fn activate(&mut self, _x: i32, _y: i32) {
        show_main_window(&self.app);
    }

    fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
        use ksni::menu::StandardItem;

        vec![
            StandardItem {
                label: "Открыть MouseVPN".to_owned(),
                icon_name: "window-new".to_owned(),
                activate: Box::new(|tray: &mut Self| show_main_window(&tray.app)),
                ..Default::default()
            }
            .into(),
            StandardItem {
                label: "Отключить VPN".to_owned(),
                icon_name: "network-vpn-disconnected".to_owned(),
                activate: Box::new(|tray: &mut Self| {
                    let state = tray.app.state::<AppState>();
                    let _ = disconnect_inner(&state);
                }),
                ..Default::default()
            }
            .into(),
            ksni::MenuItem::Separator,
            StandardItem {
                label: "Выйти".to_owned(),
                icon_name: "application-exit".to_owned(),
                activate: Box::new(|tray: &mut Self| {
                    let state = tray.app.state::<AppState>();
                    let _ = disconnect_inner(&state);
                    tray.app.exit(0);
                }),
                ..Default::default()
            }
            .into(),
        ]
    }
}

fn start_linux_tray(app: tauri::AppHandle) {
    thread::spawn(move || {
        use ksni::blocking::TrayMethods;

        match (MouseVpnTray { app }).spawn() {
            Ok(_tray) => loop {
                thread::park();
            },
            Err(error) => eprintln!("MouseVPN tray unavailable: {error}"),
        }
    });
}

fn run_gui() {
    tauri::Builder::default()
        .manage(AppState::default())
        .setup(|app| {
            start_linux_tray(app.handle().clone());

            if let Some(window) = app.get_webview_window("main") {
                let hidden_window = window.clone();
                window.on_window_event(move |event| {
                    if let WindowEvent::CloseRequested { api, .. } = event {
                        api.prevent_close();
                        let _ = hidden_window.hide();
                    }
                });
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            list_profiles,
            import_profile,
            delete_profile,
            connect_profile,
            disconnect,
            connection_status,
        ])
        .run(tauri::generate_context!())
        .expect("failed to run MouseVPN GUI");
}

fn show_main_window(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

fn main() {
    let arguments: Vec<String> = std::env::args().collect();
    let helper_path = match arguments.as_slice() {
        [_, helper, config, path] if helper == "--helper" && config == "--config" => Some(path),
        _ => None,
    };
    if let Some(path) = helper_path {
        if let Err(error) = helper_runtime::run(Path::new(path.as_str())) {
            eprintln!("MOUSEVPN_ERROR={error}");
            std::process::exit(1);
        }
    } else {
        run_gui();
    }
}
