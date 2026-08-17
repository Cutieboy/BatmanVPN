#![allow(clippy::needless_pass_by_value)]
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::{
    io::{BufRead, BufReader, Write},
    path::Path,
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread,
};

use mousevpn_config::{load_toml, ClientConfig};
use serde::Serialize;
use tauri::{Manager, State};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

mod app_exclusions;
mod helper_log;
mod profiles;
mod tray;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
#[cfg(windows)]
const AUTOSTART_TASK_NAME: &str = "MouseVPN";

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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Diagnostics {
    platform: String,
    running_under_wine: bool,
    wintun_available: bool,
    elevated: bool,
    message: String,
}

#[derive(Default)]
pub(crate) struct AppState {
    child: Mutex<Option<Child>>,
    snapshot: Arc<Mutex<ConnectionSnapshot>>,
    generation: Arc<AtomicU64>,
    last_profile_id: Mutex<Option<String>>,
    quitting: AtomicBool,
}

#[tauri::command]
fn runtime_diagnostics() -> Diagnostics {
    let report = mousevpn_windows_client::diagnose();
    Diagnostics {
        platform: report.platform.to_owned(),
        running_under_wine: report.running_under_wine,
        wintun_available: report.wintun_available,
        elevated: report.elevated,
        message: report.message,
    }
}

#[tauri::command]
fn list_profiles() -> Result<Vec<profiles::ProfileSummary>, String> {
    profiles::list()
}

#[tauri::command]
fn import_profile(token: String, password: String) -> Result<profiles::ProfileSummary, String> {
    profiles::import(token, password)
}

#[tauri::command]
fn delete_profile(id: String, state: State<'_, AppState>) -> Result<(), String> {
    let id = profiles::normalized_id(&id)?;
    let snapshot = lock(&state.snapshot)?.clone();
    if snapshot.profile_id.as_deref() == Some(id.as_str()) && snapshot.state != "disconnected" {
        return Err("Сначала отключите активный профиль".to_owned());
    }
    profiles::remove(&id)
}

#[tauri::command]
fn get_app_routing() -> Result<app_exclusions::AppRoutingSettings, String> {
    app_exclusions::get()
}

#[tauri::command]
fn choose_executable() -> Result<Option<String>, String> {
    app_exclusions::choose_executable()
}

#[tauri::command]
fn add_routed_app(path: String) -> Result<app_exclusions::AppRoutingSettings, String> {
    app_exclusions::add(path)
}

#[tauri::command]
fn remove_routed_app(path: String) -> Result<app_exclusions::AppRoutingSettings, String> {
    app_exclusions::remove(path)
}

#[tauri::command]
fn set_app_routing_mode(
    mode: mousevpn_windows_client::AppRoutingMode,
) -> Result<app_exclusions::AppRoutingSettings, String> {
    app_exclusions::set_mode(mode)
}

#[tauri::command]
fn clear_routed_apps() -> Result<app_exclusions::AppRoutingSettings, String> {
    app_exclusions::clear()
}

#[tauri::command]
#[cfg(windows)]
fn autostart_enabled() -> Result<bool, String> {
    let mut command = Command::new("schtasks.exe");
    command.creation_flags(CREATE_NO_WINDOW);
    command
        .args(["/Query", "/TN", AUTOSTART_TASK_NAME])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .map_err(display_error)
}

#[tauri::command]
#[cfg(not(windows))]
#[allow(clippy::unnecessary_wraps)]
fn autostart_enabled() -> Result<bool, String> {
    Ok(false)
}

#[tauri::command]
#[cfg(windows)]
fn set_autostart(enabled: bool) -> Result<bool, String> {
    let mut command = Command::new("schtasks.exe");
    command.creation_flags(CREATE_NO_WINDOW);
    if enabled {
        let executable = std::env::current_exe().map_err(display_error)?;
        let task_command = autostart_command(&executable);
        command.args([
            "/Create",
            "/TN",
            AUTOSTART_TASK_NAME,
            "/SC",
            "ONLOGON",
            "/RL",
            "HIGHEST",
            "/DELAY",
            "0000:10",
            "/TR",
            &task_command,
            "/F",
        ]);
    } else {
        if !autostart_enabled()? {
            return Ok(false);
        }
        command.args(["/Delete", "/TN", AUTOSTART_TASK_NAME, "/F"]);
    }
    let output = command.output().map_err(display_error)?;
    if !output.status.success() {
        let details = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        return Err(if details.is_empty() {
            format!("Task Scheduler завершился с кодом {}", output.status)
        } else {
            details
        });
    }
    Ok(enabled)
}

#[tauri::command]
#[cfg(not(windows))]
#[allow(clippy::unnecessary_wraps)]
fn set_autostart(_enabled: bool) -> Result<bool, String> {
    Err("Автозапуск доступен только в Windows".to_owned())
}

#[cfg(any(windows, test))]
fn autostart_command(executable: &Path) -> String {
    format!("\"{}\" --minimized", executable.display())
}

#[tauri::command]
fn connect_profile(id: String, state: State<'_, AppState>) -> Result<ConnectionSnapshot, String> {
    connect_profile_inner(id, &state)
}

pub(crate) fn connect_profile_inner(
    id: String,
    state: &AppState,
) -> Result<ConnectionSnapshot, String> {
    let id = profiles::normalized_id(&id)?;
    let path = profiles::profile_path(&id)?;
    let config: ClientConfig = load_toml(&path).map_err(display_error)?;
    config.validate().map_err(display_error)?;

    let mut child_slot = lock(&state.child)?;
    if let Some(child) = child_slot.as_mut() {
        if child.try_wait().map_err(display_error)?.is_none() {
            return Err("VPN уже запущен".to_owned());
        }
        *child_slot = None;
    }
    let mut command = Command::new(std::env::current_exe().map_err(display_error)?);
    #[cfg(windows)]
    command.creation_flags(CREATE_NO_WINDOW);
    let mut child = command
        .arg("--helper")
        .arg("--config")
        .arg(path)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("Не удалось запустить Windows helper: {error}"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "Не удалось открыть журнал helper-процесса".to_owned())?;
    let snapshot = ConnectionSnapshot {
        state: "connecting".to_owned(),
        message: "Настраиваем Wintun и маршруты…".to_owned(),
        profile_id: Some(id.clone()),
    };
    *lock(&state.snapshot)? = snapshot.clone();
    *lock(&state.last_profile_id)? = Some(id);
    let shared_snapshot = Arc::clone(&state.snapshot);
    let generation = Arc::clone(&state.generation);
    let reader_generation = generation.fetch_add(1, Ordering::AcqRel) + 1;
    let log = helper_log::HelperLog::open().ok();
    thread::spawn(move || {
        read_helper_status(
            stderr,
            &shared_snapshot,
            &generation,
            reader_generation,
            log,
        );
    });
    *child_slot = Some(child);
    Ok(snapshot)
}

#[tauri::command]
fn disconnect(state: State<'_, AppState>) -> Result<ConnectionSnapshot, String> {
    disconnect_inner(&state)
}

pub(crate) fn disconnect_inner(state: &AppState) -> Result<ConnectionSnapshot, String> {
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
    state.generation.fetch_add(1, Ordering::AcqRel);
    let mut snapshot = lock(&state.snapshot)?;
    "disconnecting".clone_into(&mut snapshot.state);
    "Восстанавливаем маршруты и DNS…".clone_into(&mut snapshot.message);
    Ok(snapshot.clone())
}

#[tauri::command]
fn connection_status(state: State<'_, AppState>) -> Result<ConnectionSnapshot, String> {
    connection_status_inner(&state)
}

pub(crate) fn connection_status_inner(state: &AppState) -> Result<ConnectionSnapshot, String> {
    let mut child_slot = lock(&state.child)?;
    if let Some(child) = child_slot.as_mut() {
        if let Some(exit) = child.try_wait().map_err(display_error)? {
            state.generation.fetch_add(1, Ordering::AcqRel);
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

pub(crate) fn tray_toggle(state: &AppState) -> Result<(), String> {
    let snapshot = connection_status_inner(state)?;
    if matches!(
        snapshot.state.as_str(),
        "connecting" | "connected" | "disconnecting"
    ) {
        if snapshot.state != "disconnecting" {
            disconnect_inner(state)?;
        }
        return Ok(());
    }

    let remembered = lock(&state.last_profile_id)?.clone();
    let id = match remembered {
        Some(id) if profiles::profile_path(&id)?.exists() => id,
        _ => profiles::list()?
            .first()
            .map(|profile| profile.id().to_owned())
            .ok_or_else(|| "Сначала добавьте профиль в окне MouseVPN".to_owned())?,
    };
    connect_profile_inner(id, state).map(|_| ())
}

pub(crate) fn set_tray_error(state: &AppState, message: String) {
    if let Ok(mut snapshot) = state.snapshot.lock() {
        "error".clone_into(&mut snapshot.state);
        snapshot.message = message;
    }
}

pub(crate) fn shutdown_for_exit(state: &AppState) {
    state.quitting.store(true, Ordering::Release);
    let Ok(mut child_slot) = state.child.lock() else {
        return;
    };
    let Some(child) = child_slot.as_mut() else {
        return;
    };
    if let Some(stdin) = child.stdin.as_mut() {
        let _ = stdin.write_all(b"stop\n");
        let _ = stdin.flush();
    }
    for _ in 0..100 {
        if child.try_wait().is_ok_and(|status| status.is_some()) {
            *child_slot = None;
            return;
        }
        thread::sleep(std::time::Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
    *child_slot = None;
    drop(child_slot);
    let _ = mousevpn_windows_client::repair_network();
}

fn read_helper_status(
    stderr: impl std::io::Read,
    snapshot: &Arc<Mutex<ConnectionSnapshot>>,
    generation: &AtomicU64,
    reader_generation: u64,
    mut log: Option<helper_log::HelperLog>,
) {
    let log_path = log.as_ref().map(|log| log.path().display().to_string());
    if let Some(log) = log.as_mut() {
        log.write("MOUSEVPN_STATE=helper_started");
    }
    for line in BufReader::new(stderr).lines().map_while(Result::ok) {
        if let Some(log) = log.as_mut() {
            log.write(&line);
        }
        if generation.load(Ordering::Acquire) != reader_generation {
            continue;
        }
        let Ok(mut current) = snapshot.lock() else {
            return;
        };
        if generation.load(Ordering::Acquire) != reader_generation {
            continue;
        }
        if line == "MOUSEVPN_STATE=connected" {
            "connected".clone_into(&mut current.state);
            "Защищённое соединение установлено".clone_into(&mut current.message);
        } else if line == "MOUSEVPN_STATE=reconnecting" {
            "connecting".clone_into(&mut current.state);
            "Связь потеряна, переподключаемся…".clone_into(&mut current.message);
        } else if line == "MOUSEVPN_STATE=reconnected" {
            "connected".clone_into(&mut current.state);
            "Соединение восстановлено".clone_into(&mut current.message);
        } else if matches!(
            line.as_str(),
            "MOUSEVPN_STATE=restarting" | "MOUSEVPN_STATE=failed_closed"
        ) {
            "connecting".clone_into(&mut current.state);
            if !current.message.starts_with("Восстанавливаем VPN:") {
                "Перезапускаем сетевой туннель без утечки трафика…"
                    .clone_into(&mut current.message);
            }
        } else if let Some(message) = line.strip_prefix("MOUSEVPN_RUNTIME_WARNING=") {
            "connecting".clone_into(&mut current.state);
            current.message = format!("Восстанавливаем VPN: {message}");
        } else if let Some(message) = line.strip_prefix("MOUSEVPN_ERROR=") {
            "error".clone_into(&mut current.state);
            current.message = log_path.as_ref().map_or_else(
                || message.to_owned(),
                |path| format!("{message}\nЖурнал: {path}"),
            );
        }
    }
    if let Some(log) = log.as_mut() {
        log.write("MOUSEVPN_STATE=helper_stderr_closed");
    }
}

fn run_helper(path: &Path) -> Result<(), String> {
    let config: ClientConfig = load_toml(path).map_err(display_error)?;
    let config = config.validate().map_err(display_error)?;
    let app_routing = app_exclusions::policy()?;
    let stopping = Arc::new(AtomicBool::new(false));
    let stdin_stopping = Arc::clone(&stopping);
    thread::spawn(move || {
        let mut line = String::new();
        let _ = std::io::stdin().read_line(&mut line);
        stdin_stopping.store(true, Ordering::Release);
    });
    let mut backoff = std::time::Duration::from_secs(1);
    eprintln!("MOUSEVPN_STATE=connecting");
    loop {
        match mousevpn_windows_client::run_with_stop(&config, &stopping, &app_routing) {
            Ok(()) => return Ok(()),
            Err(_) if stopping.load(Ordering::Acquire) => return Ok(()),
            Err(error) => {
                eprintln!("MOUSEVPN_RUNTIME_WARNING={error}");
                eprintln!("MOUSEVPN_STATE=restarting");
                if wait_for_stop(&stopping, backoff) {
                    return Ok(());
                }
                backoff = (backoff * 2).min(std::time::Duration::from_secs(16));
            }
        }
    }
}

fn wait_for_stop(stopping: &AtomicBool, duration: std::time::Duration) -> bool {
    let deadline = std::time::Instant::now() + duration;
    while !stopping.load(Ordering::Acquire) {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return false;
        }
        thread::sleep(remaining.min(std::time::Duration::from_millis(100)));
    }
    true
}

fn lock<T>(mutex: &Mutex<T>) -> Result<std::sync::MutexGuard<'_, T>, String> {
    mutex
        .lock()
        .map_err(|_| "Внутренняя блокировка повреждена".to_owned())
}

fn display_error(error: impl std::fmt::Display) -> String {
    error.to_string()
}

fn run_gui(minimized: bool) {
    tauri::Builder::default()
        .manage(AppState::default())
        .setup(move |app| {
            tray::install(app)?;
            if minimized {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.hide();
                }
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                let state = window.state::<AppState>();
                if !state.quitting.load(Ordering::Acquire) {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            runtime_diagnostics,
            list_profiles,
            import_profile,
            delete_profile,
            get_app_routing,
            choose_executable,
            add_routed_app,
            remove_routed_app,
            set_app_routing_mode,
            clear_routed_apps,
            autostart_enabled,
            set_autostart,
            connect_profile,
            disconnect,
            connection_status,
        ])
        .run(tauri::generate_context!())
        .expect("failed to run MouseVPN Windows GUI");
}

fn main() {
    let arguments: Vec<String> = std::env::args().collect();
    match arguments.as_slice() {
        [_, diagnose] if diagnose == "--diagnose" => {
            let report = mousevpn_windows_client::diagnose();
            println!("platform={}", report.platform);
            println!("running_under_wine={}", report.running_under_wine);
            println!("wintun_available={}", report.wintun_available);
            println!("elevated={}", report.elevated);
            println!("message={}", report.message);
        }
        [_, repair] if repair == "--repair-network" => {
            match mousevpn_windows_client::repair_network() {
                Ok(()) => println!("MouseVPN network state repaired"),
                Err(error) => {
                    eprintln!("MOUSEVPN_ERROR={error}");
                    std::process::exit(1);
                }
            }
        }
        [_, report] if report == "--network-report" => {
            match mousevpn_windows_client::network_report() {
                Ok(report) => println!("{report}"),
                Err(error) => {
                    eprintln!("MOUSEVPN_ERROR={error}");
                    std::process::exit(1);
                }
            }
        }
        [_, helper, config, path] if helper == "--helper" && config == "--config" => {
            if let Err(error) = run_helper(Path::new(path)) {
                eprintln!("MOUSEVPN_ERROR={error}");
                std::process::exit(1);
            }
        }
        [_, minimized] if minimized == "--minimized" => run_gui(true),
        _ => run_gui(false),
    }
}

#[cfg(test)]
mod helper_status_tests {
    use std::{
        io::Cursor,
        sync::{atomic::AtomicU64, Arc, Mutex},
    };

    use super::{autostart_command, read_helper_status, ConnectionSnapshot};

    #[test]
    fn autostart_quotes_the_executable_and_starts_minimized() {
        assert_eq!(
            autostart_command(std::path::Path::new(
                r"C:\Program Files\MouseVPN\MouseVPN.exe"
            )),
            r#""C:\Program Files\MouseVPN\MouseVPN.exe" --minimized"#
        );
    }

    #[test]
    fn stale_helper_cannot_overwrite_a_new_connection() {
        let snapshot = Arc::new(Mutex::new(ConnectionSnapshot {
            state: "connected".to_owned(),
            message: "new connection".to_owned(),
            profile_id: Some("new".to_owned()),
        }));
        read_helper_status(
            Cursor::new(b"MOUSEVPN_STATE=restarting\n"),
            &snapshot,
            &AtomicU64::new(2),
            1,
            None,
        );
        let snapshot = snapshot.lock().expect("snapshot");
        assert_eq!(snapshot.state, "connected");
        assert_eq!(snapshot.message, "new connection");
    }

    #[test]
    fn restart_state_preserves_the_specific_runtime_error() {
        let snapshot = Arc::new(Mutex::new(ConnectionSnapshot::default()));
        read_helper_status(
            Cursor::new(
                b"MOUSEVPN_RUNTIME_WARNING=network cleanup failed\nMOUSEVPN_STATE=restarting\n",
            ),
            &snapshot,
            &AtomicU64::new(1),
            1,
            None,
        );
        let snapshot = snapshot.lock().expect("snapshot");
        assert_eq!(snapshot.state, "connecting");
        assert_eq!(
            snapshot.message,
            "Восстанавливаем VPN: network cleanup failed"
        );
    }
}
