use std::{
    fs::{self, OpenOptions},
    io,
    net::Ipv4Addr,
    path::Path,
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

use fs2::FileExt;
use mousevpn_config::{load_toml, ClientConfig};
use mousevpn_linux_client::run_with_stop;

const RUNTIME_LOCK_PATH: &str = "/run/mousevpn-linux-gui.lock";

pub fn run(config_path: &Path) -> Result<(), String> {
    let lock = open_runtime_lock()?;
    acquire_runtime_lock(&lock)?;
    let config: ClientConfig = load_toml(config_path).map_err(display_error)?;
    let config = config.validate().map_err(display_error)?;
    let server_ip = match config.server.ip() {
        std::net::IpAddr::V4(address) => address,
        std::net::IpAddr::V6(_) => {
            return Err("Адрес VPN-сервера IPv6 пока не поддерживается".to_owned());
        }
    };
    spawn_watchdog(server_ip)?;
    let stopping = Arc::new(AtomicBool::new(false));
    let stdin_stopping = Arc::clone(&stopping);
    thread::spawn(move || {
        let mut line = String::new();
        let _ = std::io::stdin().read_line(&mut line);
        stdin_stopping.store(true, Ordering::Release);
    });
    eprintln!("MOUSEVPN_STATE=connecting");
    run_with_stop(&config, stopping).map_err(display_error)
}

pub fn run_watchdog(parent: u32, started: u64, server: Ipv4Addr) -> Result<(), String> {
    loop {
        match process_identity(parent) {
            Ok((state, actual_start)) if state != 'Z' && actual_start == started => {
                thread::sleep(Duration::from_millis(250));
            }
            Ok(_) | Err(_) => break,
        }
    }
    let lock = open_runtime_lock()?;
    match lock.try_lock_exclusive() {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
        Err(error) => return Err(display_error(error)),
    }
    mousevpn_linux_client::repair_stale_network(server).map_err(display_error)
}

fn open_runtime_lock() -> Result<std::fs::File, String> {
    use std::os::unix::fs::OpenOptionsExt;

    OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .mode(0o600)
        .open(RUNTIME_LOCK_PATH)
        .map_err(display_error)
}

fn spawn_watchdog(server: Ipv4Addr) -> Result<(), String> {
    let parent = std::process::id();
    let (_, started) = process_identity(parent).map_err(display_error)?;
    Command::new(std::env::current_exe().map_err(display_error)?)
        .args([
            "--network-watchdog",
            "--parent",
            &parent.to_string(),
            "--started",
            &started.to_string(),
            "--server",
            &server.to_string(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .spawn()
        .map(|_| ())
        .map_err(|error| format!("Не удалось запустить watchdog MouseVPN: {error}"))
}

fn process_identity(pid: u32) -> io::Result<(char, u64)> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let command_end = stat
        .rfind(')')
        .ok_or_else(|| io::Error::other("invalid /proc process stat"))?;
    let mut fields = stat[command_end + 1..].split_whitespace();
    let state = fields
        .next()
        .and_then(|value| value.chars().next())
        .ok_or_else(|| io::Error::other("process state is unavailable"))?;
    let started = fields
        .nth(18)
        .ok_or_else(|| io::Error::other("process start time is unavailable"))?
        .parse()
        .map_err(|error| io::Error::other(format!("invalid process start time: {error}")))?;
    Ok((state, started))
}

fn acquire_runtime_lock(lock: &std::fs::File) -> Result<(), String> {
    const LOCK_WAIT: Duration = Duration::from_secs(2);
    const LOCK_POLL: Duration = Duration::from_millis(50);

    let deadline = Instant::now() + LOCK_WAIT;
    loop {
        match lock.try_lock_exclusive() {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err("Другой процесс MouseVPN уже подключается или работает".to_owned());
                }
                thread::sleep(LOCK_POLL);
            }
            Err(error) => return Err(display_error(error)),
        }
    }
}

fn display_error(error: impl std::fmt::Display) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests {
    use super::process_identity;

    #[test]
    fn reads_the_current_process_identity() {
        let (state, started) = process_identity(std::process::id()).unwrap();
        assert_ne!(state, 'Z');
        assert!(started > 0);
    }
}
