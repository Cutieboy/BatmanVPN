#![cfg_attr(not(target_os = "macos"), allow(dead_code, unused_imports))]

#[cfg(target_os = "macos")]
mod network;
#[cfg(target_os = "macos")]
mod state;
#[cfg(target_os = "macos")]
mod utun;

#[cfg(target_os = "macos")]
use std::{
    env,
    error::Error,
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, RwLock,
    },
    thread,
    time::{Duration, Instant},
};

#[cfg(target_os = "macos")]
use mousevpn_apple::AppleSession;
#[cfg(target_os = "macos")]
use mousevpn_profile_cli::decrypt_profile;
#[cfg(target_os = "macos")]
use serde::{Deserialize, Serialize};
#[cfg(target_os = "macos")]
use signal_hook::{
    consts::signal::{SIGINT, SIGTERM},
    flag,
};
#[cfg(target_os = "macos")]
use zeroize::Zeroize;

#[cfg(target_os = "macos")]
use crate::{
    network::{primary_ipv4, NetworkConfiguration},
    state::StateWriter,
    utun::Utun,
};

#[cfg(target_os = "macos")]
const RECEIVE_TIMEOUT: Duration = Duration::from_millis(250);
#[cfg(target_os = "macos")]
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
#[cfg(target_os = "macos")]
const SESSION_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(target_os = "macos")]
const MAX_RECONNECT_BACKOFF: Duration = Duration::from_secs(16);

#[cfg(target_os = "macos")]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct HelperProfile {
    token: String,
    password: String,
}

#[cfg(target_os = "macos")]
struct ResolvedProfile {
    id: String,
    name: String,
    endpoint: String,
    server_public_key: String,
    client_private_key: String,
}

#[cfg(target_os = "macos")]
impl Drop for ResolvedProfile {
    fn drop(&mut self) {
        self.server_public_key.zeroize();
        self.client_private_key.zeroize();
    }
}

#[cfg(target_os = "macos")]
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProfileSummary<'a> {
    id: &'a str,
    name: &'a str,
    endpoint: &'a str,
}

#[cfg(target_os = "macos")]
struct Arguments {
    config: PathBuf,
    state: PathBuf,
    pid_file: PathBuf,
    stop_file: PathBuf,
}

#[cfg(target_os = "macos")]
struct TunnelRuntime<'a> {
    profile: &'a ResolvedProfile,
    state: &'a StateWriter,
    tun: Arc<Utun>,
    sessions: Arc<RwLock<Arc<AppleSession>>>,
    reconnecting: Arc<AtomicBool>,
    stopping: Arc<AtomicBool>,
    worker: mpsc::Receiver<String>,
    network: NetworkConfiguration,
    parameters: mousevpn_apple::TunnelParameters,
    server_ip: std::net::Ipv4Addr,
    stop_file: &'a Path,
}

#[cfg(target_os = "macos")]
fn main() {
    let result = if env::args().nth(1).as_deref() == Some("--inspect-profile") {
        inspect_profile()
    } else {
        run_main()
    };
    if let Err(error) = result {
        eprintln!("MouseVPN helper failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("mousevpn-macos-helper can only run on macOS");
    std::process::exit(1);
}

#[cfg(target_os = "macos")]
fn run_main() -> Result<(), Box<dyn Error>> {
    let arguments = parse_arguments()?;
    let state = StateWriter::new(arguments.state.clone());
    if unsafe { libc::geteuid() } != 0 {
        state.write("error", "Требуются права администратора", None)?;
        return Err("helper must run as root".into());
    }
    if let Err(error) = acquire_pid_file(&arguments.pid_file) {
        state.write("error", &error.to_string(), None)?;
        return Err(error.into());
    }
    let _pid = PidFileGuard(arguments.pid_file);

    state.write("connecting", "Расшифровка MV1-профиля", None)?;
    let mut endpoint = None;
    let result = (|| -> Result<(), io::Error> {
        let profile = load_profile(&arguments.config)?;
        endpoint = Some(profile.endpoint.clone());
        run_tunnel(&profile, &state, &arguments.stop_file)
    })();
    match &result {
        Ok(()) => state.write("disconnected", "VPN отключён", endpoint.as_deref())?,
        Err(error) => state.write("error", &error.to_string(), endpoint.as_deref())?,
    }
    result.map_err(Into::into)
}

#[cfg(target_os = "macos")]
fn inspect_profile() -> Result<(), Box<dyn Error>> {
    if env::args().count() != 2 {
        return Err("usage: mousevpn-macos-helper --inspect-profile".into());
    }
    let mut bytes = Vec::new();
    io::stdin().take(2 * 1024 * 1024).read_to_end(&mut bytes)?;
    let profile = decode_profile(&bytes)?;
    serde_json::to_writer(
        io::stdout(),
        &ProfileSummary {
            id: &profile.id,
            name: &profile.name,
            endpoint: &profile.endpoint,
        },
    )?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn load_profile(path: &Path) -> Result<ResolvedProfile, io::Error> {
    let bytes = fs::read(path)?;
    let _ = fs::remove_file(path);
    decode_profile(&bytes)
}

#[cfg(target_os = "macos")]
fn decode_profile(bytes: &[u8]) -> Result<ResolvedProfile, io::Error> {
    let mut wrapper: HelperProfile = serde_json::from_slice(bytes).map_err(io::Error::other)?;
    let decrypted = decrypt_profile(&wrapper.token, wrapper.password.as_bytes())
        .map_err(|error| io::Error::new(io::ErrorKind::PermissionDenied, error.to_string()));
    wrapper.password.zeroize();
    let profile = decrypted?;
    let (id, name, endpoint, server_public_key, client_private_key) = profile.into_parts();
    Ok(ResolvedProfile {
        id,
        name,
        endpoint,
        server_public_key,
        client_private_key,
    })
}

#[cfg(target_os = "macos")]
fn run_tunnel(
    profile: &ResolvedProfile,
    state: &StateWriter,
    stop_file: &Path,
) -> Result<(), io::Error> {
    state.write(
        "connecting",
        &format!("Подключение профиля {}", profile.name),
        Some(&profile.endpoint),
    )?;
    let physical_address = primary_ipv4()?;
    eprintln!("MOUSEVPN_OUTER_ADDRESS={physical_address}");
    let session = Arc::new(
        AppleSession::connect_from(
            &profile.endpoint,
            profile.server_public_key.clone(),
            profile.client_private_key.clone(),
            Some(physical_address.into()),
        )
        .map_err(io::Error::other)?,
    );
    let parameters = session.parameters().clone();
    let server_ip = match parameters.remote_address {
        std::net::IpAddr::V4(address) => address,
        std::net::IpAddr::V6(_) => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "IPv6-адрес VPN-сервера пока не поддерживается helper-режимом",
            ));
        }
    };

    let tun = Arc::new(Utun::create()?);
    tun.set_nonblocking()?;
    tun.configure(
        parameters.client_address,
        parameters.prefix_len,
        parameters.mtu,
    )?;
    let network = NetworkConfiguration::install(tun.name(), server_ip, parameters.dns)?;

    let stopping = Arc::new(AtomicBool::new(false));
    flag::register(SIGINT, Arc::clone(&stopping))?;
    flag::register(SIGTERM, Arc::clone(&stopping))?;
    let sessions = Arc::new(RwLock::new(session));
    let reconnecting = Arc::new(AtomicBool::new(false));
    let (worker_tx, worker_rx) = mpsc::sync_channel(1);
    let outgoing_tun = Arc::clone(&tun);
    let outgoing_sessions = Arc::clone(&sessions);
    let outgoing_stopping = Arc::clone(&stopping);
    let outgoing_reconnecting = Arc::clone(&reconnecting);
    thread::spawn(move || {
        if let Err(error) = outgoing_loop(
            &outgoing_tun,
            &outgoing_sessions,
            &outgoing_stopping,
            &outgoing_reconnecting,
            &worker_tx,
        ) {
            let _ = worker_tx.send(error.to_string());
        }
    });

    TunnelRuntime {
        profile,
        state,
        tun,
        sessions,
        reconnecting,
        stopping,
        worker: worker_rx,
        network,
        parameters,
        server_ip,
        stop_file,
    }
    .run()
}

#[cfg(target_os = "macos")]
impl TunnelRuntime<'_> {
    fn run(mut self) -> Result<(), io::Error> {
        self.state
            .write("connected", "VPN работает", Some(&self.profile.endpoint))?;
        eprintln!("MOUSEVPN_STATE=connected");
        eprintln!("MouseVPN connected through {}", self.tun.name());

        let mut last_keepalive = Instant::now();
        let mut last_activity = Instant::now();
        while !stop_requested(&self.stopping, self.stop_file) {
            let mut reconnect_reason = self.worker.try_recv().ok();
            let session = session_snapshot(&self.sessions)?;
            if reconnect_reason.is_none() {
                match session.receive_packets(RECEIVE_TIMEOUT, 32) {
                    Ok(batch) => {
                        if batch.had_activity {
                            last_activity = Instant::now();
                        }
                        self.write_packets(&batch.packets)?;
                    }
                    Err(error) => {
                        reconnect_reason = Some(format!("receiving tunnel packets: {error}"));
                    }
                }
            }
            if reconnect_reason.is_none() && last_activity.elapsed() >= SESSION_TIMEOUT {
                reconnect_reason = Some("сервер не отвечает на keepalive".to_owned());
            }
            if reconnect_reason.is_none() && last_keepalive.elapsed() >= KEEPALIVE_INTERVAL {
                if let Err(error) = session.send_keepalive() {
                    reconnect_reason = Some(format!("sending keepalive: {error}"));
                }
                last_keepalive = Instant::now();
            }
            if let Some(reason) = reconnect_reason {
                if let Err(error) = self.reconnect_session(&reason) {
                    if stop_requested(&self.stopping, self.stop_file)
                        && error.kind() == io::ErrorKind::Interrupted
                    {
                        return Ok(());
                    }
                    return Err(error);
                }
                last_activity = Instant::now();
                last_keepalive = Instant::now();
            }
        }
        Ok(())
    }

    fn write_packets(&self, packets: &[Vec<u8>]) -> Result<(), io::Error> {
        for packet in packets {
            self.tun.write_packet(packet).map_err(|error| {
                io::Error::new(error.kind(), format!("writing to utun: {error}"))
            })?;
        }
        Ok(())
    }

    fn reconnect_session(&mut self, reason: &str) -> Result<(), io::Error> {
        eprintln!("MOUSEVPN_RECONNECT_REASON={reason}");
        self.reconnecting.store(true, Ordering::Relaxed);
        self.state.write(
            "reconnecting",
            "Восстановление защищённой сессии",
            Some(&self.profile.endpoint),
        )?;
        let replacement = reconnect(
            self.profile,
            &self.parameters,
            self.server_ip,
            &mut self.network,
            &self.stopping,
            self.stop_file,
            self.state,
        )?;
        *self
            .sessions
            .write()
            .map_err(|_| io::Error::other("session lock is poisoned"))? = replacement;
        while self.worker.try_recv().is_ok() {}
        self.reconnecting.store(false, Ordering::Relaxed);
        self.state.write(
            "connected",
            "VPN переподключён",
            Some(&self.profile.endpoint),
        )?;
        eprintln!("MOUSEVPN_STATE=reconnected");
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn outgoing_loop(
    tun: &Utun,
    sessions: &RwLock<Arc<AppleSession>>,
    stopping: &AtomicBool,
    reconnecting: &AtomicBool,
    errors: &mpsc::SyncSender<String>,
) -> Result<(), io::Error> {
    let mut packet = vec![0_u8; 65_535];
    while !stopping.load(Ordering::Relaxed) {
        if reconnecting.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_millis(10));
            continue;
        }
        match tun.read_packet(&mut packet) {
            Ok(Some(length)) => {
                let session = session_snapshot(sessions)?;
                if let Err(error) = session.send_packets(&[&packet[..length]]) {
                    let _ = errors.try_send(format!("sending packets from utun: {error}"));
                    thread::sleep(Duration::from_millis(10));
                }
            }
            Ok(None) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(2));
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn session_snapshot(sessions: &RwLock<Arc<AppleSession>>) -> Result<Arc<AppleSession>, io::Error> {
    sessions
        .read()
        .map(|session| Arc::clone(&session))
        .map_err(|_| io::Error::other("session lock is poisoned"))
}

#[cfg(target_os = "macos")]
fn reconnect(
    profile: &ResolvedProfile,
    expected: &mousevpn_apple::TunnelParameters,
    server_ip: std::net::Ipv4Addr,
    network: &mut NetworkConfiguration,
    stopping: &AtomicBool,
    stop_file: &Path,
    state: &StateWriter,
) -> Result<Arc<AppleSession>, io::Error> {
    let mut backoff = Duration::from_secs(1);
    loop {
        if stop_requested(stopping, stop_file) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "reconnect stopped",
            ));
        }
        let attempt = (|| -> Result<Arc<AppleSession>, io::Error> {
            network.refresh_server_route(server_ip)?;
            let physical_address = primary_ipv4()?;
            let replacement = Arc::new(
                AppleSession::connect_from(
                    &profile.endpoint,
                    profile.server_public_key.clone(),
                    profile.client_private_key.clone(),
                    Some(physical_address.into()),
                )
                .map_err(io::Error::other)?,
            );
            let actual = replacement.parameters();
            if actual.client_address != expected.client_address
                || actual.prefix_len != expected.prefix_len
                || actual.dns != expected.dns
                || actual.mtu != expected.mtu
            {
                return Err(io::Error::other(
                    "server changed tunnel parameters during reconnect",
                ));
            }
            Ok(replacement)
        })();
        match attempt {
            Ok(session) => return Ok(session),
            Err(error) => {
                eprintln!("MOUSEVPN_RECONNECT_ERROR={error}");
                state.write(
                    "reconnecting",
                    &format!("Повтор через {} с: {error}", backoff.as_secs()),
                    Some(&profile.endpoint),
                )?;
            }
        }
        sleep_with_stop(backoff, stopping, stop_file);
        backoff = (backoff * 2).min(MAX_RECONNECT_BACKOFF);
    }
}

#[cfg(target_os = "macos")]
fn sleep_with_stop(duration: Duration, stopping: &AtomicBool, stop_file: &Path) {
    let deadline = Instant::now() + duration;
    while !stop_requested(stopping, stop_file) && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(target_os = "macos")]
fn stop_requested(stopping: &AtomicBool, stop_file: &Path) -> bool {
    stopping.load(Ordering::Relaxed) || stop_file.exists()
}

#[cfg(target_os = "macos")]
fn parse_arguments() -> Result<Arguments, io::Error> {
    let mut arguments = env::args_os().skip(1);
    let mut config = None;
    let mut state = None;
    let mut pid_file = None;
    let mut stop_file = None;
    while let Some(argument) = arguments.next() {
        match argument.to_str() {
            Some("--config") => config = arguments.next().map(PathBuf::from),
            Some("--state") => state = arguments.next().map(PathBuf::from),
            Some("--pid-file") => pid_file = arguments.next().map(PathBuf::from),
            Some("--stop-file") => stop_file = arguments.next().map(PathBuf::from),
            _ => return Err(io::Error::new(io::ErrorKind::InvalidInput, usage())),
        }
    }
    Ok(Arguments {
        config: config.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, usage()))?,
        state: state.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, usage()))?,
        pid_file: pid_file.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, usage()))?,
        stop_file: stop_file.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, usage()))?,
    })
}

#[cfg(target_os = "macos")]
fn usage() -> &'static str {
    "usage: mousevpn-macos-helper --config <profile.json> --state <state.json> --pid-file <helper.pid> --stop-file <stop-request>"
}

#[cfg(target_os = "macos")]
fn acquire_pid_file(path: &Path) -> Result<(), io::Error> {
    if let Ok(contents) = fs::read_to_string(path) {
        if let Ok(pid) = contents.trim().parse::<libc::pid_t>() {
            let alive = unsafe { libc::kill(pid, 0) } == 0;
            if alive {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "MouseVPN helper is already running",
                ));
            }
        }
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, std::process::id().to_string())
}

#[cfg(target_os = "macos")]
struct PidFileGuard(PathBuf);

#[cfg(target_os = "macos")]
impl Drop for PidFileGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use std::{fs, time::SystemTime};

    use mousevpn_profile_cli::{encrypt_profile, PortableProfile};
    use serde_json::json;

    use super::load_profile;

    #[test]
    fn mv1_envelope_is_decrypted_and_removed() {
        let profile =
            PortableProfile::new("MacBook", "198.51.100.9:51820", "server-key", "client-key");
        let token = encrypt_profile(&profile, b"correct horse").expect("encrypt test profile");
        let unique = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "mousevpn-macos-profile-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&directory).expect("create test directory");
        let path = directory.join("profile.json");
        fs::write(
            &path,
            serde_json::to_vec(&json!({
                "token": token,
                "password": "correct horse"
            }))
            .expect("serialize wrapper"),
        )
        .expect("write wrapper");

        let resolved = load_profile(&path).expect("decrypt wrapper");
        assert_eq!(resolved.name, "MacBook");
        assert_eq!(resolved.endpoint, "198.51.100.9:51820");
        assert_eq!(resolved.server_public_key, "server-key");
        assert_eq!(resolved.client_private_key, "client-key");
        assert!(!path.exists());
        fs::remove_dir(directory).expect("remove test directory");
    }
}
