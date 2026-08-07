use std::{
    fs::OpenOptions,
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
};

use fs2::FileExt;
use mousevpn_config::{load_toml, ClientConfig};
use mousevpn_linux_client::run_with_stop;

pub fn run(config_path: &Path) -> Result<(), String> {
    use std::os::unix::fs::OpenOptionsExt;

    let lock = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .mode(0o600)
        .open("/run/mousevpn-linux-gui.lock")
        .map_err(display_error)?;
    lock.try_lock_exclusive().map_err(|error| {
        if error.kind() == std::io::ErrorKind::WouldBlock {
            "Другой процесс MouseVPN уже подключается или работает".to_owned()
        } else {
            display_error(error)
        }
    })?;
    let config: ClientConfig = load_toml(config_path).map_err(display_error)?;
    let config = config.validate().map_err(display_error)?;
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

fn display_error(error: impl std::fmt::Display) -> String {
    error.to_string()
}
