use std::{fs, path::PathBuf, process::Command};

use std::os::windows::process::CommandExt;

use crate::{network, ClientError};

const WINTUN_DLL: &[u8] = include_bytes!("../vendor/wintun/wintun.dll");
pub(crate) const WINTUN_VERSION: &str = "0.14.1";
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeDiagnostics {
    pub platform: &'static str,
    pub running_under_wine: bool,
    pub wintun_available: bool,
    pub elevated: bool,
    pub message: String,
}

#[must_use]
pub fn diagnose() -> RuntimeDiagnostics {
    let running_under_wine = is_wine();
    let elevated = is_elevated();
    let message = match (running_under_wine, elevated) {
        (true, _) => {
            "Wine detected: headless checks are supported, but the Wintun driver is unavailable"
                .to_owned()
        }
        (false, true) => format!("Windows runtime is ready (embedded Wintun {WINTUN_VERSION})"),
        (false, false) => "MouseVPN must be started as Administrator".to_owned(),
    };
    RuntimeDiagnostics {
        platform: "windows",
        running_under_wine,
        wintun_available: !running_under_wine,
        elevated,
        message,
    }
}

pub(crate) fn ensure_supported_runtime() -> Result<(), ClientError> {
    if is_wine() {
        return Err(ClientError::Platform(
            "Wintun cannot run under Wine; use Windows or a Windows VM for tunnel tests".to_owned(),
        ));
    }
    if !is_elevated() {
        return Err(ClientError::Platform(
            "MouseVPN must be started as Administrator".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) fn materialize_wintun() -> Result<PathBuf, ClientError> {
    let directory = network::runtime_dir()?;
    fs::create_dir_all(&directory)?;
    let destination = directory.join(format!("wintun-{WINTUN_VERSION}.dll"));
    if fs::read(&destination).is_ok_and(|contents| contents == WINTUN_DLL) {
        return Ok(destination);
    }
    let temporary = directory.join(format!(
        "wintun-{WINTUN_VERSION}.tmp-{}",
        std::process::id()
    ));
    fs::write(&temporary, WINTUN_DLL)?;
    if destination.exists() {
        fs::remove_file(&destination)?;
    }
    if let Err(error) = fs::rename(&temporary, &destination) {
        let _ = fs::remove_file(&temporary);
        return Err(error.into());
    }
    Ok(destination)
}

fn is_elevated() -> bool {
    let mut command = Command::new("net");
    command.creation_flags(CREATE_NO_WINDOW);
    command
        .arg("session")
        .output()
        .is_ok_and(|output| output.status.success())
}

fn is_wine() -> bool {
    let mut command = Command::new("reg.exe");
    command.creation_flags(CREATE_NO_WINDOW);
    command
        .args(["query", r"HKCU\Software\Wine"])
        .output()
        .is_ok_and(|output| output.status.success())
}
