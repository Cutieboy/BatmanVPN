use std::{fs, io, os::unix::fs::PermissionsExt, path::PathBuf};

use serde::Serialize;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HelperState<'a> {
    status: &'a str,
    message: &'a str,
    server: Option<&'a str>,
    pid: u32,
}

pub(crate) struct StateWriter {
    path: PathBuf,
}

impl StateWriter {
    pub(crate) fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub(crate) fn write(
        &self,
        status: &str,
        message: &str,
        server: Option<&str>,
    ) -> Result<(), io::Error> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let state = HelperState {
            status,
            message,
            server,
            pid: std::process::id(),
        };
        let bytes = serde_json::to_vec(&state).map_err(io::Error::other)?;
        fs::write(&self.path, bytes)?;
        let mut permissions = fs::metadata(&self.path)?.permissions();
        permissions.set_mode(0o644);
        fs::set_permissions(&self.path, permissions)
    }
}
