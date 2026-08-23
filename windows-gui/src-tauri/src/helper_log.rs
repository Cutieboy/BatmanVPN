use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

const MAX_LOG_BYTES: u64 = 2 * 1024 * 1024;

pub(crate) struct HelperLog {
    /// Absent only for the moment a rotation holds, because Windows will not
    /// rename a file that is still open.
    file: Option<File>,
    path: PathBuf,
    written: u64,
}

impl HelperLog {
    pub(crate) fn open() -> io::Result<Self> {
        let path = path()?;
        let directory = path
            .parent()
            .ok_or_else(|| io::Error::other("helper log has no parent directory"))?;
        fs::create_dir_all(directory)?;
        if fs::metadata(&path).is_ok_and(|metadata| metadata.len() >= MAX_LOG_BYTES) {
            rotate(&path)?;
        }
        let file = append_to(&path)?;
        let written = file.metadata().map_or(0, |metadata| metadata.len());
        Ok(Self {
            file: Some(file),
            path,
            written,
        })
    }

    pub(crate) fn path(&self) -> &PathBuf {
        &self.path
    }

    pub(crate) fn write(&mut self, message: &str) {
        // Checked on every line, not only when the helper starts. A tunnel
        // left connected for weeks never reopens its log, so a cap applied
        // once at startup is no cap at all: the file grows for as long as the
        // session lasts.
        if self.written >= MAX_LOG_BYTES {
            self.roll();
        }
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs());
        let line = format!("{timestamp} {message}\n");
        if let Some(file) = self.file.as_mut() {
            let _ = file.write_all(line.as_bytes());
            let _ = file.flush();
        }
        self.written = self
            .written
            .saturating_add(u64::try_from(line.len()).unwrap_or(u64::MAX));
    }

    /// Starts a fresh log, keeping the one just filled as the previous.
    ///
    /// The counter is reset before anything is attempted: a rotation that
    /// cannot happen — a locked file, a full disk — must not be retried on
    /// every line for the rest of the session. Losing the rotation costs an
    /// oversized log, which is a far smaller problem than a helper that stops
    /// recording what it is doing.
    fn roll(&mut self) {
        self.written = 0;
        // Dropping the handle first is what makes the rename possible at all;
        // Windows refuses to move a file that is still open.
        self.file = None;
        if rotate(&self.path).is_err() {
            return;
        }
        self.file = append_to(&self.path).ok();
    }
}

fn append_to(path: &Path) -> io::Result<File> {
    OpenOptions::new().create(true).append(true).open(path)
}

/// Moves `path` aside, replacing whichever previous log was already there.
fn rotate(path: &Path) -> io::Result<()> {
    let previous = path.with_file_name("helper.previous.log");
    match fs::remove_file(&previous) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    fs::rename(path, previous)
}

pub(crate) fn path() -> io::Result<PathBuf> {
    dirs::data_local_dir()
        .map(|directory| directory.join("MouseVPN").join("logs").join("helper.log"))
        .ok_or_else(|| io::Error::other("LOCALAPPDATA is unavailable"))
}
