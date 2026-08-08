use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

const MAX_LOG_BYTES: u64 = 2 * 1024 * 1024;

pub(crate) struct HelperLog {
    file: File,
    path: PathBuf,
}

impl HelperLog {
    pub(crate) fn open() -> io::Result<Self> {
        let path = path()?;
        let directory = path
            .parent()
            .ok_or_else(|| io::Error::other("helper log has no parent directory"))?;
        fs::create_dir_all(directory)?;
        if fs::metadata(&path).is_ok_and(|metadata| metadata.len() >= MAX_LOG_BYTES) {
            let previous = path.with_file_name("helper.previous.log");
            match fs::remove_file(&previous) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
            fs::rename(&path, previous)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Self { file, path })
    }

    pub(crate) fn path(&self) -> &PathBuf {
        &self.path
    }

    pub(crate) fn write(&mut self, message: &str) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs());
        let _ = writeln!(self.file, "{timestamp} {message}");
        let _ = self.file.flush();
    }
}

pub(crate) fn path() -> io::Result<PathBuf> {
    dirs::data_local_dir()
        .map(|directory| directory.join("MouseVPN").join("logs").join("helper.log"))
        .ok_or_else(|| io::Error::other("LOCALAPPDATA is unavailable"))
}
