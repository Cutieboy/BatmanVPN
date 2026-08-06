use std::{error::Error, fmt};

#[derive(Debug)]
pub enum ServerDaemonError {
    Io(std::io::Error),
    Configuration(String),
    WorkerStopped,
}

impl fmt::Display for ServerDaemonError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "server I/O error: {error}"),
            Self::Configuration(error) => write!(formatter, "server configuration error: {error}"),
            Self::WorkerStopped => formatter.write_str("server packet worker stopped"),
        }
    }
}

impl Error for ServerDaemonError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Configuration(_) | Self::WorkerStopped => None,
        }
    }
}

impl From<std::io::Error> for ServerDaemonError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}
