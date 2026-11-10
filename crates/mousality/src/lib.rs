#![doc = "Mousality: the `MouseVPN` tunnel inside what looks like a browser's TLS 1.3 visit to a real site."]

mod channel;
mod hello;
mod probe;
mod record;
mod server_hello;
mod shape;
mod wire;

use std::{error::Error, fmt, io};

pub use channel::{
    accept, accept_routed, connect, connect_version, Accepted, Channel, ChannelReader,
    ChannelWriter, ClientSettings, ReplayCache, ServerSettings,
};
pub use hello::{Authentication, ClientHello, ParsedClientHello, VERSION_1, VERSION_2};
pub use probe::probe_site;
pub use record::MAX_DATAGRAM_LEN;
pub use server_hello::ServerTemplate;
pub use x25519_dalek::StaticSecret;

#[derive(Debug)]
pub enum MousalityError {
    Io(io::Error),
    /// The bytes are not the TLS structure expected here.
    Malformed,
    /// The peer is not the Mousality endpoint holding the expected key.
    Unauthenticated,
    InvalidKey,
    InvalidServerName,
    TooLarge,
    SequenceExhausted,
    Random,
    /// The peer ended the connection with an alert.
    Closed,
}

impl fmt::Display for MousalityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "Mousality I/O failed: {error}"),
            Self::Malformed => formatter.write_str("malformed TLS data"),
            Self::Unauthenticated => formatter.write_str(
                "the server did not prove it holds the Mousality key; check that the device \
                 clock is within 10 minutes of the correct time",
            ),
            Self::InvalidKey => formatter.write_str("invalid Mousality key material"),
            Self::InvalidServerName => formatter.write_str("invalid camouflage server name"),
            Self::TooLarge => formatter.write_str("datagram does not fit a record"),
            Self::SequenceExhausted => formatter.write_str("record sequence exhausted"),
            Self::Random => formatter.write_str("random generator failed"),
            Self::Closed => formatter.write_str("the peer closed the connection"),
        }
    }
}

impl Error for MousalityError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for MousalityError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
