//! Both handshakes over a byte stream and the datagram channel they open.

use std::{
    collections::HashMap,
    io::{Read, Write},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use x25519_dalek::{PublicKey, StaticSecret};

use crate::{
    hello::{client_hello_record_version_ok, ClientHello, ParsedClientHello, VERSION_2},
    record::{frames, RecordOpener, RecordSealer},
    server_hello::{change_cipher_spec, respond, ParsedServerHello, ServerTemplate, SessionKeys},
    shape::Shaper,
    wire::{
        Reader, CONTENT_ALERT, CONTENT_APPLICATION_DATA, CONTENT_CHANGE_CIPHER_SPEC,
        CONTENT_HANDSHAKE, MAX_CIPHERTEXT_LEN, RECORD_HEADER_LEN,
    },
    MousalityError,
};

/// How far a client's clock may be from the server's. Phones set by hand
/// are often minutes off, and a client outside this window only learns that
/// the server did not authenticate. The replay cache, not the clock, stops
/// replays, so a wider window costs only cache memory.
pub(crate) const CLOCK_TOLERANCE_SECONDS: u64 = 600;
/// Most hellos the replay cache holds: enough for 200 connections a second
/// over the whole window, about 20 MiB at most.
const MAX_REMEMBERED_HELLOS: usize = 262_144;
/// Expired hellos are swept once the cache holds this many, at most once a second.
const SWEEP_THRESHOLD: usize = 4_096;
/// The body length of the client's imitation of its TLS 1.3 `Finished`.
const CLIENT_FINISHED_LEN: usize = 53;
/// A hello larger than this is not Chrome's and is left to the real site.
const MAX_CLIENT_HELLO_LEN: usize = 8_192;

/// What a client needs to reach a Mousality server.
pub struct ClientSettings<'a> {
    /// The camouflage site's name, sent in clear as Chrome would.
    pub server_name: &'a str,
    /// The server's static X25519 key, the same as its Noise key.
    pub server_static: [u8; 32],
}

/// Runs the client handshake and returns the open channel.
///
/// # Errors
///
/// Returns [`MousalityError::Unauthenticated`] when the other side is not
/// the Mousality server that holds the key: a real site, a different key, a
/// clock far off, or an interception.
pub fn connect<S: Read + Write>(
    stream: &mut S,
    settings: &ClientSettings<'_>,
    unix_seconds: u64,
) -> Result<Channel, MousalityError> {
    connect_version(stream, settings, unix_seconds, VERSION_2)
}

/// Runs the client handshake of a given protocol version: [`VERSION_2`], or
/// [`VERSION_1`] for a server whose agent predates Mousality 2.0.
///
/// # Errors
///
/// As [`connect`]; a version 1 server also answers a version 2 hello with
/// [`MousalityError::Unauthenticated`].
pub fn connect_version<S: Read + Write>(
    stream: &mut S,
    settings: &ClientSettings<'_>,
    unix_seconds: u64,
    version: u8,
) -> Result<Channel, MousalityError> {
    let hello = ClientHello::build_version(
        settings.server_name,
        &settings.server_static,
        unix_seconds,
        version,
    )?;
    stream.write_all(&hello.record)?;

    let mut buffer = Vec::new();
    let header = read_record(stream, &mut buffer)?;
    if header[0] != CONTENT_HANDSHAKE {
        return Err(MousalityError::Unauthenticated);
    }
    let server_hello = buffer.clone();
    let parsed = ParsedServerHello::parse(&server_hello, &hello.session_id)?;
    let keys = SessionKeys::derive_client(
        &hello.x25519,
        &PublicKey::from(parsed.x25519),
        &PublicKey::from(settings.server_static),
        &hello.message,
        &server_hello,
    )?;
    let mut opener = RecordOpener::new(keys.server_to_client);
    let mut sealer = RecordSealer::new(keys.client_to_server);

    // The first protected record is what only the real server can produce.
    loop {
        let header = read_record(stream, &mut buffer)?;
        match header[0] {
            CONTENT_CHANGE_CIPHER_SPEC => {}
            CONTENT_APPLICATION_DATA => {
                opener.open(header, &mut buffer)?;
                break;
            }
            _ => return Err(MousalityError::Unauthenticated),
        }
    }
    let mut finished = change_cipher_spec().to_vec();
    sealer.seal(&[], CLIENT_FINISHED_LEN, &mut finished)?;
    stream.write_all(&finished)?;
    Ok(Channel::new(sealer, opener, version >= VERSION_2))
}

/// What a server needs to answer clients.
pub struct ServerSettings {
    /// The server's static X25519 secret, the same as its Noise key.
    pub server_static: StaticSecret,
    /// Names a client may present; anything else goes to the real site.
    pub server_names: Vec<String>,
    pub template: ServerTemplate,
}

/// The outcome of reading a connection's first flight.
pub enum Accepted {
    /// An authenticated Mousality client; the channel is open.
    Tunnel(Box<Channel>),
    /// Anything else. These bytes were read and must reach the real site
    /// first, followed by the rest of the connection.
    Foreign(Vec<u8>),
}

/// Reads a connection's first flight and answers an authenticated client.
///
/// Every failure to authenticate yields [`Accepted::Foreign`] with the bytes
/// consumed, so that a prober sees the real site.
///
/// # Errors
///
/// Returns an error only for I/O failures and when the answer cannot be built.
pub fn accept<S: Read + Write>(
    stream: &mut S,
    settings: &ServerSettings,
    replay: &mut ReplayCache,
    unix_seconds: u64,
) -> Result<Accepted, MousalityError> {
    accept_routed(stream, &[settings], replay, unix_seconds).map(|(accepted, _)| accepted)
}

/// Selects the camouflage flight by SNI, returning its route index even for
/// foreign traffic so the caller can forward it to the corresponding real site.
/// Unknown names use route zero.
///
/// # Errors
/// Returns an error for empty routes, I/O failures or an invalid response.
pub fn accept_routed<S: Read + Write>(
    stream: &mut S,
    routes: &[&ServerSettings],
    replay: &mut ReplayCache,
    unix_seconds: u64,
) -> Result<(Accepted, usize), MousalityError> {
    if routes.is_empty() {
        return Err(MousalityError::Malformed);
    }
    let mut consumed = Vec::with_capacity(2_048);
    let Some(hello) = read_client_hello(stream, &mut consumed)? else {
        return Ok((Accepted::Foreign(consumed), 0));
    };
    let Ok(parsed) = ParsedClientHello::parse(&hello) else {
        return Ok((Accepted::Foreign(consumed), 0));
    };
    let selected = parsed.server_name.as_deref().and_then(|name| {
        routes.iter().position(|settings| {
            settings
                .server_names
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(name))
        })
    });
    let index = selected.unwrap_or(0);
    let settings = routes[index];
    let name_allowed = parsed.server_name.as_deref().is_some_and(|name| {
        settings
            .server_names
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(name))
    });
    let authentication = parsed
        .authenticate(&settings.server_static)
        .filter(|authentication| {
            u64::from(authentication.unix_seconds).abs_diff(unix_seconds & u64::from(u32::MAX))
                <= CLOCK_TOLERANCE_SECONDS
        });
    // A replayed hello goes to the real site too, so a prober that replays a
    // client's hello learns nothing.
    let Some(authentication) = authentication.filter(|_| name_allowed) else {
        return Ok((Accepted::Foreign(consumed), index));
    };
    if !replay.insert(*parsed.random()) {
        return Ok((Accepted::Foreign(consumed), index));
    }
    let response = respond(&parsed, &settings.server_static, &settings.template)?;
    stream.write_all(&response.records)?;
    // Released version 1 clients keep getting exactly the records they did.
    let shaped = authentication.version >= VERSION_2;
    Ok((
        Accepted::Tunnel(Box::new(Channel::new(
            response.sealer,
            response.opener,
            shaped,
        ))),
        index,
    ))
}

/// Reads handshake records until one whole `ClientHello` message is in hand.
///
/// Returns `None`, with whatever was read in `consumed`, for anything that is
/// not a TLS handshake the size of a browser's hello.
fn read_client_hello<S: Read>(
    stream: &mut S,
    consumed: &mut Vec<u8>,
) -> Result<Option<Vec<u8>>, MousalityError> {
    let mut message = Vec::new();
    loop {
        let start = consumed.len();
        consumed.resize(start + RECORD_HEADER_LEN, 0);
        stream.read_exact(&mut consumed[start..])?;
        let header = &consumed[start..];
        let version = u16::from_be_bytes([header[1], header[2]]);
        let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
        if header[0] != CONTENT_HANDSHAKE
            || !client_hello_record_version_ok(version)
            || length == 0
            || message.len() + length > MAX_CLIENT_HELLO_LEN
        {
            return Ok(None);
        }
        let body = consumed.len();
        consumed.resize(body + length, 0);
        stream.read_exact(&mut consumed[body..])?;
        message.extend_from_slice(&consumed[body..]);
        if message.len() >= 4 {
            let mut reader = Reader::new(&message[1..4]);
            let expected = 4 + reader.u24()?;
            if expected > MAX_CLIENT_HELLO_LEN {
                return Ok(None);
            }
            if message.len() == expected {
                return Ok(Some(message));
            }
            if message.len() > expected {
                return Ok(None);
            }
        }
    }
}

/// Reads one record into `body` and returns its header.
fn read_record<S: Read>(
    stream: &mut S,
    body: &mut Vec<u8>,
) -> Result<[u8; RECORD_HEADER_LEN], MousalityError> {
    let mut header = [0_u8; RECORD_HEADER_LEN];
    stream.read_exact(&mut header)?;
    let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
    if length > MAX_CIPHERTEXT_LEN {
        return Err(MousalityError::Malformed);
    }
    body.resize(length, 0);
    stream.read_exact(body)?;
    Ok(header)
}

/// Remembers the hellos a server accepted for as long as their clock
/// reading stays acceptable.
#[derive(Clone, Default)]
pub struct ReplayCache {
    seen: Arc<Mutex<Remembered>>,
}

#[derive(Default)]
struct Remembered {
    hellos: HashMap<[u8; 32], Instant>,
    swept: Option<Instant>,
}

impl ReplayCache {
    /// Records a hello's random; false when it was already seen.
    pub fn insert(&mut self, random: [u8; 32]) -> bool {
        let now = Instant::now();
        let window = Duration::from_secs(2 * CLOCK_TOLERANCE_SECONDS + 1);
        // A panic elsewhere must not turn every later client away.
        let mut seen = self
            .seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let due = seen
            .swept
            .is_none_or(|swept| now.duration_since(swept) >= Duration::from_secs(1));
        if seen.hellos.len() >= SWEEP_THRESHOLD && due {
            seen.hellos
                .retain(|_, seen| now.duration_since(*seen) < window);
            seen.swept = Some(now);
        }
        match seen.hellos.get(&random) {
            Some(seen) if now.duration_since(*seen) < window => false,
            _ => {
                // Bound memory under a flood of valid but unique hellos.
                if seen.hellos.len() >= MAX_REMEMBERED_HELLOS {
                    return false;
                }
                seen.hellos.insert(random, now);
                true
            }
        }
    }
}

/// An open Mousality connection carrying whole datagrams both ways.
pub struct Channel {
    writer: ChannelWriter,
    reader: ChannelReader,
}

impl Channel {
    fn new(sealer: RecordSealer, opener: RecordOpener, shaped: bool) -> Self {
        Self {
            writer: ChannelWriter {
                sealer,
                shaper: shaped.then(Shaper::new),
                output: Vec::with_capacity(17_000),
            },
            reader: ChannelReader {
                opener,
                record: Vec::with_capacity(17_000),
                position: 0,
                end: 0,
            },
        }
    }

    /// Separates the directions so that two threads can each own one.
    #[must_use]
    pub fn split(self) -> (ChannelReader, ChannelWriter) {
        (self.reader, self.writer)
    }
}

/// The sending half of a channel.
pub struct ChannelWriter {
    sealer: RecordSealer,
    /// Present on Mousality 2.0 connections.
    shaper: Option<Shaper>,
    output: Vec<u8>,
}

impl ChannelWriter {
    /// Sends datagrams in one record.
    ///
    /// # Errors
    ///
    /// Returns an error when they do not fit one record or the write fails.
    pub fn send<S: Write>(
        &mut self,
        stream: &mut S,
        datagrams: &[&[u8]],
    ) -> Result<(), MousalityError> {
        self.output.clear();
        let ciphertext_len = match &mut self.shaper {
            Some(shaper) => {
                let frames_len = datagrams.iter().map(|datagram| 2 + datagram.len()).sum();
                shaper.ciphertext_len(frames_len, Instant::now())?
            }
            None => 0,
        };
        self.sealer
            .seal(datagrams, ciphertext_len, &mut self.output)?;
        stream.write_all(&self.output)?;
        Ok(())
    }
}

/// The receiving half of a channel.
pub struct ChannelReader {
    opener: RecordOpener,
    record: Vec<u8>,
    /// The unread frames of the last record: `record[position..end]`.
    position: usize,
    end: usize,
}

impl ChannelReader {
    /// Reads the next datagram into `output`.
    ///
    /// # Errors
    ///
    /// Returns an error when the stream ends, a record fails authentication
    /// or the peer sends an alert.
    pub fn receive<S: Read>(
        &mut self,
        stream: &mut S,
        output: &mut Vec<u8>,
    ) -> Result<(), MousalityError> {
        loop {
            if let Some(frame) = frames(&self.record[self.position..self.end]).next() {
                let frame = frame?;
                output.clear();
                output.extend_from_slice(frame);
                self.position += 2 + frame.len();
                return Ok(());
            }
            let header = read_record(stream, &mut self.record)?;
            match header[0] {
                CONTENT_CHANGE_CIPHER_SPEC => self.end = 0,
                CONTENT_APPLICATION_DATA => {
                    self.end = self.opener.open(header, &mut self.record)?.len();
                }
                CONTENT_ALERT => return Err(MousalityError::Closed),
                _ => return Err(MousalityError::Malformed),
            }
            self.position = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        thread,
    };

    use x25519_dalek::{PublicKey, StaticSecret};

    use super::*;
    use crate::hello::VERSION_1;

    const NOW: u64 = 1_793_500_000;

    fn settings() -> ServerSettings {
        ServerSettings {
            server_static: StaticSecret::from([9_u8; 32]),
            server_names: vec!["www.example.com".to_owned()],
            template: ServerTemplate::default(),
        }
    }

    fn server_public() -> [u8; 32] {
        *PublicKey::from(&settings().server_static).as_bytes()
    }

    /// Runs `server` on one accepted connection and `client` against it.
    fn exchange<T: Send + 'static>(
        server: impl FnOnce(TcpStream) -> T + Send + 'static,
        client: impl FnOnce(TcpStream),
    ) -> T {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = thread::spawn(move || server(listener.accept().unwrap().0));
        client(TcpStream::connect(address).unwrap());
        handle.join().unwrap()
    }

    #[test]
    fn datagrams_cross_an_authenticated_connection_both_ways() {
        let echoed = exchange(
            |mut stream| {
                let Accepted::Tunnel(channel) =
                    accept(&mut stream, &settings(), &mut ReplayCache::default(), NOW).unwrap()
                else {
                    panic!("an authenticated client was sent to the site");
                };
                let (mut reader, mut writer) = channel.split();
                let mut datagram = Vec::new();
                reader.receive(&mut stream, &mut datagram).unwrap();
                writer.send(&mut stream, &[&datagram, b"second"]).unwrap();
                datagram
            },
            |mut stream| {
                let settings = ClientSettings {
                    server_name: "www.example.com",
                    server_static: server_public(),
                };
                let (mut reader, mut writer) =
                    connect(&mut stream, &settings, NOW + 30).unwrap().split();
                writer.send(&mut stream, &[b"hello tunnel"]).unwrap();
                let mut datagram = Vec::new();
                reader.receive(&mut stream, &mut datagram).unwrap();
                assert_eq!(datagram, b"hello tunnel");
                reader.receive(&mut stream, &mut datagram).unwrap();
                assert_eq!(datagram, b"second");
            },
        );
        assert_eq!(echoed, b"hello tunnel");
    }

    #[test]
    fn version_1_clients_keep_unshaped_records_and_version_2_clients_get_padding() {
        for (version, shaped) in [(VERSION_1, false), (VERSION_2, true)] {
            let (record_len, server_shaped) = exchange(
                |mut stream| {
                    let Accepted::Tunnel(channel) =
                        accept(&mut stream, &settings(), &mut ReplayCache::default(), NOW).unwrap()
                    else {
                        panic!("an authenticated client was sent to the site");
                    };
                    let server_shaped = channel.writer.shaper.is_some();
                    let (mut reader, mut writer) = channel.split();
                    let mut datagram = Vec::new();
                    reader.receive(&mut stream, &mut datagram).unwrap();
                    writer.send(&mut stream, &[&datagram]).unwrap();
                    (writer.output.len(), server_shaped)
                },
                |mut stream| {
                    let settings = ClientSettings {
                        server_name: "www.example.com",
                        server_static: server_public(),
                    };
                    let (mut reader, mut writer) =
                        connect_version(&mut stream, &settings, NOW, version)
                            .unwrap()
                            .split();
                    assert_eq!(writer.shaper.is_some(), shaped);
                    writer.send(&mut stream, &[b"ping"]).unwrap();
                    let mut datagram = Vec::new();
                    reader.receive(&mut stream, &mut datagram).unwrap();
                    assert_eq!(datagram, b"ping");
                },
            );
            assert_eq!(server_shaped, shaped, "version {version}");
            // Header, one framed four-byte datagram and the tag.
            let unpadded = RECORD_HEADER_LEN + 2 + 4 + crate::record::TAG_LEN;
            if shaped {
                assert!(record_len >= RECORD_HEADER_LEN + 900, "{record_len}");
            } else {
                assert_eq!(record_len, unpadded);
            }
        }
    }

    fn rejected(server_name: &str, server_static: [u8; 32], client_seconds: u64) -> Vec<u8> {
        let server_name = server_name.to_owned();
        exchange(
            |mut stream| match accept(&mut stream, &settings(), &mut ReplayCache::default(), NOW)
                .unwrap()
            {
                Accepted::Foreign(consumed) => consumed,
                Accepted::Tunnel(_) => panic!("an unauthenticated client got a tunnel"),
            },
            move |mut stream| {
                let hello =
                    ClientHello::build(&server_name, &server_static, client_seconds).unwrap();
                stream.write_all(&hello.record).unwrap();
            },
        )
    }

    #[test]
    fn wrong_keys_names_clocks_and_replays_go_to_the_real_site() {
        let other = *PublicKey::from(&StaticSecret::from([1_u8; 32])).as_bytes();
        assert!(!rejected("www.example.com", other, NOW).is_empty());
        assert!(!rejected("other.example.com", server_public(), NOW).is_empty());
        assert!(!rejected(
            "www.example.com",
            server_public(),
            NOW - CLOCK_TOLERANCE_SECONDS - 1
        )
        .is_empty());

        let hello = ClientHello::build("www.example.com", &server_public(), NOW).unwrap();
        let mut replay = ReplayCache::default();
        let first = hello.record.clone();
        let accepted = exchange(
            move |mut stream| {
                let first = matches!(
                    accept(&mut stream, &settings(), &mut replay, NOW).unwrap(),
                    Accepted::Tunnel(_)
                );
                (first, replay)
            },
            move |mut stream| stream.write_all(&first).unwrap(),
        );
        assert!(accepted.0);
        let mut replay = accepted.1;
        let replayed = hello.record.clone();
        let second = exchange(
            move |mut stream| {
                matches!(
                    accept(&mut stream, &settings(), &mut replay, NOW).unwrap(),
                    Accepted::Foreign(_)
                )
            },
            move |mut stream| stream.write_all(&replayed).unwrap(),
        );
        assert!(second);
    }

    #[test]
    fn anything_but_a_hello_is_handed_over_byte_for_byte() {
        let consumed = exchange(
            |mut stream| match accept(&mut stream, &settings(), &mut ReplayCache::default(), NOW)
                .unwrap()
            {
                Accepted::Foreign(consumed) => consumed,
                Accepted::Tunnel(_) => panic!("a plain request got a tunnel"),
            },
            |mut stream| {
                stream
                    .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
                    .unwrap();
            },
        );
        assert_eq!(consumed, b"GET /");
    }

    #[test]
    fn a_client_refuses_a_server_without_the_key() {
        exchange(
            |mut stream| {
                let mut settings = settings();
                settings.server_static = StaticSecret::from([2_u8; 32]);
                // Pretend to be a server that accepts anything.
                let mut consumed = Vec::new();
                let hello = read_client_hello(&mut stream, &mut consumed)
                    .unwrap()
                    .unwrap();
                let parsed = ParsedClientHello::parse(&hello).unwrap();
                let response =
                    respond(&parsed, &settings.server_static, &settings.template).unwrap();
                stream.write_all(&response.records).unwrap();
                let mut rest = Vec::new();
                let _ = stream.read_to_end(&mut rest);
            },
            |mut stream| {
                let settings = ClientSettings {
                    server_name: "www.example.com",
                    server_static: server_public(),
                };
                let result = connect(&mut stream, &settings, NOW);
                assert!(matches!(result, Err(MousalityError::Unauthenticated)));
            },
        );
    }
}
