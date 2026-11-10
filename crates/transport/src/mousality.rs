//! Blocking datagram API over a Mousality byte stream. Dedicated I/O workers
//! retain partial records across caller timeouts and isolate slow TCP peers.
use std::{
    io,
    net::{Shutdown, SocketAddr, TcpStream},
    sync::{mpsc, Arc, Mutex},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use mousevpn_mousality::{Channel, ClientSettings, MousalityError, MAX_DATAGRAM_LEN, VERSION_2};

use crate::DatagramTransport;

const QUEUE_LEN: usize = 128;
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);

struct Shared {
    socket: TcpStream,
    incoming: Mutex<mpsc::Receiver<io::Result<Vec<u8>>>>,
    outgoing: mpsc::SyncSender<Vec<u8>>,
}

impl Drop for Shared {
    fn drop(&mut self) {
        let _ = self.socket.shutdown(Shutdown::Both);
    }
}

#[derive(Clone)]
pub struct MousalityTransport {
    shared: Arc<Shared>,
    timeout: Option<Duration>,
}

impl std::fmt::Debug for MousalityTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MousalityTransport").finish_non_exhaustive()
    }
}

impl MousalityTransport {
    /// Connects TCP and authenticates the camouflage handshake.
    ///
    /// # Errors
    /// Returns an error if TCP setup or authentication fails.
    pub fn connect(
        peer: SocketAddr,
        server_name: &str,
        server_static: [u8; 32],
        timeout: Duration,
    ) -> io::Result<Self> {
        Self::connect_version(peer, server_name, server_static, timeout, VERSION_2)
    }

    /// Connects with a given outer protocol version; see
    /// [`crate::connect_pooled`] for choosing it.
    ///
    /// # Errors
    /// Returns an error if TCP setup or authentication fails.
    pub fn connect_version(
        peer: SocketAddr,
        server_name: &str,
        server_static: [u8; 32],
        timeout: Duration,
        version: u8,
    ) -> io::Result<Self> {
        let started = std::time::Instant::now();
        let mut stream = TcpStream::connect_timeout(&peer, timeout)?;
        let remaining = timeout
            .saturating_sub(started.elapsed())
            .max(Duration::from_millis(1));
        stream.set_nodelay(true)?;
        stream.set_read_timeout(Some(remaining))?;
        stream.set_write_timeout(Some(remaining))?;
        let channel = mousevpn_mousality::connect_version(
            &mut stream,
            &ClientSettings {
                server_name,
                server_static,
            },
            unix_seconds(),
            version,
        )
        .map_err(mousality_io)?;
        Self::from_channel(stream, channel)
    }

    /// Takes an authenticated stream and starts bounded datagram workers.
    ///
    /// # Errors
    /// Returns an error if socket setup or worker creation fails.
    pub fn from_channel(stream: TcpStream, channel: Channel) -> io::Result<Self> {
        stream.set_nodelay(true)?;
        // Never interrupt a partial record; callers time out on the queue.
        stream.set_read_timeout(None)?;
        stream.set_write_timeout(Some(WRITE_TIMEOUT))?;
        let mut read_stream = stream.try_clone()?;
        let mut write_stream = stream.try_clone()?;
        let (mut reader, mut writer) = channel.split();
        let (received_tx, received_rx) = mpsc::sync_channel(QUEUE_LEN);
        let (send_tx, send_rx) = mpsc::sync_channel::<Vec<u8>>(QUEUE_LEN);
        thread::Builder::new()
            .name("mousality-read".into())
            .spawn(move || loop {
                let mut packet = Vec::new();
                let result = reader
                    .receive(&mut read_stream, &mut packet)
                    .map_err(mousality_io);
                let failed = result.is_err();
                if failed {
                    let _ = read_stream.shutdown(Shutdown::Both);
                }
                if received_tx.send(result.map(|()| packet)).is_err() || failed {
                    break;
                }
            })?;
        thread::Builder::new()
            .name("mousality-write".into())
            .spawn(move || {
                let mut pending = None;
                while let Some(packet) = pending.take().or_else(|| send_rx.recv().ok()) {
                    let mut used = packet.len() + 2;
                    let mut packets = vec![packet];
                    // Combine only datagrams already queued: no timer or extra
                    // latency. Busy streams naturally produce larger TLS records.
                    while let Ok(next) = send_rx.try_recv() {
                        if used + next.len() + 2 > MAX_DATAGRAM_LEN + 2 {
                            pending = Some(next);
                            break;
                        }
                        used += next.len() + 2;
                        packets.push(next);
                    }
                    let slices: Vec<_> = packets.iter().map(Vec::as_slice).collect();
                    if writer.send(&mut write_stream, &slices).is_err() {
                        let _ = write_stream.shutdown(Shutdown::Both);
                        break;
                    }
                }
            })?;
        Ok(Self {
            shared: Arc::new(Shared {
                socket: stream,
                incoming: Mutex::new(received_rx),
                outgoing: send_tx,
            }),
            timeout: None,
        })
    }

    #[must_use]
    pub fn same_connection(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.shared, &other.shared)
    }

    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) {
        self.timeout = timeout;
    }

    /// Interrupts both stream directions.
    ///
    /// # Errors
    /// Returns an error if the socket cannot be shut down.
    pub fn shutdown(&self) -> io::Result<()> {
        self.shared.socket.shutdown(Shutdown::Both)
    }

    /// Takes the next datagram as the reader produced it, without a copy.
    ///
    /// # Errors
    /// Returns an error when the timeout passes or the connection ends.
    pub fn receive_packet(&mut self) -> io::Result<Vec<u8>> {
        let incoming = self
            .shared
            .incoming
            .lock()
            .map_err(|_| io::Error::other("Mousality reader poisoned"))?;
        match self.timeout {
            Some(timeout) => incoming
                .recv_timeout(timeout)
                .map_err(|error| match error {
                    mpsc::RecvTimeoutError::Timeout => {
                        io::Error::new(io::ErrorKind::TimedOut, "Mousality receive timed out")
                    }
                    mpsc::RecvTimeoutError::Disconnected => disconnected(),
                })?,
            None => incoming.recv().map_err(|_| disconnected())?,
        }
    }
}

impl DatagramTransport for MousalityTransport {
    fn send(&mut self, packet: &[u8]) -> io::Result<()> {
        if packet.is_empty() || packet.len() > MAX_DATAGRAM_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid Mousality datagram size",
            ));
        }
        self.shared
            .outgoing
            .try_send(packet.to_vec())
            .map_err(|error| match error {
                mpsc::TrySendError::Full(_) => {
                    io::Error::new(io::ErrorKind::WouldBlock, "Mousality send queue is full")
                }
                mpsc::TrySendError::Disconnected(_) => disconnected(),
            })
    }

    fn receive(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let packet = self.receive_packet()?;
        if packet.len() > output.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Mousality receive buffer too small",
            ));
        }
        output[..packet.len()].copy_from_slice(&packet);
        Ok(packet.len())
    }
}

fn disconnected() -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionReset,
        "Mousality connection closed",
    )
}

#[must_use]
pub fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Whether `error` says the peer answered but was not the Mousality server,
/// as a server with an older protocol version does.
#[must_use]
pub fn is_unauthenticated(error: &io::Error) -> bool {
    error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<MousalityError>())
        .is_some_and(|inner| matches!(inner, MousalityError::Unauthenticated))
}

#[must_use]
pub fn mousality_io(error: MousalityError) -> io::Error {
    match error {
        MousalityError::Io(error)
            if matches!(
                error.kind(),
                io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
            ) =>
        {
            error
        }
        MousalityError::Io(error) if error.kind() == io::ErrorKind::UnexpectedEof => disconnected(),
        MousalityError::Io(error) => error,
        MousalityError::Closed => disconnected(),
        error => io::Error::new(io::ErrorKind::InvalidData, error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mousevpn_mousality::{Accepted, ReplayCache, ServerSettings, ServerTemplate, StaticSecret};
    use std::{
        io::{Read, Write},
        net::TcpListener,
    };

    struct Fragmented {
        stream: TcpStream,
        partial: mpsc::Sender<()>,
        resume: mpsc::Receiver<()>,
    }
    impl Write for Fragmented {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.stream.write_all(&bytes[..3])?;
            self.partial.send(()).unwrap();
            self.resume.recv_timeout(Duration::from_secs(3)).unwrap();
            self.stream.write_all(&bytes[3..])?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            self.stream.flush()
        }
    }

    #[test]
    fn caller_timeouts_preserve_a_partial_record_and_shutdown_wakes_the_reader() {
        let keys = mousevpn_crypto::KeyPair::generate().unwrap();
        let public = *keys.public.as_bytes();
        let secret = StaticSecret::from(keys.secret.expose_for_provisioning());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap();
        let (partial_tx, partial_rx) = mpsc::channel();
        let (resume_tx, resume_rx) = mpsc::channel();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let settings = ServerSettings {
                server_static: secret,
                server_names: vec!["www.example.com".into()],
                template: ServerTemplate::default(),
            };
            let Accepted::Tunnel(channel) = mousevpn_mousality::accept(
                &mut stream,
                &settings,
                &mut ReplayCache::default(),
                unix_seconds(),
            )
            .unwrap() else {
                panic!("expected tunnel");
            };
            let (mut reader, mut writer) = channel.split();
            let mut packet = Vec::new();
            reader.receive(&mut stream, &mut packet).unwrap();
            assert_eq!(packet, b"go");
            let mut fragmented = Fragmented {
                stream,
                partial: partial_tx,
                resume: resume_rx,
            };
            writer.send(&mut fragmented, &[b"intact datagram"]).unwrap();
            let mut eof = [0; 1];
            assert_eq!(fragmented.stream.read(&mut eof).unwrap(), 0);
        });
        let mut client = MousalityTransport::connect(
            endpoint,
            "www.example.com",
            public,
            Duration::from_secs(3),
        )
        .unwrap();
        client.send(b"go").unwrap();
        partial_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        client.set_read_timeout(Some(Duration::from_millis(20)));
        let mut packet = [0; 100];
        assert_eq!(
            client.receive(&mut packet).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        resume_tx.send(()).unwrap();
        client.set_read_timeout(Some(Duration::from_secs(3)));
        let length = client.receive(&mut packet).unwrap();
        assert_eq!(&packet[..length], b"intact datagram");
        client.shutdown().unwrap();
        assert!(client.receive(&mut packet).is_err());
        server.join().unwrap();
    }
    #[test]
    fn queued_datagrams_preserve_order_across_full_and_combined_records() {
        let keys = mousevpn_crypto::KeyPair::generate().unwrap();
        let public = *keys.public.as_bytes();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap();
        let sizes = [1, 1300, MAX_DATAGRAM_LEN, 9000];
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let settings = ServerSettings {
                server_static: StaticSecret::from(keys.secret.expose_for_provisioning()),
                server_names: vec!["www.example.com".into()],
                template: ServerTemplate::default(),
            };
            let Accepted::Tunnel(channel) = mousevpn_mousality::accept(
                &mut stream,
                &settings,
                &mut ReplayCache::default(),
                unix_seconds(),
            )
            .unwrap() else {
                panic!("expected tunnel");
            };
            let (mut reader, mut writer) = channel.split();
            for index in 0_u8..40 {
                let mut packet = Vec::new();
                reader.receive(&mut stream, &mut packet).unwrap();
                assert_eq!(packet, vec![index; sizes[usize::from(index) % sizes.len()]]);
                writer.send(&mut stream, &[&packet]).unwrap();
            }
        });
        let mut client = MousalityTransport::connect(
            endpoint,
            "www.example.com",
            public,
            Duration::from_secs(3),
        )
        .unwrap();
        client.set_read_timeout(Some(Duration::from_secs(3)));
        for index in 0_u8..40 {
            client
                .send(&vec![index; sizes[usize::from(index) % sizes.len()]])
                .unwrap();
        }
        let mut packet = vec![0; MAX_DATAGRAM_LEN];
        for index in 0_u8..40 {
            let length = client.receive(&mut packet).unwrap();
            assert_eq!(
                &packet[..length],
                &vec![index; sizes[usize::from(index) % sizes.len()]]
            );
        }
        server.join().unwrap();
    }
}
