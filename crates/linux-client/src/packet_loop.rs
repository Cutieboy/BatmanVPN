use std::{
    io,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{Receiver, TryRecvError},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use mousevpn_config::ValidatedClientConfig;
use mousevpn_data_plane::{DecodedPacket, PacketDevice, TunnelDataPlane};
use mousevpn_linux_platform::LinuxTun;
use mousevpn_protocol::SessionParameters;
use mousevpn_transport::{DatagramTransport, UdpTransport};

use crate::{
    handshake::negotiate,
    liveness::{Action, Liveness},
    ClientError,
};

const PACKET_BUFFER_LEN: usize = 65_535;
pub(crate) const POLL_INTERVAL: Duration = Duration::from_millis(500);

enum ReceiveEvent {
    Packet(usize),
    Idle,
    PeerUnavailable,
}

pub(crate) struct PacketLoop<'a> {
    pub(crate) config: &'a ValidatedClientConfig,
    pub(crate) transport: UdpTransport,
    pub(crate) parameters: SessionParameters,
    pub(crate) tun: Arc<LinuxTun>,
    pub(crate) plane: Arc<Mutex<TunnelDataPlane>>,
    pub(crate) stopping: Arc<AtomicBool>,
    pub(crate) reconnecting: Arc<AtomicBool>,
    pub(crate) worker: Receiver<Result<(), ClientError>>,
}

impl PacketLoop<'_> {
    pub(crate) fn run(mut self) -> Result<(), ClientError> {
        let mut datagram = vec![0_u8; PACKET_BUFFER_LEN];
        let mut liveness = Liveness::new(Instant::now());
        while !self.stopping.load(Ordering::Relaxed) {
            check_worker(&self.worker)?;
            match self.receive(&mut datagram)? {
                ReceiveEvent::Packet(length) => {
                    let decoded = self
                        .plane
                        .lock()
                        .map_err(|_| ClientError::WorkerStopped)?
                        .decode(&datagram[..length]);
                    if let Ok(packet) = decoded {
                        liveness.packet_received(Instant::now());
                        if let DecodedPacket::Ip(packet) = packet {
                            self.tun.send(&packet)?;
                        }
                    }
                }
                ReceiveEvent::Idle => {}
                ReceiveEvent::PeerUnavailable => liveness.connection_lost(Instant::now()),
            }
            self.maintain_liveness(&mut liveness)?;
        }
        Ok(())
    }

    fn receive(&mut self, datagram: &mut [u8]) -> Result<ReceiveEvent, ClientError> {
        match self.transport.receive(datagram) {
            Ok(length) => Ok(ReceiveEvent::Packet(length)),
            Err(error)
                if error.kind() == io::ErrorKind::Interrupted
                    && self.stopping.load(Ordering::Relaxed) =>
            {
                Ok(ReceiveEvent::Idle)
            }
            Err(error) if is_timeout(&error) => {
                check_worker(&self.worker)?;
                Ok(ReceiveEvent::Idle)
            }
            Err(error) if is_peer_unavailable(&error) => Ok(ReceiveEvent::PeerUnavailable),
            Err(error) => Err(error.into()),
        }
    }

    fn maintain_liveness(&mut self, liveness: &mut Liveness) -> Result<(), ClientError> {
        let now = Instant::now();
        match liveness.action(now) {
            Action::None => Ok(()),
            Action::Keepalive => {
                match send_keepalive(&mut self.transport, &self.plane) {
                    Ok(()) => liveness.keepalive_sent(now),
                    Err(ClientError::Io(error)) if is_peer_unavailable(&error) => {
                        liveness.connection_lost(now);
                    }
                    Err(error) => return Err(error),
                }
                Ok(())
            }
            Action::Reconnect => self.reconnect(liveness, now),
        }
    }

    fn reconnect(&mut self, liveness: &mut Liveness, now: Instant) -> Result<(), ClientError> {
        liveness.reconnect_attempted(now);
        self.reconnecting.store(true, Ordering::Relaxed);
        eprintln!("MouseVPN session timed out; reconnecting");
        let result = negotiate(&mut self.transport, self.config);
        self.transport.set_read_timeout(Some(POLL_INTERVAL))?;
        match result {
            Ok((replacement, parameters)) => {
                if parameters != self.parameters {
                    self.reconnecting.store(false, Ordering::Relaxed);
                    return Err(ClientError::SessionParametersChanged);
                }
                *self.plane.lock().map_err(|_| ClientError::WorkerStopped)? = replacement;
                liveness.reconnected(Instant::now());
                eprintln!("MouseVPN reconnected");
            }
            Err(error) => eprintln!("MouseVPN reconnect failed: {error}"),
        }
        self.reconnecting.store(false, Ordering::Relaxed);
        Ok(())
    }
}

fn send_keepalive(
    transport: &mut impl DatagramTransport,
    plane: &Mutex<TunnelDataPlane>,
) -> Result<(), ClientError> {
    let packet = plane
        .lock()
        .map_err(|_| ClientError::WorkerStopped)?
        .encode_keepalive()?;
    transport.send(&packet)?;
    Ok(())
}

fn check_worker(receiver: &Receiver<Result<(), ClientError>>) -> Result<(), ClientError> {
    match receiver.try_recv() {
        Ok(Err(error)) => Err(error),
        Ok(Ok(())) | Err(TryRecvError::Disconnected) => Err(ClientError::WorkerStopped),
        Err(TryRecvError::Empty) => Ok(()),
    }
}

fn is_timeout(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

fn is_peer_unavailable(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::NotConnected
    )
}
