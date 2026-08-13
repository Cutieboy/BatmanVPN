use std::{
    io,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::Receiver,
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use mousevpn_data_plane::{PacketDevice, TunnelSender};
use mousevpn_linux_platform::LinuxTun;
use mousevpn_transport::{UdpBatch, UdpTransport};
use nix::poll::{poll, PollFd, PollFlags};

use crate::{
    error::{is_peer_unavailable, is_retryable_network},
    ClientError,
};

const PACKET_BUFFER_LEN: usize = 65_535;
const BATCH_SIZE: usize = 32;
const TUN_POLL_MS: u16 = 100;
/// Minimum gap between reports of dropped packets, so a broken flow cannot
/// flood the journal.
const DROP_REPORT_INTERVAL: Duration = Duration::from_secs(30);

pub(crate) struct ReconnectControl {
    pub(crate) paused: Arc<AtomicBool>,
    pub(crate) requested: Arc<AtomicU64>,
    pub(crate) generation: Arc<AtomicU64>,
    pub(crate) transport_replacements: Receiver<UdpTransport>,
}

pub(crate) fn run(
    tun: &LinuxTun,
    sender: &Mutex<TunnelSender>,
    transport: &mut UdpTransport,
    stopping: &Arc<AtomicBool>,
    reconnect: &ReconnectControl,
) -> Result<(), ClientError> {
    let mut packets: Vec<Vec<u8>> = (0..BATCH_SIZE)
        .map(|_| vec![0_u8; PACKET_BUFFER_LEN])
        .collect();
    let mut datagrams: Vec<Vec<u8>> = (0..BATCH_SIZE)
        .map(|_| Vec::with_capacity(PACKET_BUFFER_LEN))
        .collect();
    let mut drops = Drops::default();
    let mut udp_batch = UdpBatch::default();

    while !stopping.load(Ordering::Relaxed) {
        // A connected UDP socket can retain its pre-suspend source address and
        // route.  Reconnect creates a fresh socket and hands its clone to this
        // direction before unpausing packet delivery.
        while let Ok(replacement) = reconnect.transport_replacements.try_recv() {
            *transport = replacement;
        }
        if reconnect.paused.load(Ordering::Relaxed) {
            let _ = poll(&mut [], TUN_POLL_MS);
            continue;
        }

        let mut descriptors = [PollFd::new(tun.as_fd(), PollFlags::POLLIN)];
        match poll(&mut descriptors, TUN_POLL_MS) {
            Ok(0) | Err(nix::errno::Errno::EINTR) => continue,
            Ok(_) => {}
            Err(error) => return Err(io::Error::from(error).into()),
        }
        if reconnect.paused.load(Ordering::Relaxed) {
            continue;
        }

        let mut lengths = Vec::with_capacity(BATCH_SIZE);
        for packet in &mut packets {
            match tun.receive(packet) {
                Ok(length) => lengths.push(length),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) if is_retryable_network(&error) => break,
                Err(error) => return Err(error.into()),
            }
        }
        if lengths.is_empty() {
            continue;
        }

        let mut encoded = 0;
        {
            let mut sender = sender.lock().map_err(|_| ClientError::WorkerStopped)?;
            for (index, &length) in lengths.iter().enumerate() {
                if is_ipv6(&packets[index][..length]) {
                    continue;
                }
                if let Err(error) =
                    sender.encode_ip_into(&packets[index][..length], &mut datagrams[encoded])
                {
                    drops.record(&error);
                    continue;
                }
                encoded += 1;
            }
        }
        if encoded == 0 {
            continue;
        }
        match transport.send_batch_with(&datagrams[..encoded], &mut udp_batch) {
            Ok(sent) if sent == encoded => {}
            Ok(sent) => drops.record(&format_args!(
                "UDP send queue accepted {sent} of {encoded} batched packets"
            )),
            // The receive loop owns liveness, but both directions share one
            // kernel socket, so the peer's ICMP error is delivered to whichever
            // syscall runs first. Under load that is almost always this send,
            // and swallowing it here left the receive loop waiting out the full
            // session timeout instead of reconnecting.
            Err(error) if is_peer_unavailable(&error) => {
                let generation = reconnect.generation.load(Ordering::Relaxed);
                reconnect.requested.store(generation, Ordering::Relaxed);
            }
            Err(error) if is_retryable_network(&error) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

#[derive(Default)]
struct Drops {
    count: u64,
    last_report: Option<Instant>,
}

impl Drops {
    fn record(&mut self, error: &impl std::fmt::Display) {
        self.count += 1;
        let now = Instant::now();
        if self
            .last_report
            .is_none_or(|last| now.duration_since(last) >= DROP_REPORT_INTERVAL)
        {
            eprintln!(
                "MouseVPN dropped {} outgoing packet(s); most recent: {error}",
                self.count
            );
            self.last_report = Some(now);
        }
    }
}

fn is_ipv6(packet: &[u8]) -> bool {
    packet.first().is_some_and(|byte| byte >> 4 == 6)
}

#[cfg(test)]
mod tests {
    use super::is_ipv6;

    #[test]
    fn identifies_ipv6_without_hiding_malformed_ipv4() {
        assert!(is_ipv6(&[0x60]));
        assert!(!is_ipv6(&[0x45]));
        assert!(!is_ipv6(&[]));
    }
}
