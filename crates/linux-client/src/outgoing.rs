use std::{
    io,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use mousevpn_data_plane::{PacketDevice, TunnelSender};
use mousevpn_linux_platform::LinuxTun;
use mousevpn_transport::{DatagramTransport, UdpTransport};

use crate::ClientError;

const PACKET_BUFFER_LEN: usize = 65_535;
const PAUSE_POLL: Duration = Duration::from_millis(5);
/// Minimum gap between reports of dropped packets, so a broken flow cannot
/// flood the journal.
const DROP_REPORT_INTERVAL: Duration = Duration::from_secs(30);

pub(crate) fn run(
    tun: &LinuxTun,
    sender: &Mutex<TunnelSender>,
    transport: &mut UdpTransport,
    stopping: &Arc<AtomicBool>,
    paused: &Arc<AtomicBool>,
) -> Result<(), ClientError> {
    let mut packet = vec![0_u8; PACKET_BUFFER_LEN];
    // Reused for every datagram: the send path allocates nothing in steady state.
    let mut datagram = Vec::with_capacity(PACKET_BUFFER_LEN);
    let mut drops = Drops::default();

    while !stopping.load(Ordering::Relaxed) {
        let length = match tun.receive(&mut packet) {
            Ok(length) => length,
            Err(error) if is_retryable(&error) => continue,
            Err(error) => return Err(error.into()),
        };
        if is_ipv6(&packet[..length]) {
            continue;
        }
        while paused.load(Ordering::Relaxed) && !stopping.load(Ordering::Relaxed) {
            std::thread::sleep(PAUSE_POLL);
        }

        {
            let mut sender = sender.lock().map_err(|_| ClientError::WorkerStopped)?;
            // One unencodable packet is a packet to drop, not a reason to tear
            // the tunnel down.
            if let Err(error) = sender.encode_ip_into(&packet[..length], &mut datagram) {
                drops.record(&error);
                continue;
            }
        }
        match transport.send(&datagram) {
            Ok(()) => {}
            // The peer is unreachable right now; the receive loop owns liveness
            // and will reconnect.
            Err(error) if is_retryable(&error) => {}
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

fn is_retryable(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::Interrupted
            | io::ErrorKind::WouldBlock
            | io::ErrorKind::TimedOut
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::NotConnected
    )
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
