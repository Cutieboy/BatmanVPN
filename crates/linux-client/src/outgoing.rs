use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};

use mousevpn_data_plane::{PacketDevice, TunnelDataPlane};
use mousevpn_linux_platform::LinuxTun;
use mousevpn_transport::{DatagramTransport, UdpTransport};

use crate::ClientError;

const PACKET_BUFFER_LEN: usize = 65_535;

pub(crate) fn run(
    tun: &LinuxTun,
    plane: &Mutex<TunnelDataPlane>,
    transport: &mut UdpTransport,
    stopping: &Arc<AtomicBool>,
    paused: &Arc<AtomicBool>,
) -> Result<(), ClientError> {
    let mut packet = vec![0_u8; PACKET_BUFFER_LEN];
    while !stopping.load(Ordering::Relaxed) {
        let length = tun.receive(&mut packet)?;
        if is_ipv6(&packet[..length]) {
            continue;
        }
        while paused.load(Ordering::Relaxed) && !stopping.load(Ordering::Relaxed) {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let datagram = plane
            .lock()
            .map_err(|_| ClientError::WorkerStopped)?
            .encode_ip(&packet[..length])?;
        transport.send(&datagram)?;
    }
    Ok(())
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
