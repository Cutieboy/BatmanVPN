use std::{io, net::Ipv4Addr};

use mousevpn_data_plane::PacketDevice;
use tun_rs::{DeviceBuilder, SyncDevice};

pub const DEFAULT_TX_QUEUE_LEN: u32 = 2_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinuxTunConfig {
    pub name: String,
    pub address: Ipv4Addr,
    pub prefix_len: u8,
    pub mtu: u16,
    pub tx_queue_len: u32,
}

pub struct LinuxTun {
    device: SyncDevice,
}

impl LinuxTun {
    /// Creates and configures a Linux layer-3 TUN interface.
    ///
    /// This operation normally requires `CAP_NET_ADMIN`.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the interface cannot be created or configured.
    pub fn create(config: &LinuxTunConfig) -> io::Result<Self> {
        let device = DeviceBuilder::new()
            .name(&config.name)
            .ipv4(config.address, config.prefix_len, None)
            .mtu(config.mtu)
            .tx_queue_len(config.tx_queue_len)
            .build_sync()?;
        Ok(Self { device })
    }

    /// Returns the assigned interface name.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the interface name cannot be queried.
    pub fn name(&self) -> io::Result<String> {
        self.device.name()
    }
}

impl PacketDevice for LinuxTun {
    fn receive(&self, output: &mut [u8]) -> io::Result<usize> {
        self.device.recv(output)
    }

    fn send(&self, packet: &[u8]) -> io::Result<()> {
        let written = self.device.send(packet)?;
        if written == packet.len() {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "partial TUN packet write",
            ))
        }
    }
}
