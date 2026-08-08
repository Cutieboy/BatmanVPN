use std::{io, net::Ipv4Addr, sync::Mutex};

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
    config: Mutex<LinuxTunConfig>,
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
        Ok(Self {
            device,
            config: Mutex::new(config.clone()),
        })
    }

    /// Returns the assigned interface name.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the interface name cannot be queried.
    pub fn name(&self) -> io::Result<String> {
        self.device.name()
    }

    /// Atomically updates the IPv4 address and MTU as far as the platform API
    /// permits, rolling back to the previous values if a step fails.
    ///
    /// # Errors
    ///
    /// Returns an error if the new settings cannot be applied or the previous
    /// settings cannot be restored after a partial failure.
    pub fn reconfigure(&self, address: Ipv4Addr, prefix_len: u8, mtu: u16) -> io::Result<()> {
        let mut current = self
            .config
            .lock()
            .map_err(|_| io::Error::other("TUN configuration lock was poisoned"))?;
        if current.address == address && current.prefix_len == prefix_len && current.mtu == mtu {
            return Ok(());
        }

        let previous = current.clone();
        self.device.set_mtu(mtu)?;
        if let Err(error) = self.device.set_network_address(address, prefix_len, None) {
            let address_rollback =
                self.device
                    .set_network_address(previous.address, previous.prefix_len, None);
            let mtu_rollback = self.device.set_mtu(previous.mtu);
            if let Err(rollback) = address_rollback.and(mtu_rollback) {
                return Err(io::Error::other(format!(
                    "applying TUN parameters failed: {error}; rollback failed: {rollback}"
                )));
            }
            return Err(error);
        }

        current.address = address;
        current.prefix_len = prefix_len;
        current.mtu = mtu;
        Ok(())
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
