use std::io;

pub trait PacketDevice {
    /// Receives one layer-3 packet.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when reading from the device fails.
    fn receive(&self, output: &mut [u8]) -> io::Result<usize>;

    /// Sends one complete layer-3 packet.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when writing to the device fails.
    fn send(&self, packet: &[u8]) -> io::Result<()>;
}
