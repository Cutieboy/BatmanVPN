use std::io;

pub trait DatagramTransport {
    /// Sends one complete protocol datagram.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the datagram cannot be sent in full.
    fn send(&mut self, packet: &[u8]) -> io::Result<()>;

    /// Receives one complete protocol datagram into `output`.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when receiving fails or `output` cannot hold the
    /// transport's datagram.
    fn receive(&mut self, output: &mut [u8]) -> io::Result<usize>;
}
