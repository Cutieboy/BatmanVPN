use std::{
    io,
    net::{SocketAddr, UdpSocket},
    time::Duration,
};

use socket2::SockRef;

use crate::DatagramTransport;

const SOCKET_BUFFER_LEN: usize = 4 * 1024 * 1024;

#[derive(Debug)]
pub struct UdpTransport {
    socket: UdpSocket,
}

impl UdpTransport {
    /// Binds a UDP socket and connects it to one peer.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when bind or connect fails.
    pub fn bind(local: SocketAddr, peer: SocketAddr) -> io::Result<Self> {
        Self::from_socket(UdpSocket::bind(local)?, peer)
    }

    /// Connects an existing UDP socket to one peer.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when connect fails.
    pub fn from_socket(socket: UdpSocket, peer: SocketAddr) -> io::Result<Self> {
        socket.connect(peer)?;
        let socket_ref = SockRef::from(&socket);
        socket_ref.set_recv_buffer_size(SOCKET_BUFFER_LEN)?;
        socket_ref.set_send_buffer_size(SOCKET_BUFFER_LEN)?;
        Ok(Self { socket })
    }

    /// Sets the receive timeout.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the socket option cannot be changed.
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.socket.set_read_timeout(timeout)
    }

    /// Returns the bound local socket address.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the address cannot be queried.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Clones the underlying connected socket for a second packet loop.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the OS socket cannot be duplicated.
    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            socket: self.socket.try_clone()?,
        })
    }
}

impl DatagramTransport for UdpTransport {
    fn send(&mut self, packet: &[u8]) -> io::Result<()> {
        let written = self.socket.send(packet)?;
        if written == packet.len() {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "partial UDP datagram write",
            ))
        }
    }

    fn receive(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.socket.recv(output)
    }
}
