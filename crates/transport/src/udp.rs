use std::{
    io,
    net::{SocketAddr, UdpSocket},
    time::Duration,
};

#[cfg(any(target_os = "linux", target_os = "android"))]
use std::{
    io::{IoSlice, IoSliceMut},
    os::fd::AsRawFd,
};

#[cfg(any(target_os = "linux", target_os = "android"))]
use nix::sys::socket::{recvmmsg, sendmmsg, MsgFlags, MultiHeaders};

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

    /// Sends a group of connected UDP datagrams with one syscall on Linux and Android.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the syscall fails. A successful partial write is
    /// reported as the number of datagrams accepted by the kernel.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub fn send_batch(&mut self, packets: &[Vec<u8>]) -> io::Result<usize> {
        if packets.is_empty() {
            return Ok(0);
        }
        if packets.len() > 32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "UDP batch exceeds 32 datagrams",
            ));
        }
        let slices: [[IoSlice<'_>; 1]; 32] = std::array::from_fn(|index| {
            [IoSlice::new(packets.get(index).map_or(&[], Vec::as_slice))]
        });
        let addresses = [None::<()>; 32];
        let mut headers = MultiHeaders::<()>::preallocate(packets.len(), None);
        let sent = sendmmsg(
            self.socket.as_raw_fd(),
            &mut headers,
            &slices[..packets.len()],
            &addresses[..packets.len()],
            [],
            MsgFlags::empty(),
        )
        .map_err(io::Error::from)?
        .count();
        Ok(sent)
    }

    /// Receives up to 32 connected UDP datagrams with one syscall.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when batch reception fails.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub fn receive_batch(
        &mut self,
        buffers: &mut [Vec<u8>],
        lengths: &mut Vec<usize>,
    ) -> io::Result<()> {
        if buffers.is_empty() || buffers.len() > 32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "UDP receive batch must contain 1 to 32 buffers",
            ));
        }
        let mut slices: Vec<_> = buffers
            .iter_mut()
            .map(|buffer| [IoSliceMut::new(buffer)])
            .collect();
        let mut headers = MultiHeaders::<()>::preallocate(slices.len(), None);
        let messages = recvmmsg(
            self.socket.as_raw_fd(),
            &mut headers,
            slices.iter_mut(),
            MsgFlags::MSG_WAITFORONE,
            None,
        )
        .map_err(io::Error::from)?;
        lengths.clear();
        lengths.extend(messages.map(|message| message.bytes));
        Ok(())
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

#[cfg(all(test, any(target_os = "linux", target_os = "android")))]
mod tests {
    use std::{net::UdpSocket, time::Duration};

    use super::UdpTransport;

    #[test]
    fn sends_connected_datagrams_as_a_batch() {
        let receiver = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
        receiver
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("set timeout");
        let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
        let mut transport =
            UdpTransport::from_socket(sender, receiver.local_addr().expect("receiver address"))
                .expect("create transport");
        let packets = vec![b"one".to_vec(), b"two".to_vec(), b"three".to_vec()];

        assert_eq!(
            transport.send_batch(&packets).expect("send batch"),
            packets.len()
        );

        let mut buffer = [0_u8; 16];
        for expected in packets {
            let length = receiver.recv(&mut buffer).expect("receive datagram");
            assert_eq!(&buffer[..length], expected);
        }
    }

    #[test]
    fn receives_connected_datagrams_as_a_batch() {
        let receiver = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
        let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
        let receiver_address = receiver.local_addr().expect("receiver address");
        let sender_address = sender.local_addr().expect("sender address");
        let mut sender =
            UdpTransport::from_socket(sender, receiver_address).expect("create sender");
        let mut receiver =
            UdpTransport::from_socket(receiver, sender_address).expect("create receiver");
        receiver
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("set timeout");
        let packets = vec![b"one".to_vec(), b"two".to_vec(), b"three".to_vec()];
        assert_eq!(
            sender.send_batch(&packets).expect("send batch"),
            packets.len()
        );
        let mut buffers: Vec<Vec<u8>> = (0..32).map(|_| vec![0_u8; 16]).collect();
        let mut lengths = Vec::with_capacity(32);

        receiver
            .receive_batch(&mut buffers, &mut lengths)
            .expect("receive batch");

        assert_eq!(lengths.len(), packets.len());
        for ((buffer, length), expected) in buffers.iter().zip(lengths).zip(packets) {
            assert_eq!(&buffer[..length], expected);
        }
    }
}
