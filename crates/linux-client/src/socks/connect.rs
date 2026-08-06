use std::{
    io,
    net::{Ipv4Addr, SocketAddrV4},
};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::net::TcpStream;

pub(super) async fn connect_marked(
    address: Ipv4Addr,
    port: u16,
    mark: u32,
) -> io::Result<TcpStream> {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_mark(mark)?;
    socket.set_nonblocking(true)?;
    let destination = SockAddr::from(SocketAddrV4::new(address, port));
    match socket.connect(&destination) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
        Err(error) if error.raw_os_error() == Some(115) => {}
        Err(error) => return Err(error),
    }
    let stream = TcpStream::from_std(socket.into())?;
    stream.writable().await?;
    if let Some(error) = stream.take_error()? {
        return Err(error);
    }
    Ok(stream)
}
