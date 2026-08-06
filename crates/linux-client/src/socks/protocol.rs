use std::{io, net::SocketAddr};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

pub(super) enum Target {
    Ipv4(std::net::Ipv4Addr, u16),
    Domain(String, u16),
}

pub(super) struct RequestError {
    pub(super) source: io::Error,
    pub(super) reply_code: u8,
}

impl RequestError {
    fn new(kind: io::ErrorKind, message: &'static str, reply_code: u8) -> Self {
        Self {
            source: io::Error::new(kind, message),
            reply_code,
        }
    }
}

pub(super) async fn read_request(stream: &mut TcpStream) -> Result<Target, RequestError> {
    negotiate_auth(stream).await?;
    let mut header = [0_u8; 4];
    stream.read_exact(&mut header).await.map_err(io_error)?;
    if header[0] != 5 || header[2] != 0 {
        return Err(RequestError::new(
            io::ErrorKind::InvalidData,
            "invalid SOCKS5 request",
            0x01,
        ));
    }
    if header[1] != 1 {
        return Err(RequestError::new(
            io::ErrorKind::Unsupported,
            "only SOCKS5 CONNECT is supported",
            0x07,
        ));
    }
    match header[3] {
        1 => read_ipv4(stream).await,
        3 => read_domain(stream).await,
        _ => Err(RequestError::new(
            io::ErrorKind::Unsupported,
            "only IPv4 and domain SOCKS5 targets are supported",
            0x08,
        )),
    }
}

async fn negotiate_auth(stream: &mut TcpStream) -> Result<(), RequestError> {
    let mut greeting = [0_u8; 2];
    stream.read_exact(&mut greeting).await.map_err(io_error)?;
    if greeting[0] != 5 || greeting[1] == 0 {
        return Err(RequestError::new(
            io::ErrorKind::InvalidData,
            "invalid SOCKS5 greeting",
            0x01,
        ));
    }
    let mut methods = vec![0_u8; usize::from(greeting[1])];
    stream.read_exact(&mut methods).await.map_err(io_error)?;
    if !methods.contains(&0) {
        stream.write_all(&[5, 0xff]).await.map_err(io_error)?;
        return Err(RequestError::new(
            io::ErrorKind::PermissionDenied,
            "SOCKS5 client did not offer no-auth mode",
            0x01,
        ));
    }
    stream.write_all(&[5, 0]).await.map_err(io_error)
}

async fn read_ipv4(stream: &mut TcpStream) -> Result<Target, RequestError> {
    let mut value = [0_u8; 6];
    stream.read_exact(&mut value).await.map_err(io_error)?;
    Ok(Target::Ipv4(
        std::net::Ipv4Addr::new(value[0], value[1], value[2], value[3]),
        u16::from_be_bytes([value[4], value[5]]),
    ))
}

async fn read_domain(stream: &mut TcpStream) -> Result<Target, RequestError> {
    let length = stream.read_u8().await.map_err(io_error)?;
    if length == 0 {
        return Err(RequestError::new(
            io::ErrorKind::InvalidData,
            "empty SOCKS5 domain",
            0x04,
        ));
    }
    let mut value = vec![0_u8; usize::from(length) + 2];
    stream.read_exact(&mut value).await.map_err(io_error)?;
    let name = std::str::from_utf8(&value[..usize::from(length)])
        .map_err(|_| {
            RequestError::new(io::ErrorKind::InvalidData, "non-UTF-8 SOCKS5 domain", 0x04)
        })?
        .to_owned();
    let port = u16::from_be_bytes([value[usize::from(length)], value[usize::from(length) + 1]]);
    Ok(Target::Domain(name, port))
}

pub(super) async fn write_success(stream: &mut TcpStream, bound: SocketAddr) -> io::Result<()> {
    let address = match bound.ip() {
        std::net::IpAddr::V4(address) => address.octets(),
        std::net::IpAddr::V6(_) => [0; 4],
    };
    let mut response = [0_u8; 10];
    response[..4].copy_from_slice(&[5, 0, 0, 1]);
    response[4..8].copy_from_slice(&address);
    response[8..].copy_from_slice(&bound.port().to_be_bytes());
    stream.write_all(&response).await
}

pub(super) async fn write_failure(stream: &mut TcpStream, reply_code: u8) -> io::Result<()> {
    stream
        .write_all(&[5, reply_code, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
}

fn io_error(source: io::Error) -> RequestError {
    RequestError {
        source,
        reply_code: 0x01,
    }
}
