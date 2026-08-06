use std::{
    io,
    net::{Ipv4Addr, SocketAddrV4},
    time::Duration,
};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::{net::UdpSocket, time::timeout};

const DNS_TIMEOUT: Duration = Duration::from_secs(4);

pub(super) async fn resolve_ipv4(
    name: &str,
    dns_server: Ipv4Addr,
    mark: u32,
) -> io::Result<Ipv4Addr> {
    let mut identifier = [0_u8; 2];
    getrandom::fill(&mut identifier).map_err(io::Error::other)?;
    let query = build_query(name, identifier)?;
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_mark(mark)?;
    socket.bind(&SockAddr::from(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)))?;
    socket.connect(&SockAddr::from(SocketAddrV4::new(dns_server, 53)))?;
    socket.set_nonblocking(true)?;
    let socket = UdpSocket::from_std(socket.into())?;
    timeout(DNS_TIMEOUT, socket.send(&query))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS query timed out"))??;
    let mut response = [0_u8; 4096];
    let length = timeout(DNS_TIMEOUT, socket.recv(&mut response))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS response timed out"))??;
    parse_response(&response[..length], identifier)
}

fn build_query(name: &str, identifier: [u8; 2]) -> io::Result<Vec<u8>> {
    let name = name.trim_end_matches('.');
    if name.is_empty() || name.len() > 253 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid DNS name",
        ));
    }
    let mut query = Vec::with_capacity(name.len() + 18);
    query.extend_from_slice(&identifier);
    query.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 || !label.is_ascii() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid DNS label",
            ));
        }
        query.push(u8::try_from(label.len()).expect("DNS label is at most 63 bytes"));
        query.extend_from_slice(label.as_bytes());
    }
    query.extend_from_slice(&[0, 0, 1, 0, 1]);
    Ok(query)
}

fn parse_response(packet: &[u8], identifier: [u8; 2]) -> io::Result<Ipv4Addr> {
    if packet.len() < 12 || packet[..2] != identifier || packet[2] & 0x80 == 0 {
        return Err(invalid_response());
    }
    if packet[3] & 0x0f != 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "DNS name not found",
        ));
    }
    let questions = read_u16(packet, 4)?;
    let answers = read_u16(packet, 6)?;
    let mut offset = 12;
    for _ in 0..questions {
        offset = skip_name(packet, offset)?;
        offset = offset
            .checked_add(4)
            .filter(|end| *end <= packet.len())
            .ok_or_else(invalid_response)?;
    }
    for _ in 0..answers {
        offset = skip_name(packet, offset)?;
        if offset + 10 > packet.len() {
            return Err(invalid_response());
        }
        let record_type = read_u16(packet, offset)?;
        let class = read_u16(packet, offset + 2)?;
        let length = usize::from(read_u16(packet, offset + 8)?);
        offset += 10;
        let end = offset
            .checked_add(length)
            .filter(|end| *end <= packet.len())
            .ok_or_else(invalid_response)?;
        if record_type == 1 && class == 1 && length == 4 {
            return Ok(Ipv4Addr::new(
                packet[offset],
                packet[offset + 1],
                packet[offset + 2],
                packet[offset + 3],
            ));
        }
        offset = end;
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "DNS response has no IPv4 address",
    ))
}

fn skip_name(packet: &[u8], mut offset: usize) -> io::Result<usize> {
    loop {
        let length = *packet.get(offset).ok_or_else(invalid_response)?;
        offset += 1;
        if length == 0 {
            return Ok(offset);
        }
        if length & 0xc0 == 0xc0 {
            if packet.get(offset).is_none() {
                return Err(invalid_response());
            }
            return Ok(offset + 1);
        }
        if length & 0xc0 != 0 {
            return Err(invalid_response());
        }
        offset = offset
            .checked_add(usize::from(length))
            .filter(|end| *end <= packet.len())
            .ok_or_else(invalid_response)?;
    }
}

fn read_u16(packet: &[u8], offset: usize) -> io::Result<u16> {
    let bytes = packet
        .get(offset..offset + 2)
        .ok_or_else(invalid_response)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn invalid_response() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid DNS response")
}

#[cfg(test)]
mod tests {
    use super::{build_query, parse_response};
    use std::net::Ipv4Addr;

    #[test]
    fn encodes_query_and_decodes_compressed_a_answer() {
        let id = [0x12, 0x34];
        let query = build_query("example.com", id).expect("query");
        let mut response = query;
        response[2..4].copy_from_slice(&[0x81, 0x80]);
        response[6..8].copy_from_slice(&[0, 1]);
        response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4]);
        assert_eq!(
            parse_response(&response, id).expect("answer"),
            Ipv4Addr::new(1, 2, 3, 4)
        );
    }

    #[test]
    fn rejects_oversized_labels() {
        let name = format!("{}.example", "a".repeat(64));
        assert!(build_query(&name, [0, 1]).is_err());
    }
}
