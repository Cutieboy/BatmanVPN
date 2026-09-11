//! Send real ICMP packets through a registered test device without a local TUN.
//! Run with a dedicated, disposable profile: a handshake replaces that device's
//! existing session. Usage: `packet_probe PROFILE PROTOCOL DESTINATION_IPV4`.

use std::{
    error::Error,
    io,
    net::{Ipv4Addr, UdpSocket},
    path::Path,
    time::{Duration, Instant},
};

use mousevpn_client_wire::ClientWire;
use mousevpn_config::{load_toml, ClientConfig, ClientProtocol, ValidatedClientConfig};
use mousevpn_crypto::ClientHandshake;
use mousevpn_data_plane::TunnelDataPlane;
use mousevpn_protocol::{Datagram, Header, PacketKind, SessionParameters};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 3 {
        return Err("usage: packet_probe PROFILE PROTOCOL DESTINATION_IPV4".into());
    }
    let mut config: ClientConfig = load_toml(Path::new(&args[0]))?;
    config.protocol = match args[1].as_str() {
        "speedy" => ClientProtocol::Speedy,
        "legacy" => ClientProtocol::Legacy,
        "morph_quiet" => ClientProtocol::MorphQuiet,
        "morph_balanced" => ClientProtocol::MorphBalanced,
        "morph_paranoid" => ClientProtocol::MorphParanoid,
        _ => return Err("unknown protocol".into()),
    };
    let destination: Ipv4Addr = args[2].parse()?;
    let config = config.validate()?;
    let wire = ClientWire::from_config(&config)?;
    let socket = UdpSocket::bind(if config.server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })?;
    socket.connect(config.server)?;
    let started = Instant::now();
    let (mut plane, parameters) = handshake(&socket, &wire, &config)?;
    println!(
        "protocol={} endpoint={} source={} assigned={} mtu={} handshake_ms={:.3}",
        args[1],
        config.server,
        socket.local_addr()?,
        parameters.client_address,
        parameters.mtu,
        started.elapsed().as_secs_f64() * 1000.0
    );
    socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    for length in [64, parameters.mtu] {
        let mut elapsed = Vec::new();
        for sequence in 1..=10 {
            let request = echo_packet(parameters.client_address, destination, length, sequence);
            let mut encoded = Vec::new();
            wire.encode(&plane.encode_ip(&request)?, &mut encoded)?;
            let sent = Instant::now();
            socket.send(&encoded)?;
            receive_echo(&socket, &wire, &mut plane, &request)?;
            elapsed.push(sent.elapsed().as_secs_f64() * 1000.0);
        }
        println!(
            "destination={destination} ip_bytes={length} sent=10 received=10 rtt_ms_min={:.3} rtt_ms_mean={:.3} rtt_ms_max={:.3}",
            elapsed.iter().copied().fold(f64::INFINITY, f64::min),
            elapsed.iter().sum::<f64>() / 10.0,
            elapsed.iter().copied().fold(0.0, f64::max),
        );
    }
    Ok(())
}

fn handshake(
    socket: &UdpSocket,
    wire: &ClientWire,
    config: &ValidatedClientConfig,
) -> Result<(TunnelDataPlane, SessionParameters)> {
    let mut random = [0; 8];
    getrandom::fill(&mut random)?;
    let session_id = u64::from_be_bytes(random);
    let mut handshake = ClientHandshake::new(
        &config.client_private_key,
        &config.server_public_key,
        &config.context,
    )?;
    let initial = handshake.write_initial(&[])?;
    let request = Datagram::new(
        Header {
            kind: PacketKind::HandshakeInit,
            flags: 0,
            session_id,
            sequence: 0,
        },
        &initial,
    )
    .encode();
    let mut incoming = vec![0; 65_535];
    let mut decoded = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        let mut encoded = Vec::new();
        wire.encode(&request, &mut encoded)?;
        socket.send(&encoded)?;
        socket.set_read_timeout(Some(Duration::from_millis(700)))?;
        let length = match socket.recv(&mut incoming) {
            Ok(length) => length,
            Err(error) if timeout(&error) => continue,
            Err(error) => return Err(error.into()),
        };
        if !wire.decode(&incoming[..length], &mut decoded)? {
            continue;
        }
        let response = Datagram::decode(&decoded)?;
        if response.header.kind != PacketKind::HandshakeResponse
            || response.header.session_id != session_id
        {
            continue;
        }
        let (crypto, payload) = handshake.finish(response.payload)?;
        let parameters = SessionParameters::decode(&payload)?;
        return Ok((
            TunnelDataPlane::new(session_id, usize::from(parameters.mtu), crypto),
            parameters,
        ));
    }
    Err("handshake timeout".into())
}

fn echo_packet(source: Ipv4Addr, destination: Ipv4Addr, length: u16, sequence: u16) -> Vec<u8> {
    let mut packet = vec![0xa5; usize::from(length)];
    packet[..28].fill(0);
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&length.to_be_bytes());
    packet[6] = 0x40; // Don't fragment: test the negotiated MTU as a datagram.
    packet[8] = 64;
    packet[9] = 1; // ICMP.
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&destination.octets());
    let ip_checksum = checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
    packet[20] = 8; // Echo request.
    packet[24..26].copy_from_slice(&0x5350_u16.to_be_bytes());
    packet[26..28].copy_from_slice(&sequence.to_be_bytes());
    let icmp_checksum = checksum(&packet[20..]);
    packet[22..24].copy_from_slice(&icmp_checksum.to_be_bytes());
    packet
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = bytes
        .chunks(2)
        .map(|word| u32::from(u16::from_be_bytes([word[0], *word.get(1).unwrap_or(&0)])))
        .sum();
    while sum > u32::from(u16::MAX) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !u16::try_from(sum).expect("folded checksum")
}

fn receive_echo(
    socket: &UdpSocket,
    wire: &ClientWire,
    plane: &mut TunnelDataPlane,
    request: &[u8],
) -> Result<()> {
    let mut incoming = vec![0; 65_535];
    let mut decoded = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        let length = socket.recv(&mut incoming)?;
        if !wire.decode(&incoming[..length], &mut decoded)? {
            continue;
        }
        let packet = plane.decode_ip(&decoded)?;
        if packet.len() < 28 || packet[0] >> 4 != 4 || packet[9] != 1 {
            continue;
        }
        let header_len = usize::from(packet[0] & 0xf) * 4;
        if header_len < 20 || packet.len() < header_len + 8 {
            continue;
        }
        let icmp = &packet[header_len..];
        if packet[12..16] == request[16..20]
            && packet[16..20] == request[12..16]
            && icmp[0] == 0
            && icmp[1] == 0
            && icmp[4..] == request[24..]
            && checksum(&packet[..header_len]) == 0
            && checksum(icmp) == 0
        {
            return Ok(());
        }
    }
    Err("no matching ICMP echo reply".into())
}

fn timeout(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    )
}
