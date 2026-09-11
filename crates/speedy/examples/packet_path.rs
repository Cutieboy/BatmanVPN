//! CPU-only comparison at identical IP sizes; no TUN, UDP or network throughput.
use std::{hint::black_box, time::Instant};

use mousevpn_crypto::{ClientHandshake, KeyPair, ProtocolContext, ServerHandshake};
use mousevpn_data_plane::{Decoded, TunnelDataPlane};
use mousevpn_morph::{Direction as MorphDirection, MorphCodec, MorphKey, Profile};
use mousevpn_protocol::Datagram;
use mousevpn_speedy::{Direction, SpeedyCodec, SpeedyKey};

enum Wire {
    Legacy,
    Speedy(SpeedyCodec),
    Morph(MorphCodec),
}

impl Wire {
    fn encode(&self, input: &[u8], output: &mut Vec<u8>) {
        match self {
            Self::Legacy => {
                output.clear();
                output.extend_from_slice(input);
            }
            Self::Speedy(codec) => codec
                .encode(input, Direction::ClientToServer, output)
                .unwrap(),
            Self::Morph(codec) => codec
                .encode_payload(input, MorphDirection::ClientToServer, output)
                .unwrap(),
        }
    }

    fn decode(&self, input: &[u8], output: &mut Vec<u8>) {
        match self {
            Self::Legacy => {
                output.clear();
                output.extend_from_slice(input);
            }
            Self::Speedy(codec) => codec
                .decode(input, Direction::ClientToServer, output)
                .unwrap(),
            Self::Morph(codec) => {
                codec
                    .decode(input, MorphDirection::ClientToServer, output)
                    .unwrap();
            }
        }
    }
}

fn main() {
    let iterations = std::env::var("MOUSEVPN_BENCH_PACKETS")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|count| *count > 0)
        .unwrap_or(100_000);
    println!("mode,ip_bytes,iterations,encode_decode_ns,wire_bytes");
    for size in [64_u16, 512, 1_280] {
        for (name, wire) in [
            ("legacy", Wire::Legacy),
            (
                "speedy",
                Wire::Speedy(SpeedyCodec::new(SpeedyKey::from_bytes([7; 32]))),
            ),
            (
                "morph_balanced",
                Wire::Morph(MorphCodec::new(
                    MorphKey::from_bytes([8; 32]),
                    Profile::Balanced,
                )),
            ),
        ] {
            measure(name, &wire, size, iterations);
        }
    }
}

#[allow(clippy::cast_precision_loss)]
fn measure(name: &str, wire: &Wire, size: u16, iterations: u32) {
    let client = KeyPair::generate().unwrap();
    let server = KeyPair::generate().unwrap();
    let context = if matches!(wire, Wire::Speedy(_)) {
        ProtocolContext::for_speedy_server(&server.public)
    } else {
        ProtocolContext::for_server(&server.public)
    };
    let mut initiator = ClientHandshake::new(&client.secret, &server.public, &context).unwrap();
    let mut responder = ServerHandshake::new(&server.secret, &context).unwrap();
    responder
        .read_initial(&initiator.write_initial(&[]).unwrap())
        .unwrap();
    let (server_crypto, response) = responder.finish(&[]).unwrap();
    let (client_crypto, _) = initiator.finish(&response).unwrap();
    let (mut sender, _) = TunnelDataPlane::new(7, 1_391, client_crypto).split();
    let (_, mut receiver) = TunnelDataPlane::new(7, 1_391, server_crypto).split();
    let mut packet = vec![42; usize::from(size)];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&size.to_be_bytes());
    let mut inner = Vec::with_capacity(1_472);
    let mut outer = Vec::with_capacity(1_472);
    let mut unmasked = Vec::with_capacity(1_472);
    let mut plaintext = Vec::with_capacity(1_472);
    let mut run = || {
        sender
            .encode_ip_into(black_box(&packet), &mut inner)
            .unwrap();
        wire.encode(&inner, &mut outer);
        wire.decode(black_box(&outer), &mut unmasked);
        let decoded = receiver
            .decode_into(Datagram::decode(&unmasked).unwrap(), &mut plaintext)
            .unwrap();
        assert_eq!(black_box(decoded), Decoded::Ip(packet.as_slice()));
        outer.len()
    };
    for _ in 0..1_000 {
        run();
    }
    let started = Instant::now();
    let mut total_bytes = 0_u64;
    for _ in 0..iterations {
        total_bytes += run() as u64;
    }
    println!(
        "{name},{size},{iterations},{:.0},{:.1}",
        started.elapsed().as_secs_f64() * 1e9 / f64::from(iterations),
        total_bytes as f64 / f64::from(iterations)
    );
}
