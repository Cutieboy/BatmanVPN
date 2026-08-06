//! Compares the allocating packet path with the buffer-reusing one.
//!
//! Run with `cargo run --release --example packet_path -p mousevpn-data-plane`.

use std::{hint::black_box, time::Instant};

use mousevpn_crypto::{ClientHandshake, KeyPair, ProtocolContext, SecureSession, ServerHandshake};
use mousevpn_data_plane::TunnelDataPlane;
use mousevpn_protocol::Datagram;

const ITERATIONS: u32 = 200_000;
const PAYLOAD_LEN: u32 = 1_380;
const SESSION_ID: u64 = 1;
const MTU: usize = 1_420;

fn main() {
    let packet = ipv4_packet(PAYLOAD_LEN);

    let owned = measure_owned(&packet);
    let borrowed = measure_split(&packet);

    report("allocating path", owned);
    report("buffer-reusing path", borrowed);
    println!(
        "speedup: {:.2}x",
        owned.as_secs_f64() / borrowed.as_secs_f64()
    );
}

fn measure_owned(packet: &[u8]) -> std::time::Duration {
    let (client, server) = establish();
    let mut sender = TunnelDataPlane::new(SESSION_ID, MTU, client);
    let mut receiver = TunnelDataPlane::new(SESSION_ID, MTU, server);

    let started = Instant::now();
    for _ in 0..ITERATIONS {
        let wire = sender.encode_ip(black_box(packet)).expect("encode");
        let decoded = receiver.decode_ip(&wire).expect("decode");
        black_box(decoded);
    }
    started.elapsed()
}

fn measure_split(packet: &[u8]) -> std::time::Duration {
    let (client, server) = establish();
    let (mut sender, _) = TunnelDataPlane::new(SESSION_ID, MTU, client).split();
    let (_, mut receiver) = TunnelDataPlane::new(SESSION_ID, MTU, server).split();
    let mut wire = Vec::new();
    let mut plaintext = Vec::new();

    let started = Instant::now();
    for _ in 0..ITERATIONS {
        sender
            .encode_ip_into(black_box(packet), &mut wire)
            .expect("encode");
        let decoded = receiver
            .decode_into(Datagram::decode(&wire).expect("frame"), &mut plaintext)
            .expect("decode");
        black_box(decoded);
    }
    started.elapsed()
}

fn report(label: &str, elapsed: std::time::Duration) {
    let bits = f64::from(ITERATIONS) * f64::from(PAYLOAD_LEN) * 8.0;
    let per_packet = elapsed.as_secs_f64() / f64::from(ITERATIONS) * 1e9;
    println!(
        "{label:>22}: {:>7.0} Mbit/s, {per_packet:>5.0} ns/packet, {elapsed:.2?}",
        bits / elapsed.as_secs_f64() / 1e6
    );
}

fn establish() -> (SecureSession, SecureSession) {
    let client_keys = KeyPair::generate().expect("client keys");
    let server_keys = KeyPair::generate().expect("server keys");
    let context = ProtocolContext::for_server(&server_keys.public);
    let mut client = ClientHandshake::new(&client_keys.secret, &server_keys.public, &context)
        .expect("client handshake");
    let initial = client.write_initial(&[]).expect("initial");
    let mut server = ServerHandshake::new(&server_keys.secret, &context).expect("server handshake");
    server.read_initial(&initial).expect("read initial");
    let (server_session, response) = server.finish(&[]).expect("response");
    let (client_session, _) = client.finish(&response).expect("finish");
    (client_session, server_session)
}

fn ipv4_packet(payload_len: u32) -> Vec<u8> {
    let total_len = u16::try_from(20 + payload_len).expect("packet length");
    let mut packet = vec![0xAB; usize::from(total_len)];
    packet[0] = 0x45;
    packet[1] = 0;
    packet[2..4].copy_from_slice(&total_len.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&[10, 77, 0, 2]);
    packet[16..20].copy_from_slice(&[1, 1, 1, 1]);
    packet
}
