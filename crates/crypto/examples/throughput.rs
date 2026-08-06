use std::{hint::black_box, time::Instant};

use mousevpn_crypto::{ClientHandshake, KeyPair, ProtocolContext, ServerHandshake};

const ITERATIONS: u32 = 100_000;
const PAYLOAD_LEN: u32 = 1_200;

fn main() {
    let (client, mut server) = establish();
    let payload = vec![0xA5; PAYLOAD_LEN as usize];
    let started = Instant::now();

    for sequence in 0..ITERATIONS {
        let ciphertext = client
            .encrypt(u64::from(sequence), black_box(&payload))
            .expect("benchmark encryption");
        let plaintext = server
            .decrypt(u64::from(sequence), black_box(&ciphertext))
            .expect("benchmark decryption");
        black_box(plaintext);
    }

    let elapsed = started.elapsed();
    let payload_bits = f64::from(ITERATIONS) * f64::from(PAYLOAD_LEN) * 8.0;
    let megabits_per_second = payload_bits / elapsed.as_secs_f64() / 1_000_000.0;
    println!(
        "{ITERATIONS} packets of {PAYLOAD_LEN} bytes: {megabits_per_second:.2} Mbit/s, {elapsed:.2?}"
    );
}

fn establish() -> (
    mousevpn_crypto::SecureSession,
    mousevpn_crypto::SecureSession,
) {
    let client_keys = KeyPair::generate().expect("client keys");
    let server_keys = KeyPair::generate().expect("server keys");
    let context = ProtocolContext::for_server(&server_keys.public);
    let mut client = ClientHandshake::new(&client_keys.secret, &server_keys.public, &context)
        .expect("client handshake");
    let initial = client.write_initial(&[]).expect("initial message");
    let mut server = ServerHandshake::new(&server_keys.secret, &context).expect("server handshake");
    server.read_initial(&initial).expect("read initial");
    let (server_session, response) = server.finish(&[]).expect("server response");
    let (client_session, _) = client.finish(&response).expect("client finish");
    (client_session, server_session)
}
