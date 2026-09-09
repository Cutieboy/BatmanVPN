//! CPU-only envelope benchmark; does not measure TUN, UDP or network throughput.
use std::{hint::black_box, time::Instant};

use mousevpn_morph::{Direction, MorphCodec, MorphKey, Profile};

fn main() {
    let iterations: u32 = std::env::var("MOUSEVPN_BENCH_PACKETS")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(100_000);
    let codec = MorphCodec::new(MorphKey::from_bytes([7; 32]), Profile::Balanced);
    println!("inner_bytes,packets,encode_decode_ns_per_packet");
    for size in [64, 512, 1_317] {
        let payload = vec![42; size];
        let mut encoded = Vec::with_capacity(1_472);
        let mut decoded = Vec::with_capacity(1_472);
        for _ in 0..1_000 {
            codec
                .encode_payload(&payload, Direction::ClientToServer, &mut encoded)
                .unwrap();
            codec
                .decode(&encoded, Direction::ClientToServer, &mut decoded)
                .unwrap();
        }
        let started = Instant::now();
        for _ in 0..iterations {
            codec
                .encode_payload(black_box(&payload), Direction::ClientToServer, &mut encoded)
                .unwrap();
            codec
                .decode(black_box(&encoded), Direction::ClientToServer, &mut decoded)
                .unwrap();
            black_box(&decoded);
        }
        println!(
            "{size},{iterations},{:.0}",
            started.elapsed().as_secs_f64() * 1e9 / f64::from(iterations)
        );
    }
}
