//! Writes the `ClientHello` records a Mousality client would send, for
//! comparison with a browser capture.
//!
//! `cargo run -p mousevpn-mousality --example hello -- www.example.com OUT_DIR [COUNT]`

use std::time::{SystemTime, UNIX_EPOCH};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args().skip(1);
    let name = arguments
        .next()
        .ok_or("usage: hello <server name> <output directory> [count]")?;
    let directory = std::path::PathBuf::from(arguments.next().ok_or("missing output directory")?);
    let count: usize = arguments.next().map_or(Ok(1), |value| value.parse())?;
    std::fs::create_dir_all(&directory)?;
    let server = mousevpn_mousality::StaticSecret::from([7_u8; 32]);
    let server_public = x25519_dalek::PublicKey::from(&server);
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    for index in 0..count {
        let hello = mousevpn_mousality::ClientHello::build(&name, server_public.as_bytes(), now)?;
        std::fs::write(directory.join(format!("hello-{index}.bin")), &hello.record)?;
    }
    Ok(())
}
