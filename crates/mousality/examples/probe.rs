//! Prints how a site answers the hello a Mousality client sends.
//!
//! `cargo run -p mousevpn-mousality --example probe -- www.example.com [address:port]`

use std::{
    net::TcpStream,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args().skip(1);
    let name = arguments
        .next()
        .ok_or("usage: probe <server name> [address:port]")?;
    let address = arguments.next().unwrap_or_else(|| format!("{name}:443"));
    let mut stream = TcpStream::connect(&address)?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let template = mousevpn_mousality::probe_site(&mut stream, &name, now)?;
    println!("{template:?}");
    Ok(())
}
