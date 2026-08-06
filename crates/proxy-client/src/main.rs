use std::{env, error::Error, io, net::SocketAddrV4, path::PathBuf};

use mousevpn_config::{load_toml, ClientConfig};
use mousevpn_linux_client::run_proxy;

const DEFAULT_LISTEN: &str = "127.0.0.1:1080";

struct Arguments {
    config: PathBuf,
    listen: SocketAddrV4,
}

fn main() -> Result<(), Box<dyn Error>> {
    let arguments = arguments()?;
    let config: ClientConfig = load_toml(&arguments.config)?;
    let config = config.validate()?;
    run_proxy(&config, arguments.listen)?;
    Ok(())
}

fn arguments() -> Result<Arguments, io::Error> {
    let values: Vec<String> = env::args().skip(1).collect();
    let config = option(&values, "--config")?.into();
    let listen = optional_option(&values, "--listen")
        .unwrap_or(DEFAULT_LISTEN)
        .parse::<SocketAddrV4>()
        .map_err(|_| usage())?;
    if values.len() != 2 && values.len() != 4 {
        return Err(usage());
    }
    Ok(Arguments { config, listen })
}

fn option<'a>(values: &'a [String], flag: &str) -> Result<&'a str, io::Error> {
    optional_option(values, flag).ok_or_else(usage)
}

fn optional_option<'a>(values: &'a [String], flag: &str) -> Option<&'a str> {
    values
        .chunks_exact(2)
        .find(|pair| pair[0] == flag)
        .map(|pair| pair[1].as_str())
}

fn usage() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "usage: mousevpn-proxy-client --config <client.toml> [--listen 127.0.0.1:1080]",
    )
}

#[cfg(test)]
mod tests {
    use super::DEFAULT_LISTEN;

    #[test]
    fn default_is_loopback() {
        let address = DEFAULT_LISTEN
            .parse::<std::net::SocketAddrV4>()
            .expect("address");
        assert!(address.ip().is_loopback());
    }
}
