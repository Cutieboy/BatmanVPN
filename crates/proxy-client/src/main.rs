use std::{
    env,
    error::Error,
    io,
    net::{Ipv4Addr, SocketAddrV4},
    path::PathBuf,
};

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
    parse_arguments(&values)
}

fn parse_arguments(values: &[String]) -> Result<Arguments, io::Error> {
    let config = option(values, "--config")?.into();
    let explicit_listen = optional_option(values, "--listen");
    let port = optional_option(values, "--port");
    if explicit_listen.is_some() && port.is_some() {
        return Err(usage());
    }
    let listen = match (explicit_listen, port) {
        (Some(address), None) => address.parse::<SocketAddrV4>().map_err(|_| usage())?,
        (None, Some(port)) => SocketAddrV4::new(
            Ipv4Addr::LOCALHOST,
            port.parse::<u16>()
                .ok()
                .filter(|port| *port != 0)
                .ok_or_else(usage)?,
        ),
        (None, None) => DEFAULT_LISTEN
            .parse::<SocketAddrV4>()
            .map_err(|_| usage())?,
        (Some(_), Some(_)) => unreachable!("conflicting options were rejected"),
    };
    let expected_length = 2 + usize::from(explicit_listen.is_some() || port.is_some()) * 2;
    if values.len() != expected_length {
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
        "usage: mousevpn-proxy-client --config <client.toml> [--port 1080 | --listen 127.0.0.1:1080]",
    )
}

#[cfg(test)]
mod tests {
    use super::{parse_arguments, DEFAULT_LISTEN};

    #[test]
    fn default_is_loopback() {
        let address = DEFAULT_LISTEN
            .parse::<std::net::SocketAddrV4>()
            .expect("address");
        assert!(address.ip().is_loopback());
    }

    #[test]
    fn accepts_custom_port_on_loopback() {
        let values = ["--config", "friend.toml", "--port", "2080"].map(String::from);
        let arguments = parse_arguments(&values).expect("arguments");
        assert_eq!(arguments.listen.to_string(), "127.0.0.1:2080");
    }

    #[test]
    fn rejects_zero_or_conflicting_port() {
        let zero = ["--config", "friend.toml", "--port", "0"].map(String::from);
        assert!(parse_arguments(&zero).is_err());
        let conflict = [
            "--config",
            "friend.toml",
            "--port",
            "2080",
            "--listen",
            "127.0.0.1:1080",
        ]
        .map(String::from);
        assert!(parse_arguments(&conflict).is_err());
    }
}
