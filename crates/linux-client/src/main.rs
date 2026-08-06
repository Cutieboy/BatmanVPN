use std::{env, error::Error, io, path::Path};

use mousevpn_config::{load_toml, ClientConfig};
use mousevpn_linux_client::{probe, run};

enum Mode {
    Run,
    Probe,
}

fn main() -> Result<(), Box<dyn Error>> {
    let (mode, path) = arguments()?;
    let config: ClientConfig = load_toml(Path::new(&path))?;
    let config = config.validate()?;
    match mode {
        Mode::Run => run(&config)?,
        Mode::Probe => {
            let parameters = probe(&config)?;
            println!(
                "MouseVPN handshake succeeded: address={}/{} mtu={} dns={}",
                parameters.client_address, parameters.prefix_len, parameters.mtu, parameters.dns,
            );
        }
    }
    Ok(())
}

fn arguments() -> Result<(Mode, String), io::Error> {
    let arguments: Vec<String> = env::args().skip(1).collect();
    match arguments.as_slice() {
        [config, path] if config == "--config" => Ok((Mode::Run, path.clone())),
        [probe, config, path] if probe == "--probe" && config == "--config" => {
            Ok((Mode::Probe, path.clone()))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage:\n  mousevpn-linux-client --config <client.toml>\n  mousevpn-linux-client --probe --config <client.toml>",
        )),
    }
}
