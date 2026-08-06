use std::{env, error::Error, io, path::Path};

use mousevpn_config::{load_toml, ClientConfig};
use mousevpn_linux_client::run;

fn main() -> Result<(), Box<dyn Error>> {
    let path = config_path()?;
    let config: ClientConfig = load_toml(Path::new(&path))?;
    let config = config.validate()?;
    run(&config)?;
    Ok(())
}

fn config_path() -> Result<String, io::Error> {
    let mut arguments = env::args().skip(1);
    match (
        arguments.next().as_deref(),
        arguments.next(),
        arguments.next(),
    ) {
        (Some("--config"), Some(path), None) => Ok(path),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: mousevpn-linux-client --config <client.toml>",
        )),
    }
}
