use std::{
    env,
    error::Error,
    fs::OpenOptions,
    io::{self, Write},
    net::Ipv4Addr,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

use mousevpn_config::{encode_public_key, encode_secret_key, load_toml, ClientConfig};
use mousevpn_crypto::KeyPair;

struct Arguments {
    base_config: PathBuf,
    client_out: PathBuf,
    server_entry_out: PathBuf,
    name: String,
    address: Ipv4Addr,
}

fn main() -> Result<(), Box<dyn Error>> {
    let arguments = arguments()?;
    let base: ClientConfig = load_toml(&arguments.base_config)?;
    base.validate()?;
    let base: ClientConfig = load_toml(&arguments.base_config)?;
    let keys = KeyPair::generate()?;
    let client = format!(
        "server = \"{}\"\nserver_public_key = \"{}\"\nclient_private_key = \"{}\"\ntun_name = \"mousevpn0\"\n",
        base.server,
        base.server_public_key,
        encode_secret_key(&keys.secret),
    );
    let server_entry = format!(
        "[[clients]]\nname = \"{}\"\npublic_key = \"{}\"\naddress = \"{}\"\n",
        arguments.name,
        encode_public_key(&keys.public),
        arguments.address,
    );
    write_new(&arguments.client_out, client.as_bytes())?;
    if let Err(error) = write_new(&arguments.server_entry_out, server_entry.as_bytes()) {
        let _ = std::fs::remove_file(&arguments.client_out);
        return Err(error.into());
    }
    println!("Device files created; no secret key was printed.");
    Ok(())
}

fn arguments() -> Result<Arguments, io::Error> {
    let values: Vec<String> = env::args().skip(1).collect();
    if values.len() != 10 {
        return Err(usage());
    }
    let value = |flag: &str| -> Result<String, io::Error> {
        values
            .chunks_exact(2)
            .find(|pair| pair[0] == flag)
            .map(|pair| pair[1].clone())
            .ok_or_else(usage)
    };
    Ok(Arguments {
        base_config: value("--base-config")?.into(),
        client_out: value("--client-out")?.into(),
        server_entry_out: value("--server-entry-out")?.into(),
        name: value("--name")?,
        address: value("--address")?.parse().map_err(|_| usage())?,
    })
}

fn usage() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "usage: mousevpn-device --base-config <toml> --client-out <toml> --server-entry-out <toml> --name <name> --address <IPv4>",
    )
}

fn write_new(path: &Path, contents: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(contents)?;
    file.sync_all()
}
