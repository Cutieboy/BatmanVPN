use std::{
    fs::OpenOptions,
    io::{self, Write},
    net::SocketAddr,
    path::Path,
};

use mousevpn_config::{encode_public_key, encode_secret_key};
use mousevpn_crypto::KeyPair;

/// Generates one server and one client configuration with private file modes.
///
/// Existing files are never overwritten.
///
/// # Errors
///
/// Returns an error when key generation or exclusive file creation fails.
pub fn generate_example_configs(
    server_path: &Path,
    client_path: &Path,
    server_endpoint: SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    let server_keys = KeyPair::generate()?;
    let client_keys = KeyPair::generate()?;
    let server_config = format!(
        "listen = \"0.0.0.0:{}\"\nserver_public_key = \"{}\"\nserver_private_key = \"{}\"\n\n[tun]\nname = \"mousevpn0\"\naddress = \"10.77.0.1\"\nprefix_len = 24\nmtu = 1280\ndns = \"1.1.1.1\"\n\n[[clients]]\nname = \"owner\"\npublic_key = \"{}\"\naddress = \"10.77.0.2\"\n",
        server_endpoint.port(),
        encode_public_key(&server_keys.public),
        encode_secret_key(&server_keys.secret),
        encode_public_key(&client_keys.public),
    );
    let client_config = format!(
        "server = \"{server_endpoint}\"\nserver_public_key = \"{}\"\nclient_private_key = \"{}\"\ntun_name = \"mousevpn0\"\n",
        encode_public_key(&server_keys.public),
        encode_secret_key(&client_keys.secret),
    );

    write_private_new(server_path, server_config.as_bytes())?;
    if let Err(error) = write_private_new(client_path, client_config.as_bytes()) {
        let _ = std::fs::remove_file(server_path);
        return Err(error.into());
    }
    Ok(())
}

#[cfg(unix)]
fn write_private_new(path: &Path, contents: &[u8]) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(contents)?;
    file.sync_all()
}

#[cfg(not(unix))]
fn write_private_new(path: &Path, contents: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(contents)?;
    file.sync_all()
}
