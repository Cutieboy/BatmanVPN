use std::{env, error::Error, io, path::Path};

use mousevpn_config::{load_toml, ClientConfig};
use mousevpn_profile_cli::{encrypt_profile, PortableProfile};
use zeroize::Zeroize;

fn main() -> Result<(), Box<dyn Error>> {
    let (path, name) = arguments()?;
    let config: ClientConfig = load_toml(Path::new(&path))?;
    config.validate()?;
    let config: ClientConfig = load_toml(Path::new(&path))?;
    let profile = PortableProfile::new(
        name,
        config.server.to_string(),
        config.server_public_key,
        config.client_private_key,
    );

    let mut password = rpassword::prompt_password("Пароль профиля: ")?;
    let mut confirmation = rpassword::prompt_password("Повторите пароль: ")?;
    if password.len() < 8 {
        password.zeroize();
        confirmation.zeroize();
        return Err("пароль должен содержать минимум 8 символов".into());
    }
    if password != confirmation {
        password.zeroize();
        confirmation.zeroize();
        return Err("пароли не совпадают".into());
    }
    confirmation.zeroize();
    let token = encrypt_profile(&profile, password.as_bytes())?;
    password.zeroize();
    println!("{token}");
    Ok(())
}

fn arguments() -> Result<(String, String), io::Error> {
    let mut args = env::args().skip(1);
    match (
        args.next().as_deref(),
        args.next(),
        args.next().as_deref(),
        args.next(),
        args.next(),
    ) {
        (Some("--config"), Some(path), Some("--name"), Some(name), None)
            if !name.trim().is_empty() =>
        {
            Ok((path, name))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: mousevpn-profile --config <client.toml> --name <profile-name>",
        )),
    }
}
