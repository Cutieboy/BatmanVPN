use std::{env, error::Error, io, path::Path};

use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit, Nonce,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use mousevpn_config::{load_toml, ClientConfig};
use pbkdf2::pbkdf2_hmac;
use serde::Serialize;
use sha2::Sha256;
use uuid::Uuid;
use zeroize::Zeroize;

const ITERATIONS: u32 = 210_000;
const AAD: &[u8] = b"MouseVPN profile v1";

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PortableProfile {
    version: u8,
    id: String,
    name: String,
    endpoint: String,
    server_public_key: String,
    client_private_key: String,
}

fn main() -> Result<(), Box<dyn Error>> {
    let (path, name) = arguments()?;
    let config: ClientConfig = load_toml(Path::new(&path))?;
    let profile = PortableProfile {
        version: 1,
        id: Uuid::new_v4().to_string(),
        name,
        endpoint: config.server.to_string(),
        server_public_key: config.server_public_key.clone(),
        client_private_key: config.client_private_key.clone(),
    };
    config.validate()?;

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
    let token = encrypt(&profile, password.as_bytes())?;
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

fn encrypt(profile: &PortableProfile, password: &[u8]) -> Result<String, Box<dyn Error>> {
    let mut salt = [0_u8; 16];
    let mut nonce = [0_u8; 12];
    getrandom::fill(&mut salt)?;
    getrandom::fill(&mut nonce)?;
    let mut key = [0_u8; 32];
    pbkdf2_hmac::<Sha256>(password, &salt, ITERATIONS, &mut key);
    let cipher = Aes256Gcm::new_from_slice(&key)?;
    let plaintext = serde_json::to_vec(profile)?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: AAD,
            },
        )
        .map_err(|_| "profile encryption failed")?;
    key.zeroize();
    let mut packed = Vec::with_capacity(salt.len() + nonce.len() + ciphertext.len());
    packed.extend_from_slice(&salt);
    packed.extend_from_slice(&nonce);
    packed.extend_from_slice(&ciphertext);
    Ok(format!("MV1.{}", URL_SAFE_NO_PAD.encode(packed)))
}
