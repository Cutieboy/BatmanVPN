use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroize;

const FORMAT_VERSION: u32 = 1;
const MIN_PASSWORD_LENGTH: usize = 8;
const KDF_ITERATIONS: u32 = 150_000;
const SALT_SIZE: usize = 16;
const IV_SIZE: usize = 12;
const TAG_SIZE: usize = 16;
const KEY_SIZE: usize = 32;
const AAD: &[u8] = b"BatmanVPN backup v1";

#[derive(Debug, Deserialize, Serialize)]
struct Envelope {
    format: u32,
    kdf: String,
    iterations: u32,
    salt: String,
    iv: String,
    ciphertext: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct Snapshot {
    format: u32,
    app: String,
    profiles: serde_json::Value,
    routing: serde_json::Value,
}

pub(crate) fn export(password: &mut String) -> Result<Vec<u8>, String> {
    validate_password(password)?;
    let snapshot = Snapshot {
        format: FORMAT_VERSION,
        app: "BatmanVPN".to_owned(),
        profiles: crate::profiles::export_json()?,
        routing: crate::app_exclusions::export_json()?,
    };
    let plaintext = serde_json::to_vec(&snapshot).map_err(display_error)?;
    let envelope = encrypt(&plaintext, password)?;
    plaintext.zeroize();
    password.zeroize();
    serde_json::to_vec(&envelope).map_err(display_error)
}

pub(crate) fn import(data: &[u8], password: &mut String) -> Result<(), String> {
    validate_password(password)?;
    let envelope: Envelope = serde_json::from_slice(data)
        .map_err(|_| "Файл не является резервной копией BatmanVPN".to_owned())?;
    if envelope.format != FORMAT_VERSION
        || envelope.kdf != "PBKDF2WithHmacSHA256"
        || envelope.iterations != KDF_ITERATIONS
    {
        return Err("Неподдерживаемый формат резервной копии".to_owned());
    }

    let plaintext = decrypt(&envelope, password)?;
    password.zeroize();
    let snapshot: Snapshot = serde_json::from_slice(&plaintext)
        .map_err(|_| "Резервная копия повреждена".to_owned())?;
    if snapshot.format != FORMAT_VERSION || snapshot.app != "BatmanVPN" {
        return Err("Неподдерживаемый формат резервной копии".to_owned());
    }

    // Validate both stores completely before replacing either one.
    crate::profiles::validate_json(&snapshot.profiles)?;
    crate::app_exclusions::validate_json(&snapshot.routing)?;
    crate::profiles::import_json(&snapshot.profiles)?;
    crate::app_exclusions::import_json(&snapshot.routing)?;
    Ok(())
}

fn validate_password(password: &str) -> Result<(), String> {
    if password.chars().count() < MIN_PASSWORD_LENGTH {
        return Err(format!(
            "Пароль резервной копии должен содержать не менее {MIN_PASSWORD_LENGTH} символов"
        ));
    }
    Ok(())
}

fn encrypt(plaintext: &[u8], password: &str) -> Result<Envelope, String> {
    let salt = random_bytes(SALT_SIZE)?;
    let iv = random_bytes(IV_SIZE)?;
    let key = derive_key(password, &salt)?;
    let (ciphertext, tag) = aes_gcm_seal(&key, &iv, plaintext)?;
    let mut packed = ciphertext;
    packed.extend_from_slice(&tag);
    Ok(Envelope {
        format: FORMAT_VERSION,
        kdf: "PBKDF2WithHmacSHA256".to_owned(),
        iterations: KDF_ITERATIONS,
        salt: base64::encode(salt),
        iv: base64::encode(iv),
        ciphertext: base64::encode(packed),
    })
}

fn decrypt(envelope: &Envelope, password: &str) -> Result<Vec<u8>, String> {
    let salt = base64::decode(&envelope.salt)?;
    let iv = base64::decode(&envelope.iv)?;
    let packed = base64::decode(&envelope.ciphertext)?;
    if salt.len() != SALT_SIZE || iv.len() != IV_SIZE || packed.len() <= TAG_SIZE {
        return Err("Резервная копия повреждена".to_owned());
    }
    let ciphertext_len = packed.len() - TAG_SIZE;
    let key = derive_key(password, &salt)?;
    aes_gcm_open(&key, &iv, &packed[..ciphertext_len], &packed[ciphertext_len..])
}

fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; KEY_SIZE], String> {
    let mut key = [0u8; KEY_SIZE];
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(
        password.as_bytes(),
        salt,
        KDF_ITERATIONS,
        &mut key,
    );
    Ok(key)
}

fn random_bytes(len: usize) -> Result<Vec<u8>, String> {
    let mut bytes = vec![0u8; len];
    getrandom::fill(&mut bytes).map_err(display_error)?;
    Ok(bytes)
}

fn aes_gcm_seal(key: &[u8; KEY_SIZE], iv: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    use aes_gcm::{aead::{AeadInPlace, KeyInit}, Aes256Gcm, Nonce};
    let cipher = Aes256Gcm::new_from_slice(key).map_err(display_error)?;
    let nonce = Nonce::from_slice(iv);
    let mut buffer = plaintext.to_vec();
    let tag = cipher.encrypt_in_place_detached(nonce, AAD, &mut buffer).map_err(display_error)?;
    Ok((buffer, tag.to_vec()))
}

fn aes_gcm_open(key: &[u8; KEY_SIZE], iv: &[u8], ciphertext: &[u8], tag: &[u8]) -> Result<Vec<u8>, String> {
    use aes_gcm::{aead::{AeadInPlace, KeyInit}, Aes256Gcm, Nonce, Tag};
    let cipher = Aes256Gcm::new_from_slice(key).map_err(display_error)?;
    let nonce = Nonce::from_slice(iv);
    let mut buffer = ciphertext.to_vec();
    let tag = Tag::from_slice(tag);
    cipher.decrypt_in_place_detached(nonce, AAD, &mut buffer, tag)
        .map_err(|_| "Неверный пароль или повреждённая резервная копия".to_owned())?;
    Ok(buffer)
}

fn base64_encode(data: &[u8]) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine};
    STANDARD.encode(data)
}

mod base64 {
    pub fn encode(data: impl AsRef<[u8]>) -> String {
        super::base64_encode(data.as_ref())
    }
    pub fn decode(value: &str) -> Result<Vec<u8>, String> {
        use ::base64::{engine::general_purpose::STANDARD, Engine};
        STANDARD.decode(value).map_err(|_| "Резервная копия повреждена".to_owned())
    }
}

fn display_error(error: impl std::fmt::Display) -> String {
    error.to_string()
}
