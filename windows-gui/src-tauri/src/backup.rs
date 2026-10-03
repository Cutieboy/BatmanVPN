use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes256Gcm, Nonce, Tag,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use getrandom::fill as random_fill;
use pbkdf2::pbkdf2_hmac;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fs;
use std::path::Path;
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

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ImportResult {
    pub(crate) selected_profile_id: Option<String>,
    pub(crate) profile_count: usize,
    pub(crate) routed_app_count: usize,
}

pub(crate) fn export(mut password: String) -> Result<Vec<u8>, String> {
    let result = export_inner(&password);
    password.zeroize();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_round_trip_uses_the_android_compatible_envelope() {
        let plain = br#"{"format":1,"app":"BatmanVPN"}"#;
        let envelope = encrypt(plain, "correct horse battery staple").unwrap();
        assert_eq!(envelope.format, 1);
        assert_eq!(envelope.kdf, "PBKDF2WithHmacSHA256");
        assert_eq!(envelope.iterations, 150_000);
        let decoded = decrypt(&envelope, "correct horse battery staple").unwrap();
        assert_eq!(decoded, plain);
    }

    #[test]
    fn wrong_password_is_rejected() {
        let envelope = encrypt(b"secret", "correct horse battery staple").unwrap();
        assert!(decrypt(&envelope, "wrong password").is_err());
    }
}

fn export_inner(password: &str) -> Result<Vec<u8>, String> {
    validate_password(password)?;
    let snapshot = Snapshot {
        format: FORMAT_VERSION,
        app: "BatmanVPN".to_owned(),
        profiles: crate::profiles::export_json()?,
        routing: crate::app_exclusions::export_json()?,
    };
    let mut plaintext = serde_json::to_vec(&snapshot).map_err(display_error)?;
    let envelope = encrypt(&plaintext, password)?;
    plaintext.zeroize();
    serde_json::to_vec(&envelope).map_err(display_error)
}

pub(crate) fn import_from_path(path: &Path, mut password: String) -> Result<ImportResult, String> {
    let result = (|| {
        let data = fs::read(path).map_err(display_error)?;
        import_from_bytes(&data, &password)
    })();
    password.zeroize();
    result
}

fn import_from_bytes(data: &[u8], password: &str) -> Result<ImportResult, String> {
    validate_password(password)?;
    let envelope: Envelope = serde_json::from_slice(data)
        .map_err(|_| "Файл не является резервной копией BatmanVPN".to_owned())?;
    if envelope.format != FORMAT_VERSION
        || envelope.kdf != "PBKDF2WithHmacSHA256"
        || envelope.iterations != KDF_ITERATIONS
    {
        return Err("Неподдерживаемый формат резервной копии".to_owned());
    }

    let mut plaintext = decrypt(&envelope, password)?;
    let snapshot: Snapshot = serde_json::from_slice(&plaintext)
        .map_err(|_| "Резервная копия повреждена".to_owned())?;
    plaintext.zeroize();
    if snapshot.format != FORMAT_VERSION || snapshot.app != "BatmanVPN" {
        return Err("Неподдерживаемый формат резервной копии".to_owned());
    }

    let validated_profiles = crate::profiles::validate_json(&snapshot.profiles)?;
    let validated_routing = crate::app_exclusions::validate_json(&snapshot.routing)?;
    crate::profiles::import_validated(validated_profiles)?;
    crate::app_exclusions::import_validated(validated_routing)?;

    let selected_profile_id = crate::profiles::last_used_id()?;
    let profile_count = crate::profiles::list()?.len();
    let routed_app_count = crate::app_exclusions::backup_app_count()?;

    Ok(ImportResult {
        selected_profile_id,
        profile_count,
        routed_app_count,
        autostart: snapshot.autostart,
    })
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
    let mut salt = [0u8; SALT_SIZE];
    let mut iv = [0u8; IV_SIZE];
    random_fill(&mut salt).map_err(display_error)?;
    random_fill(&mut iv).map_err(display_error)?;

    let mut key = derive_key(password, &salt);
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(display_error)?;
    let nonce = Nonce::from_slice(&iv);
    let mut ciphertext = plaintext.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(nonce, AAD, &mut ciphertext)
        .map_err(display_error)?;
    ciphertext.extend_from_slice(&tag);

    let envelope = Envelope {
        format: FORMAT_VERSION,
        kdf: "PBKDF2WithHmacSHA256".to_owned(),
        iterations: KDF_ITERATIONS,
        salt: BASE64.encode(salt),
        iv: BASE64.encode(iv),
        ciphertext: BASE64.encode(ciphertext),
    };
    key.zeroize();
    Ok(envelope)
}

fn decrypt(envelope: &Envelope, password: &str) -> Result<Vec<u8>, String> {
    let salt = BASE64
        .decode(&envelope.salt)
        .map_err(|_| "Резервная копия повреждена".to_owned())?;
    let iv = BASE64
        .decode(&envelope.iv)
        .map_err(|_| "Резервная копия повреждена".to_owned())?;
    let packed = BASE64
        .decode(&envelope.ciphertext)
        .map_err(|_| "Резервная копия повреждена".to_owned())?;
    if salt.len() != SALT_SIZE || iv.len() != IV_SIZE || packed.len() <= TAG_SIZE {
        return Err("Резервная копия повреждена".to_owned());
    }

    let ciphertext_len = packed.len() - TAG_SIZE;
    let mut key = derive_key(password, &salt);
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(display_error)?;
    let nonce = Nonce::from_slice(&iv);
    let tag = Tag::from_slice(&packed[ciphertext_len..]);
    let mut plaintext = packed[..ciphertext_len].to_vec();
    let result = cipher
        .decrypt_in_place_detached(nonce, AAD, &mut plaintext, tag)
        .map_err(|_| "Неверный пароль или повреждённая резервная копия".to_owned());
    key.zeroize();
    result.map(|_| plaintext)
}

fn derive_key(password: &str, salt: &[u8]) -> [u8; KEY_SIZE] {
    let mut key = [0u8; KEY_SIZE];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, KDF_ITERATIONS, &mut key);
    key
}

fn display_error(error: impl std::fmt::Display) -> String {
    error.to_string()
}
