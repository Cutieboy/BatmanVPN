//! The client's first flight: a Chrome-shaped TLS 1.3 `ClientHello` whose
//! `legacy_session_id` carries the Mousality authentication.

use hkdf::Hkdf;
use ml_kem::{DecapsulationKey, KeyExport, MlKem768, Seed};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::{
    wire::{
        handshake_message, push_extension, push_u16, push_vec, random_bytes, record_header, Reader,
        CONTENT_HANDSHAKE, EXTENSION_KEY_SHARE, EXTENSION_SERVER_NAME, GROUP_X25519,
        GROUP_X25519_MLKEM768, HANDSHAKE_CLIENT_HELLO, MLKEM768_ENCAPSULATION_KEY_LEN, TLS_1_2,
        TLS_1_3, X25519_LEN,
    },
    MousalityError,
};

/// Offset of the 32 session ID bytes inside the handshake message: type (1),
/// length (3), version (2), random (32), session ID length (1).
const SESSION_ID_OFFSET: usize = 39;
const SESSION_ID_LEN: usize = 32;
/// The original protocol: a Chrome 13x-shaped hello and unshaped records.
pub const VERSION_1: u8 = 1;
/// Mousality 2.0: a Chrome 156 hello and shaped records in both directions.
pub const VERSION_2: u8 = 2;
const AUTH_SALT: &[u8] = b"MouseVPN Mousality v1 auth";

/// The Trust Anchor IDs Chrome 156 offers in extension `0xca34`, a fixed
/// list taken from its root store.
const CHROME_TRUST_ANCHORS: [u8; 186] = [
    0x00, 0xb8, 0x05, 0x82, 0xdf, 0x13, 0x02, 0x01, 0x05, 0x82, 0xdf, 0x13, 0x02, 0x06, 0x05, 0x82,
    0xdf, 0x13, 0x02, 0x0d, 0x05, 0x82, 0xdf, 0x13, 0x02, 0x0e, 0x05, 0x82, 0xdf, 0x13, 0x02, 0x0f,
    0x05, 0x82, 0xdf, 0x13, 0x02, 0x12, 0x05, 0x82, 0xdf, 0x13, 0x02, 0x13, 0x05, 0x82, 0xdf, 0x13,
    0x02, 0x14, 0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x07, 0x08, 0x83, 0x9a, 0x64, 0x8c,
    0x9b, 0x2d, 0x01, 0x08, 0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x09, 0x08, 0x83, 0x9a,
    0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0a, 0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0b, 0x08,
    0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0c, 0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01,
    0x0d, 0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x12, 0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b,
    0x2d, 0x01, 0x13, 0x04, 0xd6, 0x79, 0x09, 0x01, 0x04, 0xd6, 0x79, 0x09, 0x04, 0x04, 0xd6, 0x79,
    0x09, 0x05, 0x04, 0xd6, 0x79, 0x09, 0x06, 0x04, 0xd6, 0x79, 0x09, 0x07, 0x04, 0xd6, 0x79, 0x09,
    0x08, 0x04, 0xd6, 0x79, 0x09, 0x0a, 0x04, 0xd6, 0x79, 0x09, 0x0b, 0x04, 0xd6, 0x79, 0x09, 0x0c,
    0x04, 0xd6, 0x79, 0x09, 0x0d, 0x04, 0xd6, 0x79, 0x09, 0x0f,
];

/// What a valid hello proves: its protocol version and the client's clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Authentication {
    pub version: u8,
    pub unix_seconds: u32,
}

/// A Chrome-shaped `ClientHello` ready to send, and what the client keeps.
pub struct ClientHello {
    /// The complete TLS record.
    pub record: Vec<u8>,
    pub(crate) message: Vec<u8>,
    pub(crate) session_id: [u8; SESSION_ID_LEN],
    pub(crate) x25519: StaticSecret,
}

impl ClientHello {
    /// Builds a hello for `server_name` that only the holder of the secret
    /// behind `server_static` can recognise.
    ///
    /// # Errors
    ///
    /// Returns an error when the random generator fails or `server_name` is
    /// empty or longer than a DNS name.
    pub fn build(
        server_name: &str,
        server_static: &[u8; 32],
        unix_seconds: u64,
    ) -> Result<Self, MousalityError> {
        Self::build_version(server_name, server_static, unix_seconds, VERSION_2)
    }

    /// Builds the hello of a given protocol version; older ones stay for
    /// compatibility tests against released clients.
    pub(crate) fn build_version(
        server_name: &str,
        server_static: &[u8; 32],
        unix_seconds: u64,
        version: u8,
    ) -> Result<Self, MousalityError> {
        if server_name.is_empty() || server_name.len() > 253 {
            return Err(MousalityError::InvalidServerName);
        }
        let x25519 = StaticSecret::from(random_bytes::<32>()?);
        let x25519_public = PublicKey::from(&x25519);
        let mut seed = random_bytes::<64>()?;
        let ml_kem = DecapsulationKey::<MlKem768>::from_seed(Seed::from(seed));
        seed.zeroize();
        let encapsulation_key = ml_kem.encapsulation_key().to_bytes();

        let random = random_bytes::<32>()?;
        let mut body = Vec::with_capacity(1_900);
        push_u16(&mut body, TLS_1_2);
        body.extend_from_slice(&random);
        push_vec(&mut body, 1, &[0; SESSION_ID_LEN]);
        let grease = Grease::new()?;
        push_vec(&mut body, 2, &cipher_suites(grease.cipher));
        push_vec(&mut body, 1, &[0]);
        let extensions = extensions(
            server_name,
            &grease,
            x25519_public.as_bytes(),
            encapsulation_key.as_slice(),
            version,
        )?;
        push_vec(&mut body, 2, &extensions);

        let mut message = handshake_message(HANDSHAKE_CLIENT_HELLO, &body);
        let shared = x25519.diffie_hellman(&PublicKey::from(*server_static));
        if !shared.was_contributory() {
            return Err(MousalityError::InvalidKey);
        }
        let session_id =
            seal_session_id(shared.as_bytes(), &random, &message, unix_seconds, version)?;
        message[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN].copy_from_slice(&session_id);

        // Chrome writes its first record with the TLS 1.0 version for
        // compatibility with old middleboxes.
        let mut record = Vec::with_capacity(5 + message.len());
        record.extend_from_slice(&record_header(CONTENT_HANDSHAKE, 0x0301, message.len()));
        record.extend_from_slice(&message);
        Ok(Self {
            record,
            message,
            session_id,
            x25519,
        })
    }
}

/// What a server reads from any `ClientHello`, authenticated or not.
pub struct ParsedClientHello {
    pub(crate) message: Vec<u8>,
    pub(crate) random: [u8; 32],
    pub(crate) session_id: [u8; SESSION_ID_LEN],
    pub server_name: Option<String>,
    pub(crate) x25519: Option<[u8; X25519_LEN]>,
    pub(crate) ml_kem: Option<Vec<u8>>,
}

impl ParsedClientHello {
    /// Parses one complete handshake message.
    ///
    /// # Errors
    ///
    /// Returns an error for anything that is not a well-formed `ClientHello`.
    pub fn parse(message: &[u8]) -> Result<Self, MousalityError> {
        let mut reader = Reader::new(message);
        if reader.u8()? != HANDSHAKE_CLIENT_HELLO {
            return Err(MousalityError::Malformed);
        }
        let length = reader.u24()?;
        let body = reader.take(length)?;
        if !reader.is_empty() {
            return Err(MousalityError::Malformed);
        }
        let mut reader = Reader::new(body);
        let _version = reader.u16()?;
        let random: [u8; 32] = reader
            .take(32)?
            .try_into()
            .map_err(|_| MousalityError::Malformed)?;
        let session_id = reader.vec8()?;
        let _cipher_suites = reader.vec16()?;
        let _compression = reader.vec8()?;
        let mut parsed = Self {
            message: message.to_vec(),
            random,
            session_id: session_id.try_into().unwrap_or([0; SESSION_ID_LEN]),
            server_name: None,
            x25519: None,
            ml_kem: None,
        };
        if reader.is_empty() {
            return Ok(parsed);
        }
        let mut extensions = Reader::new(reader.vec16()?);
        while !extensions.is_empty() {
            let kind = extensions.u16()?;
            let data = extensions.vec16()?;
            match kind {
                EXTENSION_SERVER_NAME => parsed.server_name = parse_server_name(data)?,
                EXTENSION_KEY_SHARE => parsed.read_key_shares(data)?,
                _ => {}
            }
        }
        Ok(parsed)
    }

    fn read_key_shares(&mut self, data: &[u8]) -> Result<(), MousalityError> {
        let mut shares = Reader::new(Reader::new(data).vec16()?);
        while !shares.is_empty() {
            let group = shares.u16()?;
            let key = shares.vec16()?;
            match (group, key.len()) {
                (GROUP_X25519, X25519_LEN) => {
                    self.x25519 = key.try_into().ok();
                }
                (GROUP_X25519_MLKEM768, length)
                    if length == MLKEM768_ENCAPSULATION_KEY_LEN + X25519_LEN =>
                {
                    let (ml_kem, x25519) = key.split_at(MLKEM768_ENCAPSULATION_KEY_LEN);
                    self.ml_kem = Some(ml_kem.to_vec());
                    if self.x25519.is_none() {
                        self.x25519 = x25519.try_into().ok();
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Checks the authentication a Mousality client hid in the session ID.
    ///
    /// Returns the client's protocol version and clock reading, or `None` for
    /// any hello without a valid authentication.
    #[must_use]
    pub fn authenticate(&self, server_static: &StaticSecret) -> Option<Authentication> {
        let x25519 = self.x25519?;
        if self.message.len() < SESSION_ID_OFFSET + SESSION_ID_LEN
            || self.message[SESSION_ID_OFFSET - 1] != 32
        {
            return None;
        }
        let shared = server_static.diffie_hellman(&PublicKey::from(x25519));
        if !shared.was_contributory() {
            return None;
        }
        open_session_id(
            shared.as_bytes(),
            &self.random,
            &self.message,
            &self.session_id,
        )
    }

    /// The client's freshly chosen random, unique per connection attempt.
    #[must_use]
    pub const fn random(&self) -> &[u8; 32] {
        &self.random
    }
}

fn parse_server_name(data: &[u8]) -> Result<Option<String>, MousalityError> {
    let mut names = Reader::new(Reader::new(data).vec16()?);
    while !names.is_empty() {
        let kind = names.u8()?;
        let name = names.vec16()?;
        if kind == 0 {
            return Ok(std::str::from_utf8(name).ok().map(str::to_ascii_lowercase));
        }
    }
    Ok(None)
}

fn auth_key(shared: &[u8; 32], random: &[u8; 32]) -> Result<LessSafeKey, MousalityError> {
    let mut key = [0_u8; 32];
    Hkdf::<Sha256>::new(Some(AUTH_SALT), shared)
        .expand(&random[..20], &mut key)
        .map_err(|_| MousalityError::InvalidKey)?;
    let unbound = UnboundKey::new(&CHACHA20_POLY1305, &key).map_err(|_| MousalityError::InvalidKey);
    key.zeroize();
    Ok(LessSafeKey::new(unbound?))
}

fn auth_nonce(random: &[u8; 32]) -> Nonce {
    let mut nonce = [0_u8; 12];
    nonce.copy_from_slice(&random[20..]);
    Nonce::assume_unique_for_key(nonce)
}

/// The hello with its session ID zeroed: what the tag authenticates.
fn auth_data(message: &[u8]) -> Vec<u8> {
    let mut data = message.to_vec();
    data[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN].fill(0);
    data
}

fn seal_session_id(
    shared: &[u8; 32],
    random: &[u8; 32],
    message: &[u8],
    unix_seconds: u64,
    version: u8,
) -> Result<[u8; SESSION_ID_LEN], MousalityError> {
    let mut session_id = [0_u8; SESSION_ID_LEN];
    session_id[0] = version;
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the clock is compared modulo 2^32 seconds, which wraps in 2106"
    )]
    session_id[4..8].copy_from_slice(&(unix_seconds as u32).to_be_bytes());
    let (plaintext, tag) = session_id.split_at_mut(16);
    let sealed = auth_key(shared, random)?
        .seal_in_place_separate_tag(auth_nonce(random), Aad::from(auth_data(message)), plaintext)
        .map_err(|_| MousalityError::InvalidKey)?;
    tag.copy_from_slice(sealed.as_ref());
    Ok(session_id)
}

fn open_session_id(
    shared: &[u8; 32],
    random: &[u8; 32],
    message: &[u8],
    session_id: &[u8; SESSION_ID_LEN],
) -> Option<Authentication> {
    let mut opened = *session_id;
    let plaintext = auth_key(shared, random)
        .ok()?
        .open_in_place(
            auth_nonce(random),
            Aad::from(auth_data(message)),
            &mut opened,
        )
        .ok()?;
    if !matches!(plaintext[0], VERSION_1 | VERSION_2)
        || plaintext[1..4] != [0; 3]
        || plaintext[8..] != [0; 8]
    {
        return None;
    }
    Some(Authentication {
        version: plaintext[0],
        unix_seconds: u32::from_be_bytes([plaintext[4], plaintext[5], plaintext[6], plaintext[7]]),
    })
}

/// The GREASE values (RFC 8701) of one hello, distinct per position like
/// Chrome's.
struct Grease {
    cipher: u16,
    group: u16,
    version: u16,
    signature: u16,
    first_extension: u16,
    last_extension: u16,
}

impl Grease {
    fn new() -> Result<Self, MousalityError> {
        let random = random_bytes::<6>()?;
        let value = |byte: u8| {
            let nibble = u16::from(byte & 0x0f);
            0x0a0a | nibble << 12 | nibble << 4
        };
        let first_extension = value(random[3]);
        let mut last_extension = value(random[4]);
        if last_extension == first_extension {
            last_extension ^= 0x1010;
        }
        Ok(Self {
            cipher: value(random[0]),
            group: value(random[1]),
            version: value(random[2]),
            signature: value(random[5]),
            first_extension,
            last_extension,
        })
    }
}

fn cipher_suites(grease: u16) -> Vec<u8> {
    let mut suites = Vec::with_capacity(32);
    for suite in [
        grease, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
        0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
    ] {
        push_u16(&mut suites, suite);
    }
    suites
}

/// Chrome's extensions in a fresh random order, between its two GREASE
/// extensions, as Chrome has sent them since version 110. Version 2 adds what
/// Chrome 156 sends on top: GREASE and ML-DSA signature algorithms and the
/// Trust Anchor IDs extension.
fn extensions(
    server_name: &str,
    grease: &Grease,
    x25519: &[u8; 32],
    ml_kem: &[u8],
    version: u8,
) -> Result<Vec<u8>, MousalityError> {
    let mut list: Vec<(u16, Vec<u8>)> = Vec::with_capacity(18);

    let mut name = vec![0];
    push_vec(&mut name, 2, server_name.as_bytes());
    let mut names = Vec::new();
    push_vec(&mut names, 2, &name);
    list.push((EXTENSION_SERVER_NAME, names));
    list.push((0x0017, Vec::new()));
    list.push((0xff01, vec![0]));

    let mut groups = Vec::new();
    for group in [
        grease.group,
        GROUP_X25519_MLKEM768,
        GROUP_X25519,
        0x0017,
        0x0018,
    ] {
        push_u16(&mut groups, group);
    }
    let mut supported_groups = Vec::new();
    push_vec(&mut supported_groups, 2, &groups);
    list.push((0x000a, supported_groups));
    list.push((0x000b, vec![1, 0]));
    list.push((0x0023, Vec::new()));
    list.push((0x0010, {
        let mut protocols = Vec::new();
        push_vec(&mut protocols, 1, b"h2");
        push_vec(&mut protocols, 1, b"http/1.1");
        let mut alpn = Vec::new();
        push_vec(&mut alpn, 2, &protocols);
        alpn
    }));
    list.push((0x0005, vec![1, 0, 0, 0, 0]));
    list.push((0x000d, {
        let mut algorithms = Vec::new();
        if version >= VERSION_2 {
            for algorithm in [grease.signature, 0x0904, 0x0905, 0x0906] {
                push_u16(&mut algorithms, algorithm);
            }
        }
        for algorithm in [
            0x0403_u16, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
        ] {
            push_u16(&mut algorithms, algorithm);
        }
        let mut signature_algorithms = Vec::new();
        push_vec(&mut signature_algorithms, 2, &algorithms);
        signature_algorithms
    }));
    list.push((0x0012, Vec::new()));
    list.push((EXTENSION_KEY_SHARE, {
        let mut shares = Vec::new();
        push_u16(&mut shares, grease.group);
        push_vec(&mut shares, 2, &[0]);
        push_u16(&mut shares, GROUP_X25519_MLKEM768);
        let mut hybrid = ml_kem.to_vec();
        hybrid.extend_from_slice(x25519);
        push_vec(&mut shares, 2, &hybrid);
        push_u16(&mut shares, GROUP_X25519);
        push_vec(&mut shares, 2, x25519);
        let mut key_share = Vec::new();
        push_vec(&mut key_share, 2, &shares);
        key_share
    }));
    list.push((0x002d, vec![1, 1]));
    list.push((0x002b, {
        let mut versions = Vec::new();
        for version in [grease.version, TLS_1_3, TLS_1_2] {
            push_u16(&mut versions, version);
        }
        let mut supported_versions = Vec::new();
        push_vec(&mut supported_versions, 1, &versions);
        supported_versions
    }));
    list.push((0x001b, vec![2, 0, 2]));
    list.push((0x44cd, {
        let mut protocols = Vec::new();
        push_vec(&mut protocols, 1, b"h2");
        let mut settings = Vec::new();
        push_vec(&mut settings, 2, &protocols);
        settings
    }));
    list.push((0xfe0d, grease_ech()?));
    if version >= VERSION_2 {
        list.push((0xca34, CHROME_TRUST_ANCHORS.to_vec()));
    }

    shuffle(&mut list)?;
    let mut extensions = Vec::with_capacity(1_700);
    push_extension(&mut extensions, grease.first_extension, &[]);
    for (kind, body) in &list {
        push_extension(&mut extensions, *kind, body);
    }
    push_extension(&mut extensions, grease.last_extension, &[0]);
    Ok(extensions)
}

/// A GREASE `encrypted_client_hello` outer extension, as Chrome sends when
/// the site publishes no ECH configuration.
fn grease_ech() -> Result<Vec<u8>, MousalityError> {
    let random = random_bytes::<2>()?;
    let payload_len = [144_usize, 176, 208, 240][usize::from(random[1] & 3)];
    let mut ech = vec![0];
    push_u16(&mut ech, 0x0001);
    push_u16(&mut ech, 0x0001);
    ech.push(random[0]);
    push_vec(&mut ech, 2, &random_bytes::<32>()?);
    let mut payload = vec![0_u8; payload_len];
    getrandom::fill(&mut payload).map_err(|_| MousalityError::Random)?;
    push_vec(&mut ech, 2, &payload);
    Ok(ech)
}

fn shuffle<T>(items: &mut [T]) -> Result<(), MousalityError> {
    let mut random = [0_u8; 64];
    getrandom::fill(&mut random).map_err(|_| MousalityError::Random)?;
    for index in (1..items.len()).rev() {
        let draw = u16::from_be_bytes([random[2 * index], random[2 * index + 1]]);
        // The bias of a 16-bit draw over at most 20 slots is far below what
        // anyone could measure from extension orders.
        items.swap(index, usize::from(draw) % (index + 1));
    }
    Ok(())
}

pub(crate) fn client_hello_record_version_ok(version: u16) -> bool {
    matches!(version, 0x0301 | TLS_1_2)
}

#[cfg(test)]
mod tests {
    use x25519_dalek::{PublicKey, StaticSecret};

    use super::*;

    fn server() -> (StaticSecret, [u8; 32]) {
        let secret = StaticSecret::from([7_u8; 32]);
        let public = *PublicKey::from(&secret).as_bytes();
        (secret, public)
    }

    #[test]
    fn a_hello_carries_its_name_keys_and_authentication() {
        let (secret, public) = server();
        let hello = ClientHello::build("www.example.com", &public, 1_000_000).unwrap();
        assert_eq!(&hello.record[..3], &[CONTENT_HANDSHAKE, 3, 1]);
        let parsed = ParsedClientHello::parse(&hello.record[5..]).unwrap();
        assert_eq!(parsed.server_name.as_deref(), Some("www.example.com"));
        assert_eq!(
            parsed.x25519,
            Some(*PublicKey::from(&hello.x25519).as_bytes())
        );
        assert_eq!(parsed.ml_kem.as_ref().map(Vec::len), Some(1_184));
        assert_eq!(
            parsed.authenticate(&secret),
            Some(Authentication {
                version: VERSION_2,
                unix_seconds: 1_000_000
            })
        );
        // Chrome-sized: well over 1.5 KiB with the post-quantum share.
        assert!(hello.record.len() > 1_700, "{}", hello.record.len());
    }

    #[test]
    fn another_server_key_or_any_changed_byte_fails_authentication() {
        let (secret, public) = server();
        let hello = ClientHello::build("www.example.com", &public, 5).unwrap();
        assert!(ParsedClientHello::parse(&hello.message)
            .unwrap()
            .authenticate(&StaticSecret::from([8_u8; 32]))
            .is_none());
        for index in [10, SESSION_ID_OFFSET, hello.message.len() - 1] {
            let mut changed = hello.message.clone();
            changed[index] ^= 1;
            let parsed = ParsedClientHello::parse(&changed).unwrap();
            assert!(parsed.authenticate(&secret).is_none(), "byte {index}");
        }
    }

    #[test]
    fn hellos_differ_in_order_grease_and_randomness() {
        let (_, public) = server();
        let first = ClientHello::build("www.example.com", &public, 5).unwrap();
        let second = ClientHello::build("www.example.com", &public, 5).unwrap();
        assert_ne!(first.message, second.message);
        assert_ne!(first.session_id, second.session_id);
    }

    #[test]
    fn released_version_1_hellos_still_authenticate_and_unknown_versions_do_not() {
        let (secret, public) = server();
        let old = ClientHello::build_version("www.example.com", &public, 9, VERSION_1).unwrap();
        let parsed = ParsedClientHello::parse(&old.message).unwrap();
        assert_eq!(
            parsed.authenticate(&secret).map(|auth| auth.version),
            Some(VERSION_1)
        );
        let shape = Shape::of(&old.record);
        assert!(!shape.extensions.contains(&0xca34));
        assert_eq!(shape.signature_algorithms.len(), 8);

        let future = ClientHello::build_version("www.example.com", &public, 9, 3).unwrap();
        assert!(ParsedClientHello::parse(&future.message)
            .unwrap()
            .authenticate(&secret)
            .is_none());
    }

    /// The parts of a hello that fingerprints such as JA4 are made of, with
    /// GREASE values and per-connection randomness left out.
    #[derive(Debug, PartialEq, Eq)]
    struct Shape {
        record_version: [u8; 2],
        cipher_suites: Vec<u16>,
        extensions: Vec<u16>,
        signature_algorithms: Vec<u16>,
        groups: Vec<u16>,
        key_shares: Vec<(u16, usize)>,
        alpn: Vec<u8>,
        trust_anchors: Option<Vec<u8>>,
        ech_len: usize,
    }

    impl Shape {
        fn of(record: &[u8]) -> Self {
            let is_grease = |value: u16| value & 0x0f0f == 0x0a0a && value >> 8 == value & 0xff;
            let u16s = |data: &[u8]| -> Vec<u16> {
                data.chunks_exact(2)
                    .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
                    .filter(|value| !is_grease(*value))
                    .collect()
            };
            let mut reader = Reader::new(&record[5..]);
            reader.u8().unwrap();
            let length = reader.u24().unwrap();
            let mut body = Reader::new(reader.take(length).unwrap());
            body.take(34).unwrap();
            body.vec8().unwrap();
            let cipher_suites = u16s(body.vec16().unwrap());
            body.vec8().unwrap();
            let mut extensions = Reader::new(body.vec16().unwrap());
            let mut shape = Self {
                record_version: [record[1], record[2]],
                cipher_suites,
                extensions: Vec::new(),
                signature_algorithms: Vec::new(),
                groups: Vec::new(),
                key_shares: Vec::new(),
                alpn: Vec::new(),
                trust_anchors: None,
                ech_len: 0,
            };
            while !extensions.is_empty() {
                let kind = extensions.u16().unwrap();
                let data = extensions.vec16().unwrap();
                if is_grease(kind) {
                    continue;
                }
                shape.extensions.push(kind);
                match kind {
                    0x000d => shape.signature_algorithms = u16s(&data[2..]),
                    0x000a => shape.groups = u16s(&data[2..]),
                    0x0010 => shape.alpn = data.to_vec(),
                    0xca34 => shape.trust_anchors = Some(data.to_vec()),
                    0xfe0d => shape.ech_len = data.len(),
                    EXTENSION_KEY_SHARE => {
                        let mut shares = Reader::new(Reader::new(data).vec16().unwrap());
                        while !shares.is_empty() {
                            let group = shares.u16().unwrap();
                            let key = shares.vec16().unwrap();
                            if !is_grease(group) {
                                shape.key_shares.push((group, key.len()));
                            }
                        }
                    }
                    _ => {}
                }
            }
            // Chrome permutes the extensions on every connection.
            shape.extensions.sort_unstable();
            shape
        }
    }

    #[test]
    fn version_2_matches_a_chrome_156_capture() {
        let chrome = Shape::of(include_bytes!("../testdata/chrome-156-client-hello.bin"));
        let (_, public) = server();
        let ech_lengths = [186, 218, 250, 282];
        assert!(ech_lengths.contains(&chrome.ech_len));
        for _ in 0..16 {
            let ours = ClientHello::build("www.microsoft.com", &public, 5).unwrap();
            let mut shape = Shape::of(&ours.record);
            assert!(ech_lengths.contains(&shape.ech_len), "{}", shape.ech_len);
            shape.ech_len = chrome.ech_len;
            assert_eq!(shape, chrome);
        }
    }

    #[test]
    fn truncated_or_foreign_messages_are_malformed() {
        let (_, public) = server();
        let hello = ClientHello::build("www.example.com", &public, 5).unwrap();
        assert!(ParsedClientHello::parse(&hello.message[..hello.message.len() - 1]).is_err());
        assert!(ParsedClientHello::parse(&[2, 0, 0, 0]).is_err());
        assert!(ParsedClientHello::parse(b"GET / HTTP/1.1\r\n").is_err());
    }
}
