//! The server's answer to an authenticated hello, shaped after the real site's,
//! and the session keys both sides derive from it.

use hkdf::Hkdf;
use ml_kem::{EncapsulationKey, MlKem768, B32};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::{
    hello::ParsedClientHello,
    record::{DirectionKey, RecordOpener, RecordSealer, TAG_LEN},
    wire::{
        handshake_message, push_extension, push_u16, push_vec, random_bytes, record_header, Reader,
        CONTENT_CHANGE_CIPHER_SPEC, CONTENT_HANDSHAKE, EXTENSION_KEY_SHARE,
        EXTENSION_SUPPORTED_VERSIONS, GROUP_X25519, GROUP_X25519_MLKEM768, HANDSHAKE_SERVER_HELLO,
        MAX_CIPHERTEXT_LEN, MLKEM768_CIPHERTEXT_LEN, TLS_1_2, TLS_1_3, X25519_LEN,
    },
    MousalityError,
};

const SESSION_SALT: &[u8] = b"MouseVPN Mousality v1 session";
/// RFC 8446 §4.1.3: the random that marks a `HelloRetryRequest`.
const HELLO_RETRY_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

/// How the camouflage site answers a Chrome hello, so an authenticated
/// client gets an answer of the same shape.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerTemplate {
    pub cipher_suite: u16,
    /// The key exchange group the site picks from Chrome's offer.
    pub group: u16,
    /// Whether `key_share` precedes `supported_versions` in its `ServerHello`.
    pub key_share_first: bool,
    /// Body lengths of the encrypted records the site sends before it waits
    /// for the client: encrypted extensions, certificate, signature, finished.
    pub flight: Vec<usize>,
}

impl Default for ServerTemplate {
    /// A typical answer from a site with an ECDSA certificate chain, used
    /// until the real site has been probed.
    fn default() -> Self {
        Self {
            cipher_suite: 0x1301,
            group: GROUP_X25519_MLKEM768,
            key_share_first: false,
            flight: vec![36, 3_065, 96, 53],
        }
    }
}

/// Everything a server sends in answer to an authenticated hello.
pub struct ServerResponse {
    /// `ServerHello`, `ChangeCipherSpec` and the encrypted flight.
    pub records: Vec<u8>,
    pub(crate) sealer: RecordSealer,
    pub(crate) opener: RecordOpener,
}

/// Answers an authenticated hello in the template's shape.
///
/// # Errors
///
/// Returns an error when the hello has no X25519 share or the random
/// generator fails.
pub fn respond(
    hello: &ParsedClientHello,
    server_static: &StaticSecret,
    template: &ServerTemplate,
) -> Result<ServerResponse, MousalityError> {
    let client_x25519 = PublicKey::from(hello.x25519.ok_or(MousalityError::Malformed)?);
    let ephemeral = StaticSecret::from(random_bytes::<32>()?);
    let ephemeral_public = PublicKey::from(&ephemeral);

    // Answer with the site's group when the client's hybrid key is valid, as
    // the site itself would; otherwise plain X25519.
    let hybrid_ciphertext = (template.group == GROUP_X25519_MLKEM768)
        .then(|| hello.ml_kem.as_deref().and_then(encapsulate))
        .flatten();
    let mut key_share = Vec::new();
    if let Some(ciphertext) = &hybrid_ciphertext {
        push_u16(&mut key_share, GROUP_X25519_MLKEM768);
        let mut key = ciphertext.clone();
        key.extend_from_slice(ephemeral_public.as_bytes());
        push_vec(&mut key_share, 2, &key);
    } else {
        push_u16(&mut key_share, GROUP_X25519);
        push_vec(&mut key_share, 2, ephemeral_public.as_bytes());
    }

    let mut random = random_bytes::<32>()?;
    if random == HELLO_RETRY_RANDOM {
        random[0] ^= 1;
    }
    let mut body = Vec::with_capacity(1_300);
    push_u16(&mut body, TLS_1_2);
    body.extend_from_slice(&random);
    push_vec(&mut body, 1, &hello.session_id);
    push_u16(&mut body, template.cipher_suite);
    body.push(0);
    let mut extensions = Vec::new();
    let versions = TLS_1_3.to_be_bytes();
    if template.key_share_first {
        push_extension(&mut extensions, EXTENSION_KEY_SHARE, &key_share);
        push_extension(&mut extensions, EXTENSION_SUPPORTED_VERSIONS, &versions);
    } else {
        push_extension(&mut extensions, EXTENSION_SUPPORTED_VERSIONS, &versions);
        push_extension(&mut extensions, EXTENSION_KEY_SHARE, &key_share);
    }
    push_vec(&mut body, 2, &extensions);
    let server_hello = handshake_message(HANDSHAKE_SERVER_HELLO, &body);

    let keys = SessionKeys::derive(
        &ephemeral,
        server_static,
        &client_x25519,
        &hello.message,
        &server_hello,
    )?;
    let mut sealer = RecordSealer::new(keys.server_to_client);
    let mut records = Vec::with_capacity(5_000);
    records.extend_from_slice(&record_header(
        CONTENT_HANDSHAKE,
        TLS_1_2,
        server_hello.len(),
    ));
    records.extend_from_slice(&server_hello);
    records.extend_from_slice(&change_cipher_spec());
    for &length in &template.flight {
        sealer.seal(&[], length.clamp(TAG_LEN, MAX_CIPHERTEXT_LEN), &mut records)?;
    }
    Ok(ServerResponse {
        records,
        sealer,
        opener: RecordOpener::new(keys.client_to_server),
    })
}

fn encapsulate(key: &[u8]) -> Option<Vec<u8>> {
    let key = EncapsulationKey::<MlKem768>::new(key.try_into().ok()?).ok()?;
    let mut randomness = random_bytes::<32>().ok()?;
    let (ciphertext, mut shared) = key.encapsulate_deterministic(&B32::from(randomness));
    randomness.zeroize();
    shared.zeroize();
    debug_assert_eq!(ciphertext.len(), MLKEM768_CIPHERTEXT_LEN);
    Some(ciphertext.to_vec())
}

pub(crate) fn change_cipher_spec() -> [u8; 6] {
    let header = record_header(CONTENT_CHANGE_CIPHER_SPEC, TLS_1_2, 1);
    [header[0], header[1], header[2], header[3], header[4], 1]
}

/// What a client reads from the server's `ServerHello`.
pub(crate) struct ParsedServerHello {
    pub(crate) x25519: [u8; X25519_LEN],
}

impl ParsedServerHello {
    pub(crate) fn parse(message: &[u8], session_id: &[u8; 32]) -> Result<Self, MousalityError> {
        let mut reader = Reader::new(message);
        if reader.u8()? != HANDSHAKE_SERVER_HELLO {
            return Err(MousalityError::Malformed);
        }
        let length = reader.u24()?;
        let mut body = Reader::new(reader.take(length)?);
        let _version = body.u16()?;
        if body.take(32)? == HELLO_RETRY_RANDOM {
            // A retry is what a real site sends, never a Mousality server.
            return Err(MousalityError::Unauthenticated);
        }
        if body.vec8()? != session_id {
            return Err(MousalityError::Unauthenticated);
        }
        let _cipher_suite = body.u16()?;
        let _compression = body.u8()?;
        let mut extensions = Reader::new(body.vec16()?);
        while !extensions.is_empty() {
            let kind = extensions.u16()?;
            let data = extensions.vec16()?;
            if kind != EXTENSION_KEY_SHARE {
                continue;
            }
            let mut share = Reader::new(data);
            let group = share.u16()?;
            let key = share.vec16()?;
            let x25519 = match group {
                GROUP_X25519 => key,
                GROUP_X25519_MLKEM768 if key.len() == MLKEM768_CIPHERTEXT_LEN + X25519_LEN => {
                    &key[MLKEM768_CIPHERTEXT_LEN..]
                }
                _ => return Err(MousalityError::Malformed),
            };
            return Ok(Self {
                x25519: x25519.try_into().map_err(|_| MousalityError::Malformed)?,
            });
        }
        Err(MousalityError::Malformed)
    }
}

/// The two directions' record keys.
pub(crate) struct SessionKeys {
    pub(crate) client_to_server: DirectionKey,
    pub(crate) server_to_client: DirectionKey,
}

impl SessionKeys {
    /// Derives the keys from both Diffie-Hellman results and the transcript.
    ///
    /// The ephemeral exchange gives forward secrecy for the outer layer; the
    /// exchange with the server's static key is what only the real server can
    /// complete, so an active attacker cannot sit in the middle.
    fn derive(
        local_ephemeral: &StaticSecret,
        local_or_server_static: &StaticSecret,
        peer_ephemeral: &PublicKey,
        client_hello: &[u8],
        server_hello: &[u8],
    ) -> Result<Self, MousalityError> {
        let ephemeral = local_ephemeral.diffie_hellman(peer_ephemeral);
        let static_exchange = local_or_server_static.diffie_hellman(peer_ephemeral);
        Self::expand(
            ephemeral.as_bytes(),
            static_exchange.as_bytes(),
            ephemeral.was_contributory() && static_exchange.was_contributory(),
            client_hello,
            server_hello,
        )
    }

    /// The client's side of [`Self::derive`].
    pub(crate) fn derive_client(
        client_ephemeral: &StaticSecret,
        server_ephemeral: &PublicKey,
        server_static: &PublicKey,
        client_hello: &[u8],
        server_hello: &[u8],
    ) -> Result<Self, MousalityError> {
        let ephemeral = client_ephemeral.diffie_hellman(server_ephemeral);
        let static_exchange = client_ephemeral.diffie_hellman(server_static);
        Self::expand(
            ephemeral.as_bytes(),
            static_exchange.as_bytes(),
            ephemeral.was_contributory() && static_exchange.was_contributory(),
            client_hello,
            server_hello,
        )
    }

    fn expand(
        ephemeral: &[u8; 32],
        static_exchange: &[u8; 32],
        contributory: bool,
        client_hello: &[u8],
        server_hello: &[u8],
    ) -> Result<Self, MousalityError> {
        if !contributory {
            return Err(MousalityError::InvalidKey);
        }
        let mut input = [0_u8; 64];
        input[..32].copy_from_slice(ephemeral);
        input[32..].copy_from_slice(static_exchange);
        let hkdf = Hkdf::<Sha256>::new(Some(SESSION_SALT), &input);
        input.zeroize();
        let transcript = Sha256::new()
            .chain_update(client_hello)
            .chain_update(server_hello)
            .finalize();
        let expand = |label: &[u8], output: &mut [u8]| {
            let mut info = label.to_vec();
            info.extend_from_slice(&transcript);
            hkdf.expand(&info, output)
                .map_err(|_| MousalityError::InvalidKey)
        };
        let (mut client_key, mut server_key) = ([0_u8; 32], [0_u8; 32]);
        let (mut client_iv, mut server_iv) = ([0_u8; 12], [0_u8; 12]);
        expand(b"c2s key", &mut client_key)?;
        expand(b"c2s iv", &mut client_iv)?;
        expand(b"s2c key", &mut server_key)?;
        expand(b"s2c iv", &mut server_iv)?;
        Ok(Self {
            client_to_server: DirectionKey::new(client_key, client_iv)?,
            server_to_client: DirectionKey::new(server_key, server_iv)?,
        })
    }
}
