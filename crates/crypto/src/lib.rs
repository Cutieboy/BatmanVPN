#![doc = "Cryptographic session boundary for `MouseVPN`."]

mod context;
mod error;
mod handshake;
mod keys;
mod replay;
mod session;

pub use context::ProtocolContext;
pub use error::CryptoError;
pub use handshake::{ClientHandshake, ServerHandshake};
pub use keys::{derive_morph_key, KeyPair, PublicKey, SecretKey, KEY_LEN};
pub use replay::{ReplayError, REPLAY_WINDOW_SIZE};
pub use session::{ReceiveHalf, SecureSession, SendHalf, AUTH_TAG_LEN};

pub const NOISE_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_SHA256";
pub const MAX_NOISE_MESSAGE_LEN: usize = 65_535;
