use std::{error::Error, fmt, net::SocketAddr};

use mousevpn_crypto::{CryptoError, KeyPair, PublicKey, SecretKey, SecureSession};

use crate::{
    ActiveSession, RegistryError, SessionAccessError, SessionInsertError, SessionTable, User,
    UserId, UserRegistry,
};

pub struct ProvisionedDevice {
    pub public_key: PublicKey,
    pub secret_key: SecretKey,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RevokeResult {
    pub revoked: bool,
    pub closed_sessions: usize,
}

pub struct ServerState {
    next_user_id: u64,
    users: UserRegistry,
    sessions: SessionTable,
}

impl ServerState {
    #[must_use]
    pub fn new(maximum_sessions: usize) -> Self {
        Self {
            next_user_id: 1,
            users: UserRegistry::new(),
            sessions: SessionTable::new(maximum_sessions),
        }
    }

    /// Creates a user with no authorized device keys.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid user attributes or exhausted IDs.
    pub fn create_user(
        &mut self,
        name: impl Into<String>,
        max_sessions: usize,
    ) -> Result<User, StateError> {
        let id = UserId(self.next_user_id);
        self.next_user_id = self
            .next_user_id
            .checked_add(1)
            .ok_or(StateError::UserIdExhausted)?;
        let user = User::new(id, name, max_sessions);
        self.users.add_user(user.clone())?;
        Ok(user)
    }

    /// Generates and authorizes a new device key for a user.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown user or failed key generation.
    pub fn provision_device(&mut self, user_id: UserId) -> Result<ProvisionedDevice, StateError> {
        let keys = KeyPair::generate()?;
        self.users.add_device(user_id, keys.public)?;
        Ok(ProvisionedDevice {
            public_key: keys.public,
            secret_key: keys.secret,
        })
    }

    pub fn revoke_device(&mut self, public_key: &PublicKey) -> RevokeResult {
        let revoked = self.users.revoke_device(public_key).is_some();
        let closed_sessions = if revoked {
            self.sessions.remove_device(public_key)
        } else {
            0
        };
        RevokeResult {
            revoked,
            closed_sessions,
        }
    }

    pub fn revoke_user(&mut self, user_id: UserId) -> RevokeResult {
        let revoked = self.users.revoke_user(user_id).is_some();
        let closed_sessions = if revoked {
            self.sessions.remove_user(user_id)
        } else {
            0
        };
        RevokeResult {
            revoked,
            closed_sessions,
        }
    }

    #[must_use]
    pub fn authorize(&self, public_key: &PublicKey) -> Option<User> {
        self.users.authorize(public_key).cloned()
    }

    /// Inserts an authenticated network session for an authorized user.
    ///
    /// # Errors
    ///
    /// Returns an error when a global or per-user limit is reached.
    pub fn insert_session(
        &mut self,
        session_id: u64,
        user: &User,
        peer: SocketAddr,
        crypto: SecureSession,
    ) -> Result<(), StateError> {
        self.sessions.insert(session_id, user, peer, crypto)?;
        Ok(())
    }

    /// Gets a session after verifying its UDP peer address.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown session or mismatched peer address.
    pub fn session_mut(
        &mut self,
        session_id: u64,
        peer: SocketAddr,
    ) -> Result<&mut ActiveSession, SessionAccessError> {
        self.sessions.get_mut(session_id, peer)
    }

    #[must_use]
    pub fn user_count(&self) -> usize {
        self.users.len()
    }

    #[must_use]
    pub fn device_count(&self) -> usize {
        self.users.device_count()
    }
}

#[derive(Debug)]
pub enum StateError {
    Crypto(CryptoError),
    Registry(RegistryError),
    Session(SessionInsertError),
    UserIdExhausted,
}

impl fmt::Display for StateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Crypto(error) => write!(formatter, "key generation failed: {error}"),
            Self::Registry(error) => write!(formatter, "registry update failed: {error}"),
            Self::Session(error) => write!(formatter, "session insert failed: {error}"),
            Self::UserIdExhausted => formatter.write_str("user ID space exhausted"),
        }
    }
}

impl Error for StateError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Crypto(error) => Some(error),
            Self::Registry(error) => Some(error),
            Self::Session(error) => Some(error),
            Self::UserIdExhausted => None,
        }
    }
}

impl From<CryptoError> for StateError {
    fn from(error: CryptoError) -> Self {
        Self::Crypto(error)
    }
}

impl From<RegistryError> for StateError {
    fn from(error: RegistryError) -> Self {
        Self::Registry(error)
    }
}

impl From<SessionInsertError> for StateError {
    fn from(error: SessionInsertError) -> Self {
        Self::Session(error)
    }
}
