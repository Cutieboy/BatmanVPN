use std::{
    collections::HashMap,
    error::Error,
    fmt,
    net::SocketAddr,
    time::{Duration, Instant},
};

use mousevpn_crypto::SecureSession;

use crate::{User, UserId};

pub struct ActiveSession {
    user_id: UserId,
    peer: SocketAddr,
    crypto: SecureSession,
    last_seen: Instant,
}

impl ActiveSession {
    #[must_use]
    pub const fn user_id(&self) -> UserId {
        self.user_id
    }

    #[must_use]
    pub const fn peer(&self) -> SocketAddr {
        self.peer
    }

    pub fn crypto_mut(&mut self) -> &mut SecureSession {
        &mut self.crypto
    }

    pub fn touch(&mut self) {
        self.last_seen = Instant::now();
    }
}

pub struct SessionTable {
    sessions: HashMap<u64, ActiveSession>,
    maximum: usize,
}

impl SessionTable {
    #[must_use]
    pub fn new(maximum: usize) -> Self {
        Self {
            sessions: HashMap::new(),
            maximum,
        }
    }

    /// Inserts a session after its client key has been authorized.
    ///
    /// # Errors
    ///
    /// Returns an error for duplicate IDs or exceeded global/user limits.
    pub fn insert(
        &mut self,
        session_id: u64,
        user: &User,
        peer: SocketAddr,
        crypto: SecureSession,
    ) -> Result<(), SessionInsertError> {
        if self.sessions.contains_key(&session_id) {
            return Err(SessionInsertError::SessionIdInUse);
        }
        if self.sessions.len() >= self.maximum {
            return Err(SessionInsertError::TableFull);
        }
        let user_sessions = self
            .sessions
            .values()
            .filter(|session| session.user_id == user.id)
            .count();
        if user_sessions >= user.max_sessions {
            return Err(SessionInsertError::UserLimitReached(user.id));
        }

        self.sessions.insert(
            session_id,
            ActiveSession {
                user_id: user.id,
                peer,
                crypto,
                last_seen: Instant::now(),
            },
        );
        Ok(())
    }

    /// Finds a session and verifies the datagram source address.
    ///
    /// # Errors
    ///
    /// Returns an error when the ID is unknown or belongs to another peer.
    pub fn get_mut(
        &mut self,
        session_id: u64,
        peer: SocketAddr,
    ) -> Result<&mut ActiveSession, SessionAccessError> {
        let session = self
            .sessions
            .get_mut(&session_id)
            .ok_or(SessionAccessError::UnknownSession)?;
        if session.peer != peer {
            return Err(SessionAccessError::PeerMismatch);
        }
        session.touch();
        Ok(session)
    }

    pub fn remove_expired(&mut self, maximum_idle: Duration) -> usize {
        let before = self.sessions.len();
        self.sessions
            .retain(|_, session| session.last_seen.elapsed() <= maximum_idle);
        before - self.sessions.len()
    }

    pub fn remove_user(&mut self, user_id: UserId) -> usize {
        let before = self.sessions.len();
        self.sessions
            .retain(|_, session| session.user_id != user_id);
        before - self.sessions.len()
    }

    pub fn remove_device(&mut self, public_key: &mousevpn_crypto::PublicKey) -> usize {
        let before = self.sessions.len();
        self.sessions
            .retain(|_, session| session.crypto.peer_static_key() != *public_key);
        before - self.sessions.len()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionInsertError {
    SessionIdInUse,
    TableFull,
    UserLimitReached(UserId),
}

impl fmt::Display for SessionInsertError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SessionIdInUse => formatter.write_str("session ID is already active"),
            Self::TableFull => formatter.write_str("global session table is full"),
            Self::UserLimitReached(id) => {
                write!(formatter, "session limit reached for user {}", id.0)
            }
        }
    }
}

impl Error for SessionInsertError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionAccessError {
    UnknownSession,
    PeerMismatch,
}

impl fmt::Display for SessionAccessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownSession => formatter.write_str("unknown session"),
            Self::PeerMismatch => formatter.write_str("session belongs to another peer address"),
        }
    }
}

impl Error for SessionAccessError {}
