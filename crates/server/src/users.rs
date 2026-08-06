use std::{collections::HashMap, error::Error, fmt};

use mousevpn_crypto::PublicKey;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct UserId(pub u64);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct User {
    pub id: UserId,
    pub name: String,
    pub max_sessions: usize,
}

impl User {
    #[must_use]
    pub fn new(id: UserId, name: impl Into<String>, max_sessions: usize) -> Self {
        Self {
            id,
            name: name.into(),
            max_sessions,
        }
    }
}

#[derive(Debug, Default)]
pub struct UserRegistry {
    users: HashMap<UserId, User>,
    devices: HashMap<PublicKey, UserId>,
}

impl UserRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a user before device keys are provisioned.
    ///
    /// # Errors
    ///
    /// Returns an error for a duplicate ID, blank name or zero session limit.
    pub fn add_user(&mut self, user: User) -> Result<(), RegistryError> {
        if user.name.trim().is_empty() {
            return Err(RegistryError::BlankUserName);
        }
        if user.max_sessions == 0 {
            return Err(RegistryError::ZeroSessionLimit);
        }
        if self.users.contains_key(&user.id) {
            return Err(RegistryError::DuplicateUserId(user.id));
        }
        self.users.insert(user.id, user);
        Ok(())
    }

    /// Authorizes a device key for an existing user.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown user or duplicate key.
    pub fn add_device(&mut self, user_id: UserId, key: PublicKey) -> Result<(), RegistryError> {
        if !self.users.contains_key(&user_id) {
            return Err(RegistryError::UnknownUser(user_id));
        }
        if self.devices.insert(key, user_id).is_some() {
            return Err(RegistryError::DuplicateKey);
        }
        Ok(())
    }

    #[must_use]
    pub fn authorize(&self, key: &PublicKey) -> Option<&User> {
        self.devices
            .get(key)
            .and_then(|user_id| self.users.get(user_id))
    }

    pub fn revoke_device(&mut self, key: &PublicKey) -> Option<UserId> {
        self.devices.remove(key)
    }

    pub fn revoke_user(&mut self, user_id: UserId) -> Option<User> {
        let removed = self.users.remove(&user_id)?;
        self.devices.retain(|_, owner| *owner != user_id);
        Some(removed)
    }

    #[must_use]
    pub fn user(&self, user_id: UserId) -> Option<&User> {
        self.users.get(&user_id)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.users.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.users.is_empty()
    }

    #[must_use]
    pub fn device_count(&self) -> usize {
        self.devices.len()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistryError {
    BlankUserName,
    DuplicateKey,
    DuplicateUserId(UserId),
    UnknownUser(UserId),
    ZeroSessionLimit,
}

impl fmt::Display for RegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BlankUserName => formatter.write_str("user name must not be blank"),
            Self::DuplicateKey => formatter.write_str("device public key is already registered"),
            Self::DuplicateUserId(id) => {
                write!(formatter, "user ID {} is already registered", id.0)
            }
            Self::UnknownUser(id) => write!(formatter, "user ID {} does not exist", id.0),
            Self::ZeroSessionLimit => {
                formatter.write_str("session limit must be greater than zero")
            }
        }
    }
}

impl Error for RegistryError {}
