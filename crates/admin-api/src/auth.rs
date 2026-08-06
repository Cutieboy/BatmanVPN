use std::{error::Error, fmt};

const MINIMUM_TOKEN_LEN: usize = 32;

pub struct AdminToken(Vec<u8>);

impl AdminToken {
    /// Creates an admin bearer token.
    ///
    /// # Errors
    ///
    /// Returns an error when the token is shorter than 32 bytes.
    pub fn new(token: impl Into<Vec<u8>>) -> Result<Self, TokenError> {
        let token = token.into();
        if token.len() < MINIMUM_TOKEN_LEN {
            return Err(TokenError::TooShort {
                actual: token.len(),
                minimum: MINIMUM_TOKEN_LEN,
            });
        }
        Ok(Self(token))
    }

    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenError {
    TooShort { actual: usize, minimum: usize },
}

impl fmt::Display for TokenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { actual, minimum } => {
                write!(
                    formatter,
                    "admin token has {actual} bytes; minimum is {minimum}"
                )
            }
        }
    }
}

impl Error for TokenError {}
