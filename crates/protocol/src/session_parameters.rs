use std::{error::Error, fmt, net::Ipv4Addr};

pub const SESSION_PARAMETERS_LEN: usize = 11;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionParameters {
    pub client_address: Ipv4Addr,
    pub prefix_len: u8,
    pub mtu: u16,
    pub dns: Ipv4Addr,
}

impl SessionParameters {
    #[must_use]
    pub fn encode(self) -> [u8; SESSION_PARAMETERS_LEN] {
        let mut output = [0_u8; SESSION_PARAMETERS_LEN];
        output[0..4].copy_from_slice(&self.client_address.octets());
        output[4] = self.prefix_len;
        output[5..7].copy_from_slice(&self.mtu.to_be_bytes());
        output[7..11].copy_from_slice(&self.dns.octets());
        output
    }

    /// Decodes and validates negotiated tunnel settings.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid length, prefix or MTU.
    pub fn decode(input: &[u8]) -> Result<Self, SessionParametersError> {
        if input.len() != SESSION_PARAMETERS_LEN {
            return Err(SessionParametersError::InvalidLength {
                actual: input.len(),
                expected: SESSION_PARAMETERS_LEN,
            });
        }
        let parameters = Self {
            client_address: Ipv4Addr::new(input[0], input[1], input[2], input[3]),
            prefix_len: input[4],
            mtu: u16::from_be_bytes([input[5], input[6]]),
            dns: Ipv4Addr::new(input[7], input[8], input[9], input[10]),
        };
        if parameters.prefix_len > 32 {
            return Err(SessionParametersError::InvalidPrefix(parameters.prefix_len));
        }
        if !(576..=9_000).contains(&parameters.mtu) {
            return Err(SessionParametersError::InvalidMtu(parameters.mtu));
        }
        Ok(parameters)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionParametersError {
    InvalidLength { actual: usize, expected: usize },
    InvalidPrefix(u8),
    InvalidMtu(u16),
}

impl fmt::Display for SessionParametersError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { actual, expected } => write!(
                formatter,
                "session parameters have {actual} bytes; expected {expected}"
            ),
            Self::InvalidPrefix(prefix) => write!(formatter, "invalid IPv4 prefix length {prefix}"),
            Self::InvalidMtu(mtu) => write!(formatter, "invalid tunnel MTU {mtu}"),
        }
    }
}

impl Error for SessionParametersError {}
