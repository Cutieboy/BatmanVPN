use mousevpn_config::ValidatedClientConfig;
use mousevpn_protocol::SessionParameters;

use crate::{handshake::connect, ClientError};

/// Completes an authenticated handshake without changing TUN, routes or DNS.
///
/// # Errors
///
/// Returns the same network, configuration and cryptographic errors as the
/// regular client handshake.
pub fn probe(config: &ValidatedClientConfig) -> Result<SessionParameters, ClientError> {
    let (_, _, parameters) = connect(config)?;
    Ok(parameters)
}
