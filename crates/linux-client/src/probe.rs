use mousevpn_config::ValidatedClientConfig;
use mousevpn_protocol::SessionParameters;

use mousevpn_client_wire::ClientWire;

use crate::{handshake::connect, ClientError};

/// Completes an authenticated handshake without changing TUN, routes or DNS.
///
/// # Errors
///
/// Returns the same network, configuration and cryptographic errors as the
/// regular client handshake.
pub fn probe(config: &ValidatedClientConfig) -> Result<SessionParameters, ClientError> {
    let wire = ClientWire::from_config(config)?;
    let (_, _, parameters) = connect(config, &wire)?;
    Ok(parameters)
}
