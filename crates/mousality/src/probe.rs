//! Learning how the camouflage site answers a Chrome hello.

use std::io::{self, Read, Write};

use crate::{
    hello::ClientHello,
    server_hello::ServerTemplate,
    wire::{
        Reader, CONTENT_ALERT, CONTENT_APPLICATION_DATA, CONTENT_CHANGE_CIPHER_SPEC,
        CONTENT_HANDSHAKE, EXTENSION_KEY_SHARE, EXTENSION_SUPPORTED_VERSIONS,
        HANDSHAKE_SERVER_HELLO, MAX_CIPHERTEXT_LEN, RECORD_HEADER_LEN, TLS_1_3,
    },
    MousalityError,
};

/// Most records a site's first encrypted flight is read for.
const MAX_FLIGHT_RECORDS: usize = 16;

/// Sends the site the hello a Mousality client would and records the shape
/// of its answer.
///
/// The caller sets a read timeout on the stream: the site stops sending once
/// its flight is out, because it waits for the client's `Finished`, and the
/// timeout is what ends the flight.
///
/// # Errors
///
/// Returns an error when the site does not answer with TLS 1.3.
pub fn probe_site<S: Read + Write>(
    stream: &mut S,
    server_name: &str,
    unix_seconds: u64,
) -> Result<ServerTemplate, MousalityError> {
    // Any key will do: the site cannot read the authentication anyway.
    let hello = ClientHello::build(server_name, &[9; 32], unix_seconds)?;
    stream.write_all(&hello.record)?;

    let mut header = [0_u8; RECORD_HEADER_LEN];
    stream.read_exact(&mut header)?;
    let mut body = vec![0_u8; record_length(header)?];
    stream.read_exact(&mut body)?;
    if header[0] == CONTENT_ALERT {
        return Err(MousalityError::Closed);
    }
    if header[0] != CONTENT_HANDSHAKE {
        return Err(MousalityError::Malformed);
    }
    let mut template = parse_server_hello(&body)?;

    template.flight.clear();
    while template.flight.len() < MAX_FLIGHT_RECORDS {
        match stream.read_exact(&mut header) {
            Ok(()) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                break;
            }
            Err(error) => return Err(error.into()),
        }
        let length = record_length(header)?;
        let mut body = vec![0_u8; length];
        stream.read_exact(&mut body)?;
        match header[0] {
            CONTENT_CHANGE_CIPHER_SPEC => {}
            CONTENT_APPLICATION_DATA => template.flight.push(length),
            _ => break,
        }
    }
    if template.flight.is_empty() {
        return Err(MousalityError::Malformed);
    }
    Ok(template)
}

fn record_length(header: [u8; RECORD_HEADER_LEN]) -> Result<usize, MousalityError> {
    let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
    if length > MAX_CIPHERTEXT_LEN {
        return Err(MousalityError::Malformed);
    }
    Ok(length)
}

fn parse_server_hello(message: &[u8]) -> Result<ServerTemplate, MousalityError> {
    let mut reader = Reader::new(message);
    if reader.u8()? != HANDSHAKE_SERVER_HELLO {
        return Err(MousalityError::Malformed);
    }
    let length = reader.u24()?;
    let mut body = Reader::new(reader.take(length)?);
    let _version = body.u16()?;
    let _random = body.take(32)?;
    let _session_id = body.vec8()?;
    let cipher_suite = body.u16()?;
    let _compression = body.u8()?;
    let mut extensions = Reader::new(body.vec16()?);
    let (mut group, mut tls13, mut key_share_first, mut seen_versions) =
        (None, false, false, false);
    while !extensions.is_empty() {
        let kind = extensions.u16()?;
        let data = extensions.vec16()?;
        match kind {
            EXTENSION_SUPPORTED_VERSIONS => {
                seen_versions = true;
                tls13 = Reader::new(data).u16()? == TLS_1_3;
            }
            EXTENSION_KEY_SHARE => {
                key_share_first = !seen_versions;
                group = Some(Reader::new(data).u16()?);
            }
            _ => {}
        }
    }
    let group = group.filter(|_| tls13).ok_or(MousalityError::Malformed)?;
    Ok(ServerTemplate {
        cipher_suite,
        group,
        key_share_first,
        flight: Vec::new(),
    })
}
