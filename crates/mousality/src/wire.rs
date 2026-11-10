//! TLS byte-level helpers shared by the hello, record and handshake code.

use crate::MousalityError;

pub(crate) const CONTENT_CHANGE_CIPHER_SPEC: u8 = 0x14;
pub(crate) const CONTENT_ALERT: u8 = 0x15;
pub(crate) const CONTENT_HANDSHAKE: u8 = 0x16;
pub(crate) const CONTENT_APPLICATION_DATA: u8 = 0x17;

pub(crate) const RECORD_HEADER_LEN: usize = 5;
/// RFC 8446 §5.1: a plaintext record carries at most 2^14 bytes.
pub(crate) const MAX_PLAINTEXT_LEN: usize = 16_384;
/// RFC 8446 §5.2: a protected record carries at most 2^14 + 256 bytes.
pub(crate) const MAX_CIPHERTEXT_LEN: usize = MAX_PLAINTEXT_LEN + 256;

pub(crate) const HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
pub(crate) const HANDSHAKE_SERVER_HELLO: u8 = 0x02;

pub(crate) const TLS_1_2: u16 = 0x0303;
pub(crate) const TLS_1_3: u16 = 0x0304;

pub(crate) const GROUP_X25519: u16 = 0x001d;
pub(crate) const GROUP_X25519_MLKEM768: u16 = 0x11ec;

pub(crate) const EXTENSION_SERVER_NAME: u16 = 0x0000;
pub(crate) const EXTENSION_SUPPORTED_VERSIONS: u16 = 0x002b;
pub(crate) const EXTENSION_KEY_SHARE: u16 = 0x0033;

pub(crate) const X25519_LEN: usize = 32;
pub(crate) const MLKEM768_ENCAPSULATION_KEY_LEN: usize = 1_184;
pub(crate) const MLKEM768_CIPHERTEXT_LEN: usize = 1_088;

/// A bounds-checked cursor over TLS structures.
pub(crate) struct Reader<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    pub(crate) const fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }

    pub(crate) const fn is_empty(&self) -> bool {
        self.position >= self.data.len()
    }

    pub(crate) fn take(&mut self, length: usize) -> Result<&'a [u8], MousalityError> {
        let end = self
            .position
            .checked_add(length)
            .filter(|end| *end <= self.data.len())
            .ok_or(MousalityError::Malformed)?;
        let slice = &self.data[self.position..end];
        self.position = end;
        Ok(slice)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, MousalityError> {
        Ok(self.take(1)?[0])
    }

    pub(crate) fn u16(&mut self) -> Result<u16, MousalityError> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    pub(crate) fn u24(&mut self) -> Result<usize, MousalityError> {
        let bytes = self.take(3)?;
        Ok(usize::from(bytes[0]) << 16 | usize::from(bytes[1]) << 8 | usize::from(bytes[2]))
    }

    pub(crate) fn vec8(&mut self) -> Result<&'a [u8], MousalityError> {
        let length = usize::from(self.u8()?);
        self.take(length)
    }

    pub(crate) fn vec16(&mut self) -> Result<&'a [u8], MousalityError> {
        let length = usize::from(self.u16()?);
        self.take(length)
    }
}

pub(crate) fn push_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_be_bytes());
}

/// Appends `body` behind a big-endian length of `width` bytes.
pub(crate) fn push_vec(output: &mut Vec<u8>, width: usize, body: &[u8]) {
    let length = body.len().to_be_bytes();
    output.extend_from_slice(&length[length.len() - width..]);
    output.extend_from_slice(body);
}

/// Appends one extension: type, then its body as a 16-bit vector.
pub(crate) fn push_extension(output: &mut Vec<u8>, kind: u16, body: &[u8]) {
    push_u16(output, kind);
    push_vec(output, 2, body);
}

/// Wraps a handshake body into a handshake message with its 24-bit length.
pub(crate) fn handshake_message(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(4 + body.len());
    message.push(kind);
    push_vec(&mut message, 3, body);
    message
}

pub(crate) fn record_header(content: u8, version: u16, length: usize) -> [u8; RECORD_HEADER_LEN] {
    let [version_high, version_low] = version.to_be_bytes();
    let length = u16::try_from(length).unwrap_or(u16::MAX).to_be_bytes();
    [content, version_high, version_low, length[0], length[1]]
}

pub(crate) fn random_bytes<const N: usize>() -> Result<[u8; N], MousalityError> {
    let mut bytes = [0_u8; N];
    getrandom::fill(&mut bytes).map_err(|_| MousalityError::Random)?;
    Ok(bytes)
}
