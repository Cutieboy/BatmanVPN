use std::{
    ffi::{c_char, CStr, CString},
    panic::{catch_unwind, AssertUnwindSafe},
    ptr, slice,
    time::Duration,
};

use crate::{session::MAX_PACKET_BATCH, AppleClientError, AppleSession};

const MAX_FRAMED_PACKET: usize = 65_535;

#[repr(C)]
pub struct MvOwnedBytes {
    data: *mut u8,
    len: usize,
    capacity: usize,
}

impl MvOwnedBytes {
    const fn empty() -> Self {
        Self {
            data: ptr::null_mut(),
            len: 0,
            capacity: 0,
        }
    }

    fn from_vec(mut value: Vec<u8>) -> Self {
        let result = Self {
            data: value.as_mut_ptr(),
            len: value.len(),
            capacity: value.capacity(),
        };
        std::mem::forget(value);
        result
    }
}

#[repr(C)]
pub struct MvError {
    message: *mut c_char,
}

#[no_mangle]
pub extern "C" fn mousevpn_apple_connect(
    endpoint: *const c_char,
    server_public_key: *const c_char,
    client_private_key: *const c_char,
    parameters_json: *mut MvOwnedBytes,
    error: *mut MvError,
) -> *mut AppleSession {
    ffi_pointer(error, || {
        let endpoint = unsafe { required_string(endpoint, "endpoint") }?;
        let server_public_key = unsafe { required_string(server_public_key, "server public key") }?;
        let client_private_key =
            unsafe { required_string(client_private_key, "client private key") }?;
        let session = Box::new(AppleSession::connect(
            &endpoint,
            server_public_key,
            client_private_key,
        )?);
        let parameters = session.parameters();
        let json = serde_json::to_vec(&serde_json::json!({
            "address": parameters.client_address.to_string(),
            "prefix": parameters.prefix_len,
            "dns": parameters.dns.to_string(),
            "mtu": parameters.mtu,
            "remoteAddress": parameters.remote_address.to_string(),
        }))
        .map_err(|json_error| AppleClientError::new(json_error.to_string()))?;
        unsafe { write_owned_bytes(parameters_json, json)? };
        Ok(Box::into_raw(session))
    })
}

#[no_mangle]
pub extern "C" fn mousevpn_apple_send_packet_batch(
    session: *mut AppleSession,
    framed_packets: *const u8,
    framed_length: usize,
    error: *mut MvError,
) -> bool {
    ffi_bool(error, || {
        let session = unsafe { required_session(session)? };
        let framed = unsafe { required_bytes(framed_packets, framed_length, "packet batch")? };
        let packets = decode_batch(framed)?;
        session.send_packets(&packets)?;
        Ok(())
    })
}

/// Returns 1 for a non-empty batch, 0 for a timeout, and -1 for an error.
#[no_mangle]
pub extern "C" fn mousevpn_apple_receive_packet_batch(
    session: *mut AppleSession,
    timeout_millis: u64,
    maximum_packets: usize,
    framed_packets: *mut MvOwnedBytes,
    error: *mut MvError,
) -> i32 {
    ffi_i32(error, || {
        let session = unsafe { required_session(session)? };
        let batch = session.receive_packets(
            Duration::from_millis(timeout_millis.max(1)),
            maximum_packets,
        )?;
        if batch.packets.is_empty() {
            return Ok(0);
        }
        let framed = encode_batch(&batch.packets)?;
        unsafe { write_owned_bytes(framed_packets, framed)? };
        Ok(1)
    })
}

#[no_mangle]
pub extern "C" fn mousevpn_apple_send_keepalive(
    session: *mut AppleSession,
    error: *mut MvError,
) -> bool {
    ffi_bool(error, || {
        let session = unsafe { required_session(session)? };
        session.send_keepalive()
    })
}

#[no_mangle]
pub extern "C" fn mousevpn_apple_session_free(session: *mut AppleSession) {
    if session.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
        drop(Box::from_raw(session));
    }));
}

#[no_mangle]
pub extern "C" fn mousevpn_apple_bytes_free(bytes: *mut MvOwnedBytes) {
    if bytes.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
        let value = &mut *bytes;
        if !value.data.is_null() {
            drop(Vec::from_raw_parts(value.data, value.len, value.capacity));
        }
        *value = MvOwnedBytes::empty();
    }));
}

#[no_mangle]
pub extern "C" fn mousevpn_apple_error_free(error: *mut MvError) {
    if error.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
        let value = &mut *error;
        if !value.message.is_null() {
            drop(CString::from_raw(value.message));
            value.message = ptr::null_mut();
        }
    }));
}

fn decode_batch(input: &[u8]) -> Result<Vec<&[u8]>, AppleClientError> {
    let mut cursor = 0;
    let count = read_u32(input, &mut cursor)? as usize;
    if !(1..=MAX_PACKET_BATCH).contains(&count) {
        return Err(AppleClientError::new("invalid packet batch count"));
    }
    let mut packets = Vec::with_capacity(count);
    for _ in 0..count {
        let length = read_u32(input, &mut cursor)? as usize;
        if length == 0 || length > MAX_FRAMED_PACKET || input.len() - cursor < length {
            return Err(AppleClientError::new("invalid framed packet length"));
        }
        packets.push(&input[cursor..cursor + length]);
        cursor += length;
    }
    if cursor != input.len() {
        return Err(AppleClientError::new("trailing bytes in packet batch"));
    }
    Ok(packets)
}

fn encode_batch(packets: &[Vec<u8>]) -> Result<Vec<u8>, AppleClientError> {
    let mut output =
        Vec::with_capacity(4 + packets.iter().map(|packet| 4 + packet.len()).sum::<usize>());
    write_u32(&mut output, packets.len())?;
    for packet in packets {
        write_u32(&mut output, packet.len())?;
        output.extend_from_slice(packet);
    }
    Ok(output)
}

fn read_u32(input: &[u8], cursor: &mut usize) -> Result<u32, AppleClientError> {
    let end = cursor.saturating_add(4);
    let bytes: [u8; 4] = input
        .get(*cursor..end)
        .ok_or_else(|| AppleClientError::new("truncated packet batch"))?
        .try_into()
        .map_err(|_| AppleClientError::new("invalid packet batch header"))?;
    *cursor = end;
    Ok(u32::from_be_bytes(bytes))
}

fn write_u32(output: &mut Vec<u8>, value: usize) -> Result<(), AppleClientError> {
    let value =
        u32::try_from(value).map_err(|_| AppleClientError::new("packet batch is too large"))?;
    output.extend_from_slice(&value.to_be_bytes());
    Ok(())
}

unsafe fn required_string(value: *const c_char, name: &str) -> Result<String, AppleClientError> {
    if value.is_null() {
        return Err(AppleClientError::new(format!("missing {name}")));
    }
    unsafe { CStr::from_ptr(value) }
        .to_str()
        .map(str::to_owned)
        .map_err(|_| AppleClientError::new(format!("{name} is not valid UTF-8")))
}

unsafe fn required_bytes<'a>(
    value: *const u8,
    length: usize,
    name: &str,
) -> Result<&'a [u8], AppleClientError> {
    if value.is_null() || length == 0 {
        return Err(AppleClientError::new(format!("missing {name}")));
    }
    Ok(unsafe { slice::from_raw_parts(value, length) })
}

unsafe fn required_session<'a>(
    session: *mut AppleSession,
) -> Result<&'a AppleSession, AppleClientError> {
    unsafe { session.as_ref() }.ok_or_else(|| AppleClientError::new("missing session"))
}

unsafe fn write_owned_bytes(
    output: *mut MvOwnedBytes,
    value: Vec<u8>,
) -> Result<(), AppleClientError> {
    let output =
        unsafe { output.as_mut() }.ok_or_else(|| AppleClientError::new("missing output buffer"))?;
    *output = MvOwnedBytes::from_vec(value);
    Ok(())
}

fn ffi_pointer<F>(error: *mut MvError, operation: F) -> *mut AppleSession
where
    F: FnOnce() -> Result<*mut AppleSession, AppleClientError>,
{
    match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(Ok(value)) => value,
        Ok(Err(failure)) => {
            set_error(error, &failure);
            ptr::null_mut()
        }
        Err(_) => {
            set_error(error, &AppleClientError::new("native panic"));
            ptr::null_mut()
        }
    }
}

fn ffi_bool<F>(error: *mut MvError, operation: F) -> bool
where
    F: FnOnce() -> Result<(), AppleClientError>,
{
    match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(Ok(())) => true,
        Ok(Err(failure)) => {
            set_error(error, &failure);
            false
        }
        Err(_) => {
            set_error(error, &AppleClientError::new("native panic"));
            false
        }
    }
}

fn ffi_i32<F>(error: *mut MvError, operation: F) -> i32
where
    F: FnOnce() -> Result<i32, AppleClientError>,
{
    match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(Ok(value)) => value,
        Ok(Err(failure)) => {
            set_error(error, &failure);
            -1
        }
        Err(_) => {
            set_error(error, &AppleClientError::new("native panic"));
            -1
        }
    }
}

fn set_error(output: *mut MvError, error: &AppleClientError) {
    let Some(output) = (unsafe { output.as_mut() }) else {
        return;
    };
    let message = CString::new(error.to_string())
        .unwrap_or_else(|_| CString::new("native error").expect("static string is valid"));
    output.message = message.into_raw();
}

#[cfg(test)]
mod tests {
    use super::{decode_batch, encode_batch};

    #[test]
    fn packet_batch_round_trips() {
        let packets = vec![vec![0x45, 0, 0, 20], vec![0x45, 1, 2, 3, 4]];
        let encoded = encode_batch(&packets).expect("encode batch");
        let decoded = decode_batch(&encoded).expect("decode batch");
        assert_eq!(decoded, vec![packets[0].as_slice(), packets[1].as_slice()]);
    }

    #[test]
    fn truncated_packet_batch_is_rejected() {
        let input = [0, 0, 0, 1, 0, 0, 0, 10, 0x45];
        assert!(decode_batch(&input).is_err());
    }
}
