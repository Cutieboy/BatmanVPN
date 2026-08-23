#![doc = "Dynamic bindings to the vendored WinDivert 2.2 user-mode library."]

pub(crate) mod flow;
pub(crate) mod packet;

use std::{
    ffi::CString,
    os::windows::ffi::OsStrExt,
    path::{Path, PathBuf},
    ptr,
    sync::Arc,
};

use windows_sys::Win32::{
    Foundation::{HANDLE, INVALID_HANDLE_VALUE},
    System::LibraryLoader::{GetProcAddress, LoadLibraryW},
};

use crate::ClientError;

/// Layer identifiers from `WINDIVERT_LAYER`.
pub(crate) const LAYER_NETWORK: u32 = 0;
pub(crate) const LAYER_FLOW: u32 = 2;

/// Event identifiers from `WINDIVERT_EVENT`.
pub(crate) const EVENT_FLOW_ESTABLISHED: u32 = 1;
pub(crate) const EVENT_FLOW_DELETED: u32 = 2;

/// Handle flags from `WINDIVERT_FLAG_*`.
pub(crate) const FLAG_SNIFF: u64 = 0x0001;
pub(crate) const FLAG_RECV_ONLY: u64 = 0x0004;

/// `WINDIVERT_SHUTDOWN_BOTH`.
const SHUTDOWN_BOTH: u32 = 0x3;

/// The largest packet WinDivert will hand back, from `WINDIVERT_MTU_MAX`.
pub(crate) const MTU_MAX: usize = 40 + 0xFFFF;

type OpenFn = unsafe extern "system" fn(*const i8, u32, i16, u64) -> HANDLE;
type RecvFn = unsafe extern "system" fn(HANDLE, *mut u8, u32, *mut u32, *mut Address) -> i32;
type SendFn = unsafe extern "system" fn(HANDLE, *const u8, u32, *mut u32, *const Address) -> i32;
type ShutdownFn = unsafe extern "system" fn(HANDLE, u32) -> i32;
type CloseFn = unsafe extern "system" fn(HANDLE) -> i32;
type CalcChecksumsFn = unsafe extern "system" fn(*mut u8, u32, *mut Address, u64) -> i32;

/// A WinDivert address, mirroring `WINDIVERT_ADDRESS`.
///
/// The C definition packs `Layer`, `Event` and eight one-bit properties into a
/// single `UINT32` bitfield. Rust has no bitfields, so the word is stored raw
/// and read through the accessors below. MSVC allocates bitfields from the
/// least significant bit upwards, which is what the shifts assume.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct Address {
    pub(crate) timestamp: i64,
    bitfield: u32,
    _reserved: u32,
    /// The `WINDIVERT_DATA_*` union. Read it with [`Address::flow`] or
    /// [`Address::network`], which check the layer first.
    payload: [u8; 64],
}

/// `WINDIVERT_DATA_FLOW`.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct FlowData {
    pub(crate) endpoint_id: u64,
    pub(crate) parent_endpoint_id: u64,
    pub(crate) process_id: u32,
    pub(crate) local_addr: [u32; 4],
    pub(crate) remote_addr: [u32; 4],
    pub(crate) local_port: u16,
    pub(crate) remote_port: u16,
    pub(crate) protocol: u8,
}

/// `WINDIVERT_DATA_NETWORK`.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct NetworkData {
    pub(crate) if_idx: u32,
    pub(crate) sub_if_idx: u32,
}

impl Address {
    pub(crate) const fn zeroed() -> Self {
        Self {
            timestamp: 0,
            bitfield: 0,
            _reserved: 0,
            payload: [0; 64],
        }
    }

    pub(crate) const fn layer(&self) -> u32 {
        self.bitfield & 0xFF
    }

    pub(crate) const fn event(&self) -> u32 {
        (self.bitfield >> 8) & 0xFF
    }

    pub(crate) const fn outbound(&self) -> bool {
        (self.bitfield >> 17) & 1 == 1
    }

    pub(crate) const fn loopback(&self) -> bool {
        (self.bitfield >> 18) & 1 == 1
    }

    pub(crate) const fn ipv6(&self) -> bool {
        (self.bitfield >> 20) & 1 == 1
    }

    /// Reinterprets the union as flow data.
    ///
    /// Returns `None` unless the address came from the flow layer, so a
    /// mismatched layer cannot be read as the wrong union member.
    pub(crate) fn flow(&self) -> Option<FlowData> {
        (self.layer() == LAYER_FLOW).then(|| {
            // SAFETY: `FlowData` is 64 bytes of plain integers with no
            // padding requirements beyond 8-byte alignment, `payload` is 64
            // bytes inside a structure aligned to 8, and the layer check above
            // establishes that WinDivert wrote this union member.
            unsafe { ptr::read_unaligned(self.payload.as_ptr().cast::<FlowData>()) }
        })
    }

    /// Reinterprets the union as network data.
    pub(crate) fn network(&self) -> Option<NetworkData> {
        (self.layer() == LAYER_NETWORK).then(|| {
            // SAFETY: as above, for the two-`u32` network member.
            unsafe { ptr::read_unaligned(self.payload.as_ptr().cast::<NetworkData>()) }
        })
    }
}

/// The loaded `WinDivert.dll` and the entry points MouseVPN uses.
///
/// The library is resolved next to the running executable rather than embedded
/// and extracted like `wintun.dll`. WinDivert is used under the LGPL, which
/// requires that a user be able to drop in their own build; a copy rewritten
/// from the executable on every launch would defeat that. It also lets
/// `WinDivert.dll` find `WinDivert64.sys` beside itself, which is how it
/// installs and removes the driver service on its own.
pub(crate) struct Library {
    // Kept as a `usize` so the library stays `Send`: handles are shared with
    // the flow watcher and packet threads.
    _module: usize,
    open: OpenFn,
    recv: RecvFn,
    send: SendFn,
    shutdown: ShutdownFn,
    close: CloseFn,
    calc_checksums: CalcChecksumsFn,
}

// SAFETY: the module handle is only held to keep the DLL loaded, and every
// entry point is a plain function pointer into it. WinDivert's own handles
// carry the per-handle state and are documented as usable from any thread.
unsafe impl Send for Library {}
unsafe impl Sync for Library {}

impl Library {
    /// Loads `WinDivert.dll` from the directory holding the current executable.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Platform`] when the DLL is missing, cannot be
    /// loaded, or does not export the expected WinDivert 2.2 entry points.
    pub(crate) fn load() -> Result<Arc<Self>, ClientError> {
        let path = library_path()?;
        let wide = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        // SAFETY: `wide` is a NUL-terminated UTF-16 path that outlives the call.
        let module = unsafe { LoadLibraryW(wide.as_ptr()) };
        if module.is_null() {
            return Err(ClientError::Platform(format!(
                "failed to load {}: {}",
                path.display(),
                std::io::Error::last_os_error()
            )));
        }
        let module_address = module as usize;

        // SAFETY: each name is a NUL-terminated literal, and the signatures
        // match `windivert.h` for the version pinned in `vendor/windivert`.
        // `resolve` fails rather than returning a null pointer, so no
        // transmute below can produce a dangling function.
        let library = unsafe {
            Self {
                _module: module_address,
                open: std::mem::transmute::<*const (), OpenFn>(resolve(module, c"WinDivertOpen")?),
                recv: std::mem::transmute::<*const (), RecvFn>(resolve(module, c"WinDivertRecv")?),
                send: std::mem::transmute::<*const (), SendFn>(resolve(module, c"WinDivertSend")?),
                shutdown: std::mem::transmute::<*const (), ShutdownFn>(resolve(
                    module,
                    c"WinDivertShutdown",
                )?),
                close: std::mem::transmute::<*const (), CloseFn>(resolve(
                    module,
                    c"WinDivertClose",
                )?),
                calc_checksums: std::mem::transmute::<*const (), CalcChecksumsFn>(resolve(
                    module,
                    c"WinDivertHelperCalcChecksums",
                )?),
            }
        };
        Ok(Arc::new(library))
    }

    /// Opens a WinDivert handle for `filter` on `layer`.
    ///
    /// Opening a handle is what installs and starts the driver service, so the
    /// first call on a machine is also the one that surfaces a missing or
    /// unloadable `WinDivert64.sys`.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Platform`] when the filter is rejected or the
    /// driver cannot be started. `ERROR_ACCESS_DENIED` means the process is
    /// not elevated; `ERROR_INVALID_IMAGE_HASH` means the driver's signature
    /// was refused.
    pub(crate) fn open(
        self: &Arc<Self>,
        filter: &str,
        layer: u32,
        priority: i16,
        flags: u64,
    ) -> Result<Handle, ClientError> {
        let filter = CString::new(filter).map_err(|_| {
            ClientError::Platform("WinDivert filter contained an interior NUL".to_owned())
        })?;
        // SAFETY: `filter` is NUL-terminated and outlives the call; WinDivert
        // copies the compiled filter into the driver before returning.
        let handle = unsafe { (self.open)(filter.as_ptr(), layer, priority, flags) };
        if handle == INVALID_HANDLE_VALUE {
            return Err(open_error(&std::io::Error::last_os_error()));
        }
        Ok(Handle {
            library: Arc::clone(self),
            handle: handle as usize,
        })
    }
}

/// An open WinDivert handle.
///
/// Dropping the handle closes it, which is also what lets WinDivert stop the
/// driver service once the last handle in the system goes away. A helper that
/// crashes therefore cannot leave the machine diverting packets to nowhere.
pub(crate) struct Handle {
    library: Arc<Library>,
    handle: usize,
}

// SAFETY: WinDivert handles are ordinary kernel handles and are documented as
// safe to use concurrently; the packet threads rely on that.
unsafe impl Send for Handle {}
unsafe impl Sync for Handle {}

impl Handle {
    /// Receives one packet or event.
    ///
    /// Returns the number of bytes written into `packet`, which is zero for the
    /// event layers such as flow. A shut-down handle reports `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Platform`] when the receive fails for any reason
    /// other than the handle being shut down.
    pub(crate) fn recv(
        &self,
        packet: &mut [u8],
        address: &mut Address,
    ) -> Result<Option<usize>, ClientError> {
        const ERROR_NO_DATA: i32 = 232;
        let capacity = u32::try_from(packet.len()).unwrap_or(u32::MAX);
        let mut received = 0_u32;
        // SAFETY: the buffer and address outlive the call and `capacity` never
        // exceeds the buffer length.
        let ok = unsafe {
            (self.library.recv)(
                self.handle as HANDLE,
                packet.as_mut_ptr(),
                capacity,
                &raw mut received,
                address,
            )
        };
        if ok != 0 {
            return Ok(Some(received as usize));
        }
        let error = std::io::Error::last_os_error();
        // A shutdown drains the queue and then reports no more data. That is
        // an orderly stop, not a failure.
        if error.raw_os_error() == Some(ERROR_NO_DATA) {
            return Ok(None);
        }
        Err(ClientError::Platform(format!(
            "WinDivert receive failed: {error}"
        )))
    }

    /// Injects `packet` back into the network stack.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Platform`] when the injection is rejected.
    pub(crate) fn send(&self, packet: &[u8], address: &Address) -> Result<usize, ClientError> {
        let length = u32::try_from(packet.len()).map_err(|_| {
            ClientError::Platform("packet is too large for WinDivert".to_owned())
        })?;
        let mut sent = 0_u32;
        // SAFETY: the packet and address outlive the call.
        let ok = unsafe {
            (self.library.send)(
                self.handle as HANDLE,
                packet.as_ptr(),
                length,
                &raw mut sent,
                address,
            )
        };
        if ok == 0 {
            return Err(ClientError::Platform(format!(
                "WinDivert injection failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(sent as usize)
    }

    /// Recomputes whichever checksums a rewritten packet invalidated.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Platform`] when WinDivert cannot parse the packet.
    pub(crate) fn calc_checksums(
        &self,
        packet: &mut [u8],
        address: &mut Address,
    ) -> Result<(), ClientError> {
        let length = u32::try_from(packet.len()).unwrap_or(u32::MAX);
        // SAFETY: the packet and address outlive the call; a zero flag word
        // asks for every checksum the packet actually carries.
        let ok = unsafe { (self.library.calc_checksums)(packet.as_mut_ptr(), length, address, 0) };
        if ok == 0 {
            return Err(ClientError::Platform(format!(
                "WinDivert could not recompute checksums: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    /// Unblocks a thread parked in [`Handle::recv`].
    ///
    /// This is the only safe way to stop a receive loop: closing the handle
    /// from another thread while a receive is in flight is a use-after-free.
    pub(crate) fn shutdown(&self) {
        // SAFETY: the handle stays valid until `Drop`, which cannot run while
        // a caller still holds a reference.
        unsafe {
            (self.library.shutdown)(self.handle as HANDLE, SHUTDOWN_BOTH);
        }
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: the handle was produced by `WinDivertOpen` and is closed
        // exactly once.
        unsafe {
            (self.library.close)(self.handle as HANDLE);
        }
    }
}

/// Resolves one export, failing when the DLL predates the pinned version.
unsafe fn resolve(
    module: windows_sys::Win32::Foundation::HMODULE,
    name: &std::ffi::CStr,
) -> Result<*const (), ClientError> {
    // SAFETY: `name` is NUL-terminated and `module` came from `LoadLibraryW`.
    let symbol = unsafe { GetProcAddress(module, name.as_ptr().cast()) };
    symbol.map(|address| address as *const ()).ok_or_else(|| {
        ClientError::Platform(format!(
            "WinDivert.dll does not export {}; expected the vendored 2.2 build",
            name.to_string_lossy()
        ))
    })
}

/// Locates `WinDivert.dll` beside the running executable.
fn library_path() -> Result<PathBuf, ClientError> {
    let executable = std::env::current_exe().map_err(|error| {
        ClientError::Platform(format!("failed to locate the MouseVPN executable: {error}"))
    })?;
    let directory = executable.parent().ok_or_else(|| {
        ClientError::Platform("the MouseVPN executable has no parent directory".to_owned())
    })?;
    let path = directory.join("WinDivert.dll");
    if !path.is_file() {
        return Err(missing_library(directory));
    }
    // The DLL installs the driver from its own directory, so a present DLL
    // with no .sys beside it fails later, inside WinDivertOpen, with a much
    // less obvious error.
    if !directory.join("WinDivert64.sys").is_file() {
        return Err(ClientError::Platform(format!(
            "WinDivert64.sys is missing from {}; the split tunnel driver cannot start",
            directory.display()
        )));
    }
    Ok(path)
}

fn missing_library(directory: &Path) -> ClientError {
    ClientError::Platform(format!(
        "WinDivert.dll is missing from {}; reinstall MouseVPN to restore it",
        directory.display()
    ))
}

/// Turns the documented `WinDivertOpen` failures into actionable messages.
fn open_error(error: &std::io::Error) -> ClientError {
    const ERROR_ACCESS_DENIED: i32 = 5;
    const ERROR_INVALID_IMAGE_HASH: i32 = 577;
    const ERROR_DRIVER_BLOCKED: i32 = 1275;
    let message = match error.raw_os_error() {
        Some(ERROR_ACCESS_DENIED) => {
            "MouseVPN must be started as Administrator to open WinDivert".to_owned()
        }
        Some(ERROR_INVALID_IMAGE_HASH) => {
            "Windows refused the WinDivert driver signature; the vendored WinDivert64.sys is \
             damaged or was replaced"
                .to_owned()
        }
        Some(ERROR_DRIVER_BLOCKED) => {
            "Windows blocked the WinDivert driver, usually via the vulnerable driver blocklist \
             or a security policy"
                .to_owned()
        }
        _ => format!("failed to open a WinDivert handle: {error}"),
    };
    ClientError::Platform(message)
}

#[cfg(test)]
mod tests {
    use super::{Address, FlowData, EVENT_FLOW_ESTABLISHED, LAYER_FLOW, LAYER_NETWORK};

    #[test]
    fn address_matches_the_windivert_abi() {
        // WINDIVERT_ADDRESS is a 64-bit timestamp, one packed word, one
        // reserved word and a 64-byte union.
        assert_eq!(size_of::<Address>(), 80);
        assert_eq!(align_of::<Address>(), 8);
        // WINDIVERT_DATA_FLOW has to fit the union it shares.
        assert!(size_of::<FlowData>() <= 64);
    }

    #[test]
    fn decodes_the_packed_layer_and_event_word() {
        let mut address = Address::zeroed();
        // Layer occupies the low byte, Event the next, and Outbound is bit 17.
        address.bitfield = LAYER_FLOW | (EVENT_FLOW_ESTABLISHED << 8) | (1 << 17);
        assert_eq!(address.layer(), LAYER_FLOW);
        assert_eq!(address.event(), EVENT_FLOW_ESTABLISHED);
        assert!(address.outbound());
        assert!(!address.ipv6());
        assert!(address.network().is_none());
        assert!(address.flow().is_some());
    }

    #[test]
    fn reads_the_union_only_for_the_matching_layer() {
        let mut address = Address::zeroed();
        address.bitfield = LAYER_NETWORK;
        assert!(address.flow().is_none());
        assert!(address.network().is_some());
    }
}
