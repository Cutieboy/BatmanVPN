use std::{
    ffi::c_void,
    ptr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use windows_sys::Win32::{
    Foundation::{HANDLE, WIN32_ERROR},
    NetworkManagement::IpHelper::{
        CancelMibChangeNotify2, ConvertInterfaceLuidToIndex, NotifyUnicastIpAddressChange,
        MIB_NOTIFICATION_TYPE, MIB_UNICASTIPADDRESS_ROW,
    },
    Networking::WinSock::AF_UNSPEC,
    System::Power::{
        PowerRegisterSuspendResumeNotification, PowerUnregisterSuspendResumeNotification,
        DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS,
    },
    UI::WindowsAndMessaging::{DEVICE_NOTIFY_CALLBACK, PBT_APMRESUMEAUTOMATIC},
};
use wintun::Adapter;

use crate::ClientError;

const DEBOUNCE: Duration = Duration::from_millis(400);
const ERROR_SUCCESS: WIN32_ERROR = 0;

struct EventContext {
    reconnect_requested: Arc<AtomicBool>,
    tunnel_index: u32,
    last_request: Mutex<Option<Instant>>,
}

impl EventContext {
    fn request_reconnect(&self) {
        let Ok(mut last) = self.last_request.lock() else {
            return;
        };
        let now = Instant::now();
        if last.is_none_or(|previous| now.duration_since(previous) >= DEBOUNCE) {
            *last = Some(now);
            self.reconnect_requested.store(true, Ordering::Release);
        }
    }
}

pub(crate) struct NetworkEventGuard {
    address_handle: HANDLE,
    power_handle: isize,
    _context: Box<EventContext>,
}

impl NetworkEventGuard {
    pub(crate) fn subscribe(
        adapter: &Adapter,
        reconnect_requested: Arc<AtomicBool>,
    ) -> Result<Self, ClientError> {
        let mut tunnel_index = 0_u32;
        let luid = adapter.get_luid();
        let result =
            unsafe { ConvertInterfaceLuidToIndex((&raw const luid).cast(), &raw mut tunnel_index) };
        if result != ERROR_SUCCESS {
            return Err(win32_error("resolve the Wintun interface index", result));
        }

        let context = Box::new(EventContext {
            reconnect_requested,
            tunnel_index,
            last_request: Mutex::new(None),
        });
        let context_ptr = (&raw const *context).cast::<c_void>();
        let mut address_handle = ptr::null_mut();
        let result = unsafe {
            NotifyUnicastIpAddressChange(
                AF_UNSPEC,
                Some(address_changed),
                context_ptr,
                false,
                &raw mut address_handle,
            )
        };
        if result != ERROR_SUCCESS {
            return Err(win32_error("subscribe to Windows address changes", result));
        }

        let parameters = DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS {
            Callback: Some(power_changed),
            Context: context_ptr.cast_mut(),
        };
        let mut power_handle = ptr::null_mut();
        let result = unsafe {
            PowerRegisterSuspendResumeNotification(
                DEVICE_NOTIFY_CALLBACK,
                (&raw const parameters).cast_mut().cast(),
                &raw mut power_handle,
            )
        };
        if result != ERROR_SUCCESS {
            unsafe { CancelMibChangeNotify2(address_handle) };
            return Err(win32_error("subscribe to Windows resume events", result));
        }

        Ok(Self {
            address_handle,
            power_handle: power_handle as isize,
            _context: context,
        })
    }
}

unsafe extern "system" fn address_changed(
    context: *const c_void,
    row: *const MIB_UNICASTIPADDRESS_ROW,
    _notification: MIB_NOTIFICATION_TYPE,
) {
    if context.is_null() || row.is_null() {
        return;
    }
    let context = unsafe { &*context.cast::<EventContext>() };
    if unsafe { (*row).InterfaceIndex } != context.tunnel_index {
        context.request_reconnect();
    }
}

unsafe extern "system" fn power_changed(
    context: *const c_void,
    event: u32,
    _setting: *const c_void,
) -> u32 {
    if event == PBT_APMRESUMEAUTOMATIC && !context.is_null() {
        unsafe { &*context.cast::<EventContext>() }.request_reconnect();
    }
    ERROR_SUCCESS
}

impl Drop for NetworkEventGuard {
    fn drop(&mut self) {
        unsafe {
            CancelMibChangeNotify2(self.address_handle);
            PowerUnregisterSuspendResumeNotification(self.power_handle);
        }
    }
}

fn win32_error(operation: &str, code: WIN32_ERROR) -> ClientError {
    ClientError::Platform(format!("failed to {operation}: Windows error {code}"))
}
