#![doc = "Native Windows interface, address and route configuration."]

use std::{
    ffi::c_void,
    mem,
    net::{Ipv4Addr, Ipv6Addr},
    ptr, thread,
    time::{Duration, Instant},
};

use windows_sys::Win32::{
    NetworkManagement::{
        IpHelper::{
            ConvertInterfaceAliasToLuid, ConvertInterfaceLuidToAlias, ConvertInterfaceLuidToIndex,
            CreateIpForwardEntry2,
            CreateUnicastIpAddressEntry, DeleteIpForwardEntry2, DeleteUnicastIpAddressEntry,
            FreeMibTable, GetBestRoute2, GetIpForwardTable2, GetIpInterfaceEntry,
            GetUnicastIpAddressTable, InitializeIpForwardEntry, InitializeUnicastIpAddressEntry,
            SetIpInterfaceEntry, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2, MIB_IPINTERFACE_ROW,
            MIB_UNICASTIPADDRESS_ROW, MIB_UNICASTIPADDRESS_TABLE,
        },
        Ndis::NET_LUID_LH,
    },
    Networking::WinSock::{
        IpDadStatePreferred, AF_INET, AF_INET6, IN6_ADDR, IN6_ADDR_0, IN_ADDR, IN_ADDR_0,
        MIB_IPPROTO_NETMGMT, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_IN6_0, SOCKADDR_INET,
    },
};

use crate::ClientError;

const ERROR_SUCCESS: u32 = 0;
const ERROR_FILE_NOT_FOUND: u32 = 2;
const ERROR_NOT_FOUND: u32 = 1168;
const ERROR_OBJECT_ALREADY_EXISTS: u32 = 5010;

/// How long to let Windows attach IPv4 to a newly created tunnel interface.
const INTERFACE_READY_TIMEOUT: Duration = Duration::from_secs(5);
const INTERFACE_READY_POLL: Duration = Duration::from_millis(25);

/// Reports whether a delete already had nothing to delete.
const fn already_gone(status: u32) -> bool {
    status == ERROR_NOT_FOUND || status == ERROR_FILE_NOT_FOUND
}

/// Route metric shared by every route `MouseVPN` installs, so cleanup can
/// recognise its own routes without consulting a journal.
pub(crate) const ROUTE_METRIC: u32 = 4242;
/// Interface metric for the tunnel. It has to beat every physical interface so
/// the two half-default routes win against the physical default route.
const TUNNEL_INTERFACE_METRIC: u32 = 1;

/// The physical addresses the split-tunnel WFP callouts bind excluded
/// applications to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PhysicalAddresses {
    pub(crate) ipv4: Ipv4Addr,
    pub(crate) ipv6: Option<Ipv6Addr>,
}

/// The physical IPv4 default route the tunnel endpoint has to keep using.
#[derive(Clone, Copy)]
pub(crate) struct DefaultRoute {
    pub(crate) interface_luid: NET_LUID_LH,
    pub(crate) interface_index: u32,
    pub(crate) next_hop: Ipv4Addr,
}

/// One IPv4 route `MouseVPN` owns, for verification and cleanup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OwnedRoute {
    pub(crate) destination: Ipv4Addr,
    pub(crate) prefix_len: u8,
    pub(crate) interface_index: u32,
    pub(crate) next_hop: Ipv4Addr,
}

/// Resolves an interface alias to its LUID.
///
/// # Errors
///
/// Returns an error when Windows has no interface with that alias.
pub(crate) fn interface_luid(alias: &str) -> Result<NET_LUID_LH, ClientError> {
    let alias = alias
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut luid: NET_LUID_LH = unsafe { mem::zeroed() };
    let status = unsafe { ConvertInterfaceAliasToLuid(alias.as_ptr(), &raw mut luid) };
    if status == ERROR_SUCCESS {
        Ok(luid)
    } else {
        Err(win32_error("resolve the MouseVPN interface", status))
    }
}

/// Reports whether an interface with this alias currently exists.
pub(crate) fn interface_exists(alias: &str) -> bool {
    interface_luid(alias).is_ok()
}

/// Resolves a LUID to the interface index Windows uses in route entries.
///
/// # Errors
///
/// Returns an error when the interface has disappeared.
pub(crate) fn interface_index(luid: NET_LUID_LH) -> Result<u32, ClientError> {
    let mut index = 0_u32;
    let status = unsafe { ConvertInterfaceLuidToIndex(&raw const luid, &raw mut index) };
    if status == ERROR_SUCCESS {
        Ok(index)
    } else {
        Err(win32_error("resolve the MouseVPN interface index", status))
    }
}

unsafe fn owned_route(row: &MIB_IPFORWARD_ROW2) -> OwnedRoute {
    OwnedRoute {
        destination: unsafe { ipv4_from_sockaddr(&row.DestinationPrefix.Prefix) },
        prefix_len: row.DestinationPrefix.PrefixLength,
        interface_index: row.InterfaceIndex,
        next_hop: unsafe { ipv4_from_sockaddr(&row.NextHop) },
    }
}

unsafe fn forward_rows<'table>(table: *const MIB_IPFORWARD_TABLE2) -> &'table [MIB_IPFORWARD_ROW2] {
    if table.is_null() {
        return &[];
    }
    unsafe {
        std::slice::from_raw_parts(
            (*table).Table.as_ptr(),
            usize::try_from((*table).NumEntries).unwrap_or(0),
        )
    }
}

unsafe fn unicast_rows<'table>(
    table: *const MIB_UNICASTIPADDRESS_TABLE,
) -> &'table [MIB_UNICASTIPADDRESS_ROW] {
    if table.is_null() {
        return &[];
    }
    unsafe {
        std::slice::from_raw_parts(
            (*table).Table.as_ptr(),
            usize::try_from((*table).NumEntries).unwrap_or(0),
        )
    }
}

fn luid_value(luid: NET_LUID_LH) -> u64 {
    unsafe { luid.Value }
}

fn same_luid(left: NET_LUID_LH, right: NET_LUID_LH) -> bool {
    luid_value(left) == luid_value(right)
}

fn sockaddr_v4(address: Ipv4Addr) -> SOCKADDR_INET {
    let mut value: SOCKADDR_INET = unsafe { mem::zeroed() };
    value.Ipv4 = SOCKADDR_IN {
        sin_family: AF_INET,
        sin_port: 0,
        sin_addr: IN_ADDR {
            S_un: IN_ADDR_0 {
                S_addr: u32::from_ne_bytes(address.octets()),
            },
        },
        sin_zero: [0; 8],
    };
    value
}

fn sockaddr_v6(address: Ipv6Addr) -> SOCKADDR_INET {
    let mut value: SOCKADDR_INET = unsafe { mem::zeroed() };
    value.Ipv6 = SOCKADDR_IN6 {
        sin6_family: AF_INET6,
        sin6_port: 0,
        sin6_flowinfo: 0,
        sin6_addr: IN6_ADDR {
            u: IN6_ADDR_0 {
                Byte: address.octets(),
            },
        },
        Anonymous: SOCKADDR_IN6_0 { sin6_scope_id: 0 },
    };
    value
}

unsafe fn ipv4_from_sockaddr(value: &SOCKADDR_INET) -> Ipv4Addr {
    Ipv4Addr::from(unsafe { value.Ipv4.sin_addr.S_un.S_addr }.to_ne_bytes())
}

unsafe fn ipv6_from_sockaddr(value: &SOCKADDR_INET) -> Ipv6Addr {
    Ipv6Addr::from(unsafe { value.Ipv6.sin6_addr.u.Byte })
}

fn win32_error(operation: &str, code: u32) -> ClientError {
    ClientError::Platform(format!("failed to {operation}: Windows error {code}"))
}

#[cfg(test)]
mod tests {
    use super::{ipv4_from_sockaddr, ipv6_from_sockaddr, is_link_local_v6, sockaddr_v4, sockaddr_v6};
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn round_trips_an_ipv4_sockaddr() {
        let address = Ipv4Addr::new(10, 8, 0, 7);
        assert_eq!(unsafe { ipv4_from_sockaddr(&sockaddr_v4(address)) }, address);
    }

    #[test]
    fn round_trips_an_ipv6_sockaddr() {
        let address: Ipv6Addr = "2001:db8::1".parse().expect("address");
        assert_eq!(unsafe { ipv6_from_sockaddr(&sockaddr_v6(address)) }, address);
    }

    #[test]
    fn recognizes_link_local_ipv6_addresses() {
        assert!(is_link_local_v6("fe80::1".parse().expect("address")));
        assert!(!is_link_local_v6("2001:db8::1".parse().expect("address")));
    }
}
