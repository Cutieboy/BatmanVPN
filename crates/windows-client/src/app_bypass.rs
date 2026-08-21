use std::{
    ffi::c_void,
    net::{Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
    process::Command,
    ptr,
    sync::{Arc, Mutex},
};

use windows_sys::{
    core::GUID,
    Win32::{
        Foundation::{LocalFree, HANDLE},
        NetworkManagement::WindowsFilteringPlatform::{
            FwpmCalloutAdd0, FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFreeMemory0,
            FwpmGetAppIdFromFileName0, FwpmProviderAdd0, FwpmProviderContextAdd0, FwpmSubLayerAdd0,
            FwpmTransactionAbort0, FwpmTransactionBegin0, FwpmTransactionCommit0, FWPM_ACTION0,
            FWPM_ACTION0_0, FWPM_CALLOUT0, FWPM_CALLOUT_FLAG_USES_PROVIDER_CONTEXT,
            FWPM_CONDITION_ALE_APP_ID, FWPM_CONDITION_ALE_PACKAGE_ID, FWPM_CONDITION_ALE_USER_ID,
            FWPM_CONDITION_IP_LOCAL_ADDRESS, FWPM_DISPLAY_DATA0, FWPM_FILTER0, FWPM_FILTER0_0,
            FWPM_FILTER_CONDITION0, FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT,
            FWPM_FILTER_FLAG_HAS_PROVIDER_CONTEXT, FWPM_GENERAL_CONTEXT,
            FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            FWPM_LAYER_ALE_BIND_REDIRECT_V4, FWPM_LAYER_ALE_BIND_REDIRECT_V6, FWPM_PROVIDER0,
            FWPM_PROVIDER_CONTEXT0, FWPM_PROVIDER_CONTEXT0_0, FWPM_SESSION0,
            FWPM_SESSION_FLAG_DYNAMIC, FWPM_SUBLAYER0, FWP_ACTION_BLOCK,
            FWP_ACTION_CALLOUT_TERMINATING, FWP_ACTION_PERMIT, FWP_ACTRL_MATCH_FILTER,
            FWP_BYTE_BLOB, FWP_BYTE_BLOB_TYPE, FWP_CONDITION_VALUE0, FWP_CONDITION_VALUE0_0,
            FWP_MATCH_EQUAL, FWP_SECURITY_DESCRIPTOR_TYPE, FWP_SID, FWP_V4_ADDR_AND_MASK,
            FWP_V4_ADDR_MASK, FWP_V6_ADDR_AND_MASK, FWP_V6_ADDR_MASK,
        },
        Security::{
            Authorization::{
                BuildExplicitAccessWithNameW, BuildSecurityDescriptorW, ConvertStringSidToSidW,
                EXPLICIT_ACCESS_W, GRANT_ACCESS,
            },
            PSECURITY_DESCRIPTOR, PSID,
        },
        System::Rpc::RPC_C_AUTHN_WINNT,
    },
};

use std::os::windows::process::CommandExt;

use crate::{
    network::{self, PhysicalAddresses},
    AppRoutingMode, AppRoutingPolicy, ClientError,
};

const SERVICE_NAME: &str = "MouseVpnSplitTunnel";
const DRIVER_FILE: &str = "MouseVpnSplitTunnel.sys";
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

const PROVIDER_KEY: GUID = GUID::from_u128(0x8148ae22_9f61_4798_89e5_02107d18808a);
const SUBLAYER_KEY: GUID = GUID::from_u128(0x32733b84_083d_4c21_b0e2_5f9e6500804f);
const BIND_CALLOUT_KEY: GUID = GUID::from_u128(0x02b4a98b_cd65_490d_83c6_0bfb6f10fa95);
const IPV4_CONTEXT_KEY: GUID = GUID::from_u128(0x3762a995_29e1_4507_be82_8f2ee765811c);
const BIND_V6_CALLOUT_KEY: GUID = GUID::from_u128(0xc61160b3_be17_41ef_b7a6_2f669da8cc96);
const IPV6_CONTEXT_KEY: GUID = GUID::from_u128(0xad93e1c7_bdac_472e_9b64_c3e6abbaffdd);

pub(crate) struct AppBypassGuard {
    state: Arc<Mutex<BypassState>>,
}

#[derive(Clone)]
pub(crate) struct AppBypassRefresher {
    state: Arc<Mutex<BypassState>>,
}

struct BypassState {
    engine: usize,
    policy: AppRoutingPolicy,
    physical_addresses: PhysicalAddresses,
}

impl AppBypassGuard {
    pub(crate) fn install(policy: &AppRoutingPolicy) -> Result<Option<Self>, ClientError> {
        if policy.apps.is_empty()
            && policy.package_sids.is_empty()
            && policy.mode == AppRoutingMode::Exclude
        {
            return Ok(None);
        }
        for app in &policy.apps {
            if !app.is_absolute() || !app.is_file() {
                return Err(ClientError::Platform(format!(
                    "excluded Windows application is unavailable: {}",
                    app.display()
                )));
            }
        }

        let driver = driver_path()?;
        ensure_driver_started(&driver)?;
        let physical_addresses = network::physical_addresses()?;
        match open_engine(policy, physical_addresses) {
            Ok(engine) => Ok(Some(Self {
                state: Arc::new(Mutex::new(BypassState {
                    engine: engine as usize,
                    policy: policy.clone(),
                    physical_addresses,
                })),
            })),
            Err(error) => Err(error),
        }
    }

    pub(crate) fn refresher(&self) -> AppBypassRefresher {
        AppBypassRefresher {
            state: Arc::clone(&self.state),
        }
    }
}

impl Drop for AppBypassGuard {
    fn drop(&mut self) {
        if let Ok(mut state) = self.state.lock() {
            close_engine(&mut state.engine);
        }
        // Dynamic WFP filters disappear with the engine. Keep the signed,
        // policy-free callout driver loaded so the next connection does not
        // depend on the original package still being in the same directory.
    }
}

impl AppBypassRefresher {
    pub(crate) fn refresh(&self) -> Result<(), ClientError> {
        let physical_addresses = network::physical_addresses()?;
        let mut state = self.state.lock().map_err(|_| {
            ClientError::Platform("application bypass refresh lock was poisoned".to_owned())
        })?;
        if physical_addresses == state.physical_addresses && state.engine != 0 {
            return Ok(());
        }

        // Fixed WFP object keys cannot coexist in two dynamic sessions. Closing
        // the old one first briefly fails closed under the firewall kill switch.
        close_engine(&mut state.engine);
        let engine = open_engine(&state.policy, physical_addresses)?;
        state.engine = engine as usize;
        state.physical_addresses = physical_addresses;
        Ok(())
    }
}

fn open_engine(
    policy: &AppRoutingPolicy,
    addresses: PhysicalAddresses,
) -> Result<HANDLE, ClientError> {
    let mut session_name = wide("MouseVPN application bypass");
    let session = FWPM_SESSION0 {
        displayData: display_data(&mut session_name),
        flags: FWPM_SESSION_FLAG_DYNAMIC,
        ..Default::default()
    };
    let mut engine = ptr::null_mut();
    check_wfp(
        unsafe {
            FwpmEngineOpen0(
                ptr::null(),
                RPC_C_AUTHN_WINNT,
                ptr::null(),
                &raw const session,
                &raw mut engine,
            )
        },
        "open the WFP engine",
    )?;

    let result = unsafe { configure_engine(engine, policy, addresses) };
    if let Err(error) = result {
        unsafe {
            FwpmEngineClose0(engine);
        }
        return Err(error);
    }
    Ok(engine)
}

fn close_engine(engine: &mut usize) {
    if *engine != 0 {
        unsafe {
            FwpmEngineClose0(*engine as HANDLE);
        }
        *engine = 0;
    }
}

unsafe fn configure_engine(
    engine: HANDLE,
    policy: &AppRoutingPolicy,
    addresses: PhysicalAddresses,
) -> Result<(), ClientError> {
    check_wfp(
        unsafe { FwpmTransactionBegin0(engine, 0) },
        "begin the WFP transaction",
    )?;
    let result = unsafe { configure_transaction(engine, policy, addresses) };
    match result {
        Ok(()) => check_wfp(
            unsafe { FwpmTransactionCommit0(engine) },
            "commit the WFP transaction",
        ),
        Err(error) => {
            unsafe {
                FwpmTransactionAbort0(engine);
            }
            Err(error)
        }
    }
}

unsafe fn configure_transaction(
    engine: HANDLE,
    policy: &AppRoutingPolicy,
    addresses: PhysicalAddresses,
) -> Result<(), ClientError> {
    let mut provider_name = wide("MouseVPN application bypass");
    let mut provider = FWPM_PROVIDER0 {
        providerKey: PROVIDER_KEY,
        displayData: display_data(&mut provider_name),
        ..Default::default()
    };
    check_wfp(
        unsafe { FwpmProviderAdd0(engine, &raw const provider, ptr::null_mut()) },
        "add the MouseVPN WFP provider",
    )?;

    let mut sublayer_name = wide("MouseVPN application bypass policy");
    let sublayer = FWPM_SUBLAYER0 {
        subLayerKey: SUBLAYER_KEY,
        displayData: display_data(&mut sublayer_name),
        providerKey: ptr::from_mut(&mut provider.providerKey),
        weight: 0xfffe,
        ..Default::default()
    };
    check_wfp(
        unsafe { FwpmSubLayerAdd0(engine, &raw const sublayer, ptr::null_mut()) },
        "add the MouseVPN WFP sublayer",
    )?;

    add_callout(
        engine,
        BIND_CALLOUT_KEY,
        FWPM_LAYER_ALE_BIND_REDIRECT_V4,
        &mut provider.providerKey,
        "MouseVPN application bypass",
    )?;
    if addresses.ipv6.is_some() {
        add_callout(
            engine,
            BIND_V6_CALLOUT_KEY,
            FWPM_LAYER_ALE_BIND_REDIRECT_V6,
            &mut provider.providerKey,
            "MouseVPN IPv6 application bypass",
        )?;
    }

    add_redirect_context(
        engine,
        &mut provider.providerKey,
        IPV4_CONTEXT_KEY,
        &mut RedirectContext::ipv4(addresses.ipv4),
        "MouseVPN physical IPv4 address",
    )?;

    if let Some(ipv6) = addresses.ipv6 {
        add_redirect_context(
            engine,
            &mut provider.providerKey,
            IPV6_CONTEXT_KEY,
            &mut RedirectContext::ipv6(ipv6),
            "MouseVPN physical IPv6 address",
        )?;
    }

    match policy.mode {
        AppRoutingMode::Exclude => {
            for path in &policy.apps {
                let app_id = AppId::from_path(path)?;
                add_excluded_identity_filters(
                    engine,
                    FilterIdentity::Application(app_id.blob),
                    addresses.ipv6.is_some(),
                )?;
            }
            for sid in &policy.package_sids {
                let package_sid = PackageSid::from_string(sid)?;
                add_excluded_identity_filters(
                    engine,
                    FilterIdentity::Package(package_sid.sid),
                    addresses.ipv6.is_some(),
                )?;
            }
        }
        AppRoutingMode::Include => {
            add_default_bypass_filters(engine, addresses.ipv6.is_some())?;
            // Windows performs DNS lookups for desktop and packaged apps in the
            // shared DNS Client service. Match its service SID as well as
            // svchost.exe so unrelated Windows services keep bypassing the VPN.
            add_dns_client_vpn_filters(engine, addresses.ipv6.is_some())?;
            for path in &policy.apps {
                let app_id = AppId::from_path(path)?;
                add_vpn_identity_filters(
                    engine,
                    FilterIdentity::Application(app_id.blob),
                    addresses,
                )?;
            }
            for sid in &policy.package_sids {
                let package_sid = PackageSid::from_string(sid)?;
                add_vpn_identity_filters(
                    engine,
                    FilterIdentity::Package(package_sid.sid),
                    addresses,
                )?;
            }
        }
    }
    Ok(())
}

fn add_redirect_context(
    engine: HANDLE,
    provider_key: &mut GUID,
    context_key: GUID,
    redirect_bytes: &mut [u8],
    name: &str,
) -> Result<(), ClientError> {
    let mut redirect_blob = FWP_BYTE_BLOB {
        size: u32::try_from(redirect_bytes.len()).expect("redirect context fits in u32"),
        data: redirect_bytes.as_mut_ptr(),
    };
    let mut name = wide(name);
    let context = FWPM_PROVIDER_CONTEXT0 {
        providerContextKey: context_key,
        displayData: display_data(&mut name),
        providerKey: ptr::from_mut(provider_key),
        r#type: FWPM_GENERAL_CONTEXT,
        Anonymous: FWPM_PROVIDER_CONTEXT0_0 {
            dataBuffer: ptr::from_mut(&mut redirect_blob),
        },
        ..Default::default()
    };
    check_wfp(
        unsafe {
            FwpmProviderContextAdd0(engine, &raw const context, ptr::null_mut(), ptr::null_mut())
        },
        "add a physical-address WFP context",
    )
}

fn add_excluded_identity_filters(
    engine: HANDLE,
    identity: FilterIdentity,
    ipv6: bool,
) -> Result<(), ClientError> {
    add_redirect_filter(
        engine,
        Some(identity),
        FWPM_LAYER_ALE_BIND_REDIRECT_V4,
        BIND_CALLOUT_KEY,
        IPV4_CONTEXT_KEY,
        15,
        "MouseVPN excluded application",
    )?;
    add_permit_filter(engine, identity)?;
    if ipv6 {
        add_redirect_filter(
            engine,
            Some(identity),
            FWPM_LAYER_ALE_BIND_REDIRECT_V6,
            BIND_V6_CALLOUT_KEY,
            IPV6_CONTEXT_KEY,
            15,
            "MouseVPN excluded IPv6 application",
        )?;
        add_permit_filter_for_layer(engine, identity, FWPM_LAYER_ALE_AUTH_CONNECT_V6)?;
    }
    Ok(())
}

fn add_default_bypass_filters(engine: HANDLE, ipv6: bool) -> Result<(), ClientError> {
    add_redirect_filter(
        engine,
        None,
        FWPM_LAYER_ALE_BIND_REDIRECT_V4,
        BIND_CALLOUT_KEY,
        IPV4_CONTEXT_KEY,
        10,
        "MouseVPN default bypass",
    )?;
    if ipv6 {
        add_redirect_filter(
            engine,
            None,
            FWPM_LAYER_ALE_BIND_REDIRECT_V6,
            BIND_V6_CALLOUT_KEY,
            IPV6_CONTEXT_KEY,
            10,
            "MouseVPN default IPv6 bypass",
        )?;
    }
    Ok(())
}

fn add_vpn_identity_filters(
    engine: HANDLE,
    identity: FilterIdentity,
    addresses: PhysicalAddresses,
) -> Result<(), ClientError> {
    add_permit_filter_for_layer(engine, identity, FWPM_LAYER_ALE_BIND_REDIRECT_V4)?;
    add_direct_ipv4_block_filter(engine, identity, addresses.ipv4)?;
    if let Some(ipv6) = addresses.ipv6 {
        add_permit_filter_for_layer(engine, identity, FWPM_LAYER_ALE_BIND_REDIRECT_V6)?;
        add_direct_ipv6_block_filter(engine, identity, ipv6)?;
    }
    Ok(())
}

fn add_direct_ipv4_block_filter(
    engine: HANDLE,
    identity: FilterIdentity,
    address: Ipv4Addr,
) -> Result<(), ClientError> {
    let mut address = FWP_V4_ADDR_AND_MASK {
        addr: u32::from(address),
        mask: u32::MAX,
    };
    let mut conditions = [identity.condition(), local_ipv4_condition(&mut address)];
    add_block_filter_for_conditions(
        engine,
        &mut conditions,
        FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        "MouseVPN selected application direct IPv4 block",
    )
}

fn add_direct_ipv6_block_filter(
    engine: HANDLE,
    identity: FilterIdentity,
    address: Ipv6Addr,
) -> Result<(), ClientError> {
    let mut address = FWP_V6_ADDR_AND_MASK {
        addr: address.octets(),
        prefixLength: 128,
    };
    let mut conditions = [identity.condition(), local_ipv6_condition(&mut address)];
    add_block_filter_for_conditions(
        engine,
        &mut conditions,
        FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        "MouseVPN selected application direct IPv6 block",
    )
}

fn add_dns_client_vpn_filters(engine: HANDLE, ipv6: bool) -> Result<(), ClientError> {
    let system_root = std::env::var_os("SystemRoot")
        .ok_or_else(|| ClientError::Platform("Windows SystemRoot is unavailable".to_owned()))?;
    let app_id = AppId::from_path(&PathBuf::from(system_root).join("System32\\svchost.exe"))?;
    let mut service = UserSecurityDescriptor::for_account("NT SERVICE\\Dnscache")?;
    let mut conditions = [
        FilterIdentity::Application(app_id.blob).condition(),
        service.condition(),
    ];
    add_permit_filter_for_conditions(
        engine,
        &mut conditions,
        FWPM_LAYER_ALE_BIND_REDIRECT_V4,
        "MouseVPN DNS Client permit",
    )?;
    if ipv6 {
        add_permit_filter_for_conditions(
            engine,
            &mut conditions,
            FWPM_LAYER_ALE_BIND_REDIRECT_V6,
            "MouseVPN DNS Client IPv6 permit",
        )?;
    }
    Ok(())
}

fn add_callout(
    engine: HANDLE,
    key: GUID,
    layer: GUID,
    provider_key: &mut GUID,
    name: &str,
) -> Result<(), ClientError> {
    let mut name = wide(name);
    let callout = FWPM_CALLOUT0 {
        calloutKey: key,
        displayData: display_data(&mut name),
        flags: FWPM_CALLOUT_FLAG_USES_PROVIDER_CONTEXT,
        providerKey: ptr::from_mut(provider_key),
        applicableLayer: layer,
        ..Default::default()
    };
    check_wfp(
        unsafe { FwpmCalloutAdd0(engine, &raw const callout, ptr::null_mut(), ptr::null_mut()) },
        "register the MouseVPN WFP callout",
    )
}

fn add_redirect_filter(
    engine: HANDLE,
    identity: Option<FilterIdentity>,
    layer: GUID,
    callout: GUID,
    context_key: GUID,
    filter_weight: u64,
    name: &str,
) -> Result<(), ClientError> {
    let mut conditions = Vec::with_capacity(1);
    if let Some(identity) = identity {
        conditions.push(identity.condition());
    }
    let mut name = wide(name);
    let mut provider_key = PROVIDER_KEY;
    let mut weight = filter_weight;
    let condition_pointer = if conditions.is_empty() {
        ptr::null_mut()
    } else {
        conditions.as_mut_ptr()
    };
    let filter = FWPM_FILTER0 {
        displayData: display_data(&mut name),
        flags: FWPM_FILTER_FLAG_HAS_PROVIDER_CONTEXT,
        providerKey: ptr::from_mut(&mut provider_key),
        layerKey: layer,
        subLayerKey: SUBLAYER_KEY,
        weight: windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_VALUE0 {
            r#type: windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_UINT64,
            Anonymous:
                windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_VALUE0_0 {
                    uint64: ptr::from_mut(&mut weight),
                },
        },
        numFilterConditions: u32::try_from(conditions.len()).expect("condition count fits u32"),
        filterCondition: condition_pointer,
        action: FWPM_ACTION0 {
            r#type: FWP_ACTION_CALLOUT_TERMINATING,
            Anonymous: FWPM_ACTION0_0 {
                calloutKey: callout,
            },
        },
        Anonymous: FWPM_FILTER0_0 {
            providerContextKey: context_key,
        },
        ..Default::default()
    };
    check_wfp(
        unsafe { FwpmFilterAdd0(engine, &raw const filter, ptr::null_mut(), ptr::null_mut()) },
        "add an application redirect filter",
    )
}

fn add_permit_filter(engine: HANDLE, identity: FilterIdentity) -> Result<(), ClientError> {
    add_permit_filter_for_layer(engine, identity, FWPM_LAYER_ALE_AUTH_CONNECT_V4)
}

fn add_permit_filter_for_layer(
    engine: HANDLE,
    identity: FilterIdentity,
    layer: GUID,
) -> Result<(), ClientError> {
    let mut condition = identity.condition();
    add_permit_filter_for_conditions(
        engine,
        std::slice::from_mut(&mut condition),
        layer,
        "MouseVPN application permit",
    )
}

fn add_permit_filter_for_conditions(
    engine: HANDLE,
    conditions: &mut [FWPM_FILTER_CONDITION0],
    layer: GUID,
    name: &str,
) -> Result<(), ClientError> {
    let mut name = wide(name);
    let mut provider_key = PROVIDER_KEY;
    let mut weight = 15_u64;
    let filter = FWPM_FILTER0 {
        displayData: display_data(&mut name),
        flags: FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT,
        providerKey: ptr::from_mut(&mut provider_key),
        layerKey: layer,
        subLayerKey: SUBLAYER_KEY,
        weight: windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_VALUE0 {
            r#type: windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_UINT64,
            Anonymous:
                windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_VALUE0_0 {
                    uint64: ptr::from_mut(&mut weight),
                },
        },
        numFilterConditions: u32::try_from(conditions.len()).expect("condition count fits u32"),
        filterCondition: conditions.as_mut_ptr(),
        action: FWPM_ACTION0 {
            r#type: FWP_ACTION_PERMIT,
            ..Default::default()
        },
        ..Default::default()
    };
    check_wfp(
        unsafe { FwpmFilterAdd0(engine, &raw const filter, ptr::null_mut(), ptr::null_mut()) },
        "add an application firewall permit",
    )
}

fn add_block_filter_for_conditions(
    engine: HANDLE,
    conditions: &mut [FWPM_FILTER_CONDITION0],
    layer: GUID,
    name: &str,
) -> Result<(), ClientError> {
    let mut name = wide(name);
    let mut provider_key = PROVIDER_KEY;
    let mut weight = 20_u64;
    let filter = FWPM_FILTER0 {
        displayData: display_data(&mut name),
        flags: FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT,
        providerKey: ptr::from_mut(&mut provider_key),
        layerKey: layer,
        subLayerKey: SUBLAYER_KEY,
        weight: windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_VALUE0 {
            r#type: windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_UINT64,
            Anonymous:
                windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_VALUE0_0 {
                    uint64: ptr::from_mut(&mut weight),
                },
        },
        numFilterConditions: u32::try_from(conditions.len()).expect("condition count fits u32"),
        filterCondition: conditions.as_mut_ptr(),
        action: FWPM_ACTION0 {
            r#type: FWP_ACTION_BLOCK,
            ..Default::default()
        },
        ..Default::default()
    };
    check_wfp(
        unsafe { FwpmFilterAdd0(engine, &raw const filter, ptr::null_mut(), ptr::null_mut()) },
        "add a selected-application direct-connection block",
    )
}

fn local_ipv4_condition(address: &mut FWP_V4_ADDR_AND_MASK) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_IP_LOCAL_ADDRESS,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_V4_ADDR_MASK,
            Anonymous: FWP_CONDITION_VALUE0_0 {
                v4AddrMask: ptr::from_mut(address),
            },
        },
    }
}

fn local_ipv6_condition(address: &mut FWP_V6_ADDR_AND_MASK) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_IP_LOCAL_ADDRESS,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_V6_ADDR_MASK,
            Anonymous: FWP_CONDITION_VALUE0_0 {
                v6AddrMask: ptr::from_mut(address),
            },
        },
    }
}

#[derive(Clone, Copy)]
enum FilterIdentity {
    Application(*mut FWP_BYTE_BLOB),
    Package(PSID),
}

impl FilterIdentity {
    fn condition(self) -> FWPM_FILTER_CONDITION0 {
        let (field_key, value_type, value) = match self {
            Self::Application(app_id) => (
                FWPM_CONDITION_ALE_APP_ID,
                FWP_BYTE_BLOB_TYPE,
                FWP_CONDITION_VALUE0_0 { byteBlob: app_id },
            ),
            Self::Package(sid) => (
                FWPM_CONDITION_ALE_PACKAGE_ID,
                FWP_SID,
                FWP_CONDITION_VALUE0_0 { sid: sid.cast() },
            ),
        };
        FWPM_FILTER_CONDITION0 {
            fieldKey: field_key,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: value_type,
                Anonymous: value,
            },
        }
    }
}

struct AppId {
    blob: *mut FWP_BYTE_BLOB,
}

impl AppId {
    fn from_path(path: &Path) -> Result<Self, ClientError> {
        let path = crate::normalize_windows_path(path);
        let path = wide(&path.display().to_string());
        let mut blob = ptr::null_mut();
        check_wfp(
            unsafe { FwpmGetAppIdFromFileName0(path.as_ptr(), &raw mut blob) },
            "resolve an application path for WFP",
        )?;
        Ok(Self { blob })
    }
}

impl Drop for AppId {
    fn drop(&mut self) {
        unsafe {
            FwpmFreeMemory0(ptr::from_mut(&mut self.blob).cast::<*mut c_void>());
        }
    }
}

struct PackageSid {
    sid: PSID,
}

impl PackageSid {
    fn from_string(value: &str) -> Result<Self, ClientError> {
        let value = wide(value);
        let mut sid = ptr::null_mut();
        if unsafe { ConvertStringSidToSidW(value.as_ptr(), &raw mut sid) } == 0 || sid.is_null() {
            return Err(ClientError::Platform(format!(
                "invalid Windows application package SID: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(Self { sid })
    }
}

impl Drop for PackageSid {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.sid.cast());
        }
    }
}

struct UserSecurityDescriptor {
    descriptor: PSECURITY_DESCRIPTOR,
    blob: FWP_BYTE_BLOB,
}

impl UserSecurityDescriptor {
    fn for_account(account: &str) -> Result<Self, ClientError> {
        let mut account = wide(account);
        let mut access = EXPLICIT_ACCESS_W::default();
        unsafe {
            BuildExplicitAccessWithNameW(
                &raw mut access,
                account.as_mut_ptr(),
                FWP_ACTRL_MATCH_FILTER,
                GRANT_ACCESS,
                0,
            );
        }

        let mut size = 0_u32;
        let mut descriptor = ptr::null_mut();
        let result = unsafe {
            BuildSecurityDescriptorW(
                ptr::null(),
                ptr::null(),
                1,
                &raw const access,
                0,
                ptr::null(),
                ptr::null_mut(),
                &raw mut size,
                &raw mut descriptor,
            )
        };
        if result != 0 || descriptor.is_null() {
            return Err(ClientError::Platform(format!(
                "failed to resolve the Windows DNS Client service identity: Windows error {result}"
            )));
        }
        Ok(Self {
            descriptor,
            blob: FWP_BYTE_BLOB {
                size,
                data: descriptor.cast(),
            },
        })
    }

    fn condition(&mut self) -> FWPM_FILTER_CONDITION0 {
        FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_ALE_USER_ID,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_SECURITY_DESCRIPTOR_TYPE,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    sd: &raw mut self.blob,
                },
            },
        }
    }
}

impl Drop for UserSecurityDescriptor {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.descriptor.cast());
        }
    }
}

struct RedirectContext;

impl RedirectContext {
    fn ipv4(address: Ipv4Addr) -> [u8; 20] {
        let mut bytes = [0_u8; 20];
        bytes[..2].copy_from_slice(&2_u16.to_ne_bytes()); // AF_INET
        bytes[4..8].copy_from_slice(&address.octets());
        bytes
    }

    fn ipv6(address: Ipv6Addr) -> [u8; 20] {
        let mut bytes = [0_u8; 20];
        bytes[..2].copy_from_slice(&23_u16.to_ne_bytes()); // AF_INET6
        bytes[4..].copy_from_slice(&address.octets());
        bytes
    }
}

fn ensure_driver_started(path: &Path) -> Result<(), ClientError> {
    let query = run_sc(["query", SERVICE_NAME])?;
    if query.0 {
        if path.is_file() {
            let path = path.display().to_string();
            let configured = run_sc(["config", SERVICE_NAME, "binPath=", &path])?;
            if !configured.0 {
                return Err(sc_error(
                    "update the application bypass driver",
                    &configured.1,
                ));
            }
        } else {
            let started = run_sc(["start", SERVICE_NAME])?;
            if started.0 || started.1.contains("1056") {
                return Ok(());
            }
            return Err(ClientError::Platform(format!(
                "application bypass driver is installed but cannot be started, and the package copy is missing: {}; {}",
                path.display(),
                started.1
            )));
        }
    } else {
        if !path.is_file() {
            return Err(ClientError::Platform(format!(
                "application bypass driver is missing: {}; install the complete MouseVPN package",
                path.display()
            )));
        }
        let path = path.display().to_string();
        let created = run_sc([
            "create",
            SERVICE_NAME,
            "type=",
            "kernel",
            "start=",
            "demand",
            "binPath=",
            &path,
            "DisplayName=",
            "MouseVPN Split Tunnel",
        ])?;
        if !created.0 {
            return Err(sc_error(
                "install the application bypass driver",
                &created.1,
            ));
        }
    }
    let started = run_sc(["start", SERVICE_NAME])?;
    if started.0 || started.1.contains("1056") {
        Ok(())
    } else {
        Err(sc_error("start the application bypass driver", &started.1))
    }
}

fn driver_path() -> Result<PathBuf, ClientError> {
    let executable = std::env::current_exe()?;
    let directory = executable.parent().ok_or_else(|| {
        ClientError::Platform("MouseVPN executable has no parent directory".to_owned())
    })?;
    Ok(directory.join(DRIVER_FILE))
}

fn run_sc<const N: usize>(arguments: [&str; N]) -> Result<(bool, String), ClientError> {
    let mut command = Command::new("sc.exe");
    command.creation_flags(CREATE_NO_WINDOW);
    let output = command.args(arguments).output()?;
    let details = format!(
        "{} {}",
        String::from_utf8_lossy(&output.stdout).trim(),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok((output.status.success(), details.trim().to_owned()))
}

fn sc_error(operation: &str, details: &str) -> ClientError {
    ClientError::Platform(format!("failed to {operation}: {details}"))
}

pub(crate) fn check_wfp(code: u32, operation: &str) -> Result<(), ClientError> {
    if code == 0 {
        Ok(())
    } else {
        Err(ClientError::Platform(format!(
            "failed to {operation}: Windows error {code}"
        )))
    }
}

pub(crate) fn display_data(name: &mut [u16]) -> FWPM_DISPLAY_DATA0 {
    FWPM_DISPLAY_DATA0 {
        name: name.as_mut_ptr(),
        description: ptr::null_mut(),
    }
}

pub(crate) fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
        FWPM_CONDITION_ALE_USER_ID, FWP_SECURITY_DESCRIPTOR_TYPE, FWP_V4_ADDR_AND_MASK,
        FWP_V4_ADDR_MASK, FWP_V6_ADDR_AND_MASK, FWP_V6_ADDR_MASK,
    };

    use super::{
        local_ipv4_condition, local_ipv6_condition, RedirectContext, UserSecurityDescriptor,
    };

    #[test]
    fn redirect_context_matches_the_driver_abi() {
        assert_eq!(
            RedirectContext::ipv4(Ipv4Addr::new(192, 168, 1, 7)),
            [2, 0, 0, 0, 192, 168, 1, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn ipv6_redirect_context_matches_the_driver_abi() {
        let address = "2001:db8::7".parse::<Ipv6Addr>().unwrap();
        let context = RedirectContext::ipv6(address);
        assert_eq!(&context[..4], &[23, 0, 0, 0]);
        assert_eq!(&context[4..], &address.octets());
    }

    #[test]
    fn resolves_the_dns_client_service_identity() {
        let mut descriptor = UserSecurityDescriptor::for_account("NT SERVICE\\Dnscache").unwrap();
        assert!(!descriptor.descriptor.is_null());
        assert!(descriptor.blob.size > 0);
        let condition = descriptor.condition();
        assert_eq!(condition.fieldKey.data1, FWPM_CONDITION_ALE_USER_ID.data1);
        assert_eq!(condition.fieldKey.data2, FWPM_CONDITION_ALE_USER_ID.data2);
        assert_eq!(condition.fieldKey.data3, FWPM_CONDITION_ALE_USER_ID.data3);
        assert_eq!(condition.fieldKey.data4, FWPM_CONDITION_ALE_USER_ID.data4);
        assert_eq!(
            condition.conditionValue.r#type,
            FWP_SECURITY_DESCRIPTOR_TYPE
        );
    }

    #[test]
    fn physical_address_conditions_are_exact_host_addresses() {
        let mut ipv4 = FWP_V4_ADDR_AND_MASK {
            addr: u32::from(Ipv4Addr::new(192, 168, 0, 103)),
            mask: u32::MAX,
        };
        let ipv4_condition = local_ipv4_condition(&mut ipv4);
        assert_eq!(ipv4_condition.conditionValue.r#type, FWP_V4_ADDR_MASK);
        assert_eq!(ipv4.addr, 0xc0a8_0067);
        assert_eq!(ipv4.mask, u32::MAX);

        let address = "2001:db8::7".parse::<Ipv6Addr>().unwrap();
        let mut ipv6 = FWP_V6_ADDR_AND_MASK {
            addr: address.octets(),
            prefixLength: 128,
        };
        let ipv6_condition = local_ipv6_condition(&mut ipv6);
        assert_eq!(ipv6_condition.conditionValue.r#type, FWP_V6_ADDR_MASK);
        assert_eq!(ipv6.addr, address.octets());
        assert_eq!(ipv6.prefixLength, 128);
    }
}
