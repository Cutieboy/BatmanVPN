use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    net::Ipv4Addr,
    os::windows::process::CommandExt,
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex},
};

use fs2::FileExt;
use mousevpn_protocol::SessionParameters;
use serde::{Deserialize, Serialize};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;

use crate::{
    app_bypass::{AppBypassGuard, AppBypassRefresher},
    netcfg::{self, OwnedRoute},
    AppRoutingMode, AppRoutingPolicy, ClientError,
};

pub(crate) use crate::netcfg::PhysicalAddresses;

pub(crate) const ADAPTER_NAME: &str = "MouseVPN";
const FIREWALL_GROUP: &str = "MouseVPN Kill Switch";
const STATE_FILE: &str = "network-state.toml";
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// The two halves of the default route the tunnel installs. Two `/1` routes
/// beat a physical `0.0.0.0/0` on prefix length without replacing it, so the
/// original default route survives for the tunnel endpoint itself.
const TUNNEL_HALVES: [Ipv4Addr; 2] = [Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(128, 0, 0, 0)];

pub(crate) struct RuntimeLock {
    _file: File,
}

impl RuntimeLock {
    pub(crate) fn acquire() -> Result<Self, ClientError> {
        let directory = runtime_dir()?;
        fs::create_dir_all(&directory)?;
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(directory.join("runtime.lock"))?;
        file.try_lock_exclusive().map_err(|error| {
            if error.kind() == io::ErrorKind::WouldBlock {
                ClientError::Platform(
                    "another MouseVPN Windows helper is already running".to_owned(),
                )
            } else {
                error.into()
            }
        })?;
        Ok(Self { _file: file })
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct RecoveryState {
    server_ip: Ipv4Addr,
}

pub(crate) struct NetworkGuard {
    state: RecoveryState,
    state_path: PathBuf,
    refresh_lock: Arc<Mutex<()>>,
    app_routing: AppRoutingPolicy,
    app_bypass: Option<AppBypassGuard>,
    parameters: SessionParameters,
}

#[derive(Clone)]
pub(crate) struct NetworkRefresher {
    server_ip: Ipv4Addr,
    refresh_lock: Arc<Mutex<()>>,
    app_routing: AppRoutingPolicy,
    app_bypass: Option<AppBypassRefresher>,
}

impl NetworkGuard {
    pub(crate) fn install(
        server_ip: Ipv4Addr,
        server_port: u16,
        parameters: SessionParameters,
        app_routing: &AppRoutingPolicy,
        app_bypass: Option<AppBypassGuard>,
    ) -> Result<Self, ClientError> {
        let state = RecoveryState { server_ip };
        let state_path = state_path()?;
        write_state(&state_path, &state)?;
        if let Err(error) = install_policy(server_ip, parameters, app_routing) {
            if cleanup().is_ok() {
                let _ = fs::remove_file(&state_path);
            }
            return Err(error);
        }
        eprintln!("MOUSEVPN_POLICY=installed for {server_ip}:{server_port}");
        Ok(Self {
            state,
            state_path,
            refresh_lock: Arc::new(Mutex::new(())),
            app_routing: app_routing.clone(),
            app_bypass,
            parameters,
        })
    }

    pub(crate) fn update_parameters(
        &mut self,
        parameters: SessionParameters,
    ) -> Result<(), ClientError> {
        if parameters == self.parameters {
            return Ok(());
        }
        let _guard = self.refresh_lock.lock().map_err(|_| {
            ClientError::Platform("Windows network policy refresh lock was poisoned".to_owned())
        })?;
        let tunnel = netcfg::interface_luid(ADAPTER_NAME)?;
        let previous = self.parameters;
        if let Err(error) = apply_parameters(tunnel, parameters) {
            // Fall back to what the tunnel was already using so the interface
            // never sits without an address, then report the original failure.
            apply_parameters(tunnel, previous)?;
            return Err(ClientError::Platform(format!(
                "updating MouseVPN session parameters failed: {error}"
            )));
        }
        self.parameters = parameters;
        Ok(())
    }

    pub(crate) fn refresh(&self) -> Result<(), ClientError> {
        self.refresher().refresh()
    }

    pub(crate) fn refresher(&self) -> NetworkRefresher {
        NetworkRefresher {
            server_ip: self.state.server_ip,
            refresh_lock: Arc::clone(&self.refresh_lock),
            app_routing: self.app_routing.clone(),
            app_bypass: self.app_bypass.as_ref().map(AppBypassGuard::refresher),
        }
    }
}

impl NetworkRefresher {
    pub(crate) fn refresh(&self) -> Result<(), ClientError> {
        let _guard = self.refresh_lock.lock().map_err(|_| {
            ClientError::Platform("Windows network policy refresh lock was poisoned".to_owned())
        })?;
        let tunnel = netcfg::interface_luid(ADAPTER_NAME)?;
        repair_routes(tunnel, self.server_ip)?;
        run_powershell(
            &refresh_script(self.server_ip, &self.app_routing),
            "refresh the Windows network policy",
        )?;
        if let Some(app_bypass) = &self.app_bypass {
            app_bypass.refresh()?;
        }
        Ok(())
    }
}

fn install_policy(
    server_ip: Ipv4Addr,
    parameters: SessionParameters,
    app_routing: &AppRoutingPolicy,
) -> Result<(), ClientError> {
    let tunnel = netcfg::interface_luid(ADAPTER_NAME)?;
    // The kill switch has to be in place before the default route moves, or
    // traffic leaks over the physical interface during the switchover.
    run_powershell(
        &install_script(server_ip, app_routing),
        "install the Windows kill switch",
    )?;
    let default = netcfg::default_ipv4_route(Some(tunnel))?;
    apply_parameters(tunnel, parameters)?;
    netcfg::set_tunnel_metric(tunnel)?;
    netcfg::add_route(default.interface_luid, server_ip, 32, default.next_hop)?;
    for destination in TUNNEL_HALVES {
        netcfg::add_route(tunnel, destination, 1, Ipv4Addr::UNSPECIFIED)?;
    }
    Ok(())
}

fn apply_parameters(
    tunnel: NET_LUID_LH,
    parameters: SessionParameters,
) -> Result<(), ClientError> {
    netcfg::set_tunnel_address(tunnel, parameters.client_address, parameters.prefix_len)?;
    netcfg::set_tunnel_dns(ADAPTER_NAME, parameters.dns)
}

/// Restores any route the tunnel owns that roaming or another VPN removed.
fn repair_routes(tunnel: NET_LUID_LH, server_ip: Ipv4Addr) -> Result<(), ClientError> {
    let tunnel_index = netcfg::interface_index(tunnel)?;
    let default = netcfg::default_ipv4_route(Some(tunnel))?;
    let routes = netcfg::owned_routes()?;

    if server_route_is_stale(
        &routes,
        server_ip,
        default.interface_index,
        default.next_hop,
    ) {
        netcfg::remove_owned_routes(|route| is_server_route(route, server_ip))?;
        netcfg::add_route(default.interface_luid, server_ip, 32, default.next_hop)?;
    }

    for destination in TUNNEL_HALVES {
        let present = routes.iter().any(|route| {
            route.destination == destination
                && route.prefix_len == 1
                && route.interface_index == tunnel_index
        });
        if !present {
            netcfg::add_route(tunnel, destination, 1, Ipv4Addr::UNSPECIFIED)?;
        }
    }
    Ok(())
}

fn is_server_route(route: &OwnedRoute, server_ip: Ipv4Addr) -> bool {
    route.destination == server_ip && route.prefix_len == 32
}

/// Reports whether the endpoint route needs replacing.
///
/// It is stale when it is missing, duplicated, or points somewhere other than
/// the current physical default gateway — which is exactly what happens when
/// the machine roams to another network.
fn server_route_is_stale(
    routes: &[OwnedRoute],
    server_ip: Ipv4Addr,
    interface_index: u32,
    next_hop: Ipv4Addr,
) -> bool {
    let mut total = 0_usize;
    let mut matching = 0_usize;
    for route in routes.iter().filter(|route| is_server_route(route, server_ip)) {
        total += 1;
        if route.interface_index == interface_index && route.next_hop == next_hop {
            matching += 1;
        }
    }
    total != 1 || matching != 1
}

impl Drop for NetworkGuard {
    fn drop(&mut self) {
        if cleanup().is_ok() {
            let _ = fs::remove_file(&self.state_path);
        }
    }
}

pub(crate) fn recover_stale_state() -> Result<(), ClientError> {
    let path = state_path()?;
    if !path.exists() {
        // Policy is only ever written after the recovery journal exists, so a
        // missing journal and a missing interface together mean the machine is
        // already clean. Skipping cleanup here keeps a full PowerShell start-up
        // off every normal connection.
        if !netcfg::interface_exists(ADAPTER_NAME) {
            return Ok(());
        }
        cleanup()?;
        return Ok(());
    }
    cleanup()?;
    fs::remove_file(path)?;
    Ok(())
}

pub(crate) fn repair() -> Result<(), ClientError> {
    cleanup()?;
    match fs::remove_file(state_path()?) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

pub(crate) fn report() -> Result<String, ClientError> {
    let script = format!(
        "$vpn=Get-NetAdapter -Name '{ADAPTER_NAME}' -ErrorAction SilentlyContinue; \
         $routes=@(); $dns=@(); $category=$null; $metric=$null; $bindings=@(); $otherDns=@(); \
         if ($vpn) {{ \
           $routes=@(Get-NetRoute -InterfaceIndex $vpn.ifIndex -ErrorAction SilentlyContinue | Where-Object {{$_.DestinationPrefix -in '0.0.0.0/1','128.0.0.0/1'}} | Select-Object DestinationPrefix,InterfaceIndex,RouteMetric); \
           $dns=@((Get-DnsClientServerAddress -InterfaceIndex $vpn.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses); \
           $metric=(Get-NetIPInterface -InterfaceIndex $vpn.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).InterfaceMetric; \
           $category=(Get-NetConnectionProfile -InterfaceIndex $vpn.ifIndex -ErrorAction SilentlyContinue).NetworkCategory; \
           $bindings=@(Get-NetAdapterBinding -Name '{ADAPTER_NAME}' -ErrorAction SilentlyContinue | Where-Object {{$_.Enabled -and $_.ComponentID -in 'nt_ndisrd','nt_ndiswgc'}} | Select-Object -ExpandProperty ComponentID); \
           $otherDns=@(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {{$_.ifIndex -ne $vpn.ifIndex -and $_.Status -eq 'Up'}} | ForEach-Object {{ \
             $adapter=$_; $ip=Get-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue; $servers=@((Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses); \
             if ($servers.Count -gt 0) {{[pscustomobject]@{{interfaceAlias=$adapter.Name; interfaceMetric=$ip.InterfaceMetric; dnsServers=$servers}}}} \
           }}) \
         }}; \
         [ordered]@{{ adapterUp=[bool]($vpn -and $vpn.Status -eq 'Up'); routeCount=$routes.Count; firewallRuleCount=@(Get-NetFirewallRule -Group '{FIREWALL_GROUP}' -Enabled True -ErrorAction SilentlyContinue).Count; dnsServers=$dns; interfaceMetric=$metric; networkCategory=$category; incompatibleBindings=$bindings; otherDnsAdapters=$otherDns; stateJournal=Test-Path '{}'; ipv6DefaultRoutes=@(Get-NetRoute -AddressFamily IPv6 -DestinationPrefix '::/0' -ErrorAction SilentlyContinue).Count }} | ConvertTo-Json -Depth 4 -Compress",
        powershell_path(&state_path()?)
    );
    run_powershell_output(&script, "collect the Windows network report")
}

pub(crate) fn physical_addresses() -> Result<PhysicalAddresses, ClientError> {
    netcfg::physical_addresses(netcfg::interface_luid(ADAPTER_NAME).ok())
}

fn write_state(path: &Path, state: &RecoveryState) -> Result<(), ClientError> {
    let contents = toml::to_string(state).map_err(|error| {
        ClientError::Platform(format!("failed to encode recovery state: {error}"))
    })?;
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&temporary)?;
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
        if path.exists() {
            fs::remove_file(path)?;
        }
        fs::rename(&temporary, path)?;
        Ok::<(), io::Error>(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result.map_err(Into::into)
}

/// Undoes every network change `MouseVPN` can make.
///
/// Nothing here depends on the recovery journal: routes are recognised by the
/// metric and protocol the client always stamps on them, so a session whose
/// journal was lost still cleans up completely.
fn cleanup() -> Result<(), ClientError> {
    let mut failures = Vec::new();
    if let Ok(tunnel) = netcfg::interface_luid(ADAPTER_NAME) {
        collect(&mut failures, netcfg::reset_tunnel_dns(ADAPTER_NAME));
        collect(&mut failures, netcfg::reset_tunnel_metric(tunnel));
        collect(&mut failures, netcfg::clear_addresses(tunnel));
    }
    collect(&mut failures, netcfg::remove_owned_routes(|_| true));
    collect(
        &mut failures,
        run_powershell(
            &format!(
                "$rules=@(Get-NetFirewallRule -Group '{FIREWALL_GROUP}' -ErrorAction SilentlyContinue); \
                 if ($rules.Count -gt 0) {{ $rules | Remove-NetFirewallRule -ErrorAction Stop }}; \
                 exit 0"
            ),
            "remove the Windows kill switch",
        ),
    );
    if failures.is_empty() {
        Ok(())
    } else {
        Err(ClientError::Platform(failures.join("; ")))
    }
}

fn collect(failures: &mut Vec<String>, result: Result<(), ClientError>) {
    if let Err(error) = result {
        failures.push(error.to_string());
    }
}

fn install_script(server_ip: Ipv4Addr, app_routing: &AppRoutingPolicy) -> String {
    let prefixes = blocked_ipv4_prefixes(server_ip).join("','");
    let firewall = firewall_script(app_routing, false);
    format!(
        "$ErrorActionPreference='Stop'; \
         $blocked=@('{prefixes}'); \
         $physical=Get-NetAdapter | Where-Object {{$_.Name -ne '{ADAPTER_NAME}' -and $_.InterfaceDescription -notmatch 'Loopback'}}; \
         {firewall}"
    )
}

fn refresh_script(server_ip: Ipv4Addr, app_routing: &AppRoutingPolicy) -> String {
    let prefixes = blocked_ipv4_prefixes(server_ip).join("','");
    let firewall = firewall_script(app_routing, true);
    format!(
        "$ErrorActionPreference='Stop'; \
         $vpn=Get-NetAdapter -Name '{ADAPTER_NAME}' -ErrorAction Stop; \
         try {{ \
           $profile=Get-NetConnectionProfile -InterfaceIndex $vpn.ifIndex -ErrorAction SilentlyContinue; \
           if ($profile -and $profile.NetworkCategory -ne 'Public') {{Set-NetConnectionProfile -InterfaceIndex $vpn.ifIndex -NetworkCategory Public -ErrorAction Stop}} \
         }} catch {{Write-Warning ('Could not mark MouseVPN as a Public network: '+$_.Exception.Message)}}; \
         $blocked=@('{prefixes}'); \
         $physical=Get-NetAdapter | Where-Object {{$_.Name -ne '{ADAPTER_NAME}' -and $_.InterfaceDescription -notmatch 'Loopback'}}; \
         {firewall}"
    )
}

fn firewall_script(policy: &AppRoutingPolicy, only_missing: bool) -> String {
    match policy.mode {
        AppRoutingMode::Exclude => {
            let create_v4 = "try { New-NetFirewallRule -Name ('MouseVPN-KS-v4-'+$adapter.ifIndex) -DisplayName ('MouseVPN kill switch IPv4 '+$adapter.Name) -Group 'MouseVPN Kill Switch' -Direction Outbound -Action Block -Enabled True -Profile Any -InterfaceAlias $adapter.Name -RemoteAddress $blocked | Out-Null } catch { throw ('IPv4 firewall rule failed on adapter '+$adapter.Name+': '+$_.Exception.Message) }";
            let create_v6 = "try { New-NetFirewallRule -Name ('MouseVPN-KS-v6-'+$adapter.ifIndex) -DisplayName ('MouseVPN kill switch IPv6 '+$adapter.Name) -Group 'MouseVPN Kill Switch' -Direction Outbound -Action Block -Enabled True -Profile Any -InterfaceAlias $adapter.Name -RemoteAddress 'Internet6' | Out-Null } catch { throw ('IPv6 firewall rule failed on adapter '+$adapter.Name+': '+$_.Exception.Message) }";
            if only_missing {
                format!(
                    "foreach ($adapter in $physical) {{ if (-not (Get-NetFirewallRule -Name ('MouseVPN-KS-v4-'+$adapter.ifIndex) -ErrorAction SilentlyContinue)) {{ {create_v4} }}; if (-not (Get-NetFirewallRule -Name ('MouseVPN-KS-v6-'+$adapter.ifIndex) -ErrorAction SilentlyContinue)) {{ {create_v6} }} }}"
                )
            } else {
                format!("foreach ($adapter in $physical) {{ {create_v4}; {create_v6} }}")
            }
        }
        AppRoutingMode::Include => {
            let apps = policy
                .apps
                .iter()
                .map(|path| format!("'{}'", powershell_path(path)))
                .collect::<Vec<_>>()
                .join(",");
            let packages = policy
                .package_sids
                .iter()
                .map(|sid| format!("'{}'", sid.replace('\'', "''")))
                .collect::<Vec<_>>()
                .join(",");
            let guard = if only_missing {
                "if (-not (Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue))"
            } else {
                "if ($true)"
            };
            format!(
                "$vpnApps=@({apps}); $vpnPackages=@({packages}); foreach ($adapter in $physical) {{ $name=('MouseVPN-KS-v4-'+$adapter.ifIndex+'-dnscache'); {guard} {{ try {{ New-NetFirewallRule -Name $name -DisplayName ('MouseVPN DNS Client kill switch IPv4 '+$adapter.Name) -Group '{FIREWALL_GROUP}' -Direction Outbound -Action Block -Enabled True -Profile Any -InterfaceAlias $adapter.Name -Service Dnscache -RemoteAddress $blocked | Out-Null }} catch {{ throw ('DNS Client IPv4 firewall rule failed: '+$_.Exception.Message) }} }}; $name=('MouseVPN-KS-v6-'+$adapter.ifIndex+'-dnscache'); {guard} {{ try {{ New-NetFirewallRule -Name $name -DisplayName ('MouseVPN DNS Client kill switch IPv6 '+$adapter.Name) -Group '{FIREWALL_GROUP}' -Direction Outbound -Action Block -Enabled True -Profile Any -InterfaceAlias $adapter.Name -Service Dnscache -RemoteAddress 'Internet6' | Out-Null }} catch {{ throw ('DNS Client IPv6 firewall rule failed: '+$_.Exception.Message) }} }}; $i=0; foreach ($app in $vpnApps) {{ $name=('MouseVPN-KS-v4-'+$adapter.ifIndex+'-'+$i); {guard} {{ try {{ New-NetFirewallRule -Name $name -DisplayName ('MouseVPN selected app kill switch IPv4 '+$adapter.Name) -Group '{FIREWALL_GROUP}' -Direction Outbound -Action Block -Enabled True -Profile Any -InterfaceAlias $adapter.Name -Program $app -RemoteAddress $blocked | Out-Null }} catch {{ throw ('Selected-app IPv4 firewall rule failed for '+$app+': '+$_.Exception.Message) }} }}; $name=('MouseVPN-KS-v6-'+$adapter.ifIndex+'-'+$i); {guard} {{ try {{ New-NetFirewallRule -Name $name -DisplayName ('MouseVPN selected app kill switch IPv6 '+$adapter.Name) -Group '{FIREWALL_GROUP}' -Direction Outbound -Action Block -Enabled True -Profile Any -InterfaceAlias $adapter.Name -Program $app -RemoteAddress 'Internet6' | Out-Null }} catch {{ throw ('Selected-app IPv6 firewall rule failed for '+$app+': '+$_.Exception.Message) }} }}; $i++ }}; foreach ($package in $vpnPackages) {{ $name=('MouseVPN-KS-v4-'+$adapter.ifIndex+'-package-'+$i); {guard} {{ try {{ New-NetFirewallRule -Name $name -DisplayName ('MouseVPN selected package kill switch IPv4 '+$adapter.Name) -Group '{FIREWALL_GROUP}' -Direction Outbound -Action Block -Enabled True -Profile Any -InterfaceAlias $adapter.Name -Package $package -RemoteAddress $blocked | Out-Null }} catch {{ throw ('Selected-package IPv4 firewall rule failed for '+$package+': '+$_.Exception.Message) }} }}; $name=('MouseVPN-KS-v6-'+$adapter.ifIndex+'-package-'+$i); {guard} {{ try {{ New-NetFirewallRule -Name $name -DisplayName ('MouseVPN selected package kill switch IPv6 '+$adapter.Name) -Group '{FIREWALL_GROUP}' -Direction Outbound -Action Block -Enabled True -Profile Any -InterfaceAlias $adapter.Name -Package $package -RemoteAddress 'Internet6' | Out-Null }} catch {{ throw ('Selected-package IPv6 firewall rule failed for '+$package+': '+$_.Exception.Message) }} }}; $i++ }} }}"
            )
        }
    }
}

fn blocked_ipv4_prefixes(server_ip: Ipv4Addr) -> Vec<String> {
    let server = u32::from(server_ip);
    let mut server_network = 0_u32;
    let mut prefixes = Vec::with_capacity(32);

    for prefix_len in 1..=32 {
        let bit = 1_u32 << (32 - prefix_len);
        let sibling_network = if server & bit == 0 {
            server_network | bit
        } else {
            let sibling = server_network;
            server_network |= bit;
            sibling
        };
        prefixes.push(format!(
            "{}/{}",
            Ipv4Addr::from(sibling_network),
            prefix_len
        ));
    }

    prefixes
}

fn state_path() -> Result<PathBuf, ClientError> {
    Ok(runtime_dir()?.join(STATE_FILE))
}

pub(crate) fn runtime_dir() -> Result<PathBuf, ClientError> {
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .ok_or_else(|| ClientError::Platform("LOCALAPPDATA is unavailable".to_owned()))?;
    Ok(base.join("MouseVPN").join("runtime"))
}

fn powershell_path(path: &Path) -> String {
    crate::normalize_windows_path(path)
        .display()
        .to_string()
        .replace('\'', "''")
}

pub(crate) fn run_powershell(script: &str, operation: &str) -> Result<(), ClientError> {
    run_powershell_output(script, operation).map(|_| ())
}

fn run_powershell_output(script: &str, operation: &str) -> Result<String, ClientError> {
    let script = format!(
        "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; \
         $OutputEncoding=[Console]::OutputEncoding; \
         {script}"
    );
    let mut command = Command::new("powershell.exe");
    command.creation_flags(CREATE_NO_WINDOW);
    let output = command
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &script,
        ])
        .output()?;
    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let details = if !stderr.is_empty() {
        stderr
    } else if !stdout.is_empty() {
        stdout
    } else {
        format!("PowerShell exited with status {}", output.status)
    };
    Err(ClientError::Platform(format!(
        "failed to {operation}: {details}"
    )))
}

#[cfg(test)]
mod tests {
    use super::{
        blocked_ipv4_prefixes, firewall_script, install_script, server_route_is_stale, OwnedRoute,
    };
    use crate::{AppRoutingMode, AppRoutingPolicy};
    use std::net::Ipv4Addr;
    use std::path::PathBuf;

    const SERVER: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 10);
    const GATEWAY: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);

    fn server_route(interface_index: u32, next_hop: Ipv4Addr) -> OwnedRoute {
        OwnedRoute {
            destination: SERVER,
            prefix_len: 32,
            interface_index,
            next_hop,
        }
    }

    #[test]
    fn emits_valid_cidr_prefixes_that_exclude_the_server() {
        let prefixes = blocked_ipv4_prefixes(SERVER);
        assert_eq!(prefixes.len(), 32);
        assert!(prefixes.iter().all(|prefix| !contains(prefix, SERVER)));
        assert!(contains_any(&prefixes, Ipv4Addr::UNSPECIFIED));
        assert!(contains_any(&prefixes, Ipv4Addr::BROADCAST));
        assert!(contains_any(&prefixes, Ipv4Addr::new(203, 0, 113, 9)));
        assert!(contains_any(&prefixes, Ipv4Addr::new(203, 0, 113, 11)));
    }

    #[test]
    fn handles_ipv4_boundaries() {
        for server in [Ipv4Addr::UNSPECIFIED, Ipv4Addr::BROADCAST] {
            let prefixes = blocked_ipv4_prefixes(server);
            assert_eq!(prefixes.len(), 32);
            assert!(prefixes.iter().all(|prefix| !contains(prefix, server)));
        }
    }

    #[test]
    fn keeps_a_matching_endpoint_route() {
        assert!(!server_route_is_stale(
            &[server_route(7, GATEWAY)],
            SERVER,
            7,
            GATEWAY
        ));
    }

    #[test]
    fn replaces_an_endpoint_route_left_on_the_previous_network() {
        assert!(server_route_is_stale(
            &[server_route(7, Ipv4Addr::new(10, 0, 0, 1))],
            SERVER,
            7,
            GATEWAY
        ));
        assert!(server_route_is_stale(
            &[server_route(9, GATEWAY)],
            SERVER,
            7,
            GATEWAY
        ));
    }

    #[test]
    fn replaces_a_missing_or_duplicated_endpoint_route() {
        assert!(server_route_is_stale(&[], SERVER, 7, GATEWAY));
        assert!(server_route_is_stale(
            &[server_route(7, GATEWAY), server_route(9, GATEWAY)],
            SERVER,
            7,
            GATEWAY
        ));
    }

    #[test]
    fn install_only_configures_the_kill_switch() {
        let script = install_script(SERVER, &AppRoutingPolicy::default());
        assert!(script.contains("MouseVPN-KS-v4-"));
        // Addresses, DNS, the interface metric and routes are applied through
        // iphlpapi now, so none of them may reappear in the script.
        assert!(!script.contains("New-NetIPAddress"));
        assert!(!script.contains("New-NetRoute"));
        assert!(!script.contains("Set-DnsClientServerAddress"));
        assert!(!script.contains("Set-NetIPInterface"));
    }

    #[test]
    fn allowlist_firewall_targets_only_selected_programs() {
        let script = firewall_script(
            &AppRoutingPolicy {
                mode: AppRoutingMode::Include,
                apps: vec![PathBuf::from(r"C:\Apps\Mouse's Browser.exe")],
                package_sids: Vec::new(),
            },
            false,
        );
        assert!(script.contains("-Program $app"));
        assert!(script.contains("Mouse''s Browser.exe"));
    }

    #[test]
    fn allowlist_firewall_keeps_dns_client_on_the_tunnel() {
        let script = firewall_script(
            &AppRoutingPolicy {
                mode: AppRoutingMode::Include,
                apps: Vec::new(),
                package_sids: Vec::new(),
            },
            false,
        );
        assert!(script.contains("-Service Dnscache"));
        assert!(script.contains("-dnscache"));
        assert!(!script.contains("-Program 'C:\\Windows\\System32\\svchost.exe'"));
    }

    #[test]
    fn allowlist_firewall_uses_regular_windows_paths() {
        let script = firewall_script(
            &AppRoutingPolicy {
                mode: AppRoutingMode::Include,
                apps: vec![PathBuf::from(r"\\?\C:\Program Files\Browser\browser.exe")],
                package_sids: Vec::new(),
            },
            false,
        );
        assert!(script.contains(r"'C:\Program Files\Browser\browser.exe'"));
        assert!(!script.contains(r"\\?\"));
    }

    #[test]
    fn denylist_firewall_remains_global() {
        let script = firewall_script(&AppRoutingPolicy::default(), false);
        assert!(!script.contains("-Program"));
        assert!(script.contains("MouseVPN-KS-v4-"));
    }

    #[test]
    fn allowlist_firewall_targets_selected_store_packages() {
        let script = firewall_script(
            &AppRoutingPolicy {
                mode: AppRoutingMode::Include,
                apps: Vec::new(),
                package_sids: vec!["S-1-15-2-123".to_owned()],
            },
            false,
        );
        assert!(script.contains("-Package $package"));
        assert!(script.contains("'S-1-15-2-123'"));
    }

    fn contains_any(prefixes: &[String], address: Ipv4Addr) -> bool {
        prefixes.iter().any(|prefix| contains(prefix, address))
    }

    fn contains(prefix: &str, address: Ipv4Addr) -> bool {
        let (network, length) = prefix.split_once('/').expect("CIDR prefix");
        let network = u32::from(network.parse::<Ipv4Addr>().expect("IPv4 network"));
        let length = length.parse::<u32>().expect("prefix length");
        let mask = u32::MAX << (32 - length);
        u32::from(address) & mask == network
    }
}
