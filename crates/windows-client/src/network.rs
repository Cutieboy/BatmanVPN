#![cfg_attr(not(windows), allow(dead_code))]

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    net::{Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex},
};

use fs2::FileExt;
use mousevpn_protocol::SessionParameters;
use serde::{Deserialize, Serialize};

use crate::{
    app_bypass::{AppBypassGuard, AppBypassRefresher},
    AppRoutingMode, AppRoutingPolicy, ClientError,
};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

pub(crate) const ADAPTER_NAME: &str = "MouseVPN";
const FIREWALL_GROUP: &str = "MouseVPN Kill Switch";
const ROUTE_METRIC: u16 = 4242;
const STATE_FILE: &str = "network-state.toml";
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

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
        let prefixes = blocked_ipv4_prefixes(server_ip).join("','");
        let firewall = firewall_script(app_routing, false);
        let script = format!(
            "$ErrorActionPreference='Stop'; \
             $vpn=Get-NetAdapter -Name '{ADAPTER_NAME}' -ErrorAction Stop; \
             $blocked=@('{prefixes}'); \
             $physical=Get-NetAdapter | Where-Object {{$_.Name -ne '{ADAPTER_NAME}' -and $_.InterfaceDescription -notmatch 'Loopback'}}; \
             {firewall}; \
             $up=@(Get-NetAdapter | Where-Object {{$_.Status -eq 'Up'}}).ifIndex; \
             $default=Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' | Where-Object {{$_.NextHop -ne '0.0.0.0' -and $_.InterfaceIndex -ne $vpn.ifIndex -and $up -contains $_.InterfaceIndex}} | Sort-Object RouteMetric | Select-Object -First 1; \
             if (-not $default) {{ throw 'No active physical IPv4 default route found' }}; \
             Get-NetIPAddress -InterfaceIndex $vpn.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false; \
             Set-NetIPInterface -InterfaceIndex $vpn.ifIndex -AddressFamily IPv4 -AutomaticMetric Disabled -InterfaceMetric 1; \
             New-NetIPAddress -InterfaceIndex $vpn.ifIndex -IPAddress '{}' -PrefixLength {} | Out-Null; \
             try {{ \
               $profile=Get-NetConnectionProfile -InterfaceIndex $vpn.ifIndex -ErrorAction SilentlyContinue; \
               if ($profile -and $profile.NetworkCategory -ne 'Public') {{Set-NetConnectionProfile -InterfaceIndex $vpn.ifIndex -NetworkCategory Public -ErrorAction Stop}} \
             }} catch {{Write-Warning ('Could not mark MouseVPN as a Public network: '+$_.Exception.Message)}}; \
             Set-DnsClientServerAddress -InterfaceIndex $vpn.ifIndex -ServerAddresses '{}'; \
             New-NetRoute -DestinationPrefix '{server_ip}/32' -InterfaceIndex $default.InterfaceIndex -NextHop $default.NextHop -RouteMetric {ROUTE_METRIC} -Protocol NetMgmt -PolicyStore ActiveStore | Out-Null; \
             New-NetRoute -DestinationPrefix '0.0.0.0/1' -InterfaceIndex $vpn.ifIndex -NextHop '0.0.0.0' -RouteMetric {ROUTE_METRIC} -Protocol NetMgmt -PolicyStore ActiveStore | Out-Null; \
             New-NetRoute -DestinationPrefix '128.0.0.0/1' -InterfaceIndex $vpn.ifIndex -NextHop '0.0.0.0' -RouteMetric {ROUTE_METRIC} -Protocol NetMgmt -PolicyStore ActiveStore | Out-Null; \
             Write-Output 'MouseVPN network policy installed for {server_ip}:{server_port}'",
            parameters.client_address,
            parameters.prefix_len,
            parameters.dns,
        );
        if let Err(error) = run_powershell(&script, "install the Windows network policy") {
            if cleanup(Some(server_ip)).is_ok() {
                let _ = fs::remove_file(&state_path);
            }
            return Err(error);
        }
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
        let previous = self.parameters;
        let script = format!(
            "$ErrorActionPreference='Stop'; \
             $vpn=Get-NetAdapter -Name '{ADAPTER_NAME}' -ErrorAction Stop; \
             try {{ \
               Get-NetIPAddress -InterfaceIndex $vpn.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false -ErrorAction Stop; \
               New-NetIPAddress -InterfaceIndex $vpn.ifIndex -IPAddress '{}' -PrefixLength {} -ErrorAction Stop | Out-Null; \
               Set-DnsClientServerAddress -InterfaceIndex $vpn.ifIndex -ServerAddresses '{}' -ErrorAction Stop \
             }} catch {{ \
               $applyError=$_.Exception.Message; \
               Get-NetIPAddress -InterfaceIndex $vpn.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue; \
               New-NetIPAddress -InterfaceIndex $vpn.ifIndex -IPAddress '{}' -PrefixLength {} -ErrorAction Stop | Out-Null; \
               Set-DnsClientServerAddress -InterfaceIndex $vpn.ifIndex -ServerAddresses '{}' -ErrorAction Stop; \
               throw ('updating MouseVPN session parameters failed: '+$applyError) \
             }}",
            parameters.client_address,
            parameters.prefix_len,
            parameters.dns,
            previous.client_address,
            previous.prefix_len,
            previous.dns,
        );
        run_powershell(&script, "update the Windows tunnel parameters")?;
        self.parameters = parameters;
        Ok(())
    }

    pub(crate) fn refresh(&self) -> Result<(), ClientError> {
        NetworkRefresher {
            server_ip: self.state.server_ip,
            refresh_lock: Arc::clone(&self.refresh_lock),
            app_routing: self.app_routing.clone(),
            app_bypass: self.app_bypass.as_ref().map(AppBypassGuard::refresher),
        }
        .refresh()
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
             {firewall}; \
             $up=@(Get-NetAdapter | Where-Object {{$_.Status -eq 'Up'}}).ifIndex; \
             $default=Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' | Where-Object {{$_.NextHop -ne '0.0.0.0' -and $_.InterfaceIndex -ne $vpn.ifIndex -and $up -contains $_.InterfaceIndex}} | Sort-Object RouteMetric | Select-Object -First 1; \
             if (-not $default) {{ throw 'No active physical IPv4 default route found' }}; \
             $serverRoutes=@(Get-NetRoute -DestinationPrefix '{server_ip}/32' -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Where-Object {{$_.RouteMetric -eq {ROUTE_METRIC} -and $_.Protocol -eq 'NetMgmt'}}); \
             $routeMatches=@($serverRoutes | Where-Object {{$_.InterfaceIndex -eq $default.InterfaceIndex -and $_.NextHop -eq $default.NextHop}}); \
             if ($serverRoutes.Count -ne 1 -or $routeMatches.Count -ne 1) {{ \
               if ($serverRoutes.Count -gt 0) {{$serverRoutes | Remove-NetRoute -Confirm:$false -ErrorAction Stop}}; \
               New-NetRoute -DestinationPrefix '{server_ip}/32' -InterfaceIndex $default.InterfaceIndex -NextHop $default.NextHop -RouteMetric {ROUTE_METRIC} -Protocol NetMgmt -PolicyStore ActiveStore | Out-Null \
             }}"
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
                "$vpnApps=@({apps}); $vpnPackages=@({packages}); foreach ($adapter in $physical) {{ $i=0; foreach ($app in $vpnApps) {{ $name=('MouseVPN-KS-v4-'+$adapter.ifIndex+'-'+$i); {guard} {{ try {{ New-NetFirewallRule -Name $name -DisplayName ('MouseVPN selected app kill switch IPv4 '+$adapter.Name) -Group '{FIREWALL_GROUP}' -Direction Outbound -Action Block -Enabled True -Profile Any -InterfaceAlias $adapter.Name -Program $app -RemoteAddress $blocked | Out-Null }} catch {{ throw ('Selected-app IPv4 firewall rule failed for '+$app+': '+$_.Exception.Message) }} }}; $name=('MouseVPN-KS-v6-'+$adapter.ifIndex+'-'+$i); {guard} {{ try {{ New-NetFirewallRule -Name $name -DisplayName ('MouseVPN selected app kill switch IPv6 '+$adapter.Name) -Group '{FIREWALL_GROUP}' -Direction Outbound -Action Block -Enabled True -Profile Any -InterfaceAlias $adapter.Name -Program $app -RemoteAddress 'Internet6' | Out-Null }} catch {{ throw ('Selected-app IPv6 firewall rule failed for '+$app+': '+$_.Exception.Message) }} }}; $i++ }}; foreach ($package in $vpnPackages) {{ $name=('MouseVPN-KS-v4-'+$adapter.ifIndex+'-package-'+$i); {guard} {{ try {{ New-NetFirewallRule -Name $name -DisplayName ('MouseVPN selected package kill switch IPv4 '+$adapter.Name) -Group '{FIREWALL_GROUP}' -Direction Outbound -Action Block -Enabled True -Profile Any -InterfaceAlias $adapter.Name -Package $package -RemoteAddress $blocked | Out-Null }} catch {{ throw ('Selected-package IPv4 firewall rule failed for '+$package+': '+$_.Exception.Message) }} }}; $name=('MouseVPN-KS-v6-'+$adapter.ifIndex+'-package-'+$i); {guard} {{ try {{ New-NetFirewallRule -Name $name -DisplayName ('MouseVPN selected package kill switch IPv6 '+$adapter.Name) -Group '{FIREWALL_GROUP}' -Direction Outbound -Action Block -Enabled True -Profile Any -InterfaceAlias $adapter.Name -Package $package -RemoteAddress 'Internet6' | Out-Null }} catch {{ throw ('Selected-package IPv6 firewall rule failed for '+$package+': '+$_.Exception.Message) }} }}; $i++ }} }}"
            )
        }
    }
}

impl Drop for NetworkGuard {
    fn drop(&mut self) {
        if cleanup(Some(self.state.server_ip)).is_ok() {
            let _ = fs::remove_file(&self.state_path);
        }
    }
}

pub(crate) fn recover_stale_state() -> Result<(), ClientError> {
    let path = state_path()?;
    if !path.exists() {
        cleanup(None)?;
        return Ok(());
    }
    let state = fs::read_to_string(&path)
        .ok()
        .and_then(|contents| toml::from_str::<RecoveryState>(&contents).ok());
    cleanup(state.map(|value| value.server_ip))?;
    fs::remove_file(path)?;
    Ok(())
}

pub(crate) fn repair() -> Result<(), ClientError> {
    let path = state_path()?;
    let state = fs::read_to_string(&path)
        .ok()
        .and_then(|contents| toml::from_str::<RecoveryState>(&contents).ok());
    cleanup(state.map(|value| value.server_ip))?;
    match fs::remove_file(path) {
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

fn cleanup(server_ip: Option<Ipv4Addr>) -> Result<(), ClientError> {
    let server_cleanup = server_ip.map_or_else(
        String::new,
        |address| {
            format!(
                "$serverRoutes=@(Get-NetRoute -DestinationPrefix '{address}/32' -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Where-Object {{$_.RouteMetric -eq {ROUTE_METRIC} -and $_.Protocol -eq 'NetMgmt'}}); \
                 if ($serverRoutes.Count -gt 0) {{ Invoke-MouseVpnCleanup {{$serverRoutes | Remove-NetRoute -Confirm:$false -ErrorAction Stop}} }};"
            )
        },
    );
    let script = format!(
        "$ErrorActionPreference='Stop'; \
         $cleanupErrors=New-Object System.Collections.Generic.List[string]; \
         function Invoke-MouseVpnCleanup([scriptblock]$action) {{ \
           try {{ & $action }} catch {{ $cleanupErrors.Add($_.Exception.Message) }} \
         }}; \
         $vpn=Get-NetAdapter -Name '{ADAPTER_NAME}' -ErrorAction SilentlyContinue; \
         if ($vpn) {{ \
           $vpnRoutes=@(Get-NetRoute -InterfaceIndex $vpn.ifIndex -DestinationPrefix '0.0.0.0/1','128.0.0.0/1' -ErrorAction SilentlyContinue | Where-Object {{$_.RouteMetric -eq {ROUTE_METRIC}}}); \
           if ($vpnRoutes.Count -gt 0) {{ Invoke-MouseVpnCleanup {{$vpnRoutes | Remove-NetRoute -Confirm:$false -ErrorAction Stop}} }}; \
           Invoke-MouseVpnCleanup {{Reset-DnsClientServerAddress -InterfaceIndex $vpn.ifIndex -ErrorAction Stop}}; \
           Invoke-MouseVpnCleanup {{Set-NetIPInterface -InterfaceIndex $vpn.ifIndex -AddressFamily IPv4 -AutomaticMetric Enabled -ErrorAction Stop}}; \
           $vpnAddresses=@(Get-NetIPAddress -InterfaceIndex $vpn.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue); \
           if ($vpnAddresses.Count -gt 0) {{ Invoke-MouseVpnCleanup {{$vpnAddresses | Remove-NetIPAddress -Confirm:$false -ErrorAction Stop}} }} \
         }}; \
         {server_cleanup} \
         $firewallRules=@(Get-NetFirewallRule -Group '{FIREWALL_GROUP}' -ErrorAction SilentlyContinue); \
         if ($firewallRules.Count -gt 0) {{ Invoke-MouseVpnCleanup {{$firewallRules | Remove-NetFirewallRule -ErrorAction Stop}} }}; \
         if ($cleanupErrors.Count -gt 0) {{ throw ($cleanupErrors -join '; ') }}; \
         exit 0"
    );
    run_powershell(&script, "clean up the Windows network policy")
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
    #[cfg(windows)]
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PhysicalAddresses {
    pub(crate) ipv4: Ipv4Addr,
    pub(crate) ipv6: Option<Ipv6Addr>,
}

pub(crate) fn physical_addresses() -> Result<PhysicalAddresses, ClientError> {
    let output = run_powershell_output(
        "$vpn=Get-NetAdapter -Name 'MouseVPN' -ErrorAction SilentlyContinue; \
         $up=@(Get-NetAdapter | Where-Object {$_.Status -eq 'Up'}).ifIndex; \
         $default=Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' | \
           Where-Object {$_.NextHop -ne '0.0.0.0' -and (!$vpn -or $_.InterfaceIndex -ne $vpn.ifIndex) -and $up -contains $_.InterfaceIndex} | \
           Sort-Object RouteMetric | Select-Object -First 1; \
         if (-not $default) {throw 'No active physical IPv4 default route found'}; \
         $address=Get-NetIPAddress -InterfaceIndex $default.InterfaceIndex -AddressFamily IPv4 | \
           Where-Object {$_.AddressState -eq 'Preferred' -and -not $_.SkipAsSource} | \
           Select-Object -First 1 -ExpandProperty IPAddress; \
         if (-not $address) {throw 'No preferred physical IPv4 address found'}; \
         Write-Output ('IPv4='+$address); \
         $default6=Get-NetRoute -AddressFamily IPv6 -DestinationPrefix '::/0' -ErrorAction SilentlyContinue | \
           Where-Object {$_.NextHop -ne '::' -and (!$vpn -or $_.InterfaceIndex -ne $vpn.ifIndex) -and $up -contains $_.InterfaceIndex} | \
           Sort-Object RouteMetric | Select-Object -First 1; \
         if ($default6) { \
           $address6=Get-NetIPAddress -InterfaceIndex $default6.InterfaceIndex -AddressFamily IPv6 | \
             Where-Object {$_.AddressState -eq 'Preferred' -and -not $_.SkipAsSource -and $_.IPAddress -notlike 'fe80:*'} | \
             Select-Object -First 1 -ExpandProperty IPAddress; \
           if ($address6) {Write-Output ('IPv6='+$address6)} \
         }",
        "discover the physical IP addresses",
    )?;
    parse_physical_addresses(&output)
}

fn parse_physical_addresses(output: &str) -> Result<PhysicalAddresses, ClientError> {
    let ipv4 = output
        .lines()
        .find_map(|line| line.strip_prefix("IPv4="))
        .ok_or_else(|| {
            ClientError::Platform("Windows returned no physical IPv4 address".to_owned())
        })?;
    let ipv4 = ipv4.parse().map_err(|error| {
        ClientError::Platform(format!(
            "invalid physical IPv4 address returned by Windows ({ipv4}): {error}"
        ))
    })?;
    let ipv6 = output
        .lines()
        .find_map(|line| line.strip_prefix("IPv6="))
        .map(str::parse)
        .transpose()
        .map_err(|error| {
            ClientError::Platform(format!(
                "invalid physical IPv6 address returned by Windows: {error}"
            ))
        })?;
    Ok(PhysicalAddresses { ipv4, ipv6 })
}

#[cfg(test)]
mod tests {
    use super::{
        blocked_ipv4_prefixes, firewall_script, parse_physical_addresses, refresh_script,
        PhysicalAddresses,
    };
    use crate::{AppRoutingMode, AppRoutingPolicy};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::path::PathBuf;

    #[test]
    fn emits_valid_cidr_prefixes_that_exclude_the_server() {
        let server = Ipv4Addr::new(203, 0, 113, 10);
        let prefixes = blocked_ipv4_prefixes(server);
        assert_eq!(prefixes.len(), 32);
        assert!(prefixes.iter().all(|prefix| !contains(prefix, server)));
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
    fn refresh_only_replaces_a_stale_server_route() {
        let script = refresh_script(
            Ipv4Addr::new(203, 0, 113, 10),
            &crate::AppRoutingPolicy::default(),
        );
        assert!(script.contains("$serverRoutes.Count -ne 1 -or $routeMatches.Count -ne 1"));
        assert!(script.contains("if ($serverRoutes.Count -gt 0)"));
    }

    #[test]
    fn parses_dual_stack_physical_addresses() {
        assert_eq!(
            parse_physical_addresses("IPv4=192.168.1.20\r\nIPv6=2001:db8::20").unwrap(),
            PhysicalAddresses {
                ipv4: Ipv4Addr::new(192, 168, 1, 20),
                ipv6: Some("2001:db8::20".parse::<Ipv6Addr>().unwrap()),
            }
        );
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
