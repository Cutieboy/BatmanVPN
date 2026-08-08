# MouseVPN split-tunnel callout driver

This small Windows Filtering Platform (WFP) callout driver rewrites the local
IPv4 or IPv6 address selected for connections that the MouseVPN helper places
in its dynamic WFP session. The physical adapter address forces those sockets
to stay on the physical interface while the system-wide `/1` routes continue
to send traffic through Wintun. The helper can either redirect selected apps
(denylist mode) or redirect everything except selected apps (allowlist mode).

The driver is deliberately policy-free: application paths and the physical
address live only in the helper's dynamic WFP session and disappear if the
helper exits. With no matching WFP filters loaded, the driver does nothing.

## Build

Install Visual Studio 2022 with the Desktop C++ workload and the Windows 11
SDK/WDK, then run from an Administrator Developer PowerShell:

```powershell
msbuild .\windows-driver\MouseVpnSplitTunnel.vcxproj /p:Configuration=Release /p:Platform=x64
```

Copy the resulting `MouseVpnSplitTunnel.sys` next to the MouseVPN executable.
The helper loads it on demand when application routing needs a bypass: for one
or more exclusions, or whenever allowlist mode is active.

Windows requires production kernel drivers to be signed. Local VM testing can
use a test certificate and test-signing mode; release packages must use a
Microsoft-attested or WHQL-signed catalog. Never disable signature enforcement
on an end-user machine.

The implementation follows Microsoft's documented WFP bind/connect redirection
contract. It does not contain code from another VPN client.
