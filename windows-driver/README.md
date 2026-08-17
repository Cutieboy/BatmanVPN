# MouseVPN split-tunnel callout driver

This small Windows Filtering Platform (WFP) callout driver rewrites the local
IPv4 or IPv6 address at the ALE bind-redirection layer for sockets that the
MouseVPN helper places in its dynamic WFP session. The physical adapter address
keeps those sockets on the physical interface while the system-wide `/1`
routes continue to send other traffic through Wintun. The helper can either
redirect selected apps (denylist mode) or redirect everything except selected
apps (allowlist mode).

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

## Local test signing

Use a disposable Windows 10/11 VM first. From Administrator Developer
PowerShell, build and trust a machine-local non-exportable test certificate:

```powershell
.\windows-driver\build-test-signed.ps1 -TrustCertificate
```

Windows will load that driver only in test-signing mode. Secure Boot must be
off; if BitLocker protects the system disk, suspend it before changing Secure
Boot. Enable test signing and reboot:

```powershell
.\windows-driver\set-test-signing.ps1 -Action Enable
Restart-Computer
```

Build the test installer with the signed driver:

```powershell
.\windows-gui\build-installer.ps1 -UseTestSignedDriver
```

After testing, stop/remove the driver service, restore normal signature
enforcement, reboot, and re-enable Secure Boot/BitLocker as appropriate:

```powershell
.\windows-driver\set-test-signing.ps1 -Action Disable
Restart-Computer
```

The implementation follows Microsoft's documented WFP bind-redirection
contract. It does not contain code from another VPN client.
