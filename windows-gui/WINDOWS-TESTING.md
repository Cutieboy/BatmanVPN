# MouseVPN Windows test checklist

Use a disposable Windows 10/11 VM first, then repeat on the target machine.
The current build is unsigned, so Windows SmartScreen may warn before launch.

## 1. Build or copy the client

On Windows, install Rust and Visual Studio Build Tools with the Desktop C++
workload, then run in an Administrator PowerShell terminal:

```powershell
.\windows-gui\build-installer.ps1
```

For an initial test, the cross-built
`windows-gui\dist\MouseVPN-windows-x64.exe` can be copied directly. Windows 11
normally already contains WebView2. The NSIS installer is the supported route
for a machine where WebView2 is missing.

## 2. Normal connection

1. Start MouseVPN and approve UAC.
2. Import a disposable test profile.
3. Connect and open several IPv4 sites.
4. Confirm that DNS works and the displayed profile remains connected for at
   least five minutes.
5. Disconnect in the UI and confirm ordinary Internet access returns.

Run the automated, non-destructive checks while connected:

```powershell
.\windows-gui\test-windows.ps1
```

The script checks the Wintun adapter, both `/1` routes, firewall rules, tunnel
DNS, interface priority, three consecutive Microsoft Store CDN resolutions,
network category, known conflicting NDIS bindings and direct IPv6 reachability.

## 3. Reconnect

While connected, temporarily disable and re-enable Wi-Fi or unplug/reconnect
Ethernet. MouseVPN should show a reconnecting state and recover without removing
the kill switch. Repeat once while switching from Ethernet to Wi-Fi.

## 4. Controlled crash recovery

Save work and run:

```powershell
.\windows-gui\test-windows.ps1 -TestCrashRecovery
```

This intentionally terminates the privileged helper, verifies that direct
Internet remains blocked, and invokes `--repair-network` in a `finally` block.
If the shell itself is interrupted, repair manually from Administrator
PowerShell:

```powershell
.\windows-gui\dist\MouseVPN-windows-x64.exe --repair-network
```

## 5. Results to send back

Send the console output from `test-windows.ps1`, the Windows version from
`winver`, and whether the connection used Wi-Fi, Ethernet or both. Do not send
an `MV1` profile, password, private key, or the recovery journal from
`%LOCALAPPDATA%\MouseVPN\runtime`.

If the helper exits unexpectedly, also send
`%LOCALAPPDATA%\MouseVPN\logs\helper.log`. It contains state, warning and error
messages but does not record profile contents or keys.
