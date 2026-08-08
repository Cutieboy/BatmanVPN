# MouseVPN for Windows

Native Windows desktop client built with Tauri 2 and the shared MouseVPN Rust
protocol implementation.

## Current development slice

- imports and stores encrypted `MV1.…` profiles under `%APPDATA%\\MouseVPN`;
- performs the MouseVPN UDP/Noise handshake;
- creates a layer-3 adapter through `wintun.dll`;
- configures an IPv4 full tunnel and tunnel DNS with PowerShell;
- installs per-interface Windows Firewall kill-switch rules for IPv4 and IPv6;
- journals every network mutation before applying it and repairs stale state on
  the next launch;
- reconnects timed-out sessions with bounded exponential backoff while leaving
  the kill switch active;
- keeps running in the Windows notification area when its main window is
  closed, with show, connect/disconnect and quit actions;
- starts the tunnel helper and Windows networking commands without visible
  console windows;
- restores firewall rules, routes, the tunnel address and DNS on disconnect;
- provides a non-Windows diagnostic stub so the workspace remains testable on
  Linux and the executable UI can be smoke-tested with Wine.

The Windows networking backend is still an early MVP. Existing adapters are
protected when the tunnel starts; a background policy worker rechecks every 30
seconds and reconnects refresh the physical server route immediately. A custom
Windows Filtering Platform driver would be required to eliminate the remaining
new-adapter hot-plug race completely. Do not treat the client as leak-safe until
the real Windows test matrix in `WINDOWS-TESTING.md` passes.

## Development requirements

- Windows 10 or 11 x64;
- Rust 1.85 or newer with the MSVC target;
- Visual Studio Build Tools with the Desktop C++ workload;
- WebView2 Runtime;
- the official signed x64 Wintun library is embedded into the application;
- an Administrator terminal for tunnel tests.

Run the development application from the repository root:

```powershell
cargo tauri dev --config windows-gui/src-tauri/tauri.conf.json
```

Cross-build a release EXE on Linux with:

```sh
./windows-gui/build-windows.sh
```

The artifact is written to `windows-gui/dist/MouseVPN-windows-x64.exe`.

Release builds contain a `requireAdministrator` application manifest. The
NSIS/MSI configuration downloads the Microsoft WebView2 bootstrapper when the
runtime is missing.

For a headless Wine smoke test that does not initialize WebView2:

```sh
wine mousevpn-windows-gui.exe --diagnose
```

The repeatable wrapper is `./windows-gui/test-wine.sh [path-to-exe]`. Set
`WINE_BIN` when Wine is installed outside `PATH`.

Real Windows build and verification steps are in `WINDOWS-TESTING.md`. The
non-destructive test command is:

```powershell
.\windows-gui\test-windows.ps1
```

Add `-TestCrashRecovery` only in a disposable VM or after saving work. If a
test is interrupted while the kill switch is active, run the EXE with
`--repair-network` from Administrator PowerShell.

Wintun is not available under Wine, and current WebView2 installers are not
reliably compatible with Wine. The supported Wine test is therefore the
headless runtime diagnostic; GUI, tunnel, route, DNS and leak tests require
Windows or a Windows VM.

The bundled Wintun 0.14.1 archive was downloaded from `wintun.net` and checked
against the publisher's SHA-256 value
`07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`.
Its redistribution license is kept at
`crates/windows-client/vendor/wintun/LICENSE.txt`.
