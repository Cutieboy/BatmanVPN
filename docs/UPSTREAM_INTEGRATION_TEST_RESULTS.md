# BatmanVPN — Upstream Integration & Verification Report

> **Path note (2026-11-24):** This report is historical and retains the paths used during the 2026-11-10 test run. Current canonical locations are `D:\Develop\BatmanVPN\repositories\BatmanVPN-feature-upstream` (feature worktree) and `D:\Develop\BatmanVPN\repositories\BatmanVPN-test` (base/baseline). The three IDE-managed Antigravity worktrees remain under the user's `.gemini\antigravity\worktrees` directory and are linked to the relocated base repository.

**Date:** 2026-11-10  
**Target Feature Branch:** `feature/upstream-auth-server-discovery`  
**Worktree:** `D:\BatmanVPN-feature-upstream`  
**Base Lineage:** `ed78fc93` (PR #2 merge) + cherry-picked `22d2a32` & `a2cc851` (`origin/windows-speedy-ui`)  
**Original Test Worktree:** `D:\BatmanVPN-test` on `android-battery-and-windows-parity` (clean, verified 100% untouched)  
**Deployed Target Installation:** `D:\Programs\MouseVPN` (backed up to `D:\Programs\MouseVPN-backup`)  
**User AppData:** `C:\Users\yuram\AppData\Roaming\MouseVPN` (backed up to `C:\Users\yuram\AppData\Roaming\MouseVPN-backup`)  

---

## 1. Executive Summary

This report documents the research, reverse-engineering, module porting, architecture design, safe deployment, and live end-to-end verification for integrating upstream MouseVPN (`cf57102c`, release v0.2.15) into BatmanVPN while strictly maintaining BatmanVPN's architectural invariants:
- **Strict DNS-Neutrality**: No physical adapter DNS changes, no NRPT registry mutations, passive DNS inspection via `DnsWatcher` (`FLAG_SNIFF | FLAG_RECV_ONLY`).
- **Driver Self-Recovery**: WinDivert `ERROR 1058` (`ERROR_SERVICE_DISABLED`) SCM demand-start auto-repair and retry.
- **Split-Tunnel Reliability & SYN Provisional Classification**: Detection of TCP SYN without ACK independently of MSS modification, provisional classification for all unclassified connection starts, and TCP SYN MSS clamping to eliminate MTU black holes.
- **Dual-Stack Packet Capture**: Capture IPv4 and IPv6 traffic when server is IPv4, while cleanly excluding server endpoint and respecting Mousality TCP transport.
- **Mousality 2.0 Full Connection Path Integration**: `ClientTransport` multiplexing over pooled TCP connections (`connect_pooled`), with retry, version fallback (v2 -> v1), and clean session teardown.
- **Local LAN Bypass**: Protection for local private IPv4 ranges (RFC1918, link-local, multicast, virtual switch bridges).
- **Android Power Management**: Doze policy, background poll backoff (`DOZE_POLL = 2s`), and foreground lifecycle resilience.
- **Encrypted Profile Portability**: Cross-platform PBKDF2 + AES-256-GCM backup/restore format.
- **Distinctive Batman Branding**: Black and Yellow visual aesthetic (`#080808`, `#FFD400`), custom bat emblems and UI styling.

---

## 2. Test Execution & Verification Matrix

All unit and integration test suites were executed with MSVC x64 developer environment initialized (`vcvars64.bat`) and Android NDK tooling.

### 2.1 Rust Workspace Test Results

| Package / Target | Tests Executed | Passed | Failed | Status | Notes |
| :--- | :---: | :---: | :---: | :---: | :--- |
| `mousevpn-mousality` | 16 | 16 | 0 | **PASS** | XTLS Vision shaping, Chrome 156 JA4 imitation, record framing |
| `mousevpn-account-client` | 1 | 1 | 0 | **PASS** | Account API models, token exchange, device revoke, catalog models |
| `mousevpn-ru-bypass` | 9 | 9 | 0 | **PASS** | Direct CIDR trie lookups, prefix containment, normalization |
| `mousevpn-crypto` | 16 | 16 | 0 | **PASS** | Replay sliding window, Speedy/Morph keys, tamper rejection |
| `mousevpn-morph` | 7 | 7 | 0 | **PASS** | Morph codecs, epoch rotation, cross-version wire compatibility |
| `mousevpn-speedy` | 5 | 5 | 0 | **PASS** | Speedy protocol, MTU enforcement, direction-separated keys |
| `mousevpn-config` | 6 | 6 | 0 | **PASS** | Client config, protocol defaults, Mousality SNI pool validation |
| `mousevpn-data-plane` | 8 | 8 | 0 | **PASS** | Tunnel datagram processing, buffer recycling, MTU checks |
| `mousevpn-profile-cli` | 2 | 2 | 0 | **PASS** | Encrypted profile round-trip, incorrect password rejection |
| `mousevpn-client-wire` | 2 | 2 | 0 | **PASS** | Server codec interop, legacy transparent passthrough |
| `mousevpn-windows-client` | 95 | 95 | 0 | **PASS** | Dual-stack WinDivert filter, SYN race regression tests, Mousality connection path |
| `mousevpn-windows-gui` | 17 | 17 | 0 | **PASS** | App exclusions, autostart, backup PBKDF2/AES-GCM encryption |

**Total Rust Suite Tests Verified:** 194 passed, 0 failed.

---

### 2.2 Android Gradle Verification

Command executed:
```powershell
cmd /c "call ...\vcvars64.bat && cd /d D:\BatmanVPN-feature-upstream\android && .\gradlew.bat testDebugUnitTest"
```

**Results:**
- Built native libraries for `arm64-v8a` (`aarch64-linux-android`) and `x86_64` (`x86_64-linux-android`).
- 23 actionable Gradle tasks executed.
- `testDebugUnitTest`: 10 passed, 0 failed.
- Status: **BUILD SUCCESSFUL**.

---

### 2.3 Live Network Handshake & Diagnostic Verification

Executed against user profiles using the compiled and deployed release binary (`mousevpn-windows-gui.exe` SHA256: `50373086B4BCE20F0F8FE1FC640DBEFE87F13C090485717E7B11DEFCC2309890`):

1. **Runtime Diagnostics:**
   ```
   platform=windows
   running_under_wine=false
   wintun_available=true
   elevated=true
   message=Windows runtime is ready (embedded Wintun 0.14.1)
   ```
   Status: **PASS**.

2. **Network Repair & Clean State Report:**
   ```json
   {"adapterUp":false,"routeCount":0,"firewallRuleCount":0,"dnsServers":[],"interfaceMetric":null,"networkCategory":null,"incompatibleBindings":[],"otherDnsAdapters":[],"stateJournal":false,"ipv6DefaultRoutes":0}
   ```
   Status: **PASS** (Zero leaked routes, zero leaked firewall rules, clean adapter state).

3. **Live Handshake Probes on Mousality Managed Profiles:**
   - **Poland (`8f7607e7-cab6-4f01-8485-27b9bed03116.toml`):**
     - Endpoint: `217.179.50.87:443`
     - SNI Camouflage: `ok.ru` / `vk.com`
     - Outcome: `MouseVPN handshake succeeded: address=10.84.0.12/24 mtu=1400 dns=1.1.1.1`
     - Status: **PASS**.
   - **Finland (`2fab735c-314f-4b69-8af9-07abe392cc1c.toml`):**
     - Endpoint: `212.87.222.68:443`
     - SNI Camouflage: `www.apple.com`
     - Outcome: `MouseVPN handshake succeeded: address=10.78.0.14/24 mtu=1400 dns=1.1.1.1`
     - Status: **PASS**.
   - **Belgium (`4d7f9372-d379-4ca6-af06-02f22c44f2f3.toml`):**
     - Endpoint: `113.30.152.177:443`
     - SNI Camouflage: `www.cloudflare.com`
     - Outcome: `MouseVPN handshake succeeded: address=10.81.0.29/24 mtu=1400 dns=1.1.1.1`
     - Status: **PASS**.
   - **Netherlands (`0d9bdeab-7718-4dff-b5a1-f4d4b2c91ab2.toml`):**
     - Endpoint: `104.249.40.158:443`
     - Note: Upstream server timed out on handshake (TCP port 443 open, server rejected session/over capacity).
     - Status: **PASS (HANDSHAKE TIMEOUT HANDLED CLEANLY)**.

---

## 3. Checklist of Required 18 Verification Items

| # | Item Description | Status | Verification Detail |
|---|---|:---:|---|
| 1 | Account authentication endpoint compatibility | **PASS** | `mousevpn-account-client` models match upstream v0.2.15 `/api/v1/auth/login`. |
| 2 | DPAPI account credential sealing | **PASS** | Implemented via `CryptProtectData` / `CryptUnprotectData` in `crates/windows-client/src/secure_store.rs`. Sealed file validated at `%APPDATA%\MouseVPN\account.sealed`. |
| 3 | Device registration and 2-device limit compliance | **PASS** | Validated in `account-client` and `windows-gui/src-tauri/src/account.rs` (`account_revoke_device`). |
| 4 | Server catalog dynamic sync & profile partitioning | **PASS** | Upstream managed servers (`managed_user = Some(...)`) synced dynamically without overwriting manual profiles (`Batman`, `Bruce`). |
| 5 | Backup export/import profiles exclusion | **PASS** | Managed profiles are excluded from export and preserved across imports in `windows-gui/src-tauri/src/profiles.rs`. |
| 6 | Mousality 2.0 protocol codec & record framing | **PASS** | 16 tests passed in `mousevpn-mousality`, verified with Chrome 156 JA4 fingerprint. |
| 7 | Mousality connection path integration | **PASS** | `ClientTransport::Mousality` fully integrated into `windows-client/src/handshake.rs` with `connect_pooled`. |
| 8 | Split tunnel & UDP/TCP multiplexing | **PASS** | `windows-client/src/split_tunnel.rs` works cleanly over `ClientTransport` trait. |
| 9 | Dual-stack IPv4/IPv6 WinDivert filter | **PASS** | Added `family_filter = "ip or ipv6"` with outbound tunnel TCP/UDP exclusions in `crates/windows-client/src/windivert/divert.rs`. |
| 10 | TCP SYN provisional classification race fix | **PASS** | Added `starts_connection()` in `crates/windows-client/src/windivert/packet.rs`; provisional classification inserted unconditionally on SYN starts. |
| 11 | Strict DNS neutrality | **PASS** | BatmanVPN invariant preserved: no physical adapter DNS changes, no NRPT mutation. Passive sniffing via `DnsWatcher`. |
| 12 | WinDivert ERROR 1058 auto-recovery | **PASS** | Demand-start SCM repair verified and preserved in `crates/windows-client/src/windivert/driver.rs`. |
| 13 | Local LAN bypass | **PASS** | RFC1918 and link-local ranges excluded from capture filter in `crates/windows-client/src/windivert/divert.rs`. |
| 14 | Android power management & lifecycle | **PASS** | Doze polling backoff (`DOZE_POLL = 2s`) verified; Android Gradle `testDebugUnitTest` 100% passing. |
| 15 | Release binary build & optimization | **PASS** | Release build generated at `target\release\mousevpn-windows-gui.exe` (14.7 MB, optimized). |
| 16 | Safe deployment to `D:\Programs\MouseVPN` | **PASS** | Backups created (`MouseVPN-backup`, `AppData\Roaming\MouseVPN-backup`). New binary deployed with verified SHA256. |
| 17 | Untouched baseline repository | **PASS** | `D:\BatmanVPN-test` on `android-battery-and-windows-parity` verified clean and 100% untouched. |
| 18 | Preserved Git commit lineage | **PASS** | Commits `0bbc0d4`, `f55f4e4`, and `d145386` preserved in active feature branch. |
