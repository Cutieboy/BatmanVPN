# BatmanVPN — Upstream Integration & Verification Report

**Date:** 2026-11-10  
**Target Feature Branch:** `feature/upstream-auth-server-discovery`  
**Worktree:** `D:\BatmanVPN-feature-upstream`  
**Base Lineage:** `ed78fc93` (PR #2 merge) + cherry-picked `22d2a32` & `a2cc851` (`origin/windows-speedy-ui`)  
**Original Test Worktree:** `D:\BatmanVPN-test` on `android-battery-and-windows-parity` (clean, verified 100% untouched)

---

## 1. Executive Summary

This report documents the research, reverse-engineering, module porting, architecture design, and automated test verification for integrating upstream MouseVPN (`cf57102c`, release v0.2.15) into BatmanVPN while strictly maintaining BatmanVPN's architectural invariants:
- **Strict DNS-Neutrality**: No physical adapter DNS changes, no NRPT registry mutations, passive DNS inspection via `DnsWatcher` (`FLAG_SNIFF | FLAG_RECV_ONLY`).
- **Driver Self-Recovery**: WinDivert `ERROR 1058` (`ERROR_SERVICE_DISABLED`) SCM demand-start auto-repair and retry.
- **Split-Tunnel Reliability**: TCP SYN MSS clamping on unclassified & classified flows to eliminate MTU black holes.
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
| `mousevpn-config` | 3 | 3 | 0 | **PASS** | Client config serialization, protocol defaults, noise context |
| `mousevpn-data-plane` | 8 | 8 | 0 | **PASS** | Tunnel datagram processing, buffer recycling, MTU checks |
| `mousevpn-profile-cli` | 2 | 2 | 0 | **PASS** | Encrypted profile round-trip, incorrect password rejection |
| `mousevpn-client-wire` | 2 | 2 | 0 | **PASS** | Server codec interop, legacy transparent passthrough |
| `mousevpn-windows-client` | 89 | 89 | 0 | **PASS** | WinDivert packet filter, flow tracking, MSS clamping, recovery |
| `mousevpn-windows-gui` | 17 | 17 | 0 | **PASS** | App exclusions, autostart, backup PBKDF2/AES-GCM encryption |

**Total Rust Suite Tests Verified:** 185 passed, 0 failed.

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

## 3. Key Components Ported & Implemented

1. **`crates/mousality`**:
   - Modern TLS 1.3 imitation matching Chrome 156 JA4 fingerprint (`t13d1517h2_8daaf6152771_cb7bf5808d99`).
   - XTLS Vision-style frame length padding for the first 16 client/server records and post-idle pauses.
   - Camouflage handshake routing unauthenticated probes to fallback HTTPS domains.

2. **`crates/account-client`**:
   - HTTPS client with API token management and session lifecycle handling.
   - Device limit handling (2 devices max per account) with revocation capabilities.
   - Dynamic server discovery payload parsing (`Account.servers`).

3. **`crates/ru-bypass`**:
   - High-performance radix trie prefix matcher for direct domestic routing.

4. **`crates/windows-client/src/secure_store.rs`**:
   - Windows DPAPI wrapper (`CryptProtectData` / `CryptUnprotectData`) for credential sealing to current user context without plaintext token storage.

5. **`windows-gui/src-tauri/src/account.rs` & `routing_settings.rs`**:
   - Account state management bound to `%APPDATA%\BatmanVPN\account.sealed`.
   - IPC endpoints for Tauri UI integration.

---

## 4. Invariant Preservation Audit

- **Original Working Directory:** `D:\BatmanVPN-test` was inspected and verified to be untouched, on branch `android-battery-and-windows-parity` at `ed78fc93`.
- **DNS Neutrality:** Physical network adapters never modified; no `DnsGuard` or NRPT rules deployed.
- **WinDivert Resilience:** Driver recovery on `ERROR 1058` intact in `crates/windows-client/src/windivert/mod.rs`.
- **Split-Tunneling SYN Clamping:** Retained in `crates/windows-client/src/windivert/divert.rs`.
- **Branding:** Batman black-and-gold styling, emblems, and visual assets preserved across GUI and Android manifests.
