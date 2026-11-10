# BatmanVPN Upstream Integration Plan & Architecture Proposal

## 1. Objectives

Integrate upstream MouseVPN authentication, server discovery, and Mousality 2.0 protocol support into BatmanVPN on branch `feature/upstream-auth-server-discovery` while strictly adhering to:
1. **Preserving BatmanVPN Brand Identity**: Batman black/yellow theme, Bat logo, window sizes, branding names, localized copy.
2. **Preserving BatmanVPN Invariants**:
   - **Strict DNS-Neutrality**: Never modify physical adapter DNS servers (`DnsGuard` and `set_tunnel_dns` remain forbidden). Keep passive DNS sniffing via `DnsWatcher` (`FLAG_SNIFF | FLAG_RECV_ONLY`) on UDP port 53.
   - **WinDivert Driver Recovery (ERROR 1058)**: Retain automatic demand-start repair when WinDivert driver is disabled.
   - **Split-Tunnel TCP SYN MSS Clamping**: Clamp early on unclassified SYNs to eliminate MTU blackholes.
   - **Local LAN Bypass**: Keep RFC1918 / link-local / multicast bypass.
   - **Android Doze & Battery Optimization**: Retain battery saving poller in Android native runtime.
   - **Encrypted Backup & Restore**: Retain PBKDF2 + AES-256-GCM settings backup/restore.

---

## 2. Component Integration Matrix

| Upstream Component | Action for BatmanVPN | Notes |
|---|---|---|
| `crates/account-client` | Vendor / Import | Shared HTTPS client for `/v1/login`, `/v1/account`, `/v1/account/devices`, etc. |
| `crates/mousality` | Vendor / Import | Complete Mousality 2.0 implementation with Chrome 156 JA4 imitation. |
| `crates/ru-bypass` | Vendor / Import | Pre-compiled CIDR trie for Russian direct routing. |
| `crates/transport` | Update | Add `MousalityTransport` and `ClientTransport` enum to handle both UDP and Mousality. |
| `crates/protocol` | Update | Add `ClientCapabilities`, `DirectRoutes`, `InnerPacketKind::DirectRoutes`. |
| `crates/config` | Update | Add `ClientProtocol::Mousality`, `MousalityClientConfig`, `bypass_russia`. |
| `crates/windows-client` | Merge selectively | Add `Mousality` support in handshake/packet loop and capture filter exclusion; DO NOT import `dns_policy.rs` or NRPT/DnsGuard mutations. Keep BatmanVPN's WinDivert recovery and geo-watcher. |
| `windows-gui` | Update | Add Account tab/modal, login/logout, dynamic server selection, and DPAPI-sealed credentials under `%APPDATA%\BatmanVPN\account.sealed`. |
| `android/app` & `crates/android-native` | Update | Integrate `AccountManager`, `VpnProfile` dynamic catalog, and Mousality socket protection while keeping Doze optimization and Batman hero layout. |

---

## 3. Step-by-Step Execution Plan

### Step 1: Core Crates Integration
- Copy `crates/account-client`, `crates/mousality`, and `crates/ru-bypass` from `upstream/main`.
- Update root `Cargo.toml` to declare workspace members.
- Update `crates/config`, `crates/protocol`, and `crates/transport` with Mousality types and `ClientTransport`.

### Step 2: Windows Client Integration
- Update `crates/windows-client/src/handshake.rs` to support `ClientProtocol::Mousality` via `connect_pooled`.
- Update `crates/windows-client/src/windivert/divert.rs` to handle Mousality capture filter exclusion (`tcp and ip.DstAddr != server_ip or tcp.DstPort != 443`).
- Ensure DNS remains passive and untouched.
- Verify WinDivert recovery (`repair_driver_service`) remains fully intact.

### Step 3: Windows GUI Integration
- Implement `windows-gui/src-tauri/src/account.rs` using DPAPI for `BatmanVPN`.
- Expose Tauri commands: `account_view`, `account_login`, `account_logout`, `account_refresh`, `account_revoke_device`.
- Update UI in `linux-gui/ui/` with Batman yellow/black branding for the account/login dialogs.

### Step 4: Verification & Automated Tests
- Run `cargo test` across all modified crates using MSVC environment.
- Run Android unit tests with `gradlew testDebugUnitTest`.
- Record test outcomes in `docs/UPSTREAM_INTEGRATION_TEST_RESULTS.md`.
