# Upstream MouseVPN Modernization: Authentication, Server Discovery & Protocol Analysis

## Executive Summary

A comprehensive investigation and reverse-engineering of upstream MouseVPN (`https://github.com/Zumka1991/MouseVPN.git`) was conducted against the local BatmanVPN baseline repository (`D:\BatmanVPN-test`). Upstream has evolved from a standalone static-profile VPN to a centralized subscription service powered by `crates/control-plane` and `crates/account-client`, while introducing **Mousality** (a TLS 1.3/Chrome 156-camouflaged TCP VPN transport) and an authenticated dynamic server discovery catalog with strict device-limit quotas (2 devices per account).

---

## 1. Upstream Architecture & Evolution

### 1.1 Commit & Release Baseline
- **Derivation Fork Point (Merge Base):** `7fd4b0d8bc2fc9b3a2bcf19daf1eaf55d725d400` ("*Add Speedy protocol and ship Linux client 0.1.11*").
- **Upstream HEAD:** `cf57102c75f4da63b313c23b7736989ebc0b31f6` ("*Add Linux passwordless auto-connect on startup and Russia bypass toggle*").
- **Key Intermediate Milestones:**
  1. `3c40de2`: Added subscription management, control-plane REST API, account client, billing, support tickets, and desktop/mobile client unification.
  2. `21f4385`: Added the **Mousality** transport crate (`crates/mousality`), server protocol policies, and direct route distribution.
  3. `56ac3a0`: Added **Mousality 2.0** with JA4 Chrome 156 imitation (`testdata/chrome-156-client-hello.bin`), ML-DSA signatures, Trust Anchor IDs extension, and traffic shaping (XTLS Vision style padding).
  4. `6dd568b`: Route Russian networks around the tunnel (`crates/ru-bypass`) across all platforms.
  5. `b8582e5` & `cf57102`: Release Windows 0.2.10, Linux 0.2.7, Android 0.2.15.

---

## 2. Reverse-Engineered Authentication Mechanism

### 2.1 Endpoints & Protocol
All API calls are JSON over HTTPS to the command center (default production URL: `https://ss.libekra.ru/api`, fallback URL: configurable via build option).

1. **Sign-In (`POST /v1/login`)**:
   - **Request Payload:**
     ```json
     {
       "login": "<username>",
       "password": "<plaintext_password>"
     }
     ```
   - **Response Payload:**
     ```json
     {
       "token": "<opaque_bearer_token>",
       "account": {
         "id": "<user_uuid>",
         "login": "<username>",
         "valid_until": 1795000000,
         "active": true,
         "device_limit": 2,
         "devices": [ ... ],
         "servers": [ ... ],
         "unread_messages": 0
       }
     }
     ```
   - **Authentication Scheme:** `Authorization: Bearer <token>` on all subsequent requests.

2. **Device Enrollment (`POST /v1/account/devices`)**:
   - Every client generates a unique X25519 `KeyPair` locally.
   - Request:
     ```json
     {
       "name": "Windows" | "Android" | "<model_name>",
       "platform": "windows" | "android" | "linux",
       "public_key": "<base64_encoded_x25519_public_key>"
     }
     ```
   - Enforces max 2 devices per account (`DEVICE_LIMIT = 2`). If limit is reached, HTTP 409 Conflict is returned: `"Уже зарегистрированы два устройства. Сначала отключите одно из них."`
   - Returns updated `Account` object.

3. **Session Refresh (`GET /v1/account`)**:
   - Authenticated with `Bearer <token>`. Returns fresh `Account` object containing updated `valid_until`, `active` status, `devices`, and server catalog.

4. **Sign-Out (`POST /v1/logout`)**:
   - Invalidates token on control plane. Client drops token and clears account-managed profiles.

5. **Device Revocation (`DELETE /v1/account/devices/{id}`)**:
   - De-registers a device slot.

### 2.2 Security & Storage Model
- **Windows:** Client tokens and device private keys are encrypted on disk using Windows DPAPI (`CryptProtectData` with `CRYPTPROTECT_UI_FORBIDDEN`) at `%APPDATA%\MouseVPN\account.sealed` (for BatmanVPN: `%APPDATA%\BatmanVPN\account.sealed`). In-memory credentials implement `Zeroize`.
- **Android:** Android KeyStore / encrypted SharedPreferences (`ProfileStore`), storing `user_id`, `token`, `public_key`, `private_key`, `base`, and cached `account`.

---

## 3. Dynamic Server Discovery & Configuration

### 3.1 Server Schema in Account Object
The `servers` array returned in `Account` contains dynamic nodes:
```json
{
  "id": "fi-1",
  "name": "Финляндия 1",
  "endpoint": "212.87.222.68:51820",
  "public_key": "vX8r...",
  "protocol": "speedy",
  "allowed_protocols": ["legacy", "speedy", "mousality"],
  "supports_protocol_policy": true,
  "mousality": {
    "endpoint": "212.87.222.68:443",
    "server_names": ["www.microsoft.com", "www.bing.com"]
  },
  "online_devices": 12,
  "online_updated_at": 1762770000
}
```

### 3.2 Dynamic Profile Generation
- Server profiles are generated on the fly from the account catalog.
- If an account expires (`valid_until <= now` or `active == false`) or if the client's public key is not among `account.devices`, the client refuses connection preflight: `"Подписка истекла или доступ отключён. Обновите аккаунт."`
- The client connects using the device's generated X25519 private key. The VPN nodes periodically fetch snapshots (`/v1/node/snapshot`) of allowed device public keys from the control center. Thus, VPN data nodes authenticate the client by its public key in the Noise protocol, without checking user passwords!

---

## 4. The Mousality Protocol (Mousality 2.0)

### 4.1 Architecture & Wire Format
- **Outer Layer:** TCP over port 443. Appears on the wire as TLS 1.3.
- **ClientHello Emulation:** JA4 fingerprint `t13d1517h2_8daaf6152771_cb7bf5808d99` matching Chrome 156.
  - Sends ML-DSA signature algorithms (`0x0904`–`0x0906`) and Trust Anchor IDs extension (`0xca34`).
  - SNI is chosen randomly from `mousality.server_names` pool (e.g. `www.microsoft.com`).
  - Fallback: Unauthenticated connections or scanner probes are transparently forwarded by the node to real benign sites (e.g. Microsoft CDN).
- **Traffic Shaping (XTLS Vision Style):** The first 16 records of a connection and first 8 records after pauses >= 0.5s are padded (records < 900 bytes padded to 900–1399 bytes, larger records get 0–255 random bytes) to disguise nested TLS handshakes.
- **Inner Layer:** Once the outer TLS-like record channel is established, the standard Noise encrypted datagram protocol (with BatmanVPN / MouseVPN headers) runs inside the TCP stream.

---

## 5. Two-Device Quota Mechanism
- Quota enforcement is strictly backend-governed in `crates/control-plane/src/store.rs`:
  ```rust
  if count >= DEVICE_LIMIT { // DEVICE_LIMIT = 2
      return Err(ApiError::conflict("Уже зарегистрированы два устройства. Сначала отключите одно из них."));
  }
  ```
- Client applications inspect `account.devices.len()` and show `"X из 2 устройств"`. If 2 devices are registered and a new device logs in, enrollment fails with 409 Conflict unless the user revokes one of the existing devices via `DELETE /v1/account/devices/{id}`.
