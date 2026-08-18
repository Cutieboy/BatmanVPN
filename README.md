# MouseVPN

Experimental personal VPN protocol and implementation written primarily in
Rust, with Linux, Android and Windows clients plus a native macOS client in
development. It carries IPv4 through an authenticated
encrypted UDP tunnel and supports several independently revocable device keys.

MouseVPN is an early MVP. It has not received an independent security audit and
must not be presented as anonymous, unblockable or production-hardened software.

See [ROADMAP.md](ROADMAP.md) for scope, milestones and acceptance criteria.
The Russian installation and terminal-client guide is in
[MANUAL.md](MANUAL.md), and the Russian upgrade and rebuild instructions are in
[docs/UPGRADE.md](docs/UPGRADE.md).
The private in-tunnel management UI and API are documented in
[docs/ADMIN_API.md](docs/ADMIN_API.md).
The browser and Telegram SOCKS5 client is documented in
[docs/PROXY_CLIENT.md](docs/PROXY_CLIENT.md).
Production readiness and draft network policy are tracked in
[docs/PRODUCTION.md](docs/PRODUCTION.md).

## Workspace

- `protocol`: versioned datagrams, session parameters and inner packets;
- `crypto`: Noise IK, X25519, ChaCha20-Poly1305 and replay protection;
- `transport`: UDP transport abstraction;
- `data-plane`: encrypted IPv4 packet and keepalive processing;
- `linux-client` / `linux-platform`: TUN, routing, DNS and kill switch;
- `proxy-client`: loopback SOCKS5 client with isolated policy routing;
- `server`: multi-device Linux TUN/NAT server;
- `android-native`: Rust JNI adapter, keepalive and in-place reconnect;
- `android`: Kotlin `VpnService`, profile manager and Android Keystore storage;
- `apple-native`: batched C ABI over the shared handshake and data plane;
- `macos` / `macos-client`: SwiftUI app and a root-owned `utun` helper that
  works without the Network Extension entitlement;
- `device-cli` / `profile-cli`: per-device provisioning and encrypted `MV1.…`
  copy/paste profiles.

The cryptographic design and explicit non-goals are documented in
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) and
[docs/PROTOCOL.md](docs/PROTOCOL.md).

## Development checks

```sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

The Android build instructions are in [android/README.md](android/README.md).
Deployment drafts live under `deploy/`; review and adapt every network and
systemd setting for the target host before use.
