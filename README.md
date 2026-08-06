# MouseVPN

Experimental personal VPN protocol and implementation written primarily in
Rust, with Linux and Android clients. It carries IPv4 through an authenticated
encrypted UDP tunnel and supports several independently revocable device keys.

MouseVPN is an early MVP. It has not received an independent security audit and
must not be presented as anonymous, unblockable or production-hardened software.

See [ROADMAP.md](ROADMAP.md) for scope, milestones and acceptance criteria.
The temporary localhost management endpoints are documented in
[docs/ADMIN_API.md](docs/ADMIN_API.md).
Production readiness and draft network policy are tracked in
[docs/PRODUCTION.md](docs/PRODUCTION.md).

## Workspace

- `protocol`: versioned datagrams, session parameters and inner packets;
- `crypto`: Noise IK, X25519, ChaCha20-Poly1305 and replay protection;
- `transport`: UDP transport abstraction;
- `data-plane`: encrypted IPv4 packet and keepalive processing;
- `linux-client` / `linux-platform`: TUN, routing, DNS and kill switch;
- `server`: multi-device Linux TUN/NAT server;
- `android-native`: Rust JNI adapter, keepalive and in-place reconnect;
- `android`: Kotlin `VpnService`, profile manager and Android Keystore storage;
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
