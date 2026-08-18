# MouseVPN for macOS

Native SwiftUI client for macOS 13+. The shipping development scheme does not
use Apple's Network Extension entitlement: the app asks for administrator
authorization and starts a bundled Rust helper that owns an Apple `utun`
interface, routing and DNS configuration.

This is an early implementation and has not received an independent security
audit. It currently imports the same encrypted `MV1.…` profile as Android,
supports full IPv4 routing, DNS replacement, IPv6 bypass blocking, background
operation, multiple profiles, automatic session reconnect and safe route/DNS
rollback on normal termination. Immediate sleep/network-change handling and a
production installer are still pending.

The old `PacketTunnel` sources remain in the repository so the same packet
engine can be returned to `NEPacketTunnelProvider` if an eligible Apple
Developer team becomes available. They are not part of the current Xcode
scheme.

## Prerequisites

- full Xcode selected with `xcode-select`;
- XcodeGen 2.46+;
- rustup and the toolchain pinned by `../rust-toolchain.toml`.

No paid Apple Developer membership or Network Extension entitlement is needed
for a local Debug build.

On an Intel Homebrew installation:

```sh
brew install xcodegen rustup
PATH="/usr/local/opt/rustup/bin:$PATH" rustup toolchain install 1.97.1 \
  --profile minimal --component rustfmt --component clippy
```

Apple Silicon normally uses `/opt/homebrew/opt/rustup/bin` instead.

## Generate and run

```sh
cd macos
xcodegen generate
open MouseVPN.xcodeproj
```

Select the `MouseVPN` scheme and **My Mac**, then press Run. Click **+**, paste
the encrypted `MV1.…` token and enter its profile password once. The password is
stored for that profile in macOS Keychain. Select the imported profile and
press **Подключить**. macOS displays its normal administrator-password dialog.
The helper continues running when the GUI is closed; reopen the app and press
**Отключить** to restore the previous routes and DNS.

Closing the main window leaves MouseVPN available from its menu-bar shield.
The menu shows the current state, switches profiles, connects or disconnects,
and reopens the main window. Closing the window keeps the tunnel running, while
**Завершить MouseVPN** or Command-Q disconnects the helper before the GUI exits.

Runtime files are stored in `~/Library/Application Support/MouseVPN/`:

- `profile.json` — temporary token/password envelope, mode `0600`; the helper
  deletes it immediately after reading;
- `profiles.json` — imported encrypted MV1 tokens and display metadata, mode
  `0600`; passwords are not stored here and live in macOS Keychain instead;
- `state.json` — helper state read by the GUI;
- `helper.pid` — current background process;
- `helper.log` — diagnostics without intentionally logging secret keys.

## Packet path

1. The GUI validates the `MV1.…` envelope and writes a mode-`0600` helper config.
2. The root helper decrypts it with PBKDF2-HMAC-SHA256 and AES-256-GCM, deletes
   the temporary config, then resolves the endpoint and performs Noise IK over
   UDP before changing any routes.
3. It creates and configures `utun`, preserves a direct route to the server,
   installs the two IPv4 full-tunnel routes and replaces DNS.
4. IPv4 packets move between `utun` and the shared Rust encryption/data plane.
5. Two more-specific IPv6 routes send IPv6 into `utun`, where it is dropped
   because protocol v1 carries IPv4 only. This prevents IPv6 bypass.
6. SIGTERM, Ctrl+C and normal failures drop the guards that restore DNS and
   remove only the routes installed by MouseVPN.

## Local checks

```sh
PATH="/usr/local/opt/rustup/bin:$PATH" cargo fmt --all -- --check
PATH="/usr/local/opt/rustup/bin:$PATH" cargo clippy \
  --package mousevpn-macos-client --all-targets -- -D warnings
PATH="/usr/local/opt/rustup/bin:$PATH" cargo test \
  --package mousevpn-macos-client --package mousevpn-apple-native
xcodegen generate
xcodebuild -project MouseVPN.xcodeproj -scheme MouseVPN build
```

Direct distribution to other Macs without a Developer ID is possible only with
manual Gatekeeper approval. A friendly signed/notarized installer remains a
separate release task.
