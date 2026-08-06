# MouseVPN Android

Minimal Android client built around `VpnService` and the shared Rust protocol.

## Build

Requirements are pinned in the project: JDK 17, Android API 36, Android Gradle
Plugin 8.10.1, Gradle 8.11.1 and NDK 27.0.12077973.

```sh
export ANDROID_HOME="$HOME/Android/Sdk"
./gradlew assembleDebug
```

The Gradle build invokes `cargo ndk` and packages Rust libraries for `arm64-v8a`
and `x86_64`. The debug APK is written to
`app/build/outputs/apk/debug/app-debug.apk`.

For an installable internal release build:

```sh
./gradlew assembleRelease lintRelease
```

The APK is written to `app/build/outputs/apk/release/app-release.apk`. Internal
MVP releases use the local Android debug certificate so they can update the
development installation. Create and protect a dedicated release keystore
before any public distribution.

Create an encrypted copy/paste profile from an existing desktop client config:

```sh
cargo run --release -p mousevpn-profile-cli -- \
  --config "$HOME/.config/mousevpn/client.toml" --name "My server"
```

The command asks for a password twice and prints one opaque `MV1.…` token.

## Security model

- The portable `MV1.…` profile string is encrypted with PBKDF2-HMAC-SHA256 and AES-256-GCM.
- Multiple named server profiles, each with independent credentials, are kept in the encrypted catalog.
- The imported profile is encrypted again with an Android Keystore key at rest.
- The private client key is never displayed or written to logs.
- The Android VPN advertises only IPv4. Android blocks the unconfigured IPv6
  family instead of routing it into the IPv4-only Rust core.
- The UDP socket is protected with `VpnService.protect()` before connecting.

This is an experimental MVP. Always-on VPN, network migration, biometric profile
unlock and Play Store packaging remain future work.
