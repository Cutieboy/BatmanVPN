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
MVP releases use `../mousevpn-android-debug.keystore` (alias `androiddebugkey`,
standard debug store/key password `android`). The project explicitly selects
this certificate instead of a machine-generated key. The owner requested that
this internal key be tracked in Git for repeatable updates. Version 0.1.14 starts
a new signing identity: older APKs signed with the lost key require uninstalling
before installing this APK; preserve VPN configuration keys first.
Create and protect a dedicated release keystore before any public distribution.

Create an encrypted profile key from an existing desktop client config:

```sh
cargo run --release -p mousevpn-profile-cli -- \
  --config "$HOME/.config/mousevpn/client.toml" --name "My server"
```

The command asks for a password twice and prints one opaque `MV1.…` token.
In the Android app, tap `+`, enter that token in the configuration-key field,
and enter its password. The app does not read or write the clipboard itself.

The application-routing screen supports both modes: selected apps can bypass
the VPN, or only selected apps can use it. Search matches both the visible app
name and Android package name; a separate switch shows only selected entries.

## Security model

- The portable `MV1.…` profile string is encrypted with PBKDF2-HMAC-SHA256 and AES-256-GCM.
- Multiple named server profiles, each with independent credentials, are kept in the encrypted catalog.
- The imported profile is encrypted again with an Android Keystore key at rest.
- The private client key is never displayed or written to logs.
- The Android VPN advertises only IPv4. Android blocks the unconfigured IPv6
  family instead of routing it into the IPv4-only Rust core.
- The UDP socket is protected with `VpnService.protect()` before connecting.
- The main screen can run a 30-second TCP port 443 connectivity test against
  Google and YouTube. Its sockets deliberately remain unprotected, so the
  result measures end-to-end traffic through the active tunnel in either
  app-routing mode without presenting TLS setup time as network latency.

This is an experimental MVP. The foreground service follows Android's current
non-VPN network and migrates the protected UDP socket when the device moves
between Wi-Fi and cellular connectivity. Always-on VPN, biometric profile
unlock and Play Store packaging remain future work.
