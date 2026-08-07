# MouseVPN for Linux

Desktop client built with Tauri 2 and the existing MouseVPN Rust runtime.

## Current MVP

- imports encrypted `MV1.…` profiles with their password;
- stores one private TOML file per profile under
  `$XDG_CONFIG_HOME/mousevpn/profiles` (or `~/.config/mousevpn/profiles`) with
  mode `0600`;
- selects and deletes profiles;
- connects through a short-lived privileged helper started by PolicyKit;
- disconnects gracefully so the runtime removes its routes, DNS settings and
  isolated nftables table;
- keeps running in the system tray when the main window is closed, with tray
  actions to reopen, disconnect or quit;
- publishes the tray through the freedesktop/KDE StatusNotifier D-Bus protocol,
  so it does not require `libappindicator` at runtime;
- keeps the Tauri webview and profile management unprivileged.
- ships a small standalone privileged helper in the AppImage and copies it to
  the user's private cache before PolicyKit starts it; root never needs to
  execute a binary through the user's FUSE mount.

The helper mode is part of the same executable. The GUI invokes it as:

```text
pkexec mousevpn-linux-gui --helper --config <profile.toml>
```

No password or private key is passed on the command line. PolicyKit elevation
is requested only when the user connects.

## Development build

Tauri uses the system WebKitGTK. On Arch/CachyOS install:

```sh
sudo pacman -S --needed webkit2gtk-4.1 gtk3 base-devel
```

Debian/Ubuntu development packages use the names `libwebkit2gtk-4.1-dev` and
`libgtk-3-dev`. Then build or run from the repository root:

```sh
cargo build -p mousevpn-linux-gui
cargo run -p mousevpn-linux-gui
```

To produce a `.deb` and AppImage compatible with Ubuntu 22.04 and newer from
any Docker host, run:

```sh
./linux-gui/build-ubuntu22.sh
```

The artifacts are written to `linux-gui/dist`. The build deliberately leaves
Wayland client libraries out of the AppImage: they must match the host's EGL
graphics driver. Bundling the Ubuntu copies can make WebKit abort with
`EGL_BAD_PARAMETER` and display a blank window on rolling distributions such
as Arch/CachyOS. It also repacks with the current AppImage runtime, which uses
FUSE 3 and does not require the legacy `libfuse.so.2` compatibility package.

## Runtime support

The current networking backend requires:

- Linux with TUN support;
- `nftables` and `iproute2`;
- `systemd-resolved` with `resolvectl`;
- PolicyKit with `pkexec`;
- WebKitGTK 4.1.

This covers current Arch/CachyOS, Fedora, openSUSE and Debian/Ubuntu systems
configured with `systemd-resolved`. Supporting NetworkManager DNS directly and
non-systemd resolvers is a separate backend task; the GUI must not claim those
systems work until that implementation is tested.

The desktop panel must expose a StatusNotifier host. KDE Plasma, Ubuntu with
its AppIndicator extension, Noctalia and Waybar with the `tray` module provide
one.
