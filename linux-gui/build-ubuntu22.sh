#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd -- "$script_dir/.." && pwd)"
image_name="mousevpn-tauri-ubuntu22"
target_volume="mousevpn-ubuntu22-target"
build_network="${MOUSEVPN_BUILD_NETWORK:-default}"
run_network="${MOUSEVPN_RUN_NETWORK:-bridge}"

docker build --network "$build_network" -t "$image_name" -f "$script_dir/Dockerfile.ubuntu22" "$repo_dir"
docker volume create "$target_volume" >/dev/null

docker run --rm \
  --network "$run_network" \
  -e APPIMAGE_EXTRACT_AND_RUN=1 \
  -e CARGO_TARGET_DIR=/build/target \
  -e CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}" \
  -v "$repo_dir:/workspace" \
  -v "$target_volume:/build/target" \
  "$image_name" bash -lc '
    set -euo pipefail
    # Invoke the toolchain installed in the image directly. Going through the
    # rustup shim performs a network update check on every fresh container and
    # can stall an otherwise fully cached, reproducible build.
    export PATH=/root/.rustup/toolchains/1.97.1-x86_64-unknown-linux-gnu/bin:$PATH
    cd /workspace/linux-gui/src-tauri
    cargo build --release --bin mousevpn-helper
    cargo tauri build --bundles deb,appimage

    version="$(sed -n '\''s/^[[:space:]]*"version": "\([^"]*\)",/\1/p'\'' tauri.conf.json)"
    test -n "$version"
    appdir=/build/target/release/bundle/appimage/MouseVPN.AppDir
    output="/build/target/release/bundle/appimage/MouseVPN_${version}_amd64.AppImage"
    tool=/build/target/.tools/appimagetool-modern-x86_64.AppImage

    # libEGL is supplied by the host graphics driver. Bundling Ubuntu libwayland
    # beside it creates an incompatible EGL/Wayland pair on rolling distros and
    # makes WebKitWebProcess abort, leaving a blank Tauri window.
    rm -f \
      "$appdir/usr/lib/libwayland-client.so.0" \
      "$appdir/usr/lib/libwayland-cursor.so.0" \
      "$appdir/usr/lib/libwayland-egl.so.1" \
      "$appdir/usr/lib/libwayland-server.so.0"

    install -D -m 0755 /build/target/release/mousevpn-helper \
      "$appdir/usr/lib/mousevpn/mousevpn-helper"

    mkdir -p "$(dirname "$tool")"
    if [[ ! -x "$tool" ]]; then
      curl -fsSL \
        https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage \
        -o "$tool"
      chmod +x "$tool"
    fi

    ARCH=x86_64 APPIMAGE_EXTRACT_AND_RUN=1 "$tool" "$appdir" "$output"

    install -m 0755 "$output" \
      "/workspace/linux-gui/dist/MouseVPN_${version}_ubuntu22_amd64.AppImage"
    install -m 0644 \
      "/build/target/release/bundle/deb/MouseVPN_${version}_amd64.deb" \
      "/workspace/linux-gui/dist/MouseVPN_${version}_ubuntu22_amd64.deb"
    chown "$(stat -c %u /workspace):$(stat -c %g /workspace)" \
      "/workspace/linux-gui/dist/MouseVPN_${version}_ubuntu22_amd64.AppImage" \
      "/workspace/linux-gui/dist/MouseVPN_${version}_ubuntu22_amd64.deb"
  '
