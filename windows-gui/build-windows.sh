#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
target=x86_64-pc-windows-msvc
artifact="$repo_root/target/$target/release/mousevpn-windows-gui.exe"
dist="$repo_root/windows-gui/dist"

if ! cargo xwin --version >/dev/null 2>&1; then
    echo "cargo-xwin is required: cargo install cargo-xwin --locked" >&2
    exit 1
fi

cd "$repo_root"
rustup target add "$target"
cargo xwin build -p mousevpn-windows-gui --target "$target" --release
mkdir -p "$dist"
cp "$artifact" "$dist/MouseVPN-windows-x64.exe"
sha256sum "$dist/MouseVPN-windows-x64.exe"
