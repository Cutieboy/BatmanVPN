#!/usr/bin/env bash
set -euo pipefail

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
packaging="$repo/packaging/arch"
version=$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$repo/linux-gui/src-tauri/Cargo.toml" | head -n1)
build="$packaging/build"
mkdir -p "$build"
cp "$packaging/PKGBUILD" "$packaging/mousevpn.desktop" "$build/"
sed -i "s/^pkgver=.*/pkgver=$version/" "$build/PKGBUILD"

# Include current tracked sources plus new Rust files and crate manifests, so a
# local feature can be packaged before it is committed. Do not include arbitrary
# untracked TOML files, profiles, keystores or build output.
{
    git -C "$repo" ls-files -z -- Cargo.toml Cargo.lock crates linux-gui windows-gui
    git -C "$repo" ls-files -z --others --exclude-standard -- \
        ':(glob)crates/**/Cargo.toml' ':(glob)crates/**/*.rs'
} |
    tar -C "$repo" --null -T - --transform "s,^,mousevpn-$version/," \
        -czf "$build/mousevpn-$version.tar.gz"

cd "$build"
# Pin the exact local snapshot and desktop entry used for this build.
mapfile -t sums < <(sha256sum "mousevpn-$version.tar.gz" mousevpn.desktop | cut -d ' ' -f1)
sed -i "s/^sha256sums=.*/sha256sums=('${sums[0]}' '${sums[1]}')/" PKGBUILD
makepkg "$@"
