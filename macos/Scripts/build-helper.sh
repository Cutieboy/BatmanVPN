#!/bin/sh
set -eu

PROJECT_ROOT="$(cd "${SRCROOT}/.." && pwd)"
RUST_BIN="/usr/local/opt/rustup/bin"
if [ ! -x "${RUST_BIN}/cargo" ]; then
    RUST_BIN="${HOME}/.cargo/bin"
fi
if [ ! -x "${RUST_BIN}/cargo" ]; then
    echo "error: Rust cargo was not found. Install rustup first." >&2
    exit 1
fi

BUILD_ARGUMENTS=""
RUST_CONFIGURATION="debug"
if [ "${CONFIGURATION}" = "Release" ]; then
    BUILD_ARGUMENTS="--release"
    RUST_CONFIGURATION="release"
fi

PATH="${RUST_BIN}:${PATH}" "${RUST_BIN}/cargo" build \
    --manifest-path "${PROJECT_ROOT}/Cargo.toml" \
    --package mousevpn-macos-client \
    ${BUILD_ARGUMENTS}

DESTINATION_DIRECTORY="${SRCROOT}/Build/helper"
DESTINATION="${DESTINATION_DIRECTORY}/mousevpn-macos-helper"
/bin/mkdir -p "${DESTINATION_DIRECTORY}"
/bin/cp "${PROJECT_ROOT}/target/${RUST_CONFIGURATION}/mousevpn-macos-helper" "${DESTINATION}"
/bin/chmod 755 "${DESTINATION}"

if [ -n "${EXPANDED_CODE_SIGN_IDENTITY:-}" ]; then
    /usr/bin/codesign --force --options runtime --sign "${EXPANDED_CODE_SIGN_IDENTITY}" "${DESTINATION}"
else
    /usr/bin/codesign --force --sign - "${DESTINATION}"
fi
