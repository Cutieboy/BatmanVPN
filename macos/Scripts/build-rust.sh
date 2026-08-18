#!/bin/sh
set -eu

REPOSITORY_ROOT="${SRCROOT}/.."
OUTPUT_DIRECTORY="${SRCROOT}/Build/rust"
LIBRARIES=""

if [ -d "/usr/local/opt/rustup/bin" ]; then
    PATH="/usr/local/opt/rustup/bin:${PATH}"
    export PATH
elif [ -d "/opt/homebrew/opt/rustup/bin" ]; then
    PATH="/opt/homebrew/opt/rustup/bin:${PATH}"
    export PATH
fi

if ! command -v cargo >/dev/null 2>&1; then
    echo "error: Rust is missing. Install rustup and toolchain 1.97.1 first." >&2
    exit 1
fi

mkdir -p "${OUTPUT_DIRECTORY}"

case "${CONFIGURATION}" in
    Release)
        CARGO_PROFILE="release"
        CARGO_FLAG="--release"
        ;;
    *)
        CARGO_PROFILE="debug"
        CARGO_FLAG=""
        ;;
esac

for ARCHITECTURE in ${ARCHS}; do
    case "${ARCHITECTURE}" in
        arm64) RUST_TARGET="aarch64-apple-darwin" ;;
        x86_64) RUST_TARGET="x86_64-apple-darwin" ;;
        *)
            echo "error: unsupported macOS architecture ${ARCHITECTURE}" >&2
            exit 1
            ;;
    esac

    rustup target add "${RUST_TARGET}"
    cargo build \
        --manifest-path "${REPOSITORY_ROOT}/Cargo.toml" \
        --package mousevpn-apple-native \
        --target "${RUST_TARGET}" \
        ${CARGO_FLAG}
    LIBRARY="${REPOSITORY_ROOT}/target/${RUST_TARGET}/${CARGO_PROFILE}/libmousevpn_apple.a"
    LIBRARIES="${LIBRARIES} ${LIBRARY}"
done

# lipo also accepts one input, which keeps Debug build-active-architecture-only simple.
lipo -create ${LIBRARIES} -output "${OUTPUT_DIRECTORY}/libmousevpn_apple.a"
