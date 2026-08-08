$ErrorActionPreference = "Stop"

$repository = Split-Path -Parent $PSScriptRoot
Push-Location "$PSScriptRoot\src-tauri"
try {
    rustup target add x86_64-pc-windows-msvc
    cargo test -p mousevpn-windows-client
    cargo clippy -p mousevpn-windows-client -p mousevpn-windows-gui --all-targets -- -D warnings
    cargo tauri build --bundles nsis
} finally {
    Pop-Location
}

Write-Host "Installer output: $repository\target\release\bundle\nsis"
