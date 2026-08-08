$ErrorActionPreference = "Stop"

$repository = Split-Path -Parent $PSScriptRoot
$driverProject = Join-Path $repository "windows-driver\MouseVpnSplitTunnel.vcxproj"
$driverOutput = Join-Path $repository "windows-driver\x64\Release\MouseVpnSplitTunnel.sys"
$driverDist = Join-Path $repository "windows-driver\dist\MouseVpnSplitTunnel.sys"

msbuild $driverProject /p:Configuration=Release /p:Platform=x64
if (-not (Test-Path $driverOutput)) {
    throw "Split-tunnel driver was not produced at $driverOutput"
}
Copy-Item $driverOutput $driverDist -Force

Push-Location "$PSScriptRoot\src-tauri"
try {
    $env:TAURI_CONFIG = '{"bundle":{"resources":{"../../windows-driver/dist/*.sys":"."}}}'
    rustup target add x86_64-pc-windows-msvc
    cargo test -p mousevpn-windows-client
    cargo clippy -p mousevpn-windows-client -p mousevpn-windows-gui --all-targets -- -D warnings
    cargo tauri build --bundles nsis
} finally {
    Remove-Item Env:TAURI_CONFIG -ErrorAction SilentlyContinue
    Pop-Location
}

Write-Host "Installer output: $repository\target\release\bundle\nsis"
