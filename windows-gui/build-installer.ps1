param([switch]$UseTestSignedDriver)

$ErrorActionPreference = "Stop"

$repository = Split-Path -Parent $PSScriptRoot
$driverProject = Join-Path $repository "windows-driver\MouseVpnSplitTunnel.vcxproj"
$driverOutput = Join-Path $repository "windows-driver\x64\Release\MouseVpnSplitTunnel.sys"
$driverDist = Join-Path $repository "windows-driver\dist\MouseVpnSplitTunnel.sys"
$testCertificate = Join-Path $repository "windows-driver\dist\MouseVpnSplitTunnel-Test.cer"
$tauriDirectory = Join-Path $PSScriptRoot "src-tauri"
$generatedHook = Join-Path $tauriDirectory "friend-test-installer.generated.nsh"
$cargoHome = if ($env:CARGO_HOME) { $env:CARGO_HOME } else { Join-Path $env:USERPROFILE ".cargo" }
$cargo = Join-Path $cargoHome "bin\cargo.exe"
$rustup = Join-Path $cargoHome "bin\rustup.exe"
if (-not (Test-Path -LiteralPath $cargo) -or -not (Test-Path -LiteralPath $rustup)) {
    throw "Rustup and Cargo were not found under $cargoHome."
}

if ($UseTestSignedDriver) {
    & "$repository\windows-driver\build-test-signed.ps1"
} else {
    msbuild $driverProject /p:Configuration=Release /p:Platform=x64
    if ($LASTEXITCODE -ne 0) { throw "Split-tunnel driver build failed." }
}
if (-not (Test-Path $driverOutput)) {
    throw "Split-tunnel driver was not produced at $driverOutput"
}
New-Item -ItemType Directory -Path (Split-Path -Parent $driverDist) -Force | Out-Null
Copy-Item $driverOutput $driverDist -Force

$signature = Get-AuthenticodeSignature -LiteralPath $driverDist
if (-not $signature.SignerCertificate) {
    throw "The driver does not contain an Authenticode signature."
}
if ($UseTestSignedDriver) {
    if ($signature.SignerCertificate.Subject -ne "CN=MouseVPN Local Driver Test") {
        throw "The friends-test package must use the dedicated MouseVPN test certificate."
    }
    if (-not (Test-Path -LiteralPath $testCertificate)) {
        throw "The exported MouseVPN test certificate was not found at $testCertificate."
    }

    $hookTemplate = Get-Content -LiteralPath (Join-Path $tauriDirectory "friend-test-installer.nsh.in") -Raw
    $hook = $hookTemplate.Replace("@CERT_THUMBPRINT@", $signature.SignerCertificate.Thumbprint)
    [System.IO.File]::WriteAllText(
        $generatedHook,
        $hook,
        [System.Text.UTF8Encoding]::new($false)
    )
    $bundleConfig = "tauri.friend-test.conf.json"
} else {
    if ($signature.Status -ne "Valid") {
        throw "The release driver signature is not trusted. For local sharing tests, use -UseTestSignedDriver."
    }
    if ($signature.SignerCertificate.Subject -eq "CN=MouseVPN Local Driver Test") {
        throw "Refusing to create a release package with the MouseVPN test certificate."
    }
    $bundleConfig = "tauri.driver.conf.json"
}

$buildStartedAt = Get-Date
Push-Location $tauriDirectory
try {
    & $rustup target add x86_64-pc-windows-msvc
    if ($LASTEXITCODE -ne 0) { throw "Rust target setup failed." }
    & $cargo test -p mousevpn-windows-client
    if ($LASTEXITCODE -ne 0) { throw "Windows client tests failed." }
    & $cargo clippy -p mousevpn-windows-client -p mousevpn-windows-gui --all-targets -- -D warnings
    if ($LASTEXITCODE -ne 0) { throw "Windows Clippy checks failed." }
    & $cargo tauri build --bundles nsis --config $bundleConfig
    if ($LASTEXITCODE -ne 0) { throw "Tauri NSIS build failed." }
} finally {
    Pop-Location
}

$installerDirectory = Join-Path $repository "target\release\bundle\nsis"
$installer = Get-ChildItem -LiteralPath $installerDirectory -Filter "*.exe" -File |
    Where-Object {
        $_.LastWriteTime -ge $buildStartedAt.AddMinutes(-1) -and
        $_.Name -notlike "*-friends-test-setup.exe"
    } |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1
if (-not $installer) {
    throw "The freshly built NSIS installer was not found."
}

if ($UseTestSignedDriver) {
    $signTool = Get-ChildItem -LiteralPath "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Filter signtool.exe -File -Recurse |
        Where-Object { $_.FullName -match "\\x64\\signtool\.exe$" } |
        Sort-Object FullName -Descending |
        Select-Object -First 1
    if (-not $signTool) {
        throw "SignTool was not found."
    }
    & $signTool.FullName sign /fd SHA256 /sha1 $signature.SignerCertificate.Thumbprint /s My $installer.FullName
    if ($LASTEXITCODE -ne 0) { throw "Test-signing the NSIS installer failed." }
    $installerSignature = Get-AuthenticodeSignature -LiteralPath $installer.FullName
    if (-not $installerSignature.SignerCertificate -or
        $installerSignature.SignerCertificate.Thumbprint -ne $signature.SignerCertificate.Thumbprint) {
        throw "The NSIS installer does not contain the expected MouseVPN test signature."
    }

    $appVersion = (Get-Content -LiteralPath (Join-Path $tauriDirectory "tauri.conf.json") -Raw | ConvertFrom-Json).version
    $friendsInstaller = Join-Path $installerDirectory "MouseVPN_${appVersion}_x64-friends-test-setup.exe"
    Copy-Item -LiteralPath $installer.FullName -Destination $friendsInstaller -Force
    $installer = Get-Item -LiteralPath $friendsInstaller
}

Write-Host "Installer: $($installer.FullName)"
