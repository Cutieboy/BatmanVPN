param(
    [string]$InstallDirectory = "$env:ProgramFiles\MouseVPN"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from an Administrator PowerShell window."
}

$source = Join-Path $PSScriptRoot "dist\MouseVpnSplitTunnel.sys"
$destination = Join-Path $InstallDirectory "MouseVpnSplitTunnel.sys"
if (-not (Test-Path -LiteralPath $source)) {
    throw "The test-signed driver was not found at $source."
}
if (-not (Test-Path -LiteralPath $InstallDirectory)) {
    throw "MouseVPN is not installed at $InstallDirectory."
}

& sc.exe stop MouseVpnSplitTunnel | Out-Host
Start-Sleep -Milliseconds 300

$copied = $false
foreach ($attempt in 1..5) {
    try {
        Copy-Item -LiteralPath $source -Destination $destination -Force
        $copied = $true
        break
    } catch {
        if ($attempt -eq 5) {
            throw
        }
        Start-Sleep -Milliseconds 400
    }
}
if (-not $copied) {
    throw "Could not update the installed MouseVPN driver."
}

$signature = Get-AuthenticodeSignature -LiteralPath $destination
if ($signature.Status -ne "Valid" -or
    $signature.SignerCertificate.Subject -ne "CN=MouseVPN Local Driver Test") {
    throw "The installed driver does not have the expected valid test signature."
}

& sc.exe start MouseVpnSplitTunnel | Out-Host
if ($LASTEXITCODE -ne 0) {
    throw "The updated MouseVPN driver could not be started."
}

Write-Host "Updated and started: $destination"
