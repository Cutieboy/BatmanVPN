param(
    [switch]$TrustCertificate,
    [string]$CertificateSubject = "CN=MouseVPN Local Driver Test"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Find-MSBuild {
    $command = Get-Command msbuild.exe -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }

    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path -LiteralPath $vswhere) {
        $candidate = & $vswhere -latest -products * -requires Microsoft.Component.MSBuild -find "MSBuild\**\Bin\MSBuild.exe" | Select-Object -First 1
        if ($candidate) {
            return $candidate
        }
    }
    throw "MSBuild was not found. Install Visual Studio 2022 Build Tools, the Desktop C++ workload, and the Windows Driver Kit."
}

function Find-SignTool {
    $kits = "${env:ProgramFiles(x86)}\Windows Kits\10\bin"
    $candidate = Get-ChildItem -LiteralPath $kits -Filter signtool.exe -File -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match "\\x64\\signtool\.exe$" } |
        Sort-Object FullName -Descending |
        Select-Object -First 1
    if (-not $candidate) {
        throw "SignTool was not found. Install the Windows SDK/WDK signing tools."
    }
    return $candidate.FullName
}

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if ($TrustCertificate -and -not (Test-Administrator)) {
    throw "-TrustCertificate must be run from an Administrator PowerShell window."
}

$project = Join-Path $PSScriptRoot "MouseVpnSplitTunnel.vcxproj"
$driver = Join-Path $PSScriptRoot "x64\Release\MouseVpnSplitTunnel.sys"
$distDirectory = Join-Path $PSScriptRoot "dist"
$distDriver = Join-Path $distDirectory "MouseVpnSplitTunnel.sys"
$certificateFile = Join-Path $distDirectory "MouseVpnSplitTunnel-Test.cer"

$msbuild = Find-MSBuild
& $msbuild $project /m /p:Configuration=Release /p:Platform=x64 /p:SignMode=Off
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $driver)) {
    throw "The split-tunnel driver build failed."
}

$now = Get-Date
$certificate = Get-ChildItem Cert:\CurrentUser\My |
    Where-Object { $_.Subject -eq $CertificateSubject -and $_.NotAfter -gt $now.AddDays(30) -and $_.HasPrivateKey } |
    Sort-Object NotAfter -Descending |
    Select-Object -First 1
if (-not $certificate) {
    $certificate = New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject $CertificateSubject `
        -KeyAlgorithm RSA `
        -KeyLength 3072 `
        -HashAlgorithm SHA256 `
        -KeyExportPolicy NonExportable `
        -CertStoreLocation Cert:\CurrentUser\My `
        -NotAfter $now.AddYears(2)
}

New-Item -ItemType Directory -Path $distDirectory -Force | Out-Null
Export-Certificate -Cert $certificate -FilePath $certificateFile -Force | Out-Null
if ($TrustCertificate) {
    foreach ($store in @("Root", "TrustedPublisher")) {
        & certutil.exe -addstore -f $store $certificateFile | Out-Host
        if ($LASTEXITCODE -ne 0) {
            throw "Could not add the test certificate to the LocalMachine $store store."
        }
    }
}

$signTool = Find-SignTool
& $signTool sign /v /fd SHA256 /sha1 $certificate.Thumbprint /s My $driver
if ($LASTEXITCODE -ne 0) {
    throw "SignTool could not sign the split-tunnel driver."
}
if ($TrustCertificate) {
    & $signTool verify /v /pa $driver
    if ($LASTEXITCODE -ne 0) {
        throw "The Authenticode signature check failed."
    }
} else {
    $signature = Get-AuthenticodeSignature -LiteralPath $driver
    if (-not $signature.SignerCertificate -or $signature.SignerCertificate.Thumbprint -ne $certificate.Thumbprint) {
        throw "The driver does not contain the expected test signature."
    }
}

Copy-Item -LiteralPath $driver -Destination $distDriver -Force
Write-Host "Test-signed driver: $distDriver"
Write-Host "Certificate: $certificateFile"
if (-not $TrustCertificate) {
    Write-Warning "The test certificate was not added to LocalMachine trust stores. Re-run from Administrator PowerShell with -TrustCertificate before loading the driver."
}
Write-Host "Windows must also have TESTSIGNING enabled before this test driver can load. See README.md."
