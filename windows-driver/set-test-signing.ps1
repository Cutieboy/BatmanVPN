param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Status", "Enable", "Disable")]
    [string]$Action
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if ($Action -eq "Status") {
    try {
        Write-Host "Secure Boot: $(Confirm-SecureBootUEFI)"
    } catch {
        Write-Host "Secure Boot status is unavailable: $($_.Exception.Message)"
    }
    & bcdedit.exe /enum "{current}"
    exit $LASTEXITCODE
}

if (-not (Test-Administrator)) {
    throw "Run this command from an Administrator PowerShell window."
}

if ($Action -eq "Enable") {
    try {
        if (Confirm-SecureBootUEFI) {
            throw "Secure Boot is enabled. Suspend BitLocker first, disable Secure Boot in UEFI, then run this command again."
        }
    } catch [System.PlatformNotSupportedException] {
        # Legacy BIOS has no Secure Boot state to check.
    }
    & bcdedit.exe /set testsigning on
    if ($LASTEXITCODE -ne 0) {
        throw "BCDEdit could not enable TESTSIGNING."
    }
    Write-Warning "TESTSIGNING is enabled for the next boot. Restart Windows before loading the test driver."
    exit 0
}

& sc.exe stop MouseVpnSplitTunnel | Out-Host
& sc.exe delete MouseVpnSplitTunnel | Out-Host
& bcdedit.exe /set testsigning off
if ($LASTEXITCODE -ne 0) {
    throw "BCDEdit could not disable TESTSIGNING."
}
foreach ($store in @("Root", "TrustedPublisher")) {
    $certificates = Get-ChildItem -LiteralPath "Cert:\LocalMachine\$store" |
        Where-Object Subject -eq "CN=MouseVPN Local Driver Test"
    foreach ($certificate in $certificates) {
        & certutil.exe -delstore $store $certificate.Thumbprint | Out-Host
        if ($LASTEXITCODE -ne 0) {
            throw "Could not remove the MouseVPN test certificate from LocalMachine $store."
        }
    }
}
Write-Warning "TESTSIGNING is disabled for the next boot. Restart Windows to return to normal kernel signature enforcement."
