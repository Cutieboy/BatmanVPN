param(
    [string]$Executable = "$PSScriptRoot\dist\MouseVPN-windows-x64.exe",
    [switch]$TestCrashRecovery
)

$ErrorActionPreference = "Stop"

function Assert-Condition {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) {
        throw $Message
    }
}

function Invoke-MouseVpnCommand {
    param([string[]]$Arguments)
    $stdout = [IO.Path]::GetTempFileName()
    $stderr = [IO.Path]::GetTempFileName()
    try {
        $process = Start-Process -FilePath $Executable -ArgumentList $Arguments -Wait `
            -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
        $output = Get-Content $stdout -Raw -ErrorAction SilentlyContinue
        $errors = Get-Content $stderr -Raw -ErrorAction SilentlyContinue
        if ($process.ExitCode -ne 0) {
            throw "MouseVPN $($Arguments -join ' ') failed: $errors"
        }
        return $output.Trim()
    } finally {
        Remove-Item $stdout,$stderr -Force -ErrorAction SilentlyContinue
    }
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
Assert-Condition ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) `
    "Run this script from an Administrator PowerShell terminal."
Assert-Condition (Test-Path $Executable) "MouseVPN executable not found: $Executable"

Write-Host "MouseVPN executable: $Executable"
Invoke-MouseVpnCommand @("--diagnose") | Write-Host

$baselineIpv6 = Test-NetConnection -ComputerName "2606:4700:4700::1111" -Port 443 `
    -InformationLevel Quiet -WarningAction SilentlyContinue
try {
    $baselinePublicIp = (Invoke-RestMethod -Uri "https://api.ipify.org" -TimeoutSec 10).Trim()
    Write-Host "Public IPv4 before tunnel: $baselinePublicIp"
} catch {
    $baselinePublicIp = $null
    Write-Warning "Could not record the pre-tunnel public IPv4."
}

$gui = Start-Process -FilePath $Executable -PassThru
try {
    Write-Host "Import/select a profile, connect, and wait until the UI says connected."
    Read-Host "Press Enter to run network checks"

    $reportText = Invoke-MouseVpnCommand @("--network-report")
    $report = $reportText | ConvertFrom-Json
    $report | Format-List | Out-Host

    Assert-Condition $report.adapterUp "The MouseVPN Wintun adapter is not up."
    Assert-Condition ($report.routeCount -eq 2) "Expected two MouseVPN /1 routes."
    Assert-Condition ($report.firewallRuleCount -ge 2) "Kill-switch firewall rules are missing."
    Assert-Condition ($report.dnsServers.Count -ge 1) "Tunnel DNS is not configured."
    Assert-Condition $report.stateJournal "Crash-recovery journal is missing."

    Clear-DnsClientCache
    $dns = Resolve-DnsName -Name "example.com" -DnsOnly -ErrorAction Stop
    Assert-Condition ($dns.Count -gt 0) "DNS lookup through the tunnel failed."
    Write-Host "DNS lookup succeeded."

    $ipv6Escaped = Test-NetConnection -ComputerName "2606:4700:4700::1111" -Port 443 `
        -InformationLevel Quiet -WarningAction SilentlyContinue
    if ($baselineIpv6) {
        Assert-Condition (-not $ipv6Escaped) "IPv6 reached the Internet outside the IPv4-only tunnel."
        Write-Host "IPv6 escape test is blocked as expected."
    } else {
        Write-Warning "IPv6 was unavailable before connecting, so its leak test is inconclusive."
    }

    try {
        $publicIp = (Invoke-RestMethod -Uri "https://api.ipify.org" -TimeoutSec 10).Trim()
        Write-Host "Tunnel public IPv4: $publicIp"
        if ($baselinePublicIp -and $baselinePublicIp -eq $publicIp) {
            Write-Warning "Public IPv4 did not change. Confirm that the VPN server is expected to use a different egress address."
        }
    } catch {
        Write-Warning "Public-IP check failed: $($_.Exception.Message)"
    }

    if ($TestCrashRecovery) {
        Write-Warning "Crash test will forcibly terminate the privileged helper."
        $helper = Get-CimInstance Win32_Process | Where-Object {
            $_.ParentProcessId -eq $gui.Id -and $_.CommandLine -match "--helper"
        } | Select-Object -First 1
        Assert-Condition ($null -ne $helper) "Could not find the MouseVPN helper process."
        Stop-Process -Id $helper.ProcessId -Force
        Start-Sleep -Seconds 2

        $escaped = Test-NetConnection -ComputerName "1.1.1.1" -Port 443 `
            -InformationLevel Quiet -WarningAction SilentlyContinue
        Assert-Condition (-not $escaped) "Kill switch did not remain closed after helper crash."
        Write-Host "Crash test passed: physical Internet remains blocked."

        Invoke-MouseVpnCommand @("--repair-network") | Write-Host
        Start-Sleep -Seconds 2
        $rules = @(Get-NetFirewallRule -Group "MouseVPN Kill Switch" `
            -ErrorAction SilentlyContinue)
        Assert-Condition ($rules.Count -eq 0) "MouseVPN firewall rules remain after repair."
        Write-Host "Emergency repair removed the stale policy."
    }

    Write-Host "MouseVPN Windows checks passed." -ForegroundColor Green
    if (-not $TestCrashRecovery) {
        Write-Host "Disconnect in the MouseVPN UI before closing it."
    }
} finally {
    if ($TestCrashRecovery) {
        try {
            Invoke-MouseVpnCommand @("--repair-network") | Out-Null
        } catch {
            Write-Warning "Final emergency repair failed: $($_.Exception.Message)"
        }
    }
    if ($TestCrashRecovery -and $gui -and -not $gui.HasExited) {
        Stop-Process -Id $gui.Id -ErrorAction SilentlyContinue
    }
}
