<#
.SYNOPSIS
    Brute-Force Attack Detection Script for Windows Security Event Logs (Event ID 4625)
.DESCRIPTION
    Queries the Windows Security Event Log for failed logon attempts (Event ID 4625)
    within a configurable time window and flags source IP addresses or local console
    sessions that meet or exceed the failure threshold.
    Note: On Windows 10/11 Event ID 4625 XML schemas:
      - Properties[5]  = TargetUserName
      - Properties[8]  = FailureReason (e.g., %%2313)
      - Properties[10] = LogonType (e.g., 2 = Interactive, 3 = Network, 10 = RemoteInteractive)
      - Properties[19] = IpAddress
.PARAMETER FailureThreshold
    Minimum number of failed logon attempts from a single source to flag (default: 5)
.PARAMETER Hours
    Number of hours to look back in the Security log (default: 24)
.EXAMPLE
    .\Detect-BruteForce.ps1 -FailureThreshold 5 -Hours 24
#>

param(
    [int]$FailureThreshold = 5,
    [int]$Hours = 24
)

$TimeWindow = (Get-Date).AddHours(-$Hours)

$RawEvents = Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    ID        = 4625
    StartTime = $TimeWindow
} -ErrorAction SilentlyContinue

if (-not $RawEvents) {
    Write-Host "`nNo failed logon events (Event ID 4625) found in the last $Hours hour(s)." -ForegroundColor Green
    exit
}

$FailedLogons = $RawEvents | ForEach-Object {
    $SourceIP = $_.Properties[19].Value
    if ([string]::IsNullOrWhiteSpace($SourceIP) -or $SourceIP -eq '-') {
        $SourceIP = 'Local/Console (No IP)'
    }
    [PSCustomObject]@{
        TimeCreated   = $_.TimeCreated
        SourceIP      = $SourceIP
        TargetUser    = $_.Properties[5].Value
        LogonType     = $_.Properties[10].Value
        FailureReason = $_.Properties[8].Value
    }
}

$SuspiciousIPs = $FailedLogons |
    Group-Object SourceIP |
    Where-Object { $_.Count -ge $FailureThreshold } |
    Sort-Object Count -Descending

Write-Host "`n=== POTENTIAL BRUTE-FORCE ATTACKS DETECTED ===" -ForegroundColor Red
Write-Host "Time Window: Last $Hours hour(s) (Since $TimeWindow)" -ForegroundColor Yellow
Write-Host "Threshold:   $FailureThreshold failed attempts`n" -ForegroundColor Yellow

if ($SuspiciousIPs) {
    foreach ($IP in $SuspiciousIPs) {
        Write-Host "Source IP:       $($IP.Name)" -ForegroundColor Red
        Write-Host "Failed Attempts: $($IP.Count)" -ForegroundColor Red
        Write-Host "Targeted Accounts:" -ForegroundColor Yellow
        $IP.Group | Select-Object -ExpandProperty TargetUser -Unique | ForEach-Object {
            Write-Host "  - $_"
        }
        Write-Host ""
    }
} else {
    Write-Host "No single source exceeded the threshold of $FailureThreshold failed attempts." -ForegroundColor Green
    Write-Host "Total failed logons across all sources: $($FailedLogons.Count)`n" -ForegroundColor Cyan
}
