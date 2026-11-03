<#
.SYNOPSIS
    Comprehensive Windows Security Log Analysis Script
.DESCRIPTION
    Analyzes Windows Security Event Logs for failed logons (4625), successful logons (4624),
    account management activity (4720, 4722, 4724, 4732), lateral movement indicators
    (4648, 5140), and privilege escalation events (4672).
.PARAMETER Hours
    Number of hours to analyze (default: 24)
.EXAMPLE
    .\Analyze-SecurityLogs.ps1 -Hours 24
#>

param(
    [int]$Hours = 24
)

$StartTime = (Get-Date).AddHours(-$Hours)

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Windows Security Log Analysis Report" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "System:          $env:COMPUTERNAME" -ForegroundColor Yellow
Write-Host "Analysis Period: Last $Hours hours" -ForegroundColor Yellow
Write-Host "Start Time:      $StartTime" -ForegroundColor Yellow
Write-Host "========================================`n" -ForegroundColor Cyan

Write-Host "[1] FAILED LOGON ANALYSIS (Event ID 4625)" -ForegroundColor Green
Write-Host "-----------------------------------" -ForegroundColor Green

$FailedLogons = Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    ID        = 4625
    StartTime = $StartTime
} -ErrorAction SilentlyContinue

if ($FailedLogons) {
    Write-Host "Total Failed Logons: $($FailedLogons.Count)" -ForegroundColor Yellow

    Write-Host "`nTop 5 Source IPs:" -ForegroundColor Cyan
    $FailedLogons | ForEach-Object { $_.Properties[19].Value } |
        Where-Object { $_ -ne '-' -and $_ -ne '' } |
        Group-Object | Sort-Object Count -Descending | Select-Object -First 5 |
        Format-Table @{Name='IP Address';Expression={$_.Name}}, @{Name='Attempts';Expression={$_.Count}} -AutoSize

    Write-Host "Top 5 Targeted Accounts:" -ForegroundColor Cyan
    $FailedLogons | ForEach-Object { $_.Properties[5].Value } |
        Where-Object { $_ -ne '-' -and $_ -ne '' } |
        Group-Object | Sort-Object Count -Descending | Select-Object -First 5 |
        Format-Table @{Name='Username';Expression={$_.Name}}, @{Name='Attempts';Expression={$_.Count}} -AutoSize

    Write-Host "Failed Logon Type Distribution (Properties[10]):" -ForegroundColor Cyan
    $FailedLogons | ForEach-Object {
        $LogonType = $_.Properties[10].Value
        switch ($LogonType) {
            2  { 'Interactive (2)' }
            3  { 'Network (3)' }
            4  { 'Batch (4)' }
            5  { 'Service (5)' }
            7  { 'Unlock (7)' }
            8  { 'NetworkCleartext (8)' }
            9  { 'NewCredentials (9)' }
            10 { 'RemoteInteractive (10)' }
            11 { 'CachedInteractive (11)' }
            default { "Unknown ($LogonType)" }
        }
    } | Group-Object | Sort-Object Count -Descending |
        Format-Table @{Name='Logon Type';Expression={$_.Name}}, @{Name='Count';Expression={$_.Count}} -AutoSize
} else {
    Write-Host "No failed logons found." -ForegroundColor Green
}

Write-Host "`n[2] SUCCESSFUL LOGON ANALYSIS (Event ID 4624)" -ForegroundColor Green
Write-Host "-----------------------------------" -ForegroundColor Green

$SuccessfulLogons = Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    ID        = 4624
    StartTime = $StartTime
} -ErrorAction SilentlyContinue

if ($SuccessfulLogons) {
    Write-Host "Total Successful Logons: $($SuccessfulLogons.Count)" -ForegroundColor Yellow

    Write-Host "`nLogon Type Distribution:" -ForegroundColor Cyan
    $SuccessfulLogons | ForEach-Object {
        $LogonType = $_.Properties[8].Value
        switch ($LogonType) {
            2  { 'Interactive (2)' }
            3  { 'Network (3)' }
            4  { 'Batch (4)' }
            5  { 'Service (5)' }
            7  { 'Unlock (7)' }
            10 { 'RemoteInteractive (10)' }
            11 { 'CachedInteractive (11)' }
            default { "Type $LogonType" }
        }
    } | Group-Object | Sort-Object Count -Descending |
        Format-Table @{Name='Logon Type';Expression={$_.Name}}, @{Name='Count';Expression={$_.Count}} -AutoSize
}

Write-Host "`n[3] ACCOUNT MANAGEMENT EVENTS (4720, 4722, 4724, 4732)" -ForegroundColor Green
Write-Host "-----------------------------------" -ForegroundColor Green

$AccountEvents = Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    ID        = 4720,4722,4724,4732
    StartTime = $StartTime
} -ErrorAction SilentlyContinue

if ($AccountEvents) {
    Write-Host "Account Management Events: $($AccountEvents.Count)" -ForegroundColor Yellow
    $AccountEvents | Group-Object Id |
        Format-Table @{Name='Event ID';Expression={$_.Name}}, @{Name='Count';Expression={$_.Count}} -AutoSize
} else {
    Write-Host "No account management events found." -ForegroundColor Green
}

Write-Host "`n[4] PRIVILEGE ESCALATION & LATERAL MOVEMENT INDICATORS (4672, 4648, 5140)" -ForegroundColor Green
Write-Host "-----------------------------------" -ForegroundColor Green

$PrivEsc = Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    ID        = 4672,4648,5140
    StartTime = $StartTime
} -ErrorAction SilentlyContinue

if ($PrivEsc) {
    Write-Host "Privilege / Lateral Movement Events: $($PrivEsc.Count)" -ForegroundColor Yellow
    $PrivEsc | Group-Object Id |
        Format-Table @{Name='Event ID';Expression={$_.Name}}, @{Name='Count';Expression={$_.Count}} -AutoSize
} else {
    Write-Host "No privilege escalation or explicit credential events found." -ForegroundColor Green
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Analysis Complete" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan
