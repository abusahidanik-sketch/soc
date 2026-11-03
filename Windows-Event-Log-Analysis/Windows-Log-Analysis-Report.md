# Windows Security Log Analysis Report

**Analyst:** Abu Shahid Anik  
**Date:** November 3, 2026  
**System:** `DESKTOP-B4K066H` (Workgroup: `WORKGROUP`, Local Account: `ASUS`)  
**PowerShell Version:** `5.1.26100.9818` (Administrator)  
**Analysis Period:** November 2, 2026 02:48 PM – November 3, 2026 02:48 PM (Last 24 Hours)

## Executive Summary

An investigation of the Windows Security Event Log on workstation `DESKTOP-B4K066H` over a 24-hour window identified **6 failed logon attempts (Event ID `4625`)**, all targeting the local account `ASUS` via interactive logon (`LogonType = 2`) with failure code `0xC000006D` / sub-status `0xC000006A` (existing username with an incorrect password). Two of those events recorded `127.0.0.1` (localhost) as the source address while the remaining four had `-` (console logon), confirming that the failures resulted from local password-entry mistakes at the sign-in screen rather than an external brute-force attack. Concurrent Event ID `4624` (successful logon) and Event ID `4672` (special privileges assigned) records, alongside Event ID `5379` (Credential Manager reads) and Event IDs `4798`/`4799` (local group membership enumerations), reflect legitimate local administrative sessions with no indicators of unauthorized lateral movement or privilege escalation.

## 1. Failed Logon Analysis

### Total Failed Logons
**Count:** `6`

**Command:**
```powershell
$StartTime = (Get-Date).AddDays(-1)
$FailedLogons = Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    ID        = 4625
    StartTime = $StartTime
}
$FailedLogons.Count
```

### Top 5 Source IP Addresses
```text
Name      Count
----      -----
127.0.0.1     2
```
*(The other 4 failed logons recorded `-` for local console sign-in and were filtered out by `Where-Object`).*

**Command:**
```powershell
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    ID        = 4625
    StartTime = (Get-Date).AddDays(-1)
} | ForEach-Object {
    $_.Properties[19].Value
} | Where-Object { $_ -ne '-' -and $_ -ne '' } |
    Group-Object |
    Sort-Object Count -Descending |
    Select-Object -First 5 Name, Count
```

### Top 5 Targeted Accounts
```text
Username Failed Attempts
-------- ---------------
ASUS                   6
```

### Logon Type Distribution (Corrected to `Properties[10]`)
* **Original Command Output (`Properties[8]`):** `Unknown (%%2313) : 6` (because `Properties[8]` is `FailureReason`, while `LogonType` is stored at `Properties[10]`).
* **Corrected Output (`Properties[10]`):**
```text
Logon Type  Count
----------  -----
Interactive     6
```

## 2. Brute-Force Attack Detection

### Detection Criteria
- **Threshold:** `5` failed attempts
- **Time Window:** `1 hour` (and `24 hours` baseline review)
- **Script:** `Detect-BruteForce.ps1`

### Suspicious IPs Identified
- **Baseline:** `127.0.0.1` (`2` attempts) and local console `-` (`4` attempts) against user `ASUS` (`6` total interactive failures at the local keyboard/screen; no remote brute-force IP identified).
- **Simulated Test (Exercise 11):** Running 10 failed SMB logons (`net use \\localhost\C$ /user:FakeUser WrongPassword`) generates 10 Network (`LogonType = 3`) failures against `FakeUser`, triggering `Detect-BruteForce.ps1`.

## 3. Lateral Movement Indicators

### Explicit Credential Usage (Event ID 4648)
No unauthorized remote `RunAs` or `PsExec` explicit-credential logons targeting external hosts were observed; local `4648` records were limited to routine Windows background system services (`svchost.exe` / `lsass.exe`).

### Network Share Access (Event ID 5140)
No anomalous external SMB share access (`ADMIN$`, `C$`, `IPC$`) from remote IP addresses occurred during the analysis window.

## 4. Privilege Escalation Indicators

### Admin Group Changes (Event ID 4732)
Zero unauthorized local `Administrators` group additions (`Event ID 4732`) or new account creations (`Event ID 4720`) occurred over the last 7 days. Routine local group membership enumerations (`Event IDs 4798` and `4799`) were logged at `02:41:48 PM` and `02:47:55 PM`–`02:47:56 PM`.

### Special Privilege Assignments (Event ID 4672)
Multiple Event ID `4672` records were logged between `02:44:26 PM` and `02:47:56 PM` on `03-Nov-26`, each paired with an Event ID `4624` logon for the elevated local administrator session (`ASUS` and `SYSTEM`).

## 5. Recommendations

1. **Immediate Actions:**
   - **Enforce Account Lockout Thresholds:** Lock accounts for 15 minutes after 5 consecutive failed logon attempts (`Event ID 4625`).
   - **Fix Event 4625 Property Indexing in Scripts:** Use `Properties[10]` (or named XML `<Data Name='LogonType'>`) for `LogonType` and `Properties[8]` for `FailureReason`.

2. **Long-Term Improvements:**
   - **Separate Standard User and Admin Accounts:** Use a non-admin account for daily work and elevate only via UAC to reduce `Event ID 4672` noise.
   - **Schedule Automated Log Audits & SIEM Forwarding:** Schedule `Analyze-SecurityLogs.ps1` and `Detect-BruteForce.ps1` daily via Task Scheduler and forward Security events to a SIEM.
