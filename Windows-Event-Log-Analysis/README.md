# Windows Security Log Analysis with PowerShell

A university lab report documenting Windows Security Event Log analysis using PowerShell.
# Windows Security Log Analysis with PowerShell

A university lab report and PowerShell toolkit documenting Windows Security Event Log analysis (`DESKTOP-B4K066H`).

## Lab Objectives

- Query and filter Windows Security Event Logs with `Get-WinEvent`
- Review successful (`4624`) and failed (`4625`) logon events
- Extract event properties and inspect event XML schemas
- Identify possible brute-force patterns (`Detect-BruteForce.ps1`)
- Review explicit credential use (`4648`) and network share access (`5140`)
- Examine privilege-related events (`4672`, `4732`)

## Repository Contents

- [`Windows-Log-Analysis-Report.md`](./Windows-Log-Analysis-Report.md) — Complete Markdown lab report following the course report template
- [`Windows_Event_Log_Lab_Report.docx`](./Windows_Event_Log_Lab_Report.docx) — Word lab report with PowerShell execution screenshots
- [`Detect-BruteForce.ps1`](./Detect-BruteForce.ps1) — Automated brute-force detection script for Event ID `4625`
- [`Analyze-SecurityLogs.ps1`](./Analyze-SecurityLogs.ps1) — Comprehensive 24-hour Windows Security Event Log analysis script
- [`FailedLogons.csv`](./FailedLogons.csv) — Exported CSV of failed logon events (`Event ID 4625`)

## Key Observations

- Six failed logon events (Event ID `4625`) were observed in the last 24 hours on `DESKTOP-B4K066H`.
- All 6 attempts targeted the local account `ASUS` via Interactive logon (`LogonType = 2`) with status `0xC000006D` / sub-status `0xC000006A` (bad password).
- Source IP records included `127.0.0.1` (localhost, 2 events) and `-` (local console, 4 events), consistent with local password-entry mistakes rather than a remote brute-force attack.
- In Windows 10/11 Event ID `4625` XML, `Properties[8]` stores `FailureReason` (`%%2313`), while `LogonType` is stored at `Properties[10]`.

## Author

Abu Shahid Anik

## Lab objectives

- Query and filter Windows Security Event Logs with `Get-WinEvent`
- Review successful and failed logon events
- Extract event properties and inspect event XML
- Identify possible brute-force patterns
- Review explicit credential use and network share access
- Examine privilege-related events

## Key observations

- Six failed logon events (Event ID `4625`) were observed in the last 24 hours.
- The targeted account was `ASUS`, with six failed attempts.
- The source-IP observations included `127.0.0.1` (localhost); other records had an empty or unavailable source address.
- The observed pattern was consistent with local password-entry mistakes rather than clear evidence of a remote brute-force attack.
- The report notes a property-index issue in the logon-type exercise; event properties should be verified against the event XML.

## Tools

- Windows PowerShell
- Windows Security Event Log
- `Get-WinEvent`
- PowerShell event filtering and object pipelines

## Disclaimer

This is a controlled educational lab. Findings reflect the event logs available on the lab machine during the recorded analysis period and should not be generalized to other systems.

## Author

Abu Shahid Anik

> The original DOCX report has not yet been uploaded to this repository.
