# Windows Security Log Analysis with PowerShell

A university lab report documenting Windows Security Event Log analysis using PowerShell.

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