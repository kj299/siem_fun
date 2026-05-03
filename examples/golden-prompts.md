# Golden Prompt Examples

Use these fixtures to check that the skill returns query-first, schema-aware output and switches to discovery mode when production query assumptions would be risky.

## 1. Splunk known-schema hunt

Prompt:

```text
Use $splunk-sentinel-query-builder to build a Splunk hunt for suspicious PowerShell execution.
Platform: Splunk
Task: hunt
Time range: last 24h
Known datasets: index=windows, sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
Known fields: Image, CommandLine, ParentImage, User, host
Output style: short
```

Expected output:

- `Objective`
- `Query`
- `Assumptions`
- Uses `index=windows` and the supplied `sourcetype`
- Filters before any expensive extraction
- Does not introduce placeholder indexes

## 2. Splunk discovery mode with tstats

Prompt:

```text
Use $splunk-sentinel-query-builder to build a Splunk detection for failed admin logons.
Platform: Splunk
Task: detection
Time range: last 24h
Known datasets: unknown
Output style: full
```

Expected output:

- `Objective`
- `Query`
- `Assumptions`
- Returns `discovery`, not a production detection
- Uses a starter such as:

```spl
| tstats count where index=* by index, sourcetype
```

- States that exact index or sourcetype mapping is needed before productionizing

## 3. Sentinel known-table optimization

Prompt:

```text
Use $splunk-sentinel-query-builder to optimize this Sentinel query for speed:
SigninLogs
| extend User = tostring(UserPrincipalName)
| where TimeGenerated > ago(7d)
| where ResultType != "0"
| project TimeGenerated, User, IPAddress, AppDisplayName, ResultType
```

Expected output:

- Keeps `SigninLogs`
- Pushes `where TimeGenerated > ago(7d)` before `extend`
- Filters before shaping columns
- Explains only material tuning changes

## 4. Sentinel discovery mode with Usage and getschema

Prompt:

```text
Use $splunk-sentinel-query-builder to build a Sentinel hunt for endpoint process execution, but I do not know which table stores process events.
Platform: Sentinel
Task: hunt
Time range: last 7d
Known datasets: unknown
Output style: full
```

Expected output:

- Returns `discovery`, not a guessed production query
- Uses `Usage` to identify candidate tables or `getschema` after a table is known
- Warns against broad `union *` unless constrained

Example starter:

```kql
Usage
| where TimeGenerated > ago(7d)
| summarize TotalGB = sum(Quantity) / 1024 by DataType, Solution
| sort by TotalGB desc
```

## 5. SPL to KQL translation with data dictionary excerpt

Prompt:

```text
Use $splunk-sentinel-query-builder to translate this SPL to KQL.
Data dictionary excerpt:
- Splunk index=windows_auth maps to Sentinel SigninLogs
- Splunk user maps to UserPrincipalName
- Splunk src_ip maps to IPAddress

SPL:
index=windows_auth action=failure earliest=-24h
| stats count by user, src_ip
| where count > 10
```

Expected output:

- Returns `translation`
- Uses `SigninLogs`
- Maps `user` to `UserPrincipalName`
- Maps `src_ip` to `IPAddress`
- Calls out any assumption about `action=failure` mapping, such as `ResultType != "0"`

## 6. KQL to SPL translation with ambiguous dataset mapping

Prompt:

```text
Use $splunk-sentinel-query-builder to translate this KQL to SPL:
DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where FileName =~ "powershell.exe"
| summarize count() by DeviceName, InitiatingProcessFileName
```

Expected output:

- Returns `discovery` or a translation with explicit schema gaps
- Does not invent a Splunk index
- Provides a `tstats` discovery query to identify endpoint process indexes and sourcetypes
- States that `DeviceName`, `FileName`, and `InitiatingProcessFileName` need local field mappings
