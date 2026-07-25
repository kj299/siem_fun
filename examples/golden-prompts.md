# Golden Prompt Examples

Use these fixtures to check that the skill returns query-first, schema-aware output and switches to discovery mode when production query assumptions would be risky.

## 1. Splunk known-schema hunt

Prompt:

```text
Use $splunk-sentinel-query-builder to build a Splunk hunt for suspicious PowerShell execution.
Platform: Splunk
Task: hunt
Time range: last 24h
Known datasets: index=windows, sourcetype=XmlWinEventLog, source=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
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
- May use `EventCode=1` even though it is outside the supplied field list, provided
  it is named in `Assumptions`

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

- Returns `discovery`, not a production detection
- Uses the discovery shape: `Objective`, `Discovery query`, `Next step`
- Emits no `Tuning` or `Validate` section padded with "not applicable"
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

- Uses the optimization shape: `Objective`, `Query`, `What changed`, `Why efficient`, `Assumptions`
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

## 6. Splunk CIM multi-vendor hunt

Prompt:

```text
Use $splunk-sentinel-query-builder to hunt blocked web traffic across Zscaler, Cloudflare, and Palo Alto URL filtering.
Platform: Splunk
Task: hunt
Time range: last 24h
Known datasets: Web data model is accelerated; zscalernss-web, cloudflare:json, and pan:threat are CIM-mapped
Output style: short
```

Expected output:

- `Objective`
- `Query`
- `Assumptions`
- Uses one `tstats` query against `datamodel=Web.Web` instead of OR-ing vendor sourcetypes
- Groups by `sourcetype` or `vendor_product` so per-vendor gaps stay visible
- Uses `summariesonly=true` only because the prompt confirms acceleration
- Does not invent index names

Example shape:

```spl
| tstats summariesonly=true count from datamodel=Web.Web where Web.action="blocked" by Web.src, Web.url, sourcetype
```

## 7. KQL to SPL translation with ambiguous dataset mapping

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

## 8. Multi-index enrichment hunt with GreyNoise

Prompt:

```text
Use $splunk-enrichment-query-builder to hunt for connections to known-malicious IPs.
Platform: Splunk
Task: hunt
Time range: last 24h
Indexes: firewall, proxy
Sourcetypes: cisco:asa, bluecoat:proxysg:access:kv
GreyNoise: yes
Output style: short
```

Expected output:

- `Objective`
- `Query`
- `Assumptions`
- Uses `index IN (firewall, proxy)` rather than an `OR` chain
- Pre-filters to IPv4 values before enrichment (`gnenrich ip_field=...` or a `greynoise_indicators` lookup join)
- Quotes boolean lookup values in `where` clauses (`noise="true"`, not `noise=true`)
- Does not invent sourcetypes beyond the two provided

## 9. Enrichment discovery mode with unknown sourcetypes

Prompt:

```text
Use $splunk-enrichment-query-builder to build a detection across index=net_dmz and index=net_core.
Platform: Splunk
Task: detection
Time range: last 7d
Indexes: net_dmz, net_core
Output style: full
```

Expected output:

- Returns discovery mode, not a production detection
- Provides `| tstats count where index IN (net_dmz, net_core) by index, sourcetype | sort - count`
- Instructs the user to run the query and re-invoke the skill with confirmed sourcetypes
- Does not guess sourcetypes for the unfamiliar index names

## 10. Data dictionary build without pasted credentials

Prompt:

```text
Use $splunk-data-dictionary-builder to discover accessible Splunk indexes, sourcetypes, fields, sample values, and CIM data model coverage, then output a structured data dictionary. Use local credentials from environment variables or CLI arguments, and never ask me to paste secrets into chat.
```

Expected output:

- Runs `build_splunk_dictionary.py` with credentials from environment variables or CLI arguments
- Never asks the user to paste a token or password into chat
- Reports permission gaps explicitly instead of treating missing data as absent
- Output JSON includes `indexes`, `sourcetypes`, `cim_datamodels`, `cim_coverage`, `field_samples`, and `warnings`
