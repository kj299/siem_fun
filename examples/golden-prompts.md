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

Grader spec:

```json
{
  "sections": ["Objective", "Query", "Assumptions"],
  "forbid_sections": ["Why efficient", "Tuning", "Validate"],
  "query_matches": ["index=windows", "sourcetype=XmlWinEventLog"],
  "indexes": ["windows"],
  "sourcetypes": ["XmlWinEventLog"],
  "assumed_if_used": ["EventCode"]
}
```

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

Grader spec:

```json
{
  "sections": ["Objective", "Discovery query", "Next step"],
  "forbid_sections": ["Why efficient", "Tuning", "Validate"],
  "query_matches": ["\\|\\s*tstats\\s+count\\s+where\\s+index=\\*[^\\n|]*\\bby\\s+index,\\s*sourcetype"],
  "matches": ["(?i)re-?invoke"],
  "indexes": [],
  "sourcetypes": []
}
```

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

Grader spec:

```json
{
  "sections": ["Objective", "Query", "What changed", "Why efficient", "Assumptions"],
  "forbid_sections": ["Tuning"],
  "tables": ["SigninLogs"],
  "query_lang": "kql",
  "query_matches": ["^SigninLogs", "where\\s+TimeGenerated\\s*>\\s*ago\\(7d\\)", "ResultType\\s*!=\\s*\"0\""],
  "query_not_matches": ["(?s)\\|\\s*extend.*\\|\\s*where\\s+TimeGenerated"]
}
```

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
- Uses `Usage` to identify candidate tables or `getschema` after a table is
  known. Either satisfies the spec, which is why they are one alternation and
  not two `matches` entries: separate entries are ANDed, so requiring both
  failed a correct answer that enumerated with `Usage` and told the user to
  re-invoke with the table it found.
- Does not reach for an unconstrained `union *`. query-workflow.md tells the
  model to prefer `Usage` for pure enumeration and to use `union *` sparingly,
  so an answer that never proposes one has nothing to warn about. The spec
  used to *require* a union wildcard here, which failed a correct answer for
  following the skill: the second fixture found to contradict the skill it
  exercises, after fixture 8.

Example starter:

```kql
Usage
| where TimeGenerated > ago(7d)
| summarize TotalGB = sum(Quantity) / 1024 by DataType, Solution
| sort by TotalGB desc
```

Grader spec:

```json
{
  "sections": ["Objective", "Discovery query", "Next step"],
  "forbid_sections": ["Why efficient", "Tuning", "Validate"],
  "matches": ["(?i)\\bUsage\\b|getschema"],
  "tables": ["Usage", "DeviceProcessEvents", "SecurityEvent", "Syslog", "CommonSecurityLog"]
}
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

Grader spec:

```json
{
  "sections": ["Objective", "Query", "Why efficient", "Assumptions", "Data dictionary notes", "Tuning", "Validate"],
  "tables": ["SigninLogs"],
  "query_lang": "kql",
  "query_matches": ["^SigninLogs", "UserPrincipalName", "IPAddress", "ago\\(24h\\)", "count\\(\\)", "ResultType"],
  "query_not_matches": ["\\bsrc_ip\\b", "\\buser\\b", "windows_auth"],
  "matches": ["ResultType"]
}
```

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

Grader spec:

```json
{
  "sections": ["Objective", "Query", "Assumptions"],
  "forbid_sections": ["Why efficient", "Tuning", "Validate"],
  "query_matches": ["^\\|\\s*tstats\\b", "summariesonly=true", "datamodel=Web\\.Web", "\\bby\\b[^\\n]*\\b(sourcetype|vendor_product)\\b"],
  "query_not_matches": ["\\bsourcetype\\s*=\\s*\\S+[^\\n]*\\bOR\\b[^\\n]*\\bsourcetype\\s*="],
  "indexes": [],
  "sourcetypes": ["zscalernss-web", "cloudflare:json", "pan:threat"]
}
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

Grader spec:

```json
{
  "sections": ["Objective"],
  "matches": ["\\|\\s*tstats\\b"],
  "contains": ["DeviceName", "FileName", "InitiatingProcessFileName"],
  "indexes": []
}
```

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
- Scopes both indexes in one base search: `index IN (firewall, proxy)` when the
  fields line up, or `((index=firewall sourcetype=cisco:asa) OR (index=proxy sourcetype=bluecoat:proxysg:access:kv))`
  when the schemas differ, which they do here. Never a bare
  `index=firewall OR index=proxy` chain. The first run of this fixture asserted
  only the `IN` form and failed a correct answer that had followed the skill's
  own per-index rule; the two shapes are both documented in
  multi-index-patterns.md
- Pre-filters to IPv4 values before enrichment (`gnenrich ip_field=...` or a `greynoise_indicators` lookup join)
- Filters on `classification` (the field the documented enrichment paths return),
  not on a `noise` column that `greynoise_indicators` does not carry
- If it does compare a boolean-ish lookup field, quotes the value
  (`noise="true"`, never `noise=true`)
- Does not invent sourcetypes beyond the two provided

Grader spec:

```json
{
  "sections": ["Objective", "Query", "Assumptions"],
  "forbid_sections": ["Why efficient", "Tuning", "Validate"],
  "query_matches": ["index\\s+IN\\s*\\(\\s*firewall\\s*,\\s*proxy\\s*\\)|\\(\\s*index=firewall\\s+\\w+=cisco:asa\\s*\\)\\s+OR\\s+\\(\\s*index=proxy\\s+\\w+=bluecoat:proxysg:access:kv\\s*\\)", "(?i)gnenrich|greynoise_indicators", "classification"],
  "query_not_matches": ["\\bindex=firewall\\s+OR\\s+index=proxy\\b", "(?s)greynoise_indicators.*\\bnoise\\b"],
  "indexes": ["firewall", "proxy"],
  "sourcetypes": ["cisco:asa", "bluecoat:proxysg:access:kv"]
}
```

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

Grader spec:

```json
{
  "sections": ["Objective", "Discovery query", "Next step"],
  "forbid_sections": ["Why efficient", "Tuning", "Validate"],
  "query_matches": ["\\|\\s*tstats\\s+count\\s+where\\s+index\\s+IN\\s*\\(\\s*net_dmz\\s*,\\s*net_core\\s*\\)\\s+by\\s+index\\s*,\\s*sourcetype\\s*\\|\\s*sort\\s+-\\s*count"],
  "matches": ["(?i)re-?invoke"],
  "indexes": ["net_dmz", "net_core"],
  "sourcetypes": []
}
```

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

Grader spec:

```json
{
  "contains": ["build_splunk_dictionary.py", "indexes", "sourcetypes", "cim_datamodels", "cim_coverage", "field_samples", "warnings"],
  "matches": ["SPLUNK_TOKEN|SPLUNK_PASSWORD|\\$env:|--token|--password", "(?i)permission"]
}
```
