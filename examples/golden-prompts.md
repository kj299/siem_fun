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

- The data-model coverage starter from query-workflow.md
  (`| tstats count from datamodel=Authentication.Authentication by index, sourcetype`)
  is equally acceptable here: the task maps to one CIM model, and the skill
  documents both starters without ranking them
- States that exact index or sourcetype mapping is needed before productionizing

Grader spec:

```json
{
  "sections": ["Objective", "Discovery query", "Next step"],
  "forbid_sections": ["Why efficient", "Tuning", "Validate"],
  "query_matches": ["\\|\\s*tstats\\s+(?:count\\s+where\\s+index=\\*|(?:summariesonly=true\\s+)?count\\s+from\\s+datamodel=Authentication\\.Authentication\\b)[^\\n|]*\\bby\\s+index,\\s*sourcetype"],
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
  not two entries: separate entries are ANDed, so requiring both failed a
  correct answer that enumerated with `Usage` and told the user to re-invoke
  with the table it found. It is a `query_matches`, not a `matches`, because
  `matches` searches the whole answer: prose promising to run `getschema`
  later satisfied it while the Discovery query itself was a guessed production
  query, which is the one thing this fixture exists to forbid.
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
  "query_matches": ["(?i)\\bUsage\\b|getschema"],
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
- A sourcetype filter inside that query, scoping it to the three named vendors, is fine in either syntax (an `OR` group or `IN (...)`); what fails is a raw search in place of the data model, which the `tstats` and `datamodel` assertions already reject
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
  when the schemas differ, which they do here, with or without further
  per-index filter terms inside each group. Never a bare
  `index=firewall OR index=proxy` chain. The first run of this fixture asserted
  only the `IN` form and failed a correct answer that had followed the skill's
  own per-index rule; the fifth run failed another for adding `action=permitted`
  inside the firewall group, which the per-index shape exists to allow. Both
  shapes are documented in multi-index-patterns.md
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
  "query_matches": ["index\\s+IN\\s*\\(\\s*firewall\\s*,\\s*proxy\\s*\\)|\\(\\s*index=firewall\\s[^)]*\\w+=cisco:asa[^)]*\\)\\s+OR\\s+\\(\\s*index=proxy\\s[^)]*\\w+=bluecoat:proxysg:access:kv[^)]*\\)", "(?i)gnenrich|greynoise_indicators", "classification"],
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
- Provides `| tstats count where index IN (net_dmz, net_core) by index, sourcetype | sort - count`, optionally bounded by the prompt's `earliest=-7d`
- Instructs the user to run the query and re-invoke the skill with confirmed sourcetypes
- Does not guess sourcetypes for the unfamiliar index names

Grader spec:

```json
{
  "sections": ["Objective", "Discovery query", "Next step"],
  "forbid_sections": ["Why efficient", "Tuning", "Validate"],
  "query_matches": ["\\|\\s*tstats\\s+count\\s+where\\s+index\\s+IN\\s*\\(\\s*net_dmz\\s*,\\s*net_core\\s*\\)(?:\\s+(?:earliest|latest)=\\S+)*\\s+by\\s+index\\s*,\\s*sourcetype\\s*\\|\\s*sort\\s+-\\s*count"],
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

## 11. Agentic framework user-agent hunt from the reference

Prompt:

```text
Use $splunk-sentinel-query-builder to hunt for inbound requests from the ARTEX and CAIRN agentic attack frameworks by their user-agent strings.
Platform: Splunk
Task: hunt
Time range: last 24h
Known datasets: Web data model is accelerated
Output style: short
```

Expected output:

- `Objective`
- `Query`
- `Assumptions`
- Loads agentic-ai-attacks.md, because the request names two of the frameworks it covers
- Uses one `tstats` query against `datamodel=Web.Web`, with `summariesonly=true` because the prompt confirms acceleration
- Filters on `http_user_agent` using ARTEX user-agents the reference names (`artex-enrich/1.0`, `Mozilla/5.0 (compatible; ArtEx/1.0)` and the like)
- Invents no user-agent for CAIRN: the reference gives none, so the answer says so instead of writing one into the query
- Says what the reference says about these strings: they catch default or careless deployments, any operator can change them, and their absence proves nothing
- Does not invent index names
- Not machine-checked, reviewer's job: generic clients (`python-requests`, `curl`) are context in the reference, never a standalone match, and the answer should not present the user-agents as a blocklist

Grader spec:

```json
{
  "sections": ["Objective", "Query", "Assumptions"],
  "forbid_sections": ["Why efficient", "Tuning", "Validate"],
  "query_matches": ["^\\|\\s*tstats\\b", "summariesonly=true", "datamodel=Web\\.Web", "http_user_agent", "(?i)artex"],
  "query_not_matches": ["(?i)\"[^\"\\n]*cairn[^\"\\n]*\""],
  "matches": ["(?i)cairn", "(?i)default|careless|absence|absent|chang|strip|spoof"],
  "indexes": [],
  "sourcetypes": []
}
```

## 12. Sentinel identity hunt for leaked application secrets

Prompt:

```text
Use $splunk-sentinel-query-builder to build a Sentinel hunt for the ARTEX exposed-secrets campaign: one source signing in as many service principals with leaked application secrets.
Platform: Sentinel
Task: hunt
Time range: last 30d
Known datasets: AADServicePrincipalSignInLogs
Output style: short
```

Expected output:

- `Objective`
- `Query`
- `Assumptions`
- Loads agentic-ai-attacks.md and builds the hunt it describes in prose (the reference names H-AGT-022 but does not carry its KQL)
- Queries `AADServicePrincipalSignInLogs` and no other table, bounded to `ago(30d)`
- Counts distinct service principals per `IPAddress` and keeps three or more, the threshold the reference gives
- Uses both error codes the reference gives for an invalid and an expired client secret, 7000215 and 7000222
- Hunts the shape: the addresses Microsoft published are context, not the filter
- Not machine-checked, reviewer's job: `ResultType` holds the bare number, so a comparison against the `AADSTS`-prefixed form matches nothing; and a failure followed by a success from one source is the urgent case

Grader spec:

```json
{
  "sections": [
    "Objective",
    "Query",
    "Assumptions"
  ],
  "forbid_sections": [
    "Why efficient",
    "Tuning",
    "Validate"
  ],
  "query_matches": [
    "^AADServicePrincipalSignInLogs",
    "ago\\(30d\\)",
    "dcount\\(",
    "IPAddress",
    "7000215",
    "7000222",
    ">=\\s*3|>\\s*2"
  ],
  "tables": [
    "AADServicePrincipalSignInLogs"
  ]
}
```

## 13. Sentinel hunt for agent probe accounts by naming shape

Prompt:

```text
Use $splunk-sentinel-query-builder to build a Sentinel hunt for the probe accounts ARTEX agents self-register, as Okta Threat Intelligence described them.
Platform: Sentinel
Task: hunt
Time range: last 30d
Known datasets: AuditLogs, SigninLogs (Microsoft Entra ID)
Output style: short
```

Expected output:

- `Objective`
- `Query`
- `Assumptions`
- Uses only the two supplied tables
- Matches the naming shape the reference gives, the letter i, an intent number, the word probe and a ten-digit UNIX time, with a digit class rather than a fixed string
- Does not hard-code the reference's one example address: the reference says these patterns are behaviors and the hunts match the shape
- Not machine-checked, reviewer's job: the shared-mailbox prefixes and disposable mail domains the reference lists are a reasonable addition, and the answer should say the pattern was reported against Okta and Auth0 tenants, so Entra coverage is an adaptation

Grader spec:

```json
{
  "sections": [
    "Objective",
    "Query",
    "Assumptions"
  ],
  "forbid_sections": [
    "Why efficient",
    "Tuning",
    "Validate"
  ],
  "query_matches": [
    "(?i)probe",
    "\\[0-9\\]|\\\\d"
  ],
  "query_not_matches": [
    "1792451568"
  ],
  "tables": [
    "AuditLogs",
    "SigninLogs"
  ]
}
```

## 14. Sentinel discovery when the identity provider's table is unknown

Prompt:

```text
Use $splunk-sentinel-query-builder to build a Sentinel hunt for the probe accounts that ARTEX agents self-register in our Okta tenant.
Platform: Sentinel
Task: hunt
Time range: last 30d
Known datasets: unknown; Okta logs are ingested but I do not know the table name
Output style: full
```

Expected output:

- Returns `discovery`, not a production hunt
- Uses the discovery shape: `Objective`, `Discovery query`, `Next step`
- Starts from `Usage` or `getschema`, as sentinel-table-catalog.md says to
- Names no Okta table in query position: none is catalogued, and the user said the name is unknown
- Does not substitute an Entra query (`AuditLogs`, `SigninLogs`) for the Okta one the user asked for, even though the reference's own hunt for this pattern is written against Entra

Grader spec:

```json
{
  "sections": [
    "Objective",
    "Discovery query",
    "Next step"
  ],
  "forbid_sections": [
    "Why efficient",
    "Tuning",
    "Validate"
  ],
  "query_matches": [
    "(?i)\\bUsage\\b|getschema"
  ],
  "matches": [
    "(?i)re-?invoke"
  ],
  "tables": [
    "Usage"
  ]
}
```

## 15. ATT&CK technique lookup from the agentic framework map

Prompt:

```text
Use $splunk-sentinel-query-builder to build a Splunk hunt for ATT&CK technique T1546.018 as the agentic attack frameworks' operators have used it.
Platform: Splunk
Task: hunt
Time range: last 30d
Known datasets: Endpoint data model is accelerated
Output style: short
```

Expected output:

- `Objective`
- `Query`
- `Assumptions`
- Resolves the technique ID through the map in agentic-ai-attacks.md: Python Startup Hooks, one row, CAIRN only, from one report
- Hunts the artifact that row evidences, a write of `sitecustomize.py`, with `tstats` against the Endpoint data model the prompt supplies
- Attributes it to CAIRN and not to the frameworks the row does not list
- Does not invent index names
- Not machine-checked, reviewer's job: widening to other startup-hook files is a choice the answer should label as beyond the evidence, and package installs write this file legitimately

Grader spec:

```json
{
  "sections": [
    "Objective",
    "Query",
    "Assumptions"
  ],
  "forbid_sections": [
    "Why efficient",
    "Tuning",
    "Validate"
  ],
  "query_matches": [
    "^\\|\\s*tstats\\b",
    "datamodel=Endpoint\\.",
    "(?i)sitecustomize"
  ],
  "matches": [
    "(?i)cairn"
  ],
  "indexes": [],
  "sourcetypes": []
}
```

## 16. ATT&CK technique the map does not carry

Prompt:

```text
Use $splunk-sentinel-query-builder to build a Splunk hunt for ATT&CK technique T1486 as ARTEX operators have used it.
Platform: Splunk
Task: hunt
Time range: last 30d
Known datasets: Endpoint data model is accelerated
Output style: short
```

Expected output:

- `Objective`
- `Query`
- `Assumptions`
- Says the map has no row for this technique: no report used ties these frameworks to encrypting data for impact, and the reference calls a blank an intelligence gap, not an assurance
- Offers a hunt for the technique in general against the supplied Endpoint data model, and says that is what it is
- Writes no ARTEX-specific indicator into the query (an extension, a note name, a tool name): none is reported, so any would be invented
- Not machine-checked, reviewer's job: pointing to the Impact techniques the map does evidence is a good addition, and the answer must not claim a clean result says anything about ARTEX

Grader spec:

```json
{
  "sections": [
    "Objective",
    "Query",
    "Assumptions"
  ],
  "forbid_sections": [
    "Why efficient",
    "Tuning",
    "Validate"
  ],
  "query_matches": [
    "^\\|\\s*tstats\\b",
    "datamodel=Endpoint\\."
  ],
  "query_not_matches": [
    "(?i)artex"
  ],
  "matches": [
    "(?i)intelligence gap|no T1486 row|absent from|no (row|evidence|entry|report)"
  ],
  "indexes": [],
  "sourcetypes": []
}
```

## 17. Splunk detection for source-centric password spraying

Prompt:

```text
Use $splunk-sentinel-query-builder to build a Splunk detection for the source-centric password spraying that agentic attack frameworks such as ARTEX run.
Platform: Splunk
Task: detection
Time range: last 60m
Known datasets: Authentication data model is accelerated
Output style: short
```

Expected output:

- `Objective`
- `Query`
- `Assumptions`
- Builds the behavior the reference ranks second: one source failing many principals a few times each, below any per-principal rule
- Uses `tstats` against `datamodel=Authentication`, with `summariesonly=true` because the prompt confirms acceleration
- Counts distinct users and groups by the source, not by the user: a per-user threshold is the rule this behavior is built to stay under
- Says the thresholds are starting points to derive from a baseline, as the reference does
- Does not invent index names
- Not machine-checked, reviewer's job: shared egress (NAT, VPN, proxy) trips a per-source rule, and a spray spread over a residential proxy pool stays under it

Grader spec:

```json
{
  "sections": [
    "Objective",
    "Query",
    "Assumptions"
  ],
  "forbid_sections": [
    "Why efficient",
    "Tuning",
    "Validate"
  ],
  "query_matches": [
    "^\\|\\s*tstats\\b",
    "summariesonly=true",
    "datamodel=Authentication",
    "(?i)\\b(dc|distinct_count|estdc)\\(",
    "\\bby\\b[^\\n]*\\bsrc\\b"
  ],
  "matches": [
    "(?i)baseline"
  ],
  "indexes": [],
  "sourcetypes": []
}
```

## 18. Sentinel hunt for OAuth application user-agent drift

Prompt:

```text
Use $splunk-sentinel-query-builder to build a Sentinel hunt for OAuth applications whose Microsoft Graph user-agent has drifted from their own baseline, the way the hijacked ConnectWise applications were caught.
Platform: Sentinel
Task: hunt
Time range: last 24h, compared with the 30d before it
Known datasets: MicrosoftGraphActivityLogs
Output style: short
```

Expected output:

- `Objective`
- `Query`
- `Assumptions`
- Builds the Huntress method the reference describes: each application's own user-agents over the baseline period, compared with what it sent in the recent window
- Queries `MicrosoftGraphActivityLogs` only, grouped per `AppId`, with the baseline window bounded
- Does not write the one vendor's baseline client into the query: that value belongs to the ConnectWise applications, and every other application has its own
- Not machine-checked, reviewer's job: the generic clients the reference names are context for a known application, never an alert by themselves, and an SDK version bump is drift too

Grader spec:

```json
{
  "sections": [
    "Objective",
    "Query",
    "Assumptions"
  ],
  "forbid_sections": [
    "Why efficient",
    "Tuning",
    "Validate"
  ],
  "query_matches": [
    "MicrosoftGraphActivityLogs",
    "UserAgent",
    "\\bby\\b[^\\n]*\\bAppId\\b",
    "ago\\((30|31)d\\)"
  ],
  "query_not_matches": [
    "(?i)kiota"
  ],
  "tables": [
    "MicrosoftGraphActivityLogs"
  ]
}
```

## 19. Splunk detection for a canary username followed by an admin login

Prompt:

```text
Use $splunk-sentinel-query-builder to build a Splunk detection for the canary-username-then-admin login pattern that ARTEX agents use against login pages.
Platform: Splunk
Task: detection
Time range: last 60m
Known datasets: Authentication data model is accelerated
Output style: short
```

Expected output:

- `Objective`
- `Query`
- `Assumptions`
- Uses `tstats` against `datamodel=Authentication`, paired by source
- Keys the canary on the shape the reference gives (a username that starts with zz, or contains nonexistent or not-a-user), then an attempt as admin, administrator or root from the same source shortly after
- Does not fall back to a guessed definition of a canary: the reference lists the verified values
- Does not invent index names
- Not machine-checked, reviewer's job: matching only the two literal usernames is weaker than the shape, the admin name list is a placeholder for the deployment's own, and a shared egress address breaks the pairing

Grader spec:

```json
{
  "sections": [
    "Objective",
    "Query",
    "Assumptions"
  ],
  "forbid_sections": [
    "Why efficient",
    "Tuning",
    "Validate"
  ],
  "query_matches": [
    "^\\|\\s*tstats\\b",
    "datamodel=Authentication",
    "(?i)zz",
    "(?i)admin",
    "\\bby\\b[^\\n]*\\bsrc\\b"
  ],
  "indexes": [],
  "sourcetypes": []
}
```

## 20. Sentinel hunt for credentials added to applications

Prompt:

```text
Use $splunk-sentinel-query-builder to build a Sentinel hunt for the identity persistence ARTEX operators set up after access: credentials added to OAuth applications or service principals.
Platform: Sentinel
Task: hunt
Time range: last 30d
Known datasets: AuditLogs
Output style: short
```

Expected output:

- `Objective`
- `Query`
- `Assumptions`
- Builds the fourth behavior the reference ranks: credentials added to OAuth applications or service principals
- Queries `AuditLogs` only, bounded to `ago(30d)`, filtering on `OperationName`
- Says this is behavior, not an indicator match, so legitimate secret rotation is returned too
- Not machine-checked, reviewer's job: the application operation name carries a dash character that varies, so a phrase match is safer than equality, and an application adding a credential to itself is the row to read first

Grader spec:

```json
{
  "sections": [
    "Objective",
    "Query",
    "Assumptions"
  ],
  "forbid_sections": [
    "Why efficient",
    "Tuning",
    "Validate"
  ],
  "query_matches": [
    "^AuditLogs",
    "ago\\(30d\\)",
    "OperationName",
    "(?i)credential|secret|certificate"
  ],
  "tables": [
    "AuditLogs"
  ]
}
```

## 21. Splunk detection for legitimate services, with a blocklist request refused

Prompt:

```text
Use $splunk-sentinel-query-builder to build a Splunk detection for our servers calling the LLM APIs and webhook.site that ARTEX agents use, and tell me which of those domains to add to the proxy blocklist.
Platform: Splunk
Task: detection
Time range: last 24h
Known datasets: Network_Resolution data model is accelerated
Output style: short
```

Expected output:

- `Objective`
- `Query`
- `Assumptions`
- Builds the detection with `tstats` against `datamodel=Network_Resolution` for the hosts the reference names
- Answers the blocklist question with none: the reference carries LLM API hosts and webhook.site as legitimate services, behavioral signals only, never on a block action
- Adds no LLM host the reference does not name
- Does not invent index names
- Does not single out the reseller or webhook.site as the ones to block. The spec's `never_block` reads the answer clause by clause, because an answer can refuse the LLM hosts and recommend blocking these two in the same sentence, and a required phrase such as "do not block" would pass it
- Not machine-checked, reviewer's job: the answer should say servers with a sanctioned integration will match, should leave server scoping to the reader instead of inventing a subnet, and should not recommend a block by pronoun ("block it") or as a condition ("block it if nobody uses it"), which the clause check cannot see

Grader spec:

```json
{
  "sections": [
    "Objective",
    "Query",
    "Assumptions"
  ],
  "forbid_sections": [
    "Why efficient",
    "Tuning",
    "Validate"
  ],
  "query_matches": [
    "^\\|\\s*tstats\\b",
    "datamodel=Network_Resolution",
    "(?i)webhook\\.site"
  ],
  "matches": [
    "(?i)legitimate",
    "(?i)\\bnone\\b[^\\n]{0,60}(domain|block)|never (on|as) a block|do not (add|block)|not block"
  ],
  "never_block": ["xcai.pro", "webhook.site"],
  "indexes": [],
  "sourcetypes": []
}
```
