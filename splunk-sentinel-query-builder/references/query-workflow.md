# Query Workflow

## Use this file when

- the user asks for a new hunt or detection query
- the environment is only partially known
- you need to explain why a query is fast or risky
- the user provides an internal URL with schema or index documentation

## Environment-first workflow

### 1. Define the question

Convert the request into a concrete analyst goal.

Examples:

- find failed logons followed by a success
- detect suspicious PowerShell execution
- show top outbound connections by rare destination
- identify sign-ins from impossible travel patterns

### 2. Identify the data scope

For Splunk, look for:

- `index`
- `sourcetype`
- `source`
- common extracted fields
- CIM data model coverage when the source is a mapped vendor product; see [cim-vendor-alignment.md](cim-vendor-alignment.md)

For Sentinel, look for:

- table name
- connector or solution name
- normalized table if available
- `TimeGenerated` and entity fields

If an internal data dictionary exists, extract:

- the exact dataset names to use
- the canonical field names
- any deprecated or preferred data sources
- parsing caveats and latency notes

### 3. Build the narrow filter

Start with:

- exact data source
- exact action or event type
- exact time range
- exact entities if known

### 4. Add parsing only if needed

Use regex, extraction, or computed fields only when a needed field is missing.

### 5. Shape the result

Choose the minimum useful output:

- raw events for triage
- grouped counts for detections
- time bins for trends
- entity lists for enrichment

### 6. Add tuning guidance

Always include:

- false-positive levers
- thresholds
- time-window suggestions
- field substitutions for different schemas
- dictionary-specific caveats such as delayed ingestion or deprecated fields

## What goes in each section

The section list itself lives in [SKILL.md](../SKILL.md) and is the single
source of truth. Do not add, rename, or drop sections here: this file said
"fast-tuning notes" and "logic summary" while SKILL.md mandates `Tuning` and
`Objective`, so the shape depended on which file was read last.

What changes per task is the *content* of those sections, not their names:

### Hunt

- `Objective`: the analyst question in one line.
- `Why efficient`: which filter does the work, and why it is cheap.
- `Tuning`: the levers that widen or narrow the hunt.

### Detection

- `Objective`: the detection logic in one line, including the trigger condition.
- `Tuning`: thresholds, suppression candidates, and the false-positive levers.
- `Validate`: how to confirm the rule fires on a known-true event.

### Translation

- `Objective`: the original intent, stated independently of either dialect.
- `Assumptions`: the schema gaps and any mapping that is not one-to-one.
- `Why efficient`: only the platform differences that change cost.

### Optimization

Use the `optimization` shape from SKILL.md, which replaces `Tuning` with
`What changed`. List only edits that alter cost, each with the reason.

## When to stop and ask for schema details

Do not fake confidence when the query depends on unknown names for:

- Splunk indexes or sourcetypes
- Sentinel tables or custom connector output
- entity fields that vary by parser

If these are missing, provide:

- a short schema discovery checklist
- a starter query from the discovery sections below
- a note about whether an internal data dictionary URL would remove the ambiguity
- no invented production dataset names

## Splunk discovery via tstats

`tstats` reads indexed metadata, so it is far cheaper than `stats` for enumerating datasets, hosts, or indexed fields.

### Index and sourcetype enumeration

List every index and its sourcetypes:

```spl
| tstats count where index=* by index, sourcetype
```

Scope to one index to find contributing hosts and sourcetypes:

```spl
| tstats count where index=YOUR_INDEX by host, sourcetype
```

### Data model coverage

Use these against the Common Information Model or any accelerated data model:

```spl
| tstats count from datamodel=YOUR_DATAMODEL.ROOT_DATASET by index
| tstats count from datamodel=Authentication.Authentication by index, sourcetype
| tstats count from datamodel=Endpoint.Processes by index
```

Add `summariesonly=true` when the data model is accelerated and only summarized results are needed:

```spl
| tstats summariesonly=true count from datamodel=Authentication.Authentication by index, sourcetype
```

### Verify a field is indexed

If a query depends on an unfamiliar field, confirm it is searchable via `tstats` before relying on it:

```spl
| tstats values(YOUR_FIELD) where index=YOUR_INDEX
```

An empty result means the field is not indexed and a raw-event search with extraction is required.

### When to return these instead of a production query

Return one of the queries above (and stop) when:

- the exact index or sourcetype is unknown
- a CIM-backed detection is requested but data model coverage is unclear
- a KQL-to-SPL translation hinges on which Splunk index receives the source data

For vendor-to-CIM sourcetype mappings and CIM query patterns, read [cim-vendor-alignment.md](cim-vendor-alignment.md).

## Sentinel discovery via Usage, Heartbeat, and getschema

Log Analytics has no `tstats` analogue, but small metadata tables and the `getschema` operator give the same answers cheaply.

### Workspace and table coverage

`Usage` is a metering table that lists every table that received data, with volume and the connector behind it:

```kql
Usage
| where TimeGenerated > ago(7d)
| summarize TotalGB = sum(Quantity) / 1024 by DataType, Solution
| sort by TotalGB desc
```

### Connector and host coverage

`Heartbeat` shows agent-side visibility:

```kql
Heartbeat
| where TimeGenerated > ago(24h)
| summarize LastSeen = max(TimeGenerated) by Computer, OSType, Category
```

`_SentinelHealth()` shows connector and analytics-rule status. Prefer the
prebuilt function over the `SentinelHealth` table: Microsoft maintains it across
schema changes, so a query built on it keeps working when the table changes.

```kql
_SentinelHealth()
| where TimeGenerated > ago(7d)
| summarize count() by SentinelResourceName, Status
```

### Column and value discovery within a known table

Two statements, so they need the semicolon: KQL requires any two statements to
be separated by one, and without it this is a syntax error rather than two
queries.

```kql
TableName | getschema;
TableName | take 5
```

`getschema` returns column names and types without scanning events. `take 5` is the cheapest way to see real values.

### Cross-table search when the right table is unknown

```kql
union withsource=Table_ *
| where TimeGenerated > ago(1h)
| where SomeField has "value"
| summarize count() by Table_
```

Use sparingly - `union *` scans every table. Always constrain `TimeGenerated` first and prefer `Usage` for pure enumeration.

### When to return these instead of a production query

Return one of the queries above (and stop) when:

- the exact table or normalized table is unknown
- the connector or solution feeding the data is unclear
- an SPL-to-KQL translation hinges on which Sentinel table receives the source data
