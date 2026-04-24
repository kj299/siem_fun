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

## Output templates

### Hunt query

- objective
- query
- assumptions
- fast-tuning notes

### Detection query

- logic summary
- query
- data dictionary notes
- threshold options
- suppression ideas
- validation method

### Translation

- original intent
- translated query
- schema gaps
- platform differences

## When to stop and ask for schema details

Do not fake confidence when the query depends on unknown names for:

- Splunk indexes or sourcetypes
- Sentinel tables or custom connector output
- entity fields that vary by parser

If these are missing, provide:

- a short schema discovery checklist
- a starter query for enumerating likely fields or values
- a note about whether an internal data dictionary URL would remove the ambiguity
- no invented production dataset names
