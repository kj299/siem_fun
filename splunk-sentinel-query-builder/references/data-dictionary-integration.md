# Data Dictionary Integration

## Use this file when

- the user gives an internal URL that documents Splunk indexes or Sentinel tables
- the environment has a wiki, portal, SharePoint, Confluence page, or internal app with schema definitions
- query quality depends on index meanings, field definitions, or parser notes

## Goal

Turn internal schema documentation into reliable query inputs instead of guessing index or field names.

## Token discipline

- Extract only the section relevant to the current query.
- Prefer short pasted excerpts over entire wiki pages.
- Do not repeat long dictionary text in the final answer.
- Summarize dictionary-derived facts instead of quoting documentation.

## Preferred extraction targets

Capture these details from the dictionary if they exist:

- index or table name
- platform
- sourcetype, source, connector, or parser
- event category
- entity fields
- aliases and renamed fields
- required parsing notes
- common filters
- deprecated datasets
- data latency or freshness expectations
- sample values or enumerations

## How to use the dictionary

### Before building a query

1. Identify whether the dictionary covers Splunk, Sentinel, or both.
2. Extract the exact names for indexes, sourcetypes, tables, and important fields.
3. Look for notes on preferred datasets, summary indexes, normalized tables, or deprecated sources.
4. Note any caveats that affect query performance or correctness.

### While building a query

- Use canonical names from the dictionary.
- Prefer documented entity fields over regex extraction.
- If multiple datasets could work, prefer the one the dictionary marks as authoritative.
- If the dictionary notes ingestion delay, mention that in validation guidance.
- If the dictionary lists aliases, mention the chosen mapping in the assumptions.

### After building a query

Report which parts came from the dictionary:

- dataset selection
- field names
- parser or connector assumptions
- known caveats

## Fallback behavior

If the internal URL cannot be opened directly:

- state that the URL could not be accessed from the current environment
- ask for pasted excerpts or an exported file only if the schema is required to avoid a risky guess
- otherwise provide a discovery query and list exactly what schema details are still needed

## Suggested user prompt pattern

Encourage prompts shaped like:

- "Use this internal data dictionary URL and build a Splunk query for failed admin logons."
- "Translate this SPL to KQL using the field definitions from this internal wiki page."
- "Optimize this Sentinel query using the table notes from our internal data dictionary."
