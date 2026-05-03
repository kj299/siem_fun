# Splunk Data Dictionary Workflow

## Use this file when

- building a data dictionary from a Splunk instance
- troubleshooting Splunk connection or permissions
- preparing schema context for query generation

## Discovery Strategy

Start cheap and broad, then sample narrowly:

1. List accessible indexes through Splunk REST.
2. Use `tstats` to enumerate sourcetypes per index.
3. Sample a small number of events per index/sourcetype.
4. Collect field names, observed types, and sample values.
5. Record permission warnings and incomplete coverage.

## Permissions Handling

If an index or endpoint is hidden by role permissions, do not call it absent. Record:

- endpoint attempted
- status code
- message returned by Splunk
- likely remediation, such as asking a Splunk admin for role access

## Output Guidance

The dictionary should be useful to an LLM and a human analyst:

- keep field samples short
- record source index and sourcetype for every field
- preserve exact field names and casing
- note fields that appear sparsely
- include warnings when samples are too small

## Query Builder Handoff

Pass the generated JSON or a relevant excerpt to `splunk-sentinel-query-builder` as the internal data dictionary. The query builder should treat exact index, sourcetype, and field names from this output as higher priority than generic assumptions.
