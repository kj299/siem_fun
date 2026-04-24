---
name: splunk-sentinel-query-builder
description: Build and optimize Splunk SPL and Microsoft Sentinel KQL queries for hunts, detections, triage, dashboards, and translations between SPL and KQL. Use when the user needs environment-aware query generation, index or table discovery prompts, performance tuning, regex or field extraction strategy, side-by-side Splunk and Sentinel query equivalents, or an internal data-dictionary URL that explains indexes, tables, sourcetypes, and fields.
---

# Splunk Sentinel Query Builder

Use this skill when the user needs SIEM queries that are specific, performant, and grounded in the target environment instead of generic syntax.

## Outcome

Produce one of these:

- a fast hunt query
- a detection-ready query with tuning notes
- a translation from SPL to KQL or KQL to SPL
- an environment-discovery checklist when the schema is still unknown
- a schema-aware query that cites an internal data dictionary

## Default workflow

1. Identify the target platform: `splunk`, `sentinel`, or `both`.
2. Restate the detection or hunt objective in one sentence.
3. Gather environment context before writing the final query.
4. Constrain data early by time, index or table, and high-selectivity fields.
5. Parse and enrich only the fields needed for the answer.
6. Aggregate late.
7. Return the query plus assumptions, tuning knobs, and validation steps.

If the user provides an internal URL to a data dictionary, treat it as the preferred schema source before falling back to generic assumptions.

## Discovery questions to answer implicitly or explicitly

Gather as many of these as you can from the repo, prompt, or user context:

- internal documentation URLs that describe the environment
- Splunk indexes
- Splunk sourcetypes and source names
- Sentinel tables and connectors
- normalized schemas such as process, network, auth, email, cloud, or identity data
- key entity fields: user, host, ip, process, parent, hash, url, device, tenant
- desired time window
- whether this is for hunting, analytics rules, dashboards, or triage

If the environment is still unclear, return a short discovery checklist first instead of pretending the schema is known.

## Internal data dictionary support

If the user references an internal URL, extract and use these details when available:

- platform ownership: Splunk, Sentinel, or both
- index names and what each index contains
- sourcetypes, sources, hosts, and parser notes
- Sentinel tables, connectors, normalized schema mappings, and watchlists
- field definitions, aliases, enums, event IDs, and allowed values
- data quality notes such as delayed ingestion, null-heavy columns, or fields that exist only after parsing
- usage caveats such as deprecated sources, high-cost joins, or preferred summary datasets

Prefer dictionary-backed names over guessed names.

If the internal URL is unavailable from the current environment:

- say that you could not open it directly
- ask for pasted content or an exported file only if needed
- otherwise provide a starter query plus a schema checklist

When a dictionary is available, call out which query elements came from it.

## Query construction rules

### Splunk

- Start as narrowly as possible with `index=`, `sourcetype=`, `source=`, and time filters.
- Prefer fielded predicates over broad raw text searches.
- Put expensive commands such as `rex`, `eval`, and multi-stage transforms after early filtering.
- Use `stats`, `timechart`, `top`, `rare`, and `table` intentionally.
- Call out where a lookup, data model, or summary index would improve the query.
- If an internal dictionary marks an index as authoritative or deprecated, follow that guidance explicitly.
- If the dictionary documents canonical field names, use them instead of ad hoc regex extraction.

### Microsoft Sentinel

- Start with a concrete table and an early `where TimeGenerated` filter.
- Add narrow filters before `extend`, `parse`, `extract`, joins, or `mv-expand`.
- Use `project` or `project-away` to keep the result set small.
- Prefer `summarize` and `bin()` for grouped or time-based results.
- Mention when an analytics rule, hunting query, watchlist, or normalization layer would improve the solution.
- If the dictionary identifies normalized tables or preferred connectors, choose those first.
- If field aliases are documented, mention the mapping when translating or tuning queries.

## Translation rules

When translating, preserve analyst intent first and syntax second.

- Map data scope first: Splunk indexes and sourcetypes versus Sentinel tables and connectors.
- Map filtering second.
- Map parsing and enrichment third.
- Map aggregation and presentation last.
- If no safe one-to-one equivalent exists, say so and provide the closest operational pattern.

Read [references/splunk-to-kql-mapping.md](references/splunk-to-kql-mapping.md) for common command mappings.

## Performance rules

- Prefer the smallest reasonable time window.
- Filter early, parse late.
- Keep only needed columns near the end.
- Call out any likely expensive regex, join, wildcard, or sessionization step.
- When the user asks to optimize an existing query, explain what is being pushed earlier in the pipeline and why.
- Use dictionary hints about low-cardinality fields, summary datasets, or expensive tables when available.

## Response shape

Use this structure unless the user asks for something shorter:

1. Objective
2. Query
3. Why this is efficient
4. Assumptions
5. Data dictionary notes
6. Tuning ideas
7. Validation steps

## References

- For the end-to-end workflow and output patterns, read [references/query-workflow.md](references/query-workflow.md).
- For SPL to KQL mappings, read [references/splunk-to-kql-mapping.md](references/splunk-to-kql-mapping.md).
- For using internal URLs and schema dictionaries, read [references/data-dictionary-integration.md](references/data-dictionary-integration.md).
