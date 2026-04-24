---
name: splunk-sentinel-query-builder
description: Build and optimize Splunk SPL and Microsoft Sentinel KQL queries for hunts, detections, triage, dashboards, and translations between SPL and KQL. Use when the user needs environment-aware query generation, index or table discovery prompts, performance tuning, regex or field extraction strategy, or side-by-side Splunk and Sentinel query equivalents.
---

# Splunk Sentinel Query Builder

Use this skill when the user needs SIEM queries that are specific, performant, and grounded in the target environment instead of generic syntax.

## Outcome

Produce one of these:

- a fast hunt query
- a detection-ready query with tuning notes
- a translation from SPL to KQL or KQL to SPL
- an environment-discovery checklist when the schema is still unknown

## Default workflow

1. Identify the target platform: `splunk`, `sentinel`, or `both`.
2. Restate the detection or hunt objective in one sentence.
3. Gather environment context before writing the final query.
4. Constrain data early by time, index or table, and high-selectivity fields.
5. Parse and enrich only the fields needed for the answer.
6. Aggregate late.
7. Return the query plus assumptions, tuning knobs, and validation steps.

## Discovery questions to answer implicitly or explicitly

Gather as many of these as you can from the repo, prompt, or user context:

- Splunk indexes
- Splunk sourcetypes and source names
- Sentinel tables and connectors
- normalized schemas such as process, network, auth, email, cloud, or identity data
- key entity fields: user, host, ip, process, parent, hash, url, device, tenant
- desired time window
- whether this is for hunting, analytics rules, dashboards, or triage

If the environment is still unclear, return a short discovery checklist first instead of pretending the schema is known.

## Query construction rules

### Splunk

- Start as narrowly as possible with `index=`, `sourcetype=`, `source=`, and time filters.
- Prefer fielded predicates over broad raw text searches.
- Put expensive commands such as `rex`, `eval`, and multi-stage transforms after early filtering.
- Use `stats`, `timechart`, `top`, `rare`, and `table` intentionally.
- Call out where a lookup, data model, or summary index would improve the query.

### Microsoft Sentinel

- Start with a concrete table and an early `where TimeGenerated` filter.
- Add narrow filters before `extend`, `parse`, `extract`, joins, or `mv-expand`.
- Use `project` or `project-away` to keep the result set small.
- Prefer `summarize` and `bin()` for grouped or time-based results.
- Mention when an analytics rule, hunting query, watchlist, or normalization layer would improve the solution.

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

## Response shape

Use this structure unless the user asks for something shorter:

1. Objective
2. Query
3. Why this is efficient
4. Assumptions
5. Tuning ideas
6. Validation steps

## References

- For the end-to-end workflow and output patterns, read [references/query-workflow.md](references/query-workflow.md).
- For SPL to KQL mappings, read [references/splunk-to-kql-mapping.md](references/splunk-to-kql-mapping.md).
