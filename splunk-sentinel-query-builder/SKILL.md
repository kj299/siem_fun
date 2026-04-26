---
name: splunk-sentinel-query-builder
description: Build and optimize Splunk SPL and Microsoft Sentinel KQL for SIEM hunts, detections, triage, tuning, and SPL/KQL translation using real environment metadata and internal data-dictionary URLs. Use when the user wants query authoring, optimization, or translation in Splunk or Sentinel. Do not use for SIEM deployment, connector setup, platform administration, or generic security education without a query-building objective.
---

# Splunk Sentinel Query Builder

Use this skill for environment-aware SIEM queries. Keep answers short, schema-driven, and operational.

## Important

- Never invent production dataset names when discovery is safer.
- Prefer the internal data dictionary over guessed schema.
- Return `discovery` instead of a production query when the schema is not reliable.
- Keep the answer query-first and stop after the smallest useful result.

## Token rules

- Do not explain basic SPL or KQL syntax unless asked.
- Do not repeat the user's prompt in long prose.
- Prefer exact dataset and field names over generic examples.
- Load only the reference file needed for the task.
- If schema is unknown, ask for the smallest missing fact or return a discovery query.
- Do not invent specific index, sourcetype, or table names when discovery is safer.

## Inputs

Expect these inputs when available:

- platform
- task type
- objective
- time range
- data dictionary URL or excerpt
- known datasets
- known fields
- desired output style

## Outputs

Return one of these:

- `query`: quick hunt or triage query
- `detection`: query plus threshold and tuning notes
- `translation`: SPL to KQL or KQL to SPL
- `discovery`: checklist plus starter query when schema is missing

Default response shape:

1. Objective
2. Query
3. Why efficient
4. Assumptions
5. Data dictionary notes
6. Tuning
7. Validate

If the user wants a short answer, return only `Objective`, `Query`, and `Assumptions`.

## Truth order

Use schema inputs in this order:

1. Internal data dictionary URL or excerpt
2. Explicit user-provided dataset and field names
3. Repo references
4. Discovery query

Do not let lower-priority hints override higher-priority schema facts.

## Core workflow

1. Identify platform: `splunk`, `sentinel`, or `both`.
2. Identify task: hunt, detection, triage, dashboard, or translation.
3. Prefer the internal data dictionary if the user provides a URL or excerpt.
4. Constrain time and dataset first.
5. Filter early, parse late, aggregate late.
6. Name assumptions explicitly.

## Stop conditions

Return `discovery` instead of a guessed production query when:

- the exact dataset name is missing
- the field mapping depends on an unknown parser or connector
- a translation depends on unknown source-table or source-index mapping

Use the Splunk `tstats` and Sentinel discovery starters in [references/query-workflow.md](references/query-workflow.md).

## Internal data dictionary support

If the user provides an internal URL or excerpt, treat it as the schema source of truth. Extract only:

- dataset names
- canonical fields and aliases
- parser or connector notes
- latency or data-quality caveats
- preferred or deprecated sources

Prefer dictionary-backed names over guessed names. If the URL cannot be opened, say so briefly and either ask for an excerpt or return a discovery query.

## Reference loading

Load only the smallest relevant reference:

- [references/query-workflow.md](references/query-workflow.md) for new hunts, detections, or triage
- [references/splunk-to-kql-mapping.md](references/splunk-to-kql-mapping.md) for translation
- [references/data-dictionary-integration.md](references/data-dictionary-integration.md) for internal URLs or excerpts
- [references/examples-and-troubleshooting.md](references/examples-and-troubleshooting.md) for concrete prompt patterns and failure handling
- [references/model-guidance.md](references/model-guidance.md) only when tuning the skill itself

## Platform rules

### Splunk

- Start with `index=`, `sourcetype=`, `source=`, and time bounds.
- Prefer fielded predicates over raw text scans.
- Delay `rex`, `eval`, and heavy transforms until after filtering.
- Prefer documented field names over ad hoc extraction.

### Sentinel

- Start with a concrete table and `where TimeGenerated`.
- Filter before `extend`, `parse`, `extract`, joins, or `mv-expand`.
- Keep columns small with `project`.
- Prefer normalized or documented tables when available.

## Translation rules

- Preserve intent before syntax.
- Map scope first, then filters, then parsing, then aggregation.
- If no safe one-to-one mapping exists, say so and provide the closest operational pattern.

Read [references/splunk-to-kql-mapping.md](references/splunk-to-kql-mapping.md) for command mappings.

## Model notes

Keep top-level answers structured, assumption-driven, and query-first. Read [references/model-guidance.md](references/model-guidance.md) only when tuning the skill or prompt style for Claude Opus 4.6 or Codex GPT-5.4.
