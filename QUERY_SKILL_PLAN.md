# Splunk + Microsoft Sentinel Query Skill Plan

## Goal

Create a reusable Codex skill that can:

- understand a target SIEM environment before writing queries
- generate and optimize Splunk SPL and Microsoft Sentinel KQL
- translate common hunts and detections between SPL and KQL
- explain performance tradeoffs, parsing strategy, and field assumptions

## Why this plan

The referenced material points to the right foundations:

- Splunk search pipelines are built from indexed search terms followed by pipe-based transforming commands, and Splunk emphasizes reducing data scanned early by narrowing index and time first.
- The Splunk search tutorial is organized around learning the Search app, loading known data, searching, enriching with lookups, then producing reports and dashboards.
- Microsoft Sentinel documentation centers on onboarding data, connectors, normalization and parsing, running KQL, analytics rules, and threat hunting.

That means the skill should not start from syntax alone. It should start from environment discovery, then schema mapping, then optimized query construction.

## Coding plan

### Phase 1: Environment discovery contract

Build the skill around a required discovery pass before writing production queries.

Outputs the skill should ask for or infer:

- platform: `splunk`, `sentinel`, or `both`
- use case: hunt, detection, dashboard, triage, metrics, or parsing
- time window and expected result grain
- data source names
- index names and sourcetypes for Splunk
- tables, connectors, and normalized schemas for Sentinel
- high-value fields: user, host, src, dest, ip, process, hash, url, action, result
- constraints: latency, cost, volume, real-time vs historical

### Phase 2: Query generation workflow

Teach the skill to build queries in this order:

1. Define the analyst question in plain English.
2. Pick the narrowest data scope.
3. Filter as early as possible.
4. Parse only the fields needed.
5. Aggregate late and only when required.
6. Return a readable output table with clear aliases.
7. Add notes about assumptions, false positives, and tuning knobs.

### Phase 3: Cross-platform mapping

Create a reference mapping for common equivalents:

- Splunk `index`, `sourcetype`, `source`, `host`
- Sentinel `table`, `TimeGenerated`, connector-specific schemas, normalized tables
- Splunk `stats`, `timechart`, `rex`, `eval`, `lookup`, `transaction`, `where`
- Sentinel `summarize`, `bin()`, `extract()`, `extend`, `lookup/join`, sessionization patterns, `where`

This lets the skill translate intent instead of producing one-off syntax conversions.

### Phase 4: Optimization guidance

Add explicit optimization rules.

For Splunk:

- prefer tight `index=`, `sourcetype=`, and time bounds first
- avoid leading wildcards where possible
- favor fielded searches over raw text scans
- keep expensive extraction and regex after initial filters
- use `table` or `fields` to reduce payload near the end

For Sentinel:

- scope with `where TimeGenerated` first
- filter table rows before `parse`, `extend`, `mv-expand`, or joins
- project only needed columns
- prefer summarized datasets over wide raw result sets
- use joins carefully and keep the smaller side constrained

### Phase 5: Detection-ready outputs

Teach the skill to emit one of four answer shapes:

- quick query
- optimized query with comments
- translation from SPL to KQL or KQL to SPL
- detection package with query, logic notes, tuning notes, and validation steps

### Phase 6: Validation checklist

Each final query should be checked for:

- correct platform syntax
- environment-specific schema assumptions
- field existence assumptions
- performance risks
- expected output columns
- easy tuning points for analysts

## Recommended file layout

```text
prompts/siem_fun/
|-- QUERY_SKILL_PLAN.md
`-- splunk-sentinel-query-builder/
    |-- SKILL.md
    `-- references/
        |-- query-workflow.md
        `-- splunk-to-kql-mapping.md
```

## Suggested next coding steps

1. Use the skill for a few real prompts from your environment.
2. Add local references for your actual Splunk indexes and Sentinel tables.
3. Add environment-specific examples once schemas stabilize.
4. Optionally add a script later that templates query skeletons from a JSON schema file.

## Source links

- [Splunk SPL cheat sheet](https://www.splunk.com/en_us/blog/learn/splunk-cheat-sheet-query-spl-regex-commands.html)
- [Splunk Search Tutorial 9.4](https://help.splunk.com/en/splunk-enterprise/get-started/search-tutorial/9.4/introduction/about-the-search-tutorial)
- [Microsoft Sentinel documentation](https://learn.microsoft.com/en-us/azure/sentinel/)
