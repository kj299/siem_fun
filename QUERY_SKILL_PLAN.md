# Splunk + Microsoft Sentinel Query Skill Plan

## Goal

Create a reusable Codex skill that can:

- understand a target SIEM environment before writing queries
- generate and optimize Splunk SPL and Microsoft Sentinel KQL
- translate common hunts and detections between SPL and KQL
- explain performance tradeoffs, parsing strategy, and field assumptions
- consume an internal URL that documents indexes, tables, and field definitions
- stay concise and predictable for Claude Opus 4.6 and Codex GPT-5.4

## Why this plan

The referenced material points to the right foundations:

- Splunk search pipelines are built from indexed search terms followed by pipe-based transforming commands, and Splunk emphasizes reducing data scanned early by narrowing index and time first.
- The Splunk search tutorial is organized around learning the Search app, loading known data, searching, enriching with lookups, then producing reports and dashboards.
- Microsoft Sentinel documentation centers on onboarding data, connectors, normalization and parsing, running KQL, analytics rules, and threat hunting.

That means the skill should not start from syntax alone. It should start from environment discovery, then schema mapping, then optimized query construction.

## Coding plan

### Phase 0: Token optimization

Keep the main `SKILL.md` short and procedural.

- move detail into references
- avoid duplicate instructions across files
- keep the default output shape fixed
- optimize for "query first" answers rather than tutorial prose
- prefer explicit skill invocation when the client supports it

### Phase 1: Environment discovery contract

Build the skill around a required discovery pass before writing production queries.

Outputs the skill should ask for or infer:

- platform: `splunk`, `sentinel`, or `both`
- use case: hunt, detection, dashboard, triage, metrics, or parsing
- time window and expected result grain
- internal data-dictionary URL when one exists
- data source names
- index names and sourcetypes for Splunk
- tables, connectors, and normalized schemas for Sentinel
- high-value fields: user, host, src, dest, ip, process, hash, url, action, result
- constraints: latency, cost, volume, real-time vs historical

### Phase 2: Query generation workflow

Teach the skill to build queries in this order:

1. Define the analyst question in plain English.
2. Pull schema facts from the internal data dictionary when available.
3. Pick the narrowest data scope.
4. Filter as early as possible.
5. Parse only the fields needed.
6. Aggregate late and only when required.
7. Return a readable output table with clear aliases.
8. Add notes about assumptions, false positives, and tuning knobs.

### Phase 3: Cross-platform mapping

Create a reference mapping for common equivalents:

- Splunk `index`, `sourcetype`, `source`, `host`
- Sentinel `table`, `TimeGenerated`, connector-specific schemas, normalized tables
- Splunk `stats`, `timechart`, `rex`, `eval`, `lookup`, `transaction`, `where`
- Sentinel `summarize`, `bin()`, `extract()`, `extend`, `lookup/join`, sessionization patterns, `where`

This lets the skill translate intent instead of producing one-off syntax conversions.

### Phase 3a: Internal dictionary ingestion

Teach the skill to treat internal documentation URLs as first-class schema inputs.

The skill should know how to consume:

- internal wiki pages that document Splunk indexes
- SharePoint or portal pages that describe Sentinel tables and connectors
- internal runbooks listing canonical field names and aliases
- parser notes that explain field availability, latency, or deprecation

When the URL cannot be opened directly, the skill should fall back gracefully by requesting a pasted excerpt or by producing a schema discovery query.

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
|-- README.md
`-- splunk-sentinel-query-builder/
    |-- agents/
    |   `-- openai.yaml
    |-- SKILL.md
    `-- references/
        |-- data-dictionary-integration.md
        |-- model-guidance.md
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
