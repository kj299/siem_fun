# Splunk + Microsoft Sentinel Query Skill Plan

**Status: every phase below has shipped.** This file is kept as the design
record -- the reasoning behind what was built, in the order it was decided --
rather than as a roadmap. For what the pack does today, read
[README.md](README.md); for the rules that keep it correct, read
[CLAUDE.md](CLAUDE.md). The one item still genuinely open is listed at the end.

## Goal

Create a reusable skill, for both Claude and Codex, that can:

- understand a target SIEM environment before writing queries
- generate and optimize Splunk SPL and Microsoft Sentinel KQL
- translate common hunts and detections between SPL and KQL
- explain performance tradeoffs, parsing strategy, and field assumptions
- consume an internal URL that documents indexes, tables, and field definitions
- stay concise and predictable for Claude Opus 4.6 and Codex GPT-5.4
- express clear trigger boundaries, examples, and troubleshooting via progressive disclosure
- generate Splunk data dictionaries from accessible indexes, sourcetypes, and sampled fields
- align Splunk guidance with the Common Information Model so multi-vendor sources are queried through shared data models (vendors and coverage depth listed in the README and cim-vendor-alignment.md)

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
- keep examples and troubleshooting in references instead of bloating the top-level skill

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

The top-level skill should also make these boundaries explicit:

- what the skill does
- when it should trigger
- when it should not trigger

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

Teach the skill to emit one of the five answer shapes SKILL.md declares
(`query`, `detection`, `translation`, `optimization`, `discovery`):

- `query`: quick hunt, triage, or dashboard-panel query
- `detection`: query plus threshold and tuning notes
- `translation`: SPL to KQL or KQL to SPL
- `optimization`: rewritten query plus what changed and why it is cheaper
- `discovery`: checklist plus starter query when the schema is missing

`discovery` is not optional garnish: Phase 1 above builds the whole skill around
a discovery pass before any production query, so a list that omits it
contradicts the phase it depends on.

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
siem_fun/
|-- .claude/
|   `-- settings.json
|-- .env.example
|-- .github/
|   `-- workflows/
|       `-- validate.yml
|-- .gitignore
|-- examples/
|   `-- golden-prompts.md
|-- CLAUDE.md
|-- QUERY_SKILL_PLAN.md
|-- README.md
|-- scripts/
|   |-- tests/
|   |   |-- mutation-check.py
|   |   `-- validate-skill-pack.tests.ps1
|   |-- required-checks.txt
|   `-- validate-skill-pack.ps1
|-- splunk-data-dictionary-builder/
|   |-- agents/
|   |   |-- claude-opus.yaml
|   |   |-- codex-gpt-5.4.yaml
|   |   `-- openai.yaml
|   |-- references/
|   |   `-- workflow.md
|   |-- scripts/
|   |   `-- build_splunk_dictionary.py
|   |-- tests/
|   |   `-- test_build_splunk_dictionary.py
|   `-- SKILL.md
|-- splunk-enrichment-query-builder/
|   |-- agents/
|   |   |-- claude-opus.yaml
|   |   |-- codex-gpt-5.4.yaml
|   |   `-- openai.yaml
|   |-- references/
|   |   |-- greynoise-integration.md
|   |   |-- multi-index-patterns.md
|   |   |-- splunk-cloud-index-management.md
|   |   `-- splunkbase-app-catalog.md
|   `-- SKILL.md
`-- splunk-sentinel-query-builder/
    |-- agents/
    |   |-- claude-opus.yaml
    |   |-- codex-gpt-5.4.yaml
    |   `-- openai.yaml
    |-- SKILL.md
    `-- references/
        |-- cim-vendor-alignment.md
        |-- data-dictionary-integration.md
        |-- examples-and-troubleshooting.md
        |-- model-guidance.md
        |-- query-workflow.md
        |-- sentinel-table-catalog.md
        `-- splunk-to-kql-mapping.md
```

## What was built beyond this plan

The phases above describe the skills. What they do not describe, because it
was not foreseen, is the verification layer that now makes up roughly half the
repository: a validator that checks every sourcetype written in query position,
every colon-delimited sourcetype named in prose, and every Sentinel table in
the documents against a cited catalogue, lints SPL for the silent-failure patterns,
and enforces parity across the helper files; a mutation harness that breaks
each of those checks on purpose and asserts it fires; and a check inventory
that makes deleting a check a build failure. That layer exists because the
documents are read by a model at query time, so a factual error in them is a
wrong query with no error message. README.md explains what it enforces;
CLAUDE.md explains what it deliberately does not.

## What is still open

Executing the fixtures in [examples/golden-prompts.md](examples/golden-prompts.md)
against a model and grading the output. The structural half is done -- every
fixture asserts only output sections a skill declares, and the fixtures inherit
every identifier and SPL check -- but the behavioral half needs a model call,
which this repository's CI cannot make. It is the only remaining way to find
the class of defect neither the checks nor a careful read can reach: guidance
that is accurate and consistent and still produces a poor query.

## For your own environment

1. Run `splunk-data-dictionary-builder` against your instance and pass its JSON
   to the query builder as the internal data dictionary.
2. Add your own indexes, tables, and field aliases as a data-dictionary excerpt
   rather than editing the reference files; the references describe vendor
   defaults, and your deployment will differ.

## Source links

- [Splunk SPL cheat sheet](https://www.splunk.com/en_us/blog/learn/splunk-cheat-sheet-query-spl-regex-commands.html)
- [Splunk Search Tutorial 9.4](https://help.splunk.com/en/splunk-enterprise/get-started/search-tutorial/9.4/introduction/about-the-search-tutorial)
- [Microsoft Sentinel documentation](https://learn.microsoft.com/en-us/azure/sentinel/)
