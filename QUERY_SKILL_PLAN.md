# Splunk + Microsoft Sentinel Query Skill Plan

**Status: every phase below has shipped.** This file is kept as the design
record -- the reasoning behind what was built, in the order it was decided --
rather than as a roadmap. For what the pack does today, read
[README.md](README.md); for the rules that keep it correct, read
[CLAUDE.md](CLAUDE.md). What the first model run found, and the one decision
still open, are at the end.

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
|   |   |-- test_grade_golden_output.py
|   |   `-- validate-skill-pack.tests.ps1
|   |-- grade_golden_output.py
|   |-- required-checks.txt
|   |-- run_golden_prompts.py
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

## What the first model run found

The last open item was executing the fixtures in
[examples/golden-prompts.md](examples/golden-prompts.md) against a model and
grading the output: the only way to find guidance that is accurate and
consistent and still produces a poor query. That now has tooling. Each fixture
carries a grader spec next to its prose bullets;
[scripts/grade_golden_output.py](scripts/grade_golden_output.py) grades an
answer against the spec and against the rules the validator applies to the
documents; [scripts/run_golden_prompts.py](scripts/run_golden_prompts.py)
drives a model through all ten with the skill loaded exactly as a client would
load it. The grader's checks are mutation-tested like the validator's.

First run, 2026-09-02, on Claude Opus (the session's `opus` alias) with each
fixture executed by an agent given SKILL.md and the references the way the
runner hands them over. Result after correction: 10 of 10.

- **One fixture was wrong, no skill was.** Fixture 8 asserted
  `index IN (firewall, proxy)`. The skill says to filter per index when the
  sourcetypes' schemas differ, the two supplied ones do, and the model did
  exactly that, explaining why in Assumptions. The fixture failed a correct
  answer. It now accepts either documented shape and forbids only the bare
  `OR` chain. Neither the validator nor a careful read could have found this:
  the fixture and the skill are each internally consistent.
- **Four grader rules were too strict for real answers**, each corrected and
  now unit-tested: a discovery answer offering three starter queries was
  graded on the first fence only; a translation answer echoing the source SPL
  under Query tripped a rule about the target KQL; a `getschema` block was
  held to the `TimeGenerated` rule; and "I will never ask you to type a
  token" tripped the credential-request check.
- **Every answer** bounded time first, named its assumptions, switched to
  discovery when the dataset was unknown, used only supplied or catalogued
  identifiers, and never asked for a credential. Answer 10's claims about the
  dictionary builder's flags and environment-variable defaults were checked
  against the script and are true.

## What checking the catalogues against the vendors found

The validator checks the documents against the catalogues. Nothing checked the
catalogues against the vendors, so a sourcetype or table that was renamed,
deprecated or never existed would pass every run. First pass, 2026-09-04.

- **All 20 Sentinel tables verified** against the Microsoft page each row
  cites. Every name exists with the exact casing the catalogue uses, every
  cited page still resolves, and the anchors still name a real heading. The
  descriptive claims hold too: `Usage` really does carry `DataType`,
  `Quantity` in Mbytes, `IsBillable` and `Solution`, and the `Operation` row's
  data-allowance records are documented on the page cited, with a sample
  query. Nothing needed correcting.
- **11 of the 67 Splunk sourcetypes spot-checked**, chosen as the likeliest to
  have drifted: the CrowdStrike, Carbon Black, Defender, Zscaler NSS, Okta,
  Qualys and Microsoft Cloud Services names. All are current, including the
  awkward ones (`qualys:hostDetection` really is camel-cased, and the Carbon
  Black caveat about `vmware:cb:edr:json` is right). The other 56 are unread.
- **The two catalogues are asymmetric, and only one says so.** Every Sentinel
  row cites Microsoft per table, and the file requires a citation before a
  table may be added. The Splunkbase catalogue carries no per-row citation at
  all, so re-verifying it means finding the vendor documentation again from
  scratch each time. Adding a Reference column to it is the obvious fix and is
  a larger content change than this pass took on.
- The Okta rows list `OktaIM2:log` only; the add-on also ships `OktaIM2:user`,
  `:group`, `:app`, `:groupUser` and `:appUser`. Not an error, an omission.

Direct fetches of vendor documentation are blocked by this environment's
network policy, so the Splunk half was checked through search rather than by
reading the pages. That is weaker evidence than the Sentinel half, where
Microsoft's documentation was read directly.

## What is still open

Running the model half on a schedule. CI holds no model credential, so the
weekly run covers everything except the one check that needs a model. Adding
a repository secret for the API key would close that, and it is the repository
owner's decision, not this plan's.

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
