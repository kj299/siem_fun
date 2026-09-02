# siem_fun

`siem_fun` is a skill pack that makes a language model produce Splunk SPL and
Microsoft Sentinel KQL that runs correctly in *your* environment -- and that
refuses to guess when it cannot.

## The problem it exists to solve

A model asked for a SIEM query will produce something plausible. The danger is
that in SPL and KQL, plausible-but-wrong usually fails **silently**: a
sourcetype that does not exist, a Sentinel table with the wrong casing
(`SignInLogs` for `SigninLogs`), an unquoted boolean in `| where`, or a Cisco
message ID mislabelled as an ACL deny all return an empty or wrong result set
with no error. The analyst sees "no matches" and concludes the threat is absent.

This pack is built around two commitments that address that directly:

1. **Never invent an identifier.** Index names, sourcetypes, and table names in
   every reference document are real, and each skill is instructed to emit a
   *discovery query* -- something that enumerates what the environment actually
   has -- rather than guess when the schema is unknown.
2. **Verify the content mechanically.** Because a model reads these files at
   runtime, a wrong fact here becomes a wrong query there. Every sourcetype written in
   the colon-delimited form most add-ons use (`cisco:asa`) must resolve to the
   Splunkbase catalogue; every Sentinel table must resolve to a catalogue that
   cites Microsoft's own documentation per table;
   SPL patterns are linted for the silent-failure bugs above; and every one of
   those checks is mutation-tested, so it is known to fire rather than assumed
   to. See [How the content is kept correct](#how-the-content-is-kept-correct).

## What this repo gives you

Three skills that form a pipeline from "what is in this Splunk?" to "here is
the query":

- **`splunk-data-dictionary-builder`**: a local script that discovers accessible
  indexes, sourcetypes, fields, installed CIM data models, and live CIM coverage
  by sourcetype, and writes it as JSON. Run it first when the schema is unknown;
  its output is the schema context the other two skills consume.
- **`splunk-sentinel-query-builder`**: builds, optimizes, and translates SPL and
  KQL against real schema context, and returns a discovery query instead of a
  production query when that context is missing.
- **`splunk-enrichment-query-builder`**: builds queries spanning multiple
  user-provided indexes using a catalogue of 30+ Splunkbase add-ons and their
  CIM mappings, with optional GreyNoise IP enrichment and Splunk Cloud index
  guidance.

Supporting all three:

- Splunk Common Information Model (CIM) alignment for common vendor sources; see the coverage table below for the vendor list and depth
- support for internal data dictionaries that describe indexes, sourcetypes, tables, connectors, and fields
- lower-token guidance optimized for Claude Opus 4.6 and Codex GPT-5.4
- helper metadata for both Codex/OpenAI and Claude-style prompting, with parity of detail enforced by the validator

## Repository layout

```text
siem_fun/
|-- .github/
|   `-- workflows/
|       `-- validate.yml
|-- .claude/
|   `-- settings.json
|-- .env.example
|-- .gitignore
|-- examples/
|   `-- golden-prompts.md
|-- CLAUDE.md
|-- README.md
|-- QUERY_SKILL_PLAN.md
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

## Best way to use it

The query builder skill works best when your prompt includes three things:

1. The platform: `Splunk`, `Sentinel`, or `both`
2. The task: hunt, detection, triage, dashboard, translation, or optimization
3. The environment context: index names, table names, or an internal data-dictionary URL

The model performs better when you give it the real schema instead of asking it to guess.

If your client supports named skills, the best path is to invoke it explicitly:

```text
Use $splunk-sentinel-query-builder to ...
```

Use the data dictionary builder first when you do not yet know the local Splunk schema:

```text
Use $splunk-data-dictionary-builder to discover accessible Splunk indexes, sourcetypes, fields, sample values, and CIM data model coverage.
```

Use the enrichment query builder when the user provides a list of indexes to cover, names a vendor product or Splunkbase add-on, or needs GreyNoise IP enrichment:

```text
Use $splunk-enrichment-query-builder to build a hunt across index=firewall, index=proxy, and index=endpoint that enriches source IPs with GreyNoise classification.
```

## Local Setup

The repo includes shared Claude Code defaults in [.claude/settings.json](.claude/settings.json). Per-user Claude settings stay ignored in `.claude/settings.local.json`.

If you use the Splunk data dictionary helper script, copy [.env.example](.env.example) to `.env` and fill in local values. The `.env` file is ignored and should never be committed.

Build a local Splunk data dictionary with:

```powershell
python .\splunk-data-dictionary-builder\scripts\build_splunk_dictionary.py --base-url https://splunk.example.com:8089 --token $env:SPLUNK_TOKEN --output .\out\splunk-data-dictionary.json
```

The script writes one JSON file describing the instance:

- `indexes` and `sourcetypes`: what is accessible, with `cim_datamodel_hints` on recognized vendor sourcetypes
- `cim_datamodels`: installed data models with their root datasets and acceleration status, enough to build `datamodel=MODEL.ROOT_DATASET` queries
- `cim_coverage`: which sourcetypes actually feed each data model, queried live from the instance as ground truth that supersedes the static hints
- `field_samples`: sampled fields, observed types, and example values per index/sourcetype
- `warnings` and `permission_notes`: gaps that may reflect role permissions rather than true absence

The coverage pass runs extra `tstats` searches; add `--no-cim-coverage` to skip it on large or slow instances. Pass the JSON, or a relevant excerpt, to the query builder as the internal data dictionary.

Validation parses the helper YAML with the `powershell-yaml` module, so install it
once first:

```powershell
Install-Module powershell-yaml -Scope CurrentUser -Force
```

Then run validation locally with:

```powershell
pwsh -NoProfile -File .\scripts\validate-skill-pack.ps1
```

Run the validator's own unit tests (no test framework required):

```powershell
pwsh -NoProfile -File .\scripts\tests\validate-skill-pack.tests.ps1
```

Run the dictionary builder unit tests (stdlib only, nothing to install):

```bash
python -m unittest discover -s splunk-data-dictionary-builder/tests
```

Mutation-check the suites and the validator (reintroduces each bug and asserts
it is caught; also runs in CI):

```bash
python3 scripts/tests/mutation-check.py
```

Tests tagged `REGRESSION` pin behavior that a shipped defect got wrong. Keep them
passing rather than adjusting the expectation, and add a case whenever a bug is
fixed in the builder.

## How the content is kept correct

Roughly half of this repository is verification tooling, and that is
deliberate. The reference documents are read by a model at query time, so an
error in them is not a documentation bug -- it is a wrong query, and in SPL and
KQL a wrong query usually returns nothing rather than an error. The tooling
exists to make that class of mistake fail the build instead.

What the validator enforces on every run:

- **Identifier provenance.** Every sourcetype written in the colon-delimited
  form (`cisco:asa`) must be catalogued in the Splunkbase catalogue or the CIM
  alignment reference. That covers most of them but not all: colon-free and
  hyphenated names such as `WinEventLog`, `fgt_traffic` and `zscalernss-web`
  are real, catalogued, and **not yet checked**, so an invented name in that
  shape passes today. The intended fix is a positional check on `sourcetype=`
  that does not depend on the name's shape, which is how the Sentinel check
  below already works. Every
  Sentinel table named in table position in a KQL block must be catalogued in
  the Sentinel table catalogue, where each entry cites Microsoft's own
  documentation. The Sentinel comparison is case-sensitive, because the tables
  are.
- **SPL correctness.** Unquoted booleans in `| where`, bare `index=` chains
  that should be `index IN (...)`, raw-event searches with no time bound, and
  `| lookup ... OUTPUT` fields that the same document does not list.
- **Structural integrity.** Helper YAML parity across the Claude and Codex
  files, relative links that resolve, markdown tables whose rows match their
  header, ASCII-only bytes on disk, and no conflict markers.
- **Its own completeness.** Every check the validator performs is listed in
  [scripts/required-checks.txt](scripts/required-checks.txt) and cross-checked
  in both directions, so a check cannot be deleted quietly.

What the mutation harness proves: each of those checks is broken on purpose,
under both CRLF and LF line endings, and the validator is asserted to fail
*and name the right reason*. A check that exists but never fires is
indistinguishable from no check at all, and three checks in this repository's
history were exactly that on the only operating system CI runs them on. The
harness runs in CI on every pull request.

What is deliberately **not** checked, and why, is recorded in
[CLAUDE.md](CLAUDE.md): field names, because no exhaustive per-dataset
registry exists; and lookup-null handling, because whether a filter *means* to
keep unmatched rows cannot be read off the text.

## Security

This public repo has GitHub secret scanning, push protection, Dependabot alerts, and Dependabot security updates enabled. Local secret-like files are ignored by `.gitignore`; use `.env.example` as the documented template and keep real credentials in `.env`.

## Splunk CIM and vendor integration coverage

The query builder is aligned with the Splunk Common Information Model so hunts and detections can target shared data models instead of per-vendor sourcetypes. The mapping lives in [splunk-sentinel-query-builder/references/cim-vendor-alignment.md](splunk-sentinel-query-builder/references/cim-vendor-alignment.md). The data dictionary builder complements it from the live instance: it tags recognized vendor sourcetypes with CIM hints, reports installed data models with their root datasets and acceleration status, and queries actual CIM coverage by sourcetype so query generation can rely on ground truth rather than assumed mappings.

Degree of detail per integration:

| Integration | Coverage level | What is documented |
| --- | --- | --- |
| Zscaler (ZIA and ZPA) | Mapped | NSS/LSS sourcetypes, Web / Network_Traffic / Network_Resolution / Network_Sessions models, key CIM fields, feed-configuration caveats |
| CrowdStrike Falcon | Mapped | FDR sensor sourcetype with the Endpoint model (CIM covers a subset of events) and the Event Streams alerts sourcetype with the Alerts model, plus the field-divergence caveat between the two feeds |
| Palo Alto Networks (PAN-OS) | Mapped | pan:traffic / pan:threat / pan:globalprotect sourcetypes and their Network_Traffic, Intrusion_Detection, Malware, Web, Authentication models |
| Cisco (ASA, Firepower/FTD, Umbrella, ISE) | Mapped | Per-product sourcetypes and their Network_Traffic, Intrusion_Detection, Network_Resolution, Authentication, Network_Sessions models |
| Microsoft Windows Defender / Defender for Endpoint | Mapped | Both the Defender for Endpoint alert feed and the on-host operational log path, with Alerts / Malware / Endpoint models and key fields |
| Proofpoint (TAP and PPS) | Mapped | TAP and mail gateway sourcetypes with Email / Malware models and key fields |
| Web proxy infrastructure (ProxySG, Squid, generic) | Mapped | The Web data model as the shared proxy contract, with the canonical field set and cross-proxy query strategy |
| Cloudflare | Partial | HTTP, firewall, and Gateway DNS log mappings to Web / Intrusion_Detection / Network_Resolution; field availability flagged as dependent on app version and Logpush field selection |
| Akamai App & API Protector | Mapped | akamaisiem sourcetype with Web / Intrusion_Detection models and key fields |
| Akamai Noname (API Security) | Outline | Guidance only: no standard CIM add-on exists, so events are treated as Alerts with locally verified field aliases |
| Other vendors | Procedure | A generic four-step process: find the add-on, check its tags, verify model coverage with tstats, fall back to the dictionary builder |

What "Mapped" means here: typical add-on sourcetypes, target CIM data models, key normalized fields, tstats query patterns, and coverage-verification queries are documented at the query-guidance level. This repo does not ship add-on configurations (props/transforms), detection content, or index names - index naming is deployment-specific and should come from discovery or the data dictionary builder.

## Quick-start prompt patterns

Use prompts shaped like these:

```text
Use $splunk-sentinel-query-builder to build a Splunk hunt query for suspicious PowerShell execution in index=windows earliest=-24h.
```

```text
Build a Splunk hunt query for suspicious PowerShell execution in index=windows earliest=-24h.
```

```text
Optimize this Sentinel query for speed and explain the tuning changes:
[paste query]
```

```text
Translate this SPL to KQL and preserve the detection logic:
[paste query]
```

```text
Use this internal data dictionary URL and build a Splunk detection for failed admin logons:
https://internal.example/data-dictionary
```

```text
I do not know the right indexes yet. Give me a discovery query and tell me the smallest missing schema facts.
```

## Best prompt format

If you want the most reliable output, use this template:

```text
Platform: Splunk | Sentinel | Both
Task: hunt | detection | triage | dashboard | translation | optimization
Objective: what you want to find or detect
Time range: last 1h | 24h | 7d
Data dictionary URL or schema notes: optional but strongly recommended
Known datasets: indexes, sourcetypes, tables, connectors
Known fields: user, host, src, dest, process, hash, url, action
Output style: short | full
```

## Internal data dictionary workflow

This repo is especially useful when your environment has internal documentation that explains:

- which Splunk indexes are authoritative
- which sourcetypes or sources are preferred
- which Sentinel tables or normalized schemas should be used
- which field names are canonical
- which datasets are deprecated, delayed, or expensive

When you provide an internal URL or excerpt, the skill should use that as the source of truth for schema decisions.

If the model cannot directly access the URL, the best fallback is to provide:

- a pasted excerpt
- a table export
- a screenshot converted to text
- a short list of the relevant indexes, tables, and fields

For lower token use, paste only the relevant section of the data dictionary instead of the whole page.

## What good output should look like

The exact sections are declared in each skill's `SKILL.md`, which is the single
source of truth; this is a reader's summary, not a second definition. For the
query builder the default shape is:

1. `Objective`
2. `Query`
3. `Why efficient`
4. `Assumptions`
5. `Data dictionary notes`
6. `Tuning`
7. `Validate`

For short prompts (`Output style: short`), the answer is just:

- `Objective`
- `Query`
- `Assumptions`

## Tips for better results

- Give exact index names and sourcetypes for Splunk whenever possible.
- Give exact table names and connectors for Sentinel whenever possible.
- Provide a time range so the model can optimize for performance.
- Ask for a discovery query when you are unsure of the schema.
- Ask for translation only after clarifying the source dataset mapping.
- Ask for tuning if you already have a working query and want it faster or cleaner.

## Model guidance

This repo has been tuned for:

- Claude Opus 4.6
- Codex GPT-5.4

To get the best results with either model:

- invoke the skill explicitly when possible
- ask for a structured answer
- keep the objective narrow
- give real schema context
- avoid asking for tutorials unless you actually want explanation
- ask for short output when you only need a working query

## Common use cases

- build a Splunk data dictionary from accessible indexes and sourcetypes
- hunt across multi-vendor sources through one CIM data model query
- build a new hunt query from a detection idea
- turn a hunt into a detection
- optimize a slow Splunk or Sentinel query
- translate SPL to KQL
- translate KQL to SPL
- use internal schema documentation to avoid bad assumptions
- generate discovery queries when the environment is unclear
- build a hunt across multiple user-provided indexes with Splunkbase-aware field knowledge
- enrich query results with GreyNoise noise and threat-intelligence classification
- look up Splunkbase add-on sourcetypes and CIM field mappings for a named vendor product

## Files to read

- [CLAUDE.md](CLAUDE.md): conventions, enforced invariants, and language traps for anyone (human or agent) changing this repo
- [QUERY_SKILL_PLAN.md](QUERY_SKILL_PLAN.md): the design record -- why each part was built, and the one item still open
- [.claude/settings.json](.claude/settings.json): shared Claude Code defaults
- [.env.example](.env.example): optional local helper environment variables
- [examples/golden-prompts.md](examples/golden-prompts.md): golden prompt fixtures for review and testing
- [scripts/validate-skill-pack.ps1](scripts/validate-skill-pack.ps1): local validation for metadata, links, helpers, and encoding
- [scripts/tests/validate-skill-pack.tests.ps1](scripts/tests/validate-skill-pack.tests.ps1): unit tests for the validator's helper functions, including regression coverage for past defects
- [scripts/tests/mutation-check.py](scripts/tests/mutation-check.py): reintroduces each bug the tests exist for and asserts it is caught, and proves every validator check fires
- [scripts/required-checks.txt](scripts/required-checks.txt): the inventory of checks the validator must perform, cross-checked against it in both directions
- [splunk-data-dictionary-builder/scripts/build_splunk_dictionary.py](splunk-data-dictionary-builder/scripts/build_splunk_dictionary.py): the helper script the Local Setup section runs
- [splunk-data-dictionary-builder/SKILL.md](splunk-data-dictionary-builder/SKILL.md): skill for building Splunk data dictionaries, including the JSON output shape
- [splunk-data-dictionary-builder/references/workflow.md](splunk-data-dictionary-builder/references/workflow.md): discovery strategy, CIM coverage, and query-builder handoff
- [splunk-data-dictionary-builder/tests/test_build_splunk_dictionary.py](splunk-data-dictionary-builder/tests/test_build_splunk_dictionary.py): unit tests for the dictionary builder helpers, including regression coverage for past defects
- [splunk-sentinel-query-builder/agents/openai.yaml](splunk-sentinel-query-builder/agents/openai.yaml): UI metadata and default skill prompt
- [splunk-sentinel-query-builder/agents/codex-gpt-5.4.yaml](splunk-sentinel-query-builder/agents/codex-gpt-5.4.yaml): detailed Codex/OpenAI companion helper
- [splunk-sentinel-query-builder/agents/claude-opus.yaml](splunk-sentinel-query-builder/agents/claude-opus.yaml): companion helper for Claude-style prompting
- [splunk-sentinel-query-builder/SKILL.md](splunk-sentinel-query-builder/SKILL.md): main skill instructions
- [references/query-workflow.md](splunk-sentinel-query-builder/references/query-workflow.md): query workflow
- [references/cim-vendor-alignment.md](splunk-sentinel-query-builder/references/cim-vendor-alignment.md): CIM data models and vendor sourcetype mappings
- [references/splunk-to-kql-mapping.md](splunk-sentinel-query-builder/references/splunk-to-kql-mapping.md): translation support
- [references/sentinel-table-catalog.md](splunk-sentinel-query-builder/references/sentinel-table-catalog.md): the provenance registry for Sentinel table names
- [references/data-dictionary-integration.md](splunk-sentinel-query-builder/references/data-dictionary-integration.md): internal URL usage
- [references/examples-and-troubleshooting.md](splunk-sentinel-query-builder/references/examples-and-troubleshooting.md): prompt patterns and failure handling
- [references/model-guidance.md](splunk-sentinel-query-builder/references/model-guidance.md): model-specific prompt tuning
- [splunk-enrichment-query-builder/SKILL.md](splunk-enrichment-query-builder/SKILL.md): multi-index enrichment skill instructions
- [splunk-enrichment-query-builder/references/splunkbase-app-catalog.md](splunk-enrichment-query-builder/references/splunkbase-app-catalog.md): Splunkbase add-on sourcetypes, key fields, and CIM mappings
- [splunk-enrichment-query-builder/references/multi-index-patterns.md](splunk-enrichment-query-builder/references/multi-index-patterns.md): SPL patterns for multi-index search and iteration
- [splunk-enrichment-query-builder/references/greynoise-integration.md](splunk-enrichment-query-builder/references/greynoise-integration.md): GreyNoise SPL commands, lookups, and enrichment patterns
- [splunk-enrichment-query-builder/references/splunk-cloud-index-management.md](splunk-enrichment-query-builder/references/splunk-cloud-index-management.md): Splunk Cloud index properties, stack types, and REST API

## Practical note

This repo does not replace knowledge of your own environment. The best results come from combining the skill with:

- real indexes or tables
- real field names
- real detection goals
- real internal documentation

That combination is what turns the output from "generic SIEM prompt" into something operational.
