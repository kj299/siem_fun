# siem_fun

`siem_fun` is a prompt and skill pack for building better SIEM queries with:

- Splunk SPL
- Microsoft Sentinel KQL
- internal schema documentation such as data-dictionary URLs, wiki pages, and field references

The main goal is simple: help the model generate queries that are fast, environment-aware, and useful in real operations instead of generic demo syntax.

## What this repo gives you

- a reusable skill for Splunk and Sentinel query generation
- a Splunk data dictionary builder skill with a local helper script that discovers indexes, sourcetypes, fields, installed CIM data models, and live CIM coverage by sourcetype
- Splunk Common Information Model (CIM) alignment for common vendor sources; see the coverage table below for the vendor list and depth
- support for query building, query optimization, and SPL/KQL translation
- support for internal data dictionaries that describe indexes, sourcetypes, tables, connectors, and fields
- lower-token guidance optimized for Claude Opus 4.6 and Codex GPT-5.4
- helper metadata for both Codex/OpenAI and Claude-style prompting, with parity of detail

## Repository layout

```text
siem_fun/
|-- .github/
|   `-- workflows/
|       `-- validate.yml
|-- .claude/
|   `-- settings.json
|-- .env.example
|-- examples/
|   `-- golden-prompts.md
|-- README.md
|-- QUERY_SKILL_PLAN.md
|-- scripts/
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

Run validation locally with:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\validate-skill-pack.ps1
```

## Security

This public repo has GitHub secret scanning, push protection, Dependabot alerts, and Dependabot security updates enabled. Local secret-like files are ignored by `.gitignore`; use `.env.example` as the documented template and keep real credentials in `.env`.

## Splunk CIM and vendor integration coverage

The query builder is aligned with the Splunk Common Information Model so hunts and detections can target shared data models instead of per-vendor sourcetypes. The mapping lives in [splunk-sentinel-query-builder/references/cim-vendor-alignment.md](splunk-sentinel-query-builder/references/cim-vendor-alignment.md). The data dictionary builder complements it from the live instance: it tags recognized vendor sourcetypes with CIM hints, reports installed data models with their root datasets and acceleration status, and queries actual CIM coverage by sourcetype so query generation can rely on ground truth rather than assumed mappings.

Degree of detail per integration:

| Integration | Coverage level | What is documented |
| --- | --- | --- |
| Zscaler (ZIA and ZPA) | Mapped | NSS/LSS sourcetypes, Web / Network_Traffic / Network_Resolution / Network_Sessions models, key CIM fields, feed-configuration caveats |
| CrowdStrike Falcon | Mapped | Event Streams sourcetype, Endpoint / Malware / Intrusion_Detection models, key fields, FDR field-divergence caveat |
| Palo Alto Networks (PAN-OS) | Mapped | pan:traffic / pan:threat / pan:globalprotect sourcetypes and their Network_Traffic, Intrusion_Detection, Malware, Web, Authentication models |
| Cisco (ASA, Firepower/FTD, Umbrella, ISE) | Mapped | Per-product sourcetypes and their Network_Traffic, Intrusion_Detection, Network_Resolution, Authentication, Network_Sessions models |
| Microsoft Windows Defender / Defender for Endpoint | Mapped | Both the Defender for Endpoint alert feed and the on-host operational log path, with Alerts / Malware / Endpoint models and key fields |
| Proofpoint (TAP and PPS) | Mapped | TAP and mail gateway sourcetypes with Email / Malware models and key fields |
| Web proxy infrastructure (ProxySG, Squid, generic) | Mapped | The Web data model as the shared proxy contract, with the canonical field set and cross-proxy query strategy |
| Cloudflare | Partial | HTTP, firewall, and Gateway DNS log mappings to Web / Intrusion_Detection / Network_Resolution; field availability flagged as dependent on app version and Logpush field selection |
| Akamai App & API Protector | Mapped | akamai:siem sourcetype with Web / Intrusion_Detection models and key fields |
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

A strong answer should usually include:

1. A clear objective
2. The query
3. Short assumptions
4. Performance or tuning notes
5. Validation guidance

For short prompts, the best answer is usually just:

- objective
- query
- assumptions

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

## Files to read

- [QUERY_SKILL_PLAN.md](QUERY_SKILL_PLAN.md): overall design and roadmap
- [.claude/settings.json](.claude/settings.json): shared Claude Code defaults
- [.env.example](.env.example): optional local helper environment variables
- [examples/golden-prompts.md](examples/golden-prompts.md): golden prompt fixtures for review and testing
- [scripts/validate-skill-pack.ps1](scripts/validate-skill-pack.ps1): local validation for metadata, links, helpers, and encoding
- [splunk-data-dictionary-builder/SKILL.md](splunk-data-dictionary-builder/SKILL.md): skill for building Splunk data dictionaries, including the JSON output shape
- [splunk-data-dictionary-builder/references/workflow.md](splunk-data-dictionary-builder/references/workflow.md): discovery strategy, CIM coverage, and query-builder handoff
- [agents/openai.yaml](splunk-sentinel-query-builder/agents/openai.yaml): UI metadata and default skill prompt
- [agents/codex-gpt-5.4.yaml](splunk-sentinel-query-builder/agents/codex-gpt-5.4.yaml): detailed Codex/OpenAI companion helper
- [agents/claude-opus.yaml](splunk-sentinel-query-builder/agents/claude-opus.yaml): companion helper for Claude-style prompting
- [splunk-sentinel-query-builder/SKILL.md](splunk-sentinel-query-builder/SKILL.md): main skill instructions
- [references/query-workflow.md](splunk-sentinel-query-builder/references/query-workflow.md): query workflow
- [references/cim-vendor-alignment.md](splunk-sentinel-query-builder/references/cim-vendor-alignment.md): CIM data models and vendor sourcetype mappings
- [references/splunk-to-kql-mapping.md](splunk-sentinel-query-builder/references/splunk-to-kql-mapping.md): translation support
- [references/data-dictionary-integration.md](splunk-sentinel-query-builder/references/data-dictionary-integration.md): internal URL usage
- [references/examples-and-troubleshooting.md](splunk-sentinel-query-builder/references/examples-and-troubleshooting.md): prompt patterns and failure handling
- [references/model-guidance.md](splunk-sentinel-query-builder/references/model-guidance.md): model-specific prompt tuning

## Practical note

This repo does not replace knowledge of your own environment. The best results come from combining the skill with:

- real indexes or tables
- real field names
- real detection goals
- real internal documentation

That combination is what turns the output from "generic SIEM prompt" into something operational.
