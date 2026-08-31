---
name: splunk-data-dictionary-builder
description: Build a structured data dictionary for a Splunk instance by discovering accessible indexes, sourcetypes, fields, sample values, and permission limits. Use when the user wants to inventory Splunk data, generate data dictionary JSON, or prepare schema context for SIEM query generation. Do not use for writing hunt queries unless the goal is first to discover Splunk schema.
---

# Splunk Data Dictionary Builder

Use this skill to generate schema context from a Splunk instance before authoring SPL or translating queries.

## Important

- Never ask the user to paste secrets into chat.
- Prefer environment variables, local `.env`, or explicit CLI arguments for credentials.
- Report permission gaps instead of treating missing indexes or fields as absent.
- Keep output structured so it can feed `splunk-sentinel-query-builder`.

## Inputs

Expect these when available:

- Splunk management API URL
- username/password or token
- target indexes or allowlist
- time window for sampling
- maximum events per index/sourcetype
- output path

## Workflow

1. Confirm the connection method and target scope.
2. Run [scripts/build_splunk_dictionary.py](scripts/build_splunk_dictionary.py) when local execution is appropriate.
3. If connection fails, explain whether the failure is auth, TLS, network, or permission related.
4. Summarize discovered indexes, sourcetypes, CIM data models, fields, and sampling limits.
5. Note which sourcetypes carry CIM data model hints so the output can drive CIM-first queries.
6. Save or return structured JSON.

## Output Shape

Return or write JSON with:

- `generated_at`
- `splunk_base_url`
- `indexes`
- `sourcetypes` (rows include `cim_datamodel_hints` for recognized vendor sourcetypes)
- `cim_datamodels` (installed data models with root dataset names and acceleration status, enough to build `datamodel=MODEL.ROOT_DATASET` queries)
- `cim_coverage` (per model root dataset: the sourcetypes actually feeding it with event counts; ground truth that supersedes `cim_datamodel_hints`)
- `field_samples` (per index/sourcetype: `fields` with `sample_values` and `observed_types`)
- `warnings`
- `permission_notes`

## Script Usage

Read credentials from the environment rather than typing them into the command.
A literal password or token on the command line lands in shell history and is
visible to every other user on the host through `ps`. Copy `.env.example` to
`.env` and export the values, or pass them as below:

```powershell
python .\splunk-data-dictionary-builder\scripts\build_splunk_dictionary.py --base-url $env:SPLUNK_BASE_URL --username $env:SPLUNK_USERNAME --password $env:SPLUNK_PASSWORD --output .\out\splunk-data-dictionary.json
```

For token auth:

```powershell
python .\splunk-data-dictionary-builder\scripts\build_splunk_dictionary.py --base-url $env:SPLUNK_BASE_URL --token $env:SPLUNK_TOKEN --output .\out\splunk-data-dictionary.json
```

## References

- Read [references/workflow.md](references/workflow.md) for discovery strategy, permissions handling, and output interpretation.
