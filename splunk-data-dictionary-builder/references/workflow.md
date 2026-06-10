# Splunk Data Dictionary Workflow

## Use this file when

- building a data dictionary from a Splunk instance
- troubleshooting Splunk connection or permissions
- preparing schema context for query generation

## Discovery Strategy

Start cheap and broad, then sample narrowly:

1. List accessible indexes through Splunk REST.
2. Use `tstats` to enumerate sourcetypes per index.
3. List installed data models and their acceleration status through Splunk REST.
4. Sample a small number of events per index/sourcetype.
5. Collect field names, observed types, and sample values.
6. Tag recognized vendor sourcetypes with likely CIM data models.
7. Record permission warnings and incomplete coverage.

## CIM Mapping

The helper script reports CIM facts at three levels of trust:

- `cim_coverage` is ground truth: for each model root dataset it queries the live instance with `| tstats count from datamodel=MODEL.ROOT_DATASET by sourcetype` and records which sourcetypes actually feed the model. This also captures mappings that sourcetype names cannot express, such as on-host Windows Defender events reaching the Malware model. Disable with `--no-cim-coverage` when the extra searches are too costly.
- `cim_datamodels` lists installed models with `root_datasets` and acceleration status, enough to build the qualified `datamodel=MODEL.ROOT_DATASET` form directly.
- `cim_datamodel_hints` are static fallback hints for sourcetypes from common add-ons (Zscaler, Akamai, Microsoft Defender, CrowdStrike, Cloudflare, Proofpoint, web proxies, Cisco, Palo Alto). A hint means the sourcetype is usually CIM-mapped by its standard add-on; actual coverage depends on the add-on being installed and tags being intact. When `cim_coverage` is present, prefer it over hints; unrecognized sourcetypes may still be CIM-mapped by custom local configuration.

## Permissions Handling

If an index or endpoint is hidden by role permissions, do not call it absent. Record:

- endpoint attempted
- status code
- message returned by Splunk
- likely remediation, such as asking a Splunk admin for role access

## Output Guidance

The dictionary should be useful to an LLM and a human analyst:

- keep field samples short
- record source index and sourcetype for every field
- preserve exact field names and casing
- note fields that appear sparsely
- include warnings when samples are too small

## Query Builder Handoff

Pass the generated JSON or a relevant excerpt to `splunk-sentinel-query-builder` as the internal data dictionary. The query builder should treat exact index, sourcetype, and field names from this output as higher priority than generic assumptions. Prefer a CIM `tstats` query for a sourcetype when `cim_coverage` shows it feeding a model root dataset, using `summariesonly=true` only if that model is accelerated in `cim_datamodels`; use raw sourcetype searches for everything else. Fall back to `cim_datamodel_hints` for this decision only when coverage data is absent.
