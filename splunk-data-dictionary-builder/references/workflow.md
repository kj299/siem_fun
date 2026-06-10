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

The helper script tags sourcetypes from common add-ons (Zscaler, Akamai, Microsoft Defender, CrowdStrike, Cloudflare, Proofpoint, web proxies, Cisco, Palo Alto) with `cim_datamodel_hints` and lists installed data models under `cim_datamodels`, including each model's `root_datasets` so consumers can build the qualified `datamodel=MODEL.ROOT_DATASET` form directly. Treat hints as starting points, not proof of coverage:

- a hint means the sourcetype is usually CIM-mapped by its standard add-on
- actual coverage depends on the add-on being installed and tags being intact
- confirm with `| tstats count from datamodel=MODEL.ROOT_DATASET by index, sourcetype` (for example `datamodel=Web.Web`) before relying on a data model
- unrecognized sourcetypes may still be CIM-mapped by custom local configuration

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

Pass the generated JSON or a relevant excerpt to `splunk-sentinel-query-builder` as the internal data dictionary. The query builder should treat exact index, sourcetype, and field names from this output as higher priority than generic assumptions. When `cim_datamodel_hints` and an accelerated model in `cim_datamodels` agree, the query builder should prefer a CIM `tstats` query over raw sourcetype searches.
