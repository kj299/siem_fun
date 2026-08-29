---
name: splunk-enrichment-query-builder
description: Build Splunk queries that span multiple user-provided indexes with Splunkbase add-on sourcetype and field knowledge, and optionally enrich results with GreyNoise threat intelligence. Use when the user provides a list of indexes, names a Splunkbase add-on or vendor product, or requests IP-based enrichment in a Splunk environment. Do not use for Sentinel/KQL queries, data dictionary generation, or single-index queries where the schema is fully known.
---

# Splunk Enrichment Query Builder

Use this skill to build multi-index Splunk queries grounded in Splunkbase add-on field schemas and enriched with GreyNoise context when IP addresses are present.

## Important

- Never invent index names, sourcetypes, or GreyNoise field names. If the schema is uncertain, return a discovery query from [multi-index-patterns.md](references/multi-index-patterns.md) and stop.
- Prefer `index IN (...)` over `OR`-chained index filters (Splunk 6.6+). It is shorthand for the same OR chain, so prefer it for readability, not speed.
- GreyNoise enrichment requires the GreyNoise App for Splunk (SA-GreyNoise). Fall back to a join against the app's `greynoise_indicators` KV store lookup when the custom commands are unavailable, inspecting its fields with `inputlookup` first.
- Splunk Cloud imposes index naming and management constraints that differ from self-managed deployments; see [splunk-cloud-index-management.md](references/splunk-cloud-index-management.md).
- Never ask the user to paste API tokens, passwords, or Splunk credentials into chat.

## Inputs

Required:
- `indexes`: one or more index names provided by the user
- `task`: hunt | detection | triage | enrichment | discovery
- `objective`: what to find, detect, or enrich

Optional but recommended:
- `sourcetypes`: known sourcetypes within the provided indexes
- `greynoise`: yes | no (default: include when IP fields are present)
- `time_range`: earliest=-24h | -7d | etc.
- `output_style`: short | full
- `environment`: splunk-cloud | self-managed
- `data_dictionary`: URL or pasted excerpt from an internal data dictionary

## Workflow

### 1. Classify each index

For each provided index name:
1. If sourcetypes are unknown, return the enumeration query from [multi-index-patterns.md](references/multi-index-patterns.md) and stop before writing a production query. Use the discovery shape defined in step 4; the query is
   `| tstats count where index IN (<indexes>) by index, sourcetype | sort - count`.
2. If sourcetypes are known or can be inferred from the index name, look them up in [splunkbase-app-catalog.md](references/splunkbase-app-catalog.md) to identify CIM model mappings and key fields.
3. When the environment is Splunk Cloud, check index naming and REST constraints in [splunk-cloud-index-management.md](references/splunk-cloud-index-management.md).

### 2. Build the multi-index query

Use patterns from [multi-index-patterns.md](references/multi-index-patterns.md):
- Prefer `index IN (idx1, idx2, ...)` for simple multi-index event searches.
- Use per-index sourcetype filters when schemas differ significantly across indexes.
- Prefer CIM data model queries via `tstats` when multiple source types feed the same model.

### 3. Enrich with GreyNoise (when IP fields are present)

When the query output contains IP fields (src, dest, src_ip, dest_ip, ClientIP, or equivalent), add GreyNoise enrichment per [greynoise-integration.md](references/greynoise-integration.md):
- Use `gnenrich ip_field="<field>"` when the GreyNoise App is installed.
- Fall back to a `lookup greynoise_indicators` join when the custom command is unavailable, confirming the lookup's key field with `inputlookup` first.
- Filter known-benign infrastructure only when the chosen path actually returns a
  Business Services Intelligence / RIOT field. `greynoise_indicators` does not carry
  one; `gnquick` and `gn_scan_deployment_ip_lookup` do. Otherwise filter on
  `classification` and say so in `Assumptions` rather than inventing a field.

### 4. Shape the output

Default output:
1. Objective
2. Query
3. Why efficient
4. Assumptions
5. Enrichment notes (if GreyNoise added)
6. Tuning
7. Validate

Short output (`output_style: short`):
1. Objective
2. Query
3. Assumptions

Discovery mode (step 1) overrides both, whatever `output_style` was requested:
1. Objective (one line naming what is unknown)
2. Discovery query
3. Next step
4. Assumptions (only if something was inferred; omit otherwise)

Never emit a `Tuning`, `Validate`, or `Why efficient` section whose content is
"not applicable". A section with nothing to say means the wrong shape was chosen.

## References

- [splunkbase-app-catalog.md](references/splunkbase-app-catalog.md): Splunkbase add-on sourcetypes, key fields, and CIM data model mappings
- [multi-index-patterns.md](references/multi-index-patterns.md): SPL patterns for multi-index search, discovery, and iteration
- [greynoise-integration.md](references/greynoise-integration.md): GreyNoise SPL commands, lookup files, field reference, and enrichment patterns
- [splunk-cloud-index-management.md](references/splunk-cloud-index-management.md): Splunk Cloud index properties, naming constraints, REST API, and stack types
