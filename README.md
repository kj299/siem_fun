# siem_fun

`siem_fun` is a prompt and skill pack for building better SIEM queries with:

- Splunk SPL
- Microsoft Sentinel KQL
- internal schema documentation such as data-dictionary URLs, wiki pages, and field references

The main goal is simple: help the model generate queries that are fast, environment-aware, and useful in real operations instead of generic demo syntax.

## What this repo gives you

- a reusable skill for Splunk and Sentinel query generation
- support for query building, query optimization, and SPL/KQL translation
- support for internal data dictionaries that describe indexes, sourcetypes, tables, connectors, and fields
- lower-token guidance optimized for Claude Opus 4.6 and Codex GPT-5.4

## Repository layout

```text
siem_fun/
|-- README.md
|-- QUERY_SKILL_PLAN.md
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

## Best way to use it

The skill works best when your prompt includes three things:

1. The platform: `Splunk`, `Sentinel`, or `both`
2. The task: hunt, detection, triage, dashboard, translation, or optimization
3. The environment context: index names, table names, or an internal data-dictionary URL

The model performs better when you give it the real schema instead of asking it to guess.

If your client supports named skills, the best path is to invoke it explicitly:

```text
Use $splunk-sentinel-query-builder to ...
```

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

- build a new hunt query from a detection idea
- turn a hunt into a detection
- optimize a slow Splunk or Sentinel query
- translate SPL to KQL
- translate KQL to SPL
- use internal schema documentation to avoid bad assumptions
- generate discovery queries when the environment is unclear

## Files to read

- [QUERY_SKILL_PLAN.md](QUERY_SKILL_PLAN.md): overall design and roadmap
- [agents/openai.yaml](splunk-sentinel-query-builder/agents/openai.yaml): UI metadata and default skill prompt
- [splunk-sentinel-query-builder/SKILL.md](splunk-sentinel-query-builder/SKILL.md): main skill instructions
- [references/query-workflow.md](splunk-sentinel-query-builder/references/query-workflow.md): query workflow
- [references/splunk-to-kql-mapping.md](splunk-sentinel-query-builder/references/splunk-to-kql-mapping.md): translation support
- [references/data-dictionary-integration.md](splunk-sentinel-query-builder/references/data-dictionary-integration.md): internal URL usage
- [references/model-guidance.md](splunk-sentinel-query-builder/references/model-guidance.md): model-specific prompt tuning

## Practical note

This repo does not replace knowledge of your own environment. The best results come from combining the skill with:

- real indexes or tables
- real field names
- real detection goals
- real internal documentation

That combination is what turns the output from "generic SIEM prompt" into something operational.
