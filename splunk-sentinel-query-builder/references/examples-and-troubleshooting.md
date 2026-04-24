# Examples and Troubleshooting

## Use this file when

- you need concrete prompt patterns
- you need examples for Claude or Codex users
- the request is failing because schema, mapping, or source selection is unclear

## Example 1: Splunk hunt with known schema

User says:

```text
Use $splunk-sentinel-query-builder to build a Splunk hunt for suspicious PowerShell in index=windows earliest=-24h.
```

Expected behavior:

- return `query`
- use `index=windows` directly
- avoid generic placeholder indexes
- include short assumptions only if fields are not explicit

## Example 2: Sentinel optimization

User says:

```text
Optimize this Sentinel query for speed and explain the tuning changes:
[paste query]
```

Expected behavior:

- return `query` or `detection` depending on context
- push `where TimeGenerated` and high-selectivity filters earlier
- reduce columns with `project`
- explain only the tuning changes that materially affect performance

## Example 3: Translation with data dictionary

User says:

```text
Translate this SPL to KQL using this internal data dictionary excerpt:
[paste excerpt]
[paste query]
```

Expected behavior:

- return `translation`
- use documented tables and field aliases from the excerpt
- state schema gaps clearly if the excerpt is incomplete
- avoid pretending a one-to-one mapping exists when it does not

## Troubleshooting

### Problem: exact dataset names are missing

Cause:

- the environment context is too vague for a reliable production query

Response:

- return `discovery`
- provide the smallest discovery query that will identify the right index, sourcetype, or table

### Problem: internal URL cannot be opened

Cause:

- the model does not have access to the internal site from the current environment

Response:

- say that briefly
- request a short pasted excerpt only if it is needed to avoid a risky guess
- otherwise continue with discovery mode

### Problem: multiple plausible tables or indexes exist

Cause:

- the same detection intent could map to several datasets

Response:

- name the ambiguity
- prefer the authoritative source if the dictionary specifies one
- otherwise return discovery mode instead of choosing arbitrarily
