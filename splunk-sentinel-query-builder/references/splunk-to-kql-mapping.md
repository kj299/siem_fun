# SPL to KQL Mapping

## Scope mapping

| Intent | Splunk | Sentinel |
| --- | --- | --- |
| Time filter | `earliest=`, `latest=` | `where TimeGenerated >= ago(...)` |
| Data scope | `index=`, `sourcetype=`, `source=`, `host=` | `TableName` plus `where` filters |
| Keep columns | `table`, `fields` | `project`, `project-away` |
| Rename column | `rename` | `project-rename` |

## Filtering and expressions

| Intent | Splunk | Sentinel |
| --- | --- | --- |
| Predicate filter | `search`, `where` | `where` |
| Calculated field | `eval` | `extend` |
| Conditional logic | `case()`, `if()` | `case()`, `iff()` |
| Regex extract | `rex` | `extract()`, `parse`, `parse kind=regex` |
| CIDR match | `cidrmatch()` | ipv4 helper functions or explicit range logic |

## Aggregation

| Intent | Splunk | Sentinel |
| --- | --- | --- |
| Grouped stats | `stats` | `summarize` |
| Time series | `timechart` | `summarize ... by bin(TimeGenerated, ...)` |
| Top values | `top` | `summarize count() by field | top` style ordering with `sort by` |
| Rare values | `rare` | `summarize count() by field | sort by count_ asc` |
| Deduplicate | `dedup` | `summarize arg_max()` or `distinct` patterns |

## Enrichment and joins

| Intent | Splunk | Sentinel |
| --- | --- | --- |
| Lookup enrichment | `lookup` | `lookup` or `join` or watchlist patterns |
| Append results | `append`, `appendcols` | `union`, join variants |
| Correlation | `transaction`, `stats`, `streamstats` | joins, sessionization, ordered summarize patterns |

## Practical notes

- `transaction` in Splunk often has no clean one-line KQL equivalent. Translate the behavior, not the command.
- Splunk free-text search near the start of the pipeline often maps poorly to Sentinel unless a specific column is known.
- Sentinel queries are usually stronger when you know the exact table and columns up front.
- Splunk queries usually become faster when index, sourcetype, and time are specified before regex or heavy transforms.
