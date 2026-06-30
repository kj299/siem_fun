# Multi-Index Query Patterns

## Use this file when

- the user provides a list of two or more Splunk indexes
- a hunt or detection needs to cover multiple data sources in one query
- you need to enumerate what is inside a set of provided indexes before writing a production query
- per-index sourcetype schemas differ and need separate filters

## Discovery pass (run first when sourcetypes are unknown)

Enumerate sourcetypes across all provided indexes:

```spl
| tstats count where index IN (idx1, idx2, idx3) by index, sourcetype
| sort - count
```

Scope to one index and add host:

```spl
| tstats count where index=idx1 by host, sourcetype
```

Return these queries (and stop) before writing a production query when:
- the exact sourcetype within a provided index is unknown
- a CIM-backed detection is requested but data model coverage is unconfirmed
- the query depends on a field name that may vary by add-on or parser

## Index filter patterns

### Preferred: `index IN (...)` (Splunk 8.2+)

```spl
index IN (firewall, proxy, dns) sourcetype=pan:traffic earliest=-24h
| stats count by src, dest, dest_port
```

`index IN (...)` is evaluated at the Bloom filter layer and scales better than an equivalent `OR` chain.

### `OR` chain (Splunk 7.x and earlier, or when only two indexes)

```spl
(index=firewall OR index=proxy) sourcetype=pan:traffic earliest=-24h
```

### Per-index sourcetype filter (when schemas differ across indexes)

When indexes feed different add-ons with different field names, filter per-index and normalize with `coalesce`:

```spl
((index=firewall sourcetype=cisco:asa) OR (index=proxy sourcetype=bluecoat:proxysg:access:kv) OR (index=dns sourcetype=cisco:umbrella:dns))
earliest=-24h
| eval common_src=coalesce(src, src_ip, ClientIP)
| eval common_dest=coalesce(dest, dest_ip, url)
| stats count by common_src, common_dest, sourcetype
```

### CIM-backed multi-index query (preferred when CIM is populated)

One `tstats` call covers all contributing sourcetypes regardless of index. The CIM data model handles the fan-out:

```spl
| tstats summariesonly=true count from datamodel=Network_Traffic.All_Traffic
  where index IN (firewall, proxy)
  by All_Traffic.src, All_Traffic.dest, All_Traffic.dest_port, index, sourcetype
```

Drop `summariesonly=true` when the model is not accelerated or events are very recent (within the last few minutes).

### Subsearch from a lookup (dynamic index list)

When the index list is stored in a CSV lookup file:

```spl
[inputlookup index_list.csv | rename index_name as index | return 100 index]
sourcetype=pan:traffic earliest=-24h
```

`return` converts each row into an `OR`-ed index filter up to the specified row limit.

### Macro expansion (for recurring multi-index queries)

Define a macro `security_indexes` that expands to the standard index filter:

```spl
`security_indexes` sourcetype=pan:traffic earliest=-24h
```

Macro definition in Splunk: `index IN (firewall, proxy, dns, endpoint)`.

## tstats patterns across multiple indexes

Enumerate indexed fields and counts by index:

```spl
| tstats count where index IN (idx1, idx2, idx3) by index, sourcetype, _time span=1d
```

Verify that a specific field is indexed before using it as a filter:

```spl
| tstats values(src) where index IN (firewall, proxy) by index, sourcetype
```

An empty result for a field means the field is not index-time extracted; a raw-event search with inline extraction is required.

## Per-index summary in one pass

Produce counts broken down by index and sourcetype:

```spl
index IN (firewall, proxy, endpoint) earliest=-24h
| stats count by index, sourcetype
| sort - count
```

## Iterating over a user-provided index list

When the user provides N index names, build the filter dynamically and validate with a discovery pass first:

```spl
| tstats count where index IN (user_index_1, user_index_2, user_index_3) by index, sourcetype, _time span=1h
| sort - count
```

After sourcetypes are confirmed, replace with the production query using the same `index IN (...)` filter.

## Performance guidance

- Always specify `earliest` and `latest` before other filters; time bounds are the first optimization Splunk applies.
- Add `sourcetype=` after the index filter when sourcetypes are known. This eliminates unrelated events before any pipeline processing.
- Use `| tstats` for counting, bucketing, and summary queries. It reads TSIDX metadata and avoids raw event decompression.
- Avoid `index=*` in production queries. Enumerate known indexes explicitly.
- When different indexes feed the same CIM data model, one `tstats from datamodel=` query replaces N `OR`-ed sourcetype filters.
- For high-cardinality fields, use `tstats count` grouped by that field rather than `stats` on raw events.
