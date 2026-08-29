# Splunk Cloud Platform Index Management

## Use this file when

- the environment is Splunk Cloud (not Splunk Enterprise on-prem)
- you need to enumerate, create, or validate indexes in Splunk Cloud
- the query involves `_internal`, `_audit`, or other system indexes
- index retention or sizing constraints affect query design
- federated search across Splunk Cloud stacks is required
- the user asks about index limits, naming rules, or data archive options

## Stack types

Splunk Cloud runs on two infrastructure models:

| Feature | Victoria Experience | Classic Experience |
| --- | --- | --- |
| Self-service index creation | Yes, via Settings > Indexes in Splunk Web | No; requires a Splunk Support case |
| Programmatic index management | Yes, via ACS at `admin.splunk.com` | Limited; structural changes go through Support |
| Direct forwarder port (9997) | Yes | Yes |
| HEC ingestion | Yes | Yes |
| `_internal` access | Restricted; granted through the admin role, not self-service | Restricted by default |
| Storage tiers | Hot/Warm/Frozen + Dynamic Data Active Archive | Same |
| Self-service index count | Up to the subscription tier limit | Same via Support |

Victoria is the default for new Splunk Cloud deployments. Classic stacks remain for legacy customers.

## Index naming constraints

Rules that apply to both stack types:

- Lowercase letters, digits, hyphens (`-`), and underscores (`_`) only.
- Cannot start with a hyphen or underscore.
- Cannot contain the word `kvstore` anywhere in the name.
- A leading `_` denotes an internal index and is reserved.
- Valid examples: `firewall`, `prod-windows-endpoint`, `aws_cloudtrail_2024`.

Verify the current constraint set against Splunk Cloud documentation before
scripting index creation; limits differ by stack type and change between releases.

## Index types

| Type | `datatype` value | Use case |
| --- | --- | --- |
| Event | `event` | Timestamped log events (default) |
| Metric | `metric` | Numeric time-series data for `mstats` queries |

`datatype` is set at creation time and cannot be changed afterward. There is no
`summary` datatype: a summary index is an ordinary `event` index that happens to
receive `sistats`/`sitimechart` output from a scheduled search.

## Key index properties

| Property | Description | Default on Splunk Cloud |
| --- | --- | --- |
| `maxTotalDataSizeMB` | Maximum on-disk size before data is frozen | Subscription-dependent; often 500 GB per index |
| `frozenTimePeriodInSecs` | Age in seconds after which events freeze (deleted or archived) | Subscription-dependent; commonly 90 days on Splunk Cloud. 188697600 (~6 years) is the Splunk Enterprise indexes.conf default, not a Cloud default. |
| `homePath` | Hot/warm bucket path | Platform-managed; do not set manually |
| `coldPath` | Cold bucket path | Platform-managed |
| `enableDataIntegrityControl` | SHA-256 hash per bucket for tamper detection | Configurable on request |

On Splunk Cloud, `homePath` and `coldPath` are platform-managed. Setting them manually causes errors.

## Dynamic Data Active Archive (DDAA)

DDAA provides long-term object-storage retention beyond the standard frozen window:

- Archived data is retained in object storage (S3-equivalent) and is searchable on demand.
- Archived buckets are not immediately queryable; a restore operation warms them to an accessible tier first.
- Use `frozenTimePeriodInSecs` to control when events transition from cold to the archive tier.
- DDAA requires a separate subscription entitlement. Contact Splunk to enable it.

When writing queries that may touch archived data, budget additional latency and inform the user that a restore step may be needed.

## Enumerating indexes via REST (management token required)

```spl
| rest /services/data/indexes splunk_server=local
| table title, datatype, totalEventCount, frozenTimePeriodInSecs, maxTotalDataSizeMB, disabled
```

List only enabled event indexes sorted by event volume:

```spl
| rest /services/data/indexes splunk_server=local
| where datatype="event" AND disabled="0"
| table title, totalEventCount, frozenTimePeriodInSecs, maxTotalDataSizeMB
| sort - totalEventCount
```

On Splunk Cloud, `splunk_server` must be `local` or the search head hostname. Wildcard REST calls to indexers are blocked by default.

## Enumerating indexes via tstats (no admin permissions required)

Any user whose role grants read access to an index can enumerate it:

```spl
| tstats count where index=* by index
| sort - count
```

Scoped to known indexes (faster and safer in production):

```spl
| tstats count where index IN (firewall, proxy, endpoint, cloud) by index, sourcetype
```

## System indexes and access restrictions

| Index | Contents | Splunk Cloud access |
| --- | --- | --- |
| `_internal` | Platform logs: scheduler, metrics, dispatch | Admin role only |
| `_audit` | Search audit and file integrity events | Admin role only |
| `_introspection` | Splunk performance metrics | Admin role only |
| `_telemetry` | Anonymous usage telemetry | Not user-accessible |
| `history` | Search job history | Owner only |
| `summary` | Output from scheduled summary searches | User-accessible if role grants it |

If a query must target `_internal` (for audit or performance investigation), use the Splunk Monitoring Console or request a platform-managed query through Splunk Support.

## Federated search

Federated search allows a Splunk Cloud deployment to query an external Splunk Enterprise environment or a second Splunk Cloud stack as a remote peer. In standard mode, address the remote index by prefixing its name with `federated:`:

```spl
index=federated:remote_firewall sourcetype=cisco:asa earliest=-24h
| stats count by src, dest
```

Prerequisites:
- A federated provider configured under Settings > Federated Search, with a federated index defined that maps to the remote index.
- Network connectivity and mutual trust between the environments.
- The `federated:` prefix is applied to the index name itself (`index=federated:<name>`); the search otherwise uses standard syntax.

## Creating an index (Victoria, self-service)

**Splunk Web**: Settings > Indexes > New Index > fill in name, type, and retention.

**Admin Config Service (ACS)**, the supported programmatic path on Victoria:

```bash
curl -H "Authorization: Bearer $SPLUNK_ACS_TOKEN" \
  https://admin.splunk.com/YOUR-STACK/adminconfig/v2/indexes \
  -H "Content-Type: application/json" \
  -d '{"name":"new_index","searchableDays":90,"maxDataSizeMB":0}'
```

ACS is the supported path for CREATING and modifying indexes on Splunk Cloud, and
it takes its own parameters (`searchableDays`, `maxDataSizeMB`) rather than
indexes.conf keys. The search head's `:8089/services/data/indexes` endpoint
remains available for READING index metadata, which is what the `| rest` queries
above rely on. Confirm the current ACS surface against Splunk's ACS
documentation before scripting against it.
Never pass `-k`: it disables certificate verification while sending a bearer
token, and both `admin.splunk.com` and stack hostnames present valid public CA
certificates. Take the token from the environment rather than pasting it inline.

**Classic stack**: open a Splunk Support case with the index name, type, retention period, and maximum size.

## Query design considerations for Splunk Cloud

- Always specify `earliest` and `latest`; Splunk Cloud deployments often hold years of data across many indexes.
- Use explicit `index IN (...)` filters rather than `index=*`.
- `_internal` queries require admin access and should go through the Monitoring Console.
- For high-volume indexes, use `tstats` with a CIM data model to avoid raw event scans.
- Archived data in DDAA is not immediately searchable; restore latency may be minutes to hours depending on bucket count.
- REST API calls to `/services/data/indexes` on Classic stacks may be blocked or return partial results without a management token.
