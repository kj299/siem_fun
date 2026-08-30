# GreyNoise Splunk Integration

Verified against the SA-GreyNoise app source (commands.conf, transforms.conf, README
on GitHub) and GreyNoise documentation. Where the app's exact join fields or value
casing are not documented, the patterns below inspect before relying on them, per
this repo's rule to discover rather than guess.

## Use this file when

- a query surfaces IP fields (src, dest, src_ip, dest_ip, ClientIP, or equivalent) and enrichment with internet-noise context reduces false positives
- you need to filter background scanner traffic from an investigation
- the user asks for GreyNoise-enriched detections, dashboards, or feeds
- you need GreyNoise field names, SPL commands, or lookup table names

## GreyNoise concepts

| Term | Meaning |
| --- | --- |
| Noise | An IP observed mass-scanning or crawling the public internet (Shodan-style scanners, vulnerability scanners, opportunistic exploiters). A noisy IP is likely opportunistic, not a targeted threat. |
| Business Services Intelligence (formerly RIOT, "Rule It Out") | IPs belonging to known internet services such as Google DNS, AWS CloudFront, and Fastly. Filter these first to reduce alert volume. Older app versions and field names still say RIOT. |
| Classification | One of four values: `malicious`, `suspicious`, `benign`, `unknown`. |
| Tags | Behavioral labels such as `SSH Scanner`, `Tor Exit Node`, `Mirai`, `Log4Shell Exploit`, `VNC Scanner`, `Web Crawler`. |

## Installation

Install the **GreyNoise App for Splunk** (SA-GreyNoise, Splunkbase app 4113). The app:
- Registers the custom SPL commands listed below
- Ships KV store and CSV lookups populated by scheduled saved searches (v3.0.0 moved from CSV to KV store lookups)
- Includes three dashboards: **Overview**, **Queried IP Addresses**, and **Live Investigation**
- Requires a valid GreyNoise API key configured under Apps > GreyNoise App for Splunk > Configuration

## Custom SPL commands

Per the app's `commands.conf`, the registered commands are: `gnip`, `gnquick`,
`gnquery`, `gnstats`, `gnmulti`, `gncontext`, `gnfilter`, `gnenrich`,
`gnoverview`, `gniptimeline`, `gncve`, and `maintaincache`.

The two most used in query building:

### `gnenrich` - enrich search results with GreyNoise context

Enriches the events returned by a search with context for the IPs in a named
field. The argument is `ip_field`:

```spl
index=firewall sourcetype=cisco:asa earliest=-24h
| where isnotnull(src) AND match(src, "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
| stats count by src
| gnenrich ip_field="src"
```

### `gncontext` / `gnip` - full context for a single IP

```spl
| gncontext ip="203.0.113.42"
```

`gnquick` returns the lighter noise/BSI status check, `gnquery` runs GNQL
queries, and `gnfilter` filters events by noise status. Command-based
enrichment calls the GreyNoise API, so batch or pre-filter large result sets.
See the app README for the full syntax of each command.

## Lookup-based enrichment (no API calls at search time)

The app ships lookups populated on a schedule:

| Lookup | Type | Notes |
| --- | --- | --- |
| `greynoise_indicators` | KV store | Feed indicators; enrichment fields include `actor`, `first_seen`, `last_seen`, `classification`, `tags`, `cve`, `source_country`, `asn`. The IP key field is deliberately not named here because it varies by app version; confirm it with `inputlookup` before joining. Populated by the `greynoise_feed` saved search; indicators with `last_seen` older than 7 days are purged. |
| `gn_scan_deployment_ip_lookup` | KV store | Results for IPs queried from your deployment; fields include `noise`, `RIOT`, `classification`, `business_service_intelligence`, `internet_scanner_intelligence`. |
| `greynoise_ip_intel_malicious` / `_suspicious` / `_unknown` / `_benign` | CSV | Per-classification IP intel files. |

Inspect a lookup's actual fields and value formats before joining against it;
they vary by app version:

```spl
| inputlookup greynoise_indicators | head 5
```

Join pattern once fields are confirmed:

```spl
index=firewall sourcetype=cisco:asa action=blocked earliest=-24h
| where isnotnull(src) AND match(src, "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
| stats count by src
| lookup greynoise_indicators ip AS src OUTPUT classification, tags, actor, last_seen
| where classification="malicious" OR classification="suspicious"
| sort - count
```

Confirm the lookup's IP field name from the `inputlookup` inspection first; if
the join returns no matches, the key field name differs in your app version.

## Field reference

Fields come from different GreyNoise API responses; no single flat schema
carries all of them:

| Origin | Fields |
| --- | --- |
| Quick check (`gnquick`) | `ip`, `noise` (boolean), `riot` (boolean) |
| Context (`gncontext` / `gnip`) | `ip`, `first_seen`, `last_seen`, `seen`, `tags`, `actor`, `spoofable`, `classification`, `cve`, `bot`, `vpn`, plus `metadata.asn`, `metadata.city`, `metadata.country`, `metadata.country_code`, `metadata.organization` |
| `greynoise_indicators` lookup | `actor`, `first_seen`, `last_seen`, `classification`, `tags`, `cve`, `source_country`, `asn`, plus a version-dependent IP key field (confirm with `inputlookup`; the examples above show it as `ip`) |

When filtering on boolean-like fields (`noise`, `RIOT`) after a lookup join,
quote the comparison value: `| where` uses eval semantics, so an unquoted
`noise=true` reads `true` as a field name and matches nothing. Verify the
actual stored values first (`| inputlookup gn_scan_deployment_ip_lookup
| stats values(noise)`), since casing and type vary by app version. Unquoted
values are fine in the `search` command.

## Common enrichment patterns

### Bulk-enrich firewall traffic and keep the risky results

```spl
index=firewall sourcetype=cisco:asa action=permitted earliest=-24h
| where isnotnull(src) AND match(src, "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
| stats count by src
| gnenrich ip_field="src"
| search classification="malicious" OR classification="suspicious"
| sort - count
```

The IPv4 pre-filter keeps hostnames and IPv6 values out of the API-backed
command, which both saves quota and avoids unsupported lookups.

### Feed-based malicious IP match across indexes (no API calls)

```spl
index IN (firewall, proxy) earliest=-24h
| eval ip_field=coalesce(src, src_ip)
| where isnotnull(ip_field) AND match(ip_field, "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
| stats count by ip_field, index, sourcetype
| lookup greynoise_indicators ip AS ip_field OUTPUT classification, tags, actor, last_seen
| where classification="malicious"
| table ip_field, count, index, sourcetype, tags, actor, last_seen
```

Run the `inputlookup` inspection first to confirm the lookup's IP key field
name in your installed version.

### Single-IP triage during an investigation

```spl
| gncontext ip="203.0.113.42"
```

## Caveats

- Classification has four values (`malicious`, `suspicious`, `benign`, `unknown`); a filter that only handles three silently misses `suspicious`.
- Lookup freshness depends on the `greynoise_feed` schedule, and indicators with `last_seen` older than 7 days are purged from `greynoise_indicators`; use the commands when real-time accuracy matters.
- Command-based enrichment calls the GreyNoise API at search time; pre-filter to a small IP list for large result sets.
- GreyNoise coverage is primarily IPv4; verify IPv6 behavior for your subscription before relying on it.
- Command names and lookup schemas have changed between app versions; when in doubt, `| rest /services/data/commands splunk_server=local | search title=gn*` lists what your installed version registers.
