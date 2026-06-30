# GreyNoise Splunk Integration

## Use this file when

- a query surfaces IP fields (src, dest, src_ip, dest_ip, ClientIP, or equivalent) and enrichment with internet-noise context reduces false positives
- you need to filter background scanner traffic from an investigation
- the user asks for GreyNoise-enriched detections, dashboards, or feeds
- you need GreyNoise field names, SPL commands, or lookup table names

## GreyNoise concepts

| Term | Meaning |
| --- | --- |
| Noise | An IP observed actively scanning or crawling the public internet. A `noise=true` IP is likely an opportunistic scanner, not a targeted threat. |
| RIOT (Rule It Out) | IPs belonging to known-benign services: Google, Cloudflare, AWS, Akamai, and similar web-scale platforms. Filter these first to reduce alert volume. |
| Classification | `malicious`: associated with known attack tooling or campaigns. `benign`: a recognized scanner or service with no attack history. `unknown`: not observed in GreyNoise data. |
| Tags | Behavioral labels such as `SSH Scanner`, `Tor Exit Node`, `Mirai`, `Log4Shell Exploit`, `VNC Scanner`, `Web Crawler`. |

## Installation

Install the **GreyNoise App and Add-On for Splunk** from Splunkbase. The app:
- Registers custom SPL commands (`gnlookup`, `gnenrich`, `gnmeta`)
- Ships two synced CSV lookup files (`greynoise_full.csv`, `greynoise_riot.csv`)
- Includes pre-built intelligence dashboards
- Requires a valid GreyNoise API key configured under the app setup page

## Custom SPL commands

### `gnlookup` - single IP lookup

Useful for investigating one IP ad hoc:

```spl
| gnlookup ip="203.0.113.42"
```

Returns one row with all GreyNoise context fields.

### `gnenrich` - bulk IP enrichment across a dataset

Enrich a field containing IP addresses across all rows of the current pipeline. Batches API calls automatically:

```spl
index=firewall sourcetype=cisco:asa earliest=-24h
| stats count by src
| gnenrich field=src
| where noise=true OR classification="malicious"
| sort - count
```

`gnenrich` requires a configured API key and consumes GreyNoise API quota. Pre-filter to a smaller IP list before enrichment on large result sets.

### `gnmeta` - account metadata

Returns API quota information and account context; useful for troubleshooting:

```spl
| gnmeta
```

## Lookup-based enrichment (no custom commands required)

Use the scheduled lookup files when the GreyNoise App is installed but the custom commands are unavailable, or for scheduled saved searches where API quota must be conserved.

### `greynoise_full.csv` - active noise and malicious IPs

```spl
index=firewall sourcetype=cisco:asa earliest=-24h
| stats count by src
| lookup greynoise_full ip AS src OUTPUT classification, noise, riot, tags, name, last_seen
| where noise=true OR classification="malicious"
| sort - count
```

### `greynoise_riot.csv` - known-benign service IPs

Use RIOT as a pre-filter to remove large-platform traffic before investigating:

```spl
index=proxy sourcetype=bluecoat:proxysg:access:kv earliest=-24h
| stats count by dest
| lookup greynoise_riot ip AS dest OUTPUT riot, name AS riot_service
| where isnull(riot) OR riot=false
| sort - count
```

## GreyNoise field reference

| Field | Type | Description |
| --- | --- | --- |
| `ip` | string | The IP address looked up |
| `noise` | boolean | True if the IP is actively scanning the public internet |
| `riot` | boolean | True if the IP belongs to a known-benign service |
| `classification` | string | `malicious`, `benign`, or `unknown` |
| `name` | string | Organization or actor name |
| `tags` | string | Comma-separated behavioral tags |
| `first_seen` | date | First date the IP was observed by GreyNoise |
| `last_seen` | date | Most recent observation date |
| `country` | string | Country of origin (full name) |
| `country_code` | string | ISO 3166-1 alpha-2 country code |
| `city` | string | City of origin |
| `organization` | string | ASN organization name |
| `asn` | string | Autonomous system number (e.g., AS15169) |
| `actor` | string | Named threat actor if known |
| `cve` | string | Associated CVE identifiers |

## Common enrichment patterns

### Noise filter: remove background scanners from a firewall investigation

```spl
index=firewall sourcetype=cisco:asa action=blocked earliest=-24h
| stats count by src
| lookup greynoise_full ip AS src OUTPUT noise, classification, tags
| where noise=false AND classification!="benign"
| sort - count
| table src, count, classification, tags
```

### Malicious IP detection: connections to or from known-malicious IPs

```spl
index IN (firewall, proxy) earliest=-24h
| eval ip_field=coalesce(src, src_ip, ClientIP)
| stats count by ip_field, index, sourcetype
| lookup greynoise_full ip AS ip_field OUTPUT classification, actor, tags, last_seen
| where classification="malicious"
| table ip_field, count, index, sourcetype, actor, tags, last_seen
```

### RIOT enrichment: identify traffic to major CDNs and SaaS platforms

```spl
index=proxy sourcetype=bluecoat:proxysg:access:kv earliest=-24h
| stats count by dest
| lookup greynoise_riot ip AS dest OUTPUT riot, name AS riot_service
| where riot=true
| stats sum(count) AS total_hits by riot_service
| sort - total_hits
```

### Emerging threats: IPs first seen by GreyNoise within the last 24 hours

```spl
| inputlookup greynoise_full
| where strptime(first_seen, "%Y-%m-%d") > relative_time(now(), "-24h@h")
| where classification="malicious"
| table ip, tags, actor, country, first_seen
```

### Cross-reference with internal firewall permit logs

```spl
index=firewall sourcetype=cisco:asa action=permitted earliest=-24h
| stats count by src
| lookup greynoise_full ip AS src OUTPUT classification, noise, riot, tags, actor, last_seen
| where classification="malicious" OR (noise=true AND riot=false)
| table src, count, classification, noise, tags, actor, last_seen
```

### Multi-index IP enrichment

When the user provides multiple indexes that each surface IP fields:

```spl
index IN (firewall, proxy, endpoint) earliest=-24h
| eval ip_field=coalesce(src, src_ip, dest, dest_ip)
| where isnotnull(ip_field) AND match(ip_field, "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
| stats count by ip_field, index, sourcetype
| lookup greynoise_full ip AS ip_field OUTPUT classification, noise, riot, tags, actor
| where classification="malicious" OR noise=true
| sort - count
| table ip_field, count, classification, noise, tags, actor, index
```

## Dashboard guidance

The GreyNoise App ships pre-built dashboards:

- **GreyNoise Intelligence**: top noise sources, classification breakdown, country and tag distribution
- **GreyNoise Threat Feed**: newly classified malicious IPs with actor and tag context

Custom dashboard base queries:
- Top noise countries: group `greynoise_full` by `country`, count rows, sort descending
- Classification trend: join `greynoise_full` to firewall logs, `timechart` by `classification`
- Emerging actors: filter `first_seen > -24h`, group by `actor`

## Caveats

- GreyNoise covers IPv4 addresses only. IPv6 addresses return no match.
- RIOT covers major cloud and CDN ranges but not every benign IP. Absence from RIOT does not imply the IP is malicious.
- `noise=true` means the IP sends unsolicited traffic to the public internet, not necessarily that it targeted your environment.
- `gnenrich` consumes API quota. Use the scheduled lookup files for high-volume or recurring searches.
- Lookup file freshness depends on the sync schedule configured in the app. Use `gnenrich` when real-time accuracy matters.
