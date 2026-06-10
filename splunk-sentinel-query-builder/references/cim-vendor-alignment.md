# Splunk CIM and Vendor Alignment

## Use this file when

- the environment ingests multi-vendor security data into Splunk
- a hunt or detection should work across products that feed the same CIM data model
- the user names a vendor (Zscaler, CrowdStrike, Palo Alto, Cisco, Cloudflare, Proofpoint, Akamai, Microsoft Defender, a web proxy) and the query should use normalized fields
- you must decide between raw sourcetype fields and CIM data model fields

## Core rule

Prefer CIM data model names and fields when the source is CIM-mapped by its add-on. Fall back to raw vendor sourcetypes only when:

- the data model is not populated or not accelerated for the needed window
- the query needs vendor-specific fields the CIM does not carry
- coverage verification (below) shows the sourcetype is not mapped

Never assume index names. Indexes are deployment-specific; verify with discovery or the data dictionary builder output.

## CIM data models that matter here

| Data model | Root dataset | Core fields |
| --- | --- | --- |
| Web | Web | action, src, dest, url, uri_path, http_method, status, http_user_agent, bytes_in, bytes_out, category, user |
| Network_Traffic | All_Traffic | action, src, dest, dest_port, transport, app, rule, bytes_in, bytes_out, user |
| Network_Resolution | DNS | src, dest, query, reply_code, record_type, answer |
| Network_Sessions | All_Sessions | action, src_ip, dest_ip, user, duration |
| Authentication | Authentication | action, app, src, dest, user, signature, authentication_method |
| Endpoint | Processes, Filesystem, Registry, Services | process, process_name, parent_process_name, process_guid, dest, user, action |
| Malware | Malware_Attacks | signature, action, file_name, file_path, file_hash, dest, user, vendor_product |
| Email | All_Email | action, src_user, recipient, subject, file_name, file_hash, url, message_id |
| Intrusion_Detection | IDS_Attacks | signature, severity, action, src, dest, category, vendor_product |
| Alerts | Alerts | severity, signature, src, dest, user, vendor_product, description |

## CIM query patterns

Qualify the `from` clause as `datamodel=MODEL.ROOT_DATASET`, per the Splunk `tstats` reference. Field references keep the root dataset prefix (`Web.src`, `All_Traffic.dest`). Splunk also accepts the bare model name for single-root models (Splunk ESCU detections commonly ship that form), but the qualified form works everywhere and is required for multi-root models. Select a child dataset with `where nodename=ROOT_DATASET.CHILD_DATASET`.

Accelerated data model search (fast path):

```spl
| tstats summariesonly=true count from datamodel=Web.Web where Web.action="blocked" by Web.src, Web.user, Web.url
```

```spl
| tstats summariesonly=true count from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port=445 by All_Traffic.src, All_Traffic.dest
```

```spl
| tstats summariesonly=true count from datamodel=Authentication.Authentication where Authentication.action="failure" by Authentication.user, Authentication.src
```

Drop `summariesonly=true` when the model is not accelerated or very recent events matter. The Endpoint model has several root datasets (Processes, Filesystem, Registry, Services); select one in the `from` clause and prefix fields with it:

```spl
| tstats summariesonly=true count from datamodel=Endpoint.Processes by Processes.process_name, Processes.dest
```

## Coverage verification

Before shipping a CIM-backed query, verify which sourcetypes feed the model:

```spl
| tstats count from datamodel=Web.Web by index, sourcetype
```

Spot-check normalized events:

```spl
| datamodel Web search | head 5
```

Check tagging when a sourcetype is missing from the model:

```spl
sourcetype=YOUR_SOURCETYPE | head 5 | table tag, eventtype, sourcetype
```

If a vendor sourcetype is absent from the expected model, return `discovery` with these queries instead of guessing.

## Vendor mappings

Sourcetypes below are the typical names produced by the standard Splunkbase add-on for each product. Real deployments rename indexes and sometimes sourcetypes, so verify with the coverage queries above or with `splunk-data-dictionary-builder` output.

### Zscaler (ZIA and ZPA)

- Add-on: Splunk Add-on for Zscaler (NSS or Cloud NSS feeds).
- `zscalernss-web` -> Web: action, src, dest, url, http_method, status, user, bytes_in, bytes_out, category.
- `zscalernss-fw` -> Network_Traffic: action, src, dest, dest_port, transport.
- `zscalernss-dns` -> Network_Resolution: src, query, reply_code.
- `zscalerlss-zpa-app` -> Network_Sessions and Web: user, src_ip, dest_ip, application access.
- Caveat: feed configuration controls which fields are emitted; missing CIM fields usually mean a trimmed NSS feed, not a parsing bug.

### Akamai

- App & API Protector / Kona via the Akamai SIEM Integration add-on: `akamai:siem` -> Web and Intrusion_Detection: action, src, dest, url, signature, severity.
- Akamai Noname (API Security): no standard CIM-mapped Splunkbase add-on; events usually arrive as custom JSON over HEC. Treat as Alerts (severity, signature, description) plus Web-style fields through local aliases. Confirm local field names with the data dictionary builder before writing detections; this mapping is outline-level only.

### Microsoft Windows Defender / Defender for Endpoint

- Defender for Endpoint alerts via the Splunk Add-on for Microsoft Security: `ms:defender:atp:alerts` -> Alerts, Malware, Endpoint: signature, severity, dest, user, file_name, file_hash.
- On-host Windows Defender operational log via the Splunk Add-on for Microsoft Windows: `XmlWinEventLog` with source `Microsoft-Windows-Windows Defender/Operational` -> Malware: signature, action, file_name, file_path, dest, user.

### CrowdStrike Falcon

- Add-on: CrowdStrike Falcon Event Streams: `crowdstrike:events:sensor` -> Endpoint, Malware, Intrusion_Detection: process, parent_process_name, file_hash, dest, user, action, severity, signature.
- Falcon Data Replicator (FDR) feeds Endpoint at higher volume; field names differ from Event Streams, so verify before reusing a query across both.

### Cloudflare

- Logpush to HEC, commonly `cloudflare:json`.
- HTTP request logs -> Web: src, dest, url (ClientRequestURI alias), status, action, http_user_agent.
- Firewall events -> Web and Intrusion_Detection: action, signature, src.
- Gateway DNS -> Network_Resolution: src, query, reply_code.
- Caveat: CIM compliance depends on the Cloudflare app version and Logpush field selection; treat field availability as partial until verified.

### Proofpoint

- TAP via the Proofpoint TAP modular input: `proofpoint:tap:siem` (message and click events) -> Email and Malware: src_user, recipient, subject, url, file_name, file_hash, action.
- Proofpoint email gateway (PPS): `pps_messagelog` -> Email: src_user, recipient, subject, action, message_id.

### Web proxy infrastructure (generic)

The Web data model is the canonical contract for every proxy. Once mapped, one tstats pattern covers all of them:

- Symantec ProxySG / Blue Coat: `bluecoat:proxysg:access:*` -> Web.
- Squid: `squid:access` -> Web.
- Zscaler web (above), Cloudflare Gateway, and other forward proxies -> Web.
- Key fields: action, src, dest, url, status, http_method, http_user_agent, bytes_in, bytes_out, category, user.

### Cisco

- ASA via the Splunk Add-on for Cisco ASA: `cisco:asa` -> Network_Traffic, Network_Sessions (VPN), Authentication: src, dest, dest_port, action, transport, user.
- Firepower / FTD via eStreamer (eNcore) or Cisco Security Cloud: `cisco:estreamer:data` -> Intrusion_Detection and Network_Traffic: signature, severity, src, dest, action.
- Umbrella via the Cisco Umbrella add-on: `cisco:umbrella:dns` -> Network_Resolution (and Web for proxied traffic): src, query, action, category.
- ISE: `cisco:ise:syslog` -> Authentication and Network_Sessions: user, src, action, authentication_method.

### Palo Alto Networks (PAN-OS)

- Add-on: Palo Alto Networks Add-on for Splunk (Splunk_TA_paloalto).
- `pan:traffic` -> Network_Traffic: src, dest, dest_port, action, app, rule, bytes_in, bytes_out.
- `pan:threat` -> Intrusion_Detection and Malware; URL filtering subtype -> Web: signature, severity, action, url, category.
- `pan:globalprotect` -> Authentication and Network_Sessions: user, src, action.

### Any other vendor

1. Find the vendor add-on on Splunkbase and note its sourcetypes.
2. Check which CIM models its tags and eventtypes target.
3. Run the coverage verification queries above against those models.
4. If no add-on or mapping exists, build the schema with `splunk-data-dictionary-builder` and query raw sourcetypes with explicit assumptions.

## Cross-vendor query strategy

For hunts that span vendors (for example, blocked web traffic across Zscaler, Cloudflare, and Palo Alto URL filtering):

1. Query the shared data model once instead of OR-ing vendor sourcetypes.
2. Group by `sourcetype` or `vendor_product` in the output so per-vendor gaps are visible.
3. State which vendors were verified as feeding the model and which are assumed.
4. If one vendor is not CIM-mapped, add a second raw-sourcetype query for it rather than weakening the CIM query.
