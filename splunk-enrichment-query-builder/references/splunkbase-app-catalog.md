# Splunkbase App and Add-on Catalog

## Use this file when

- the user names a vendor product or Splunkbase add-on and the query needs to know its sourcetypes, key fields, or CIM data model mappings
- you need to verify what fields an add-on produces before writing a detection
- the user provides index names and you need to infer likely sourcetypes from them

## Splunkbase listing metadata

Each Splunkbase listing describes:

| Metadata | Description |
| --- | --- |
| App name / slug | Installable package name (e.g., `Splunk_TA_paloalto`) |
| Type | Add-on (TA) vs. App vs. Premium App |
| CIM version | Which CIM release the add-on targets |
| Platform compatibility | Splunk Cloud, Enterprise (on-prem), or both |
| Inputs | How data is collected: forwarder, modular input, HEC, REST poll |
| Sourcetypes | The `sourcetype` values the add-on assigns to parsed events |
| CIM tags | Which CIM data models the add-on populates via `eventtypes.conf` and `tags.conf` |
| Lookups | Reference tables shipped with the add-on |
| Custom commands | Any SPL commands the add-on registers |

## Verifying an installed add-on

List installed add-ons:

```spl
| rest /services/apps/local | search title="Splunk_TA_*" OR title="TA-*" | table title, version, visible
```

Check CIM tagging for a sourcetype:

```spl
sourcetype=YOUR_SOURCETYPE | head 5 | table tag, eventtype, sourcetype
```

Verify CIM coverage:

```spl
| tstats count from datamodel=Web.Web by sourcetype
```

## Endpoint security add-ons

### Splunk Add-on for Microsoft Windows (`Splunk_TA_windows`)

Since add-on v5.0.0 the sourcetypes are `WinEventLog` (Classic channels) and
`XmlWinEventLog` (XML channels); the channel lives in `source`. v8.8.0 renamed
the sourcetypes to lowercase (`wineventlog`, `xmlwineventlog`); SPL matching is
case-insensitive, so either casing searches both.

| Sourcetype | Source | CIM data model | Key fields |
| --- | --- | --- | --- |
| `WinEventLog` | `WinEventLog:Security` | Authentication, Endpoint | EventCode, user, src_user, dest, action |
| `XmlWinEventLog` | `XmlWinEventLog:Security` | Authentication, Endpoint | EventCode, user, src_user, dest, action |
| `WinEventLog` | `WinEventLog:System` | Change | EventCode, host |
| `WinEventLog` | `WinEventLog:Application` | Change | EventCode, host |
| `Perfmon:*` (e.g. `Perfmon:CPU`, `Perfmon:Memory`) | -- | Performance | object, counter, instance, Value |

Key EventCodes: 4624/4625 (logon/fail), 4648 (explicit logon), 4688 (process create), 4720/4726 (account create/delete), 4776 (NTLM auth), 4768/4769 (Kerberos TGT/TGS), 4663 (object access), 7045 (service install).

### Splunk Add-on for Sysmon (`Splunk_TA_microsoft_sysmon`)

| Sourcetype | Source | CIM data model | Key fields |
| --- | --- | --- | --- |
| `XmlWinEventLog` | `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` | Endpoint (Processes, Filesystem, Registry, Services, Ports) | EventCode, process, process_id, parent_process, dest, user, hash, TargetFilename, TargetObject |

The Windows Event Collector variant uses sourcetype `XmlWinEventLog:WEC-Sysmon`.
Older community Sysmon TAs assigned the full channel path as the sourcetype, so
`sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` still appears
in legacy deployments; on the Splunk-supported add-on, filter on the source.

Key EventCodes: 1 (process create), 3 (network connect), 7 (image load), 8 (create remote thread), 10 (process access), 11 (file create), 12/13/14 (registry), 22 (DNS query).

### CrowdStrike Falcon

| Add-on | Sourcetype | CIM data model | Key fields |
| --- | --- | --- | --- |
| Splunk Add-on for CrowdStrike FDR (app 5579) | `crowdstrike:events:sensor` | Endpoint (CIM normalization covers a subset of events) | event_simpleName, ComputerName, ImageFileName, CommandLine, SHA256HashData, LocalAddressIP4, RemoteAddressIP4 |
| Splunk Add-on for CrowdStrike FDR | `crowdstrike:inventory:aidmaster` | -- | aid, ComputerName, AgentVersion |
| CrowdStrike Falcon Event Streams TA (app 5082) | `CrowdStrike:Event:Streams:JSON` | Alerts | event_type, ComputerName, UserName, Severity |

Caveat: FDR sensor telemetry and Event Streams alerts use different field
names; verify before reusing a query across both feeds.

### Microsoft Defender for Endpoint (Splunk Add-on for Microsoft Security)

| Sourcetype | CIM data model | Key fields |
| --- | --- | --- |
| `ms:defender:atp:alerts` | Alerts, Malware, Endpoint | AlertId, Severity, title, machineId, computerDnsName, sha256, fileName, user |

On-host Windows Defender operational log (via `Splunk_TA_windows`):

| Sourcetype | Source | CIM data model | Key fields |
| --- | --- | --- | --- |
| `XmlWinEventLog` | `XmlWinEventLog:Microsoft-Windows-Windows Defender/Operational` | Malware | EventCode (1116/1117), Severity Name, Path, Threat Name |

### Carbon Black

| Add-on | Sourcetype | CIM data model | Key fields |
| --- | --- | --- | --- |
| Carbon Black Cloud (Endpoint Standard app) | `carbonblack:defense:json` | Endpoint, Malware | process_name, cmdline, parent_name, sha256, device_name, username |
| Splunk Add-on for Carbon Black EDR (app 2790) | `bit9:carbonblack:json` | Endpoint | process_name, cmdline, parent_name, md5, hostname |

Newer Carbon Black EDR guidance also uses `vmware:cb:edr:json`; confirm which
add-on feeds your indexes with a discovery query before writing detections.

## Network security add-ons

### Palo Alto Networks Add-on (`Splunk_TA_paloalto`)

| Sourcetype | CIM data model | Key fields |
| --- | --- | --- |
| `pan:traffic` | Network_Traffic | src, dest, dest_port, app, rule, action, bytes_in, bytes_out, transport |
| `pan:threat` | Intrusion_Detection, Web (url subtype), Malware (wildfire subtype) | signature, severity, action, category, url, file_hash |
| `pan:globalprotect` | Authentication, Network_Sessions | user, src, action, machine |
| `pan:system` | -- | eventid, object, result |
| `pan:hipmatch` | -- | host_id, match_name, user |

`pan:globalprotect` exists only in the newer PaloAltoNetworks Splunk-Apps TA
(v7+); the older Splunk_TA_paloalto routes GlobalProtect events without a
dedicated sourcetype.

### Cisco ASA (`Splunk_TA_cisco_asa`)

| Sourcetype | CIM data model | Key fields |
| --- | --- | --- |
| `cisco:asa` | Network_Traffic, Authentication, Network_Sessions | src, dest, dest_port, action, transport, user, bytes_in, bytes_out, signature |

Key message IDs: %ASA-6-106015 (deny by ACL), %ASA-5-111008 (user command), %ASA-6-716001 (VPN connect).

### Cisco Firepower / FTD eStreamer

| Sourcetype | CIM data model | Key fields |
| --- | --- | --- |
| `cisco:estreamer:data` | Intrusion_Detection, Network_Traffic | ImpactBits, Severity, SignatureId, GeneratorId, src, dest |

### Cisco Umbrella (Cisco Cloud Security Add-On for Splunk)

| Sourcetype | CIM data model | Key fields |
| --- | --- | --- |
| `cisco:umbrella:dns` | Network_Resolution, Web (proxied traffic) | src, query, action, category, reply_code |

### Cisco ISE

| Sourcetype | CIM data model | Key fields |
| --- | --- | --- |
| `cisco:ise:syslog` | Authentication, Network_Sessions | user, src, dest, action, authentication_method, endpoint_id |

### Fortinet FortiGate

| Sourcetype | CIM data model | Key fields |
| --- | --- | --- |
| `fgt_traffic` | Network_Traffic | srcip, dstip, dstport, action, app, proto, rcvdbyte, sentbyte |
| `fgt_utm` | Intrusion_Detection, Web | subtype, level, msg, action |
| `fgt_event` | Change | subtype, level, msg |

`fgt_log` is the raw input sourcetype the add-on re-types into
`fgt_traffic`/`fgt_utm`/`fgt_event`; do not filter on it in detections.

### Check Point

| Sourcetype | CIM data model | Key fields |
| --- | --- | --- |
| `cp_log` | Network_Traffic, Intrusion_Detection | orig, src, dst, service, action, rule, proto |

### Juniper Junos

| Sourcetype | CIM data model | Key fields |
| --- | --- | --- |
| `juniper:junos:firewall` / `juniper:junos:firewall:structured` | Network_Traffic | src, dest, dest_port, action, transport |
| `juniper:junos:idp` / `juniper:junos:idp:structured` | Intrusion_Detection | signature, severity, src, dest |

Bare `juniper:junos` is not an assigned sourcetype; the add-on always
suffixes the log family.

### F5 BIG-IP

| Sourcetype | CIM data model | Key fields |
| --- | --- | --- |
| `f5:bigip:apm:syslog` | Authentication, Network_Sessions | user, src, session_id |
| `f5:bigip:asm:syslog` | Web, Intrusion_Detection | attack_type, violations, src_ip, dest_ip, request |

iRule-based LTM access logging via Splunk Connect for Syslog uses
`f5:bigip:ltm:access_json`.

## Web and proxy add-ons

### Zscaler (`Splunk_TA_zscaler` / NSS or Cloud NSS)

| Sourcetype | CIM data model | Key fields |
| --- | --- | --- |
| `zscalernss-web` | Web | src, dest, url, action, status, user, bytes_in, bytes_out, category |
| `zscalernss-fw` | Network_Traffic | src, dest, dest_port, action, transport |
| `zscalernss-dns` | Network_Resolution | src, query, reply_code |
| `zscalerlss-zpa-app` | Network_Sessions, Web | user, src_ip, dest_ip, app |

### Symantec ProxySG / Blue Coat

| Sourcetype | CIM data model | Key fields |
| --- | --- | --- |
| `bluecoat:proxysg:access:kv` | Web | src, dest, url, action, status, http_method, http_user_agent, bytes_in, bytes_out, category |

### Cloudflare (`cloudflare-app-for-splunk`)

| Sourcetype | CIM data model | Key fields |
| --- | --- | --- |
| `cloudflare:json` | Web, Intrusion_Detection, Network_Resolution | ClientIP, ClientRequestURI, EdgeResponseStatus, WAFAction, WAFRuleID, QueryName |

Field availability depends on Logpush field selection; treat as partial until verified.

### Akamai SIEM Integration

| Sourcetype | CIM data model | Key fields |
| --- | --- | --- |
| `akamaisiem` | Web, Intrusion_Detection | attackData.rules, attackData.ruleActions, httpMessage.requestHeaders, geo.country |

### Squid Proxy

| Sourcetype | CIM data model | Key fields |
| --- | --- | --- |
| `squid:access` | Web | src, dest, url, action, status, http_method, bytes_out |

### Imperva WAF

| Sourcetype | CIM data model | Key fields |
| --- | --- | --- |
| `imperva:waf` | Web, Intrusion_Detection | src, dest, url, action, severity, sig_id, http_method |

## Email security add-ons

### Proofpoint TAP

| Sourcetype | CIM data model | Key fields |
| --- | --- | --- |
| `proofpoint_tap_siem` | Email, Malware | sender, recipient, subject, url, hash, action, threatStatus |

### Proofpoint Protection Server (PPS)

| Sourcetype | CIM data model | Key fields |
| --- | --- | --- |
| `pps_messagelog` | Email | sender, recipients, subject, action, disposition |

The same add-on also assigns the companion sourcetype `pps_maillog`.

## Identity and access add-ons

### Okta Identity Cloud Add-on for Splunk

| Sourcetype | Source | CIM data model | Key fields |
| --- | --- | --- | --- |
| `OktaIM2:log` | `okta:im2` | Authentication | user, src_ip, action, outcome, authenticationContext.authenticationStep, client.userAgent.rawUserAgent |

`okta:im2` is the *source* on all events from this add-on; the sourcetypes are
`OktaIM2:log` plus per-object types (`OktaIM2:user`, `OktaIM2:group`,
`OktaIM2:app`, `OktaIM2:groupUser`, `OktaIM2:appUser`).

### Duo Security (Duo Splunk Connector)

| Sourcetype | CIM data model | Key fields |
| --- | --- | --- |
| `duo` | Authentication | user, result, reason, factor, ip, integration |

The Duo Splunk Connector reached end of life on May 1, 2025; Cisco's Security
Cloud app is the successor. Confirm the sourcetype with a discovery query on
deployments migrated after that date.

### Active Directory (via `Splunk_TA_windows`)

Events from `WinEventLog:Security` cover AD authentication. Additional AD-specific channels:

| Sourcetype | Source | CIM data model | Key fields |
| --- | --- | --- | --- |
| `WinEventLog` | `Active Directory Web Services` | Change | EventCode, src_user, dest_user |

## DNS and network resolution add-ons

### Infoblox (Splunk Add-on for Infoblox)

| Sourcetype | CIM data model | Key fields |
| --- | --- | --- |
| `infoblox:dns` | Network_Resolution | src, query, record_type, reply_code, answer |
| `infoblox:dhcp` | Network_Sessions | src_ip, dest, lease_time, mac |

### Windows DNS (via `Splunk_TA_windows`)

| Sourcetype | Source | CIM data model | Key fields |
| --- | --- | --- | --- |
| `XmlWinEventLog` | `Microsoft-Windows-DNS-Server/Analytical` | Network_Resolution | EventCode, QNAME, QTYPE, PacketData |

## Cloud platform add-ons

### Splunk Add-on for AWS (`Splunk_TA_aws`)

| Sourcetype | CIM data model | Key fields |
| --- | --- | --- |
| `aws:cloudtrail` | Authentication, Change | eventName, userIdentity.arn, sourceIPAddress, errorCode, awsRegion |
| `aws:s3:accesslogs` | Web | remote_ip, bucket, key, operation, http_status, bytes_sent |
| `aws:cloudwatchlogs:vpcflow` | Network_Traffic | srcAddr, dstAddr, dstPort, protocol, action, logStatus |
| `aws:cloudwatch:guardduty` | Alerts, Intrusion_Detection | type, severity, description, resource.instanceDetails |
| `aws:securityhub:finding` | Alerts | Title, Severity.Label, ProductArn, FindingProviderFields |
| `aws:config` | Change | configurationItem.resourceType, changeType |

The newer standalone Splunk Add-on for AWS Security Hub emits
`ocsf:aws:securityhub:finding` instead.

### Microsoft Azure

Two different add-ons cover Azure; do not mix their sourcetypes.

Splunk Add-on for Microsoft Cloud Services (`Splunk_TA_microsoft-cloudservices`):

| Sourcetype | CIM data model | Key fields |
| --- | --- | --- |
| `mscs:azure:audit` | Change, Authentication | operationName, caller, resultType |
| `mscs:nsg:flow` | Network_Traffic | src_ip, dest_ip, dest_port, protocol, action |
| `azure:monitor:aad` | Authentication, Change | Event Hub AAD logs; SignInLogs and AuditLogs are categories within this sourcetype |

Splunk Add-on for Microsoft Azure (TA-MS-AAD, community-supported):

| Sourcetype | CIM data model | Key fields |
| --- | --- | --- |
| `azure:aad:signin` | Authentication | userPrincipalName, ipAddress, status.errorCode, clientAppUsed, location |
| `azure:aad:audit` | Change | operationType, result, initiatedBy |

### Splunk Add-on for Google Cloud

| Sourcetype | CIM data model | Key fields |
| --- | --- | --- |
| `google:gcp:pubsub:message` | -- | Pub/Sub-delivered logs, including Cloud Audit payloads |
| `google:gcp:pubsub:audit:auth` | Authentication | protoPayload.methodName, protoPayload.authenticationInfo.principalEmail |
| `google:gcp:pubsub:audit:change` | Change | protoPayload.methodName, resource.type |
| `google:gcp:buckets:jsondata` / `google:gcp:buckets:csvdata` | -- | bucket-input payloads by format |

## Vulnerability management add-ons

### Tenable Add-on for Splunk

| Sourcetype | CIM data model | Key fields |
| --- | --- | --- |
| `tenable:io:vuln` | Vulnerabilities | severity, plugin_name, cve, dest, port |
| `tenable:io:assets` | -- | ip, hostname, os, last_seen |

### Qualys Add-on

| Sourcetype | CIM data model | Key fields |
| --- | --- | --- |
| `qualys:hostDetection` | Vulnerabilities | severity, qid, title, ip, port |

The add-on's event type `qualys_vm_detection_event` searches
`qualys:hostDetection` (and the legacy `qualys_vm_detection`).

## Threat intelligence add-ons (lookups only, no sourcetypes)

These add-ons provide lookup files and custom commands, not sourcetypes.

| Add-on | Lookup / command | Key fields |
| --- | --- | --- |
| GreyNoise App for Splunk (SA-GreyNoise) | `greynoise_indicators` KV lookup; commands `gnquick`, `gncontext`, `gnenrich` | classification, tags, actor, cve, first_seen, last_seen |
| Recorded Future App | `recordedfuture_threat` lookup | risk_score, evidence_summary, triggered_rules |
| VirusTotal Add-on | `vt` custom command | positives, permalink, scan_date |

See [greynoise-integration.md](greynoise-integration.md) for GreyNoise field details and SPL patterns.

## NetFlow add-ons

| Add-on | Sourcetype | CIM data model | Key fields |
| --- | --- | --- | --- |
| Splunk Add-on for NetFlow (`Splunk_TA_flowfix`; deprecated 2019, EOL) | `netflow` | Network_Traffic | src_ip, dst_ip, dst_port, protocol, in_bytes, out_bytes, packets |
| Splunk Stream (current Splunk-shipped path) | `stream:netflow` | Network_Traffic | src_ip, dest_ip, dest_port, protocol, bytes_in, bytes_out |

Do not recommend the EOL add-on for new deployments; `netflow` still appears
in environments that predate its retirement.

## Inferring sourcetypes from index name patterns

When the user provides index names but no sourcetypes, apply these heuristics before returning a discovery query:

| Index name pattern | Likely sourcetypes | First step |
| --- | --- | --- |
| `*firewall*`, `*paloalto*`, `*pan*` | `pan:traffic`, `cisco:asa`, `fgt_traffic` | `tstats count where index=NAME by sourcetype` |
| `*network*`, `*netflow*` | `netflow`, `pan:traffic` | same |
| `*endpoint*`, `*edr*`, `*crowdstrike*` | `crowdstrike:events:sensor`, `XmlWinEventLog` | same |
| `*proxy*`, `*web*`, `*zscaler*` | `zscalernss-web`, `bluecoat:proxysg:access:kv` | same |
| `*dns*` | `cisco:umbrella:dns`, `infoblox:dns` | same |
| `*cloud*`, `*aws*` | `aws:cloudtrail`, `aws:cloudwatchlogs:vpcflow` | same |
| `*azure*` | `mscs:azure:audit`, `azure:aad:signin` | same |
| `*email*`, `*mail*`, `*proofpoint*` | `proofpoint_tap_siem`, `pps_messagelog` | same |
| `*auth*`, `*iam*`, `*identity*` | `OktaIM2:log`, `duo` | same |
| `*vuln*` | `tenable:io:vuln`, `qualys:hostDetection` | same |
| `*windows*`, `*winevent*` | `WinEventLog`, `XmlWinEventLog` | same |

Always confirm with `tstats count where index=NAME by sourcetype` before writing a production query.
