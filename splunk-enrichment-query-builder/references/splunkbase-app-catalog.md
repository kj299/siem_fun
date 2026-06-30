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

| Sourcetype | CIM data model | Key fields |
| --- | --- | --- |
| `WinEventLog:Security` | Authentication, Endpoint | EventCode, user, src_user, dest, action |
| `XmlWinEventLog:Security` | Authentication, Endpoint | EventCode, user, src_user, dest, action |
| `WinEventLog:System` | Change | EventCode, host |
| `WinEventLog:Application` | Change | EventCode, host |
| `Perfmon:*` | Performance | object, counter, instance, Value |

Key EventCodes: 4624/4625 (logon/fail), 4648 (explicit logon), 4688 (process create), 4720/4726 (account create/delete), 4776 (NTLM auth), 4768/4769 (Kerberos TGT/TGS), 4663 (object access), 7045 (service install).

### Splunk Add-on for Microsoft Sysmon (`Splunk_TA_microsoft_sysmon`)

| Sourcetype | CIM data model | Key fields |
| --- | --- | --- |
| `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` | Endpoint (Processes, Filesystem, Registry, NetworkTraffic) | EventCode, process, process_id, parent_process, dest, user, hash, TargetFilename, TargetObject |

Key EventCodes: 1 (process create), 3 (network connect), 7 (image load), 8 (create remote thread), 10 (process access), 11 (file create), 12/13/14 (registry), 22 (DNS query).

### CrowdStrike Falcon Event Streams

| Sourcetype | CIM data model | Key fields |
| --- | --- | --- |
| `crowdstrike:events:sensor` | Endpoint, Malware, Intrusion_Detection | event_type, ComputerName, UserName, ImageFileName, CommandLine, SHA256HashData, Severity |
| `crowdstrike:fdr:json` | Endpoint | event_simpleName, ContextBaseFileName, CommandLine, SHA256HashData, LocalAddressIP4, RemoteAddressIP4 |

Caveat: FDR field names differ from Event Streams; verify before reusing a query across both feeds.

### Microsoft Defender for Endpoint (`Splunk_TA_microsoft_defender`)

| Sourcetype | CIM data model | Key fields |
| --- | --- | --- |
| `ms:defender:atp:alerts` | Alerts, Malware, Endpoint | AlertId, Severity, title, machineId, computerDnsName, sha256, fileName, user |

On-host Windows Defender operational log (via `Splunk_TA_windows`):

| Sourcetype | Source | CIM data model | Key fields |
| --- | --- | --- | --- |
| `XmlWinEventLog` | `Microsoft-Windows-Windows Defender/Operational` | Malware | EventCode (1116/1117), Severity Name, Path, Threat Name |

### Carbon Black (VMware Carbon Black Cloud)

| Sourcetype | CIM data model | Key fields |
| --- | --- | --- |
| `carbonblack:events` | Endpoint, Malware | process_name, cmdline, parent_name, sha256, device_name, username |

## Network security add-ons

### Palo Alto Networks Add-on (`Splunk_TA_paloalto`)

| Sourcetype | CIM data model | Key fields |
| --- | --- | --- |
| `pan:traffic` | Network_Traffic | src, dest, dest_port, app, rule, action, bytes_in, bytes_out, transport |
| `pan:threat` | Intrusion_Detection, Web (url subtype), Malware (wildfire subtype) | signature, severity, action, category, url, file_hash |
| `pan:globalprotect` | Authentication, Network_Sessions | user, src, action, machine |
| `pan:system` | -- | eventid, object, result |
| `pan:hip-match` | -- | host_id, match_name, user |

### Cisco ASA (`Splunk_TA_cisco_asa`)

| Sourcetype | CIM data model | Key fields |
| --- | --- | --- |
| `cisco:asa` | Network_Traffic, Authentication, Network_Sessions | src, dest, dest_port, action, transport, user, bytes_in, bytes_out, signature |

Key message IDs: %ASA-6-106015 (deny by ACL), %ASA-5-111008 (user command), %ASA-6-716001 (VPN connect).

### Cisco Firepower / FTD eStreamer

| Sourcetype | CIM data model | Key fields |
| --- | --- | --- |
| `cisco:estreamer:data` | Intrusion_Detection, Network_Traffic | ImpactBits, Severity, SignatureId, GeneratorId, src, dest |

### Cisco Umbrella (`TA-cisco-umbrella`)

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
| `fgt_log` | Intrusion_Detection, Web | subtype, level, msg, action |

### Check Point

| Sourcetype | CIM data model | Key fields |
| --- | --- | --- |
| `cp_log` | Network_Traffic, Intrusion_Detection | orig, src, dst, service, action, rule, proto |

### Juniper Junos

| Sourcetype | CIM data model | Key fields |
| --- | --- | --- |
| `juniper:junos` | Network_Traffic | src, dest, dest_port, action, transport |

### F5 BIG-IP

| Sourcetype | CIM data model | Key fields |
| --- | --- | --- |
| `f5:bigip:ltm:access:accesspolicyresult` | Authentication | user, src, dest |
| `f5:bigip:apm:access` | Authentication, Network_Sessions | user, src, session_id |
| `f5:bigip:asm:syslog` | Web, Intrusion_Detection | attack_type, violations, src_ip, dest_ip, request |

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
| `akamai:siem` | Web, Intrusion_Detection | attackData.rules, attackData.ruleActions, httpMessage.requestHeaders, geo.country |

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
| `proofpoint:tap:siem` | Email, Malware | sender, recipient, subject, url, hash, action, threatStatus |

### Proofpoint Protection Server (PPS)

| Sourcetype | CIM data model | Key fields |
| --- | --- | --- |
| `pps_messagelog` | Email | sender, recipients, subject, action, disposition |

## Identity and access add-ons

### Okta Add-on for Splunk (`Splunk_TA_okta`)

| Sourcetype | CIM data model | Key fields |
| --- | --- | --- |
| `okta:im2` | Authentication | user, src_ip, action, outcome, authenticationContext.authenticationStep, client.userAgent.rawUserAgent |

### Duo Security Add-on

| Sourcetype | CIM data model | Key fields |
| --- | --- | --- |
| `duo:authentication` | Authentication | user, result, reason, factor, ip, integration |

### Active Directory (via `Splunk_TA_windows`)

Events from `WinEventLog:Security` cover AD authentication. Additional AD-specific channels:

| Sourcetype | Source | CIM data model | Key fields |
| --- | --- | --- | --- |
| `WinEventLog` | `Active Directory Web Services` | Change | EventCode, src_user, dest_user |

## DNS and network resolution add-ons

### Infoblox (`TA-infoblox`)

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
| `aws:vpc:flow` | Network_Traffic | srcAddr, dstAddr, dstPort, protocol, action, logStatus |
| `aws:guardduty` | Alerts, Intrusion_Detection | type, severity, description, resource.instanceDetails |
| `aws:securityhub` | Alerts | Title, Severity.Label, ProductArn, FindingProviderFields |
| `aws:config` | Change | configurationItem.resourceType, changeType |

### Splunk Add-on for Microsoft Azure

| Sourcetype | CIM data model | Key fields |
| --- | --- | --- |
| `mscs:azure:audit` | Change, Authentication | operationName, caller, resultType |
| `mscs:azure:nsg:flow` | Network_Traffic | src_ip, dest_ip, dest_port, protocol, action |
| `azure:monitor:aad:signin` | Authentication | userPrincipalName, ipAddress, status.errorCode, clientAppUsed, location |
| `azure:monitor:aad:audit` | Change | operationType, result, initiatedBy |

### Splunk Add-on for Google Cloud

| Sourcetype | CIM data model | Key fields |
| --- | --- | --- |
| `google:gcp:buckets:accesslogs` | Web | remoteIp, resource, status, bytesSent |
| `google:gcp:cloudaudit:data_access` | Authentication, Change | protoPayload.methodName, protoPayload.authenticationInfo.principalEmail |

## Vulnerability management add-ons

### Tenable Add-on for Splunk

| Sourcetype | CIM data model | Key fields |
| --- | --- | --- |
| `tenable:io:vulnerabilities` | Vulnerabilities | severity, plugin_name, cve, dest, port |
| `tenable:io:assets` | -- | ip, hostname, os, last_seen |

### Qualys Add-on

| Sourcetype | CIM data model | Key fields |
| --- | --- | --- |
| `qualys:vuln` | Vulnerabilities | severity, qid, title, ip, port |

## Threat intelligence add-ons (lookups only, no sourcetypes)

These add-ons provide lookup files and custom commands, not sourcetypes.

| Add-on | Lookup / command | Key fields |
| --- | --- | --- |
| GreyNoise App for Splunk | `greynoise_full.csv`, `greynoise_riot.csv`, `gnenrich`, `gnlookup` | ip, noise, riot, classification, tags, actor |
| Recorded Future App | `recordedfuture_threat` lookup | risk_score, evidence_summary, triggered_rules |
| VirusTotal Add-on | `vt` custom command | positives, permalink, scan_date |

See [greynoise-integration.md](greynoise-integration.md) for GreyNoise field details and SPL patterns.

## NetFlow add-ons

### Splunk Add-on for NetFlow

| Sourcetype | CIM data model | Key fields |
| --- | --- | --- |
| `netflow` | Network_Traffic | src_ip, dst_ip, dst_port, protocol, in_bytes, out_bytes, packets |

## Inferring sourcetypes from index name patterns

When the user provides index names but no sourcetypes, apply these heuristics before returning a discovery query:

| Index name pattern | Likely sourcetypes | First step |
| --- | --- | --- |
| `*firewall*`, `*paloalto*`, `*pan*` | `pan:traffic`, `cisco:asa`, `fgt_traffic` | `tstats count where index=NAME by sourcetype` |
| `*network*`, `*netflow*` | `netflow`, `pan:traffic` | same |
| `*endpoint*`, `*edr*`, `*crowdstrike*` | `crowdstrike:events:sensor`, `WinEventLog:Security` | same |
| `*proxy*`, `*web*`, `*zscaler*` | `zscalernss-web`, `bluecoat:proxysg:access:kv` | same |
| `*dns*` | `cisco:umbrella:dns`, `infoblox:dns` | same |
| `*cloud*`, `*aws*` | `aws:cloudtrail`, `aws:vpc:flow` | same |
| `*azure*` | `mscs:azure:audit`, `azure:monitor:aad:signin` | same |
| `*email*`, `*mail*`, `*proofpoint*` | `proofpoint:tap:siem`, `pps_messagelog` | same |
| `*auth*`, `*iam*`, `*identity*` | `okta:im2`, `duo:authentication` | same |
| `*vuln*` | `tenable:io:vulnerabilities`, `qualys:vuln` | same |
| `*windows*`, `*winevent*` | `WinEventLog:Security`, `XmlWinEventLog:Security` | same |

Always confirm with `tstats count where index=NAME by sourcetype` before writing a production query.
