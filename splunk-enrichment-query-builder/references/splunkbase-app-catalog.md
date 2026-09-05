# Splunkbase App and Add-on Catalog

## Use this file when

- the user names a vendor product or Splunkbase add-on and the query needs to know its sourcetypes, key fields, or CIM data model mappings
- you need to verify what fields an add-on produces before writing a detection
- the user provides index names and you need to infer likely sourcetypes from them

This file is the provenance registry for Splunk sourcetypes. The validator
reads every backticked name in the column headed `Sourcetype` and checks every
sourcetype the documents write in query position against that set, so a name
absent from these tables is reported as invented.

## Adding a sourcetype

Only add a sourcetype you have confirmed on a page that names it, and cite the
page in the row's `Reference` column: the add-on's own sourcetype
documentation first, then a Splunk repository that defines the sourcetype
(Splunk Connect for Syslog, the Splunk Threat Research data-source objects),
then a Splunkbase listing. The validator fails a row whose `Reference` cell is
empty. If you cannot confirm a sourcetype, do not guess at it; emit a discovery
query instead:

```spl
| tstats count where index=* earliest=-24h by index, sourcetype
```

A reference proves the name exists. It does not prove the deployment in front
of you uses it: an index may hold events under a customised sourcetype, and a
retired add-on's name can still be in the data. Confirm with the discovery
query before writing a production search.

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

| Sourcetype | Source | CIM data model | Key fields | Reference |
| --- | --- | --- | --- | --- |
| `WinEventLog` | `WinEventLog:Security` | Authentication, Endpoint | EventCode, user, src_user, dest, action | [Windows add-on source types](https://splunk.github.io/splunk-add-on-for-microsoft-windows/SourcetypeAndCIM/) |
| `XmlWinEventLog` | `XmlWinEventLog:Security` | Authentication, Endpoint | EventCode, user, src_user, dest, action | [Windows add-on source types](https://splunk.github.io/splunk-add-on-for-microsoft-windows/SourcetypeAndCIM/) |
| `WinEventLog` | `WinEventLog:System` | Change | EventCode, host | [Windows add-on source types](https://splunk.github.io/splunk-add-on-for-microsoft-windows/SourcetypeAndCIM/) |
| `WinEventLog` | `WinEventLog:Application` | Change | EventCode, host | [Windows add-on source types](https://splunk.github.io/splunk-add-on-for-microsoft-windows/SourcetypeAndCIM/) |
| `Perfmon:*` (e.g. `Perfmon:CPU`, `Perfmon:Memory`) | -- | Performance | object, counter, instance, Value | [Windows add-on source types](https://splunk.github.io/splunk-add-on-for-microsoft-windows/SourcetypeAndCIM/) |

Key EventCodes: 4624/4625 (logon/fail), 4648 (explicit logon), 4688 (process create), 4720/4726 (account create/delete), 4776 (NTLM auth), 4768/4769 (Kerberos TGT/TGS), 4663 (object access), 7045 (service install).

### Splunk Add-on for Sysmon (`Splunk_TA_microsoft_sysmon`)

| Sourcetype | Source | CIM data model | Key fields | Reference |
| --- | --- | --- | --- | --- |
| `XmlWinEventLog` | `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` | Endpoint (Processes, Filesystem, Registry); network-connect events (EventCode 3) normalize to Network_Traffic, not to an Endpoint dataset | EventCode, process, process_id, parent_process, dest, user, hash, TargetFilename, TargetObject | [Sysmon add-on source types](https://splunk.github.io/splunk-add-on-for-microsoft-sysmon/Sourcetypes/) |
| `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` | (the channel path itself) | Endpoint | Legacy only: older community Sysmon TAs assigned the full channel path as the sourcetype. On the Splunk-supported add-on that string is the source, not the sourcetype; catalogued so legacy queries that filter on it are recognised as real rather than invented. | [ES tutorial filtering on the channel path as a sourcetype](https://help.splunk.com/en/splunk-enterprise-security-7/tutorials-and-use-cases/7.3/risk-based-alerting-tutorial/part-3-create-a-risk-incident-rule)<br>[Sysmon EventID 1 data source, where it is the source](https://research.splunk.com/sources/) |

The Windows Event Collector variant uses sourcetype `XmlWinEventLog:WEC-Sysmon`.
Older community Sysmon TAs assigned the full channel path as the sourcetype, so
`sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` still appears
in legacy deployments; on the Splunk-supported add-on, filter on the source.

Key EventCodes: 1 (process create), 3 (network connect), 7 (image load), 8 (create remote thread), 10 (process access), 11 (file create), 12/13/14 (registry), 22 (DNS query).

### CrowdStrike Falcon

| Add-on | Sourcetype | CIM data model | Key fields | Reference |
| --- | --- | --- | --- | --- |
| Splunk Add-on for CrowdStrike FDR (app 5579) | `crowdstrike:events:sensor` | Endpoint (CIM normalization covers a subset of events) | event_simpleName, ComputerName, ImageFileName, CommandLine, SHA256HashData, LocalAddressIP4, RemoteAddressIP4 | [CrowdStrike FDR add-on source types](https://splunk.github.io/splunk-add-on-for-crowdstrike-fdr/Sourcetypes/) |
| Splunk Add-on for CrowdStrike FDR | `crowdstrike:inventory:aidmaster` | -- | aid, ComputerName, AgentVersion | [CrowdStrike FDR add-on source types](https://splunk.github.io/splunk-add-on-for-crowdstrike-fdr/Sourcetypes/) |
| CrowdStrike Falcon Event Streams TA (app 5082) | `CrowdStrike:Event:Streams:JSON` | Alerts | event_type, ComputerName, UserName, Severity | [CrowdStrike Falcon Stream Alert data source](https://research.splunk.com/sources/52b38751-b0db-4965-a800-ebaabd1fd7d5/) |

Caveat: FDR sensor telemetry and Event Streams alerts use different field
names; verify before reusing a query across both feeds.

### Microsoft Defender for Endpoint (Splunk Add-on for Microsoft Security)

| Sourcetype | CIM data model | Key fields | Reference |
| --- | --- | --- | --- |
| `ms:defender:atp:alerts` | Alerts, Malware, Endpoint | AlertId, Severity, title, machineId, computerDnsName, sha256, fileName, user | [Microsoft Security add-on source types](https://splunk.github.io/splunk-add-on-for-microsoft-365-defender/Sourcetypes/) |

On-host Windows Defender operational log (via `Splunk_TA_windows`):

| Sourcetype | Source | CIM data model | Key fields | Reference |
| --- | --- | --- | --- | --- |
| `XmlWinEventLog` | `XmlWinEventLog:Microsoft-Windows-Windows Defender/Operational` | Malware | EventCode (1116/1117), Severity Name, Path, Threat Name | [Windows add-on source types](https://splunk.github.io/splunk-add-on-for-microsoft-windows/SourcetypeAndCIM/) |

### Carbon Black

| Add-on | Sourcetype | CIM data model | Key fields | Reference |
| --- | --- | --- | --- | --- |
| Carbon Black Cloud (Endpoint Standard app) | `carbonblack:defense:json` | Endpoint, Malware | process_name, cmdline, parent_name, sha256, device_name, username | [Cb Defense app README, cbdefense macro](https://github.com/carbonblack/cb-defense-splunk-app/blob/master/DA-ESS-CbDefense/README.md) |
| Splunk Add-on for Carbon Black EDR (app 2790) | `bit9:carbonblack:json` | Endpoint | process_name, cmdline, parent_name, md5, hostname | [Carbon Black add-on source types](https://docs.splunk.com/Documentation/AddOns/released/Bit9CarbonBlack/Sourcetypes)<br>[Carbon Black EDR Splunk app guide](https://developer.carbonblack.com/reference/enterprise-response/connectors/splunk-user-guide/) |

The Endpoint Standard app is no longer supported; its Splunkbase listing
(app 3905) directs users to the unified VMware Carbon Black Cloud app (app
5332). Newer Carbon Black EDR guidance also uses `vmware:cb:edr:json`; confirm
which add-on feeds your indexes with a discovery query before writing
detections.

## Network security add-ons

### Palo Alto Networks Add-on (`Splunk_TA_paloalto`)

| Sourcetype | CIM data model | Key fields | Reference |
| --- | --- | --- | --- |
| `pan:traffic` | Network_Traffic | src, dest, dest_port, app, rule, action, bytes_in, bytes_out, transport | [Palo Alto Networks add-on source types](https://splunk.github.io/splunk-add-on-for-palo-alto-networks/Cimmapping/) |
| `pan:threat` | Intrusion_Detection, Web (url subtype), Malware (wildfire subtype) | signature, severity, action, category, url, file_hash | [Palo Alto Networks add-on source types](https://splunk.github.io/splunk-add-on-for-palo-alto-networks/Cimmapping/) |
| `pan:globalprotect` | Authentication, Network_Sessions | user, src, action, machine | [Palo Alto Networks add-on source types](https://splunk.github.io/splunk-add-on-for-palo-alto-networks/Cimmapping/) |
| `pan:system` | -- | eventid, object, result | [Palo Alto Networks add-on source types](https://splunk.github.io/splunk-add-on-for-palo-alto-networks/Cimmapping/) |
| `pan:hipmatch` | -- | host_id, match_name, user | [Palo Alto Networks add-on source types](https://splunk.github.io/splunk-add-on-for-palo-alto-networks/Cimmapping/) |

`pan:globalprotect` exists only in the newer PaloAltoNetworks Splunk-Apps TA
(v7+); the older Splunk_TA_paloalto routes GlobalProtect events without a
dedicated sourcetype.

### Cisco ASA (`Splunk_TA_cisco_asa`)

| Sourcetype | CIM data model | Key fields | Reference |
| --- | --- | --- | --- |
| `cisco:asa` | Network_Traffic, Authentication, Network_Sessions | src, dest, dest_port, action, transport, user, bytes_in, bytes_out, signature | [Cisco ASA add-on source and event types](https://docs.splunk.com/Documentation/AddOns/released/CiscoASA/DataTypes)<br>[SC4S Cisco ASA](https://splunk.github.io/splunk-connect-for-syslog/main/sources/vendor/Cisco/cisco_asa/) |

Key message IDs: %ASA-4-106023 (deny by ACL), %ASA-6-106015 (deny TCP with no
existing connection -- a state-table drop evaluated BEFORE the ACL, so it is
not a policy denial), %ASA-5-111008 (user command), %ASA-6-716001 (VPN connect).

Build "blocked by firewall policy" detections on 106023. A detection built on
106015 returns connection-table drops and silently misses every real ACL deny.

### Cisco Firepower / FTD eStreamer

| Sourcetype | CIM data model | Key fields | Reference |
| --- | --- | --- | --- |
| `cisco:estreamer:data` | Intrusion_Detection, Network_Traffic | ImpactBits, Severity, SignatureId, GeneratorId, src, dest | [eStreamer eNcore for Splunk operations guide](https://www.cisco.com/c/en/us/td/docs/security/firepower/670/api/eStreamer_enCore/eStreamereNcoreSplunkOperationsGuide_409.html) |

### Cisco Umbrella (Cisco Cloud Security Add-On for Splunk)

| Sourcetype | CIM data model | Key fields | Reference |
| --- | --- | --- | --- |
| `cisco:umbrella:dns` | Network_Resolution, Web (proxied traffic) | src, query, action, category, reply_code | [Cisco Secure Access App for Splunk](https://developer.cisco.com/docs/cloud-security/cisco-cloud-security-app-for-splunk/) |

### Cisco ISE

| Sourcetype | CIM data model | Key fields | Reference |
| --- | --- | --- | --- |
| `cisco:ise:syslog` | Authentication, Network_Sessions | user, src, dest, action, authentication_method, endpoint_id | [Cisco ISE add-on source types](https://splunk.github.io/splunk-add-on-for-cisco-identity-services/Sourcetypes/) |

### Fortinet FortiGate

| Sourcetype | CIM data model | Key fields | Reference |
| --- | --- | --- | --- |
| `fgt_traffic` | Network_Traffic | srcip, dstip, dstport, action, app, proto, rcvdbyte, sentbyte | [SC4S Fortinet FortiOS](https://splunk.github.io/splunk-connect-for-syslog/main/sources/vendor/Fortinet/fortios/) |
| `fgt_utm` | Intrusion_Detection, Web | subtype, level, msg, action | [SC4S Fortinet FortiOS](https://splunk.github.io/splunk-connect-for-syslog/main/sources/vendor/Fortinet/fortios/) |
| `fgt_event` | Change | subtype, level, msg | [SC4S Fortinet FortiOS](https://splunk.github.io/splunk-connect-for-syslog/main/sources/vendor/Fortinet/fortios/) |

`fgt_log` is the raw input sourcetype the add-on re-types into
`fgt_traffic`/`fgt_utm`/`fgt_event`; do not filter on it in detections.
Fortinet's own deployment guide names only `fgt_log`; the three derived names
are documented by SC4S, which routes to the same add-on.

### Check Point

| Sourcetype | CIM data model | Key fields | Reference |
| --- | --- | --- | --- |
| `cp_log` | Network_Traffic, Intrusion_Detection | orig, src, dst, service, action, rule, proto | [Check Point Log Exporter add-on source types](https://splunk.github.io/splunk-add-on-for-checkpoint-log-exporter/Sourcetypes/) |

Via SC4S the RFC 5424 Log Exporter path assigns `cp_log:syslog` instead; the
add-on documents both.

### Juniper Junos

| Sourcetype | CIM data model | Key fields | Reference |
| --- | --- | --- | --- |
| `juniper:junos:firewall` / `juniper:junos:firewall:structured` | Network_Traffic | src, dest, dest_port, action, transport | [Juniper add-on source types](https://splunk.github.io/splunk-add-on-for-juniper/Sourcetypes/) |
| `juniper:junos:idp` / `juniper:junos:idp:structured` | Intrusion_Detection | signature, severity, src, dest | [Juniper add-on source types](https://splunk.github.io/splunk-add-on-for-juniper/Sourcetypes/) |

Bare `juniper:junos` is not an assigned sourcetype; the add-on always
suffixes the log family.

### F5 BIG-IP

| Sourcetype | CIM data model | Key fields | Reference |
| --- | --- | --- | --- |
| `f5:bigip:apm:syslog` | Authentication, Network_Sessions | user, src, session_id | [F5 BIG-IP add-on source types](https://splunk.github.io/splunk-add-on-for-f5-big-ip/Sourcetypes/) |
| `f5:bigip:asm:syslog` | Web, Intrusion_Detection | attack_type, violations, src_ip, dest_ip, request | [F5 BIG-IP add-on source types](https://splunk.github.io/splunk-add-on-for-f5-big-ip/Sourcetypes/) |

iRule-based LTM access logging via Splunk Connect for Syslog uses
`f5:bigip:ltm:access_json`.

## Web and proxy add-ons

### Zscaler (`Splunk_TA_zscaler` / NSS or Cloud NSS)

| Sourcetype | CIM data model | Key fields | Reference |
| --- | --- | --- | --- |
| `zscalernss-web` | Web | src, dest, url, action, status, user, bytes_in, bytes_out, category | [Zscaler and Splunk deployment guide (PDF)](https://help.zscaler.com/downloads/zscaler-technology-partners/operations/zscaler-and-splunk-deployment-guide/Zscaler-Splunk-Deployment-Guide-FINAL.pdf)<br>[SC4S Zscaler NSS](https://splunk.github.io/splunk-connect-for-syslog/main/sources/vendor/Zscaler/nss/) |
| `zscalernss-fw` | Network_Traffic | src, dest, dest_port, action, transport | [Zscaler and Splunk deployment guide (PDF)](https://help.zscaler.com/downloads/zscaler-technology-partners/operations/zscaler-and-splunk-deployment-guide/Zscaler-Splunk-Deployment-Guide-FINAL.pdf)<br>[SC4S Zscaler NSS](https://splunk.github.io/splunk-connect-for-syslog/main/sources/vendor/Zscaler/nss/) |
| `zscalernss-dns` | Network_Resolution | src, query, reply_code | [Zscaler and Splunk deployment guide (PDF)](https://help.zscaler.com/downloads/zscaler-technology-partners/operations/zscaler-and-splunk-deployment-guide/Zscaler-Splunk-Deployment-Guide-FINAL.pdf)<br>[SC4S Zscaler NSS](https://splunk.github.io/splunk-connect-for-syslog/main/sources/vendor/Zscaler/nss/) |
| `zscalerlss-zpa-app` | Network_Sessions, Web | user, src_ip, dest_ip, app | [Zscaler and Splunk deployment guide (PDF)](https://help.zscaler.com/downloads/zscaler-technology-partners/operations/zscaler-and-splunk-deployment-guide/Zscaler-Splunk-Deployment-Guide-FINAL.pdf)<br>[SC4S Zscaler LSS](https://splunk.github.io/splunk-connect-for-syslog/main/sources/vendor/Zscaler/lss/) |

### Symantec ProxySG / Blue Coat

| Sourcetype | CIM data model | Key fields | Reference |
| --- | --- | --- | --- |
| `bluecoat:proxysg:access:kv` | Web | src, dest, url, action, status, http_method, http_user_agent, bytes_in, bytes_out, category | [Blue Coat ProxySG add-on sourcetypes](https://docs.splunk.com/Documentation/AddOns/released/BlueCoatProxySG/Sourcetypes) |

### Cloudflare (`cloudflare-app-for-splunk`)

| Sourcetype | CIM data model | Key fields | Reference |
| --- | --- | --- | --- |
| `cloudflare:json` | Web, Intrusion_Detection, Network_Resolution | ClientIP, ClientRequestURI, EdgeResponseStatus, WAFAction, WAFRuleID, QueryName | [Cloudflare Logpush to Splunk](https://developers.cloudflare.com/logs/logpush/logpush-job/enable-destinations/splunk/) |

Field availability depends on Logpush field selection; treat as partial until verified.

### Akamai SIEM Integration

| Sourcetype | CIM data model | Key fields | Reference |
| --- | --- | --- | --- |
| `akamaisiem` | Web, Intrusion_Detection | attackData.rules, attackData.ruleActions, httpMessage.requestHeaders, geo.country | [Akamai SIEM Splunk connector](https://techdocs.akamai.com/siem-integration/docs/siem-splunk-connector) |

### Squid Proxy

| Sourcetype | CIM data model | Key fields | Reference |
| --- | --- | --- | --- |
| `squid:access` | Web | src, dest, url, action, status, http_method, bytes_out | [Squid Proxy add-on source types](https://docs.splunk.com/Documentation/AddOns/released/Squid/Sourcetypes) |

### Imperva WAF

| Sourcetype | CIM data model | Key fields | Reference |
| --- | --- | --- | --- |
| `imperva:waf` | Web, Intrusion_Detection | src, dest, url, action, severity, sig_id, http_method | [SC4S Imperva SecureSphere WAF](https://splunk.github.io/splunk-connect-for-syslog/main/sources/vendor/Imperva/waf/) |

## Email security add-ons

### Proofpoint TAP

| Sourcetype | CIM data model | Key fields | Reference |
| --- | --- | --- | --- |
| `proofpoint_tap_siem` | Email, Malware | sender, recipient, subject, url, hash, action, threatStatus | [CCX Extensions for Proofpoint Products listing](https://splunkbase.splunk.com/app/6339) (third-party listing; the TAP Modular Input's own documentation is behind a Proofpoint login) |

### Proofpoint Protection Server (PPS)

The Proofpoint Email Security Add-On using Remote Syslog (app 3080) covers the
on-premises Proofpoint Protection Server. It collects on `pps_log` and re-types
into the two sourcetypes below.

| Sourcetype | CIM data model | Key fields | Reference |
| --- | --- | --- | --- |
| `pps_filter_log` | Email | sender, recipients, subject, action, disposition | [SC4S Proofpoint Protection Server](https://splunk.github.io/splunk-connect-for-syslog/main/sources/vendor/Proofpoint/) |
| `pps_mail_log` | Email | sendmail-style delivery records; SC4S notes the name collides with a host's own sendmail syslog | [SC4S Proofpoint Protection Server](https://splunk.github.io/splunk-connect-for-syslog/main/sources/vendor/Proofpoint/) |

### Proofpoint on Demand (PoD)

The Proofpoint On Demand Email Security Add-on (app 4327) covers the hosted
service and assigns different names. Earlier versions of this catalogue listed
`pps_messagelog` under the PPS heading; it belongs here.

| Sourcetype | CIM data model | Key fields | Reference |
| --- | --- | --- | --- |
| `pps_messagelog` | Email | sender, recipients, subject, action, disposition | [CCX Extensions for Proofpoint Products listing](https://splunkbase.splunk.com/app/6339) (third-party listing; the add-on's own listing describes "message and mail logs" without naming the sourcetypes) |

The same add-on also assigns the companion sourcetype `pps_maillog`.

## Identity and access add-ons

### Okta Identity Cloud Add-on for Splunk

| Sourcetype | Source | CIM data model | Key fields | Reference |
| --- | --- | --- | --- | --- |
| `OktaIM2:log` | `okta:im2` | Authentication | user, src_ip, action, outcome, authenticationContext.authenticationStep, client.userAgent.rawUserAgent | [Okta add-on source and event types](https://splunk.github.io/splunk-add-on-for-okta-identity-cloud/Sourcetypes/) |
| `OktaIM2:user` | `okta:im2` | Inventory (User) | Okta user objects (event type `okta_user`) | [Okta add-on source and event types](https://splunk.github.io/splunk-add-on-for-okta-identity-cloud/Sourcetypes/) |
| `OktaIM2:group` | `okta:im2` | -- | Okta group objects; no event type | [Okta add-on source and event types](https://splunk.github.io/splunk-add-on-for-okta-identity-cloud/Sourcetypes/) |
| `OktaIM2:app` | `okta:im2` | Inventory (User) | Okta app objects (event type `okta_app`) | [Okta add-on source and event types](https://splunk.github.io/splunk-add-on-for-okta-identity-cloud/Sourcetypes/) |
| `OktaIM2:groupUser` | `okta:im2` | -- | users associated to a group; no event type | [Okta add-on source and event types](https://splunk.github.io/splunk-add-on-for-okta-identity-cloud/Sourcetypes/) |
| `OktaIM2:appUser` | `okta:im2` | Change (Account_Management) | users associated to an app (event type `okta_app_user`) | [Okta add-on source and event types](https://splunk.github.io/splunk-add-on-for-okta-identity-cloud/Sourcetypes/) |

`okta:im2` is the *source* on all events from this add-on. The add-on's own
documentation marks `OktaIM2:app` "not recommended until really needed", and
lists no event type or CIM model for the group and groupUser inventories.

### Duo Security (Duo Splunk Connector)

| Sourcetype | CIM data model | Key fields | Reference |
| --- | --- | --- | --- |
| `duo` | Authentication | user, result, reason, factor, ip, integration | unconfirmed |
| `cisco:duo:activity` / `cisco:duo:administrator` | -- (not stated by the data-source objects) | Duo activity and administrator log events, source `cisco_duo` | [Cisco Duo Activity data source](https://research.splunk.com/sources/83f727f6-8754-41f8-b9f7-8226886a659e/)<br>[Cisco Duo Administrator data source](https://research.splunk.com/sources/38e22de6-8b6b-449c-ae26-a640c88ff7f9/) |

The Duo Splunk Connector reached end of life on May 1, 2025; Cisco's Security
Cloud app is the successor and assigns the `cisco:duo:*` family above. No
reachable page names the connector's bare `duo` sourcetype (Duo's own
connector documentation and release notes describe the logs collected without
naming a sourcetype), so confirm it with a discovery query on any deployment
that still runs the connector.

### Active Directory (via `Splunk_TA_windows`)

Events from `WinEventLog:Security` cover AD authentication. Additional AD-specific channels:

| Sourcetype | Source | CIM data model | Key fields | Reference |
| --- | --- | --- | --- | --- |
| `WinEventLog` | `WinEventLog:Active Directory Web Services` | Change | EventCode, src_user, dest_user | [Windows add-on source types](https://splunk.github.io/splunk-add-on-for-microsoft-windows/SourcetypeAndCIM/) |

## DNS and network resolution add-ons

### Infoblox (Splunk Add-on for Infoblox)

| Sourcetype | CIM data model | Key fields | Reference |
| --- | --- | --- | --- |
| `infoblox:dns` | Network_Resolution | src, query, record_type, reply_code, answer | [Infoblox add-on source types](https://splunk.github.io/splunk-add-on-for-infoblox/Sourcetypes/) |
| `infoblox:dhcp` | Network_Sessions | src_ip, dest, lease_time, mac | [Infoblox add-on source types](https://splunk.github.io/splunk-add-on-for-infoblox/Sourcetypes/) |

### Windows DNS (via `Splunk_TA_windows`)

| Sourcetype | Source | CIM data model | Key fields | Reference |
| --- | --- | --- | --- | --- |
| `XmlWinEventLog` | `XmlWinEventLog:Microsoft-Windows-DNS-Server/Analytical` | Network_Resolution | EventCode, QNAME, QTYPE, PacketData | [Windows add-on source types](https://splunk.github.io/splunk-add-on-for-microsoft-windows/SourcetypeAndCIM/) |

## Cloud platform add-ons

### Splunk Add-on for AWS (`Splunk_TA_aws`)

| Sourcetype | CIM data model | Key fields | Reference |
| --- | --- | --- | --- |
| `aws:cloudtrail` | Authentication, Change | eventName, userIdentity.arn, sourceIPAddress, errorCode, awsRegion | [AWS add-on source types](https://splunk.github.io/splunk-add-on-for-amazon-web-services/DataTypes/) |
| `aws:s3:accesslogs` | Web | remote_ip, bucket, key, operation, http_status, bytes_sent | [AWS add-on source types](https://splunk.github.io/splunk-add-on-for-amazon-web-services/DataTypes/) |
| `aws:cloudwatchlogs:vpcflow` | Network_Traffic | srcAddr, dstAddr, dstPort, protocol, action, logStatus | [AWS add-on source types](https://splunk.github.io/splunk-add-on-for-amazon-web-services/DataTypes/) |
| `aws:cloudwatch:guardduty` | Alerts, Intrusion_Detection | type, severity, description, resource.instanceDetails | [AWS add-on source types](https://splunk.github.io/splunk-add-on-for-amazon-web-services/DataTypes/) |
| `aws:securityhub:finding` | Alerts | Title, Severity.Label, ProductArn, FindingProviderFields | [AWS add-on source types](https://splunk.github.io/splunk-add-on-for-amazon-web-services/DataTypes/) |
| `aws:config` | Change | configurationItem.resourceType, changeType | [AWS add-on source types](https://splunk.github.io/splunk-add-on-for-amazon-web-services/DataTypes/) |

The newer standalone Splunk Add-on for AWS Security Hub emits
`ocsf:aws:securityhub:finding` instead.

### Microsoft Azure

Two different add-ons cover Azure; do not mix their sourcetypes.

Splunk Add-on for Microsoft Cloud Services (`Splunk_TA_microsoft-cloudservices`):

| Sourcetype | CIM data model | Key fields | Reference |
| --- | --- | --- | --- |
| `mscs:azure:audit` | Change, Authentication | operationName, caller, resultType | [Microsoft Cloud Services add-on source types](https://splunk.github.io/splunk-add-on-for-microsoft-cloud-services/Sourcetypes/) |
| `mscs:nsg:flow` | Network_Traffic | src_ip, dest_ip, dest_port, protocol, action | [Splunking Azure NSG flow logs (Splunk blog)](https://www.splunk.com/en_us/blog/platform/splunking-azure-nsg-flow-logs.html) (the add-on's own source type page does not list it; the blog shows the Storage Blob input assigning it) |
| `azure:monitor:aad` | Authentication, Change | Event Hub AAD logs; SigninLogs and AuditLogs are categories within this sourcetype | [Microsoft Cloud Services add-on source types](https://splunk.github.io/splunk-add-on-for-microsoft-cloud-services/Sourcetypes/) |

Splunk Add-on for Microsoft Azure (TA-MS-AAD, community-supported):

| Sourcetype | CIM data model | Key fields | Reference |
| --- | --- | --- | --- |
| `azure:aad:signin` | Authentication | userPrincipalName, ipAddress, status.errorCode, clientAppUsed, location | [TA-MS-AAD props.conf](https://github.com/splunk/splunk-add-on-microsoft-azure/blob/main/package/default/props.conf) |
| `azure:aad:audit` | Change | operationType, result, initiatedBy | [TA-MS-AAD props.conf](https://github.com/splunk/splunk-add-on-microsoft-azure/blob/main/package/default/props.conf) |

TA-MS-AAD's inputs have migrated to the Splunk Add-on for Microsoft Cloud
Services; its own README points at the migration guide. Its `eventtypes.conf`
searches the older `ms:aad:signin` name alongside `azure:aad:signin`, so
either can appear in a long-lived index.

### Splunk Add-on for Google Cloud

| Sourcetype | CIM data model | Key fields | Reference |
| --- | --- | --- | --- |
| `google:gcp:pubsub:message` | -- | Pub/Sub-delivered logs, including Cloud Audit payloads | [Google Cloud add-on source types](https://splunk.github.io/splunk-add-on-for-google-cloud-platform/Sourcetypes/) |
| `google:gcp:pubsub:audit:auth` | Authentication | protoPayload.methodName, protoPayload.authenticationInfo.principalEmail | [Google Cloud add-on source types](https://splunk.github.io/splunk-add-on-for-google-cloud-platform/Sourcetypes/) |
| `google:gcp:pubsub:audit:change` | Change | protoPayload.methodName, resource.type | [Google Cloud add-on source types](https://splunk.github.io/splunk-add-on-for-google-cloud-platform/Sourcetypes/) |
| `google:gcp:buckets:jsondata` / `google:gcp:buckets:csvdata` | -- | bucket-input payloads by format | [Google Cloud add-on source types](https://splunk.github.io/splunk-add-on-for-google-cloud-platform/Sourcetypes/) |

## Vulnerability management add-ons

### Tenable Add-on for Splunk

| Sourcetype | CIM data model | Key fields | Reference |
| --- | --- | --- | --- |
| `tenable:io:vuln` | Vulnerabilities | severity, plugin_name, cve, dest, port | [Tenable add-on source and source types](https://docs.tenable.com/integrations/Splunk/Content/SourceandSourceTypes.htm) |
| `tenable:io:assets` | -- | ip, hostname, os, last_seen | [Tenable add-on source and source types](https://docs.tenable.com/integrations/Splunk/Content/SourceandSourceTypes.htm) |

### Qualys Add-on

| Sourcetype | CIM data model | Key fields | Reference |
| --- | --- | --- | --- |
| `qualys:hostDetection` | Vulnerabilities | severity, qid, title, ip, port | [Qualys TA event types](https://docs.qualys.com/en/integration/splunk-ta/event_type/event_types.htm) |

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

| Add-on | Sourcetype | CIM data model | Key fields | Reference |
| --- | --- | --- | --- | --- |
| Splunk Add-on for NetFlow (`Splunk_TA_flowfix`; deprecated 2019, EOL) | `netflow` | Network_Traffic | src_ip, dst_ip, dst_port, protocol, in_bytes, out_bytes, packets | [NetFlow add-on source types](https://docs.splunk.com/Documentation/AddOns/released/NetFlow/DataTypes) (page withdrawn with the add-on; read from the Internet Archive's 2018 copy) |
| Splunk Stream (current Splunk-shipped path) | `stream:netflow` | Network_Traffic | src_ip, dest_ip, dest_port, protocol, bytes_in, bytes_out | [Use Splunk Stream to ingest NetFlow and IPFIX data](https://help.splunk.com/en/splunk-cloud-platform/collect-stream-data/install-and-configure-splunk-stream/8.1/configure-your-splunk-stream-installation/use-splunk-stream-to-ingest-netflow-and-ipfix-data) |

Do not recommend the EOL add-on for new deployments; `netflow` still appears
in environments that predate its retirement.

## Inferring sourcetypes from index name patterns

When the user provides index names but no sourcetypes, apply these heuristics before returning a discovery query:

| Index name pattern | Likely sourcetypes | First step |
| --- | --- | --- |
| `*firewall*`, `*paloalto*`, `*pan*` | `pan:traffic`, `cisco:asa`, `fgt_traffic` | `\| tstats count where index=NAME by sourcetype` |
| `*network*`, `*netflow*` | `netflow`, `pan:traffic` | same |
| `*endpoint*`, `*edr*`, `*crowdstrike*` | `crowdstrike:events:sensor`, `XmlWinEventLog` | same |
| `*proxy*`, `*web*`, `*zscaler*` | `zscalernss-web`, `bluecoat:proxysg:access:kv` | same |
| `*dns*` | `cisco:umbrella:dns`, `infoblox:dns` | same |
| `*cloud*`, `*aws*` | `aws:cloudtrail`, `aws:cloudwatchlogs:vpcflow` | same |
| `*azure*` | `mscs:azure:audit`, `azure:aad:signin` | same |
| `*email*`, `*mail*`, `*proofpoint*` | `proofpoint_tap_siem`, `pps_filter_log`, `pps_messagelog` | same |
| `*auth*`, `*iam*`, `*identity*` | `OktaIM2:log`, `duo` | same |
| `*vuln*` | `tenable:io:vuln`, `qualys:hostDetection` | same |
| `*windows*`, `*winevent*` | `WinEventLog`, `XmlWinEventLog` | same |

Always confirm with `| tstats count where index=NAME by sourcetype` before writing a production query.
