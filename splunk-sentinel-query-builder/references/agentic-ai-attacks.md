# Agentic AI attack frameworks

AI-driven offensive frameworks are open-source tools that put one or more large
language models in a loop with real penetration-testing tooling: a planner picks
the next action, a worker runs it against the target, and the result feeds the
next round. They run on the attacker's own infrastructure and, by themselves,
install nothing on the victim. What a defender sees is (1) machine-speed tempo
against the edge, (2) ordinary post-exploitation artifacts the agents leave
behind, and (3) the frameworks' own fingerprints when a host of yours is turned
into agent infrastructure. Six are covered here, all reported in use or exposed
between September and November 2026:

- **ARTEX** (Go + Next.js; author handle Autumn-27). Multi-agent pentest system.
  Used by VAPOR PANDA, Storm-0940 (tracked by GTIG as UNC7228), an unattributed
  actor against South Korean banks, CRAFTY FALCON (CERT-In), and -- since late
  October 2026 -- the North Korean groups Onyx Sleet (Andariel, ATT&CK G0138)
  and Pearl Sleet (Microsoft, 2026-10-29). GTIG describes six specialized
  sub-agents and a fork sold as ARTEX PRO.
- **CAIRN** (FastAPI; no built-in authentication). State-space search engine:
  workers post Facts and Intents to a shared board, the operator adds Hints.
  Cluster AIA0001 ran more than 1,100 attack projects against shops and payment
  sites.
- **CyberStrikeAI** (Go). Carries a built-in C2 (beacon generator and listener),
  a web-shell manager, and a FOFA client. Kaspersky (2026-11-02) documented it
  in intrusions at education organizations in Latin America and Africa
  (September-October 2026): the model runs on the attacker's C2, the implant
  only executes commands, and domain admin fell three to four days after the
  implant went in. Also linked by Team Cymru to FortiGate targeting; named by
  CERT-In.
- **PentAGI** (Go + Svelte). Autonomous multi-agent system; GTIG observed a
  customized build used for reconnaissance and vulnerability scanning in Asia,
  and some operations progressing to intrusion.
- **STRIX** (Python; usestrix/strix). Runs its agent in a Kali sandbox and
  proxies target traffic through an embedded Caido instance. Seen in Gambit
  Security's retail campaign in a scanning role alongside Hermes and CAIRN.
- **HexStrike-AI** (Python; Flask + MCP). Orchestrates 150+ Kali tools. Check
  Point reported threat-actor discussion of it for scanning and exploiting
  NetScaler instances.

Two framings matter for detection. First, signatures for a framework barely
help on the target, because it rarely touches the victim's disk; tempo and
ordinary artifacts do. Second, STRIX's own prompt tells the operator to strip
identifiable markers from requests, so the user-agent fingerprints below catch
default or careless deployments, not a determined operator -- treat their
absence as nothing.

## Current developments (as of 2026-11-05, refreshed late in the day)

- **Trojanized ARTEX images.** Researcher Badbyte (primary write-up,
  2026-11-04) found the backdoor in exactly two Docker Hub images,
  `tomicdd/artex` (9,008 pulls by 5 November) and its byte-identical re-push
  `congdonglinux/artex`; none of about 34 other `artex` namespaces carries it.
  The console's login handler runs a marked CAPTCHA value as root before any
  credential check -- an unauthenticated root shell. It was opportunistic: the
  `tomicdd` account appeared about nine hours after ARTEX's author announced the
  project was going closed source, and a fork swapped one line of its
  docker-compose file to pull the image; 637 repositories in that fork network
  still pull it. 62 consoles served the backdoored build on 2-4 November (a
  floor -- about 590 more run an unversioned build from the same source), out of
  1,645 live ARTEX consoles. Updating does not help: the bundled update script
  re-pulls the same image. The IOC file carries the backdoored binary and layer
  hashes and the console's UI build ID, a one-string fingerprint for scanning
  your own estate. On 5 November Docker Hub's registry refused anonymous access
  to both repositories, which may mean they were taken down (not confirmed).
- **State adoption widens.** Microsoft (2026-10-29) reports North Korea's Onyx
  Sleet and Pearl Sleet using ARTEX since late October, alongside the
  China-nexus and financially motivated users already reported.
- **CyberStrikeAI is now primary-confirmed in intrusions.** Kaspersky's report
  gives the full chain -- SQL Server access, PowerShell and certutil staging,
  scheduled-task and Run-key persistence, Kerberoasting, AS-REP Roasting, LSASS
  and registry credential dumping, DCSync and a Golden Ticket, WMI/WinRM/SMB
  lateral movement -- plus beacon hashes, C2 hosts, and a distinctive
  `X-Implant-Token` HTTP header on every implant request.
- **Exposure keeps growing.** AhnLab counted about 900 ARTEX-hosting IPs by
  14 October; Badbyte counted 1,645 consoles by 4 November.
- **CyberStrikeAI in Japan.** TrendAI (Trend Micro; via The Hacker News,
  2026-10-27) analysed three exposed attacker environments. In the most
  automated, a CyberStrikeAI platform split the work across 44 agents and put at
  least 19 organizations (16 in Japan, plus targets in Taiwan and Hong Kong)
  through validation activity, generating Japanese-language forms and fake
  login pages. TrendAI's own framing is the right one for defenders: AI added
  workforce, but the work is still looking for unlocked doors.
- **Supply-chain fallout.** After the Storm-0940 campaign, which began in early
  September, ConnectWise suspended its Cloud Backup, SaaS Security and Cloud
  Management services (SecurityWeek, 2026-10-23).
- **AI agents as an attack surface.** CERT-In's earlier advisory CIAD-2026-0049
  (15 October, critical) covers two kinds of incident: criminals using
  open-source agentic tools, and AI agents under research and evaluation that
  exceeded their assigned authorization and accessed live systems. The second is
  a governance problem for any organization running its own agents.
- **Figures that disagree.** Some coverage says VAPOR PANDA compromised about
  140 targets in 11 days; CrowdStrike's own post reports more than 200
  organizations targeted, post-exploitation confirmed at nine, and spraying at
  twelve more. This section uses CrowdStrike's figures.
- **Telemetry and monitoring signals.** Beyond the user-agents seen arriving at
  your edge, three frameworks emit identifiable strings to their OWN endpoints
  (STRIX's `X-Title: Strix` and `strix.ai` referer on LLM calls, CyberStrikeAI's
  `X-CyberStrike-Summarization` header, PentAGI's `langfuse golang sdk`): a host
  of yours emitting these is running the framework, and the strip-markers habit
  that hides edge user-agents does not reach them. In cloud audit logs,
  Storm-0940's ARTEX operators used `azure-toolkit/1.0` and specific Boto3 /
  aws-cli build strings. The most durable monitoring signal is not an indicator
  at all: Huntress found the hijacked ConnectWise apps normally call Graph as
  `kiota-dotnet`, and the giveaway was that user-agent being replaced by
  `Python-urllib/3.12`. Baseline each vendor application's user-agent and alert
  on drift (hunt H-AGT-016). The generic clients (`python-requests`, `curl`,
  `Python-urllib`) are noisy alone -- Wiz says so explicitly -- and are context,
  never a standalone alert.

## How to use this section

- **MITRE ATT&CK map** -- the table below maps every technique these frameworks'
  operators were observed using to the public report that evidences it. The same
  data drives an ATT&CK Navigator layer at
  [examples/agentic-ai-attacks/attack-navigator-layer.json](../../examples/agentic-ai-attacks/attack-navigator-layer.json)
  (score = number of independent evidence rows). Built against ATT&CK v20;
  `T1574.001` is what versions before v18 called DLL Side-Loading.
- **IOCs** -- [examples/agentic-ai-attacks/iocs.csv](../../examples/agentic-ai-attacks/iocs.csv)
  carries every indicator with a `framework` column, a named source, a
  confidence, and a recommended action. Network, host-hash, user-agent and
  cloud/identity indicators are included. Each was verified against its primary
  source or against the framework's own source code; the literal values (ports,
  image tags, panel titles, config paths) live there rather than in this prose.
  **Legitimate services** (LLM API hosts, webhook.site, dnslog.cn, public
  callback services) appear only as behavioral signals and are never on a block
  action.
- **Detections** -- ready-to-adapt content, all `needs_validation` (tested for
  logic, not run against a live SIEM):
  [splunk-savedsearches.conf](../../examples/agentic-ai-attacks/splunk-savedsearches.conf)
  (CIM-based Splunk saved searches and baseline builders, plus two chained
  rules), [splunk-morpheus-native.conf](../../examples/agentic-ai-attacks/splunk-morpheus-native.conf)
  (variants for an estate running the NVIDIA Morpheus behavioral pipeline),
  [sentinel-rules.yaml](../../examples/agentic-ai-attacks/sentinel-rules.yaml)
  (Microsoft Sentinel scheduled analytic rules), and
  [hunting.kql](../../examples/agentic-ai-attacks/hunting.kql) -- including
  H-AGT-015 (framework self-telemetry on egress) and H-AGT-016 (OAuth
  application user-agent drift, the Huntress method). Lookups the rules read are
  in [examples/agentic-ai-attacks/lookups/](../../examples/agentic-ai-attacks/lookups/);
  the cloud-log and baseline indicators are deliberately kept out of the
  auto-block sweep.
- **Build a query** -- when the request is to detect this activity in a specific
  SIEM, follow the query workflow in [query-workflow.md](query-workflow.md) and
  the CIM and table provenance in
  [cim-vendor-alignment.md](cim-vendor-alignment.md) and
  [sentinel-table-catalog.md](sentinel-table-catalog.md). Never scope to a raw
  index, sourcetype or table you have not confirmed; emit a discovery query
  instead.

## Behaviors worth detecting first

The techniques below cluster into a handful of observable behaviors. Rank your
coverage against these:

1. **Machine-speed enumeration** of your web applications -- far more distinct
   paths per minute, or a far more regular request cadence, than a human. The
   non-browser or forged-browser user-agents in the IOC list sharpen it.
2. **Source-centric credential spraying** -- one source failing many principals a
   few times each, below any per-principal rule.
3. **Web shells** written after an upload, SQL injection, deserialization, or
   database-log poisoning -- a web-server or database process spawning a shell.
4. **Identity and cloud persistence** -- credentials added to OAuth applications
   or service principals, roles assigned, AWS SSM or Lambda used to run commands.
5. **Framework infrastructure on your own hosts** -- a server reaching an LLM API
   or a framework's update or telemetry host, or carrying a framework's image,
   config directory, or default listening service. Any host running a
   trojanized ARTEX image should be treated as compromised.
6. **Active Directory credential attacks at machine speed** -- Kerberoasting,
   AS-REP Roasting, LSASS and registry dumps, DCSync and Golden Ticket inside
   hours of an implant landing (the CyberStrikeAI chain). Detection here is the
   familiar one; what changed is the time available to respond.

## MITRE ATT&CK technique map

Technique IDs are the authors' mapping of the quoted evidence; each row cites the
report or the framework source it rests on. "Frameworks" names which of the six
the evidence concerns. Credential-access and discovery coverage is heaviest
because that is where the public reporting is most concrete; a blank cell for a
tactic is an intelligence gap, not an assurance.

| Technique | Name | Tactic | Frameworks | Example evidence | Source |
| --- | --- | --- | --- | --- | --- |
| T1590 | Gather Victim Network Information | Reconnaissance | PentAGI, STRIX | Target network and host information gathered at scale before any exploitation attempt | Gambit Security 2026-09-22 |
| T1595.001 | Scanning IP Blocks | Reconnaissance | CyberStrikeAI | Scanning for management interfaces on ports 443, 8443, 10443 and 4443 of edge devices | Amazon Threat Intelligence 2026-02-20 |
| T1595.002 | Vulnerability Scanning | Reconnaissance | ARTEX, CAIRN, CyberStrikeAI, PentAGI, STRIX | Agents probe peripheral internet-facing applications (customer inquiry portals, mobile app backends) and shopping sites selected by traffic before ... | GTIG 2026-10-30; Gambit Security 2026-09-22; TrendAI via The Hacker News 2026-10-27; Zscaler ThreatLabz 2026-10-14 |
| T1595.003 | Wordlist Scanning | Reconnaissance | ARTEX | Baseline probe GET /zzz-nonexistent-xyz123 and more than 60 SSO route variants tried per target | Wiz 2026-10-22 |
| T1596.002 | WHOIS | Reconnaissance | PentAGI | Most observed PentAGI activity stayed at WHOIS asset mapping or active vulnerability scanning | GTIG 2026-10-30 |
| T1583.004 | Server | Resource Development | ARTEX, CyberStrikeAI | Actor-controlled server 38.244.50.120 hosting the ARTEX instance, plus five work servers and a SOCKS upstream | CrowdStrike 2026-10-07; Team Cymru 2026-03-02 |
| T1583.006 | Web Services | Resource Development | ARTEX, CAIRN, STRIX | Cairn control panels on hosting providers (AS56594, Vultr, AlexHost); ARTEX agents posting command output to 491 rotating webhook.site endpoints | NorForge 2026-10-19; Strix source |
| T1588.002 | Tool | Resource Development | ARTEX, CAIRN, CyberStrikeAI, PentAGI | CERT-In names ARTEX, PentAGI, Cairn and CyberStrikeAI as the publicly available AI offensive-security systems the actor uses | CERT-In CIAD-2026-0058; Microsoft Threat Intelligence 2026-10-29 |
| T1588.006 | Vulnerabilities | Resource Development | HexStrike-AI | Framework applied within hours of a vulnerability disclosure | Check Point Research 2025-09-02 |
| T1608.001 | Upload Malware | Resource Development | ARTEX | Backdoored ARTEX image staged on Docker Hub about twelve days before the first exposed console running it | Badbyte via The Hacker News 2026-11-05 |
| T1078 | Valid Accounts | Initial Access | ARTEX, CAIRN, CyberStrikeAI, PentAGI | Stolen credentials used to connect to victim internal networks | Amazon Threat Intelligence 2026-02-20; CERT-In CIAD-2026-0058 via The Hacker News |
| T1078.004 | Cloud Accounts | Initial Access | ARTEX | Sign-ins with compromised application identities across tenants; authentication keys exposed in a 2022 mail-server export reused for access | Microsoft |
| T1133 | External Remote Services | Initial Access | CyberStrikeAI | Exposed management ports and weak single-factor credentials used for access | Amazon Threat Intelligence 2026-02-20 |
| T1190 | Exploit Public-Facing Application | Initial Access | ARTEX, CAIRN, CyberStrikeAI, HexStrike-AI, PentAGI | SQL injection and authentication bypass in peripheral web apps (Zscaler); two Zammad zero-days CVE-2026-102489/102490 (DIVD); unauthenticated image... | GTIG 2026-10-30; TrendAI via The Hacker News 2026-10-27; Zscaler |
| T1195.002 | Compromise Software Supply Chain | Initial Access | ARTEX, CAIRN, CyberStrikeAI, PentAGI | Compromised ConnectWise Cloud Backup multi-tenant OAuth application identities used to sign in to more than 2,250 Microsoft 365 tenants | Badbyte via The Hacker News 2026-11-05; CERT-In CIAD-2026-0058 via The Hacker News; Microsoft 2026-10-21 |
| T1047 | Windows Management Instrumentation | Execution | CyberStrikeAI | WMI (Invoke-CimMethod and a second WMI method) and Impacket WMIExec used to distribute and run p1.ps1 | Kaspersky Securelist 2026-11-02 |
| T1053.003 | Cron | Execution | CyberStrikeAI | Linux persistence via an @reboot crontab entry for the beacon | Kaspersky Securelist 2026-11-02 |
| T1053.005 | Scheduled Task | Execution | CyberStrikeAI | Scheduled tasks as SYSTEM via schtasks (including remote /s) and the Schedule.Service COM object; persistence task SystemUpdate | Kaspersky Securelist 2026-11-02 |
| T1059 | Command and Scripting Interpreter | Execution | ARTEX, CAIRN, CyberStrikeAI, PentAGI | Native curl used to pull down dynamically generated PowerShell and batch scripts; custom Python, C# and PowerShell staged | CERT-In CIAD-2026-0058; GTIG 2026-10-30 |
| T1059.001 | PowerShell | Execution | CyberStrikeAI | Base64-encoded PowerShell payloads executed after access through a compromised SQL Server | Kaspersky Securelist 2026-11-02 |
| T1574.001 | DLL | Execution | ARTEX | Legitimate GameHook binary renamed svchost.exe loads graphics-hook-filter64.dll (BLOODALCHEMY loader); maps to T1574.002 DLL Side-Loading in ATT&CK... | CrowdStrike 2026-10-29 |
| T1648 | Serverless Execution | Execution | ARTEX, CAIRN, CyberStrikeAI, PentAGI | Lambda abused to run code and deploy files | CERT-In CIAD-2026-0058 |
| T1651 | Cloud Administration Command | Execution | ARTEX, CAIRN, CyberStrikeAI, PentAGI | Cloud management services such as AWS Systems Manager and Lambda abused to execute commands and deploy malicious files, blending into legitimate ma... | CERT-In CIAD-2026-0058 |
| T1098.001 | Additional Cloud Credentials | Persistence | ARTEX | Application credential changes (credentials added to the application) for persistence after the original access | Microsoft 2026-10-21 |
| T1098.003 | Additional Cloud Roles | Persistence | ARTEX | Changes involving identities, groups and privileged roles; an application self-assigning Global Administrator | Microsoft 2026-10-21 |
| T1136.003 | Cloud Account | Persistence | ARTEX | Accounts named ArtexProbe created with is_admin=true; t3.micro jump instances created | GTIG 2026-10-30 |
| T1505.003 | Web Shell | Persistence | ARTEX, CAIRN, HexStrike-AI | Operator transcripts directing agents to write web shells, JSP and PHP (CrowdStrike); uploader shell saved by move_uploaded_file as the Cairn task ... | Check Point Research 2025-09-02; CrowdStrike |
| T1546.004 | Unix Shell Configuration Modification | Persistence | CyberStrikeAI | Linux persistence via a nohup beacon launch appended to ~/.bashrc | Kaspersky Securelist 2026-11-02 |
| T1547.001 | Registry Run Keys / Startup Folder | Persistence | CyberStrikeAI | Persistence via the SystemUpdate value under the HKCU Run key | Kaspersky Securelist 2026-11-02 |
| T1068 | Exploitation for Privilege Escalation | Privilege Escalation | ARTEX | Zammad local privilege escalation to root (CVE-2026-102490) chained after the session-hijack RCE; initial access to root in twelve minutes | DIVD 2026-10-31 |
| T1134 | Access Token Manipulation | Privilege Escalation | ARTEX | Abused resource-based constrained delegation to impersonate a privileged account | CrowdStrike 2026-10-29 |
| T1027 | Obfuscated Files or Information | Defense Evasion | CyberStrikeAI | Payload split across multiple files; SQL and LDAP queries obfuscated | Kaspersky Securelist 2026-11-02 |
| T1036.005 | Match Legitimate Resource Name or Location | Defense Evasion | ARTEX, CyberStrikeAI | Loader binary renamed svchost.exe outside the Windows system directory | CrowdStrike 2026-10-29; Kaspersky Securelist 2026-11-02 |
| T1070 | Indicator Removal | Defense Evasion | ARTEX, CAIRN, CyberStrikeAI, PentAGI | Log deletion after compromise | CERT-In CIAD-2026-0058 via The Hacker News |
| T1140 | Deobfuscate/Decode Files or Information | Defense Evasion | CyberStrikeAI | certutil decodes a payload split into fragments (d3.b64) | Kaspersky Securelist 2026-11-02 |
| T1685 | Disable or Modify Tools | Defense Evasion | ARTEX, CAIRN, CyberStrikeAI, PentAGI | Endpoint security tampering after compromise (Disable or Modify Tools; T1562.001 before ATT&CK v19/v20) | CERT-In CIAD-2026-0058 via The Hacker News |
| T1003.001 | LSASS Memory | Credential Access | CyberStrikeAI | LSASS dumped with comsvcs.dll MiniDump, addressed by PID | Kaspersky Securelist 2026-11-02 |
| T1003.002 | Security Account Manager | Credential Access | CyberStrikeAI | reg.exe used to dump registry hives containing credentials | Kaspersky Securelist 2026-11-02 |
| T1003.006 | DCSync | Credential Access | ARTEX, CyberStrikeAI | DCSync scripts executed to steal the domain krbtgt key and cloud AD-sync credentials after an offline cracking pause | GTIG 2026-10-30; Kaspersky Securelist 2026-11-02 |
| T1110 | Brute Force | Credential Access | CyberStrikeAI | Authentication attempts against management interfaces after scanning | Amazon Threat Intelligence 2026-02-20 |
| T1110.003 | Password Spraying | Credential Access | ARTEX | 151,000+ failed logons against 327 accounts across 8 organizations, peaking at 2,900 per minute (Microsoft); sprays with a 1-second median gap in 2... | Microsoft 2026-10-21 |
| T1528 | Steal Application Access Token | Credential Access | ARTEX | Abuse of trusted application access tokens to reach downstream customer environments | Microsoft 2026-10-21 |
| T1552.001 | Credentials In Files | Credential Access | ARTEX, CAIRN, CyberStrikeAI, PentAGI | DPAPI-protected secret recovered from a config-derived file (Kaspersky); plaintext credentials in configs or code used for access (CERT-In via THN) | Kaspersky Securelist 2026-11-02 |
| T1552.004 | Private Keys | Credential Access | ARTEX, CAIRN, CyberStrikeAI, PentAGI | Wallet keys stolen and funds siphoned from cryptocurrency wallets | CERT-In CIAD-2026-0058 |
| T1552.005 | Cloud Instance Metadata API | Credential Access | ARTEX | Queried the cloud instance metadata service through the SAML/XXE chain to obtain cloud credentials | CrowdStrike 2026-10-29 |
| T1555 | Credentials from Password Stores | Credential Access | ARTEX | Read Local Administrator Password Solution (LAPS) passwords | CrowdStrike 2026-10-29 |
| T1555.006 | Cloud Secrets Management Stores | Credential Access | ARTEX | Enumerated cloud resources and read secrets at scale across multiple Azure Key Vaults; key enumeration and a key-unwrapping operation | Microsoft 2026-10-21 |
| T1558.001 | Golden Ticket | Credential Access | CyberStrikeAI | Renamed mimikatz used for a Golden Ticket attack | Kaspersky Securelist 2026-11-02 |
| T1558.003 | Kerberoasting | Credential Access | ARTEX, CyberStrikeAI | Kerberoasting scripts run to harvest service tickets across compromised domains | GTIG 2026-10-30; Kaspersky Securelist 2026-11-02 |
| T1558.004 | AS-REP Roasting | Credential Access | CyberStrikeAI | LDAP queries to find AS-REP Roastable accounts | Kaspersky Securelist 2026-11-02 |
| T1606 | Forge Web Credentials | Credential Access | ARTEX | Unsigned JWT probe with header alg none against SSO endpoints | Wiz 2026-10-22 |
| T1606.002 | SAML Tokens | Credential Access | ARTEX | Unsigned SAML assertion combined with an XXE flaw to query the cloud instance metadata service for credentials | CrowdStrike 2026-10-29 |
| T1016 | System Network Configuration Discovery | Discovery | CyberStrikeAI | External IP lookup via the public dnslog.cn service | Kaspersky Securelist 2026-11-02 |
| T1046 | Network Service Discovery | Discovery | ARTEX | Network scanning and reconnaissance after initial access; lateral movement and database exploitation automated by the frameworks | CrowdStrike |
| T1087.002 | Domain Account | Discovery | ARTEX, CyberStrikeAI | Enumerated over 110,000 Active Directory objects from a domain controller and retrieved the Domain Admins group | GTIG 2026-10-30; Kaspersky Securelist 2026-11-02 |
| T1087.004 | Cloud Account | Discovery | ARTEX | Reconnaissance through Microsoft Graph after sign-in with the compromised application | Microsoft 2026-10-21 |
| T1518.001 | Security Software Discovery | Discovery | ARTEX, CyberStrikeAI | Endpoint sensor evasion built into the agentic workflow, including instructions to identify hosts without the CrowdStrike Falcon sensor | CrowdStrike 2026-10-29; Kaspersky Securelist 2026-11-02 |
| T1580 | Cloud Infrastructure Discovery | Discovery | ARTEX | Sub-second Azure capability checks: blob writes and deletes, ARM deployment validation dry-run sweeps across resource types; AWS DryRun permission ... | GTIG 2026-10-30 |
| T1021 | Remote Services | Lateral Movement | ARTEX | Internet-exposed non-production environments (UAT, staging, testing) used as entry points, followed by movement to production through shared creden... | CERT-In CIAD-2026-0058 |
| T1021.002 | SMB/Windows Admin Shares | Lateral Movement | CyberStrikeAI | Lateral movement via shared network admin folders (SMB) | Kaspersky Securelist 2026-11-02 |
| T1021.006 | Windows Remote Management | Lateral Movement | CyberStrikeAI | Lateral movement via WinRM initiated from PowerShell | Kaspersky Securelist 2026-11-02 |
| T1534 | Internal Spearphishing | Lateral Movement | ARTEX | Forced an application's notification system to broadcast test emails to over 1,300 internal users | GTIG 2026-10-30 |
| T1550.001 | Application Access Token | Lateral Movement | ARTEX, CAIRN, CyberStrikeAI, PentAGI | Stolen long-lived static API tokens used for initial access | CERT-In CIAD-2026-0058 via The Hacker News |
| T1005 | Data from Local System | Collection | CyberStrikeAI | Database export via PowerShell-generated SQL and a recursive scan for files of interest | Kaspersky Securelist 2026-11-02 |
| T1113 | Screen Capture | Collection | CyberStrikeAI | Screenshots captured on Windows and Linux | Kaspersky Securelist 2026-11-02 |
| T1185 | Browser Session Hijacking | Collection | CAIRN, STRIX | Card-stealing skimmer scripts installed on the websites of five retailers; loader shape new Function(atob(...)) with a junk prefix | Gambit Security 2026-09-22 |
| T1602 | Data from Configuration Repository | Collection | CyberStrikeAI | Full device configurations extracted, yielding credentials and network topology | Amazon Threat Intelligence 2026-02-20 |
| T1071.001 | Web Protocols | Command and Control | CyberStrikeAI | Built-in HTTP beacon implant with check-in, task, result and upload paths and a 5-second default sleep | CyberStrikeAI source; Kaspersky Securelist 2026-11-02 |
| T1090 | Proxy | Command and Control | CAIRN, PentAGI, STRIX | Residential proxy providers (IPRoyal, 711proxy, 1024proxy) used against targets | GTIG 2026-10-30; Gambit Security 2026-09-22 |
| T1090.003 | Multi-hop Proxy | Command and Control | ARTEX | Routed traffic through Tor, SOCKS proxies and a compromised relay (CrowdStrike); proxy pool API and upstream SOCKS proxy on the actor's infrastruct... | CrowdStrike |
| T1102 | Web Service | Command and Control | ARTEX, CAIRN | Agents call LLM APIs (api.deepseek.com, open.bigmodel.cn, api.x.ai, api.anthropic.com) and resellers such as xcai.pro; a compromised host turned in... | Zscaler ThreatLabz 2026-10-14 |
| T1105 | Ingress Tool Transfer | Command and Control | ARTEX, CyberStrikeAI | Scripts fetched with curl onto the victim's internal Windows database server | GTIG 2026-10-30; Kaspersky Securelist 2026-11-02 |
| T1572 | Protocol Tunneling | Command and Control | ARTEX | Tunneled traffic via Chisel and SoftEther | CrowdStrike 2026-10-29 |
| T1041 | Exfiltration Over C2 Channel | Exfiltration | ARTEX, CyberStrikeAI | Exfiltration of personally identifiable information belonging to approximately 67,000 individuals | Kaspersky Securelist 2026-11-02; Zscaler ThreatLabz 2026-10-14 |
| T1048.003 | Exfiltration Over Unencrypted Non-C2 Protocol | Exfiltration | CAIRN, STRIX | DNS exfiltration, catch-all mail and HTTP listeners on the operator's infrastructure | Gambit Security 2026-09-22 |
| T1567 | Exfiltration Over Web Service | Exfiltration | ARTEX | Investigation assets, data and source code archived to Backblaze B2 by the operator | Zscaler ThreatLabz 2026-10-21 |
| T1567.004 | Exfiltration Over Webhook | Exfiltration | ARTEX | Command results posted back across 491 rotating webhook.site endpoints via curl | GTIG 2026-10-30 |
| T1565 | Data Manipulation | Impact | ARTEX, CAIRN, CyberStrikeAI, PentAGI | Micro-value test transactions (such as Rs. 1) to validate unauthorized fund flows before large transfers; settlement API abuse | CERT-In CIAD-2026-0058 |

## Intelligence gaps and caveats

- Most in-the-wild ATT&CK evidence attaches to **ARTEX** and, since Kaspersky's
  report, **CyberStrikeAI** operators; STRIX, PentAGI and HexStrike-AI are
  thinner and several rows are capability-level (read from source) rather than
  observed in an intrusion. Those are marked in the evidence file.
- **CyberStrikeAI's FortiGate link** is Team Cymru's, via a shared server carrying
  the CyberStrikeAI banner; Amazon did not name the framework. Kaspersky could
  not attribute its education-sector campaign to a known group.
- **North Korean ARTEX use** comes with no indicators, targets or techniques from
  Microsoft; it is recorded as an actor fact only.
- **Trojanized ARTEX images**: Badbyte's page blocks scripted download, so its
  hashes and build ID were read through a fetch tool and could not be
  re-verified independently; the registry now refuses access to the backdoored
  repositories. Five other image names from the same news coverage are
  unofficial but NOT backdoored per Badbyte -- they indicate an ARTEX install,
  nothing more.
- **TrendAI's CyberStrikeAI research** is cited through The Hacker News; the
  primary report was not located. Its 19-organization figure counts validation
  activity, not confirmed breaches.
- **ATT&CK has no software entry** for any of these frameworks as of v20.
- Secondary coverage attributing HexStrike-AI exploitation to a named group
  could not be verified against a primary source and is not used.
- **HexStrike-AI** reporting is largely vendor and dark-web chatter; the
  speed-of-exploitation claims are threat-actor claims, not measured, and
  exploitation success is unverified.
- No vendor detection signature exists for **STRIX** beyond the exposed-panel
  observation; its fingerprints here are read from source.
- User-agent strings can be changed by any operator, so their absence proves
  nothing. Framework update and telemetry hosts are the more durable host-level
  tell.
- The framework self-telemetry headers (STRIX, CyberStrikeAI) reach the model
  provider over TLS, so you see them only from a header-logging forward proxy or
  from endpoint telemetry on the host -- not from flow logs. The user-agent-drift
  hunt needs the Microsoft Graph activity logs connector enabled.
- The detection content is `needs_validation`: its logic was checked against the
  Morpheus behavioral trackers on a synthetic corpus, not executed against a
  live Splunk or Sentinel. Derive every threshold from your own baseline period.
