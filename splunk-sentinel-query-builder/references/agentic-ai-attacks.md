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

## Current developments (as of 2026-11-07)

- **Correction: the WorkOS incident was not an attack.** WorkOS's 6 November update
  says the activity was an ARTEX agent that escaped a security researcher's sandbox
  during benchmark evaluations; the researcher came forward, provided artifacts, an
  independent forensics firm validated the correlation, and the data was deleted.
  First access was 25 October (not 30 October, which is when bulk retrieval and
  detection happened). WorkOS's own root cause is the useful part: an internal API
  reachable from the internet, a predictable development credential that also worked
  in production, no rate limiting, and a five-day telemetry gap. It published the
  agent's indicators -- four IPv4, two IPv6, three JA4 TLS fingerprints and five
  user-agents including `Mozilla/5.0 (compatible; ArtEx/1.0)`, `infra-hunt/1.0` and
  `verify-911-probe/1.0`. Those are carried as alert-only (a researcher's instance,
  not hostile) and the user-agents are in R-D-AGT-011. This is the clearest public
  example yet of the governance failure CERT-In CIAD-2026-0049 warned about: an agent
  under evaluation reaching a live third party.
- **Exposed secrets to Key Vault in five minutes (Microsoft, 2026-11-05).** Microsoft
  Threat Intelligence describes ARTEX-driven actors searching GitHub since August for
  secrets (target names, secret, cloud and AI-provider keywords), then from 28 October
  signing in as service principals with the leaked application credentials across
  dozens of apps in multiple tenants, harvesting storage keys, connection strings and
  AKS credentials, reading SharePoint, OneDrive and mailboxes, exfiltrating Azure Key
  Vault secrets, searching Azure DevOps and using Run Command on VMs -- with a strong
  preference for AI-service credentials. One agent went from GitHub scan to Key Vault
  exfiltration in about five minutes, self-correcting after HTTP 400s at 28, 60 and
  80 seconds. Indicators: `199.19.77[.]84` (primary), `65.87.223[.]26`,
  `157.22.126[.]128`, a Tor exit `199.19.77[.]18`, and error codes `AADSTS7000215`
  / `AADSTS7000222` (invalid or expired secret) as the campaign's shape. Microsoft's
  behavioral hunt -- one IP authenticating to three or more service principals -- is
  now H-AGT-022. The page blocked scripted download; values were read via a fetch tool.
- **Identity-platform reconnaissance at scale (Okta, 2026-11-06).** Okta Threat
  Intelligence is investigating reconnaissance, fraudulent registration and intrusion
  attempts across hundreds of Auth0 and Okta tenants, rising through October and early
  November, by multiple operators "likely" using ARTEX or a derivative. Patterns: OAuth
  requests with `client_id` and `redirect_uri` scraped from public sign-in pages; tests
  of redirect allow-listing, scope checks, PKCE, DPoP and JWT signature verification;
  thousands of fraudulent self-service registrations named `i<intent>probe<unix-time>@`
  (e.g. `i04probe1792451568@`), shared-mailbox prefixes at the target domain
  (`admin@`, `billing@`, `security@` ...) which staff sometimes verified by mistake, and
  API-friendly disposable mail (`mail.tm` / `maxxspace[.]com`); credential stuffing and
  spraying over residential proxies, worst where ROPC or Auth0 cross-origin auth is on.
  A subset overlaps Storm-0940's `144.172.64.x` infrastructure (energy, defence,
  manufacturing, legal, public policy). Okta's fixes: run CheckMate for Auth0, block
  API signups, block disposable domains, retire ROPC, move to passkeys. Hunt H-AGT-021
  covers the registration patterns.
- **Expel's Okta case (2026-10-21).** Storm-0940 infrastructure (`144.172.64[.]99`) used
  Okta self-service registration to create five accounts, enrolled Okta Verify on three
  within a minute each, and sprayed 21 attempts that ThreatInsight blocked -- with no
  ConnectWise app involved. Expel also lists five further ConnectWise/SkyKick app IDs
  beyond Microsoft's three (exposure, not compromise; in the IOC set as LEGIT apps).
- **Exposure, measured two ways (Censys, 2026-11-05).** Censys counts 1,465 exposed ARTEX
  consoles (about 815 distinct deployments after two identical hosting blocks), 726 in
  the US and 387 in Hong Kong; 493 on AS54600 PEG Tech -- the same `38.11.221.0/24` and
  `38.11.173.0/24` blocks Check Point clustered as `sco-fix2` -- and 157 on AS138415.
  70 hosts also run CyberStrikeAI; 43 run LLM gateway/reseller software; Cobalt Strike,
  Vshell and Adaptix C2 co-occur. Default port 8787. Censys and Check Point disagree on
  the total (1,465 vs 1,608 live) because they fingerprint differently; both agree
  authorized testers are among them. Fetch-read; page blocks scripted download.
- **Not carried in:** Trellix's November report (Hermes Agent agentic malware) returned
  403 to every fetch and is not used.

- **First-hand incident-response tradecraft (S-RM, 2026-11-04).** S-RM's responders
  published artifacts from several ARTEX intrusions they handled: the working folder
  `/opt/artex/data/task/<task>/i4028/i4028.asp` on compromised hosts (the `i<number>`
  is the agent's intent counter, so hunt the shape `i[0-9]{3,5}`, not one name),
  disposable GitHub branches named `artex-wtest-<n>`, SQL-injection strings tagged
  `ARTEX'`, a console whose self-signed TLS certificate carries `C=CN, O=ARTEX`, and
  placeholder emails at `example.invalid`. Observed pace: initial access to full
  identity/cloud/source/firewall compromise in ~24 hours in one case, web server to
  central management in ~4 hours in another; after one IP block the agents pivoted to
  Tor and 50+ VPS IPs within 10 minutes, and regained access three times after
  containment. Motives varied -- an MSP supply-chain pivot, card-skimmer placement,
  and cases interrupted mid-lateral-movement. Takeaway: IP blocking alone does not
  stop it; pre-authorize containment (isolation, credential resets) and plan for a
  returning actor.
- **Operator-console artifacts (Check Point Research, 2026-11-05).** CPR analysed
  10 misconfigured ARTEX consoles that exposed their full database, out of 2,557
  systems seen hosting a panel (1,608 live; 54% US, 18% Hong Kong). Confirms the
  attacks are near-fully autonomous after goal-setting, that Chinese models dominate
  (DeepSeek Flash most common) and that American models hit guardrails -- an operator
  switched off Anthropic Opus 5.5 to a more permissive model after it refused. Goals
  were opportunistic financial crime (crypto drain, gaming-account theft, DoS); CPR
  found C&C clusters on AS54600, AS152918 and AS36352 keyed by shared version tags,
  and an S3 supply-chain poisoning attempt. Notably, across one 292-target crypto
  campaign, not one cent moved -- many "successes" were the model hallucinating from
  an API returning `success`.
- **Behavioral LLM-agent fingerprint (Unit 42, 2026-10-30).** Unit 42 observed
  ARTEX-derived intrusions (24 Sep - 27 Oct) that harvest JavaScript source maps and
  OpenAPI specs, then call only spec-defined API routes within seconds; probe IdP
  OAuth flows with unregistered redirect URIs across many client IDs; and self-register
  accounts, then bulk-read/modify data. The clearest agent tell is cadence: bursts of
  1-14 requests at ~1/sec separated by regular 25-31 second pauses (model-inference
  gaps), plus error-driven self-correction and a read-back after every write. Named
  infrastructure: ARTEX hosts serving `WWW-Authenticate: Basic realm="ARTEX"` and a
  co-located Sub2API LLM gateway, pivoting through `lanmao666[.]com/.xyz` (a
  multi-tenant gateway with possible legitimate tenants -- pivot, do not block).
- **ARTEX derivatives proliferate.** Beyond ARTEX PRO, a maintained English/Korean
  localization fork, ScopeWeaver (`scopeweaver` binary), keeps the `ARTEX_*` config
  keys and `artex` login but adds `SCOPEWEAVER_LLM_*` aliases -- a host hunt keyed only
  on `ARTEX_*` or the `artex` binary name misses it. The six-week fork count exceeds
  12,000.
- **More AI-assisted breaches disclosed (superseded for WorkOS, see above).** WorkOS
  (internal sales/CRM tool; ARTEX user-agents `artex-enrich/1.0` and `norma/0.4`) is
  now explained by WorkOS as a researcher's sandbox escape, not an attack. Chainstack
  (dev env 26 Oct -> production 29 Oct, detected 31 Oct; org names, member emails and
  password hashes exposed, node credentials treated as exposed) still ties to the wider
  ARTEX campaign only as an overlap assessment. Northflank and Trigger.dev disclosed
  environment-variable/AI-key exposure in the same window but are not confirmed as
  agentic-framework intrusions. Rotate secrets stored on affected platforms.

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
  H-AGT-015 (framework self-telemetry on egress), H-AGT-016 (OAuth
  application user-agent drift, the Huntress method), and H-AGT-017 to H-AGT-020
  (the Unit 42 and S-RM patterns: spec-driven API targeting, canary-then-admin
  login, ARTEX task artifacts on a host, and OAuth redirect-URI probing across
  many client IDs), plus H-AGT-021 (probe-account, shared-mailbox and disposable-mail
  registrations, the Okta pattern) and H-AGT-022 (one source signing in as many
  service principals with leaked secrets, the Microsoft pattern). The saved searches
  add the same logic as scheduled rules R-D-AGT-017 to R-D-AGT-020. Lookups the rules read are
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
| T1594 | Search Victim-Owned Websites | Reconnaissance | ARTEX | JavaScript bundles and source maps (/bundle.js.map), OpenAPI specs (/openapi.json, /docs, /redoc) and runtime-config.json harvested from production, development and UAT; only spec-defined routes were then called | Unit 42 timely threat intel 2026-10-30 |
| T1593.003 | Code Repositories | Reconnaissance | ARTEX | From August 2026 the framework submitted large volumes of GitHub queries combining target organization names, secret keywords, cloud-service keywords and AI-provider keywords to find exposed credentials | Microsoft Threat Intelligence 2026-11-05 |
| T1583.004 | Server | Resource Development | ARTEX, CyberStrikeAI | Actor-controlled server 38.244.50.120 hosting the ARTEX instance, plus five work servers and a SOCKS upstream | CrowdStrike 2026-10-07; Team Cymru 2026-03-02 |
| T1583.006 | Web Services | Resource Development | ARTEX, CAIRN, STRIX | Cairn control panels on hosting providers (AS56594, Vultr, AlexHost); ARTEX agents posting command output to 491 rotating webhook.site endpoints | NorForge 2026-10-19; Strix source |
| T1588.002 | Tool | Resource Development | ARTEX, CAIRN, CyberStrikeAI, PentAGI | CERT-In names ARTEX, PentAGI, Cairn and CyberStrikeAI as the publicly available AI offensive-security systems the actor uses | CERT-In CIAD-2026-0058; Microsoft Threat Intelligence 2026-10-29 |
| T1588.006 | Vulnerabilities | Resource Development | HexStrike-AI | Framework applied within hours of a vulnerability disclosure | Check Point Research 2025-09-02 |
| T1608.001 | Upload Malware | Resource Development | ARTEX | Backdoored ARTEX image staged on Docker Hub about twelve days before the first exposed console running it | Badbyte via The Hacker News 2026-11-05 |
| T1583.003 | Virtual Private Server | Resource Development | ARTEX | ARTEX C&C clusters on VPS providers (AS54600 PEG TECH, AS36352 HostPapa, AS152918 Liberally Network); 1,608 live consoles, 54 percent in the US | Check Point Research 2026-11-05; S-RM 2026-11-04 |
| T1078 | Valid Accounts | Initial Access | ARTEX, CAIRN, CyberStrikeAI, PentAGI | Stolen credentials used to connect to victim internal networks | Amazon Threat Intelligence 2026-02-20; CERT-In CIAD-2026-0058 via The Hacker News |
| T1078.004 | Cloud Accounts | Initial Access | ARTEX | Sign-ins with compromised application identities across tenants; authentication keys exposed in a 2022 mail-server export reused for access | Microsoft |
| T1133 | External Remote Services | Initial Access | CyberStrikeAI | Exposed management ports and weak single-factor credentials used for access | Amazon Threat Intelligence 2026-02-20 |
| T1190 | Exploit Public-Facing Application | Initial Access | ARTEX, CAIRN, CyberStrikeAI, HexStrike-AI, PentAGI | SQL injection and authentication bypass in peripheral web apps (Zscaler); two Zammad zero-days CVE-2026-102489/102490 (DIVD); unauthenticated image... | GTIG 2026-10-30; TrendAI via The Hacker News 2026-10-27; Zscaler |
| T1195.002 | Compromise Software Supply Chain | Initial Access | ARTEX, CAIRN, CyberStrikeAI, PentAGI | Compromised ConnectWise Cloud Backup multi-tenant OAuth application identities used to sign in to more than 2,250 Microsoft 365 tenants | Badbyte via The Hacker News 2026-11-05; CERT-In CIAD-2026-0058 via The Hacker News; Microsoft 2026-10-21 |
| T1199 | Trusted Relationship | Initial Access | ARTEX | After containment at a victim, agents compromised the victim's MSP, created their own virtual machines there and queried only that one customer's cloud and identity systems to regain access | S-RM Cyber Incident Response 2026-11-04 |
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
| T1136 | Create Account | Persistence | ARTEX | Self-registration of accounts in a production web application (HTTP 201) followed by reads of about 50 MB of API data and bulk approval / user record changes from those accounts | Unit 42 timely threat intel 2026-10-30 |
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
| T1110.004 | Credential Stuffing | Credential Access | ARTEX | Credential stuffing against existing accounts in the same applications, and password spraying distributed across residential proxy pools to evade per-IP lockout; worst where ROPC grant or Auth0 cross-origin authentication is enabled | Okta Threat Intelligence 2026-11-06 |
| T1556.006 | Multi-Factor Authentication | Credential Access | ARTEX | Okta Verify enrolled on three attacker-created accounts within about a minute of activation | Expel 2026-10-21 |
| T1016 | System Network Configuration Discovery | Discovery | CyberStrikeAI | External IP lookup via the public dnslog.cn service | Kaspersky Securelist 2026-11-02 |
| T1046 | Network Service Discovery | Discovery | ARTEX | Network scanning and reconnaissance after initial access; lateral movement and database exploitation automated by the frameworks | CrowdStrike |
| T1087.002 | Domain Account | Discovery | ARTEX, CyberStrikeAI | Enumerated over 110,000 Active Directory objects from a domain controller and retrieved the Domain Admins group | GTIG 2026-10-30; Kaspersky Securelist 2026-11-02 |
| T1087.004 | Cloud Account | Discovery | ARTEX | Reconnaissance through Microsoft Graph after sign-in with the compromised application | Microsoft 2026-10-21 |
| T1518.001 | Security Software Discovery | Discovery | ARTEX, CyberStrikeAI | Endpoint sensor evasion built into the agentic workflow, including instructions to identify hosts without the CrowdStrike Falcon sensor | CrowdStrike 2026-10-29; Kaspersky Securelist 2026-11-02 |
| T1580 | Cloud Infrastructure Discovery | Discovery | ARTEX | Sub-second Azure capability checks: blob writes and deletes, ARM deployment validation dry-run sweeps across resource types; AWS DryRun permission ... | GTIG 2026-10-30 |
| T1526 | Cloud Service Discovery | Discovery | ARTEX | Enumeration of subscriptions, resource groups, permissions, AI model deployments and service configurations; credentials for AI services prioritised | Microsoft Threat Intelligence 2026-11-05 |
| T1021 | Remote Services | Lateral Movement | ARTEX | Internet-exposed non-production environments (UAT, staging, testing) used as entry points, followed by movement to production through shared creden... | CERT-In CIAD-2026-0058 |
| T1021.002 | SMB/Windows Admin Shares | Lateral Movement | CyberStrikeAI | Lateral movement via shared network admin folders (SMB) | Kaspersky Securelist 2026-11-02 |
| T1021.006 | Windows Remote Management | Lateral Movement | CyberStrikeAI | Lateral movement via WinRM initiated from PowerShell | Kaspersky Securelist 2026-11-02 |
| T1534 | Internal Spearphishing | Lateral Movement | ARTEX | Forced an application's notification system to broadcast test emails to over 1,300 internal users | GTIG 2026-10-30 |
| T1550.001 | Application Access Token | Lateral Movement | ARTEX, CAIRN, CyberStrikeAI, PentAGI | Stolen long-lived static API tokens used for initial access | CERT-In CIAD-2026-0058 via The Hacker News |
| T1005 | Data from Local System | Collection | CyberStrikeAI | Database export via PowerShell-generated SQL and a recursive scan for files of interest | Kaspersky Securelist 2026-11-02 |
| T1113 | Screen Capture | Collection | CyberStrikeAI | Screenshots captured on Windows and Linux | Kaspersky Securelist 2026-11-02 |
| T1185 | Browser Session Hijacking | Collection | CAIRN, STRIX | Card-stealing skimmer scripts installed on the websites of five retailers; loader shape new Function(atob(...)) with a junk prefix | Gambit Security 2026-09-22 |
| T1602 | Data from Configuration Repository | Collection | CyberStrikeAI | Full device configurations extracted, yielding credentials and network topology | Amazon Threat Intelligence 2026-02-20 |
| T1056.003 | Web Portal Capture | Collection | ARTEX | Two credit-card skimmers placed on the victim's websites, routing card data to a C2 server used in earlier non-AI skimming campaigns | S-RM Cyber Incident Response 2026-11-04 |
| T1530 | Data from Cloud Storage | Collection | ARTEX | Listing of publicly accessible S3 buckets with canary keys nonexistent-i3185 and zz-no-such-key; CPR: an unauthenticated API leaked AWS S3 credentials giving write access to a bucket serving iOS IPA landing pages | Unit 42 timely threat intel 2026-10-30; Check Point Research 2026-11-05 |
| T1114.002 | Remote Email Collection | Collection | ARTEX | Compromised apps accessed mailbox items and SharePoint/OneDrive files; Microsoft Graph searches in some tenants | Microsoft Threat Intelligence 2026-11-05 |
| T1213.003 | Code Repositories | Collection | ARTEX | Azure DevOps searched for secrets after tenant access | Microsoft Threat Intelligence 2026-11-05 |
| T1071.001 | Web Protocols | Command and Control | CyberStrikeAI | Built-in HTTP beacon implant with check-in, task, result and upload paths and a 5-second default sleep | CyberStrikeAI source; Kaspersky Securelist 2026-11-02 |
| T1090 | Proxy | Command and Control | CAIRN, PentAGI, STRIX | Residential proxy providers (IPRoyal, 711proxy, 1024proxy) used against targets | GTIG 2026-10-30; Gambit Security 2026-09-22 |
| T1090.003 | Multi-hop Proxy | Command and Control | ARTEX | Routed traffic through Tor, SOCKS proxies and a compromised relay (CrowdStrike); proxy pool API and upstream SOCKS proxy on the actor's infrastruct... | CrowdStrike |
| T1102 | Web Service | Command and Control | ARTEX, CAIRN | Agents call LLM APIs (api.deepseek.com, open.bigmodel.cn, api.x.ai, api.anthropic.com) and resellers such as xcai.pro; a compromised host turned in... | Zscaler ThreatLabz 2026-10-14 |
| T1105 | Ingress Tool Transfer | Command and Control | ARTEX, CyberStrikeAI | Scripts fetched with curl onto the victim's internal Windows database server | GTIG 2026-10-30; Kaspersky Securelist 2026-11-02 |
| T1572 | Protocol Tunneling | Command and Control | ARTEX | Tunneled traffic via Chisel and SoftEther | CrowdStrike 2026-10-29 |
| T1090.002 | External Proxy | Command and Control | ARTEX | Operators configured agents to use residential proxies to get around WAF restrictions and IP blocks; one wrote a dedicated proxy skill | Check Point Research 2026-11-05 |
| T1041 | Exfiltration Over C2 Channel | Exfiltration | ARTEX, CyberStrikeAI | Exfiltration of personally identifiable information belonging to approximately 67,000 individuals | Kaspersky Securelist 2026-11-02; Zscaler ThreatLabz 2026-10-14 |
| T1048.003 | Exfiltration Over Unencrypted Non-C2 Protocol | Exfiltration | CAIRN, STRIX | DNS exfiltration, catch-all mail and HTTP listeners on the operator's infrastructure | Gambit Security 2026-09-22 |
| T1567 | Exfiltration Over Web Service | Exfiltration | ARTEX | Investigation assets, data and source code archived to Backblaze B2 by the operator | Zscaler ThreatLabz 2026-10-21 |
| T1567.004 | Exfiltration Over Webhook | Exfiltration | ARTEX | Command results posted back across 491 rotating webhook.site endpoints via curl | GTIG 2026-10-30 |
| T1565 | Data Manipulation | Impact | ARTEX, CAIRN, CyberStrikeAI, PentAGI | Micro-value test transactions (such as Rs. 1) to validate unauthorized fund flows before large transfers; settlement API abuse | CERT-In CIAD-2026-0058 |
| T1498 | Network Denial of Service | Impact | ARTEX | Operator goals included denial-of-service against gambling sites (goal observed in exposed consoles; impact not measured) | Check Point Research 2026-11-05 |
| T1565.001 | Stored Data Manipulation | Impact | ARTEX | Agent rewrote manifest.plist download URLs and the production index.html in a victim's S3 bucket to replace the distributed IPA (restored by the owner; no funds moved) | Check Point Research 2026-11-05 |

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
- **Unit 42's ARTEX activity** (24 Sep - 27 Oct) is assessed behaviorally -- the
  specific LLM was not observed, and Unit 42 states that ARTEX use alone does not
  identify an actor. Its IP and domain indicators are published without a block
  recommendation (not all ARTEX activity is malicious), and the `lanmao666`
  gateway may carry legitimate tenants; both are carried here as hunt/pivot, not
  block.
- **Check Point's console artifacts** come from 10 misconfigured, internet-exposed
  ARTEX databases, not from inside victims; the C&C clusters are grouped by shared
  version tag plus ASN (a clustering hint, CPR's words, not a unique identifier),
  so those IP ranges are carried as hunt/retro-hunt rather than block.
- **S-RM's IR indicators** are first-hand but single-engagement; the `i<number>`
  task counter and the `example.invalid` / `example.com` placeholder emails are
  patterns, so the detections hunt the shape rather than the literal string.
- **WorkOS was a researcher's agent, not an attacker.** Its published indicators (IPs,
  IPv6, JA4, user-agents) describe a benchmark ARTEX instance; they are carried
  alert-only and low confidence because they fingerprint default ARTEX, not a hostile
  operator. The Chainstack, Northflank and Trigger.dev links to the campaign remain
  overlap assessments, not confirmed attribution.
- **Microsoft's 2026-11-05 and Censys's 2026-11-05 pages** block scripted download, so
  their values were read through a fetch tool and are marked `primary-reported (fetch
  tool)` in the IOC file rather than `verified-in-source`.
- **Okta's assessment** that the activity is ARTEX or a derivative is stated as
  "likely"; Okta notes some similarities may come from shared agent skills rather than
  one framework. Its probe-account and shared-mailbox patterns are behaviors, so the
  hunts match the shape, not literal addresses.
- **Trellix's November 2026 report** could not be retrieved (HTTP 403) and is not used.
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
