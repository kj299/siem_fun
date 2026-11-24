# WAF filtering rules for agentic attack frameworks

Edge rules for F5 BIG-IP, Akamai App and API Protector, and anything that reads
ModSecurity SecLang, built from the indicators in [../iocs.csv](../iocs.csv)
and the reporting summarised in
[agentic-ai-attacks.md](../../../splunk-sentinel-query-builder/references/agentic-ai-attacks.md)
(intelligence as of 2026-11-24). They target ARTEX and CAIRN first, and the
other four frameworks that document covers where they leave an edge-visible
fingerprint.

**Status: `needs_validation`.** The patterns were exercised offline against
the indicator values; no file here has been loaded on a live device. What was
checked against vendor documentation on 2026-11-24:

- **Akamai**: field names, condition types and enum values in the JSON match
  the Application Security API reference for custom rules and rate policies.
  The reference documents wildcard values for header conditions only, so the
  path, query and POST-argument rules are the least certain.
- **F5**: the iRule's use of `class match`, `call` with a local `proc`,
  body collection and the `noserver` response flag matches the iRules
  reference on clouddocs.f5.com.
- **ModSecurity**: not checked against an engine or its reference.

Deploy every rule in log or alert mode first.

## Read this before blocking anything

A WAF signature stops a default or careless deployment, not a determined
operator. Three facts from the reporting set the ceiling:

- STRIX's own prompt tells the operator to strip identifiable markers, and
  every user-agent below is one config line away from changing. Absence of a
  hit means nothing.
- S-RM watched agents move to Tor and more than 50 VPS addresses within ten
  minutes of one IP block, and Check Point saw operators write a
  residential-proxy skill to get around WAF restrictions. Address blocks and
  per-address rate limits are a speed bump.
- F5 Labs (2026-11-23) watched ARTEX treat a WAF as an oracle: it enumerates
  what is allowed and blocked, then evades by keyword substitution and
  splitting, encoding variants and payload padding, and when standard pages
  stay blocked it pivots to discovering APIs and business-logic flaws. Their
  summary: agentic activity "is seldom identifiable by stateless detection
  rules" unless the agent names itself in the User-Agent.
- Unit 42's clearest agent tell is cadence (bursts of 1 to 14 requests at
  about one a second, then a 25 to 31 second model-inference pause). A WAF
  cannot see that shape; the SIEM rules next door can.

So the pack is three tiers, and the value rises as you go down: fingerprints
are cheap and brittle, exposure reduction removes what the agent reads first,
and tempo controls hit the one thing an agent cannot hide without giving up
its speed advantage.

## Files

| File | What it is |
| --- | --- |
| [f5-irule-agentic.tcl](f5-irule-agentic.tcl) | iRule for a BIG-IP HTTP virtual server: tiers 1 and 2. Log-only by default. |
| [f5-data-groups.tmsh](f5-data-groups.tmsh) | The data groups the iRule reads, as tmsh commands. |
| [akamai-custom-rules.json](akamai-custom-rules.json) | Akamai custom rules (tiers 1 and 2) and rate policies (tier 3), each with a recommended action. |
| [modsecurity-agentic.conf](modsecurity-agentic.conf) | The same rules in SecLang, plus simple per-source counters for tier 3. |
| [ua-block.txt](ua-block.txt) | Lower-case user-agent substrings that are safe to deny. Read directly by the SecLang file. |
| [ua-alert.txt](ua-alert.txt) | User-agent substrings with legitimate users. Log only. |
| [blocklist-ipv4.txt](blocklist-ipv4.txt) | The IPv4 rows of `iocs.csv` whose action starts with `block`. |

[scripts/tests/test_agentic_ai_attacks.py](../../../scripts/tests/test_agentic_ai_attacks.py)
keeps these in step with `iocs.csv`: the address list must equal the
block-action rows, every platform file must carry every user-agent substring,
every inbound user-agent indicator must be covered, and no legitimate service
may appear in a rule file.

## Tier 1: deterministic fingerprints (deny after a log-only week)

| Rule | Matches | Where | Evidence | False-positive risk |
| --- | --- | --- | --- | --- |
| W-AGT-001 | Framework user-agents: `artex-enrich/`, `compatible; ArtEx/`, `infra-hunt/`, `verify-911-probe/`, `spa-api-recon`, `security-testing; authorized`, `recon-audit`, `ReconProbe/`, `HexStrike-`, `CyberStrikeAI`, `PentAGI/`, `tcp_beacon` | User-Agent header | Framework source code; WorkOS 2026-11-06; Unit 42 2026-10-30; Wiz 2026-10-22 | Low. An authorized tester running a default build will be blocked too; that is a finding, not a false positive. |
| W-AGT-002 | `CyberStrikeAI-WebShell` user-agent | User-Agent header | CyberStrikeAI source (web-shell manager) | None, and blocking is not enough: this is someone driving a shell they believe is on your server. Investigate the requested path. |
| W-AGT-003 | `norma/0.`, `Fuzz Faster U Fool`, `PentAGI-Installer` | User-Agent header | Nextron (Norma is not ARTEX-exclusive); Unit 42 | High if denied. Log only. |
| W-AGT-004 | Canary probes `/zzz-nonexistent-xyz123`, `/zzzrandom12345`; `artex-probe-<number>` files and `ArtexProbe` account names (GTIG); canary identities `zz_no_such_user_9f3a`, `zzq.nonexistent9x7`, `precheck.not-a-user@example.invalid`; any address at `example.invalid`; OAuth `state=notvalidb64`; cloud metadata address in a parameter | Path, query, body | Wiz 2026-10-22; Unit 42 2026-10-30; S-RM 2026-11-04; CrowdStrike 2026-10-29 | Low. `.invalid` is a reserved top-level domain that can never receive mail. Matched as prefixes, so a changed suffix still hits. |
| W-AGT-005 | JWT whose header is `alg` `none` (base64 prefix `eyJhbGciOiJub25l` and casings) | Authorization, cookies, URL | Wiz 2026-10-22 | None. No working deployment issues unsigned tokens. |
| W-AGT-006 | SQL injection strings tagged `ARTEX'` | Query, body | S-RM 2026-11-04 | Low. |
| W-AGT-007 | Probe-account identity `i<intent>probe<unix-time>@` | Sign-up, login and recovery bodies | Okta 2026-11-06 | Low. |
| W-AGT-008 | Script named like an agent task artifact, `i<3 to 5 digits>.<asp, aspx, jsp, php ...>`, requested or uploaded | Path, upload filename | S-RM 2026-11-04 (`i4028.asp`) | Medium. Single-engagement indicator; check your own file naming first. Akamai's wildcard version is looser, so it ships as alert. |
| W-AGT-008 (second shape) | JSP shell named 1-2 letters, 4 digits, optional letter (`cl1217.jsp`, `f1219a.jsp`, `z1219.jsp`) | Path | GTIG 2026-10-30 (MySQL general-log poisoning) | Medium. Not expressible in Akamai's wildcard builder. |
| W-AGT-009 | Inline DTD or entity declaration in an XML body | Body | CrowdStrike 2026-10-29 (unsigned SAML plus XXE to the metadata service) | Low, but partial: a base64 SAML response hides it from the edge. The real fix is DTD processing off and signature validation on in the service provider. |
| W-AGT-010 | 44 source addresses, including the eight Storm-3358 ARTEX and C2 servers Microsoft published on 2026-11-06 | Client address | `iocs.csv` rows marked block (CrowdStrike, Zscaler, NorForge, Kaspersky, Microsoft and others) | Low today, decaying. The FBI FLASH of 2026-11-13 asks you to vet addresses before blocking because hosting addresses get reassigned. Review on every `iocs.csv` update; expire after 90 days. |
| W-AGT-011 | Shell command syntax in the User-Agent (`$(`, a backtick, `; curl`, a pipe to `sh`) | User-Agent header | Microsoft 2026-11-05 (exploitation by shell commands embedded in a user agent) | None for browsers. |
| W-AGT-012 | Upload filename containing `../`, or named `sitecustomize.py` or `usercustomize.py` | Multipart body | Amazon 2026-11-20: Cairn agents found a path-traversal zero-day in an upload filename parameter in about 11 minutes and wrote a Python auto-import file for a root shell | Low. On Akamai this is left to the managed attack groups. |
| W-AGT-013 | `isCliRequest` request header | Header | Amazon, November 2026: authentication bypass in the ARTEX playbook against One API family LLM gateways | Log only. Relevant only in front of such a gateway. |

Deliberately **not** blocked, because the IOC file says so and the test
enforces it: LLM API hosts, `webhook.site`, `dnslog.cn`, the `lanmao666`
gateway, the Check Point cluster ranges, the Unit 42 addresses, the addresses
Amazon published from its decoy sensors (for review, and three sit in a
shared CDN range), and the WorkOS researcher's addresses and JA4 fingerprints. The three JA4 values in
`iocs.csv` identify an HTTP client library rather than an actor: if your
platform exposes JA4, use them to raise a score, never as a deny on their own.

On a deny, return the same generic 403 your application returns elsewhere.
The agents self-correct from error bodies (Microsoft saw one adjust after
HTTP 400s at 28, 60 and 80 seconds), so a block page that explains itself is
a hint.

## Tier 2: remove what the agent reads first

Unit 42 saw ARTEX-derived agents harvest JavaScript source maps and OpenAPI
documents, then call only the routes those documents define, within seconds.
WorkOS's root cause was an internal API reachable from the internet with a
predictable development credential and no rate limiting.

- **W-AGT-020**: refuse `*.js.map`, `/openapi.json`, `/swagger.json`,
  `/v3/api-docs` and `/runtime-config.json` to clients outside your own
  ranges. Shipped disabled or as alert, because some of you publish an API
  specification on purpose. Better still, stop deploying source maps to
  production.
- Put non-production hosts (UAT, staging, test) behind an allowlist or
  identity-aware proxy. CERT-In names exposed non-production environments as
  the entry point, with shared credentials carrying the agent into production.
- Enforce a positive security model on APIs where the platform supports it
  (F5 Advanced WAF with an imported OpenAPI file, Akamai API request
  constraints): reject undeclared routes, methods and parameters.
- Admin and management paths: deny from the internet outright rather than
  rate limiting them. The FBI FLASH names Kudu/SCM publishing endpoints,
  hypervisors and backup platforms specifically.
- **Inventory the peripheral applications.** Akamai (2026-10-23) and the FBI
  both put the weight here: partner and supplier portals, mobile backends,
  employee and sales-support applications, legacy services and third-party
  integrations get less attention than the flagship site and are what the
  agents find. A rule pack attached only to the main virtual server or
  property protects the wrong thing.
- **LLM gateways and AI application builders are targets in their own right.**
  Amazon saw an ARTEX campaign harvest provider keys from exposed One API,
  New API, LiteLLM, Dify, Langflow, RAGFlow and Open WebUI installs through
  unclaimed setup pages, anonymous management endpoints and default master
  keys. Keep their management interfaces off the internet; Akamai's guidance
  is to put a WAF or AI gateway in front of model and MCP endpoints and rate
  limit by identity and cost.
- **Return less.** The FBI asks that unauthenticated users never see stack
  traces, SQL errors, internal paths or framework details; F5's lab found the
  attacks that still succeeded behind a full stack hit endpoints returning
  data without an authorization check. Response-side leakage rules and
  server-side authorization matter more than another request signature.

## Tier 3: tempo and abuse controls (the durable part)

Thresholds below are starting points. Derive your own from a baseline week;
the SIEM rules in this folder do the same.

| Rule | Control | Starting threshold | Evidence |
| --- | --- | --- | --- |
| W-AGT-030 | Error-rate enumeration: count 400, 401, 403, 404 and 405 responses per client | More than 30 in 60 seconds, then a 10-minute penalty | Wiz: more than 60 SSO route variants per target; R-D-AGT-001 alerts at 200 distinct paths in 10 minutes |
| W-AGT-031 | Source-centric login failures, across any number of usernames | More than 10 in 5 minutes | Microsoft: 151,000 failures against 327 accounts, peaking at 2,900 a minute |
| W-AGT-032 | Self-registration rate, plus refusal of disposable mail domains and of shared-mailbox prefixes at your own domain (`admin@`, `billing@`, `security@` ...) | More than 3 sign-ups an hour per client | Okta 2026-11-06; Expel 2026-10-21 |
| W-AGT-033 | OAuth authorize and token endpoints: rate the error responses | More than 3 a second burst | Unit 42 and Okta: unregistered redirect URIs tried across many client IDs |
| W-AGT-034 | Repeat violator: a client that keeps drawing WAF denials is probing the ruleset, so escalate from challenge to block | More than 5 denials in 2 minutes, then a 30-minute penalty | F5 Labs 2026-11-23: rapid probing that adapts to the previous response is the strongest agent signal |

Platform notes:

- **Key the counters on more than the address.** Use a TLS fingerprint,
  session cookie or device identifier where the platform has one, because the
  spraying is spread over residential proxy pools precisely to stay under
  per-address limits. F5 measured one proxy service on an exposed attacker
  server handing out 79 exit addresses for the first 100 identities tested.
- **Use reputation for the egress the agents favour.** F5 Labs notes the
  rotation usually lands on Tor and residential proxy networks, so IP
  reputation feeds and geofencing still bite even though a static list does
  not.
- **Guard the business function, not only the request.** The FBI recommends
  rate limits, recipient limits and transaction thresholds on high-impact
  APIs, and alerts on sequential lookups or unusually many records per
  session on partner and employee portals.
- **F5**: the iRule carries no counters on purpose. On BIG-IP use Advanced
  WAF brute-force protection with source-based and distributed-attack
  detection for W-AGT-031, session tracking with violation thresholds for
  W-AGT-030 and W-AGT-034, and Bot Defense on login, sign-up and recovery
  URLs. F5's own ARTEX testing (2026-11-13) was on Distributed Cloud, not
  BIG-IP: signatures stopped the first wave, the agent pivoted to APIs, and
  what held was malicious user detection (one score per actor across WAF
  violations, failed logins, bot telemetry and rate-limit hits, keyed on JA4,
  cookies and JWT claims as well as address), Bot Defense client telemetry,
  and OpenAPI schema enforcement. F5 reports more than 70 percent fewer
  successful attacks with the first two and more than 90 percent with all
  four, in its lab, against a deliberately vulnerable application.
- **Akamai**: the rate policies in the JSON cover W-AGT-030 to W-AGT-033 and
  count per address and TLS fingerprint. For W-AGT-034 turn on the security
  policy's penalty box. Akamai's Adaptive Security Engine also ships
  AI-powered WAF detections (announced 2026-08-13, manageable by API);
  Akamai's own example of one is a request whose User-Agent contains
  `PentestAgent`. Keep the managed attack groups in deny: W-AGT-009 and
  W-AGT-012 rely on them here.
  Pair the rate policies with Bot Manager on the same endpoints, and add a
  Client Reputation deny for the web-scanner and web-attacker categories at
  high scores.
- **Step up, do not only block.** A challenge on sign-up and recovery costs a
  person a few seconds and costs an agent its unattended loop.

## What the edge cannot do

Pair these rules with the detections in this folder rather than treating
either as complete:

- Cadence and spec-driven API targeting: R-B-AGT-002 and R-D-AGT-017.
- A canary username followed by an admin login: R-D-AGT-018.
- Leaked application secrets used against Entra, and identity persistence
  afterwards: R-D-AGT-020 and R-B-AGT-008. No inbound WAF sees these.
- A web shell written through SQL injection or log poisoning: R-B-AGT-005 and
  R-D-AGT-013.
- Card skimmers placed after access (CAIRN and ARTEX cases): a
  Content-Security-Policy with reporting, and subresource integrity, not a
  request filter.
- Your own hosts turned into agent infrastructure: egress rules R-B-AGT-004
  and R-D-AGT-016.

Microsoft (2026-11-06) adds a control this pack does not ship: decoys and
tarpits, which in its testing consumed the agent's time and budget and cut
the attack traffic reaching real assets.

S-RM's conclusion applies to the whole pack: blocking alone does not stop a
returning agent, so pre-authorize containment (isolation, credential resets)
alongside it.

## Rolling out

1. Load the data groups, network list or files; enable every rule in log or
   alert mode.
2. After a week, review hits. Tier 1 rules other than W-AGT-008 should be
   silent or obviously hostile; move them to deny.
3. Set tier 3 thresholds from the observed baseline, then enforce.
4. When `iocs.csv` changes, regenerate `blocklist-ipv4.txt` and the
   `agt_ip_block` data group from its block-action IPv4 rows; the test fails
   until they agree.

## Sources read for the 2026-11-24 refresh

Read in full: FBI FLASH-20261113-001; F5 Labs, "The ARTEX framework"
(2026-11-23); F5, "Stopping ARTEX cybersecurity attacks" (2026-11-13);
Amazon Threat Intelligence's two posts on ARTEX and Cairn agents; Microsoft's
Storm-3358 post (2026-11-06); Akamai's API reference; F5's iRules reference.

Not read, and so not relied on for any rule: Akamai's blog posts (the site
refuses automated clients, so only search summaries were seen), Unit 42's
CL-STA-1238 Cairn report, Sophos, CERT-EU and the Cloud Security Alliance
notes. Two addresses that secondary coverage attributes to CL-STA-1238 were
left out of `iocs.csv` for that reason.
