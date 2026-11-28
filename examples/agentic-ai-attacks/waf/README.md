# WAF filtering rules for agentic attack frameworks

Edge rules for F5 BIG-IP, Akamai App and API Protector, and anything that reads
ModSecurity SecLang, built from the indicators in [../iocs.csv](../iocs.csv)
and the reporting summarised in
[agentic-ai-attacks.md](../../../splunk-sentinel-query-builder/references/agentic-ai-attacks.md)
(intelligence as of 2026-11-24, with additions from reports read on
2026-11-27). They target ARTEX and CAIRN first, and the
other four frameworks that document covers where they leave an edge-visible
fingerprint.

**Status: `needs_validation`.** No file here has seen production traffic, so
false-positive rates are unmeasured. Deploy every rule in log or alert mode
first.

## What was executed, and what was only read

The three platform files do not carry the same weight of evidence. On
2026-11-24:

- **ModSecurity: executed.** The file was loaded on Apache 2.4.58 with
  mod_security 2.9.7 and on nginx 1.24 with libmodsecurity 3.0.12, each with
  the two body-processor rules of the recommended base configuration, alone
  and again after OWASP Core Rule Set 3.3.5. Every rule that ships enabled,
  and W-AGT-020 with its comment marks removed, was sent a request that
  should match and one that should not; the two log-only rules were read from
  the engine's log. The tempo rules were driven from separate source
  addresses, and in a test copy with every window shortened to check that a
  window ends and that a tripped counter is cleared. Each defect listed below
  was then put back, one at a time, to confirm a test fails for it. Coraza
  was not tried, and nginx was run with one worker (see the tempo section for
  why that matters).
- **F5: logic executed, platform not.** The iRule was run in `tclsh` against
  its real data groups, inside a stand-in for the iRule runtime that follows
  the command semantics on clouddocs.f5.com. That proves the rule's logic. It
  does not prove a BIG-IP behaves the same way, and the tmsh file has not
  been loaded on a device.
- **Akamai: read only.** Field names, condition types and enum values match
  the Application Security API reference for custom rules and rate policies.
  Nothing was imported into a configuration. The reference documents
  wildcard values and wildcard names for header conditions only, so the
  path, query and POST-argument rules are the least certain thing in this
  folder, and whether a path condition sees the path as sent or normalized is
  not stated on the public pages.

On 2026-11-28 the rules changed since then (the wider intent counter in
W-AGT-007 and W-AGT-008, two more W-AGT-004 canaries, the W-AGT-003 additions
and its anchored Norma match, and the iRule's read of a repeated
Transfer-Encoding header) were run again the same way, each with a request
that should match and one that should not, and each new matching case was
confirmed to fail against the previous files. The Akamai file changed in
step and, as before, was only read.

The request cases are in
[scripts/tests/test_waf_engines.py](../../../scripts/tests/test_waf_engines.py)
and [scripts/tests/waf/](../../../scripts/tests/waf/irule_cases.tcl). CI runs
them against both engines on every pull request. Run them yourself before a
deployment, and add a case when you change a rule:

```text
apt-get install apache2 libapache2-mod-security2 nginx libnginx-mod-http-modsecurity modsecurity-crs tcl
python3 -m unittest discover -s scripts/tests -p "test_waf_engines.py" -v
```

The first time these files were executed they were wrong in ways that
reading them had not shown, and the list is worth knowing because the same
traps wait for any rule you add:

- The SecLang file did not load on ModSecurity v2 at all. Apache collapses a
  doubled backslash inside a quoted directive, so a character class holding
  one reached the regex compiler unterminated. Version 3 loaded the same
  text. Write a backslash in a pattern as `\x5c`.
- W-AGT-009 cannot see an XML body on v2 once the XML body processor is
  selected, which the recommended base configuration does. The rule file
  carries a commented v2-only block for it; v3 needs nothing.
- The per-client counters were opened after the tier 1 rules, and a denial
  ends its phase, so a request refused in phase 1 was missing from every
  counter.
- Each counter re-armed its own expiry on every hit, which makes the window
  slide: a counter fed more often than its window never expires, and a busy
  shared address would have crossed any threshold eventually.
- W-AGT-034 counted every 403, including the application's own, and the
  W-AGT-032 limit refused every request from the address, not only sign-ups.
- Path rules matched the path as sent. `/%61ctuator/env` and `/.%65nv` were
  served on v2 and through the iRule, and `/actuator;x/env`,
  `/actuator/health/..;/env` and `/i4028.php;.jpg` on every platform.
- The iRule skipped any body over 64 KB and every chunked body, read only
  the last of a repeated header, and did not treat `+` as a space.

A second, independent review then ran the corrected file the way its own
header says to deploy it, after the Core Rule Set, and found two more:

- The counters were kept in the `IP` collection. The Core Rule Set opens
  that collection first, keyed on the address and a hash of the User-Agent,
  and on v2 a second `initcol` is ignored: a client that changed its
  User-Agent on every request got fresh counters each time and was never
  boxed. The counters now live in `RESOURCE`, keyed on the address.
- A comment recommended counting Core Rule Set blocks by editing the actions
  of its blocking rule. On libmodsecurity 3 that replaced the rule's deny and
  the Core Rule Set stopped blocking. The recipe is gone; an optional rule
  that reads the score instead is in the file, commented.

Nothing here was found by reading the rules. All of it was found by running
them, and the second batch only by running them beside the software they are
meant to run beside.

## Read this before blocking anything

A WAF signature stops a default or careless deployment, not a determined
operator. Four facts from the reporting set the ceiling:

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
  cannot see that shape. The SIEM rules next door take it in two halves:
  R-B-AGT-002 alerts on evenly spaced requests, which is a throttled agent,
  and R-B-AGT-030 on bursts separated by pauses of constant length.

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
may appear in a rule file. That test compares the files with each other; the
engine tests above are what run them.

## Tier 1: deterministic fingerprints (deny after a log-only week)

| Rule | Matches | Where | Evidence | False-positive risk |
| --- | --- | --- | --- | --- |
| W-AGT-001 | Framework user-agents: `artex-enrich/`, `compatible; ArtEx/`, `infra-hunt/`, `verify-911-probe/`, `spa-api-recon`, `security-testing; authorized`, `recon-audit`, `HexStrike-`, `CyberStrikeAI`, `PentAGI/`, `tcp_beacon`. Also the name `artex`, in any case, as a word (not after a letter; followed by the end, a non-letter, or `probe` or `bot`): the agent makes up a user-agent per task and 44 of the 46 that F5 Labs lists carry the name | User-Agent header | Framework source code; WorkOS 2026-11-06; Unit 42 2026-10-30; Wiz 2026-10-22; F5 Labs 2026-11-23 (appendix) | Low. An authorized tester running a default build will be blocked too; that is a finding, not a false positive. The name rule is the exception: medium. It does not match SmartExchange or ArtExpo, but any product whose name is exactly that word would be refused, and six refusals box the address. Akamai's wildcard version cannot say what may follow the name, so it ships as a separate alert rule (W-AGT-001b). F5's caveat: the agent changes the header when blocked. |
| W-AGT-002 | `CyberStrikeAI-WebShell` user-agent | User-Agent header | CyberStrikeAI source (web-shell manager) | None, and blocking is not enough: this is someone driving a shell they believe is on your server. Investigate the requested path. |
| W-AGT-003 | `norma/0.`, and any user-agent that begins `norma/` (a separate anchored match: Microsoft lists it as `norma/*`); `Fuzz Faster U Fool`, `PentAGI-Installer`; `ReconProbe/` (low confidence and hunt only in the IOC file, so logged, not denied); and user-agents that declare themselves authorized, read-only or pentest: `pentest-probe`, `authorized-pentest`, `authorized-security-research`, `research-readonly`, `research; read-only`, `read-only-audit` | User-Agent header | Nextron (Norma is not ARTEX-exclusive); Microsoft 2026-11-25; Unit 42; Wiz 2026-10-22 (ReconProbe); Bitrise and Barracuda incidents as compiled in Wiz's Black October indicator list | High if denied. Log only. A real authorized tester sends the self-declared strings too, which is why they are logged; an attacker can write them as easily. Wiz (2026-11-23) also names a family of `pentest-recon` user-agents but prints no full string, so nothing here matches it. |
| W-AGT-004 | Canary probes `/zzz-nonexistent-xyz123`, and the same word with an underscore (`zzz_nonexistent_abc.txt`, Datadog), `/zzzrandom12345`; `artex-probe-<number>` files and `ArtexProbe` account names (GTIG); the SSRF canary path `_i<2 to 7 digits>_probe_missing` (`/_i6084_probe_missing`, Bitrise); canary identities `zz_no_such_user_9f3a`, `zzq.nonexistent9x7`, `precheck.not-a-user@example.invalid`; any address at `example.invalid`; OAuth `state=notvalidb64`; cloud metadata address in a parameter | Path, query, body | Wiz 2026-10-22; Unit 42 2026-10-30; S-RM 2026-11-04; CrowdStrike 2026-10-29; Datadog 2026-11-09; Bitrise incident as compiled in Wiz's Black October indicator list | Low. `.invalid` is a reserved top-level domain that can never receive mail. Matched as prefixes, so a changed suffix still hits. Left out on purpose, because they are too ordinary to deny on: `Notexist-xyz` and `/nope-1774` (Datadog, Bitrise), `evil.com` and `test@example.com` (every tester and tutorial sends them), and Unit 42's placeholder `deadbeefdeadbeefdeadbeef12`, which is a hunt in the IOC file. |
| W-AGT-005 | JWT whose header is `alg` `none` (base64 prefix `eyJhbGciOiJub25l` and casings) | Authorization, cookies, URL | Wiz 2026-10-22 | None. No working deployment issues unsigned tokens. |
| W-AGT-006 | SQL injection strings tagged `ARTEX'` | Query, body | S-RM 2026-11-04 | Low. |
| W-AGT-007 | Probe-account identity `i<intent>probe<unix-time>@`, the intent counter two to seven digits | Sign-up, login and recovery bodies | Okta 2026-11-06; Wiz 2026-11-25 (the counter runs from `i49` to `i808807`) | Low. The looser shapes in the reporting (`pentest-probe-...`, `i3694canary`) carry no timestamp and are left to the hunts. |
| W-AGT-008 | Script named like an agent task artifact, `i<3 to 7 digits>.<asp, aspx, jsp, php ...>`, requested or uploaded, including with path info or a `;parameter` after the name | Path, upload filename | S-RM 2026-11-04 (`i4028.asp`); Wiz 2026-11-25 (the counter runs from `i49` to `i808807`) | Medium. Single-engagement indicator; check your own file naming first. The rule starts at three digits although Wiz saw two, because a two-digit name such as `i18.php` is far likelier in a real application; that floor is this pack's choice, and the hunts match from two digits. Akamai's wildcard version is looser, so it ships as alert: `?` is any character, so it holds only the first character after the `i` to a digit. Its values before 2026-11-28 (`i???` to `i???????`) matched ordinary names too: `index.php`, `info.php`, `install.php`, `include.php`. The current values still match one ordinary name, `i18n.php` (and `I18n.php`), because the stem `i18n` fits `i1??`: a known false positive, accepted because the Akamai rule only alerts. |
| W-AGT-008 (second shape) | JSP shell named 1-2 letters, 4 digits, optional letter (`cl1217.jsp`, `f1219a.jsp`, `z1219.jsp`) | Path | GTIG 2026-10-30 (MySQL general-log poisoning) | Medium. Not expressible in Akamai's wildcard builder. |
| W-AGT-009 | Inline DTD or entity declaration in an XML body | Body | CrowdStrike 2026-10-29 (unsigned SAML plus XXE to the metadata service) | Low, but partial: a base64 SAML response hides it from the edge, and on ModSecurity v2 the rule needs the v2-only block in the rule file. The real fix is DTD processing off and signature validation on in the service provider. |
| W-AGT-010 | 43 source addresses, including the eight Storm-3358 ARTEX and C2 servers Microsoft published on 2026-11-06 | Client address | `iocs.csv` rows marked block (CrowdStrike, Zscaler, NorForge, Kaspersky, Microsoft and others) | Low today, decaying. The FBI FLASH of 2026-11-13 asks you to vet addresses before blocking because hosting addresses get reassigned. Review on every `iocs.csv` update; expire after 90 days. |
| W-AGT-011 | Shell command syntax in the User-Agent (`$(`, a backtick, `; curl`, a pipe to `sh`) | User-Agent header | Microsoft 2026-11-05 (exploitation by shell commands embedded in a user agent) | None for browsers. |
| W-AGT-012 | Upload filename containing `../`, or named `sitecustomize.py` or `usercustomize.py` | Multipart body | Amazon 2026-11-20: Cairn agents found a path-traversal zero-day in an upload filename parameter in about 11 minutes and wrote a Python auto-import file for a root shell | Low. On Akamai this is left to the managed attack groups. |
| W-AGT-014 | Path traversal in the path or a parameter: `../`, a backslash form, and the encoded forms (`%2e%2e`, `..%2f`, `..%5c`, half-encoded, double-encoded and overlong dots), and `..;` in the path (not the query), which Tomcat and Spring resolve as `..` | Path, query, form body | Amazon 2026-11-20: Cairn agents found traversal in an upload endpoint's filename parameter and reached arbitrary file write in about 11 minutes | Low in a path, where a browser resolves dot-segments before sending. Medium in parameters: an application that passes relative paths or redirect targets in a parameter will trip it, so read the log-only week before enforcing. Your managed rule set already covers this class; this keeps it on when that set runs permissively. |
| W-AGT-013 | `isCliRequest` request header | Header | Amazon, November 2026: authentication bypass in the ARTEX playbook against One API family LLM gateways | Log only. Relevant only in front of such a gateway. |

W-AGT-004 matches the metadata address only as written (169.254.169.254 and
the Google name). Other spellings of the same address, the decimal form among
them (`http://2852039166/`), are generic SSRF and are left to the Core Rule
Set and to the application.

The user-agent and probe-string rules deny on values the IOC file does not
mark block. Most it marks alert; some it marks hunt: the W-AGT-004 canaries
`zzz_nonexistent_abc.txt`, `zzzrandom12345`, `zz_no_such_user_9f3a`,
`zzq.nonexistent9x7`, `precheck.not-a-user@example.invalid` and the
`@example.invalid` pattern, and the user-agents `artex-agent` and
`artex-judge-r121`, which the W-AGT-001 name rule refuses. None it marks low
confidence is denied (`ReconProbe/` is logged instead). The judgement is that
no legitimate visitor sends them, and it is this pack's, not a source's.
Addresses are different. An address is
denied only where the IOC file marks it block, and 21 of the 43 are also on
the FBI's list, which asks for vetting first; nine of those the FBI labels
proxy addresses. Treat W-AGT-010 as the rule most likely to age badly.

Deliberately **not** blocked, because the IOC file says so and the test
enforces it: LLM API hosts, `webhook.site`, `dnslog.cn`, the `lanmao666`
gateway, the Check Point cluster ranges, the Unit 42 addresses, the addresses
Amazon published from its decoy sensors (Amazon lists them as indicators
and does not say how to use them; leaving them unblocked is this pack's
choice, made because four sit in a range a CDN announces), and the WorkOS researcher's addresses and JA4 fingerprints. The three JA4 values in
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
  `/v2/api-docs`, `/v3/api-docs`, `/runtime-config.json`, Swagger UI
  (`*/swagger-ui*`) and `/swagger-resources` to clients outside your own
  ranges. Shipped disabled or as alert, because some of you publish an API
  specification on purpose. Better still, stop deploying source maps to
  production.
- **W-AGT-021**: refuse secret files to everyone (`*/.env`, `*/.env.*`,
  `*/.git/*`) and management endpoints to clients outside your own ranges
  (`*/actuator/*` for Spring Boot Actuator, `*/debug/pprof*` for Go). On by
  default, unlike W-AGT-020, because nothing public should depend on these.
  `/actuator/health` is exempt so an external load balancer or uptime monitor
  keeps working; `/actuator/env`, `/actuator/heapdump` and the rest are not.
  The exemption is deliberately narrow, plain path segments only (on Akamai,
  a list: `health`, `health/liveness`, `health/readiness`), because
  `/actuator/health/..;/env` is `/actuator/env` to Tomcat and Spring, and it
  must be the first `/actuator` in the path, because
  `/actuator/jolokia/exec/x/actuator/health` is not the health endpoint
  (W-AGT-021c on Akamai). The rules decode the path and treat `;` as a
  boundary for the same reason.
  Evidence, stated plainly: Amazon reports ARTEX agents harvesting secrets
  from "debug routes, and environment files", and Unit 42 reports them
  fetching API documentation pages. No report read for this pack names
  Actuator, pprof or Swagger UI specifically; those paths are the framework
  defaults for that class, chosen by the maintainer. Set the internal ranges
  (`agt_internal_nets`, or the address list in the other two files) to your
  own before relying on the exemption.
- Put non-production hosts (UAT, staging, test) behind an allowlist or
  identity-aware proxy. CERT-In names exposed non-production environments as
  the entry point, with shared credentials carrying the agent into production.
- Enforce a positive security model on APIs where the platform supports it
  (F5 Advanced WAF with an imported OpenAPI file, Akamai API request
  constraints): reject undeclared routes, methods and parameters.
- Admin and management paths: deny from the internet outright rather than
  rate limiting them. The FBI FLASH names Kudu/SCM publishing endpoints,
  hypervisors and backup platforms specifically.
- **Inventory the peripheral applications.** The FBI puts the weight here,
  and so, going by search summaries of a 2026-10-23 post that was not read in
  full, does Akamai: partner and supplier portals, mobile backends,
  employee and sales-support applications, legacy services and third-party
  integrations get less attention than the flagship site and are what the
  agents find. A rule pack attached only to the main virtual server or
  property protects the wrong thing.
- **LLM gateways and AI application builders are targets in their own right.**
  Amazon saw an ARTEX campaign harvest provider keys from exposed One API,
  New API, LiteLLM, Dify, Langflow, RAGFlow and Open WebUI installs through
  unclaimed setup pages, anonymous management endpoints and default master
  keys. Keep their management interfaces off the internet. Akamai's guidance,
  again known here only from search summaries, is to put a WAF or AI gateway
  in front of model and MCP endpoints and rate limit by identity and cost.
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
| W-AGT-032 | Self-registration rate: further sign-up posts are refused, the client's other requests are not. Pair it with refusal of disposable mail domains and of shared-mailbox prefixes at your own domain (`admin@`, `billing@`, `security@` ...), which no file here implements | More than 3 sign-ups an hour per client | Okta 2026-11-06; Expel 2026-10-21 |
| W-AGT-033 | OAuth authorize and token endpoints: rate the error responses | More than 3 a second burst | Unit 42 and Okta: unregistered redirect URIs tried across many client IDs |
| W-AGT-034 | Repeat violator: a client that keeps drawing WAF denials is probing the ruleset, so escalate from challenge to block. Counts the WAF's own denials, not the application's 403s | More than 5 denials in 2 minutes, then a 30-minute penalty | F5 Labs 2026-11-23: very rapid probing "is a strong signal", and stronger when the probing adapts to the previous response |

The windows are fixed: a counter starts when its first event arrives and is
cleared when it trips or its window ends. The SecLang counters are keyed on
the client address alone, so everyone behind one NAT address shares them;
that is the reason for the thresholds above being loose and for the next
note. Three things about where those counters live:

- They are in ModSecurity's `RESOURCE` collection, not `IP`, so that the
  Core Rule Set's own use of `IP` (keyed on address and User-Agent) cannot
  split them.
- On nginx they are held in each worker process's memory. With more than one
  worker a client is counted separately by each, so a threshold is reached
  later than written and a boxed client is refused only by the workers that
  boxed it. A review run with four workers left 44 of 100 six-denial
  sequences unboxed. On Apache the counters are shared through `SecDataDir`.
- On Apache a penalty lasts no longer than `SecCollectionTimeout`. The Core
  Rule Set's setup file sets that to 600 seconds, which cuts the 30-minute
  penalty of W-AGT-034 and the 15-minute one of W-AGT-031 to ten. Set it to
  1800 after that include if you want the penalties as written. On nginx the
  directive made no difference.

Tier 3 needs libmodsecurity 3.0.11 or later for `expirevar`; it was run on
3.0.12.

On Akamai the table's low thresholds cannot be written. A rate policy counts
hits per second and the lowest value is 1, about 120 requests in two
minutes, so the W-AGT-031 and W-AGT-032 policies in the JSON catch only the
machine-speed end of those behaviours.

Platform notes:

- **Key the counters on more than the address.** Use a TLS fingerprint,
  session cookie or device identifier where the platform has one, because the
  spraying is spread over residential proxy pools precisely to stay under
  per-address limits. F5 (2026-11-13) cites an analysis of an exposed
  attacker server, without saying whose, in which one proxy service handed
  out 79 exit addresses for the first 100 identities tested.
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
  four, in its lab, against a deliberately vulnerable application, with no
  published method; F5 adds that the results are specific to that
  configuration. It is the only measured result for any edge control in the
  reporting read for this pack, and it is the vendor's own.
- **Akamai**: the rate policies in the JSON cover W-AGT-030 to W-AGT-033 and
  count per address and TLS fingerprint, at the per-second floor described
  above; use Account Protector or Bot Manager for the slow end. For
  W-AGT-034 turn on the security policy's penalty box. Search summaries of
  Akamai's posts, which were not read in full, describe AI-powered WAF
  detections in its Adaptive Security Engine (announced 2026-08-13,
  manageable by API), with a request whose User-Agent contains
  `PentestAgent` as the example. Keep the managed attack groups in deny: W-AGT-009 and
  W-AGT-012 rely on them here, and W-AGT-014 is only a second line behind
  the local-file-inclusion group.
  Pair the rate policies with Bot Manager on the same endpoints, and add a
  Client Reputation deny for the web-scanner and web-attacker categories at
  high scores.
- **Step up, do not only block.** A challenge on sign-up and recovery costs a
  person a few seconds and costs an agent its unattended loop.

## What the edge cannot do

Pair these rules with the detections in this folder rather than treating
either as complete:

- A steady request timer, the burst-and-pause cadence Unit 42 describes, and
  spec-driven API targeting: R-B-AGT-002, R-B-AGT-030 and R-D-AGT-017.
- A client walking consecutive record identifiers: R-D-AGT-029.
- What happens after access: in the cloud control plane, R-D-AGT-021 to
  R-D-AGT-023; in the domain, R-D-AGT-024 and R-D-AGT-027; on the host,
  R-D-AGT-025 and R-D-AGT-026.
- Credential guessing at volume against services a WAF does not front (SSH,
  VPN): R-D-AGT-028.
- A canary username followed by an admin login, failed or successful:
  R-D-AGT-018.
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
"F5 Labs" above means the research article of 2026-11-23; the lab figures
come from the F5 company blog post of 2026-11-13, which is a product post.

Not read, and so not relied on for any rule: Akamai's blog posts (the site
refuses automated clients, so only search summaries were seen, and each use
above says so), Sophos, CERT-EU and the Cloud Security Alliance notes.
Unit 42's CL-STA-1238 report was read on 2026-11-27; its two addresses are in
`iocs.csv` as alert, not block, so no WAF rule denies them.
