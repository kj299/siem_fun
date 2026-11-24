# WAF filtering rules for agentic attack frameworks

Edge rules for F5 BIG-IP, Akamai App and API Protector, and anything that reads
ModSecurity SecLang, built from the indicators in [../iocs.csv](../iocs.csv)
and the reporting summarised in
[agentic-ai-attacks.md](../../../splunk-sentinel-query-builder/references/agentic-ai-attacks.md)
(intelligence as of 2026-11-07). They target ARTEX and CAIRN first, and the
other four frameworks that document covers where they leave an edge-visible
fingerprint.

**Status: `needs_validation`.** The patterns were exercised offline against
the indicator values; no file here has been loaded on a live device. The
Akamai JSON is additionally an unverified schema, written without access to
Akamai's documentation. Deploy every rule in log or alert mode first.

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
| W-AGT-004 | Canary probes `/zzz-nonexistent-xyz123`, `/zzzrandom12345`; canary identities `zz_no_such_user_9f3a`, `zzq.nonexistent9x7`, `precheck.not-a-user@example.invalid`; any address at `example.invalid`; OAuth `state=notvalidb64`; cloud metadata address in a parameter | Path, query, body | Wiz 2026-10-22; Unit 42 2026-10-30; S-RM 2026-11-04; CrowdStrike 2026-10-29 | Low. `.invalid` is a reserved top-level domain that can never receive mail. Matched as prefixes, so a changed suffix still hits. |
| W-AGT-005 | JWT whose header is `alg` `none` (base64 prefix `eyJhbGciOiJub25l` and casings) | Authorization, cookies, URL | Wiz 2026-10-22 | None. No working deployment issues unsigned tokens. |
| W-AGT-006 | SQL injection strings tagged `ARTEX'` | Query, body | S-RM 2026-11-04 | Low. |
| W-AGT-007 | Probe-account identity `i<intent>probe<unix-time>@` | Sign-up, login and recovery bodies | Okta 2026-11-06 | Low. |
| W-AGT-008 | Script named like an agent task artifact, `i<3 to 5 digits>.<asp, aspx, jsp, php ...>`, requested or uploaded | Path, upload filename | S-RM 2026-11-04 (`i4028.asp`) | Medium. Single-engagement indicator; check your own file naming first. Akamai's wildcard version is looser, so it ships as alert. |
| W-AGT-009 | Inline DTD or entity declaration in an XML body | Body | CrowdStrike 2026-10-29 (unsigned SAML plus XXE to the metadata service) | Low, but partial: a base64 SAML response hides it from the edge. The real fix is DTD processing off and signature validation on in the service provider. |
| W-AGT-010 | 36 source addresses | Client address | `iocs.csv` rows marked block (CrowdStrike, Zscaler, NorForge, Kaspersky and others) | Low today, decaying. Review on every `iocs.csv` update; expire after 90 days. |

Deliberately **not** blocked, because the IOC file says so and the test
enforces it: LLM API hosts, `webhook.site`, `dnslog.cn`, the `lanmao666`
gateway, the Check Point cluster ranges, the Unit 42 addresses, and the WorkOS
researcher's addresses and JA4 fingerprints. The three JA4 values in
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
  rate limiting them.

## Tier 3: tempo and abuse controls (the durable part)

Thresholds below are starting points. Derive your own from a baseline week;
the SIEM rules in this folder do the same.

| Rule | Control | Starting threshold | Evidence |
| --- | --- | --- | --- |
| W-AGT-030 | Error-rate enumeration: count 400, 401, 403, 404 and 405 responses per client | More than 30 in 60 seconds, then a 10-minute penalty | Wiz: more than 60 SSO route variants per target; R-D-AGT-001 alerts at 200 distinct paths in 10 minutes |
| W-AGT-031 | Source-centric login failures, across any number of usernames | More than 10 in 5 minutes | Microsoft: 151,000 failures against 327 accounts, peaking at 2,900 a minute |
| W-AGT-032 | Self-registration rate, plus refusal of disposable mail domains and of shared-mailbox prefixes at your own domain (`admin@`, `billing@`, `security@` ...) | More than 3 sign-ups an hour per client | Okta 2026-11-06; Expel 2026-10-21 |
| W-AGT-033 | OAuth authorize and token endpoints: rate the error responses | More than 3 a second burst | Unit 42 and Okta: unregistered redirect URIs tried across many client IDs |

Platform notes:

- **Key the counters on more than the address.** Use address plus user-agent
  at minimum, and a TLS fingerprint or device identifier where the platform
  has one, because the spraying is spread over residential proxy pools
  precisely to stay under per-address limits.
- **F5**: the iRule carries no counters on purpose. Use Advanced WAF
  brute-force protection with source-based and distributed-attack detection
  for W-AGT-031, session tracking with violation thresholds for W-AGT-030,
  and Bot Defense (browser verification, device ID) on login, sign-up and
  recovery URLs.
- **Akamai**: the rate policies in the JSON cover W-AGT-030 to W-AGT-033.
  Pair them with Bot Manager on the same endpoints, and add a Client
  Reputation deny for the web-scanner and web-attacker categories at high
  scores.
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
