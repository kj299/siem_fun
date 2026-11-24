# Splunk + Microsoft Sentinel Query Skill Plan

**Status: every phase below has shipped.** This file is kept as the design
record -- the reasoning behind what was built, in the order it was decided --
rather than as a roadmap. For what the pack does today, read
[README.md](README.md); for the rules that keep it correct, read
[CLAUDE.md](CLAUDE.md). What the model runs found, what checking the
catalogues against the vendors found, and the one decision still open, are at
the end.

## Goal

Create a reusable skill, for both Claude and Codex, that can:

- understand a target SIEM environment before writing queries
- generate and optimize Splunk SPL and Microsoft Sentinel KQL
- translate common hunts and detections between SPL and KQL
- explain performance tradeoffs, parsing strategy, and field assumptions
- consume an internal URL that documents indexes, tables, and field definitions
- stay concise and predictable for Claude Opus 4.6 and Codex GPT-5.4
- express clear trigger boundaries, examples, and troubleshooting via progressive disclosure
- generate Splunk data dictionaries from accessible indexes, sourcetypes, and sampled fields
- align Splunk guidance with the Common Information Model so multi-vendor sources are queried through shared data models (vendors and coverage depth listed in the README and cim-vendor-alignment.md)

## Why this plan

The referenced material points to the right foundations:

- Splunk search pipelines are built from indexed search terms followed by pipe-based transforming commands, and Splunk emphasizes reducing data scanned early by narrowing index and time first.
- The Splunk search tutorial is organized around learning the Search app, loading known data, searching, enriching with lookups, then producing reports and dashboards.
- Microsoft Sentinel documentation centers on onboarding data, connectors, normalization and parsing, running KQL, analytics rules, and threat hunting.

That means the skill should not start from syntax alone. It should start from environment discovery, then schema mapping, then optimized query construction.

## Coding plan

### Phase 0: Token optimization

Keep the main `SKILL.md` short and procedural.

- move detail into references
- avoid duplicate instructions across files
- keep the default output shape fixed
- optimize for "query first" answers rather than tutorial prose
- prefer explicit skill invocation when the client supports it
- keep examples and troubleshooting in references instead of bloating the top-level skill

### Phase 1: Environment discovery contract

Build the skill around a required discovery pass before writing production queries.

Outputs the skill should ask for or infer:

- platform: `splunk`, `sentinel`, or `both`
- use case: hunt, detection, dashboard, triage, metrics, or parsing
- time window and expected result grain
- internal data-dictionary URL when one exists
- data source names
- index names and sourcetypes for Splunk
- tables, connectors, and normalized schemas for Sentinel
- high-value fields: user, host, src, dest, ip, process, hash, url, action, result
- constraints: latency, cost, volume, real-time vs historical

The top-level skill should also make these boundaries explicit:

- what the skill does
- when it should trigger
- when it should not trigger

### Phase 2: Query generation workflow

Teach the skill to build queries in this order:

1. Define the analyst question in plain English.
2. Pull schema facts from the internal data dictionary when available.
3. Pick the narrowest data scope.
4. Filter as early as possible.
5. Parse only the fields needed.
6. Aggregate late and only when required.
7. Return a readable output table with clear aliases.
8. Add notes about assumptions, false positives, and tuning knobs.

### Phase 3: Cross-platform mapping

Create a reference mapping for common equivalents:

- Splunk `index`, `sourcetype`, `source`, `host`
- Sentinel `table`, `TimeGenerated`, connector-specific schemas, normalized tables
- Splunk `stats`, `timechart`, `rex`, `eval`, `lookup`, `transaction`, `where`
- Sentinel `summarize`, `bin()`, `extract()`, `extend`, `lookup/join`, sessionization patterns, `where`

This lets the skill translate intent instead of producing one-off syntax conversions.

### Phase 3a: Internal dictionary ingestion

Teach the skill to treat internal documentation URLs as first-class schema inputs.

The skill should know how to consume:

- internal wiki pages that document Splunk indexes
- SharePoint or portal pages that describe Sentinel tables and connectors
- internal runbooks listing canonical field names and aliases
- parser notes that explain field availability, latency, or deprecation

When the URL cannot be opened directly, the skill should fall back gracefully by requesting a pasted excerpt or by producing a schema discovery query.

### Phase 4: Optimization guidance

Add explicit optimization rules.

For Splunk:

- prefer tight `index=`, `sourcetype=`, and time bounds first
- avoid leading wildcards where possible
- favor fielded searches over raw text scans
- keep expensive extraction and regex after initial filters
- use `table` or `fields` to reduce payload near the end

For Sentinel:

- scope with `where TimeGenerated` first
- filter table rows before `parse`, `extend`, `mv-expand`, or joins
- project only needed columns
- prefer summarized datasets over wide raw result sets
- use joins carefully and keep the smaller side constrained

### Phase 5: Detection-ready outputs

Teach the skill to emit one of the five answer shapes SKILL.md declares
(`query`, `detection`, `translation`, `optimization`, `discovery`):

- `query`: quick hunt, triage, or dashboard-panel query
- `detection`: query plus threshold and tuning notes
- `translation`: SPL to KQL or KQL to SPL
- `optimization`: rewritten query plus what changed and why it is cheaper
- `discovery`: checklist plus starter query when the schema is missing

`discovery` is not optional garnish: Phase 1 above builds the whole skill around
a discovery pass before any production query, so a list that omits it
contradicts the phase it depends on.

### Phase 6: Validation checklist

Each final query should be checked for:

- correct platform syntax
- environment-specific schema assumptions
- field existence assumptions
- performance risks
- expected output columns
- easy tuning points for analysts

## Recommended file layout

```text
siem_fun/
|-- .claude/
|   `-- settings.json
|-- .env.example
|-- .github/
|   `-- workflows/
|       `-- validate.yml
|-- .gitignore
|-- examples/
|   |-- agentic-ai-attacks/
|   |   |-- lookups/
|   |   |   |-- README.md
|   |   |   |-- agt_asset_ip.csv
|   |   |   |-- agt_host_history.csv
|   |   |   |-- agt_host_llm_seen.csv
|   |   |   |-- agt_host_roles.csv
|   |   |   |-- agt_iocs.csv
|   |   |   |-- agt_scheduled_clients.csv
|   |   |   |-- agt_sp_change_actors.csv
|   |   |   |-- agt_web_proc_pairs.csv
|   |   |   |-- llm_api_domains.csv
|   |   |   `-- sentinel_watchlist.csv
|   |   |-- attack-navigator-layer.json
|   |   |-- hunting.kql
|   |   |-- iocs.csv
|   |   |-- sentinel-rules.yaml
|   |   |-- splunk-morpheus-native.conf
|   |   |-- splunk-savedsearches.conf
|   |   `-- waf/
|   |       |-- README.md
|   |       |-- akamai-custom-rules.json
|   |       |-- blocklist-ipv4.txt
|   |       |-- f5-data-groups.tmsh
|   |       |-- f5-irule-agentic.tcl
|   |       |-- modsecurity-agentic.conf
|   |       |-- ua-alert.txt
|   |       `-- ua-block.txt
|   |-- golden-prompts.md
|   `-- golden-run.json
|-- CLAUDE.md
|-- QUERY_SKILL_PLAN.md
|-- README.md
|-- scripts/
|   |-- tests/
|   |   |-- mutation-check.py
|   |   |-- shared-rule-cases.json
|   |   |-- test_agentic_ai_attacks.py
|   |   |-- test_grade_golden_output.py
|   |   |-- test_record_golden_run.py
|   |   `-- validate-skill-pack.tests.ps1
|   |-- grade_golden_output.py
|   |-- record_golden_run.py
|   |-- required-checks.txt
|   |-- run_golden_prompts.py
|   `-- validate-skill-pack.ps1
|-- splunk-data-dictionary-builder/
|   |-- agents/
|   |   |-- claude-opus.yaml
|   |   |-- codex-gpt-5.4.yaml
|   |   `-- openai.yaml
|   |-- references/
|   |   `-- workflow.md
|   |-- scripts/
|   |   `-- build_splunk_dictionary.py
|   |-- tests/
|   |   `-- test_build_splunk_dictionary.py
|   `-- SKILL.md
|-- splunk-enrichment-query-builder/
|   |-- agents/
|   |   |-- claude-opus.yaml
|   |   |-- codex-gpt-5.4.yaml
|   |   `-- openai.yaml
|   |-- references/
|   |   |-- greynoise-integration.md
|   |   |-- multi-index-patterns.md
|   |   |-- splunk-cloud-index-management.md
|   |   `-- splunkbase-app-catalog.md
|   `-- SKILL.md
`-- splunk-sentinel-query-builder/
    |-- agents/
    |   |-- claude-opus.yaml
    |   |-- codex-gpt-5.4.yaml
    |   `-- openai.yaml
    |-- SKILL.md
    `-- references/
        |-- agentic-ai-attacks.md
        |-- cim-vendor-alignment.md
        |-- data-dictionary-integration.md
        |-- examples-and-troubleshooting.md
        |-- model-guidance.md
        |-- query-workflow.md
        |-- sentinel-table-catalog.md
        `-- splunk-to-kql-mapping.md
```

## What was built beyond this plan

The phases above describe the skills. What they do not describe, because it
was not foreseen, is the verification layer that now makes up roughly half the
repository: a validator that checks every sourcetype written in query position,
every colon-delimited sourcetype named in prose, and every Sentinel table in
the documents against a cited catalogue, lints SPL for the silent-failure patterns,
and enforces parity across the helper files; a mutation harness that breaks
each of those checks on purpose and asserts it fires; and a check inventory
that makes deleting a check a build failure. That layer exists because the
documents are read by a model at query time, so a factual error in them is a
wrong query with no error message. README.md explains what it enforces;
CLAUDE.md explains what it deliberately does not.

## What the first model run found

The last open item was executing the fixtures in
[examples/golden-prompts.md](examples/golden-prompts.md) against a model and
grading the output: the only way to find guidance that is accurate and
consistent and still produces a poor query. That now has tooling. Each fixture
carries a grader spec next to its prose bullets;
[scripts/grade_golden_output.py](scripts/grade_golden_output.py) grades an
answer against the spec and against the rules the validator applies to the
documents; [scripts/run_golden_prompts.py](scripts/run_golden_prompts.py)
drives a model through all ten with the skill loaded exactly as a client would
load it. The grader's checks are mutation-tested like the validator's.

First run, 2026-09-02, on Claude Opus (the session's `opus` alias) with each
fixture executed by an agent given SKILL.md and the references the way the
runner hands them over. Result after correction: 10 of 10.

- **One fixture was wrong, no skill was.** Fixture 8 asserted
  `index IN (firewall, proxy)`. The skill says to filter per index when the
  sourcetypes' schemas differ, the two supplied ones do, and the model did
  exactly that, explaining why in Assumptions. The fixture failed a correct
  answer. It now accepts either documented shape and forbids only the bare
  `OR` chain. Neither the validator nor a careful read could have found this:
  the fixture and the skill are each internally consistent.
- **Four grader rules were too strict for real answers**, each corrected and
  now unit-tested: a discovery answer offering three starter queries was
  graded on the first fence only; a translation answer echoing the source SPL
  under Query tripped a rule about the target KQL; a `getschema` block was
  held to the `TimeGenerated` rule; and "I will never ask you to type a
  token" tripped the credential-request check.
- **Every answer** bounded time first, named its assumptions, switched to
  discovery when the dataset was unknown, used only supplied or catalogued
  identifiers, and never asked for a credential. Answer 10's claims about the
  dictionary builder's flags and environment-variable defaults were checked
  against the script and are true.

## What the second model run found

Second run, 2026-09-04, same method: each fixture executed by an agent handed
`SKILL.md` and every file under `references/` exactly as
[scripts/run_golden_prompts.py](scripts/run_golden_prompts.py) assembles them,
then graded by [scripts/grade_golden_output.py](scripts/grade_golden_output.py).
Result after correction: 10 of 10.

- **A second fixture contradicted the skill, and again no skill was wrong.**
  Fixture 4 asks for a Sentinel hunt when the table is unknown. Its spec
  required the answer to contain a `union` wildcard. But query-workflow.md
  tells the model to use `union *` *sparingly* and to prefer `Usage` for pure
  enumeration, which is exactly what this prompt is. The answer used `Usage`
  and `getschema`, named the candidate tables, and never proposed a union, so
  it had nothing to warn about. The spec failed it for following the skill.
  Note that the fixture's own prose bullet said the answer "warns against
  broad `union *`" -- the spec had turned a warning into a requirement, and
  the two sat next to each other unread. The union match is gone; `Usage`,
  `getschema` and the table allowlist still pin the shape.
- **Same root cause as run 1's fixture 8**, one run apart: a fixture and a
  skill that are each internally consistent and disagree with each other.
  Nothing but a model run finds these. Two of ten fixtures have now been
  wrong; the skills have been right both times.
- **The other nine passed unchanged**, including every generic rule: time
  bounded first, assumptions named, discovery returned rather than a guessed
  production query, only supplied or catalogued identifiers, and no request
  for a credential.

## What the third model run found

Third run, 2026-09-05, same method as the first two, executed to give the new
freshness marker a real result to record rather than a placeholder. 10 of 10
with no correction needed: the first run in which neither a fixture nor a
skill was wrong. The marker in [examples/golden-run.json](examples/golden-run.json)
records the content this run saw; the validator will name whichever of those
files changes next.

## What the fourth and fifth model runs found

Fourth run, 2026-09-05, against the content the catalogue-citation work
(PR #47) had just merged: 9 of 10. Fixture 9 failed a correct answer. The
prompt gives "Time range: last 7d", the answer bounded the discovery pass with
`earliest=-7d`, and the fixture's regular expression demanded the bare shape
`SKILL.md` prints, with nothing between the index list and `by`. Reading the
skill first, as the rule in CLAUDE.md says to, showed the skill neither
requires nor forbids the bound; the fixture was over-specified, so its regular
expression now tolerates an `earliest=` or `latest=` term.

Fifth run, same day and same method, re-ran only the two enrichment fixtures,
because the correction below changed splunkbase-app-catalog.md and left every
other fixture's prompt bytes identical to the fourth run's. It failed fixture 8
for the same reason in a different place: the answer wrote
`(index=firewall sourcetype=cisco:asa action=permitted) OR (index=proxy ...)`
and the fixture's alternative shape closed the parenthesis right after the
sourcetype, so a per-index filter term -- the whole point of the per-index
shape -- failed it. The expression now allows further terms inside each group.

A sixth run, two fixtures again, followed a further prose edit to the same
catalogue section so the recorded marker would match the tree that shipped:
10 of 10, no correction.

Two fixture defects in the first three runs, two more here, and still no
skill defect found by a run. The pattern is consistent enough to state plainly:
these fixtures fail by pinning one string where the skill licenses a family, so
read the skill before touching the answer. Both corrections are fixture-side;
neither skill changed, and the marker in
[examples/golden-run.json](examples/golden-run.json) now records 10 of 10
against this tree.

## What checking the catalogues against the vendors found

The validator checks the documents against the catalogues. Nothing checked the
catalogues against the vendors, so a sourcetype or table that was renamed,
deprecated or never existed would pass every run. First pass, 2026-09-04.

- **All 20 Sentinel tables verified** against the Microsoft page each row
  cites. Every name exists with the exact casing the catalogue uses, every
  cited page still resolves, and the anchors still name a real heading. The
  descriptive claims hold too: `Usage` really does carry `DataType`,
  `Quantity` in Mbytes, `IsBillable` and `Solution`, and the `Operation` row's
  data-allowance records are documented on the page cited, with a sample
  query. Nothing needed correcting.
- **11 of the 67 Splunk sourcetypes spot-checked**, chosen as the likeliest to
  have drifted: the CrowdStrike, Carbon Black, Defender, Zscaler NSS, Okta,
  Qualys and Microsoft Cloud Services names. All are current, including the
  awkward ones (`qualys:hostDetection` really is camel-cased, and the Carbon
  Black caveat about `vmware:cb:edr:json` is right). The other 56 are unread.
- **The two catalogues are asymmetric, and only one says so.** Every Sentinel
  row cites Microsoft per table, and the file requires a citation before a
  table may be added. The Splunkbase catalogue carries no per-row citation at
  all, so re-verifying it means finding the vendor documentation again from
  scratch each time. Adding a Reference column to it is the obvious fix and is
  a larger content change than this pass took on.
- The Okta rows list `OktaIM2:log` only; the add-on also ships `OktaIM2:user`,
  `:group`, `:app`, `:groupUser` and `:appUser`. Not an error, an omission.

Direct fetches of vendor documentation were blocked by that environment's
network policy, so the Splunk half was checked through search rather than by
reading the pages. That is weaker evidence than the Sentinel half, where
Microsoft's documentation was read directly.

### Second pass, 2026-09-05: every Splunk sourcetype read on a page

Run from an environment with open outbound access, so every citation below
was read from the page itself rather than from a search snippet. The two
environments are the whole reason there were two passes: the first could
reach Microsoft's documentation and nothing of Splunk's or the vendors', so
it verified the Sentinel catalogue at page-read quality and the Splunkbase
catalogue only by search. Two Splunk hosts still refused this pass:
docs.splunk.com returns a 403 from its load balancer to non-browser clients,
and help.splunk.com's per-add-on pages are landing pages that link back to
docs.splunk.com. The four names that live only on docs.splunk.com (Squid,
Blue Coat, Carbon Black EDR, the retired NetFlow add-on) were read from the
Internet Archive's copy of the docs.splunk.com page and cite the
docs.splunk.com URL.

Method: extract the sourcetypes the way the validator does (every backticked
name in the column headed `Sourcetype`, 67 names), find a page that names
each one, read it, and record the URL in a new `Reference` column, last in
every catalogue table. Preference order, strongest first: the add-on's own
sourcetype page (splunk.github.io, help.splunk.com, docs.splunk.com, or the
vendor's own documentation for a vendor-published add-on); a Splunk
repository that defines the sourcetype (Splunk Connect for Syslog vendor
pages, the Threat Research data-source objects, an add-on's `props.conf`);
a Splunkbase listing or Splunk blog; nothing.

| Evidence tier | Sourcetypes | Names |
| --- | --- | --- |
| Add-on or vendor documentation | 55 | the Windows (4, the two Perfmon names included), Sysmon, CrowdStrike FDR, Microsoft Security, Palo Alto, Cisco ASA, Cisco ISE, Check Point, Juniper, F5, Okta, Infoblox, AWS, Microsoft Cloud Services (2 of 3), Google Cloud families; Carbon Black EDR and Cloud; eStreamer; Umbrella; Zscaler; Blue Coat; Cloudflare; Akamai; Squid; Tenable; Qualys; NetFlow; Stream; the legacy Sysmon channel-path sourcetype (a help.splunk.com tutorial filters on it) |
| Splunk repository defining the sourcetype | 8 | `fgt_traffic`, `fgt_utm`, `fgt_event`, `imperva:waf` (SC4S); `CrowdStrike:Event:Streams:JSON` (Threat Research data source); `azure:aad:signin`, `azure:aad:audit` (TA-MS-AAD `props.conf`); the `Perfmon:*` wildcard, which no page writes as such and the Windows page's individual Perfmon names back |
| Splunkbase listing or Splunk blog | 3 | `proofpoint_tap_siem` and `pps_messagelog` (named only by a third-party CIM extension's listing; Proofpoint's own documentation is behind a login and the add-ons' listings describe the logs without naming them); `mscs:nsg:flow` (a Splunk blog; the add-on's source type page does not list it) |
| Unconfirmed | 1 | `duo`: Duo's connector documentation and release notes, the Splunkbase listing and its release API, Duo's GitHub, and Splunk Lantern were read and none names the connector's sourcetype. Left in place with its Reference cell marked `unconfirmed`. |

Corrections made, each with the evidence in the row:

- **`pps_messagelog` was filed under the wrong add-on.** The catalogue listed
  it as the Proofpoint Protection Server sourcetype. SC4S's Proofpoint page
  names the PPS add-on's sourcetypes as `pps_filter_log` and `pps_mail_log`;
  `pps_messagelog` (with `pps_maillog`) belongs to the Proofpoint On Demand
  add-on, which is a different product and a different Splunkbase listing.
  The catalogue now has a PPS table with the two SC4S names and a PoD table
  with `pps_messagelog`; cim-vendor-alignment.md's bullet says PoD too. No
  name was removed, so no existing query breaks.
- **The Okta family was incomplete.** Only `OktaIM2:log` was catalogued; the
  add-on's source type page lists `OktaIM2:user`, `OktaIM2:group`,
  `OktaIM2:app`, `OktaIM2:groupUser` and `OktaIM2:appUser` too, with their
  event types and CIM models. All five are now rows, with the page's own
  caveat that `OktaIM2:app` is "not recommended until really needed".
- **The Duo successor was missing.** The connector's EOL note pointed at
  Cisco Security Cloud without saying what it assigns; the Threat Research
  data sources name `cisco:duo:activity` and `cisco:duo:administrator`, now a
  row next to the unconfirmed `duo`.
- **Two sourcetypes are named by weaker evidence than the row implied.** The
  Sysmon legacy channel-path row is backed by a Splunk tutorial that filters
  on it, not by the add-on (whose page names it as the source, which the row
  already said). The Carbon Black Cloud row cites the Endpoint Standard app's
  own README, and now says that app is unsupported and names its successor.

Nothing else needed correcting: every other name exists with the exact casing
the catalogue uses, on a page that describes the same add-on the catalogue
attributes it to.

The rule is now enforced, not just stated: the catalogue's new "Adding a
sourcetype" paragraph requires a citation or a discovery query, mirroring the
Sentinel catalogue's "Adding a table", and the validator fails any row of a
Sourcetype-headed table in a registry file whose `Reference` cell is empty,
and any such table with no `Reference` column. Both checks have a mutation
and a unit test. The asymmetry the first pass reported is closed.

### Third pass, 2026-09-05: the Proofpoint rows

A review comment on the merged citation work pointed at the two Proofpoint
Protection Server rows, and reading them against Splunk Connect for Syslog's
own vendor page found three things wrong with the surrounding claims rather
than with the names.

- The sourcetypes are right. SC4S's Proofpoint Protection Server page names
  `pps_filter_log` and `pps_mail_log` in its own sourcetype table, under the
  keys `proofpoint_pps_filter` and `proofpoint_pps_sendmail` into an `email`
  index. That page was read again for this pass.
- The add-on attribution was not. The catalogue said the two names come from
  "the Proofpoint Email Security Add-On using Remote Syslog (app 3080)" and
  that it "collects on `pps_log`" -- an add-on number and a third sourcetype
  that no cited page in this repository supports, and SC4S's own page links
  Splunkbase app 4327, the number the catalogue gives the hosted Proofpoint on
  Demand product below. The uncited add-on number and the uncited `pps_log`
  are gone; the section now says what the cited page says and marks the
  listing number as unresolved.
- `pps_maillog` was named in prose, with no `Reference` cell, because prose
  escapes the validator's row check. It is a table row now, carrying the same
  third-party listing and the same caveat as `pps_messagelog`.

`pps_mail_log`'s `Key fields` cell held a prose note instead of fields, so a
reader looking for fields got none; the cell now says the cited page names
none, and SC4S's warning that the name collides with a host's own sendmail
syslog sits in prose under the table where it belongs.

Splunkbase itself is unreachable from the trusted-network environment, so the
two add-on listing numbers stay unverified here; cim-vendor-alignment.md still
names the PPS add-on in prose. Re-checking both is work for the open-network
environment.

## Whether the model half was re-run

Three fixture defects have been found only by a model run, and CI cannot
perform one, so whether the run was repeated after a `SKILL.md` or reference
change was an honour-system rule. It is now a recorded fact:
[examples/golden-run.json](examples/golden-run.json) holds a content hash of
every file the run depends on -- each skill's `SKILL.md`, every markdown file
under its `references/`, and the fixture file -- written by
[scripts/record_golden_run.py](scripts/record_golden_run.py) at the moment of
the run (the API runner records automatically after a full passing run). The
validator compares those hashes to the tree on every run and prints a NOTICE
naming any file changed since. A notice, not a failure, on purpose: the fix is
a model run CI cannot perform, and a check that blocks every content edit
until someone finds a credential gets routed around rather than obeyed.

Hashes are of LF-normalised bytes, because the validator runs on a CRLF
checkout; without that every file would read as changed on the only platform
that runs it.

Two review findings on the shipped version, both about a check that accepted
too much. The recorder wrote a marker for any non-empty `--result`, so a
partial or failing run ("9 of 10", or "2 of 2" from re-running two fixtures)
silenced the notice while the behavioral baseline was unproven -- on exactly
the path a run by subagents has to take, since the API runner guards itself.
It now requires a result naming every fixture, all passing. The validator
accepted any `files` value that existed and was non-null, so valid JSON
carrying an array, a string or a number reached the enumeration and produced a
recorded set nothing could match, downgrading a malformed marker to an
ordinary freshness notice; the value now has to be a map. Both have
mutations.

## Running the model half on a schedule against a credential, 2026-09-16

The weekly Routine (issue #44) runs the model half with subagents, which
needs no secret, and reports only when something fails; what it cannot do is
push the refreshed marker, so a stale NOTICE after a content change still
waited on a person to re-run and record. Adding a repository secret so the
API runner could do both in CI was left as the repository owner's decision,
not this plan's -- and the owner made it: `.github/workflows/validate.yml`
gained a third job, `golden-run`, that runs only on the weekly schedule or a
manual dispatch (never on a pull_request or a push, which hold no credential
and would make a paid model call on every PR). It calls `ANTHROPIC_API_KEY`
from a repository secret, pushes the refreshed marker to `main` itself on a
full pass, and opens an issue naming the failure otherwise, touching nothing.

This is a second path to the same mechanism the Routine already drives, not
a replacement for it: the Routine also runs the validator, both unit suites,
and the mutation harness in one pass, and can be made to open an issue on
any of those once issue #44 is done. `golden-run` only ever exercises the
model half and the marker.

What it actually did, recorded 2026-11-21: the secret was never added, so
every scheduled run from 2026-09-21 on failed in `golden-run`. Failing was
right -- there was nothing to grade. How it failed was wrong. With no
credential the SDK raises `TypeError` while building the request, not the
`AuthenticationError` the runner caught, so the runner died on a traceback and
Python exited 1, which is the code the job reads as a graded fixture failure.
It opened an issue naming a fixture failure every Monday: nine between #53 and
#65, each titled with the `TypeError`, none of which had graded anything. The
runner now treats any exception that escapes it as a setup problem (exit 2),
which fails the job without filing an issue; a REGRESSION test reproduces the
`TypeError`, and a mutation proves the test catches the old behavior. The job
still fails every week until the `ANTHROPIC_API_KEY` secret exists.

## Agentic AI attack frameworks, 2026-11

PRs #60 to #63 added
[references/agentic-ai-attacks.md](splunk-sentinel-query-builder/references/agentic-ai-attacks.md),
which the query builder loads when a request names one of the six frameworks
it covers or asks for detections of machine-speed intrusions, and its assets
under [examples/agentic-ai-attacks/](examples/agentic-ai-attacks/): an IOC
list with a source and confidence on every row, an ATT&CK Navigator layer,
Splunk saved searches with Morpheus-native variants, Sentinel scheduled rules,
hunting KQL, and the lookups those read. The Sentinel tables the new content
uses were added to the table catalogue with Microsoft citations.

What checks it: [scripts/tests/test_agentic_ai_attacks.py](scripts/tests/test_agentic_ai_attacks.py)
keeps `iocs.csv`, the layer and the reference doc's technique table
consistent. The validator's content checks read markdown only, so the queries
in the asset files are neither linted nor provenance-checked; CLAUDE.md records
that boundary. Checked once by hand on 2026-11-21, by running the validator's
own functions against them: every KQL table is catalogued and every hunt
bounds time; every Splunk saved search is bounded by `dispatch.earliest_time`;
the only uncatalogued sourcetypes are the Morpheus pipeline's three per-layer
score sourcetypes (layers 3, 6 and 7), which that pipeline's own TA defines. `lookups/agt_iocs.csv` and
`lookups/sentinel_watchlist.csv` carry the same 186 indicators, each present
in `iocs.csv` with the same type, confidence and source, but no test pins
that.

A later change added [examples/agentic-ai-attacks/waf/](examples/agentic-ai-attacks/waf/README.md):
the edge-visible indicators as WAF rules for F5 BIG-IP, Akamai and
ModSecurity. The same test file pins its address list and user-agent lists to
`iocs.csv`; the rule syntax itself was not loaded on any device. The Akamai
JSON and the iRule's commands were later checked against the vendors' API
references. A later change added path rules: traversal sequences in a
path or parameter, secret files, management endpoints such as Spring Boot
Actuator, and Swagger UI.

No golden-prompt fixture exercises the new reference yet. Because the section
changed the query builder's `SKILL.md` and two reference files, the golden-run
marker went stale; the seventh model run, below, recorded it again.

## What the seventh model run found

Seventh run, 2026-11-21, same method as the earlier ones, after the agentic-AI
section changed the query builder's `SKILL.md` and two of its reference files.
9 of 10 before correction. Fixture 6 failed a correct answer. Asked to hunt
blocked web traffic across Zscaler, Cloudflare and Palo Alto, the answer
queried the Web data model once and grouped by sourcetype, as
cim-vendor-alignment.md's cross-vendor strategy says, and also scoped that
query to the three named sourcetypes with an `OR` group. The spec forbade any
`OR`-ed sourcetypes on one line.

This was the first run in which the skill's own wording could be read as
backing the fixture -- "query the shared data model once instead of OR-ing
vendor sourcetypes" -- so the skill was read first, and two more samples of the
same fixture were taken. Both added the same scope filter, written as
`sourcetype IN (...)`, and both passed: the rule distinguished syntax, not
behavior, and the repo's own stated preference is the `IN` form. The skill's
sentence contrasts the data model with a raw search, which the spec's `tstats`
and `datamodel` assertions already reject, so the syntax-only rule is gone and
the prose bullet now says a vendor scope filter is fine. No skill changed and no
prompt byte moved, so the ten answers were re-graded rather than re-run: 10 of
10, and the marker records it. Five fixture defects across seven runs, in four
fixtures, and still no skill defect found by a run.

## What the eighth model run found

Eighth run, 2026-11-24, same method, after the intelligence refresh added a
dated section and 16 technique rows to agentic-ai-attacks.md. 9 of 10 before
correction. Fixture 2 failed a correct answer. Asked for a detection of failed
admin logons with no known dataset, the answer returned `discovery` in the
right shape and led with the data-model coverage starter,
`| tstats count from datamodel=Authentication.Authentication ... by index, sourcetype`,
which query-workflow.md prints verbatim under "Data model coverage". It named
the `index=*` enumeration as the fallback, but in an inline code span under
`Assumptions` rather than in a second fenced block. The spec required the
`index=*` form in a query block and nothing else.

The skill was read first. query-workflow.md documents both starters and does
not rank them, and the fixture's own prose bullet says "a starter such as",
so the spec was stricter than both. Two more samples of the fixture were
taken: both led with the same data-model query and passed only because they
also put the `index=*` enumeration in a second fenced block. All three
answers made the same choice; the rule was grading where the fallback was
written, not whether discovery was done. The spec now accepts either
documented starter, still as a `tstats` grouped by index and sourcetype, and a
raw `index=*` search is still rejected. No skill changed and no prompt byte
moved, so the ten answers were re-graded rather than re-run: 10 of 10, and the
marker records it. Six fixture defects across eight runs, in five fixtures,
and still no skill defect found by a run.

No fixture exercised the agentic-AI reference in this run, so it said nothing
about whether the refreshed section changes an answer; it showed only that the
larger reference did not disturb the ten existing behaviors. The ninth run
closes that gap.

## What the ninth model run found

Ninth run, 2026-11-24, for new fixture 11: a Splunk hunt for inbound ARTEX
and CAIRN requests by user-agent, with only the accelerated Web data model
known. It is the first fixture to make the query builder load
agentic-ai-attacks.md, and it is built around a fact the reference rests on:
CAIRN has no user-agent indicator in any report used. The spec asks for a
`tstats` against `Web.Web` filtered on `http_user_agent` with an ARTEX string,
forbids any quoted string containing the name CAIRN inside a query block, and
requires the answer to mention CAIRN and to carry the reference's caveat that
these strings catch default builds only.

Three samples before any content change: two passed and one failed, and all
three showed the same gap. The failing answer wrote the framework name between
wildcards into the query as a "name-based placeholder" and said so in
`Assumptions`. The two that passed left CAIRN out, but every one of the three
told the reader to fetch "the CAIRN user-agent rows" from `iocs.csv`, which
has none. The skill was read first, as always, and this time the skill was the
problem: agentic-ai-attacks.md listed user-agents only in passing, never said
which frameworks have one, and had no rule against writing an unverified
indicator into a query. A model run is the only thing that could have shown
it; every document check was green.

The reference now lists the verified inbound user-agents by framework
(ARTEX, CyberStrikeAI, HexStrike-AI, PentAGI), states that CAIRN has none and
that STRIX's one string is context only, and says to offer behavior instead
of a guessed pattern.
[scripts/tests/test_agentic_ai_attacks.py](scripts/tests/test_agentic_ai_attacks.py)
pins that list to `iocs.csv` by framework, so the doc cannot gain a
user-agent the IOC file lacks. Because the query builder's content changed,
fixtures 1 to 7 and 11 were re-run; 8 to 10 exercise the other two skills,
whose content did not move, so their answers from the eighth run stand. 11 of
11, and three of three samples of fixture 11: each now matches the six
verified ARTEX strings exactly, writes no CAIRN term, says why, and points to
tempo and canary-probe hunts for CAIRN. The marker records it.

Six fixture defects across nine runs, in five fixtures, and one skill-content
gap, found by the first fixture written to exercise that content.

## What the tenth model run found

Tenth run, 2026-11-24, for three more fixtures against agentic-ai-attacks.md,
covering what fixture 11 left out: the Sentinel side and the identity hunts.
The reference names its hunts (H-AGT-021, H-AGT-022) but does not carry their
KQL, which lives in an asset file a client does not load, so each of these
asks the model to build the hunt from the reference's prose and the table
catalogue.

- **Fixture 12**, leaked application secrets: one source signing in as many
  service principals. Known table `AADServicePrincipalSignInLogs`. The spec
  wants that table only, a 30-day bound, a distinct count per `IPAddress` with
  the reference's threshold of three, and both error codes the reference
  gives.
- **Fixture 13**, probe accounts by naming shape, with `AuditLogs` and
  `SigninLogs` supplied. The spec wants a digit class around the word probe
  and forbids the reference's one example address, because the reference says
  to match the shape.
- **Fixture 14**, the same probe accounts but in an Okta tenant whose table is
  unknown. The spec wants `discovery` from `Usage`, and its table allowlist
  rejects both a guessed Okta table and an Entra query substituted for the one
  asked for. The reference's own hunt for this pattern is written against
  Entra, which is the temptation the fixture is there to test.

Three samples of each, nine answers: nine passed, and reading them found
nothing the specs missed. Every fixture 12 answer compared `ResultType` to the
bare number, not the prefixed code that would match nothing, and used
Microsoft's published addresses only to flag and sort rows. Every fixture 13
answer wrote the shape as a regular expression, said the pattern was reported
against Okta and Auth0 so Entra coverage is an adaptation, and one widened the
match for the `#EXT#` rewrite of external users. Every fixture 14 answer went
to `Usage`, named no Okta table, and carried the registration shapes forward
into its next step. No skill and no reference changed, so the eleven earlier
answers were re-graded rather than re-run: 14 of 14, and the marker records
it.

That is a result, not an absence of one: the gap fixture 11 found was about a
missing fact, and these three ask for things the reference does state. What
was still not exercised by any fixture after this run: the ATT&CK technique
map, the OAuth user-agent drift hunt, the Splunk identity rules
(source-centric spraying), and the reference's rule that legitimate services
are never a block action. The eleventh run takes the first and third.

## What the eleventh model run found

Eleventh run, 2026-11-24, for three fixtures on the ATT&CK map and the Splunk
identity side.

- **Fixture 15**, a technique the map has: T1546.018, asked for by ID only,
  with the Endpoint data model known. The spec wants a `tstats` against that
  model for the one artifact the row evidences, and CAIRN named.
- **Fixture 16**, a technique the map does not have: T1486, asked for "as
  ARTEX operators have used it". This is the same kind of question as fixture
  11's CAIRN user-agent, which found the reference gap: a request that
  presupposes evidence the reference lacks. The spec wants the answer to say
  the map has no row and forbids the framework's name inside the query.
- **Fixture 17**, source-centric password spraying against the accelerated
  Authentication data model. The spec wants a distinct count grouped by the
  source and the word baseline next to the thresholds.

Three samples of each, nine answers, nine passed, and reading them found
nothing the specs missed. Every fixture 15 answer resolved the ID to Python
Startup Hooks, matched only the file the row evidences, and said only CAIRN
has reporting for it. Every fixture 16 answer opened by saying the map has no
T1486 row, quoted the reference's own line that a blank is an intelligence
gap and not an assurance, offered a generic bulk-file-rewrite hunt labelled as
generic, and listed the Impact techniques the map does evidence. Fixture 11
failed one sample in three on the same kind of question before the reference
was fixed; the difference here is that the reference already states how to
read a missing row. Every fixture 17 answer grouped by source, kept a
per-user ceiling so the rule fires on many users failing a few times each,
and said a spray spread over a residential proxy pool stays under it.

Each spec was also checked the other way, against an answer edited to do the
wrong thing: an invented extension carrying the framework's name in the query,
the missing-row statement removed, grouping by user, and CAIRN removed. All
four were rejected.

No skill and no reference changed, so the fourteen earlier answers were
re-graded rather than re-run: 17 of 17, and the marker records it. Still not
exercised by any fixture after this run: the OAuth user-agent drift hunt, the
canary-username login rule, identity persistence in cloud audit logs, and the
rule that legitimate services are never a block action. The twelfth run takes
all four.

## What the twelfth model run found

Twelfth run, 2026-11-24, for the four items left over.

- **Fixture 18**, OAuth application user-agent drift, with
  `MicrosoftGraphActivityLogs` known. The spec wants that table only, grouped
  per `AppId` against a bounded baseline, and forbids the one vendor's baseline
  client in the query.
- **Fixture 19**, a canary username followed by an admin login, against the
  accelerated Authentication data model.
- **Fixture 20**, credentials added to applications or service principals,
  with `AuditLogs` known.
- **Fixture 21**, a detection for servers calling the LLM APIs and
  webhook.site the agents use, with a request to say which of those domains to
  blocklist. The spec wants the detection and wants the blocklist refused.

Ten samples were taken before any spec was written. Fixtures 18, 20 and 21
needed nothing: both drift answers built a per-application baseline and said
the generic clients are context only; both persistence answers matched the
operation name as a phrase because its dash character varies; and all three
blocklist answers opened with "none", cited the reference's rule, and treated
the reseller the same way.

Fixture 19 was the second skill-content gap a run has found, and the same
kind as the first. The reference named the canary-then-admin rule in its list
of hunts and nowhere said what a canary username looks like. All three
answers said so in almost the same words, that the loaded material carries no
verified canary login name, and then defined a canary as any failed non-admin
username with no success in the window. That is the honest move the reference
asks for since the ninth run, and it is also a worse detection than the
repo's own rule: a person mistyping a username before signing in as an
administrator matches it. The IOC file has the verified values, and the saved
search R-D-AGT-018 keys on their shape; a client just never loads either.

The reference now carries the verified probe and canary values (login
canaries, the path canary, the cloud-storage key canaries and the artifact
names) with the shape each hunt should match, and says to define an unlisted
pattern by behavior. A test pins every value in that list to a canary row of
`iocs.csv`. Because the query builder's content changed, all eighteen
fixtures that exercise it were re-run (1 to 7 and 11 to 21); 8 to 10 use the
other two skills and stand. 21 of 21, and three of three samples of fixture
19, each keyed on a username that starts with zz or contains nonexistent or
not-a-user, followed by admin, administrator or root from the same source
within a minute. The three pre-fix answers fail the spec, as they should.

Each new spec was also checked against an answer edited to do the wrong
thing: the vendor's baseline client written into the drift query, a second
table, the pre-fix canary answer, and a blocklist answer with the refusal
removed. All were rejected.

Fixture 21 was then tightened. Its refusal check was a required phrase, and
an answer that refuses the LLM hosts while recommending a block on the
reseller or webhook.site contains that phrase too. The grader gained a
`never_block` spec key that reads the answer's prose clause by clause for
advice to block a named service; sentence by sentence is not enough, because
the answer it exists for carries its refusal and its recommendation in one
sentence. The four real answers to fixture 21 pass it and no other answer in
the run trips it; answers edited to recommend the block fail. It reads prose,
so it has stated misses: advice by pronoun and advice hedged with a
condition. No prompt and no skill content moved, so the twenty-one answers
were re-graded, not re-run, and the marker was recorded again.

Fixture 20 was tightened the same day. It had checked only that the filter
was on the operation name and concerned credentials. It now requires both
operations that add one, the service principal operation and the application
operation matched by its ending, which are the two the pack's own Sentinel
rule matches and the two all three real answers chose. It also forbids the
application operation's full name typed with a plain hyphen, which matches
nothing because the real name carries a different dash. Re-graded, not
re-run.

Six fixture defects and two skill-content gaps across twelve runs. Both gaps
were a hunt the reference named while leaving its key values in a file the
skill does not load, and both were found by the first fixture to ask for that
hunt. Nothing on the list of uncovered items remains; what a fixture still
cannot show is whether a hunt returns anything on real data.

## For your own environment

1. Run `splunk-data-dictionary-builder` against your instance and pass its JSON
   to the query builder as the internal data dictionary.
2. Add your own indexes, tables, and field aliases as a data-dictionary excerpt
   rather than editing the reference files; the references describe vendor
   defaults, and your deployment will differ.

## Source links

- [Splunk SPL cheat sheet](https://www.splunk.com/en_us/blog/learn/splunk-cheat-sheet-query-spl-regex-commands.html)
- [Splunk Search Tutorial 9.4](https://help.splunk.com/en/splunk-enterprise/get-started/search-tutorial/9.4/introduction/about-the-search-tutorial)
- [Microsoft Sentinel documentation](https://learn.microsoft.com/en-us/azure/sentinel/)
