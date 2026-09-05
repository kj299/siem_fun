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
|   |-- golden-prompts.md
|   `-- golden-run.json
|-- CLAUDE.md
|-- QUERY_SKILL_PLAN.md
|-- README.md
|-- scripts/
|   |-- tests/
|   |   |-- mutation-check.py
|   |   |-- shared-rule-cases.json
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

Three fixture defects in the first three runs, two more here, and still no
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

## What is still open

Running the model half on a schedule against a credential. A weekly Routine
now runs it with subagents instead, which needs no secret, and reports only
when something fails; what it cannot do is push the refreshed marker, so a
stale NOTICE after a content change still waits on a person to re-run and
record. Adding a repository secret so the API runner could do both in CI
remains the repository owner's decision, not this plan's.

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
