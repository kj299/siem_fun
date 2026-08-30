# Working in this repo

A pack of three Splunk/Sentinel query skills plus the tooling that keeps them
consistent. Most files here are reference material an LLM reads at runtime, so
correctness of the *content* matters as much as the code.

## Commands

```bash
# Validator (needs the module once: Install-Module powershell-yaml -Scope CurrentUser -Force)
pwsh -NoProfile -File ./scripts/validate-skill-pack.ps1

# Validator's own unit tests
pwsh -NoProfile -File ./scripts/tests/validate-skill-pack.tests.ps1

# Dictionary builder unit tests
python -m unittest discover -s splunk-data-dictionary-builder/tests

# Mutation-check both suites (proves the REGRESSION tests actually catch their bugs)
python3 scripts/tests/mutation-check.py
```

CI runs all three on every pull request and on pushes to `main` (two jobs:
`validate` on windows-latest, `python` on ubuntu-latest), plus weekly on a
schedule so runner-image and module drift surfaces on its own rather than as a
mystery failure in whatever PR happens to come next. A push to a topic branch
with no open PR runs nothing, so run them locally before pushing; several bugs
in this repo's history reached CI only because a local run was skipped.

## Hard rules

- **ASCII only.** Every tracked file must contain only tab, LF, CR, and
  printable ASCII (32-126). The validator fails otherwise. In practice: no em
  dashes, curly quotes, arrows, or accented characters, in prose or in code.
- **Never commit secrets.** `.env` is gitignored; `.env.example` is the
  template. Never ask the user to paste a token or password into chat -- the
  dictionary builder reads credentials from environment variables or CLI
  arguments only. The validator enforces two halves of this: `.gitignore` must
  keep its bare `.env` entry, and no tracked file may contain a high-precision
  credential shape (AWS key id, GitHub/Slack token, private key block, or a
  Splunk/Bearer value of 40+ base64 characters). Generic `password=` patterns
  are deliberately not matched -- a check that fires on docs discussing
  credentials gets switched off rather than fixed. A test that needs a literal
  credential shape must split it (`"AKIA" + "..."`) so the file does not trip
  the check it is testing.
- **Never invent Splunk or Sentinel identifiers.** Index names, sourcetypes, and
  table names in reference docs must be real. If a schema is uncertain, the
  skills are supposed to emit a discovery query instead of guessing, and the
  docs should model that.

  **Field names are deliberately looser, and this file used to contradict the
  skills on it.** `splunk-sentinel-query-builder/SKILL.md` states the rule the
  pack actually ships: the dataset rule covers indexes, sourcetypes and tables,
  *not* fields, and a well-known field of a named dataset may be used even when
  it is absent from a supplied field list, provided it is named in
  `Assumptions` so the user can drop it (`EventCode=1` on a Sysmon sourcetype is
  the usual case). Fields are therefore not mechanically checked: there is no
  exhaustive per-dataset field registry to check against, and the catalogues
  list *key* fields as a highlight rather than a schema, so a check built on
  them would reject correct queries. The lookup `OUTPUT` rule below is the one
  field-level case that *is* decidable, because there the doc supplies both
  halves itself.

  Two parts of the identifier rule are mechanical:
  - **Sourcetypes** must be catalogued in
    [splunkbase-app-catalog.md](splunk-enrichment-query-builder/references/splunkbase-app-catalog.md)
    or [cim-vendor-alignment.md](splunk-sentinel-query-builder/references/cim-vendor-alignment.md).
  - **Sentinel tables** named in table position in a `kql` block must be
    catalogued in [sentinel-table-catalog.md](splunk-sentinel-query-builder/references/sentinel-table-catalog.md),
    which cites Microsoft's own documentation per table. **KQL table names are
    case-sensitive**: `SignInLogs` is a different, non-existent table to
    `SigninLogs` and returns nothing, so the comparison is case-sensitive too.
    That exact mistake was already in the docs.

    The check is positional, not shape-based: it reads the leading identifier
    of a block plus `union` and `join` operands. CamelCase alone is far too
    common a shape -- field names, vendor names, and this repo's own class
    names all match it. Index names are deliberately not registered: they are
    customer-defined, so `index=firewall` is a placeholder, not a claim.

## Invariants the validator enforces

Breaking any of these fails CI, so change them deliberately:

- `agents/claude-opus.yaml` and `agents/codex-gpt-5.4.yaml` in a skill must
  carry identical `prompt_shape`, `default_sections`, `short_sections`,
  `optimization_sections`, `discovery_sections`, `token_rules`, `truth_order`,
  and `stop_conditions`. Comparison is case-sensitive and order-sensitive. Edit
  both files together. (The enrichment skill has no `optimization_sections`;
  each skill's compared set is declared in `$helperChecks`.)
  - Query-builder skills additionally need `behavior.trigger_tuning` in the
    claude helper and `behavior.packaging_rules` in the codex helper.
  - `splunk-data-dictionary-builder` uses a simpler shape: only `token_rules`
    and `stop_conditions` are compared, and it has neither tuning section.
- Per skill, `openai.yaml` `interface.default_prompt` must be byte-identical to
  `invocation.preferred_prompt` in both helpers. This has drifted before.
- `openai.yaml` must set `policy.allow_implicit_invocation` to `false`, and must
  carry non-empty `interface.display_name`, `interface.short_description`, and
  `interface.default_prompt`.
- No tracked file may contain a git conflict marker.
- Every tracked file must be ASCII on disk. The check reads BYTES, so a UTF-8
  BOM or a UTF-16 re-encode fails even though it would decode to clean text.
- Every `CIM_SOURCETYPE_HINTS` key in the dictionary builder must be documented
  in [cim-vendor-alignment.md](splunk-sentinel-query-builder/references/cim-vendor-alignment.md).
- Relative markdown links must resolve. Links inside fenced code blocks are
  ignored, so illustrative examples are safe.
- Adding a file that must not disappear? Add it to `$requiredFiles` in the
  validator.
- Every `Add-Issue` message must be listed verbatim in
  [scripts/required-checks.txt](scripts/required-checks.txt), and every line
  there must match a live `Add-Issue`. Cross-checked in both directions on every
  run, so **adding a check means adding a line, and rewording a message means
  editing one.** This exists because a check can be deleted together with the
  mutation that covered it, which leaves the mutation suite self-consistent and
  the run green while the check is simply gone. Not hypothetical: a merge
  resolution dropped 81 of the 82 lines of the KQL provenance feature and
  validation still passed, because the catalogue it read was still a required
  file. Section `[E]` of the mutation script cannot catch that -- it only proves
  the checks that *exist* have mutations.
- Golden-prompt fixtures assert output shapes. A section named in backticks on a
  fixture's "shape" bullet must be declared by some `SKILL.md`. Checked against
  the union across skills, because a fixture does not record which skill it
  exercises and inferring that from its prose would be guesswork.

## SPL in reference docs

- In `| where`, quote boolean comparisons: `noise="true"`, not `noise=true`.
  `where` uses eval semantics, so a bare `true` is a *field reference* and the
  filter silently matches nothing. The validator checks markdown for this
  case-insensitively (`riot=TRUE` has the identical bug) across three input
  sets: fenced blocks of any language, inline code spans -- which is how table
  cells carry queries, and how splunk-to-kql-mapping.md writes every one of
  them -- and raw lines beginning with `| where`. Scanning per code snippet
  rather than per file is what lets the pattern be unanchored without flagging
  prose that names `| where` and `noise=true` in two separate spans, as the
  bullet above does. Unquoted values are fine in the `search` command.
- Every field named by `| lookup <name> ... OUTPUT` must appear in that lookup's
  documented field list in the same file. The validator enforces this. The join
  KEY is deliberately exempt: these docs treat the key field name as
  version-dependent and tell the reader to confirm it with `inputlookup`, so
  requiring it to be listed would contradict them.
- Lookup joins leave nulls for unmatched rows. A filter meant to keep unmatched
  rows needs `isnull(...)` or `coalesce(field, "")`, or it silently drops them.
  **Not machine-checked, and deliberately so:** whether a filter is *meant* to
  keep unmatched rows cannot be read off the text, so any check would be
  guessing at intent. Reviewer's job, not the validator's.
- Prefer `index IN (a, b)` over `OR` chains. The validator reports three or more
  **bare** `index=` terms chained with `OR`. It does not report
  `((index=firewall sourcetype=cisco:asa) OR (index=proxy sourcetype=...))`,
  which is the documented correct pattern when schemas differ per index and is
  something `index IN (...)` cannot express.
- Always bound time first. The validator reports an `spl` block whose first line
  is a raw-event search carrying no `earliest=`, no `_time`, and no `| head`.
  Blocks starting with a generating command (`| tstats ...`) are exempt: that is
  the documented discovery shape and runs unbounded on purpose.

## Language traps that have actually broken this repo

Each of these shipped and had to be fixed. Test locally rather than assuming.

**PowerShell**

- `@(@("a","b"))` unwraps to `@("a","b")`. An outer `@()` around a *single*
  inner array is discarded, so `foreach` iterates the strings, not the pair.
- `-eq`, `-ne`, `-match`, `-notmatch` are case-insensitive. Use `-ceq`, `-cne`,
  `-cmatch`, `-cnotmatch` when case matters.
- `"$name:"` in a double-quoted string parses as a scope-qualified variable and
  is a parse error. Write `"${name}:"`.
- Returning an empty array unrolls to nothing, so the caller sees `$null`. Use
  `return , $items`, and decide key presence with `.Contains()` rather than by
  testing the returned value for `$null`.
- `Get-Content -Raw` returns `$null` for an empty file; calling a method on it
  throws.

**Python**

- `$` in a regex also matches before a trailing newline, so
  `re.match(r"^\w+$", "x\n")` succeeds. Use `fullmatch` with no anchors.
- `bool("0")` is `True`. Splunk REST returns booleans as strings in places;
  normalize through `parse_bool`.

## Testing policy

- Two suites, both dependency-free on purpose: stdlib `unittest` for Python,
  and a few assertion helpers for PowerShell. Do not add pytest or Pester --
  the suites must run anywhere the scripts themselves run.
- Tests tagged `REGRESSION` pin behavior that a shipped defect got wrong. Keep
  them passing rather than adjusting the expectation, and read the comment
  before touching one.
- Fix a bug in the validator or the dictionary builder, add a case.
- `MainEndToEndTests` drives `main()` against a stubbed `SplunkClient.request`,
  which is the single network chokepoint (`get` and `search_oneshot` both funnel
  through it). Every other Python test covers a parser in isolation; without
  this one the path that actually runs -- argument handling, the `discover_*`
  sequence, CIM hint attachment, the sampling slice, and the assembled JSON --
  was exercised nowhere, and CI only byte-compiles the builder.
- Section `[E]` of the mutation script asserts that every `Add-Issue` message in
  the validator is reachable by some registered mutation. Section `[C]` is
  hand-maintained, so a new check could otherwise ship with nothing proving it
  fires -- which is exactly how the `$requiredFiles` guard shipped uncovered. A
  message whose literal text is too generic to match automatically goes in
  `COVERED_BY_NAME` pointing at the mutation that covers it, and that mutation
  is asserted to have run; one with genuinely no mutation goes in
  `UNMUTATED_MESSAGES` with a reason. Both are checked for staleness.
- When a test is meant to catch a specific bug, reintroduce that bug and
  confirm the test fails. Several tests here looked correct but proved nothing
  until that check was run. `scripts/tests/mutation-check.py` automates this and
  runs in CI: it covers every REGRESSION test in both suites, every check the
  validator performs, and the CI-only environment cases. Add a case to it when
  you add a REGRESSION test or a validator check; if a test genuinely cannot be
  mutated, record it in that script's `NOT_MUTATABLE` with the reason rather
  than leaving a silent gap.
- The validator runs only on windows-latest, which checks out CRLF while your
  tree is almost certainly LF. Two checks were silently no-ops on CI for exactly
  this reason. The mutation-check script exercises a CRLF checkout, a UTF-8 BOM,
  a UTF-16 file and a wildcard filename; keep those passing.

## Adding a new skill

1. `SKILL.md` with frontmatter (`name` matching the directory, `description`
   stating when to use and when not to), plus `## Important` and `## Inputs`.
   The validator compares `name` to the directory case-sensitively: skills are
   loaded by that name, so a mismatch is a live routing break rather than a
   cosmetic one.
2. `agents/openai.yaml`, `agents/claude-opus.yaml`, `agents/codex-gpt-5.4.yaml`
   following the parity rules above.
3. `references/` for detail; keep `SKILL.md` short and link out.
4. Register it in the validator: add the directory to `$skills` (every per-skill
   check iterates that list), its files to `$requiredFiles`, and an entry to
   `$helperChecks` declaring which sections its helper pair must share. The
   validator cross-checks `$skills` against `$helperChecks`, against
   `$requiredFiles`, and against the directories on disk that hold a SKILL.md,
   in both directions -- so a skill registered nowhere is reported rather than
   silently receiving zero checks.
5. Update the layout trees and file lists in [README.md](README.md) and
   [QUERY_SKILL_PLAN.md](QUERY_SKILL_PLAN.md).
6. Add fixtures to [examples/golden-prompts.md](examples/golden-prompts.md).
