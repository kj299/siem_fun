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
```

CI runs all three on every pull request and on pushes to `main` (two jobs:
`validate` on windows-latest, `python` on ubuntu-latest). A push to a topic
branch with no open PR runs nothing, so run them locally before pushing;
several bugs in this repo's history reached CI only because a local run was
skipped.

## Hard rules

- **ASCII only.** Every tracked file must contain only tab, LF, CR, and
  printable ASCII (32-126). The validator fails otherwise. In practice: no em
  dashes, curly quotes, arrows, or accented characters, in prose or in code.
- **Never commit secrets.** `.env` is gitignored; `.env.example` is the
  template. Never ask the user to paste a token or password into chat -- the
  dictionary builder reads credentials from environment variables or CLI
  arguments only.
- **Never invent Splunk or Sentinel identifiers.** Index names, sourcetypes,
  table names, and field names in reference docs must be real. If a schema is
  uncertain, the skills are supposed to emit a discovery query instead of
  guessing, and the docs should model that.

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

## SPL in reference docs

- In `| where`, quote boolean comparisons: `noise="true"`, not `noise=true`.
  `where` uses eval semantics, so a bare `true` is a *field reference* and the
  filter silently matches nothing. The validator greps markdown for this.
  Unquoted values are fine in the `search` command.
- Lookup joins leave nulls for unmatched rows. A filter meant to keep unmatched
  rows needs `isnull(...)` or `coalesce(field, "")`, or it silently drops them.
- Prefer `index IN (a, b)` over `OR` chains, and always bound time first.

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
- When a test is meant to catch a specific bug, reintroduce that bug and
  confirm the test fails. Several tests here looked correct but proved nothing
  until that check was run.

## Adding a new skill

1. `SKILL.md` with frontmatter (`name` matching the directory, `description`
   stating when to use and when not to), plus `## Important` and `## Inputs`.
2. `agents/openai.yaml`, `agents/claude-opus.yaml`, `agents/codex-gpt-5.4.yaml`
   following the parity rules above.
3. `references/` for detail; keep `SKILL.md` short and link out.
4. Register it in the validator: add the directory to `$skills` (every per-skill
   check iterates that list), its files to `$requiredFiles`, and an entry to
   `$helperChecks` declaring which sections its helper pair must share. The
   validator cross-checks `$skills` against `$helperChecks`, so missing one is
   reported rather than silently skipping checks.
5. Update the layout trees and file lists in [README.md](README.md) and
   [QUERY_SKILL_PLAN.md](QUERY_SKILL_PLAN.md).
6. Add fixtures to [examples/golden-prompts.md](examples/golden-prompts.md).
