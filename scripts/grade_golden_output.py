#!/usr/bin/env python3
"""Grade a model's answer to a golden-prompt fixture.

    python3 scripts/grade_golden_output.py --fixture 3 --response out/golden/03.md
    python3 scripts/grade_golden_output.py --all out/golden
    python3 scripts/grade_golden_output.py --list

The structural half of the fixtures in examples/golden-prompts.md is enforced
by the validator (every section a fixture names must be one a SKILL.md
declares). This script is the behavioral half: given what a model actually
answered, does the answer meet the fixture's assertions?

Each fixture carries a fenced ```json block, its grader spec, alongside the
prose "Expected output" bullets. The prose is for a reader; the spec is what
runs. Keeping them adjacent in the same file is the drift defence: a bullet
changed without its spec is visible in the same diff.

Spec keys, all optional:

  sections         required section names, in the order they must appear
  forbid_sections  section names that must not appear at all
  contains         literal substrings the answer must contain (case-sensitive)
  not_contains     literal substrings it must not contain
  matches          regular expressions that must find a match
  not_matches      regular expressions that must not
  query_matches    regular expressions at least one query block must match: the
                   fenced blocks under the Query or Discovery query label
  query_not_matches  regular expressions no query block may match
  query_lang       consider only query blocks fenced with this language; a
                   translation answer echoes the source query under Query, and
                   a rule about the target must not fire on the source
  assumed_if_used  tokens that may appear in a code block only if the
                   Assumptions section also names them (EventCode=1 on a
                   Sysmon sourcetype is the documented case)
  indexes          every index= value in a code block must be one of these
  sourcetypes      every sourcetype= value in a code block must be one of these
  tables           every leading KQL table in a kql block must be one of these
  code_block       whether a fenced block is required at all (default true)

Generic checks run on every answer regardless of spec: no unquoted boolean in
'| where', every raw-event spl block is time-bound, every kql block names
TimeGenerated, and the answer never asks the user to paste a credential. These
are the same rules the validator applies to the reference docs, applied to the
output the docs produce.

Section names are read from the numbered output shapes in every SKILL.md, the
way the validator reads them, so a section the grader looks for is one the pack
actually declares. Only stdlib is used; this runs anywhere the scripts do.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES = os.path.join(REPO, "examples", "golden-prompts.md")
SKILLS = (
    "splunk-sentinel-query-builder",
    "splunk-enrichment-query-builder",
    "splunk-data-dictionary-builder",
)

# `## 3. Sentinel known-table optimization`
_FIXTURE_HEADING_RE = re.compile(r"(?m)^## (\d+)\. (.+?)[ \t]*$")
# Fenced blocks, any language, CRLF-tolerant. The closing fence is anchored the
# same way the validator anchors it.
_FENCE_RE = re.compile(r"(?ms)^[ \t]*```([A-Za-z0-9_-]*)[ \t]*\r?\n(.*?)^[ \t]*```[ \t]*\r?$")
# `Use $splunk-sentinel-query-builder to ...`
_SKILL_RE = re.compile(r"\$(splunk-[a-z-]+builder)")
# Numbered output-shape items in a SKILL.md: `3. Why efficient` or
# `4. Assumptions (only if ...)`. Same shape the validator reads.
_SKILL_SECTION_RE = re.compile(r"(?m)^\d+\.[ \t]+`?([A-Z][A-Za-z ]{2,30}?)`?[ \t]*(?:\(|\r?$)")

# A line that is a section label. Models write these several ways:
#   ## Objective        **Objective**        Objective:        3. Assumptions
#   ### 2. Query        **Why efficient:**   Objective (one line ...)
# Leading markers and trailing decoration are stripped; the core must be the
# name and nothing else.
_LABEL_LINE_RE = re.compile(
    r"^[ \t]*(?:#{1,6}[ \t]*)?(?:\d+[.)][ \t]*)?(?:\*\*|__|`)?"
    r"(?P<name>[A-Z][A-Za-z ]{2,30}?)"
    r"(?:\*\*|__|`)?[ \t]*:?[ \t]*(?:\([^)]*\))?[ \t]*(?:\*\*)?[ \t]*$"
)

# Positional identifier reads, mirroring the validator's.
_INDEX_VALUE_RE = re.compile(r'(?i)\bindex[ \t]*=[ \t]*"?([^\s"|),`\]]+)"?')
_INDEX_IN_RE = re.compile(r"(?i)\bindex[ \t]+IN[ \t]*\(([^)]*)\)")
_SOURCETYPE_VALUE_RE = re.compile(r'(?i)\bsourcetype[ \t]*=[ \t]*"?([^\s"|),`\]]+)"?')
_SOURCETYPE_IN_RE = re.compile(r"(?i)\bsourcetype[ \t]+IN[ \t]*\(([^)]*)\)")
_KQL_LEADING_TABLE_RE = re.compile(r"(?m)^[ \t]*([A-Z][A-Za-z0-9_]*)[ \t]*(?:\r?$|\|)")
# Unquoted boolean in an eval-semantics where: the value is a field reference
# and the filter silently matches nothing.
_WHERE_BOOLEAN_RE = re.compile(r"(?i)\|[ \t]*where\b[^|\r\n]*=[ \t]*(true|false)\b")
# An actual time PREDICATE, not a mention of _time. Ported verbatim from the
# validator's $splTimePredicateRegex: `index=windows | stats latest(_time)`
# scans all history but contains the string `_time`, so the substring test this
# replaces graded it as bounded.
_TIME_PREDICATE_RE = re.compile(
    r"(?i)(\bearliest[ \t]*=|\blatest[ \t]*=|_time[ \t]*(?:>=|<=|<|>|=)"
    r"|(?:>=|<=|<|>)[ \t]*_time)"
)
# Binning is NOT a bound, and was wrongly treated as one here and in the
# validator: `bin(_time, "1h")` groups events into buckets without restricting
# the window, so the search still scans all retained history.
# `| head` is an accepted alternative bound, as it is in the validator.
_HEAD_BOUND_RE = re.compile(r"(?i)\|[ \t]*head\b")
# A DENYLIST of leading commands, not a whitelist of generating ones, for the
# reason the validator gives: in SPL a leading pipe already means the first
# command is generating, and every app adds its own. What a leading pipe does
# NOT guarantee is that the command generates rather than searches.
_SPL_NON_GENERATING_LEAD = frozenset({"search"})
_SPL_LEAD_COMMAND_RE = re.compile(r"^\|[ \t]*([A-Za-z_]\w*)")
# The one rule that outranks every output shape.
_PASTE_SECRET_RE = re.compile(
    r"(?i)\b(paste|share|send|provide|enter|type)\b[^.\n]{0,60}\b(token|password|secret|credential|api key)"
)
# "I will never ask you to type a token here" is the rule being kept, not
# broken. A negation shortly before the verb clears the match.
_NEGATION_RE = re.compile(r"(?i)\b(never|not|no|without|don't|do not|won't)\b")


def asks_for_secret(text: str) -> bool:
    for m in _PASTE_SECRET_RE.finditer(text):
        window = text[max(0, m.start() - 40):m.start()]
        if not _NEGATION_RE.search(window):
            return True
    return False


def spl_is_raw_event_search(body: str) -> bool:
    """True when the time rule applies to this spl block.

    Mirrors the validator. A block leading with a generating command
    (`| tstats ...`) is the documented discovery shape and runs unbounded on
    purpose, but `| search index=windows` is a raw-event search wearing a
    generating command's syntax. Exempting every leading pipe let that one skip
    the check entirely.
    """
    lines = [ln for ln in body.splitlines() if ln.strip()]
    if not lines:
        return False
    first = lines[0].strip()
    if first.startswith("|"):
        cmd = _SPL_LEAD_COMMAND_RE.match(first)
        return bool(cmd and cmd.group(1).lower() in _SPL_NON_GENERATING_LEAD)
    return True


def spl_time_bound(body: str) -> bool:
    """Whole block, not just the base search: a base search may wrap onto a
    second line before its earliest=, and the predicate pattern is precise
    enough that scanning further cannot accept a bare mention of _time."""
    return bool(_TIME_PREDICATE_RE.search(body) or _HEAD_BOUND_RE.search(body))


SPEC_KEYS = frozenset({
    "sections", "forbid_sections", "contains", "not_contains", "matches",
    "not_matches", "query_matches", "query_not_matches", "query_lang",
    "assumed_if_used", "indexes", "sourcetypes", "tables", "code_block",
})

# Table names the catalogue itself lists as placeholders, so a discovery answer
# that writes `TableName | getschema` is making no claim about a real table.
PLACEHOLDER_TABLES = frozenset({"TableName", "YOUR_TABLE"})
# Table references in KQL, ported from the validator's Get-KqlTableReferences.
# The line-oriented scan this replaces could not see a table bound by `let` or
# a join operand on the line after its `(`, so an invented table in either
# position satisfied a fixture's `tables` allowlist.
#
# The trailing \b(?![ \t]*=) on the union pattern is load-bearing and both
# parts are needed: without the lookahead `union withsource=Table_ *`
# backtracks and captures `withsource`; without the \b it captures `withsourc`,
# which the lookahead then accepts because the next character is `e`.
_KQL_UNION_REF_RE = re.compile(
    r"\bunion\b(?:[ \t]+\w+[ \t]*=[ \t]*\S+)*[ \t]+\(?[ \t]*([A-Za-z_][A-Za-z0-9_]*)\b(?![ \t]*=)"
)
# `union (A | take 5), (B | take 5)`: KQL allows a parenthesized subquery as an
# operand, and each one names a table. The bare-identifier list pattern below
# cannot reach them, because its scan stops at the first `|` and these have one
# inside the parentheses. Applied to the union statement only, so a `(` in a
# `project` or `summarize` elsewhere is not read as an operand.
_KQL_UNION_PAREN_RE = re.compile(r"\([ \t\r\n]*([A-Za-z_][A-Za-z0-9_]*)")
# union takes a comma-separated list, so operands after the first need their
# own pass.
_KQL_UNION_MORE_RE = re.compile(r",[ \t\r\n]*\(?[ \t]*([A-Za-z_][A-Za-z0-9_]*)\b(?![ \t]*[=(])")
# re.DOTALL so `join (` followed by the table on the NEXT line is still seen.
_KQL_JOIN_REF_RE = re.compile(r"\bjoin\b[^(\r\n]*\([ \t\r\n]*([A-Za-z_][A-Za-z0-9_]*)", re.S)
# `let recent = SigninLogs;` binds a table. The negative lookahead for `(`
# keeps function calls out: `let cutoff = ago(1d);` must not read as `ago`.
_KQL_LET_VALUE_RE = re.compile(r"\blet[ \t]+\w+[ \t]*=[ \t]*([A-Za-z_][A-Za-z0-9_]*)\b(?![ \t]*\()")
# The names those let statements bind. They are locals, not tables, so a later
# `recent | take 5` must not be read as an uncatalogued table.
_KQL_LET_NAME_RE = re.compile(r"\blet[ \t]+([A-Za-z_][A-Za-z0-9_]*)[ \t]*=")
# Operators that can stand where a table would, so they are never table names.
KQL_KEYWORDS = frozenset({
    "let", "union", "search", "find", "print", "range", "datatable",
    "externaldata", "materialize", "where", "set", "declare", "evaluate",
})


@dataclass
class Fixture:
    number: int
    title: str
    skill: str
    prompt: str
    spec: dict


@dataclass
class Result:
    passed: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)

    def ok(self, msg: str) -> None:
        self.passed.append(msg)

    def bad(self, msg: str) -> None:
        self.failed.append(msg)

    @property
    def success(self) -> bool:
        return not self.failed


class FixtureError(ValueError):
    """A fixture is missing something the grader needs. Raised, not skipped:
    a fixture that silently grades nothing would read as a pass."""


def fenced_blocks(text: str) -> list[tuple[str, str]]:
    """(language, body) for every fenced block, in order."""
    return [(m.group(1).lower(), m.group(2)) for m in _FENCE_RE.finditer(text)]


def parse_fixtures(text: str) -> list[Fixture]:
    headings = list(_FIXTURE_HEADING_RE.finditer(text))
    fixtures: list[Fixture] = []
    for i, h in enumerate(headings):
        end = headings[i + 1].start() if i + 1 < len(headings) else len(text)
        body = text[h.start():end]
        number = int(h.group(1))
        title = h.group(2).strip()
        blocks = fenced_blocks(body)
        prompts = [b for lang, b in blocks if lang == "text"]
        specs = [b for lang, b in blocks if lang == "json"]
        if not prompts:
            raise FixtureError(f"fixture {number} has no ```text prompt block")
        if len(specs) != 1:
            raise FixtureError(f"fixture {number} needs exactly one ```json grader spec, found {len(specs)}")
        skill_match = _SKILL_RE.search(prompts[0])
        if not skill_match:
            raise FixtureError(f"fixture {number} prompt names no $skill")
        try:
            spec = json.loads(specs[0])
        except json.JSONDecodeError as error:
            raise FixtureError(f"fixture {number} grader spec is not valid JSON: {error}") from error
        unknown = set(spec) - SPEC_KEYS
        if unknown:
            raise FixtureError(f"fixture {number} grader spec has unknown keys: {sorted(unknown)}")
        fixtures.append(Fixture(number, title, skill_match.group(1), prompts[0].strip(), spec))
    if not fixtures:
        raise FixtureError("no fixtures found")
    return fixtures


def load_fixtures(path: str = FIXTURES) -> list[Fixture]:
    with open(path, encoding="ascii") as fh:
        return parse_fixtures(fh.read())


def declared_sections(repo: str = REPO) -> set[str]:
    """Every output section any SKILL.md declares. Empty is an error, not a
    vacuous pass: the validator's first version of this read nothing."""
    found: set[str] = set()
    for skill in SKILLS:
        path = os.path.join(repo, skill, "SKILL.md")
        if not os.path.exists(path):
            continue
        with open(path, encoding="ascii") as fh:
            for m in _SKILL_SECTION_RE.finditer(fh.read()):
                found.add(m.group(1).strip())
    if not found:
        raise FixtureError("no output sections could be read from any SKILL.md")
    return found


def find_sections(text: str, declared: set[str]) -> list[str]:
    """Declared section names in the order they label the answer.

    Matching is case-insensitive: a model that writes 'Why Efficient' has still
    produced the section. Fenced blocks are skipped so a query line such as
    'Query' inside SPL cannot pose as a label.
    """
    lowered = {name.lower(): name for name in declared}
    stripped = _FENCE_RE.sub("", text)
    order: list[str] = []
    for line in stripped.splitlines():
        m = _LABEL_LINE_RE.match(line)
        if not m:
            continue
        name = lowered.get(m.group("name").strip().lower())
        if name and name not in order:
            order.append(name)
    return order


def _label_at(line: str, declared: set[str]) -> str | None:
    m = _LABEL_LINE_RE.match(line)
    if not m:
        return None
    lowered = {name.lower(): name for name in declared}
    return lowered.get(m.group("name").strip().lower())


def section_body(text: str, name: str, declared: set[str]) -> str:
    """Text under a section label up to the next declared label, or '' when
    the section is absent. Fenced blocks inside the section are kept."""
    lines = text.splitlines()
    start = None
    for i, line in enumerate(lines):
        label = _label_at(line, declared)
        if start is None:
            if label == name:
                start = i + 1
        elif label is not None and label != name:
            return "\n".join(lines[start:i])
    return "\n".join(lines[start:]) if start is not None else ""


def query_blocks(text: str, declared: set[str], lang: str | None = None) -> list[str]:
    """Every fenced block under the Query or Discovery query label.

    Specs assert on THESE blocks rather than on every fence, because an
    optimization answer legitimately quotes the slow original under
    What changed, and a rule such as 'no extend before the time filter' must
    not fire on the query the answer is replacing. A discovery answer may
    offer several starters, so a positive rule is satisfied by any of them.
    """
    found: list[str] = []
    for label in ("Query", "Discovery query"):
        body = section_body(text, label, declared)
        found += [b for l, b in fenced_blocks(body) if lang is None or l == lang]
    return found


def _split_values(raw: str) -> list[str]:
    return [v.strip().strip('"') for v in raw.split(",") if v.strip().strip('"')]


def _placeholder(value: str) -> bool:
    return value.startswith(("YOUR_", "<")) or value == "..." or "*" in value


def index_values(text: str) -> set[str]:
    values = {m.group(1) for m in _INDEX_VALUE_RE.finditer(text)}
    for m in _INDEX_IN_RE.finditer(text):
        values.update(_split_values(m.group(1)))
    return {v for v in values if not _placeholder(v)}


def sourcetype_values(text: str) -> set[str]:
    values = {m.group(1) for m in _SOURCETYPE_VALUE_RE.finditer(text)}
    for m in _SOURCETYPE_IN_RE.finditer(text):
        values.update(_split_values(m.group(1)))
    return {v for v in values if not _placeholder(v)}


def _union_statement(text: str) -> str:
    """The union statement starting at `text`, operands and all.

    It ends at the first `|` or newline whose parentheses are BALANCED. Depth is
    what makes both halves work: `union (A | take 5), (B | take 5)` keeps its
    inner pipes because they sit at depth 1, while `union A, B | summarize by
    X, Y` still ends at the pipe so the summarize columns are not read as
    operands. A trailing comma carries the list onto the next line.
    """
    depth = 0
    for i, ch in enumerate(text):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        elif depth == 0 and ch in "|\n":
            if ch == "\n" and text[:i].rstrip().endswith(","):
                continue
            return text[:i]
    return text


def kql_tables(body: str) -> set[str]:
    """Every table a kql block references: the leading source, plus `union` and
    `join` operands and any table bound by `let`. Function calls
    (`let x = toscalar(...)`) and operators are not tables.

    Scanned whole-body rather than line-at-a-time, because a join operand may
    sit on the line after its `(` and a union list may wrap.
    """
    tables: set[str] = set()
    lines = [ln for ln in body.splitlines() if ln.strip() and not ln.strip().startswith("//")]
    # Collected first so a later reference to a local is not read as a table.
    locals_ = {m.group(1) for m in _KQL_LET_NAME_RE.finditer(body)}
    # The source is the first line that is not part of a `let` preamble.
    # Reading line 0 unconditionally meant `let cutoff = ago(1d);` followed by
    # `GhostTable | where ...` put the real table on line 2, where nothing read
    # it. The validator had the identical hole and was fixed with it.
    lead = next((ln.strip() for ln in lines if not re.match(r"^let\b", ln.strip())), None)
    if lead:
        m = re.match(r"^([A-Z][A-Za-z0-9_]*)\b(?![(])", lead)
        if m and m.group(1) not in KQL_KEYWORDS:
            tables.add(m.group(1))
    for pattern in (_KQL_UNION_REF_RE, _KQL_JOIN_REF_RE, _KQL_LET_VALUE_RE):
        for m in pattern.finditer(body):
            if m.group(1) not in KQL_KEYWORDS:
                tables.add(m.group(1))
    # Trailing operands of a union list, taken only from the union statement
    # itself so commas elsewhere (project, summarize by) are not mistaken for
    # table references.
    # Trailing operands of a union list, bare or parenthesized. Both are read
    # from the union STATEMENT, scanned from the union KEYWORD: starting at the
    # end of the match would begin the depth count inside a parenthesis the
    # match had already consumed.
    for u in _KQL_UNION_REF_RE.finditer(body):
        statement = _union_statement(body[u.start():])
        for pattern in (_KQL_UNION_MORE_RE, _KQL_UNION_PAREN_RE):
            for m in pattern.finditer(statement):
                if m.group(1) not in KQL_KEYWORDS:
                    tables.add(m.group(1))
    tables -= locals_
    return {t for t in tables if t not in PLACEHOLDER_TABLES and not t.startswith("YOUR_")}


def grade(fixture: Fixture, answer: str, declared: set[str]) -> Result:
    r = Result()
    spec = fixture.spec
    code = fenced_blocks(answer)
    code_text = "\n".join(body for _, body in code)

    # Shape.
    order = find_sections(answer, declared)
    required = spec.get("sections", [])
    for name in required:
        if name not in declared:
            raise FixtureError(f"fixture {fixture.number} requires section '{name}' that no SKILL.md declares")
    missing = [s for s in required if s not in order]
    if missing:
        r.bad(f"missing section(s): {', '.join(missing)}")
    else:
        positions = [order.index(s) for s in required]
        if positions == sorted(positions):
            if required:
                r.ok(f"sections present in order: {', '.join(required)}")
        else:
            r.bad(f"sections out of order: wanted {required}, saw {[s for s in order if s in required]}")
    for name in spec.get("forbid_sections", []):
        if name in order:
            r.bad(f"forbidden section present: {name}")
        else:
            r.ok(f"no {name} section")

    # Literal and pattern assertions.
    for needle in spec.get("contains", []):
        (r.ok if needle in answer else r.bad)(f"contains {needle!r}")
    for needle in spec.get("not_contains", []):
        (r.bad if needle in answer else r.ok)(f"does not contain {needle!r}")
    for pattern in spec.get("matches", []):
        (r.ok if re.search(pattern, answer) else r.bad)(f"matches /{pattern}/")
    for pattern in spec.get("not_matches", []):
        (r.bad if re.search(pattern, answer) else r.ok)(f"no match for /{pattern}/")
    if spec.get("query_matches") or spec.get("query_not_matches"):
        queries = query_blocks(answer, declared, spec.get("query_lang"))
        if not queries:
            r.bad("no fenced block under a Query or Discovery query label"
                  + (f" in language {spec['query_lang']}" if spec.get("query_lang") else ""))
        else:
            for pattern in spec.get("query_matches", []):
                hit = any(re.search(pattern, q) for q in queries)
                (r.ok if hit else r.bad)(f"a query block matches /{pattern}/")
            for pattern in spec.get("query_not_matches", []):
                hit = any(re.search(pattern, q) for q in queries)
                (r.bad if hit else r.ok)(f"no query block matches /{pattern}/")
    for token in spec.get("assumed_if_used", []):
        if token in code_text:
            assumptions = section_body(answer, "Assumptions", declared)
            (r.ok if token in assumptions else r.bad)(f"{token} is used, so Assumptions must name it")
        else:
            r.ok(f"{token} not used")

    # Identifier discipline, read positionally from code blocks only: prose
    # may legitimately discuss an index it then declines to guess.
    if "indexes" in spec:
        allowed = set(spec["indexes"])
        invented = sorted(index_values(code_text) - allowed)
        (r.bad if invented else r.ok)(f"index names within {sorted(allowed)}" + (f": invented {invented}" if invented else ""))
    if "sourcetypes" in spec:
        allowed = set(spec["sourcetypes"])
        invented = sorted(sourcetype_values(code_text) - allowed)
        (r.bad if invented else r.ok)(f"sourcetypes within {sorted(allowed)}" + (f": invented {invented}" if invented else ""))
    if "tables" in spec:
        allowed = set(spec["tables"])
        seen: set[str] = set()
        for lang, body in code:
            if lang == "kql":
                seen |= kql_tables(body)
        invented = sorted(seen - allowed)
        (r.bad if invented else r.ok)(f"KQL tables within {sorted(allowed)}" + (f": invented {invented}" if invented else ""))

    # Generic rules, the same ones the validator holds the docs to.
    if spec.get("code_block", True):
        (r.ok if code else r.bad)("has a fenced code block")
    if _WHERE_BOOLEAN_RE.search(answer):
        r.bad("unquoted true/false in '| where' (silently matches nothing)")
    else:
        r.ok("no unquoted boolean in '| where'")
    for lang, body in code:
        first = next((ln.strip() for ln in body.splitlines() if ln.strip()), "")
        if lang == "spl" and spl_is_raw_event_search(body):
            (r.ok if spl_time_bound(body) else r.bad)(f"spl block is time-bound: {first[:60]}")
        # getschema reads metadata, not rows; there is nothing to bound.
        if lang == "kql" and "getschema" not in body:
            (r.ok if "TimeGenerated" in body else r.bad)(f"kql block bounds TimeGenerated: {first[:60]}")
    if asks_for_secret(answer):
        r.bad("asks the user to paste or provide a credential")
    else:
        r.ok("never asks for a credential in chat")
    return r


def report(fixture: Fixture, result: Result, verbose: bool = True) -> None:
    verdict = "PASS" if result.success else "FAIL"
    print(f"[{verdict}] fixture {fixture.number}: {fixture.title} ({fixture.skill})")
    if verbose:
        for msg in result.passed:
            print(f"    ok    {msg}")
    for msg in result.failed:
        print(f"    FAIL  {msg}")


def response_path(out_dir: str, number: int) -> str:
    return os.path.join(out_dir, f"{number:02d}.md")


def read_answer(path: str) -> str:
    with open(path, encoding="utf-8", newline="") as fh:
        return fh.read().replace("\r\n", "\n")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--fixture", type=int, help="fixture number to grade")
    ap.add_argument("--response", help="file holding the model's answer")
    ap.add_argument("--all", metavar="DIR", help="grade every NN.md found in DIR")
    ap.add_argument("--list", action="store_true", help="print each fixture's prompt and stop")
    ap.add_argument("--quiet", action="store_true", help="print only failures and verdicts")
    args = ap.parse_args(argv)

    fixtures = load_fixtures()
    if args.list:
        for f in fixtures:
            print(f"## {f.number}. {f.title}  [{f.skill}]\n{f.prompt}\n")
        return 0
    declared = declared_sections()

    targets: list[tuple[Fixture, str]] = []
    if args.all:
        for f in fixtures:
            p = response_path(args.all, f.number)
            if os.path.exists(p):
                targets.append((f, p))
        if not targets:
            print(f"no NN.md responses found in {args.all}", file=sys.stderr)
            return 2
    elif args.fixture and args.response:
        match = [f for f in fixtures if f.number == args.fixture]
        if not match:
            print(f"no fixture numbered {args.fixture}", file=sys.stderr)
            return 2
        targets.append((match[0], args.response))
    else:
        ap.error("give --fixture N --response FILE, or --all DIR, or --list")

    failures = 0
    for fixture, path in targets:
        result = grade(fixture, read_answer(path), declared)
        report(fixture, result, verbose=not args.quiet)
        failures += 0 if result.success else 1
    graded = len(targets)
    print(f"\n{graded - failures} of {graded} graded fixture(s) passed"
          + (f"; {len(fixtures) - graded} fixture(s) had no response file" if graded < len(fixtures) else ""))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
