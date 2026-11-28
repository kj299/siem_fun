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
  tables           every table a kql block references must be one of these
  tables_required  every one of these must be referenced by a kql block under
                   the Query or Discovery query label, wherever in the block it
                   sits: after a comment, after a let, indented inside one
  code_block       whether a fenced block is required at all (default true)
  never_block      names the answer must not recommend blocking, for a request
                   that asks which services to blocklist when the reference
                   says none of them (see block_recommendations)

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


# A request can ask which named services to blocklist when the reference says
# none of them. `never_block` names services the answer must not recommend
# blocking. A phrase the answer must contain ("none", "do not block") is not
# enough: "block the reseller; the LLM hosts are legitimate, so do not block
# those" contains it and still gives the recommendation. So the text is read
# clause by clause, and a clause that names one of the services together with
# a block word, and carries nothing that negates, defers or explains, counts.
_BLOCK_WORD_RE = re.compile(
    r"(?i)\b(?:block(?:s|ed|ing|list(?:ed|ing)?)?|deny(?:list(?:ed|ing)?)?|denied)\b"
)
_BLOCK_EXEMPT_RE = re.compile(
    r"(?i)(?:\b(?:"
    r"not|never|none|no|nor|neither|nothing|without|instead|rather"  # negates it
    r"|break|breaks|breaking"                 # says what blocking would cost
    r"|alert-only|alert only|off|out of"      # states the alternative
    r"|whether|unless|until|depends"          # defers the decision
    r"|which of"                              # restates the question asked
    r")\b|n't)"
)
# A period inside a host name is followed by a letter, not by a space, so
# splitting on a stop followed by whitespace leaves `webhook.site` whole.
_SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?;])\s+")
# Where one clause ends inside a sentence. A contrast ("but", "however") turns
# the advice around, and a reason ("since", "because") is not part of it: in
# "add X to the blocklist, since neither has a business use" the negation
# belongs to the reason and must not clear the advice. "and" splits only when
# a new instruction follows it, so the "and" inside a list of hosts does not.
_CLAUSE_SPLIT_RE = re.compile(
    r"(?i)\b(?:but|while|whereas|however|though|except|since|because)\b"
    r"|\band\b(?=\s+(?:do not|don't|never|leave|keep|alert|only|block|blocklist|deny|add)\b)"
)
_BULLET_RE = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s")
_BLOCKLIST_HEADING_RE = re.compile(r"(?i)\b(?:block|deny) ?list\b[^\n]*:\s*$")


def block_recommendations(text: str, names: list[str]) -> list[str]:
    """The clauses of `text` that recommend blocking one of `names`.

    Fenced blocks are skipped: a query that searches for a host is not advice
    about it. Two forms are read. A clause that names a service and a block
    word with no exempting word is one. The other is a list: a line that ends
    in a colon and mentions a blocklist, followed by bullets naming a service.

    This is a reading of prose, so it has limits, and they are deliberate
    misses rather than false alarms: advice given by pronoun ("block it"),
    and advice hedged with an exempting word ("block it unless someone uses
    it"), are not seen. A fixture using this key should say so in its prose.
    """
    lowered = [n.lower() for n in names]

    def names_one(s: str) -> bool:
        return any(n in s.lower() for n in lowered)

    offending: list[str] = []
    under_heading = False
    for line in _FENCE_RE.sub("", text).split("\n"):
        if not line.strip():
            continue
        if under_heading and _BULLET_RE.match(line):
            if names_one(line) and not _BLOCK_EXEMPT_RE.search(line):
                offending.append(line.strip())
                continue
        else:
            under_heading = bool(_BLOCKLIST_HEADING_RE.search(line)) and not _BLOCK_EXEMPT_RE.search(line)
        for sentence in _SENTENCE_SPLIT_RE.split(line):
            for clause in _CLAUSE_SPLIT_RE.split(sentence):
                if names_one(clause) and _BLOCK_WORD_RE.search(clause) and not _BLOCK_EXEMPT_RE.search(clause):
                    offending.append(clause.strip())
    return offending


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
    "assumed_if_used", "indexes", "sourcetypes", "tables", "tables_required",
    "code_block", "never_block",
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
# The head of a union statement: the keyword and its options. An option value
# never contains a space, a comma, a parenthesis or a pipe, so
# `union withsource=Table_ *` ends at the star and names no operand. An option
# NAME may carry a dot: `hint.concurrency` and `hint.spread` are documented
# union options, and a name read as \w+ stopped at the dot and reported `hint`
# as a table while the first real operand was never read.
_KQL_UNION_HEAD_RE = re.compile(r"\bunion\b(?:[ \t\r\n]+[A-Za-z_][\w.]*[ \t]*=[ \t]*[^\s,()|;]+)*")
# One union operand, bare or parenthesized, wherever the line breaks fall. The
# pack's own hunts write `union` alone on a line with the operands below it,
# and a pattern that wanted the first operand on the keyword's line read no
# table at all from that layout. A name followed by `(` is a function call and
# one followed by `=` is an option, so neither is an operand.
_KQL_OPERAND_RE = re.compile(r"[ \t\r\n]*(\()?[ \t\r\n]*([A-Za-z_][A-Za-z0-9_]*)\b(?![ \t]*[=(])")
# re.DOTALL so `join (` followed by the table on the NEXT line is still seen.
_KQL_JOIN_REF_RE = re.compile(r"\bjoin\b[^(\r\n]*\([ \t\r\n]*([A-Za-z_][A-Za-z0-9_]*)", re.S)
# `let recent = SigninLogs;` binds a table, and so does a let whose value
# starts on the next line or inside a parenthesis, which is how a model writes
# any let longer than one operator. The name the let binds is a local.
_KQL_LET_HEAD_RE = re.compile(r"let[ \t\r\n]+([A-Za-z_][A-Za-z0-9_]*)[ \t\r\n]*=")
# What a let's value opens with. A function call (`ago(`), a path
# (`InitiatedBy.user`), a typed parameter (`T:`), an index (`ids[0]`) and a
# string prefix (`h"..."`) are not tables.
_KQL_LET_SOURCE_RE = re.compile(r"""[ \t\r\n(]*([A-Za-z_][A-Za-z0-9_]*)\b(?![ \t]*[(.:\["'])""")
# What a tabular statement opens with. Any case, as the validator reads it: a
# table written in the wrong case (`auditlogs`) is exactly the claim the
# allowlist exists to catch, and reading capitals only let it through. A
# lower-case local (`hits | take 5`) is removed below with the other locals.
_KQL_LEAD_RE = re.compile(r"[ \t\r\n(]*([A-Za-z_][A-Za-z0-9_]*)\b(?![ \t]*\()")
# Operators that can stand where a table would, so they are never table names.
KQL_KEYWORDS = frozenset({
    "let", "union", "search", "find", "print", "range", "datatable",
    "externaldata", "materialize", "where", "set", "declare", "evaluate",
    # Literals a let can be bound to: `let strict = true;` names no table.
    "true", "false", "null",
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


# Fence labels that name the same language. Microsoft Learn fences KQL as
# `kusto`, so an answer that copies that label wrote KQL all the same, and
# every KQL rule keyed on the label `kql` read nothing from it: a `kusto` block
# with an invented table passed the `tables` allowlist and the TimeGenerated
# check.
_LANG_ALIASES = {"kusto": "kql"}


def fenced_blocks(text: str) -> list[tuple[str, str]]:
    """(language, body) for every fenced block, in order. The language is
    lower-cased and an alias is read as the language it names."""
    out = []
    for m in _FENCE_RE.finditer(text):
        lang = m.group(1).lower()
        out.append((_LANG_ALIASES.get(lang, lang), m.group(2)))
    return out


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


def _kql_statements(body: str) -> list[str]:
    """The statements of a kql block, with comments dropped and every string
    literal emptied.

    Statements end at a semicolon. Reading the block statement by statement is
    what finds the source of a query that follows a multi-line `let`: the
    first line that does not start with `let` is then the let's own body, not
    the query. Comments and string contents go because prose is not a query:
    `// union of both tables` named a table called `of`.
    """
    out: list[str] = []
    cur: list[str] = []
    i, n = 0, len(body)
    while i < n:
        ch = body[i]
        if ch in "\"'":
            verbatim = i > 0 and body[i - 1] == "@"
            j = i + 1
            while j < n and body[j] != ch and body[j] != "\n":
                j += 2 if (body[j] == "\\" and not verbatim) else 1
            cur.append('""')
            i = j + 1
        elif body.startswith("//", i):
            j = body.find("\n", i)
            i = n if j < 0 else j
        elif ch == ";":
            out.append("".join(cur))
            cur = []
            i += 1
        else:
            cur.append(ch)
            i += 1
    out.append("".join(cur))
    return [s for s in out if s.strip()]


def _union_operands(text: str) -> list[str]:
    """The names in operand position of the union statement starting at `text`.

    An operand is what follows the head or a comma, at parenthesis depth 0.
    Depth is what makes every half work: `union (A | take 5), (B | take 5)`
    keeps its inner pipes because they sit at depth 1, a function argument
    inside an operand (`isnotempty(IPAddress)`) is not at depth 0 and is not
    read, and `union A, B | summarize by X, Y` ends at the pipe so the
    summarize columns are not operands.
    """
    head = _KQL_UNION_HEAD_RE.match(text)
    names: list[str] = []
    i, depth, want = head.end(), 0, True
    while i < len(text):
        if want and depth == 0:
            want = False
            m = _KQL_OPERAND_RE.match(text, i)
            if m:
                names.append(m.group(2))
                depth = 1 if m.group(1) else 0
                i = m.end()
                continue
        ch = text[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        elif depth == 0 and ch == ",":
            want = True
        elif depth == 0 and ch == "|":
            break
        i += 1
    return names


def kql_tables(body: str) -> set[str]:
    """Every table a kql block references: the source of each statement, the
    value of each `let`, and `union` and `join` operands. Function calls
    (`let x = toscalar(...)`) and operators are not tables.

    Read statement by statement and whole-statement rather than a line at a
    time, because a join operand may sit on the line after its `(`, a union
    list may wrap or start on the line after the keyword, and a let's value
    may start on the line after its `=`.
    """
    tables: set[str] = set()
    # The names let statements bind. They are locals, not tables, so a later
    # `recent | take 5` must not be read as an uncatalogued table.
    locals_: set[str] = set()
    for statement in _kql_statements(body):
        statement = statement.strip()
        let = _KQL_LET_HEAD_RE.match(statement)
        if let:
            locals_.add(let.group(1))
            source = _KQL_LET_SOURCE_RE.match(statement, let.end())
        else:
            source = _KQL_LEAD_RE.match(statement)
        if source:
            tables.add(source.group(1))
        for u in _KQL_UNION_HEAD_RE.finditer(statement):
            tables.update(_union_operands(statement[u.start():]))
        for m in _KQL_JOIN_REF_RE.finditer(statement):
            tables.add(m.group(1))
    tables -= locals_
    return {t for t in tables
            if t not in KQL_KEYWORDS and t not in PLACEHOLDER_TABLES and not t.startswith("YOUR_")}


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

    if "tables_required" in spec:
        # The positive half of `tables`, read by the same reader. A pattern
        # anchored to the start of the block failed a correct answer that bound
        # a list with let first; one anchored to the start of any line fails an
        # indented one and cannot tell a table from a comment that names it.
        read: set[str] = set()
        for body in query_blocks(answer, declared, "kql"):
            read |= kql_tables(body)
        unread = sorted(set(spec["tables_required"]) - read)
        (r.bad if unread else r.ok)(f"a query block reads {sorted(spec['tables_required'])}"
                                    + (f": not read {unread}" if unread else ""))

    if spec.get("never_block"):
        offending = block_recommendations(answer, spec["never_block"])
        (r.bad if offending else r.ok)(
            f"never recommends blocking {sorted(spec['never_block'])}"
            + (f": {offending[0][:120]!r}" if offending else "")
        )

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
