#!/usr/bin/env python3
"""Mutation-check the repo's own test suites and the validator's checks.

    python3 scripts/tests/mutation-check.py

Three sections, all run against a scratch copy so the working tree is never
touched:

  [B] UNIT MUTATIONS - for each REGRESSION test, reintroduce the bug its
      docstring names and assert the suite goes red. A test that stays green
      when its bug returns proves nothing, and this repo has shipped several
      of those.

  [C] VALIDATOR CHECKS - the unit suite dot-sources the validator with
      -FunctionsOnly, which returns before any check executes, so the checks
      themselves have no unit coverage. Break the repo in the specific way each
      check exists to catch and assert the validator reports it. Two real holes
      were found in exactly this untested region.

  [D] ENVIRONMENT - conditions CI sees that a Linux dev box does not: a CRLF
      checkout, a UTF-8 BOM, a UTF-16 file, a wildcard filename, a relative
      -Root, and runtime.

Exit 0 means every mutation was caught. Add a case here whenever you add a
REGRESSION test; see NOT_MUTATABLE for the ones that deliberately have none.
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
WORK = os.path.join(tempfile.gettempdir(), "siem-fun-mutation-check")
SRC = "splunk-data-dictionary-builder/scripts/build_splunk_dictionary.py"
TESTS_PY = "splunk-data-dictionary-builder/tests/test_build_splunk_dictionary.py"
VAL = "scripts/validate-skill-pack.ps1"
BT = chr(96) * 3

fails: list[str] = []

# Every suite below runs once per mutation. The WAF engine suites start two web
# servers and take half a minute where the engines are installed, and they are
# not what any mutation here is aimed at: the static tests in the same file are.
os.environ["WAF_ENGINES_SKIP"] = "1"

# Tests that cannot be mutation-checked, and why. Listed so the gap is explicit
# rather than looking like an oversight.
NOT_MUTATABLE = {
    "the engine suites of test_waf_engines.py":
        "they need Apache, nginx, the Core Rule Set and tclsh, which the Windows "
        "runner this harness runs on does not have, so they are skipped here (see "
        "WAF_ENGINES_SKIP above). WAF_MUTS below mutates the rule file against the "
        "static tests of the same module, which need no engine. The engine suites "
        "were mutation-checked by hand, each rule defect put back in turn; the "
        "list and the result are in QUERY_SKILL_PLAN.md",
    "tolerates YAML shapes the old regex parser rejected":
        "asserts ConvertFrom-Yaml's own behaviour; there is no repo code to break",
    "returns null for a non-dictionary value":
        "the IDictionary guard can be removed without any current caller passing a "
        "non-dictionary, so no mutation makes it fail (kept as documentation)",
    "a reader of shared-rule-cases.json that asserts nothing":
        "deleting an assertion makes a suite PASS, and every mutation here asserts "
        "a suite goes RED, so no mutation can catch a reader that parses the corpus "
        "and then compares nothing. The corpus is instead proved load-bearing by "
        "gutting its case lists, which the readers' non-empty guards catch, and the "
        "RULES it covers are proved by mutating the two tools themselves",
}


def sh(cmd: str, cwd: str = WORK) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, cwd=cwd)


PY_EXE = f'"{sys.executable}"'


def unittest_green(stderr: str) -> bool:
    """True when unittest's verdict line says every test that ran passed.

    The line is "OK", or "OK (skipped=N)" when a suite skipped something. The
    WAF engine tests skip wherever Apache, nginx and tclsh are not installed,
    which includes the Windows runner this harness runs on; reading only a
    bare trailing "OK" would call that a failure, and then every mutation
    below would be CAUGHT by a suite that was never green to begin with.
    """
    lines = stderr.strip().splitlines()
    return bool(lines) and re.fullmatch(r"OK(?: \(skipped=\d+\))?", lines[-1]) is not None


def py_suite() -> str:
    r = sh(f"{PY_EXE} -m unittest discover -s splunk-data-dictionary-builder/tests")
    return "OK" if unittest_green(r.stderr) else "FAILED"


GRADER = "scripts/grade_golden_output.py"


def grader_suite() -> str:
    r = sh(f'{PY_EXE} -m unittest discover -s scripts/tests -p "test_*.py"')
    return "OK" if unittest_green(r.stderr) else "FAILED"


def ps_suite() -> str:
    r = sh("pwsh -NoProfile -File ./scripts/tests/validate-skill-pack.tests.ps1")
    for line in r.stdout.splitlines():
        if "passed," in line:
            return line.strip()
    return "<none>"


def validator() -> str:
    r = sh(f"pwsh -NoProfile -File ./{VAL}")
    return "PASSED" if "validation passed" in r.stdout else "FAILED"


def validator_output() -> str:
    return sh(f"pwsh -NoProfile -File ./{VAL}").stdout


def edit(path: str, old: str, new: str) -> bool:
    p = os.path.join(WORK, path)
    t = open(p).read()
    if t.count(old) != 1:
        return False
    open(p, "w").write(t.replace(old, new, 1))
    return True


def _force_writable(func, path, _exc) -> None:
    """rmtree error hook: clear the read-only bit and retry.

    Git marks files under .git read-only, and on Windows a read-only file cannot
    be unlinked -- which is why the scratch directory must not be removed with
    the errors ignored.
    """
    os.chmod(path, stat.S_IWRITE)
    func(path)


def _rmtree(path: str) -> None:
    """Remove a tree and PROVE it is gone.

    Never silence the errors here: on Windows that left the directory in place,
    so the next copytree failed with FileExistsError several cases later, far
    from the cause.
    """
    if not os.path.exists(path):
        return
    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=_force_writable)
    else:
        shutil.rmtree(path, onerror=_force_writable)
    if os.path.exists(path):
        raise RuntimeError(f"could not remove scratch directory {path}")


def fresh() -> None:
    """Rebuild WORK from the pristine repo.

    Not `git checkout -- .`: that restores from the INDEX, so a case that staged
    a file leaked state into the next one and made a check report the wrong
    answer.
    """
    _rmtree(WORK)
    shutil.copytree(REPO, WORK)
    sh("git add -A && git -c user.email=t@t -c user.name=t commit -qm mutation-base")


def unit_mutation(label: str, path: str, old: str, new: str, suite) -> None:
    fresh()
    if not edit(path, old, new):
        print(f"  SETUP-FAIL     {label}")
        fails.append(f"setup: {label}")
        return
    res = suite()
    caught = res in ("FAILED",) or (res != "<none>" and "passed," in res and not res.endswith(", 0 failed"))
    print(f"  {'CAUGHT ' if caught else '*** MISSED ***'} {label}")
    if not caught:
        fails.append(label)


def _tree_fingerprint() -> str:
    """Content hash of the scratch tree, used to prove a breaker did something.

    Hashes contents, not sizes: a same-length edit (a case flip, say) leaves
    every size identical and would look like a breaker that did nothing.
    """
    h = hashlib.sha256()
    for root, dirs, files in os.walk(WORK):
        dirs[:] = [d for d in dirs if d != ".git"]
        for fn in sorted(files):
            fp = os.path.join(root, fn)
            try:
                h.update(os.path.relpath(fp, WORK).encode())
                h.update(open(fp, "rb").read())
            except OSError:
                pass
    return h.hexdigest()


# Counts for the summary line. Derived, not hand-maintained: a literal here goes
# stale the moment a check is added, and the summary is the only line a reader
# skims to see how much ran.
run_counts = {"validator": 0, "environment": 0, "notice": 0}

# Every expect_text passed to check_mutation, used by section [E] to prove that
# no validator check shipped without a mutation behind it.
expect_texts: list[str] = []

# Add-Issue messages that deliberately have no mutation of their own, and why.
# Keep this small: an entry here is a check nothing proves fires.
UNMUTATED_MESSAGES = {
    "$RelativePath is missing $Description":
        "generic Assert-Contains template; every caller is covered by its own "
        "mutation (## Inputs, the frontmatter shape, the 'Do not use' clause)",
}

# Messages whose literal text is too generic to match a mutation automatically,
# mapped to the mutation that DOES cover them. Section [E] asserts each named
# mutation actually ran, so this cannot become a way to wave a check through.
COVERED_BY_NAME = {
    "$($entry.Path) is missing $($entry.Section).$($entry.Key)":
        "helper missing invocation.preferred_prompt entirely",
}

# Labels of the mutations that ran, for the COVERED_BY_NAME assertion above.
ran_labels: list[str] = []


TEXT_EXTENSIONS = ("md", "yaml", "yml", "json", "ps1", "py", "txt", "example")


def convert_line_endings(to_crlf: bool) -> None:
    """Rewrite every text file in the scratch tree to one line ending.

    A file that will not decode as UTF-8 is left alone: the non-ASCII mutation
    plants a byte on purpose, and rewriting it would destroy what is under test.
    Anything named .git* is skipped, including the .git-hidden left behind by the
    git-ls-files mutation, so a conversion never walks into object storage.
    """
    for root, dirs, files in os.walk(WORK):
        dirs[:] = [d for d in dirs if not d.startswith(".git")]
        for fn in files:
            if fn.rsplit(".", 1)[-1] not in TEXT_EXTENSIONS:
                continue
            path = os.path.join(root, fn)
            try:
                # newline="" reads without translation, so a CRLF checkout
                # arrives as \r\n rather than already-normalised \n.
                text = open(path, newline="").read()
            except (OSError, UnicodeDecodeError):
                continue
            text = text.replace("\r\n", "\n")
            with open(path, "w", newline=("\r\n" if to_crlf else "\n")) as fh:
                fh.write(text)


def check_mutation(label: str, breaker, expect_text: str) -> None:
    """Break the repo, then assert the validator reports it AND says why.

    Run under BOTH line endings, explicitly normalised, rather than under
    whatever the checkout happens to use. Otherwise the harness silently tests
    a different thing on each platform: a Linux dev box only ever exercises LF,
    and a check whose pattern ends in a bare '$' is a no-op on CRLF while every
    local mutation still passes. That shipped -- the fixture-shape check did
    nothing on Windows and only CI could see it.

    The breaker's effect is verified: an edit() whose pattern was ambiguous
    returns False and changes nothing, which would otherwise read as a MISSED
    check against an unmodified repo rather than as the harness bug it is.
    """
    run_counts["validator"] += 1
    expect_texts.append(expect_text)
    ran_labels.append(label)
    fresh()
    before = _tree_fingerprint()
    breaker()
    if _tree_fingerprint() == before:
        print(f"  SETUP-FAIL     {label}  (breaker changed nothing)")
        fails.append(f"setup: {label}")
        return

    missed = []
    for ending, to_crlf in (("LF", False), ("CRLF", True)):
        convert_line_endings(to_crlf)
        out = validator_output()
        failed = "validation passed" not in out
        named = expect_text.lower() in out.lower()
        if not (failed and named):
            missed.append(f"{ending}(failed={failed} named={named})")
    if missed:
        print(f"  *** MISSED *** {label}  {' '.join(missed)}")
        fails.append(f"{label} [{' '.join(missed)}]")
    else:
        print(f"  CAUGHT  {label}")


def check_notice(label: str, breaker, expect_text: str) -> None:
    """Break the repo in a way the validator must NOTICE but must not FAIL.

    The golden-run freshness check is the one finding that is deliberately a
    notice: the fix is a model run a pull request's CI cannot perform. So the
    assertion is the inverse of check_mutation's on the verdict -- "validation
    passed" must still appear -- while the reason must still be named, under
    both line endings like every other validator mutation.
    """
    run_counts["notice"] += 1
    ran_labels.append(label)
    fresh()
    before = _tree_fingerprint()
    breaker()
    if _tree_fingerprint() == before:
        print(f"  SETUP-FAIL     {label}  (breaker changed nothing)")
        fails.append(f"setup: {label}")
        return
    missed = []
    for ending, to_crlf in (("LF", False), ("CRLF", True)):
        convert_line_endings(to_crlf)
        out = validator_output()
        passed = "validation passed" in out
        named = expect_text.lower() in out.lower()
        if not (passed and named):
            missed.append(f"{ending}(passed={passed} named={named})")
    if missed:
        print(f"  *** MISSED *** {label}  {' '.join(missed)}")
        fails.append(f"{label} [{' '.join(missed)}]")
    else:
        print(f"  NOTICED {label}")


print("=" * 74)
print("MUTATION CHECK")
print("=" * 74)
fresh()

print("\n[A] BASELINE AT HEAD")
# Assert the baseline, do not merely print it. A mutation is judged CAUGHT when
# the suite turns red, so a suite that is ALREADY red makes every mutation
# against it look caught and can still exit 0. Abort instead: with a red
# baseline every result below is meaningless, not merely suspect.
_v, _ps, _py, _gr = validator(), ps_suite(), py_suite(), grader_suite()
print(f"  validator      : {_v}")
print(f"  powershell     : {_ps}")
print(f"  python         : {_py}")
print(f"  grader         : {_gr}")
_baseline = []
if _v != "PASSED":
    _baseline.append(f"validator not green at baseline ({_v})")
if not (_ps.endswith(", 0 failed") and _ps[0].isdigit()):
    _baseline.append(f"powershell suite not green at baseline ({_ps})")
if _py != "OK":
    _baseline.append(f"python suite not green at baseline ({_py})")
if _gr != "OK":
    _baseline.append(f"grader suite not green at baseline ({_gr})")
if _baseline:
    print("\n" + "=" * 74)
    print("ABORTING: baseline is not green, so no mutation result would mean anything.")
    for b in _baseline:
        print(f"  - {b}")
    sys.exit(1)

print("\n[B] UNIT MUTATIONS - each REGRESSION test vs the bug it names")
PY_MUTS = [
    ("max-sourcetypes sampling slice",
     "    for row in sourcetypes[: args.max_sourcetypes]:",
     "    for row in sourcetypes:"),
    ("ipv6 brackets preserved in redaction",
     '        if ":" in host:', '        if False:'),
    ("redaction fails closed on unparseable url",
     '        return "<redacted-unparseable-url>"', '        return url'),
    ("leading hyphen rejected as SPL identifier",
     'r"[A-Za-z0-9_][A-Za-z0-9_-]*"', 'r"[A-Za-z0-9_-]+"'),
    ("trailing newline rejected (fullmatch not $)",
     "    if _SAFE_IDENT_RE.fullmatch(value):",
     '    if re.match(r"^[A-Za-z0-9_][A-Za-z0-9_-]*$", value):'),
    ("env_bool / _content_flag share polarity",
     "    if isinstance(value, str):\n        return parse_bool(value, False)",
     '    if isinstance(value, str):\n        return value.strip().lower() not in {"0", "false", "no"}'),
    ("_content_flag treats '0' as false",
     "    if isinstance(value, str):\n        return parse_bool(value, False)",
     "    if isinstance(value, str):\n        return bool(value)"),
    ("env_bool empty == unset",
     "    if value is None or not value.strip():", "    if value is None:"),
    ("ERROR/FATAL search messages collected",
     '        if isinstance(message, dict) and message.get("type") in {"ERROR", "FATAL"}:',
     '        if False:'),
    ("non-object JSON attribute warns",
     "    if value is not None and warnings is not None:", "    if False:"),
    ("malformed JSON attribute warns",
     '            if warnings is not None:\n                warnings.append(f"Could not parse JSON for {context!r}: {error}; skipping")\n',
     ""),
    ("blank attribute is unset, not malformed",
     "        if not value.strip():\n            # Blank means the attribute is unset, not malformed. Warning here",
     "        if False:\n            # Blank means the attribute is unset, not malformed. Warning here"),
    ("CIM hint prefix needs a separator (no superstring match)",
     '        if key == prefix or (key.startswith(prefix) and key[len(prefix)] in ":-_"):',
     "        if key.startswith(prefix):"),
    ("sourcetype discovery sorts by volume",
     " | sort 0 - count", ""),
    ("oneshot count=0 (no silent 100-row cap)",
     '                "count": "0",\n', ""),
    ("non-UTF-8 body -> RuntimeError",
     '                raw = response.read()\n            try:\n                body = raw.decode("utf-8")\n                return json.loads(body)',
     '                raw = response.read()\n                body = raw.decode("utf-8")\n            try:\n                return json.loads(body)'),
    ("transport read failure -> RuntimeError",
     "        except (OSError, http.client.HTTPException) as error:\n            # urllib only wraps connect-phase failures in URLError. Reading the",
     "        except (ZeroDivisionError,) as error:\n            # urllib only wraps connect-phase failures in URLError. Reading the"),
    ("HTTPError body read guarded",
     '            except (OSError, http.client.HTTPException) as read_error:\n                body = f"<error body unreadable: {read_error!r}>"',
     '            except (ZeroDivisionError,) as read_error:\n                body = f"<error body unreadable: {read_error!r}>"'),
]
for label, old, new in PY_MUTS:
    unit_mutation(label, SRC, old, new, py_suite)

PS_MUTS = [
    ("binning re-admitted as a time bound",
     # bin(_time, "1h") groups events without restricting the window, so a
     # search carrying it still scans all retained history. Both tools listed
     # it as a predicate until a review caught it; shared-rule-cases.json holds
     # the case, and the grader has the mirror mutation.
     "$script:splTimePredicateRegex = '(?i)(\\bearliest[ \\t]*=|\\blatest[ \\t]*=|_time[ \\t]*(?:>=|<=|<|>|=)|(?:>=|<=|<|>)[ \\t]*_time)'",
     "$script:splTimePredicateRegex = '(?i)(\\bearliest[ \\t]*=|\\blatest[ \\t]*=|_time[ \\t]*(?:>=|<=|<|>|=)|(?:>=|<=|<|>)[ \\t]*_time|\\bbin[ \\t]*\\([ \\t]*_time)'"),
    ("union statement depth guard",
     # Without the depth test the statement ends at the first pipe, including
     # one INSIDE a parenthesized subquery operand, so
     # 'union (A | take 5), (B | take 5)' loses B. The grader has the mirror
     # mutation; shared-rule-cases.json holds the case both are checked against.
     "        } elseif ($depth -eq 0 -and $ch -ceq [char]'|') {",
     "        } elseif ($ch -ceq [char]'|') {"),
    # The statement-by-statement reader of 2026-11-28, mirrored from GRADER_MUTS: each puts
    # back one way the line-oriented reader missed a table or invented one.
    ("validator: the KQL source is read statement by statement, past any let",
     "    foreach ($raw in (Get-KqlStatements $Body)) {",
     "    foreach ($raw in @($Body)) {"),
    ("validator: a union operand on the line after the keyword is a table reference",
     "$script:kqlOperandRegex   = [regex]'\\G[ \\t\\r\\n]*(\\()?[ \\t\\r\\n]*",
     "$script:kqlOperandRegex   = [regex]'\\G[ \\t]*(\\()?[ \\t]*"),
    ("validator: comments are not read for tables",
     "        } elseif ($ch -ceq [char]'/' -and $i + 1 -lt $n -and $Body[$i + 1] -ceq [char]'/') {",
     "        } elseif ($false) {"),
    ("validator: a let bound to a literal names no table",
     '    "true", "false", "null"\n',
     '    "zzz-none"\n'),
    # P2V-6: the three reader mutations GRADER_MUTS carried with no PowerShell counterpart.
    ("validator: string contents are not read for tables",
     "            $null = $cur.Append('\"\"')",
     "            $null = $cur.Append($Body.Substring($i, [Math]::Min($j + 1, $n) - $i))"),
    ("validator: a let whose value starts on the next line binds a table",
     "$script:kqlLetSourceRegex = [regex]'\\G[ \\t\\r\\n(]*",
     "$script:kqlLetSourceRegex = [regex]'\\G[ \\t(]*"),
    ("validator: a let bound to a parenthesized query binds a table",
     "$script:kqlLetSourceRegex = [regex]'\\G[ \\t\\r\\n(]*",
     "$script:kqlLetSourceRegex = [regex]'\\G[ \\t\\r\\n]*"),
    # P2V-5 and P2V-4, each mirrored in GRADER_MUTS.
    ("validator: a union option name may carry a dot",
     "$script:kqlUnionHeadRegex = [regex]'\\bunion\\b(?:[ \\t\\r\\n]+[A-Za-z_][\\w.]*[ \\t]*=",
     "$script:kqlUnionHeadRegex = [regex]'\\bunion\\b(?:[ \\t\\r\\n]+\\w+[ \\t]*="),
    ("validator: a fence label is read lower-cased",
     "        $lang = $m.Groups['lang'].Value.Trim().ToLowerInvariant()",
     "        $lang = $m.Groups['lang'].Value.Trim()"),
    ("validator: a block fenced kusto is read as kql",
     "        if ($lang -ceq 'kusto') {",
     "        if ($false) {"),
    ("conflict-marker regex CRLF anchor",
     r"""$script:conflictMarkerRegex = '(?m)^(<{7}( |\r?$)|={7}\r?$|>{7}( |\r?$))'""",
     r"""$script:conflictMarkerRegex = '(?m)^(<{7}( |$)|={7}$|>{7}( |$))'"""),
    ("fenced-block regex CRLF anchor",
     r"""$script:fencedBlockRegex    = '(?ms)^[ \t]*""" + BT + r""".*?^[ \t]*""" + BT + r"""[ \t]*\r?$'""",
     r"""$script:fencedBlockRegex    = '(?ms)^\s*""" + BT + r""".*?^\s*""" + BT + r"""[ \t]*$'"""),
    ("where-boolean regex",
     r"""$script:whereBooleanRegex   = '(?i)\|[ \t]*where\b[^|\r\n]*=[ \t]*(true|false)\b'""",
     r"""$script:whereBooleanRegex   = '(?i)ZZZNEVERMATCHES'"""),
    ("where-boolean line-anchored regex",
     r"""$script:whereBooleanLineRegex = '(?im)^[ \t]*\|[ \t]*where\b[^|\r\n]*=[ \t]*(true|false)\b'""",
     r"""$script:whereBooleanLineRegex = '(?im)^ZZZNEVERMATCHES'"""),
    ("Read-Text uses -LiteralPath",
     "        $raw = Get-Content -Raw -LiteralPath $path",
     "        $raw = Get-Content -Raw -Path $path"),
    ("Read-Text returns '' for a missing file",
     "    if (Test-Path -LiteralPath $path -PathType Leaf) {",
     "    if ($true) {"),
    ("Read-Text returns '' for an empty file",
     "        if ($null -ne $raw) {\n            $text = $raw\n        }",
     "        $text = $raw"),
    ("Get-YamlList distinguishes declared-empty from absent",
     "    if ($sectionValue -isnot [System.Collections.IDictionary] -or -not $sectionValue.Contains($Key)) {",
     "    if ($null -eq (Get-MapValue $sectionValue $Key)) {"),
    ("Assert-ListsEqual is case-sensitive",
     "    if ($leftText -cne $rightText) {", "    if ($leftText -ne $rightText) {"),
    ("Assert-ListsEqual reports absent-on-both-sides",
     '        Add-Issue "Helper drift: $Name is declared in neither file"\n        return',
     "        return"),
    ("Assert-Contains is case-sensitive",
     "    if ($text -cnotmatch $Pattern) {", "    if ($text -notmatch $Pattern) {"),
    ("golden-run marker: files must BE a map, not merely present",
     # Review finding on the shipped check. The first version accepted any
     # files value that existed and was non-null, so valid JSON carrying an
     # array, a string or a number passed the guard; enumerating its members
     # then yields a recorded set nothing matches, which turns a malformed
     # marker into an ordinary freshness notice.
     '    if ($null -eq $marker -or $marker.files -isnot [System.Management.Automation.PSCustomObject]) {',
     '    if ($null -eq $marker -or -not ($marker.PSObject.Properties.Name -contains "files") -or $null -eq $marker.files) {'),
    ("invalid YAML is reported as an issue",
     '            Add-Issue "$RelativePath is not valid YAML: $($_.Exception.Message)"',
     "            $null = $_"),
]
for label, old, new in PS_MUTS:
    unit_mutation(label, VAL, old, new, ps_suite)

# The golden-prompt grader applies the validator's rules to model OUTPUT, so a
# grader check that silently stopped firing would let a bad answer pass the
# behavioral half while the structural half still reported green. Each entry
# disables one check; the grader suite must go red.
GRADER_MUTS = [
    ("grader: binning re-admitted as a time bound",
     '    r"|(?:>=|<=|<|>)[ \\t]*_time)"',
     '    r"|(?:>=|<=|<|>)[ \\t]*_time|\\bbin[ \\t]*\\([ \\t]*_time)"'),
    ("grader: unquoted where-boolean check",
     r'_WHERE_BOOLEAN_RE = re.compile(r"(?i)\|[ \t]*where\b[^|\r\n]*=[ \t]*(true|false)\b")',
     r'_WHERE_BOOLEAN_RE = re.compile(r"ZZZNEVERMATCHES")'),
    ("grader: raw-event spl block needs a time bound",
     '        if lang == "spl" and spl_is_raw_event_search(body):',
     "        if False:"),
    ("grader: a leading-pipe '| search' is still a raw-event search",
     '_SPL_NON_GENERATING_LEAD = frozenset({"search"})',
     "_SPL_NON_GENERATING_LEAD = frozenset()"),
    ("grader: _time mentioned but not compared is not a time bound",
     '    r"|(?:>=|<=|<|>)[ \\t]*_time)"',
     '    r"|(?:>=|<=|<|>)[ \\t]*_time|\\b_time\\b)"'),
    ("grader: a KQL table bound by let is a table reference",
     "            source = _KQL_LET_SOURCE_RE.match(statement, let.end())",
     "            source = None"),
    ("grader: a parenthesized union operand is a table reference",
     '_KQL_OPERAND_RE = re.compile(r"[ \\t\\r\\n]*(\\()?[ \\t\\r\\n]*([A-Za-z_][A-Za-z0-9_]*)\\b(?![ \\t]*[=(])")',
     '_KQL_OPERAND_RE = re.compile(r"[ \\t\\r\\n]*(ZZZ)?[ \\t\\r\\n]*([A-Za-z_][A-Za-z0-9_]*)\\b(?![ \\t]*[=(])")'),
    ("grader: a union statement is not ended by a pipe inside its parentheses",
     '        elif depth == 0 and ch == "|":',
     '        elif ch == "|":'),
    ("grader: a KQL join operand on the next line is a table reference",
     '_KQL_JOIN_REF_RE = re.compile(r"\\bjoin\\b[^(\\r\\n]*\\([ \\t\\r\\n]*([A-Za-z_][A-Za-z0-9_]*)", re.S)',
     '_KQL_JOIN_REF_RE = re.compile(r"\\bjoin\\b[^(\\r\\n]*\\([ \\t]*([A-Za-z_][A-Za-z0-9_]*)")'),
    # The reader of TST-1 (second retrospective, 2026-11-28): the shipped one read no table from
    # a union whose operands start on the next line, and took a multi-line let's own body for
    # the query's source, so a fixture's allowlist passed answers reading an unlisted table.
    ("grader: the KQL source is read statement by statement, past any let",
     "    for statement in _kql_statements(body):",
     "    for statement in [body]:"),
    ("grader: a union operand on the line after the keyword is a table reference",
     '_KQL_OPERAND_RE = re.compile(r"[ \\t\\r\\n]*(\\()?[ \\t\\r\\n]*([A-Za-z_][A-Za-z0-9_]*)\\b(?![ \\t]*[=(])")',
     '_KQL_OPERAND_RE = re.compile(r"[ \\t]*(\\()?[ \\t]*([A-Za-z_][A-Za-z0-9_]*)\\b(?![ \\t]*[=(])")'),
    ("grader: a let whose value starts on the next line binds a table",
     '_KQL_LET_SOURCE_RE = re.compile(r"""[ \\t\\r\\n(]*',
     '_KQL_LET_SOURCE_RE = re.compile(r"""[ \\t(]*'),
    ("grader: a let bound to a parenthesized query binds a table",
     '_KQL_LET_SOURCE_RE = re.compile(r"""[ \\t\\r\\n(]*',
     '_KQL_LET_SOURCE_RE = re.compile(r"""[ \\t\\r\\n]*'),
    ("grader: comments are not read for tables",
     '        elif body.startswith("//", i):',
     "        elif False:"),
    ("grader: string contents are not read for tables",
     "            cur.append('\"\"')",
     "            cur.append(body[i:j + 1])"),
    ("grader: a let bound to a literal names no table",
     '    "true", "false", "null",\n',
     ""),
    ("grader: a leading table in the wrong case is read",
     '_KQL_LEAD_RE = re.compile(r"[ \\t\\r\\n(]*([A-Za-z_][A-Za-z0-9_]*)\\b(?![ \\t]*\\()")',
     '_KQL_LEAD_RE = re.compile(r"[ \\t\\r\\n(]*([A-Z][A-Za-z0-9_]*)\\b(?![ \\t]*\\()")'),
    ("grader: tables_required is applied when a spec names it",
     '        unread = sorted(set(spec["tables_required"]) - read)',
     "        unread = []"),
    ("grader: a block fenced kusto is read as kql",
     '_LANG_ALIASES = {"kusto": "kql"}',
     "_LANG_ALIASES = {}"),
    ("grader: a fence label is read lower-cased",
     "        lang = m.group(1).lower()",
     "        lang = m.group(1)"),
    ("grader: a union option name may carry a dot",
     '_KQL_UNION_HEAD_RE = re.compile(r"\\bunion\\b(?:[ \\t\\r\\n]+[A-Za-z_][\\w.]*[ \\t]*=',
     '_KQL_UNION_HEAD_RE = re.compile(r"\\bunion\\b(?:[ \\t\\r\\n]+\\w+[ \\t]*='),
    ("grader: placeholders and wildcards are not identifier claims",
     '    return value.startswith(("YOUR_", "<")) or value == "..." or "*" in value',
     "    return False"),
    ("grader: section order enforced",
     "        if positions == sorted(positions):",
     "        if True:"),
    ("grader: labels inside fenced blocks ignored",
     '    stripped = _FENCE_RE.sub("", text)',
     "    stripped = text"),
    ("grader: credential-paste check",
     '    r"(?i)\\b(paste|share|send|provide|enter|type)\\b[^.\\n]{0,60}\\b(token|password|secret|credential|api key)"',
     '    r"ZZZNEVERMATCHES"'),
    ("grader: CRLF answers normalised before grading",
     '        return fh.read().replace("\\r\\n", "\\n")',
     "        return fh.read()"),
    ("grader: query block read from under the Query label, not the first fence",
     '    for label in ("Query", "Discovery query"):\n        body = section_body(text, label, declared)',
     '    for label in ("Query", "Discovery query"):\n        body = text'),
    ("grader: a fixture with no spec is an error",
     "        if len(specs) != 1:",
     "        if len(specs) > 1:"),
    # never_block reads prose for advice to block a named service. Read a
    # sentence at a time it is fooled by the very answer it exists for, one
    # that refuses some hosts and recommends blocking others in one sentence.
    ("grader: never_block reads clause by clause, so a refusal elsewhere in the sentence does not clear it",
     "            for clause in _CLAUSE_SPLIT_RE.split(sentence):",
     "            for clause in [sentence]:"),
    ("grader: never_block is applied when a spec names it",
     '        offending = block_recommendations(answer, spec["never_block"])',
     "        offending = []"),
    ("grader: never_block exempts a clause that negates, defers or explains",
     "                if names_one(clause) and _BLOCK_WORD_RE.search(clause) and not _BLOCK_EXEMPT_RE.search(clause):",
     "                if names_one(clause) and _BLOCK_WORD_RE.search(clause):"),
]
for label, old, new in GRADER_MUTS:
    unit_mutation(label, GRADER, old, new, grader_suite)

# The recorder is the path a run by subagents must take, and it is the only
# writer of the marker the freshness notice reads. A check that stopped firing
# here would let a partial or failing run silence the notice, which is worse
# than no notice: the tree would claim a behavioral baseline it never had.
RECORDER = "scripts/record_golden_run.py"

RECORDER_MUTS = [
    ("recorder: a partial or failing run is refused",
     "    if not full_pass(args.result):",
     "    if False:"),
    ("recorder: the result must cover EVERY fixture, not just agree with itself",
     "    return passed == graded == total",
     "    return passed == graded"),
    ("recorder: the whole result string is the subject, not a prefix of it",
     # `$` in a Python regex also matches before a trailing newline, so an
     # anchored search accepts more than it looks like it does; a prefix match
     # accepts "10 of 10" followed by anything at all.
     '    m = re.fullmatch(r"\\s*(\\d+)\\s+of\\s+(\\d+)\\s*", result)',
     '    m = re.match(r"\\s*(\\d+)\\s+of\\s+(\\d+)", result)'),
]
for label, old, new in RECORDER_MUTS:
    unit_mutation(label, RECORDER, old, new, grader_suite)

# The runner's exit code is the golden-run job's only signal: 1 opens an issue
# naming a fixture failure, 2 fails the job as a setup problem. An uncaught
# exception that reaches Python's own exit 1 turns a missing credential into a
# fixture failure, which is what filed a bogus issue every week.
RUNNER = "scripts/run_golden_prompts.py"

RUNNER_MUTS = [
    ("runner: a crash before grading exits 2, not the graded-failure 1",
     "        traceback.print_exc()\n        return 2",
     "        raise"),
]
for label, old, new in RUNNER_MUTS:
    unit_mutation(label, RUNNER, old, new, grader_suite)

# The ModSecurity rule file. Each mutation puts back a defect that shipped and
# that an engine found; the static REGRESSION tests in test_waf_engines.py must
# go red with no engine installed, because this harness runs where there is none.
WAF_CONF = "examples/agentic-ai-attacks/waf/modsecurity-agentic.conf"

WAF_MUTS = [
    ("waf: a doubled backslash in a pattern (the file did not load on v2)",
     'SecRule ARGS_GET|ARGS_POST "@rx \\.\\.(?:/|\\x5c)"',
     'SecRule ARGS_GET|ARGS_POST "@rx \\.\\.[/\\\\]"'),
    ("waf: no counter collection opened ahead of the deny rules",
     'SecAction "id:9907100,phase:1,pass,nolog,initcol:resource=agt_%{REMOTE_ADDR}"',
     'SecAction "id:9907100,phase:1,pass,nolog"'),
    ("waf: counters in the collection the Core Rule Set keys on the User-Agent",
     "initcol:resource=agt_%{REMOTE_ADDR}",
     "initcol:ip=%{REMOTE_ADDR}"),
    ("waf: a counter re-arms its own expiry on every hit (sliding window)",
     "setvar:resource.agt_err=+1,setvar:tx.agt_err_hit=1",
     "setvar:resource.agt_err=+1,expirevar:resource.agt_err=60,setvar:tx.agt_err_hit=1"),
    ("waf: a counter whose window is never armed",
     '    SecRule RESOURCE:AGT_DENIED "@eq 1" "expirevar:resource.agt_denied=120"',
     '    SecRule RESOURCE:AGT_DENIED "@eq 1" "t:none"'),
    ("waf: a denying rule that does not feed the repeat-violator counter",
     '"id:9907004,phase:2,deny,status:403,log,setvar:tx.agt_deny=1,',
     '"id:9907004,phase:2,deny,status:403,log,'),
    ("waf: the sign-up limit refuses every request, not only sign-ups",
     'SecRule TX:AGT_SIGNUP_HIT "@eq 1" \\\n'
     "    \"id:9907107,phase:2,deny,status:429,log,msg:'W-AGT-032 self-registration rate',tag:'agentic-ai',chain\"\n"
     '    SecRule RESOURCE:AGT_SIGNUP "@gt 3"',
     'SecRule RESOURCE:AGT_SIGNUP "@gt 3" \\\n'
     "    \"id:9907107,phase:2,deny,status:429,log,msg:'W-AGT-032 self-registration rate',tag:'agentic-ai'\""),
    ("waf: a path rule that matches the path as sent",
     '"id:9907021,phase:1,deny,status:404,log,setvar:tx.agt_deny=1,t:none,t:urlDecodeUni,',
     '"id:9907021,phase:1,deny,status:404,log,setvar:tx.agt_deny=1,t:none,'),
    ("waf: the XML rule reads the media type case-sensitively",
     '"id:9907009,phase:2,deny,status:403,log,t:none,t:lowercase,chain,',
     '"id:9907009,phase:2,deny,status:403,log,chain,'),
    ("waf: the Core Rule Set blocking rule edited to count its blocks",
     "#SecRule TX:ANOMALY_SCORE \"@ge %{tx.inbound_anomaly_score_threshold}\" \\\n"
     '#    "id:9907160,phase:5,pass,nolog,setvar:tx.agt_deny=1"',
     'SecRuleUpdateActionById 949110 "setvar:tx.agt_deny=1"'),
    ("waf: the ARTEX name pattern loses its right boundary",
     "(?:^|[^a-z])artex(?:$|[^a-z]|probe|bot)",
     "(?:^|[^a-z])artex"),
]
for label, old, new in WAF_MUTS:
    unit_mutation(label, WAF_CONF, old, new, grader_suite)

# The Splunk saved searches. One shape is checkable without a Splunk: a doubled
# dollar sign, which savedsearches.conf reads as an escaped dollar.
SAVED_SEARCHES = "examples/agentic-ai-attacks/splunk-savedsearches.conf"

DETECTION_MUTS = [
    ("detections: a regex ending in an escaped dollar and an anchor",
     'substr(ServiceName, -1)!=dollar',
     'NOT match(ServiceName, "\\$$")'),
]
for label, old, new in DETECTION_MUTS:
    unit_mutation(label, SAVED_SEARCHES, old, new, grader_suite)

# The indicator sweep (R-D-AGT-012), its two lookup files, and the schedule every saved search
# keeps. Each mutation puts back a defect that shipped: the sweep matched an indicator address
# only as a destination, low-confidence shared egress would have been matched inbound, the
# lookups were held to iocs.csv by nothing, and nine rules read a window longer than they ran.
SENTINEL_RULES = "examples/agentic-ai-attacks/sentinel-rules.yaml"
SWEEP_LOOKUP = "examples/agentic-ai-attacks/lookups/agt_iocs.csv"
SWEEP_WATCHLIST = "examples/agentic-ai-attacks/lookups/sentinel_watchlist.csv"
HUNTS = "examples/agentic-ai-attacks/hunting.kql"

SWEEP_MUTS = [
    ("sweep: no leg matches an indicator address as the source of an authentication",
     SAVED_SEARCHES, "rename ioc AS Authentication.src | fields Authentication.src", "rename ioc AS Authentication.dest | fields Authentication.dest"),
    ("sweep: a low-confidence shared-egress address is matched as a web source",
     SAVED_SEARCHES, 'where ioc_type="ipv4" AND confidence!="low" | rename ioc AS Web.src', 'where ioc_type="ipv4" | rename ioc AS Web.src'),
    ("sweep (Sentinel): low-confidence rows raise a High alert again",
     SENTINEL_RULES, '      | where Confidence != "low";\n', "      ;\n"),
    ("sweep (Sentinel): service principal sign-ins are not read",
     SENTINEL_RULES, "      (AADServicePrincipalSignInLogs\n", "      (SigninLogs\n"),
    ("sweep lookup: a row's confidence drifts from iocs.csv",
     SWEEP_LOOKUP, "nginxmysql.com,domain,high,", "nginxmysql.com,domain,medium,"),
    ("sweep lookup: the Splunk file and the Sentinel watchlist differ",
     SWEEP_WATCHLIST, "nginxmysql.com,domain,high,BLOODALCHEMY C2 (VAPOR PANDA)", "nginxmysql.com,domain,high,BLOODALCHEMY C2"),
    ("sweep lookup: a row the rule has no leg for (an application ID) is carried",
     SWEEP_LOOKUP, "nginxmysql.com,domain,high,", "506e08f9-6e9a-4da4-942b-a099a03644ae,entra_app_id,high,x,Microsoft 2026-10-21 Storm-0940\nnginxmysql.com,domain,high,"),
    ("hunt H-AGT-016: a published application ID is not watched",
     HUNTS, ', "412dcf96-176d-4b3a-a1b0-4981ad66971e"]);', "]);"),
    ("schedule: a per-event rule reads further back than it runs",
     SAVED_SEARCHES, "dispatch.earliest_time = -20m@m\ndispatch.latest_time   = -5m@m\nsearch = index=<ZAMMAD_INDEX>", "dispatch.earliest_time = -30m@m\ndispatch.latest_time   = -5m@m\nsearch = index=<ZAMMAD_INDEX>"),
    ("schedule: a time bound typed in the search disagrees with the stanza",
     SAVED_SEARCHES, 'sourcetype=<ZAMMAD_SOURCETYPE> earliest=-20m@m "ERROR', 'sourcetype=<ZAMMAD_SOURCETYPE> earliest=-30m@m "ERROR'),
    ("schedule: a rule listed as sliding no longer overlaps",
     SAVED_SEARCHES, "dispatch.earliest_time = -70m@m\ndispatch.latest_time   = -10m@m\nsearch = index=<AAD_INDEX> sourcetype=<AAD_SP_SIGNIN_SOURCETYPE>", "dispatch.earliest_time = -25m@m\ndispatch.latest_time   = -10m@m\nsearch = index=<AAD_INDEX> sourcetype=<AAD_SP_SIGNIN_SOURCETYPE>"),
]
for label, path, old, new in SWEEP_MUTS:
    unit_mutation(label, path, old, new, grader_suite)

# The unscheduled Splunk hunts, the other query files, the reference and the Navigator layer
# (second retrospective, 2026-11-28). Before these, the tests added for the hunts had no mutation,
# and the REGRESSION dollar-sign test had been extended to a file no mutation touched: reverting
# it to read the saved searches only left the harness green. Each mutation is one defect the
# suite let through, or one way a check could stop firing.
SPLUNK_HUNTS = "examples/agentic-ai-attacks/splunk-hunting.conf"
MORPHEUS = "examples/agentic-ai-attacks/splunk-morpheus-native.conf"
AGENTIC_DOC = "splunk-sentinel-query-builder/references/agentic-ai-attacks.md"
AGENTIC_LAYER = "examples/agentic-ai-attacks/attack-navigator-layer.json"
IOCS_CSV = "examples/agentic-ai-attacks/iocs.csv"
AKAMAI = "examples/agentic-ai-attacks/waf/akamai-custom-rules.json"
H033 = " ATT&CK T1552, T1530.\nenableSched            = 0\n"
H033_END = "| sort 0 -secret_searches -calls\n"

ASSET_MUTS = [
    ("hunts: a Splunk hunt whose number has no Sentinel hunt",
     SPLUNK_HUNTS, "[H-AGT-044 - Certificate requests", "[H-AGT-046 - Certificate requests"),
    ("hunts: one hunt number on two stanzas",
     SPLUNK_HUNTS, "[H-AGT-033 - CloudWatch Logs", "[H-AGT-032 - CloudWatch Logs"),
    ("hunts: a stanza wearing another hunt's title",
     SPLUNK_HUNTS, "[H-AGT-033 - CloudWatch Logs searched for secrets]", "[H-AGT-033 - Self-registration traded for AWS credentials]"),
    ("hunts: a hunt left scheduled",
     SPLUNK_HUNTS, H033, H033.replace("= 0", "= 1")),
    ("hunts: a second enableSched after the first, which wins",
     SPLUNK_HUNTS, H033, H033 + "enableSched            = 1\n"),
    ("hunts: an alert action on a hunt",
     SPLUNK_HUNTS, H033, H033 + "action.email = 1\n"),
    ("hunts: a hunt with no time range, which searches all time",
     SPLUNK_HUNTS, H033 + "dispatch.earliest_time = -14d@d\n", H033),
    ("hunts: a hunt that writes what it finds to an index",
     SPLUNK_HUNTS, H033_END, H033_END.rstrip("\n") + " \\\n| collect index=agt_hunts\n"),
    ("hunts: a hunt that writes a CSV",
     SPLUNK_HUNTS, H033_END, H033_END.rstrip("\n") + " \\\n| outputcsv agt_hunt_033\n"),
    ("hunts: a description that names no ATT&CK technique",
     SPLUNK_HUNTS, " ATT&CK T1552, T1530.", ""),
    ("hunts: a description citing an ID that ATT&CK v20 revoked",
     SPLUNK_HUNTS, "ATT&CK T1518.001, T1685.", "ATT&CK T1518.001, T1562.001."),
    ("hunts: a search line that lost its continuation backslash",
     SPLUNK_HUNTS, "| bin _time span=1h \\\n| stats count AS calls sum(at_limit)", "| bin _time span=1h\n| stats count AS calls sum(at_limit)"),
    ("hunts: a backslash after the last line of a search",
     SPLUNK_HUNTS, H033_END, H033_END.rstrip("\n") + " \\\n"),
    ("hunts: two dollar signs on one line of a hunt",
     SPLUNK_HUNTS, "| where secret_searches > 0 OR", '| where match(actor, "\\$$") OR secret_searches > 0 OR'),
    ("hunts: a placeholder the header does not declare",
     SPLUNK_HUNTS, "search = index=<AWS_INDEX> sourcetype=aws:cloudtrail eventName=FilterLogEvents",
     "search = index=<CLOUD_INDEX> sourcetype=aws:cloudtrail eventName=FilterLogEvents"),
    ("hunts: a novelty hunt whose 30 days are set only by the stanza",
     SPLUNK_HUNTS, 'source="XmlWinEventLog:Security" earliest=-30d@d EventCode', 'source="XmlWinEventLog:Security" EventCode'),
    ("hunts: a process name dropped from the Splunk side of H-AGT-036",
     SPLUNK_HUNTS, 'datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("w3wp.exe","httpd","httpd.exe","apache2","nginx","nginx.exe","lighttpd","java","java.exe","jspawnhelper","node",',
     'datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("w3wp.exe","httpd","httpd.exe","apache2","nginx","nginx.exe","lighttpd","java","java.exe","node",'),
    ("hunts: a threshold changed on the Splunk side of H-AGT-035",
     SPLUNK_HUNTS, "| where services >= 10 AND regions >= 4", "| where services >= 10 AND regions >= 3"),
    ("hunts: a stats BY actor that can be null",
     SPLUNK_HUNTS, "'initiatedBy.app.displayName', \"(unknown)\"), src = ", "'initiatedBy.app.displayName'), src = "),
    ("hunts: the H-AGT-044 template pattern differs from the KQL one",
     SPLUNK_HUNTS, "(?<template>[^\\s<&]+)", "(?<template>[^\\s]+)"),
    ("hunts: a sort on a time already turned into text",
     SPLUNK_HUNTS, "| sort 0 +first_seen \\\n| convert ctime(first_seen) ctime(last_seen)",
     "| convert ctime(first_seen) ctime(last_seen) \\\n| sort 0 +first_seen"),
    ("hunts (KQL): one union leg reads all retention",
     HUNTS, '  (DeviceRegistryEvents | where TimeGenerated > ago(30d)\n', '  (DeviceRegistryEvents\n'),
    ("hunts (KQL): a table on the union's own line is not catalogued",
     HUNTS, 'AWSCloudTrail\n| where TimeGenerated > ago(14d) and EventName == "FilterLogEvents"',
     'union AWSCloudtrail, AWSCloudTrail\n| where TimeGenerated > ago(14d) and EventName == "FilterLogEvents"'),
    ("hunts (KQL): file events read whatever their action",
     HUNTS, '     | where ActionType in ("FileCreated", "FileModified", "FileRenamed")\n     | where FolderPath has "ld.so.preload"',
     '     | where FolderPath has "ld.so.preload"'),
    ("hunts (KQL): the workspace ID counted as a tenant",
     HUNTS, "Regions = dcount(AWSRegion), Sources = make_set(SourceIpAddress, 5), UserAgents",
     "Regions = dcount(TenantId), Sources = make_set(SourceIpAddress, 5), UserAgents"),
    ("hunts (KQL): a comparison cast to a number",
     HUNTS, 'iff(ProcessCommandLine contains "nmap", 1, 0)', 'toint(ProcessCommandLine contains "nmap")'),
    # Second retrospective, pass 2 (P2V-2, P2V-3, P2H-01, P2H-02, P2W-04, R1-D1).
    ("hunts (KQL): an unbounded union leg on the line of the previous operand",
     HUNTS, 'Signal = "run value SystemUpdate", Detail = RegistryValueData)\n',
     'Signal = "run value SystemUpdate", Detail = RegistryValueData), (AzureActivity | project TimeGenerated, DeviceName = Caller, Signal = "x", Detail = "x")\n'),
    ("tests: the table registry drops a name with a digit",
     "scripts/tests/test_agentic_ai_attacks.py", 'r"^\\| `([A-Za-z_][A-Za-z0-9_]*)` \\|"', 'r"^\\| `([A-Za-z_]+)` \\|"'),
    ("hunts: a novelty hunt of 2026-11-28 whose 30 days are set only by the stanza",
     SPLUNK_HUNTS, 'where earliest=-30d@d Processes.parent_process_name="sqlservr.exe"', 'where Processes.parent_process_name="sqlservr.exe"'),
    ("rules: GSocket's saved names dropped from R-D-AGT-025 while H-AGT-030 keeps them",
     SAVED_SEARCHES, '"gs-dbus","gs-db","defunct",', ""),
    ("rules: the gsocket command-line term dropped from R-D-AGT-025",
     SAVED_SEARCHES, ' OR Processes.process="*gsocket*"', ""),
    ("hunts: an nc image dropped from the Splunk port check of H-AGT-039",
     SPLUNK_HUNTS, 'in(pname, "nc", "ncat", "netcat", "nc.openbsd", "nc.traditional", "busybox")',
     'in(pname, "nc", "ncat", "netcat", "nc.openbsd", "nc.traditional")'),
    ("hunts (KQL): the H-AGT-039 port check needs two spaces before -z again",
     HUNTS, '(nc|ncat|netcat)(\\.[a-z]+)?\\s"\n', '(nc|ncat|netcat)(\\.[a-z]+)?\\s.*\\s-[a-z]*z"\n'),
    ("rules: R-D-AGT-014's artx- pattern differs between the platforms",
     SAVED_SEARCHES, 'match(evidence, "(?i)(^|[^a-z0-9])artx-[a-z0-9]")', 'match(evidence, "(?i)artx-(guard|ngx)")'),
    ("rules: a threshold changed on the Splunk side of R-D-AGT-017",
     SAVED_SEARCHES, "(t_api - t_spec) <= 120 AND api_urls >= 5", "(t_api - t_spec) <= 120 AND api_urls >= 3"),
    ("iocs: a block row read only at second hand",
     IOCS_CSV, "nginxmysql.com,ARTEX,BLOODALCHEMY C2 (VAPOR PANDA),CrowdStrike 2026-10-29 VAPOR PANDA,https://www.crowdstrike.com/en-us/blog/vapor-panda-uses-artex-to-scale-global-campaign/,high,block + retro-hunt 90d,verified-in-source",
     "nginxmysql.com,ARTEX,BLOODALCHEMY C2 (VAPOR PANDA),CrowdStrike 2026-10-29 VAPOR PANDA,https://www.crowdstrike.com/en-us/blog/vapor-panda-uses-artex-to-scale-global-campaign/,high,block + retro-hunt 90d,reported-secondary"),
    ("waf (Akamai): W-AGT-008 matches index.php and info.php again",
     AKAMAI, '"i0??",', '"i???",'),
    ("waf (Akamai): the SSRF canary dropped from W-AGT-004b",
     AKAMAI, '"*metadata.google.internal*",\n              "*_i??_probe_missing*",', '"*metadata.google.internal*",\n              "*_i??_probe_missig*",'),
    ("detections: two dollar signs on an indented subsearch line",
     SAVED_SEARCHES, "  [| tstats summariesonly=true count min(_time) AS first_time from datamodel=Network_Resolution.DNS ",
     '  [| tstats summariesonly=true count min(_time) AS first_time from datamodel=Network_Resolution.DNS where NOT match(ioc, "\\$$") '),
    ("detections: a scheduled search with no time range",
     SAVED_SEARCHES, "dispatch.earliest_time = -25m@m\ndispatch.latest_time   = -10m@m\nalert.suppress         = 1\nalert.suppress.fields  = dest,process_name\n",
     "dispatch.latest_time   = -10m@m\nalert.suppress         = 1\nalert.suppress.fields  = dest,process_name\n"),
    ("detections: a saved search that lost a continuation backslash",
     SAVED_SEARCHES, "| lookup agt_host_roles.csv host_key AS dest OUTPUT role \\\n", "| lookup agt_host_roles.csv host_key AS dest OUTPUT role\n"),
    ("morpheus: two dollar signs on a search line",
     MORPHEUS, '| where match(lower(parent_image_path), "(w3wp|', '| where match(dst_ip, "\\$$") AND match(lower(parent_image_path), "(w3wp|'),
    ("morpheus: one stanza name used twice",
     MORPHEUS, "[R-C-AGT-003-M - New TLS client then regular calls to an LLM API]", "[R-B-AGT-005-M - Novel child of a web server process]"),
    ("morpheus: a per-event rule reads further back than it runs",
     MORPHEUS, "dispatch.earliest_time = -20m@m\ndispatch.latest_time   = -10m@m", "dispatch.earliest_time = -25m@m\ndispatch.latest_time   = -10m@m"),
    ("reference: the Splunk hunts file is not named",
     AGENTIC_DOC, "[splunk-hunting.conf](../../examples/agentic-ai-attacks/splunk-hunting.conf)", "the Splunk hunts file"),
    ("reference: a technique row dropped from the table while the layer keeps it",
     AGENTIC_DOC, "| T1611 | ", "| T1611x | "),
    ("reference: a technique under a tactic ATT&CK does not give it",
     AGENTIC_DOC, "| T1611 | Escape to Host | Privilege Escalation |", "| T1611 | Escape to Host | Execution |"),
    ("reference: a technique name that is not the catalogue's",
     AGENTIC_DOC, "| T1611 | Escape to Host |", "| T1611 | Container Escape |"),
    ("layer: a technique the reference table does not carry",
     AGENTIC_LAYER, '"techniqueID": "T1611"', '"techniqueID": "T1612"'),
    ("layer: built against an ATT&CK version that has the old IDs",
     AGENTIC_LAYER, '"attack": "20"', '"attack": "17"'),
    # Caught by test_layer_matches_the_doc_table as well as test_v20_renames_are_used: any
    # layer-only change breaks the first, so a one-file mutation proves the pair, not the second.
    ("layer: an ID that ATT&CK v20 no longer has",
     AGENTIC_LAYER, '"techniqueID": "T1574.001"', '"techniqueID": "T1574.002"'),
]
for label, path, old, new in ASSET_MUTS:
    unit_mutation(label, path, old, new, grader_suite)


def function_mutation(label: str, breaker, suite) -> None:
    """unit_mutation for a defect one text replacement cannot express: two files changed together
    so that only the check under test sees a difference, or a JSON edit that must not depend on the
    numbers the file happens to hold today."""
    fresh()
    if not breaker():
        print(f"  SETUP-FAIL     {label}")
        fails.append(f"setup: {label}")
        return
    res = suite()
    caught = res == "FAILED"
    print(f"  {'CAUGHT ' if caught else '*** MISSED ***'} {label}")
    if not caught:
        fails.append(label)


def _edit_layer(change) -> bool:
    import json as _json
    path = os.path.join(WORK, AGENTIC_LAYER)
    layer = _json.load(open(path))
    change(layer)
    _json.dump(layer, open(path, "w"), indent=1)
    return True


def _bump_meta(layer, name, by):
    for m in layer["metadata"]:
        if m["name"] == name:
            m["value"] = str(int(m["value"]) + by)


def _context_drift() -> bool:
    # Both lookups changed alike, so only the comparison with iocs.csv can see it.
    import csv as _csv
    import io as _io
    for rel in (SWEEP_LOOKUP, SWEEP_WATCHLIST):
        p = os.path.join(WORK, rel)
        raw = open(p, newline="").read()
        rows = list(_csv.reader(_io.StringIO(raw)))
        if len(rows) < 2:
            return False
        rows[1][3] += " (stale)"
        buf = _io.StringIO()
        _csv.writer(buf, lineterminator="\r\n" if "\r\n" in raw else "\n").writerows(rows)
        open(p, "w", newline="").write(buf.getvalue())
    return True


def _duplicate_table_row() -> bool:
    p = os.path.join(WORK, AGENTIC_DOC)
    text = open(p).read()
    m = re.search(r"^\| T1611 \|.*\n", text, re.M)
    if not m:
        return False
    open(p, "w").write(text[:m.end()] + m.group(0) + text[m.end():])
    return True


def _score_above_its_sources(layer) -> None:
    # The score and the total move together, so only the per-row check sees it.
    t = layer["techniques"][0]
    extra = len(t["comment"].split("Sources: ", 1)[1].split("; ")) + 1 - t["score"]
    t["score"] += extra
    _bump_meta(layer, "evidence_rows", extra)
    layer["gradient"]["maxValue"] = max(x["score"] for x in layer["techniques"])


FUNCTION_MUTS = [
    ("lookups: a context that drifted from iocs.csv in both lookups", _context_drift),
    ("reference: one technique row written twice", _duplicate_table_row),
    ("layer: evidence_rows is no longer the sum of the scores",
     lambda: _edit_layer(lambda l: _bump_meta(l, "evidence_rows", 1))),
    ("layer: the gradient's top is not the highest score",
     lambda: _edit_layer(lambda l: l["gradient"].update(maxValue=l["gradient"]["maxValue"] + 1))),
    ("layer: one technique listed twice",
     lambda: _edit_layer(lambda l: l["techniques"].append(dict(l["techniques"][0])))),
    ("layer: a comment that is not its table row",
     lambda: _edit_layer(lambda l: l["techniques"][0].update(comment=l["techniques"][0]["comment"] + " x"))),
    ("layer: a score above the sources its row names",
     lambda: _edit_layer(_score_above_its_sources)),
]
for label, breaker in FUNCTION_MUTS:
    function_mutation(label, breaker, grader_suite)

# The shared rule corpus, and the two readers that consume it. Kept separate
# from the lists above because these mutations target the TEST files and the
# corpus itself rather than one tool's source, so each carries its own path and
# its own suite.
#
# What they prove is that the corpus is load-bearing. A reader that parses the
# file and then compares nothing, or a corpus emptied of its cases, would leave
# both suites green while the two implementations were free to diverge again --
# which is the exact state this file was added to end.
PS_TESTS = "scripts/tests/validate-skill-pack.tests.ps1"
GRADER_TESTS = "scripts/tests/test_grade_golden_output.py"
CORPUS = "scripts/tests/shared-rule-cases.json"

# The corpus's own cases are proved load-bearing by GUTTING the data, not by
# weakening a reader: a mutation that deletes an assertion makes a suite pass,
# and every mutation here asserts a suite goes red. See NOT_MUTATABLE for that
# gap, which is a property of mutation testing rather than of this corpus.
PS_TESTS = "scripts/tests/validate-skill-pack.tests.ps1"
GRADER_TESTS = "scripts/tests/test_grade_golden_output.py"
CORPUS = "scripts/tests/shared-rule-cases.json"


def _empty_the_corpus() -> None:
    """Strip the corpus to one case each and assert both readers notice.

    Emptied rather than deleted: a missing file is already a $requiredFiles
    failure, while a file that still parses and simply asserts almost nothing
    is the quiet version of the same loss.
    """
    import json as _json
    path = os.path.join(WORK, CORPUS)
    data = _json.load(open(path))
    data["kql_tables"] = data["kql_tables"][:1]
    data["spl_time_bound"] = data["spl_time_bound"][:1]
    data["fence_language"] = data["fence_language"][:1]
    _json.dump(data, open(path, "w"), indent=2)


for label, suite in (("corpus: gutted case lists fail the python reader", grader_suite),
                     ("corpus: gutted case lists fail the powershell reader", ps_suite)):
    fresh()
    _empty_the_corpus()
    res = suite()
    caught = res == "FAILED" or (res != "<none>" and "passed," in res and not res.endswith(", 0 failed"))
    print(f"  {'CAUGHT ' if caught else '*** MISSED ***'} {label}")
    if not caught:
        fails.append(label)

for name, why in NOT_MUTATABLE.items():
    print(f"  (skipped)      {name}\n                 reason: {why}")

print("\n[C] VALIDATOR CHECKS - break the repo, assert the validator says why")


def write(rel: str, data: bytes) -> None:
    with open(os.path.join(WORK, rel), "wb") as fh:
        fh.write(data)


def append(rel: str, text: str) -> None:
    with open(os.path.join(WORK, rel), "a") as fh:
        fh.write(text)


def append_bytes(rel: str, data: bytes) -> None:
    """Append raw bytes. Used for the non-ASCII case: writing a literal
    non-ASCII character in THIS file would itself break the repo's ASCII rule
    (the validator caught exactly that while this script was being written)."""
    with open(os.path.join(WORK, rel), "ab") as fh:
        fh.write(data)


def rm(rel: str) -> None:
    os.remove(os.path.join(WORK, rel))


check_mutation("missing required file",
               lambda: rm("splunk-sentinel-query-builder/references/model-guidance.md"),
               "Missing required file")
check_mutation("SKILL.md missing '## Inputs'",
               lambda: write("splunk-enrichment-query-builder/SKILL.md",
                             open(os.path.join(WORK, "splunk-enrichment-query-builder/SKILL.md")).read()
                             .replace("## Inputs", "## Not Inputs").encode()),
               "is missing Inputs section")
check_mutation("conflict marker in a tracked file",
               lambda: append("README.md", "\n<<<<<<< HEAD\nx\n"),
               "conflict marker")
check_mutation("non-ASCII byte in a tracked file",
               lambda: append_bytes("README.md", b"\ncaf\xc3\xa9\n"),
               "non-ASCII or control byte")
MDOC = "splunk-enrichment-query-builder/references/multi-index-patterns.md"
check_mutation("unquoted SPL where-boolean in markdown",
               lambda: append(MDOC, "\n| where noise=true\n"),
               "unquoted true/false")
# The three forms that evaded the original line-anchored, case-sensitive check.
# Each has the identical silent-no-match bug in SPL, so each is a real defect.
check_mutation("unquoted where-boolean mid-line in a fenced block",
               lambda: append(MDOC, f"\n{BT}spl\nindex=foo | where noise=true\n{BT}\n"),
               "unquoted true/false")
check_mutation("unquoted where-boolean with an uppercase value",
               lambda: append(MDOC, f"\n{BT}spl\n| where riot=TRUE\n{BT}\n"),
               "unquoted true/false")
check_mutation("unquoted where-boolean inside a markdown table cell",
               # Query text in a table is an inline code span, not a fenced
               # block. splunk-to-kql-mapping.md is written entirely this way,
               # so a fence-only scanner skips that file completely.
               lambda: append(MDOC, "\n| SPL | Note |\n| --- | --- |\n"
                                    f"| {BT[0]}index=a | where noise=true{BT[0]} | x |\n"),
               "unquoted true/false")


def _undocument_lookup_field(field: str) -> None:
    """Drop one field from EVERY documented list for greynoise_indicators.

    The documented set is the union over every line naming the lookup, so
    removing the field from a single row proves nothing -- the other row still
    covers it.
    """
    p = os.path.join(WORK, "splunk-enrichment-query-builder/references/greynoise-integration.md")
    # Read before opening for write: open(p, "w") truncates, so passing an
    # inline read as the write argument silently produces an empty file.
    text = open(p).read()
    token = f"{BT[0]}{field}{BT[0]}, "
    assert text.count(token) >= 2, f"expected {field} in both documented rows"
    open(p, "w").write(text.replace(token, ""))


def _strip_layout_tree(rel: str) -> None:
    """Remove the siem_fun/ layout tree block entirely.

    Deleting the tree must fail rather than silence the check, or the easiest
    way past a stale-tree failure would be to delete the tree.
    """
    p = os.path.join(WORK, rel)
    text = open(p).read()
    stripped = re.sub(r"```text\n(siem_fun/.*?)```", "(tree removed)\n", text, flags=re.S)
    assert stripped != text, f"no layout tree found in {rel}"
    open(p, "w").write(stripped)


def _drop_golden_fixtures(skill: str) -> None:
    """Remove every mention of one skill from golden-prompts.md.

    The check asks whether the skill is named at all, so deleting a single
    fixture heading would leave the other mentions covering it.
    """
    p = os.path.join(WORK, "examples/golden-prompts.md")
    text = open(p).read()
    assert skill in text, f"{skill} is not mentioned in golden-prompts.md"
    open(p, "w").write(text.replace(skill, "some-other-skill"))


def _drop_yaml_section(rel: str, header: str) -> None:
    """Delete a top-level YAML block: its header line and every indented line
    under it, stopping at the next line that starts in column zero."""
    p = os.path.join(WORK, rel)
    lines = open(p).read().splitlines(keepends=True)
    start = next(i for i, ln in enumerate(lines) if ln.startswith(header))
    end = start + 1
    while end < len(lines) and (lines[end].startswith((" ", "\t")) or not lines[end].strip()):
        end += 1
    open(p, "w").write("".join(lines[:start] + lines[end:]))


check_mutation("lookup OUTPUT field absent from the documented field list",
               lambda: _undocument_lookup_field("classification"),
               "documented field list")
check_mutation("three or more bare index= terms chained with OR",
               lambda: append(MDOC, f"\n{BT}spl\nindex=a OR index=b OR index=c earliest=-24h\n{BT}\n"),
               "bare index= terms with OR")
check_mutation("raw-event SPL search with no time bound",
               lambda: append(MDOC, f"\n{BT}spl\nindex=firewall sourcetype=cisco:asa\n| stats count by src\n{BT}\n"),
               "no time bound")
check_mutation("SKILL.md name that does not match its directory",
               # Skills are loaded by this name, so a mismatch is a live routing
               # break. The frontmatter check validates only the name's shape.
               lambda: edit("splunk-enrichment-query-builder/SKILL.md",
                            "name: splunk-enrichment-query-builder",
                            "name: wrong-name"),
               "does not match its directory")
check_mutation(".env removed from .gitignore",
               lambda: edit(".gitignore", "\n.env\n", "\n"),
               "no bare '.env' entry")
# Split so this file does not itself trip the check it is testing.
_AWS_KEY = "AKIA" + "ABCDEFGHIJKLMNOP"
check_mutation("committed credential shape in a tracked file",
               lambda: append("README.md", f"\n{_AWS_KEY}\n"),
               "credentials must never be committed")
check_mutation("uncatalogued sourcetype in a reference doc",
               lambda: append(MDOC, f"\n{BT}spl\nindex=foo sourcetype=acme:invented:product\n| head 5\n{BT}\n"),
               "never invent Splunk identifiers")
KDOC = "splunk-sentinel-query-builder/references/query-workflow.md"
check_mutation("reference file absent from a helper's references map",
               # The pair-parity check only proves the two helpers agree; both
               # were equally wrong about sentinel-table-catalog.md for two days.
               lambda: edit("splunk-sentinel-query-builder/agents/claude-opus.yaml",
                            '  sentinel_table_catalog: "../references/sentinel-table-catalog.md"\n', ""),
               "does not list references/")
check_mutation("helper listing a reference file that does not exist",
               lambda: edit("splunk-sentinel-query-builder/agents/codex-gpt-5.4.yaml",
                            "../references/model-guidance.md", "../references/ghost.md"),
               "which does not exist")
check_mutation("tracked file absent from the layout trees",
               # CLAUDE.md requires updating both trees when a file is added,
               # and required-checks.txt was missing from both for a day.
               lambda: (write("splunk-sentinel-query-builder/references/brand-new.md", b"# new\n"),
                        sh("git add -A")),
               "layout tree does not mention")
check_mutation("layout tree deleted outright",
               lambda: _strip_layout_tree("README.md"),
               "no siem_fun/ layout tree")
check_mutation("markdown table row with an unescaped pipe in a cell",
               # GFM splits the row on it even inside an inline code span, so the
               # cell count no longer matches the header. Two rows of
               # splunk-to-kql-mapping.md shipped this way.
               lambda: append(KDOC, "\n| A | B |\n| --- | --- |\n"
                                    f"| x | {BT[0]}count() by f | top{BT[0]} |\n"),
               "malformed table row")
check_mutation("uncatalogued Sentinel table in a KQL block",
               lambda: append(KDOC, f"\n{BT}kql\nInventedTable\n| where TimeGenerated > ago(1d)\n{BT}\n"),
               "never invent Sentinel identifiers")
check_mutation("Sentinel table named with the wrong casing",
               # KQL table names are case-sensitive: SignInLogs is a different,
               # non-existent table to SigninLogs and returns nothing. The
               # catalogue shipped with the wrong casing in a prose mention.
               lambda: append(KDOC, f"\n{BT}kql\nSignInLogs\n| where ResultType == 0\n{BT}\n"),
               "never invent Sentinel identifiers")
check_mutation("uncatalogued Sentinel table in a block fenced kusto",
               # P2V-4: the grader read a kusto fence as KQL and the validator
               # tested the raw label with -ceq "kql", so this block was read by
               # no KQL rule. Microsoft Learn fences KQL this way.
               lambda: append(KDOC, f"\n{BT}kusto\nInventedTable\n| where TimeGenerated > ago(1d)\n{BT}\n"),
               "never invent Sentinel identifiers")
check_mutation("uncatalogued Sentinel table in a block fenced KQL",
               lambda: append(KDOC, f"\n{BT}KQL\nInventedTable\n| where TimeGenerated > ago(1d)\n{BT}\n"),
               "never invent Sentinel identifiers")
check_mutation("invented colon-free sourcetype in query position",
               # Exactly the shape the token check never saw: WinEventLog,
               # fgt_traffic and 12 more real sourcetypes share it, so an
               # invented one passed. Verified passing before this check existed.
               lambda: append(MDOC, f"\n{BT}spl\nindex=foo sourcetype=made_up_source earliest=-24h\n| stats count\n{BT}\n"),
               "not a catalogued sourcetype of any shape")
check_mutation("invented hyphenated sourcetype in query position",
               lambda: append(MDOC, f"\n{BT}spl\nindex=foo sourcetype=also-invented-web earliest=-24h\n| stats count\n{BT}\n"),
               "not a catalogued sourcetype of any shape")
check_mutation("a catalogued SOURCE written as a sourcetype",
               # okta:im2 is in the catalogue, in the source column, next to
               # its real sourcetype OktaIM2:log. The first positional check
               # accepted any colon token from the registry files and so let
               # this through; reviewed as a P1 after it merged.
               lambda: append(MDOC, f"\n{BT}spl\nindex=foo sourcetype=okta:im2 earliest=-24h\n| stats count\n{BT}\n"),
               "not a catalogued sourcetype of any shape")
CATALOG = "splunk-enrichment-query-builder/references/splunkbase-app-catalog.md"


def _swap_catalogue_sourcetype_column() -> None:
    """Relabel the catalogue's Sourcetype column as Source, and vice versa.

    The positional registry reads the column the catalogue LABELS Sourcetype,
    so this moves XmlWinEventLog out of it and the golden-prompt fixture that
    filters on that sourcetype stops resolving.

    Verified to be MISSED by the read this replaced: taking the first
    backticked cell of a row ignores headers entirely, so it kept registering
    the same names and reported nothing. That read also put 11 index globs in
    the registry and left out 9 real sourcetypes, the CrowdStrike and Carbon
    Black families among them, so writing one of those in query position was
    reported as invented.

    newline='' preserves a CRLF checkout's endings; the anchor is a single
    line, so the swap lands under either.
    """
    path = os.path.join(WORK, CATALOG)
    text = open(path, newline="").read()
    open(path, "w", newline="").write(text.replace(
        "| Sourcetype | Source | CIM data model | Key fields |",
        "| Source | Sourcetype | CIM data model | Key fields |"))


check_mutation("catalogue Sourcetype column relabelled as Source",
               _swap_catalogue_sourcetype_column,
               "not a catalogued sourcetype of any shape")


def _blank_one_catalogue_reference() -> None:
    """Empty the Reference cell of one catalogue row, leaving the row's shape.

    The row keeps its cell count, so the malformed-table check stays quiet and
    only the citation check can notice. The aidmaster row is unique in the
    file, which is what makes the edit deterministic.
    """
    path = os.path.join(WORK, CATALOG)
    text = open(path, newline="").read()
    marker = "| `crowdstrike:inventory:aidmaster` |"
    assert text.count(marker) == 1, "aidmaster row is no longer unique"
    start = text.index(marker)
    line_end = text.index("\n", start)
    row = text[start:line_end]
    # newline='' preserves a CRLF checkout's endings, so the CR is part of the
    # row here and has to be put back.
    cr = "\r" if row.endswith("\r") else ""
    cells = row.rstrip("\r").split("|")
    # Cells: '', Add-on, Sourcetype, CIM, Key fields, Reference, ''.
    cells[-2] = " "
    open(path, "w", newline="").write(text[:start] + "|".join(cells) + cr + text[line_end:])


check_mutation("catalogue row with an empty Reference cell",
               # The Splunkbase catalogue shipped with no citations at all for
               # a year while the Sentinel catalogue required one per table.
               _blank_one_catalogue_reference,
               "empty Reference cell")
check_mutation("catalogue table with its Reference column renamed",
               # Only the first table loses its column; every row of it keeps
               # its cells, so this is the header check alone firing.
               lambda: edit(CATALOG,
                            "| Sourcetype | Source | CIM data model | Key fields | Reference |\n| --- | --- | --- | --- | --- |\n| `WinEventLog` | `WinEventLog:Security` |",
                            "| Sourcetype | Source | CIM data model | Key fields | Citation |\n| --- | --- | --- | --- | --- |\n| `WinEventLog` | `WinEventLog:Security` |"),
               "no Reference column")
check_mutation("uncatalogued MIXED-CASE sourcetype",
               # The token pattern required a lowercase first letter, so the
               # catalogue's own OktaIM2:* family was never matched and an
               # invented OktaIM2:whatever bypassed the check entirely.
               lambda: append(MDOC, f"\n{BT}spl\nindex=foo sourcetype=OktaIM2:invented\n| head 5\n{BT}\n"),
               "never invent Splunk identifiers")
check_mutation("uncatalogued table in a union list or multiline join",
               lambda: append(KDOC, f"\n{BT}kql\nSigninLogs\n| union AuditLogs, InventedTable\n{BT}\n"),
               "never invent Sentinel identifiers")
check_mutation("uncatalogued table bound by let",
               lambda: append(KDOC, f"\n{BT}kql\nlet recent = InventedTable;\nrecent | take 5\n{BT}\n"),
               "never invent Sentinel identifiers")
check_mutation("uncatalogued table as a parenthesized union operand",
               # KQL's commonest union form. The pattern accepted only a bare
               # identifier after 'union', so an invented table inside the
               # parentheses was read by nothing.
               lambda: append(KDOC, f"\n{BT}kql\nunion (InventedTable | where TimeGenerated > ago(1d))\n{BT}\n"),
               "never invent Sentinel identifiers")
check_mutation("uncatalogued table behind a let preamble",
               # The source was read from line 0 only. A 'let' there is a
               # keyword and was discarded, and the let-value pattern skips a
               # function call, so the real table on line 2 was read by nothing.
               lambda: append(KDOC, f"\n{BT}kql\nlet cutoff = ago(1d);\nInventedTable\n| where TimeGenerated > cutoff\n{BT}\n"),
               "never invent Sentinel identifiers")
check_mutation("raw-event search whose only _time is an aggregation",
               lambda: append(MDOC, f"\n{BT}spl\nindex=firewall\n| stats latest(_time)\n{BT}\n"),
               "no time bound")
check_mutation("unbounded '| search' wearing a leading pipe",
               lambda: append(MDOC, f"\n{BT}spl\n| search index=firewall sourcetype=cisco:asa\n| stats count\n{BT}\n"),
               "no time bound")
GOLDEN_MARKER = "examples/golden-run.json"


def _corrupt_golden_marker() -> None:
    """A marker that no longer parses must be an issue, not a quiet 'nothing
    recorded': otherwise the whole freshness check goes silent."""
    write(GOLDEN_MARKER, b"{ not json\n")


def _record_a_file_that_no_longer_exists() -> None:
    """Make the marker claim the run saw a reference file that is not in the
    tree. The notice must name it: a run that saw a file which no longer
    exists is not a fresh run. Done by editing the marker rather than deleting
    a real reference file, because every real one is also a required file and
    deleting it would fail validation for that reason instead."""
    import json as _json
    path = os.path.join(WORK, GOLDEN_MARKER)
    marker = _json.load(open(path))
    marker["files"]["splunk-enrichment-query-builder/references/never-existed.md"] = "0" * 64
    _json.dump(marker, open(path, "w"), indent=2)


# Freshness of the last model run. These are NOTICES: the validator keeps
# passing and says why. Every file class the watched-set rule covers gets a
# case, so a rule that silently stopped watching one of them would show here.
check_notice("a SKILL.md edited after the recorded model run",
             lambda: append("splunk-sentinel-query-builder/SKILL.md", "\nAn edit the last model run never saw.\n"),
             "splunk-sentinel-query-builder/SKILL.md")
check_notice("a reference file edited after the recorded model run",
             lambda: append("splunk-enrichment-query-builder/references/multi-index-patterns.md", "\nAn edit.\n"),
             "references/multi-index-patterns.md")
check_notice("the fixture file edited after the recorded model run",
             lambda: append("examples/golden-prompts.md", "\nAn edit.\n"),
             "examples/golden-prompts.md")
check_notice("a watched file the recorded run saw no longer exists",
             _record_a_file_that_no_longer_exists,
             "references/never-existed.md")
check_mutation("golden-run marker that does not parse",
               _corrupt_golden_marker,
               "not valid JSON or lacks a files map")


def _delete_a_check(fragment: str) -> None:
    """Delete one Add-Issue call outright, as a bad merge would.

    The manifest is what notices. Nothing else does: deleting a check together
    with its mutation leaves section [E] self-consistent and the run green.
    """
    p = os.path.join(WORK, VAL)
    text = open(p).read()
    line = next(ln for ln in text.splitlines() if "Add-Issue" in ln and fragment in ln)
    open(p, "w").write(text.replace(line + "\n", ""))


check_mutation("a validator check deleted outright",
               lambda: _delete_a_check("never invent Sentinel identifiers"),
               "no longer performs")
check_mutation("a check performed but absent from required-checks.txt",
               lambda: edit("scripts/required-checks.txt",
                            "$File names Sentinel table", "$File names SOMETHING ELSE"),
               "not listed in required-checks.txt")
check_mutation("gutted check inventory",
               lambda: write("scripts/required-checks.txt", b""),
               "check inventory cannot be verified")
def _flatten_skill_output_shapes() -> None:
    """Turn every numbered list item in every SKILL.md into a bullet.

    That makes the declared-section list unreadable, which is what the guard
    exists for: the first version of the fixture-shape check sat above the
    $skills definition, read nothing, and would have passed vacuously had the
    fixtures happened to name no sections.
    """
    changed = 0
    for skill in ("splunk-sentinel-query-builder", "splunk-enrichment-query-builder",
                  "splunk-data-dictionary-builder"):
        p = os.path.join(WORK, skill, "SKILL.md")
        text = open(p).read()
        flattened = re.sub(r"(?m)^\d+\.[ \t]+", "- ", text)
        if flattened != text:
            open(p, "w").write(flattened)
            changed += 1
    assert changed, "no SKILL.md had a numbered output shape to flatten"


check_mutation("no output sections readable from any SKILL.md",
               _flatten_skill_output_shapes,
               "No output sections could be read")
check_mutation("golden-prompt fixture asserting an undeclared output section",
               lambda: append("examples/golden-prompts.md",
                              "\n- Uses the invented shape: `Objective`, `Executive Summary`\n"),
               "that no SKILL.md declares")
check_mutation("gutted Sentinel table registry",
               lambda: write("splunk-sentinel-query-builder/references/sentinel-table-catalog.md", b""),
               "Sentinel table provenance cannot be checked")
check_mutation("gutted sourcetype registry",
               # A registry file that is empty would otherwise make every
               # sourcetype in every doc look invented at once.
               lambda: write("splunk-enrichment-query-builder/references/splunkbase-app-catalog.md", b""),
               "provenance cannot be checked")
check_mutation("registered skill with no golden-prompt fixture",
               lambda: _drop_golden_fixtures("splunk-data-dictionary-builder"),
               "no fixture in examples/golden-prompts.md")
check_mutation("SKILL.md description with no 'Do not use' clause",
               lambda: edit("splunk-data-dictionary-builder/SKILL.md",
                            "Do not use for writing hunt queries",
                            "Also fine for writing hunt queries"),
               "'Do not use' clause")
check_mutation("openai.yaml with no interface section at all",
               lambda: _drop_yaml_section("splunk-enrichment-query-builder/agents/openai.yaml",
                                          "interface:"),
               "missing the interface section")
check_mutation("openai.yaml with no policy section at all",
               lambda: _drop_yaml_section("splunk-enrichment-query-builder/agents/openai.yaml",
                                          "policy:"),
               "missing the policy section")
check_mutation("helper missing invocation.preferred_prompt entirely",
               lambda: _drop_yaml_section("splunk-enrichment-query-builder/agents/claude-opus.yaml",
                                          "invocation:"),
               "is missing invocation.preferred_prompt")
check_mutation("a helper file that is not valid YAML",
               lambda: append("splunk-enrichment-query-builder/agents/openai.yaml",
                              "\ninterface:\n  - broken\n   bad_indent: [unclosed\n"),
               "is not valid YAML")
check_mutation("CIM_SOURCETYPE_HINTS dictionary removed from the builder",
               # The declaration is annotated, so it is not a bare '... = {'.
               # The new name must not START with CIM_SOURCETYPE_HINTS either:
               # the validator matches '^CIM_SOURCETYPE_HINTS[^=]*=', so a
               # _RENAMED suffix still satisfies it and the mutation passed.
               lambda: edit(SRC, "CIM_SOURCETYPE_HINTS: dict[str, list[str]] = {",
                            "RENAMED_HINTS: dict[str, list[str]] = {"),
               "missing the CIM_SOURCETYPE_HINTS dictionary")
check_mutation("broken relative markdown link",
               lambda: append("README.md", "\nSee [ghost](no-such-file.md).\n"),
               "broken local link")
check_mutation("helper pair drift",
               lambda: edit("splunk-enrichment-query-builder/agents/codex-gpt-5.4.yaml",
                            '    - "Why efficient"', '    - "Why Efficient"'),
               "Helper drift")
check_mutation("openai.yaml allow_implicit_invocation flipped",
               lambda: edit("splunk-enrichment-query-builder/agents/openai.yaml",
                            "allow_implicit_invocation: false", "allow_implicit_invocation: true"),
               "allow_implicit_invocation")
check_mutation("openai.yaml missing interface key",
               lambda: edit("splunk-enrichment-query-builder/agents/openai.yaml",
                            "  display_name:", "  display_name_x:"),
               # Deliberately includes the leading "is": section [E] matches the
               # literal fragment of "$openaiPath is missing interface.$key"
               # against this text, and that fragment carries the "is".
               "is missing interface.display_name")
check_mutation("invocation prompt drift across the three files",
               lambda: edit("splunk-enrichment-query-builder/agents/claude-opus.yaml",
                            '  preferred_prompt: "Use $', '  preferred_prompt: "Please use $'),
               "Invocation prompt drift")
check_mutation("trigger_tuning removed from a claude helper",
               lambda: edit("splunk-sentinel-query-builder/agents/claude-opus.yaml",
                            "  trigger_tuning:", "  trigger_tuning_x:"),
               "missing behavior.trigger_tuning")
check_mutation("packaging_rules removed from a codex helper",
               lambda: edit("splunk-sentinel-query-builder/agents/codex-gpt-5.4.yaml",
                            "  packaging_rules:", "  packaging_rules_x:"),
               "missing behavior.packaging_rules")
check_mutation("undocumented CIM hint sourcetype",
               lambda: edit(SRC, '    "squid:access": ["Web"],',
                            '    "squid:access": ["Web"],\n    "acme:invented:type": ["Web"],'),
               "not documented in cim-vendor-alignment.md")
check_mutation("skill on disk not registered in $skills",
               lambda: (os.makedirs(os.path.join(WORK, "splunk-ghost-skill"), exist_ok=True),
                        write("splunk-ghost-skill/SKILL.md", b"---\nname: splunk-ghost-skill\n---\n"),
                        sh("git add -A")),
               "not registered in the validator")
check_mutation("$skills entry with no SKILL.md on disk",
               lambda: edit(VAL, '    "splunk-enrichment-query-builder"\n)',
                            '    "splunk-enrichment-query-builder",\n    "splunk-phantom-skill"\n)'),
               "no SKILL.md on disk")
def _drop_required_entries(prefix: str) -> None:
    """Remove EVERY $requiredFiles entry for one skill.

    The guard fires only when a skill has no entries at all, so dropping a single
    line proves nothing -- the first draft of this mutation did exactly that.
    """
    p = os.path.join(WORK, VAL)
    lines = open(p).read().splitlines(keepends=True)

    # Scope every edit below to the $requiredFiles array. An earlier draft
    # searched the whole file for the closing ")" and found the one belonging to
    # param() on line 7, stripped a comma there, and broke the script's parse --
    # so the validator failed for the wrong reason and the mutation scored as a
    # bogus catch.
    start = next(i for i, ln in enumerate(lines)
                 if ln.startswith("$requiredFiles = @("))
    end = next(i for i in range(start + 1, len(lines)) if lines[i].strip() == ")")

    body = [ln for ln in lines[start + 1:end] if f'"{prefix}/' not in ln]
    assert len(body) < end - start - 1, f"no $requiredFiles entries matched {prefix}"
    # This skill's entries end the array, so removing them strands a trailing
    # comma on the new last element, which is also a parse error.
    body[-1] = body[-1].rstrip().rstrip(",") + "\n"

    open(p, "w").write("".join(lines[:start + 1] + body + lines[end:]))


check_mutation("skill with no $requiredFiles entries",
               # A skill on disk AND in $skills AND in $helperChecks, but absent
               # from $requiredFiles: its files could then be deleted without the
               # run noticing. Nothing else covered this guard, so breaking it
               # left every other mutation passing.
               lambda: _drop_required_entries("splunk-enrichment-query-builder"),
               "no entries in")
check_mutation("helperChecks entry missing for a registered skill",
               lambda: edit(VAL, '    @{ Skill = "splunk-data-dictionary-builder";',
                            '    @{ Skill = "splunk-absent-from-skills";'),
               "helperChecks")
check_mutation("git ls-files unusable",
               lambda: shutil.move(os.path.join(WORK, ".git"), os.path.join(WORK, ".git-hidden")),
               "refusing to report success")

print("\n[D] ENVIRONMENT - conditions CI sees that a Linux dev box does not")


def expect(label: str, got: str, want: str) -> None:
    run_counts["environment"] += 1
    ok = got == want
    print(f"  {'OK  ' if ok else '*** FAIL ***'} {label:38} got={got} want={want}")
    if not ok:
        fails.append(label)


fresh()
# convert_line_endings, not a shell heredoc: this script also runs on the
# Windows job, where the shell is cmd.exe and heredocs do not exist. Section [C]
# uses the same helper, so there is one conversion implementation rather than
# two that can drift.
convert_line_endings(to_crlf=True)
expect("fully-CRLF repo validates", validator(), "PASSED")

fresh()
convert_line_endings(to_crlf=False)
expect("fully-LF repo validates", validator(), "PASSED")

fresh()
r = sh("pwsh -NoProfile -File ./validate-skill-pack.ps1 -Root ..", cwd=os.path.join(WORK, "scripts"))
expect("relative -Root", "PASSED" if "validation passed" in r.stdout else "FAILED", "PASSED")

fresh()
shutil.copy(os.path.join(WORK, "README.md"), os.path.join(WORK, "weird[1].md"))
# The fixture file is tracked, so the layout-tree check now wants it listed.
# Register it in both trees rather than weakening the assertion: the case exists
# to prove a '[' in a filename does not abort the run under
# ErrorActionPreference=Stop, and "PASSED" is the sharpest way to say that.
for _doc in ("README.md", "QUERY_SKILL_PLAN.md"):
    _p = os.path.join(WORK, _doc)
    _t = open(_p).read()
    assert "siem_fun/\n" in _t, f"no layout tree root in {_doc}"
    open(_p, "w").write(_t.replace("siem_fun/\n", "siem_fun/\n|-- weird[1].md\n", 1))
sh("git add -A")
expect("tracked 'weird[1].md' does not abort", validator(), "PASSED")

fresh()
_orig = open(os.path.join(WORK, "README.md"), "rb").read()
write("README.md", b"\xef\xbb\xbf" + _orig)
expect("UTF-8 BOM rejected", validator(), "FAILED")

fresh()
# Read BEFORE opening for write: open(...,"wb") truncates, so an inline
# read-inside-write argument silently produced an EMPTY file.
_txt = open(os.path.join(WORK, "README.md"), "rb").read().decode("utf-8")
write("README.md", _txt.encode("utf-16-le"))
expect("UTF-16LE rejected", validator(), "FAILED")

fresh()
t0 = time.time()
validator()
runtime = time.time() - t0
# Generous on purpose, and this also runs on a slower Windows CI runner. The
# regression being guarded was a ~37x blow-up (a per-byte pipeline), so a real
# one lands far above this; a tight bound here would just flake.
budget = 20.0
run_counts["environment"] += 1
ok = runtime < budget
# No reference figure here on purpose: a literal "~1.8s on a Linux dev box" has
# now gone stale three times as checks were added, and a stale number in a
# passing line is exactly the sort of quiet drift this script exists to catch.
# The budget is the assertion; the measured value is context.
print(f"  {'OK  ' if ok else '*** FAIL ***'} {'validator runtime':38} {runtime:.2f}s (budget {budget:.0f}s)")
if not ok:
    fails.append("validator runtime regression")

print("\n[E] CHECK COVERAGE - every Add-Issue in the validator has a mutation")
# Section [C] is hand-maintained, so a new validator check could ship with no
# mutation behind it and every existing case would still pass -- which is
# exactly how the $requiredFiles guard shipped uncovered. Comparing the
# validator's Add-Issue sites against the registered expect texts closes that
# class instead of catching it one gap at a time in review.
_val_src = open(os.path.join(REPO, VAL)).read()
_messages = sorted(set(re.findall(r'Add-Issue\s+"([^"]*)"', _val_src)))
_lowered = [e.lower() for e in expect_texts]


def _covered(template: str) -> bool:
    """Is this Add-Issue message reachable by some registered mutation?

    Matching runs both ways because the message is a PowerShell interpolated
    string. 'is missing interface.$key' can never contain the expect text
    'missing interface.display_name', but its literal fragment
    'is missing interface.' is contained BY it. Matching one way only reported
    two checks as uncovered that are in fact exercised.
    """
    low = template.lower()
    if any(e in low for e in _lowered):
        return True
    # The literal spans of the template, with the $var and $(...) holes removed.
    fragments = [f.strip().lower()
                 for f in re.split(r'\$\([^)]*\)|\$\w+', template)
                 if len(f.strip()) >= 12]
    return any(any(f in e for e in _lowered) for f in fragments)


_uncovered = [m for m in _messages
              if m not in UNMUTATED_MESSAGES
              and m not in COVERED_BY_NAME
              and not _covered(m)]
# A COVERED_BY_NAME entry naming a mutation that does not exist would wave a
# check through, so assert the named mutation actually ran.
for _msg, _label in COVERED_BY_NAME.items():
    if _label not in ran_labels:
        print(f"  *** BAD MAPPING *** '{_label}' does not name a mutation that ran")
        fails.append(f"COVERED_BY_NAME names no such mutation: {_label}")
print(f"  {len(_messages)} Add-Issue messages, {len(expect_texts)} mutations, "
      f"{len(UNMUTATED_MESSAGES)} exemption(s), {len(COVERED_BY_NAME)} named mapping(s)")
for _m in _uncovered:
    print(f"  *** UNCOVERED *** {_m[:88]}")
    fails.append(f"no mutation covers: {_m[:60]}")
# A stale exemption is a silent gap too: it would keep excusing a message that
# no longer exists, or one that has since gained a mutation.
for _m in list(UNMUTATED_MESSAGES) + list(COVERED_BY_NAME):
    if _m not in _messages:
        print(f"  *** STALE EXEMPTION *** {_m[:70]}")
        fails.append(f"stale exemption: {_m[:60]}")
if not _uncovered:
    print("  OK   every Add-Issue message is reachable by a registered mutation")

_rmtree(WORK)
print("\n" + "=" * 74)
if fails:
    print(f"RESULT: {len(fails)} PROBLEM(S)")
    for f in fails:
        print(f"  - {f}")
    sys.exit(1)
print(f"RESULT: all mutations caught ({len(PY_MUTS)} python + {len(PS_MUTS)} powershell + "
      f"{len(GRADER_MUTS)} grader unit + {len(RECORDER_MUTS)} recorder + "
      f"{len(RUNNER_MUTS)} runner + {len(WAF_MUTS)} waf rule file + {len(DETECTION_MUTS)} detection + {len(SWEEP_MUTS)} indicator sweep and schedule + "
      f"{len(ASSET_MUTS) + len(FUNCTION_MUTS)} hunt, query file, reference and layer + 2 shared corpus, "
      f"{run_counts['validator']} validator checks, {run_counts['notice']} freshness notices, "
      f"{run_counts['environment']} environment)")
sys.exit(0)
