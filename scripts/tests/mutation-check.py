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
import shutil
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

# Tests that cannot be mutation-checked, and why. Listed so the gap is explicit
# rather than looking like an oversight.
NOT_MUTATABLE = {
    "tolerates YAML shapes the old regex parser rejected":
        "asserts ConvertFrom-Yaml's own behaviour; there is no repo code to break",
    "returns null for a non-dictionary value":
        "the IDictionary guard can be removed without any current caller passing a "
        "non-dictionary, so no mutation makes it fail (kept as documentation)",
}


def sh(cmd: str, cwd: str = WORK) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, cwd=cwd)


PY_EXE = f'"{sys.executable}"'


def py_suite() -> str:
    r = sh(f"{PY_EXE} -m unittest discover -s splunk-data-dictionary-builder/tests")
    return "OK" if r.stderr.strip().endswith("OK") else "FAILED"


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


def fresh() -> None:
    """Rebuild WORK from the pristine repo.

    Not `git checkout -- .`: that restores from the INDEX, so a case that staged
    a file leaked state into the next one and made a check report the wrong
    answer.
    """
    shutil.rmtree(WORK, ignore_errors=True)
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


def check_mutation(label: str, breaker, expect_text: str) -> None:
    """Break the repo, then assert the validator reports it AND says why.

    The breaker's effect is verified: an edit() whose pattern was ambiguous
    returns False and changes nothing, which would otherwise read as a MISSED
    check against an unmodified repo rather than as the harness bug it is.
    """
    fresh()
    before = _tree_fingerprint()
    breaker()
    if _tree_fingerprint() == before:
        print(f"  SETUP-FAIL     {label}  (breaker changed nothing)")
        fails.append(f"setup: {label}")
        return
    out = validator_output()
    failed = "validation passed" not in out
    named = expect_text.lower() in out.lower()
    ok = failed and named
    detail = "" if ok else f"  (failed={failed} named={named})"
    print(f"  {'CAUGHT ' if ok else '*** MISSED ***'} {label}{detail}")
    if not ok:
        fails.append(label)


print("=" * 74)
print("MUTATION CHECK")
print("=" * 74)
fresh()

print("\n[A] BASELINE AT HEAD")
# Assert the baseline, do not merely print it. A mutation is judged CAUGHT when
# the suite turns red, so a suite that is ALREADY red makes every mutation
# against it look caught and can still exit 0. Abort instead: with a red
# baseline every result below is meaningless, not merely suspect.
_v, _ps, _py = validator(), ps_suite(), py_suite()
print(f"  validator      : {_v}")
print(f"  powershell     : {_ps}")
print(f"  python         : {_py}")
_baseline = []
if _v != "PASSED":
    _baseline.append(f"validator not green at baseline ({_v})")
if not (_ps.endswith(", 0 failed") and _ps[0].isdigit()):
    _baseline.append(f"powershell suite not green at baseline ({_ps})")
if _py != "OK":
    _baseline.append(f"python suite not green at baseline ({_py})")
if _baseline:
    print("\n" + "=" * 74)
    print("ABORTING: baseline is not green, so no mutation result would mean anything.")
    for b in _baseline:
        print(f"  - {b}")
    sys.exit(1)

print("\n[B] UNIT MUTATIONS - each REGRESSION test vs the bug it names")
PY_MUTS = [
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
    ("conflict-marker regex CRLF anchor",
     r"""$script:conflictMarkerRegex = '(?m)^(<{7}( |\r?$)|={7}\r?$|>{7}( |\r?$))'""",
     r"""$script:conflictMarkerRegex = '(?m)^(<{7}( |$)|={7}$|>{7}( |$))'"""),
    ("fenced-block regex CRLF anchor",
     r"""$script:fencedBlockRegex    = '(?ms)^[ \t]*""" + BT + r""".*?^[ \t]*""" + BT + r"""[ \t]*\r?$'""",
     r"""$script:fencedBlockRegex    = '(?ms)^\s*""" + BT + r""".*?^\s*""" + BT + r"""[ \t]*$'"""),
    ("where-boolean regex",
     r"""$script:whereBooleanRegex   = '(?m)^\s*\| where [^|\r\n]*=\s*(true|false)\b'""",
     r"""$script:whereBooleanRegex   = '(?m)^ZZZNEVERMATCHES'"""),
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
    ("invalid YAML is reported as an issue",
     '            Add-Issue "$RelativePath is not valid YAML: $($_.Exception.Message)"',
     "            $null = $_"),
]
for label, old, new in PS_MUTS:
    unit_mutation(label, VAL, old, new, ps_suite)

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
check_mutation("unquoted SPL where-boolean in markdown",
               lambda: append("splunk-enrichment-query-builder/references/multi-index-patterns.md",
                              "\n| where noise=true\n"),
               "unquoted true/false")
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
               "missing interface.display_name")
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
check_mutation("helperChecks entry missing for a registered skill",
               lambda: edit(VAL, '    @{ Skill = "splunk-data-dictionary-builder";',
                            '    @{ Skill = "splunk-absent-from-skills";'),
               "helperChecks")
check_mutation("git ls-files unusable",
               lambda: shutil.move(os.path.join(WORK, ".git"), os.path.join(WORK, ".git-hidden")),
               "refusing to report success")

print("\n[D] ENVIRONMENT - conditions CI sees that a Linux dev box does not")


def expect(label: str, got: str, want: str) -> None:
    ok = got == want
    print(f"  {'OK  ' if ok else '*** FAIL ***'} {label:38} got={got} want={want}")
    if not ok:
        fails.append(label)


fresh()
# In-process, not a shell heredoc: this script also runs on the Windows job,
# where the shell is cmd.exe and heredocs do not exist.
for _root, _dirs, _files in os.walk(WORK):
    _dirs[:] = [d for d in _dirs if d != ".git"]
    for _fn in _files:
        if _fn.rsplit(".", 1)[-1] in ("md", "yaml", "yml", "json", "ps1", "py", "example", "txt"):
            _p = os.path.join(_root, _fn)
            try:
                _c = open(_p, newline="").read()
            except (OSError, UnicodeDecodeError):
                continue
            open(_p, "w", newline="\r\n").write(_c)
expect("fully-CRLF repo validates", validator(), "PASSED")

fresh()
r = sh("pwsh -NoProfile -File ./validate-skill-pack.ps1 -Root ..", cwd=os.path.join(WORK, "scripts"))
expect("relative -Root", "PASSED" if "validation passed" in r.stdout else "FAILED", "PASSED")

fresh()
shutil.copy(os.path.join(WORK, "README.md"), os.path.join(WORK, "weird[1].md"))
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
ok = runtime < 3.0
print(f"  {'OK  ' if ok else '*** FAIL ***'} {'validator runtime':38} {runtime:.2f}s (was 1.65s before byte checks)")
if not ok:
    fails.append("validator runtime regression")

shutil.rmtree(WORK, ignore_errors=True)
print("\n" + "=" * 74)
if fails:
    print(f"RESULT: {len(fails)} PROBLEM(S)")
    for f in fails:
        print(f"  - {f}")
    sys.exit(1)
print(f"RESULT: all mutations caught ({len(PY_MUTS)} python + {len(PS_MUTS)} powershell unit, "
      f"17 validator checks, 6 environment)")
sys.exit(0)
