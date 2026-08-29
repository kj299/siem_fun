#!/usr/bin/env python3
"""Mutation-check the repo's own test suites.

    python3 scripts/tests/mutation-check.py

For each REGRESSION test, reintroduce the bug it names and assert the suite goes
red. A test that stays green when its bug returns proves nothing, and this repo
has shipped several of those. Also runs second-order checks that the validator
behaves on inputs CI sees but a Linux dev box does not: a CRLF checkout, a UTF-8
BOM, a UTF-16 file, a filename containing wildcard characters, a relative -Root.

Runs against a scratch copy; never mutates the working tree. Exit 0 = every
mutation was caught."""
import os
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
WORK = os.path.join(tempfile.gettempdir(), "siem-fun-mutation-check")
SRC = "splunk-data-dictionary-builder/scripts/build_splunk_dictionary.py"
VAL = "scripts/validate-skill-pack.ps1"
BT = chr(96) * 3

fails = []


def sh(cmd, cwd=WORK):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, cwd=cwd)


def py_suite():
    r = sh("python3 -m unittest discover -s splunk-data-dictionary-builder/tests")
    return "OK" if r.stderr.strip().endswith("OK") else "FAILED"


def ps_suite():
    r = sh(f"pwsh -NoProfile -File ./scripts/tests/validate-skill-pack.tests.ps1")
    for line in r.stdout.splitlines():
        if "passed," in line:
            return line.strip()
    return "<none>"


def validator():
    r = sh(f"pwsh -NoProfile -File ./{VAL}")
    return "PASSED" if "validation passed" in r.stdout else "FAILED"


def mutate(path, old, new):
    p = os.path.join(WORK, path)
    t = open(p).read()
    if t.count(old) != 1:
        return False
    open(p, "w").write(t.replace(old, new, 1))
    return True


def restore():
    sh("git checkout -- . && git clean -fdq")


print("=" * 72)
print("PASS 3 - FINAL VALIDATION")
print("=" * 72)
shutil.rmtree(WORK, ignore_errors=True)
shutil.copytree(REPO, WORK)
sh("git add -A && git -c user.email=t@t -c user.name=t commit -qm p3base")

print("\n[A] BASELINE AT HEAD")
print(f"  validator      : {validator()}")
print(f"  powershell     : {ps_suite()}")
print(f"  python         : {py_suite()}")

print("\n[B] MUTATION-VERIFY EVERY REGRESSION TEST ADDED THIS SESSION")
PY_MUTS = [
    ("transport read failure -> RuntimeError",
     "        except (OSError, http.client.HTTPException) as error:\n            # urllib only wraps connect-phase failures in URLError. Reading the",
     "        except (ZeroDivisionError,) as error:\n            # urllib only wraps connect-phase failures in URLError. Reading the"),
    ("HTTPError body read guarded",
     '            except (OSError, http.client.HTTPException) as read_error:\n                body = f"<error body unreadable: {read_error!r}>"',
     '            except (ZeroDivisionError,) as read_error:\n                body = f"<error body unreadable: {read_error!r}>"'),
    ("env_bool empty == unset",
     "    if value is None or not value.strip():",
     "    if value is None:"),
    ("blank attribute is unset not malformed",
     "        if not value.strip():\n            # Blank means the attribute is unset, not malformed. Warning here",
     "        if False:\n            # Blank means the attribute is unset, not malformed. Warning here"),
    ("malformed JSON warns",
     '            if warnings is not None:\n                warnings.append(f"Could not parse JSON for {context!r}: {error}; skipping")\n',
     ""),
    ("oneshot count=0 (no 100-row cap)",
     '                "count": "0",\n', ""),
    ("sourcetype discovery sorts by volume",
     " | sort 0 - count", ""),
]
for label, old, new in PY_MUTS:
    restore()
    if not mutate(SRC, old, new):
        print(f"  SETUP-FAIL  {label}")
        fails.append(label)
        continue
    res = py_suite()
    mark = "CAUGHT " if res == "FAILED" else "*** MISSED ***"
    print(f"  {mark} {label}")
    if res != "FAILED":
        fails.append(label)
restore()

PS_MUTS = [
    ("conflict regex CRLF anchor", VAL,
     r"""$script:conflictMarkerRegex = '(?m)^(<{7}( |\r?$)|={7}\r?$|>{7}( |\r?$))'""",
     r"""$script:conflictMarkerRegex = '(?m)^(<{7}( |$)|={7}$|>{7}( |$))'"""),
    ("fence regex CRLF anchor", VAL,
     r"""$script:fencedBlockRegex    = '(?ms)^[ \t]*""" + BT + r""".*?^[ \t]*""" + BT + r"""[ \t]*\r?$'""",
     r"""$script:fencedBlockRegex    = '(?ms)^\s*""" + BT + r""".*?^\s*""" + BT + r"""[ \t]*$'"""),
    ("where-boolean regex", VAL,
     r"""$script:whereBooleanRegex   = '(?m)^\s*\| where [^|\r\n]*=\s*(true|false)\b'""",
     r"""$script:whereBooleanRegex   = '(?m)^ZZZNEVER'"""),
    ("Read-Text -LiteralPath", VAL,
     "        $raw = Get-Content -Raw -LiteralPath $path",
     "        $raw = Get-Content -Raw -Path $path"),
]
for label, path, old, new in PS_MUTS:
    restore()
    if not mutate(path, old, new):
        print(f"  SETUP-FAIL  {label}")
        fails.append(label)
        continue
    res = ps_suite()
    caught = res != "38 passed, 0 failed"
    print(f"  {'CAUGHT ' if caught else '*** MISSED ***'} {label}  ({res})")
    if not caught:
        fails.append(label)
restore()

print("\n[C] SECOND-ORDER CHECKS ON THE PASS-2 FIXES")

def fresh():
    """Rebuild WORK from the pristine repo. Prior cases staged files, and
    `git checkout -- .` restores from the INDEX, so state leaked between checks
    and made one of them silently report the wrong answer."""
    shutil.rmtree(WORK, ignore_errors=True)
    shutil.copytree(REPO, WORK)
    sh("git add -A && git -c user.email=t@t -c user.name=t commit -qm p3base")

def expect(label, got, want):
    ok = got == want
    print(f"  {'OK  ' if ok else '*** FAIL ***'} {label:32} got={got} want={want}")
    if not ok:
        fails.append(label)

fresh()
sh("""python3 - <<'EOF'
import subprocess
for f in subprocess.check_output(['git','ls-files']).decode().split():
    if f.rsplit('.',1)[-1] in ('md','yaml','yml','json','ps1','py','example','txt'):
        try: t=open(f,newline='').read()
        except Exception: continue
        open(f,'w',newline='\\r\\n').write(t)
EOF""")
expect("fully-CRLF repo validates", validator(), "PASSED")

fresh()
r = sh("pwsh -NoProfile -File ./validate-skill-pack.ps1 -Root ..", cwd=f"{WORK}/scripts")
expect("relative -Root", "PASSED" if "validation passed" in r.stdout else "FAILED", "PASSED")

fresh()
expect("hoisted regexes visible to suite", ps_suite(), "38 passed, 0 failed")

fresh()
shutil.copy(f"{WORK}/README.md", f"{WORK}/weird[1].md")
sh("git add -A")
expect("tracked 'weird[1].md' no abort", validator(), "PASSED")

fresh()
# Write the BOM bytes with Python: subprocess(shell=True) uses /bin/sh (dash),
# whose printf does not support \x hex escapes and wrote the literal text.
_orig_bom = open(f"{WORK}/README.md", "rb").read()
open(f"{WORK}/README.md", "wb").write(b"\xef\xbb\xbf" + _orig_bom)
expect("UTF-8 BOM detected", validator(), "FAILED")

fresh()
# Read BEFORE opening for write: open(...,"wb") truncates, so an inline
# read-inside-write argument silently produced an EMPTY file.
_orig = open(f"{WORK}/README.md", "rb").read().decode("utf-8")
open(f"{WORK}/README.md", "wb").write(_orig.encode("utf-16-le"))
expect("UTF-16LE detected", validator(), "FAILED")

fresh()
import time
t0 = time.time(); validator(); runtime = time.time() - t0
print(f"  {'OK  ' if runtime < 2.5 else '*** FAIL ***'} {'validator runtime':32} {runtime:.2f}s (baseline 1.65s)")
if runtime >= 2.5:
    fails.append("validator runtime regression")

print("\n" + "=" * 72)
if fails:
    print(f"PASS 3 RESULT: {len(fails)} PROBLEM(S)")
    for f in fails:
        print(f"  - {f}")
    sys.exit(1)
print("PASS 3 RESULT: all mutation checks caught, all second-order checks clean")
sys.exit(0)
