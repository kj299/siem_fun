#!/usr/bin/env python3
"""Record which skill content the golden prompts were last run against.

    python3 scripts/record_golden_run.py --method agents --result "10 of 10"
    python3 scripts/record_golden_run.py --check          # what changed since?

The behavioral half of the golden prompts (a model driven through every
fixture, then graded) cannot run in CI, so whether it was re-run after a
SKILL.md or reference change has been an honour-system rule. This makes the
gap visible instead of trusted: examples/golden-run.json holds a content hash
of every file the model run depends on, written at the moment of the run, and
the validator compares those hashes to the tree on every run. A mismatch is
printed as a NOTICE naming the files -- not a failure, because the fix is a
model run that CI cannot perform, and a check that blocks every content edit
until someone remembers a credential gets routed around rather than obeyed.

Hashes are of LF-normalised bytes on purpose. The validator runs on
windows-latest, which checks the tree out with CRLF line endings, and a hash
of the raw bytes would report every file as changed on that platform while
agreeing with itself on Linux. The PowerShell side normalises the same way;
scripts/tests/shared-rule-cases.json is not involved because this is not a
query rule, but the two implementations are pinned to each other by a test
that hashes the same fixture bytes both ways.

The watched set is defined by RULE rather than by a list in this file, so a
new reference file is watched the moment it exists: every skill's SKILL.md,
every markdown file under its references/ directory, and the fixture file
itself. Which skills exist is taken from the grader, which already knows.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import grade_golden_output as grader  # noqa: E402

MARKER = "examples/golden-run.json"
FIXTURES = "examples/golden-prompts.md"


def watched_files(repo: str | None = None) -> list[str]:
    """Repo-relative paths, forward slashes, sorted. The rule, not a list."""
    repo = repo or grader.REPO
    paths: list[str] = []
    for skill in grader.SKILLS:
        paths.append(f"{skill}/SKILL.md")
        ref_dir = os.path.join(repo, skill, "references")
        if os.path.isdir(ref_dir):
            paths += [f"{skill}/references/{n}" for n in os.listdir(ref_dir) if n.endswith(".md")]
    paths.append(FIXTURES)
    return sorted(p for p in paths if os.path.isfile(os.path.join(repo, p)))


def file_hash(path: str) -> str:
    """sha256 of the file's bytes with every CRLF folded to LF."""
    with open(path, "rb") as fh:
        data = fh.read()
    return hashlib.sha256(data.replace(b"\r\n", b"\n")).hexdigest()


def current_hashes(repo: str | None = None) -> dict[str, str]:
    repo = repo or grader.REPO
    return {p: file_hash(os.path.join(repo, p)) for p in watched_files(repo)}


def read_marker(repo: str | None = None) -> dict:
    repo = repo or grader.REPO
    with open(os.path.join(repo, MARKER), encoding="ascii") as fh:
        return json.load(fh)


def staleness(repo: str | None = None) -> list[str]:
    """Files whose content differs from the recorded run, plus any watched file
    the marker does not know and any recorded file that no longer exists.
    Empty means the last model run saw exactly this content."""
    repo = repo or grader.REPO
    recorded = read_marker(repo).get("files", {})
    now = current_hashes(repo)
    changed = [p for p in now if recorded.get(p) != now[p]]
    removed = [p for p in recorded if p not in now]
    return sorted(changed + removed)


def write_marker(method: str, result: str, repo: str | None = None,
                 date: str | None = None) -> str:
    repo = repo or grader.REPO
    marker = {
        "_comment": "Written by scripts/record_golden_run.py after a model run of every fixture. "
                    "The validator compares these LF-normalised sha256 hashes to the tree and "
                    "prints a NOTICE naming any file changed since. Do not edit by hand.",
        "date": date or dt.date.today().isoformat(),
        "method": method,
        "result": result,
        "files": current_hashes(repo),
    }
    path = os.path.join(repo, MARKER)
    with open(path, "w", encoding="ascii", newline="\n") as fh:
        json.dump(marker, fh, indent=2)
        fh.write("\n")
    return path


def full_pass(result: str, total: int | None = None) -> bool:
    """True when `result` says every fixture was graded and every one passed.

    A marker exists to say "the behavioral baseline held for this content", and
    the validator's notice stays quiet while it holds. Recording a partial or
    failing run would silence the notice on a baseline that is neither, so the
    recorder refuses one: the API runner already records only a full passing
    run, and this is the same rule on the path a run by subagents must take.

    `fullmatch` with no anchors on purpose: `$` in a Python regex also matches
    before a trailing newline, so "10 of 10\n" would pass an anchored match.
    """
    m = re.fullmatch(r"\s*(\d+)\s+of\s+(\d+)\s*", result)
    if not m:
        return False
    passed, graded = int(m.group(1)), int(m.group(2))
    if total is None:
        total = len(grader.load_fixtures())
    return passed == graded == total


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--method", choices=["agents", "api"],
                    help="how the run was driven: subagents loaded with the skill, or the API runner")
    ap.add_argument("--result", help='the graded outcome, for example "10 of 10"')
    ap.add_argument("--check", action="store_true", help="list watched files changed since the recorded run")
    args = ap.parse_args(argv)

    if args.check:
        stale = staleness()
        if not stale:
            print("golden prompts: the recorded run saw the current skill content")
            return 0
        print("golden prompts: content changed since the recorded run:")
        for p in stale:
            print(f"  {p}")
        return 1

    if not (args.method and args.result):
        ap.error("--method and --result are required unless --check is given")
    n = len(grader.load_fixtures())
    if not full_pass(args.result):
        ap.error(f'--result must record every fixture passing, written as "{n} of {n}"; '
                 f'got "{args.result}". A partial or failing run is not a baseline, and '
                 f'recording it would silence the validator\'s freshness notice while the '
                 f'behavioral half is unproven. Fix what failed, re-run, then record.')
    path = write_marker(args.method, args.result)
    print(f"recorded {len(watched_files())} files in {os.path.relpath(path, grader.REPO)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
