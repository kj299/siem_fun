#!/usr/bin/env python3
"""Unit tests for the golden-run marker and the runner's recording of it.

Run from the repository root:

    python -m unittest discover -s scripts/tests -p "test_*.py"

Stdlib unittest only. The marker is a content hash of every file a model run
depends on; the validator compares it to the tree and prints a NOTICE naming
files changed since the last run. These tests pin the two halves that make
that trustworthy: the hash ignores line endings (CI checks out CRLF), and the
watched set is a rule, so a new reference file is watched without anyone
editing a list.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
import types
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import grade_golden_output as grader  # noqa: E402
import record_golden_run as rec  # noqa: E402
import run_golden_prompts as runner  # noqa: E402


def _scratch_repo() -> str:
    """A minimal tree with every skill dir the grader knows, so watched_files
    resolves the same rule against it as against the real repository."""
    root = tempfile.mkdtemp(prefix="golden-run-")
    for skill in grader.SKILLS:
        os.makedirs(os.path.join(root, skill, "references"))
        with open(os.path.join(root, skill, "SKILL.md"), "w", newline="\n") as fh:
            fh.write(f"# {skill}\n")
        with open(os.path.join(root, skill, "references", "a.md"), "w", newline="\n") as fh:
            fh.write("alpha\n")
    os.makedirs(os.path.join(root, "examples"))
    with open(os.path.join(root, "examples", "golden-prompts.md"), "w", newline="\n") as fh:
        fh.write("# fixtures\n")
    return root


class HashTests(unittest.TestCase):
    def test_crlf_and_lf_hash_identically(self):
        # REGRESSION-class guard: the validator runs on windows-latest, which
        # checks out CRLF. A raw-bytes hash would report every watched file as
        # changed there while agreeing with itself on Linux, so the notice
        # would fire on every CI run and be ignored within a week.
        with tempfile.TemporaryDirectory() as d:
            lf, crlf = os.path.join(d, "lf.md"), os.path.join(d, "crlf.md")
            open(lf, "wb").write(b"one\ntwo\n")
            open(crlf, "wb").write(b"one\r\ntwo\r\n")
            self.assertEqual(rec.file_hash(lf), rec.file_hash(crlf))
            # And it is the plain sha256 of the LF form, which is what the
            # PowerShell side computes and what the PowerShell suite asserts.
            self.assertEqual(rec.file_hash(lf), hashlib.sha256(b"one\ntwo\n").hexdigest())

    def test_a_lone_cr_is_not_folded(self):
        # Only the CRLF pair is a line-ending artefact. A bare CR is content.
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "x.md")
            open(p, "wb").write(b"a\rb\n")
            self.assertEqual(rec.file_hash(p), hashlib.sha256(b"a\rb\n").hexdigest())


class WatchedSetTests(unittest.TestCase):
    def test_every_skill_md_reference_and_the_fixture_file(self):
        root = _scratch_repo()
        try:
            got = rec.watched_files(root)
            for skill in grader.SKILLS:
                self.assertIn(f"{skill}/SKILL.md", got)
                self.assertIn(f"{skill}/references/a.md", got)
            self.assertIn("examples/golden-prompts.md", got)
            self.assertEqual(got, sorted(got))
        finally:
            shutil.rmtree(root)

    def test_a_new_reference_file_is_watched_without_editing_a_list(self):
        root = _scratch_repo()
        try:
            before = rec.watched_files(root)
            new = os.path.join(root, grader.SKILLS[0], "references", "zzz.md")
            open(new, "w").write("new\n")
            after = rec.watched_files(root)
            self.assertEqual(set(after) - set(before), {f"{grader.SKILLS[0]}/references/zzz.md"})
        finally:
            shutil.rmtree(root)

    def test_only_markdown_under_references_counts(self):
        root = _scratch_repo()
        try:
            open(os.path.join(root, grader.SKILLS[0], "references", "notes.txt"), "w").write("x")
            self.assertNotIn(f"{grader.SKILLS[0]}/references/notes.txt", rec.watched_files(root))
        finally:
            shutil.rmtree(root)


class StalenessTests(unittest.TestCase):
    def test_fresh_after_recording(self):
        root = _scratch_repo()
        try:
            rec.write_marker("agents", "3 of 3", repo=root, date="2026-01-01")
            self.assertEqual(rec.staleness(root), [])
            marker = rec.read_marker(root)
            self.assertEqual(marker["method"], "agents")
            self.assertEqual(marker["result"], "3 of 3")
            self.assertEqual(marker["date"], "2026-01-01")
        finally:
            shutil.rmtree(root)

    def test_a_changed_watched_file_is_named(self):
        root = _scratch_repo()
        try:
            rec.write_marker("agents", "3 of 3", repo=root)
            with open(os.path.join(root, "examples", "golden-prompts.md"), "a") as fh:
                fh.write("changed\n")
            self.assertEqual(rec.staleness(root), ["examples/golden-prompts.md"])
        finally:
            shutil.rmtree(root)

    def test_a_recorded_file_that_disappeared_is_named(self):
        root = _scratch_repo()
        try:
            rec.write_marker("agents", "3 of 3", repo=root)
            gone = f"{grader.SKILLS[0]}/references/a.md"
            os.remove(os.path.join(root, gone))
            self.assertEqual(rec.staleness(root), [gone])
        finally:
            shutil.rmtree(root)

    def test_a_new_watched_file_is_named(self):
        root = _scratch_repo()
        try:
            rec.write_marker("agents", "3 of 3", repo=root)
            new = f"{grader.SKILLS[0]}/references/b.md"
            open(os.path.join(root, new), "w").write("b\n")
            self.assertEqual(rec.staleness(root), [new])
        finally:
            shutil.rmtree(root)

    def test_the_marker_is_ascii_and_lf(self):
        root = _scratch_repo()
        try:
            path = rec.write_marker("api", "3 of 3", repo=root)
            data = open(path, "rb").read()
            self.assertTrue(all(b in (9, 10) or 32 <= b <= 126 for b in data))
            self.assertNotIn(b"\r", data)
        finally:
            shutil.rmtree(root)


class _Message:
    def __init__(self, text: str, stop_reason: str = "end_turn"):
        self.content = [types.SimpleNamespace(type="text", text=text)]
        self.stop_reason = stop_reason
        self.model = "stub"
        self.usage = types.SimpleNamespace(input_tokens=1, output_tokens=1)


class RunnerRecordingTests(unittest.TestCase):
    """The runner records a marker only for a run of EVERY fixture that passed.

    The model call is stubbed the same way the runner's own tests stub it.
    Recording is redirected to a scratch repo by patching write_marker, so no
    test touches the real examples/golden-run.json.
    """

    def setUp(self):
        self.fake = types.ModuleType("anthropic")
        self.fake.Anthropic = lambda: object()
        self.fake.AuthenticationError = type("AuthenticationError", (Exception,), {})
        self.saved_mod = sys.modules.get("anthropic")
        self.saved_call = runner.call_model
        self.saved_write = rec.write_marker
        sys.modules["anthropic"] = self.fake
        self.recorded: list[tuple[str, str]] = []
        rec.write_marker = lambda method, result, **kw: self.recorded.append((method, result)) or "x"

    def tearDown(self):
        runner.call_model = self.saved_call
        rec.write_marker = self.saved_write
        if self.saved_mod is None:
            del sys.modules["anthropic"]
        else:
            sys.modules["anthropic"] = self.saved_mod

    def _run(self, argv: list[str], answer: str) -> int:
        runner.call_model = lambda c, p: _Message(answer)
        with tempfile.TemporaryDirectory() as d:
            with redirect_stdout(io.StringIO()):
                return runner.main(argv + ["--out", d])

    def test_a_partial_run_is_not_recorded(self):
        self._run(["--fixture", "1"], "## Objective\nx\n")
        self.assertEqual(self.recorded, [])

    def test_no_record_flag_is_honoured(self):
        self._run(["--no-record"], "## Objective\nx\n")
        self.assertEqual(self.recorded, [])

    def test_a_failing_full_run_is_not_recorded(self):
        # An answer with no sections and no code block fails every fixture.
        code = self._run([], "nothing useful")
        self.assertEqual(code, 1)
        self.assertEqual(self.recorded, [])

    def test_full_run_records_only_when_every_fixture_passes(self):
        # Force every grade to pass so the recording path itself is exercised
        # without depending on a stub answer that satisfies ten real specs.
        saved = grader.grade
        grader.grade = lambda f, t, d: types.SimpleNamespace(success=True, passed=["ok"], failed=[])
        saved_report = grader.report
        grader.report = lambda *a, **k: None
        try:
            code = self._run([], "## Objective\nx\n")
        finally:
            grader.grade = saved
            grader.report = saved_report
        self.assertEqual(code, 0)
        n = len(grader.load_fixtures())
        self.assertEqual(self.recorded, [("api", f"{n} of {n}")])


class FullPassTests(unittest.TestCase):
    """REGRESSION: only a run of every fixture, all passing, may be recorded.

    Review finding. The CLI wrote a marker for any non-empty --result, so
    "9 of 10" or "2 of 2" from a partial or failing run silenced the
    validator's freshness notice while the behavioral baseline was unproven --
    on the very path a run by subagents has to take, since the API runner
    guards itself.
    """

    def test_a_full_pass_of_every_fixture_is_accepted(self):
        n = len(grader.load_fixtures())
        self.assertTrue(rec.full_pass(f"{n} of {n}"))
        self.assertTrue(rec.full_pass(f"  {n}  of  {n}  "))

    def test_a_trailing_newline_does_not_smuggle_anything_past_the_match(self):
        # `$` in a Python regex also matches before a trailing newline, so an
        # anchored search would accept "10 of 10\nand 3 failed". fullmatch
        # with no anchors is what makes the whole string the subject.
        n = len(grader.load_fixtures())
        self.assertTrue(rec.full_pass(f"{n} of {n}\n"))
        self.assertFalse(rec.full_pass(f"{n} of {n}\nand 3 failed"))

    def test_a_partial_or_failing_run_is_rejected(self):
        n = len(grader.load_fixtures())
        self.assertFalse(rec.full_pass(f"{n - 1} of {n}"))
        self.assertFalse(rec.full_pass("2 of 2"))          # a partial run, all passing
        self.assertFalse(rec.full_pass(f"{n} of {n + 1}"))
        self.assertFalse(rec.full_pass("all passed"))
        self.assertFalse(rec.full_pass(""))

    def test_the_total_is_the_fixture_count_not_a_constant(self):
        self.assertTrue(rec.full_pass("3 of 3", total=3))
        self.assertFalse(rec.full_pass("3 of 3", total=4))


class CliTests(unittest.TestCase):
    def test_check_reports_fresh_or_stale(self):
        root = _scratch_repo()
        saved = grader.REPO
        try:
            rec.write_marker("agents", "3 of 3", repo=root)
            # The CLI defaults to the real repo; point it at the scratch one.
            rec.grader.REPO = root
            out = io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(rec.main(["--check"]), 0)
            self.assertIn("saw the current skill content", out.getvalue())
            with open(os.path.join(root, "examples", "golden-prompts.md"), "a") as fh:
                fh.write("edit\n")
            out = io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(rec.main(["--check"]), 1)
            self.assertIn("examples/golden-prompts.md", out.getvalue())
        finally:
            rec.grader.REPO = saved
            shutil.rmtree(root)

    def test_recording_a_partial_run_is_refused(self):
        # write_marker is patched, so a regression here cannot touch the real
        # marker: the test proves the CLI never reaches it.
        saved = rec.write_marker
        calls: list[tuple[str, str]] = []
        rec.write_marker = lambda method, result, **kw: calls.append((method, result)) or "x"
        try:
            n = len(grader.load_fixtures())
            # An empty --result is refused one step earlier, by the
            # required-arguments check, so it is not in this list.
            for bad in [f"{n - 1} of {n}", "2 of 2", "green"]:
                err = io.StringIO()
                with redirect_stderr(err):
                    with self.assertRaises(SystemExit) as cm:
                        rec.main(["--method", "agents", "--result", bad])
                self.assertEqual(cm.exception.code, 2)
                self.assertIn("every fixture passing", err.getvalue())
            self.assertEqual(calls, [])
            with redirect_stdout(io.StringIO()):
                self.assertEqual(rec.main(["--method", "agents", "--result", f"{n} of {n}"]), 0)
            self.assertEqual(calls, [("agents", f"{n} of {n}")])
        finally:
            rec.write_marker = saved


if __name__ == "__main__":
    unittest.main()
