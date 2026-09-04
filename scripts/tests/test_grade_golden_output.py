#!/usr/bin/env python3
"""Unit tests for the golden-prompt grader and runner.

Run from the repository root:

    python -m unittest discover -s scripts/tests -p "test_*.py"

Stdlib unittest only, like the dictionary builder's suite. The runner's one
network call is stubbed: CI holds no model credential, and the test proves the
request shape and the write-then-grade path without one.

scripts/tests/mutation-check.py breaks the grader in each way these tests
exist to catch and asserts the suite goes red; add a GRADER_MUTS entry there
when adding a check here.
"""
from __future__ import annotations

import io
import os
import sys
import tempfile
import types
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import grade_golden_output as g  # noqa: E402
import run_golden_prompts as runner  # noqa: E402

DECLARED = {
    "Objective", "Query", "Why efficient", "Assumptions", "Data dictionary notes",
    "Tuning", "Validate", "What changed", "Discovery query", "Next step",
    "Enrichment notes",
}


def fx(number: int = 1, skill: str = "splunk-sentinel-query-builder", **spec) -> g.Fixture:
    return g.Fixture(number, "t", skill, "Use $" + skill + " to do a thing", spec)


def fixture_doc(spec_block: str = '{"sections": ["Objective"]}', prompt: str = "Use $splunk-sentinel-query-builder to x") -> str:
    return (
        "# Golden\n\n## 1. One\n\nPrompt:\n\n```text\n" + prompt + "\n```\n\n"
        "Expected output:\n\n- `Objective`\n\nGrader spec:\n\n```json\n" + spec_block + "\n```\n"
    )


GOOD_SHORT = """## Objective
Find it.

## Query

```spl
index=windows sourcetype=XmlWinEventLog EventCode=1 earliest=-24h
| stats count by host
```

## Assumptions
- EventCode=1 is Sysmon process creation; drop it if your TA differs.
"""


class FixtureParsingTests(unittest.TestCase):
    def test_real_fixture_file_parses_with_a_spec_per_fixture(self):
        fixtures = g.load_fixtures()
        self.assertEqual([f.number for f in fixtures], list(range(1, len(fixtures) + 1)))
        self.assertGreaterEqual(len(fixtures), 10)
        for f in fixtures:
            self.assertIn(f.skill, g.SKILLS, f"fixture {f.number}")
            self.assertTrue(set(f.spec) <= g.SPEC_KEYS, f"fixture {f.number}")
            self.assertTrue(f.prompt.startswith("Use $"), f"fixture {f.number}")

    def test_declared_sections_come_from_the_skills(self):
        declared = g.declared_sections()
        for name in ("Objective", "Discovery query", "What changed", "Enrichment notes"):
            self.assertIn(name, declared)

    def test_fixture_without_a_spec_is_an_error_not_a_pass(self):
        doc = fixture_doc().replace("```json", "```yaml")
        with self.assertRaises(g.FixtureError):
            g.parse_fixtures(doc)

    def test_two_specs_or_unknown_keys_are_errors(self):
        with self.assertRaises(g.FixtureError):
            g.parse_fixtures(fixture_doc() + "\n```json\n{}\n```\n")
        with self.assertRaises(g.FixtureError):
            g.parse_fixtures(fixture_doc('{"sectionz": []}'))

    def test_prompt_must_name_a_skill(self):
        with self.assertRaises(g.FixtureError):
            g.parse_fixtures(fixture_doc(prompt="build me a query"))

    def test_spec_requiring_an_undeclared_section_is_an_error(self):
        with self.assertRaises(g.FixtureError):
            g.grade(fx(sections=["Executive Summary"]), GOOD_SHORT, DECLARED)


class SectionDetectionTests(unittest.TestCase):
    def test_label_styles_are_all_recognised(self):
        text = "## Objective\nx\n**Query**\n```spl\n| tstats count\n```\n3. Why efficient\ny\nAssumptions:\nz\n### 4. Tuning (only if needed)\nq\n"
        self.assertEqual(g.find_sections(text, DECLARED),
                         ["Objective", "Query", "Why efficient", "Assumptions", "Tuning"])

    def test_label_match_is_case_insensitive(self):
        self.assertEqual(g.find_sections("## Why Efficient\n", DECLARED), ["Why efficient"])

    def test_labels_inside_fenced_blocks_are_not_sections(self):
        text = "## Objective\n```spl\n| tstats count\nTuning\n```\n"
        self.assertEqual(g.find_sections(text, DECLARED), ["Objective"])

    def test_section_order_is_enforced(self):
        swapped = GOOD_SHORT.replace("## Objective\nFind it.\n\n", "") + "\n## Objective\nFind it.\n"
        r = g.grade(fx(sections=["Objective", "Query", "Assumptions"]), swapped, DECLARED)
        self.assertTrue(any("out of order" in m for m in r.failed), r.failed)

    def test_missing_and_forbidden_sections(self):
        r = g.grade(fx(sections=["Objective", "Tuning"], forbid_sections=["Query"]), GOOD_SHORT, DECLARED)
        self.assertTrue(any("missing section(s): Tuning" in m for m in r.failed), r.failed)
        self.assertTrue(any("forbidden section present: Query" in m for m in r.failed), r.failed)

    def test_section_body_stops_at_the_next_label(self):
        self.assertIn("EventCode=1 is Sysmon", g.section_body(GOOD_SHORT, "Assumptions", DECLARED))
        self.assertNotIn("stats count", g.section_body(GOOD_SHORT, "Assumptions", DECLARED))
        self.assertEqual(g.section_body(GOOD_SHORT, "Tuning", DECLARED), "")


class QueryBlockTests(unittest.TestCase):
    def test_query_block_is_the_one_under_query_not_the_original_under_what_changed(self):
        text = ("## Query\n```kql\nSigninLogs\n| where TimeGenerated > ago(7d)\n| extend U = x\n```\n"
                "## What changed\nBefore:\n```kql\nSigninLogs\n| extend U = x\n| where TimeGenerated > ago(7d)\n```\n")
        r = g.grade(fx(query_not_matches=[r"(?s)\|\s*extend.*\|\s*where\s+TimeGenerated"]), text, DECLARED)
        self.assertTrue(r.success, r.failed)

    def test_positive_query_rule_is_satisfied_by_any_block_in_the_section(self):
        text = ("## Discovery query\n```spl\n| tstats count from datamodel=Authentication.Authentication by index\n```\n"
                "or\n```spl\n| tstats count where index=* earliest=-24h by index, sourcetype\n```\n")
        r = g.grade(fx(query_matches=[r"where\s+index=\*[^\n|]*\bby\s+index,\s*sourcetype"]), text, DECLARED)
        self.assertTrue(r.success, r.failed)

    def test_query_lang_ignores_the_echoed_source_query(self):
        text = ("## Query\nSource:\n```spl\nindex=windows_auth earliest=-24h\n| stats count by user\n```\n"
                "Target:\n```kql\nSigninLogs\n| where TimeGenerated > ago(24h)\n```\n")
        r = g.grade(fx(query_not_matches=[r"\buser\b"]), text, DECLARED)
        self.assertFalse(r.success)
        r = g.grade(fx(query_not_matches=[r"\buser\b"], query_lang="kql"), text, DECLARED)
        self.assertTrue(r.success, r.failed)

    def test_query_rules_fail_without_a_query_block(self):
        r = g.grade(fx(query_matches=["x"], code_block=False), "## Objective\nnothing\n", DECLARED)
        self.assertTrue(any("no fenced block under" in m for m in r.failed), r.failed)

    def test_assumed_if_used_requires_the_assumption(self):
        r = g.grade(fx(assumed_if_used=["EventCode"]), GOOD_SHORT, DECLARED)
        self.assertTrue(r.success, r.failed)
        silent = GOOD_SHORT.replace("- EventCode=1 is Sysmon process creation; drop it if your TA differs.", "- none")
        r = g.grade(fx(assumed_if_used=["EventCode"]), silent, DECLARED)
        self.assertTrue(any("Assumptions must name it" in m for m in r.failed), r.failed)


class IdentifierTests(unittest.TestCase):
    def test_index_and_sourcetype_values_read_positionally(self):
        text = 'index=firewall sourcetype="cisco:asa" | search index IN (proxy, "dns") sourcetype IN (bluecoat:proxysg:access:kv)'
        self.assertEqual(g.index_values(text), {"firewall", "proxy", "dns"})
        self.assertEqual(g.sourcetype_values(text), {"cisco:asa", "bluecoat:proxysg:access:kv"})

    def test_placeholders_and_wildcards_are_not_claims(self):
        text = "index=* index=YOUR_INDEX index=<name> sourcetype=... sourcetype=zscaler*"
        self.assertEqual(g.index_values(text), set())
        self.assertEqual(g.sourcetype_values(text), set())

    def test_invented_index_is_reported_only_from_code_blocks(self):
        text = "## Objective\nprose mentions index=guess\n## Query\n```spl\nindex=windows earliest=-1h\n| head 5\n```\n"
        r = g.grade(fx(indexes=["windows"], sections=[]), text, DECLARED)
        self.assertTrue(r.success, r.failed)
        r = g.grade(fx(indexes=["proxy"]), text, DECLARED)
        self.assertTrue(any("invented ['windows']" in m for m in r.failed), r.failed)

    def test_kql_tables_leading_union_join_and_let(self):
        self.assertEqual(g.kql_tables("SigninLogs\n| union AuditLogs, Ghost\n| join kind=inner (SecurityEvent) on x"),
                         {"SigninLogs", "AuditLogs", "Ghost", "SecurityEvent"})
        # The let binds a FUNCTION CALL, so it contributes no table -- but
        # `Usage` on the next line is the query's source and is reported. This
        # asserted set() while the leading table was read from line 0 only,
        # which contradicted the `Usage`-leads case asserted directly below.
        self.assertEqual(g.kql_tables("let recent = toscalar(1);\nUsage\n| where TimeGenerated > ago(7d)"), {"Usage"})
        self.assertEqual(g.kql_tables("Usage\n| summarize by DataType"), {"Usage"})
        self.assertEqual(g.kql_tables("// comment\nDeviceProcessEvents\n| getschema"), {"DeviceProcessEvents"})

    def test_kql_placeholders_and_union_options_are_not_tables(self):
        self.assertEqual(g.kql_tables("TableName | getschema;\nTableName | take 5"), set())
        self.assertEqual(g.kql_tables("union withsource=Table_ *\n| where TimeGenerated > ago(1h)"), set())
        self.assertEqual(g.kql_tables("SigninLogs\n| join kind=inner (AuditLogs) on Id"), {"SigninLogs", "AuditLogs"})

    def test_a_table_bound_by_let_is_a_table_reference(self):
        # REGRESSION: the scan only read `union`/`join` lines and the leading
        # identifier, so a table introduced by `let` was invisible and an
        # invented one satisfied a fixture's `tables` allowlist. The name the
        # let BINDS is a local, not a table, and must not be reported.
        self.assertEqual(g.kql_tables("let recent = GhostTable;\nrecent | take 5"), {"GhostTable"})
        self.assertEqual(g.kql_tables("let cutoff = ago(1d);\nSigninLogs\n| where TimeGenerated > cutoff"),
                         {"SigninLogs"})

    def test_a_join_operand_on_the_next_line_is_a_table_reference(self):
        # REGRESSION: the line-oriented scan could not see past the newline
        # after `join (`, which is how a model formats a wide join.
        self.assertEqual(g.kql_tables("SigninLogs\n| join (\n    GhostTable\n    | take 5\n) on Id"),
                         {"SigninLogs", "GhostTable"})


class GenericRuleTests(unittest.TestCase):
    def test_unquoted_where_boolean_fails(self):
        text = GOOD_SHORT.replace("| stats count by host", "| where noise=true")
        r = g.grade(fx(), text, DECLARED)
        self.assertTrue(any("unquoted true/false" in m for m in r.failed), r.failed)
        r = g.grade(fx(), text.replace("noise=true", 'noise="true"'), DECLARED)
        self.assertTrue(r.success, r.failed)

    def test_raw_spl_search_needs_a_time_bound_but_tstats_does_not(self):
        unbounded = GOOD_SHORT.replace(" earliest=-24h", "")
        r = g.grade(fx(), unbounded, DECLARED)
        self.assertTrue(any("time-bound" in m for m in r.failed), r.failed)
        r = g.grade(fx(), "## Query\n```spl\n| tstats count where index=* by index, sourcetype\n```\n", DECLARED)
        self.assertTrue(r.success, r.failed)

    def test_kql_block_must_bound_timegenerated_unless_it_reads_schema(self):
        r = g.grade(fx(), "## Query\n```kql\nSigninLogs\n| take 5\n```\n", DECLARED)
        self.assertTrue(any("TimeGenerated" in m for m in r.failed), r.failed)
        r = g.grade(fx(), "## Query\n```kql\nSigninLogs\n| getschema\n```\n", DECLARED)
        self.assertTrue(r.success, r.failed)

    def test_leading_pipe_search_is_still_a_raw_event_search(self):
        # REGRESSION: the check skipped every block whose first line began with
        # a pipe, on the assumption that a leading pipe means a generating
        # command. '| search index=windows' is a raw-event search wearing that
        # syntax and scanned all history while the grader ran no check at all.
        r = g.grade(fx(), "## Query\n```spl\n| search index=windows\n| stats count\n```\n", DECLARED)
        self.assertTrue(any("time-bound" in m for m in r.failed), r.failed)

    def test_a_generating_command_is_still_exempt(self):
        r = g.grade(fx(), "## Query\n```spl\n| tstats count where index=x by sourcetype\n```\n", DECLARED)
        self.assertFalse(any("time-bound" in m for m in r.failed), r.failed)

    def test_time_mentioned_in_an_aggregation_is_not_a_time_bound(self):
        # REGRESSION: the pattern accepted any occurrence of '_time', so
        # 'index=windows | stats latest(_time)' graded as bounded while
        # scanning all history. A bound needs an actual predicate.
        r = g.grade(fx(), "## Query\n```spl\nindex=windows | stats latest(_time)\n```\n", DECLARED)
        self.assertTrue(any("time-bound" in m for m in r.failed), r.failed)
        r = g.grade(fx(), '## Query\n```spl\nindex=windows\n| where _time > relative_time(now(), "-1d")\n```\n', DECLARED)
        self.assertFalse(any("time-bound" in m for m in r.failed), r.failed)

    def test_head_still_bounds_a_raw_search(self):
        r = g.grade(fx(), "## Query\n```spl\nindex=windows\n| head 5\n```\n", DECLARED)
        self.assertFalse(any("time-bound" in m for m in r.failed), r.failed)

    def test_time_bound_may_sit_on_the_second_line_of_the_search(self):
        text = ("## Query\n```spl\n((index=firewall sourcetype=cisco:asa) OR (index=proxy sourcetype=bluecoat:proxysg:access:kv))\n"
                "earliest=-24h latest=now\n| stats count by src\n```\n")
        r = g.grade(fx(), text, DECLARED)
        self.assertTrue(r.success, r.failed)
        r = g.grade(fx(), text.replace("earliest=-24h latest=now\n", ""), DECLARED)
        self.assertTrue(any("time-bound" in m for m in r.failed), r.failed)

    def test_negated_credential_sentence_is_the_rule_being_kept(self):
        self.assertTrue(g.asks_for_secret("Please paste your Splunk token here."))
        self.assertFalse(g.asks_for_secret("I will never ask you to type a token or password here."))
        self.assertFalse(g.asks_for_secret("Do not share the password with me; export it instead."))

    def test_asking_for_a_pasted_credential_fails(self):
        r = g.grade(fx(code_block=False), "Please paste your Splunk token here and I will run it.", DECLARED)
        self.assertTrue(any("credential" in m for m in r.failed), r.failed)
        r = g.grade(fx(code_block=False), "Export SPLUNK_TOKEN in your shell; never paste it into chat.", DECLARED)
        self.assertFalse(any("credential" in m for m in r.failed), r.failed)

    def test_missing_code_block_fails_unless_waived(self):
        r = g.grade(fx(), "## Objective\nwords only\n", DECLARED)
        self.assertTrue(any("fenced code block" in m for m in r.failed), r.failed)
        r = g.grade(fx(code_block=False), "## Objective\nwords only\n", DECLARED)
        self.assertTrue(r.success, r.failed)

    def test_crlf_answer_grades_like_lf(self):
        # Line splitting, the fence regex, and the section extractor (which
        # rejoins with LF) tolerate CRLF on their own; what needs the
        # normalisation is a top-level pattern that writes a literal newline,
        # which an author on either platform may reasonably do.
        spec = fx(sections=["Objective", "Query", "Assumptions"],
                  matches=["earliest=-24h\n\\| stats count"])
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "01.md")
            with open(p, "w", newline="") as fh:
                fh.write(GOOD_SHORT.replace("\n", "\r\n"))
            r = g.grade(spec, g.read_answer(p), DECLARED)
        self.assertTrue(r.success, r.failed)


class CliTests(unittest.TestCase):
    def _run(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = g.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_list_prints_every_prompt(self):
        code, out, _ = self._run(["--list"])
        self.assertEqual(code, 0)
        self.assertIn("## 1.", out)
        self.assertIn("splunk-data-dictionary-builder", out)

    def test_all_grades_present_responses_and_reports_absent_ones(self):
        with tempfile.TemporaryDirectory() as d:
            code, out, err = self._run(["--all", d])
            self.assertEqual(code, 2)
            self.assertIn("no NN.md responses", err)
            with open(os.path.join(d, "01.md"), "w") as fh:
                fh.write(GOOD_SHORT)
            code, out, _ = self._run(["--all", d, "--quiet"])
        self.assertEqual(code, 0, out)
        self.assertIn("[PASS] fixture 1", out)
        self.assertIn("had no response file", out)

    def test_single_fixture_failure_exits_nonzero(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "x.md")
            with open(p, "w") as fh:
                fh.write("## Objective\nno query\n")
            code, out, _ = self._run(["--fixture", "1", "--response", p])
        self.assertEqual(code, 1)
        self.assertIn("[FAIL] fixture 1", out)


class _Block:
    def __init__(self, type_, text=""):
        self.type, self.text = type_, text


class _Usage:
    input_tokens, output_tokens, cache_read_input_tokens = 10, 20, 5


class _Message:
    def __init__(self, text: str, stop_reason: str = "end_turn"):
        self.content = [_Block("thinking"), _Block("text", text)]
        self.stop_reason, self.usage, self.model = stop_reason, _Usage(), "claude-opus-5"


class RunnerTests(unittest.TestCase):
    def test_request_shape(self):
        f = g.load_fixtures()[0]
        p = runner.request_params(f, "claude-opus-5", "high")
        self.assertEqual(p["model"], "claude-opus-5")
        self.assertEqual(p["fallbacks"], "default")
        self.assertEqual(p["betas"], ["server-side-fallback-2026-07-01"])
        self.assertEqual(p["output_config"], {"effort": "high"})
        self.assertNotIn("thinking", p)
        self.assertEqual(p["system"][0]["cache_control"], {"type": "ephemeral"})
        self.assertEqual(p["messages"], [{"role": "user", "content": f.prompt}])

    def test_system_prompt_carries_skill_and_every_reference(self):
        text = runner.build_system("splunk-sentinel-query-builder")
        self.assertIn('<file path="splunk-sentinel-query-builder/SKILL.md">', text)
        for ref in os.listdir(os.path.join(g.REPO, "splunk-sentinel-query-builder", "references")):
            self.assertIn(f'<file path="splunk-sentinel-query-builder/references/{ref}">', text)
        self.assertTrue(text.startswith(runner.SYSTEM_PREAMBLE))

    def test_answer_text_keeps_only_text_blocks(self):
        self.assertEqual(runner.answer_text(_Message("hello")), "hello")

    def test_dry_run_calls_nothing(self):
        out = io.StringIO()
        with redirect_stdout(out):
            code = runner.main(["--dry-run", "--fixture", "2"])
        self.assertEqual(code, 0)
        self.assertIn("=== fixture 2", out.getvalue())
        self.assertNotIn("=== fixture 1", out.getvalue())

    def test_run_writes_answers_and_grades_them_through_a_stub(self):
        fake = types.ModuleType("anthropic")
        fake.Anthropic = lambda: object()
        fake.AuthenticationError = type("AuthenticationError", (Exception,), {})
        calls = []

        def stub(client, params):
            calls.append(params["model"])
            return _Message(GOOD_SHORT)

        saved_mod, saved_call = sys.modules.get("anthropic"), runner.call_model
        sys.modules["anthropic"], runner.call_model = fake, stub
        try:
            with tempfile.TemporaryDirectory() as d:
                out = io.StringIO()
                with redirect_stdout(out):
                    code = runner.main(["--fixture", "1", "--out", d])
                with open(os.path.join(d, "01.md")) as fh:
                    written = fh.read()
        finally:
            runner.call_model = saved_call
            if saved_mod is None:
                del sys.modules["anthropic"]
            else:
                sys.modules["anthropic"] = saved_mod
        self.assertEqual(code, 0, out.getvalue())
        self.assertEqual(calls, ["claude-opus-5"])
        self.assertIn("stop_reason: end_turn", written)
        self.assertTrue(written.endswith(GOOD_SHORT))
        self.assertIn("[PASS] fixture 1", out.getvalue())

    def test_refusal_is_a_failure_not_a_grade(self):
        fake = types.ModuleType("anthropic")
        fake.Anthropic = lambda: object()
        fake.AuthenticationError = type("AuthenticationError", (Exception,), {})
        saved_mod, saved_call = sys.modules.get("anthropic"), runner.call_model
        sys.modules["anthropic"], runner.call_model = fake, lambda c, p: _Message("", "refusal")
        try:
            with tempfile.TemporaryDirectory() as d:
                out = io.StringIO()
                with redirect_stdout(out):
                    code = runner.main(["--fixture", "1", "--out", d])
        finally:
            runner.call_model = saved_call
            if saved_mod is None:
                del sys.modules["anthropic"]
            else:
                sys.modules["anthropic"] = saved_mod
        self.assertEqual(code, 1)
        self.assertIn("refused", out.getvalue())


if __name__ == "__main__":
    unittest.main()
