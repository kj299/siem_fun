#!/usr/bin/env python3
"""Unit tests for the Splunk data dictionary builder helpers.

Run from the repository root:

    python -m unittest discover -s splunk-data-dictionary-builder/tests

Tests tagged REGRESSION lock down a defect that actually shipped and was caught
in review. The named bug is the reason the assertion exists; do not relax one
without understanding what it protects.

Only stdlib unittest is used so the suite runs anywhere the script itself runs,
with no dependency to install.
"""

from __future__ import annotations

import json
import sys
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import build_splunk_dictionary as bsd  # noqa: E402


class _FakeResponse:
    """Context-manager stand-in for the object urlopen returns."""

    def __init__(self, payload: bytes) -> None:
        self._payload = payload

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, *exc_info: object) -> bool:
        return False

    def read(self) -> bytes:
        return self._payload


class _RecordingClient:
    """Minimal SplunkClient stand-in that records searches and replays a canned payload."""

    def __init__(self, payload: dict | None = None, error: Exception | None = None) -> None:
        self.payload = {"results": []} if payload is None else payload
        self.error = error
        self.searches: list[tuple[str, str]] = []

    def search_oneshot(self, search: str, earliest: str) -> dict:
        self.searches.append((search, earliest))
        if self.error is not None:
            raise self.error
        return self.payload


class TestRedactUrlCredentials(unittest.TestCase):
    def test_strips_userinfo(self) -> None:
        self.assertEqual(
            bsd._redact_url_credentials("https://admin:secret@host:8089"),
            "https://host:8089",
        )

    def test_leaves_credential_free_url_untouched(self) -> None:
        self.assertEqual(
            bsd._redact_url_credentials("https://host:8089"),
            "https://host:8089",
        )

    def test_strips_username_only_userinfo(self) -> None:
        self.assertEqual(
            bsd._redact_url_credentials("https://admin@host:8089"),
            "https://host:8089",
        )

    def test_handles_missing_port(self) -> None:
        self.assertEqual(
            bsd._redact_url_credentials("https://admin:secret@host"),
            "https://host",
        )

    def test_preserves_ipv6_brackets(self) -> None:
        """REGRESSION: urlparse().hostname drops the brackets from IPv6 literals.

        Rebuilding the netloc from the bare hostname produced
        'https://2001:db8::1:8089', where host and port are indistinguishable.
        """
        self.assertEqual(
            bsd._redact_url_credentials("https://admin:secret@[2001:db8::1]:8089"),
            "https://[2001:db8::1]:8089",
        )

    def test_preserves_ipv6_brackets_without_port(self) -> None:
        self.assertEqual(
            bsd._redact_url_credentials("https://admin:secret@[2001:db8::1]"),
            "https://[2001:db8::1]",
        )

    def test_fails_closed_on_unparseable_url(self) -> None:
        """REGRESSION: redaction used to fail OPEN.

        A malformed port makes urlparse raise on .port access. The original
        implementation swallowed that and returned the input string unchanged,
        writing the credentials it exists to strip straight into the output.
        """
        redacted = bsd._redact_url_credentials("https://admin:secret@host:8089x")
        self.assertNotIn("secret", redacted)
        self.assertNotIn("admin", redacted)


class TestSafeSplIdent(unittest.TestCase):
    def test_accepts_plain_identifier(self) -> None:
        warnings: list[str] = []
        self.assertEqual(bsd._safe_spl_ident("Network_Traffic", "ctx", warnings), "Network_Traffic")
        self.assertEqual(warnings, [])

    def test_accepts_internal_hyphen(self) -> None:
        """Splunk permits hyphens in dataset IDs; rejecting them skipped real coverage."""
        warnings: list[str] = []
        self.assertEqual(bsd._safe_spl_ident("my-dataset", "ctx", warnings), "my-dataset")
        self.assertEqual(warnings, [])

    def test_rejects_leading_hyphen(self) -> None:
        """REGRESSION: a leading hyphen reads as a malformed option in unquoted SPL."""
        warnings: list[str] = []
        self.assertIsNone(bsd._safe_spl_ident("-dataset", "ctx", warnings))
        self.assertIsNone(bsd._safe_spl_ident("-", "ctx", warnings))

    def test_rejects_trailing_newline(self) -> None:
        """REGRESSION: the original guard used re.match with a '$' anchor.

        Python's '$' also matches before a trailing newline, so 'Web\\n' passed
        validation and was interpolated unquoted into the tstats search.
        """
        warnings: list[str] = []
        self.assertIsNone(bsd._safe_spl_ident("Web\n", "ctx", warnings))

    def test_rejects_spl_metacharacters(self) -> None:
        warnings: list[str] = []
        for value in ('Net Traffic', 'x"y', "a|b", "a b", "", "a\tb"):
            with self.subTest(value=value):
                self.assertIsNone(bsd._safe_spl_ident(value, "ctx", warnings))

    def test_records_a_warning_when_rejecting(self) -> None:
        warnings: list[str] = []
        bsd._safe_spl_ident("bad name", "data model name", warnings)
        self.assertEqual(len(warnings), 1)
        self.assertIn("data model name", warnings[0])


class TestBooleanParsing(unittest.TestCase):
    def test_parse_bool_truthy_values(self) -> None:
        for value in ("1", "true", "TRUE", " yes ", "on"):
            with self.subTest(value=value):
                self.assertTrue(bsd.parse_bool(value, False))

    def test_parse_bool_falsy_values(self) -> None:
        for value in ("0", "false", "FALSE", " no ", "off", ""):
            with self.subTest(value=value):
                self.assertFalse(bsd.parse_bool(value, True))

    def test_parse_bool_unknown_returns_default(self) -> None:
        self.assertTrue(bsd.parse_bool("maybe", True))
        self.assertFalse(bsd.parse_bool("maybe", False))

    def test_env_bool_and_content_flag_share_polarity(self) -> None:
        """REGRESSION: these were two parsers with opposite-polarity truth sets.

        env_bool treated anything not in {0,false,no} as True while _content_flag
        treated anything not in {1,true,yes} as False, so 'on' parsed True through
        one and False through the other.
        """
        for value in ("on", "off", "yes", "no", "1", "0", "true", "false"):
            with self.subTest(value=value):
                with mock.patch.dict("os.environ", {"SPLUNK_TEST_FLAG": value}):
                    self.assertEqual(
                        bsd.env_bool("SPLUNK_TEST_FLAG", False),
                        bsd._content_flag(value),
                    )

    def test_env_bool_returns_default_when_unset(self) -> None:
        with mock.patch.dict("os.environ", {}, clear=True):
            self.assertTrue(bsd.env_bool("SPLUNK_ABSENT_FLAG", True))
            self.assertFalse(bsd.env_bool("SPLUNK_ABSENT_FLAG", False))

    def test_content_flag_treats_string_zero_as_false(self) -> None:
        """REGRESSION: the code used bool(value), and bool('0') is True.

        Splunk REST can serialize content booleans as strings, so an enabled
        index was dropped from discovery and an unaccelerated data model was
        queried with summariesonly=true.
        """
        self.assertFalse(bsd._content_flag("0"))
        self.assertFalse(bsd._content_flag("false"))
        self.assertTrue(bsd._content_flag("1"))

    def test_content_flag_handles_native_types(self) -> None:
        self.assertTrue(bsd._content_flag(True))
        self.assertFalse(bsd._content_flag(False))
        self.assertTrue(bsd._content_flag(1))
        self.assertFalse(bsd._content_flag(0))
        self.assertFalse(bsd._content_flag(None))


class TestCollectSearchMessages(unittest.TestCase):
    def test_collects_error_and_fatal(self) -> None:
        """REGRESSION: Splunk returns search failures inside HTTP 200 bodies.

        Reading only payload['results'] made a FATAL search look identical to a
        successful search that matched nothing.
        """
        warnings: list[str] = []
        payload = {
            "messages": [
                {"type": "FATAL", "text": "Error in 'tstats' command"},
                {"type": "ERROR", "text": "insufficient permissions"},
            ],
            "results": [],
        }
        bsd._collect_search_messages(payload, "ctx", warnings)
        self.assertEqual(len(warnings), 2)
        self.assertIn("Error in 'tstats' command", warnings[0])
        self.assertIn("ctx", warnings[0])

    def test_ignores_informational_messages(self) -> None:
        warnings: list[str] = []
        payload = {"messages": [{"type": "INFO", "text": "ok"}, {"type": "WARN", "text": "meh"}]}
        bsd._collect_search_messages(payload, "ctx", warnings)
        self.assertEqual(warnings, [])

    def test_tolerates_missing_and_malformed_messages(self) -> None:
        warnings: list[str] = []
        bsd._collect_search_messages({}, "ctx", warnings)
        bsd._collect_search_messages({"messages": ["a string", None]}, "ctx", warnings)
        self.assertEqual(warnings, [])

    def test_falls_back_when_text_is_absent(self) -> None:
        warnings: list[str] = []
        bsd._collect_search_messages({"messages": [{"type": "FATAL"}]}, "ctx", warnings)
        self.assertIn("unknown error", warnings[0])


class TestRunSearch(unittest.TestCase):
    def test_returns_none_and_warns_on_failure(self) -> None:
        warnings: list[str] = []
        client = _RecordingClient(error=RuntimeError("connection refused"))
        self.assertIsNone(bsd._run_search(client, "| tstats count", "-24h", "ctx", warnings))
        self.assertEqual(warnings, ["connection refused"])

    def test_returns_payload_and_collects_messages(self) -> None:
        warnings: list[str] = []
        client = _RecordingClient({"messages": [{"type": "ERROR", "text": "bad"}], "results": [{"a": 1}]})
        payload = bsd._run_search(client, "| tstats count", "-24h", "ctx", warnings)
        self.assertEqual(payload["results"], [{"a": 1}])
        self.assertEqual(len(warnings), 1)


class TestParseJsonAttribute(unittest.TestCase):
    def test_parses_json_string(self) -> None:
        self.assertEqual(bsd.parse_json_attribute('{"enabled": true}'), {"enabled": True})

    def test_passes_through_dict(self) -> None:
        self.assertEqual(bsd.parse_json_attribute({"a": 1}), {"a": 1})

    def test_invalid_json_returns_empty(self) -> None:
        self.assertEqual(bsd.parse_json_attribute("not json"), {})

    def test_warns_when_json_is_not_an_object(self) -> None:
        """REGRESSION: a JSON array parsed to [] and was silently discarded."""
        warnings: list[str] = []
        self.assertEqual(bsd.parse_json_attribute("[1, 2]", warnings=warnings, context="acceleration"), {})
        self.assertEqual(len(warnings), 1)
        self.assertIn("acceleration", warnings[0])

    def test_none_is_silent(self) -> None:
        warnings: list[str] = []
        self.assertEqual(bsd.parse_json_attribute(None, warnings=warnings, context="acceleration"), {})
        self.assertEqual(warnings, [])


class TestSplQuote(unittest.TestCase):
    def test_quotes_plain_value(self) -> None:
        self.assertEqual(bsd.spl_quote("firewall"), '"firewall"')

    def test_escapes_quotes_and_backslashes(self) -> None:
        self.assertEqual(bsd.spl_quote('a"b'), '"a\\"b"')
        self.assertEqual(bsd.spl_quote("a\\b"), '"a\\\\b"')

    def test_neutralizes_an_spl_breakout_attempt(self) -> None:
        quoted = bsd.spl_quote('x" | delete "')
        self.assertTrue(quoted.startswith('"') and quoted.endswith('"'))
        self.assertNotIn('" | delete "', quoted)


class TestCimHints(unittest.TestCase):
    def test_exact_match(self) -> None:
        self.assertEqual(bsd.cim_hints_for_sourcetype("cisco:asa"), ["Network_Traffic", "Network_Sessions", "Authentication"])

    def test_separated_variant_matches(self) -> None:
        self.assertEqual(bsd.cim_hints_for_sourcetype("pan:threat:custom"), ["Intrusion_Detection", "Malware", "Web"])
        self.assertEqual(bsd.cim_hints_for_sourcetype("bluecoat:proxysg:access:kv"), ["Web"])

    def test_does_not_match_accidental_superstring(self) -> None:
        """REGRESSION: prefix matching alone mapped 'zscalernss-weblogging' to Web."""
        self.assertEqual(bsd.cim_hints_for_sourcetype("zscalernss-weblogging"), [])

    def test_is_case_insensitive(self) -> None:
        self.assertEqual(bsd.cim_hints_for_sourcetype("CISCO:ASA"), bsd.cim_hints_for_sourcetype("cisco:asa"))

    def test_unknown_sourcetype_returns_empty(self) -> None:
        self.assertEqual(bsd.cim_hints_for_sourcetype("acme:widget"), [])

    def test_every_hint_key_resolves_to_its_own_models(self) -> None:
        """No hint key may be shadowed by an earlier prefix in the lookup order."""
        for key, models in bsd.CIM_SOURCETYPE_HINTS.items():
            with self.subTest(sourcetype=key):
                self.assertEqual(bsd.cim_hints_for_sourcetype(key), models)


class TestDiscoverSourcetypes(unittest.TestCase):
    def test_sorts_by_volume(self) -> None:
        """REGRESSION: without an explicit sort the max-sourcetypes slice took
        tstats group-by order, so the sampled subset was arbitrary rather than
        the highest-volume sourcetypes."""
        client = _RecordingClient()
        bsd.discover_sourcetypes(client, ["firewall"], "-24h", [])
        search = client.searches[0][0]
        self.assertIn("| sort 0 - count", search)

    def test_quotes_index_names(self) -> None:
        client = _RecordingClient()
        bsd.discover_sourcetypes(client, ["firewall", "proxy"], "-24h", [])
        search = client.searches[0][0]
        self.assertIn('index="firewall"', search)
        self.assertIn('index="proxy"', search)

    def test_returns_empty_without_indexes(self) -> None:
        client = _RecordingClient()
        self.assertEqual(bsd.discover_sourcetypes(client, [], "-24h", []), [])
        self.assertEqual(client.searches, [])

    def test_records_warning_on_search_failure(self) -> None:
        warnings: list[str] = []
        client = _RecordingClient(error=RuntimeError("boom"))
        self.assertEqual(bsd.discover_sourcetypes(client, ["firewall"], "-24h", warnings), [])
        self.assertEqual(warnings, ["boom"])


class TestSplunkClientRequest(unittest.TestCase):
    def _client(self) -> bsd.SplunkClient:
        return bsd.SplunkClient("https://host:8089", "token", None, None, True)

    def test_requires_credentials(self) -> None:
        client = bsd.SplunkClient("https://host:8089", None, None, None, True)
        with self.assertRaises(ValueError):
            client.request("/services/data/indexes")

    def test_returns_parsed_json(self) -> None:
        payload = json.dumps({"entry": [{"name": "firewall"}]}).encode("utf-8")
        with mock.patch.object(urllib.request, "urlopen", return_value=_FakeResponse(payload)):
            self.assertEqual(self._client().request("/x"), {"entry": [{"name": "firewall"}]})

    def test_non_json_body_raises_runtime_error(self) -> None:
        with mock.patch.object(urllib.request, "urlopen", return_value=_FakeResponse(b"<html>login</html>")):
            with self.assertRaises(RuntimeError) as caught:
                self._client().request("/x")
        self.assertIn("8089", str(caught.exception))

    def test_non_utf8_body_raises_runtime_error(self) -> None:
        """REGRESSION: the success path decoded strictly and outside any handler.

        A non-UTF-8 HTTP 200 body raised UnicodeDecodeError, which callers that
        catch only RuntimeError could not handle, crashing the whole run.
        """
        with mock.patch.object(urllib.request, "urlopen", return_value=_FakeResponse(b"\xff\xfe\x00binary")):
            with self.assertRaises(RuntimeError):
                self._client().request("/x")

    def test_http_error_becomes_runtime_error(self) -> None:
        error = urllib.error.HTTPError("https://host:8089/x", 401, "Unauthorized", {}, None)
        error.read = lambda: b"denied"  # type: ignore[method-assign]
        with mock.patch.object(urllib.request, "urlopen", side_effect=error):
            with self.assertRaises(RuntimeError) as caught:
                self._client().request("/x")
        self.assertIn("401", str(caught.exception))

    def test_search_oneshot_disables_the_result_cap(self) -> None:
        """REGRESSION: the oneshot endpoint caps output at 100 rows by default,
        silently truncating sourcetype discovery and CIM coverage."""
        captured: dict[str, bytes] = {}

        def _capture(request, **kwargs):
            captured["data"] = request.data
            return _FakeResponse(b"{}")

        with mock.patch.object(urllib.request, "urlopen", side_effect=_capture):
            self._client().search_oneshot("| tstats count", "-24h")
        self.assertIn("count=0", captured["data"].decode("utf-8"))


if __name__ == "__main__":
    unittest.main()
