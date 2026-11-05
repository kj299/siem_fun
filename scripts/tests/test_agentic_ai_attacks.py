"""Consistency tests for the agentic-AI-attacks section.

The section is three artifacts that describe the same facts and would drift apart silently: the IOC
CSV, the ATT&CK Navigator layer, and the technique table in the reference doc. These tests pin them to
each other. They are stdlib unittest, like the rest of the repo, and need no network: ATT&CK itself is
not vendored, so technique IDs are checked for shape here and against the live catalogue only by the
build step that produced the layer.
"""
import csv
import json
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
DOC = ROOT / "splunk-sentinel-query-builder" / "references" / "agentic-ai-attacks.md"
ASSETS = ROOT / "examples" / "agentic-ai-attacks"
IOCS = ASSETS / "iocs.csv"
LAYER = ASSETS / "attack-navigator-layer.json"

TECHNIQUE_ID = re.compile(r"T\d{4}(?:\.\d{3})?")
IPV4 = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")
PLACEHOLDER_ACTIONS = ("<", "YOUR_")


def doc_technique_ids():
    """Every technique ID in the reference doc's technique table (the table whose header starts with Technique)."""
    ids = set()
    in_table = False
    for line in DOC.read_text().splitlines():
        if line.startswith("| Technique"):
            in_table = True
            continue
        if in_table:
            if not line.startswith("|"):
                in_table = False
                continue
            cell = line.split("|")[1].strip()
            m = TECHNIQUE_ID.fullmatch(cell.strip("`"))
            if m:
                ids.add(m.group(0))
    return ids


class IocCsvTests(unittest.TestCase):
    def setUp(self):
        with open(IOCS, newline="") as fh:
            self.rows = list(csv.DictReader(fh))

    def test_columns_and_non_empty(self):
        self.assertEqual(list(self.rows[0].keys()),
                         ["type", "value", "framework", "context", "source", "source_url", "confidence", "action", "status"])
        self.assertGreater(len(self.rows), 100)

    def test_every_row_has_a_real_source(self):
        # R2/R3 of the threat-intel discipline: no indicator without a named source.
        for r in self.rows:
            self.assertTrue(r["source"].strip(), r)
            self.assertNotIn(r["source"].strip().lower(), ("unknown", "n/a", "general knowledge"), r)
            self.assertIn(r["confidence"], ("high", "medium", "low"), r)

    def test_value_shapes(self):
        for r in self.rows:
            v = r["value"]
            if r["type"] == "ipv4":
                self.assertTrue(IPV4.fullmatch(v) and all(int(o) < 256 for o in v.split(".")), v)
            elif r["type"] == "sha256":
                self.assertRegex(v, r"^[0-9a-f]{64}$")
            elif r["type"] == "md5":
                self.assertRegex(v, r"^[0-9a-f]{32}$")
            elif r["type"] == "domain":
                self.assertRegex(v, r"^[a-z0-9.-]+\.[a-z]+$")

    def test_no_duplicate_values(self):
        values = [r["value"] for r in self.rows]
        self.assertEqual(len(values), len(set(values)))

    def test_legitimate_services_are_never_marked_block(self):
        # LLM API hosts and public callback services are real services; a row for one must not say block.
        for r in self.rows:
            if r["type"] == "domain" and ("LEGIT" in r["context"] or "legitimate" in r["context"].lower()):
                self.assertNotIn("block", r["action"].lower(), r)

    def test_ascii_only(self):
        self.assertTrue(all(b < 127 for b in IOCS.read_bytes()))


class NavigatorLayerTests(unittest.TestCase):
    def setUp(self):
        self.layer = json.loads(LAYER.read_text())

    def test_layer_shape(self):
        self.assertEqual(self.layer["domain"], "enterprise-attack")
        self.assertEqual(self.layer["versions"]["attack"], "20")
        self.assertGreater(len(self.layer["techniques"]), 30)
        for t in self.layer["techniques"]:
            self.assertTrue(TECHNIQUE_ID.fullmatch(t["techniqueID"]), t)
            self.assertGreaterEqual(t["score"], 1)

    def test_layer_matches_the_doc_table(self):
        # The doc is what a reader sees; the layer is what Navigator loads. They must name the same set.
        self.assertEqual({t["techniqueID"] for t in self.layer["techniques"]}, doc_technique_ids())

    def test_v20_renames_are_used(self):
        # DLL Side-Loading (T1574.002) and Impair Defenses (T1562) do not exist in ATT&CK v20.
        ids = {t["techniqueID"] for t in self.layer["techniques"]}
        self.assertNotIn("T1574.002", ids)
        self.assertNotIn("T1562", ids)
        self.assertNotIn("T1562.001", ids)


class ReferenceDocTests(unittest.TestCase):
    def test_doc_names_every_framework_and_the_assets(self):
        text = DOC.read_text()
        for name in ("ARTEX", "CAIRN", "CyberStrikeAI", "PentAGI", "STRIX", "HexStrike"):
            self.assertIn(name, text)
        for asset in ("iocs.csv", "attack-navigator-layer.json", "splunk-savedsearches.conf", "sentinel-rules.yaml", "hunting.kql"):
            self.assertIn(asset, text)

    def test_doc_technique_table_is_non_trivial(self):
        self.assertGreater(len(doc_technique_ids()), 30)


if __name__ == "__main__":
    unittest.main()
