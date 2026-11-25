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
WAF = ASSETS / "waf"
WAF_PLATFORM_FILES = ("f5-data-groups.tmsh", "akamai-custom-rules.json")

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
        for asset in ("iocs.csv", "attack-navigator-layer.json", "splunk-savedsearches.conf", "sentinel-rules.yaml", "hunting.kql",
                      "waf/README.md"):
            self.assertIn(asset, text)

    def test_user_agent_list_in_the_doc_is_exactly_ioc_rows(self):
        # The skill loads only this doc at runtime, not iocs.csv, so the list is what a model can
        # put in a query. A value here that is not an IOC row is an invented indicator.
        text = DOC.read_text().replace("\r\n", "\n")
        block = text.split("IOC file):\n\n", 1)[1].split("\n\n", 1)[0]
        listed = re.findall(r"`([^`]+)`", block)
        with open(IOCS, newline="") as fh:
            ioc_uas = {r["value"]: r["framework"] for r in csv.DictReader(fh) if r["type"] == "user_agent"}
        self.assertGreaterEqual(len(listed), 8)
        for line in block.splitlines():
            framework = line[2:].split(":", 1)[0]
            for value in re.findall(r"`([^`]+)`", line):
                self.assertEqual(ioc_uas.get(value), framework, value)
        self.assertNotIn("- CAIRN:", block)

    def test_canary_values_in_the_doc_are_exactly_ioc_rows(self):
        # Same reason as the user-agent list: the doc is what a model can put in a query.
        text = DOC.read_text().replace("\r\n", "\n")
        block = text.split("not the literal value:\n\n", 1)[1].split("\n\n", 1)[0]
        listed = re.findall(r"`([^`]+)`", block)
        with open(IOCS, newline="") as fh:
            canaries = {r["value"] for r in csv.DictReader(fh) if r["type"] == "canary_string"}
        self.assertGreaterEqual(len(listed), 6)
        for value in listed:
            self.assertIn(value, canaries)

    def test_entra_operation_names_in_the_doc_are_those_of_the_rule(self):
        # The doc tells a model which AuditLogs operations to match; the Sentinel rule is what ships.
        text = DOC.read_text().replace("\r\n", "\n")
        block = text.split("behavior matches (R-B-AGT-008):\n\n", 1)[1].split("\n\n", 1)[0]
        listed = set(re.findall(r"`([^`]+)`", block))
        rules = (ASSETS / "sentinel-rules.yaml").read_text()
        ops = re.search(r"let ops = dynamic\(\[(.*?)\]\);", rules, re.S).group(1)
        self.assertEqual(listed, set(re.findall(r'"([^"]+)"', ops)))
        # One entry is the ending of a longer name, so an equality test against the list matches nothing.
        self.assertNotIn("OperationName in (ops)", rules)

    def test_doc_technique_table_is_non_trivial(self):
        self.assertGreater(len(doc_technique_ids()), 30)


class WafRulePackTests(unittest.TestCase):
    """The WAF pack restates indicators from iocs.csv in three vendors' syntax; pin the copies to the source."""

    def setUp(self):
        with open(IOCS, newline="") as fh:
            self.rows = list(csv.DictReader(fh))
        self.ua_block = (WAF / "ua-block.txt").read_text().split("\n")[:-1]
        self.ua_alert = (WAF / "ua-alert.txt").read_text().split("\n")[:-1]
        self.blocklist = (WAF / "blocklist-ipv4.txt").read_text().split()

    def test_blocklist_is_exactly_the_block_action_ipv4_rows(self):
        # An address the IOC file marks hunt, alert or do-NOT-block must never reach a deny list.
        expected = {r["value"] for r in self.rows if r["type"] == "ipv4" and r["action"].startswith("block")}
        self.assertEqual(len(self.blocklist), len(set(self.blocklist)))
        self.assertEqual(set(self.blocklist), expected)

    def test_f5_ip_data_group_matches_the_blocklist(self):
        line = next(l for l in (WAF / "f5-data-groups.tmsh").read_text().splitlines()
                    if l.startswith("create ltm data-group internal agt_ip_block "))
        self.assertEqual(set(re.findall(r"((?:\d{1,3}\.){3}\d{1,3})/32", line)), set(self.blocklist))

    def test_every_inbound_user_agent_indicator_is_covered(self):
        inbound = [r["value"] for r in self.rows
                   if r["type"] == "user_agent" and r["action"].startswith("alert on inbound")]
        self.assertGreater(len(inbound), 10)
        for value in inbound:
            self.assertTrue(any(s in value.lower() for s in self.ua_block + self.ua_alert), value)

    def test_user_agent_substrings_are_lower_case_and_match_an_indicator(self):
        # A substring matching no indicator is an invented fingerprint.
        values = [r["value"].lower() for r in self.rows if r["type"] == "user_agent"]
        for s in self.ua_block + self.ua_alert:
            self.assertEqual(s, s.lower())
            self.assertGreaterEqual(len(s), 8, s)
            self.assertTrue(any(s in v for v in values), s)

    def test_low_confidence_user_agents_are_not_on_the_deny_list(self):
        for r in self.rows:
            if r["type"] == "user_agent" and (r["confidence"] == "low" or "never block" in r["action"]):
                if r["value"] == "ReconProbe/1.0":
                    continue  # self-describing recon client: no legitimate visitor sends it
                self.assertFalse(any(s in r["value"].lower() for s in self.ua_block), r["value"])

    def test_each_platform_file_carries_every_user_agent_substring(self):
        for name in WAF_PLATFORM_FILES:
            text = (WAF / name).read_text()
            for s in self.ua_block + self.ua_alert:
                self.assertIn(s, text, f"{name} is missing {s!r}")

    def test_akamai_file_is_json_with_named_rules(self):
        doc = json.loads((WAF / "akamai-custom-rules.json").read_text())
        for entry in doc["customRules"]:
            self.assertIn(entry["action"], ("alert", "deny"))
            self.assertRegex(entry["rule"]["name"], r"^W-AGT-\d{3}")
            self.assertTrue(entry["rule"]["conditions"])
        for entry in doc["ratePolicies"]:
            # A rate threshold copied from someone else's traffic must not ship as a deny.
            self.assertEqual(entry["action"], "alert")

    def test_no_legitimate_service_or_do_not_block_indicator_in_a_rule_file(self):
        forbidden = [r["value"] for r in self.rows
                     if r["type"] in ("ipv4", "ipv6", "domain", "ja4") and not r["action"].startswith("block")]
        forbidden += ["webhook.site", "kiota-dotnet", "python-requests", "curl/"]
        for path in WAF.iterdir():
            if path.suffix == ".md":
                continue
            text = path.read_text().lower()
            for value in forbidden:
                self.assertNotIn(value.lower(), text, f"{path.name} contains {value}")

    def test_every_rule_id_in_a_rule_file_is_documented(self):
        readme = (WAF / "README.md").read_text()
        for path in WAF.iterdir():
            if path.suffix in (".tcl", ".conf", ".json"):
                for rule in set(re.findall(r"W-AGT-\d{3}", path.read_text())):
                    self.assertIn(rule, readme, f"{path.name}: {rule} is not in README.md")

    def test_ascii_only(self):
        for path in WAF.iterdir():
            self.assertTrue(all(b < 127 for b in path.read_bytes()), path.name)


class DetectionAssetTests(unittest.TestCase):
    """The Splunk rules, Sentinel rules and hunts are three files nothing executes. These tests
    cannot run a query; they pin the things that can be pinned without one: identifiers are unique,
    every Sentinel table is one the catalogue vouches for, a rule shipped on both platforms matches
    the same operations on each, and the reference names what ships."""

    CATALOG = ROOT / "splunk-sentinel-query-builder" / "references" / "sentinel-table-catalog.md"
    RULE_ID = re.compile(r"\b[RH](?:-[A-Z])?-AGT-\d{3}\b")

    @classmethod
    def setUpClass(cls):
        cls.splunk = (ASSETS / "splunk-savedsearches.conf").read_text()
        cls.sentinel = (ASSETS / "sentinel-rules.yaml").read_text()
        cls.hunts = (ASSETS / "hunting.kql").read_text()
        cls.doc = DOC.read_text()
        cls.tables = set(re.findall(r"^\| `([A-Za-z_]+)` \|", cls.CATALOG.read_text(), re.M))

    def test_sentinel_rule_ids_and_names_are_unique(self):
        ids = re.findall(r"^id: (\S+)$", self.sentinel, re.M)
        names = re.findall(r"^name: (\S+) ", self.sentinel, re.M)
        self.assertGreater(len(ids), 20)
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(len(names), len(ids))
        self.assertEqual(len(names), len(set(names)))
        for name in names:
            self.assertRegex(name, r"^R-[A-Z]-AGT-\d{3}$")

    def test_splunk_stanzas_and_hunt_headers_are_unique(self):
        stanzas = re.findall(r"^\[(R-[A-Z]-AGT-\d{3}) ", self.splunk, re.M)
        hunts = re.findall(r"^// --- (H-AGT-\d{3}) ", self.hunts, re.M)
        self.assertGreater(len(stanzas), 30)
        self.assertGreater(len(hunts), 20)
        self.assertEqual(len(stanzas), len(set(stanzas)))
        self.assertEqual(len(hunts), len(set(hunts)))

    def test_every_sentinel_rule_has_a_splunk_rule_of_the_same_id(self):
        splunk = set(re.findall(r"^\[(R-[A-Z]-AGT-\d{3}) ", self.splunk, re.M))
        for name in re.findall(r"^name: (\S+) ", self.sentinel, re.M):
            self.assertIn(name, splunk)

    def test_every_table_a_query_reads_is_in_the_catalogue(self):
        # A table in table position: an identifier alone at the start of a line (after an opening
        # bracket or a let binding), followed by a pipe or the end of the line. KQL names are
        # case-sensitive, and a wrong one returns nothing instead of failing.
        position = re.compile(r"^\s*(?:let \w+ = |\()?\s*([A-Z][A-Za-z]+)\s*(?:\||$)", re.M)
        seen = set()
        for text in (self.sentinel, self.hunts):
            body = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith(("//", "#")))
            for name in position.findall(body):
                seen.add(name)
        seen -= {"Scheduled"}   # the YAML value of `kind:`, not a table
        self.assertGreater(len(seen), 10)
        for name in sorted(seen):
            self.assertIn(name, self.tables, f"{name} is read by a query but is not in sentinel-table-catalog.md")

    def test_azure_operations_are_the_same_on_both_platforms(self):
        # R-D-AGT-023 is one rule written twice. The operation names come from Microsoft's
        # resource provider reference; the two copies must not drift.
        pattern = re.compile(r"microsoft\.[a-z]+/[a-z/]+/action", re.I)
        stanza = self.splunk[self.splunk.index("[R-D-AGT-023 "):self.splunk.index("[R-D-AGT-024 ")]
        search = stanza[stanza.index("search = "):]
        start = self.sentinel.index("name: R-D-AGT-023 ")
        rule = self.sentinel[start:self.sentinel.index("entityMappings:", start)]
        query = rule[rule.index("query: |"):]
        splunk_ops = {m.lower() for m in pattern.findall(search)}
        sentinel_ops = {m.lower() for m in pattern.findall(query)}
        self.assertEqual(len(splunk_ops), 8)
        self.assertEqual(splunk_ops, sentinel_ops)

    def test_the_reference_names_every_detection_added_since_the_first_set(self):
        # The first twenty rules predate this test and the reference describes them in prose.
        # From 021 (rules) and 023 (hunts) on, a detection the reference does not name is one the
        # query-builder skill cannot point anyone to.
        shipped = set(self.RULE_ID.findall(self.splunk)) | set(self.RULE_ID.findall(self.sentinel)) | \
            set(re.findall(r"^// --- (H-AGT-\d{3}) ", self.hunts, re.M))
        for rule in sorted(shipped):
            number = int(rule[-3:])
            if (rule.startswith("H-") and number >= 23) or (rule.startswith("R-") and number >= 21):
                self.assertIn(rule, self.doc, rule)

    def test_no_saved_search_leaves_a_dollar_pair_for_splunk_to_substitute(self):
        # REGRESSION: in savedsearches.conf a pair of dollar signs is an escaped dollar and
        # $name$ is a token, so a regex written "\$$" does not mean "ends with a dollar".
        for line in self.splunk.splitlines():
            if line.startswith(("search =", "|")):
                self.assertNotIn("$$", line, line[:80])
                self.assertNotRegex(line, r"\$\w+\$", line[:80])


if __name__ == "__main__":
    unittest.main()
