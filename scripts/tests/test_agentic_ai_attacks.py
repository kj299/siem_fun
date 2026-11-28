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
        self.assertGreater(len(seen), 10)
        for name in sorted(seen):
            self.assertIn(name, self.tables, f"{name} is read by a query but is not in sentinel-table-catalog.md")

    def test_azure_operations_are_the_same_on_both_platforms(self):
        # R-D-AGT-023 is one rule written twice. The operation names come from Microsoft's
        # resource provider reference; the two copies must not drift.
        pattern = re.compile(r"microsoft\.[a-z]+/[a-z/]+/(?:action|write)", re.I)
        stanza = self.splunk[self.splunk.index("[R-D-AGT-023 "):self.splunk.index("[R-D-AGT-024 ")]
        search = stanza[stanza.index("search = "):]
        start = self.sentinel.index("name: R-D-AGT-023 ")
        rule = self.sentinel[start:self.sentinel.index("entityMappings:", start)]
        query = rule[rule.index("query: |"):]
        splunk_ops = {m.lower() for m in pattern.findall(search)}
        sentinel_ops = {m.lower() for m in pattern.findall(query)}
        self.assertEqual(len(splunk_ops), 10)
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

    def test_no_saved_search_line_carries_two_dollar_signs(self):
        # REGRESSION: savedsearches.conf treats text between two dollar signs as a token to
        # substitute and a doubled one as an escape, so a regex ending in an escaped dollar and an
        # anchor, or two "ends with a dollar" tests on one line, may not reach the search as
        # written. One per line is the shape the older rules already use; where a literal dollar
        # is needed, build it (printf("%c", 36)) instead of typing it.
        for line in self.splunk.splitlines():
            if line.startswith(("search =", "|")):
                self.assertLess(line.count("$"), 2, line[:80])

    def test_sentinel_queries_stay_inside_their_yaml_block(self):
        # No YAML parser in the standard library, so this checks the one thing that breaks the
        # file quietly: a query line that is not indented ends the block scalar early.
        blocks = re.findall(r"^query: \|\n(.*?)^entityMappings:", self.sentinel, re.S | re.M)
        self.assertEqual(len(blocks), len(re.findall(r"^id: ", self.sentinel, re.M)))
        for block in blocks:
            for line in block.splitlines():
                self.assertTrue(line == "" or line.startswith("  "), line[:80])

    def test_only_known_normalizing_parsers_are_called(self):
        # A misspelt parser is an unknown function, and the table test cannot see it.
        for text in (self.sentinel, self.hunts):
            for name in re.findall(r"\b_Im_\w+", text):
                self.assertIn(name, ("_Im_WebSession", "_Im_Authentication"))


def _sweep_held_back(action):
    """True for an indicator the IOC file says not to act on automatically. The sweep is a scheduled
    rule that raises alerts, so a row marked hunt, monitor or retro-hunt only, a baseline, a signup
    deny-list entry, or a legitimate service stays out of its lookup and is used from iocs.csv."""
    a = action.lower()
    return (a.startswith(("hunt", "monitor only", "retro-hunt only", "baseline", "deny self-service"))
            or "legitimate service" in a)


class IocSweepTests(unittest.TestCase):
    """R-D-AGT-012 matches published indicators against telemetry. Three things about it went wrong
    without any test noticing, and all three are properties of files, so they can be pinned:

    - the two lookup files are copies of iocs.csv rows and nothing held them to it;
    - the lookups carried rows the rule has no leg to match (application IDs), and five shared-egress
      addresses whose own action says retro-hunt only, beside four identical ones that were left out;
    - REGRESSION: the rule matched an indicator address only as a DESTINATION. About half of the
      published addresses are attacker sources (spray, sign-in, proxy and reconnaissance origins),
      which an egress match never sees, so a sign-in from a high-confidence address went unreported.
    """

    MATCHED_TYPES = {"domain", "ipv4", "user_agent", "sha256", "md5"}

    @classmethod
    def setUpClass(cls):
        with open(IOCS, newline="") as fh:
            cls.iocs = {r["value"].lower(): r for r in csv.DictReader(fh)}
        with open(ASSETS / "lookups" / "agt_iocs.csv", newline="") as fh:
            cls.lookup = list(csv.DictReader(fh))
        with open(ASSETS / "lookups" / "sentinel_watchlist.csv", newline="") as fh:
            cls.watchlist = list(csv.DictReader(fh))
        splunk = (ASSETS / "splunk-savedsearches.conf").read_text()
        sentinel = (ASSETS / "sentinel-rules.yaml").read_text()
        cls.splunk_rule = re.search(r"^\[R-D-AGT-012 .*?(?=^\[|\Z)", splunk, re.S | re.M).group(0)
        cls.sentinel_rule = re.search(r"^name: R-D-AGT-012 .*?(?=^---$|\Z)", sentinel, re.S | re.M).group(0)
        cls.hunts = (ASSETS / "hunting.kql").read_text()

    def test_the_two_lookups_carry_the_same_rows(self):
        self.assertEqual(list(self.lookup[0].keys()), ["ioc", "ioc_type", "confidence", "context", "source"])
        self.assertEqual(list(self.watchlist[0].keys()), ["Ioc", "IocType", "Confidence", "Context", "Source"])
        self.assertEqual([list(r.values()) for r in self.lookup], [list(r.values()) for r in self.watchlist])

    def test_every_lookup_row_is_an_ioc_row_with_the_same_facts(self):
        self.assertGreater(len(self.lookup), 100)
        for r in self.lookup:
            src = self.iocs.get(r["ioc"].lower())
            self.assertIsNotNone(src, f"{r['ioc']} is in the sweep lookup but not in iocs.csv")
            self.assertEqual((r["ioc_type"], r["confidence"], r["source"]),
                             (src["type"], src["confidence"], src["source"]), r["ioc"])

    def test_the_lookup_is_exactly_the_rows_the_rule_may_alert_on(self):
        want = {v for v, r in self.iocs.items()
                if r["type"] in self.MATCHED_TYPES and not _sweep_held_back(r["action"])}
        have = {r["ioc"].lower() for r in self.lookup}
        self.assertEqual(have - want, set(), "in the sweep lookup, but not matchable or marked hands-off in iocs.csv")
        self.assertEqual(want - have, set(), "an alertable indicator in iocs.csv is missing from the sweep lookup")

    def test_the_rule_has_a_leg_for_every_type_in_the_lookup(self):
        for ioc_type in sorted({r["ioc_type"] for r in self.lookup}):
            self.assertIn(ioc_type, self.MATCHED_TYPES)
            self.assertIn(f'"{ioc_type}"', self.splunk_rule, f"no Splunk leg reads {ioc_type} rows")

    def test_addresses_are_matched_as_a_source_as_well_as_a_destination(self):
        # REGRESSION. Splunk: one leg per data model that carries an inbound source address.
        for field in ("All_Traffic.dest", "All_Traffic.src", "Web.src", "Authentication.src"):
            self.assertRegex(self.splunk_rule, r"rename ioc AS " + re.escape(field) + r"\b", field)
        # Sentinel: the three Entra sign-in tables and the source address of a web session.
        for table in ("SigninLogs", "AADNonInteractiveUserSignInLogs", "AADServicePrincipalSignInLogs"):
            self.assertRegex(self.sentinel_rule, r"\(" + table + r"\n", table)
        self.assertEqual(len(re.findall(r"Ioc = IPAddress", self.sentinel_rule)), 3)
        self.assertIn("pack_array(HttpUserAgent, SrcIpAddr)", self.sentinel_rule)

    def test_low_confidence_rows_are_not_matched_inbound_or_raised_as_high(self):
        # A shared VPN or CDN egress address matched as a SOURCE fires on ordinary visitors.
        inbound = [l for l in self.splunk_rule.splitlines()
                   if re.search(r"rename ioc AS (All_Traffic\.src|Web\.src|Authentication\.src)", l)]
        self.assertEqual(len(inbound), 3)
        for leg in inbound:
            self.assertIn('confidence!="low"', leg)
        self.assertIn('| where Confidence != "low";', self.sentinel_rule)

    def test_the_hunt_for_application_ids_watches_every_published_one(self):
        apps = {v for v, r in self.iocs.items() if r["type"] == "entra_app_id"}
        self.assertGreater(len(apps), 3)
        block = re.search(r"^// --- H-AGT-016 .*?^let watched = dynamic\(\[(.*?)\]\);", self.hunts, re.S | re.M)
        self.assertIsNotNone(block)
        self.assertEqual(set(re.findall(r'"([0-9a-f-]{36})"', block.group(1))), apps)


class SavedSearchScheduleTests(unittest.TestCase):
    """REGRESSION. A rule that judges single events and reads a window longer than its schedule
    writes an event in the overlap to the risk index twice. Nine of the first rules did; the rules
    added later were fixed and these were not. A rule may still read further back than it runs when
    it has to, and then it is named here with the reason, so the overlap is a decision on the page
    rather than an accident in a stanza."""

    # Rules that count or pair events ACROSS a window and so must look back further than they run.
    # Each reports again while its condition holds; a consumer that sums risk should count one
    # finding per rule and entity per window, as the chain rules do (first occurrence per host).
    SLIDING = {
        "R-B-AGT-002": "regular cadence needs 12 gaps in 24 hours",
        "R-D-AGT-003": "spray: 10 principals in an hour",
        "R-B-AGT-004": "first contact, judged against an hour and a baseline",
        "R-B-AGT-005": "novel child process, judged against an hour and a baseline",
        "R-B-AGT-008": "a day's writes against a 30-day envelope",
        "R-C-AGT-001": "chain: steps up to 26 hours apart",
        "R-C-AGT-002": "chain: steps up to 5 hours apart",
        "R-D-AGT-017": "pair: a specification fetch, then routes within two minutes",
        "R-D-AGT-018": "pair: a canary login, then an admin attempt within a minute",
        "R-D-AGT-019": "three accounts from one source inside the window",
        "R-D-AGT-020": "three service principals, or a failure then a success, in an hour",
        "R-D-AGT-028": "credential guessing at volume in an hour",
    }

    @staticmethod
    def _minutes(value):
        m = re.fullmatch(r"-(\d+)([mhd])@[mhd]", value)
        if m:
            return int(m.group(1)) * {"m": 1, "h": 60, "d": 1440}[m.group(2)]
        if re.fullmatch(r"@[mhd]|now", value):
            return 0
        raise AssertionError(f"unreadable time modifier {value!r}")

    def _rules(self):
        text = (ASSETS / "splunk-savedsearches.conf").read_text()
        for stanza in re.split(r"\n(?=\[)", text):
            head = re.match(r"\[(R-[A-Z]-AGT-\d{3}) ", stanza)
            earliest = re.search(r"^dispatch\.earliest_time\s*=\s*(\S+)", stanza, re.M)
            if not head or not earliest:
                continue  # a baseline builder, or a rule that bounds time inside its own search
            latest = re.search(r"^dispatch\.latest_time\s*=\s*(\S+)", stanza, re.M).group(1)
            minute, hour = re.search(r"^cron_schedule\s*=\s*(\S+) (\S+) ", stanza, re.M).groups()
            if minute.startswith("*/"):
                period = int(minute[2:])
            elif hour == "*":
                period = 60 // len(minute.split(","))
            else:
                period = 1440
            window = self._minutes(earliest.group(1)) - self._minutes(latest)
            yield head.group(1), window, period, stanza, earliest.group(1)

    def test_a_rule_reads_one_schedule_period_unless_it_is_named_as_sliding(self):
        seen = 0
        for rule, window, period, _stanza, _earliest in self._rules():
            seen += 1
            if rule in self.SLIDING:
                continue
            self.assertEqual(window, period, f"{rule} reads {window} minutes every {period}: an event in the overlap is written twice")
        self.assertGreater(seen, 25)

    def test_every_rule_named_as_sliding_still_overlaps(self):
        found = {rule: (window, period) for rule, window, period, _s, _e in self._rules()}
        for rule in self.SLIDING:
            self.assertIn(rule, found)
            window, period = found[rule]
            self.assertGreater(window, period, f"{rule} no longer overlaps; take it off the list")

    def test_a_time_bound_inside_a_search_agrees_with_its_stanza(self):
        # An earliest= typed in the search string overrides dispatch.earliest_time, so a stanza
        # edited alone changes nothing. Only the minute-scale bounds are compared: a baseline or a
        # tstats subsearch that reads days is a different window on purpose.
        for rule, _window, _period, stanza, earliest in self._rules():
            first_line = re.search(r"^search = (.*)$", stanza, re.M).group(1)
            for inline in re.findall(r"(?<![.\w])earliest=(-\d+m@m)", first_line):
                self.assertEqual(inline, earliest, f"{rule}: earliest={inline} in the search, {earliest} in the stanza")


if __name__ == "__main__":
    unittest.main()
