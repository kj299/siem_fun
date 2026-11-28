"""Consistency tests for the agentic-AI-attacks section.

The section is three artifacts that describe the same facts and would drift apart silently: the IOC
CSV, the ATT&CK Navigator layer, and the technique table in the reference doc. These tests pin them to
each other, and pin what can be pinned in the rule, hunt and lookup files without running them. They
are stdlib unittest, like the rest of the repo, and need no network: the ATT&CK catalogue the pack is
built against is vendored as a list of IDs, names and tactics (attack-enterprise-20.1.tsv beside this
file), so a technique ID is checked against it rather than for its shape only.
"""
import csv
import json
import pathlib
import re
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import grade_golden_output as grader  # noqa: E402

DOC = ROOT / "splunk-sentinel-query-builder" / "references" / "agentic-ai-attacks.md"
ASSETS = ROOT / "examples" / "agentic-ai-attacks"
IOCS = ASSETS / "iocs.csv"
LAYER = ASSETS / "attack-navigator-layer.json"
WAF = ASSETS / "waf"
WAF_PLATFORM_FILES = ("f5-data-groups.tmsh", "akamai-custom-rules.json")

ATTACK_CATALOGUE = pathlib.Path(__file__).resolve().parent / "attack-enterprise-20.1.tsv"
CONF_FILES = ("splunk-savedsearches.conf", "splunk-hunting.conf", "splunk-morpheus-native.conf")
QUERY_FILES = CONF_FILES + ("sentinel-rules.yaml", "hunting.kql")

TECHNIQUE_ID = re.compile(r"T\d{4}(?:\.\d{3})?")
IPV4 = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")
PLACEHOLDER_ACTIONS = ("<", "YOUR_")
DETECTION_ID = r"[RH](?:-[A-Z])?-AGT-\d{3}(?:-M)?"


def attack_catalogue():
    """{technique ID: (name, set of tactics, status)} for ATT&CK Enterprise 20.1. Status is live,
    deprecated, or revoked-by the ID that replaced it."""
    out = {}
    for line in ATTACK_CATALOGUE.read_text().splitlines():
        if line.startswith("#"):
            continue
        tid, name, tactics, status = line.split("\t")
        out[tid] = (name, set(tactics.split(", ")) if tactics else set(), status)
    return out


def doc_technique_rows():
    """The cells of every row of the reference doc's technique table: ID, Name, Tactic, Frameworks,
    Example evidence, Source."""
    rows = []
    for line in DOC.read_text().splitlines():
        cells = [c.strip() for c in line.split("|")]
        if len(cells) == 8 and TECHNIQUE_ID.fullmatch(cells[1]):
            rows.append(cells[1:7])
    return rows


def read_asset(name):
    return (ASSETS / name).read_text()


# ----------------------------------------------------------------------------- Splunk parsing
def conf_stanzas(text):
    """[(name, {key: value})]. A value continues while its line ends in a backslash."""
    out, name, keys, key, cont = [], None, {}, None, False
    for line in text.splitlines():
        if cont:
            keys[key] += "\n" + line
            cont = line.endswith("\\")
            continue
        m = re.match(r"^\[(.+)\]\s*$", line)
        if m:
            if name is not None:
                out.append((name, keys))
            name, keys = m.group(1), {}
            continue
        m = re.match(r"^([A-Za-z_.0-9]+)\s*=\s?(.*)$", line)
        if m and name is not None:
            key = m.group(1)
            keys[key] = m.group(2)
            cont = line.endswith("\\")
    if name is not None:
        out.append((name, keys))
    return out


def split_top(s, sep):
    """Split on sep outside double quotes, single quotes, () and []."""
    out, cur, depth, quote, i = [], "", 0, None, 0
    while i < len(s):
        c = s[i]
        if quote:
            cur += c
            if c == "\\" and i + 1 < len(s):
                cur += s[i + 1]
                i += 1
            elif c == quote:
                quote = None
        elif c in "\"'":
            quote = c
            cur += c
        elif c in "([":
            depth += 1
            cur += c
        elif c in ")]":
            depth -= 1
            cur += c
        elif c == sep and depth == 0:
            out.append(cur)
            cur = ""
        else:
            cur += c
        i += 1
    out.append(cur)
    return out


def spl_commands(search):
    """The commands of a search: split on pipes outside quotes and outside [subsearches]."""
    return [c.strip() for c in split_top(re.sub(r"\\\n", " ", search), "|") if c.strip()]


def unquote(s):
    return re.sub(r'"(?:\\.|[^"\\])*"', '""', s)


def splunk_searches():
    """(file, stanza name, keys) for every stanza in the three .conf files that carries a search."""
    for fname in CONF_FILES:
        for name, keys in conf_stanzas(read_asset(fname)):
            if "search" in keys:
                yield fname, name, keys


def kql_units():
    """(id, query without comment lines) for each hunt in hunting.kql and each Sentinel rule."""
    parts = re.split(r"^// --- (H-AGT-\d{3}) .*$", read_asset("hunting.kql"), flags=re.M)
    for i in range(1, len(parts), 2):
        yield parts[i], "\n".join(l for l in parts[i + 1].splitlines() if not l.lstrip().startswith("//"))
    for doc in re.split(r"^---$", read_asset("sentinel-rules.yaml"), flags=re.M):
        n = re.search(r"^name: (\S+)", doc, re.M)
        q = re.search(r"^query: \|\n(.*?)^entityMappings:", doc, re.S | re.M)
        if n and q:
            yield n.group(1), "\n".join(l for l in q.group(1).splitlines() if not l.lstrip().startswith("//"))


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

    def test_layer_lists_each_technique_once_and_its_totals_agree(self):
        # The set comparison above passes a technique listed twice, and nothing summed the scores:
        # evidence_rows and the gradient's top were right only because the script that wrote the
        # layer computed them.
        ids = [t["techniqueID"] for t in self.layer["techniques"]]
        self.assertEqual(len(ids), len(set(ids)))
        scores = [t["score"] for t in self.layer["techniques"]]
        meta = {m["name"]: m["value"] for m in self.layer["metadata"]}
        self.assertEqual(int(meta["evidence_rows"]), sum(scores))
        self.assertEqual(self.layer["gradient"]["maxValue"], max(scores))

    def test_each_comment_is_its_table_row_and_no_score_exceeds_its_sources(self):
        # The comment is what Navigator shows on hover, and it is written from the row. A score
        # counts independent evidence, and an entry that only restates a report the row already
        # cites is not counted, so a score can be lower than the sources the row names (scores keep
        # their history) but never higher.
        rows = {r[0]: r for r in doc_technique_rows()}
        for t in self.layer["techniques"]:
            row = rows[t["techniqueID"]]
            self.assertEqual(t["comment"], f"Frameworks: {row[3]}. Sources: {row[5]}.", t["techniqueID"])
            self.assertLessEqual(t["score"], len(row[5].split("; ")), t["techniqueID"])

    def test_doc_table_rows_are_unique(self):
        ids = [r[0] for r in doc_technique_rows()]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(len(ids), len(self.layer["techniques"]))

    def test_every_technique_is_live_in_attack_20_1_with_its_name_and_tactic(self):
        # The layer says it is built against ATT&CK 20 and was checked against 20.1. A revoked or
        # deprecated ID, a name that is not the catalogue's, or a tactic the technique does not sit
        # under was caught only by whoever re-ran that check by hand.
        catalogue = attack_catalogue()
        for t in self.layer["techniques"]:
            self.assertEqual(catalogue.get(t["techniqueID"], ("", set(), "not in ATT&CK"))[2], "live", t["techniqueID"])
        for tid, name, tactic, *_ in doc_technique_rows():
            want_name, tactics, status = catalogue.get(tid, ("", set(), "not in ATT&CK"))
            self.assertEqual(status, "live", tid)
            self.assertEqual(name, want_name, tid)
            self.assertIn(tactic, tactics, f"{tid} is not under {tactic} in ATT&CK 20.1")


class ReferenceDocTests(unittest.TestCase):
    def test_doc_names_every_framework_and_the_assets(self):
        text = DOC.read_text()
        for name in ("ARTEX", "CAIRN", "CyberStrikeAI", "PentAGI", "STRIX", "HexStrike"):
            self.assertIn(name, text)
        for asset in ("iocs.csv", "attack-navigator-layer.json", "splunk-savedsearches.conf", "sentinel-rules.yaml", "hunting.kql",
                      "splunk-hunting.conf", "waf/README.md"):
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
        cls.splunk_hunts = (ASSETS / "splunk-hunting.conf").read_text()
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
        # Read with the golden-prompt grader's own table reader, statement by statement: the
        # source of each statement, let values, and union and join operands, wherever the line
        # breaks fall. A position regex read here before could not see a table written on the
        # union's own line (union AWSCloudtrail, AWSCloudTrail). KQL names are case-sensitive,
        # and a wrong one returns nothing instead of failing.
        seen = set()
        for uid, body in kql_units():
            for name in grader.kql_tables(body):
                seen.add(name)
                self.assertIn(name, self.tables, f"{uid}: {name} is read by a query but is not in sentinel-table-catalog.md")
        self.assertGreater(len(seen), 10)

    def test_every_kql_hunt_bounds_time_for_each_table_it_reads(self):
        # QUERY_SKILL_PLAN.md recorded this as checked once by hand on 2026-11-21, 23 hunts ago.
        # Per source, not per hunt: a union leg that lost its bound reads all retention while the
        # other legs keep the hunt looking bounded. A hunt led by a parser or a placeholder is
        # bounded through the parser's starttime argument.
        position = re.compile(r"^\s*(?:let \w+ = |\()?\s*([A-Z][A-Za-z]+)\s*(?:\||$)", re.M)
        bound = re.compile(r"\bTimeGenerated\s*(?:>=?|between\b)|\bstarttime\s*=\s*ago\(")
        hunts = [(uid, body) for uid, body in kql_units() if uid.startswith("H-")]
        self.assertGreater(len(hunts), 30)
        legs = 0
        for uid, body in hunts:
            sources = [m for m in position.finditer(body) if m.group(1) in self.tables]
            if not sources:
                self.assertRegex(body, bound, uid)
            for i, m in enumerate(sources):
                legs += 1
                end = sources[i + 1].start() if i + 1 < len(sources) else len(body)
                self.assertRegex(body[m.start():end], bound, f"{uid}: {m.group(1)} is read with no time bound")
        self.assertGreater(legs, 40)

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

    def test_splunk_hunts_are_the_sentinel_hunts_of_the_same_number(self):
        # splunk-hunting.conf is the Splunk side of hunting.kql from H-AGT-032 on. H-AGT-045
        # reads a published list with externaldata, which has no Splunk equivalent, and is the
        # one hunt allowed to exist on one platform only.
        sentinel = {h for h in re.findall(r"^// --- (H-AGT-\d{3}) ", self.hunts, re.M) if int(h[-3:]) >= 32}
        splunk = re.findall(r"^\[(H-AGT-\d{3}) - ", self.splunk_hunts, re.M)
        self.assertEqual(len(splunk), len(set(splunk)))
        self.assertGreater(len(splunk), 10)
        self.assertEqual(set(splunk), sentinel - {"H-AGT-045"})

    def test_splunk_hunts_are_unscheduled_bounded_and_write_nothing(self):
        # A hunt returns rows for a person to read. One that is scheduled, or that collects into
        # the risk index, is a rule nobody tuned; one with no time range searches all time.
        stanzas = re.split(r"^(?=\[H-AGT-\d{3} )", self.splunk_hunts, flags=re.M)[1:]
        self.assertGreater(len(stanzas), 10)
        for stanza in stanzas:
            name = stanza.splitlines()[0]
            self.assertRegex(stanza, r"(?m)^enableSched\s*= 0$", name)
            self.assertRegex(stanza, r"(?m)^dispatch\.earliest_time\s*= -\d+d@d$", name)
            self.assertRegex(stanza, r"(?m)^description = .*ATT&CK T\d{4}", name)
            # A command that writes or sends. The list is from memory and was not checked against
            # Splunk's Search Reference (stash, summaryindex and sumindex as names for collect
            # included): a name here that is not a command costs nothing.
            self.assertNotRegex(stanza, r"\|\s*(?:collect|stash|summaryindex|sumindex|tscollect|mcollect|meventcollect|"
                                        r"outputlookup|outputcsv|sendalert|sendemail|delete|dump)\b", name)
            # Each setting once and no other: a second enableSched wins over the first, and an
            # alert action (action.email, alert.track) turns a hunt into a rule.
            keys = re.findall(r"(?m)^([A-Za-z][\w.]*)\s*=", stanza[:stanza.index("search = ") + 9])
            self.assertEqual(sorted(keys), ["description", "dispatch.earliest_time", "dispatch.latest_time", "enableSched", "search"], name)
            self.assertNotIn("<RISK_INDEX>", stanza, name)
            # Every continued line ends in a backslash, or the search is cut short there.
            search = stanza[stanza.index("search = "):].rstrip("\n").splitlines()
            for line in search[:-1]:
                self.assertTrue(line.endswith(" \\"), line[:80])
            self.assertFalse(search[-1].endswith("\\"), name)

    def test_no_saved_search_line_carries_two_dollar_signs(self):
        # REGRESSION: savedsearches.conf treats text between two dollar signs as a token to
        # substitute and a doubled one as an escape, so a regex ending in an escaped dollar and an
        # anchor, or two "ends with a dollar" tests on one line, may not reach the search as
        # written. One per line is the shape the older rules already use; where a literal dollar
        # is needed, build it (printf("%c", 36)) instead of typing it. Every .conf file, and every
        # search line however it is indented: four subsearch lines of R-D-AGT-012 start with two
        # spaces, and the Morpheus file was not read at all.
        for name in CONF_FILES:
            for line in read_asset(name).splitlines():
                if line.lstrip().startswith(("search =", "|", "[|")):
                    self.assertLess(line.count("$"), 2, f"{name}: {line[:80]}")

    def test_conf_stanza_names_are_unique_in_every_file(self):
        for name in CONF_FILES:
            stanzas = re.findall(r"^\[([^\]\n]+)\]$", read_asset(name), re.M)
            self.assertGreater(len(stanzas), 3, name)
            self.assertEqual(len(stanzas), len(set(stanzas)), name)

    def test_every_scheduled_search_has_a_time_range(self):
        # In the stanza, or typed into the search: the five baselines and R-P-AGT-010 do the second.
        for name in ("splunk-savedsearches.conf", "splunk-morpheus-native.conf"):
            for stanza, keys in conf_stanzas(read_asset(name)):
                has_range = keys.get("dispatch.earliest_time", "").strip() or re.search(r"\bearliest=-\d", keys.get("search", ""))
                self.assertTrue(has_range, f"{name} [{stanza}] searches all time")

    def test_splunk_hunts_use_only_the_placeholders_their_header_declares(self):
        header, body = self.splunk_hunts.split("\n[H-AGT-", 1)
        declared = set(re.findall(r"<[A-Z_]+>", header))
        used = set()
        for _name, keys in conf_stanzas("[H-AGT-" + body):
            used |= set(re.findall(r"<[A-Z_]+>", keys.get("search", "")))
        self.assertGreater(len(used), 3)
        self.assertEqual(used - declared, set())

    def test_a_splunk_hunt_carries_the_title_of_its_sentinel_hunt(self):
        # The number is pinned above; a stanza under the right number and another hunt's title
        # sends a reader comparing the two platforms to the wrong query.
        kql = dict(re.findall(r"^// --- (H-AGT-\d{3})\s+(.*?)[ -]*$", self.hunts, re.M))
        titles = re.findall(r"^\[(H-AGT-\d{3}) - (.*)\]$", self.splunk_hunts, re.M)
        self.assertGreater(len(titles), 10)
        for number, title in titles:
            self.assertTrue(kql[number].startswith(title), f"{number}: {title!r} is not how {kql[number]!r} opens")

    def test_a_hunt_that_judges_novelty_carries_its_range_in_the_search(self):
        # H-AGT-043 and H-AGT-044 call a caller or requester new if it is absent from the rest of
        # the result set, so the 30 days of history must be in the result set. A range set only by
        # dispatch.earliest_time is lost when the search is pasted into the search bar or run with
        # the time picker moved, and then everything seen in the last day is new. Where a hunt
        # writes earliest= in its search, it must agree with the stanza.
        for name, keys in conf_stanzas(self.splunk_hunts):
            inline = re.findall(r"(?<![.\w])earliest=(\S+)", keys.get("search", ""))
            for value in inline:
                self.assertEqual(value, keys["dispatch.earliest_time"].strip(), name)
            if name.startswith(("H-AGT-043 ", "H-AGT-044 ")):
                self.assertEqual(inline, ["-30d@d"], name)

    def test_every_technique_a_query_file_cites_is_live_in_attack_20_1(self):
        # splunk-hunting.conf cited T1562.001 and T1562.008, which ATT&CK v20 revoked (by T1685 and
        # T1685.002), while test_v20_renames_are_used read only the layer. Checked against the whole
        # catalogue, not a list of known-bad IDs: the rule files cite IDs the layer does not carry.
        catalogue = attack_catalogue()
        cited = 0
        for name in QUERY_FILES:
            for tid in sorted(set(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", read_asset(name)))):
                cited += 1
                status = catalogue.get(tid, ("", set(), "not in ATT&CK"))[2]
                self.assertEqual(status, "live", f"{name} cites {tid}: {status}")
        self.assertGreater(cited, 50)

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
            # Context too: 154.64.252.77 gained a clause in iocs.csv and kept the old one in both
            # lookups, which the alert then shows an analyst.
            self.assertEqual((r["ioc_type"], r["confidence"], r["source"], r["context"]),
                             (src["type"], src["confidence"], src["source"], src["context"]), r["ioc"])

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
        "R-C-AGT-003-M": "pair: a new TLS client, then regular calls within the hour",
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
        # The Morpheus variants too: R-B-AGT-005-M ran every 10 minutes and read 15, the same
        # double write, in the one file this test did not open.
        text = read_asset("splunk-savedsearches.conf") + "\n" + read_asset("splunk-morpheus-native.conf")
        for stanza in re.split(r"\n(?=\[)", text):
            head = re.match(r"\[(R-[A-Z]-AGT-\d{3}(?:-M)?) ", stanza)
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



class TwinHuntTests(unittest.TestCase):
    """splunk-hunting.conf is the Splunk side of hunting.kql from H-AGT-032 on, and its header says
    every list, pattern and threshold is the KQL hunt's. Only the hunt numbers were compared, while
    eleven searches were rewritten by script; a dropped process name or a changed threshold would
    have passed. Lists are read where both platforms write them literally; thresholds in every
    hunt of the pair."""

    @classmethod
    def setUpClass(cls):
        cls.kql = {uid: body for uid, body in kql_units() if uid.startswith("H-")}
        cls.spl = {re.match(DETECTION_ID, name).group(0): keys["search"]
                   for fname, name, keys in splunk_searches() if fname == "splunk-hunting.conf"}

    @staticmethod
    def _in_list(text, field):
        """Values of `field in~ (...)` (KQL) or `field IN (...)` (SPL), lower-cased."""
        out = set()
        for m in re.finditer(r"(?<![\w.])" + re.escape(field) + r"\s+(?:in~?|IN)\s*\(([^)]*)\)", text):
            out |= {v.lower() for v in re.findall(r'"([^"\\]*)"', m.group(1))}
        return out

    def test_the_process_lists_of_h_agt_036_are_the_same(self):
        k, s = self.kql["H-AGT-036"], self.spl["H-AGT-036"]
        kql_parents = self._in_list(k, "InitiatingProcessFileName") | {
            v.lower() + "*" for v in re.findall(r'InitiatingProcessFileName startswith "([^"]+)"', k)}
        spl_parents = self._in_list(s, "Processes.parent_process_name") | {
            v.lower() for v in re.findall(r'Processes\.parent_process_name="([^"]+\*)"', s)}
        self.assertGreater(len(kql_parents), 8)
        self.assertEqual(spl_parents, kql_parents)
        kql_children = self._in_list(k, "FileName")
        self.assertGreater(len(kql_children), 15)
        self.assertEqual(self._in_list(s, "Processes.process_name"), kql_children)

    def test_the_scanner_and_tracer_lists_of_h_agt_038_are_the_same(self):
        k, s = self.kql["H-AGT-038"], self.spl["H-AGT-038"]
        kql_scanners = set(re.findall(r'iff\(ProcessCommandLine contains "(\w+)", 1, 0\)', k))
        self.assertGreater(len(kql_scanners), 5)
        self.assertEqual(set(re.findall(r'if\(like\(cmd, "%(\w+)%"\), 1, 0\)', s)), kql_scanners)
        kql_names = set(re.findall(r'FileName =~ "(\w+)"', k))
        spl_names = set(re.findall(r'(?<![\w.])process_name="(\w+)"', s))
        for m in re.finditer(r"in\(process_name, ([^)]*)\)", s):
            spl_names |= set(re.findall(r'"(\w+)"', m.group(1)))
        self.assertGreater(len(kql_names), 3)
        self.assertEqual(spl_names, kql_names)

    def test_the_file_types_of_h_agt_040_are_the_same(self):
        k, s = self.kql["H-AGT-040"], self.spl["H-AGT-040"]
        kql_ext = set(re.search(r'\\\.\(([a-z|]+)\)\$', k).group(1).split("|"))
        self.assertGreater(len(kql_ext), 5)
        self.assertEqual(set(re.findall(r'TargetFilename="\*\.(\w+)"', s)), kql_ext)
        self.assertIn('"web.config"', k)
        self.assertIn('"web.config"', s)

    def test_the_event_names_of_h_agt_042_are_the_same(self):
        k, s = self.kql["H-AGT-042"], self.spl["H-AGT-042"]
        names = set(re.findall(r'"([A-Z][A-Za-z]+)"', k))
        self.assertGreater(len(names), 12)
        self.assertEqual(set(re.findall(r'"([A-Z][A-Za-z]+)"', s)), names)

    # A comparison written on one platform only, for a platform reason.
    THRESHOLD_ONE_SIDE = {
        "H-AGT-034": ("splunk", {("<", "3")},
                      "Splunk names the signal with if(distinct_errors < 3, ...) where KQL writes iff(DistinctErrors >= 3, ...)"),
        "H-AGT-037": ("kql", {(">", "0")},
                      "KQL drops a command naming no kind with array_length(...) > 0; Splunk with isnotnull(kind)"),
        "H-AGT-041": ("kql", {("<=", "60")},
                      "KQL pairs the two operations within 60 minutes with datetime_diff; Splunk with streamstats time_window=1h, asserted below"),
    }

    @staticmethod
    def _thresholds(text):
        text = re.sub(r'@?"(?:[^"\\]|\\.)*"', '""', text)
        return set(re.findall(r"(>=|<=|>|<)\s*(\d+(?:\.\d+)?)\b(?!\s*[dhms]\b)", text))

    def test_every_threshold_is_the_same_on_both_platforms(self):
        self.assertGreater(len(self.spl), 10)
        for uid in sorted(self.spl):
            spl, kql = self._thresholds(self.spl[uid]), self._thresholds(self.kql[uid])
            side, extra, _why = self.THRESHOLD_ONE_SIDE.get(uid, ("", set(), ""))
            if side == "splunk":
                self.assertEqual(spl - kql, extra, f"{uid}: the platform difference listed here is gone or has changed")
                spl -= extra
            elif side == "kql":
                self.assertEqual(kql - spl, extra, f"{uid}: the platform difference listed here is gone or has changed")
                kql -= extra
            self.assertEqual(spl, kql, uid)
        self.assertIn("time_window=1h", self.spl["H-AGT-041"])


class StatsByNullTests(unittest.TestCase):
    """In the draft of splunk-hunting.conf (6323e10), H-AGT-032, H-AGT-033 and H-AGT-043 grouped by
    an actor built with coalesce() over optional fields, and H-AGT-044 by a requester and a template
    taken straight from extractions. `stats ... BY` leaves out an event whose BY field is null, so
    the hunt was silent exactly where the record is unusual. The review added "(unknown)" fallbacks
    to those four hunts and to no other search; seven scheduled searches carried the same shape.
    That `stats ... BY f` drops events where f is null is from memory, not checked against
    Splunk's documentation."""

    ALWAYS_PRESENT = {"_time", "host", "source", "sourcetype", "index"}

    # stanza id -> {field: why a null is impossible or intended}. A reviewer's decision, on the page.
    BY_FIELD_ALLOWED = {
        "H-AGT-034": {"sourceIPAddress": "CloudTrail records a source address on every event"},
        "H-AGT-035": {"userIdentity.arn": "the search keeps userIdentity.type=AssumedRole, which always carries an ARN"},
        "R-C-AGT-001": {"target_host": "chain is per target host by design; a risk event without one cannot chain"},
        "R-D-AGT-029": {"path_template": "built from groups of one rex, after a where that keeps only rows the rex matched"},
        "R-D-AGT-001-M": {"src_ip": "Morpheus score events are keyed on it"},
        "R-B-AGT-002-M": {"src_ip": "Morpheus score events are keyed on it", "dst_ip": "same", "flow_pair_key": "same"},
        "R-B-AGT-005-M": {"endpoint_host": "Morpheus score events are keyed on it"},
        "R-C-AGT-003-M": {"src_ip": "Morpheus score events are keyed on it"},
    }

    @classmethod
    def never_null(cls, expr, safe):
        e = expr.strip()
        if re.fullmatch(r'"(?:\\.|[^"\\])*"', e) or re.fullmatch(r"-?\d+(\.\d+)?", e):
            return True
        if re.fullmatch(r"'?[\w.{}]+'?", e):
            return e.strip("'") in safe
        parts = split_top(e, ".")
        if len(parts) > 1 and all(p.strip() for p in parts):
            return all(cls.never_null(p, safe) for p in parts)          # a . b . c
        m = re.fullmatch(r"(lower|upper|trim|tostring|round|tonumber|mvindex|substr)\((.*)\)", e, re.S)
        if m:
            return cls.never_null(split_top(m.group(2), ",")[0], safe)
        m = re.fullmatch(r"coalesce\((.*)\)", e, re.S)
        if m:
            return any(cls.never_null(a, safe) for a in split_top(m.group(1), ","))
        m = re.fullmatch(r"if\((.*)\)", e, re.S)
        if m:
            a = split_top(m.group(1), ",")
            return len(a) == 3 and cls.never_null(a[1], safe) and cls.never_null(a[2], safe)
        m = re.fullmatch(r"case\((.*)\)", e, re.S)
        if m:
            a = split_top(m.group(1), ",")
            return len(a) >= 2 and a[-2].strip() in ("true()", "1=1") and all(cls.never_null(x, safe) for x in a[1::2])
        return False

    @classmethod
    def by_field_problems(cls, search):
        """Fields a `stats ... BY` groups on that nothing earlier in the search makes non-null."""
        problems, safe = [], set(cls.ALWAYS_PRESENT)
        flat = re.sub(r"\\\n", " ", search)
        # Fields a tstats groups on exist in every row it returns, in the main search or a subsearch.
        for by in re.findall(r"\btstats\b[^|\]]*?\bby\b([^|\]]*)", flat, re.I):
            for f in re.findall(r"[A-Za-z_][\w.]*", by):
                safe |= {f, f.split(".")[-1]}
        # A literal assigned inside a subsearch (eval kind = "web") survives the union.
        for f in re.findall(r"\[[^\]]*?\beval\s+(\w+)\s*=\s*\"[^\"]*\"\s*\]", flat):
            safe.add(f)
        for cmd in spl_commands(search):
            head = cmd.split(None, 1)[0]
            body = cmd[len(head):]
            if head == "eval":
                for part in split_top(body, ","):
                    m = re.match(r"\s*([A-Za-z_][\w.]*|'[^']+')\s*=(?!=)(.*)$", part, re.S)
                    if m:
                        field = m.group(1).strip("'")
                        (safe.add if cls.never_null(m.group(2), safe) else safe.discard)(field)
            elif head == "fillnull":
                safe |= set(re.findall(r"[A-Za-z_][\w.]*", re.sub(r"value=\S+", "", body)))
            elif head == "where":
                safe |= set(re.findall(r"isnotnull\(\s*'?([\w.]+)'?\s*\)", body))
                safe |= set(re.findall(r"\b([A-Za-z_][\w.]*)\s*(?:>=|<=|>|<|=|!=)\s*(?:\"|\d)", body))
            elif head == "search":
                safe |= set(re.findall(r"\b([A-Za-z_][\w.]*)\s*=\s*\S", body))
            elif head == "rename":
                for a, b in re.findall(r"([\w.*]+)\s+AS\s+([\w.*]+)", body, re.I):
                    if a in safe:
                        safe.add(b)
            elif head == "stats":
                m = re.search(r"\bBY\b(.*)$", unquote(body), re.I | re.S)
                fields = [f.strip("'") for f in re.findall(r"'[^']+'|[A-Za-z_][\w.{}]*", m.group(1))] if m else []
                problems += [f for f in fields if f not in safe]
                safe = set(fields) | set(cls.ALWAYS_PRESENT)
                safe |= set(re.findall(r"\b(?:count|dc|sum)\b(?:\([^)]*\))?\s+AS\s+(\w+)", body, re.I))
            # rex: a capture group is null when the pattern misses, so it makes nothing safe.
        return problems

    def test_a_stats_by_field_is_made_non_null_first_or_is_named_with_a_reason(self):
        failures, allowed_and_seen = [], set()
        for fname, name, keys in splunk_searches():
            m = re.match(DETECTION_ID, name)
            if not m:
                continue                           # baseline builders: a null key is not a lookup row
            allowed = self.BY_FIELD_ALLOWED.get(m.group(0), {})
            for field in self.by_field_problems(keys["search"]):
                if field in allowed:
                    allowed_and_seen.add((m.group(0), field))
                else:
                    failures.append(f"{fname} [{m.group(0)}] stats BY {field}")
        self.assertEqual(failures, [], "\n" + "\n".join(failures))
        listed = {(uid, f) for uid, fields in self.BY_FIELD_ALLOWED.items() for f in fields}
        self.assertEqual(listed - allowed_and_seen, set(), "allowed, but no longer grouped on unchecked: take it off the list")


class FileEventActionTests(unittest.TestCase):
    """Three detections titled as a file being WRITTEN read file events of every kind, deletions
    included: R-D-AGT-026 and H-AGT-031 (found by review in pull request 72) and H-AGT-039 (found by
    review in pull request 73), then H-AGT-013 and R-D-AGT-013 on 2026-11-28. Same defect, three
    reviews, no test in between."""

    # A detection that only asks whether a file or a hash was ever seen may read every action.
    ANY_FILE_ACTION = {
        "H-AGT-014": "implant file names: presence in any event is the signal",
        "H-AGT-019": "task artifact paths: presence in any event is the signal",
        "R-D-AGT-006": "side-load artifact names: presence is the signal",
        "R-D-AGT-012": "hash sweep: a listed hash in any file event is a match",
        "R-D-AGT-014": "framework artifacts on a host: presence is the signal",
    }

    def test_a_read_of_file_events_tests_the_action_or_is_named_with_a_reason(self):
        untested = set()
        for uid, body in kql_units():
            for m in re.finditer(r"\bDeviceFileEvents\b(.*?)(?=^\s*\(?[A-Z][A-Za-z]+\s*(?:\||$)|\Z)", body, re.S | re.M):
                if "ActionType" not in m.group(1):
                    untested.add(uid)
        for fname, name, keys in splunk_searches():
            for read_ in re.findall(r"datamodel=Endpoint\.Filesystem\b[^\]|]*", keys["search"]):
                if "Filesystem.action" not in read_:
                    untested.add(re.match(DETECTION_ID, name).group(0) if re.match(DETECTION_ID, name) else f"{fname} [{name[:30]}]")
        self.assertEqual(sorted(untested - set(self.ANY_FILE_ACTION)), [], "file events read with no action test")
        self.assertEqual(sorted(set(self.ANY_FILE_ACTION) - untested), [], "now tests the action: take it off the list")


class TwinRegexTests(unittest.TestCase):
    """A detection written once per platform carried two versions of one expression. In the draft
    of splunk-hunting.conf, H-AGT-044's template pattern was [^\\s]+ in Splunk and [^\\s<&]+ in KQL,
    and H-AGT-032's label pattern stopped after one character in KQL. Then H-AGT-032's counter was
    taken with a left boundary and (?i) in Splunk and with neither in KQL, and R-D-AGT-020 and
    H-AGT-022 drifted the same way for four days. Expressions are compared where both platforms
    carry a regular expression; a difference both sides show fails."""

    REGEX_META = re.compile(r"\\[dsw]|\[\^|\(\?|\{\d")

    # id -> why the two platforms' expressions are meant to differ.
    REGEX_DIFFERS = {
        "R-D-AGT-001": "Splunk needs a full-string replace() pattern; KQL extract() takes the group alone",
        "R-D-AGT-013": "the Splunk rule has a query-log leg KQL does not; the file test is a wildcard list in Splunk",
        "H-AGT-038": "Splunk counts -prune inside the same rex; KQL counts it with a second countof()",
        "H-AGT-040": "Splunk splits the folder off the path with rex; KQL tests the extension by regex",
    }
    # id -> {Splunk expression, normalised: (the KQL expression it stands for, or None for one with no
    # KQL counterpart, and why)}.
    SPLUNK_FORM = {
        "H-AGT-032": {
            "(^|[^a-z0-9])((pentest|artex|artx|csai)-[a-z0-9][a-z0-9_-]*|i\\d{2,7}[-_]?(probe|canary)|(probe|canary)[-_]?i\\d{2,7}|tasks/[^/\\s\"]+/i\\d{2,7}|exp\\d+-worker-i\\d{2,7})":
                ("(^|[^a-z0-9])((pentest|artex|artx|csai)-[a-z0-9][a-z0-9_-]*|i\\d{2,7}[-_]?(probe|canary)|(probe|canary)[-_]?i\\d{2,7}|tasks/[^/\\s]+/i\\d{2,7}|exp\\d+-worker-i\\d{2,7})",
                 "_raw is JSON in Splunk, so a double quote also ends the tasks/ segment"),
            "^[^a-za-z0-9]+": ("[^a-za-z0-9]+", "replace() needs the anchor that KQL's trim_start() implies"),
            'identity/claims/upn"\\s*:\\s*"([^"]+)"': (None, "Splunk reads the claim from raw JSON; KQL has it as a column"),
            'identity/claims/objectidentifier"\\s*:\\s*"([^"]+)"': (None, "same"),
        },
        "R-D-AGT-027": {
            "artexprobe|^(i[0-9]{2,7}[-_]?(probe|canary)|pentest[-_]?prob)":
                ("^(i[0-9]{2,7}[-_]?(probe|canary)|pentest[-_]?prob)",
                 "Splunk folds the artexprobe substring into the match(); KQL tests it with contains"),
        },
    }

    @staticmethod
    def normal(rx, splunk):
        if splunk:
            rx = rx.replace('\\"', '"').replace("\\\\", "\\")
        rx = re.sub(r"\(\?<\w+>", "(", rx).replace("(?:", "(")
        rx = re.sub(r"^\(\?i\)", "", rx).replace("\\z", "$")
        return rx.lower()

    def regexes(self, text, splunk):
        return {self.normal(s, splunk) for s in re.findall(r'@?"((?:[^"\\]|\\.)*)"', text)
                if self.REGEX_META.search(s) and len(s) >= 8}

    def test_an_expression_both_platforms_carry_is_the_same_expression(self):
        kql = dict(kql_units())
        failures, compared = [], 0
        for fname, name, keys in splunk_searches():
            m = re.match(DETECTION_ID, name)
            if not m or m.group(0) not in kql:
                continue
            uid = m.group(0)
            a, b = self.regexes(keys["search"], True), self.regexes(kql[uid], False)
            forms = self.SPLUNK_FORM.get(uid, {})
            for expr in forms:
                self.assertIn(expr, a, f"{uid}: the Splunk form listed here is gone; take it off the list")
            a = {forms[x][0] if x in forms else x for x in a} - {None}
            differs = bool((a - b) and (b - a))
            if uid in self.REGEX_DIFFERS:
                self.assertTrue(differs, f"{uid} no longer differs; take it off REGEX_DIFFERS")
                continue
            compared += 1
            if differs:
                failures.append("%s\n    splunk only:   %s\n    sentinel only: %s" % (
                    uid, " ;; ".join(sorted(a - b))[:300], " ;; ".join(sorted(b - a))[:300]))
        self.assertEqual(failures, [], "\n" + "\n".join(failures))
        self.assertGreater(compared, 20)


class SortAfterConvertTests(unittest.TestCase):
    """In the draft of splunk-hunting.conf, H-AGT-032, H-AGT-039 and H-AGT-043 ran
    `convert ctime(first_seen)` and then sorted on the same field, which orders the rows by the
    text of the date and not by the time. Fixed by hand in review; nothing pinned it."""

    def test_no_search_sorts_on_a_field_it_has_already_turned_into_text(self):
        seen = 0
        for fname, name, keys in splunk_searches():
            converted = set()
            for cmd in spl_commands(keys["search"]):
                seen += 1
                if cmd.startswith("convert"):
                    converted |= set(re.findall(r"\bctime\((\w+)\)", cmd))
                elif cmd.startswith(("eval", "fieldformat")):
                    converted |= set(re.findall(r"(\w+)\s*=\s*strftime\(\s*\1\b", cmd))
                elif cmd.startswith("sort"):
                    fields = set(re.findall(r"[A-Za-z_]\w*", unquote(cmd[4:])))
                    self.assertFalse(fields & converted,
                                     f"{fname} [{name[:40]}]: sorts on {sorted(fields & converted)} after convert ctime()")
        self.assertGreater(seen, 200)


class KqlShapeTests(unittest.TestCase):
    """dcount(TenantId) shipped in H-AGT-016 from 2026-11-05 to 2026-11-24: Microsoft's table
    references describe TenantId as the Log Analytics workspace ID, so the count is always 1.
    toint() of a comparison shipped in the draft of H-AGT-038 seven times and was rewritten as
    iff(..., 1, 0) in review."""

    def test_the_workspace_id_is_not_counted_as_a_tenant(self):
        for uid, body in kql_units():
            self.assertNotRegex(body, r"dcount\(\s*TenantId\s*\)", uid)
            self.assertNotRegex(body, r"\bby\b[^|\n]*\bTenantId\b", uid)

    def test_a_comparison_is_not_cast_to_a_number(self):
        for uid, body in kql_units():
            self.assertNotRegex(body, r"\bto(?:int|long)\(\s*[^()]*\b(?:contains|has|startswith|endswith)\b", uid)


class ContinuationTests(unittest.TestCase):
    """The continuation check used to cover the hunts file only, 13 of the pack's searches. A line
    that loses its backslash cuts the search short there, and the rest is read as stanza keys or
    dropped, silently."""

    KNOWN_KEYS = re.compile(r"^(description|search|enableSched|cron_schedule|dispatch\.(earliest|latest)_time|"
                            r"alert\.suppress(\.fields|\.period)?|alert\.track|counttype|relation|quantity|"
                            r"action\.[\w.]+|schedule_window|disabled|is_visible|request\.ui_dispatch_app)$")

    def test_every_search_in_every_conf_file_is_continued_to_its_end(self):
        seen = 0
        for fname, name, keys in splunk_searches():
            lines = keys["search"].split("\n")
            seen += 1
            for line in lines[:-1]:
                self.assertTrue(line.endswith(" \\"), f"{fname} [{name[:40]}]: {line[-50:]!r}")
            self.assertFalse(lines[-1].endswith("\\"), f"{fname} [{name[:40]}]: last line ends in a backslash")
            for line in lines[1:]:
                self.assertRegex(line, r"^\s*[|\[\]]",
                                 f"{fname} [{name[:40]}]: continuation that is neither a pipe nor a subsearch bracket: {line[:50]!r}")
        self.assertGreater(seen, 50)

    def test_a_lost_backslash_does_not_turn_the_rest_of_a_search_into_keys(self):
        # After a line with no trailing backslash the value is over. If what follows is the tail of
        # a search, Splunk reads it as a key ("| eval x" up to its first "="), or drops it. Either
        # way it is not one of the keys these files use.
        for fname in CONF_FILES:
            for name, keys in conf_stanzas(read_asset(fname)):
                for key in keys:
                    self.assertRegex(key, self.KNOWN_KEYS, f"{fname} [{name[:40]}]: unexpected key {key!r}")
            cont = False
            for line in read_asset(fname).splitlines():
                if not cont and line.strip() and not line.startswith(("#", "[")):
                    self.assertRegex(line, r"^[A-Za-z_.0-9]+\s*=", f"{fname}: stray line {line[:60]!r}")
                cont = line.endswith("\\") and not line.startswith("#")


if __name__ == "__main__":
    unittest.main()
