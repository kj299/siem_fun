# f5-irule-agentic.tcl - edge filter for agentic attack frameworks (ARTEX, CAIRN and kin).
#
# Rule IDs (W-AGT-nnn) and the evidence behind each are in README.md next to this file.
# Needs the data groups in f5-data-groups.tmsh. Attach to the HTTP virtual server.
#
# Status: needs_validation. Command usage (class match, call/proc, HTTP::collect,
# HTTP::respond with noserver, HTTP::header values) was checked against F5's iRules
# reference on clouddocs.f5.com on 2026-11-24, and the rule's logic was executed against
# its data groups in a Tcl stand-in for the iRule runtime (README.md, "What was executed").
# It has not been loaded on a live device. Start with agt_log_only 1, read /var/log/ltm
# for "agt_waf", then switch.
#
# What this does NOT do: rate limiting and brute-force control. Use Advanced WAF
# brute-force protection, Bot Defense and session tracking for those (README.md, tier 3);
# a table-based counter in an iRule is per-TMM-cheap to write and expensive to run.

when RULE_INIT {
    # 1 = log only, 0 = respond 403. Flip per rule class below if you want a mixed mode.
    set static::agt_log_only 1
    # Bytes of request body inspected. A longer body has its first agt_max_body bytes
    # inspected; the rest goes through unread.
    set static::agt_max_body 65536
    # 1 = refuse source maps, API specs and Swagger UI to clients outside agt_internal_nets
    # (W-AGT-020). Leave 0 if you publish your OpenAPI document on purpose.
    set static::agt_block_specs 0
    # 1 = refuse management endpoints (Spring Boot Actuator, Go pprof) to clients outside
    # agt_internal_nets (W-AGT-021). /actuator/health stays open for load balancers.
    set static::agt_block_mgmt 1
}

proc agt_act { rule detail enforce } {
    # The detail is attacker-controlled text: cap it and keep it on one line.
    set d [string range [string map [list "\r" " " "\n" " "] $detail] 0 160]
    log local0.warn "agt_waf rule=$rule client=[IP::client_addr] host=[HTTP::host] detail=\"$d\""
    if { $enforce && !$static::agt_log_only } {
        HTTP::respond 403 content "Forbidden" noserver "Connection" "close"
        return 1
    }
    return 0
}

when HTTP_REQUEST {
    # "HTTP::header value" returns only the LAST header of a name, so a client that sends
    # the header twice chooses which one is read. Join every value instead. (F5 notes that
    # "HTTP::header values" can drop colons from what it returns; nothing matched here has one.)
    set agt_ua [string tolower [join [HTTP::header values "User-Agent"] " "]]
    # HTTP::path is the path as sent: still percent-encoded and still carrying ;parameters.
    # Decode it, or /%61ctuator/env and /.%65nv walk past the path rules below.
    set agt_path [string tolower [URI::decode [HTTP::path]]]
    set agt_uri_raw [HTTP::uri]
    # "+" is a space in a query string and URI::decode leaves it alone: map it first, or
    # artex'+union+select is not the artex' union select that W-AGT-006 looks for.
    set agt_uri [string tolower [URI::decode [string map {+ " "} $agt_uri_raw]]]
    set agt_auth [join [HTTP::header values "Authorization"] " "]

    # W-AGT-010: verified hostile infrastructure (block-action IPv4 rows of iocs.csv).
    # If a CDN or proxy sits in front, match the trusted client-IP header instead.
    if { [class match -- [IP::client_addr] equals agt_ip_block] } {
        if { [call agt_act "W-AGT-010" "ioc-ip" 1] } { return }
    }

    # W-AGT-001: user-agents compiled into the frameworks (default builds only), and the
    # framework's own name at the start of a word. F5 Labs (2026-11-23) lists 46 user-agents
    # it tied to ARTEX; the agent makes them up per task and 44 carry the name. The word
    # start keeps SmartExchange out. The agent changes the header when blocked.
    if { $agt_ua ne "" && ([class match -- $agt_ua contains agt_ua_block] || [regexp {(^|[^a-z])artex} $agt_ua]) } {
        # A request from the CyberStrikeAI web-shell manager means a shell may already
        # be on this server: page someone, do not just block.
        if { $agt_ua contains "cyberstrikeai-webshell" } {
            log local0.crit "agt_waf rule=W-AGT-002 client=[IP::client_addr] host=[HTTP::host] path=[HTTP::path] webshell-manager-inbound"
        }
        if { [call agt_act "W-AGT-001" $agt_ua 1] } { return }
    }
    # W-AGT-011: shell command syntax inside the User-Agent (Microsoft 2026-11-05: exploitation
    # "by embedded shell commands in a user agent"). No browser sends these characters.
    if { [regexp {(\$\(|`|;\s*(curl|wget|bash|sh|nc|python[0-9.]*)\s|\|\s*(sh|bash)($|\s))} $agt_ua] } {
        if { [call agt_act "W-AGT-011" $agt_ua 1] } { return }
    }
    # W-AGT-013: One API family auth-bypass header (Amazon). Log only: only LLM gateways care.
    if { [HTTP::header exists "isCliRequest"] } {
        call agt_act "W-AGT-013" "iscli-header" 0
    }
    # W-AGT-003: agent-adjacent tooling with legitimate users. Never enforced here.
    if { $agt_ua ne "" && [class match -- $agt_ua contains agt_ua_alert] } {
        call agt_act "W-AGT-003" $agt_ua 0
    }

    # W-AGT-004: canary probes, OAuth junk state, metadata-service SSRF, in path or query.
    if { [class match -- $agt_uri contains agt_canary_strings] } {
        if { [call agt_act "W-AGT-004" $agt_uri 1] } { return }
    }

    # W-AGT-005: unsigned JWT (header alg none). Base64 is case-sensitive: no tolower.
    if { [class match -- $agt_auth contains agt_jwt_none] || [class match -- $agt_uri_raw contains agt_jwt_none] || [class match -- [join [HTTP::header values "Cookie"] ";"] contains agt_jwt_none] } {
        if { [call agt_act "W-AGT-005" "jwt-alg-none" 1] } { return }
    }

    # W-AGT-006: ARTEX-tagged SQL injection probe (S-RM).
    if { [regexp {artex'\s*(/\*|--|#|union\s|and\s|or\s)} $agt_uri] } {
        if { [call agt_act "W-AGT-006" $agt_uri 1] } { return }
    }

    # W-AGT-007: probe-account naming, i<intent>probe<unix-time>@ (Okta).
    if { [regexp {i[0-9]{2,5}probe[0-9]{10}@} $agt_uri] } {
        if { [call agt_act "W-AGT-007" $agt_uri 1] } { return }
    }

    # W-AGT-008: request for a script named like an agent task artifact, i<number>.<ext>.
    # The name may be followed by path info or a ;parameter: both still run the script.
    if { [regexp {/i[0-9]{3,5}\.(asp|aspx|ashx|jsp|jspx|php)($|[/;])} $agt_path] } {
        if { [call agt_act "W-AGT-008" $agt_path 1] } { return }
    }

    # W-AGT-008 (second shape): JSP shells GTIG saw written by MySQL log poisoning
    # (cl1217.jsp, f1219a.jsp, z1219.jsp): 1-2 letters, 4 digits, optional letter.
    if { [regexp {/[a-z]{1,2}[0-9]{4}[a-z]?\.jspx?($|[/;])} $agt_path] } {
        if { [call agt_act "W-AGT-008" $agt_path 1] } { return }
    }

    # W-AGT-014: path traversal in the path or query. Checked on the raw URI (lower-cased)
    # for the encoded forms and on the decoded one for the plain forms. A browser resolves
    # dot-segments before it sends a request, so ../ in a path is never typed by a person.
    # Amazon 2026-11-20: Cairn agents found traversal in a filename parameter in 11 minutes.
    if { [class match -- [string tolower $agt_uri_raw] contains agt_traversal] || [class match -- $agt_uri contains agt_traversal] } {
        if { [call agt_act "W-AGT-014" $agt_uri 1] } { return }
    }

    # W-AGT-021: files and endpoints that should never be served to the internet.
    # Secret files (.env, .git) are refused to everyone; management endpoints to outsiders.
    # Anchored on purpose: a plain "contains /.env" also refuses /docs/.environment-setup,
    # and "contains /actuator" refuses /actuators-catalogue. ";" counts as a boundary
    # because Tomcat and Spring drop ;parameters (/actuator;x/env is /actuator/env).
    if { [regexp {/\.env([.;]|$)|/\.git([/;]|$)} $agt_path] } {
        if { [call agt_act "W-AGT-021" $agt_path 1] } { return }
    }
    # /actuator/health and its probe groups stay open for load balancers. The exemption
    # accepts plain path segments only, so /actuator/health/..;/env does not ride through.
    if { $static::agt_block_mgmt && [regexp {/actuator([/;]|$)|/debug/pprof} $agt_path] && ![regexp {/actuator/health(/[a-z0-9_-]+)*/?$} $agt_path] && ![class match -- [IP::client_addr] equals agt_internal_nets] } {
        if { [call agt_act "W-AGT-021" $agt_path 1] } { return }
    }

    # W-AGT-020: source maps, API specs and Swagger UI to outside clients (exposure reduction).
    # Tested on the path with any ;parameters removed, since ends_with would miss them.
    set agt_path_bare [regsub -all {;[^/]*} $agt_path ""]
    if { $static::agt_block_specs && ([class match -- $agt_path_bare ends_with agt_spec_paths] || $agt_path_bare contains "/swagger-ui") && ![class match -- [IP::client_addr] equals agt_internal_nets] } {
        if { [call agt_act "W-AGT-020" $agt_path 1] } { return }
    }

    # Inspect form/JSON/XML bodies for the same strings (logins, sign-up, recovery).
    # Collect the declared length, capped at agt_max_body; a chunked body declares none, so
    # ask for the cap. Skipping bodies over the cap, as this rule first did, let a client
    # opt out of every body rule by padding the request, and skipped chunked bodies entirely.
    set agt_len 0
    if { [HTTP::header exists "Content-Length"] && [string is integer -strict [HTTP::header value "Content-Length"]] } {
        set agt_len [HTTP::header value "Content-Length"]
        if { $agt_len > $static::agt_max_body } { set agt_len $static::agt_max_body }
    } elseif { [string tolower [HTTP::header value "Transfer-Encoding"]] contains "chunked" } {
        set agt_len $static::agt_max_body
    }
    if { [HTTP::method] eq "POST" || [HTTP::method] eq "PUT" || [HTTP::method] eq "PATCH" } {
        if { $agt_len > 0 } {
            HTTP::collect $agt_len
        }
    }
}

when HTTP_REQUEST_DATA {
    set agt_body_raw [HTTP::payload]
    # "+" is a space in a form body; see the note on agt_uri above.
    set agt_body [string tolower [URI::decode [string map {+ " "} $agt_body_raw]]]
    # Media types are case-insensitive and the "contains" operator is not.
    set agt_ctype [string tolower [join [HTTP::header values "Content-Type"] " "]]

    if { [class match -- $agt_body contains agt_canary_strings] } {
        if { [call agt_act "W-AGT-004" "body-canary" 1] } { return }
    }
    if { [class match -- $agt_body_raw contains agt_jwt_none] } {
        if { [call agt_act "W-AGT-005" "body-jwt-alg-none" 1] } { return }
    }
    if { [regexp {artex'\s*(/\*|--|#|union\s|and\s|or\s)} $agt_body] } {
        if { [call agt_act "W-AGT-006" "body-sqli-tag" 1] } { return }
    }
    if { [regexp {i[0-9]{2,5}probe[0-9]{10}@} $agt_body] } {
        if { [call agt_act "W-AGT-007" "body-probe-account" 1] } { return }
    }
    # W-AGT-014 in a form body: a parameter value that climbs directories. Form bodies only;
    # JSON and XML carry ../ legitimately too often (relative links, import paths).
    if { $agt_ctype starts_with "application/x-www-form-urlencoded" && [regexp {(^|[=&])[^&]*\.\.[/\\]} $agt_body] } {
        if { [call agt_act "W-AGT-014" "body-traversal" 1] } { return }
    }
    # W-AGT-008 in an upload: multipart filename shaped like an agent task artifact.
    if { [regexp {filename="?i[0-9]{3,5}\.(asp|aspx|ashx|jsp|jspx|php)} $agt_body] } {
        if { [call agt_act "W-AGT-008" "upload-task-artifact" 1] } { return }
    }
    # W-AGT-012: upload filename that climbs out of the upload directory, or names a Python
    # auto-import file (Amazon 2026-11-20: Cairn agents wrote sitecustomize.py this way).
    if { [regexp {filename="?[^"\r\n]*(\.\./|\.\.\\|sitecustomize\.py|usercustomize\.py)} $agt_body] } {
        if { [call agt_act "W-AGT-012" "upload-traversal" 1] } { return }
    }
    # W-AGT-009: inline DTD in an XML body (the XXE half of the SAML chain, CrowdStrike).
    # A base64 SAMLResponse hides this from the edge: the fix for that is in the IdP/SP.
    if { $agt_ctype contains "xml" && ($agt_body contains "<!doctype" || $agt_body contains "<!entity") } {
        if { [call agt_act "W-AGT-009" "xml-dtd" 1] } { return }
    }
    HTTP::release
}
