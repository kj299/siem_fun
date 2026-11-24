# f5-irule-agentic.tcl - edge filter for agentic attack frameworks (ARTEX, CAIRN and kin).
#
# Rule IDs (W-AGT-nnn) and the evidence behind each are in README.md next to this file.
# Needs the data groups in f5-data-groups.tmsh. Attach to the HTTP virtual server.
#
# Status: needs_validation. Written against the BIG-IP iRules API (v13+), not loaded on a
# live device. Start with agt_log_only 1, read /var/log/ltm for "agt_waf", then switch.
#
# What this does NOT do: rate limiting and brute-force control. Use Advanced WAF
# brute-force protection, Bot Defense and session tracking for those (README.md, tier 3);
# a table-based counter in an iRule is per-TMM-cheap to write and expensive to run.

when RULE_INIT {
    # 1 = log only, 0 = respond 403. Flip per rule class below if you want a mixed mode.
    set static::agt_log_only 1
    # Largest request body inspected, in bytes. Bodies above it are not collected.
    set static::agt_max_body 65536
    # 1 = refuse source maps and API specs to clients outside agt_internal_nets (W-AGT-020).
    # Leave 0 if you publish your OpenAPI document on purpose.
    set static::agt_block_specs 0
}

proc agt_act { rule detail enforce } {
    # The detail is attacker-controlled text: cap it and keep it on one line.
    set d [string range [string map [list "\r" " " "\n" " "] $detail] 0 160]
    log local0.warn "agt_waf rule=$rule client=[IP::client_addr] host=[HTTP::host] detail=\"$d\""
    if { $enforce && !$static::agt_log_only } {
        HTTP::respond 403 content "Forbidden" "Connection" "close"
        return 1
    }
    return 0
}

when HTTP_REQUEST {
    set agt_ua [string tolower [HTTP::header value "User-Agent"]]
    set agt_path [string tolower [HTTP::path]]
    set agt_uri_raw [HTTP::uri]
    set agt_uri [string tolower [URI::decode $agt_uri_raw]]
    set agt_auth [HTTP::header value "Authorization"]

    # W-AGT-010: verified hostile infrastructure (block-action IPv4 rows of iocs.csv).
    # If a CDN or proxy sits in front, match the trusted client-IP header instead.
    if { [class match [IP::client_addr] equals agt_ip_block] } {
        if { [call agt_act "W-AGT-010" "ioc-ip" 1] } { return }
    }

    # W-AGT-001: user-agents compiled into the frameworks. Default builds only.
    if { $agt_ua ne "" && [class match $agt_ua contains agt_ua_block] } {
        # A request from the CyberStrikeAI web-shell manager means a shell may already
        # be on this server: page someone, do not just block.
        if { $agt_ua contains "cyberstrikeai-webshell" } {
            log local0.crit "agt_waf rule=W-AGT-002 client=[IP::client_addr] host=[HTTP::host] path=[HTTP::path] webshell-manager-inbound"
        }
        if { [call agt_act "W-AGT-001" $agt_ua 1] } { return }
    }
    # W-AGT-003: agent-adjacent tooling with legitimate users. Never enforced here.
    if { $agt_ua ne "" && [class match $agt_ua contains agt_ua_alert] } {
        call agt_act "W-AGT-003" $agt_ua 0
    }

    # W-AGT-004: canary probes, OAuth junk state, metadata-service SSRF, in path or query.
    if { [class match $agt_uri contains agt_canary_strings] } {
        if { [call agt_act "W-AGT-004" $agt_uri 1] } { return }
    }

    # W-AGT-005: unsigned JWT (header alg none). Base64 is case-sensitive: no tolower.
    if { [class match $agt_auth contains agt_jwt_none] || [class match $agt_uri_raw contains agt_jwt_none] || [class match [HTTP::header value "Cookie"] contains agt_jwt_none] } {
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
    if { [regexp {/i[0-9]{3,5}\.(asp|aspx|ashx|jsp|jspx|php)$} $agt_path] } {
        if { [call agt_act "W-AGT-008" $agt_path 1] } { return }
    }

    # W-AGT-020: source maps and API specs to outside clients (exposure reduction).
    if { $static::agt_block_specs && [class match $agt_path ends_with agt_spec_paths] && ![class match [IP::client_addr] equals agt_internal_nets] } {
        if { [call agt_act "W-AGT-020" $agt_path 1] } { return }
    }

    # Inspect small form/JSON/XML bodies for the same strings (logins, sign-up, recovery).
    set agt_len 0
    if { [HTTP::header exists "Content-Length"] && [string is integer -strict [HTTP::header value "Content-Length"]] } {
        set agt_len [HTTP::header value "Content-Length"]
    }
    if { [HTTP::method] eq "POST" || [HTTP::method] eq "PUT" || [HTTP::method] eq "PATCH" } {
        if { $agt_len > 0 && $agt_len <= $static::agt_max_body } {
            HTTP::collect $agt_len
        }
    }
}

when HTTP_REQUEST_DATA {
    set agt_body_raw [HTTP::payload]
    set agt_body [string tolower [URI::decode $agt_body_raw]]

    if { [class match $agt_body contains agt_canary_strings] } {
        if { [call agt_act "W-AGT-004" "body-canary" 1] } { return }
    }
    if { [class match $agt_body_raw contains agt_jwt_none] } {
        if { [call agt_act "W-AGT-005" "body-jwt-alg-none" 1] } { return }
    }
    if { [regexp {artex'\s*(/\*|--|#|union\s|and\s|or\s)} $agt_body] } {
        if { [call agt_act "W-AGT-006" "body-sqli-tag" 1] } { return }
    }
    if { [regexp {i[0-9]{2,5}probe[0-9]{10}@} $agt_body] } {
        if { [call agt_act "W-AGT-007" "body-probe-account" 1] } { return }
    }
    # W-AGT-008 in an upload: multipart filename shaped like an agent task artifact.
    if { [regexp {filename="?i[0-9]{3,5}\.(asp|aspx|ashx|jsp|jspx|php)} $agt_body] } {
        if { [call agt_act "W-AGT-008" "upload-task-artifact" 1] } { return }
    }
    # W-AGT-009: inline DTD in an XML body (the XXE half of the SAML chain, CrowdStrike).
    # A base64 SAMLResponse hides this from the edge: the fix for that is in the IdP/SP.
    if { [HTTP::header value "Content-Type"] contains "xml" && ($agt_body contains "<!doctype" || $agt_body contains "<!entity") } {
        if { [call agt_act "W-AGT-009" "xml-dtd" 1] } { return }
    }
    HTTP::release
}
