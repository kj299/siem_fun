# irule_runtime.tcl - a stand-in for the BIG-IP iRule runtime, for scripts/tests/test_waf_engines.py.
#
# Usage: tclsh irule_runtime.tcl <irule.tcl> <data-groups.tmsh> <cases.tcl>
#
# It implements just enough of the iRule surface to EXECUTE f5-irule-agentic.tcl against its real
# data groups: when, call, class match, HTTP::*, IP::client_addr, URI::decode, log, and the three
# infix operators (contains, starts_with, ends_with), which stock Tcl's expr does not have and
# which are therefore rewritten to a helper call before the rule is evaluated.
#
# What a pass here means: the rule's LOGIC is right under the command semantics F5 documents.
# What it does not mean: that a BIG-IP behaves the same. Three semantics are modelled from the
# documentation and matter to the cases: HTTP::header value returns the LAST header of a name,
# URI::decode leaves "+" alone, and class match treats a leading "-" as an option unless "--"
# ends option parsing (modelled as an error, which is the conservative reading).
set irule_path [lindex $argv 0]; set dg_path [lindex $argv 1]
# --- data groups -----------------------------------------------------------------------
array set DG {}; array set DGTYPE {}
set fh [open $dg_path]; set txt [read $fh]; close $fh
foreach line [split $txt "\n"] {
    if {![regexp {^create ltm data-group internal (\S+) type (\S+) records add \{(.*)\}\s*$} $line -> name type body]} continue
    set recs {}
    if {$type eq "string"} {
        foreach {m v} [regexp -all -inline {"((?:[^"\\]|\\.)*)"\s*\{\s*\}} $body] { lappend recs [string map [list "\\\\" "\\" "\\\"" "\""] $v] }
    } else {
        foreach {m v} [regexp -all -inline {(\S+)\s*\{\s*\}} $body] { lappend recs $v }
    }
    set DG($name) $recs; set DGTYPE($name) $type
}
proc ip2int {ip} { set n 0; foreach o [split $ip .] { set n [expr {($n<<8)|$o}] }; return $n }
proc class {sub args} {
    global DG DGTYPE
    if {$sub ne "match"} { error "class $sub not stubbed" }
    if {[lindex $args 0] eq "--"} { set args [lrange $args 1 end] } elseif {[string index [lindex $args 0] 0] eq "-"} { error "class match: value starting with - parsed as an option" }
    lassign $args value op name
    if {![info exists DG($name)]} { error "data group $name does not exist" }
    foreach r $DG($name) {
        if {$DGTYPE($name) eq "ip"} {
            if {$op ne "equals"} { error "ip data group needs equals" }
            lassign [split $r /] net bits; if {$bits eq ""} {set bits 32}
            set mask [expr {$bits==0 ? 0 : (0xffffffff << (32-$bits)) & 0xffffffff}]
            if {([ip2int $value] & $mask) == ([ip2int $net] & $mask)} { return 1 }
        } else {
            switch $op {
                contains    { if {[string first $r $value] >= 0} { return 1 } }
                equals      { if {$r eq $value} { return 1 } }
                ends_with   { if {[string length $r] <= [string length $value] && [string range $value end-[expr {[string length $r]-1}] end] eq $r} { return 1 } }
                starts_with { if {[string first $r $value] == 0} { return 1 } }
                default     { error "class match operator $op not stubbed" }
            }
        }
    }
    return 0
}
proc f5op {op a b} {
    switch $op {
        contains    { return [expr {[string first $b $a] >= 0}] }
        starts_with { return [expr {[string first $b $a] == 0}] }
        ends_with   { return [expr {[string length $b] <= [string length $a] && [string range $a end-[expr {[string length $b]-1}] end] eq $b}] }
    }
}
# --- request state and F5 commands ------------------------------------------------------
namespace eval static {}
namespace eval HTTP {
    proc header {sub name} {
        global REQ
        set k [string tolower $name]
        if {$sub eq "value"}  { return [expr {[dict exists $REQ headers $k] ? [dict get $REQ headers $k] : ""}] }
        if {$sub eq "exists"} { return [dict exists $REQ headers $k] }
        if {$sub eq "values"} { return [expr {[dict exists $REQ dup $k] ? [dict get $REQ dup $k] : ([dict exists $REQ headers $k] ? [list [dict get $REQ headers $k]] : {})}] }
        error "HTTP::header $sub not stubbed"
    }
    proc uri {}    { global REQ; return [dict get $REQ uri] }
    proc path {}   { global REQ; return [lindex [split [dict get $REQ uri] ?] 0] }
    proc host {}   { return "www.example.test" }
    proc method {} { global REQ; return [dict get $REQ method] }
    proc payload {} { global REQ COLLECT; return [string range [dict get $REQ body] 0 [expr {$COLLECT-1}]] }
    proc collect {{n ""}} { global COLLECT; if {$n eq ""} { error "collect without a length" }; set COLLECT $n }
    proc release {} { global RELEASED; set RELEASED 1 }
    proc respond {code args} { global RESP; if {$RESP ne ""} { error "Multiple HTTP::respond invocations" }; set RESP $code }
}
namespace eval IP  { proc client_addr {} { global REQ; return [dict get $REQ ip] } }
namespace eval URI {
    # F5 documents URI::decode as percent-decoding; "+" is left alone.
    proc decode {s} {
        set out ""; set i 0; set n [string length $s]
        while {$i < $n} {
            set c [string index $s $i]
            if {$c eq "%" && [regexp {^[0-9a-fA-F]{2}$} [string range $s [expr {$i+1}] [expr {$i+2}]]]} {
                append out [format %c [scan [string range $s [expr {$i+1}] [expr {$i+2}]] %x]]; incr i 3
            } else { append out $c; incr i }
        }
        return $out
    }
}
proc log {args} { global LOGS; lappend LOGS [lindex $args end] }
proc call {name args} { return [uplevel 1 [list $name {*}$args]] }
array set EVENT {}
proc when {ev body} { global EVENT; set EVENT($ev) $body }
# --- load the iRule, rewriting the three F5-only infix operators --------------------------
set fh [open $irule_path]; set src [read $fh]; close $fh
set n [regsub -all {(\$[A-Za-z_:]+|\[HTTP::header value "[^"]+"\]|\[string tolower \[HTTP::header value "[^"]+"\]\])\s+(contains|ends_with|starts_with)\s+("[^"]*")} $src {[f5op \2 \1 \3]} src]
if {[regexp {\s(contains|ends_with|starts_with|equals)\s+"} $src]} { error "an F5 infix operator survived the rewrite" }
puts "rewrote $n F5 infix operators; data groups: [lsort [array names DG]]"
eval $src
catch {uplevel #0 $EVENT(RULE_INIT)}
proc run {req} {
    global REQ RESP LOGS COLLECT RELEASED EVENT
    set REQ [dict merge {method GET uri / ip 198.51.100.7 headers {} body "" dup {}} $req]
    set h {}; dict for {k v} [dict get $REQ headers] { dict set h [string tolower $k] $v }
    if {[dict get $REQ body] ne "" && ![dict exists $h content-length] && ![dict exists $h transfer-encoding]} { dict set h content-length [string length [dict get $REQ body]] }
    if {![dict exists $h user-agent]} { dict set h user-agent "Mozilla/5.0 (X11; Linux x86_64) Chrome/130.0.0.0 Safari/537.36" }
    dict set REQ headers $h
    set RESP ""; set LOGS {}; set COLLECT 0; set RELEASED 0
    set rc [catch {uplevel #0 $EVENT(HTTP_REQUEST)} err]
    if {$rc == 1} { return [list ERROR $err {}] }
    if {$RESP eq "" && $COLLECT > 0} {
        set rc [catch {uplevel #0 $EVENT(HTTP_REQUEST_DATA)} err]
        if {$rc == 1} { return [list ERROR $err {}] }
        if {$RESP eq "" && !$RELEASED} { return [list HUNG "collected but never released" {}] }
    }
    set rules {}; foreach l $LOGS { if {[regexp {rule=(W-AGT-[0-9]+)} $l -> r]} { lappend rules $r } }
    return [list [expr {$RESP eq "" ? "pass" : $RESP}] [lsort -unique $rules] $LOGS]
}
set fail 0; set total 0
proc t {name req want_status want_rules} {
    global fail total; incr total
    lassign [run $req] st rules logs
    set ok [expr {$st eq $want_status && $rules eq [lsort -unique $want_rules]}]
    if {!$ok} { incr fail; puts "FAIL $name: got $st {$rules} want $want_status {$want_rules}" } elseif {[info exists ::env(VERBOSE)]} { puts "ok   $name" }
}
source [lindex $argv 2]
puts "failures: $fail of $total"
