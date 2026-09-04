param(
    [string]$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path,

    # Define the helper functions and return without running any checks, so the
    # test suite can dot-source this script and exercise them in isolation.
    [switch]$FunctionsOnly
)

$ErrorActionPreference = "Stop"
$issues = New-Object System.Collections.Generic.List[string]

# .NET file APIs resolve relative paths against the process working directory
# while PowerShell cmdlets resolve against the session location. Pin $Root to an
# absolute path so both agree when -Root is passed relative.
$Root = (Resolve-Path -LiteralPath $Root).Path

# Helper YAML is parsed with a real parser rather than regexes, so legal
# reformatting (inline comments, flow lists, differing indent width) cannot
# produce phantom drift failures. Required rather than optional: silently
# skipping the parity checks would let real drift pass unnoticed.
if (-not (Get-Module -ListAvailable -Name powershell-yaml)) {
    Write-Host "The powershell-yaml module is required. Install it with:" -ForegroundColor Red
    Write-Host "  Install-Module powershell-yaml -Scope CurrentUser -Force" -ForegroundColor Red
    exit 1
}
Import-Module powershell-yaml -ErrorAction Stop

function Add-Issue {
    param([string]$Message)
    $issues.Add($Message) | Out-Null
}

function Get-RepoFile {
    param([string]$RelativePath)
    return Join-Path $Root $RelativePath
}

$script:textCache = @{}
$script:yamlCache = @{}

function Read-Text {
    param([string]$RelativePath)
    if ($script:textCache.ContainsKey($RelativePath)) {
        return $script:textCache[$RelativePath]
    }
    $path = Get-RepoFile $RelativePath
    $text = ""
    if (Test-Path -LiteralPath $path -PathType Leaf) {
        # Assert-Exists reports missing required files; returning empty text
        # lets the run finish and print every collected issue.
        # -LiteralPath, not -Path: a filename containing [ or ] is a wildcard to
        # -Path and would abort the run under ErrorActionPreference=Stop.
        $raw = Get-Content -Raw -LiteralPath $path
        if ($null -ne $raw) {
            $text = $raw
        }
    }
    $script:textCache[$RelativePath] = $text
    return $text
}

function Assert-Exists {
    param([string]$RelativePath)
    if (-not (Test-Path -LiteralPath (Get-RepoFile $RelativePath))) {
        Add-Issue "Missing required file: $RelativePath"
    }
}

function Test-RepoFile {
    param([string]$RelativePath)
    return Test-Path -LiteralPath (Get-RepoFile $RelativePath) -PathType Leaf
}

function Assert-Contains {
    param(
        [string]$RelativePath,
        [string]$Pattern,
        [string]$Description
    )
    $text = Read-Text $RelativePath
    if ($text -cnotmatch $Pattern) {
        Add-Issue "$RelativePath is missing $Description"
    }
}

function Get-YamlDocument {
    param([string]$RelativePath)

    if ($script:yamlCache.ContainsKey($RelativePath)) {
        return $script:yamlCache[$RelativePath]
    }
    $document = $null
    $text = Read-Text $RelativePath
    if (-not [string]::IsNullOrWhiteSpace($text)) {
        try {
            $document = ConvertFrom-Yaml $text
        } catch {
            Add-Issue "$RelativePath is not valid YAML: $($_.Exception.Message)"
            $document = $null
        }
    }
    $script:yamlCache[$RelativePath] = $document
    return $document
}

function Get-MapValue {
    param(
        $Map,
        [string]$Key
    )

    # ConvertFrom-Yaml returns a mapping type that varies by module version
    # (Hashtable or OrderedDictionary); both expose ContainsKey and an indexer,
    # so go through IDictionary rather than assuming a concrete type.
    if ($null -eq $Map -or $Map -isnot [System.Collections.IDictionary]) {
        return $null
    }
    if (-not $Map.Contains($Key)) {
        return $null
    }
    return $Map[$Key]
}

function Get-YamlList {
    param(
        $Document,
        [string]$Section,
        [string]$Key
    )

    # Returns $null when the section or key is absent, so callers can tell
    # "not declared" apart from "declared empty". A real YAML parse replaces
    # the previous hand-rolled regex, which broke on legal reformatting
    # (inline comments, flow lists, differing indent width).
    #
    # Presence is decided with Contains rather than by testing the returned
    # value against $null: PowerShell unrolls an empty array on return, so a
    # declared-but-empty list would arrive as $null and be misreported as
    # missing from both files.
    $sectionValue = Get-MapValue $Document $Section
    if ($sectionValue -isnot [System.Collections.IDictionary] -or -not $sectionValue.Contains($Key)) {
        return $null
    }
    $keyValue = $sectionValue[$Key]
    if ($null -eq $keyValue) {
        # 'key:' with no value parses to null; it is declared, just empty.
        return , @()
    }
    if ($keyValue -is [string] -or $keyValue -isnot [System.Collections.IEnumerable]) {
        return @([string]$keyValue)
    }

    $items = @()
    foreach ($item in $keyValue) {
        $items += [string]$item
    }
    return , $items
}

function Assert-ListsEqual {
    param(
        [string]$Name,
        $Left,
        $Right
    )

    # $null means the section or key is absent; an empty array means it is
    # declared with no items. Both sides absent is a real problem (the check
    # would otherwise pass vacuously), so report it rather than comparing.
    if ($null -eq $Left -and $null -eq $Right) {
        Add-Issue "Helper drift: $Name is declared in neither file"
        return
    }
    if ($null -eq $Left -or $null -eq $Right) {
        Add-Issue "Helper drift: $Name is declared in only one of the two files"
        return
    }
    $leftText = (@($Left) -join "`n")
    $rightText = (@($Right) -join "`n")
    if ($leftText -cne $rightText) {
        Add-Issue "Helper drift detected in $Name"
    }
}

# Line-ending-sensitive patterns, defined above the -FunctionsOnly return so the
# unit suite can assert their CRLF behaviour directly. CI checks out CRLF while
# the usual dev tree is LF, so a bare '$' anchor here is a silent no-op on the
# only OS that runs this script.
$script:conflictMarkerRegex = '(?m)^(<{7}( |\r?$)|={7}\r?$|>{7}( |\r?$))'
$script:fencedBlockRegex    = '(?ms)^[ \t]*```.*?^[ \t]*```[ \t]*\r?$'
# Single-backtick spans. Query text in these docs lives in fenced blocks OR in
# table cells written as inline code, and a scanner that reads only fences
# silently skips whole files -- splunk-to-kql-mapping.md has no fenced block at
# all, and examples-and-troubleshooting.md puts SPL in ```text.
$script:inlineCodeRegex     = '`([^`\r\n]+)`'
# Deliberately unanchored and case-insensitive, and applied per code snippet
# rather than to whole-file text. The previous '^\s*\| where' anchor missed
# 'index=x | where noise=true' written on one line and every table cell, and the
# case-sensitive compare missed 'riot=TRUE', which has the identical
# silent-no-match bug. Scanning per snippet is what makes dropping the anchor
# safe: prose that names '| where' and 'noise=true' in two separate code spans
# (CLAUDE.md does exactly this) never forms a single matching string.
# [^|\r\n]* keeps the match inside one clause on one line.
$script:whereBooleanRegex   = '(?i)\|[ \t]*where\b[^|\r\n]*=[ \t]*(true|false)\b'
# The same pattern anchored to the start of a line, applied to raw file text.
# The snippet scan alone would have LOST the original check's coverage of a bare
# prose line beginning with '| where', so both input sets are kept and the
# issue is raised if either fires.
$script:whereBooleanLineRegex = '(?im)^[ \t]*\|[ \t]*where\b[^|\r\n]*=[ \t]*(true|false)\b'
# Every OUTPUT field of a documented lookup must appear in that lookup's
# documented field list. The join KEY is intentionally not checked: these docs
# treat the key field name as version-dependent and tell the reader to confirm
# it with inputlookup, so requiring it to be listed would contradict them.
$script:lookupUsageRegex    = '(?im)\|[ \t]*lookup[ \t]+(?<name>[A-Za-z_]\w*)\b[^|\r\n]*?\bOUTPUT(?:NEW)?[ \t]+(?<fields>[^|\r\n]+)'
$script:backtickTokenRegex  = '`([A-Za-z_][A-Za-z0-9_.:]*)`'
# Language-tagged fenced blocks, so SPL-only rules can be applied to SPL only.
$script:fencedWithLangRegex = '(?ms)^[ \t]*```(?<lang>[^\r\n]*)\r?\n(?<body>.*?)^[ \t]*```[ \t]*\r?$'
# Three or more BARE index= terms chained with OR. Deliberately not any OR
# chain: multi-index-patterns.md documents
# '((index=firewall sourcetype=cisco:asa) OR (index=proxy sourcetype=...))' as
# the correct pattern when schemas differ per index, which 'index IN (...)'
# cannot express. Requiring the disjuncts to be bare index= terms spares it.
$script:bareIndexOrRegex    = '(?i)index[ \t]*=[ \t]*[\w:*]+(?:[ \t]+OR[ \t]+index[ \t]*=[ \t]*[\w:*]+){2,}'
# A DENYLIST, not a whitelist of generating commands. In SPL a leading pipe
# already means the first command is generating -- you cannot pipe into the
# first command -- and every app adds its own (the GreyNoise commands here start
# pipelines the same way tstats does), so a whitelist can never be complete and
# would report each new one as a defect. What a leading pipe does NOT guarantee
# is that the command generates rather than searches: '| search index=... ' is
# a raw-event search wearing a generating command's syntax, and that is the case
# worth naming.
$script:splNonGeneratingLeadCommands = @("search")
# An actual time PREDICATE, not a mention of _time. 'index=firewall | stats
# latest(_time)' scans all history but contains the string '_time', so a bare
# substring test exempted it.
$script:splTimePredicateRegex = '(?i)(\bearliest[ \t]*=|\blatest[ \t]*=|_time[ \t]*(?:>=|<=|<|>|=)|(?:>=|<=|<|>)[ \t]*_time|\bbin[ \t]*\([ \t]*_time)'
# High-precision credential shapes only. A generic 'password=...' pattern would
# fire on docs that discuss credentials, and a check that cries wolf gets turned
# off rather than fixed.
$script:secretPatterns = @(
    @{ Name = "an AWS access key id";           Pattern = 'AKIA[0-9A-Z]{16}' },
    @{ Name = "a GitHub token";                 Pattern = 'gh[pousr]_[A-Za-z0-9]{36}' },
    @{ Name = "a Slack token";                  Pattern = 'xox[baprs]-[A-Za-z0-9-]{10,}' },
    @{ Name = "a private key block";            Pattern = '-----BEGIN [A-Z ]*PRIVATE KEY-----' },
    @{ Name = "a Splunk session key or bearer token"; Pattern = '(?i)\b(Splunk|Bearer)[ \t]+[A-Za-z0-9+/]{40,}={0,2}\b' }
)

# Colon-delimited lowercase tokens: the shape of a Splunk sourcetype. (?-i) is
# Segments accept either case. An earlier version required a lowercase first
# letter on the assumption that sourcetypes are lowercase; the repo's own
# catalogue disproves it (OktaIM2:log), and the effect was that the whole
# OktaIM2:* family -- including an invented OktaIM2:whatever -- was never
# matched and so bypassed the provenance check entirely.
# The colon is what identifies the shape, not the casing. Registry comparison
# stays case-sensitive (an ordinal HashSet), so wrong casing is still reported.
# The (?<!\$) rules out PowerShell scope syntax: allowing uppercase segments
# made '$env:SPLUNK_TOKEN' in the README read as a sourcetype.
$script:sourcetypeTokenRegex = '(?-i)(?<!\$)\b[A-Za-z][A-Za-z0-9_]*(?::[A-Za-z0-9_*]+){1,4}\b'
# Provenance registry for sourcetypes, populated below from the two docs that
# already exist to catalogue them. Deliberately NOT a new parallel list: a
# second registry would drift from the catalogue, and "add it to the catalogue"
# is the behaviour this check should be pushing authors toward anyway.
$script:knownSourcetypes = New-Object 'System.Collections.Generic.HashSet[string]'
$script:sourcetypeRegistryFiles = @(
    "splunk-enrichment-query-builder/references/splunkbase-app-catalog.md",
    "splunk-sentinel-query-builder/references/cim-vendor-alignment.md"
)

# The token check above reads sourcetypes by SHAPE, and only the colon-delimited
# shape, so the catalogue's colon-free names -- WinEventLog, XmlWinEventLog,
# fgt_traffic, the zscaler* family, 14 of 53 in all -- could never be checked and
# an invented name in that shape passed. This reads them by POSITION instead:
# every value written after 'sourcetype=' or inside 'sourcetype IN (...)' must
# be catalogued, whatever its shape, which is how the Sentinel table check
# already works. Probed first: the docs contain 8 distinct such values, all of
# which resolve once the legacy Sysmon channel-path sourcetype is catalogued.
$script:sourcetypeValueRegex = '(?i)\bsourcetype[ \t]*=[ \t]*"?([^\s"|),`\]]+)"?'
$script:sourcetypeInRegex    = '(?i)\bsourcetype[ \t]+IN[ \t]*\(([^)]*)\)'
# Catalogued names of ANY shape: every backticked name in the column the
# catalogue itself labels "Sourcetype", plus the backticked name that opens each
# vendor bullet in cim-vendor-alignment.
#
# Read by COLUMN NAME rather than from the first cell of the row, because the
# catalogue's tables are not uniform and never were. Most lead with the
# sourcetype, two lead with the add-on name written as plain prose
# ("Splunk Add-on for CrowdStrike FDR (app 5579)"), and the index-naming table
# leads with index globs. Taking the first cell therefore registered 11 index
# globs as sourcetypes and missed 9 real ones -- the CrowdStrike and Carbon
# Black families, both Perfmon names, and the two netflow names -- so a
# documented sourcetype written in query position was reported as invented.
#
# Kept separate from $knownSourcetypes on purpose: that set is colon tokens
# harvested from all prose, and replacing it with this one would make the prose
# check report WinEventLog:Security -- a SOURCE, correctly listed in the Source
# column -- as an uncatalogued sourcetype. The positional check accepts ONLY
# this set: the colon-token set contains those same sources, and accepting it as
# a fallback let a catalogued source pass as a sourcetype.
$script:knownSourcetypeNames = New-Object 'System.Collections.Generic.HashSet[string]'
$script:cimBulletNameRegex     = '(?m)^-[ \t]+[^`\r\n]*`([A-Za-z][A-Za-z0-9_:.*/-]*)`[^`\r\n]*->'
$script:tableSeparatorRegex    = '^:?-{3,}:?$'
$script:backtickedNameRegex    = '`([^`]+)`'

# One markdown table row, split into trimmed cells.
function Get-TableCells {
    param([string]$Line)

    $inner = $Line.Trim()
    if ($inner.StartsWith("|")) { $inner = $inner.Substring(1) }
    if ($inner.EndsWith("|"))   { $inner = $inner.Substring(0, [Math]::Max(0, $inner.Length - 1)) }
    $cells = @(($inner -split '\|') | ForEach-Object { $_.Trim() })
    # An empty array unrolls to nothing on return, so the caller would see $null.
    return , $cells
}

# Add every backticked name in the "Sourcetype" column of each catalogue table
# to $Names. In markdown the header is the row ABOVE the "| --- |" separator, so
# the separator is what identifies it; until one has been seen there is no known
# column and rows are skipped rather than guessed at. A table with no Sourcetype
# column contributes nothing, which is what the CIM alignment file's one table
# ("Data model | Root dataset | Core fields") should contribute.
function Add-CatalogueSourcetypeNames {
    param([string]$Text, [System.Collections.Generic.HashSet[string]]$Names)

    $column = -1
    $previous = $null
    foreach ($line in ($Text -split "\r?\n")) {
        if (-not $line.TrimStart().StartsWith("|")) {
            $column = -1
            $previous = $null
            continue
        }
        $cells = Get-TableCells $line
        $notSeparator = @($cells | Where-Object { $_ -notmatch $script:tableSeparatorRegex })
        if ($cells.Count -gt 0 -and $notSeparator.Count -eq 0) {
            $column = -1
            if ($null -ne $previous) {
                for ($i = 0; $i -lt $previous.Count; $i++) {
                    if ($previous[$i] -eq "Sourcetype" -or $previous[$i] -eq "Sourcetypes") {
                        $column = $i
                        break
                    }
                }
            }
            $previous = $null
            continue
        }
        if ($column -ge 0) {
            if ($column -lt $cells.Count) {
                foreach ($m in [regex]::Matches($cells[$column], $script:backtickedNameRegex)) {
                    $name = $m.Groups[1].Value.Trim()
                    if ($name.Length -gt 0) {
                        $null = $Names.Add($name)
                    }
                }
            }
            continue
        }
        $previous = $cells
    }
}

# Every sourcetype value written in query position, placeholders removed.
function Get-SourcetypeValues {
    param([string]$Text)

    $values = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($m in [regex]::Matches($Text, $script:sourcetypeValueRegex)) {
        $null = $values.Add($m.Groups[1].Value)
    }
    foreach ($m in [regex]::Matches($Text, $script:sourcetypeInRegex)) {
        foreach ($raw in ($m.Groups[1].Value -split ',')) {
            $v = $raw.Trim().Trim('"')
            if ($v.Length -gt 0) {
                $null = $values.Add($v)
            }
        }
    }
    # A placeholder makes no claim: YOUR_SOURCETYPE, <name>, the ellipsis in an
    # illustrative snippet, and any wildcard.
    $real = @($values | Where-Object {
        -not ($_.StartsWith("YOUR_") -or $_.StartsWith("<") -or $_ -eq "..." -or $_.Contains("*"))
    })
    # An empty array unrolls to nothing on return, so the caller would see $null.
    return , $real
}

function Test-SourcetypeValues {
    param([string]$File, [string]$Text)

    foreach ($value in (Get-SourcetypeValues $Text)) {
        # Only the positional registry counts here. The colon-token set is
        # harvested from every backticked token in the registry files, and that
        # includes SOURCES the catalogue lists next to their sourcetype:
        # okta:im2 is named there as the source whose sourcetype is OktaIM2:log,
        # so accepting it from that set let sourcetype=okta:im2 pass and return
        # nothing. Reviewed as a P1 after the check first shipped.
        if ($script:knownSourcetypeNames.Contains($value)) {
            continue
        }
        Add-Issue "$File writes sourcetype=$value, which is not a catalogued sourcetype of any shape; never invent Splunk identifiers"
    }
}

# "Never invent Splunk or Sentinel identifiers" is this repo's highest-stakes
# content rule and had no mechanical enforcement at all. Every sourcetype named
# anywhere in the docs must resolve to the catalogue.
function Test-SourcetypeProvenance {
    param([string]$File, [string]$Text)

    $reported = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($m in [regex]::Matches($Text, $script:sourcetypeTokenRegex)) {
        $token = $m.Value
        # host:port from a URL, not a sourcetype.
        if ($token -match ':\d+$') {
            continue
        }
        # Splunk's documented prefix for a federated index; the part after the
        # colon is an index name, which is customer-defined by nature and so
        # cannot be registered.
        if ($token.StartsWith("federated:")) {
            continue
        }
        if ($script:knownSourcetypes.Contains($token)) {
            continue
        }
        # One issue per distinct token per file; a sourcetype used in six
        # examples is one mistake, not six.
        if ($reported.Add($token)) {
            Add-Issue "$File names sourcetype '$token', which is not catalogued in splunkbase-app-catalog.md or cim-vendor-alignment.md; never invent Splunk identifiers"
        }
    }
}

# KQL table names are CamelCase, which is far too common a shape to sweep for:
# field names (CommandLine), vendor names (PaloAltoNetworks) and even this
# repo's own class names match it. So the check is POSITIONAL -- an identifier
# is only treated as a table when it stands where a table must stand.
$script:kqlKeywords = @(
    "let", "union", "search", "find", "print", "range", "datatable",
    "externaldata", "materialize", "where", "set", "declare", "evaluate"
)
# A leading identifier: the source of a query, unless it is an operator.
# The (?!\() matters: a query may lead with a FUNCTION rather than a table.
# Microsoft ships _SentinelHealth() and _SentinelAudit() and tells you to prefer
# them over the underlying tables, and without this guard the recommended form
# is reported as an uncatalogued table. The let-value pattern below already
# excluded function calls for the same reason.
$script:kqlLeadingRefRegex = '^[ \t]*([A-Za-z_][A-Za-z0-9_]*)\b(?![ \t]*\()'
# 'union [withsource=X] [kind=inner] Table' and 'join [kind=leftouter] (Table'.
# The trailing \b(?![ \t]*=) is load-bearing, and BOTH parts are needed.
# Without the lookahead, 'union withsource=Table_ *' backtracks: the option group
# matches zero times and 'withsource' is captured as the table name. Without the
# \b, it backtracks one character further and captures 'withsourc', which the
# lookahead then happily accepts because the next character is 'e', not '='.
# Together they force the option group to consume the named option, after which
# '*' is correctly seen as no table at all.
$script:kqlUnionRefRegex   = '\bunion\b(?:[ \t]+\w+[ \t]*=[ \t]*\S+)*[ \t]+([A-Za-z_][A-Za-z0-9_]*)\b(?![ \t]*=)'
# union takes a comma-separated list, so the operands after the first need their
# own pass: 'union SigninLogs, InventedTable' hid everything past the comma.
$script:kqlUnionMoreRegex  = ',[ \t\r\n]*([A-Za-z_][A-Za-z0-9_]*)\b(?![ \t]*[=(])'
# (?s) so 'join (' followed by the table on the NEXT line is still seen. The
# line-at-a-time version missed every multiline join.
$script:kqlJoinRefRegex    = '(?s)\bjoin\b[^(\r\n]*\([ \t\r\n]*([A-Za-z_][A-Za-z0-9_]*)'
# 'let recent = SigninLogs;' binds a table. The negative lookahead for '(' keeps
# function calls out ('let cutoff = ago(1d);' must not read as a table 'ago').
$script:kqlLetValueRegex   = '\blet[ \t]+\w+[ \t]*=[ \t]*([A-Za-z_][A-Za-z0-9_]*)\b(?![ \t]*\()'
# The names those let statements bind. They are locals, not tables, and a later
# 'recent | take 5' must not be reported as an uncatalogued table.
$script:kqlLetNameRegex    = '\blet[ \t]+([A-Za-z_][A-Za-z0-9_]*)[ \t]*='
$script:knownKqlTables = New-Object 'System.Collections.Generic.HashSet[string]'
$script:kqlRegistryFile = "splunk-sentinel-query-builder/references/sentinel-table-catalog.md"
$script:requiredChecksFile = "scripts/required-checks.txt"

# Table references in a KQL block: the leading source, plus union and join
# operands. Returns names only; the caller decides what is registered.
function Get-KqlTableReferences {
    param([string]$Body)

    $refs = New-Object 'System.Collections.Generic.HashSet[string]'
    $lines = @(($Body -split '\r?\n') | Where-Object { $_.Trim().Length -gt 0 -and -not $_.Trim().StartsWith("//") })

    # Names bound by 'let' are locals, not tables. Collected first so a later
    # reference to one is not reported as an uncatalogued table.
    $locals = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($m in [regex]::Matches($Body, $script:kqlLetNameRegex)) {
        $null = $locals.Add($m.Groups[1].Value)
    }

    # The query's source is the first line that is not part of a 'let'
    # preamble. Reading line 0 unconditionally meant that
    # 'let cutoff = ago(1d);' followed by 'GhostTable | where ...' put the real
    # table on line 2, where nothing read it: 'let' is a keyword so the lead was
    # discarded, and the let-value pattern skips a function call, so an invented
    # table behind a let preamble was reported by nothing.
    $leadLine = @($lines | Where-Object { $_.Trim() -notmatch '^let\b' })
    if ($leadLine.Count -gt 0) {
        $lead = [regex]::Match($leadLine[0], $script:kqlLeadingRefRegex)
        if ($lead.Success -and $script:kqlKeywords -cnotcontains $lead.Groups[1].Value) {
            $null = $refs.Add($lead.Groups[1].Value)
        }
    }
    # Whole-body, not line-at-a-time: a join operand may sit on the line after
    # its '(', and a union list may wrap.
    foreach ($pattern in @($script:kqlUnionRefRegex, $script:kqlJoinRefRegex, $script:kqlLetValueRegex)) {
        foreach ($m in [regex]::Matches($Body, $pattern)) {
            $name = $m.Groups[1].Value
            # 'union withsource=Table_ *' has no named operand, and an
            # operator after union (union kind=outer ...) is not a table.
            if ($script:kqlKeywords -cnotcontains $name) {
                $null = $refs.Add($name)
            }
        }
    }
    # Trailing operands of a union list, taken only from the union statement
    # itself so that commas elsewhere (project, summarize by) are not mistaken
    # for table references.
    foreach ($u in [regex]::Matches($Body, $script:kqlUnionRefRegex)) {
        $tail = $Body.Substring($u.Index + $u.Length)
        $stop = $tail.IndexOfAny([char[]]@("|", "`r", "`n"))
        if ($stop -ge 0) {
            $tail = $tail.Substring(0, $stop)
        }
        foreach ($m in [regex]::Matches($tail, $script:kqlUnionMoreRegex)) {
            $name = $m.Groups[1].Value
            if ($script:kqlKeywords -cnotcontains $name) {
                $null = $refs.Add($name)
            }
        }
    }
    foreach ($local in $locals) {
        $null = $refs.Remove($local)
    }
    # An empty array unrolls to nothing on return, so the caller would see $null.
    return , @($refs)
}

# The other half of "never invent Splunk or Sentinel identifiers". The
# sourcetype check covers Splunk; this covers Sentinel, whose table names are
# case-sensitive -- SignInLogs is a different, non-existent table to SigninLogs.
function Test-KqlTableProvenance {
    param([string]$File, [string]$Body)

    foreach ($name in (Get-KqlTableReferences $Body)) {
        if (-not $script:knownKqlTables.Contains($name)) {
            Add-Issue "$File names Sentinel table '$name', which is not catalogued in sentinel-table-catalog.md; never invent Sentinel identifiers"
        }
    }
}

# A fixture asserting a shape names its sections in backticks, e.g.
# "Uses the optimization shape: `Objective`, `Query`, `What changed`".
# '\r?$', not a bare '$'. On CI's CRLF checkout the line ends '...\r\n', so
# [^\r\n]* stops at the \r and a bare '$' -- which matches only before the \n --
# never matches. The check was a complete no-op on the only OS that runs it, and
# a Linux run cannot see that: CI caught it, the local suite did not.
$script:fixtureShapeLineRegex = '(?im)^[^\r\n]*\bshape\b[^\r\n]*\r?$'
# Sections a SKILL.md declares, as numbered list items in its output shapes.
$script:skillSectionRegex     = '(?m)^\d+\.[ \t]+`?([A-Z][A-Za-z ]{2,30}?)`?[ \t]*(?:\(|\r?$)'

# Golden prompts assert the shape of a skill's answer. If a fixture names a
# section no skill declares, either the fixture or the skill has drifted and the
# fixture is no longer testing the contract it claims to.
function Test-FixtureShapeSections {
    param([string]$FixtureText, [string[]]$DeclaredSections)

    foreach ($line in [regex]::Matches($FixtureText, $script:fixtureShapeLineRegex)) {
        foreach ($m in [regex]::Matches($line.Value, '`([A-Z][A-Za-z ]{2,30})`')) {
            $section = $m.Groups[1].Value.Trim()
            if ($DeclaredSections -cnotcontains $section) {
                Add-Issue "examples/golden-prompts.md asserts an output section '$section' that no SKILL.md declares"
            }
        }
    }
}

# GFM splits a table row on every unescaped '|', INCLUDING one inside an inline
# code span. Query text in a table cell therefore has to write it as '\|', and
# forgetting that silently mangles the row into extra columns. Two rows of
# splunk-to-kql-mapping.md shipped broken this way, and escaping a leading pipe
# into a cell of splunkbase-app-catalog.md broke a third while fixing them.
function Test-MarkdownTables {
    param([string]$File, [string]$Text)

    $lines = $Text -split '\r?\n'
    $headerCells = -1
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i].Trim()
        if (-not ($line.StartsWith("|") -and $line.EndsWith("|"))) {
            $headerCells = -1
            continue
        }
        # Count cells the way GFM does: split on unescaped pipes.
        $cells = ([regex]::Split($line, '(?<!\\)\|')).Count - 2
        if ($headerCells -lt 0) {
            $headerCells = $cells
            continue
        }
        # The --- separator row under the header is not a data row.
        if ($line -match '^\|[ \t:|-]+\|$') {
            continue
        }
        if ($cells -ne $headerCells) {
            Add-Issue "$File has a malformed table row at line $($i + 1): $cells cells against a $headerCells-cell header (an unescaped | inside a cell splits it; write it as \|)"
        }
    }
}

# The layout trees in README.md and QUERY_SKILL_PLAN.md. CLAUDE.md requires
# updating both when a file is added, and nothing enforced it -- scripts/
# required-checks.txt was missing from both for a day after being added.
#
# Deliberately a BASENAME PRESENCE test rather than a parse of the ASCII art.
# Parsing it is fiddly enough that the first attempt at one reported README.md
# as absent from its own tree, and the failure this guards against is omission,
# which a presence test catches. A file listed under the wrong parent still
# passes; that is the accepted false negative in exchange for a check that
# cannot itself be subtly wrong.
$script:layoutTreeRegex = '(?ms)^```text\r?$\r?\n(siem_fun/.*?)^```'
$script:layoutTreeDocs = @("README.md", "QUERY_SKILL_PLAN.md")

function Test-LayoutTree {
    param([string]$File, [string]$Text, [string[]]$TrackedFiles)

    $m = [regex]::Match($Text, $script:layoutTreeRegex)
    if (-not $m.Success) {
        Add-Issue "$File has no siem_fun/ layout tree, so the file list cannot be checked"
        return
    }
    $tree = $m.Groups[1].Value
    foreach ($tracked in $TrackedFiles) {
        $name = Split-Path -Leaf $tracked
        if (-not $tree.Contains($name)) {
            Add-Issue "$File's layout tree does not mention '$name' ($tracked)"
        }
    }
}

# A helper's references: map tells the model which files exist for progressive
# disclosure, so a reference file missing from it is one the model never learns
# about. Nothing compared the map to the directory: the pair-parity check only
# proves the two helpers agree, and they were both equally wrong about
# sentinel-table-catalog.md for two days after it was added.
$script:helperReferenceRegex = '(?m)^[ \t]+\w+:[ \t]*"\.\./references/([^"]+)"'

function Test-HelperReferences {
    param([string]$Skill, [string]$HelperPath, [string]$HelperText, [string[]]$ReferenceFiles)

    $listed = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($m in [regex]::Matches($HelperText, $script:helperReferenceRegex)) {
        $null = $listed.Add($m.Groups[1].Value)
    }
    foreach ($reference in $ReferenceFiles) {
        if (-not $listed.Contains($reference)) {
            Add-Issue "$HelperPath does not list references/$reference, so the model is never pointed at it"
        }
    }
    foreach ($entry in $listed) {
        if ($ReferenceFiles -cnotcontains $entry) {
            Add-Issue "$HelperPath lists references/$entry, which does not exist"
        }
    }
}

# Fenced blocks split into their language tag and body.
function Get-FencedBlocks {
    param([string]$Text)

    $blocks = New-Object System.Collections.Generic.List[object]
    foreach ($m in [regex]::Matches($Text, $script:fencedWithLangRegex)) {
        $blocks.Add([pscustomobject]@{
            Language = $m.Groups['lang'].Value.Trim()
            Body     = $m.Groups['body'].Value
        })
    }
    # An empty array unrolls to nothing on return, so the caller would see $null.
    return , $blocks.ToArray()
}

# SPL correctness rules that can be decided from the text alone.
function Test-SplBlock {
    param([string]$File, [string]$Body)

    if ($Body -match $script:bareIndexOrRegex) {
        Add-Issue "$File chains three or more bare index= terms with OR; use 'index IN (...)'"
    }
    # Time bounding. Only raw-event searches are checked: a generating command
    # ('| tstats ...') is the documented discovery shape and is expected to run
    # unbounded. '| head' is accepted as an alternative bound, which is how the
    # schema-inspection snippets legitimately avoid earliest=.
    $lines = @(($Body -split '\r?\n') | Where-Object { $_.Trim().Length -gt 0 })
    if ($lines.Count -eq 0) {
        return
    }
    $first = $lines[0].Trim()
    if ($first.StartsWith("|")) {
        # Only GENERATING commands are exempt, not every pipeline-prefixed
        # query. Exempting any leading pipe let '| search index=firewall ...'
        # -- a raw-event search by any other name -- skip the check entirely.
        $cmd = [regex]::Match($first, '^\|[ \t]*([A-Za-z_]\w*)')
        if (-not ($cmd.Success -and $script:splNonGeneratingLeadCommands -contains $cmd.Groups[1].Value.ToLowerInvariant())) {
            return
        }
    }
    if ($Body -notmatch $script:splTimePredicateRegex -and
        $Body -notmatch '(?i)\|[ \t]*head\b') {
        Add-Issue "$File has a raw-event SPL search with no time bound; add earliest= (or bound it with | head)"
    }
}

# Returns the code snippets of a markdown document: the body of every fenced
# block (any language tag) plus every inline code span outside those blocks.
function Get-CodeSnippets {
    param([string]$Text)

    $snippets = New-Object System.Collections.Generic.List[string]
    foreach ($m in [regex]::Matches($Text, $script:fencedBlockRegex)) {
        $snippets.Add($m.Value)
    }
    # Replace fenced blocks with a newline before hunting inline spans, so the
    # fence markers themselves cannot pair up into a bogus span.
    $outsideFences = [regex]::Replace($Text, $script:fencedBlockRegex, "`n")
    foreach ($m in [regex]::Matches($outsideFences, $script:inlineCodeRegex)) {
        $snippets.Add($m.Groups[1].Value)
    }
    # An empty array unrolls to nothing on return, so the caller would see $null.
    return , $snippets.ToArray()
}

# A doc that lists a lookup's fields in one place and OUTPUTs a different field
# in an example is internally inconsistent, and the query is the half a reader
# copies. greynoise-integration.md shipped exactly that.
function Test-LookupOutputFields {
    param([string]$File, [string]$Text)

    $bt = [string][char]96
    $usages = [regex]::Matches($Text, $script:lookupUsageRegex)
    if ($usages.Count -eq 0) {
        return
    }
    # Split once, not once per usage.
    $lines = $Text -split '\r?\n'
    foreach ($m in $usages) {
        $name = $m.Groups['name'].Value
        $marker = "$bt$name$bt"

        # The documented field list is every backticked identifier on a line that
        # names this lookup in backticks. A query line names it unbackticked, so
        # a usage can never document itself.
        $documented = New-Object 'System.Collections.Generic.HashSet[string]'
        foreach ($line in $lines) {
            if (-not $line.Contains($marker)) {
                continue
            }
            foreach ($t in [regex]::Matches($line, $script:backtickTokenRegex)) {
                $null = $documented.Add($t.Groups[1].Value)
            }
        }
        # The lookup has no documented field list here, so there is nothing to
        # cross-check. Reporting would just be noise about an undocumented lookup.
        if ($documented.Count -eq 0) {
            continue
        }

        foreach ($raw in ($m.Groups['fields'].Value -split ',')) {
            $field = $raw.Trim()
            if ($field.Length -eq 0) {
                continue
            }
            if (-not $documented.Contains($field)) {
                Add-Issue "$File OUTPUTs '$field' from lookup '$name', which is not in that lookup's documented field list"
            }
        }
    }
}

if ($FunctionsOnly) {
    return
}

$requiredFiles = @(
    "README.md",
    "CLAUDE.md",
    "QUERY_SKILL_PLAN.md",
    ".claude/settings.json",
    ".env.example",
    "splunk-sentinel-query-builder/SKILL.md",
    "splunk-sentinel-query-builder/agents/openai.yaml",
    "splunk-sentinel-query-builder/agents/claude-opus.yaml",
    "splunk-sentinel-query-builder/agents/codex-gpt-5.4.yaml",
    "splunk-sentinel-query-builder/references/data-dictionary-integration.md",
    "splunk-sentinel-query-builder/references/examples-and-troubleshooting.md",
    "splunk-sentinel-query-builder/references/model-guidance.md",
    "splunk-sentinel-query-builder/references/query-workflow.md",
    "splunk-sentinel-query-builder/references/cim-vendor-alignment.md",
    "splunk-sentinel-query-builder/references/splunk-to-kql-mapping.md",
    "splunk-sentinel-query-builder/references/sentinel-table-catalog.md",
    "splunk-data-dictionary-builder/SKILL.md",
    "splunk-data-dictionary-builder/agents/openai.yaml",
    "splunk-data-dictionary-builder/agents/claude-opus.yaml",
    "splunk-data-dictionary-builder/agents/codex-gpt-5.4.yaml",
    "splunk-data-dictionary-builder/references/workflow.md",
    "splunk-data-dictionary-builder/scripts/build_splunk_dictionary.py",
    "splunk-data-dictionary-builder/tests/test_build_splunk_dictionary.py",
    "scripts/tests/validate-skill-pack.tests.ps1",
    "scripts/tests/mutation-check.py",
    "scripts/tests/test_grade_golden_output.py",
    "scripts/grade_golden_output.py",
    "scripts/run_golden_prompts.py",
    "scripts/required-checks.txt",
    "examples/golden-prompts.md",
    "splunk-enrichment-query-builder/SKILL.md",
    "splunk-enrichment-query-builder/agents/openai.yaml",
    "splunk-enrichment-query-builder/agents/claude-opus.yaml",
    "splunk-enrichment-query-builder/agents/codex-gpt-5.4.yaml",
    "splunk-enrichment-query-builder/references/splunkbase-app-catalog.md",
    "splunk-enrichment-query-builder/references/multi-index-patterns.md",
    "splunk-enrichment-query-builder/references/greynoise-integration.md",
    "splunk-enrichment-query-builder/references/splunk-cloud-index-management.md"
)

foreach ($file in $requiredFiles) {
    Assert-Exists $file
}

# The hard rule is "never commit secrets"; .env being gitignored is what makes
# that survivable in practice, and nothing verified the entry stayed there.
$gitignoreText = Read-Text ".gitignore"
if ($gitignoreText -notmatch '(?m)^\.env[ \t]*\r?$') {
    Add-Issue ".gitignore has no bare '.env' entry, so a real credentials file could be committed"
}

# quotepath=false emits non-ASCII filenames raw instead of C-quoted octal,
# which would fail Test-Path and silently skip those files from validation.
$trackedFiles = @(git -C $Root -c core.quotepath=false ls-files)
# Every whole-repo content check below iterates this list. If git fails or the
# list comes back empty, those checks would each no-op and the run would still
# print "validation passed" -- reporting a clean bill of health for a repo it
# never actually read. Fail loudly instead.
if ($LASTEXITCODE -ne 0 -or $trackedFiles.Count -eq 0) {
    Add-Issue "Could not enumerate tracked files (git ls-files exit $LASTEXITCODE, $($trackedFiles.Count) files); refusing to report success on an unread repository"
    # Print rather than bare-exit: issues already collected above (missing
    # required files, for one) are the more actionable report.
    Write-Host "Skill pack validation failed:" -ForegroundColor Red
    foreach ($issue in $issues) { Write-Host " - $issue" -ForegroundColor Red }
    exit 1
}

# Check inventory. A check can be deleted together with the mutation that
# covered it, which leaves the mutation suite self-consistent and the run green
# while the check is simply gone -- a merge resolution did exactly that to 81 of
# the 82 lines of the KQL provenance feature, and validation still passed.
# Cross-checked in BOTH directions, like $skills against the filesystem.
$manifestText = Read-Text $script:requiredChecksFile
if ($manifestText.Length -eq 0) {
    Add-Issue "$($script:requiredChecksFile) is missing or empty, so the validator's own check inventory cannot be verified"
} else {
    $declaredChecks = @(
        $manifestText -split '\r?\n' |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_.Length -gt 0 -and -not $_.StartsWith("#") }
    )
    # Read this script's own source. The extraction pattern cannot match itself:
    # 'Add-Issue' is followed by '[' here, not by the space its own [ \t]+ needs.
    $ownSource = Read-Text "scripts/validate-skill-pack.ps1"
    $ownMessages = @(
        [regex]::Matches($ownSource, 'Add-Issue[ \t]+"([^"]*)"') |
            ForEach-Object { $_.Groups[1].Value }
    )
    foreach ($declared in $declaredChecks) {
        if ($ownMessages -cnotcontains $declared) {
            Add-Issue "required-checks.txt lists a check the validator no longer performs: '$declared'"
        }
    }
    foreach ($message in $ownMessages) {
        if ($declaredChecks -cnotcontains $message) {
            Add-Issue "the validator performs a check that is not listed in required-checks.txt: '$message'"
        }
    }
}

# Populate the sourcetype registry before the content loop reads anything.
# A registry file that is missing or empty would make every sourcetype look
# invented, so say that plainly instead of emitting one issue per token.
foreach ($registryFile in $script:sourcetypeRegistryFiles) {
    $registryText = Read-Text $registryFile
    if ($registryText.Length -eq 0) {
        Add-Issue "$registryFile is missing or empty, so sourcetype provenance cannot be checked"
        continue
    }
    foreach ($m in [regex]::Matches($registryText, $script:sourcetypeTokenRegex)) {
        $null = $script:knownSourcetypes.Add($m.Value)
    }
    # Names of any shape, taken from the catalogue's Sourcetype column rather
    # than by shape.
    Add-CatalogueSourcetypeNames $registryText $script:knownSourcetypeNames
    foreach ($m in [regex]::Matches($registryText, $script:cimBulletNameRegex)) {
        $null = $script:knownSourcetypeNames.Add($m.Groups[1].Value)
    }
}

# Populate the Sentinel table registry. Only the FIRST column of a catalogue
# table row is read, so the column names and functions the catalogue also
# mentions in backticks cannot quietly widen the registry.
$kqlRegistryText = Read-Text $script:kqlRegistryFile
if ($kqlRegistryText.Length -eq 0) {
    Add-Issue "$($script:kqlRegistryFile) is missing or empty, so Sentinel table provenance cannot be checked"
} else {
    foreach ($m in [regex]::Matches($kqlRegistryText, '(?m)^\|[ \t]*`([A-Za-z_][A-Za-z0-9_]*)`[ \t]*\|')) {
        $null = $script:knownKqlTables.Add($m.Groups[1].Value)
    }
}

foreach ($layoutDoc in $script:layoutTreeDocs) {
    Test-LayoutTree $layoutDoc (Read-Text $layoutDoc) $trackedFiles
}

foreach ($file in $trackedFiles) {
    $path = Get-RepoFile $file
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        continue
    }
    # -LiteralPath, not -Path: a tracked filename containing [ or ] is a wildcard
    # to -Path and would abort the run under ErrorActionPreference=Stop.
    $bytes = [System.IO.File]::ReadAllBytes($path)
    $text = Get-Content -Raw -LiteralPath $path
    if ($null -eq $text) {
        $text = ""
    }
    # ASCII is checked against BYTES, not the decoded string: Get-Content sniffs
    # and strips a UTF-8 BOM and transparently decodes UTF-16, so a non-ASCII
    # file could pass a decoded-character check while violating the hard rule
    # on disk.
    # A foreach/break loop, not a Where-Object pipeline: piping every byte of
    # every tracked file costs roughly 10us/byte and dominated the whole run.
    foreach ($b in $bytes) {
        if ($b -ne 9 -and $b -ne 10 -and $b -ne 13 -and ($b -lt 32 -or $b -gt 126)) {
            Add-Issue "$file contains a non-ASCII or control byte 0x$($b.ToString('X2'))"
            break
        }
    }
    # Git conflict markers are exactly seven chars followed by a space+label
    # (<<<<<<< / >>>>>>>) or alone on the line (=======); the right-side anchor
    # avoids flagging setext heading underlines of eight or more equals signs.
    # '\r?$' is required: CI checks out CRLF, where a bare '$' sits after the
    # CR and the lone-marker branch could never match.
    if ($text -match $script:conflictMarkerRegex) {
        Add-Issue "$file contains a conflict marker"
    }
    # SPL 'where' uses eval semantics: an unquoted true/false is a field
    # reference, so the comparison silently matches nothing. Enforce the
    # quoting rule documented in greynoise-integration.md across all docs.
    if ($file -like "*.md") {
        # Cheap necessary condition first: every snippet is a substring of the
        # file, so if the unanchored pattern matches nowhere in the raw text it
        # cannot match a snippet either. Only then pay for snippet extraction,
        # which is what rules out prose naming the two halves in separate spans.
        if ($text -match $script:whereBooleanRegex) {
            $whereHit = $text -match $script:whereBooleanLineRegex
            if (-not $whereHit) {
                foreach ($snippet in (Get-CodeSnippets $text)) {
                    if ($snippet -match $script:whereBooleanRegex) {
                        $whereHit = $true
                        break
                    }
                }
            }
            if ($whereHit) {
                Add-Issue "$file compares against unquoted true/false in an SPL where clause; quote the value (=`"true`")"
            }
        }
        Test-LookupOutputFields $file $text
        Test-SourcetypeProvenance $file $text
        Test-SourcetypeValues $file $text
        Test-MarkdownTables $file $text
        foreach ($block in (Get-FencedBlocks $text)) {
            if ($block.Language -ceq "spl") {
                Test-SplBlock $file $block.Body
            } elseif ($block.Language -ceq "kql") {
                Test-KqlTableProvenance $file $block.Body
            }
        }
    }
    # Credential shapes are checked in EVERY tracked file, not just markdown:
    # a leaked key is as damaging in a yaml helper or a script as in a doc.
    foreach ($secret in $script:secretPatterns) {
        if ($text -match $secret.Pattern) {
            Add-Issue "$file appears to contain $($secret.Name); credentials must never be committed"
        }
    }
}

# Single source of truth for which skills exist. Every per-skill check below
# iterates this list, so adding a skill here cannot leave it silently skipping
# some checks while passing others.
$skills = @(
    "splunk-sentinel-query-builder",
    "splunk-data-dictionary-builder",
    "splunk-enrichment-query-builder"
)

# $skills is hand-maintained, so cross-check it against the filesystem in BOTH
# directions. A skill directory that exists on disk but is registered nowhere
# receives zero checks and passes green -- the failure this guard exists to
# prevent. A registered skill with no SKILL.md means the list has gone stale.
# A directory is a skill if and only if it holds a SKILL.md.
$onDisk = @(
    Get-ChildItem -LiteralPath $Root -Directory |
        Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName "SKILL.md") -PathType Leaf } |
        ForEach-Object { $_.Name }
)
foreach ($dir in $onDisk) {
    if ($skills -cnotcontains $dir) {
        Add-Issue "$dir has a SKILL.md but is not registered in the validator's `$skills list, so none of the per-skill checks run against it"
    }
}
foreach ($registered in $skills) {
    if ($onDisk -cnotcontains $registered) {
        Add-Issue "`$skills lists '$registered', which has no SKILL.md on disk"
    }
}

# Required-file coverage: a registered skill whose files were never added to
# $requiredFiles can have them deleted without the run noticing.
foreach ($skill in $skills) {
    if (-not ($requiredFiles | Where-Object { $_ -clike "$skill/*" })) {
        Add-Issue "$skill has no entries in `$requiredFiles, so its files can be deleted without failing validation"
    }
}

# Each helper's references: map against the skill's actual reference directory.
foreach ($skill in $skills) {
    $referenceDir = Get-RepoFile "$skill/references"
    if (-not (Test-Path -LiteralPath $referenceDir -PathType Container)) {
        continue
    }
    $referenceFiles = @(
        Get-ChildItem -LiteralPath $referenceDir -Filter "*.md" -File | ForEach-Object { $_.Name }
    )
    foreach ($helper in @("claude-opus.yaml", "codex-gpt-5.4.yaml")) {
        $helperPath = "$skill/agents/$helper"
        if (Test-RepoFile $helperPath) {
            Test-HelperReferences $skill $helperPath (Read-Text $helperPath) $referenceFiles
        }
    }
}

# Golden-prompt fixtures are checked against the union of sections declared by
# all skills rather than per skill: a fixture does not record which skill it
# exercises, and inferring that from its prose would be guesswork. The union
# still catches a fixture asserting a section that exists nowhere in the pack.
$declaredSections = New-Object 'System.Collections.Generic.HashSet[string]'
foreach ($skill in $skills) {
    foreach ($m in [regex]::Matches((Read-Text "$skill/SKILL.md"), $script:skillSectionRegex)) {
        $null = $declaredSections.Add($m.Groups[1].Value.Trim())
    }
}
# A run that found no sections at all would pass this check vacuously, which
# is how the first version of it behaved: it sat above the $skills definition,
# iterated nothing, and reported every fixture section as undeclared.
if ($declaredSections.Count -eq 0) {
    Add-Issue "No output sections could be read from any SKILL.md, so golden-prompt shapes cannot be checked"
} else {
    Test-FixtureShapeSections (Read-Text "examples/golden-prompts.md") @($declaredSections)
}

foreach ($skill in $skills) {
    $skillFile = "$skill/SKILL.md"
    # A missing file is already reported by Assert-Exists; content checks on it
    # would only add misdirecting issues.
    if (-not (Test-RepoFile $skillFile)) {
        continue
    }
    Assert-Contains $skillFile '(?s)^---\s+name:\s+[-a-z0-9]+\s+description:\s+.+?\s+---' "valid skill frontmatter"
    # The frontmatter check above validates only the SHAPE of the name. Skills
    # are loaded by that name, so one that does not match its directory is a
    # live routing break, and it passed validation until this check existed.
    $nameMatch = [regex]::Match((Read-Text $skillFile), '(?m)^name:[ \t]+(?<n>[^\r\n]+?)[ \t]*\r?$')
    if ($nameMatch.Success -and $nameMatch.Groups['n'].Value -cne $skill) {
        Add-Issue "$skillFile declares name '$($nameMatch.Groups['n'].Value)', which does not match its directory '$skill'"
    }
    Assert-Contains $skillFile '## Important' "top-level Important section"
    Assert-Contains $skillFile '## Inputs' "Inputs section"
    # A description that says only when to USE a skill leaves the router to
    # guess between overlapping skills. splunk-sentinel-query-builder's
    # negatives did not exclude multi-index Splunk work, which is
    # splunk-enrichment-query-builder's positive trigger, so a request naming
    # two indexes matched both. Whether two descriptions genuinely overlap needs
    # a reader; that every skill states its exclusions does not.
    Assert-Contains $skillFile '(?m)^description:[^\r\n]*\bDo not use\b' "a 'Do not use' clause in its description"
    # CLAUDE.md's "adding a new skill" checklist ends with "add fixtures to
    # golden-prompts.md", which nothing enforced.
    if (-not (Read-Text "examples/golden-prompts.md").Contains($skill)) {
        Add-Issue "$skill has no fixture in examples/golden-prompts.md"
    }
}

foreach ($skill in $skills) {
    $openaiPath = "$skill/agents/openai.yaml"
    if (-not (Test-RepoFile $openaiPath)) {
        continue
    }
    $openaiDoc = Get-YamlDocument $openaiPath
    $interface = Get-MapValue $openaiDoc "interface"
    if ($null -eq $interface) {
        Add-Issue "$openaiPath is missing the interface section"
    } else {
        foreach ($key in @("display_name", "short_description", "default_prompt")) {
            if ([string]::IsNullOrWhiteSpace([string](Get-MapValue $interface $key))) {
                Add-Issue "$openaiPath is missing interface.$key"
            }
        }
    }
    $policy = Get-MapValue $openaiDoc "policy"
    if ($null -eq $policy) {
        Add-Issue "$openaiPath is missing the policy section"
    } elseif ("$(Get-MapValue $policy 'allow_implicit_invocation')".ToLowerInvariant() -ne "false") {
        Add-Issue "$openaiPath must set policy.allow_implicit_invocation to false"
    }
}

# Helper pair parity: both companion files in a skill must carry the same
# section lists. Query-builder skills use the full structured contract and
# require the model-specific tuning sections; the data-dictionary builder
# uses a simpler helper shape.
$sectionParents = @{
    prompt_shape          = "invocation"
    default_sections      = "response_contract"
    short_sections        = "response_contract"
    optimization_sections = "response_contract"
    discovery_sections    = "response_contract"
    token_rules           = "behavior"
    truth_order           = "behavior"
    stop_conditions       = "behavior"
}
$helperChecks = @(
    @{ Skill = "splunk-sentinel-query-builder";   Sections = @("prompt_shape", "default_sections", "short_sections", "optimization_sections", "discovery_sections", "token_rules", "truth_order", "stop_conditions"); RequireTuningSections = $true },
    @{ Skill = "splunk-enrichment-query-builder"; Sections = @("prompt_shape", "default_sections", "short_sections", "discovery_sections", "token_rules", "truth_order", "stop_conditions"); RequireTuningSections = $true },
    @{ Skill = "splunk-data-dictionary-builder";  Sections = @("token_rules", "stop_conditions"); RequireTuningSections = $false }
)
# The table above is the one per-skill registry that cannot be derived from
# $skills, since each skill declares its own section set. Guard both directions
# so a skill cannot be added to one and forgotten in the other.
$configuredSkills = @($helperChecks | ForEach-Object { $_.Skill })
foreach ($skill in $skills) {
    if ($configuredSkills -notcontains $skill) {
        Add-Issue "$skill has no helperChecks entry, so its helper parity would go unchecked"
    }
}
foreach ($configured in $configuredSkills) {
    if ($skills -notcontains $configured) {
        Add-Issue "helperChecks references '$configured', which is not in the skills list"
    }
}

foreach ($check in $helperChecks) {
    $claudePath = "$($check.Skill)/agents/claude-opus.yaml"
    $codexPath = "$($check.Skill)/agents/codex-gpt-5.4.yaml"
    if (-not (Test-RepoFile $claudePath) -or -not (Test-RepoFile $codexPath)) {
        continue
    }
    $claudeDoc = Get-YamlDocument $claudePath
    $codexDoc = Get-YamlDocument $codexPath
    foreach ($section in $check.Sections) {
        $parent = $sectionParents[$section]
        Assert-ListsEqual "$claudePath / $section" (Get-YamlList $claudeDoc $parent $section) (Get-YamlList $codexDoc $parent $section)
    }
    if ($check.RequireTuningSections) {
        # claude-opus helpers must carry trigger_tuning; codex helpers must carry packaging_rules.
        if ($null -eq (Get-MapValue (Get-MapValue $claudeDoc "behavior") "trigger_tuning")) {
            Add-Issue "$claudePath is missing behavior.trigger_tuning"
        }
        if ($null -eq (Get-MapValue (Get-MapValue $codexDoc "behavior") "packaging_rules")) {
            Add-Issue "$codexPath is missing behavior.packaging_rules"
        }
    }
}

# The canonical invocation prompt is duplicated across openai.yaml and both
# companion helpers; it has drifted before, so enforce three-way equality.
foreach ($skill in $skills) {
    $prompts = @{}
    foreach ($entry in @(
        @{ Path = "$skill/agents/openai.yaml"; Section = "interface"; Key = "default_prompt" },
        @{ Path = "$skill/agents/claude-opus.yaml"; Section = "invocation"; Key = "preferred_prompt" },
        @{ Path = "$skill/agents/codex-gpt-5.4.yaml"; Section = "invocation"; Key = "preferred_prompt" }
    )) {
        if (-not (Test-RepoFile $entry.Path)) {
            continue
        }
        $value = Get-MapValue (Get-MapValue (Get-YamlDocument $entry.Path) $entry.Section) $entry.Key
        if ([string]::IsNullOrWhiteSpace([string]$value)) {
            Add-Issue "$($entry.Path) is missing $($entry.Section).$($entry.Key)"
        } else {
            $prompts[$entry.Path] = [string]$value
        }
    }
    if (($prompts.Values | Select-Object -Unique).Count -gt 1) {
        Add-Issue "Invocation prompt drift in ${skill}: openai default_prompt and helper preferred_prompt values differ"
    }
}

$dictionaryScript = Read-Text "splunk-data-dictionary-builder/scripts/build_splunk_dictionary.py"
$cimReference = Read-Text "splunk-sentinel-query-builder/references/cim-vendor-alignment.md"
$hintsBlock = [regex]::Match($dictionaryScript, '(?ms)^CIM_SOURCETYPE_HINTS[^=]*=\s*\{(.*?)^\}')
if (-not $hintsBlock.Success) {
    Add-Issue "build_splunk_dictionary.py is missing the CIM_SOURCETYPE_HINTS dictionary"
} else {
    foreach ($match in [regex]::Matches($hintsBlock.Groups[1].Value, '(?m)^\s+"([^"]+)":')) {
        $sourcetype = $match.Groups[1].Value
        if ($cimReference -cnotmatch [regex]::Escape($sourcetype)) {
            Add-Issue "CIM hint sourcetype '$sourcetype' is not documented in cim-vendor-alignment.md"
        }
    }
}

$markdownFiles = $trackedFiles | Where-Object { $_ -like "*.md" }
$linkRegex = '\[[^\]]+\]\(([^)]+)\)'
foreach ($file in $markdownFiles) {
    $text = Read-Text $file
    # Fenced code blocks quote example markdown; links inside them are
    # illustrations, not navigation, so strip the blocks before scanning.
    # '[ \t]*' (not '\s*') keeps the opening fence anchored to its own line, and
    # '\r?$' is required because CI checks out CRLF: with a bare '$' the closing
    # fence never matched there, so this strip was a no-op on the only OS that
    # runs the validator.
    $scanText = [regex]::Replace($text, $script:fencedBlockRegex, '')
    $baseDir = Split-Path -Parent (Get-RepoFile $file)
    foreach ($match in [regex]::Matches($scanText, $linkRegex)) {
        $target = $match.Groups[1].Value.Trim()
        # Normalize the CommonMark forms: <bracketed destination> and an
        # optional quoted title after the destination.
        $target = $target -replace '^\<(.*)\>$', '$1'
        $target = ($target -replace '\s+"[^"]*"\s*$', '').Trim()
        if ($target -match '^(https?://|mailto:|#)') {
            continue
        }
        $targetPath = ($target -split '#')[0]
        if ([string]::IsNullOrWhiteSpace($targetPath)) {
            continue
        }
        $targetPath = [uri]::UnescapeDataString($targetPath)
        $resolved = Join-Path $baseDir $targetPath
        if (-not (Test-Path -LiteralPath $resolved)) {
            Add-Issue "$file has broken local link: $target"
        }
    }
}

if ($issues.Count -gt 0) {
    Write-Host "Skill pack validation failed:" -ForegroundColor Red
    foreach ($issue in $issues) {
        Write-Host " - $issue" -ForegroundColor Red
    }
    exit 1
}

Write-Host "Skill pack validation passed." -ForegroundColor Green
