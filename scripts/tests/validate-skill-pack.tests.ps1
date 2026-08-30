#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Unit tests for the helper functions in validate-skill-pack.ps1.

.DESCRIPTION
    Run from the repository root:

        pwsh -NoProfile -File ./scripts/tests/validate-skill-pack.tests.ps1

    Tests marked REGRESSION pin behavior that a shipped defect got wrong. The
    named bug is the reason the assertion exists; do not relax one without
    understanding what it protects.

    No test framework is used. Pester is not bundled with PowerShell and would
    have to be installed to run these, which would mean authoring tests that
    cannot be executed everywhere the validator runs. The handful of assertions
    below are cheaper than that dependency.
#>

$ErrorActionPreference = "Stop"

$script:passed = 0
$script:failed = 0

function Test-Case {
    param(
        [string]$Name,
        [scriptblock]$Body
    )
    Reset-ValidatorState
    try {
        & $Body
        $script:passed++
        Write-Host "  PASS  $Name" -ForegroundColor Green
    } catch {
        $script:failed++
        Write-Host "  FAIL  $Name" -ForegroundColor Red
        Write-Host "        $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Fail {
    param([string]$Message)
    throw $Message
}

function Assert-Equal {
    param($Expected, $Actual, [string]$Because = "")
    $e = if ($null -eq $Expected) { "<null>" } else { ($Expected -join ", ") }
    $a = if ($null -eq $Actual) { "<null>" } else { ($Actual -join ", ") }
    if ($e -cne $a) {
        Fail "expected [$e] but got [$a]. $Because"
    }
}

function Assert-Null {
    param($Value, [string]$Because = "")
    if ($null -ne $Value) {
        Fail "expected <null> but got [$($Value -join ', ')]. $Because"
    }
}

function Assert-NotNull {
    param($Value, [string]$Because = "")
    if ($null -eq $Value) {
        Fail "expected a value but got <null>. $Because"
    }
}

function Assert-True {
    param([bool]$Condition, [string]$Because = "")
    if (-not $Condition) {
        Fail "expected condition to be true. $Because"
    }
}

function Assert-NoIssues {
    if ($issues.Count -ne 0) {
        Fail "expected no issues but got: $($issues -join ' | ')"
    }
}

function Assert-IssueMatching {
    param([string]$Pattern)
    $hit = $issues | Where-Object { $_ -match $Pattern }
    if (-not $hit) {
        Fail "expected an issue matching '$Pattern' but got: $($issues -join ' | ')"
    }
}

function Assert-IssueCount {
    param([int]$Expected)
    if ($issues.Count -ne $Expected) {
        Fail "expected $Expected issue(s) but got $($issues.Count): $($issues -join ' | ')"
    }
}

function Reset-ValidatorState {
    # Caches and the issue list are script-scoped in the validator; a dot-source
    # puts them in this scope, so tests can clear them between cases.
    if ($null -ne $issues) { $issues.Clear() }
    if ($null -ne $script:textCache) { $script:textCache.Clear() }
    if ($null -ne $script:yamlCache) { $script:yamlCache.Clear() }
}

# --- load the validator's functions and point them at a fixture directory ---

$fence = [string][char]96 + [char]96 + [char]96

$fixtureRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("skillpack-tests-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $fixtureRoot -Force | Out-Null

try {
    . (Join-Path $PSScriptRoot "..\validate-skill-pack.ps1") -Root $fixtureRoot -FunctionsOnly

    Write-Host "Get-MapValue" -ForegroundColor Cyan

    Test-Case "returns the value for an existing key" {
        $map = @{ a = "one" }
        Assert-Equal "one" (Get-MapValue $map "a")
    }

    Test-Case "returns null for a missing key" {
        Assert-Null (Get-MapValue @{ a = "one" } "b")
    }

    Test-Case "returns null for a null map" {
        Assert-Null (Get-MapValue $null "a")
    }

    Test-Case "returns null for a non-dictionary value" {
        # Guards against indexing into a scalar or list when the YAML shape is
        # not what the caller assumed.
        Assert-Null (Get-MapValue "just a string" "a")
        Assert-Null (Get-MapValue @("x", "y") "a")
    }

    Test-Case "works with OrderedDictionary as well as Hashtable" {
        # ConvertFrom-Yaml returns different mapping types by module version;
        # Get-MapValue goes through IDictionary so both must work.
        $ordered = [ordered]@{ a = "one" }
        Assert-Equal "one" (Get-MapValue $ordered "a")
        Assert-True ($ordered -is [System.Collections.IDictionary]) "OrderedDictionary should be IDictionary"
    }

    Write-Host "Get-YamlList" -ForegroundColor Cyan

    $doc = @{
        behavior = @{
            token_rules = @("first", "second")
            empty_rules = @()
            scalar_rule = "lonely"
        }
    }

    Test-Case "returns the items of a declared list" {
        Assert-Equal @("first", "second") (Get-YamlList $doc "behavior" "token_rules")
    }

    Test-Case "preserves item order" {
        $result = Get-YamlList $doc "behavior" "token_rules"
        Assert-Equal "first" $result[0]
        Assert-Equal "second" $result[1]
    }

    Test-Case "returns null when the section is absent" {
        Assert-Null (Get-YamlList $doc "no_such_section" "token_rules")
    }

    Test-Case "returns null when the key is absent" {
        Assert-Null (Get-YamlList $doc "behavior" "no_such_key")
    }

    Test-Case "distinguishes a declared-empty list from an absent one" {
        # REGRESSION: the previous version returned an empty array for both,
        # so Assert-ListsEqual could not tell "declared empty" from "missing"
        # and a missing section passed vacuously.
        $empty = Get-YamlList $doc "behavior" "empty_rules"
        Assert-NotNull $empty "an empty but declared list must not be null"
        Assert-Equal 0 $empty.Count
        Assert-Null (Get-YamlList $doc "behavior" "absent_rules")
    }

    Test-Case "coerces a scalar to a single-item list" {
        Assert-Equal @("lonely") (Get-YamlList $doc "behavior" "scalar_rule")
    }

    Write-Host "Assert-ListsEqual" -ForegroundColor Cyan

    Test-Case "identical lists raise no issue" {
        Assert-ListsEqual "x" @("a", "b") @("a", "b")
        Assert-NoIssues
    }

    Test-Case "differing content is reported as drift" {
        Assert-ListsEqual "x" @("a", "b") @("a", "c")
        Assert-IssueMatching "drift detected"
    }

    Test-Case "differing order is reported as drift" {
        Assert-ListsEqual "x" @("a", "b") @("b", "a")
        Assert-IssueMatching "drift detected"
    }

    Test-Case "a case-only difference is reported as drift" {
        # REGRESSION: -ne is case-insensitive in PowerShell, so real case drift
        # between the two helper files passed silently until -cne was used.
        Assert-ListsEqual "x" @("Objective") @("objective")
        Assert-IssueMatching "drift detected"
    }

    Test-Case "absent on both sides is reported, not passed over" {
        # REGRESSION: comparing two empty results passed vacuously, so a section
        # missing from both helpers looked identical to a section that matched.
        Assert-ListsEqual "x" $null $null
        Assert-IssueMatching "declared in neither"
    }

    Test-Case "absent on one side is reported distinctly" {
        Assert-ListsEqual "x" @("a") $null
        Assert-IssueMatching "declared in only one"
        Reset-ValidatorState
        Assert-ListsEqual "x" $null @("a")
        Assert-IssueMatching "declared in only one"
    }

    Test-Case "declared-empty on both sides matches" {
        Assert-ListsEqual "x" @() @()
        Assert-NoIssues
    }

    Test-Case "declared-empty against a populated list is drift" {
        Assert-ListsEqual "x" @() @("a")
        Assert-IssueMatching "drift detected"
    }

    Write-Host "Read-Text and Test-RepoFile" -ForegroundColor Cyan

    Set-Content -LiteralPath (Join-Path $fixtureRoot "present.md") -Value "hello" -NoNewline
    Set-Content -LiteralPath (Join-Path $fixtureRoot "empty.md") -Value "" -NoNewline
    New-Item -ItemType Directory -Path (Join-Path $fixtureRoot "adir") -Force | Out-Null

    Test-Case "reads an existing file" {
        Assert-Equal "hello" (Read-Text "present.md")
    }

    Test-Case "returns empty string for a missing file instead of throwing" {
        # REGRESSION: Get-Content under ErrorActionPreference=Stop threw, which
        # killed the run mid-way and suppressed every issue collected so far.
        Assert-Equal "" (Read-Text "definitely-not-here.md")
    }

    Test-Case "returns empty string for an empty file" {
        # REGRESSION: Get-Content -Raw returns $null for a zero-byte file, and
        # calling .ToCharArray() on it threw.
        Assert-Equal "" (Read-Text "empty.md")
    }

    Test-Case "caches file contents" {
        $probe = Join-Path $fixtureRoot "vanishing.md"
        Set-Content -LiteralPath $probe -Value "original" -NoNewline
        Assert-Equal "original" (Read-Text "vanishing.md")
        Set-Content -LiteralPath $probe -Value "changed" -NoNewline
        Assert-Equal "original" (Read-Text "vanishing.md") "second read should come from the cache"
        Remove-Item -LiteralPath $probe -Force
    }

    Test-Case "Read-Text handles a filename containing wildcard characters" {
        # REGRESSION: Get-Content -Path treats [ ] as a wildcard, so a tracked file
        # named like this aborted the whole run under ErrorActionPreference=Stop
        # instead of being read.
        Set-Content -LiteralPath (Join-Path $fixtureRoot "weird[1].md") -Value "bracket content" -NoNewline
        Assert-Equal "bracket content" (Read-Text "weird[1].md")
    }

    Test-Case "Test-RepoFile distinguishes files, directories and absences" {
        Assert-True (Test-RepoFile "present.md") "an existing file should be true"
        Assert-True (-not (Test-RepoFile "definitely-not-here.md")) "a missing path should be false"
        Assert-True (-not (Test-RepoFile "adir")) "a directory should be false, not a leaf"
    }

    Write-Host "Get-YamlDocument" -ForegroundColor Cyan

    Test-Case "parses a valid helper document" {
        Set-Content -LiteralPath (Join-Path $fixtureRoot "good.yaml") -Value "behavior:`n  token_rules:`n    - `"a`"`n"
        $parsed = Get-YamlDocument "good.yaml"
        Assert-NotNull $parsed
        Assert-Equal @("a") (Get-YamlList $parsed "behavior" "token_rules")
        Assert-NoIssues
    }

    Test-Case "reports invalid YAML as an issue rather than failing silently" {
        # REGRESSION: unparseable YAML previously yielded empty results, which
        # surfaced as confusing drift instead of naming the real problem.
        Set-Content -LiteralPath (Join-Path $fixtureRoot "bad.yaml") -Value "behavior:`n  - [unclosed`n   nope: {`n"
        $parsed = Get-YamlDocument "bad.yaml"
        Assert-Null $parsed
        Assert-IssueMatching "not valid YAML"
    }

    Test-Case "a missing file yields no document and no duplicate issue" {
        # Assert-Exists already reports missing required files; reporting again
        # here would bury the root cause under derived noise.
        Assert-Null (Get-YamlDocument "absent.yaml")
        Assert-IssueCount 0
    }

    Test-Case "an empty flow list in YAML is declared, not absent" {
        # REGRESSION: PowerShell unrolls an empty array on return, so a
        # declared-but-empty list came back as $null and Assert-ListsEqual
        # reported it as "declared in neither file". Presence is now decided
        # with Contains. Exercised through the real parser, not a hand-built
        # hashtable, because the parser's empty-collection type differs.
        Set-Content -LiteralPath (Join-Path $fixtureRoot "emptylist.yaml") -Value "behavior:`n  token_rules: []`n  other_rules:`n"
        $parsed = Get-YamlDocument "emptylist.yaml"
        $flow = Get-YamlList $parsed "behavior" "token_rules"
        Assert-NotNull $flow "'token_rules: []' is declared and must not read as absent"
        Assert-Equal 0 $flow.Count
        $valueless = Get-YamlList $parsed "behavior" "other_rules"
        Assert-NotNull $valueless "'other_rules:' with no value is declared and must not read as absent"
        Assert-Equal 0 $valueless.Count
        Assert-Null (Get-YamlList $parsed "behavior" "never_declared")
    }

    Test-Case "two helpers both declaring an empty list agree" {
        # The pairing of the above: both sides declared-empty must compare as
        # equal rather than tripping the "declared in neither" guard.
        Assert-ListsEqual "x" (Get-YamlList @{ b = @{ k = @() } } "b" "k") (Get-YamlList @{ b = @{ k = @() } } "b" "k")
        Assert-NoIssues
    }

    Test-Case "tolerates YAML shapes the old regex parser rejected" {
        # REGRESSION: the hand-rolled parser broke on inline comments, single
        # quotes, and a missing trailing newline, reporting phantom drift.
        $yaml = "behavior:  # a comment`n  token_rules:  # another`n    - 'a'`n    - `"b`""
        Set-Content -LiteralPath (Join-Path $fixtureRoot "shapes.yaml") -Value $yaml -NoNewline
        Assert-Equal @("a", "b") (Get-YamlList (Get-YamlDocument "shapes.yaml") "behavior" "token_rules")
        Assert-NoIssues
    }

    Write-Host "Line-ending-sensitive patterns (CI checks out CRLF)" -ForegroundColor Cyan

    Test-Case "conflict-marker regex catches a lone marker on both LF and CRLF" {
        # REGRESSION: the lone-marker branch was '={7}$'. In .NET multiline mode
        # '$' matches before the LF, i.e. AFTER the CR, so on a CRLF checkout the
        # branch could never match -- and CI is the only place this runs.
        Assert-True (("a`n=======`nb" -match $script:conflictMarkerRegex)) "LF lone marker must match"
        Assert-True (("a`r`n=======`r`nb" -match $script:conflictMarkerRegex)) "CRLF lone marker must match"
        Assert-True (("a`r`n<<<<<<< HEAD`r`nb" -match $script:conflictMarkerRegex)) "CRLF labelled marker must match"
    }

    Test-Case "conflict-marker regex ignores a setext heading underline" {
        Assert-True (-not ("Heading`r`n========`r`n" -match $script:conflictMarkerRegex)) "8 equals signs is a heading, not a marker"
        Assert-True (-not ("Heading`n========`n" -match $script:conflictMarkerRegex)) "same on LF"
    }

    Test-Case "fenced-block strip removes the block on both LF and CRLF" {
        # REGRESSION: the closing-fence anchor was '[ \t]*$', which cannot match
        # before a CR. The strip was a complete no-op on CRLF, so the documented
        # guarantee that fenced links are ignored was false on the CI runner.
        $lf   = "intro`n" + $fence + "`n[x](nope.md)`n" + $fence + "`n"
        $crlf = $lf -replace "`n", "`r`n"
        Assert-True (-not ([regex]::Replace($lf,   $script:fencedBlockRegex, "") -match "nope.md")) "LF block must be stripped"
        Assert-True (-not ([regex]::Replace($crlf, $script:fencedBlockRegex, "") -match "nope.md")) "CRLF block must be stripped"
    }

    Test-Case "fenced-block strip leaves prose links alone" {
        $crlf = "see [real](target.md) here`r`n"
        Assert-True ([regex]::Replace($crlf, $script:fencedBlockRegex, "") -match "target.md") "a link outside any fence must survive"
    }

    Test-Case "where-boolean regex flags unquoted booleans on CRLF too" {
        Assert-True (("| where noise=true`r`n" -match $script:whereBooleanLineRegex)) "CRLF unquoted boolean must be caught"
        Assert-True (("| where noise=true`n"   -match $script:whereBooleanLineRegex)) "LF unquoted boolean must be caught"
        Assert-True (-not ('| where noise="true"' -match $script:whereBooleanLineRegex)) "quoted form must pass"
    }

    Test-Case "where-boolean regex catches mid-line and uppercase forms" {
        # REGRESSION: the original pattern anchored on '^\s*\| where' and compared
        # with -cmatch, so a single-line 'index=x | where noise=true' and an
        # uppercase 'riot=TRUE' both evaded it. Both have the identical
        # silent-no-match bug in SPL.
        Assert-True ('index=x | where noise=true' -match $script:whereBooleanRegex) "mid-line form must be caught"
        Assert-True ('| where riot=TRUE' -match $script:whereBooleanRegex) "uppercase value must be caught"
        Assert-True (-not ('index=x | where noise=true' -match $script:whereBooleanLineRegex)) "the line-anchored pattern is what missed it"
        Assert-True (-not ('| where a=1 | eval b=true' -match $script:whereBooleanRegex)) "a later command's boolean is not a where comparison"
    }

    Write-Host "Get-CodeSnippets and lookup OUTPUT fields" -ForegroundColor Cyan

    Test-Case "code snippets cover fenced bodies and inline spans" {
        $bt = [string][char]96
        $fence = $bt * 3
        $doc = $fence + "spl`nindex=a`n" + $fence + "`n`nprose " + $bt + "inline=1" + $bt + " tail`n"
        $snips = Get-CodeSnippets $doc
        Assert-True (($snips -join "|") -match "index=a") "fenced body must be captured"
        Assert-True (($snips -join "|") -match "inline=1") "inline span must be captured"
    }

    Test-Case "two code spans on one prose line do not combine into a match" {
        # REGRESSION: dropping the line anchor to catch table cells would flag
        # CLAUDE.md's own statement of the rule, where '| where' and 'noise=true'
        # sit in two separate spans. Scanning per snippet is what makes it safe.
        $bt = [string][char]96
        $doc = 'In ' + $bt + '| where' + $bt + ', quote booleans: ' + $bt +
               'noise="true"' + $bt + ', not ' + $bt + 'noise=true' + $bt + '.'
        $hit = $false
        foreach ($s in (Get-CodeSnippets $doc)) {
            if ($s -match $script:whereBooleanRegex) { $hit = $true }
        }
        Assert-True (-not $hit) "separate code spans must not combine into a match"
    }

    Test-Case "an OUTPUT field missing from the documented list is reported" {
        $bt = [string][char]96
        $fence = $bt * 3
        $doc = '| ' + $bt + 'mylookup' + $bt + ' | fields ' + $bt + 'a' + $bt + ', ' + $bt + 'b' + $bt +
               " |`n`n" + $fence + "spl`n| lookup mylookup key OUTPUT a, zzz`n" + $fence + "`n"
        Test-LookupOutputFields "doc.md" $doc
        Assert-IssueMatching "documented field list"
    }

    Test-Case "OUTPUT fields that are all documented raise no issue" {
        $bt = [string][char]96
        $fence = $bt * 3
        $doc = '| ' + $bt + 'mylookup' + $bt + ' | fields ' + $bt + 'a' + $bt + ', ' + $bt + 'b' + $bt +
               " |`n`n" + $fence + "spl`n| lookup mylookup key OUTPUT a, b`n" + $fence + "`n"
        Test-LookupOutputFields "doc.md" $doc
        Assert-NoIssues
    }

    Test-Case "fenced blocks are split into language tag and body" {
        $bt = [string][char]96
        $fence = $bt * 3
        $doc = $fence + "spl`nindex=a`n" + $fence + "`n`n" + $fence + "kql`nTable`n" + $fence + "`n"
        $blocks = Get-FencedBlocks $doc
        Assert-Equal @("spl", "kql") @($blocks | ForEach-Object { $_.Language })
        Assert-True ($blocks[0].Body -match "index=a") "spl body must be captured"
    }

    Test-Case "three or more bare index= terms chained with OR is reported" {
        Test-SplBlock "d.md" "index=a OR index=b OR index=c earliest=-24h"
        Assert-IssueMatching "bare index= terms with OR"
    }

    Test-Case "an index/sourcetype-paired OR chain is not reported" {
        # REGRESSION: multi-index-patterns.md documents this as the CORRECT
        # pattern when schemas differ per index, and 'index IN (...)' cannot
        # express it. A blanket OR-chain check flagged the repo's own guidance.
        Test-SplBlock "d.md" "((index=firewall sourcetype=cisco:asa) OR (index=proxy sourcetype=bluecoat:x)) earliest=-24h"
        Assert-NoIssues
    }

    Test-Case "a raw-event search with no time bound is reported" {
        Test-SplBlock "d.md" "index=firewall sourcetype=cisco:asa`n| stats count by src"
        Assert-IssueMatching "no time bound"
    }

    Test-Case "mentioning _time is not a time bound" {
        # REGRESSION: the exemption tested for the substring '_time', so an
        # aggregation over it exempted a search that scans all history.
        Test-SplBlock "d.md" "index=firewall`n| stats latest(_time)"
        Assert-IssueMatching "no time bound"
        Reset-ValidatorState
        Test-SplBlock "d.md" "index=firewall`n| where _time > relative_time(now(), `"-1d`")"
        Assert-NoIssues
    }

    Test-Case "a leading pipe alone does not exempt a raw-event search" {
        # REGRESSION: every pipeline-prefixed block was exempt, so '| search ...'
        # -- a raw-event search in generating-command clothing -- skipped the
        # check. Custom generating commands from apps must stay exempt, which is
        # why this is a denylist rather than a whitelist of known commands.
        Test-SplBlock "d.md" "| search index=firewall sourcetype=cisco:asa`n| stats count"
        Assert-IssueMatching "no time bound"
        Reset-ValidatorState
        Test-SplBlock "d.md" "| gncontext ip=`"203.0.113.42`""
        Assert-NoIssues
    }

    Test-Case "generating commands and head-bounded searches need no earliest" {
        # '| tstats ...' is the documented discovery shape and runs unbounded;
        # '| head' is the bound the schema-inspection snippets actually use.
        Test-SplBlock "d.md" "| tstats count where index IN (a, b) by index, sourcetype"
        Assert-NoIssues
        Reset-ValidatorState
        Test-SplBlock "d.md" "sourcetype=YOUR_SOURCETYPE | head 5 | table tag, eventtype"
        Assert-NoIssues
    }

    Test-Case "the leading identifier of a KQL block is a table reference" {
        Assert-Equal @("SigninLogs") (Get-KqlTableReferences "SigninLogs`n| where ResultType == 0")
    }

    Test-Case "KQL operators in leading position are not table references" {
        Assert-Equal @() (Get-KqlTableReferences "let x = 1;")
        Assert-Equal @() (Get-KqlTableReferences "search *`n| distinct `$table")
    }

    Test-Case "a leading comment does not hide the table reference" {
        Assert-Equal @("Heartbeat") (Get-KqlTableReferences "// find stale agents`nHeartbeat`n| summarize max(TimeGenerated)")
    }

    Test-Case "union and join operands are table references" {
        Assert-Equal @("SigninLogs", "AuditLogs") (Get-KqlTableReferences "SigninLogs`n| union AuditLogs")
        Assert-Equal @("SigninLogs", "Syslog") (Get-KqlTableReferences "SigninLogs`n| join kind=inner (Syslog) on X")
    }

    Test-Case "every operand of a union list is a table reference" {
        # REGRESSION: only the first operand was read, so everything after the
        # comma in 'union SigninLogs, InventedTable' skipped validation.
        Assert-Equal @("SigninLogs", "AuditLogs", "Heartbeat") (Get-KqlTableReferences "SigninLogs`n| union AuditLogs, Heartbeat")
    }

    Test-Case "a join operand on the following line is still found" {
        # REGRESSION: matching ran line-at-a-time, so a multiline join hid its
        # operand entirely.
        Assert-Equal @("SigninLogs", "InventedTable") (Get-KqlTableReferences "SigninLogs`n| join (`n    InventedTable`n) on X")
    }

    Test-Case "a let-bound table is a reference, and the local name is not" {
        # REGRESSION: 'let recent = InventedTable;' bound a table that was never
        # checked. The binding NAME must not then be reported as a table itself.
        Assert-Equal @("InventedTable") (Get-KqlTableReferences "let recent = InventedTable;`nrecent | take 5")
    }

    Test-Case "a function call on the right of a let is not a table" {
        Assert-Equal @() (Get-KqlTableReferences "let cutoff = ago(1d);`nlet x = 5;")
    }

    Test-Case "union withsource=X * names no table" {
        # REGRESSION: the union pattern backtracks twice given this input. With
        # no trailing lookahead the option group matches zero times and
        # 'withsource' is captured as a table; with the lookahead but no \b it
        # backtracks one character further and captures 'withsourc', which the
        # lookahead accepts because the next character is 'e' rather than '='.
        # Both forms shipped before this test existed.
        Assert-Equal @() (Get-KqlTableReferences "union withsource=Table_ *`n| summarize count() by Table_")
    }

    Test-Case "a fixture section no skill declares is reported" {
        $bt = [string][char]96
        $line = '- Uses the optimization shape: ' + $bt + 'Objective' + $bt + ', ' + $bt + 'Executive Summary' + $bt
        Test-FixtureShapeSections $line @("Objective", "Query")
        Assert-IssueMatching "Executive Summary"
    }

    Test-Case "a fixture naming only declared sections is silent" {
        $bt = [string][char]96
        $line = '- Uses the optimization shape: ' + $bt + 'Objective' + $bt + ', ' + $bt + 'What changed' + $bt
        Test-FixtureShapeSections $line @("Objective", "What changed")
        Assert-NoIssues
    }

    Test-Case "backticked names outside a shape line are not treated as sections" {
        # Fixtures backtick datasets and fields constantly; only the bullet that
        # asserts a SHAPE is making a claim about output sections.
        $bt = [string][char]96
        $line = '- Keeps ' + $bt + 'SigninLogs' + $bt + ' and ' + $bt + 'ResultType' + $bt
        Test-FixtureShapeSections $line @("Objective")
        Assert-NoIssues
    }

    Test-Case "a lookup with no documented field list is not reported" {
        # Otherwise every undocumented lookup would produce noise and the check
        # would get switched off rather than fixed. The join key is exempt for
        # the same reason: these docs treat it as version-dependent on purpose.
        $bt = [string][char]96
        $fence = $bt * 3
        $doc = $fence + "spl`n| lookup undocumented_lookup key OUTPUT a, zzz`n" + $fence + "`n"
        Test-LookupOutputFields "doc.md" $doc
        Assert-NoIssues
    }

    Write-Host "Assert-Exists and Assert-Contains" -ForegroundColor Cyan

    Test-Case "Assert-Exists reports only genuinely missing files" {
        Assert-Exists "present.md"
        Assert-NoIssues
        Assert-Exists "definitely-not-here.md"
        Assert-IssueMatching "Missing required file"
    }

    Test-Case "Assert-Contains is case-sensitive" {
        # REGRESSION: -notmatch is case-insensitive, so a wrongly-cased section
        # heading satisfied the check.
        Assert-Contains "present.md" "hello" "greeting"
        Assert-NoIssues
        Assert-Contains "present.md" "HELLO" "uppercase greeting"
        Assert-IssueMatching "is missing uppercase greeting"
    }
}
finally {
    Remove-Item -LiteralPath $fixtureRoot -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ""
if ($script:failed -gt 0) {
    Write-Host "$($script:passed) passed, $($script:failed) failed" -ForegroundColor Red
    exit 1
}
Write-Host "$($script:passed) passed, 0 failed" -ForegroundColor Green
exit 0
