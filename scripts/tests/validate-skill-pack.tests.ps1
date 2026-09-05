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
    if ($null -ne $script:notices) { $script:notices.Clear() }
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

    Test-Case "a reference file missing from a helper's map is reported" {
        $doc = "references:`n  primary_skill: `"../SKILL.md`"`n  a: `"../references/a.md`"`n"
        Test-HelperReferences "skill" "skill/agents/claude-opus.yaml" $doc @("a.md", "b.md")
        Assert-IssueMatching "does not list references/b.md"
    }

    Test-Case "a helper listing a reference that does not exist is reported" {
        $doc = "references:`n  a: `"../references/a.md`"`n  ghost: `"../references/ghost.md`"`n"
        Test-HelperReferences "skill" "skill/agents/claude-opus.yaml" $doc @("a.md")
        Assert-IssueMatching "which does not exist"
    }

    Test-Case "a helper map matching the reference directory is silent" {
        $doc = "references:`n  primary_skill: `"../SKILL.md`"`n  a: `"../references/a.md`"`n  b: `"../references/b.md`"`n"
        Test-HelperReferences "skill" "skill/agents/claude-opus.yaml" $doc @("a.md", "b.md")
        Assert-NoIssues
    }

    Test-Case "a tracked file missing from the layout tree is reported" {
        $bt = [string][char]96
        $fence = $bt * 3
        $doc = $fence + "text`nsiem_fun/`n|-- README.md`n" + $fence + "`n"
        Test-LayoutTree "README.md" $doc @("README.md", "scripts/required-checks.txt")
        Assert-IssueMatching "required-checks.txt"
    }

    Test-Case "a layout tree listing every tracked file is silent" {
        $bt = [string][char]96
        $fence = $bt * 3
        $doc = $fence + "text`nsiem_fun/`n|-- README.md`n|-- scripts/`n|   ``-- a.ps1`n" + $fence + "`n"
        Test-LayoutTree "README.md" $doc @("README.md", "scripts/a.ps1")
        Assert-NoIssues
    }

    Test-Case "a document with no layout tree is reported, not skipped" {
        # Otherwise deleting the tree would silence the check rather than fail it.
        Test-LayoutTree "README.md" "no tree here" @("README.md")
        Assert-IssueMatching "no siem_fun/ layout tree"
    }

    Test-Case "an unescaped pipe inside a table cell is reported" {
        $bt = [string][char]96
        $doc = "| A | B |`n| --- | --- |`n| x | " + $bt + "count() by f | top" + $bt + " |"
        Test-MarkdownTables "d.md" $doc
        Assert-IssueMatching "malformed table row"
    }

    Test-Case "an escaped pipe inside a table cell is fine" {
        $bt = [string][char]96
        $doc = "| A | B |`n| --- | --- |`n| x | " + $bt + "count() by f \| top" + $bt + " |"
        Test-MarkdownTables "d.md" $doc
        Assert-NoIssues
    }

    Test-Case "the header separator row is not counted as a data row" {
        # ':---' and '---:' alignment forms must not read as a short row.
        Test-MarkdownTables "d.md" "| A | B | C |`n| :--- | ---: | --- |`n| 1 | 2 | 3 |"
        Assert-NoIssues
    }

    Test-Case "sourcetype values are read by position, unquoted and quoted" {
        # REGRESSION: the shape-based token check only ever saw colon-delimited
        # names, so 14 of the catalogue's 53 sourcetypes -- WinEventLog among
        # them -- and any invented name in that shape were never checked.
        Assert-Equal @("fgt_traffic") (Get-SourcetypeValues 'index=x sourcetype=fgt_traffic earliest=-24h')
        Assert-Equal @("cisco:asa") (Get-SourcetypeValues 'sourcetype="cisco:asa" | stats count')
    }

    Test-Case "sourcetype IN lists yield every member" {
        Assert-Equal @("cisco:asa", "pan:traffic") (Get-SourcetypeValues 'sourcetype IN (cisco:asa, "pan:traffic")')
    }

    Test-Case "sourcetype placeholders and wildcards are not values" {
        Assert-Equal @() (Get-SourcetypeValues 'sourcetype=YOUR_SOURCETYPE | head 5')
        Assert-Equal @() (Get-SourcetypeValues '(index=proxy sourcetype=...) OR (index=dns sourcetype=<name>)')
        Assert-Equal @() (Get-SourcetypeValues 'sourcetype=pan:* earliest=-1h')
    }

    Test-Case "source= is not mistaken for sourcetype=" {
        Assert-Equal @("XmlWinEventLog") (Get-SourcetypeValues 'sourcetype=XmlWinEventLog source=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational')
    }

    Write-Host "Add-CatalogueSourcetypeNames" -ForegroundColor Cyan

    Test-Case "the Sourcetype column is read wherever it sits" {
        # REGRESSION: the registry used to take the first backticked cell of
        # every row, and the catalogue's tables do not agree on column order.
        # Two of them lead with the add-on name, so five real sourcetypes
        # (the CrowdStrike and Carbon Black families) were absent from the
        # registry and writing one after sourcetype= was reported as invented.
        $names = New-Object 'System.Collections.Generic.HashSet[string]'
        Add-CatalogueSourcetypeNames (
            "| Add-on | Sourcetype | CIM data model |`n" +
            "| --- | --- | --- |`n" +
            "| Splunk Add-on for CrowdStrike FDR (app 5579) | ``crowdstrike:events:sensor`` | Endpoint |`n"
        ) $names
        Assert-True $names.Contains("crowdstrike:events:sensor") "second-column sourcetype must be registered"
        Assert-Equal 1 $names.Count
    }

    Test-Case "a column that is not the Sourcetype column is not registered" {
        # REGRESSION: the same first-cell read registered 11 index globs
        # (*auth*, *firewall*) from the index-naming table, and the Source
        # column next to a sourcetype. Registering a SOURCE is the P1 that
        # let a query name one as its sourcetype and return nothing.
        $names = New-Object 'System.Collections.Generic.HashSet[string]'
        Add-CatalogueSourcetypeNames (
            "| Sourcetype | Source | CIM data model |`n" +
            "| --- | --- | --- |`n" +
            "| ``WinEventLog`` | ``WinEventLog:Security`` | Authentication |`n`n" +
            "| Index name pattern | Likely sourcetypes | First step |`n" +
            "| --- | --- | --- |`n" +
            "| ``*auth*``, ``*iam*`` | ``OktaIM2:log`` | same |`n"
        ) $names
        Assert-True $names.Contains("WinEventLog") "the Sourcetype column must be registered"
        Assert-True (-not $names.Contains("WinEventLog:Security")) "a Source must not be registered"
        Assert-True (-not $names.Contains("*auth*")) "an index glob must not be registered"
        Assert-Equal 1 $names.Count
    }

    Test-Case "a table with no Sourcetype column contributes nothing" {
        # cim-vendor-alignment.md's one table is 'Data model | Root dataset |
        # Core fields'. Reading its first cell would have registered CIM data
        # model names as sourcetypes.
        $names = New-Object 'System.Collections.Generic.HashSet[string]'
        Add-CatalogueSourcetypeNames (
            "| Data model | Root dataset | Core fields |`n" +
            "| --- | --- | --- |`n" +
            "| ``Authentication`` | ``Authentication`` | user, src |`n"
        ) $names
        Assert-Equal 0 $names.Count
    }

    Test-Case "a row before any separator is not read as data" {
        # The header is the row above the separator, so a stray table-shaped
        # line with no separator under it has no known column and is skipped.
        $names = New-Object 'System.Collections.Generic.HashSet[string]'
        Add-CatalogueSourcetypeNames "| ``not:a:table`` | x |`n" $names
        Assert-Equal 0 $names.Count
    }

    Test-Case "every sourcetype the docs write in query position is catalogued" {
        # A guard, not a REGRESSION: it pins no shipped defect, it proves the
        # registry rebuild did not quietly drop a name the documents rely on.
        # These are the values the reference files actually write in query
        # position, so losing one turns a correct document into a reported
        # error.
        $names = New-Object 'System.Collections.Generic.HashSet[string]'
        foreach ($registryFile in $script:sourcetypeRegistryFiles) {
            Add-CatalogueSourcetypeNames (Get-Content -Raw (Join-Path $PSScriptRoot "../../$registryFile")) $names
        }
        foreach ($used in @("cisco:asa", "pan:traffic", "cisco:umbrella:dns",
                            "bluecoat:proxysg:access:kv", "XmlWinEventLog",
                            "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational")) {
            Assert-True $names.Contains($used) "$used is written in query position and must stay catalogued"
        }
    }

    Write-Host "Test-CatalogueReferences" -ForegroundColor Cyan

    Test-Case "a catalogue row with an empty Reference cell is reported" {
        # The Splunkbase catalogue carried no citations for a year while the
        # Sentinel catalogue required one per table; this is the check that
        # keeps the two symmetric now that both cite.
        Test-CatalogueReferences "c.md" (
            "| Sourcetype | CIM data model | Reference |`n" +
            "| --- | --- | --- |`n" +
            "| ``cisco:asa`` | Network_Traffic | [ASA](https://example.invalid/asa) |`n" +
            "| ``pan:traffic`` | Network_Traffic | |`n"
        )
        Assert-IssueMatching "row at line 4 with an empty Reference cell"
    }

    Test-Case "a Sourcetype table with no Reference column is reported once" {
        Test-CatalogueReferences "c.md" (
            "| Add-on | Sourcetype | CIM data model |`n" +
            "| --- | --- | --- |`n" +
            "| FDR | ``crowdstrike:events:sensor`` | Endpoint |`n" +
            "| FDR | ``crowdstrike:inventory:aidmaster`` | -- |`n"
        )
        Assert-IssueMatching "table at line 2 with no Reference column"
        Assert-Equal 1 $issues.Count "the header issue covers every row; rows must not be reported again"
    }

    Test-Case "a short row with no Reference cell at all is reported" {
        # A row that stops before the Reference column is as uncited as an
        # empty cell, and indexing past the end must not throw.
        Test-CatalogueReferences "c.md" (
            "| Sourcetype | Reference |`n" +
            "| --- | --- |`n" +
            "| ``cisco:asa`` |`n"
        )
        Assert-IssueMatching "row at line 3 with an empty Reference cell"
    }

    Test-Case "a catalogue table citing every row is silent, wherever the column sits" {
        Test-CatalogueReferences "c.md" (
            "| Add-on | Sourcetype | Reference | Key fields |`n" +
            "| --- | --- | --- | --- |`n" +
            "| FDR | ``crowdstrike:events:sensor`` | [FDR](https://example.invalid/fdr) | aid |`n"
        )
        Assert-NoIssues
    }

    Test-Case "a table with no Sourcetype column needs no Reference" {
        # The index-inference table ('Likely sourcetypes') and the metadata
        # table are not registries and must not be asked for citations.
        Test-CatalogueReferences "c.md" (
            "| Index name pattern | Likely sourcetypes | First step |`n" +
            "| --- | --- | --- |`n" +
            "| ``*dns*`` | ``infoblox:dns`` | same |`n"
        )
        Assert-NoIssues
    }

    Test-Case "the shipped catalogue cites every row" {
        foreach ($registryFile in $script:sourcetypeRegistryFiles) {
            Test-CatalogueReferences $registryFile (Get-Content -Raw (Join-Path $PSScriptRoot "../../$registryFile"))
        }
        Assert-NoIssues
    }

    Test-Case "a query leading with a function is not a table reference" {
        # REGRESSION: Microsoft tells you to prefer _SentinelHealth() over the
        # SentinelHealth table, and the leading-identifier pattern reported that
        # recommended form as an uncatalogued table.
        Assert-Equal @() (Get-KqlTableReferences "_SentinelHealth()`n| where SentinelResourceType == `"Analytics Rule`"")
    }

    Test-Case "a function call on the right of a let is not a table" {
        Assert-Equal @() (Get-KqlTableReferences "let cutoff = ago(1d);`nlet x = 5;")
    }

    Test-Case "a parenthesized union operand is a table reference" {
        # REGRESSION: KQL allows a parenthesized subquery as a union operand,
        # and the pattern accepted only a bare identifier after 'union', so an
        # invented table in the commonest union form was reported by nothing.
        $refs = [string[]](Get-KqlTableReferences "union (InventedTable | where TimeGenerated > ago(7d))")
        Assert-True ($refs -ccontains "InventedTable") "a parenthesized operand must be read"
        $refs = [string[]](Get-KqlTableReferences "union isfuzzy=true (InventedTable | take 5)")
        Assert-True ($refs -ccontains "InventedTable") "options before a parenthesized operand must be skipped"
    }

    Test-Case "a union operand list may wrap or carry a subquery pipe" {
        # The statement ends at the first '|' or newline whose parentheses are
        # balanced: a subquery's inner pipe does not end it, a trailing comma
        # carries the list on, and a downstream summarize is still excluded.
        $refs = [string[]](Get-KqlTableReferences "union (SigninLogs | take 5),`n      (AuditLogs | take 5)")
        Assert-True ($refs -ccontains "SigninLogs" -and $refs -ccontains "AuditLogs") "both wrapped operands must be read"
        $refs = [string[]](Get-KqlTableReferences "SigninLogs`n| union AuditLogs`n| summarize count() by Alpha, Beta")
        Assert-True (-not ($refs -ccontains "Beta")) "summarize columns must not be read as operands"
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

    Test-Case "a fixture section is found on a CRLF line too" {
        # REGRESSION: the shape-line pattern ended in a bare '$', which on a
        # CRLF checkout never matches, because [^\r\n]* stops at the \r while
        # '$' matches only before the \n. The check was a complete no-op on
        # Windows, which is the only OS that runs the validator in CI, and the
        # Linux suite passed throughout.
        $bt = [string][char]96
        $crlf = '- Uses the shape: ' + $bt + 'Executive Summary' + $bt + "`r`n"
        Test-FixtureShapeSections $crlf @("Objective")
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

    Write-Host "Golden-run freshness" -ForegroundColor Cyan

    Test-Case "the content hash folds CRLF to LF and is the plain sha256 of the LF form" {
        # REGRESSION-class guard: the validator runs on a CRLF checkout. A
        # raw-bytes hash would report every watched file as changed there
        # while agreeing with itself on Linux, so the notice would fire on
        # every CI run and be ignored within a week. The Python side computes
        # the same value; its test asserts the same constant.
        $lf = Join-Path $fixtureRoot "hash-lf.md"
        $crlf = Join-Path $fixtureRoot "hash-crlf.md"
        [System.IO.File]::WriteAllBytes($lf, [System.Text.Encoding]::ASCII.GetBytes("one`ntwo`n"))
        [System.IO.File]::WriteAllBytes($crlf, [System.Text.Encoding]::ASCII.GetBytes("one`r`ntwo`r`n"))
        $h = Get-NormalisedFileHash $lf
        Assert-Equal $h (Get-NormalisedFileHash $crlf) "CRLF and LF must hash identically"
        Assert-Equal "c3f9c8c283a2b1f2f1896f27a01cbe3cddc0c9d93f752e4639035a0f5b36f6e8" $h "known sha256 of one LF two LF, the value the Python suite pins too"
    }

    Test-Case "a lone CR is content, not a line ending" {
        $p = Join-Path $fixtureRoot "hash-cr.md"
        [System.IO.File]::WriteAllBytes($p, [System.Text.Encoding]::ASCII.GetBytes("a`rb`n"))
        $plain = Join-Path $fixtureRoot "hash-plain.md"
        [System.IO.File]::WriteAllBytes($plain, [System.Text.Encoding]::ASCII.GetBytes("ab`n"))
        Assert-True ((Get-NormalisedFileHash $p) -cne (Get-NormalisedFileHash $plain)) "a bare CR must not be dropped"
    }

    # A skill laid out under the fixture root, so the watched-set rule and the
    # freshness check run against files this suite controls.
    $gs = "golden-skill"
    New-Item -ItemType Directory -Path (Join-Path $fixtureRoot "$gs/references") -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $fixtureRoot "examples") -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $fixtureRoot "$gs/SKILL.md") -Value "# skill" -NoNewline
    Set-Content -LiteralPath (Join-Path $fixtureRoot "$gs/references/a.md") -Value "alpha" -NoNewline
    Set-Content -LiteralPath (Join-Path $fixtureRoot "$gs/references/notes.txt") -Value "not watched" -NoNewline
    Set-Content -LiteralPath (Join-Path $fixtureRoot "examples/golden-prompts.md") -Value "# fixtures" -NoNewline

    Test-Case "the watched set is every SKILL.md, references/*.md and the fixture file" {
        $w = [string[]](Get-GoldenWatchedFiles @($gs))
        Assert-True ($w -ccontains "$gs/SKILL.md") "SKILL.md must be watched"
        Assert-True ($w -ccontains "$gs/references/a.md") "references/*.md must be watched"
        Assert-True (-not ($w -ccontains "$gs/references/notes.txt")) "only markdown under references/ is watched"
        Assert-True ($w -ccontains "examples/golden-prompts.md") "the fixture file must be watched"
    }

    function Write-GoldenMarker {
        param([hashtable]$Files, [string]$Extra = "")
        $entries = ($Files.GetEnumerator() | ForEach-Object { '"' + $_.Key + '": "' + $_.Value + '"' }) -join ", "
        $json = '{ "date": "2026-01-01", "method": "agents", "result": "1 of 1", "files": { ' + $entries + ' }' + $Extra + ' }'
        Set-Content -LiteralPath (Join-Path $fixtureRoot "examples/golden-run.json") -Value $json -NoNewline
        Reset-ValidatorState
    }

    Test-Case "a marker matching the tree raises no notice and no issue" {
        $files = @{}
        foreach ($rel in [string[]](Get-GoldenWatchedFiles @($gs))) { $files[$rel] = Get-NormalisedFileHash (Join-Path $fixtureRoot $rel) }
        Write-GoldenMarker $files
        Test-GoldenRunFreshness @($gs)
        Assert-NoIssues
        Assert-Equal 0 $script:notices.Count "no notice expected for a fresh marker"
    }

    Test-Case "a changed watched file is named in a notice, and validation is not failed" {
        $files = @{}
        foreach ($rel in [string[]](Get-GoldenWatchedFiles @($gs))) { $files[$rel] = Get-NormalisedFileHash (Join-Path $fixtureRoot $rel) }
        Write-GoldenMarker $files
        Set-Content -LiteralPath (Join-Path $fixtureRoot "$gs/references/a.md") -Value "alpha changed" -NoNewline
        Test-GoldenRunFreshness @($gs)
        Assert-NoIssues
        Assert-Equal 1 $script:notices.Count "exactly one notice"
        Assert-True ($script:notices[0] -clike "*$gs/references/a.md*") "the notice must name the changed file"
        Assert-True ($script:notices[0] -clike "*2026-01-01 (1 of 1)*") "the notice must say when and with what result the last run happened"
    }

    Test-Case "a recorded file that no longer exists is named too" {
        $files = @{}
        foreach ($rel in [string[]](Get-GoldenWatchedFiles @($gs))) { $files[$rel] = Get-NormalisedFileHash (Join-Path $fixtureRoot $rel) }
        $files["$gs/references/gone.md"] = "0000"
        Write-GoldenMarker $files
        Test-GoldenRunFreshness @($gs)
        Assert-True ($script:notices.Count -ge 1 -and $script:notices[0] -clike "*gone.md*") "a removed file must be reported"
    }

    Test-Case "a malformed marker is an issue, not a notice" {
        # A marker that no longer parses would otherwise be read as 'nothing
        # recorded' and the whole check would go quiet.
        Set-Content -LiteralPath (Join-Path $fixtureRoot "examples/golden-run.json") -Value "{ not json" -NoNewline
        Reset-ValidatorState
        Test-GoldenRunFreshness @($gs)
        Assert-IssueMatching "not valid JSON or lacks a files map"
        Set-Content -LiteralPath (Join-Path $fixtureRoot "examples/golden-run.json") -Value '{ "date": "x" }' -NoNewline
        Reset-ValidatorState
        Test-GoldenRunFreshness @($gs)
        Assert-IssueMatching "not valid JSON or lacks a files map"
    }

    Write-Host "Shared rule corpus" -ForegroundColor Cyan

    # The half of shared-rule-cases.json this tool is responsible for. The
    # Python suite reads the same file and asserts the same outcomes against
    # the grader. That is the point: the two tools are one rule set written
    # twice, and they drifted on three rules at once without anything noticing.
    # A case that holds there and not here now fails a suite.
    $corpusPath = Join-Path $PSScriptRoot "shared-rule-cases.json"
    $corpus = Get-Content -Raw -LiteralPath $corpusPath | ConvertFrom-Json
    $placeholders = [string[]]$corpus.placeholders

    Test-Case "the shared corpus is not silently empty" {
        # A reader pointed at a renamed or truncated file would otherwise pass
        # every case vacuously, which is the failure this file exists to
        # prevent in the tools it checks.
        Assert-True (@($corpus.kql_tables).Count -ge 15) "expected at least 15 kql cases"
        Assert-True (@($corpus.spl_time_bound).Count -ge 10) "expected at least 10 spl cases"
    }

    foreach ($case in $corpus.kql_tables) {
        # $case is captured by the scriptblock, so bind it per iteration.
        $c = $case
        Test-Case "kql tables: $($c.name)" {
            # The validator returns the documented placeholders and lets the
            # catalogue accept them; the grader filters them itself. Subtracting
            # here compares the rule rather than where each tool draws the line.
            # Assign BEFORE piping. Get-KqlTableReferences returns ', $items',
            # so the array arrives as one pipeline object and a Where-Object
            # applied directly would filter the wrapper, not its elements --
            # the trap CLAUDE.md names. The assignment unrolls it first.
            $refs = Get-KqlTableReferences $c.query
            $got = [string[]]@($refs | Where-Object { $placeholders -cnotcontains $_ })
            [array]::Sort($got)
            $want = [string[]]@($c.tables)
            [array]::Sort($want)
            Assert-Equal ($want -join ", ") ($got -join ", ") "table references for: $($c.query)"
        }
    }

    foreach ($case in $corpus.spl_time_bound) {
        $c = $case
        Test-Case "spl time bound: $($c.name)" {
            Test-SplBlock "corpus.md" $c.query
            $reported = @($issues | Where-Object { $_ -match "no time bound" }).Count -gt 0
            Assert-Equal $c.reported $reported "time-bound outcome for: $($c.query)"
        }
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
