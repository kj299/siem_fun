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
