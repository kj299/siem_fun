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
    if ($lines[0].Trim().StartsWith("|")) {
        return
    }
    if ($Body -notmatch '(?i)\bearliest[ \t]*=' -and
        $Body -notmatch '_time' -and
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
    "splunk-data-dictionary-builder/SKILL.md",
    "splunk-data-dictionary-builder/agents/openai.yaml",
    "splunk-data-dictionary-builder/agents/claude-opus.yaml",
    "splunk-data-dictionary-builder/agents/codex-gpt-5.4.yaml",
    "splunk-data-dictionary-builder/references/workflow.md",
    "splunk-data-dictionary-builder/scripts/build_splunk_dictionary.py",
    "splunk-data-dictionary-builder/tests/test_build_splunk_dictionary.py",
    "scripts/tests/validate-skill-pack.tests.ps1",
    "scripts/tests/mutation-check.py",
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
        foreach ($block in (Get-FencedBlocks $text)) {
            if ($block.Language -cne "spl") {
                continue
            }
            Test-SplBlock $file $block.Body
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
