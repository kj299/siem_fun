param(
    [string]$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
)

$ErrorActionPreference = "Stop"
$issues = New-Object System.Collections.Generic.List[string]

function Add-Issue {
    param([string]$Message)
    $issues.Add($Message) | Out-Null
}

function Get-RepoFile {
    param([string]$RelativePath)
    return Join-Path $Root $RelativePath
}

$script:textCache = @{}

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
        $raw = Get-Content -Raw -Path $path
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

function Get-YamlList {
    param(
        [string]$Text,
        [string]$Section,
        [string]$Key
    )

    # The header match stops at the line break (not ':\s*') so the child lines
    # keep their indentation; '\s*' would swallow the first child's indent and
    # the '^\s{2}' / '^\s{4}' anchors below would never match it. An optional
    # trailing '# comment' and end-of-file (for a header on the last line) are
    # tolerated. Only block-style lists ('key:' then 4-space '- "item"' lines)
    # are machine-checked; inline flow lists like 'key: []' are not supported.
    $headerTail = "[ \t]*(?:#[^\r\n]*)?(?:\r?\n|\z)"
    $sectionPattern = "(?ms)^$([regex]::Escape($Section)):$headerTail(.*?)(?=^\S|\z)"
    $sectionMatch = [regex]::Match($Text, $sectionPattern)
    if (-not $sectionMatch.Success) {
        return @()
    }

    $sectionBody = $sectionMatch.Groups[1].Value
    $keyPattern = "(?ms)^\s{2}$([regex]::Escape($Key)):$headerTail(.*?)(?=^\s{2}\S|\z)"
    $keyMatch = [regex]::Match($sectionBody, $keyPattern)
    if (-not $keyMatch.Success) {
        return @()
    }

    $items = @()
    foreach ($line in ($keyMatch.Groups[1].Value -split "`r?`n")) {
        if ($line -match '^\s{4}-\s+"?(.*?)"?\s*$') {
            $items += $Matches[1]
        }
    }
    return $items
}

function Assert-ListsEqual {
    param(
        [string]$Name,
        [string[]]$Left,
        [string[]]$Right
    )

    if ($Left.Count -eq 0 -and $Right.Count -eq 0) {
        Add-Issue "Helper drift: $Name is missing or empty in both files"
        return
    }
    $leftText = ($Left -join "`n")
    $rightText = ($Right -join "`n")
    if ($leftText -cne $rightText) {
        Add-Issue "Helper drift detected in $Name"
    }
}

$requiredFiles = @(
    "README.md",
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

# quotepath=false emits non-ASCII filenames raw instead of C-quoted octal,
# which would fail Test-Path and silently skip those files from validation.
$trackedFiles = git -C $Root -c core.quotepath=false ls-files
foreach ($file in $trackedFiles) {
    $path = Get-RepoFile $file
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        continue
    }
    $text = Get-Content -Raw -Path $path
    if ($null -eq $text) {
        continue
    }
    # Git conflict markers are exactly seven chars followed by a space+label
    # (<<<<<<< / >>>>>>>) or alone on the line (=======); the right-side anchor
    # avoids flagging setext heading underlines of eight or more equals signs.
    if ($text -match '(?m)^(<{7}( |$)|={7}$|>{7}( |$))') {
        Add-Issue "$file contains a conflict marker"
    }
    # SPL 'where' uses eval semantics: an unquoted true/false is a field
    # reference, so the comparison silently matches nothing. Enforce the
    # quoting rule documented in greynoise-integration.md across all docs.
    if ($file -like "*.md" -and $text -cmatch '(?m)^\s*\| where [^|\r\n]*=\s*(true|false)\b') {
        Add-Issue "$file compares against unquoted true/false in an SPL where clause; quote the value (=`"true`")"
    }
    foreach ($char in $text.ToCharArray()) {
        $code = [int][char]$char
        $allowed = ($code -eq 9) -or ($code -eq 10) -or ($code -eq 13) -or (($code -ge 32) -and ($code -le 126))
        if (-not $allowed) {
            Add-Issue "$file contains non-ASCII character U+$($code.ToString('X4'))"
            break
        }
    }
}

foreach ($skill in @("splunk-sentinel-query-builder/SKILL.md", "splunk-data-dictionary-builder/SKILL.md", "splunk-enrichment-query-builder/SKILL.md")) {
    # A missing file is already reported by Assert-Exists; content checks on it
    # would only add misdirecting issues.
    if (-not (Test-RepoFile $skill)) {
        continue
    }
    Assert-Contains $skill '(?s)^---\s+name:\s+[-a-z0-9]+\s+description:\s+.+?\s+---' "valid skill frontmatter"
    Assert-Contains $skill '## Important' "top-level Important section"
    Assert-Contains $skill '## Inputs' "Inputs section"
}

$requiredOpenaiKeys = @("interface:", "display_name:", "short_description:", "default_prompt:", "policy:", "allow_implicit_invocation: false")
foreach ($skill in @("splunk-sentinel-query-builder", "splunk-data-dictionary-builder", "splunk-enrichment-query-builder")) {
    if (-not (Test-RepoFile "$skill/agents/openai.yaml")) {
        continue
    }
    $skillOpenai = Read-Text "$skill/agents/openai.yaml"
    foreach ($key in $requiredOpenaiKeys) {
        if ($skillOpenai -cnotmatch [regex]::Escape($key)) {
            Add-Issue "$skill/agents/openai.yaml is missing $key"
        }
    }
}

# Helper pair parity: both companion files in a skill must carry the same
# section lists. Query-builder skills use the full structured contract and
# require the model-specific tuning sections; the data-dictionary builder
# uses a simpler helper shape.
$sectionParents = @{
    prompt_shape     = "invocation"
    default_sections = "response_contract"
    short_sections   = "response_contract"
    token_rules      = "behavior"
    truth_order      = "behavior"
    stop_conditions  = "behavior"
}
$helperChecks = @(
    @{ Skill = "splunk-sentinel-query-builder";   Sections = @("prompt_shape", "default_sections", "short_sections", "token_rules", "truth_order", "stop_conditions"); RequireTuningSections = $true },
    @{ Skill = "splunk-enrichment-query-builder"; Sections = @("prompt_shape", "default_sections", "short_sections", "token_rules", "truth_order", "stop_conditions"); RequireTuningSections = $true },
    @{ Skill = "splunk-data-dictionary-builder";  Sections = @("token_rules", "stop_conditions"); RequireTuningSections = $false }
)
foreach ($check in $helperChecks) {
    $claudePath = "$($check.Skill)/agents/claude-opus.yaml"
    $codexPath = "$($check.Skill)/agents/codex-gpt-5.4.yaml"
    if (-not (Test-RepoFile $claudePath) -or -not (Test-RepoFile $codexPath)) {
        continue
    }
    $claude = Read-Text $claudePath
    $codex = Read-Text $codexPath
    foreach ($section in $check.Sections) {
        $parent = $sectionParents[$section]
        Assert-ListsEqual "$claudePath / $section" (Get-YamlList $claude $parent $section) (Get-YamlList $codex $parent $section)
    }
    if ($check.RequireTuningSections) {
        # claude-opus helpers must carry trigger_tuning; codex helpers must carry packaging_rules.
        if ($claude -cnotmatch 'trigger_tuning:') {
            Add-Issue "$claudePath is missing trigger_tuning section"
        }
        if ($codex -cnotmatch 'packaging_rules:') {
            Add-Issue "$codexPath is missing packaging_rules section"
        }
    }
}

# The canonical invocation prompt is duplicated across openai.yaml and both
# companion helpers; it has drifted before, so enforce three-way equality.
foreach ($skill in @("splunk-sentinel-query-builder", "splunk-data-dictionary-builder", "splunk-enrichment-query-builder")) {
    $prompts = @{}
    foreach ($entry in @(
        @{ Path = "$skill/agents/openai.yaml"; Key = "default_prompt" },
        @{ Path = "$skill/agents/claude-opus.yaml"; Key = "preferred_prompt" },
        @{ Path = "$skill/agents/codex-gpt-5.4.yaml"; Key = "preferred_prompt" }
    )) {
        if (-not (Test-RepoFile $entry.Path)) {
            continue
        }
        $match = [regex]::Match((Read-Text $entry.Path), "(?m)^\s*$($entry.Key):\s*""(.*)""\s*$")
        if ($match.Success) {
            $prompts[$entry.Path] = $match.Groups[1].Value
        } else {
            Add-Issue "$($entry.Path) is missing a quoted $($entry.Key)"
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
    $scanText = [regex]::Replace($text, '(?ms)^\s*```.*?^\s*```[ \t]*$', '')
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
