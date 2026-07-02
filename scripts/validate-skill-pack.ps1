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

function Read-Text {
    param([string]$RelativePath)
    $path = Get-RepoFile $RelativePath
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        # Assert-Exists reports missing required files; returning empty text
        # lets the run finish and print every collected issue.
        return ""
    }
    $text = Get-Content -Raw -Path $path
    if ($null -eq $text) {
        return ""
    }
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

$trackedFiles = git -C $Root ls-files
foreach ($file in $trackedFiles) {
    $path = Get-RepoFile $file
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        continue
    }
    $text = Get-Content -Raw -Path $path
    if ($null -eq $text) {
        continue
    }
    if ($text -match '(?m)^(<<<<<<<|=======|>>>>>>>)') {
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

# Query-builder skills (sentinel, enrichment) use a structured response contract;
# check that both helper files carry the same sections.
foreach ($helperPair in @(
    @("splunk-sentinel-query-builder/agents/claude-opus.yaml", "splunk-sentinel-query-builder/agents/codex-gpt-5.4.yaml"),
    @("splunk-enrichment-query-builder/agents/claude-opus.yaml", "splunk-enrichment-query-builder/agents/codex-gpt-5.4.yaml")
)) {
    if (-not (Test-RepoFile $helperPair[0]) -or -not (Test-RepoFile $helperPair[1])) {
        continue
    }
    $claude = Read-Text $helperPair[0]
    $codex = Read-Text $helperPair[1]
    foreach ($section in @("prompt_shape", "default_sections", "short_sections", "token_rules", "truth_order", "stop_conditions")) {
        $parent = if ($section -in @("prompt_shape")) { "invocation" } elseif ($section -in @("default_sections", "short_sections")) { "response_contract" } else { "behavior" }
        Assert-ListsEqual "$($helperPair[0]) / $section" (Get-YamlList $claude $parent $section) (Get-YamlList $codex $parent $section)
    }
    # claude-opus helpers must carry trigger_tuning; codex helpers must carry packaging_rules.
    if ($claude -cnotmatch 'trigger_tuning:') {
        Add-Issue "$($helperPair[0]) is missing trigger_tuning section"
    }
    if ($codex -cnotmatch 'packaging_rules:') {
        Add-Issue "$($helperPair[1]) is missing packaging_rules section"
    }
}

# Data-dictionary builder uses a simpler helper structure; check only the sections it defines.
if ((Test-RepoFile "splunk-data-dictionary-builder/agents/claude-opus.yaml") -and (Test-RepoFile "splunk-data-dictionary-builder/agents/codex-gpt-5.4.yaml")) {
    $claude = Read-Text "splunk-data-dictionary-builder/agents/claude-opus.yaml"
    $codex = Read-Text "splunk-data-dictionary-builder/agents/codex-gpt-5.4.yaml"
    foreach ($section in @("token_rules", "stop_conditions")) {
        Assert-ListsEqual "splunk-data-dictionary-builder helpers / $section" (Get-YamlList $claude "behavior" $section) (Get-YamlList $codex "behavior" $section)
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
    $baseDir = Split-Path -Parent (Get-RepoFile $file)
    foreach ($match in [regex]::Matches($text, $linkRegex)) {
        $target = $match.Groups[1].Value
        if ($target -match '^(https?://|mailto:|#)') {
            continue
        }
        $targetPath = ($target -split '#')[0]
        if ([string]::IsNullOrWhiteSpace($targetPath)) {
            continue
        }
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
