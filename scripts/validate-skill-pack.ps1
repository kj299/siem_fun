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
    return Get-Content -Raw -Path (Get-RepoFile $RelativePath)
}

function Assert-Exists {
    param([string]$RelativePath)
    if (-not (Test-Path -LiteralPath (Get-RepoFile $RelativePath))) {
        Add-Issue "Missing required file: $RelativePath"
    }
}

function Assert-Contains {
    param(
        [string]$RelativePath,
        [string]$Pattern,
        [string]$Description
    )
    $text = Read-Text $RelativePath
    if ($text -notmatch $Pattern) {
        Add-Issue "$RelativePath is missing $Description"
    }
}

function Get-YamlList {
    param(
        [string]$Text,
        [string]$Section,
        [string]$Key
    )

    $sectionPattern = "(?ms)^$([regex]::Escape($Section)):\s*(.*?)(?=^\S|\z)"
    $sectionMatch = [regex]::Match($Text, $sectionPattern)
    if (-not $sectionMatch.Success) {
        return @()
    }

    $sectionBody = $sectionMatch.Groups[1].Value
    $keyPattern = "(?ms)^\s{2}$([regex]::Escape($Key)):\s*(.*?)(?=^\s{2}\S|\z)"
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

    $leftText = ($Left -join "`n")
    $rightText = ($Right -join "`n")
    if ($leftText -ne $rightText) {
        Add-Issue "Helper drift detected in $Name"
    }
}

$requiredFiles = @(
    "README.md",
    "QUERY_SKILL_PLAN.md",
    "splunk-sentinel-query-builder/SKILL.md",
    "splunk-sentinel-query-builder/agents/openai.yaml",
    "splunk-sentinel-query-builder/agents/claude-opus.yaml",
    "splunk-sentinel-query-builder/agents/codex-gpt-5.4.yaml",
    "splunk-sentinel-query-builder/references/data-dictionary-integration.md",
    "splunk-sentinel-query-builder/references/examples-and-troubleshooting.md",
    "splunk-sentinel-query-builder/references/model-guidance.md",
    "splunk-sentinel-query-builder/references/query-workflow.md",
    "splunk-sentinel-query-builder/references/splunk-to-kql-mapping.md"
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
    if ($text -match '(?m)^(<<<<<<<|=======|>>>>>>>)') {
        Add-Issue "$file contains a conflict marker"
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

Assert-Contains "splunk-sentinel-query-builder/SKILL.md" '(?s)^---\s+name:\s+splunk-sentinel-query-builder\s+description:\s+.+?\s+---' "valid skill frontmatter"
Assert-Contains "splunk-sentinel-query-builder/SKILL.md" '## Important' "top-level Important section"
Assert-Contains "splunk-sentinel-query-builder/SKILL.md" '## Inputs' "Inputs section"
Assert-Contains "splunk-sentinel-query-builder/SKILL.md" '## Outputs' "Outputs section"

$openai = Read-Text "splunk-sentinel-query-builder/agents/openai.yaml"
foreach ($key in @("interface:", "display_name:", "short_description:", "default_prompt:", "policy:", "allow_implicit_invocation: false")) {
    if ($openai -notmatch [regex]::Escape($key)) {
        Add-Issue "agents/openai.yaml is missing $key"
    }
}

$claude = Read-Text "splunk-sentinel-query-builder/agents/claude-opus.yaml"
$codex = Read-Text "splunk-sentinel-query-builder/agents/codex-gpt-5.4.yaml"

foreach ($section in @("prompt_shape", "default_sections", "short_sections", "token_rules", "truth_order", "stop_conditions")) {
    $parent = if ($section -in @("prompt_shape")) { "invocation" } elseif ($section -in @("default_sections", "short_sections")) { "response_contract" } else { "behavior" }
    Assert-ListsEqual $section (Get-YamlList $claude $parent $section) (Get-YamlList $codex $parent $section)
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
