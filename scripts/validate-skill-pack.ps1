param(
    [string]$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
)

$ErrorActionPreference = "Stop"
$issues = New-Object System.Collections.Generic.List[string]

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
    $sectionValue = Get-MapValue $Document $Section
    if ($null -eq $sectionValue) {
        return $null
    }
    $keyValue = Get-MapValue $sectionValue $Key
    if ($null -eq $keyValue) {
        return $null
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
    "splunk-data-dictionary-builder/tests/test_build_splunk_dictionary.py",
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

foreach ($skill in @("splunk-sentinel-query-builder", "splunk-data-dictionary-builder", "splunk-enrichment-query-builder")) {
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
foreach ($skill in @("splunk-sentinel-query-builder", "splunk-data-dictionary-builder", "splunk-enrichment-query-builder")) {
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
