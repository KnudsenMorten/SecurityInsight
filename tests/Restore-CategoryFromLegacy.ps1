#Requires -Version 5.1
<#
.SYNOPSIS
    Restore Category / Subcategory `extend` lines from the legacy
    v2.1 YAML into matching v2.2 reports. Replaces 's platform-pull
    case() blocks (which read from wrong fields like `DeviceCategory` and
    `IdentityType`) with the v2.1-vintage author intent.

.DESCRIPTION
    Mining strategy:
      1. Parse the legacy YAML at v2.2/legacy/risk-analysis/...legacy.yaml
      2. For each `- ReportName:` block, capture the LAST `| extend Category = ...`
         and `| extend Subcategory = ...` lines that appear in the ReportQuery
         (the rightmost extend wins per KQL last-extend-wins semantics).
      3. Match to v2.2 by stripping `_BucketFilter` / `_Detailed_BucketFilter`
         suffix and pairing legacy `_Summary_BucketFilter` with v2.2 `_Summary`,
         legacy `_Detailed_BucketFilter` with v2.2 `_Detailed`.
      4. In v2.2 YAML, REPLACE the platform-pull
         `| extend Category = case(...)` block with the legacy literal/dynamic
         line. Same for Subcategory.

    Idempotent: a report whose v2.2 query already contains a non-platform-pull
    extend Category gets left alone. Reports without a legacy match are listed
    so the operator can hand-author.
#>
[CmdletBinding()]
param(
    [string]$Legacy = (Join-Path $PSScriptRoot '..\legacy\risk-analysis\RiskAnalysis_Queries_Locked_legacy.yaml'),
    [string]$V22    = (Join-Path $PSScriptRoot '..\risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'),
    [switch]$WhatIfMode
)

# ---------- 1. Parse legacy: ReportName -> @{Category, Subcategory} ----------
$legacyRaw = Get-Content -LiteralPath $Legacy -Raw
# Legacy uses 4-space indented `- ReportName:` under `ReportTemplates:`.
# Split on those report boundaries.
$legacyBlocks = [regex]::Split($legacyRaw, '(?m)(?=^\s+- ReportName:)')

$legacyTbl = @{}
foreach ($b in $legacyBlocks) {
    if ($b -notmatch 'ReportName:') { continue }
    $name = if ($b -match '- ReportName:\s*(\S+)') { $matches[1] } else { continue }

    # Capture the LAST `| extend Category = <expr>` -- supports either
    # static literal `"foo"` or dynamic `tostring(<source>)` or the `=` line
    # may continue onto the next line (Subcategory often does this for the
    # comma-separated dynamic-from-source list). Use a non-greedy lazy match
    # bounded by the next pipeline-operator line.
    $catLine = $null
    foreach ($m in [regex]::Matches($b, '(?m)^\s*\|\s*extend\s+Category\s*=\s*[^\r\n]+(?:\r?\n\s+[^\r\n|]+)*')) {
        $catLine = $m.Value.Trim()
    }
    $subLine = $null
    foreach ($m in [regex]::Matches($b, '(?m)^\s*\|\s*extend\s+Subcategory\s*=\s*[^\r\n]+(?:\r?\n\s+[^\r\n|]+)*')) {
        $subLine = $m.Value.Trim()
    }

    if ($catLine -or $subLine) {
        $legacyTbl[$name] = @{ Category = $catLine; Subcategory = $subLine }
    }
}
Write-Host ("Parsed legacy: {0} reports with Category/Subcategory extends" -f $legacyTbl.Count) -ForegroundColor Cyan

# ---------- 2. Build legacy-name -> v2.2-name mapping ----------
# Legacy: Device_Missing_CVEs_Summary_BucketFilter
# v2.2:   Device_Missing_CVEs_Summary
# Legacy: ..._Detailed_BucketFilter
# v2.2:   ..._Detailed
function Convert-LegacyNameToV22 {
    param([string]$Name)
    return ($Name -replace '_BucketFilter$', '')
}

# ---------- 3. Process v2.2 reports ----------
$v22Raw = Get-Content -LiteralPath $V22 -Raw
$v22Blocks = [regex]::Split($v22Raw, '(?m)(?=^- ReportName:)')

$rewritten = 0
$skipped   = 0
$noLegacy  = New-Object System.Collections.Generic.List[string]
$out = New-Object System.Collections.Generic.List[string]

foreach ($block in $v22Blocks) {
    if ($block -notmatch 'ReportName:') { $out.Add($block); continue }
    $name = if ($block -match '- ReportName:\s*(\S+)') { $matches[1] } else { '' }
    $sd   = if ($block -match '(?m)^\s*SecurityDomain:\s*(\S+)') { $matches[1] } else { '' }

    # Naming convention drift between legacy and v2.2:
    #   v2.2 `*_Summary`              -> legacy `*_Summary` OR `*_Summary_BucketFilter`
    #   v2.2 `*_Summary_Detailed`     -> legacy `*_Detailed` OR `*_Detailed_BucketFilter`
    #   v2.2 `*_Detailed` (no Summary)-> legacy `*_Detailed_BucketFilter`
    #   v2.2 `Attack_Paths_Summary_X` -> legacy `Attack_Paths_Summary_BucketFilter_X`
    #   v2.2 `Attack_Paths_Summary_X_Detailed` -> legacy `Attack_Paths_Detailed_BucketFilter_X`
    $cands = New-Object System.Collections.Generic.List[string]
    [void]$cands.Add($name)
    [void]$cands.Add($name + '_BucketFilter')
    if ($name -match '_Summary_Detailed$') {
        $base = $name -replace '_Summary_Detailed$', '_Detailed'
        [void]$cands.Add($base)
        [void]$cands.Add($base + '_BucketFilter')
    }
    if ($name -match '^Attack_Paths_Summary_(.+)_Detailed$') {
        [void]$cands.Add("Attack_Paths_Detailed_BucketFilter_$($matches[1])")
    } elseif ($name -match '^Attack_Paths_Summary_(.+)$') {
        [void]$cands.Add("Attack_Paths_Summary_BucketFilter_$($matches[1])")
    }
    $legacyName = $null
    foreach ($candidate in $cands) {
        if ($legacyTbl.ContainsKey($candidate)) { $legacyName = $candidate; break }
    }
    if (-not $legacyName) {
        $noLegacy.Add($name) | Out-Null
        $out.Add($block); $skipped++
        continue
    }

    $cat = $legacyTbl[$legacyName].Category
    $sub = $legacyTbl[$legacyName].Subcategory
    $newBlock = $block

    # Replace the platform-pull `extend Category = case(...)` (multi-line)
    # with the legacy line. Pattern: starts with `| extend Category = case(`,
    # ends with `, "")` on its own line.
    if ($cat) {
        $catCasePat = '(?ms)^\s*\|\s*extend\s+Category\s*=\s*case\(.*?,\s*\r?\n\s*""\)\r?\n'
        if ([regex]::IsMatch($newBlock, $catCasePat)) {
            $indent = '            '   # match the v2.2 query's 12-space body indent
            $newBlock = [regex]::Replace($newBlock, $catCasePat, ($indent + $cat + "`r`n"), 1)
        }
    }
    if ($sub) {
        $subCasePat = '(?ms)^\s*\|\s*extend\s+Subcategory\s*=\s*case\(.*?,\s*\r?\n\s*""\)\r?\n'
        if ([regex]::IsMatch($newBlock, $subCasePat)) {
            $indent = '            '
            $newBlock = [regex]::Replace($newBlock, $subCasePat, ($indent + $sub + "`r`n"), 1)
        }
    }

    if ($newBlock -ne $block) { $rewritten++ }
    $out.Add($newBlock)
}

Write-Host ("Rewritten: {0}  Skipped (no legacy match): {1}" -f $rewritten, $skipped) -ForegroundColor Cyan
if ($noLegacy.Count -gt 0) {
    Write-Host '--- v2.2 reports with NO legacy source (need manual Category/Subcategory authoring) ---' -ForegroundColor Yellow
    $noLegacy | Sort-Object | Format-Table | Out-String -Width 200 | Write-Host
}

if ($WhatIfMode) {
    Write-Host '(WhatIf -- no writes)' -ForegroundColor White
    return
}
Set-Content -LiteralPath $V22 -Value ($out -join '') -Encoding UTF8 -NoNewline
Write-Host 'YAML rewritten in place.' -ForegroundColor Green
