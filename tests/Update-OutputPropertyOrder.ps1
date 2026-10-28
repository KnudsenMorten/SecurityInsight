#Requires -Version 5.1
<#
.SYNOPSIS
    rewrite every report's OutputPropertyOrder block in the
    locked YAML to the canonical 20-column set, preserving any report-specific
    extras AFTER the canonical columns.

.DESCRIPTION
    Canonical column set (user-finalized, 2026-04-30):
      SecurityDomain, Category, Subcategory, ConfigurationName, ConfigurationId,
      Impact, SecuritySeverity, CriticalityTier, CriticalityTierLevel,
      RiskFactor_Consequence, RiskFactor_Probability, RiskFactor_Probability_Detailed,
      RiskFactor_Weight, RiskConsequenceScore, RiskProbabilityScore,
      RiskScoreTotal, RiskScoreTotal_Weighted, AssetCount, TotalIssues, ImpactedAssets

    Each report keeps any extra columns it had (e.g. AppHttpAllowed,
    EdgeLabel, SourceNodeName, TargetNodeName) -- they slot in AFTER the
    canonical 20 so the engine + downstream consumers see a stable shape.
#>
[CmdletBinding()]
param(
    [string]$Yaml = (Join-Path $PSScriptRoot '..\risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'),
    [switch]$WhatIfMode
)

$canonical = @(
    'SecurityDomain'
    'Category'
    'Subcategory'
    'ConfigurationName'
    'ConfigurationId'
    'Impact'
    'SecuritySeverity'
    'CriticalityTier'
    'CriticalityTierLevel'
    'RiskFactor_Consequence'
    'RiskFactor_Probability'
    'RiskFactor_Probability_Detailed'
    'RiskFactor_Weight'
    'RiskConsequenceScore'
    'RiskProbabilityScore'
    'RiskScoreTotal'
    'RiskScoreTotal_Weighted'
    'AssetCount'
    'TotalIssues'
    'Issues_Details'
    'ImpactedAssets'
)

$content = Get-Content -LiteralPath $Yaml -Raw

# Match every "OutputPropertyOrder:" block: starts with two spaces + key, then
# 1+ lines of "  - <name>" until a non-list line. Capture the items.
# Single-line regex with greedy match would over-capture; use a lookahead for the
# "next non-list line" terminator.
$pattern = '(?ms)(^  OutputPropertyOrder:\r?\n)((?:  - [^\r\n]+\r?\n)+)'
$count = 0
$skipped = 0

$updated = [regex]::Replace($content, $pattern, {
    param($m)
    $script:count++

    # Extract existing items
    $items = @()
    foreach ($line in $m.Groups[2].Value -split "`r?`n") {
        if ($line -match '^  - (.+)$') { $items += $matches[1].Trim() }
    }

    # Extras = items not in canonical
    $extras = @($items | Where-Object { $_ -notin $canonical })

    # Build new block: canonical 20, then extras (preserving original order among extras)
    $merged = @($canonical) + $extras

    $newBlock = ($merged | ForEach-Object { "  - $_" }) -join "`r`n"
    return $m.Groups[1].Value + $newBlock + "`r`n"
})

Write-Host ("Reports updated: {0}" -f $count) -ForegroundColor Cyan

if ($WhatIfMode) {
    Write-Host '(WhatIf mode -- no writes)' -ForegroundColor White
    # Show diff sample for the first 2 changed reports
    $orig = $content -split "`r?`n"
    $new  = $updated -split "`r?`n"
    $changes = 0
    for ($i = 0; $i -lt [Math]::Min($orig.Count, $new.Count); $i++) {
        if ($orig[$i] -ne $new[$i] -and $changes -lt 30) {
            Write-Host ("L{0}:" -f ($i+1)) -ForegroundColor Cyan
            Write-Host ("- " + $orig[$i]) -ForegroundColor Red
            Write-Host ("+ " + $new[$i]) -ForegroundColor Green
            $changes++
        }
    }
    return
}

Set-Content -LiteralPath $Yaml -Value $updated -Encoding UTF8 -NoNewline
Write-Host 'YAML rewritten in place.' -ForegroundColor Green
