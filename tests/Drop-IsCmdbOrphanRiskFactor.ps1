#Requires -Version 5.1
<#
.SYNOPSIS
    drop IsCmdbOrphan as a risk factor across all RA queries.

.DESCRIPTION
    Per user 2026-04-30: IsCmdbOrphan is not a risk factor for the RA engine.
    Stays as a profile-time field on Endpoint/Identity/Azure Profile rows
    (still useful for hygiene queries / dashboards), just stops contributing
    to RiskFactor_Probability + RiskFactor_Probability_Detailed.

    Patterns rewritten:
      - "+ toint(iff(...IsCmdbOrphan..., 1, 0))" -> ""  (when added to others)
      - lone "toint(iff(...IsCmdbOrphan..., 1, 0))" -> "0"  (when only factor)
      - "..., iff(...IsCmdbOrphan..., 'IsCmdbOrphan', '')" -> ""  (trailing in pack_array)
      - "pack_array(iff(...IsCmdbOrphan..., '...', ''))" -> "pack_array()"
      - gold-template (Device_Recommendations): drop RF_P_CmdbOrphan factor
    Also drops IsCmdbOrphan from perEngineFields in
    risk-analysis-detection/riskscore_weighted.schema.custom.json
    so the consolidator stops re-emitting it.

    Idempotent.
#>
[CmdletBinding()]
param(
    [string]$Yaml = (Join-Path $PSScriptRoot '..\risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'),
    [string]$WeightedSchema = (Join-Path $PSScriptRoot '..\risk-analysis-detection\riskscore_weighted.schema.custom.json'),
    [switch]$WhatIfMode
)

$total = 0

# ---------------------------------------------------------------------------
# 1) Rewrite the deployed RA queries yaml
# ---------------------------------------------------------------------------
$y    = Get-Content -LiteralPath $Yaml -Raw
$orig = $y

# Pattern A: " + toint(iff(...IsCmdbOrphan..., 1, 0))" -- drop trailing additive term
$y = $y -replace ' \+ toint\(iff\(tobool\(column_ifexists\("IsCmdbOrphan", false\)\) == true, 1, 0\)\)', ''

# Pattern B: lone "toint(iff(...IsCmdbOrphan..., 1, 0))" -- only factor -> 0
$y = $y -replace 'toint\(iff\(tobool\(column_ifexists\("IsCmdbOrphan", false\)\) == true, 1, 0\)\)', '0'

# Pattern C: ", iff(...IsCmdbOrphan...)" trailing in pack_array -- drop
$y = $y -replace ', iff\(tobool\(column_ifexists\("IsCmdbOrphan", false\)\) == true, "IsCmdbOrphan", ""\)', ''

# Pattern D: pack_array(iff(...IsCmdbOrphan...)) -- drop the only entry
$y = $y -replace 'pack_array\(iff\(tobool\(column_ifexists\("IsCmdbOrphan", false\)\) == true, "IsCmdbOrphan", ""\)\)', 'pack_array()'

# Pattern E (gold-template Device_Recommendations): drop RF_P_CmdbOrphan factor
# - the iff() definition line
$y = $y -replace '(?m)^\s*\| extend RF_P_CmdbOrphan\s+= iff\(IsCmdbOrphan == true, 1, 0\)\r?\n', ''
# - the additive term inside RiskFactor_Probability
$y = $y -replace ' \+ RF_P_CmdbOrphan', ''
# - the array_concat entry inside RiskFactor_Probability_Detailed (one of 4 lines)
$y = $y -replace ',\r?\n\s*iff\(RF_P_CmdbOrphan\s+== 1, dynamic\(\["IsCmdbOrphan"\]\),\s+dynamic\(\[\]\)\)', ''

# Pattern F: trailing IsCmdbOrphan entry in Flags-style strcat label string
# strcat(..., iff(IsCmdbOrphan==true,"CmdbOrphan ", "")) -- drop the trailing entry
$y = $y -replace ',\r?\n\s*iff\(IsCmdbOrphan==true,"CmdbOrphan ", ""\)\)', ')'

if ($y -ne $orig) {
    if (-not $WhatIfMode) { Set-Content -LiteralPath $Yaml -Value $y -Encoding UTF8 -NoNewline }
    $diff = ([regex]::Matches($orig, 'IsCmdbOrphan').Count - [regex]::Matches($y, 'IsCmdbOrphan').Count)
    Write-Host ("[yaml] dropped {0} IsCmdbOrphan refs ({1} remain)" -f $diff, ([regex]::Matches($y, 'IsCmdbOrphan').Count)) -ForegroundColor Cyan
    $total += $diff
} else {
    Write-Host '[yaml] no changes (already clean)' -ForegroundColor White
}

# ---------------------------------------------------------------------------
# 2) Drop IsCmdbOrphan from perEngineFields in the weighted-score schema
# ---------------------------------------------------------------------------
$j    = Get-Content -LiteralPath $WeightedSchema -Raw
$jOrig = $j
$j = $j -replace '"IsExternalIdentity",\s*"IsCmdbOrphan"', '"IsExternalIdentity"'
$j = $j -replace '"IsStaleAsset",\s*"IsCmdbOrphan"',      '"IsStaleAsset"'
$j = $j -replace '"azure":\s*\["IsCmdbOrphan"\]',         '"azure":     []'
# Update the comment too so it's accurate
$j = $j -replace 'IsCmdbOrphan = audit, ',               ''

if ($j -ne $jOrig) {
    if (-not $WhatIfMode) { Set-Content -LiteralPath $WeightedSchema -Value $j -Encoding UTF8 -NoNewline }
    Write-Host '[schema] dropped IsCmdbOrphan from perEngineFields' -ForegroundColor Cyan
    $total++
} else {
    Write-Host '[schema] no changes' -ForegroundColor White
}

Write-Host ''
Write-Host ("Total occurrences removed: {0}" -f $total) -ForegroundColor Green
if ($WhatIfMode) { Write-Host '(WhatIf -- no writes)' -ForegroundColor White }
