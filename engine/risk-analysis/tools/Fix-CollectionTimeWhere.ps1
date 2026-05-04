#Requires -Version 5.1
<#
.SYNOPSIS
    One-time transformation of every Risk Analysis KQL to use latest-CollectionTime
    PER ASSET (instead of one global max).

.DESCRIPTION
    Background: tier-driven cadence gives each asset its own
    CollectionTime depending on its tier (T0=12h, T1=24h, T2=3d, T3=7d). The
    pre-query pattern:

        let _t = toscalar(<TABLE> | summarize max(CollectionTime));
        <TABLE>
        | where CollectionTime == _t

    picks ONE global max -- which is whatever the most recent T0 run's stamp
    is. Every T1/T2/T3 row whose CollectionTime is older than that gets
    silently dropped from the report.

    This transform replaces the let-block with:

        <TABLE>
        | where TimeGenerated > ago(8d)
        | summarize arg_max(CollectionTime, *) by PrimaryEntityId

    `arg_max(CollectionTime, *) by PrimaryEntityId` returns the latest snapshot
    of EACH asset, regardless of when its tier-cadence last fired. The 8-day
    `ago(8d)` window matches T3's max staleness + 1d safety buffer.

    Files updated:
      * v2.2/risk-analysis-detection/RiskAnalysis_Queries_Locked.yaml
      * v2.2/risk-analysis-detection/RiskAnalysis_Queries_Custom.yaml (if tracked)
      * v2.2/engine/risk-analysis/_source/*.yaml (authoring inputs -- so future
        Build-RiskAnalysis.ps1 consolidations stay correct)

    Reports each rewritten match (file, line, before/after snippet).
#>

[CmdletBinding()]
param(
    [Parameter()][string]$RiskAnalysisDir = (Join-Path $PSScriptRoot '..'),
    [Parameter()][switch]$WhatIf,
    [Parameter()][string[]]$Targets = @('locked','custom','_source')
)

$ErrorActionPreference = 'Stop'
$RiskAnalysisDir = (Resolve-Path -LiteralPath $RiskAnalysisDir).Path

# Match the let-block + table + where-_t pattern. Multi-line; tolerant of any
# table name and any indentation prefix. Captures the leading indent so the
# replacement preserves it.
#
# Group 1 = leading indent of the `let _t` line (e.g. "    " -- 4 spaces inside
#           a YAML | block scalar, or whatever the file uses)
# Group 2 = table name (SI_Endpoint_Profile_CL etc.)
$pattern = '(?ms)^(\s*)let _t = toscalar\(\s*([A-Za-z][A-Za-z0-9_]*)\s*\|\s*summarize\s+max\(CollectionTime\)\s*\)\s*;\s*\r?\n\s*\2\s*\r?\n\s*\|\s*where\s+CollectionTime\s*==\s*_t\s*\r?\n'

function _Transform([string]$content) {
    return ([regex]::Replace($content, $pattern, {
        param($m)
        $indent = $m.Groups[1].Value
        $table  = $m.Groups[2].Value
        # New 3-line block. Same indent as the original.
        return ('{0}{1}{2}| where TimeGenerated > ago(8d){2}| summarize arg_max(CollectionTime, *) by PrimaryEntityId{3}' -f `
            $indent, $table, ([Environment]::NewLine + $indent), [Environment]::NewLine)
    }, [System.Text.RegularExpressions.RegexOptions]::Multiline))
}

function _ProcessFile([string]$path) {
    if (-not (Test-Path -LiteralPath $path)) { return }
    $raw = [System.IO.File]::ReadAllText($path)
    $matchCount = ([regex]::Matches($raw, $pattern)).Count
    if ($matchCount -eq 0) { return }
    $new = _Transform $raw
    if ($WhatIf) {
        Write-Host ('  [WhatIf] {0} -- {1} match(es) would be rewritten' -f $path, $matchCount)
    } else {
        [System.IO.File]::WriteAllText($path, $new, (New-Object System.Text.UTF8Encoding($false)))
        Write-Host ('  rewrote {0} match(es) in {1}' -f $matchCount, $path)
    }
    return $matchCount
}

$total = 0
foreach ($target in $Targets) {
    $dir = Join-Path $RiskAnalysisDir $target
    if (-not (Test-Path -LiteralPath $dir)) {
        Write-Host ('[skip] {0} not found' -f $dir)
        continue
    }
    Write-Host ('[{0}] processing {1}' -f $target, $dir)
    $files = Get-ChildItem -Path $dir -Filter '*.yaml' -Recurse -File
    foreach ($f in $files) {
        $n = _ProcessFile -path $f.FullName
        if ($n) { $total += $n }
    }
}

Write-Host ''
Write-Host ('Total replacements: {0}' -f $total)
