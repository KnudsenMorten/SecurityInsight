#Requires -Version 5.1
<#
.SYNOPSIS
    hotfix: in 's `extend Category/Subcategory = case(...)`
    blocks, wrap the VALUE-side `tostring(<col>)` in `column_ifexists` so the
    query parses even when the source column doesn't exist in this table.

.DESCRIPTION
    Live RA log showed BadRequest "Syntax Error" on Azure
    posture reports (Azure_PublicIp_OnTier01Subscription, Azure_AppService_*,
    Azure_SQL_NoAadOnly, ...). Bisect identified `| extend Category = case(`
    as the failing line.

    Root cause: generated patterns like
        | extend Category = case(
            isnotempty(tostring(column_ifexists("EG_NodeLabel", ""))), tostring(EG_NodeLabel),
            ...
        )
    `column_ifexists` makes the PREDICATE safe (returns "" if the column is
    missing). But the VALUE expression `tostring(EG_NodeLabel)` references the
    column DIRECTLY -- KQL parses the entire query before evaluating short-
    circuit branches, so an unknown column name produces a Syntax Error at
    parse time, even though the predicate would never let that branch execute.

    Fix: rewrite every `tostring(EG_NodeLabel)` (or any source-field name) on
    the value side to also use `tostring(column_ifexists("EG_NodeLabel", ""))`.
    Idempotent.
#>
[CmdletBinding()]
param(
    [string]$Yaml = (Join-Path $PSScriptRoot '..\risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'),
    [switch]$WhatIfMode
)

$raw = Get-Content -LiteralPath $Yaml -Raw

# Match lines like:
#   isnotempty(tostring(column_ifexists("EG_NodeLabel", ""))), tostring(EG_NodeLabel),
# and rewrite the second tostring(...) to tostring(column_ifexists(...)).
# Capture group 1 = the column name. Replacement preserves comma + indent.
$pattern = '(?m)(isnotempty\(tostring\(column_ifexists\("(\w+)", ""\)\)\),\s*)tostring\(\2\)'
$count = ([regex]::Matches($raw, $pattern)).Count
Write-Host ("Matches: {0}" -f $count) -ForegroundColor Cyan

if ($count -eq 0) {
    Write-Host 'Nothing to rewrite (already safe).' -ForegroundColor Green
    return
}

$new = [regex]::Replace($raw, $pattern, '$1tostring(column_ifexists("$2", ""))')

if ($WhatIfMode) {
    Write-Host '(WhatIf -- no writes)' -ForegroundColor White
    return
}
Set-Content -LiteralPath $Yaml -Value $new -Encoding UTF8 -NoNewline
Write-Host ("Rewrote {0} value-side refs to use column_ifexists." -f $count) -ForegroundColor Green
