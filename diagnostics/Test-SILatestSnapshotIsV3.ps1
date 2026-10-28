#Requires -Version 7.0
<#
    IS THE NEWEST PROFILE SNAPSHOT A v3 ONE? Check this BEFORE trusting any Risk Analysis measurement.

    🔴 WHY THIS EXISTS. Both editions write the SAME `SI_*_Profile_CL` tables, and v2.2 emits none of
    the v3 identity columns. A report that selects `CollectionTime == max(CollectionTime)` therefore
    reads v2.2 data whenever v2.2 ran last, and then filters on columns that are not there.
    Measured 2026-08-29: a v2.2 run landed at 13:00Z, `SI_Identity_Profile_CL` went from 765 rows to
    64, `SolutionVersion` was empty and `SI_AssetName`/`SI_AssetId` were 0 -- and SEVEN Identity
    reports returned ZERO findings on an otherwise successful run. Nothing failed; the run was green.

    The catalog now prefers the newest v3 snapshot (falling back to the newest of any kind, so a
    pure-v2.2 install is unaffected). This script is the human-facing precondition check: if it says
    the newest snapshot is v2.2, re-run the profilers before measuring anything, or you are measuring
    the other edition's data.

    STRICTLY READ-ONLY -- every statement is a KQL read.

    🔒 NO KEY VAULT NAME, NO TENANT VALUE, NO SPN BOOTSTRAP IN HERE. `diagnostics/` ships to the PUBLIC
    mirror and the publish-sanitization gate fails on an internal infrastructure name -- it caught an
    earlier version of this very file. Connect first, then run this; the workspace comes from config.
#>
[CmdletBinding()]
param(
    # config\SecurityInsight.custom.ps1 is GITIGNORED, so a git worktree never receives it. Default to
    # the canonical tree's copy, the same way Measure-SIv3Columns.ps1 does.
    [string] $ConfigPath = 'C:\SCRIPTS\AutomateIT\SOLUTIONS\SecurityInsight\config\SecurityInsight.custom.ps1',
    [string[]] $Tables = @('SI_Identity_Profile_CL','SI_Endpoint_Profile_CL','SI_Azure_Profile_CL')
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path $ConfigPath)) { throw "config not found: $ConfigPath" }
. $ConfigPath
$wsId = $global:SI_WorkspaceResourceId
if ([string]::IsNullOrWhiteSpace($wsId)) { throw 'SI_WorkspaceResourceId is not set in config\SecurityInsight.custom.ps1' }
. (Join-Path $PSScriptRoot '_DiagnosticsAzure.ps1')
$null = Connect-SIDiagnosticsAzure    # SPN + certificate or managed identity; see _DiagnosticsAzure.ps1

# The resource id names the workspace's subscription, so no "current subscription" is involved.
$custId = Get-SIDiagnosticsWorkspaceId -WorkspaceResourceId $wsId

Write-Host "`n=== newest profile snapshot per table -- is it v3? (read-only) ===" -ForegroundColor Cyan

$anyStale = $false
foreach ($t in $Tables) {
    # columnifexists(): a column absent from the table is exactly the condition being detected, so a
    # bare reference would fail the query instead of reporting it.
    $q = @"
let L = toscalar($t | summarize max(CollectionTime));
$t
| where CollectionTime == L
| summarize Rows = count(),
            Ver    = make_set(tostring(columnifexists('SolutionVersion','')), 5),
            SiName = countif(isnotempty(tostring(columnifexists('SI_AssetName','')))),
            SiId   = countif(isnotempty(tostring(columnifexists('SI_AssetId',''))))
| extend Snapshot = L
"@
    try {
        $rows = @(Invoke-SIDiagnosticsKql -WorkspaceId $custId -Query $q)
        if ($rows.Count -eq 0) { Write-Host ("{0,-24} no rows / table absent" -f $t) -ForegroundColor DarkYellow; continue }
        $r    = $rows[0]
        $tot  = [int]$r.Rows
        $isV3 = ($tot -gt 0 -and [int]$r.SiId -eq $tot -and [int]$r.SiName -eq $tot)
        if (-not $isV3) { $anyStale = $true }
        $colour = if ($isV3) { 'Green' } else { 'Red' }
        Write-Host ("{0,-24} {1}  rows={2,-5} SolutionVersion={3}" -f $t, $r.Snapshot, $tot, (@($r.Ver) -join ',')) -ForegroundColor $colour
        Write-Host ("{0,-24}    SI_AssetName={1}/{2}  SI_AssetId={3}/{2}  =>  {4}" -f `
            '', $r.SiName, $tot, $r.SiId, $(if ($isV3) { 'v3 snapshot' } else { 'NOT a v3 snapshot' })) -ForegroundColor $colour
    } catch {
        Write-Host ("{0,-24} QUERY FAILED: {1}" -f $t, $_.Exception.Message) -ForegroundColor Red
    }
}

Write-Host ''
if ($anyStale) {
    Write-Host 'At least one table''s newest snapshot was NOT written by v3.' -ForegroundColor Red
    Write-Host 'Re-run the profilers before measuring Risk Analysis, or you are measuring v2.2 data.' -ForegroundColor Red
    exit 1
}
Write-Host 'Every table''s newest snapshot is a v3 one -- safe to measure.' -ForegroundColor Green
exit 0
