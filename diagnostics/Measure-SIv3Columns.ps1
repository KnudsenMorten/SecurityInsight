#Requires -Version 7.0
<#
    SI v3 step 1+2 VERIFICATION -- did SI_AssetId and ExposureGraphNodeId actually land as COLUMNS?

    The two columns are wired and unit-tested but, until this script returns a number, they have never
    been produced by a real engine run. A schema declaration without working derivation ships a 100%
    null column, which is indistinguishable from "the signal does not cover these assets" -- this
    codebase already carries that scar (AssetName, declared and never wired). So the only thing that
    settles it is reading the ingested rows back.

    STRICTLY READ-ONLY. Every statement is a KQL read.

    It prints CollectionTime for every table on purpose. Log Analytics ingestion lags a run by minutes,
    so a query issued too early measures the PREVIOUS snapshot and reports 0% for a column that works.
    Compare the timestamp against the run you just made before believing any percentage below.

    Also asserted: the original AssetId column is left untouched. SI_AssetId is additive by design --
    the unprefixed AssetId already means three different things across the engines and RA populates its
    own, so a change there would move a live 93.4%-populated column that consumers may bind to.
#>
[CmdletBinding()]
param(
    # config\SecurityInsight.custom.ps1 is GITIGNORED, so a git worktree never receives it. Default to
    # the canonical tree's copy, the same way Measure-SICorrelationCoverage.ps1 does.
    [string] $ConfigPath = 'C:\SCRIPTS\AutomateIT\SOLUTIONS\SecurityInsight\config\SecurityInsight.custom.ps1'
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

function Invoke-Kql {
    param([string]$Query)
    Invoke-SIDiagnosticsKql -WorkspaceId $custId -Query $Query
}

# columnifexists() rather than a bare reference: a column absent from the table is the exact failure
# this script exists to detect, and a bare reference would fail the whole query instead of reporting 0%.
function New-ColumnQuery {
    param([string]$Table)
@"
let T = $Table | where CollectionTime == toscalar($Table | summarize max(CollectionTime));
T
| extend _si  = tostring(columnifexists('SI_AssetId', ''))
| extend _eg  = tostring(columnifexists('ExposureGraphNodeId', ''))
| extend _old = tostring(columnifexists('AssetId', ''))
| extend _pk  = tostring(columnifexists('PrimaryEntityId', ''))
| summarize
    Rows            = count(),
    Snapshot        = max(CollectionTime),
    SiAssetId       = countif(isnotempty(_si)),
    SiAssetIdUniq   = dcount(_si),
    EgNodeId        = countif(isnotempty(_eg)),
    EgNodeIdUniq    = dcount(_eg),
    OldAssetId      = countif(isnotempty(_old)),
    PrimaryEntityId = countif(isnotempty(_pk))
| extend Table = '$Table'
"@
}

$tables = @('SI_Endpoint_Profile_CL','SI_Identity_Profile_CL','SI_Azure_Profile_CL','SI_PublicIP_Profile_CL')

Write-Host "`n=== SI v3  step 1+2 column verification  (read-only) ===" -ForegroundColor Cyan
Write-Host "workspace: $($wsId.Split('/')[-1])`n"

foreach ($t in $tables) {
    try {
        $rows = Invoke-Kql (New-ColumnQuery -Table $t)
        if (-not $rows -or @($rows).Count -eq 0) {
            Write-Host ("{0,-26} no rows / table absent" -f $t) -ForegroundColor DarkYellow
            continue
        }
        $r   = $rows[0]
        $tot = [int]$r.Rows
        # 0 rows must read as 0%, never 100% and never a divide-by-zero.
        $pct = { param($n) if ($tot -gt 0) { [math]::Round(100.0 * [int]$n / $tot, 1) } else { 0.0 } }

        Write-Host ("{0}" -f $t) -ForegroundColor White
        Write-Host ("  snapshot {0}   rows {1}" -f $r.Snapshot, $tot)
        Write-Host ("  SI_AssetId           {0,6}%   distinct {1}" -f (& $pct $r.SiAssetId), $r.SiAssetIdUniq) `
            -ForegroundColor $(if ([int]$r.SiAssetId -gt 0) { 'Green' } else { 'Red' })
        Write-Host ("  ExposureGraphNodeId  {0,6}%   distinct {1}" -f (& $pct $r.EgNodeId), $r.EgNodeIdUniq) `
            -ForegroundColor $(if ([int]$r.EgNodeId -gt 0) { 'Green' } else { 'Red' })
        Write-Host ("  AssetId (pre-existing, must be UNCHANGED)  {0,6}%" -f (& $pct $r.OldAssetId)) -ForegroundColor DarkGray
        Write-Host ("  PrimaryEntityId                            {0,6}%" -f (& $pct $r.PrimaryEntityId)) -ForegroundColor DarkGray

        # SI_AssetId is documented as unique per ROW, not per asset. If distinct < rows the derivation
        # is collapsing rows together, which would silently merge two assets in any downstream join.
        if ([int]$r.SiAssetId -gt 0 -and [int]$r.SiAssetIdUniq -lt $tot) {
            Write-Host ("  WARNING: SI_AssetId is not unique per row ({0} distinct over {1} rows)" -f $r.SiAssetIdUniq, $tot) -ForegroundColor Yellow
        }
        Write-Host ''
    } catch {
        Write-Host ("{0,-26} QUERY FAILED: {1}" -f $t, $_.Exception.Message) -ForegroundColor Red
    }
}
