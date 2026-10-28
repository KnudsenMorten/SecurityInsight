#Requires -Version 7.0
<#
    SI v3 PoC-0 -- LIVE coverage measurement.

    Answers the one question the whole v3 design bends around: IS CORRELATION A JOIN, OR A FUZZY
    MATCHING PROBLEM? If most assets carry hard cross-engine identifiers it is a join, and the build is
    small. If they do not, it is entity resolution with confidence thresholds and a human review queue,
    and the ticket unit, the CI-creation policy and whether auto-close is safe all change with it.

    🔒 STRICTLY READ-ONLY. Every statement below is a KQL read. Nothing is written, ingested or created.

    Counting is done SERVER-SIDE in KQL rather than by pulling rows: it is faster, moves no data, and
    avoids paging limits silently truncating the denominator -- which would flatter the result.

    🪤 Denominators are ALL rows in the latest snapshot, never "rows that carry the identifier". The
    second reads as 100% for an estate where one asset in a hundred is correlatable.
#>
[CmdletBinding()]
param(
    [string] $OutputPath,
    # config\SecurityInsight.custom.ps1 is GITIGNORED, so it exists only in the tree that was set up --
    # a git worktree does not receive ignored files. Default to the canonical tree's copy.
    [string] $ConfigPath = 'C:\SCRIPTS\AutomateIT\SOLUTIONS\SecurityInsight\config\SecurityInsight.custom.ps1'
)

$ErrorActionPreference = 'Stop'
$siRoot = Split-Path -Parent $PSScriptRoot

# ---- config + auth -------------------------------------------------------------------------------
if (-not (Test-Path $ConfigPath)) { throw "config not found: $ConfigPath" }
. $ConfigPath
$wsId = $global:SI_WorkspaceResourceId
if ([string]::IsNullOrWhiteSpace($wsId)) { throw 'SI_WorkspaceResourceId is not set in config\SecurityInsight.custom.ps1' }

. (Join-Path $PSScriptRoot '_DiagnosticsAzure.ps1')
$null = Connect-SIDiagnosticsAzure    # SPN + certificate or managed identity; see _DiagnosticsAzure.ps1

# Resolve the workspace CustomerId directly rather than dot-sourcing the RA query stack -- that stack
# pulls in engine helpers this PoC has no other need for, and a missing one fails every query at once.
# The resource id names the workspace's subscription, so no "current subscription" is involved.
$custId = Get-SIDiagnosticsWorkspaceId -WorkspaceResourceId $wsId

function Invoke-Kql {
    param([string]$Query)
    Invoke-SIDiagnosticsKql -WorkspaceId $custId -Query $Query
}

# EntityIds is dynamic and may serialise as a JSON string; todynamic() handles both.
# 'EgNodeId' and 'ExposureGraphNodeId' are the same fact under two spellings -- counting only one
# would UNDER-report graph coverage, which is the number the architecture turns on.
function New-CoverageQuery {
    param([string]$Table)
@"
let T = $Table | where CollectionTime == toscalar($Table | summarize max(CollectionTime));
let total = toscalar(T | count);
T
| extend _e = todynamic(EntityIds)
| mv-apply _x = _e on (
    summarize
        eg   = countif(tostring(_x.type) in~ ('EgNodeId','ExposureGraphNodeId')),
        az   = countif(tostring(_x.type) =~ 'AzureResourceId'),
        mde  = countif(tostring(_x.type) =~ 'MdeDeviceId'),
        aad  = countif(tostring(_x.type) =~ 'AadDeviceId'),
        adg  = countif(tostring(_x.type) =~ 'ActiveDirectoryObjectGuid'),
        sid  = countif(tostring(_x.type) =~ 'SecurityIdentifier'),
        host = countif(tostring(_x.type) =~ 'Hostname')
  )
| summarize
    RowsWithEgNode   = countif(eg   > 0),
    RowsWithAzureId  = countif(az   > 0),
    RowsWithMdeId    = countif(mde  > 0),
    RowsWithAadId    = countif(aad  > 0),
    RowsWithAdGuid   = countif(adg  > 0),
    RowsWithSid      = countif(sid  > 0),
    RowsWithHostname = countif(host > 0)
| extend Table = '$Table', Total = total
"@
}

$tables = @('SI_Endpoint_Profile_CL','SI_Identity_Profile_CL','SI_Azure_Profile_CL','SI_PublicIP_Profile_CL')
$report = New-Object System.Collections.ArrayList

Write-Host "`n=== PoC-0  CORRELATION COVERAGE  (read-only) ===" -ForegroundColor Cyan
Write-Host "workspace: $($wsId.Split('/')[-1])`n"

foreach ($t in $tables) {
    try {
        $rows = Invoke-Kql (New-CoverageQuery -Table $t)
        if (-not $rows -or @($rows).Count -eq 0) { Write-Host ("{0,-26} no rows / table absent" -f $t) -ForegroundColor DarkYellow; continue }
        $r = $rows[0]
        $tot = [int]$r.Total
        # 🪤 0 rows must read as 0%, never 100% and never a divide-by-zero.
        $pct = { param($n) if ($tot -gt 0) { [math]::Round(100.0 * [int]$n / $tot, 1) } else { 0.0 } }
        $o = [pscustomobject]@{
            Table       = $t
            Rows        = $tot
            EgNodePct   = & $pct $r.RowsWithEgNode
            AzureIdPct  = & $pct $r.RowsWithAzureId
            MdeIdPct    = & $pct $r.RowsWithMdeId
            AadIdPct    = & $pct $r.RowsWithAadId
            AdGuidPct   = & $pct $r.RowsWithAdGuid
            SidPct      = & $pct $r.RowsWithSid
            HostnamePct = & $pct $r.RowsWithHostname
        }
        [void]$report.Add($o)
        Write-Host ("{0,-26} rows={1,-7} EG={2,5}%  AzId={3,5}%  MdeId={4,5}%  AdGuid={5,5}%  SID={6,5}%  Host={7,5}%" -f `
            $t, $tot, $o.EgNodePct, $o.AzureIdPct, $o.MdeIdPct, $o.AdGuidPct, $o.SidPct, $o.HostnamePct)
    } catch {
        Write-Host ("{0,-26} QUERY FAILED: {1}" -f $t, $_.Exception.Message) -ForegroundColor Red
    }
}

# ---- the decisive number: can endpoint and azure rows actually be JOINED? --------------------------
Write-Host "`n--- cross-engine overlap (the number that decides the architecture) ---" -ForegroundColor Cyan
$overlapQ = @"
let EP = SI_Endpoint_Profile_CL | where CollectionTime == toscalar(SI_Endpoint_Profile_CL | summarize max(CollectionTime));
let AZ = SI_Azure_Profile_CL    | where CollectionTime == toscalar(SI_Azure_Profile_CL    | summarize max(CollectionTime));
let epKeys = EP | extend _e = todynamic(EntityIds)
  | mv-apply _x = _e on (summarize az = make_set_if(tolower(tostring(_x.id)), tostring(_x.type) =~ 'AzureResourceId'))
  | mv-expand k = az to typeof(string) | where isnotempty(k) | distinct k;
let azKeys = AZ | extend k = tolower(tostring(AzureResourceId)) | where isnotempty(k) | distinct k;
let epTotal = toscalar(EP | count);
let azTotal = toscalar(AZ | count);
let shared  = toscalar(epKeys | join kind=inner azKeys on k | count);
print EndpointRows = epTotal, AzureRows = azTotal,
      EndpointCarryingAzureId = toscalar(epKeys | count),
      AzureCarryingAzureId    = toscalar(azKeys | count),
      SharedAzureResourceIds  = shared
"@
try {
    $ov = Invoke-Kql $overlapQ
    if ($ov -and @($ov).Count -gt 0) {
        $o = $ov[0]
        $epTot = [int]$o.EndpointRows
        $sharePct = if ($epTot -gt 0) { [math]::Round(100.0 * [int]$o.SharedAzureResourceIds / $epTot, 1) } else { 0.0 }
        Write-Host ("endpoint rows           : {0}" -f $o.EndpointRows)
        Write-Host ("azure rows              : {0}" -f $o.AzureRows)
        Write-Host ("endpoint carrying AzId  : {0}" -f $o.EndpointCarryingAzureId)
        Write-Host ("azure carrying AzId     : {0}" -f $o.AzureCarryingAzureId)
        Write-Host ("SHARED AzureResourceIds : {0}   ({1}% of all endpoint rows)" -f $o.SharedAzureResourceIds, $sharePct) -ForegroundColor Yellow
        [void]$report.Add([pscustomobject]@{ Table='<cross-engine>'; Rows=$epTot; SharedAzureResourceIds=[int]$o.SharedAzureResourceIds; SharedPctOfEndpoint=$sharePct })
    }
} catch { Write-Host "overlap query FAILED: $($_.Exception.Message)" -ForegroundColor Red }

# ---- a1b: can RA findings reach an asset at all? ---------------------------------------------------
Write-Host "`n--- RA findings: do they carry a stable asset id? (gap a1b) ---" -ForegroundColor Cyan
foreach ($raTable in @('SI_RiskAnalysis_Summary_CL','SI_RiskAnalysis_Detailed_CL')) {
    $q = @"
let R = $raTable | where CollectionTime == toscalar($raTable | summarize max(CollectionTime));
R | summarize Rows = count(),
    WithAssetName = countif(isnotempty(column_ifexists('AssetName','' ))),
    WithMdeId     = countif(isnotempty(column_ifexists('MdeDeviceId','' ))),
    WithAzureId   = countif(isnotempty(column_ifexists('AzureResourceId','' ))),
    WithEntraId   = countif(isnotempty(column_ifexists('EntraAccountObjectId','' )))
"@
    try {
        $rr = Invoke-Kql $q
        if ($rr -and @($rr).Count -gt 0) {
            $r = $rr[0]; $tot = [int]$r.Rows
            $p = { param($n) if ($tot -gt 0) { [math]::Round(100.0 * [int]$n / $tot, 1) } else { 0.0 } }
            Write-Host ("{0,-30} rows={1,-7} AssetName={2,5}%  MdeId={3,5}%  AzId={4,5}%  EntraId={5,5}%" -f `
                $raTable, $tot, (& $p $r.WithAssetName), (& $p $r.WithMdeId), (& $p $r.WithAzureId), (& $p $r.WithEntraId))
            [void]$report.Add([pscustomobject]@{ Table=$raTable; Rows=$tot
                AssetNamePct=(& $p $r.WithAssetName); MdeIdPct=(& $p $r.WithMdeId)
                AzureIdPct=(& $p $r.WithAzureId); EntraIdPct=(& $p $r.WithEntraId) })
        }
    } catch { Write-Host ("{0,-30} QUERY FAILED: {1}" -f $raTable, $_.Exception.Message) -ForegroundColor Red }
}

if ($OutputPath) {
    $report | ConvertTo-Json -Depth 5 | Set-Content -Path $OutputPath -Encoding utf8
    Write-Host "`nwritten: $OutputPath"
}
Write-Host ""
