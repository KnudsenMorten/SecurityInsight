#Requires -Version 7.0
<#
    SI v3 Phase 4 -- WHAT WILL THE OPERATOR TIER TAG ACTUALLY CLAIM, AND WHERE DOES THE ESTATE
    CONTRADICT ITSELF?

    `tenant_si_manual_tag` is the schema's ONLY `asserted` contributor and it emitted ZERO claims across
    150 assets, ~90 of which carry an `--SI` tier tag, because nothing on the production path produced
    it. Get-SITierFromAssetTags now does. This script answers, from the LIVE snapshot and BEFORE any
    engine run, two questions a unit test cannot:

      1. how many assets will now carry an asserted tag claim, and at which tiers;
      2. how many assets' OWN TAGS ask for two different tiers -- the finding MIN hides completely,
         because a T0 tag wins and nothing breaks.

    STRICTLY READ-ONLY. Every statement is a KQL read against the existing snapshot; nothing is
    published, and no engine is run.

    🪤 THE COLUMN IT READS IS NOT A v3 COLUMN, AND THAT IS DELIBERATE. `AssetTags` is shipped by `main`,
    so the nightly keeps it populated. Measuring `SI_TierClaims` instead would report zero on any day
    the nightly ran last, because only si-v3 emits it -- the trap that cost a session on 2026-08-21.

    The pattern is read from the schema contributor, not hardcoded, so this measures what the engine
    will actually do rather than what this script assumes it does.
#>
[CmdletBinding()]
param(
    # config\SecurityInsight.custom.ps1 is GITIGNORED, so a git worktree never receives it. Default to
    # the canonical tree's copy, the same way Measure-SIv3Columns.ps1 does.
    [string] $ConfigPath = 'C:\SCRIPTS\AutomateIT\SOLUTIONS\SecurityInsight\config\SecurityInsight.custom.ps1',
    [string] $Table      = 'SI_Endpoint_Profile_CL'
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path $ConfigPath)) { throw "config not found: $ConfigPath" }
. $ConfigPath
$wsId = $global:SI_WorkspaceResourceId
if ([string]::IsNullOrWhiteSpace($wsId)) { throw 'SI_WorkspaceResourceId is not set in config\SecurityInsight.custom.ps1' }
. (Join-Path $PSScriptRoot '_DiagnosticsAzure.ps1')
$null = Connect-SIDiagnosticsAzure    # SPN + certificate or managed identity; see _DiagnosticsAzure.ps1

$siRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $siRoot 'engine\asset-profiling\shared\Get-SITierAttribution.ps1')

# The pattern the ENGINE will use. Read from the merged schema so this measurement and the run agree.
$schema  = $null
try { $schema = Get-Content (Join-Path $siRoot 'asset-profiling-schema\endpoint.schema.locked.json') -Raw -Encoding UTF8 | ConvertFrom-Json } catch { }
$pattern = Get-SITierTagPatternFromSchema -Schema $schema
Write-Host ("tag pattern (from schema): {0}" -f $pattern) -ForegroundColor Cyan

# The resource id names the workspace's subscription, so no "current subscription" is involved.
$custId = Get-SIDiagnosticsWorkspaceId -WorkspaceResourceId $wsId

# Latest snapshot only. CollectionTime is identical across every shard of one execution, so this is the
# one run's view rather than a blend of several.
$kql = @"
let T = $Table | where CollectionTime == toscalar($Table | summarize max(CollectionTime));
T
| project AssetName = tostring(columnifexists('AssetName','')),
          Host      = tostring(columnifexists('HostName','')),
          Tier      = toint(columnifexists('Tier', int(null))),
          SetBy     = tostring(columnifexists('SI_TierSetBy','')),
          AssetTags = tostring(columnifexists('AssetTags',''))
"@

Write-Host "querying $Table (read-only) ..." -ForegroundColor DarkGray
$rows = @(Invoke-SIDiagnosticsKql -WorkspaceId $custId -Query $kql)
if ($rows.Count -eq 0) { Write-Warning "no rows returned from $Table"; return }

$total = $rows.Count
$claimRows = New-Object System.Collections.Generic.List[object]
foreach ($row in $rows) {
    $v = Get-SITierFromAssetTags -Tags $row.AssetTags -TagPattern $pattern
    if ($null -eq $v) { continue }
    $name = if ($row.AssetName) { $row.AssetName } elseif ($row.Host) { $row.Host } else { '(unnamed)' }
    [void]$claimRows.Add([pscustomobject]@{
        Asset        = $name
        EngineTier   = $row.Tier
        SetBy        = $row.SetBy
        TagTier      = $v.Tier
        ClaimedTiers = (@($v.ClaimedTiers) -join ',')
        Conflicting  = $v.Conflicting
        Agrees       = ("$($row.Tier)" -eq "$($v.Tier)")
        Tags         = $row.AssetTags
    })
}

$claimed     = $claimRows.Count
$conflicting = @($claimRows | Where-Object { $_.Conflicting }).Count
$disagree    = @($claimRows | Where-Object { -not $_.Agrees }).Count

Write-Host ''
Write-Host ("rows in latest snapshot ............ {0}" -f $total)
Write-Host ("assets that will carry a tag claim . {0}  ({1:P0})" -f $claimed, ($(if ($total) { $claimed / $total } else { 0 })))
Write-Host ("  ... whose OWN TAGS contradict ..... {0}  ({1:P0} of tagged)" -f $conflicting, ($(if ($claimed) { $conflicting / $claimed } else { 0 }))) -ForegroundColor $(if ($conflicting) { 'Yellow' } else { 'Gray' })
Write-Host ("  ... asserting a tier the engine did NOT give the asset: {0}" -f $disagree) -ForegroundColor $(if ($disagree) { 'Yellow' } else { 'Gray' })
Write-Host ''
Write-Host 'tag-claimed tier distribution:'
$claimRows | Group-Object TagTier | Sort-Object Name | ForEach-Object { Write-Host ("  T{0} : {1}" -f $_.Name, $_.Count) }

if ($conflicting -gt 0) {
    Write-Host ''
    Write-Host 'ASSETS WHOSE OWN TIER TAGS DISAGREE -- MIN hides every one of these:' -ForegroundColor Yellow
    $claimRows | Where-Object { $_.Conflicting } | Sort-Object TagTier, Asset |
        Format-Table Asset, EngineTier, SetBy, ClaimedTiers, Tags -AutoSize -Wrap | Out-String -Width 240 | Write-Host
}

if ($disagree -gt 0) {
    Write-Host 'ASSERTIONS THE ENGINE DID NOT ACT ON -- the operator wrote a tier down and it changed nothing:' -ForegroundColor Yellow
    $claimRows | Where-Object { -not $_.Agrees } | Sort-Object TagTier, Asset |
        Select-Object -First 25 Asset, EngineTier, SetBy, TagTier, ClaimedTiers |
        Format-Table -AutoSize | Out-String -Width 200 | Write-Host
}
