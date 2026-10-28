#Requires -Version 5.1
<#
.SYNOPSIS
    Inventories every Risk Analysis report (REQUIREMENTS #505): what each report reads about the ASSET, which risk-factor
    flags it computes, which joins it uses and which provider (finding) tables it reads -- and maps each asset column to
    an SI field (data-model/field-catalog.locked.json) and each RF flag to a factor (data-model/risk-factors.locked.json).

.DESCRIPTION
    Read-only. Parses risk-analysis-detection/RiskAnalysis_Queries_Locked.yaml with SecurityInsight's own YAML reader (no
    modules). The mapping of a legacy asset column to its SI field comes from risk-analysis-detection/
    ra-ci-migration.locked.json (columnMap); an RF flag maps through the factor catalog's legacyTokens.

    Per report:
      ProfileTables    SI_<x>_Profile_CL tables read (must be none after the migration, D14)
      ReadsCi          the report reads SI_CI_CL
      CiBlocks         the canonical CI blocks it carries (link / asset)
      AssetColumns     legacy profile columns the query names (profile-schema field names found in the query)
      SiFields         si_* fields the query names
      RfFlags          RF_P_* / RF_C_* flags it computes, each with its factor id ('' = not in the catalog)
      RfFromCi         RF flags computed from si_rf_p / si_rf_c (the CI's factors)
      Joins            the join keys ($left.X == $right.Y / on X)
      NameJoins        joins on a name or on AadDeviceId (forbidden after the migration outside the graph-only list)
      ProviderTables   provider tables read (finding side)
      GraphOnly        listed as graph-only in ra-ci-migration.locked.json (with its reason)

.PARAMETER OutJson   write the inventory as JSON here (default: print a summary)
.EXAMPLE
    .\tools\ra-ci\Get-RaReportInventory.ps1 -OutJson $env:TEMP\ra-inventory.json
#>
[CmdletBinding()]
param(
    [string]$YamlPath,
    [string]$OutJson,
    [switch]$PassThru
)
$ErrorActionPreference = 'Stop'
$siRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not $YamlPath) { $YamlPath = Join-Path $siRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml' }
. (Join-Path $siRoot 'engine\_shared\SI-Yaml.ps1')
. (Join-Path $siRoot 'engine\risk-analysis\_shared\RA-CiKql.ps1')

function Get-RaInvStripped {
    <# PURE. KQL with // comments and string literals removed (identifiers only). #>
    param([string]$Kql)
    $s = [regex]::Replace($Kql, '(?m)//[^\r\n]*', '')
    $s = [regex]::Replace($s, '@?"(?:[^"\\\r\n]|\\.)*"', '""')
    $s = [regex]::Replace($s, "@?'(?:[^'\\\r\n]|\\.)*'", "''")
    return $s
}

function Get-RaReportInventory {
    <# PURE over its inputs. Returns one object per report. #>
    param(
        [Parameter(Mandatory)][object[]]$Reports,
        [Parameter(Mandatory)][string[]]$ProfileColumns,
        [Parameter(Mandatory)][object[]]$Factors,
        [Parameter(Mandatory)]$Migration
    )
    $tok = @{}
    foreach ($f in $Factors) { foreach ($t in @($f.legacyTokens)) { if ($t) { $tok[[string]$t] = [string]$f.id } } }
    $profSet = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach ($c in $ProfileColumns) { if ($c) { [void]$profSet.Add($c) } }
    # the report OUTPUT columns (kept names, filled from the CI) and provider columns are not asset reads
    $outputOnly = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach ($c in 'AssetId', 'AssetName', 'AssetType', 'cmdbId', 'cmdbName', 'cmdbCriticality', 'cmdbDataSensitivity', 'MdeDeviceId', 'EntraAccountObjectId', 'AzureResourceId') { [void]$outputOnly.Add($c) }
    foreach ($p in @($Migration.columnMap.PSObject.Properties)) { if ([string]$p.Value.si -eq 'provider') { [void]$outputOnly.Add($p.Name) } }
    $graphOnly = @{}
    foreach ($g in @($Migration.graphOnly)) { $graphOnly[[string]$g.report] = [string]$g.reason }
    $providerRx = '\b(ExposureGraph(?:Nodes|Edges)|DeviceTvm\w+|DeviceInfo|DeviceNetworkInfo|Device\w*Events|SecurityRecommendation|SecurityAssessment|SecurityResources|IdentityInfo|IdentityLogonEvents|AADSignInEventsBeta|EntraIdSignInEvents|AADSpnSignInEventsBeta|SigninLogs|AuditLogs|AlertEvidence|AlertInfo|CloudAppEvents|OAuthAppInfo|SI_(?!CI_CL)(?!\w+_Profile_CL)\w+_CL)\b'
    foreach ($r in $Reports) {
        $q = (@($r.ReportQuery) -join "`n")
        $s = Get-RaInvStripped $q
        $prof = @([regex]::Matches($s, '\bSI_(\w+?)_Profile_CL\b') | ForEach-Object { 'SI_' + $_.Groups[1].Value + '_Profile_CL' } | Sort-Object -Unique)
        $ids = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
        foreach ($m in [regex]::Matches($s, '\b[A-Za-z_][A-Za-z0-9_]*\b')) { [void]$ids.Add($m.Value) }
        foreach ($m in [regex]::Matches($q, 'column_ifexists\(\s*"([^"]+)"')) { [void]$ids.Add($m.Groups[1].Value) }
        $assetCols = @($ids | Where-Object { $profSet.Contains($_) -and -not $outputOnly.Contains($_) } | Sort-Object)
        $siFields = @($ids | Where-Object { $_ -cmatch '^si_[a-z0-9_]+$' -and $_ -notmatch '_$' } | Sort-Object)
        $rf = [ordered]@{}
        $rfFromCi = New-Object System.Collections.Generic.List[string]
        foreach ($m in [regex]::Matches($s, '\b(RF_[PC]_\w+)\s*=\s*(?!=)([^\r\n|]*)')) {
            $n = $m.Groups[1].Value
            # #541 (6): RF_P_CiFactors is the factor set the engine feeds the report (si_rf_p, limited to its factors) -- every catalog factor that fits;
            # RF_P_CiFactorNames is the same set as the catalog's display names (si_rf_names_) -- the ids go to RiskFactorIds
            if (-not $rf.Contains($n)) { $rf[$n] = $(if ($n -eq 'RF_P_CiFactors') { '(the fed factor set)' } elseif ($n -eq 'RF_P_CiFactorNames') { '(the fed factor set, display names)' } elseif ($tok.ContainsKey($n)) { $tok[$n] } else { '' }) }
            if ($m.Groups[2].Value -match '\bsi_rf_[pc]\b' -and -not $rfFromCi.Contains($n)) { $rfFromCi.Add($n) }
        }
        $joins = New-Object System.Collections.Generic.List[string]
        $nameJoins = New-Object System.Collections.Generic.List[string]
        foreach ($m in [regex]::Matches($s, '(?s)\bon\s+((?:\$left\.\w+\s*==\s*\$right\.\w+(?:\s*,\s*)?|\w+(?:\s*,\s*\w+)*)+)')) {
            $on = ($m.Groups[1].Value -replace '\s+', ' ').Trim().TrimEnd(',')
            if (-not $joins.Contains($on)) { $joins.Add($on) }
            if ($on -match '(?i)AadDeviceId|AssetName|DeviceName|_SIName|SI_AssetName|DisplayName|UserPrincipalName|EpJoinKey|\bName\b|SI_AssetId|_si_PrimaryEntityId') { if (-not $nameJoins.Contains($on)) { $nameJoins.Add($on) } }
        }
        $prov = @([regex]::Matches($s, $providerRx) | ForEach-Object { $_.Value } | Sort-Object -Unique)
        $blocks = @()
        if ($q -match [regex]::Escape($script:RACiLinkBegin)) { $blocks += 'link' }
        if ($q -match [regex]::Escape($script:RACiAssetBegin)) { $blocks += 'asset' }
        if ($q -match [regex]::Escape($script:RACiPeerBegin)) { $blocks += 'peer' }
        [pscustomobject][ordered]@{
            Report         = [string]$r.ReportName
            Domain         = [string]$r.SecurityDomain
            ProfileTables  = $prof
            ReadsCi        = [bool]($s -match '\bSI_CI_CL\b')
            CiBlocks       = $blocks
            AssetColumns   = $assetCols
            SiFields       = $siFields
            RfFlags        = $rf
            RfFromCi       = $rfFromCi.ToArray()
            Joins          = $joins.ToArray()
            NameJoins      = $nameJoins.ToArray()
            ProviderTables = $prov
            GraphOnly      = $(if ($graphOnly.ContainsKey([string]$r.ReportName)) { $graphOnly[[string]$r.ReportName] } else { '' })
        }
    }
}

function Get-RaProfileColumns {
    <# The legacy profile tables' column names (asset-profiling-schema/*.schema.locked.json) plus the extra profile
       columns the migration map names (columns the profilers write that the schema files do not list). #>
    param([string]$SiRoot, $Migration)
    $cols = New-Object System.Collections.Generic.List[string]
    foreach ($f in Get-ChildItem -LiteralPath (Join-Path $SiRoot 'asset-profiling-schema') -Filter '*.schema.locked.json') {
        $j = Get-Content -LiteralPath $f.FullName -Raw | ConvertFrom-Json
        foreach ($x in @($j.fields)) { if ($x.name) { $cols.Add([string]$x.name) } }
    }
    foreach ($p in @($Migration.columnMap.PSObject.Properties)) { $cols.Add([string]$p.Name) }
    # identifiers every profile row carries that are not in the per-engine files
    foreach ($c in 'PrimaryEntityId', 'CollectionTime', 'Tier', 'cmdbId', 'cmdbName', 'cmdbCriticality', 'cmdbDataSensitivity', 'SI_AssetId', 'SI_AssetName', 'AssetName', 'AssetId', 'AssetType', 'AssetTags', 'IsExcludedByTag', 'UnsupportedOSDetected') { $cols.Add($c) }
    return @($cols | Sort-Object -Unique)
}

if ($MyInvocation.InvocationName -ne '.') {
    $doc = ConvertFrom-SIYaml -Path $YamlPath
    $reports = @($doc.Reports)
    $mig = Get-Content -LiteralPath (Join-Path $siRoot 'risk-analysis-detection\ra-ci-migration.locked.json') -Raw | ConvertFrom-Json
    $factors = @((Get-Content -LiteralPath (Join-Path $siRoot 'data-model\risk-factors.locked.json') -Raw | ConvertFrom-Json).factors)
    $inv = @(Get-RaReportInventory -Reports $reports -ProfileColumns (Get-RaProfileColumns -SiRoot $siRoot -Migration $mig) -Factors $factors -Migration $mig)
    if ($OutJson) { $inv | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $OutJson -Encoding UTF8 }
    $unmappedCols = @($inv | ForEach-Object { $_.AssetColumns } | Sort-Object -Unique | Where-Object { -not $mig.columnMap.PSObject.Properties[$_] })
    $unmappedRf = @($inv | ForEach-Object { $_.RfFlags.GetEnumerator() } | Where-Object { -not $_.Value } | ForEach-Object { $_.Key } | Sort-Object -Unique)
    Write-Host ('{0} reports; {1} read a profile table; {2} read SI_CI_CL; {3} graph-only' -f $inv.Count, @($inv | Where-Object { $_.ProfileTables.Count }).Count, @($inv | Where-Object { $_.ReadsCi }).Count, @($inv | Where-Object { $_.GraphOnly }).Count)
    Write-Host ('asset columns read: {0} distinct, {1} without an SI field in the map: {2}' -f @($inv | ForEach-Object { $_.AssetColumns } | Sort-Object -Unique).Count, $unmappedCols.Count, ($unmappedCols -join ', '))
    Write-Host ('RF flags: {0} distinct, {1} without a catalog factor: {2}' -f @($inv | ForEach-Object { $_.RfFlags.Keys } | Sort-Object -Unique).Count, $unmappedRf.Count, ($unmappedRf -join ', '))
    Write-Host ('reports joining on a name / AadDeviceId: {0}' -f @($inv | Where-Object { $_.NameJoins.Count }).Count)
    if ($PassThru) { $inv }
}
