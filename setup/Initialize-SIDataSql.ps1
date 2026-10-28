<#
.SYNOPSIS
    SecurityInsight Pro -- prepare the Pro database for the data backend (REQUIREMENTS §9.3.3 phase B).
.DESCRIPTION
    Applies sql\si-data-schema.sql (schema `sidata`: Run, Collection, Asset, AssetIdentifier, Finding, Recommendation,
    FindingDaily, VulnLifecycleDaily, FindingFacet, AssetTag, DepartmentFacet, the counted twins of the aggregates (#264) and the
    views vLatestCollection, vCurrentFinding, vCi, vExemptedFinding), then sql\si-cmdbsync-schema.sql (schema `cmdbsync`:
    the SQL CMDB connector's CI table, its identifiers, services, history and runs, and the view vConfigurationItem). Additive and
    idempotent: re-running changes nothing, and the file is checked for destructive statements before anything is sent.
    Run it again after an update that adds to the schema (the web app's collection views added columns to an existing
    install): the data sync says so when the columns it fills are missing.

    Connects the way the data sync does -- the container's managed identity when $global:SI_UseManagedIdentity, else
    the engine SPN by CERTIFICATE (Entra token, no SQL login, no secret) -- so a successful run here also proves the
    sync can reach the database.

    The identity needs, in that database: CREATE SCHEMA / CREATE TABLE / CREATE VIEW once (here), then db_datareader +
    db_datawriter for the sync. On Azure SQL with Entra-only authentication, as a contained user:
        CREATE USER [<engine app or identity name>] FROM EXTERNAL PROVIDER;
        ALTER ROLE db_datareader ADD MEMBER [<name>];
        ALTER ROLE db_datawriter ADD MEMBER [<name>];
    Without a directory identity on the server, name the identity by its client id instead:
        CREATE USER [<name>] WITH SID = 0x<the client id's 16 bytes, [guid]::ToByteArray() order, as hex>, TYPE = E;
    Container setup (Bootstrap-ContainerAppJob.ps1) prints these statements for the job's identity.
.EXAMPLE
    .\setup\Initialize-SIDataSql.ps1 -Server <server>.database.windows.net -Database sqldb-si-pro

.LINK
    https://invardia.com/docs/si/scripts/Initialize-SIDataSql/
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$Server   = $(if ($global:SI_Pro_DataSqlServer) { [string]$global:SI_Pro_DataSqlServer } else { [string]$global:SI_ProSqlServer }),
    [string]$Database = $(if ($global:SI_Pro_DataSqlDatabase) { [string]$global:SI_Pro_DataSqlDatabase } else { [string]$global:SI_ProSqlDatabase }),
    [string]$AppId          = [string]$global:SI_SPN_AppId,
    [string]$TenantId       = [string]$global:SI_SPN_TenantId,
    [string]$CertThumbprint = [string]$global:SI_SPN_CertThumbprint
)

#Requires -Version 5.1   # after the help and the param block: before the help, it hides the help from Get-Help
# framework section 12.7 / 12.10: the documentation link first, a transcript of the run, -WhatIf writes nothing
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-ScriptRun.ps1'))
$siRun = Start-SIScriptRun -Script 'Initialize-SIDataSql' -Quiet:($false)
try {
$ErrorActionPreference = 'Stop'
$siRoot = Split-Path -Parent $PSScriptRoot
if (-not $Server -or -not $Database) { throw 'Initialize-SIDataSql: pass -Server and -Database (or set SI_ProSqlServer / SI_ProSqlDatabase).' }
. (Join-Path $siRoot 'engine\_shared\SI-SchemaGate.ps1')
. (Join-Path $siRoot 'engine\_shared\data-sql\SI-DataModel.ps1')
. (Join-Path $siRoot 'engine\_shared\data-sql\SI-DataSql.ps1')
# #352: the ONE apply every path uses (setup, the internal build, the product updater) -- list, batching, gate, transaction
. (Join-Path $siRoot 'engine\pro-settings\SI-ProSchema.ps1')

$schema = Get-Content -LiteralPath (Join-Path $siRoot 'sql\si-data-schema.sql') -Raw
$check = Test-SISchemaIsAdditive -Sql $schema
# #277: a refused schema is a guard trip (mail + telemetry; never instead of the refusal)
try { . (Join-Path $siRoot 'engine\_shared\SI-Guard.ps1') } catch { }
$guardSchema = { param($file, $c) if (Get-Command -Name Send-SIGuardEvent -ErrorAction SilentlyContinue) { $null = Send-SIGuardEvent -GuardId 'schema.gate.refused' -Outcome 'refused' -Source 'setup' -Engine 'setup' -Subject $file -Detail (($c.Findings | ForEach-Object { 'line {0}: {1}' -f $_.Line, $_.Why }) -join '; ') -Values @(@{ Name = 'findings'; Label = 'Statements that could remove data'; Measured = @($c.Findings).Count; Limit = 0 }) } }
if (-not $check.IsAdditive) {
    & $guardSchema 'sql\si-data-schema.sql' $check
    throw ("Initialize-SIDataSql: sql\si-data-schema.sql is not additive -- refusing to apply it: {0}" -f (($check.Findings | ForEach-Object { 'line {0}: {1}' -f $_.Line, $_.Why }) -join '; '))
}
if ($WhatIfPreference) {
    # -WhatIf: the schema was checked above (additive); the database is not opened -- applying it is the script's only change
    Write-Host ("-WhatIf: would apply sql\si-data-schema.sql (additive, checked) to {0}/{1}, then the CMDB sync schema. Nothing was written." -f $Server, $Database) -ForegroundColor Yellow
    return
}
$invoke = New-SIDataSqlInvoke -Server $Server -Database $Database -AppId $AppId -TenantId $TenantId -CertThumbprint $CertThumbprint
Write-Host ("[STEP]  applying the data backend schema to {0}/{1}" -f $Server, $Database) -ForegroundColor Cyan
$applied = Invoke-SIProSchemaApply -SIRoot $siRoot -Invoke $invoke -Names data -Log { param($m) Write-Host $m }
if ($applied.Action -ne 'applied') { throw ("Initialize-SIDataSql: {0}" -f $applied.Reason) }
$tables = [int](& $invoke "SELECT COUNT(*) FROM sys.tables WHERE schema_id = SCHEMA_ID('sidata') AND name IN ('Run','Collection','Asset','AssetIdentifier','Finding','Recommendation','FindingDaily','VulnLifecycleDaily','FindingFacet','ServiceMember','ServiceAsset','ServiceRisk','AssetTag','DepartmentFacet')" @{} 'scalar')
$views = [int](& $invoke "SELECT COUNT(*) FROM sys.views WHERE schema_id = SCHEMA_ID('sidata') AND name IN ('vLatestCollection','vCurrentFinding','vCi')" @{} 'scalar')
if ($tables -ne 14 -or $views -ne 3) { throw ("Initialize-SIDataSql: expected 14 tables and 3 views in schema sidata, found {0} and {1}." -f $tables, $views) }
# asset responsibility (#254): the department columns the data sync stamps (the cfg tables come with the Pro settings schema)
if ([int](& $invoke "SELECT CASE WHEN COL_LENGTH('sidata.Finding', 'DepartmentId') IS NOT NULL AND COL_LENGTH('sidata.Asset', 'DepartmentId') IS NOT NULL AND COL_LENGTH('sidata.Collection', 'ResolvedVersion') IS NOT NULL THEN 1 ELSE 0 END" @{} 'scalar') -ne 1) {
    throw 'Initialize-SIDataSql: the department columns (sidata.Finding / sidata.Asset DepartmentId, sidata.Collection ResolvedVersion) are missing after the schema was applied.'
}
# the web app's collection views (#241): the columns the data sync fills from DetailJson, and their covering index
if ([int](& $invoke (Get-SIDataViewsSchemaCheckSql) @{} 'scalar') -ne 1) { throw 'Initialize-SIDataSql: the collection views'' columns (sidata.Finding RiskRating ..., sidata.Collection DerivedAt) are missing after the schema was applied.' }
# the Services view (#255): the CMDB columns and the per-collection service tables
if ([int](& $invoke (Get-SIDataServicesSchemaCheckSql) @{} 'scalar') -ne 1) { throw 'Initialize-SIDataSql: the Services view''s columns and tables (sidata.Finding CmdbId, sidata.ServiceMember / ServiceAsset / ServiceRisk) are missing after the schema was applied.' }
# exempted findings (#264): the mark on sidata.Finding and the counted twin of every pre-computed aggregate
if ([int](& $invoke (Get-SIDataExemptedSchemaCheckSql) @{} 'scalar') -ne 1) { throw 'Initialize-SIDataSql: the exemption mark (sidata.Finding ExemptionId ...) and the counted aggregates (sidata.FindingDailyCounted ...) are missing after the schema was applied.' }
# correlation evidence (#299): the evidence per CI, the id history, the conflicts and the per-collection correlation rows
. (Join-Path $siRoot 'engine\pro-data\_shared\SI-DataEvidence.ps1')
if ([int](& $invoke (Get-SIDataEvidenceSchemaCheckSql) @{} 'scalar') -ne 1) { throw 'Initialize-SIDataSql: the correlation evidence tables (sidata.AssetEvidence, AssetIdHistory, AssetConflict, AssetCorrelation, sidata.Collection CorrelatedAt) are missing after the schema was applied.' }
# full asset metadata (#408): the generic store the data sync fills when SI_AssetProperties = full
. (Join-Path $siRoot 'engine\pro-data\_shared\SI-DataAssetMetadata.ps1')
if ([int](& $invoke (Get-SIDataAssetMetadataSchemaCheckSql) @{} 'scalar') -ne 1) { throw 'Initialize-SIDataSql: the full asset metadata tables (sidata.AssetMetadata, sidata.AssetMetadataLoad) are missing after the schema was applied.' }
# the SQL CMDB connector's CI table (#271, schema cmdbsync) -- in the same database, beside the data it joins
$cmdbSchemaPath = Join-Path $siRoot 'sql\si-cmdbsync-schema.sql'
if (Test-Path -LiteralPath $cmdbSchemaPath) {
    $cmdbSchema = Get-Content -LiteralPath $cmdbSchemaPath -Raw
    $cmdbCheck = Test-SISchemaIsAdditive -Sql $cmdbSchema
    if (-not $cmdbCheck.IsAdditive) {
        & $guardSchema 'sql\si-cmdbsync-schema.sql' $cmdbCheck
        throw ("Initialize-SIDataSql: sql\si-cmdbsync-schema.sql is not additive -- refusing to apply it: {0}" -f (($cmdbCheck.Findings | ForEach-Object { 'line {0}: {1}' -f $_.Line, $_.Why }) -join '; '))
    }
    Write-Host ("[STEP]  applying the CI table schema (cmdbsync) to {0}/{1}" -f $Server, $Database) -ForegroundColor Cyan
    $applied = Invoke-SIProSchemaApply -SIRoot $siRoot -Invoke $invoke -Names cmdbsync -Log { param($m) Write-Host $m }
    if ($applied.Action -ne 'applied') { throw ("Initialize-SIDataSql: {0}" -f $applied.Reason) }
    # the SQL CMDB connector's check (the Pro package carries it; the free version has the tables, not the connector)
    $cmdbSyncLib = Join-Path $siRoot 'engine\asset-cmdb\_shared\SI-CmdbSqlSync.ps1'
    $cmdbOk = $true
    if (Test-Path -LiteralPath $cmdbSyncLib) { . $cmdbSyncLib; $cmdbOk = ([int](& $invoke (Get-SICmdbSqlSchemaCheckSql) @{} 'scalar') -eq 1) }
    if (-not $cmdbOk) { throw 'Initialize-SIDataSql: the CI tables (cmdbsync.ConfigurationItem ..., the view cmdbsync.vConfigurationItem) are missing after the schema was applied.' }
}
$n = & $invoke "SELECT COUNT(*) FROM sidata.Collection WHERE Status = 'Complete'" @{} 'scalar'
Write-Host ("[OK]    schema ready -- {0} complete collection(s) loaded so far; the data sync can connect." -f $n) -ForegroundColor Green
} finally { Stop-SIScriptRun -Run $siRun }
