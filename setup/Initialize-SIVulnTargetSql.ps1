<#
.SYNOPSIS
    SecurityInsight Pro -- prepare a SQL database as the vulnerability close-loop's target (#195).
.DESCRIPTION
    Applies sql\si-vulnerability-target.sql (schema `vuln`: VulnerabilityItem + VulnerabilityEvent). Additive and
    idempotent: re-running changes nothing. Connects as the SI engine identity with its CERTIFICATE (Entra token),
    the same way the vulnerability sync does -- so a successful run here also proves the sync can reach the database.

    The identity needs, in that database: CREATE SCHEMA / CREATE TABLE once (here), then db_datareader +
    db_datawriter for the sync. On Azure SQL with Entra-only authentication, create it as a contained user:
        CREATE USER [<engine app name>] FROM EXTERNAL PROVIDER;
        ALTER ROLE db_datareader ADD MEMBER [<engine app name>];
        ALTER ROLE db_datawriter ADD MEMBER [<engine app name>];
    FROM EXTERNAL PROVIDER needs the SQL server to have a directory identity. Without one, name the identity by its
    client id instead -- the same form serves a container job's managed identity (Pro container hosting):
        CREATE USER [<identity name>] WITH SID = 0x<the client id's 16 bytes, [guid]::ToByteArray() order, as hex>, TYPE = E;
    Container setup (Bootstrap-ContainerAppJob.ps1) prints these statements for the job's identity, ready to run.
.EXAMPLE
    .\setup\Initialize-SIVulnTargetSql.ps1 -Server <server>.database.windows.net -Database sqldb-si-vulntarget

.LINK
    https://invardia.com/docs/si/scripts/Initialize-SIVulnTargetSql/
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$Server   = [string]$global:SI_VulnSync_SqlServer,
    [string]$Database = [string]$global:SI_VulnSync_SqlDatabase,
    [string]$AppId          = [string]$global:SI_SPN_AppId,
    [string]$TenantId       = [string]$global:SI_SPN_TenantId,
    [string]$CertThumbprint = [string]$global:SI_SPN_CertThumbprint
)

#Requires -Version 5.1   # after the help and the param block: before the help, it hides the help from Get-Help
# framework section 12.7 / 12.10: the documentation link first, a transcript of the run, -WhatIf writes nothing
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-ScriptRun.ps1'))
$siRun = Start-SIScriptRun -Script 'Initialize-SIVulnTargetSql' -Quiet:($false)
try {
$ErrorActionPreference = 'Stop'
$siRoot = Split-Path -Parent $PSScriptRoot
if (-not $Server -or -not $Database) { throw 'Initialize-SIVulnTargetSql: pass -Server and -Database (or set SI_VulnSync_SqlServer / SI_VulnSync_SqlDatabase).' }
if (-not $AppId -or -not $TenantId -or -not $CertThumbprint) { throw 'Initialize-SIVulnTargetSql: the engine identity (SI_SPN_AppId / SI_SPN_TenantId / SI_SPN_CertThumbprint) is not set.' }
. (Join-Path $siRoot 'engine\asset-cmdb\_shared\SI-VulnTarget.ps1')

$schema = Get-Content -LiteralPath (Join-Path $siRoot 'sql\si-vulnerability-target.sql') -Raw
if ($WhatIfPreference) {
    # -WhatIf: the database is not opened -- applying the schema is the script's only change
    Write-Host ("-WhatIf: would apply sql\si-vulnerability-target.sql (schema vuln, additive) to {0}/{1}. Nothing was written." -f $Server, $Database) -ForegroundColor Yellow
    return
}
$tgt = New-SIVulnTargetSql -Server $Server -Database $Database -AppId $AppId -TenantId $TenantId -CertThumbprint $CertThumbprint
Write-Host ("[STEP]  applying the vulnerability target schema to {0}/{1}" -f $Server, $Database) -ForegroundColor Cyan
# #352: the ONE apply every path uses (setup, the internal build, the product updater) -- the additive gate, one transaction
. (Join-Path $siRoot 'engine\pro-settings\SI-ProSchema.ps1')
$applied = Invoke-SIProSchemaApply -SIRoot $siRoot -Invoke $tgt.Invoke -Names vuln -Log { param($m) Write-Host $m }
if ($applied.Action -ne 'applied') { throw ("Initialize-SIVulnTargetSql: {0}" -f $applied.Reason) }
$n = & $tgt.Invoke "SELECT COUNT(*) FROM sys.tables WHERE schema_id = SCHEMA_ID('vuln') AND name IN ('VulnerabilityItem','VulnerabilityEvent')" @{} 'scalar'
if ([int]$n -ne 2) { throw ("Initialize-SIVulnTargetSql: expected 2 tables in schema vuln, found {0}." -f $n) }
$rows = & $tgt.Invoke 'SELECT COUNT(*) FROM vuln.VulnerabilityItem' @{} 'scalar'
Write-Host ("[OK]    schema ready -- vuln.VulnerabilityItem holds {0} record(s); the sync can connect." -f $rows) -ForegroundColor Green
} finally { Stop-SIScriptRun -Run $siRun }
