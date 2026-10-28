#Requires -Version 5.1
<#
    Refresh-CmdbCache.ps1

    Daily sync job (ARCHITECTURE.md § 11) -- pulls CMDB data from ServiceNow
    (or, in , the local sample CSV) and writes 3 tables to the
    SecurityInsight storage account:

      cmdbservices       -- id, name, criticality, dataSensitivity, owner, environment, last_sync
      cmdbcis            -- id, name, fqdn, azure_resource_id, entra_object_id, ip_addresses, tags, environment, last_seen
      cmdbmembership     -- cmdb_ci_id -> cmdbId  (relationships ServiceNow knows)

    Run as a separate scheduled task (KEDA cron job in production). Engine
    runs read from these tables only -- never call ServiceNow live.

    Reads a customer-maintained CSV from providers/generic-cmdb/CMDB.csv, falling back to
    the shipped sample/CMDB.csv. Source-agnostic: the CSV can be exported from ServiceNow,
    from another CMDB, or maintained by hand -- nothing here is ServiceNow-specific, which
    is why the provider was renamed 'servicenow-cmdb' -> 'generic-cmdb' in v2.2.421.
    A live ServiceNow CMDB (CIs, business services, relationships) is a separate, Pro
    feature that does not exist yet; when it does it WINS over this CSV and only one CMDB
    source is ever active. See docs/REQUIREMENTS.md #58.

    Usage:
        .\Refresh-CmdbCache.ps1 -StorageAccountName <sa>

    The storage account is reached with the run's signed-in identity, which needs the
    Storage Table Data Contributor role on the account.
#>

[CmdletBinding()]
param(
    [Parameter()][string]$StorageAccountName,
    [Parameter()][string]$CsvPath,

    # Accepted for callers that still pass it; the identity is always used.
    [Parameter()][switch]$UseOAuth,

    # #275 R2 -- WHICH CMDB the cache is built from. 'auto' (a direct or scheduled run): the CMDB in the Pro database when
    # one is configured (SI_ProSqlServer + SI_ProSqlDatabase), else the CSV. Stage Schedule passes the source it RESOLVED
    # (engine\asset-profiling\shared\CmdbSource.ps1), so the two can never disagree. Both build the cache with the ONE
    # function ConvertTo-SICmdbServiceEntry from rows of the same shape -- enrichment and risk weighting are unchanged.
    [Parameter()][ValidateSet('auto', 'generic-csv', 'pro-cmdb')][string]$Source = 'auto',

    # Seams (tests): the storage context the cache is written to (e.g. New-SIStorageContext -Mock), and the Pro
    # database (sql, params, mode) the Pro CMDB is read through. Production passes neither.
    [Parameter()][object]$Context,
    [Parameter()][scriptblock]$ProInvoke
)

$ErrorActionPreference = 'Stop'

# ensure Write-SI* helpers exist when this script runs standalone.
# Stage Schedule already dot-sources Write-SIStyle before calling us, but this
# script is also runnable directly via the cron / KEDA path, in which case the
# helpers aren't loaded yet. Idempotent: re-dot-source is a no-op.
if (-not (Get-Command Write-SIInfo -ErrorAction SilentlyContinue)) {
    $siRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $siRoot 'engine\asset-profiling\_shared\Write-SIStyle.ps1')
}

# CMDB provider: OFF unless $global:SI_EnableCmdbProvider = $true -- the SAME default the engine uses
# (Invoke-Schedule refreshes the cache and Invoke-Profile stamps cmdb fields only when it is on). This script
# used to treat "not set" as ON, so a direct or scheduled run filled a cache the engine then ignored (#257).
# The RA queries do not depend on the cache existing: with no rows the cmdb columns are blank, never an error.
if (-not [bool]$global:SI_EnableCmdbProvider) {
    Write-SIInfo 'CMDB provider not turned on ($global:SI_EnableCmdbProvider is not $true). Skipping cache refresh.'
    return
}

if (-not $StorageAccountName -and $global:SI_StorageAccount) { $StorageAccountName = [string]$global:SI_StorageAccount }

$siRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $siRoot 'engine\asset-profiling\shared\CmdbSource.ps1')

# Writes the service rows (Import-Csv rows of CMDB.csv, or the Pro CMDB's services in that same shape) to the cache.
# ONE writer for both sources (#275 R2).
$writeRows = {
    param([object[]]$Rows, [string]$Origin, [string]$SourceId)
    . (Join-Path $siRoot 'engine\asset-profiling\storage\StorageContext.ps1')
    . (Join-Path $siRoot 'engine\asset-profiling\storage\CmdbCache.ps1')
    $ctx = $Context
    if (-not $ctx) {
        Write-SIInfo ('CMDB cache: storage account {0}, reached with the run identity (needs Storage Table Data Contributor on the account).' -f $StorageAccountName)
        $ctx = New-SIStorageContext -AccountName $StorageAccountName
    }
    Initialize-SICmdbCacheTables -Context $ctx | Out-Null

    Write-SIStep ('CMDB cache refresh -- source: {0}' -f $Origin)
    $now = ([datetime]::UtcNow.ToString('o'))
    $serviceCount = 0
    foreach ($r in @($Rows)) {
        Set-SICmdbServiceRecord -Context $ctx -Service (ConvertTo-SICmdbServiceEntry -Row $r -Now $now) | Out-Null
        $serviceCount++
    }
    Write-SIInfo ('cmdbservices written: {0} (with {1} extra column(s) per row)' -f $serviceCount, (Get-SICmdbExtraColumnCount -Row (@($Rows) | Select-Object -First 1)))

    # Sample CSV has no CI rows / membership rows -- those come from real
    # ServiceNow. leaves cmdbcis + cmdbmembership empty after
    # initial table creation; reconciliation handles empty cache gracefully
    # by treating every discovered asset as orphan-discovered.

    # closing banner removed: the caller's Write-SIDone reports the
    # stage completion; an extra '=== DONE ===' inside this script is redundant noise.
    [pscustomobject]@{ ServicesWritten = $serviceCount; CIsWritten = 0; MembershipWritten = 0; Source = $Origin; SourceId = $SourceId; LastSync = $now }
}

if ($Source -eq 'auto') { $Source = if (Test-SICmdbProConfigured) { 'pro-cmdb' } else { 'generic-csv' } }

if ($Source -eq 'pro-cmdb') {
    # #275 R2 -- SecurityInsight Pro: the CMDB is in the Pro database (#256). Its authoritative source's services, as
    # CMDB.csv rows. A CSV on disk is NOT read here: one source is ever active (#58.1), and reading the CSV the database
    # replaced would hide that it was never migrated.
    $homeLib = Join-Path $siRoot 'engine\asset-cmdb\_shared\SI-CmdbHome.ps1'
    if (-not (Test-Path -LiteralPath $homeLib)) { throw ("the Pro CMDB reader is not in this package ({0}) -- a Pro database is configured, but this is not the Pro package." -f $homeLib) }
    . $homeLib
    $invoke = if ($ProInvoke) { $ProInvoke } else { New-SICmdbProInvoke }
    $pro = Read-SICmdbProServices -Invoke $invoke
    $origin = ("the CMDB in the Pro database ({0}/{1}, source {2})" -f [string]$global:SI_ProSqlServer, [string]$global:SI_ProSqlDatabase, $pro.ActiveSource)
    $proRows = @($pro.Rows)
    if ($proRows.Count -eq 0) {
        $csvLeft = Find-SICmdbCsv -SolutionRoot $siRoot
        if ($csvLeft) {
            # NEVER silently read the CSV instead: that would hide the migration gap behind plausible values.
            Write-SIWarn ("The CMDB in the Pro database has NO services, but a v2.2 CMDB.csv exists at '{0}'. It was never migrated: cmdbName / cmdbCriticality / cmdbDataSensitivity and the CMDB risk weighting stay EMPTY until it is. Migrate it once with setup\Import-SICmdbCsv.ps1 -Apply (or 'Import your v2.2 CMDB.csv' on the CMDB page of the web app). The CSV is not read in Pro." -f $csvLeft)
        } else {
            Write-SIInfo ("The CMDB in the Pro database has no services (source {0}) -- cmdb* columns stay empty. Add services on the CMDB page of the web app." -f $pro.ActiveSource)
        }
        return [pscustomobject]@{ ServicesWritten = 0; CIsWritten = 0; MembershipWritten = 0; Source = $origin; SourceId = 'pro-cmdb'; LastSync = $null; UnmigratedCsv = $csvLeft }
    }
    return (& $writeRows $proRows $origin 'pro-cmdb')
}

# CSV lookup order. The customer's own CMDB.csv sits in the provider folder and is
# GITIGNORED (.gitignore: asset-profiling-providers/**/CMDB.csv), so `git pull` and the
# customer sync never overwrite it. (An earlier comment here described a
# "providers-custom/" folder -- that folder has never existed; the gitignore is the
# actual mechanism and it works.)
#   1. -CsvPath param (explicit, highest priority)
#   2. $global:SI_CmdbCsvPath (set in custom.ps1) -- use when CMDB lives outside the SI repo
#   3. providers/generic-cmdb/CMDB.csv     -- standard customer drop point (gitignored)
#   4. providers/servicenow-cmdb/CMDB.csv  -- LEGACY drop point, pre-v2.2.421 rename
#   5. providers/generic-cmdb/sample/CMDB.csv -- last-resort sample shipped with the engine
if (-not $CsvPath -and $global:SI_CmdbCsvPath) { $CsvPath = [string]$global:SI_CmdbCsvPath }
if (-not $CsvPath) {
    $siRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $customerPath = Join-Path $siRoot 'asset-profiling-providers\generic-cmdb\CMDB.csv'
    if (Test-Path $customerPath) { $CsvPath = $customerPath }
}
if (-not $CsvPath) {
    # v2.2.421 -- LEGACY FALLBACK, and it is load-bearing rather than politeness.
    # The provider was renamed servicenow-cmdb -> generic-cmdb. A customer CSV at the old
    # path is GITIGNORED, so an update neither moves nor deletes it: their file stays in the
    # old folder while the new folder arrives empty. Without this fallback the lookup below
    # would find nothing and SKIP SILENTLY -- cmdbId / cmdbName / cmdbCriticality /
    # cmdbDataSensitivity would go empty across ~510 references in the RA catalog, on a run
    # that reports success. That is audit #48's failure class (silent COLUMN loss), and note
    # the #57.1(a) row-count guard would NOT catch it: the rows still exist, only the columns
    # empty out. Warn loudly so the customer migrates, but never lose their data.
    $siRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $legacyPath = Join-Path $siRoot 'asset-profiling-providers\servicenow-cmdb\CMDB.csv'
    if (Test-Path $legacyPath) {
        $CsvPath = $legacyPath
        Write-SIWarn ("CMDB CSV found at the LEGACY path '{0}'. The provider was renamed 'servicenow-cmdb' -> 'generic-cmdb' in v2.2.421 (it was never ServiceNow-specific). Your data is being used from the old location -- move CMDB.csv to 'asset-profiling-providers\generic-cmdb\CMDB.csv' at your convenience; this fallback will not be removed without notice." -f $legacyPath)
    }
}
if (-not $CsvPath) { $CsvPath = Join-Path $PSScriptRoot 'sample\CMDB.csv' }

if (-not (Test-Path $CsvPath)) {
    # default-on means we may reach this path on customers who
    # haven't dropped a CSV yet. Skip silently (no throw) -- cache stays empty,
    # Reconcile finds zero CMDB matches, RA queries see empty cmdbId/cmdbName/
    # cmdbCriticality columns. Drop a CMDB.csv at the customer-drop path or
    # set $global:SI_CmdbCsvPath to enable enrichment.
    Write-SIInfo ('CMDB CSV not present yet (looked at -CsvPath, $global:SI_CmdbCsvPath, asset-profiling-providers\generic-cmdb\CMDB.csv, the legacy asset-profiling-providers\servicenow-cmdb\CMDB.csv, and sample\CMDB.csv). Skipping cache refresh -- cmdbId / cmdbName / cmdbCriticality / cmdbDataSensitivity will be EMPTY until a CSV is provided.')
    return
}
$pathSource = if ($CsvPath -like '*\asset-profiling-providers\*') { 'providers-custom (customer drop)' }
              elseif ($CsvPath -like '*\sample\*')        { 'sample (platform fallback)' }
              elseif ($global:SI_CmdbCsvPath -and $CsvPath -eq [string]$global:SI_CmdbCsvPath) { '$global:SI_CmdbCsvPath' }
              else { '-CsvPath param' }
Write-SIInfo ('CMDB CSV path source: {0}' -f $pathSource)

$rows = @(Import-Csv -Path $CsvPath -Delimiter ';')
return (& $writeRows $rows $CsvPath 'generic-csv')
