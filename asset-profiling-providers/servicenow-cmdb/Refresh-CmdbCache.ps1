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

    ships in SAMPLE-CSV mode: reads providers/servicenow-cmdb/
    sample/CMDB.csv. Real ServiceNow REST integration ships when a customer
    needs it.

    Usage:
        .\Refresh-CmdbCache.ps1 -StorageAccountName <sa> -StorageKey <key>
#>

[CmdletBinding()]
param(
    [Parameter()][string]$StorageAccountName,
    [Parameter()][string]$StorageKey,
    [Parameter()][string]$CsvPath
)

$ErrorActionPreference = 'Stop'

# ensure Write-SI* helpers exist when this script runs standalone.
# Stage Schedule already dot-sources Write-SIStyle before calling us, but this
# script is also runnable directly via the cron / KEDA path, in which case the
# helpers aren't loaded yet. Idempotent: re-dot-source is a no-op.
if (-not (Get-Command Write-SIInfo -ErrorAction SilentlyContinue)) {
    $v22Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $v22Root 'engine\asset-profiling\_shared\Write-SIStyle.ps1')
}

# CMDB provider DEFAULT-ON. Customers can opt out by explicitly
# setting $global:SI_EnableCmdbProvider = $false. Default-on means the RA
# queries always have a populated cmdbId / cmdbName / cmdbCriticality /
# cmdbDataSensitivity column path -- if no CMDB.csv exists yet the cache stays
# empty and the columns are just blank, but the query never errors.
if ($PSBoundParameters.ContainsKey('SI_EnableCmdbProvider') -or (Get-Variable -Name SI_EnableCmdbProvider -Scope Global -ErrorAction SilentlyContinue)) {
    if ($global:SI_EnableCmdbProvider -eq $false) {
        Write-SIInfo 'CMDB provider explicitly disabled ($global:SI_EnableCmdbProvider = $false). Skipping cache refresh.'
        return
    }
}

if (-not $StorageAccountName -and $global:SI_StorageAccount) { $StorageAccountName = [string]$global:SI_StorageAccount }
if (-not $StorageKey         -and $global:SI_StorageKey)     { $StorageKey         = [string]$global:SI_StorageKey }

# 3-tier CSV lookup. Customer files live OUTSIDE the platform-shipped
# providers/ folder so `git pull` never overwrites them.
#   1. -CsvPath param (explicit, highest priority)
#   2. $global:SI_CmdbCsvPath (set in custom.ps1) -- use when CMDB lives outside the SI repo
#   3. providers-custom/servicenow-cmdb/CMDB.csv -- standard customer drop point (gitignored)
#   4. providers/servicenow-cmdb/sample/CMDB.csv -- last-resort sample shipped with the engine
if (-not $CsvPath -and $global:SI_CmdbCsvPath) { $CsvPath = [string]$global:SI_CmdbCsvPath }
if (-not $CsvPath) {
    $v22Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $customerPath = Join-Path $v22Root 'asset-profiling-providers\servicenow-cmdb\CMDB.csv'
    if (Test-Path $customerPath) { $CsvPath = $customerPath }
}
if (-not $CsvPath) { $CsvPath = Join-Path $PSScriptRoot 'sample\CMDB.csv' }

if (-not (Test-Path $CsvPath)) {
    # default-on means we may reach this path on customers who
    # haven't dropped a CSV yet. Skip silently (no throw) -- cache stays empty,
    # Reconcile finds zero CMDB matches, RA queries see empty cmdbId/cmdbName/
    # cmdbCriticality columns. Drop a CMDB.csv at the customer-drop path or
    # set $global:SI_CmdbCsvPath to enable enrichment.
    Write-SIInfo ('CMDB CSV not present yet (looked at -CsvPath, $global:SI_CmdbCsvPath, asset-profiling-providers\servicenow-cmdb\CMDB.csv, sample\CMDB.csv). Skipping cache refresh -- cmdb columns will be empty until a CSV is provided.')
    return
}
$pathSource = if ($CsvPath -like '*\asset-profiling-providers\*') { 'providers-custom (customer drop)' }
              elseif ($CsvPath -like '*\sample\*')        { 'sample (platform fallback)' }
              elseif ($global:SI_CmdbCsvPath -and $CsvPath -eq [string]$global:SI_CmdbCsvPath) { '$global:SI_CmdbCsvPath' }
              else { '-CsvPath param' }
Write-SIInfo ('CMDB CSV path source: {0}' -f $pathSource)

$v22Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $v22Root 'engine\asset-profiling\storage\StorageContext.ps1')
. (Join-Path $v22Root 'engine\asset-profiling\storage\CmdbCache.ps1')

$ctx = New-SIStorageContext -AccountName $StorageAccountName -AccountKey $StorageKey
Initialize-SICmdbCacheTables -Context $ctx | Out-Null

Write-SIStep ('CMDB cache refresh -- source: {0}' -f $CsvPath)
$rows = Import-Csv -Path $CsvPath -Delimiter ';'
$now = ([datetime]::UtcNow.ToString('o'))

# surface ALL CSV columns into the service record (not just the
# curated subset). Set-SICmdbServiceRecord accepts an arbitrary hashtable so
# any new column the customer adds to CMDB.csv flows through to engine
# reconciliation without code changes. Required keys are normalized to a
# stable shape (id / name / criticality / dataSensitivity / owner / ownerMail
# / environment); every other column passes through verbatim using its CSV
# column name as the field name.
$reservedNorm = @('cmdbID','cmdbName','Criticality','DataSensitivity','Owner','OwnerMail','Environment')
$serviceCount = 0
foreach ($r in $rows) {
    $entry = @{
        id              = [string]$r.cmdbID
        name            = [string]$r.cmdbName
        criticality     = [string]$r.Criticality
        dataSensitivity = [string]$r.DataSensitivity
        owner           = [string]$r.Owner
        ownerMail       = [string]$r.OwnerMail
        environment     = if ($r.PSObject.Properties['Environment']) { [string]$r.Environment } else { '' }
        last_sync       = $now
    }
    foreach ($p in $r.PSObject.Properties) {
        if ($reservedNorm -contains $p.Name) { continue }
        if ([string]::IsNullOrWhiteSpace([string]$p.Value)) { continue }
        # Sanitize column name to Azure Table-safe ASCII identifier (alnum + underscore).
        $key = ($p.Name -replace '[^A-Za-z0-9_]', '_')
        if (-not $entry.ContainsKey($key)) { $entry[$key] = [string]$p.Value }
    }
    Set-SICmdbServiceRecord -Context $ctx -Service $entry | Out-Null
    $serviceCount++
}
Write-SIInfo ('cmdbservices written: {0} (with {1} extra column(s) per row)' -f $serviceCount, ($rows[0].PSObject.Properties.Name | Where-Object { $_ -notin $reservedNorm }).Count)

# Sample CSV has no CI rows / membership rows -- those come from real
# ServiceNow. leaves cmdbcis + cmdbmembership empty after
# initial table creation; reconciliation handles empty cache gracefully
# by treating every discovered asset as orphan-discovered.

# closing banner removed: the caller's Write-SIDone reports the
# stage completion; an extra '=== DONE ===' inside this script is redundant noise.
return [pscustomobject]@{ ServicesWritten = $serviceCount; CIsWritten = 0; MembershipWritten = 0; Source = $CsvPath; LastSync = $now }
