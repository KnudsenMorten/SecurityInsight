#Requires -Version 5.1
<#
    CmdbCache.ps1

    Storage adapter for the 3 CMDB cache tables (ARCHITECTURE.md § 11):

      cmdbservices      -- business services (id, name, criticality, dataSensitivity, owner, last_sync)
      cmdbcis           -- CIs (id, name, fqdn, azure_resource_id, entra_object_id, ip_addresses, tags, last_seen)
      cmdbmembership    -- cmdb_ci_id -> cmdbId relationship

    All under the same StorageContext as the rest of v2.2's storage tables
    (sifingerprint, sitypeprofiles, etc.). Per ARCHITECTURE.md rule 3,
    table names keep the descriptive prefix scheme used by the storage
    account ('si' is the project namespace; confirmed this).

    ships the table init + accessors + bulk-load helpers used
    by Refresh-CmdbCache.ps1 (sync job) and Invoke-Reconcile.ps1 (the new
    reconciliation phase).
#>

. (Join-Path $PSScriptRoot 'StorageContext.ps1')

# REST-only Azure Table Storage client (replaces AzTable module).
# AzTable was a separate PSGallery module with install-path issues on locked-down
# VMs. The same storage account is already accessed via REST + SharedKeyLite
# elsewhere in v2.2 (storage/FingerprintCache.ps1). We reuse the existing helpers
# Get-SITableAuthorizationHeader (handles both KeyAuth + OAuth bearer) and
# ConvertTo-SIRfc1123Date from storage/StorageContext.ps1.

function New-SICmdbTableIfNotExists {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Context, [Parameter(Mandatory)][string]$Table)
    # raw-canon signing (bypass [Uri].AbsolutePath normalization).
    $resourcePath = 'Tables'
    $url     = 'https://{0}.table.core.windows.net/{1}' -f $Context.AccountName, $resourcePath
    $date    = ConvertTo-SIRfc1123Date
    $canon   = '/{0}/{1}' -f $Context.AccountName, $resourcePath
    $sig     = Get-SISharedKeySignature -AccountName $Context.AccountName -AccountKey $Context.AccountKey -StringToSign ("$date`n$canon")
    $auth    = 'SharedKeyLite {0}:{1}' -f $Context.AccountName, $sig
    $headers = @{
        'x-ms-date'    = $date
        'x-ms-version' = '2020-08-04'
        Accept         = 'application/json;odata=nometadata'
        'Content-Type' = 'application/json;charset=utf-8'
        Authorization  = $auth
    }
    $bodyJson  = ConvertTo-Json @{ TableName = $Table } -Compress
    $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($bodyJson)
    try {
        Invoke-RestMethod -Method Post -Uri $url -Headers $headers -Body $bodyBytes -ErrorAction Stop | Out-Null
        Write-SIOk ("CMDB table created: {0}" -f $Table)
    } catch {
        $code = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
        if ($code -eq 409) {
            Write-SIInfo ("CMDB table already exists: {0}" -f $Table)
        } else {
            throw ('New-SICmdbTableIfNotExists POST {0} body={1} -> HTTP {2}: {3}' -f $url, $bodyJson, $code, $_.Exception.Message)
        }
    }
}

function Set-SICmdbTableEntity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][string]$Table,
        [Parameter(Mandatory)][string]$PartitionKey,
        [Parameter(Mandatory)][string]$RowKey,
        [Parameter(Mandatory)][hashtable]$Properties
    )
    $entity = @{} + $Properties
    $entity['PartitionKey'] = $PartitionKey
    $entity['RowKey']       = $RowKey
    # pre-encode body as UTF-8 bytes. PowerShell 5.1's
    # Invoke-RestMethod defaults string bodies to ISO-8859-1 / ASCII for
    # 'application/json' Content-Type -- non-ASCII chars (Danish o-slash,
    # German umlauts, etc.) get mangled and Azure Tables returns 400 Bad
    # Request on the JSON parse. Bytes bypass PS's encoding heuristic.
    $bodyJson  = $entity | ConvertTo-Json -Compress -Depth 10
    $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($bodyJson)

    # PowerShell's [Uri] class normalizes URLs in ways that break
    # SharedKeyLite signing. The URL written to the wire by Invoke-RestMethod
    # may differ from what Get-SITableAuthorizationHeader signs (via [Uri].
    # AbsolutePath which decodes %27 back to '). Build the canonicalized
    # resource string DIRECTLY (skip [Uri]) so signature matches the actual
    # request. Apostrophes in keys are doubled per OData spec.
    $pkEscaped = $PartitionKey -replace "'", "''"
    $rkEscaped = $RowKey       -replace "'", "''"
    $resourcePath = "$Table(PartitionKey='$pkEscaped',RowKey='$rkEscaped')"
    $url          = "https://$($Context.AccountName).table.core.windows.net/$resourcePath"

    # retry on 404 in case of Azure Table eventual consistency
    # (newly POST'd table not yet visible). Other errors bubble immediately.
    $delays = @(0, 500, 1500, 4000)
    $lastErr = $null
    foreach ($wait in $delays) {
        if ($wait -gt 0) { Start-Sleep -Milliseconds $wait }
        $date = ConvertTo-SIRfc1123Date
        # Build SharedKeyLite signature from raw resource path (no [Uri] roundtrip).
        $canon = '/{0}/{1}' -f $Context.AccountName, $resourcePath
        $sig   = Get-SISharedKeySignature -AccountName $Context.AccountName -AccountKey $Context.AccountKey -StringToSign ("$date`n$canon")
        $auth  = 'SharedKeyLite {0}:{1}' -f $Context.AccountName, $sig
        # NO If-Match header. Per MS docs, Insert-Or-Replace =
        # PUT WITHOUT If-Match. Including If-Match (even '*') makes the request
        # an Update Entity op, which REQUIRES the entity to already exist --
        # returns 404 for first-time inserts. That was the persistent 404 cause.
        $headers = @{
            'x-ms-date'    = $date
            'x-ms-version' = '2020-08-04'
            Accept         = 'application/json;odata=nometadata'
            'Content-Type' = 'application/json;charset=utf-8'
            Authorization  = $auth
        }
        try {
            Invoke-RestMethod -Method Put -Uri $url -Headers $headers -Body $bodyBytes -ErrorAction Stop | Out-Null
            return
        } catch {
            $code = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
            $lastErr = $_
            if ($code -ne 404) {
                # Surface the raw URL on non-404 so we can diagnose signing/path issues.
                throw ('Set-SICmdbTableEntity PUT {0} -> HTTP {1}: {2}' -f $url, $code, $_.Exception.Message)
            }
        }
    }
    throw ('Set-SICmdbTableEntity PUT {0} -> 404 after {1} retries: {2}' -f $url, $delays.Count, $lastErr.Exception.Message)
}

function Get-SICmdbTableEntities {
    <# Returns array of entity pscustomobjects. Optional partition filter.
       Pages via x-ms-continuation-Next* response headers (Table REST returns
       up to 1000 rows per call). Returns empty array on 404 (table missing). #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][string]$Table,
        [Parameter()][string]$PartitionKey
    )
    $out = New-Object System.Collections.ArrayList
    $next = $null
    $pages = 0
    do {
        $qs = @()
        if ($PartitionKey) { $qs += ('$filter=PartitionKey%20eq%20''{0}''' -f [uri]::EscapeDataString($PartitionKey)) }
        if ($next) {
            $qs += ('NextPartitionKey={0}' -f [uri]::EscapeDataString($next.Partition))
            if ($next.Row) { $qs += ('NextRowKey={0}' -f [uri]::EscapeDataString($next.Row)) }
        }
        $url = "https://$($Context.AccountName).table.core.windows.net/$Table()"
        if ($qs.Count -gt 0) { $url = $url + '?' + ($qs -join '&') }

        $date    = ConvertTo-SIRfc1123Date
        # Signing canon excludes query (Get-SITableAuthorizationHeader uses [Uri].AbsolutePath).
        $auth    = Get-SITableAuthorizationHeader -Context $Context -Date $date -Url $url
        try {
            $resp = Invoke-WebRequest -Method GET -Uri $url -Headers @{
                'x-ms-date'    = $date
                'x-ms-version' = '2020-08-04'
                Authorization  = $auth
                Accept         = 'application/json;odata=nometadata'
            } -UseBasicParsing -ErrorAction Stop
        } catch {
            if ($_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 404) { return @() }
            throw
        }
        $parsed = $resp.Content | ConvertFrom-Json
        if ($parsed.value) { foreach ($e in $parsed.value) { [void]$out.Add($e) } }

        $nextP = $resp.Headers['x-ms-continuation-NextPartitionKey']
        $nextR = $resp.Headers['x-ms-continuation-NextRowKey']
        if ($nextP) { $next = @{ Partition = [string]$nextP; Row = [string]$nextR } } else { $next = $null }
        $pages++
    } while ($next -and $pages -lt 100)
    return $out.ToArray()
}

function Initialize-SICmdbCacheTables {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Context)

    foreach ($t in @('sicmdbservices','sicmdbcis','sicmdbmembership')) {
        if ($Context.Mode -eq 'Mock') {
            if (-not $Context.MockState.Tables.ContainsKey($t)) { $Context.MockState.Tables[$t] = @{} }
            continue
        }
        New-SICmdbTableIfNotExists -Context $Context -Table $t
    }
}

function Set-SICmdbServiceRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][hashtable]$Service
    )
    $pk  = 'service'
    $rk  = ([string]$Service.id).ToLower()

    if ($Context.Mode -eq 'Mock') {
        $row = @{} + $Service
        $row['PartitionKey'] = $pk
        $row['RowKey']       = $rk
        $Context.MockState.Tables['sicmdbservices'][('{0}|{1}' -f $pk, $rk)] = $row
        return
    }
    Set-SICmdbTableEntity -Context $Context -Table 'sicmdbservices' -PartitionKey $pk -RowKey $rk -Properties $Service
}

function Get-SICmdbServices {
    <#
        Returns array of all service records. Used by reconciliation to
        validate cmdbId references in profile rows + by lint to validate
        rules-custom/ cmdbId references.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Context)

    if ($Context.Mode -eq 'Mock') {
        return @($Context.MockState.Tables['sicmdbservices'].Values | ForEach-Object { [pscustomobject]$_ })
    }
    try {
        return @(Get-SICmdbTableEntities -Context $Context -Table 'sicmdbservices' -PartitionKey 'service')
    } catch {
        Write-Warning ('Get-SICmdbServices: {0}' -f $_.Exception.Message)
        return @()
    }
}

function Get-SICmdbCIs {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Context)
    if ($Context.Mode -eq 'Mock') {
        return @($Context.MockState.Tables['sicmdbcis'].Values | ForEach-Object { [pscustomobject]$_ })
    }
    try {
        return @(Get-SICmdbTableEntities -Context $Context -Table 'sicmdbcis')
    } catch {
        return @()
    }
}

function Get-SICmdbCacheAge {
    <#
        Returns @{ HoursOld = <int>; State = 'fresh' | 'stale' | 'critical' | 'never' }
        per the staleness contract in ARCHITECTURE.md § 11:
          < 24h     fresh
          24h-7d    stale (warn)
          > 7d      critical (error + suppress gap report)
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Context)

    $services = Get-SICmdbServices -Context $Context
    if (-not $services -or $services.Count -eq 0) {
        return @{ HoursOld = -1; State = 'never' }
    }
    # parse last_sync via [DateTimeOffset] to preserve the UTC
    # 'Z' suffix correctly. [datetime]::Parse silently converts to LOCAL
    # time -- subtracting that from UtcNow produced negative hours
    # (e.g., "-2h old") on tenants in non-UTC timezones.
    $latest = ($services | ForEach-Object {
        try { [DateTimeOffset]::Parse([string]$_.last_sync).UtcDateTime } catch { $null }
    } | Where-Object { $_ } | Sort-Object -Descending | Select-Object -First 1)
    if (-not $latest) { return @{ HoursOld = -1; State = 'never' } }
    $hours = [int]([datetime]::UtcNow - $latest).TotalHours
    if ($hours -lt 0) { $hours = 0 }   # clamp on clock skew
    $state = if ($hours -lt 24) { 'fresh' } elseif ($hours -lt 168) { 'stale' } else { 'critical' }
    return @{ HoursOld = $hours; State = $state; LastSync = $latest }
}
