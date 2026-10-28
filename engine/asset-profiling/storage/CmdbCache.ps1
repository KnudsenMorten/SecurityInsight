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
# VMs. The same storage account is already accessed via REST elsewhere
# (storage/FingerprintCache.ps1). We reuse the existing helpers
# Get-SITableAuthorizationHeader (a bearer token for the run's identity) and
# ConvertTo-SIRfc1123Date from storage/StorageContext.ps1.

function New-SICmdbTableIfNotExists {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Context, [Parameter(Mandatory)][string]$Table)
    $resourcePath = 'Tables'
    $url     = 'https://{0}.table.core.windows.net/{1}' -f $Context.AccountName, $resourcePath
    $date    = ConvertTo-SIRfc1123Date
    # A bearer token for the run's identity; the URL is not signed.
    $auth    = Get-SITableAuthorizationHeader -Context $Context -Date $date -Url $url
    $headers = @{
        'x-ms-date'    = $date
        'x-ms-version' = '2020-12-06'
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

    # Apostrophes in keys are doubled per OData spec.
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
        $auth = Get-SITableAuthorizationHeader -Context $Context -Date $date -Url $url
        # NO If-Match header. Per MS docs, Insert-Or-Replace =
        # PUT WITHOUT If-Match. Including If-Match (even '*') makes the request
        # an Update Entity op, which REQUIRES the entity to already exist --
        # returns 404 for first-time inserts. That was the persistent 404 cause.
        $headers = @{
            'x-ms-date'    = $date
            'x-ms-version' = '2020-12-06'
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

# #891 part 3: the shared storage helper (Invoke-SIStorageRequest: retries on no answer, 408, 429 and 5xx, Retry-After)
if (-not (Get-Command -Name Invoke-SIStorageRequest -ErrorAction SilentlyContinue)) {
    $__azr = [System.IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), '_shared', 'SI-AzRest.ps1')
    if ([System.IO.File]::Exists($__azr)) { . $__azr }
}

function Read-SICmdbTablePages {
    <#
        #891 part 3 (sweep A-3): ONE table of the CMDB cache, a page at a time, TO THE END. Each page (up to 1,000 entities)
        goes to -OnPage { param($Entities) } before the next is read. There is NO page limit: the old reader stopped after
        100 pages (100,000 rows) without a word, which at 500,000 CIs dropped about 80 % of the cache. Every page goes
        through the shared storage helper (Invoke-SIStorageRequest -- its retry), following x-ms-continuation-Next*.
        A missing table (404) is an empty one. A page that still fails after the helper's retries THROWS with a named
        reason -- the caller treats the cache as INCOMPLETE, never as complete with fewer rows.
        -Request { param($Uri) } -> @{ Content; Headers } | $null (404): the test seam (default: the storage helper).
        Answers the number of entities read.
    #>
    param([Parameter(Mandatory)][object]$Context, [Parameter(Mandatory)][string]$Table, [string]$PartitionKey,
          [Parameter(Mandatory)][scriptblock]$OnPage, [scriptblock]$Request)
    if (-not $Request) {
        $Request = { param([string]$Uri) Invoke-SIStorageRequest -Method GET -Uri $Uri -AllowNotFound -Headers @{ 'x-ms-version' = '2020-12-06'; Accept = 'application/json;odata=nometadata' } -What ("CMDB cache table '{0}'" -f $Table) }
    }
    $n = 0L; $next = $null; $pages = 0
    do {
        $qs = @()
        if ($PartitionKey) { $qs += ('$filter=PartitionKey%20eq%20''{0}''' -f [uri]::EscapeDataString($PartitionKey)) }
        if ($next) { $qs += ('NextPartitionKey={0}' -f [uri]::EscapeDataString($next.Partition)); if ($next.Row) { $qs += ('NextRowKey={0}' -f [uri]::EscapeDataString($next.Row)) } }
        $url = "https://$($Context.AccountName).table.core.windows.net/$Table()"
        if ($qs.Count -gt 0) { $url = $url + '?' + ($qs -join '&') }
        $resp = $null
        try { $resp = & $Request $url }
        catch { throw ("the CMDB cache table '{0}' could not be read to the end (page {1}, {2} entities read): {3}" -f $Table, ($pages + 1), $n, $_.Exception.Message) }
        if ($null -eq $resp) { if ($pages -eq 0) { return $n }; throw ("the CMDB cache table '{0}' vanished while it was read (page {1})" -f $Table, ($pages + 1)) }
        $parsed = ([string]$resp.Content) | ConvertFrom-Json
        $page = @(); if ($parsed -and $parsed.value) { $page = @($parsed.value) }
        $parsed = $null
        if ($page.Count -gt 0) { $n += $page.Count; $null = & $OnPage $page }
        $page = $null
        $h = $resp.Headers
        $nextP = $null; $nextR = $null
        if ($h) { $nextP = $h['x-ms-continuation-NextPartitionKey']; $nextR = $h['x-ms-continuation-NextRowKey'] }
        if ($nextP) { $next = @{ Partition = [string](@($nextP)[0]); Row = [string](@($nextR)[0]) } } else { $next = $null }
        $resp = $null; $pages++
    } while ($next)
    $n
}

function Get-SICmdbTableEntities {
    <# Returns array of entity pscustomobjects. Optional partition filter. Every page to the end (Read-SICmdbTablePages:
       no page limit, the storage helper's retry). Returns empty array on 404 (table missing); a read that cannot finish
       THROWS -- never a shorter list. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][string]$Table,
        [Parameter()][string]$PartitionKey,
        [scriptblock]$Request
    )
    $out = New-Object System.Collections.Generic.List[object]
    $p = @{ Context = $Context; Table = $Table; PartitionKey = $PartitionKey; OnPage = { param($page) foreach ($e in $page) { $out.Add($e) } } }
    if ($Request) { $p['Request'] = $Request }
    $null = Read-SICmdbTablePages @p
    return $out.ToArray()
}

# #891 part 3: what the last cache read of this process could not finish -- table -> reason. A caller that needs the WHOLE
# cache asks Test-SICmdbCacheReadComplete and treats a failed read as an incomplete cache, never as an empty or short one.
$script:SICmdbCacheReadIssues = @{}
function Get-SICmdbCacheReadIssues { , @($script:SICmdbCacheReadIssues.GetEnumerator() | Sort-Object Name | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Value }) }
function Test-SICmdbCacheReadComplete { $script:SICmdbCacheReadIssues.Count -eq 0 }

function Initialize-SICmdbCacheTables {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Context)

    # v2.2.422 (#58.5) -- THE OAUTH BAIL-OUT IS GONE, and it was not a small thing.
    #
    # It read: "Under OAuth mode the key is empty by design, so the signature helper throws ...
    # Skip table init silently in that case -- the empty-cache path in Reconcile already handles
    # missing entries gracefully. TODO: rewrite CmdbCache to use OAuth bearer tokens."
    #
    # "Handles it gracefully" turned out to mean: the cache is never written, so cmdbName /
    # cmdbCriticality / cmdbDataSensitivity came through EMPTY on every run, for every customer on
    # OAuth storage, since v2.2.314. Measured 2026-08-11 on live output -- 0 of 1,810 Detailed rows
    # carried any of the three, while cmdbId sat at 66% (a foreign key pointing at records that were
    # never loaded, which is exactly why it looked like it was working). ~510 references to cmdbName
    # across the RA catalog silently produced blanks, and the cmdb WEIGHTED LAYER contributed nothing
    # to risk scores the whole time. The operator's own read was "used it in a VM env and not had
    # issues" -- the symptoms were absent, the data was not.
    #
    # 🔑 A silent `return` is never a graceful degradation when the thing being skipped is the only
    # writer of data other code depends on. If a capability genuinely cannot run, SAY SO.
    #
    # Both write paths are now OAuth-aware, so there is nothing to skip. Mock stays supported.
    if ([string]::IsNullOrWhiteSpace([string]$Context.AccountName) -and $Context.Mode -ne 'Mock') {
        Write-SIWarn 'CMDB cache tables cannot be initialised -- no storage account resolved. cmdb* columns will be EMPTY this run.'
        return
    }

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
        $r = @(Get-SICmdbTableEntities -Context $Context -Table 'sicmdbservices' -PartitionKey 'service')
        $script:SICmdbCacheReadIssues.Remove('sicmdbservices')
        return $r
    } catch {
        # #891 part 3: a named warning, and the cache is marked INCOMPLETE (Test-SICmdbCacheReadComplete) -- never "no services"
        $script:SICmdbCacheReadIssues['sicmdbservices'] = $_.Exception.Message
        Write-Warning ('CMDB cache INCOMPLETE -- the services could not be read: {0}' -f $_.Exception.Message)
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
        $r = @(Get-SICmdbTableEntities -Context $Context -Table 'sicmdbcis')
        $script:SICmdbCacheReadIssues.Remove('sicmdbcis')
        return $r
    } catch {
        # #891 part 3: this used to be a SILENT empty list -- now a named warning and the cache marked INCOMPLETE
        $script:SICmdbCacheReadIssues['sicmdbcis'] = $_.Exception.Message
        Write-Warning ('CMDB cache INCOMPLETE -- the CIs could not be read: {0}' -f $_.Exception.Message)
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
