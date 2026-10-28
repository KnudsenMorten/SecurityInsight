#Requires -Version 5.1
<#
    Shodan response cache + per-month scan-credit ledger (Azure Table Storage).

    Two tables under the same StorageContext:
      sishodanhosts    -- per-IP cached /host/{ip} response
                              PartitionKey = first octet (sharding)
                              RowKey       = lowercased IP
                              Columns      = JsonResponse (string), CachedAtUtc, ShodanLastUpdate
      sishodanbudget   -- per-month scan-credit usage counter
                              PartitionKey = 'shodan'
                              RowKey       = yyyy-MM   (e.g. 2026-04)
                              Columns      = ScanCreditsUsed (int), LastUpdatedUtc

    Cache TTL is policy not invariant: callers ask for "fresh within N days"
    (default 7) -- if the cached entry is older they re-fetch. Shodan re-indexes
    every IP it knows about every ~7 days anyway, so a tighter TTL just burns
    request quota with no fresh data.

    The budget ledger is advisory: callers consult before a /scan call,
    increment after success, refuse the call when over $global:SI_ShodanMonthlyCreditCap.
#>

. (Join-Path $PSScriptRoot 'StorageContext.ps1')

# 🔴 REST, NOT AzTable (#157). Under the OAuth storage context every engine uses by default, AzTable's
# CloudTable calls failed on this storage account -- measured 2026-09-28: every `Add-AzTableRow` threw
# "The specified resource does not exist" -- while the ledger READ came back empty WITHOUT an error, which
# the #127 code correctly treats as "a month with no row = 0". So the credit cap read 0 and never
# recorded a scan: fail-OPEN again, one layer below #127's fix, and no Shodan response was ever cached.
# Same REST + auth path as CmdbCache.ps1 / FingerprintCache.ps1 (a bearer token for the run's identity).
# A QUERY is used for reads, never an entity GET: on an existing table a query
# with no match is 200 + empty, and only a MISSING TABLE is 404 -- so "no row" and "cannot read" stay
# distinguishable, which the cap depends on.
function _SIShodanTableCall {
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][ValidateSet('GET','PUT','POST')][string]$Method,
        [Parameter(Mandatory)][string]$ResourcePath,
        [string]$Query,
        [hashtable]$Body
    )
    $url  = 'https://{0}.table.core.windows.net/{1}' -f $Context.AccountName, $ResourcePath
    if ($Query) { $url = $url + '?' + $Query }
    $date = ConvertTo-SIRfc1123Date
    $auth = Get-SITableAuthorizationHeader -Context $Context -Date $date -Url $url
    $headers = @{
        'x-ms-date'    = $date
        'x-ms-version' = '2020-12-06'
        Accept         = 'application/json;odata=nometadata'
        Authorization  = $auth
    }
    $req = @{ Method = $Method; Uri = $url; Headers = $headers; UseBasicParsing = $true; ErrorAction = 'Stop' }
    if ($Body) {
        # UTF-8 bytes: PS 5.1 would otherwise send a string body as ISO-8859-1.
        $req.Body        = [System.Text.Encoding]::UTF8.GetBytes(($Body | ConvertTo-Json -Compress -Depth 10))
        $req.ContentType = 'application/json;charset=utf-8'
    }
    Invoke-WebRequest @req
}

# One entity by key, via a query. Returns the entity, $null when there is no such row, and THROWS when the
# table cannot be read (missing table, auth, network) -- the caller decides what "unreadable" means.
function _SIShodanGetEntity {
    param([object]$Context, [string]$Table, [string]$PartitionKey, [string]$RowKey)
    $f = "PartitionKey eq '{0}' and RowKey eq '{1}'" -f ($PartitionKey -replace "'", "''"), ($RowKey -replace "'", "''")
    $resp = _SIShodanTableCall -Context $Context -Method GET -ResourcePath "$Table()" -Query ('$filter=' + [uri]::EscapeDataString($f))
    $rows = @(($resp.Content | ConvertFrom-Json).value)
    if ($rows.Count -eq 0) { return $null }
    return $rows[0]
}

# Insert-or-replace (PUT without If-Match -- with it, a first insert is a 404).
function _SIShodanPutEntity {
    param([object]$Context, [string]$Table, [string]$PartitionKey, [string]$RowKey, [hashtable]$Properties)
    $entity = @{} + $Properties
    $entity['PartitionKey'] = $PartitionKey
    $entity['RowKey']       = $RowKey
    $path = "$Table(PartitionKey='{0}',RowKey='{1}')" -f ($PartitionKey -replace "'", "''"), ($RowKey -replace "'", "''")
    _SIShodanTableCall -Context $Context -Method PUT -ResourcePath $path -Body $entity | Out-Null
}

function Initialize-SIShodanCacheTables {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Context)

    if ($Context.Mode -eq 'Mock') {
        foreach ($t in @('sishodanhosts','sishodanbudget')) {
            if (-not $Context.MockState.Tables.ContainsKey($t)) {
                $Context.MockState.Tables[$t] = @{}
            }
        }
        return
    }

    # Create both tables if missing (201 created, 409 already there). If storage cannot be reached, the
    # store is flagged unavailable: live fetch still works, the cache is skipped, and the credit ledger
    # reads UNKNOWN -- so paid scans are refused rather than uncapped (#127).
    foreach ($t in @('sishodanhosts','sishodanbudget')) {
        try {
            _SIShodanTableCall -Context $Context -Method POST -ResourcePath 'Tables' -Body @{ TableName = $t } | Out-Null
        } catch {
            $code = 0
            if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
            if ($code -eq 409) { continue }
            Write-Warning ('Shodan cache: storage table {0} is not reachable (HTTP {1}) -- proceeding without the cache, and paid scans are refused this run because the monthly credit count cannot be read.' -f $t, $code)
            Add-Member -InputObject $Context -NotePropertyName '_ShodanStoreUnavailable' -NotePropertyValue $true -Force
            return
        }
    }
}

# Helper: returns $true when Initialize flagged the table store as unreachable so the
# read/write helpers should no-op. Centralised so the Add/Get callers stay terse.
function _SIShodanSkip {
    param($Context)
    if (-not $Context) { return $true }
    if ($Context.PSObject.Properties['_ShodanStoreUnavailable'] -and $Context._ShodanStoreUnavailable) { return $true }
    return $false
}

function Get-SIShodanHostFromCache {
    <#
        Returns @{ Json=<raw>; CachedAtUtc=<dt>; AgeDays=<int> } when a cached
        entry exists, otherwise $null. Caller decides whether AgeDays exceeds
        the freshness budget.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][string]$Ip
    )
    $ipKey   = $Ip.ToLowerInvariant()
    $partKey = ($ipKey -split '\.')[0]   # IPv4 first octet; IPv6 uses 'ipv6' below
    if ($ipKey -like '*:*') { $partKey = 'ipv6' }

    if ($Context.Mode -eq 'Mock') {
        $store = $Context.MockState.Tables['sishodanhosts']
        $compositeKey = ('{0}|{1}' -f $partKey, $ipKey)
        if (-not $store.ContainsKey($compositeKey)) { return $null }
        $row = $store[$compositeKey]
    } else {
        if (_SIShodanSkip $Context) { return $null }
        try {
            $row = _SIShodanGetEntity -Context $Context -Table 'sishodanhosts' -PartitionKey $partKey -RowKey $ipKey
        } catch { return $null }
        if (-not $row) { return $null }
    }

    # UTC on both editions. `[datetime]"...Z"` is LOCAL time on PS 5.1 (measured: a row written a second
    # earlier read back as -1 days old on a UTC+2 host), while pwsh 7's ConvertFrom-Json already hands back
    # a DateTime. Either way it is compared against UtcNow, so normalise first.
    $cachedAt = if ($row.CachedAtUtc -is [datetime]) { ([datetime]$row.CachedAtUtc).ToUniversalTime() } else {
        [datetime]::Parse([string]$row.CachedAtUtc, [System.Globalization.CultureInfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal)
    }
    $age      = [int]([math]::Floor(([datetime]::UtcNow - $cachedAt).TotalDays))
    return @{
        Json        = [string]$row.JsonResponse
        CachedAtUtc = $cachedAt
        AgeDays     = $age
    }
}

function Set-SIShodanHostCache {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][string]$Ip,
        [Parameter(Mandatory)][AllowEmptyString()][string]$JsonResponse,
        [string]$ShodanLastUpdate = ''
    )
    $ipKey   = $Ip.ToLowerInvariant()
    $partKey = ($ipKey -split '\.')[0]
    if ($ipKey -like '*:*') { $partKey = 'ipv6' }
    $row = @{
        JsonResponse     = $JsonResponse
        CachedAtUtc      = ([datetime]::UtcNow.ToString('o'))
        ShodanLastUpdate = $ShodanLastUpdate
    }

    if ($Context.Mode -eq 'Mock') {
        $store = $Context.MockState.Tables['sishodanhosts']
        $store[('{0}|{1}' -f $partKey, $ipKey)] = $row
        return
    }
    if (_SIShodanSkip $Context) { return }
    try {
        _SIShodanPutEntity -Context $Context -Table 'sishodanhosts' -PartitionKey $partKey -RowKey $ipKey -Properties $row

    } catch {
        Write-Verbose ('Set-SIShodanHostCache: cache write skipped -- {0}' -f $_.Exception.Message)
    }
}

function Get-SIShodanCreditsUsedThisMonth {
    <#
        Paid scan credits used this month -- or $null when the ledger CANNOT BE READ.

        The cap FAILS CLOSED (#127). This used to return 0 on any failure, including the AzTable module
        being absent (which nothing installs), so the cap check "0 < cap" passed and -ForceShodanRescan
        spent paid credits with no limit at all. "Unknown" is now $null and callers must refuse a paid
        scan on it. A month with no row yet is a genuine 0.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Context)
    $month = [datetime]::UtcNow.ToString('yyyy-MM')

    if ($Context.Mode -eq 'Mock') {
        $store = $Context.MockState.Tables['sishodanbudget']
        if (-not $store.ContainsKey($month)) { return 0 }
        return [int]$store[$month].ScanCreditsUsed
    }
    if (_SIShodanSkip $Context) { return $null }
    try {
        $row = _SIShodanGetEntity -Context $Context -Table 'sishodanbudget' -PartitionKey 'shodan' -RowKey $month

    } catch { return $null }
    if (-not $row) { return 0 }
    return [int]$row.ScanCreditsUsed
}

function Add-SIShodanCreditsUsed {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][int]$Delta
    )
    if ($Delta -le 0) { return }
    $month   = [datetime]::UtcNow.ToString('yyyy-MM')
    $current = Get-SIShodanCreditsUsedThisMonth -Context $Context
    if ($null -eq $current -and $Context.Mode -ne 'Mock') {
        # Unreadable ledger: writing "0 + delta" would RESET the month's real count.
        Write-Verbose 'Add-SIShodanCreditsUsed: ledger unreadable -- not writing a guessed total'
        return
    }
    $new     = [int]$current + $Delta
    $row = @{
        ScanCreditsUsed = $new
        LastUpdatedUtc  = ([datetime]::UtcNow.ToString('o'))
    }
    if ($Context.Mode -eq 'Mock') {
        $Context.MockState.Tables['sishodanbudget'][$month] = $row
        return
    }
    if (_SIShodanSkip $Context) { return }
    try {
        _SIShodanPutEntity -Context $Context -Table 'sishodanbudget' -PartitionKey 'shodan' -RowKey $month -Properties $row

    } catch {
        Write-Verbose ('Add-SIShodanCreditsUsed: budget write skipped -- {0}' -f $_.Exception.Message)
    }
}
