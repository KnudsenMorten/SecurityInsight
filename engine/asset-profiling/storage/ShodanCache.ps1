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

    foreach ($t in @('sishodanhosts','sishodanbudget')) {
        try {
            $tbl = Get-AzStorageTable -Name $t -Context $Context.AzContext -ErrorAction Stop
        } catch {
            $tbl = New-AzStorageTable -Name $t -Context $Context.AzContext
        }
    }
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
        try {
            $tbl = Get-AzStorageTable -Name 'sishodanhosts' -Context $Context.AzContext -ErrorAction Stop
            $row = Get-AzTableRow -Table $tbl.CloudTable -PartitionKey $partKey -RowKey $ipKey -ErrorAction Stop
        } catch { return $null }
        if (-not $row) { return $null }
    }

    $cachedAt = [datetime]$row.CachedAtUtc
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
    $tbl = Get-AzStorageTable -Name 'sishodanhosts' -Context $Context.AzContext
    Add-AzTableRow -Table $tbl.CloudTable -PartitionKey $partKey -RowKey $ipKey -Property $row -UpdateExisting | Out-Null
}

function Get-SIShodanCreditsUsedThisMonth {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Context)
    $month = [datetime]::UtcNow.ToString('yyyy-MM')

    if ($Context.Mode -eq 'Mock') {
        $store = $Context.MockState.Tables['sishodanbudget']
        if (-not $store.ContainsKey($month)) { return 0 }
        return [int]$store[$month].ScanCreditsUsed
    }
    try {
        $tbl = Get-AzStorageTable -Name 'sishodanbudget' -Context $Context.AzContext -ErrorAction Stop
        $row = Get-AzTableRow -Table $tbl.CloudTable -PartitionKey 'shodan' -RowKey $month -ErrorAction Stop
    } catch { return 0 }
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
    $new     = $current + $Delta
    $row = @{
        ScanCreditsUsed = $new
        LastUpdatedUtc  = ([datetime]::UtcNow.ToString('o'))
    }
    if ($Context.Mode -eq 'Mock') {
        $Context.MockState.Tables['sishodanbudget'][$month] = $row
        return
    }
    $tbl = Get-AzStorageTable -Name 'sishodanbudget' -Context $Context.AzContext
    Add-AzTableRow -Table $tbl.CloudTable -PartitionKey 'shodan' -RowKey $month -Property $row -UpdateExisting | Out-Null
}
