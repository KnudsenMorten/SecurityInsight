#Requires -Version 5.1
<#
    Per-resource-type AI-driven property profile cache (Azure Table).

    Solves: Azure has 600+ resource types each with a different `properties`
    blob. Hardcoding "which props matter for fp_meta vs security posture"
    per type would be a never-ending tax. Instead, on first encounter of
    a new type, ask AI: "given this sample resource of type X, which top-
    level property paths are stable enough for fingerprint caching, and
    which are security-posture-relevant for tier classification?". Cache
    the verdict per (type, prompt-version) so subsequent resources of the
    same type reuse the same property selection without further AI calls.

    Schema:
      PartitionKey = 'azureresourcetype'
      RowKey       = ConvertTo-SISafeKey "{type}|{prompt-version}"
      Columns      : type_name, prompt_version, fp_meta_props (JSON string),
                     posture_props (JSON string), reasoning, cached_at

    Cost model:
      First run on a fresh customer with N distinct resource types
      -> N AI calls (~$0.01 each). Subsequent runs hit the cache for every
      asset of those types. New type appearing later = 1 new AI call.
#>

. (Join-Path $PSScriptRoot 'StorageContext.ps1')

function ConvertTo-SIUtf8Body {
    <# A JSON body as UTF-8 BYTES. On PS 5.1 Invoke-RestMethod transcodes a STRING body to a single-byte
       encoding, so AI-written text (reasoning, app names -- Danish letters, dashes) was stored mangled or
       rejected (#126; the same defect #114 fixed for Graph). CmdbCache.ps1 already sends bytes. The
       leading comma is load-bearing: without it PowerShell unrolls the byte[] into Object[] and
       Invoke-RestMethod stops treating it as a raw body. #>
    param([Parameter(Mandatory)][string]$Json)
    return ,([System.Text.Encoding]::UTF8.GetBytes($Json))
}

# Every Azure Table call of this cache goes through the SHARED storage request (Invoke-SIStorageRequest, SI-AzRest.ps1): it
# waits out Microsoft's transient answers -- no answer (a connection timeout, reset or DNS failure), 408, 429, 5xx -- with
# Retry-After honoured, a bounded number of times (2026-10-22, one install: a bare Invoke-RestMethod GET here hit "Connection
# timed out" ONCE and the whole endpoint run was thrown away). And THIS IS A CACHE: a call that still fails is a cache MISS
# with a warning (a read answers "not cached", a write is skipped) -- never a run failure.
# (the headers are written at each call: this file is also dot-sourced inside a function, where a $script: value is not reliable)

function ConvertFrom-SITableAnswer {
    <# PURE. The parsed JSON body of a table answer ($null for none / a 404). #>
    param($Response)
    if ($null -eq $Response) { return $null }
    $t = [string]$Response.Content
    if ([string]::IsNullOrWhiteSpace($t)) { return $null }
    try { return ($t | ConvertFrom-Json) } catch { return $t }
}

function Write-SITableCacheMiss {
    <# The one warning of a table call that failed after the shared retries: the cache is skipped for it this run. #>
    param([Parameter(Mandatory)][string]$What, [Parameter(Mandatory)]$ErrorRecord, [string]$Then = 'read as a cache miss this run')
    Write-Warning ('{0} failed ({1}) -- {2}.' -f $What, (([string]$ErrorRecord.Exception.Message -replace '\s+', ' ').Trim()), $Then)
}
function Initialize-SITypeProfileTable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [string]$TableName = 'sitypeprofiles'
    )

    if ($Context.Mode -eq 'Mock') {
        if (-not $Context.MockState.Tables.ContainsKey($TableName)) {
            $Context.MockState.Tables[$TableName] = @{}
        }
        return $TableName
    }

    $url = 'https://{0}.table.core.windows.net/Tables' -f $Context.AccountName
    $body = ConvertTo-Json @{ TableName = $TableName } -Compress
    # 409 = the table is there already
    $what = "Create table '{0}'" -f $TableName
    # 409 = the table is there already
    try { $null = Invoke-SIStorageRequest -Method POST -Uri $url -Body (ConvertTo-SIUtf8Body -Json $body) -ContentType 'application/json; charset=utf-8' -Headers @{ Accept = 'application/json;odata=nometadata' } -AllowStatus @(409) -What $what }
    catch { Write-SITableCacheMiss -What $what -ErrorRecord $_ -Then 'the cache is skipped this run (every read is a miss)' }
    return $TableName
}

function Get-SITypeProfileRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][string]$TableName,
        [Parameter(Mandatory)][string]$TypeName,
        [Parameter(Mandatory)][string]$PromptVersion
    )

    $rk = ConvertTo-SISafeKey -Key ('{0}|{1}' -f $TypeName, $PromptVersion)
    $pk = 'azureresourcetype'

    if ($Context.Mode -eq 'Mock') {
        $key = '{0}|{1}' -f $pk, $rk
        $hit = $Context.MockState.Tables[$TableName][$key]
        if ($null -ne $hit) { return [pscustomobject]$hit }
        return $null
    }

    $url = "https://$($Context.AccountName).table.core.windows.net/$TableName(PartitionKey='$pk',RowKey='$rk')"
    $what = "Read the type profile of '{0}' from table '{1}'" -f $TypeName, $TableName
    try { return (ConvertFrom-SITableAnswer (Invoke-SIStorageRequest -Method GET -Uri $url -Headers @{ Accept = 'application/json;odata=nometadata' } -AllowNotFound -What $what)) }
    catch { Write-SITableCacheMiss -What $what -ErrorRecord $_; return $null }
}

function Get-SITypeProfilesByPartition {
    <#
        Lists all entries in a partition. Used by the Show-SIAICache
        launcher to enumerate the full cache for review/audit. Returns
        an array of PSCustomObject (one per entry).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][string]$TableName,
        [Parameter(Mandatory)][string]$Partition
    )

    if ($Context.Mode -eq 'Mock') {
        $rows = New-Object System.Collections.ArrayList
        foreach ($k in $Context.MockState.Tables[$TableName].Keys) {
            $entry = $Context.MockState.Tables[$TableName][$k]
            if ($entry.PartitionKey -eq $Partition) { [void]$rows.Add([pscustomobject]$entry) }
        }
        return $rows.ToArray()
    }

    $filter = "PartitionKey%20eq%20'$Partition'"
    $url = "https://$($Context.AccountName).table.core.windows.net/$TableName()?`$filter=$filter"
    $what = "List partition '{0}' of table '{1}'" -f $Partition, $TableName
    $resp = $null
    try { $resp = ConvertFrom-SITableAnswer (Invoke-SIStorageRequest -Method GET -Uri $url -Headers @{ Accept = 'application/json;odata=nometadata' } -AllowNotFound -What $what) }
    catch { Write-SITableCacheMiss -What $what -ErrorRecord $_ -Then 'listed as empty this time' }
    if ($resp -and $resp.value) { return @($resp.value) }
    return @()
}

function Get-SISignalMapRecord {
    <#
        AI signal-map cache: per (engine, assetType, promptVersion) AI-discovered
        list of {path, weight, reason} entries used by Stage Enrich to compute
        a composite XENG_CriticalityScore. Same table, partition='signalmap'.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][string]$TableName,
        [Parameter(Mandatory)][string]$Engine,
        [Parameter(Mandatory)][string]$AssetType,
        [Parameter(Mandatory)][string]$PromptVersion
    )
    $rk = ConvertTo-SISafeKey -Key ('{0}|{1}|{2}' -f $Engine, $AssetType, $PromptVersion)
    $pk = 'signalmap'
    if ($Context.Mode -eq 'Mock') {
        $key = '{0}|{1}' -f $pk, $rk
        $hit = $Context.MockState.Tables[$TableName][$key]
        if ($null -ne $hit) { return [pscustomobject]$hit }
        return $null
    }
    $url = "https://$($Context.AccountName).table.core.windows.net/$TableName(PartitionKey='$pk',RowKey='$rk')"
    $what = "Read the signal map of {0}/{1} from table '{2}'" -f $Engine, $AssetType, $TableName
    try { return (ConvertFrom-SITableAnswer (Invoke-SIStorageRequest -Method GET -Uri $url -Headers @{ Accept = 'application/json;odata=nometadata' } -AllowNotFound -What $what)) }
    catch { Write-SITableCacheMiss -What $what -ErrorRecord $_; return $null }
}

function Set-SISignalMapRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][string]$TableName,
        [Parameter(Mandatory)][string]$Engine,
        [Parameter(Mandatory)][string]$AssetType,
        [Parameter(Mandatory)][string]$PromptVersion,
        [Parameter(Mandatory)]$Signals,        # array of @{path; weight; reason}
        [string]$Reasoning = ''
    )
    $rk = ConvertTo-SISafeKey -Key ('{0}|{1}|{2}' -f $Engine, $AssetType, $PromptVersion)
    $pk = 'signalmap'
    $entity = @{
        PartitionKey   = $pk
        RowKey         = $rk
        engine         = $Engine
        asset_type     = $AssetType
        prompt_version = $PromptVersion
        signals_json   = ($Signals | ConvertTo-Json -Compress -Depth 6)
        reasoning      = $Reasoning
        cached_at      = ([datetime]::UtcNow.ToString('o'))
    }
    if ($Context.Mode -eq 'Mock') {
        $key = '{0}|{1}' -f $pk, $rk
        $Context.MockState.Tables[$TableName][$key] = $entity
        return
    }
    $url = "https://$($Context.AccountName).table.core.windows.net/$TableName(PartitionKey='$pk',RowKey='$rk')"
    $body = $entity | ConvertTo-Json -Compress
    $what = "Write the signal map of {0}/{1} to table '{2}'" -f $Engine, $AssetType, $TableName
    try { $null = Invoke-SIStorageRequest -Method PUT -Uri $url -Body (ConvertTo-SIUtf8Body -Json $body) -ContentType 'application/json; charset=utf-8' -Headers @{ Accept = 'application/json;odata=nometadata' } -What $what }
    catch { Write-SITableCacheMiss -What $what -ErrorRecord $_ -Then 'not cached this run (asked again next run)' }
}

function Get-SIAppGroupRecord {
    <#
        Cache lookup for an AI-derived app-group identity. Key = SHA-256 of
        (RG, sorted member resource names). Membership change -> new key ->
        cache miss -> fresh AI call. So renames or additions naturally
        invalidate the cluster name.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][string]$TableName,
        [Parameter(Mandatory)][string]$ClusterKey
    )

    $rk = ConvertTo-SISafeKey -Key $ClusterKey
    $pk = 'appgroup'

    if ($Context.Mode -eq 'Mock') {
        $key = '{0}|{1}' -f $pk, $rk
        $hit = $Context.MockState.Tables[$TableName][$key]
        if ($null -ne $hit) { return [pscustomobject]$hit }
        return $null
    }

    $url = "https://$($Context.AccountName).table.core.windows.net/$TableName(PartitionKey='$pk',RowKey='$rk')"
    $what = "Read the app group '{0}' from table '{1}'" -f $ClusterKey, $TableName
    try { return (ConvertFrom-SITableAnswer (Invoke-SIStorageRequest -Method GET -Uri $url -Headers @{ Accept = 'application/json;odata=nometadata' } -AllowNotFound -What $what)) }
    catch { Write-SITableCacheMiss -What $what -ErrorRecord $_; return $null }
}

function Set-SIAppGroupRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][string]$TableName,
        [Parameter(Mandatory)][string]$ClusterKey,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$AppName,
        [Parameter(Mandatory)][string]$AppType,
        [double]$Confidence = 0.0,
        [string]$Reasoning  = '',
        [string[]]$MemberAssetIds = @()
    )

    $rk = ConvertTo-SISafeKey -Key $ClusterKey
    $pk = 'appgroup'

    $entity = @{
        PartitionKey      = $pk
        RowKey            = $rk
        cluster_key       = $ClusterKey
        resource_group    = $ResourceGroup
        app_name          = $AppName
        app_type          = $AppType
        confidence        = $Confidence
        reasoning         = $Reasoning
        member_asset_ids  = ($MemberAssetIds | ConvertTo-Json -Compress)
        cached_at         = ([datetime]::UtcNow.ToString('o'))
    }

    if ($Context.Mode -eq 'Mock') {
        $key = '{0}|{1}' -f $pk, $rk
        $Context.MockState.Tables[$TableName][$key] = $entity
        return
    }

    $url = "https://$($Context.AccountName).table.core.windows.net/$TableName(PartitionKey='$pk',RowKey='$rk')"
    $body = $entity | ConvertTo-Json -Compress
    $what = "Write to table '{0}' ({1})" -f $TableName, $pk
    try { $null = Invoke-SIStorageRequest -Method PUT -Uri $url -Body (ConvertTo-SIUtf8Body -Json $body) -ContentType 'application/json; charset=utf-8' -Headers @{ Accept = 'application/json;odata=nometadata' } -What $what }
    catch { Write-SITableCacheMiss -What $what -ErrorRecord $_ -Then 'not cached this run (asked again next run)' }
}

function Set-SITypeProfileRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][string]$TableName,
        [Parameter(Mandatory)][string]$TypeName,
        [Parameter(Mandatory)][string]$PromptVersion,
        [Parameter(Mandatory)][string[]]$FpMetaProps,
        [Parameter(Mandatory)][string[]]$PostureProps,
        [string]$Reasoning = ''
    )

    $rk = ConvertTo-SISafeKey -Key ('{0}|{1}' -f $TypeName, $PromptVersion)
    $pk = 'azureresourcetype'

    $entity = @{
        PartitionKey   = $pk
        RowKey         = $rk
        type_name      = $TypeName
        prompt_version = $PromptVersion
        fp_meta_props  = ($FpMetaProps  | ConvertTo-Json -Compress)
        posture_props  = ($PostureProps | ConvertTo-Json -Compress)
        reasoning      = $Reasoning
        cached_at      = ([datetime]::UtcNow.ToString('o'))
    }

    if ($Context.Mode -eq 'Mock') {
        $key = '{0}|{1}' -f $pk, $rk
        $Context.MockState.Tables[$TableName][$key] = $entity
        return
    }

    $url = "https://$($Context.AccountName).table.core.windows.net/$TableName(PartitionKey='$pk',RowKey='$rk')"
    $body = $entity | ConvertTo-Json -Compress
    $what = "Write to table '{0}' ({1})" -f $TableName, $pk
    try { $null = Invoke-SIStorageRequest -Method PUT -Uri $url -Body (ConvertTo-SIUtf8Body -Json $body) -ContentType 'application/json; charset=utf-8' -Headers @{ Accept = 'application/json;odata=nometadata' } -What $what }
    catch { Write-SITableCacheMiss -What $what -ErrorRecord $_ -Then 'not cached this run (asked again next run)' }
}
