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
    $date = ConvertTo-SIRfc1123Date
    $auth = Get-SITableAuthorizationHeader -Context $Context -Date $date -Url $url

    $headers = @{
        'x-ms-date'    = $date
        'x-ms-version' = '2020-08-04'
        'Accept'       = 'application/json;odata=nometadata'
        'Content-Type' = 'application/json'
        'Authorization'= $auth
    }
    try {
        Invoke-RestMethod -Method Post -Uri $url -Headers $headers -Body $body -ErrorAction Stop | Out-Null
    } catch {
        if ($_.Exception.Response -and [int]$_.Exception.Response.StatusCode -ne 409) { throw }
    }
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
    $date = ConvertTo-SIRfc1123Date
    $auth = Get-SITableAuthorizationHeader -Context $Context -Date $date -Url $url
    $headers = @{
        'x-ms-date'    = $date
        'x-ms-version' = '2020-08-04'
        'Accept'       = 'application/json;odata=nometadata'
        'Authorization'= $auth
    }
    try {
        return Invoke-RestMethod -Method Get -Uri $url -Headers $headers -ErrorAction Stop
    } catch {
        if ($_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 404) { return $null }
        throw
    }
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
    $date = ConvertTo-SIRfc1123Date
    $auth = Get-SITableAuthorizationHeader -Context $Context -Date $date -Url $url
    $headers = @{
        'x-ms-date'    = $date
        'x-ms-version' = '2020-08-04'
        'Accept'       = 'application/json;odata=nometadata'
        'Authorization'= $auth
    }
    try {
        $resp = Invoke-RestMethod -Method Get -Uri $url -Headers $headers -ErrorAction Stop
        if ($resp.value) { return @($resp.value) }
        return @()
    } catch {
        if ($_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 404) { return @() }
        throw
    }
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
    $date = ConvertTo-SIRfc1123Date
    $auth = Get-SITableAuthorizationHeader -Context $Context -Date $date -Url $url
    try {
        return Invoke-RestMethod -Method Get -Uri $url -Headers @{
            'x-ms-date'    = $date
            'x-ms-version' = '2020-08-04'
            'Accept'       = 'application/json;odata=nometadata'
            'Authorization'= $auth
        } -ErrorAction Stop
    } catch {
        if ($_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 404) { return $null }
        throw
    }
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
    $date = ConvertTo-SIRfc1123Date
    $auth = Get-SITableAuthorizationHeader -Context $Context -Date $date -Url $url
    Invoke-RestMethod -Method Put -Uri $url -Headers @{
        'x-ms-date'    = $date
        'x-ms-version' = '2020-08-04'
        'Accept'       = 'application/json;odata=nometadata'
        'Content-Type' = 'application/json'
        'Authorization'= $auth
    } -Body $body -ErrorAction Stop | Out-Null
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
    $date = ConvertTo-SIRfc1123Date
    $auth = Get-SITableAuthorizationHeader -Context $Context -Date $date -Url $url
    $headers = @{
        'x-ms-date'    = $date
        'x-ms-version' = '2020-08-04'
        'Accept'       = 'application/json;odata=nometadata'
        'Authorization'= $auth
    }
    try {
        return Invoke-RestMethod -Method Get -Uri $url -Headers $headers -ErrorAction Stop
    } catch {
        if ($_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 404) { return $null }
        throw
    }
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
    $date = ConvertTo-SIRfc1123Date
    $auth = Get-SITableAuthorizationHeader -Context $Context -Date $date -Url $url
    $headers = @{
        'x-ms-date'    = $date
        'x-ms-version' = '2020-08-04'
        'Accept'       = 'application/json;odata=nometadata'
        'Content-Type' = 'application/json'
        'Authorization'= $auth
    }
    Invoke-RestMethod -Method Put -Uri $url -Headers $headers -Body $body -ErrorAction Stop | Out-Null
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
    $date = ConvertTo-SIRfc1123Date
    $auth = Get-SITableAuthorizationHeader -Context $Context -Date $date -Url $url
    $headers = @{
        'x-ms-date'    = $date
        'x-ms-version' = '2020-08-04'
        'Accept'       = 'application/json;odata=nometadata'
        'Content-Type' = 'application/json'
        'Authorization'= $auth
    }
    Invoke-RestMethod -Method Put -Uri $url -Headers $headers -Body $body -ErrorAction Stop | Out-Null
}
