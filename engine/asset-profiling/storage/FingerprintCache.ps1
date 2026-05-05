#Requires -Version 5.1
<#
    SecurityInsight v2.2 -- fingerprint cache adapter (Azure Table Storage).

    Schema:
      PartitionKey = AssetId
      RowKey       = "current"
      Properties   : fp_meta, fp_enrich, si_tier, si_verdict, verdict_expires_at,
                     stable_run_count, last_seen_run_id, last_seen_at

    Multi-writer-safe: each AssetId is its own partition; concurrent writers
    on different assets never contend. ETag-based concurrency on same-asset
    races (last writer wins is acceptable -- a redundant re-classify is
    cheaper than a coordination round-trip).
#>

. (Join-Path $PSScriptRoot 'StorageContext.ps1')

function Initialize-SIFingerprintTable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [string]$TableName = 'sifingerprint'
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
        'x-ms-version' = '2020-08-04'   # min for Bearer-token Table REST
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

function Get-SIFingerprintRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][string]$TableName,
        [Parameter(Mandatory)][string]$AssetId
    )

    $pk = ConvertTo-SISafeKey -Key $AssetId

    if ($Context.Mode -eq 'Mock') {
        $key = '{0}|current' -f $pk
        $hit = $Context.MockState.Tables[$TableName][$key]
        if ($null -ne $hit) { return [pscustomobject]$hit }
        return $null
    }

    # OData v3 string literal escaping: single quote is doubled. Then URL-encode
    # the literal so + & % etc. don't confuse URI parsing. Without this, an
    # AssetId containing ' (e.g. an Azure resource named O'Brien) breaks the
    # PartitionKey='...' OData literal and Azure Tables returns 400 Bad Request.
    $pkLit = [Uri]::EscapeDataString(($pk -replace "'", "''"))
    $url = "https://$($Context.AccountName).table.core.windows.net/$TableName(PartitionKey='$pkLit',RowKey='current')"
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
        # Surface the AssetId + Azure JSON error body (the error path was bare
        # "400 Bad Request" before; impossible to tell which row crashed).
        $detail = if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $_.ErrorDetails.Message } else { $_.Exception.Message }
        throw ('Get-SIFingerprintRecord GET failed for asset={0}: {1}' -f $AssetId, $detail)
    }
}

function Set-SIFingerprintRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][string]$TableName,
        [Parameter(Mandatory)][string]$AssetId,
        [Parameter(Mandatory)][hashtable]$Properties
    )

    $pk = ConvertTo-SISafeKey -Key $AssetId

    $entity = @{} + $Properties
    $entity['PartitionKey']      = $pk
    $entity['RowKey']            = 'current'
    $entity['original_asset_id'] = $AssetId   # preserves the human-readable ID for debugging

    if ($Context.Mode -eq 'Mock') {
        $key = '{0}|current' -f $pk
        $Context.MockState.Tables[$TableName][$key] = $entity
        return
    }

    # See Get-SIFingerprintRecord for OData/URL-encoding rationale.
    $pkLit = [Uri]::EscapeDataString(($pk -replace "'", "''"))
    $url = "https://$($Context.AccountName).table.core.windows.net/$TableName(PartitionKey='$pkLit',RowKey='current')"
    $body = $entity | ConvertTo-Json -Compress -Depth 5
    $date = ConvertTo-SIRfc1123Date
    $auth = Get-SITableAuthorizationHeader -Context $Context -Date $date -Url $url
    # Insert-or-Replace semantics: PUT WITHOUT If-Match. Including If-Match
    # would switch the operation to Update-Entity (which 404s when the row is new).
    $headers = @{
        'x-ms-date'    = $date
        'x-ms-version' = '2020-08-04'
        'Accept'       = 'application/json;odata=nometadata'
        'Content-Type' = 'application/json'
        'Authorization'= $auth
    }
    try {
        Invoke-RestMethod -Method Put -Uri $url -Headers $headers -Body $body -ErrorAction Stop | Out-Null
    } catch {
        # Bubble up the Azure Tables JSON error body if present (otherwise Invoke-RestMethod
        # only surfaces "400 Bad Request" with no diagnostic).
        $detail = if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $_.ErrorDetails.Message } else { $_.Exception.Message }
        throw ('Set-SIFingerprintRecord PUT failed for asset={0}: {1}' -f $AssetId, $detail)
    }
}

