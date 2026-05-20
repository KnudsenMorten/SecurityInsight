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

function _Get-SIAzureErrorBody {
    <# Best-effort extractor for Azure REST error body. ErrorDetails.Message is
       populated for some response shapes only; on PS 5.1 + many 400s the
       Invoke-RestMethod exception swallows the body. Fall back to reading the
       response stream directly. v2.2.315. #>
    param($ErrorRecord)
    if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) {
        return [string]$ErrorRecord.ErrorDetails.Message
    }
    try {
        $resp = $ErrorRecord.Exception.Response
        if ($resp) {
            $stream = $resp.GetResponseStream()
            if ($stream) {
                # Reset stream to beginning if seekable (response stream sometimes already-consumed).
                if ($stream.CanSeek) { $stream.Position = 0 }
                $reader = New-Object System.IO.StreamReader($stream)
                try {
                    $body = $reader.ReadToEnd()
                    if (-not [string]::IsNullOrWhiteSpace($body)) { return $body }
                } finally { $reader.Close() }
            }
        }
    } catch { }
    return [string]$ErrorRecord.Exception.Message
}

function _Invoke-SITableDelete {
    <# DELETE an Azure Table entity by PK + RowKey. Idempotent: 404 (entity
       absent) is treated as success. Used by Set-SIFingerprintRecord's
       self-heal-on-400 path + -ForceOverwrite path. v2.2.315. #>
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][string]$Url
    )
    $date = ConvertTo-SIRfc1123Date
    $auth = Get-SITableAuthorizationHeader -Context $Context -Date $date -Url $Url
    $headers = @{
        'x-ms-date'    = $date
        'x-ms-version' = '2020-08-04'
        'Accept'       = 'application/json;odata=nometadata'
        'Authorization'= $auth
        'If-Match'     = '*'   # unconditional delete
    }
    try {
        Invoke-RestMethod -Method Delete -Uri $Url -Headers $headers -ErrorAction Stop | Out-Null
        return $true
    } catch {
        $code = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
        if ($code -eq 404) { return $true }   # already absent
        return $false
    }
}

function Set-SIFingerprintRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][string]$TableName,
        [Parameter(Mandatory)][string]$AssetId,
        [Parameter(Mandatory)][hashtable]$Properties,
        # v2.2.315 -- when set, skip the initial PUT and go straight to
        # DELETE+PUT. The Invoke-Classify stage uses this on ForceFullRun=true
        # to guarantee fresh column-type inference and self-heal any prior
        # property-type drift in one round-trip pair.
        [switch]$ForceOverwrite
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

    if ($ForceOverwrite) {
        # v2.2.315 -- caller wants guaranteed-fresh column types. DELETE then PUT.
        # Avoids the type-drift trap where the row's existing Edm.Int32 si_tier
        # column locks out subsequent writes whose JSON marshals it differently.
        [void](_Invoke-SITableDelete -Context $Context -Url $url)
        try {
            Invoke-RestMethod -Method Put -Uri $url -Headers $headers -Body $body -ErrorAction Stop | Out-Null
            return
        } catch {
            $detail = _Get-SIAzureErrorBody -ErrorRecord $_
            throw ('Set-SIFingerprintRecord PUT (force-overwrite) failed for asset={0}: {1}' -f $AssetId, $detail)
        }
    }

    try {
        Invoke-RestMethod -Method Put -Uri $url -Headers $headers -Body $body -ErrorAction Stop | Out-Null
    } catch {
        # v2.2.315 -- self-heal on 400. The dominant 400 cause is property-type
        # drift across writes (e.g. si_tier was Edm.Int32 from a prior schema,
        # current PUT marshals it as Edm.String). DELETE clears the column-type
        # lock; the re-PUT succeeds with fresh types from the current JSON.
        # 404 (entity absent) shouldn't reach here -- Insert-or-Replace creates;
        # other status codes (401/403/500) bypass the self-heal.
        $code = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
        $firstDetail = _Get-SIAzureErrorBody -ErrorRecord $_
        if ($code -eq 400) {
            try {
                [void](_Invoke-SITableDelete -Context $Context -Url $url)
                # Re-sign because $date moved on (clock skew); rebuild header for second PUT.
                $date2 = ConvertTo-SIRfc1123Date
                $auth2 = Get-SITableAuthorizationHeader -Context $Context -Date $date2 -Url $url
                $headers['x-ms-date']     = $date2
                $headers['Authorization'] = $auth2
                Invoke-RestMethod -Method Put -Uri $url -Headers $headers -Body $body -ErrorAction Stop | Out-Null
                Write-Verbose ('Set-SIFingerprintRecord self-healed (DELETE+PUT) for asset={0} after first PUT 400: {1}' -f $AssetId, ($firstDetail -replace "`r?`n",' '))
                return
            } catch {
                $finalDetail = _Get-SIAzureErrorBody -ErrorRecord $_
                throw ('Set-SIFingerprintRecord PUT failed for asset={0} (self-heal also failed). First 400: {1} -- Final: {2}' -f $AssetId, ($firstDetail -replace "`r?`n",' '), ($finalDetail -replace "`r?`n",' '))
            }
        }
        # Non-400: don't retry. Bubble up with body if available.
        throw ('Set-SIFingerprintRecord PUT failed for asset={0}: {1}' -f $AssetId, $firstDetail)
    }
}

