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
    $bodyJson = ConvertTo-Json @{ TableName = $TableName } -Compress
    $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($bodyJson)
    $date = ConvertTo-SIRfc1123Date
    $auth = Get-SITableAuthorizationHeader -Context $Context -Date $date -Url $url

    # v2.2.371 -- raw HttpWebRequest so the common 409 (table already exists)
    # doesn't leave a `PS>TerminatingError(Invoke-RestMethod): ... 409 Conflict.`
    # line in the transcript on every run.
    $req = [System.Net.HttpWebRequest]::CreateHttp($url)
    $req.Method      = 'POST'
    $req.ContentType = 'application/json'
    $req.Accept      = 'application/json;odata=nometadata'
    $req.Headers.Add('x-ms-date',     $date)
    $req.Headers.Add('x-ms-version',  '2020-08-04')   # min for Bearer-token Table REST
    $req.Headers.Add('Authorization', $auth)
    try {
        $reqStream = $req.GetRequestStream()
        try { $reqStream.Write($bodyBytes, 0, $bodyBytes.Length) } finally { $reqStream.Close() }
        $resp = $req.GetResponse()
        $resp.Close()
    } catch [System.Net.WebException] {
        $code = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
        if ($code -ne 409) { throw }   # 409 = table already exists, silent
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

    # v2.2.371 -- use raw HttpWebRequest instead of Invoke-RestMethod so a 404
    # cache miss (the most common path on fresh asset IDs) doesn't leave a
    # `PS>TerminatingError(Invoke-RestMethod): ... (404) Not Found.` line in
    # the PowerShell transcript. The cmdlet treats 4xx as terminating errors
    # that the transcript records BEFORE try/catch sees them; the raw .NET
    # call surfaces 4xx as a normal WebException we silently handle.
    $req = [System.Net.HttpWebRequest]::CreateHttp($url)
    $req.Method  = 'GET'
    $req.Accept  = 'application/json;odata=nometadata'
    $req.Headers.Add('x-ms-date',     $date)
    $req.Headers.Add('x-ms-version',  '2020-08-04')
    $req.Headers.Add('Authorization', $auth)
    try {
        $resp = $req.GetResponse()
        try {
            $reader = New-Object System.IO.StreamReader($resp.GetResponseStream())
            try {
                $body = $reader.ReadToEnd()
                if ([string]::IsNullOrWhiteSpace($body)) { return $null }
                return ($body | ConvertFrom-Json)
            } finally { $reader.Close() }
        } finally { $resp.Close() }
    } catch [System.Net.WebException] {
        $errResp = $_.Exception.Response
        $code = if ($errResp) { [int]$errResp.StatusCode } else { 0 }
        if ($code -eq 404) { return $null }   # cache miss -- silent, no transcript noise
        # Non-404: read the response body for the detailed Azure error and re-throw.
        $detail = ''
        if ($errResp) {
            try {
                $errReader = New-Object System.IO.StreamReader($errResp.GetResponseStream())
                try { $detail = $errReader.ReadToEnd() } finally { $errReader.Close() }
            } catch { }
        }
        if (-not $detail) { $detail = $_.Exception.Message }
        throw ('Get-SIFingerprintRecord GET failed for asset={0} (HTTP {1}): {2}' -f $AssetId, $code, $detail)
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
       self-heal-on-400 path + -ForceOverwrite path. v2.2.315.
       v2.2.371 -- switched to raw HttpWebRequest so the common idempotent-404
       case doesn't leave a transcript line. #>
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][string]$Url
    )
    $date = ConvertTo-SIRfc1123Date
    $auth = Get-SITableAuthorizationHeader -Context $Context -Date $date -Url $Url
    $req = [System.Net.HttpWebRequest]::CreateHttp($Url)
    $req.Method = 'DELETE'
    $req.Accept = 'application/json;odata=nometadata'
    $req.Headers.Add('x-ms-date',     $date)
    $req.Headers.Add('x-ms-version',  '2020-08-04')
    $req.Headers.Add('Authorization', $auth)
    $req.Headers.Add('If-Match',      '*')   # unconditional delete
    try {
        $resp = $req.GetResponse()
        try { return $true } finally { $resp.Close() }
    } catch [System.Net.WebException] {
        $code = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
        if ($code -eq 404) { return $true }   # already absent (silent)
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

