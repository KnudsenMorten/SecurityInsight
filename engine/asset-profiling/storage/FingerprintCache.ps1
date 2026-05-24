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

function _Invoke-SITablePut {
    <# PUT (insert-or-replace) an Azure Table entity. Raw HttpWebRequest so
       a 4xx (the common column-type-drift `InvalidInput` and the
       large-payload `PropertyValueTooLarge` cases) doesn't leave a
       `PS>TerminatingError(Invoke-RestMethod)` line in the PowerShell
       transcript -- Invoke-RestMethod records 4xx as a terminating error
       BEFORE try/catch sees it; the raw .NET path surfaces the same 4xx
       as a normal WebException the caller can inspect via `.Response`.
       Lets WebException propagate so the caller's `_Get-SIAzureErrorBody`
       can read the error body + parse the OData code. #>
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][string]$Body
    )
    $date = ConvertTo-SIRfc1123Date
    $auth = Get-SITableAuthorizationHeader -Context $Context -Date $date -Url $Url
    $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($Body)
    $req = [System.Net.HttpWebRequest]::CreateHttp($Url)
    $req.Method        = 'PUT'
    $req.ContentType   = 'application/json'
    $req.Accept        = 'application/json;odata=nometadata'
    $req.ContentLength = $bodyBytes.Length
    $req.Headers.Add('x-ms-date',     $date)
    $req.Headers.Add('x-ms-version',  '2020-08-04')
    $req.Headers.Add('Authorization', $auth)
    # Note: NO If-Match header -- presence would switch the operation to
    # Update-Entity (404 on new rows). Omission == Insert-or-Replace.
    $reqStream = $req.GetRequestStream()
    try { $reqStream.Write($bodyBytes, 0, $bodyBytes.Length) } finally { $reqStream.Close() }
    $resp = $req.GetResponse()
    $resp.Close()
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
    # _Invoke-SITablePut signs + builds headers internally. Insert-or-Replace
    # semantics (no If-Match) are baked into the helper -- caller just passes
    # the URL + body.

    if ($ForceOverwrite) {
        # v2.2.315 -- caller wants guaranteed-fresh column types. DELETE then PUT.
        # Avoids the type-drift trap where the row's existing Edm.Int32 si_tier
        # column locks out subsequent writes whose JSON marshals it differently.
        [void](_Invoke-SITableDelete -Context $Context -Url $url)
        try {
            _Invoke-SITablePut -Context $Context -Url $url -Body $body
            return
        } catch {
            $detail = _Get-SIAzureErrorBody -ErrorRecord $_
            $odataCode = if ($detail -match '"code"\s*:\s*"([^"]+)"') { $matches[1] } else { $null }
            $codeTag = if ($odataCode) { (' [{0}]' -f $odataCode) } else { '' }
            throw ('Set-SIFingerprintRecord PUT (force-overwrite) failed for asset={0}{1}: {2}' -f $AssetId, $codeTag, $detail)
        }
    }

    try {
        _Invoke-SITablePut -Context $Context -Url $url -Body $body
    } catch {
        # Self-heal logic: only retry on column-type drift (Azure Table
        # OData code `InvalidInput`), where DELETE clears the column-type
        # lock so the re-PUT succeeds with fresh types. Skip the self-heal
        # for body-content failures (`PropertyValueTooLarge`, malformed
        # JSON, etc.) -- a second PUT with the same body will fail with
        # the same code and just doubles the transcript noise.
        $code = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
        $firstDetail = _Get-SIAzureErrorBody -ErrorRecord $_

        # Parse OData error code from the response body. Format:
        # {"odata.error":{"code":"<Code>","message":{...}}}
        $odataCode = $null
        if ($firstDetail -match '"code"\s*:\s*"([^"]+)"') { $odataCode = $matches[1] }

        if ($code -eq 400 -and $odataCode -eq 'InvalidInput') {
            try {
                [void](_Invoke-SITableDelete -Context $Context -Url $url)
                # _Invoke-SITablePut re-signs internally with a fresh
                # x-ms-date header, so the second attempt doesn't carry
                # the stale signature from the failed first attempt.
                _Invoke-SITablePut -Context $Context -Url $url -Body $body
                Write-Verbose ('Set-SIFingerprintRecord self-healed (DELETE+PUT) for asset={0} after first PUT 400 InvalidInput: {1}' -f $AssetId, ($firstDetail -replace "`r?`n",' '))
                return
            } catch {
                $finalDetail = _Get-SIAzureErrorBody -ErrorRecord $_
                throw ('Set-SIFingerprintRecord PUT failed for asset={0} (self-heal also failed). First 400 InvalidInput: {1} -- Final: {2}' -f $AssetId, ($firstDetail -replace "`r?`n",' '), ($finalDetail -replace "`r?`n",' '))
            }
        }

        # PropertyValueTooLarge / other 400 / non-400: no self-heal possible.
        # Surface the OData code so the caller can decide (the truncation
        # guard in Invoke-Classify already caps si_verdict; if a row still
        # trips PropertyValueTooLarge here it's another property the guard
        # doesn't reach -- a real bug worth seeing in the warning).
        $codeTag = if ($odataCode) { (' [{0}]' -f $odataCode) } else { '' }
        throw ('Set-SIFingerprintRecord PUT failed for asset={0}{1}: {2}' -f $AssetId, $codeTag, $firstDetail)
    }
}

