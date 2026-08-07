#Requires -Version 5.1
<#
.SYNOPSIS
    Paged REST GET (@odata.nextLink) with transient-error retry that NEVER
    discards the pages it has already collected.

.DESCRIPTION
    Audit finding #4 (fixed 2026-08-05). The four discovery connectors each wrapped
    their entire pagination loop in ONE try/catch whose catch did `return @()`. A
    throttle on page 40 of 50 therefore threw away all 40 collected pages and handed
    the caller an empty array -- indistinguishable from "this tenant genuinely has
    none". There was no 429 handling and no retry, even though the same repo already
    retried correctly in IdentityRoleFetcher.ps1 and honoured Retry-After in
    AssetTagging.ps1.

    This helper fixes the cause and nothing else, per operator decision 2026-08-05:

      * RETRY transient failures -- 429, 502, 503, 504 and network-level errors --
        up to $MaxAttempts per page with exponential backoff, honouring the server's
        Retry-After header when it sends one (Graph and MDE both do).

      * NEVER BLOCK THE RUN. When a page finally fails, we STOP PAGING and return
        the rows gathered so far with Complete=$false. We do not throw, and we do
        not return an empty set. A source that dies after retries degrades the run;
        it must never halt it. (Operator: "solution must not be blocked due to a
        source failing after retries ... if one source fails".)

      * NO INGEST GUARD. Deliberately no shrink/row-count gate and no "primary
        source failed" abort -- both were considered and declined. The existing
        dead-critical-column check in stages/Invoke-Output.ps1 is untouched and
        still halts ingest when EVERY AlwaysOn column is 0% populated.

    ⚠️ Consequence the operator accepted: a partial snapshot still ingests and still
    becomes max(CollectionTime). Callers should surface Complete/Pages/Error so the
    run log shows a degraded source rather than a silent one.

.OUTPUTS
    PSCustomObject:
      Rows      [object[]] rows collected (possibly partial, never $null)
      Complete  [bool]     $true = every page fetched; $false = stopped early
      Pages     [int]      pages successfully fetched
      Retries   [int]      transient retries performed
      Error     [string]   failure message when Complete is $false, else $null

.EXAMPLE
    $r = Invoke-SIPagedRest -Url $url -Token $token -SourceLabel 'Entra /devices'
    if (-not $r.Complete) { Write-Warning "partial: $($r.Error)" }
    $rows = $r.Rows
#>

function Get-SIRestHttpStatus {
    # Numeric HTTP status from an ErrorRecord; 0 when it wasn't an HTTP response
    # (DNS failure, connection reset, timeout). Mirrors Get-SIGraphHttpStatus in
    # IdentityRoleFetcher.ps1 -- duplicated deliberately so the discovery
    # connectors do not have to load the identity fetcher just to page a URL.
    param([Parameter(Mandatory)][System.Management.Automation.ErrorRecord]$ErrorRecord)
    $resp = $ErrorRecord.Exception.Response
    if ($resp -and $resp.StatusCode) { return [int]$resp.StatusCode }
    if ($ErrorRecord.Exception.Message -match '\((\d{3})\)') { return [int]$Matches[1] }
    return 0
}

function Get-SIRetryAfterSeconds {
    # Honour the server's Retry-After (delta-seconds, or an HTTP-date). Returns
    # $null when absent/unparseable so the caller falls back to exponential backoff.
    param([Parameter(Mandatory)][System.Management.Automation.ErrorRecord]$ErrorRecord)
    try {
        $resp = $ErrorRecord.Exception.Response
        if (-not $resp) { return $null }
        $raw = $null
        if ($resp.Headers) {
            try { $raw = $resp.Headers['Retry-After'] } catch { $raw = $null }
        }
        if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
        $secs = 0
        if ([int]::TryParse([string]$raw, [ref]$secs)) { return [Math]::Max(0, $secs) }
        $when = [datetime]::MinValue
        if ([datetime]::TryParse([string]$raw, [ref]$when)) {
            $delta = [int]($when.ToUniversalTime() - (Get-Date).ToUniversalTime()).TotalSeconds
            if ($delta -gt 0) { return $delta }
        }
    } catch { }
    return $null
}

function Invoke-SIPagedRest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][string]$Token,
        # Used only in log lines so a degraded source is identifiable in the trace.
        [Parameter(Mandatory)][string]$SourceLabel,
        [hashtable]$ExtraHeaders,
        [int]$MaxAttempts = 4,
        # Upper bound on a single honoured Retry-After. A pathological value must not
        # stall the whole engine run.
        [int]$MaxDelaySeconds = 60
    )

    $rows    = New-Object System.Collections.ArrayList
    $headers = @{ Authorization = ('Bearer ' + $Token) }
    if ($ExtraHeaders) { foreach ($k in $ExtraHeaders.Keys) { $headers[$k] = $ExtraHeaders[$k] } }

    $pages = 0; $retries = 0; $complete = $true; $errMsg = $null
    $next = $Url

    while ($next) {
        $attempt = 0
        $resp    = $null
        $failed  = $false

        while ($true) {
            $attempt++
            try {
                $resp = Invoke-RestMethod -Method Get -Uri $next -Headers $headers -ErrorAction Stop
                break
            } catch {
                $status      = Get-SIRestHttpStatus -ErrorRecord $_
                $isTransient = ($status -in 429, 502, 503, 504) -or ($status -eq 0)
                $detail      = $_.Exception.Message
                if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $detail = $_.ErrorDetails.Message }

                if (-not $isTransient -or $attempt -ge $MaxAttempts) {
                    # Permanent (401/403/404/malformed) or retry budget exhausted.
                    # STOP PAGING, KEEP WHAT WE HAVE. Never throw, never return @().
                    $failed  = $true
                    $errMsg  = ('{0}: page {1} failed after {2} attempt(s) -- HTTP {3} {4}' -f `
                                 $SourceLabel, ($pages + 1), $attempt, $status, $detail)
                    break
                }

                $delay = Get-SIRetryAfterSeconds -ErrorRecord $_
                if ($null -eq $delay) { $delay = [int][Math]::Pow(2, $attempt - 1) }   # 1s, 2s, 4s
                if ($delay -gt $MaxDelaySeconds) { $delay = $MaxDelaySeconds }
                $retries++
                Write-Verbose ('{0}: transient HTTP {1} on page {2} -- retry {3}/{4} in {5}s' -f `
                                $SourceLabel, $status, ($pages + 1), $attempt, $MaxAttempts, $delay)
                Start-Sleep -Seconds $delay
            }
        }

        if ($failed) { $complete = $false; break }

        if ($resp.value) { foreach ($v in $resp.value) { [void]$rows.Add($v) } }
        $pages++
        $next = $resp.'@odata.nextLink'
    }

    return [pscustomobject]@{
        Rows     = $rows.ToArray()
        Complete = $complete
        Pages    = $pages
        Retries  = $retries
        Error    = $errMsg
    }
}
