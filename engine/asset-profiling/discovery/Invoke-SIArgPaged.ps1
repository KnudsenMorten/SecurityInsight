#Requires -Version 5.1
<#
    Invoke-SIArgPaged -- page an Azure Resource Graph query to the end, and survive throttling.

    The Resource Graph sibling of shared\Invoke-SIPagedRest.ps1, with the SAME contract (operator decision
    2026-08-05, recorded there): a source that dies after retries DEGRADES the run -- it never blocks it
    and it never throws away the pages it already has. A partial result is returned WITH Complete=$false
    and a loud warning, because absence reads as "removed" or "remediated" downstream.

    Why this exists (#125). The discovery connectors paged Resource Graph three different ways:
      * Get-DiscoveryFromShodan asked for `-First 1000` and never followed the SkipToken -- a tenant with
        more than 1000 public IPs silently lost the rest;
      * Get-DiscoveryFromAzureResources returned @() when ANY page failed, discarding every page already
        collected -- a throttle on page 9 made the whole Azure estate look empty;
      * none of them retried a throttle, and Resource Graph throttles large tenants routinely.

    Returns [pscustomobject]@{ Rows; Complete; Pages; Retries; Error }. Never throws.
#>

# Azure access: plain REST, no PowerShell modules (engine/_shared/SI-AzRest.ps1).
if (-not (Get-Command -Name Invoke-SIArm -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '../../_shared/SI-AzRest.ps1') }

function Test-SIArgTransientError {
    param([string]$Message)
    $m = ([string]$Message).ToLowerInvariant()
    return ($m -match 'throttl|too many requests|\b429\b|rate limit|\b50[0234]\b|service unavailable|bad gateway|gateway timeout|timed out|timeout|temporar|connection.*(closed|reset)')
}

function Write-SIReadProgress {
    <# AZHANG-1: one progress / retry line of a long read -- the run's INFO log when it is loaded, else the host. Never throws. #>
    param([string]$Text)
    try {
        if (Get-Command -Name Write-SIInfo -ErrorAction SilentlyContinue) { Write-SIInfo ('   ' + $Text) } else { Write-Host ('   ' + $Text) }
    } catch { }
}

function Get-SIAzureReadTimeoutSec {
    <# AZHANG-1: how long ONE Azure read call (one page) may wait before it counts as no answer and is retried:
       $global:SI_AzureReadTimeoutSec, else 120 s (the platform answers a page in seconds; ARM itself gives up at 60 s). #>
    $v = 0
    try { $v = [int](Get-Variable -Scope Global -Name SI_AzureReadTimeoutSec -ValueOnly -ErrorAction Ignore) } catch { $v = 0 }
    if ($v -gt 0) { return $v }
    120
}

function Invoke-SIArgPaged {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Query,
        # Used only in log lines, so a degraded source is identifiable.
        [Parameter(Mandatory)][string]$SourceLabel,
        [string[]]$SubscriptionIds = @(),
        [int]$PageSize = 1000,
        [int]$MaxAttempts = 4,
        # Backoff base in seconds (attempt n waits Base * 3^(n-1): 5, 15, 45 by default). Resource Graph
        # throttling windows are measured in seconds-to-a-minute, so the REST pager's 1/2/4s is too short.
        [int]$BackoffBaseSeconds = 5,
        # Test seam: the call that fetches one page. Defaults to Search-AzGraph.
        [scriptblock]$PageFetcher,
        # #727 PAGE BY PAGE: each page's rows go to { param($Rows) } and are let go -- Rows comes back empty, RowCount says
        # how many there were. An Azure estate of millions of resources is never held whole.
        [scriptblock]$OnPage,
        # AZHANG-1: the whole read stops (INCOMPLETE, the rows read kept) once it has taken this long; 0 = no time-out
        [double]$TimeoutMinutes = 0,
        # AZHANG-1: a progress line at least this often while the read runs (0 = none)
        [double]$ProgressSeconds = 60
    )

    if (-not $PageFetcher) {
        $PageFetcher = { param($p) Search-SIAzGraph @p -ErrorAction Stop }
    }
    # AZHANG-1: each page call waits at most Get-SIAzureReadTimeoutSec and is tried twice by the REST client (this pager retries
    # it again, 5 / 15 / 45 s) -- not 6 x 300 s silently. Read by Invoke-SIResourceGraphPage from this scope.
    $SIArgPageOptions = @{
        TimeoutSec = (Get-SIAzureReadTimeoutSec); MaxAttempts = 2
        OnRetry = { param($Code, $Wait, $Attempt, $Max, $What) Write-SIReadProgress ('{0}: Resource Graph gave no answer (HTTP {1}) -- retry in {2}s' -f $SourceLabel, $Code, $Wait) }
    }

    $rows = New-Object System.Collections.ArrayList
    $pages = 0; $retries = 0; $complete = $true; $errMsg = $null; $rowCount = 0L
    $skipToken = $null
    $started = [datetime]::UtcNow; $lastSaid = $started
    $seenTokens = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)

    do {
        if ($TimeoutMinutes -gt 0 -and ([datetime]::UtcNow - $started).TotalMinutes -ge $TimeoutMinutes) {
            $complete = $false
            $errMsg = ('{0}: the read did not finish within {1} minute(s) ({2} page(s) read) -- stopped' -f $SourceLabel, $TimeoutMinutes, $pages)
            break
        }
        $params = @{ Query = $Query; First = $PageSize }
        if (@($SubscriptionIds).Count -gt 0) { $params['Subscription'] = $SubscriptionIds }
        if ($skipToken)                      { $params['SkipToken']    = $skipToken }

        $page = $null; $attempt = 0; $failed = $false
        while ($true) {
            $attempt++
            try {
                $page = & $PageFetcher $params
                break
            } catch {
                $msg = [string]$_.Exception.Message
                if (-not (Test-SIArgTransientError -Message $msg) -or $attempt -ge $MaxAttempts) {
                    $failed = $true
                    $errMsg = ('{0}: Resource Graph page {1} failed after {2} attempt(s) -- {3}' -f $SourceLabel, ($pages + 1), $attempt, $msg)
                    break
                }
                $delay = [int]($BackoffBaseSeconds * [Math]::Pow(3, $attempt - 1))
                $retries++
                Write-SIReadProgress ('{0}: Resource Graph throttled / no answer on page {1} -- retry {2}/{3} in {4}s' -f $SourceLabel, ($pages + 1), $attempt, $MaxAttempts, $delay)
                $lastSaid = [datetime]::UtcNow
                if ($delay -gt 0) { Start-Sleep -Seconds $delay }
            }
        }

        if ($failed) { $complete = $false; break }

        # Search-AzGraph returns a response exposing .Data and .SkipToken; older module versions returned
        # the rows directly. Read .Data when it is there, otherwise enumerate the page as before.
        $pageRows = if ($null -ne $page -and $page.PSObject.Properties['Data']) { $page.Data } else { $page }
        if ($OnPage) {
            $list = New-Object System.Collections.Generic.List[object]
            foreach ($r in $pageRows) { $list.Add($r) }
            $rowCount += $list.Count
            $null = & $OnPage $list.ToArray()
            $list = $null
        } else { foreach ($r in $pageRows) { [void]$rows.Add($r) }; $rowCount = $rows.Count }
        $pages++
        $skipToken = $null
        if ($null -ne $page -and $page.PSObject.Properties['SkipToken']) { $skipToken = [string]$page.SkipToken }
        # AZHANG-1: a next-page token handed back a second time would page forever -- stop, INCOMPLETE, said
        if ($skipToken -and -not $seenTokens.Add($skipToken)) {
            $complete = $false
            $errMsg = ('{0}: Resource Graph handed back the same next-page token twice after page {1} -- the read cannot be finished' -f $SourceLabel, $pages)
            break
        }
        if ($ProgressSeconds -gt 0 -and $skipToken -and ([datetime]::UtcNow - $lastSaid).TotalSeconds -ge $ProgressSeconds) {
            Write-SIReadProgress ('{0}: page {1}, {2} row(s) so far ({3:n0}s)' -f $SourceLabel, $pages, $rowCount, ([datetime]::UtcNow - $started).TotalSeconds)
            $lastSaid = [datetime]::UtcNow
        }
    } while ($skipToken)

    if (-not $complete) {
        Write-Warning ('{0}: INCOMPLETE -- kept {1} row(s) from {2} page(s), the rest could not be retrieved. Assets missing from this run are UNKNOWN, not removed. {3}' -f $SourceLabel, $rowCount, $pages, $errMsg)
    }

    return [pscustomobject]@{
        Rows     = $rows.ToArray()
        RowCount = $rowCount
        Complete = $complete
        Pages    = $pages
        Retries  = $retries
        Error    = $errMsg
    }
}
