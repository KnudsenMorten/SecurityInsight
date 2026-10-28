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
        [scriptblock]$OnPage
    )

    if (-not $PageFetcher) {
        $PageFetcher = { param($p) Search-SIAzGraph @p -ErrorAction Stop }
    }

    $rows = New-Object System.Collections.ArrayList
    $pages = 0; $retries = 0; $complete = $true; $errMsg = $null; $rowCount = 0L
    $skipToken = $null

    do {
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
                Write-Verbose ('{0}: Resource Graph throttled/transient on page {1} -- retry {2}/{3} in {4}s' -f $SourceLabel, ($pages + 1), $attempt, $MaxAttempts, $delay)
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
