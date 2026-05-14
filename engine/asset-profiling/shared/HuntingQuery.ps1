#Requires -Version 5.1
<#
    Shared KQL submitter.

    Extracted from Stage Enrich because the schema-discovery pipeline
    needs the same function but never dot-sources Stage Enrich (different
    stage list). Both pipelines now dot-source THIS file directly.

    Run a KQL query against one of three backends:
      DefenderGraph   -- Microsoft Graph runHuntingQuery (XDR Adv. Hunting).
                         Schema: DeviceLogonEvents, IdentityInfo,
                         ExposureGraphNodes, etc.
      LogAnalytics    -- Invoke-AzOperationalInsightsQuery against the
                         v2.2 home workspace ($global:SI_WorkspaceResourceId).
                         Schema: SI_*_Profile_CL, customer tables.
      MultiWorkspace  -- LogAnalytics route + Query is expected to use
                         workspace("name") cross-workspace KQL syntax for
                         tables that live in a different LA workspace than
                         the one resolved from $global:SI_WorkspaceResourceId.
                         Same submitter as LogAnalytics; only docs differ.

    Returns an array of rows (PSCustomObjects) or @() on failure. Failures
    are non-fatal per call -- engine continues with other rules.
#>

function Invoke-SIHuntingQuery {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Query,
        [Parameter()]
        [ValidateSet('DefenderGraph','LogAnalytics','MultiWorkspace')]
        [string]$QueryEngine = 'DefenderGraph',
        # Optional workspace override. When set, the LA route queries this
        # workspace instead of the default $global:SI_WorkspaceResourceId.
        # Lets identity-related queries target the Defender workspace where
        # AADServicePrincipalSignInLogs / AADManagedIdentitySignInLogs /
        # IdentityInfo live, while SI_*_Profile_CL queries continue to use
        # the SI home workspace.
        [string]$WorkspaceResourceId
    )

    if ($QueryEngine -in 'LogAnalytics','MultiWorkspace') {
        $targetWs = if (-not [string]::IsNullOrWhiteSpace($WorkspaceResourceId)) { $WorkspaceResourceId } else { $global:SI_WorkspaceResourceId }
        if ([string]::IsNullOrWhiteSpace($targetWs)) {
            Write-Warning 'Invoke-SIHuntingQuery: LogAnalytics route needs $global:SI_WorkspaceResourceId or -WorkspaceResourceId.'
            return @()
        }
        if ($targetWs -notmatch '^/subscriptions/(?<sub>[^/]+)/resourceGroups/(?<rg>[^/]+)/providers/Microsoft\.OperationalInsights/workspaces/(?<name>[^/]+)$') {
            Write-Warning ("Invoke-SIHuntingQuery (LA): Workspace ResourceId malformed: {0}" -f $targetWs)
            return @()
        }
        $sub = $matches.sub; $rg = $matches.rg; $name = $matches.name
        Write-Verbose ("Invoke-SIHuntingQuery (LA): targeting {0}" -f $targetWs)

        # v2.2.289 -- retry loop. Transient LA backend errors (BadRequest from
        # query-time race conditions, throttling, schema-state hiccups) used to
        # drop the row from the profile-build pipeline. Retry up to 3 times
        # with exponential backoff (1s, 3s, 7s) before giving up. Hard schema
        # errors will still fail consistently across all attempts -- they get
        # logged with the response body and query preview, same as before.
        $maxRetries = if ($null -ne $global:SI_LAQueryMaxRetries) {
            [int]$global:SI_LAQueryMaxRetries
        } else { 3 }
        if ($maxRetries -lt 1) { $maxRetries = 1 }

        $attempt = 0
        $lastMsg = $null
        while ($attempt -lt $maxRetries) {
            $attempt++
            try {
                $prevCtx = Get-AzContext
                $ctxChanged = $false
                if (-not $prevCtx -or $prevCtx.Subscription.Id -ne $sub) {
                    Set-AzContext -SubscriptionId $sub -WarningAction SilentlyContinue | Out-Null
                    $ctxChanged = $true
                }
                try {
                    $ws = Get-AzOperationalInsightsWorkspace -ResourceGroupName $rg -Name $name -ErrorAction Stop
                    $resp = Invoke-AzOperationalInsightsQuery -WorkspaceId $ws.CustomerId.Guid -Query $Query -ErrorAction Stop
                    if ($attempt -gt 1) {
                        Write-Verbose ("Invoke-SIHuntingQuery (LA): succeeded on attempt {0}/{1}" -f $attempt, $maxRetries)
                    }
                    return @($resp.Results)
                } finally {
                    if ($ctxChanged -and $prevCtx) {
                        Set-AzContext -Context $prevCtx -WarningAction SilentlyContinue | Out-Null
                    }
                }
            } catch {
                $msg = $_.Exception.Message
                if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
                    $msg = $_.ErrorDetails.Message
                } elseif ($_.Exception.Response) {
                    $stream = $null; $reader = $null
                    try {
                        $stream = $_.Exception.Response.GetResponseStream()
                        $reader = New-Object System.IO.StreamReader($stream)
                        $body = $reader.ReadToEnd()
                        if ($body) { $msg = ('{0} | body: {1}' -f $msg, $body) }
                    } catch {
                    } finally {
                        if ($reader) { try { $reader.Dispose() } catch {} }
                        if ($stream) { try { $stream.Dispose() } catch {} }
                    }
                }
                $lastMsg = $msg
                if ($attempt -lt $maxRetries) {
                    $delay = @(1, 3, 7)[[Math]::Min($attempt - 1, 2)]
                    Write-Warning ("Invoke-SIHuntingQuery (LA) attempt {0}/{1} failed: {2} -- retrying in {3}s" -f $attempt, $maxRetries, $msg, $delay)
                    Start-Sleep -Seconds $delay
                }
            }
        }

        # All retries exhausted -- log final message + query preview
        Write-Warning ("Invoke-SIHuntingQuery (LA): {0} consecutive attempts failed. Last error: {1}" -f $maxRetries, $lastMsg)
        $qPreview = if ($Query.Length -gt 500) { $Query.Substring(0, 500) + '... [truncated]' } else { $Query }
        Write-Warning ('Invoke-SIHuntingQuery (LA): failing query (first 500 chars): {0}' -f $qPreview)
        return @()
    }

    # DefenderGraph (default)
    # Resolve auth helper relative to v2.2 root (../../../auth/) regardless of
    # which stage dot-sourced us.
    $siRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
    . (Join-Path $siRoot 'auth\Get-SIGraphToken.ps1')
    try {
        $token = Get-SIGraphToken -Resource Graph
    } catch {
        Write-Warning ('Invoke-SIHuntingQuery: token failed -- {0}' -f $_.Exception.Message)
        return @()
    }

    try {
        $resp = Invoke-RestMethod -Method Post `
            -Uri 'https://graph.microsoft.com/v1.0/security/runHuntingQuery' `
            -Headers @{ Authorization = ('Bearer ' + $token); 'Content-Type' = 'application/json' } `
            -Body (@{ Query = $Query } | ConvertTo-Json -Compress)
    } catch {
        $msg = $_.Exception.Message
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
            $msg = $_.ErrorDetails.Message
        } elseif ($_.Exception.Response) {
            # PS 5.1 sometimes leaves ErrorDetails empty for 400s.
            # Read the response stream directly so the actual KQL error surfaces.
            # dispose stream + reader in finally so a ReadToEnd()
            # exception doesn't leak the unmanaged HTTP response handle.
            $stream = $null; $reader = $null
            try {
                $stream = $_.Exception.Response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($stream)
                $body = $reader.ReadToEnd()
                if ($body) { $msg = ('{0} | body: {1}' -f $msg, $body) }
            } catch {
            } finally {
                if ($reader) { try { $reader.Dispose() } catch {} }
                if ($stream) { try { $stream.Dispose() } catch {} }
            }
        }
        Write-Warning ('Invoke-SIHuntingQuery: query failed -- {0}' -f $msg)
        # Also dump the first 500 chars of the QUERY so operators can spot the bad KQL
        $qPreview = if ($Query.Length -gt 500) { $Query.Substring(0, 500) + '... [truncated]' } else { $Query }
        Write-Warning ('Invoke-SIHuntingQuery: failing query (first 500 chars): {0}' -f $qPreview)
        return @()
    }

    if ($resp.results) { return $resp.results }
    if ($resp.Results) { return $resp.Results }
    return @()
}
