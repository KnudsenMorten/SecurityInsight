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

# Azure access: plain REST, no PowerShell modules (engine/_shared/SI-AzRest.ps1).
if (-not (Get-Command -Name Invoke-SIArm -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '../../_shared/SI-AzRest.ps1') }
if (-not (Get-Command -Name Read-SILaParts -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '../../_shared/SI-LaParts.ps1') }

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
                $prevCtx = Get-SIAzContext
                $ctxChanged = $false
                if (-not $prevCtx -or $prevCtx.Subscription.Id -ne $sub) {
                    Set-SIAzContext -SubscriptionId $sub -WarningAction SilentlyContinue | Out-Null
                    $ctxChanged = $true
                }
                try {
                    $ws = Get-SIAzOperationalInsightsWorkspace -ResourceGroupName $rg -Name $name -ErrorAction Stop
                    # #639 lane 4: a rule's query can return more rows than one answer carries -- read in parts (Read-SILaParts);
                    # a cut answer is refused, never handed out as the rule's whole result
                    $resp = Read-SILaParts -WorkspaceId $ws.CustomerId.Guid -Query $Query -What 'the hunting query (Log Analytics)' -Log { param($l, $m) Write-Verbose ('Invoke-SIHuntingQuery (LA): ' + $m) }
                    if ($attempt -gt 1) {
                        Write-Verbose ("Invoke-SIHuntingQuery (LA): succeeded on attempt {0}/{1}" -f $attempt, $maxRetries)
                    }
                    return @($resp.Rows)
                } finally {
                    if ($ctxChanged -and $prevCtx) {
                        Set-SIAzContext -Context $prevCtx -WarningAction SilentlyContinue | Out-Null
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
                # #639 lane 4: an answer still cut after the read in parts is not fixed by asking again
                if ((Get-Command -Name Get-SILaPartFailure -ErrorAction SilentlyContinue) -and (Get-SILaPartFailure -Err $_).Cut) { break }
                # a query the service REFUSED (a semantic or syntax error, a table or column that is not there) gives the
                # same answer when asked again: it fails on attempt 1 and must be fixed, never retried (live 2026-10-23: a
                # missing table was asked 3 times on every identity run)
                if (Test-SIHuntingQueryDefect -Message $msg) { break }
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
    # 📌 Forward slash for consistency with the newer dot-sources in this tree. It was 'auth\...'.
    # 🪤 AND THE BACKSLASH WAS NOT A BUG -- I ASSUMED IT WAS AND MEASURED OTHERWISE. The reasoning
    # looked airtight: `\` is a legal filename character on Linux, so `Join-Path '/app' 'auth\x.ps1'`
    # should yield a literal path that cannot resolve, breaking all four profiler engines in a
    # container. Tested inside the real image instead of shipping the conclusion:
    #     Join-Path "/app" "engine\asset-profiling\storage\StorageContext.ps1"
    #       -> /app/engine/asset-profiling/storage/StorageContext.ps1     Test-Path: True
    # PowerShell NORMALISES the separator. `Invoke-SIEngineRun.ps1` and ~20 other sites use backslash
    # dot-sources and are fine. **Do not "fix" them** -- it is churn against a defect that does not
    # exist, and this comment is here so the next person does not re-derive the same wrong conclusion.
    . (Join-Path $siRoot 'auth/Get-SIGraphToken.ps1')
    # The shared REST client -- for New-SIGraphJsonBody. See the body comment below.
    . (Join-Path $siRoot 'engine/_shared/SI-GraphRest.ps1')
    # #882 (A3): retried (throttling, 5xx, no answer; an expired token renewed once) and a CUT answer (Microsoft's 100,000-row
    # limit) is asked again in hash buckets that add up to the whole answer -- never a cut answer read as complete
    $one = Invoke-SIHuntingGraphRequest -Query $Query
    if (-not $one.Ok) {
        Write-Warning ('Invoke-SIHuntingQuery: query failed -- {0}' -f $one.Error)
        $qPreview = if ($Query.Length -gt 500) { $Query.Substring(0, 500) + '... [truncated]' } else { $Query }
        Write-Warning ('Invoke-SIHuntingQuery: failing query (first 500 chars): {0}' -f $qPreview)
        return @()
    }
    if (@($one.Rows).Count -lt $script:SIHuntingRowCut) { return $one.Rows }
    $whole = Invoke-SIHuntingCutSplit -Query $Query -Rows ([long]@($one.Rows).Count)
    if (-not $whole.Ok) {
        Write-Warning ('Invoke-SIHuntingQuery: the answer was cut at {0:N0} rows (Microsoft''s limit) and could not be read whole in parts -- {1}' -f $script:SIHuntingRowCut, $whole.Error)
        return @()
    }
    return $whole.Rows
}

function Test-SIHuntingQueryDefect {
    <# PURE. Is this error the service refusing the QUERY itself -- a semantic or syntax error, a table or column that does
       not resolve? Such an answer is the same on every attempt: the query is fixed, never asked again. (The same reading
       as engine\_shared\SI-ErrorClass.ps1 'kql-query-defect' / 'table-missing'; duplicated so this file loads alone.) #>
    # A refused request (400 / BadRequest) is a defect too -- EXCEPT a busy service: "exceeded the allowed limits" /
    # "preempted" / high CPU or memory is the service under load (the same reading as RA-AutoBucketing.ps1), asked again.
    param([AllowNull()][AllowEmptyString()][string]$Message)
    $m = [string]$Message
    if ($m -match '(?i)exceeded the allowed (limits|result size)|preempted|high cpu|memory resource consumption') { return $false }
    [bool]($m -match '(?i)Fix syntax errors in your query|Fix semantic errors in your query|SyntaxError|SemanticError|\bSEM\d{4}\b|\bSYN\d{4}\b|Failed to resolve|semantic error|syntax error|BadRequest|HTTP 400\b|\(400\)')
}

$script:SIHuntingRowCut = 100000

function Invoke-SIHuntingQueryResult {
    <#
        A Defender hunting query as a RESULT: @{ Ok; Rows; Error; Defect }. The same request as Invoke-SIHuntingQuery
        (retried by Invoke-SIHuntingGraphRequest: throttled / busy / 5xx / no answer asked again with a growing wait, an
        expired token renewed; a cut answer read whole in parts), but a failure is NEVER handed out as an empty answer --
        the caller says it and keeps that part's data unknown. Defect: the query was refused (400). Never throws.
        -Ask { param($Query) } -> @{ Ok; Rows; Error } (test seam; default Invoke-SIHuntingGraphRequest).
    #>
    param([Parameter(Mandatory)][string]$Query, [scriptblock]$Ask)
    if (-not $Ask) {
        $siRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
        if (-not (Get-Command -Name Get-SIGraphToken -ErrorAction SilentlyContinue)) { . (Join-Path $siRoot 'auth/Get-SIGraphToken.ps1') }
        if (-not (Get-Command -Name New-SIGraphJsonBody -ErrorAction SilentlyContinue)) { . (Join-Path $siRoot 'engine/_shared/SI-GraphRest.ps1') }
        $Ask = { param($q) Invoke-SIHuntingGraphRequest -Query $q }
    }
    $cut = if ($script:SIHuntingRowCut) { [int]$script:SIHuntingRowCut } else { 100000 }
    $one = $null
    try { $one = & $Ask $Query } catch { $one = [pscustomobject]@{ Ok = $false; Rows = @(); Error = $_.Exception.Message } }
    if (-not $one.Ok) { return [pscustomobject]@{ Ok = $false; Rows = @(); Error = [string]$one.Error; Defect = (Test-SIHuntingQueryDefect -Message ([string]$one.Error)) } }
    if (@($one.Rows).Count -lt $cut) { return [pscustomobject]@{ Ok = $true; Rows = @($one.Rows); Error = ''; Defect = $false } }
    $whole = Invoke-SIHuntingCutSplit -Query $Query -Rows ([long]@($one.Rows).Count) -Ask $Ask -Cut $cut
    if (-not $whole.Ok) { return [pscustomobject]@{ Ok = $false; Rows = @(); Error = ('the answer was cut at {0:N0} rows (Microsoft''s limit) and could not be read whole in parts -- {1}' -f $cut, $whole.Error); Defect = $false } }
    [pscustomobject]@{ Ok = $true; Rows = @($whole.Rows); Error = ''; Defect = $false }
}

function Invoke-SIHuntingGraphRequest {
    <#
        #882 (A3): ONE Defender hunting request (Microsoft Graph runHuntingQuery), retried: 429 / 5xx / no answer up to
        -MaxAttempts times with the wait Microsoft asks for (Retry-After, else 2, 4, 8 ... s); an expired token (401) renewed
        once and asked again. Returns @{ Ok; Rows; Error }. Never throws. Seams: -Send { param($Token, $Query) } (throws like
        Invoke-RestMethod), -Token { param([bool]$Force) }, -Sleep.
    #>
    param([Parameter(Mandatory)][string]$Query, [int]$MaxAttempts = 6, [scriptblock]$Send, [scriptblock]$Token, [scriptblock]$Sleep)
    if (-not $Sleep) { $Sleep = { param($s) Start-Sleep -Seconds $s } }
    if (-not $Token) { $Token = { param([bool]$Force) if ($Force) { Get-SIGraphToken -Resource Graph -ForceRefresh } else { Get-SIGraphToken -Resource Graph } } }
    if (-not $Send) {
        $Send = { param($Tk, $Q)
            Invoke-RestMethod -Method Post -Uri 'https://graph.microsoft.com/v1.0/security/runHuntingQuery' -Headers @{ Authorization = ('Bearer ' + $Tk) } `
                -ContentType 'application/json; charset=utf-8' -Body (New-SIGraphJsonBody -Object @{ Query = $Q } -Depth 5) -ErrorAction Stop }
    }
    $renewed = $false; $attempt = 0; $last = ''
    while ($attempt -lt $MaxAttempts) {
        $attempt++
        $tk = $null
        try { $tk = [string](& $Token $false) } catch { return [pscustomobject]@{ Ok = $false; Rows = @(); Error = ('token failed -- {0}' -f $_.Exception.Message) } }
        try {
            $resp = & $Send $tk $Query
            $rows = if ($resp.results) { @($resp.results) } elseif ($resp.Results) { @($resp.Results) } else { @() }
            return [pscustomobject]@{ Ok = $true; Rows = $rows; Error = '' }
        } catch {
            $err = $_
            $msg = $err.Exception.Message
            if ($err.ErrorDetails -and $err.ErrorDetails.Message) { $msg = $err.ErrorDetails.Message }
            $status = 0
            try { $r = $err.Exception.Response; if ($r -and $r.StatusCode) { $status = [int]$r.StatusCode } } catch { }
            if ($status -eq 0 -and $err.Exception.Message -match '\((\d{3})\)') { $status = [int]$Matches[1] }
            $last = ('HTTP {0} {1}' -f $status, $msg).Trim()
            if ($status -eq 401 -and -not $renewed) { $renewed = $true; $attempt--; try { $null = & $Token $true } catch { }; continue }
            if (-not (($status -in 429, 500, 502, 503, 504) -or $status -eq 0)) { break }
            if ($attempt -ge $MaxAttempts) { break }
            $d = $null
            if (Get-Command -Name Get-SIRetryAfterSeconds -ErrorAction SilentlyContinue) { try { $d = Get-SIRetryAfterSeconds -ErrorRecord $err } catch { $d = $null } }
            if ($null -eq $d) { $d = [int][Math]::Min(60, [Math]::Pow(2, $attempt)) }
            & $Sleep $d
        }
    }
    [pscustomobject]@{ Ok = $false; Rows = @(); Error = $last }
}

function Get-SIHuntingBucketQuery {
    <# PURE. #882 (A3): the part -Bucket of -Buckets of a query's answer: every row in exactly one part (a hash of the whole
       row), the hash column taken off again -- the parts add up to the answer, duplicates included. #>
    param([Parameter(Mandatory)][string]$Query, [int]$Buckets, [int]$Bucket)
    ("{0}`n| extend __siCutPart = hash(tostring(pack_all()), {1})`n| where __siCutPart == {2}`n| project-away __siCutPart" -f $Query.TrimEnd().TrimEnd(';'), $Buckets, $Bucket)
}

function Invoke-SIHuntingCutSplit {
    <#
        #882 (A3): an answer that came back with Microsoft's maximum of rows was CUT. It is asked again in hash parts --
        twice as many parts as the cut answer's size needs -- and a part that is cut again is split in two (its rows are in
        part b or b + n of the doubled count), until no part is cut. Returns @{ Ok; Rows; Parts; Error }: Ok only when
        every part came back whole. -Ask { param($Query) } -> @{ Ok; Rows; Error } (default Invoke-SIHuntingGraphRequest).
        Review M1: the two halves of a split part are asked together. A split that does NOT reduce the part -- one half cut
        again, the other half EMPTY (every row has the same hash: 100,000+ identical rows) -- can never end, so the split stops
        there and the answer is a NAMED FAILURE (Ok = $false, which part, why), never a partial answer.
    #>
    param([Parameter(Mandatory)][string]$Query, [long]$Rows = 0, [scriptblock]$Ask, [int]$Cut = $script:SIHuntingRowCut)
    if (-not $Ask) { $Ask = { param($q) Invoke-SIHuntingGraphRequest -Query $q } }
    $n = [int][Math]::Max(2, 2 * [Math]::Ceiling([Math]::Max(1, $Rows) / [double]$Cut))
    # each item: @(parts, @(bucket[, its sibling])) -- a split part's two halves travel together
    $todo = New-Object System.Collections.Generic.Queue[object]
    for ($b = 0; $b -lt $n; $b++) { $todo.Enqueue(@($n, @($b))) }
    $out = New-Object System.Collections.Generic.List[object]; $parts = 0
    while ($todo.Count -gt 0) {
        $x = $todo.Dequeue(); $pn = [int]$x[0]; $bs = @($x[1])
        $got = New-Object System.Collections.Generic.List[object]
        foreach ($pb in $bs) {
            $r = & $Ask (Get-SIHuntingBucketQuery -Query $Query -Buckets $pn -Bucket ([int]$pb))
            $parts++
            if (-not $r.Ok) { return [pscustomobject]@{ Ok = $false; Rows = @(); Parts = $parts; Error = ('part {0} of {1}: {2}' -f ([int]$pb + 1), $pn, $r.Error) } }
            $got.Add(@([int]$pb, @($r.Rows)))
        }
        if ($bs.Count -eq 2) {
            $cutHalf = @($got | Where-Object { @($_[1]).Count -ge $Cut })
            $emptyHalf = @($got | Where-Object { @($_[1]).Count -eq 0 })
            if ($cutHalf.Count -eq 1 -and $emptyHalf.Count -eq 1) {
                return [pscustomobject]@{ Ok = $false; Rows = @(); Parts = $parts
                    Error = ('part {0} of {1} is still cut at {2:N0} rows after it was split in two and the other half is empty -- its rows are identical (one hash), so splitting cannot read it whole' -f ([int]$cutHalf[0][0] + 1), $pn, $Cut) }
            }
        }
        foreach ($g in $got) {
            $pb = [int]$g[0]; $gr = @($g[1])
            if ($gr.Count -ge $Cut) { $todo.Enqueue(@((2 * $pn), @($pb, ($pb + $pn)))); continue }
            foreach ($row in $gr) { $out.Add($row) }
        }
    }
    [pscustomobject]@{ Ok = $true; Rows = $out.ToArray(); Parts = $parts; Error = '' }
}
