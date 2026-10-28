#Requires -Version 5.1
<#
    SecurityInsight -- THROTTLE-IS-NORMAL (#532; framework DOCS/REQUIREMENTS.md §12.18 holds the contract, not this file).

    A run whose failures are ALL real THROTTLING (a 429 / "too many requests" / rate-limit answer -- Get-SITransientKind in
    SI-ErrorClass.ps1, class 'throttled') and that wrote nothing is not a failed run. Its run-health ExitReason is
    'throttled' (telemetry Outcome 'warning', ErrorClass 'throttled'): no failure mail, no fix request, amber, and it runs
    again at its next scheduled time.
    2026-10-22 (owner, approved): a TIMEOUT or a service that could not be reached (5xx, a reset connection, DNS) is NOT
    throttling -- it was reported as "Microsoft throttled this run" when SI's own storage timed out. Such a run stays a real
    failure ('error'): its real error text is kept, it is mailed and reported, and a new install's first collection is
    restarted after it.

    ONE alert, only when SecurityInsight cannot handle it: the same job has not succeeded for a long stretch because of
    throttling -- the "stuck" alert (guard 'job.run.throttled-stuck'). Settable: SI_Throttle_StuckHours (default 6) and
    SI_Throttle_StuckRuns (default 12), whichever comes first, and never on one run alone. The next successful run clears
    it (nothing to acknowledge).

    What does NOT change (working rule 4: absence is not remediation):
      * a run that wrote part of its result (ExitReason 'success-partial', or a failure in a stage that writes) is never
        'throttled' -- a partial result is never shipped as whole, and a partial write stays a real failure;
      * a run with ANY other failure (403, bad data, a bug) next to the throttling is 'error', exactly as before;
      * a throttled run published nothing, so the previous whole result is still the newest: findings it could not
        collect are UNKNOWN, never resolved (every reader that waits for a 'success' / 'success-partial' run -- the data
        sync, the close-loop, the v3 snapshot -- treats 'throttled' as a run that did not succeed).

    PURE except Get-SIThrottleHistoryKql's caller (Invoke-SIThrottleStuckCheck reads Log Analytics through a seam).
    PS 5.1 safe.
#>

if (-not (Get-Command -Name Get-SIErrorClass -ErrorAction SilentlyContinue)) {
    . ([System.IO.Path]::Combine($PSScriptRoot, 'SI-ErrorClass.ps1'))
}

$script:SIThrottle = @{
    # the error class that means "Microsoft asked us to slow down" -- ONLY real throttling (Get-SITransientKind); a timeout
    # ('platform-timeout') or an unreachable service ('platform-5xx') is a real failure with its own words
    Classes          = @('throttled')
    # run-health ExitReasons that mean "nothing reached any output" -- the only ones that can become 'throttled'
    ErrorReasons     = @('error', 'failure', 'failed')
    # a failure in one of these stages may have written part of the result: never 'throttled'
    WriteStageRegex  = '(?i)output|tagging|recommendations|ingest|publish|write|post|sink|mail|apply|sync|upload|store'
    # Microsoft Graph wording a 429 can carry next to an access problem: an access refusal is never throttling
    AccessRegex      = '(?i)\b40[13]\b|\bForbidden\b|\bUnauthorized\b|Authorization_RequestDenied|AuthorizationFailed|AuthorizationPermissionMismatch|Insufficient privileges|is not authorized to perform|ForbiddenByRbac|ForbiddenByPolicy|Access denied|InvalidAuthenticationToken'
    StuckHours       = 6
    StuckRuns        = 12
    GuardId          = 'job.run.throttled-stuck'
    GuardFile        = ([System.IO.Path]::Combine($PSScriptRoot, 'SI-Guard.ps1'))
    # the customer words (plain language, no internal numbers)
    Text             = 'Microsoft throttled this run; it runs again automatically at its next scheduled time. Nothing was published from it, so the previous results stay in place.'
}

function Get-SIThrottleClasses { @($script:SIThrottle.Classes) }

function Get-SIThrottleText {
    <# PURE. The customer words for a run that ended 'throttled' (run health, the Jobs page, the flow log). A run ends
       'throttled' only when Microsoft really throttled it (Get-SITransientKind), so these words are true. #>
    $script:SIThrottle.Text
}

function Get-SIRunFailureClasses {
    <#
        PURE. Every failure a run's error text names, one error class each. SecurityInsight joins the failures of one run
        with ' | ' (SI-RunOutcome, Risk Analysis); each part is classified on its own, so "429 | 403" is two failures, not
        one throttle. A part that is classified as throttling but ALSO carries an access refusal (401 / 403 wording) adds
        'access-refused' -- Get-SIErrorClass checks throttling first and would otherwise hide it.
    #>
    param([AllowEmptyString()][AllowNull()][string]$Message)
    $out = New-Object System.Collections.Generic.List[string]
    if ([string]::IsNullOrWhiteSpace($Message)) { return @() }
    foreach ($part in ([regex]::Split([string]$Message, '\s\|\s|\r?\n'))) {
        $p = "$part".Trim()
        if (-not $p) { continue }
        $c = Get-SIErrorClass -Message $p
        $out.Add($c)
        if ($script:SIThrottle.Classes -contains $c -and $p -match $script:SIThrottle.AccessRegex) { $out.Add('access-refused') }
    }
    $out.ToArray()
}

function Test-SIThrottleOnly {
    <#
        PURE. $true when there is at least one failure and EVERY failure is throttling / service-side (Get-SIThrottleClasses).
        One unknown, access, data or query failure next to it = $false (the run is a real failure).
    #>
    param([AllowNull()][AllowEmptyCollection()][string[]]$ErrorClasses)
    $c = @(@($ErrorClasses) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($c.Count -eq 0) { return $false }
    foreach ($x in $c) { if ($script:SIThrottle.Classes -notcontains [string]$x) { return $false } }
    $true
}

function Resolve-SIThrottledExitReason {
    <#
        PURE. The run-health ExitReason a run REALLY ended with: 'throttled' when it ended 'error' (nothing reached any
        output), every failure in -ErrorMessage (or -ErrorClasses, when the caller knows them) is throttling / service-side,
        it did not fail in a stage that writes (-FailedStep), and the caller did not say it wrote part of its result
        (-WrotePartial). Anything else is returned unchanged -- 'success-partial' is never turned into 'throttled'.
    #>
    param([AllowEmptyString()][string]$ExitReason, [AllowEmptyString()][AllowNull()][string]$ErrorMessage,
          [AllowNull()][string[]]$ErrorClasses, [AllowEmptyString()][AllowNull()][string]$FailedStep, [switch]$WrotePartial)
    $x = "$ExitReason".Trim().ToLowerInvariant()
    if ($script:SIThrottle.ErrorReasons -notcontains $x) { return $ExitReason }
    if ($WrotePartial) { return $ExitReason }
    if ($FailedStep -and $FailedStep -match $script:SIThrottle.WriteStageRegex) { return $ExitReason }
    $cls = if ($null -ne $ErrorClasses -and @($ErrorClasses).Count) { @($ErrorClasses) } else { @(Get-SIRunFailureClasses -Message $ErrorMessage) }
    if (Test-SIThrottleOnly -ErrorClasses $cls) { return 'throttled' }
    $ExitReason
}

function Get-SIThrottleSetting {
    <# PURE. A positive whole number from the install's settings (-Globals, else $global:), else the default. #>
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][int]$Default, [System.Collections.IDictionary]$Globals)
    $v = if ($Globals -and $Globals.Contains($Name)) { $Globals[$Name] } else { Get-Variable -Name $Name -Scope Global -ValueOnly -ErrorAction SilentlyContinue }
    $n = 0
    if ($null -ne $v -and [int]::TryParse(([string]$v).Trim(), [ref]$n) -and $n -gt 0) { return $n }
    $Default
}

function Get-SIThrottleStuckVerdict {
    <#
        PURE. Is this job STUCK on throttling -- the one alert THROTTLE-IS-NORMAL allows?
          -History  the job's END records, any order: @{ EndedUtc; ExitReason } (newest included)
          -Hours / -Runs  the thresholds (SI_Throttle_StuckHours / SI_Throttle_StuckRuns)
        The STREAK is the unbroken run of 'throttled' records since the newest success ('success' or 'success-partial').
        Any other ending (a real failure) breaks it too -- that one alerts on its own, as before.
        Stuck = the streak has at least 2 runs AND (it spans at least -Hours from its first run to -NowUtc, OR it has at
        least -Runs runs). AlertDue = stuck now, and NOT stuck without the newest record -- so the alert goes out once per
        episode; the next success ends the episode (nothing to acknowledge).
        Returns @{ Stuck; AlertDue; Runs; SinceUtc; Hours }.
    #>
    param([AllowNull()][AllowEmptyCollection()][object[]]$History, [Parameter(Mandatory)][datetime]$NowUtc,
          [int]$Hours = $script:SIThrottle.StuckHours, [int]$Runs = $script:SIThrottle.StuckRuns)
    $now = $NowUtc.ToUniversalTime()
    $rows = @(@($History) | Where-Object { $_ -and $_.EndedUtc } | Sort-Object { ([datetime]$_.EndedUtc).ToUniversalTime() } -Descending)
    $streak = New-Object System.Collections.Generic.List[object]
    foreach ($r in $rows) {
        if ("$($r.ExitReason)".Trim().ToLowerInvariant() -ne 'throttled') { break }
        $streak.Add($r)
    }
    $judge = {
        param($list, $at)
        $n = @($list).Count
        if ($n -lt 2) { return $false }
        $first = ([datetime]@($list)[$n - 1].EndedUtc).ToUniversalTime()
        (($at - $first).TotalHours -ge $Hours) -or ($n -ge $Runs)
    }
    $stuck = [bool](& $judge $streak.ToArray() $now)
    $before = $false
    if ($stuck -and $streak.Count -ge 2) {
        # was the job already stuck when the PREVIOUS run ended? (judged at that run's own time)
        $older = @($streak.ToArray() | Select-Object -Skip 1)
        $before = [bool](& $judge $older ([datetime]$older[0].EndedUtc).ToUniversalTime())
    }
    $since = if ($streak.Count) { ([datetime]$streak[$streak.Count - 1].EndedUtc).ToUniversalTime() } else { $null }
    [pscustomobject]@{
        Stuck    = $stuck
        AlertDue = ($stuck -and -not $before)
        Runs     = $streak.Count
        SinceUtc = $since
        Hours    = $(if ($since) { [Math]::Round(($now - $since).TotalHours, 1) } else { 0 })
    }
}

function Get-SIThrottleHistoryKql {
    <#
        PURE. The KQL that reads one engine's END records of the last -Days days (newest first, at most 200) -- the
        history Get-SIThrottleStuckVerdict judges. $null for a name that is not an engine name (never put into a query).
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Engine, [int]$Days = 14)
    if ($Engine -notmatch '^[a-z0-9][a-z0-9:\-]{0,63}$') { return $null }
    "SI_RunHealth_CL | where TimeGenerated > ago($($Days)d) | where Phase == 'End' and Engine == '$Engine' and toint(ShardIndex) == 0 | project EndedUtc = TimeGenerated, ExitReason = tostring(ExitReason) | order by EndedUtc desc | take 200"
}

function Invoke-SIThrottleStuckCheck {
    <#
        At the END of a throttled run: read the job's history, add THIS run (its record may not be in the store yet) and,
        when the job has just become stuck, raise the ONE alert (guard 'job.run.throttled-stuck': the Guards page, one mail,
        one report to Invardia). NEVER throws; returns the verdict (or $null when the history could not be read).
          -Query  { param($Kql) } -> rows with EndedUtc / ExitReason (default Invoke-SILogLaQuery on SI_WorkspaceResourceId)
          -Raise  { param($Verdict, $Engine, $RunId) } (default Send-SIGuardEvent)
    #>
    param([Parameter(Mandatory)][string]$Engine, [string]$RunId, [datetime]$NowUtc = [datetime]::UtcNow,
          [scriptblock]$Query, [scriptblock]$Raise, [System.Collections.IDictionary]$Globals)
    try {
        $hours = Get-SIThrottleSetting -Name 'SI_Throttle_StuckHours' -Default $script:SIThrottle.StuckHours -Globals $Globals
        $runs = Get-SIThrottleSetting -Name 'SI_Throttle_StuckRuns' -Default $script:SIThrottle.StuckRuns -Globals $Globals
        $kql = Get-SIThrottleHistoryKql -Engine $Engine
        if (-not $kql) { return $null }
        if (-not $Query) {
            if (-not [string]$global:SI_WorkspaceResourceId -or -not (Get-Command -Name Invoke-SILogLaQuery -ErrorAction SilentlyContinue)) { return $null }
            $Query = { param($k) Invoke-SILogLaQuery -WorkspaceResourceId ([string]$global:SI_WorkspaceResourceId) -Query $k }
        }
        $rows = @(@(& $Query $kql) | Where-Object { $_ })
        $now = $NowUtc.ToUniversalTime()
        $hist = @([pscustomobject]@{ EndedUtc = $now; ExitReason = 'throttled' }) + @($rows | Where-Object { $_.EndedUtc -and ([datetime]$_.EndedUtc).ToUniversalTime() -lt $now.AddSeconds(-5) })
        $v = Get-SIThrottleStuckVerdict -History $hist -NowUtc $now -Hours $hours -Runs $runs
        if ($v.AlertDue) {
            try {
                if ($Raise) { $null = & $Raise $v $Engine $RunId }
                else {
                    if (-not (Get-Command -Name Send-SIGuardEvent -ErrorAction SilentlyContinue)) { . $script:SIThrottle.GuardFile }
                    # the cause = this job + the start of this episode: the alert goes out once per episode, and again only
                    # after a successful run has ended the episode and a new one has become stuck
                    $cause = '{0}|{1}' -f $Engine, ([datetime]$v.SinceUtc).ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
                    $null = Send-SIGuardEvent -GuardId $script:SIThrottle.GuardId -Outcome 'warning' -Engine $Engine -Subject $Engine -RunId $RunId -Globals $Globals `
                        -Detail ('The {0} job was throttled by Microsoft on every run for {1} hours ({2} runs in a row) and has not completed since.' -f $Engine, $v.Hours, $v.Runs) `
                        -Values @(@{ Name = 'hoursStuck'; Label = 'Hours without a completed run'; Measured = $v.Hours }, @{ Name = 'runsThrottled'; Label = 'Throttled runs in a row'; Measured = $v.Runs }) `
                        -CauseKeys @($cause)
                }
            } catch { Write-Warning ('The stuck-job alert could not be raised: {0}' -f $_.Exception.Message) }
        }
        $v
    } catch { $null }
}
