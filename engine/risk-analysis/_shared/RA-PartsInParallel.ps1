#Requires -Version 5.1
<#
    Risk Analysis -- SEVERAL QUERY PARTS OF A REPORT AT A TIME (REQUIREMENTS #753).

    A large report is asked in parts (query slices, "bucket 66/256"). Measured live 2026-10-18, one part took ~1.4 minutes,
    one after the other: the advanced-hunting answer 10-30 s, a second call per part (the part's own count, #641) 9-50 s,
    then the engine's own work on the part's rows -- conversion, risk scores, the column fill, the database (~30-45 s).
    While the engine worked on a part, Defender sat idle; while Defender answered, the engine sat idle.

    THE DESIGN: while the engine works on part b, the advanced-hunting requests of the next parts are already on their
    way. The engine still takes the parts ONE BY ONE, IN ORDER, on its own thread, exactly as before -- the conversion,
    the scores, the CI context, the completeness checks, the lost-slice handling, the measurements for the next run's
    part count and the streamed database write with its pacing (#749) are the one-at-a-time code, untouched. Only the
    HTTP requests run at the same time, on .NET's own threads (HttpClient): no PowerShell code runs on another thread,
    so no engine state ($script:_CurrentBucketIndex, the stream, the bucket proof, ...) is ever shared between threads.
    The stored rows and their order are therefore the same as one part at a time.

    How a part is asked ahead: Invoke-RAPartAhead builds the part's query exactly as the part's own run will
    (Invoke-GraphHuntingQuery, its slice coordinates set), with the store in "ask ahead" mode: the advanced-hunting
    transport (Invoke-SIHuntingQueryRest, engine/_shared/SI-GraphRest.ps1) SENDS the request and stops there. Every
    engine variable the build touches is put back as it was, and nothing it says is printed. When the part's turn comes,
    its own call builds the same request, and the transport hands it the answer that is already there (keyed by the
    exact request body) instead of sending it again. A request that came out different (a lookup grew meanwhile) finds
    nothing and is sent as before; the answer asked ahead is dropped -- never used for another request. Only advanced
    hunting is asked ahead: a report answered by Log Analytics or the data lake runs one part at a time, as before.

    HOW MANY AT A TIME ADAPTS (owner rule: no hard caps for scale -- measure, adapt): a report starts at 2. Every answer
    the engine had to WAIT for that came back fine and quickly counts; a full round of such answers adds one more part
    at a time, up to SI_RA_PartsInParallel_Max (not set: no fixed number, since 2026-11-23 -- was 6; never more than 4 per
    processor core). A 429 / 503 / 504
    halves it at once and no part is asked ahead until the service's Retry-After has passed (30 s when it gave none).
    An answer that was already there when its part's turn came adds nothing: then the engine is the slower half, and
    more requests at a time would not make the report faster. SI_RA_PartsInParallel_Max = 1: one part at a time.

    ON QUEUE WORKERS (#742): the Detailed reports run on up to SI_RA_WORKERS workers at once, each its own report. The
    setting is what ONE job may ask at a time, so the workers SHARE it: each gets floor(Max / workers), at least 1
    (Get-RAPartsInParallelShare) -- together never more at a time than one job, and each still halves on throttling.

    THE RUN'S BUDGET IS MEASURED (2026-11-23, owner "push harder, get it all out"): with no SI_RA_PartsInParallel_Max set
    there is no fixed number. The workers of a run keep ONE budget in the run's own storage (budget/run.json, next to the
    run's markers): it starts at one request per worker, halves for every worker at once when ANY of them is asked by
    Defender to slow down (429 / 503 / 504 -- the tenant's quota is one for all of them; nobody asks ahead until the
    Retry-After has passed), and grows by one when a worker's full round of quick answers at its share found no throttling
    in the run for two minutes. Each worker's share is the budget weighted by the query slices its report still has to
    ask (budget/item-NNNNN.json): a worker with nothing queued holds no claim, so its share goes to the reports still
    running -- at the end of a run, to the CVE report. A set SI_RA_PartsInParallel_Max is still the ceiling. A run budget
    that cannot be read is the static share above (safe).

    A SMALL SLICE MERGES WITH ITS UNTOUCHED PARTNER (2026-11-23). A slice's fixed cost (the lookups every slice repeats)
    dominates when its rows are few. In a hash partition of N slices, slice b and slice b + N/2 TOGETHER are exactly slice b
    of N/2 (h % N in {b, b + N/2} <=> h % (N/2) == b), so once an answer is small -- a doubled request still under HALF the planned rows, and the answer
    under a quarter of the slice time -- the next slice is asked together with its partner as slice b of N/2 (and with more partners while
    the answers stay small), for the rest of the report. Only partners no request has touched yet, inside the slices THIS
    process runs; the bookkeeping, the completeness checks and the losses stay per slice of N. A merged request the
    service does not answer (any error) is asked again at once as its own slice; a merged answer that fails later (too
    large for the worker's memory, unreadable) gives its partners back, each asked in its own turn, and the slice itself
    goes the way any slice does (smaller slices, or its loss recorded). Merging stops for the report either way: a failure
    never loses a partner, and a slice that stays failed is UNKNOWN (the report NOT COMPLETE), never short.
#>

$script:RAParts = $null

function Get-RAPartsInParallelMax {
    <# PURE over the setting. The most parts of a report asked at a time: SI_RA_PartsInParallel_Max; 1 / 0 / off = one part
       at a time. Not set (2026-11-23): no fixed number -- the process bound below, and the adaptive rule and the run's
       measured budget decide (-Default 0). Never more than 4 per processor core (the answers are read and converted on
       this process's own thread; more requests than that only wait longer for it). #>
    param($Setting = $global:SI_RA_PartsInParallel_Max, [int]$Cores = [Environment]::ProcessorCount, [int]$Default = 0)
    $bound = [Math]::Max(2, 4 * [Math]::Max(1, $Cores))
    if ($Default -le 0) { $Default = $bound }
    $s = if ($null -ne $Setting) { ([string]$Setting).Trim() } else { '' }
    if ($s -match '^(?i)(off|false|no|disabled?)$') { return 1 }
    $n = 0
    if ($s -ne '' -and [int]::TryParse($s, [System.Globalization.NumberStyles]::Integer, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$n)) {
        if ($n -le 1) { return 1 }
        return [Math]::Min($n, $bound)
    }
    [Math]::Max(1, [Math]::Min($Default, $bound))
}

function Get-RAPartsInParallelShare {
    <#
        PURE. THE RISK ANALYSIS QUEUE WORKERS SHARE ONE JOB'S BUDGET (#742 with #753). SI_RA_PartsInParallel_Max (-Max) is
        what ONE Risk Analysis job may ask Defender at a time. The Detailed reports may run on up to -Workers queue workers
        at once (caj-si-raworker-detailed, SI_RA_WORKERS, setup's SI_Bootstrap_RaMaxWorkers, default 4), each asking its
        own report's parts ahead with its own adaptive rule -- left alone that would be up to Workers x Max requests at
        once. So a queue worker gets its share: floor(Max / Workers), at least 1 (one part at a time, the request the
        worker needs anyway). The workers together then never ask Defender for more at a time than the one job would
        (or, when there are more workers than the budget, one request per worker -- the reviewed worker design), and
        each worker's adaptive rule still halves its own share at once on a 429 / 503 / 504.
        -Role: 'worker' for a queue worker; -Local: the producer's own worker in its container (the only one -- the whole
        budget). Anything else (one job, the producer) = -Max unchanged.
    #>
    # #831 A -- THE FREE BUDGET (measured at a large install 2026-10-20: the queue was empty after 50 minutes, three workers
    # stopped, and the last one ran its report alone for 4 h 46 m at ONE request at a time while 5 of the 6 slots were free).
    # -Open: the run's items without a marker yet (RA-ScaleOut.ps1 Get-RAScaleOutOpenItems -- this worker's own included).
    # At most that many workers can still be running an item of the run, so each divides the budget by min(Workers, Open):
    # the last worker gets all of it, two get half each. Together they still never ask more than -Max at a time: Open only
    # falls during a run, so a worker that read it earlier holds a SMALLER share, never a larger one. -Open < 1 (not known)
    # = the static share, as before.
    param([int]$Max, [AllowEmptyString()][string]$Role = '', [bool]$Local = $false, [int]$Workers = 0, [int]$Open = -1)
    if ($Max -lt 1) { $Max = 1 }
    if (([string]$Role).Trim().ToLowerInvariant() -ne 'worker' -or $Local) { return $Max }
    if ($Workers -lt 1) { $Workers = 4 }      # a worker made before SI_RA_WORKERS: setup's default worker count
    $n = $Workers
    if ($Open -ge 1 -and $Open -lt $n) { $n = $Open }
    [Math]::Max(1, [int][Math]::Floor($Max / $n))
}

function Get-RAPartsOpenItems {
    <# #831 A: the run's open items as the engine's probe tells them ($script:RAPartsOpenProbe, set by a queue worker), -1
       when there is no probe or it cannot tell. Never throws. #>
    $p = $script:RAPartsOpenProbe
    if ($null -eq $p) { return -1 }
    try { $v = & $p; if ($null -eq $v) { return -1 }; return [int]$v } catch { return -1 }
}

function Test-RAPartsShareMayRise {
    <# #831 A: this process is a queue worker whose share may rise during a report (a probe is set, the setting allows more
       than one part at a time) -- then asking ahead stays ready even while the share is one part. #>
    if ($null -eq $script:RAPartsOpenProbe -and $null -eq $script:RAPartsBudgetProbe) { return $false }
    if (([string]$global:SI_RA_ScaleOutRole).Trim().ToLowerInvariant() -ne 'worker') { return $false }
    if (([string][Environment]::GetEnvironmentVariable('SI_RA_SCALEOUT_LOCAL')).Trim() -eq '1') { return $false }
    (Get-RAPartsInParallelMax) -gt 1
}

function Get-RAPartsInParallelLimit {
    <# The most parts of a report THIS process asks at a time: the setting (Get-RAPartsInParallelMax), shared among the
       queue workers when this is one (Get-RAPartsInParallelShare; the role, SI_RA_SCALEOUT_LOCAL and SI_RA_WORKERS from
       the worker's environment). Said once per process when it is a share. #>
    $max = Get-RAPartsInParallelMax
    $w = 0; $null = [int]::TryParse(([string][Environment]::GetEnvironmentVariable('SI_RA_WORKERS')).Trim(), [ref]$w)
    $local = (([string][Environment]::GetEnvironmentVariable('SI_RA_SCALEOUT_LOCAL')).Trim() -eq '1')
    $open = -1
    if (([string]$global:SI_RA_ScaleOutRole).Trim().ToLowerInvariant() -eq 'worker' -and -not $local) { $open = Get-RAPartsOpenItems }
    $script:RAPartsShareCheckedAt = [datetime]::UtcNow
    $n = Get-RAPartsInParallelShare -Max $max -Role ([string]$global:SI_RA_ScaleOutRole) -Local $local -Workers $w -Open $open
    if ($n -lt $max -and -not $script:RAPartsShareSaid) {
        $script:RAPartsShareSaid = $true
        Write-Info ('this worker asks Defender for up to {0} -- the {1} one Risk Analysis job may ask, shared by up to {2} workers' -f $(if ($n -eq 1) { '1 part at a time' } else { '{0} parts at a time' -f $n }), $max, $(if ($w -gt 0) { $w } else { 4 }))
    }
    $n
}

function Format-RAPartsLine {
    <# PURE. "1 part at a time" / "3 parts at a time", with what made it so. #>
    param([int]$N, [string]$Why = '')
    $t = if ($N -eq 1) { '1 part at a time' } else { '{0} parts at a time' -f $N }
    if ($Why) { return ('{0} -- {1}' -f $Why, $t) }
    $t
}

function Get-RAPartsInParallelStep {
    <#
        PURE. The adaptive rule, for ONE answer of a part asked ahead. @{ N; Clean; PauseSeconds; Line }.
          429 / 503 / 504     half as many (at least 1), no part asked ahead for Retry-After seconds (30 when none)
          2xx, the engine WAITED for it (>= 1 s) and it came within QuickSeconds
                              one more clean answer; N clean answers in a row = one more part at a time (up to Max)
          anything else       no change (an answer already there: the engine is the slower half; a slow answer or an
                              error that is not throttling: the part's own run handles it, nothing is learned)
    #>
    param([int]$N, [int]$Max, [int]$Clean = 0, [int]$Status = 200, [int]$RetryAfterSec = 0, [double]$WaitedSec = 0, [double]$Seconds = 0, [double]$QuickSeconds = 120)
    if ($N -lt 1) { $N = 1 }
    if ($Status -in 429, 503, 504) {
        $n2 = [Math]::Max(1, [int][Math]::Floor($N / 2))
        $pause = if ($RetryAfterSec -gt 0) { $RetryAfterSec } else { 30 }
        return @{ N = $n2; Clean = 0; PauseSeconds = $pause; Line = (Format-RAPartsLine -N $n2 -Why 'Defender asked us to slow down') }
    }
    if ($Status -ge 200 -and $Status -lt 300 -and $WaitedSec -ge 1 -and $Seconds -le $QuickSeconds) {
        $c = $Clean + 1
        if ($c -ge $N -and $N -lt $Max) { return @{ N = ($N + 1); Clean = 0; PauseSeconds = 0; Line = (Format-RAPartsLine -N ($N + 1) -Why 'Defender answers quickly') } }
        # a full round of quick answers AT this process's limit: the run's measured budget may grow (AtMax)
        if ($c -ge $N -and $N -ge $Max) { return @{ N = $N; Clean = 0; PauseSeconds = 0; Line = ''; AtMax = $true } }
        return @{ N = $N; Clean = $c; PauseSeconds = 0; Line = '' }
    }
    @{ N = $N; Clean = $Clean; PauseSeconds = 0; Line = '' }
}

function Test-RABucketCountWanted {
    <#
        PURE. Whether ONE part is checked against the source's own count of it (#641 -- the part's second advanced-hunting
        call, "attempt 1/1", 9-50 s per part live 2026-10-18). SI_RA_BucketCountCheck:
          off / false / 0 / no        never;
          all / on / true / 1 / yes   every part (as before 2026-10-18);
          unset (the default)         only a part whose rows reach HALF the source's row limit (SI_RA_HuntingRowCap,
                                      100,000): only there can an answer be cut without an error. An answer AT the limit
                                      is refused and the part made smaller (Invoke-GraphHuntingQuery), and a part well
                                      below it was not cut.
        The REPORT's own count (Get-RAReportExpectedRows: the query whole, once per report) still checks every report: a
        report whose parts together returned fewer rows than the source holds is NOT COMPLETE, as before. Live 2026-10-13
        that whole count is what caught a short report whose every part matched its own count.
    #>
    param([long]$Rows, $Setting = $global:SI_RA_BucketCountCheck, [int]$RowLimit = 0)
    $s = if ($null -ne $Setting) { ([string]$Setting).Trim().ToLowerInvariant() } else { '' }
    if ($s -in 'off', 'false', '0', 'no') { return $false }
    if ($s -in 'all', 'on', 'true', '1', 'yes') { return $true }
    $lim = if ($RowLimit -gt 0) { $RowLimit } elseif ([int]$global:SI_RA_HuntingRowCap -gt 0) { [int]$global:SI_RA_HuntingRowCap } else { 100000 }
    ($Rows * 2) -ge $lim
}

function Reset-RAPartsInParallel {
    <# A report (or the same report with more parts) begins: answers asked ahead for anything before are dropped, and the
       report starts at 2 parts at a time (1 when it has one part, or when SI_RA_PartsInParallel_Max = 1). A queue
       worker uses its share of the setting (Get-RAPartsInParallelLimit). #>
    param([int]$PartCount = 1, [int]$Max = (Get-RAPartsInParallelLimit))
    if ($null -ne $script:SIHuntingPrefetch) { $null = Remove-SIHuntingPrefetch -Store $script:SIHuntingPrefetch }
    $script:SIHuntingPrefetch = $null
    # #831 A: a queue worker whose share may rise later in the report stays ready to ask ahead even at one part at a time
    $on = ($PartCount -gt 1 -and ($Max -gt 1 -or (Test-RAPartsShareMayRise)))
    $script:RAParts = @{ On = $on; Max = $Max; N = $(if ($on) { [Math]::Max(1, [Math]::Min(2, $Max)) } else { 1 }); Clean = 0; PauseUntil = [datetime]::MinValue
                         Started = (New-Object 'System.Collections.Generic.HashSet[int]'); Ahead = 0; Used = 0; Missed = 0; Throttled = 0; Said = $false
                         # the run's measured budget (Update-RAPartsRunShare): what to tell it, this report's weight, when it was read
                         RunEvent = ''; RunRetryAfter = 0; Remaining = [long][Math]::Max(0, $PartCount); Claimed = $false; RunCheckedAt = [datetime]::MinValue }
    if ($on) { $script:SIHuntingPrefetch = New-SIHuntingPrefetchStore }
    # a worker that keeps the run's budget reads its share for this report at once (its weight: the report's slices)
    if ($on -and $null -ne $script:RAPartsBudgetProbe) { $null = Update-RAPartsRunShare -Force }
}

function Stop-RAPartsInParallel {
    <# The report's main pass is over: what was asked ahead and not read is dropped, and it is said what asking ahead did. #>
    $p = $script:RAParts
    $dropped = 0
    if ($null -ne $script:SIHuntingPrefetch) { $dropped = Remove-SIHuntingPrefetch -Store $script:SIHuntingPrefetch }
    $script:SIHuntingPrefetch = $null
    if ($null -ne $p -and [int]$p.Ahead -gt 0) {
        $t = '{0} part(s) were asked ahead while earlier parts were processed; {1} of them were used' -f [int]$p.Ahead, [int]$p.Used
        if ([int]$p.Missed -gt 0) { $t += ('; {0} came out different when their turn came and were asked again' -f [int]$p.Missed) }
        if ($dropped -gt 0) { $t += ('; {0} were not needed' -f $dropped) }
        if ([int]$p.Throttled -gt 0) { $t += ('; Defender asked us to slow down {0} time(s)' -f [int]$p.Throttled) }
        Write-Info $t
    }
    # the run's measured budget: this report asks nothing more, so its claim is given back to the reports still running
    if ($null -ne $p -and [bool]$p.Claimed -and $null -ne $script:RAPartsBudgetProbe) { try { $null = & $script:RAPartsBudgetProbe 'release' 0L 0 } catch { } }
    $script:RAParts = $null
}

function Update-RAPartsInParallel {
    <# Reads what the answers asked ahead were like (the throttled ones as soon as they are back) and applies the rule. #>
    param([double]$QuickSeconds = 120)
    $p = $script:RAParts; $st = $script:SIHuntingPrefetch
    if ($null -eq $p -or -not $p.On -or $null -eq $st) { return }
    $events = New-Object System.Collections.Generic.List[object]
    $ra = Get-SIHuntingPrefetchThrottle -Store $st
    if ($ra -ge 0) { $events.Add(@{ Status = 429; RetryAfterSec = $ra; WaitedSec = 0; Seconds = 0 }) }
    $answers = $st.Answers.ToArray(); $st.Answers.Clear()
    foreach ($a in $answers) {
        if ([int]$a.Part -ge 0) { $p.Used++ }     # Part -1: a request the engine sent itself (measured, not asked ahead)
        # a throttled answer already looked at when it came back (above, or at an earlier look) is not counted twice
        if (([int]$a.Status -in @(429, 503, 504)) -and [bool]$a.Peeked) { continue }
        $events.Add(@{ Status = [int]$a.Status; RetryAfterSec = [int]$a.RetryAfterSec; WaitedSec = [double]$a.WaitedSec; Seconds = [double]$a.Seconds })
    }
    foreach ($e in $events) {
        $s = Get-RAPartsInParallelStep -N $p.N -Max $p.Max -Clean $p.Clean -Status $e.Status -RetryAfterSec $e.RetryAfterSec -WaitedSec $e.WaitedSec -Seconds $e.Seconds -QuickSeconds $QuickSeconds
        if ($s.PauseSeconds -gt 0) {
            $p.Throttled++
            $until = [datetime]::UtcNow.AddSeconds($s.PauseSeconds)
            if ($until -gt $p.PauseUntil) { $p.PauseUntil = $until }
            # the run's measured budget: a throttle is told to every worker of the run (Update-RAPartsShare, at once)
            $p.RunEvent = 'throttle'; $p.RunRetryAfter = [Math]::Max([int]$p.RunRetryAfter, [int]$s.PauseSeconds)
        } elseif ($s.ContainsKey('AtMax') -and $s.AtMax -and [string]$p.RunEvent -ne 'throttle') { $p.RunEvent = 'raise' }
        if ($s.Line -and ($s.N -ne $p.N -or $s.PauseSeconds -gt 0)) { Write-Info $s.Line }
        $p.N = $s.N; $p.Clean = $s.Clean
    }
}

function Update-RAPartsShare {
    <#
        #831 A: a queue worker re-reads its share of the budget at most every -EverySeconds (default SI_RA_PartsShareRecheckSeconds,
        300 -- one listing of the run's markers, never a call per part; the start of every report reads it too). When fellow
        workers have ended, the share rises (said once per rise) and the adaptive count starts climbing from 2 again; it never
        goes above the new share. The adaptive halving on 429 / 503 / 504 is unchanged. -Now: a seam for tests.
    #>
    param([int]$EverySeconds = 0, [datetime]$Now = [datetime]::UtcNow)
    $p = $script:RAParts
    if ($null -eq $p -or -not $p.On) { return }
    # 2026-11-23: the run's measured budget, when this worker keeps one (a throttle at once; else every recheck)
    if ($null -ne $script:RAPartsBudgetProbe) { if (Update-RAPartsRunShare -Now $Now) { return } }
    if ($null -eq $script:RAPartsOpenProbe) { return }
    if ($EverySeconds -le 0) { $EverySeconds = 300; $s = 0; if ([int]::TryParse(([string]$global:SI_RA_PartsShareRecheckSeconds).Trim(), [ref]$s) -and $s -gt 0) { $EverySeconds = $s } }
    $last = $script:RAPartsShareCheckedAt
    if ($last -is [datetime] -and ($Now - $last).TotalSeconds -lt $EverySeconds) { return }
    $new = Get-RAPartsInParallelLimit
    $script:RAPartsShareCheckedAt = $Now
    if ($new -eq [int]$p.Max) { return }
    if ($new -gt [int]$p.Max) {
        Write-Info ('the other workers of this run have finished -- this worker may now ask Defender for up to {0}' -f $(if ($new -eq 1) { '1 part at a time' } else { '{0} parts at a time' -f $new }))
        if ([int]$p.N -lt [Math]::Min(2, $new)) { $p.N = [Math]::Min(2, $new); $p.Clean = 0 }
    }
    $p.Max = $new
    if ([int]$p.N -gt $new) { $p.N = $new }
}

function Invoke-RAPartAhead {
    <#
        Asks ONE part ahead: its query is built exactly as the part's own run builds it, and the advanced-hunting
        transport sends the request and stops. Every engine variable the build touches is put back, and nothing it says
        is printed (the part's own run says it all). 'Started' | 'NotAhead' (this report is not answered by advanced
        hunting) | 'Failed' (the build failed -- the part's own run meets the same and handles it).
    #>
    param([Parameter(Mandatory)][int]$Part, [Parameter(Mandatory)][int]$PartCount, [Parameter(Mandatory)][string]$Query, [string]$ReportName)
    # silent: dynamic scope -- every engine function called from here finds these first
    function Write-Info { param($m) }
    function Write-Warn2 { param($m) }
    function Write-Err2 { param($m) }
    function Write-Ok { param($m) }
    function Write-Diag { param($m) }
    # what the build may change in the engine's variables -- each is put back after it (named one by one: the same
    # $script: the engine's own functions read and write)
    $s01 = $script:_CurrentBucketCount; $s02 = $script:_CurrentBucketIndex; $s03 = $script:_LastHybridInlineBytes
    $s04 = $script:_LastHybridQueryBodyOverheadBytes; $s05 = $script:_LastHybridSnapshotRowCount; $s06 = $script:_LastHybridBytesPerRow
    $s07 = $script:_RAHybridLastRequest; $s08 = $script:_RAHybridLookups; $s09 = $script:_RALookupNeededKeySets
    $s10 = $script:_RALookupKeyQueryBuilding; $s11 = $script:_LastGraphHuntingAllTimedOut; $s12 = $script:RADfcLast
    $s13 = $script:_SkipEGBucketForCrossDomain; $s14 = $script:_RACrossDomainReplicated; $s15 = $script:_SupersededAttempts
    $s16 = $script:_RALookupKeyAnswerMemo
    $reduction = if ($script:_RALookupReductionOn -is [hashtable]) { $script:_RALookupReductionOn.Clone() } else { $script:_RALookupReductionOn }
    $st = $script:SIHuntingPrefetch
    $st.Capture = $true; $st.Part = $Part
    $out = 'NotAhead'
    try {
        $q = Replace-BucketFilterBlock -Query $Query -BucketFilterKql (New-BucketFilterKql -BucketCount $PartCount -BucketIndex $Part -ReportName $ReportName)
        $script:_CurrentBucketCount = $PartCount
        $script:_CurrentBucketIndex = $Part
        $null = Invoke-GraphHuntingQuery -Query $q -ReconnectMaxAgeMinutes $global:GraphReconnectMaxAgeMinutes -MaxRetries 1
    } catch {
        $m = [string]$_.Exception.Message
        $out = if ($m -eq (Get-SIHuntingAheadStartedText)) { 'Started' } elseif ($m -eq (Get-SIHuntingNotAheadText)) { 'NotAhead' } else { 'Failed' }
    } finally {
        $st.Capture = $false; $st.Part = -1
        $script:_CurrentBucketCount = $s01; $script:_CurrentBucketIndex = $s02; $script:_LastHybridInlineBytes = $s03
        $script:_LastHybridQueryBodyOverheadBytes = $s04; $script:_LastHybridSnapshotRowCount = $s05; $script:_LastHybridBytesPerRow = $s06
        $script:_RAHybridLastRequest = $s07; $script:_RAHybridLookups = $s08; $script:_RALookupNeededKeySets = $s09
        $script:_RALookupKeyQueryBuilding = $s10; $script:_LastGraphHuntingAllTimedOut = $s11; $script:RADfcLast = $s12
        $script:_SkipEGBucketForCrossDomain = $s13; $script:_RACrossDomainReplicated = $s14; $script:_SupersededAttempts = $s15
        $script:_RALookupKeyAnswerMemo = $s16
        $script:_RALookupReductionOn = $reduction
    }
    $out
}

function Invoke-RAPartsAhead {
    <#
        The main loop has the answer of part -After and is about to work on it: the parts after it are asked ahead until
        N - 1 are on their way (the part being worked on is the Nth). Nothing while Defender asked us to wait, and nothing
        once the report proved not to be answered by advanced hunting. -AskAhead: a seam for tests (default: the engine).
    #>
    # -End (#831 B): the slice after the last one THIS process runs (a part of a split report runs [From, End) of PartCount)
    param([Parameter(Mandatory)][int]$After, [Parameter(Mandatory)][int]$PartCount, [Parameter(Mandatory)][string]$Query, [string]$ReportName, [scriptblock]$AskAhead, [int]$End = -1)
    $p = $script:RAParts; $st = $script:SIHuntingPrefetch
    if ($null -eq $p -or -not $p.On -or $null -eq $st) { return }
    if ($End -lt 0 -or $End -gt $PartCount) { $End = $PartCount }
    $p.Remaining = [long][Math]::Max(0, $End - $After)   # this report's slices still to ask (the run budget's weight)
    Update-RAPartsShare
    # the part just answered: was it asked ahead and its answer NOT used (its request came out different)? dropped, counted
    foreach ($e in @($st.Entries.Values | Where-Object { [int]$_.Part -le $After })) { $null = Remove-SIHuntingPrefetch -Store $st -Key $e.Key; $p.Missed++ }
    if ([int]$p.Missed -ge 3) {
        Write-Info 'the parts asked ahead came out different from the parts'' own requests -- this report goes on one part at a time'
        $p.On = $false; $null = Remove-SIHuntingPrefetch -Store $st; return
    }
    Update-RAPartsInParallel
    # a throttle (or a full round at the share) is told to the run's budget at once, not at the next recheck
    if ($p.RunEvent -and $null -ne $script:RAPartsBudgetProbe) { $null = Update-RAPartsRunShare -Force }
    if (-not $p.Said) { Write-Info (Format-RAPartsLine -N $p.N); $p.Said = $true }
    if ([datetime]::UtcNow -lt $p.PauseUntil) { return }
    # 2026-11-23: with slices merging (Get-RASliceRequest), a slice asked together with an earlier one is not asked ahead,
    # and a slice is asked ahead exactly as its own turn will ask it (the same decided request)
    $mg = $script:RASliceMerge
    if ($null -ne $mg -and [int]$mg.N -ne $PartCount) { $mg = $null }
    for ($k = $After + 1; $k -lt $End -and $st.Entries.Count -lt ($p.N - 1); $k++) {
        if (-not $p.Started.Add($k)) { continue }
        $kCount = $PartCount; $kIndex = $k
        if ($null -ne $mg) {
            if (Test-RASliceTaken -Merge $mg -Slice $k) { continue }
            $rq = Get-RASliceRequest -Merge $mg -Slice $k
            $kCount = [int]$rq.Count; $kIndex = [int]$rq.Index
        }
        $r = if ($AskAhead) { & $AskAhead $k } else { Invoke-RAPartAhead -Part $kIndex -PartCount $kCount -Query $Query -ReportName $ReportName }
        if ($r -eq 'Started') { $p.Ahead++; continue }
        if ($r -eq 'NotAhead') { $p.On = $false; $null = Remove-SIHuntingPrefetch -Store $st }
        break   # the build failed: the part's own run meets the same and handles it; nothing more is asked ahead now
    }
}

function Stop-RAPartsAheadForMemory {
    <#
        A part of the report did not fit in this worker's memory: answers asked ahead are held in memory while a part is
        processed, so for the rest of THIS report no part is asked ahead (what is held is dropped) -- one answer in memory at
        a time. The next report starts again as before (Reset-RAPartsInParallel). Returns $true when it changed anything.
    #>
    $p = $script:RAParts
    if ($null -eq $p -or -not [bool]$p.On) { return $false }
    $p.On = $false
    if ($null -ne $script:SIHuntingPrefetch) { $null = Remove-SIHuntingPrefetch -Store $script:SIHuntingPrefetch }
    Write-Info 'a part of this report was too large for this worker''s memory -- the rest of the report is asked one part at a time (no answer held ahead)'
    $true
}

# =====================================================================================================================
#  THE RUN'S MEASURED BUDGET (2026-11-23, owner "push harder, get it all out"). See the header: no fixed number -- the
#  workers of a run keep one budget in the run's storage, halved for all of them on any throttle, grown after quiet full
#  rounds, and shared by the query slices each running report still has to ask.
# =====================================================================================================================
# $script:RAPartsBudgetProbe -- a queue worker's: { param($Event, $Remaining, $RetryAfterSec) Sync-RAPartsRunBudget ... }
# (never set here: this file may be loaded after the worker has set it, as $script:RAPartsOpenProbe)

function Get-RAPartsField {
    <# PURE. One field of a hashtable or an object read from JSON; $null when it has none. #>
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { if ($Object.Contains($Name)) { return $Object[$Name] }; return $null }
    $pr = $Object.PSObject.Properties[$Name]
    if ($pr) { return $pr.Value }
    $null
}

function ConvertTo-RAPartsUtc {
    <# PURE. A time as UTC: a [datetime] (a time without a kind is UTC), or a round-trip text; [datetime]::MinValue when none. #>
    param($Value)
    if ($null -eq $Value) { return [datetime]::MinValue }
    if ($Value -is [datetime]) {
        if ($Value.Kind -eq [DateTimeKind]::Unspecified) { return [datetime]::SpecifyKind($Value, [DateTimeKind]::Utc) }
        return $Value.ToUniversalTime()
    }
    $s = ([string]$Value).Trim()
    if (-not $s) { return [datetime]::MinValue }
    $d = [datetime]::MinValue
    if ([datetime]::TryParse($s, [System.Globalization.CultureInfo]::InvariantCulture, ([System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal), [ref]$d)) { return [datetime]::SpecifyKind($d, [DateTimeKind]::Utc) }
    [datetime]::MinValue
}

function Get-RAPartsBudgetPath {
    <# PURE. Where a run keeps its measured budget (-Item -1: budget/run.json) and each running report's claim on it
       (budget/item-NNNNN.json), next to the run's markers. #>
    param([Parameter(Mandatory)][string]$Engine, [Parameter(Mandatory)][string]$RunId, [int]$Item = -1)
    $base = 'collect/{0}/{1}/budget' -f $Engine.ToLowerInvariant(), $RunId
    if ($Item -lt 0) { return "$base/run.json" }
    '{0}/item-{1:D5}.json' -f $base, $Item
}

function Get-RAPartsBudgetCeiling {
    <# PURE over the setting. The ceiling of the run's measured budget: a number set in SI_RA_PartsInParallel_Max (1 / off
       = one at a time); not set = 0 (no fixed number). #>
    param($Setting = $global:SI_RA_PartsInParallel_Max)
    $s = if ($null -ne $Setting) { ([string]$Setting).Trim() } else { '' }
    if ($s -match '^(?i)(off|false|no|disabled?)$') { return 1 }
    $n = 0
    if ($s -ne '' -and [int]::TryParse($s, [System.Globalization.NumberStyles]::Integer, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$n)) { return [Math]::Max(1, $n) }
    0
}

function Get-RAPartsRunBudgetNext {
    <#
        PURE. The run's budget after one event. -Budget: @{ Limit; PauseUntilUtc; ThrottledUtc; Rev } (or the object read
        back from the run's storage), $null = none yet: it starts at -Start (one request per worker).
          'read'      no change;
          'throttle'  Defender asked a worker to slow down: half (at least -Floor) and nobody asks ahead before its
                      Retry-After (30 s when it gave none). Inside a pause that is already running only the pause is made
                      longer: the workers throttled in the same window halve the budget once, not once each;
          'raise'     a worker's full round of quick answers at its share: one more -- only when no worker of the run was
                      throttled for -QuietSeconds and the pause is over, and never above -Ceiling when one is set.
        @{ Budget; Changed }.
    #>
    param($Budget = $null, [string]$Event = 'read', [int]$RetryAfterSec = 0, [int]$Floor = 1, [int]$Start = 2, [int]$Ceiling = 0,
          [datetime]$Now = [datetime]::UtcNow, [int]$QuietSeconds = 120)
    if ($Floor -lt 1) { $Floor = 1 }
    $changed = $false
    $b = @{ Limit = [Math]::Max($Floor, $Start); PauseUntilUtc = [datetime]::MinValue; ThrottledUtc = [datetime]::MinValue; Rev = 0 }
    if ($null -eq $Budget) { $changed = $true }
    else {
        $l = 0; [void][int]::TryParse([string](Get-RAPartsField $Budget 'Limit'), [ref]$l)
        if ($l -ge 1) { $b.Limit = $l } else { $changed = $true }
        $b.PauseUntilUtc = ConvertTo-RAPartsUtc (Get-RAPartsField $Budget 'PauseUntilUtc')
        $b.ThrottledUtc = ConvertTo-RAPartsUtc (Get-RAPartsField $Budget 'ThrottledUtc')
        $r = 0; [void][int]::TryParse([string](Get-RAPartsField $Budget 'Rev'), [ref]$r); $b.Rev = $r
    }
    if ($Ceiling -gt 0 -and $b.Limit -gt $Ceiling) { $b.Limit = $Ceiling; $changed = $true }
    if ($b.Limit -lt $Floor) { $b.Limit = $Floor; $changed = $true }
    $Now = ConvertTo-RAPartsUtc $Now
    switch ($Event) {
        'throttle' {
            $pause = if ($RetryAfterSec -gt 0) { $RetryAfterSec } else { 30 }
            if ($Now -ge $b.PauseUntilUtc) { $b.Limit = [Math]::Max($Floor, [int][Math]::Floor($b.Limit / 2)) }
            $until = $Now.AddSeconds($pause); if ($until -gt $b.PauseUntilUtc) { $b.PauseUntilUtc = $until }
            $b.ThrottledUtc = $Now; $changed = $true
        }
        'raise' {
            $quiet = ($b.ThrottledUtc -eq [datetime]::MinValue) -or (($Now - $b.ThrottledUtc).TotalSeconds -ge $QuietSeconds)
            if ($quiet -and $Now -ge $b.PauseUntilUtc -and ($Ceiling -le 0 -or $b.Limit -lt $Ceiling)) { $b.Limit++; $changed = $true }
        }
    }
    if ($changed) { $b.Rev++ }
    @{ Budget = $b; Changed = $changed }
}

function Get-RAPartsWeightedShare {
    <#
        PURE. THIS worker's share of the run's budget -Limit, weighted by the query slices its report still has to ask
        (-Mine) against the claims of the other reports still running (-Claims: @{ Item; Remaining; UpdatedUtc }). Its own
        -Item, a claim with nothing left and a claim not renewed for -StaleSeconds (a worker that ended or died) are left
        out: a worker with nothing queued holds nothing, so what it held goes to the reports still running. At least 1 (the
        request the worker needs anyway), never above -Bound (this process's own bound) when one is given.
    #>
    param([int]$Limit, [long]$Mine, [object[]]$Claims = @(), [int]$Item = -1, [datetime]$Now = [datetime]::UtcNow, [int]$StaleSeconds = 600, [int]$Bound = 0)
    if ($Limit -lt 1) { $Limit = 1 }
    if ($Mine -lt 1) { $Mine = 1 }
    $Now = ConvertTo-RAPartsUtc $Now
    $others = 0L
    foreach ($c in @($Claims)) {
        if ($null -eq $c) { continue }
        $ci = -1; [void][int]::TryParse([string](Get-RAPartsField $c 'Item'), [ref]$ci)
        if ($ci -eq $Item) { continue }
        $rem = 0L; [void][long]::TryParse([string](Get-RAPartsField $c 'Remaining'), [ref]$rem)
        if ($rem -le 0) { continue }
        $at = ConvertTo-RAPartsUtc (Get-RAPartsField $c 'UpdatedUtc')
        if ($at -eq [datetime]::MinValue -or ($Now - $at).TotalSeconds -gt $StaleSeconds) { continue }
        $others += $rem
    }
    $s = [int][Math]::Floor([double]$Limit * [double]$Mine / [double]($Mine + $others))
    $s = [Math]::Max(1, $s)
    if ($Bound -gt 0) { $s = [Math]::Min($s, $Bound) }
    $s
}

function Sync-RAPartsRunBudget {
    <#
        One read of the run's budget (written back only when it changed), this report's claim written (-Event 'release':
        nothing left -- the report asks nothing more), the claims of the run listed: @{ Share; Limit; PauseUntilUtc }.
        -Store: SI-CollectParts' store seam (Read / Write / List). $null when the store cannot be read: the caller keeps the
        static share (safe). Two workers writing at once: the last write wins -- a throttle may be counted twice (half
        again: the safe direction), a raise may be lost (the next round asks again).
    #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$Engine, [Parameter(Mandatory)][string]$RunId, [Parameter(Mandatory)][int]$Item,
          [long]$Remaining = 0, [string]$Event = 'read', [int]$RetryAfterSec = 0, [int]$Start = 2, [int]$Ceiling = 0, [int]$Bound = 0,
          [datetime]$Now = [datetime]::UtcNow)
    try {
        $Now = ConvertTo-RAPartsUtc $Now
        $runPath = Get-RAPartsBudgetPath -Engine $Engine -RunId $RunId
        $cur = $null; $t = & $Store.Read $runPath
        if (-not [string]::IsNullOrWhiteSpace([string]$t)) { $cur = ConvertFrom-Json -InputObject ([string]$t) }
        $ev = if ($Event -eq 'release') { 'read' } else { $Event }
        $nx = Get-RAPartsRunBudgetNext -Budget $cur -Event $ev -RetryAfterSec $RetryAfterSec -Start $Start -Ceiling $Ceiling -Now $Now
        $b = $nx.Budget
        if ($nx.Changed) {
            & $Store.Write $runPath (ConvertTo-Json -Compress -InputObject ([ordered]@{ Limit = [int]$b.Limit; PauseUntilUtc = $b.PauseUntilUtc.ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)
                ThrottledUtc = $b.ThrottledUtc.ToString('o', [System.Globalization.CultureInfo]::InvariantCulture); Rev = [int]$b.Rev }))
        }
        $rem = if ($Event -eq 'release') { 0L } else { [long][Math]::Max(0, $Remaining) }
        & $Store.Write (Get-RAPartsBudgetPath -Engine $Engine -RunId $RunId -Item $Item) (ConvertTo-Json -Compress -InputObject ([ordered]@{ Item = $Item; Remaining = $rem; UpdatedUtc = $Now.ToString('o', [System.Globalization.CultureInfo]::InvariantCulture) }))
        if ($Event -eq 'release') { return @{ Share = 1; Limit = [int]$b.Limit; PauseUntilUtc = $b.PauseUntilUtc } }
        $prefix = 'collect/{0}/{1}/budget/' -f $Engine.ToLowerInvariant(), $RunId
        $claims = New-Object System.Collections.Generic.List[object]
        foreach ($n in @(& $Store.List $prefix)) {
            if ([string]$n -notmatch 'item-(\d+)\.json$') { continue }
            if ([int]$Matches[1] -eq $Item) { continue }
            $ct = & $Store.Read ([string]$n)
            if ([string]::IsNullOrWhiteSpace([string]$ct)) { continue }
            try { $claims.Add((ConvertFrom-Json -InputObject ([string]$ct))) } catch { }
        }
        $share = Get-RAPartsWeightedShare -Limit ([int]$b.Limit) -Mine $rem -Claims $claims.ToArray() -Item $Item -Now $Now -Bound $Bound
        @{ Share = $share; Limit = [int]$b.Limit; PauseUntilUtc = $b.PauseUntilUtc }
    } catch { $null }
}

function Update-RAPartsRunShare {
    <#
        THIS worker's share of the run's measured budget, applied to the report's adaptive count: read at most every
        -EverySeconds (SI_RA_PartsBudgetSeconds, default 60 -- one read, one write and one listing; never per request), at
        once with -Force or when there is an event to tell (a throttle, a full round of quick answers at the share). A
        throttle anywhere in the run is every worker's pause. $true when the run's budget answered (the static share is
        then not read); $false when there is none or it cannot be read (Update-RAPartsShare goes on as before).
    #>
    param([switch]$Force, [int]$EverySeconds = 0, [datetime]$Now = [datetime]::UtcNow)
    $p = $script:RAParts
    if ($null -eq $p -or -not $p.On -or $null -eq $script:RAPartsBudgetProbe) { return $false }
    if ($EverySeconds -le 0) { $EverySeconds = 60; $s = 0; if ([int]::TryParse(([string]$global:SI_RA_PartsBudgetSeconds).Trim(), [ref]$s) -and $s -gt 0) { $EverySeconds = $s } }
    if (-not $Force -and -not $p.RunEvent -and ($Now - [datetime]$p.RunCheckedAt).TotalSeconds -lt $EverySeconds) { return [bool]$p.Claimed }
    $ev = if ($p.RunEvent) { [string]$p.RunEvent } else { 'read' }
    $r = $null
    try { $r = & $script:RAPartsBudgetProbe $ev ([long]$p.Remaining) ([int]$p.RunRetryAfter) } catch { $r = $null }
    $p.RunCheckedAt = $Now
    if ($null -eq $r -or -not ($r -is [System.Collections.IDictionary])) { return $false }
    $p.RunEvent = ''; $p.RunRetryAfter = 0; $p.Claimed = $true
    $new = [Math]::Max(1, [int]$r['Share'])
    $pu = ConvertTo-RAPartsUtc $r['PauseUntilUtc']
    if ($pu -gt $p.PauseUntil) { $p.PauseUntil = $pu }
    if ($new -ne [int]$p.Max) {
        $what = if ($new -eq 1) { '1 part at a time' } else { '{0} parts at a time' -f $new }
        if ($new -gt [int]$p.Max) {
            Write-Info ('the run''s measured budget gives this report up to {0} (Defender answers without throttling, and the other reports of the run need less)' -f $what)
            if ([int]$p.N -lt [Math]::Min(2, $new)) { $p.N = [Math]::Min(2, $new); $p.Clean = 0 }
        } else {
            Write-Info ('the run''s measured budget gives this report up to {0} (shared with the other reports still running, or Defender asked the run to slow down)' -f $what)
        }
        $p.Max = $new
        if ([int]$p.N -gt $new) { $p.N = $new }
    }
    $true
}

# =====================================================================================================================
#  A SMALL SLICE MERGES WITH ITS UNTOUCHED PARTNER (2026-11-23). See the header: slice b of N and its partners
#  b + j*N/D are exactly slice b of N/D; merged only while the answers stay small, only partners nothing has touched,
#  and a merged request that fails in any way is asked again as its own slice (its partners in their own turn).
# =====================================================================================================================
$script:RASliceMerge = $null

function Test-RASliceMergeWanted {
    <# PURE over the setting. SI_RA_SliceMerge: off / false / 0 / no = every slice asked on its own; else on (the default). #>
    param($Setting = $global:SI_RA_SliceMerge)
    $s = if ($null -ne $Setting) { ([string]$Setting).Trim().ToLowerInvariant() } else { '' }
    -not ($s -in 'off', 'false', '0', 'no', 'disabled', 'disable')
}

function New-RASliceMerge {
    <#
        PURE. The merge plan of ONE pass over a report's slices: -Count slices (N), THIS process runs [-From, -To). Merging
        is possible only when N is even (a partner b + N/2 exists) and -On. -RowLimit / -SecondsLimit: the rows a slice is
        planned for and the documented time limit of one request -- an answer is small when a doubled request stays under half
        the planned rows and the answer under a quarter of the time limit (Complete-RASliceRequest).
    #>
    param([Parameter(Mandatory)][int]$Count, [int]$From = 0, [int]$To = -1, [double]$RowLimit = 30000, [double]$SecondsLimit = 180, [bool]$On = $true)
    if ($To -lt 0 -or $To -gt $Count) { $To = $Count }
    if ($From -lt 0) { $From = 0 }
    @{ On = ([bool]$On -and $Count -ge 2 -and ($Count % 2) -eq 0 -and ($To - $From) -ge 2); N = $Count; From = $From; To = $To; D = 1
       RowLimit = [double]$RowLimit; SecondsLimit = [double]$SecondsLimit
       Decided = @{}; TakenBy = @{}; Done = (New-Object 'System.Collections.Generic.HashSet[int]'); Requests = 0; Merged = 0; Saved = 0; Stopped = '' }
}

function Get-RASliceRequest {
    <#
        PURE (on the plan). The request that asks slice -Slice: @{ Count; Index; Covers; Slice }. Decided ONCE per slice (the
        slice's own turn and a request asked ahead for it are the same request). With merging on at width D (1, 2, 4, ...):
        slice b is asked as slice b of N/D when b < N/D and EVERY partner b + j*N/D (j = 1 .. D-1) is inside [From, To) and
        untouched (no request decided for it, not taken by another, not done); else the widest smaller width that fits;
        else the slice alone (Count N, no partner). A partner taken here is not asked again in its own turn once the
        request is in (Complete-RASliceRequest) -- unless the request fails (Stop-RASliceMerge gives it back).
    #>
    param($Merge, [Parameter(Mandatory)][int]$Slice)
    $m = $Merge
    if ($null -eq $m) { return @{ Count = 0; Index = $Slice; Covers = @(); Slice = $Slice } }
    if ($m.Decided.ContainsKey($Slice)) { return $m.Decided[$Slice] }
    $req = @{ Count = [int]$m.N; Index = $Slice; Covers = @(); Slice = $Slice }
    if ($m.On -and -not $m.TakenBy.ContainsKey($Slice) -and -not $m.Done.Contains($Slice)) {
        $d = [int]$m.D
        while ($d -gt 1) {
            if (([int]$m.N % $d) -eq 0) {
                $c = [int]([int]$m.N / $d)
                if ($Slice -lt $c) {
                    $covers = New-Object System.Collections.Generic.List[int]; $ok = $true
                    for ($j = 1; $j -lt $d; $j++) {
                        $k = $Slice + ($j * $c)
                        if ($k -lt [int]$m.From -or $k -ge [int]$m.To -or $m.Decided.ContainsKey($k) -or $m.TakenBy.ContainsKey($k) -or $m.Done.Contains($k)) { $ok = $false; break }
                        $covers.Add($k)
                    }
                    if ($ok) { $req = @{ Count = $c; Index = $Slice; Covers = $covers.ToArray(); Slice = $Slice }; break }
                }
            }
            $d = [int]($d / 2)
        }
    }
    foreach ($k in @($req.Covers)) { $m.TakenBy[[int]$k] = $Slice }
    $m.Decided[$Slice] = $req
    $req
}

function Test-RASliceTaken {
    <# PURE. Slice -Slice is part of another slice's request (decided, maybe not answered yet): it is not asked ahead. #>
    param($Merge, [Parameter(Mandatory)][int]$Slice)
    if ($null -eq $Merge) { return $false }
    $Merge.TakenBy.ContainsKey($Slice)
}

function Test-RASliceCovered {
    <# PURE. Slice -Slice is IN: its rows came with another slice's request, which is complete (Complete-RASliceRequest).
       Its own turn asks nothing. #>
    param($Merge, [Parameter(Mandatory)][int]$Slice)
    if ($null -eq $Merge) { return $false }
    $Merge.TakenBy.ContainsKey($Slice) -and $Merge.Done.Contains($Slice)
}

function Complete-RASliceRequest {
    <#
        PURE (on the plan). Slice -Slice's request is IN (its rows stored, or none to store): the slice and every partner of
        the request are done. Then the width adapts to what was measured: per slice (-Rows / the slices the request
        held), a doubled width still under HALF the planned rows and an answer under a quarter of the time limit = twice
        as wide for the next slices; an answer over half the planned rows or half the time limit = half as wide. Returns
        the width now.
    #>
    param($Merge, [Parameter(Mandatory)][int]$Slice, [long]$Rows = 0, [double]$Seconds = 0)
    $m = $Merge
    if ($null -eq $m) { return 1 }
    $req = if ($m.Decided.ContainsKey($Slice)) { $m.Decided[$Slice] } else { @{ Covers = @() } }
    [void]$m.Done.Add($Slice)
    foreach ($k in @($req.Covers)) { [void]$m.Done.Add([int]$k) }
    $m.Requests++
    $w = 1 + @($req.Covers).Count
    if ($w -gt 1) { $m.Merged++; $m.Saved += ($w - 1) }
    if (-not $m.On) { return [int]$m.D }
    $per = [double]$Rows / [double]$w
    $lim = [double]$m.RowLimit; $sec = [double]$m.SecondsLimit
    if ($lim -le 0) { $lim = 30000 }
    if ($sec -le 0) { $sec = 180 }
    if ([double]$Rows -gt ($lim / 2) -or $Seconds -gt ($sec / 2)) { $m.D = [Math]::Max(1, [int]([int]$m.D / 2)) }
    elseif (($per * 2 * [double]$m.D) -le ($lim / 2) -and $Seconds -le ($sec / 4) -and ([int]$m.N % (2 * [int]$m.D)) -eq 0 -and (2 * [int]$m.D) -le [int]$m.N) { $m.D = 2 * [int]$m.D }
    [int]$m.D
}

function Stop-RASliceMerge {
    <#
        PURE (on the plan). A merged request failed (or the report ran out of memory): merging stops for the rest of this
        report. Every merged request that is not in yet gives its partners back -- each is asked in its own turn, as its own
        slice -- and the decision for -Slice (when given) is dropped, so it is asked again as its own slice. Returns the
        request that now asks -Slice (alone), or $null without -Slice.
    #>
    param($Merge, [int]$Slice = -1, [string]$Why = '')
    $m = $Merge
    if ($null -eq $m) { return $null }
    $m.On = $false
    if ($Why -and -not $m.Stopped) { $m.Stopped = $Why }
    foreach ($k in @($m.Decided.Keys)) {
        $r = $m.Decided[$k]
        if ($m.Done.Contains([int]$k)) { continue }
        if (@($r.Covers).Count -gt 0 -or [int]$k -eq $Slice) {
            foreach ($c in @($r.Covers)) { if ($m.TakenBy.ContainsKey([int]$c) -and -not $m.Done.Contains([int]$c)) { $m.TakenBy.Remove([int]$c) } }
            $m.Decided.Remove($k)
        }
    }
    if ($Slice -lt 0) { return $null }
    Get-RASliceRequest -Merge $m -Slice $Slice
}

function Format-RASliceMergeLine {
    <# PURE. What merging did in one pass over a report's slices, in plain words; '' when nothing was merged. #>
    param($Merge)
    if ($null -eq $Merge -or [int]$Merge.Merged -le 0) { return '' }
    $t = '{0} small part(s) of this report were asked together with their untouched partners: {1} request(s) fewer to Defender, the same rows' -f [int]$Merge.Merged, [int]$Merge.Saved
    if ($Merge.Stopped) { $t += ('; then every part was asked on its own again ({0})' -f $Merge.Stopped) }
    $t
}

function Split-RASliceRows {
    <#
        PURE (over Get-SISha256Bucket, the engine's own copy of the slice hash). The rows of a MERGED answer (slice -Slice
        of -Count with its partners -Covers, asked as one coarser slice), each put in the slice it belongs to: the slice
        key the filter hashed is read back from the row -- the first of -KeyColumns the row carries whose hash falls in the
        request's slices (the filter's own key leads: DeviceKey; the CVE reports carry it as MdeDeviceId, or as the asset id
        of an asset without a Defender id). @{ Own = rows of -Slice; Held = @{ partner = rows }; Unplaced = rows no column
        places (kept in Own -- never dropped) }. The order of the rows inside each slice is the answer's own.
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @(), [Parameter(Mandatory)][int]$Count, [Parameter(Mandatory)][int]$Slice, [int[]]$Covers = @(),
          [string[]]$KeyColumns = @('DeviceKey', 'MdeDeviceId', 'AssetId', 'NodeId', 'DeviceNodeId', 'AadDeviceId', 'DeviceId', 'MachineId', 'Id', 'SourceNodeId', 'TargetNodeId'))
    $set = New-Object 'System.Collections.Generic.HashSet[int]'
    [void]$set.Add($Slice); foreach ($c in @($Covers)) { [void]$set.Add([int]$c) }
    $own = New-Object System.Collections.Generic.List[object]
    $held = @{}; foreach ($c in @($Covers)) { $held[[int]$c] = New-Object System.Collections.Generic.List[object] }
    $memo = New-Object 'System.Collections.Generic.Dictionary[string,int]'
    $unplaced = 0
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        $at = -1
        # (a plain assignment: an if-expression would enumerate the property collection into an array)
        $props = $null
        if (-not ($r -is [System.Collections.IDictionary])) { $props = $r.PSObject.Properties }
        foreach ($col in $KeyColumns) {
            $v = $null
            if ($null -eq $props) { if ($r.Contains($col)) { $v = $r[$col] } } else { $pp = $props[$col]; if ($pp) { $v = $pp.Value } }
            $s = if ($null -eq $v) { '' } else { [string]$v }
            if ($s -eq '') { continue }
            $h = 0
            if (-not $memo.TryGetValue($s, [ref]$h)) { $h = [int](Get-SISha256Bucket -Key $s -BucketCount $Count); $memo[$s] = $h }
            if ($set.Contains($h)) { $at = $h; break }
        }
        if ($at -lt 0) { $unplaced++; $own.Add($r) }
        elseif ($at -eq $Slice) { $own.Add($r) }
        else { $held[$at].Add($r) }
    }
    $out = @{}; foreach ($k in @($held.Keys)) { $out[[int]$k] = $held[$k].ToArray() }
    @{ Own = $own.ToArray(); Held = $out; Unplaced = $unplaced }
}