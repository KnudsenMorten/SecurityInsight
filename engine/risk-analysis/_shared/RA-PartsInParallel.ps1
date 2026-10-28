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
    at a time, up to SI_RA_PartsInParallel_Max (default 6; never more than 4 per processor core). A 429 / 503 / 504
    halves it at once and no part is asked ahead until the service's Retry-After has passed (30 s when it gave none).
    An answer that was already there when its part's turn came adds nothing: then the engine is the slower half, and
    more requests at a time would not make the report faster. SI_RA_PartsInParallel_Max = 1: one part at a time.

    ON QUEUE WORKERS (#742): the Detailed reports run on up to SI_RA_WORKERS workers at once, each its own report. The
    setting is what ONE job may ask at a time, so the workers SHARE it: each gets floor(Max / workers), at least 1
    (Get-RAPartsInParallelShare) -- together never more at a time than one job, and each still halves on throttling.
#>

$script:RAParts = $null

function Get-RAPartsInParallelMax {
    <# PURE over the setting. The most parts of a report asked at a time: SI_RA_PartsInParallel_Max (default 6); 1 / 0 /
       off = one part at a time. Never more than 4 per processor core (the answers are read and converted on this
       process's own thread; more requests than that only wait longer for it). #>
    param($Setting = $global:SI_RA_PartsInParallel_Max, [int]$Cores = [Environment]::ProcessorCount, [int]$Default = 6)
    $bound = [Math]::Max(2, 4 * [Math]::Max(1, $Cores))
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
    if ($null -eq $script:RAPartsOpenProbe) { return $false }
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
                         Started = (New-Object 'System.Collections.Generic.HashSet[int]'); Ahead = 0; Used = 0; Missed = 0; Throttled = 0; Said = $false }
    if ($on) { $script:SIHuntingPrefetch = New-SIHuntingPrefetchStore }
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
        }
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
    if ($null -eq $p -or -not $p.On -or $null -eq $script:RAPartsOpenProbe) { return }
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
    Update-RAPartsShare
    # the part just answered: was it asked ahead and its answer NOT used (its request came out different)? dropped, counted
    foreach ($e in @($st.Entries.Values | Where-Object { [int]$_.Part -le $After })) { $null = Remove-SIHuntingPrefetch -Store $st -Key $e.Key; $p.Missed++ }
    if ([int]$p.Missed -ge 3) {
        Write-Info 'the parts asked ahead came out different from the parts'' own requests -- this report goes on one part at a time'
        $p.On = $false; $null = Remove-SIHuntingPrefetch -Store $st; return
    }
    Update-RAPartsInParallel
    if (-not $p.Said) { Write-Info (Format-RAPartsLine -N $p.N); $p.Said = $true }
    if ([datetime]::UtcNow -lt $p.PauseUntil) { return }
    for ($k = $After + 1; $k -lt $End -and $st.Entries.Count -lt ($p.N - 1); $k++) {
        if (-not $p.Started.Add($k)) { continue }
        $r = if ($AskAhead) { & $AskAhead $k } else { Invoke-RAPartAhead -Part $k -PartCount $PartCount -Query $Query -ReportName $ReportName }
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
