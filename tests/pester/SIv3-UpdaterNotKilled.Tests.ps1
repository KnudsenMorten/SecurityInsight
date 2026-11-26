#Requires -Version 5.1
<#
    SecurityInsight -- #1406 AN UPDATE IS NEVER STOPPED HALF-WAY (live 2026-11-26, a large install): the updater rolled all 28
    engine jobs to 3.1.51, then step 9i KEY FIGURES ran one long statement ("SQL statement running 5 min (its sign of life could
    not be written this time ...)" at 5 / 10 / 15 min); the pipeline flow tick said "an update of SecurityInsight showed no sign
    of life and was stopped: ... last reported that it was working at 05:44Z, 17 minutes ago", stopped it, took over the
    pipeline lock and started the data sync -- jobs on 3.1.51, the record (si-installed) on 3.1.43.5, the steps after 9i and
    the record never ran.

    What must hold:
      (1) a long statement keeps the sign of life: the beat writes every minute (not every 5), a failed beat is tried again at
          once on a NEW connection, and a failed beat says WHY in its line;
      (a) THE RUN'S BEAT: from the release script's first step a beat of its own (thread + connection) beats while the update
          works -- a statement runs or a step said a line in the last 14 minutes -- and only the heartbeat (never the What);
      (2) the pipeline never stops an update that has reported that it works while Azure still runs it: a stale beat is QUIET
          (waited for, one warning) until the 6 h fallback; a runner (flow) is judged as before;
      (4) the key figures read the finding lifecycle once (three passes became one);
      (5) jobs on a version the record does not reach = an update stopped part-way: the next update FINISHES it (the steps
          after the roll and the record), never "the jobs run it already".
    Offline: the beat's interval is a seam (fractions of a second), every SQL / ARM call a seam.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\_shared\SI-ExecutionLiveness.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-JobFlow.ps1')
    . (Join-Path $script:SIRoot 'setup\_shared\SI-UpdateSqlBeat.ps1')
    . (Join-Path $script:SIRoot 'container\updater\_shared\SI-UpdaterCore.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-TelemetrySend.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-ReleaseControl.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-InvardiaUpdate.ps1')
    . (Join-Path $script:SIRoot 'container\updater\_shared\SI-UpdaterInvardia.ps1')
    $script:Update = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'setup\Invoke-SIContainerUpdate.ps1'))
    $script:Now = [datetime]::SpecifyKind([datetime]'2026-11-26T06:00:54', 'Utc')
    function script:Exec([string]$Name, [int]$StartedMinAgo, [string]$Status = 'Running') {
        [pscustomobject]@{ name = $Name; properties = [pscustomobject]@{ status = $Status; startTime = $script:Now.AddMinutes(-$StartedMinAgo).ToString('yyyy-MM-ddTHH:mm:ssZ') } }
    }
    function script:Lock([string]$LockName, [string]$Holder, [int]$BeatMinAgo) {
        [pscustomobject]@{ LockName = $LockName; Holder = $Holder; HeartbeatUtc = $script:Now.AddMinutes(-$BeatMinAgo) }
    }
    function script:Invoke-Blocked([int]$Ms) { [System.Threading.Thread]::Sleep($Ms) }
    # a beat (TEXT, compiled in the beat's runspace) whose FIRST try of every second beat fails -- the try again on a new
    # connection writes it; every call recorded
    $script:FlakyBeat = @'
param($Target, $State, [string]$What)
[void]$Target.Calls.Add($What)
if ($Target.Calls.Count % 2 -eq 1) { throw 'Lock request time out period exceeded.' }
$true
'@
    $script:OkBeat = @'
param($Target, $State, [string]$What)
[void]$Target.Calls.Add([pscustomobject]@{ What = $What; Utc = [datetime]::UtcNow; Statement = [string]$Target.Statement })
$true
'@
    $script:ReleasedBeat = @'
param($Target, $State, [string]$What)
[void]$Target.Calls.Add($What)
$false
'@
    function script:New-Target { [pscustomobject]@{ Calls = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList)); Rows = @([pscustomobject]@{ LockId = 'updater'; Holder = 'caj-si-updater:caj-si-updater-w36754v' }) } }
}
AfterAll { $global:SI_UpdateRunBeat = $null; $global:SI_UpdaterExecBeat = $null; $global:SI_UpdaterLockBeat = $null }

Describe '(1)(3) a long statement keeps its sign of life' {
    It 'a beat that fails is tried again at once on a new connection -- the row is written every time, nothing is said as failed' {
        $t = New-Target; $log = New-Object IO.StringWriter
        Invoke-SIUpdateSqlBeat -What '9i. KEY FIGURES' -Target $t -IntervalSeconds 0.25 -Log $log -BeatScript $script:FlakyBeat -Action { Invoke-Blocked 1200 }
        $rec = $script:SIUpdateSqlBeatLast
        $rec.Beats | Should -BeGreaterOrEqual 3
        $rec.Failed | Should -Be 0 -Because 'the first try failed, the try again on a new connection wrote it'
        $log.ToString() | Should -Not -Match 'could not be written'
        $t.Calls.Count | Should -Be (2 * $rec.Beats)
    }
    It 'a beat that fails says WHY in its line (the live line never did)' {
        $t = New-Target; $t | Add-Member -NotePropertyName Fail -NotePropertyValue $true
        $fail = "param(`$Target, `$State, [string]`$What)`n[void]`$Target.Calls.Add(`$What)`nthrow 'Login failed for user ''<token-identified principal>''.'"
        $log = New-Object IO.StringWriter
        Invoke-SIUpdateSqlBeat -What '9i. KEY FIGURES' -Target $t -IntervalSeconds 0.25 -Log $log -BeatScript $fail -Action { Invoke-Blocked 700 }
        $log.ToString() | Should -Match "9i\. KEY FIGURES: SQL statement running 0 min \(its sign of life could not be written this time: Login failed for user '<token-identified principal>'\.; the next beat tries again in 0 s\)"
    }
    It 'the row is beaten every BeatSeconds (60 s by default), the line said every IntervalSeconds (5 min) -- beats outnumber lines' {
        $t = New-Target; $log = New-Object IO.StringWriter
        $sb = Start-SIUpdateSqlBeat -What '9i. KEY FIGURES' -Target $t -IntervalSeconds 0.9 -BeatSeconds 0.15 -Log $log -BeatScript $script:OkBeat
        Invoke-Blocked 1900
        $rec = Stop-SIUpdateSqlBeat -Beat $sb
        $lines = @($log.ToString() -split "`r?`n" | Where-Object { $_.Trim() })
        $rec.Beats | Should -BeGreaterOrEqual 8
        $lines.Count | Should -BeLessOrEqual 3
        $lines.Count | Should -BeGreaterOrEqual 1
    }
    It 'rows no longer held by the update end the beat (one line), never a line a minute' {
        $t = New-Target; $log = New-Object IO.StringWriter
        Invoke-SIUpdateSqlBeat -What '9i. KEY FIGURES' -Target $t -IntervalSeconds 0.2 -Log $log -BeatScript $script:ReleasedBeat -Action { Invoke-Blocked 900 }
        $t.Calls.Count | Should -Be 1
        $script:SIUpdateSqlBeatLast.Released | Should -BeTrue
        @($log.ToString() -split "`r?`n" | Where-Object { $_.Trim() }).Count | Should -Be 1
    }
}

Describe '(review) a take-over is never read as "let go"; nothing is beaten after the end mark' {
    It 'another execution holds the only row: a failed beat, said with why, and the beat goes on (never ended as released)' {
        $t = New-Target; $log = New-Object IO.StringWriter
        $lost = "param(`$Target, `$State, [string]`$What)`n[void]`$Target.Calls.Add(`$What)`n`$State.Lost = @('updater')`n`$false"
        Invoke-SIUpdateSqlBeat -What '9i. KEY FIGURES' -Target $t -IntervalSeconds 0.2 -Log $log -BeatScript $lost -Action { Invoke-Blocked 900 }
        $script:SIUpdateSqlBeatLast.Released | Should -Not -BeTrue
        $t.Calls.Count | Should -BeGreaterOrEqual 3
        $log.ToString() | Should -Match 'could not be written this time: another execution holds the lock row\(s\) updater now'
    }
    It 'its end mark is written: the beat ends at once and writes nothing more' {
        $t = New-Target; $log = New-Object IO.StringWriter
        $end = "param(`$Target, `$State, [string]`$What)`n[void]`$Target.Calls.Add(`$What)`n`$State.Ended = `$true`n`$false"
        $rb = Start-SIUpdateRunBeat -Target $t -BeatSeconds 0.1 -QuietSeconds 5 -Log $log -BeatScript $end
        Invoke-Blocked 600
        $t.Calls.Count | Should -Be 1
        $rec = Stop-SIUpdateRunBeat; $rec.EndMark | Should -BeTrue
        $log.ToString().Trim() | Should -BeNullOrEmpty
    }
    It 'the statements answer per row: beaten 1, let go 0, end mark -1, held by another -2 -- the end mark is checked first' {
        foreach ($s in $script:SIUpdateSqlBeatStatement, $script:SIUpdateRunBeatStatement) {
            $s.IndexOf("LockId = N'updater-ended' AND Holder = @Holder") | Should -BeLessThan $s.IndexOf('UPDATE cfg.PipelineLock')
            $s | Should -Match ([regex]::Escape('SELECT -2 AS Held'))
        }
    }
    It 'a row another RUNNING execution holds is never taken (the run beat''s row and the updater''s own row)' {
        $rows = @(@{ LockId = 'updater-run'; Holder = 'caj-si-updater:quiet-1'; HeartbeatUtc = [datetime]::UtcNow.AddMinutes(-40) })
        $store = New-SIExecutionLockStore -Invoke { param($q, $p, $m) if ($q -match 'SELECT LockId, Holder, HeartbeatUtc') { return , @($rows) }; if ($q -match 'AS Mine') { return , @(@{ Mine = 1 }) }; $null }
        $global:SI_UpdaterExecBeat = [pscustomobject]@{ Store = $store; Holder = 'caj-si-updater:me'; Beat = $null; Busy = @('quiet-1') }
        try {
            Test-SIUpdateRowFreeOfRunning -Store $store -Lock 'updater-run' -Holder 'caj-si-updater:me' | Should -BeFalse
            Enter-SIUpdateRunBeatRow -Holder 'caj-si-updater:me' | Should -BeFalse
            $global:SI_UpdaterExecBeat.Busy = @()
            Enter-SIUpdateRunBeatRow -Holder 'caj-si-updater:me' | Should -BeTrue -Because 'not running any more: the lock rule only'
        } finally { $global:SI_UpdaterExecBeat = $null }
        $rg = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\updater\_shared\SI-UpdaterRunGate.ps1'))
        $rg | Should -Match ([regex]::Escape("elseif (-not (Test-SIUpdaterRowFreeOfRunning -Store `$lockStore -Lock 'updater' -Holder `$Holder)) { `$false }"))
        $rg | Should -Match ([regex]::Escape("if ((Test-SIUpdaterRowFreeOfRunning -Store `$x.Store -Lock 'updater' -Holder `$x.Holder) -and (Enter-SIExecutionLock"))
        $up = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\updater\Start-SIUpdater.ps1'))
        $up | Should -Match ([regex]::Escape('-Holder (Get-SIUpdaterRunGateHolder -Env $Env) -Busy $busyNames'))
    }
    It 'the first update to this release (an older updater that never ends the run beat): the release script ends it at the end of its steps' {
        # (before the last step: the templates' answer stays the update's answer; an older updater's end mark and its process
        # end stop any beat after that anyway -- every beat checks the end mark first)
        $script:Update | Should -Match ([regex]::Escape('$null = Invoke-SIUpdateDisplayNames; if ($global:SI_UpdateRunBeat) { Stop-SIUpdateRunBeatAtEnd }; Install-SIUpdateDefaultTemplates }'))
        (Get-Command Stop-SIUpdateRunBeatAtEnd).Definition | Should -Match ([regex]::Escape("-match 'SI_UpdateRunBeat'"))
    }
}

Describe '(a) the run''s beat: from the first step, its own thread and connection, only while the update works' {
    AfterEach { $null = Stop-SIUpdateRunBeat }
    It 'beats while steps report; writes the heartbeat only (never the What the web app reads)' {
        $t = New-Target; $log = New-Object IO.StringWriter
        $rb = Start-SIUpdateRunBeat -Target $t -BeatSeconds 0.1 -QuietSeconds 5 -Log $log -BeatScript $script:OkBeat
        $rb | Should -Not -BeNullOrEmpty
        (Start-SIUpdateRunBeat -Target (New-Target) -BeatSeconds 0.1 -BeatScript $script:OkBeat) | Should -Be $rb -Because 'one per process'
        Invoke-Blocked 600
        $t.Calls.Count | Should -BeGreaterOrEqual 3
        @($t.Calls)[0].Statement | Should -Be $script:SIUpdateRunBeatStatement
        $script:SIUpdateRunBeatStatement | Should -Match 'SET HeartbeatUtc = SYSUTCDATETIME\(\) WHERE LockId = @LockId AND Holder = @Holder;'
        $script:SIUpdateRunBeatStatement | Should -Not -Match 'What ='
        $log.ToString().Trim() | Should -BeNullOrEmpty -Because 'the run''s beat speaks only when a beat fails'
    }
    It 'a long statement (no line for longer than the quiet time) is beaten on; a hang outside one stops being beaten' {
        $t = New-Target; $log = New-Object IO.StringWriter
        $rb = Start-SIUpdateRunBeat -Target $t -BeatSeconds 0.1 -QuietSeconds 0.3 -Log $log -BeatScript $script:OkBeat
        # inside a statement: Progress.Sql > 0 -- beaten although no step says a line
        Invoke-SIUpdateSqlBeat -What '9i. KEY FIGURES' -Target (New-Target) -IntervalSeconds 5 -BeatScript $script:OkBeat -Action { Invoke-Blocked 900 }
        $during = $t.Calls.Count
        $during | Should -BeGreaterOrEqual 5
        # outside: no line, no statement -- past the quiet time nothing is beaten (the rule judges a hang, as before)
        Invoke-Blocked 1000
        $n = $t.Calls.Count
        Invoke-Blocked 600
        $t.Calls.Count | Should -Be $n
        $log.ToString() | Should -Match 'no step has reported for 0 min'
        # a line comes again: beaten again
        Set-SIUpdateRunBeatProgress
        Invoke-Blocked 300
        $t.Calls.Count | Should -BeGreaterThan $n
    }
    It 'the updater ends it before its end mark, from the record alone (the release script''s functions may be gone)' {
        $t = New-Target
        $rb = Start-SIUpdateRunBeat -Target $t -BeatSeconds 0.1 -QuietSeconds 5 -BeatScript $script:OkBeat
        $rg = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\updater\_shared\SI-UpdaterRunGate.ps1'))
        $fn = [regex]::Match($rg, '(?s)function Unregister-SIUpdaterExecutionBeat \{.*?\n\}').Value
        $fn.IndexOf('$rb.Stop.Set()') | Should -BeLessThan $fn.LastIndexOf('Set-SIExecutionLockEnded -Store')
        $fn.IndexOf('$rb.Stop.Set()') | Should -BeGreaterThan 0
        [void]$rb.Stop.Set(); $rb.Async.AsyncWaitHandle.WaitOne(5000) | Should -BeTrue
        $n = $t.Calls.Count; Invoke-Blocked 400; $t.Calls.Count | Should -Be $n
        $global:SI_UpdateRunBeat = $null
    }
    It 'the release script starts it at its top and every Step / Info / Warn line keeps it going' {
        $script:Update | Should -Match ([regex]::Escape("if (Get-Command -Name Start-SIUpdateRunBeat -ErrorAction SilentlyContinue) { `$null = Start-SIUpdateRunBeat }"))
        $script:Update.IndexOf('$null = Start-SIUpdateRunBeat') | Should -BeLessThan $script:Update.IndexOf("Step '1. DETECT'")
        foreach ($f in 'Step', 'Info', 'Warn') {
            $a = $script:Update.IndexOf("function $f([string]`$m)"); $a | Should -BeGreaterThan 0
            $b = $script:Update.IndexOf("`nfunction ", $a + 10)
            $script:Update.Substring($a, $b - $a) | Should -Match 'Set-SIUpdateRunBeatProgress'
        }
    }
    It 'outside the updater (no row registered) nothing starts' {
        $global:SI_UpdaterExecBeat = $null; $global:SI_UpdaterLockBeat = $null
        Start-SIUpdateRunBeat | Should -BeNullOrEmpty
    }
}

Describe '(2) the pipeline never stops an update that works while Azure runs it' {
    It 'THE LIVE CASE: the update beat 17 minutes ago and Azure runs it -- it holds the pipeline (no stop, no lock take-over), one warning' {
        $ex = @((Exec 'caj-si-updater-w36754v' 25))
        # (it held the install lock: "took over the pipeline lock ... heartbeat older than 15 minutes")
        $u = Get-SIPipelineUpdateLiveness -Executions $ex -Locks @((Lock 'updater' 'caj-si-updater:caj-si-updater-w36754v' 17), (Lock 'install' 'caj-si-updater:caj-si-updater-w36754v' 17)) -LocksKnown $true -NowUtc $script:Now
        $u.Running | Should -Match '^caj-si-updater execution caj-si-updater-w36754v' -Because 'the pipeline then ends its wake-up: Busy, before it takes the lock'
        @($u.Dead).Count | Should -Be 0
        @($u.Quiet).Count | Should -Be 1
        $said = @{}; $lines = New-Object System.Collections.Generic.List[object]
        Write-SIExecutionQuietOnce -Live @($u.Quiet) -Log { param($l, $m) $lines.Add([pscustomobject]@{ L = $l; M = $m }) } -Said $said
        Write-SIExecutionQuietOnce -Live @($u.Quiet) -Log { param($l, $m) $lines.Add([pscustomobject]@{ L = $l; M = $m }) } -Said $said
        $lines.Count | Should -Be 1 -Because 'said once'
        $lines[0].L | Should -Be 'WARN'
        $lines[0].M | Should -Match '^an update of SecurityInsight has not reported for 17 minutes but Azure still runs it: caj-si-updater-w36754v \(started 2026-11-26 05:35Z\) last reported that it was working at 2026-11-26 05:43Z, 17 minutes ago -- it is not stopped'
    }
    It 'an update that has ENDED at Azure frees the pipeline (nothing to wait for); past 6 h a quiet one is stopped as before' {
        (Get-SIPipelineUpdateLiveness -Executions @((Exec 'u-ended' 25 'Failed')) -Locks @(Lock 'updater' 'caj-si-updater:u-ended' 17) -LocksKnown $true -NowUtc $script:Now).Running | Should -Be ''
        $o = Get-SIPipelineUpdateLiveness -Executions @((Exec 'u-old' 400)) -Locks @(Lock 'updater' 'caj-si-updater:u-old' 17) -LocksKnown $true -NowUtc $script:Now
        $o.Running | Should -Be ''; @($o.Dead).Name | Should -Be 'u-old'
    }
    It 'an update that never beat (never ran SecurityInsight''s code -- nothing half done) is dead after 30 minutes, as before; a stale flow runner is dead as before' {
        @((Get-SIPipelineUpdateLiveness -Executions @((Exec 'u-never' 45)) -Locks @() -LocksKnown $true -NowUtc $script:Now).Dead).Name | Should -Be 'u-never'
        (Get-SIExecutionLiveness -Execution (Exec 'caj-si-flow-x' 60) -Kind flow -Locks @(Lock 'install' 'caj-si-flow-x' 17) -NowUtc $script:Now).Alive | Should -BeFalse
    }
    It '(review) an idle hourly run that only signed in and hangs is freed at 15 / 30 minutes as before; the run beat''s row makes it quiet' {
        $idle = Get-SIPipelineUpdateLiveness -Executions @((Exec 'u-idle' 40)) -Locks @(Lock 'updater' 'caj-si-updater:u-idle' 16) -LocksKnown $true -NowUtc $script:Now
        $idle.Running | Should -Be ''; @($idle.Dead).Name | Should -Be 'u-idle'
        $chg = Get-SIPipelineUpdateLiveness -Executions @((Exec 'u-chg' 40)) -Locks @((Lock 'updater' 'caj-si-updater:u-chg' 16), (Lock 'updater-run' 'caj-si-updater:u-chg' 16)) -LocksKnown $true -NowUtc $script:Now
        @($chg.Quiet).Name | Should -Be 'u-chg'; @($chg.Dead).Count | Should -Be 0
        (Get-SIExecutionLivenessContract).UpdaterRunLock | Should -Be 'updater-run'
    }
    It 'the flow tick says the quiet update once and waits' {
        $c = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\flow\Invoke-SIJobFlowRun.ps1'))
        $c | Should -Match ([regex]::Escape('if (@($upd.Quiet).Count) { Write-SIExecutionQuietOnce -Live @($upd.Quiet) -Log $say -Said $global:SI_ExecutionQuietSaid }'))
        $c.IndexOf('Write-SIExecutionQuietOnce') | Should -BeLessThan $c.IndexOf('$updStop = Invoke-SIExecutionDeadStop')
    }
}

Describe '(5) an update stopped part-way is finished by the next update' {
    BeforeAll { $script:M = [pscustomobject]@{ Action = 'update'; Version = '3.1.51'; Sequence = 51; Reason = 'ring 1 names 3.1.51'; Manifest = [pscustomobject]@{} } }
    It 'jobs on 3.1.51, the record on 3.1.43.5: the update is FINISHED (rolled again, the steps after the roll, the record) -- never "runs it already"' {
        $d = Get-SIUpdaterInvardiaCodeDecision -Result $script:M -Deployed '3.1.51' -AppliedSequence 50 -Recorded '3.1.43.5'
        $d.Act | Should -BeTrue; $d.Applied | Should -BeFalse; $d.Resume | Should -BeTrue
        $d.Reason | Should -Match '^the jobs run 3\.1\.51 but the update to it did not finish \(the install records 3\.1\.43\.5 as installed\) -- the update is finished now'
    }
    It '(review) at most once per sequence: an applied sequence whose record lags is NOT rolled again -- it is said as a problem' {
        $d = Get-SIUpdaterInvardiaCodeDecision -Result $script:M -Deployed '3.1.51' -AppliedSequence 51 -Recorded '3.1.43.5'
        $d.Act | Should -BeFalse; $d.Applied | Should -BeTrue; $d.RecordLags | Should -BeTrue
        $d.Reason | Should -Match 'the record could not be written -- it is not rolled again'
        $inv = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\updater\_shared\SI-UpdaterInvardia.ps1'))
        # (final review) the record is NEVER re-written there (the web app may still be old): the failure 'record' every run
        $inv | Should -Not -Match ([regex]::Escape("`$s['SaveRecord']"))
        $inv | Should -Match ([regex]::Escape("Write-UpdLog ('WARNING: code: ' + `$dec.Reason); `$state.lastError = `"code: `$(`$dec.Reason)`"; & `$fail 'record' ([string]`$dec.Reason)"))
        # (the behaviour: SIv3-UpdaterPostRollRun, 'a web app roll that failed ... the next run does NOT write the record')
        (New-SIInvardiaKindState).Contains('resumeTries') | Should -BeTrue
    }
    It '(round 2) a resume is counted only where the update really starts (after the run gate, before the roll); a try that succeeds clears it; only a failing 2nd+ try raises resume' {
        $inv = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\updater\_shared\SI-UpdaterInvardia.ps1'))
        $iCount = $inv.IndexOf('$resumeTries++')
        $iCount | Should -BeGreaterThan $inv.IndexOf('if (-not $pre.Go) {') -Because 'a resume that defers behind a pipeline run never counts'
        $iCount | Should -BeLessThan $inv.IndexOf('$roll = Invoke-SIUpdaterRoll')
        $inv.Substring($iCount, 600) | Should -Match ([regex]::Escape('& $save'))
        $inv | Should -Match ([regex]::Escape("if (`$pro.ClearResume) { `$state.code.resumeVersion = ''; `$state.code.resumeTries = '' }"))
        # (review round 3) the post-roll check and the second pass stay ONE chain, exactly as before; the resume beside it
        $inv | Should -Match ([regex]::Escape("if (`$pro.PostRollFailed) { `$rc = 1; `$state.lastError = `"code: `$(`$post.Text)`"; & `$fail 'post-roll' ([string]`$post.Text) }"))
        $inv | Should -Match ('(?s)' + [regex]::Escape("& `$fail 'post-roll' ([string]`$post.Text) }") + '\s+# the updater moved onto this release[^\n]*\n\s+' + [regex]::Escape('elseif ($pro.SecondPass) { $gate.SecondPass = $true }'))
        # (the behaviour is proven on the real update path: SIv3-UpdaterPostRollRun, '#1406 a RESUMED update')
        @([regex]::Matches($inv, [regex]::Escape("& `$fail 'resume'"))).Count | Should -Be 2 -Because 'the post-roll failure and the roll failure -- never at the start'
        $inv.IndexOf("& `$fail 'resume'") | Should -BeGreaterThan $inv.IndexOf('$roll = Invoke-SIUpdaterRoll')
    }
    It '(review) an image-only patch of the recorded release (3.1.52 -> 3.1.52.1) is never finished by a full update' {
        $io = [pscustomobject]@{ Action = 'update'; Version = '3.1.52.1'; Sequence = 60; Reason = 'image patch'; Manifest = [pscustomobject]@{} }
        $d = Get-SIUpdaterInvardiaCodeDecision -Result $io -Deployed '3.1.52.1' -AppliedSequence 59 -Recorded '3.1.52'
        $d.Act | Should -BeFalse
        if ($d.PSObject.Properties['Resume']) { $d.Resume | Should -BeFalse }
    }
    It 'the record on the same version: nothing to do, as before; no record: as before' {
        (Get-SIUpdaterInvardiaCodeDecision -Result $script:M -Deployed '3.1.51' -AppliedSequence 50 -Recorded '3.1.51').Act | Should -BeFalse
        (Get-SIUpdaterInvardiaCodeDecision -Result $script:M -Deployed '3.1.51' -AppliedSequence 50 -Recorded '').Applied | Should -BeTrue
        (Get-SIUpdaterInvardiaCodeDecision -Result $script:M -Deployed '3.1.51' -AppliedSequence 50).Act | Should -BeFalse
    }
    It 'the version the jobs run is still the highest of tags and record (the from-version is unchanged); the record reaches the decision' {
        Get-SIDeployedVersionFromJobs -Jobs @([pscustomobject]@{ Name = 'caj-si-flow'; Image = 'acr.azurecr.io/si-orchestrator:v3.1.51-0123456789ab' }) -LoginServer 'acr.azurecr.io' -Recorded '3.1.43.5' | Should -Be '3.1.51'
        $up = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\updater\Start-SIUpdater.ps1'))
        $up | Should -Match ([regex]::Escape('$global:SI_UpdaterRecordedVersion = $recorded'))
        $inv = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\updater\_shared\SI-UpdaterInvardia.ps1'))
        $inv | Should -Match ([regex]::Escape('-Recorded ([string]$global:SI_UpdaterRecordedVersion)'))
    }
}

Describe '(4) on a real SQL Server: the shipped lifecycle figures are the three statements of 3.1.51, exact on edge data' {
    # (round 2, both reviewers: the one-pass #ls was 30% slower on the runner and its benefit unproven -- reverted; this test
    # now proves the three statements as shipped. A one-pass conditional aggregation without a temp table is a row for later,
    # only if measured faster at multi-million rows.)
    BeforeAll {
        . (Join-Path $script:SIRoot 'engine\pro-data\_shared\SI-DataKeyFigures.ps1')
        $all = (Get-SIDataKeyFiguresSql) -replace "`r`n", "`n"
        $a = $all.IndexOf("INSERT #kf (Block, Figure, Dim1, Dim2, Value, Assets, Total, Available, Note) SELECT N'patching', N'opened_30d'")
        $endTxt = "AND s.ClosedAt > DATEADD(day, -@kfMttr, @t) AND s.ClosedAt <= @t AND s.CloseReason = N'remediated';"
        $b = $all.IndexOf($endTxt, [Math]::Max(0, $a)) + $endTxt.Length
        $script:ShippedBlock = if ($a -ge 0 -and $b -gt $a) { $all.Substring($a, $b - $a) } else { '' }
        # the three statements of 3.1.51 (word for word), each a full pass of sidata.CiFindingState
        $script:OldBlock = @'
INSERT #kf (Block, Figure, Dim1, Dim2, Value, Assets, Total, Available, Note) SELECT N'patching', N'opened_30d', N'', N'', COUNT_BIG(*), COUNT(DISTINCT s.CiId), NULL, 1, NULL FROM sidata.CiFindingState AS s
WHERE s.FindingKey LIKE N'CVE-%' AND s.FirstDetected > DATEADD(day, -@kfRecent, @t) AND s.FirstDetected <= @t;
INSERT #kf (Block, Figure, Dim1, Dim2, Value, Assets, Total, Available, Note) SELECT N'patching', N'fixed_30d', N'', N'', COUNT_BIG(*), COUNT(DISTINCT s.CiId), NULL, 1, NULL FROM sidata.CiFindingState AS s
WHERE s.FindingKey LIKE N'CVE-%' AND s.ClosedAt > DATEADD(day, -@kfRecent, @t) AND s.ClosedAt <= @t AND s.CloseReason = N'remediated';
INSERT #kf (Block, Figure, Dim1, Dim2, Value, Assets, Total, Available, Note) SELECT N'patching', N'mean_days_to_fix', N'', N'', AVG(CONVERT(float, DATEDIFF(hour, s.FirstDetected, s.ClosedAt)) / 24.0), COUNT(DISTINCT s.CiId), COUNT_BIG(*),
                  CASE WHEN COUNT_BIG(*) > 0 THEN 1 ELSE 0 END, CASE WHEN COUNT_BIG(*) = 0 THEN N'no vulnerability was fixed in the last ' + CONVERT(nvarchar(10), @kfMttr) + N' days' END
FROM sidata.CiFindingState AS s WHERE s.FindingKey LIKE N'CVE-%' AND s.ClosedAt > DATEADD(day, -@kfMttr, @t) AND s.ClosedAt <= @t AND s.CloseReason = N'remediated';
'@
        $script:Db = 'sikfls_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
        $script:Cs = { param($d) "Server=$($env:SI_TEST_LOCALSQL);Database=$d;$($env:SI_TEST_SQL_AUTH);TrustServerCertificate=True;Pooling=false" }
        $script:Q = {
            param([string]$Sql)
            $cn = New-Object System.Data.SqlClient.SqlConnection((& $script:Cs $script:Db)); $cn.Open()
            try {
                $c = $cn.CreateCommand(); $c.CommandTimeout = 600; $c.CommandText = $Sql; $rd = $c.ExecuteReader(); $out = New-Object System.Collections.Generic.List[string]
                while ($rd.Read()) { $f = for ($i = 0; $i -lt $rd.FieldCount; $i++) { if ($rd.IsDBNull($i)) { '<null>' } else { [string]$rd.GetValue($i) } }; $out.Add(($f -join '|')) }
                $rd.Close(); , $out.ToArray()
            } finally { $cn.Dispose() }
        }
        $script:Figures = {
            param([string]$Block, [int]$Recent, [int]$Mttr)
            $x = & $script:Q ("SET NOCOUNT ON; DECLARE @t datetime2(3) = '2026-11-26T06:00:00', @kfRecent int = $Recent, @kfMttr int = $Mttr;" +
                " CREATE TABLE #kf (Block NVARCHAR(16) NOT NULL, Figure NVARCHAR(48) NOT NULL, Dim1 NVARCHAR(200) NOT NULL, Dim2 NVARCHAR(120) NOT NULL, Value FLOAT NULL, Assets INT NULL, Total INT NULL, Available BIT NOT NULL, Note NVARCHAR(400) NULL);`n" +
                $Block + "`nSELECT Figure, Value, Assets, Total, Available, Note FROM #kf ORDER BY Figure;")
            # (the rows one by one: the reader answers ONE array -- unrolled here, so every comparison compares the rows)
            $x | ForEach-Object { $_ }
        }
        if ($env:SI_TEST_LOCALSQL) {
            $m = New-Object System.Data.SqlClient.SqlConnection((& $script:Cs 'master')); $m.Open()
            try { $c = $m.CreateCommand(); $c.CommandText = "CREATE DATABASE [$($script:Db)]"; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
            $null = & $script:Q "CREATE SCHEMA sidata;"
            $null = & $script:Q "CREATE TABLE sidata.CiFindingState (OwnerKey NVARCHAR(450) NOT NULL, FindingKey NVARCHAR(256) NOT NULL, CiId NVARCHAR(64) NULL, FirstDetected DATETIME2(3) NULL, ClosedAt DATETIME2(3) NULL, CloseReason NVARCHAR(32) NULL, CONSTRAINT PK_x PRIMARY KEY (OwnerKey, FindingKey)); SELECT 1;"
        }
    }
    AfterAll {
        if ($env:SI_TEST_LOCALSQL) {
            [System.Data.SqlClient.SqlConnection]::ClearAllPools()
            $m = New-Object System.Data.SqlClient.SqlConnection((& $script:Cs 'master')); $m.Open()
            try { $c = $m.CreateCommand(); $c.CommandText = "ALTER DATABASE [$($script:Db)] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$($script:Db)]"; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
        }
    }
    It 'the same figures on edge data (window edges, NULL CI ids, other close reasons, non-CVE keys) for both windows either way round' -Skip:(-not $env:SI_TEST_LOCALSQL) {
        # @t = 2026-11-26 06:00; recent 30 d -> edge 2026-10-27 06:00; mttr 90 d -> edge 2026-08-28 06:00
        $null = & $script:Q @"
INSERT sidata.CiFindingState (OwnerKey, FindingKey, CiId, FirstDetected, ClosedAt, CloseReason) VALUES
 (N'o1', N'CVE-1', N'ci-1', '2026-11-20', NULL, NULL),
 (N'o1', N'CVE-2', N'ci-1', '2026-10-27T06:00:00', NULL, NULL),
 (N'o1', N'CVE-3', N'ci-1', '2026-10-27T06:00:00.003', NULL, NULL),
 (N'o2', N'CVE-1', NULL, '2026-11-26T06:00:00', '2026-11-26T06:00:00', N'remediated'),
 (N'o2', N'CVE-4', NULL, '2026-11-26T06:00:00.003', NULL, NULL),
 (N'o3', N'CVE-5', N'ci-3', '2026-06-01', '2026-11-01', N'remediated'),
 (N'o3', N'CVE-6', N'ci-3', '2026-06-01', '2026-09-15', N'remediated'),
 (N'o3', N'CVE-7', N'ci-3', '2026-06-01', '2026-08-28T06:00:00', N'remediated'),
 (N'o3', N'CVE-8', N'ci-3', '2026-06-01', '2026-08-28T06:00:00.003', N'remediated'),
 (N'o3', N'CVE-9', N'ci-3', '2026-06-01', '2026-11-10', N'retired'),
 (N'o4', N'CVE-10', N'ci-4', NULL, '2026-11-10', N'remediated'),
 (N'o4', N'CFG-1', N'ci-4', '2026-11-20', '2026-11-21', N'remediated'),
 (N'o4', N'cve-11', N'ci-4', '2026-11-20', '2026-11-27', N'remediated'),
 (N'o5', N'CVE-12', N'ci-5', '2026-11-25', '2026-11-25T12:00:00', N'remediated');
SELECT 1;
"@
        # the hand-worked answer for @t 2026-11-26 06:00, recent 30 d, mean time to fix 90 d (an edge is never inside: > edge):
        #   opened: o1/CVE-1, o1/CVE-3 (3 ms past the edge), o2/CVE-1 (at @t), cve-11, CVE-12 = 5 on ci-1, ci-4, ci-5 (a NULL CI is no CI)
        #   fixed : o2/CVE-1 (at @t), CVE-5, CVE-10, CVE-12 = 4 on ci-3, ci-4, ci-5 (retired, CFG-, after @t: out)
        #   mttr  : o2/CVE-1 0 d, CVE-5 153 d, CVE-6 106 d, CVE-8 88.25 d, CVE-10 (no first seen: counted, not averaged), CVE-12
        #           0.5 d = 6 rows on 3 CIs, mean (0 + 153 + 106 + 88.25 + 0.5) / 5 = 69.55 d
        foreach ($blk in @($script:ShippedBlock, $script:OldBlock)) {
            $r = @(& $script:Figures $blk 30 90)
            $r.Count | Should -Be 3
            # (ordered by figure: fixed_30d, mean_days_to_fix, opened_30d)
            $r[2] | Should -Be 'opened_30d|5|3|<null>|True|<null>'
            $r[0] | Should -Be 'fixed_30d|4|3|<null>|True|<null>'
            $m = $r[1].Split('|'); $m[0] | Should -Be 'mean_days_to_fix'
            [Math]::Round([double]::Parse($m[1], [Globalization.CultureInfo]::InvariantCulture), 6) | Should -Be 69.55
            $m[2] | Should -Be '3'; $m[3] | Should -Be '6'; $m[4] | Should -Be 'True'
        }
        foreach ($w in @(@(120, 90), @(30, 30), @(1, 365), @(0, 0))) {
            $sh = @(& $script:Figures $script:ShippedBlock $w[0] $w[1]); $ol = @(& $script:Figures $script:OldBlock $w[0] $w[1])
            $sh.Count | Should -Be 3; ($sh -join "`n") | Should -Match '^fixed_30d\|'
            ($sh -join "`n") | Should -Be ($ol -join "`n") -Because ("recent {0} d, mean time to fix {1} d" -f $w[0], $w[1])
        }
    }
}

Describe '(4) the key figures: the three lifecycle statements as before; the progress said as it comes' {
    It 'the shipped lifecycle figures are the three statements of 3.1.51, word for word (the one pass was reverted)' {
        . (Join-Path $script:SIRoot 'engine\pro-data\_shared\SI-DataKeyFigures.ps1')
        $s = (Get-SIDataKeyFiguresSql) -replace "`r`n", "`n"
        $s | Should -Not -Match '#ls'
        $old = @'
INSERT #kf (Block, Figure, Dim1, Dim2, Value, Assets, Total, Available, Note) SELECT N'patching', N'opened_30d', N'', N'', COUNT_BIG(*), COUNT(DISTINCT s.CiId), NULL, 1, NULL FROM sidata.CiFindingState AS s
WHERE s.FindingKey LIKE N'CVE-%' AND s.FirstDetected > DATEADD(day, -@kfRecent, @t) AND s.FirstDetected <= @t;
'@ -replace "`r`n", "`n"
        $s.Contains($old.TrimEnd()) | Should -BeTrue
    }
    It '9i says its lines as they come (each one a sign of life), not at its end' {
        $fn = [regex]::Match($script:Update, '(?s)function Invoke-SIUpdateKeyFigures \{.*?\n\}').Value
        $fn | Should -Match ([regex]::Escape('$r = Invoke-SIDataKeyFigures -Invoke $dataSql -Settings $settings -BudgetSeconds 900 -Log $kfLog'))
        $fn | Should -Not -Match 'foreach \(\$x in \$lines\)'
    }
}
