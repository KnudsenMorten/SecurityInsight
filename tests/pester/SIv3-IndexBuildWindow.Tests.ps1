#Requires -Version 5.1
<#
    #1050 AN INDEX THAT DOES NOT FIT AN UPDATE IS NEVER STARTED IN ONE (owner 2026-11-01). Live 2026-11-01 (a ring 2 install,
    3.0.9 -> 3.0.10): the update said "up to 10 min" and built a FILTERED index on sidata.Finding (17.2 M rows) for over two
    hours -- a filtered index cannot be resumable, so it cannot pause at the update's time, and the install and the queued run
    waited. What must hold:
      - the estimate: the table's pages at THIS database's measured rate (median of measured builds, else a resumable build,
        else a timed sample read / 2), times a margin from the measured spread -- no size cap anywhere;
      - an update starts a filtered index only when its estimate fits the minutes it has left; otherwise the index WAITS
        (cfg.IndexBuild: its statement, pages, estimate, why) with ONE plain line, and the release runs without it;
      - small or fitting tables behave as before; a resumable index is still created / resumed with MAX_DURATION;
      - the install's lock is beaten while ANY index builds (the runner's build runs asynchronously and calls the beat);
      - the idle window: the pipeline runner's wake-up starts the index build job (caj-si-index-build, #1111 -- never the
        updater) only when nothing is going, no update waits or runs, and the window fits (a resumable index: its minutes; a
        filtered one: its estimate) -- or after 7 days of waiting, ONCE (the next run waits for it);
      - the job itself (pause / resume / the update goes first / one outcome always): SIv3-IndexBuildJob.Tests.ps1.
    PURE + FAKES for the decisions; REAL SQL (the test VM's SQL Express) for the build command, the row store, the pages and
    the sample read. The ~20 M-row measurement is tagged Scale (on demand only, never in a gate).
#>

BeforeDiscovery {
    try { $script:HasSql = [bool]$env:SI_TEST_LOCALSQL -and $null -ne ('System.Data.SqlClient.SqlConnection' -as [type]) } catch { $script:HasSql = $false }
}

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\pro-settings\SI-ProSchema.ps1')
    $script:Filtered = [pscustomobject]@{ Name = 'IX_Finding_RaFindingKey'; Table = 'sidata.Finding'; Statement = 'CREATE INDEX IX_Finding_RaFindingKey ON sidata.Finding (CollectionId) WHERE RaFindingKey IS NOT NULL'; Start = 0; Length = 0 }
    $script:Plain = [pscustomobject]@{ Name = 'IX_Finding_Category'; Table = 'sidata.Finding'; Statement = 'CREATE INDEX IX_Finding_Category ON sidata.Finding (CollectionId, Category)'; Start = 0; Length = 0 }
    # a resumable database whose sidata.Finding is large; -Built: indexes there after a Run
    function script:New-Db {
        $s = [pscustomobject]@{ Ran = (New-Object System.Collections.Generic.List[string]); There = @{}; Beats = 0; Records = (New-Object System.Collections.Generic.List[string]) }
        $s | Add-Member -NotePropertyName Invoke -NotePropertyValue ({
            param($sql, $p, $mode)
            $rows = New-Object System.Collections.Generic.List[object]
            $rows.Add(@{ K = 'edition'; A = '5'; B = ''; N = 0 })
            $rows.Add(@{ K = 'large'; A = 'sidata.Finding'; B = ''; N = 17200000 })
            foreach ($k in @($s.There.Keys)) { $rows.Add(@{ K = 'index'; A = 'sidata.Finding'; B = $k; N = 0 }) }
            , $rows.ToArray()
        }.GetNewClosure())
        # the build: the statement is "run" and calls the beat twice (a long build), then the index is there
        $s | Add-Member -NotePropertyName Run -NotePropertyValue ({ param($q, $beat) $s.Ran.Add($q); if ($beat) { & $beat 1; & $beat 2 }; if ($q -match 'INDEX (\w+) ON') { $s.There[$Matches[1]] = $true } }.GetNewClosure())
        $s | Add-Member -NotePropertyName Record -NotePropertyValue ({ param($w, $i, $d) $s.Records.Add(('{0}:{1}' -f $w, $i.Name)) }.GetNewClosure())
        $s | Add-Member -NotePropertyName Beat -NotePropertyValue ({ param($w) $s.Beats++ }.GetNewClosure())
        $s
    }
    function script:Est([bool]$Known = $true, [int]$Minutes = 130, [long]$Pages = 11500000) { $e = [pscustomobject]@{ Known = $Known; Minutes = $Minutes; Pages = $Pages; PagesPerSecond = 1500.0; Source = 'measured on this database (3 build(s))' }; { param($i) $e }.GetNewClosure() }
    $script:T0 = [datetime]::SpecifyKind([datetime]'2026-11-01T10:00:00', [DateTimeKind]::Utc)
}

Describe '#1050 the estimate: this database''s own rate, never a size cap' {
    It 'measured builds: the median rate; a margin of 1.5 until three are measured, then the measured spread (at least 1.2)' {
        $two = @([pscustomobject]@{ Pps = 2000.0 }, [pscustomobject]@{ Pps = 1000.0 })
        $r = Get-SIIndexBuildRate -Samples $two
        $r.Known | Should -BeTrue; $r.PagesPerSecond | Should -Be 1500; $r.Margin | Should -Be 1.5; $r.Source | Should -Match 'measured on this database \(2 build'
        $three = @([pscustomobject]@{ Pps = 1500.0 }, [pscustomobject]@{ Pps = 1000.0 }, [pscustomobject]@{ Pps = 1600.0 })
        $r3 = Get-SIIndexBuildRate -Samples $three
        $r3.PagesPerSecond | Should -Be 1500; $r3.Margin | Should -Be 1.5 -Because 'median 1500 / slowest 1000'
        (Get-SIIndexBuildRate -Samples @([pscustomobject]@{ Pps = 1000.0 }, [pscustomobject]@{ Pps = 1010.0 }, [pscustomobject]@{ Pps = 1020.0 })).Margin | Should -Be 1.2
    }
    It 'no measured build: a resumable build here, else a timed sample read at half the speed (a build reads, sorts and writes), else unknown' {
        $r = Get-SIIndexBuildRate -ResumableRate 800.0; $r.PagesPerSecond | Should -Be 800; $r.Source | Should -Match 'resumable'
        $s = Get-SIIndexBuildRate -ReadRate 4000.0; $s.PagesPerSecond | Should -Be 2000; $s.Source | Should -Match 'sample read'
        (Get-SIIndexBuildRate).Known | Should -BeFalse
    }
    It 'the live case: 11.5 M pages at ~1,500 pages/s is about 2 h (x1.5 margin = more), far over a 10-minute update' {
        $e = Get-SIIndexBuildEstimate -Pages 11500000 -Rate (Get-SIIndexBuildRate -Samples @([pscustomobject]@{ Pps = 1500.0 }))
        $e.Known | Should -BeTrue; $e.Minutes | Should -BeGreaterThan 180
        $small = Get-SIIndexBuildEstimate -Pages 20000 -Rate (Get-SIIndexBuildRate -Samples @([pscustomobject]@{ Pps = 1500.0 }))
        $small.Minutes | Should -Be 1 -Because 'a small table is a minute at most'
    }
    It 'the stored rate: the newest seven builds, within the 400 characters of cfg.InstallState, read back as written' {
        $s = @(1..12 | ForEach-Object { [pscustomobject]@{ Pps = 1000.0 + $_; Pages = 11500000 + $_; Seconds = 7000 + $_ } })
        $v = ConvertTo-SIIndexRateValue -Samples $s
        $v.Length | Should -BeLessOrEqual 400
        $back = @(ConvertFrom-SIIndexRateValue -Value $v)
        $back.Count | Should -Be 7; $back[0].Pps | Should -Be 1001; $back[0].Pages | Should -Be 11500001
        @(ConvertFrom-SIIndexRateValue -Value 'not json').Count | Should -Be 0
    }
    It 'the sample read reads about 20,000 pages of a large table, all of a small one' {
        Get-SIIndexSamplePercent -Pages 11500000 | Should -BeLessThan 0.2
        Get-SIIndexSamplePercent -Pages 5000 | Should -Be 100
    }
    It 'STATIC GUARD: no fixed row / page / minute cap decides whether an index is built' {
        $f = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\_shared\SI-IndexBuild.ps1'))
        $f | Should -Not -Match '(?i)Max(Rows|Pages|Minutes)\s*='
    }
}

Describe '#1050 the update: a filtered index starts only when its estimate fits' {
    It 'THE LIVE CASE: about 3 h against the 10 minutes left -- NOT started; it waits with one plain line and its statement is kept' {
        $db = New-Db; $lines = New-Object System.Collections.Generic.List[string]
        $r = Invoke-SIProSchemaIndexStep -Deferred @($script:Filtered) -Invoke $db.Invoke -Run $db.Run -BudgetMinutes 10 -Log { param($m) $lines.Add($m) }.GetNewClosure() -Estimate (Est -Minutes 195) -Record $db.Record -Beat $db.Beat
        $db.Ran.Count | Should -Be 0 -Because 'a filtered build cannot pause: started, it would hold the update for hours'
        @($r.Waiting) | Should -Be @('IX_Finding_RaFindingKey')
        @($r.Pending).Count | Should -Be 0; @($r.Warnings).Count | Should -Be 0
        @($db.Records) | Should -Be @('waiting:IX_Finding_RaFindingKey')
        $t = $lines -join "`n"
        $t | Should -Match 'IX_Finding_RaFindingKey on sidata\.Finding: not built in this update -- a filtered index cannot pause'
        $t | Should -Match '11\.5 M pages take about 3 h 15 min, more than the 10 min this update has'
        $t | Should -Match 'the release works without it'
    }
    It 'an estimate that fits is built -- with the lock beaten while it builds, and its row says built' {
        $db = New-Db
        $r = Invoke-SIProSchemaIndexStep -Deferred @($script:Filtered) -Invoke $db.Invoke -Run $db.Run -BudgetMinutes 40 -Estimate (Est -Minutes 25 -Pages 120000) -Record $db.Record -Beat $db.Beat
        @($r.Built) | Should -Be @('IX_Finding_RaFindingKey')
        $db.Ran[0] | Should -Be 'CREATE INDEX IX_Finding_RaFindingKey ON sidata.Finding (CollectionId) WHERE RaFindingKey IS NOT NULL WITH (ONLINE = ON)'
        $db.Beats | Should -Be 2 -Because 'every beat of the build reaches the install''s lock'
        @($db.Records) | Should -Be @('building:IX_Finding_RaFindingKey', 'built:IX_Finding_RaFindingKey')
    }
    It 'an estimate that cannot be made waits too (never a gamble on an unknown time)' {
        $db = New-Db
        $r = Invoke-SIProSchemaIndexStep -Deferred @($script:Filtered) -Invoke $db.Invoke -Run $db.Run -BudgetMinutes 40 -Estimate (Est -Known $false)
        @($r.Waiting) | Should -Be @('IX_Finding_RaFindingKey'); $db.Ran.Count | Should -Be 0
    }
    It 'a resumable index is unchanged: created with the minutes left as MAX_DURATION, the lock beaten, no estimate asked' {
        $db = New-Db; $asked = [ref]0
        $r = Invoke-SIProSchemaIndexStep -Deferred @($script:Plain, $script:Filtered) -Invoke $db.Invoke -Run $db.Run -BudgetMinutes 10 -Estimate { param($i) $asked.Value++; [pscustomobject]@{ Known = $true; Minutes = 300; Pages = 1; Source = 'x' } }.GetNewClosure() -Beat $db.Beat
        $db.Ran[0] | Should -Be 'CREATE INDEX IX_Finding_Category ON sidata.Finding (CollectionId, Category) WITH (ONLINE = ON, RESUMABLE = ON, MAX_DURATION = 10 MINUTES)'
        $db.Ran.Count | Should -Be 1 -Because 'the filtered one does not fit'
        $asked.Value | Should -Be 1 -Because 'only the filtered index is estimated'
        @($r.Built) | Should -Be @('IX_Finding_Category'); @($r.Waiting) | Should -Be @('IX_Finding_RaFindingKey')
    }
    It 'the apply''s summary says which indexes wait for an idle window (the update''s result and its status)' {
        $root = Join-Path ([IO.Path]::GetTempPath()) ('si-ixw-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
        New-Item -ItemType Directory -Force (Join-Path $root 'sql') | Out-Null
        try {
            [IO.File]::WriteAllText((Join-Path $root 'sql\si-data-schema.sql'), "IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Finding_RaFindingKey' AND object_id = OBJECT_ID('sidata.Finding'))`n    EXEC (N'CREATE INDEX IX_Finding_RaFindingKey ON sidata.Finding (CollectionId) WHERE RaFindingKey IS NOT NULL');`n")
            $db = New-Db; $files = New-Object System.Collections.Generic.List[string]
            $runFile = { param($n, $b, $beat) $files.Add($n) }.GetNewClosure()
            $r = Invoke-SIProSchemaApply -SIRoot $root -Invoke $db.Invoke -RunFile $runFile -Log { param($m) } -IndexEstimate (Est -Minutes 195) -IndexRecord $db.Record -Beat $db.Beat
            $r.Action | Should -Be 'applied'
            $r.Reason | Should -Match '1 index\(es\) on large tables wait for an idle window \(they do not fit an update; the release works without them\): IX_Finding_RaFindingKey'
            @($files) | Should -Be @('data') -Because 'the index was not sent'
        } finally { Remove-Item -Recurse -Force $root -ErrorAction SilentlyContinue }
    }
    It 'WIRING: the runner builds through the beat-calling command; the updater passes the install''s lock as the beat' {
        $f = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\pro-settings\SI-ProSchema.ps1'))
        $f | Should -Match ([regex]::Escape('$buildCmd = ${function:Invoke-SIIndexBuildCommand}'))
        $f | Should -Match ([regex]::Escape('& $buildCmd -Connection $cn -Sql $b -Beat $Beat -BeatSeconds $beatSec'))
        $f | Should -Match ([regex]::Escape("{ param(`$s, `$b) & `$RunFile '#index' @(`$s) `$b }"))
        $u = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\updater\_shared\SI-UpdaterDatabase.ps1'))
        $u | Should -Match ([regex]::Escape('Invoke-SIUpdaterLockBeat -What $what -MinSeconds 30'))
        $u | Should -Match ([regex]::Escape("if ((Get-Command -Name Invoke-SIProSchemaApply).Parameters.ContainsKey('Beat')) { `$applyArgs.Beat = `$ixBeat }"))
    }
}

Describe '#1050 the idle window' {
    BeforeAll {
        # a FILTERED index by default (the estimate decides); -Plain: one without a filter (resumable: the window decides)
        function script:Row([string]$State = 'waiting', [int]$Est = 130, [int]$DaysAgo = 1, $Forced = $null, [string]$Name = 'IX_Finding_RaFindingKey', [switch]$Plain) {
            $stmt = if ($Plain) { "CREATE INDEX $Name ON sidata.Finding (CollectionId, Category)" } else { "CREATE INDEX $Name ON sidata.Finding (CollectionId) WHERE RaFindingKey IS NOT NULL WITH (ONLINE = ON)" }
            [pscustomobject]@{ Table = 'sidata.Finding'; Name = $Name; Statement = $stmt; State = $State; EstMinutes = $Est; SinceUtc = $script:T0.AddDays(-$DaysAgo); ForcedUtc = $Forced; LastStartUtc = $null; Why = '' }
        }
        $script:Idle = [pscustomobject]@{ Busy = $false; Why = '' }
    }
    It 'nothing waits: nothing to do' {
        (Get-SIIndexBuildWindowDecision -Rows @() -NowUtc $script:T0 -NextRunUtc $script:T0.AddHours(8) -Busy $script:Idle).Start | Should -BeFalse
        (Get-SIIndexBuildWindowDecision -Rows @((Row -State built)) -NowUtc $script:T0 -NextRunUtc $script:T0.AddHours(8) -Busy $script:Idle).Why | Should -Be ''
    }
    It 'idle and the estimate ends before the next run (with its lead): START -- the oldest waiting index first' {
        $d = Get-SIIndexBuildWindowDecision -Rows @((Row -Name 'IX_B' -DaysAgo 1), (Row -Name 'IX_A' -DaysAgo 3)) -NowUtc $script:T0 -NextRunUtc $script:T0.AddHours(8) -Busy $script:Idle
        $d.Start | Should -BeTrue; $d.Force | Should -BeFalse; $d.Index.Name | Should -Be 'IX_A'
        $d.Why | Should -Match 'about 2 h 10 min, and the next run starts 2026-11-01 18:00Z'
    }
    It 'never while a run starts or runs, an update waits or runs (#1111: the update goes first), the index build job runs, or housekeeping says busy' {
        $w = @((Row))
        (Get-SIIndexBuildWindowDecision -Rows $w -NowUtc $script:T0 -NextRunUtc $script:T0.AddHours(8) -Busy $script:Idle -RunDue $true).Start | Should -BeFalse
        (Get-SIIndexBuildWindowDecision -Rows $w -NowUtc $script:T0 -NextRunUtc $script:T0.AddHours(8) -Busy $script:Idle -UpdaterRunning 'caj-si-updater-x1').Start | Should -BeFalse
        $uw = Get-SIIndexBuildWindowDecision -Rows $w -NowUtc $script:T0 -NextRunUtc $script:T0.AddHours(8) -Busy $script:Idle -UpdateWaits 'update waits: run r-1 is running'
        $uw.Start | Should -BeFalse; $uw.Why | Should -Match 'an update waits .* -- the update goes first'
        (Get-SIIndexBuildWindowDecision -Rows @($w + (Row -State building -Name 'IX_Z')) -NowUtc $script:T0 -NextRunUtc $script:T0.AddHours(8) -Busy $script:Idle -IndexJobRunning 'caj-si-index-build-x1').Start | Should -BeFalse
        $d = Get-SIIndexBuildWindowDecision -Rows $w -NowUtc $script:T0 -NextRunUtc $script:T0.AddHours(8) -Busy ([pscustomobject]@{ Busy = $true; Why = 'a data sync is running' })
        $d.Start | Should -BeFalse; $d.Why | Should -Be 'a data sync is running'
    }
    It 'too long for the time before the next run: it waits and says what it needs' {
        $d = Get-SIIndexBuildWindowDecision -Rows @((Row -Est 130)) -NowUtc $script:T0 -NextRunUtc $script:T0.AddMinutes(140) -Busy $script:Idle
        $d.Start | Should -BeFalse -Because '130 min + 15 min lead does not fit in 140 min'
        $d.Why | Should -Match 'it needs about 2 h 10 min; the next run starts in 2 h 20 min'
    }
    It 'NO INDEX WAITS FOR EVER: after 7 days without a long-enough window it is built at the next idle moment, ONCE' {
        $d = Get-SIIndexBuildWindowDecision -Rows @((Row -Est 600 -DaysAgo 7)) -NowUtc $script:T0 -NextRunUtc $script:T0.AddMinutes(90) -Busy $script:Idle
        $d.Start | Should -BeTrue; $d.Force | Should -BeTrue
        $d.Why | Should -Match 'waited 7 days without an idle window long enough .* the next run waits for it'
        (Get-SIIndexBuildWindowDecision -Rows @((Row -Est 600 -DaysAgo 9 -Forced $script:T0.AddDays(-1))) -NowUtc $script:T0 -NextRunUtc $script:T0.AddMinutes(90) -Busy $script:Idle).Start | Should -BeFalse -Because 'the one-time build was spent'
        (Get-SIIndexBuildWindowDecision -Rows @((Row -Est 600 -DaysAgo 7)) -NowUtc $script:T0 -NextRunUtc $script:T0.AddMinutes(90) -Busy ([pscustomobject]@{ Busy = $true; Why = 'x' })).Start | Should -BeFalse -Because 'even then, never under a run, a sync or a data out'
    }
    It 'no run scheduled: a known estimate starts' {
        (Get-SIIndexBuildWindowDecision -Rows @((Row)) -NowUtc $script:T0 -NextRunUtc $null -Busy $script:Idle).Start | Should -BeTrue
    }
    It 'the status lines: waiting / building / failed, in plain words' {
        $l = @(Get-SIIndexBuildStatusLines -Rows @((Row), (Row -State building -Name 'IX_B'), (Row -State built -Name 'IX_C')))
        $l.Count | Should -Be 2
        $l[0] | Should -Match 'waits for an idle window of about 2 h 10 min'
        $l[1] | Should -Match 'IX_B on sidata\.Finding: being built now'
    }
    It '#1111 a RESUMABLE index (no filter, or a paused build) starts in any window of at least 10 min, for the window''s minutes -- never its whole estimate' {
        $d = Get-SIIndexBuildWindowDecision -Rows @((Row -Plain -Est 600)) -NowUtc $script:T0 -NextRunUtc $script:T0.AddMinutes(90) -Busy $script:Idle
        $d.Start | Should -BeTrue; $d.Resumable | Should -BeTrue; $d.Force | Should -BeFalse
        $d.Minutes | Should -Be 75 -Because '90 min to the next run minus the 15-minute lead'
        $d.Why | Should -Match 'built resumably for up to 1 h 15 min \(it pauses at the end of the window'
        $p = Get-SIIndexBuildWindowDecision -Rows @((Row -State paused -Est 600)) -NowUtc $script:T0 -NextRunUtc $script:T0.AddMinutes(90) -Busy $script:Idle
        $p.Start | Should -BeTrue -Because 'a paused build is resumable whatever its statement'; $p.Why | Should -Match '^resumed for up to 1 h 15 min'
        (Get-SIIndexBuildWindowDecision -Rows @((Row -Plain)) -NowUtc $script:T0 -NextRunUtc $script:T0.AddMinutes(20) -Busy $script:Idle).Start | Should -BeFalse -Because '5 min of window is too short'
        $n = Get-SIIndexBuildWindowDecision -Rows @((Row -Plain)) -NowUtc $script:T0 -NextRunUtc $null -Busy $script:Idle
        $n.Start | Should -BeTrue; $n.Minutes | Should -Be 0 -Because 'no run scheduled: no window end'
    }
    It '#1111 a row left ''building'' while no index build job runs is a build that ended without an outcome: it is started again' {
        $d = Get-SIIndexBuildWindowDecision -Rows @((Row -State building)) -NowUtc $script:T0 -NextRunUtc $script:T0.AddHours(8) -Busy $script:Idle
        $d.Start | Should -BeTrue; $d.Why | Should -Match 'its last build ended without an outcome'
        (Get-SIIndexBuildWindowDecision -Rows @((Row -State building)) -NowUtc $script:T0 -NextRunUtc $script:T0.AddHours(8) -Busy $script:Idle -IndexJobRunning 'caj-si-index-build-q1').Start | Should -BeFalse -Because 'the job that builds it is still running'
    }
    It '#1111 the status line of a paused index' {
        $l = @(Get-SIIndexBuildStatusLines -Rows @((Row -State paused)))
        $l[0] | Should -Match 'IX_Finding_RaFindingKey on sidata\.Finding: paused \(an update went first\) -- it resumes in the next idle window'
    }
    It 'WIRING (#1111): the runner''s wake-up decides with the housekeeping state, the next run, the update (running AND waiting) and the job, and starts caj-si-index-build -- never the updater' {
        $w = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\flow\Invoke-SIJobFlowRun.ps1'))
        $w | Should -Match ([regex]::Escape('$ixBusy = Get-SIDataHousekeepingBusy -SettingsInvoke $proStore.Invoke -JobRunning $ixJobRunning -Jobs $ixJobs'))
        $w | Should -Match ([regex]::Escape('$ixDue = Get-SIJobFlowDue -Definition $pipeDefinition -Previous $runStore.Load() -NowUtc $ixNow'))
        $w | Should -Match ([regex]::Escape('-UpdaterRunning $ixUpd -UpdateWaits $ixWaits -IndexJobRunning $ixJobRunning'))
        $w | Should -Match ([regex]::Escape("& `$armSeams.Arm 'POST' ('{0}/{1}/start' -f `$armSeams.Base, `$ixJobName) (New-SIJobStartTemplate -Job `$ixJob -Env `$ixEnv -What 'the index build job')"))
        $w.IndexOf('$ixDec = Get-SIIndexBuildWindowDecision') | Should -BeLessThan $w.IndexOf('$drain = Invoke-SIPipelineDrain') -Because 'before the drain: an index build holds the install''s lock, a run then waits'
        (Get-SIIndexBuildContract).Job | Should -Be 'caj-si-index-build'
        (Get-SIIndexBuildContract).ContainsKey('Mode') | Should -BeFalse -Because 'the updater has no index-build mode any more'
        $g = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\pro-settings\SI-EngineGrants.ps1'))
        $g | Should -Match ([regex]::Escape("@{ Object = 'cfg.IndexBuild';              Verbs = 'SELECT' }"))
        $q = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'sql\si-pro-settings.sql'))
        $q | Should -Match "IF OBJECT_ID\('cfg\.IndexBuild'\) IS NULL\s+CREATE TABLE cfg\.IndexBuild"
    }
}

Describe '#1316 follow-up: an install whose runs go back to back still gets its indexes -- built in the gap before a scheduled run' {
    BeforeAll {
        $script:CsStmt = 'CREATE NONCLUSTERED COLUMNSTORE INDEX NCCI_Finding_Load ON sidata.Finding (CollectionId, FindingId)'
        function script:CsRow([int]$Est = 95, [datetime]$Since = $script:T0, $LastStart = $null, $Forced = $null, [string]$State = 'waiting', [switch]$Plain) {
            $stmt = if ($Plain) { 'CREATE INDEX IX_Finding_Category ON sidata.Finding (CollectionId, Category)' } else { $script:CsStmt }
            [pscustomobject]@{ Table = 'sidata.Finding'; Name = $(if ($Plain) { 'IX_Finding_Category' } else { 'NCCI_Finding_Load' }); Statement = $stmt; State = $State
                               EstMinutes = $(if ($Est -gt 0) { $Est } else { $null }); SinceUtc = $Since; ForcedUtc = $Forced; LastStartUtc = $LastStart; Why = '' }
        }
        $script:Idle2 = [pscustomobject]@{ Busy = $false; Why = '' }
        # THE BUSY INSTALL: a run of 10 h, then the next one due at once -- every 5-minute wake-up is either under a run
        # (RunDue) or the scheduled start right after it (StartDue). Returns the first decision that starts, with its time.
        function script:Invoke-BusyDays([object]$Row, [int]$Days = 3, [bool]$Recent = $false) {
            $t = $script:T0
            while ($t -lt $script:T0.AddDays($Days)) {
                $sinceRunStart = ($t - $script:T0).TotalMinutes % 600
                $startDue = $sinceRunStart -lt 5
                $d = Get-SIIndexBuildWindowDecision -Rows @($Row) -NowUtc $t -NextRunUtc $t -Busy $script:Idle2 -RunDue (-not $startDue) -StartDue $startDue -IndexJobStartedRecently $Recent
                if ($d.Start) { return [pscustomobject]@{ At = $t; D = $d; StartDue = $startDue } }
                $t = $t.AddMinutes(5)
            }
            $null
        }
    }
    It 'A BUSY INSTALL (a run always going): the columnstore index is started in the gap before a scheduled run after 24 h -- never under a run -- and the run starts late' {
        $first = Invoke-BusyDays -Row (CsRow -Est 95)
        $first | Should -Not -BeNullOrEmpty -Because 'without the gap no idle window ever comes and the index is never built'
        $first.StartDue | Should -BeTrue -Because 'never while a run runs'
        ($first.At - $script:T0).TotalHours | Should -BeGreaterOrEqual 24
        ($first.At - $script:T0).TotalHours | Should -BeLessThan 34 -Because 'the first scheduled start after 24 h of waiting'
        $first.D.HoldsRun | Should -BeTrue; $first.D.Resumable | Should -BeFalse; $first.D.Force | Should -BeFalse
        $first.D.Minutes | Should -Be (Get-SIIndexBuildContract).GapLateMinutes
        $first.D.Why | Should -Match 'about 1 h 35 min, built in the gap before the scheduled run .* the next run starts late, after it'
    }
    It 'without -StartDue (the old decision) the same busy install never builds it in 3 days' {
        $t = $script:T0; $started = 0
        while ($t -lt $script:T0.AddDays(3)) {
            if ((Get-SIIndexBuildWindowDecision -Rows @((CsRow)) -NowUtc $t -NextRunUtc $t -Busy $script:Idle2 -RunDue $true).Start) { $started++ }
            $t = $t.AddMinutes(5)
        }
        $started | Should -Be 0
    }
    It 'BOUNDED: a non-resumable index longer than the late limit waits (built once after 7 days); an unknown time waits too; a resumable one pauses at the limit' {
        $long = Get-SIIndexBuildWindowDecision -Rows @((CsRow -Est 400 -Since $script:T0.AddDays(-2))) -NowUtc $script:T0 -NextRunUtc $script:T0 -Busy $script:Idle2 -StartDue $true
        $long.Start | Should -BeFalse; $long.Why | Should -Match 'more than the 3 h a run may start late'
        (Get-SIIndexBuildWindowDecision -Rows @((CsRow -Est 0 -Since $script:T0.AddDays(-2))) -NowUtc $script:T0 -NextRunUtc $script:T0 -Busy $script:Idle2 -StartDue $true).Start | Should -BeFalse
        $once = Get-SIIndexBuildWindowDecision -Rows @((CsRow -Est 400 -Since $script:T0.AddDays(-7))) -NowUtc $script:T0 -NextRunUtc $script:T0 -Busy $script:Idle2 -StartDue $true
        $once.Start | Should -BeTrue; $once.Force | Should -BeTrue; $once.HoldsRun | Should -BeTrue; $once.Why | Should -Match 'built now, once, in the gap'
        (Get-SIIndexBuildWindowDecision -Rows @((CsRow -Est 400 -Since $script:T0.AddDays(-9) -Forced $script:T0.AddDays(-1))) -NowUtc $script:T0 -NextRunUtc $script:T0 -Busy $script:Idle2 -StartDue $true).Start | Should -BeFalse -Because 'the one-time build was spent'
        $r = Get-SIIndexBuildWindowDecision -Rows @((CsRow -Plain -Est 900 -Since $script:T0.AddDays(-2))) -NowUtc $script:T0 -NextRunUtc $script:T0 -Busy $script:Idle2 -StartDue $true
        $r.Start | Should -BeTrue; $r.Resumable | Should -BeTrue; $r.HoldsRun | Should -BeTrue; $r.Minutes | Should -Be 180; $r.Why | Should -Match 'it pauses there'
    }
    It 'AT MOST ONE LATE RUN A DAY per index, and never run after run when the job did not take the install' {
        $p = CsRow -Plain -State paused -Since $script:T0.AddDays(-3) -LastStart $script:T0.AddHours(-5)
        $d = Get-SIIndexBuildWindowDecision -Rows @($p) -NowUtc $script:T0 -NextRunUtc $script:T0 -Busy $script:Idle2 -StartDue $true
        $d.Start | Should -BeFalse; $d.Why | Should -Match 'at most one late run a day'
        $p.LastStartUtc = $script:T0.AddHours(-25)
        (Get-SIIndexBuildWindowDecision -Rows @($p) -NowUtc $script:T0 -NextRunUtc $script:T0 -Busy $script:Idle2 -StartDue $true).Start | Should -BeTrue
        (Get-SIIndexBuildWindowDecision -Rows @($p) -NowUtc $script:T0 -NextRunUtc $script:T0 -Busy $script:Idle2 -StartDue $true -IndexJobStartedRecently $true).Start | Should -BeFalse
        (Invoke-BusyDays -Row (CsRow) -Recent $true) | Should -BeNullOrEmpty -Because 'a recent start (or one that cannot be read) never holds a run'
    }
    It 'NEVER while an update waits or runs, the index build job runs, a data sync / data out / open step is busy, or a run runs / resumes / is asked for' {
        $old = CsRow -Since $script:T0.AddDays(-2)
        $args0 = @{ Rows = @($old); NowUtc = $script:T0; NextRunUtc = $script:T0; Busy = $script:Idle2; StartDue = $true }
        (Get-SIIndexBuildWindowDecision @args0).Start | Should -BeTrue
        (Get-SIIndexBuildWindowDecision @args0 -UpdateWaits 'update waits').Start | Should -BeFalse
        (Get-SIIndexBuildWindowDecision @args0 -UpdaterRunning 'caj-si-updater-x').Start | Should -BeFalse
        (Get-SIIndexBuildWindowDecision @args0 -IndexJobRunning 'caj-si-index-build-x').Start | Should -BeFalse
        (Get-SIIndexBuildWindowDecision @args0 -RunDue $true).Start | Should -BeFalse
        $a = @{} + $args0; $a.Busy = [pscustomobject]@{ Busy = $true; Why = 'a data sync is running' }
        (Get-SIIndexBuildWindowDecision @a).Start | Should -BeFalse
    }
    It 'the index build job''s last start: within an hour = recent; older = not; unreadable = recent (a run is never held on a guess)' {
        $ex = { param($m) [pscustomobject]@{ name = 'x'; properties = [pscustomobject]@{ startTime = $script:T0.AddMinutes(-$m).ToString('o') } } }
        Test-SIIndexBuildJobStartedRecently -Executions @((& $ex 20)) -NowUtc $script:T0 | Should -BeTrue
        Test-SIIndexBuildJobStartedRecently -Executions @((& $ex 200)) -NowUtc $script:T0 | Should -BeFalse
        Test-SIIndexBuildJobStartedRecently -Executions @([pscustomobject]@{ name = 'x'; properties = [pscustomobject]@{ startTime = $script:T0.AddMinutes(-200) } }) -NowUtc $script:T0 | Should -BeFalse
        Test-SIIndexBuildJobStartedRecently -Executions @() -NowUtc $script:T0 | Should -BeFalse
        Test-SIIndexBuildJobStartedRecently -Executions @([pscustomobject]@{ name = 'x'; properties = [pscustomobject]@{ startTime = 'not a time' } }) -NowUtc $script:T0 | Should -BeTrue
    }
    It 'WIRING: the runner passes the scheduled start (never a Run now) and the job''s last start, and a held run is a Blocked wake-up that starts no run before the drain' {
        $w = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\flow\Invoke-SIJobFlowRun.ps1'))
        $w | Should -Match ([regex]::Escape('$ixStartDue = ([string]$ixDue.Action -eq ''Start'') -and -not [bool]$pipeRequest'))
        $w | Should -Match ([regex]::Escape('-RunDue ([string]$ixDue.Action -in @(''Resume'', ''Busy'') -or [bool]$pipeRequest) -StartDue $ixStartDue -IndexJobStartedRecently $ixRecent'))
        $w | Should -Match ([regex]::Escape('$ixRecent = Test-SIIndexBuildJobStartedRecently -Executions @($ixEx.value) -NowUtc $ixNow'))
        $w | Should -Match ([regex]::Escape('if ($ixHoldsRun) { $drain = [pscustomobject]@{ Outcome = ''Blocked''; Runs = @(); Lock = [pscustomobject]@{ What = $ixHoldsRun } } }'))
        $w.IndexOf('if ($ixHoldsRun) { $drain =') | Should -BeLessThan $w.IndexOf('$drain = Invoke-SIPipelineDrain')
        $w | Should -Match 'the scheduled run starts late: index \{0\} on \{1\} is built first'
        # a Blocked drain does no upkeep and exits 0 (the run waits; nothing fails)
        $pl = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\_shared\SI-Pipeline.ps1'))
        $pl | Should -Match ([regex]::Escape("if ([string]`$Drain.Outcome -in @('Busy', 'Blocked')) { return [pscustomobject]@{ Run = `$false"))
        $w | Should -Match ([regex]::Escape("if (`$drain.Outcome -in @('Busy', 'Blocked')) {"))
    }
}

Describe 'review item 6: the gap before a run keeps its 3-hour limit, and at most one held run a day per install' {
    BeforeAll {
        $script:CsStmt6 = 'CREATE NONCLUSTERED COLUMNSTORE INDEX NCCI_Finding_Load ON sidata.Finding (CollectionId, FindingId)'
        $script:Idle6 = [pscustomobject]@{ Busy = $false; Why = '' }
        function script:Row6([int]$Est = 400, [int]$DaysAgo = 8, [string]$Name = 'NCCI_Finding_Load') {
            [pscustomobject]@{ Table = 'sidata.Finding'; Name = $Name; Statement = $script:CsStmt6; State = 'waiting'; EstMinutes = $Est; SinceUtc = $script:T0.AddDays(-$DaysAgo); ForcedUtc = $null; LastStartUtc = $null; Why = '' }
        }
    }
    It 'the forced build in the gap is CAPPED at the late limit (Minutes = 180, never 0 = no limit); the one in a true idle window still has none' {
        $g = Get-SIIndexBuildWindowDecision -Rows @((Row6)) -NowUtc $script:T0 -NextRunUtc $script:T0 -Busy $script:Idle6 -StartDue $true
        $g.Start | Should -BeTrue; $g.Force | Should -BeTrue; $g.HoldsRun | Should -BeTrue
        $g.Minutes | Should -Be (Get-SIIndexBuildContract).GapLateMinutes
        $g.Cap | Should -BeTrue
        $g.Why | Should -Match 'at most 3 h'
        $i = Get-SIIndexBuildWindowDecision -Rows @((Row6)) -NowUtc $script:T0 -NextRunUtc $script:T0.AddMinutes(90) -Busy $script:Idle6
        $i.Start | Should -BeTrue; $i.Force | Should -BeTrue; $i.HoldsRun | Should -BeFalse
        [bool]($i.PSObject.Properties['Cap'] -and $i.Cap) | Should -BeFalse -Because 'an idle window''s forced build takes as long as it needs'
    }
    It 'at most ONE held run a day for the install, whichever index asks' {
        $args6 = @{ Rows = @((Row6 -Name 'NCCI_Finding_Load')); NowUtc = $script:T0; NextRunUtc = $script:T0; Busy = $script:Idle6; StartDue = $true }
        (Get-SIIndexBuildWindowDecision @args6 -LastGapHoldUtc $script:T0.AddHours(-3)).Start | Should -BeFalse
        (Get-SIIndexBuildWindowDecision @args6 -LastGapHoldUtc $script:T0.AddHours(-3)).Why | Should -Match 'at most one late run a day'
        (Get-SIIndexBuildWindowDecision @args6 -LastGapHoldUtc $script:T0.AddHours(-25)).Start | Should -BeTrue
        (Get-SIIndexBuildWindowDecision @args6).Start | Should -BeTrue
    }
    It 'the runner reads the install''s last held run before a scheduled start, records it when it holds one, and hands the cap to the job' {
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\flow\Invoke-SIJobFlowRun.ps1'))
        $src | Should -Match '-LastGapHoldUtc \$\(if \(\$ixStartDue\) \{ Read-SIIndexBuildGapHold -Invoke \$proStore\.Invoke'
        $src | Should -Match "if \(\`$ixDec\.HoldsRun\) \{\s+\`$null = Save-SIIndexBuildGapHold"
        $src | Should -Match "SI_INDEXBUILD_CAP = "
        (Read-SIIndexBuildGapHold -Invoke { throw 'down' } -NowUtc $script:T0) | Should -Be $script:T0 -Because 'unreadable = held just now: never a second hold on a guess'
        (Read-SIIndexBuildGapHold -Invoke { '' } -NowUtc $script:T0) | Should -BeNullOrEmpty
    }
}

Describe '#1050 REAL SQL: the build command beats the lock while it runs; the row store; the pages; the sample read' -Skip:(-not $script:HasSql) {
    BeforeAll {
        $script:Db = 'si_test_ixwin_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
        $m = New-Object System.Data.SqlClient.SqlConnection "Server=$($env:SI_TEST_LOCALSQL);Database=master;$($env:SI_TEST_SQL_AUTH);Connection Timeout=30"
        $m.Open(); try { $c = $m.CreateCommand(); $c.CommandText = "CREATE DATABASE [$script:Db]"; $c.CommandTimeout = 300; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
        $script:Cs = "Server=$($env:SI_TEST_LOCALSQL);Database=$script:Db;$($env:SI_TEST_SQL_AUTH);Connection Timeout=30"
        $cs = $script:Cs
        $script:Q = {
            param([string]$sql, $p, [string]$mode)
            $cn = New-Object System.Data.SqlClient.SqlConnection($cs)
            try {
                $cn.Open(); $cmd = $cn.CreateCommand(); $cmd.CommandText = $sql; $cmd.CommandTimeout = 600
                if ($p) { foreach ($k in $p.Keys) { [void]$cmd.Parameters.AddWithValue('@' + $k, $(if ($null -eq $p[$k]) { [System.DBNull]::Value } else { $p[$k] })) } }
                if ($mode -eq 'reader') {
                    $rd = $cmd.ExecuteReader(); $out = New-Object System.Collections.Generic.List[object]
                    while ($rd.Read()) { $h = @{}; for ($i = 0; $i -lt $rd.FieldCount; $i++) { $h[$rd.GetName($i)] = $(if ($rd.IsDBNull($i)) { $null } else { $rd.GetValue($i) }) }; $out.Add($h) }
                    $rd.Close(); , $out.ToArray()
                } elseif ($mode -eq 'scalar') { $cmd.ExecuteScalar() } else { [void]$cmd.ExecuteNonQuery() }
            } finally { $cn.Dispose() }
        }.GetNewClosure()
        # the settings schema's two tables this needs, exactly as shipped (cfg.InstallState and cfg.IndexBuild)
        $set = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'sql\si-pro-settings.sql'))
        & $script:Q "IF SCHEMA_ID('cfg') IS NULL EXEC (N'CREATE SCHEMA cfg'); IF SCHEMA_ID('sidata') IS NULL EXEC (N'CREATE SCHEMA sidata');" @{} 'nonquery'
        foreach ($t in 'cfg.InstallState', 'cfg.IndexBuild') {
            $mm = [regex]::Match($set, "(?s)IF OBJECT_ID\('" + [regex]::Escape($t) + "'\) IS NULL\s+CREATE TABLE .*?\n\);")
            if (-not $mm.Success) { throw "$t not found in the shipped settings schema" }
            & $script:Q $mm.Value @{} 'nonquery'
        }
        & $script:Q "CREATE TABLE sidata.Finding (CollectionId int NOT NULL, FindingId bigint NOT NULL, RaFindingKey nvarchar(900) NULL, Pad char(200) NOT NULL, CONSTRAINT PK_Finding PRIMARY KEY CLUSTERED (CollectionId, FindingId));
INSERT sidata.Finding (CollectionId, FindingId, RaFindingKey, Pad) SELECT TOP (20000) 1 + (n % 3), n, CASE WHEN n % 4 = 0 THEN CONCAT(N'k', n) END, 'x'
FROM (SELECT ROW_NUMBER() OVER (ORDER BY (SELECT NULL)) AS n FROM sys.all_objects a CROSS JOIN sys.all_objects b) AS x;" @{} 'nonquery'
    }
    AfterAll {
        [System.Data.SqlClient.SqlConnection]::ClearAllPools()
        $m = New-Object System.Data.SqlClient.SqlConnection "Server=$($env:SI_TEST_LOCALSQL);Database=master;$($env:SI_TEST_SQL_AUTH);Connection Timeout=30"
        $m.Open(); try { $c = $m.CreateCommand(); $c.CommandTimeout = 300; $c.CommandText = "ALTER DATABASE [$script:Db] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$script:Db]"; [void]$c.ExecuteNonQuery() } catch { } finally { $m.Dispose() }
    }
    It 'the build command calls the beat WHILE the statement runs, and returns its seconds' {
        $cn = New-Object System.Data.SqlClient.SqlConnection $script:Cs; $cn.Open()
        try {
            $beats = New-Object System.Collections.Generic.List[int]
            $secs = Invoke-SIIndexBuildCommand -Connection $cn -Sql "WAITFOR DELAY '00:00:04'; CREATE INDEX IX_Finding_RaFindingKey ON sidata.Finding (CollectionId) WHERE RaFindingKey IS NOT NULL;" -Beat { param($m) $beats.Add($m) }.GetNewClosure() -BeatSeconds 1
            $beats.Count | Should -BeGreaterOrEqual 3 -Because 'a 4-second statement with a 1-second beat'
            $secs | Should -BeGreaterOrEqual 4
        } finally { $cn.Dispose() }
        [int](& $script:Q "SELECT COUNT(*) FROM sys.indexes WHERE name = N'IX_Finding_RaFindingKey' AND has_filter = 1" @{} 'scalar') | Should -Be 1
    }
    It 'a failing statement throws the SQL error itself (not a wrapper)' {
        $cn = New-Object System.Data.SqlClient.SqlConnection $script:Cs; $cn.Open()
        try { { Invoke-SIIndexBuildCommand -Connection $cn -Sql 'CREATE INDEX IX_Bad ON sidata.NoSuchTable (x);' -BeatSeconds 1 } | Should -Throw -ExpectedMessage '*NoSuchTable*' } finally { $cn.Dispose() }
    }
    It 'the pages of a table (catalog views only) and a timed sample read of it' {
        $pg = Get-SIIndexTablePages -Invoke $script:Q -Table 'sidata.Finding'
        $pg.Rows | Should -Be 20000; $pg.Pages | Should -BeGreaterThan 400
        (Measure-SIIndexReadRate -Invoke $script:Q -Table 'sidata.Finding' -Pages $pg.Pages) | Should -BeGreaterThan 0
        $e = & (New-SIIndexBuildEstimator -Invoke $script:Q) ([pscustomobject]@{ Name = 'IX_X'; Table = 'sidata.Finding' })
        $e.Known | Should -BeTrue; $e.Source | Should -Match 'sample read'; $e.Minutes | Should -Be 1
    }
    It 'the row store: waiting keeps its first time across updates; building / built / waiting again; the rate row' {
        Save-SIIndexBuildRow -Invoke $script:Q -Table 'sidata.Finding' -Index 'IX_W' -State waiting -Statement 'CREATE INDEX IX_W ON sidata.Finding (CollectionId) WHERE RaFindingKey IS NOT NULL WITH (ONLINE = ON)' -Pages 11500000 -EstMinutes 195 -Source 'measured' -Why 'not built in this update' | Should -BeTrue
        $first = @(Read-SIIndexBuildRows -Invoke $script:Q | Where-Object Name -eq 'IX_W')[0]
        Start-Sleep -Seconds 1
        Save-SIIndexBuildRow -Invoke $script:Q -Table 'sidata.Finding' -Index 'IX_W' -State waiting -Why 'still not' | Should -BeTrue
        $again = @(Read-SIIndexBuildRows -Invoke $script:Q | Where-Object Name -eq 'IX_W')[0]
        $again.SinceUtc | Should -Be $first.SinceUtc -Because 'the 7 days count from the FIRST wait'
        $again.Statement | Should -Match 'WITH \(ONLINE = ON\)' -Because 'a later save without a statement keeps it'
        Save-SIIndexBuildRow -Invoke $script:Q -Table 'sidata.Finding' -Index 'IX_W' -State building -Forced | Should -BeTrue
        $b = @(Read-SIIndexBuildRows -Invoke $script:Q | Where-Object Name -eq 'IX_W')[0]
        $b.State | Should -Be 'building'; $b.ForcedUtc | Should -Not -BeNullOrEmpty; $b.LastStartUtc | Should -Not -BeNullOrEmpty
        Save-SIIndexBuildRow -Invoke $script:Q -Table 'sidata.Finding' -Index 'IX_W' -State waiting -Why 'failed' | Out-Null
        @(Read-SIIndexBuildRows -Invoke $script:Q | Where-Object Name -eq 'IX_W')[0].SinceUtc | Should -Be $first.SinceUtc -Because 'a failed window build does not restart the 7 days'
        Add-SIIndexBuildRateSample -Invoke $script:Q -Pages 11500000 -Seconds 7700 | Should -BeTrue
        Add-SIIndexBuildRateSample -Invoke $script:Q -Pages 100 -Seconds 2 | Should -BeFalse -Because 'too short to measure'
        @(Read-SIIndexBuildRate -Invoke $script:Q).Count | Should -Be 1
    }
    It '#1111 the row store: paused keeps the first wait time and records the end; the status says it resumes' {
        Save-SIIndexBuildRow -Invoke $script:Q -Table 'sidata.Finding' -Index 'IX_P' -State waiting -Statement 'CREATE INDEX IX_P ON sidata.Finding (CollectionId, FindingId)' -Why 'not built in this update' | Should -BeTrue
        $first = @(Read-SIIndexBuildRows -Invoke $script:Q | Where-Object Name -eq 'IX_P')[0]
        Save-SIIndexBuildRow -Invoke $script:Q -Table 'sidata.Finding' -Index 'IX_P' -State building -By 'caj-si-index-build' | Should -BeTrue
        Save-SIIndexBuildRow -Invoke $script:Q -Table 'sidata.Finding' -Index 'IX_P' -State paused -Why 'paused at 40% -- the updater runs (x1); the update went first' -By 'caj-si-index-build' | Should -BeTrue
        $p = @(Read-SIIndexBuildRows -Invoke $script:Q | Where-Object Name -eq 'IX_P')[0]
        $p.State | Should -Be 'paused'; $p.SinceUtc | Should -Be $first.SinceUtc; $p.LastEndUtc | Should -Not -BeNullOrEmpty
        $p.Statement | Should -Be 'CREATE INDEX IX_P ON sidata.Finding (CollectionId, FindingId)'
        @(Get-SIIndexBuildStatusLines -Rows @($p))[0] | Should -Match 'IX_P on sidata\.Finding: paused \(paused at 40% -- the updater runs'
    }
    It '#1111 the build command: an INTERRUPT (an update goes first) cancels a running statement at the next check and throws the reason -- the statement never runs on' {
        $cn = New-Object System.Data.SqlClient.SqlConnection $script:Cs; $cn.Open()
        $asked = New-Object System.Collections.Generic.List[int]
        $sw = [Diagnostics.Stopwatch]::StartNew()
        try {
            $err = $null
            try { $null = Invoke-SIIndexBuildCommand -Connection $cn -Sql "WAITFOR DELAY '00:01:00'; CREATE INDEX IX_Interrupted ON sidata.Finding (FindingId);" -BeatSeconds 1 -DrainSeconds 30 `
                    -Interrupt { param($m) $asked.Add($m); if ($asked.Count -ge 2) { 'the updater runs (caj-si-updater-x9)' } else { '' } }.GetNewClosure() }
            catch { $err = $_.Exception }
            $sw.Stop()
            $err | Should -Not -BeNullOrEmpty
            $err | Should -BeOfType ([System.OperationCanceledException])
            $err.Data['SIInterrupted'] | Should -Be 'the updater runs (caj-si-updater-x9)'
            $sw.Elapsed.TotalSeconds | Should -BeLessThan 30 -Because 'cancelled at the second check, not after the minute'
        } finally { $cn.Dispose() }
        Test-SIIndexExists -Invoke $script:Q -Table 'sidata.Finding' -Index 'IX_Interrupted' | Should -BeFalse
        Test-SIIndexExists -Invoke $script:Q -Table 'sidata.Finding' -Index 'IX_Finding_RaFindingKey' | Should -BeTrue
        Read-SIIndexResumableOp -Invoke $script:Q -Table 'sidata.Finding' -Index 'IX_Interrupted' | Should -BeNullOrEmpty -Because 'no resumable operation exists for it'
    }
}

Describe '#1050 SCALE: a filtered index on ~20 M rows -- the estimate against the real build (ON DEMAND ONLY)' -Tag 'Scale' -Skip:(-not $script:HasSql) {
    # Owner 2026-11-01: run ONCE on the VM for the #1050 proof; never in a gate (the tag Scale is left out by every gate).
    # SQL Express: no ONLINE builds and a 1.4 GB buffer pool -- the build reads its pages from storage, as the live one did.
    BeforeAll {
        $script:SDb = 'si_test_ixscale_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
        $m = New-Object System.Data.SqlClient.SqlConnection "Server=$($env:SI_TEST_LOCALSQL);Database=master;$($env:SI_TEST_SQL_AUTH);Connection Timeout=30"
        $m.Open(); try { $c = $m.CreateCommand(); $c.CommandText = "CREATE DATABASE [$script:SDb]; ALTER DATABASE [$script:SDb] SET RECOVERY SIMPLE;"; $c.CommandTimeout = 600; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
        $cs = "Server=$($env:SI_TEST_LOCALSQL);Database=$script:SDb;$($env:SI_TEST_SQL_AUTH);Connection Timeout=30"
        $script:SCs = $cs
        $script:SQ = {
            param([string]$sql, $p, [string]$mode)
            $cn = New-Object System.Data.SqlClient.SqlConnection($cs)
            try {
                $cn.Open(); $cmd = $cn.CreateCommand(); $cmd.CommandText = $sql; $cmd.CommandTimeout = 0
                if ($p) { foreach ($k in $p.Keys) { [void]$cmd.Parameters.AddWithValue('@' + $k, $(if ($null -eq $p[$k]) { [System.DBNull]::Value } else { $p[$k] })) } }
                if ($mode -eq 'reader') {
                    $rd = $cmd.ExecuteReader(); $out = New-Object System.Collections.Generic.List[object]
                    while ($rd.Read()) { $h = @{}; for ($i = 0; $i -lt $rd.FieldCount; $i++) { $h[$rd.GetName($i)] = $(if ($rd.IsDBNull($i)) { $null } else { $rd.GetValue($i) }) }; $out.Add($h) }
                    $rd.Close(); , $out.ToArray()
                } elseif ($mode -eq 'scalar') { $cmd.ExecuteScalar() } else { [void]$cmd.ExecuteNonQuery() }
            } finally { $cn.Dispose() }
        }.GetNewClosure()
        & $script:SQ "CREATE SCHEMA sidata;" @{} 'nonquery'
        & $script:SQ "CREATE TABLE sidata.Finding (CollectionId int NOT NULL, FindingId bigint NOT NULL, RaFindingKey nvarchar(900) NULL, Severity tinyint NOT NULL, AssetKey nvarchar(100) NOT NULL, Pad char(60) NOT NULL, CONSTRAINT PK_Finding PRIMARY KEY CLUSTERED (CollectionId, FindingId));" @{} 'nonquery'
        # ~20 M rows in 20 slices of 1 M (one collection each; a quarter of the rows keyed, as an RA collection is)
        $sw = [Diagnostics.Stopwatch]::StartNew()
        for ($c = 1; $c -le 20; $c++) {
            & $script:SQ ("INSERT sidata.Finding WITH (TABLOCK) (CollectionId, FindingId, RaFindingKey, Severity, AssetKey, Pad)
SELECT {0}, n, CASE WHEN n % 4 = 0 THEN CONCAT(N'ra-', {0}, N'-', n) END, CAST(n % 5 AS tinyint), CONCAT(N'asset-', n % 50000), 'x'
FROM (SELECT TOP (1000000) ROW_NUMBER() OVER (ORDER BY (SELECT NULL)) AS n FROM sys.all_objects a CROSS JOIN sys.all_objects b CROSS JOIN sys.all_objects c) AS x;" -f $c) @{} 'nonquery'
        }
        $script:LoadSeconds = $sw.Elapsed.TotalSeconds
        & $script:SQ "CHECKPOINT; DBCC DROPCLEANBUFFERS;" @{} 'nonquery'
    }
    AfterAll {
        [System.Data.SqlClient.SqlConnection]::ClearAllPools()
        $m = New-Object System.Data.SqlClient.SqlConnection "Server=$($env:SI_TEST_LOCALSQL);Database=master;$($env:SI_TEST_SQL_AUTH);Connection Timeout=30"
        $m.Open(); try { $c = $m.CreateCommand(); $c.CommandTimeout = 600; $c.CommandText = "ALTER DATABASE [$script:SDb] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$script:SDb]"; [void]$c.ExecuteNonQuery() } catch { } finally { $m.Dispose() }
    }
    It 'measures: rows, pages, the sample-read estimate, the real filtered build, and the measured rate (written to the log)' {
        $pg = Get-SIIndexTablePages -Invoke $script:SQ -Table 'sidata.Finding'
        $pg.Rows | Should -Be 20000000
        $est = & (New-SIIndexBuildEstimator -Invoke $script:SQ) ([pscustomobject]@{ Name = 'IX_Finding_RaFindingKey'; Table = 'sidata.Finding' })
        & $script:SQ "CHECKPOINT; DBCC DROPCLEANBUFFERS;" @{} 'nonquery'
        $cn = New-Object System.Data.SqlClient.SqlConnection $script:SCs; $cn.Open()
        $beats = New-Object System.Collections.Generic.List[int]
        try { $secs = Invoke-SIIndexBuildCommand -Connection $cn -Sql 'CREATE INDEX IX_Finding_RaFindingKey ON sidata.Finding (CollectionId) WHERE RaFindingKey IS NOT NULL;' -Beat { param($m) $beats.Add($m) }.GetNewClosure() } finally { $cn.Dispose() }
        $pps = $pg.Pages / $secs
        $rate = Get-SIIndexBuildRate -Samples @([pscustomobject]@{ Pps = $pps })
        $line = 'SCALE #1050: rows {0:N0}; pages {1:N0}; load {2:N0} s; estimate (sample read) {3} min via {4}; real filtered build {5:N1} s ({6:N0} pages/s); beats {7}; estimate from this build x1.5 = {8} min' -f `
            $pg.Rows, $pg.Pages, $script:LoadSeconds, $est.Minutes, $est.Source, $secs, $pps, $beats.Count, (Get-SIIndexBuildEstimate -Pages $pg.Pages -Rate $rate).Minutes
        Write-Host $line
        [IO.File]::WriteAllText((Join-Path ([IO.Path]::GetTempPath()) 'si-1050-scale.txt'), $line)
        $est.Known | Should -BeTrue
        ($est.Minutes * 60) | Should -BeGreaterOrEqual ($secs * 0.5) -Because 'the cold-start estimate must not promise far less than the build takes'
        $beats.Count | Should -BeGreaterOrEqual ([int][Math]::Floor($secs / 30) - 1) -Because 'the lock is beaten every 30 s through the whole build'
    }
}
