#Requires -Version 5.1
<#
    #1111 THE INDEX BUILD IS ITS OWN JOB; THE UPDATER ONLY UPDATES -- AN INSTALL NEVER STOPS GETTING UPDATES (owner 2026-11-05:
    "why not split this into 2 jobs, seems like bad design" / "we cannot have env that doesnt upd suddently").
    Live at a ring-2 install: the pipeline runner's idle wake-up started caj-si-updater in an index-build mode every 5 minutes,
    the stop tool waited for that execution and installed nothing, and each index-build run ended within seconds with no
    outcome line. What must hold:
      * the job caj-si-index-build (engine\index-build\SI-IndexBuildJob.ps1): builds ONE waiting / paused index; a resumable
        one ONLINE + RESUMABLE with the window's MAX_DURATION, a paused one RESUMED, a filtered one only when it fits;
      * THE UPDATE ALWAYS GOES FIRST: before each step and at every check while it builds -- the updater's wait mark, a running
        updater execution, the install's lock taken by the updater -- the build is PAUSED (resumable) or cancelled (filtered),
        the row says so, the lock is freed, the job ends;
      * EVERY RUN ENDS WITH ONE OUTCOME: an error anywhere, or the run being stopped from outside (proven with a flow-control
        exit that skips every catch -- the way the old run left "the lock is released" with no outcome), still logs the
        outcome, sets the row back and ends with INDEX-BUILD outcome=...;
      * the updater has NO index-build mode any more and takes the job's lock at once (its run gate's TakeFrom); the stop
        tool never counts the job as a step or as the updater;
      * every install gets the job from the updater (made, kept, read back -- as the updater's own identity), the container
        dispatches SI_ROLE = index-build to the job's entry, the runner starts THIS job (never the updater).
    Stubs in SCRIPT scope; REAL SQL (the test VM's SQL Express) for the lock take-over.
#>

BeforeDiscovery {
    try { $script:HasSql = (Get-Service -Name 'MSSQL$SQLEXPRESS' -ErrorAction Stop).Status -eq 'Running' -and $null -ne ('System.Data.SqlClient.SqlConnection' -as [type]) } catch { $script:HasSql = $false }
}

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\_shared\SI-IndexBuild.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-UpdaterStart.ps1')
    . (Join-Path $script:SIRoot 'setup\_shared\SI-DbInitJob.ps1')
    . (Join-Path $script:SIRoot 'container\updater\_shared\SI-UpdaterRunGate.ps1')
    . (Join-Path $script:SIRoot 'engine\index-build\SI-IndexBuildJob.ps1')
    $script:T0 = [datetime]::SpecifyKind([datetime]'2026-11-05T10:00:00', 'Utc')
    $script:Filtered = 'CREATE INDEX IX_Finding_RaFindingKey ON sidata.Finding (CollectionId) WHERE RaFindingKey IS NOT NULL WITH (ONLINE = ON)'
    $script:Plain = 'CREATE INDEX IX_Finding_Category ON sidata.Finding (CollectionId, Category) WITH (ONLINE = ON, RESUMABLE = ON, MAX_DURATION = 10 MINUTES)'

    # ONE fake install around the job: the row, the update signals, the lock, the database's answers, the build
    function script:New-W {
        param([string]$State = 'waiting', [switch]$Plain, [int]$Est = 60, [int]$DaysAgo = 1, [string[]]$Update = @(), [int]$Checks = 0)
        $name = if ($Plain) { 'IX_Finding_Category' } else { 'IX_Finding_RaFindingKey' }
        $w = [pscustomobject]@{
            Row = [pscustomobject]@{ Table = 'sidata.Finding'; Name = $name; Statement = $(if ($Plain) { $script:Plain } else { $script:Filtered }); State = $State
                                     Pages = 11500000; EstMinutes = $Est; Source = 'x'; Why = ''; SinceUtc = $script:T0.AddDays(-$DaysAgo); LastStartUtc = $null; LastEndUtc = $null; ForcedUtc = $null }
            Saves = (New-Object System.Collections.Generic.List[string]); Whys = (New-Object System.Collections.Generic.List[string]); Log = (New-Object System.Collections.Generic.List[string])
            Update = @($Update); UpdateCalls = 0; Checks = $Checks; Go = $true; Held = $true; Gate = 0; Exit = 0; Built = $null; Paused = $null
            Exists = $false; ExistsAfter = $true; Op = $null; OpAfter = $null; BuildThrows = $null; Rate = 0; Break = $false; ExistsThrowsAfter = $false
        }
        $s = @{
            Rows         = { , @($w.Row) }.GetNewClosure()
            Save         = { param($t, $i, $st, $why, $f) $w.Saves.Add(('{0}{1}' -f $st, $(if ($f) { '+forced' } else { '' }))); $w.Whys.Add([string]$why); $true }.GetNewClosure()
            UpdateFirst  = { $w.UpdateCalls++; if ($w.UpdateCalls -le @($w.Update).Count) { [string]@($w.Update)[$w.UpdateCalls - 1] } else { '' } }.GetNewClosure()
            OtherRunning = { '' }
            Gate         = { param($h) $w.Gate++; [pscustomobject]@{ Go = $w.Go; Reason = $(if ($w.Go) { 'no pipeline run is going' } else { 'update waits: run 42 is running' }); LockTaken = $w.Go } }.GetNewClosure()
            Beat         = { param($h, $what) $w.Held }.GetNewClosure()
            ExitGate     = { param($h) $w.Exit++ }.GetNewClosure()
            Exists       = { param($t, $i) if ($null -ne $w.Built) { if ($w.ExistsThrowsAfter) { throw 'the connection was reset' }; $w.ExistsAfter } else { $w.Exists } }.GetNewClosure()
            ResumableOp  = { param($t, $i) if ($null -ne $w.Built) { $w.OpAfter } else { $w.Op } }.GetNewClosure()
            Build        = {
                param($sql, $interrupt, $onInterrupt)
                $w.Built = $sql
                if ($w.Break) { break }
                if ($w.BuildThrows) { throw $w.BuildThrows }
                for ($k = 1; $k -le $w.Checks; $k++) {
                    $r = [string](& $interrupt $k)
                    if ($r.Trim()) { & $onInterrupt $null $r; $x = New-Object System.OperationCanceledException 'interrupted'; $x.Data['SIInterrupted'] = $r; throw $x }
                }
                7700.0
            }.GetNewClosure()
            Pause        = { param($sql) $w.Paused = $sql }.GetNewClosure()
            Rate         = { param($t, $secs) $w.Rate++ }.GetNewClosure()
        }
        $w | Add-Member -NotePropertyName Seams -NotePropertyValue $s
        $w
    }
    function script:Invoke-Job {
        param($W, $Request)
        if (-not $Request) { $Request = [pscustomobject]@{ Table = ''; Index = ''; Minutes = 75; Force = $false } }
        $lg = $W.Log
        Invoke-SIIndexBuildJob -Store ([pscustomobject]@{ Invoke = { throw 'no database in this test' } }) -Holder 'caj-si-index-build:e1' -Request $Request -Seams $W.Seams -Log { param($m) $lg.Add($m) }.GetNewClosure() -NowUtc $script:T0
    }
}

Describe '#1111 the index build job: one index, the right statement, one outcome' {
    It 'a waiting FILTERED index is built from its statement under the install''s lock: built, the rate recorded, the lock released, ONE outcome line' {
        $w = New-W
        $r = Invoke-Job $w
        $r.Outcome | Should -Be 'built'; $r.ExitCode | Should -Be 0
        $w.Built | Should -Be $script:Filtered -Because 'a filtered index cannot pause: ONLINE only'
        @($w.Saves) | Should -Be @('building', 'built')
        $w.Gate | Should -Be 1; $w.Exit | Should -Be 1; $w.Rate | Should -Be 1
        $t = $w.Log -join "`n"
        $t | Should -Match 'index build: IX_Finding_RaFindingKey on sidata\.Finding -- built online \(a filtered index cannot pause\) now in an idle window \(about 1 h\)'
        $t | Should -Match 'IX_Finding_RaFindingKey on sidata\.Finding built in 2 h 9 min \(estimated about 1 h\)'
        $w.Log[$w.Log.Count - 1] | Should -Be 'INDEX-BUILD outcome=built index=sidata.Finding/IX_Finding_RaFindingKey'
        @($w.Log | Where-Object { $_ -match '^INDEX-BUILD ' }).Count | Should -Be 1
    }
    It 'an index WITHOUT a filter is built ONLINE + RESUMABLE with the window as MAX_DURATION (its old WITH replaced)' {
        $w = New-W -Plain
        $r = Invoke-Job $w
        $w.Built | Should -Be 'CREATE INDEX IX_Finding_Category ON sidata.Finding (CollectionId, Category) WITH (ONLINE = ON, RESUMABLE = ON, MAX_DURATION = 75 MINUTES)'
        $r.Outcome | Should -Be 'built'
    }
    It 'a PAUSED build is RESUMED (never created again); a resumed build does not count as a measured rate' {
        $w = New-W -State paused -Plain; $w.Op = [pscustomobject]@{ State = 'PAUSED'; Percent = 40 }
        $r = Invoke-Job $w
        $w.Built | Should -Be 'ALTER INDEX [IX_Finding_Category] ON [sidata].[Finding] RESUME WITH (MAX_DURATION = 75 MINUTES)'
        $r.Outcome | Should -Be 'built'; $w.Rate | Should -Be 0
    }
    It 'no run scheduled (window 0): a resumable build gets a day as its MAX_DURATION' {
        $w = New-W -Plain
        $null = Invoke-Job $w ([pscustomobject]@{ Table = ''; Index = ''; Minutes = 0; Force = $false })
        $w.Built | Should -Match 'MAX_DURATION = 1440 MINUTES'
    }
    It 'the window''s end: a resumable build that paused at its MAX_DURATION is recorded paused -- progress, not a failure' {
        $w = New-W -Plain; $w.ExistsAfter = $false; $w.OpAfter = [pscustomobject]@{ State = 'PAUSED'; Percent = 70 }
        $r = Invoke-Job $w
        $r.Outcome | Should -Be 'paused'; $r.ExitCode | Should -Be 0
        @($w.Saves) | Should -Be @('building', 'paused')
        $w.Whys[1] | Should -Be 'paused at 70% at the end of its window'
    }
    It 'a filtered index whose estimate is longer than the window waits (not started) -- unless it is the one-time build after 7 days' {
        $w = New-W -Est 200
        $r = Invoke-Job $w
        $r.Outcome | Should -Be 'not-now'; $w.Built | Should -BeNullOrEmpty; @($w.Saves).Count | Should -Be 0; $w.Exit | Should -Be 1
        ($w.Log -join ' ') | Should -Match 'about 3 h 20 min, more than the 1 h 15 min before the next run'
        $f = New-W -Est 200 -DaysAgo 8
        $rf = Invoke-Job $f
        $rf.Outcome | Should -Be 'built'; @($f.Saves)[0] | Should -Be 'building+forced'
        ($f.Log -join ' ') | Should -Match 'waited 7 days without an idle window long enough, so it is built now, once -- the next pipeline run waits for it'
    }
    It 'an index already there is only recorded; nothing waits = nothing done (the lock is not even asked for)' {
        $w = New-W; $w.Exists = $true
        (Invoke-Job $w).Outcome | Should -Be 'built'; $w.Built | Should -BeNullOrEmpty; @($w.Saves) | Should -Be @('built')
        $n = New-W -State built
        $rn = Invoke-Job $n
        $rn.Outcome | Should -Be 'nothing'; $n.Gate | Should -Be 0
        $n.Log[$n.Log.Count - 1] | Should -Be 'INDEX-BUILD outcome=nothing index=none'
    }
    It 'the runner''s choice is built when it still waits; else the one that waited longest' {
        $rows = @([pscustomobject]@{ Table = 'sidata.A'; Name = 'IX_A'; Statement = 'CREATE INDEX IX_A ON sidata.A (x)'; State = 'waiting'; SinceUtc = $script:T0.AddDays(-1) },
                  [pscustomobject]@{ Table = 'sidata.B'; Name = 'IX_B'; Statement = 'CREATE INDEX IX_B ON sidata.B (x)'; State = 'paused'; SinceUtc = $script:T0.AddDays(-3) },
                  [pscustomobject]@{ Table = 'sidata.C'; Name = 'IX_C'; Statement = 'CREATE INDEX IX_C ON sidata.C (x)'; State = 'built'; SinceUtc = $script:T0.AddDays(-9) })
        (Select-SIIndexBuildJobRow -Rows $rows -Table 'sidata.A' -Index 'IX_A').Name | Should -Be 'IX_A'
        (Select-SIIndexBuildJobRow -Rows $rows).Name | Should -Be 'IX_B'
        (Select-SIIndexBuildJobRow -Rows $rows -Table 'sidata.C' -Index 'IX_C').Name | Should -Be 'IX_B' -Because 'a built index is never built again'
    }
}

Describe '#1111 THE UPDATE ALWAYS GOES FIRST' {
    It 'an update waits (the wait mark) or runs BEFORE the job starts: nothing taken, nothing built, said plainly' {
        $w = New-W -Update @('an update waits to install (the updater''s wait mark: update waits: run r-1 is running)')
        $r = Invoke-Job $w
        $r.Outcome | Should -Be 'not-now'; $r.ExitCode | Should -Be 0
        $w.Gate | Should -Be 0; $w.Built | Should -BeNullOrEmpty; @($w.Saves).Count | Should -Be 0
        ($w.Log -join ' ') | Should -Match 'not now -- an update waits to install .*; the update goes first, IX_Finding_RaFindingKey waits for the next idle window'
    }
    It 'an update that starts between the first look and the lock: the lock is given back at once, nothing built' {
        $w = New-W -Update @('', 'the updater runs (caj-si-updater-k1)')
        (Invoke-Job $w).Outcome | Should -Be 'not-now'
        $w.Gate | Should -Be 1; $w.Exit | Should -Be 1; $w.Built | Should -BeNullOrEmpty
    }
    It 'an update while a RESUMABLE build runs: the build is PAUSED (ALTER INDEX ... PAUSE), the row says paused, the lock is freed, the job ends' {
        $w = New-W -Plain -Update @('', '', '', 'the updater runs (caj-si-updater-k2)') -Checks 5
        $w.ExistsAfter = $false; $w.OpAfter = [pscustomobject]@{ State = 'PAUSED'; Percent = 40 }
        $r = Invoke-Job $w
        $w.Paused | Should -Be 'ALTER INDEX [IX_Finding_Category] ON [sidata].[Finding] PAUSE'
        $r.Outcome | Should -Be 'paused'; $r.ExitCode | Should -Be 0
        @($w.Saves) | Should -Be @('building', 'paused')
        $w.Whys[1] | Should -Be 'paused at 40% -- the updater runs (caj-si-updater-k2); the update went first'
        $w.Exit | Should -Be 1
        ($w.Log -join "`n") | Should -Match 'it resumes in the next idle window'
    }
    It 'the updater TOOK the install''s lock while it builds (the beat finds it gone): paused just the same' {
        $w = New-W -Plain -Checks 3; $w.Held = $false
        $w.ExistsAfter = $false; $w.OpAfter = [pscustomobject]@{ State = 'PAUSED'; Percent = 12 }
        $r = Invoke-Job $w
        $r.Outcome | Should -Be 'paused'; $w.Paused | Should -Match ' PAUSE$'
        $w.Whys[1] | Should -Match 'the updater took the install''s lock'
    }
    It 'an update while a FILTERED build runs: it cannot pause, so it is cancelled and waits again -- the update never waits for it' {
        $w = New-W -Update @('', '', 'an update waits to install (the updater''s wait mark)') -Checks 3
        $w.ExistsAfter = $false
        $r = Invoke-Job $w
        $w.Paused | Should -BeNullOrEmpty
        $r.Outcome | Should -Be 'waiting'; @($w.Saves) | Should -Be @('building', 'waiting')
        $w.Whys[1] | Should -Match 'stopped for an update .* a filtered index cannot pause, so it was cancelled'
        $w.Exit | Should -Be 1
    }
    It 'what "an update goes first" reads: the wait mark on the updater job, a running updater execution -- else nothing' {
        $tag = ConvertTo-SIUpdateWaitsTag -SinceUtc $script:T0 -SetUtc $script:T0 -Kind run -Reason 'update waits: run r-7 is running'
        $job = [pscustomobject]@{ tags = [pscustomobject]@{ 'si-update-waits' = $tag } }
        Get-SIIndexBuildUpdateFirst -Job $job -Executions @() -NowUtc $script:T0 | Should -Match 'an update waits to install .*run r-7 is running'
        $run = [pscustomobject]@{ name = 'caj-si-updater-u9'; properties = [pscustomobject]@{ status = 'Running'; startTime = $script:T0.AddMinutes(-3).ToString('o') } }
        Get-SIIndexBuildUpdateFirst -Job ([pscustomobject]@{ tags = [pscustomobject]@{} }) -Executions @($run) -NowUtc $script:T0 | Should -Be 'the updater runs (caj-si-updater-u9)'
        Get-SIIndexBuildUpdateFirst -Job ([pscustomobject]@{ tags = [pscustomobject]@{ 'si-update-waits' = '' } }) -Executions @() -NowUtc $script:T0 | Should -Be ''
    }
    It 'no update check wired = not now (the job never builds blind)' {
        $w = New-W; $w.Seams.Remove('UpdateFirst')
        (Invoke-Job $w).Outcome | Should -Be 'not-now'; $w.Gate | Should -Be 0
    }
}

Describe '#1111 the build that "ended in seconds": every run ends with ONE outcome' {
    It 'an error OUTSIDE the build call (reading the result back) is caught: the outcome says where, the row waits again, the lock is released' {
        $w = New-W; $w.ExistsThrowsAfter = $true
        $r = Invoke-Job $w
        $r.Outcome | Should -Be 'failed'; $r.ExitCode | Should -Be 1
        @($w.Saves) | Should -Be @('building', 'waiting')
        ($w.Log -join "`n") | Should -Match 'WARNING: the index build failed at "read back" \(the connection was reset\)'
        $w.Exit | Should -Be 1
        $w.Log[$w.Log.Count - 1] | Should -Be 'INDEX-BUILD outcome=failed index=sidata.Finding/IX_Finding_RaFindingKey'
    }
    It 'a failed build waits again (a warning) and says why' {
        $w = New-W; $w.BuildThrows = 'Could not allocate space for object'; $w.ExistsAfter = $false
        $r = Invoke-Job $w
        $r.Outcome | Should -Be 'failed'; @($w.Saves) | Should -Be @('building', 'waiting')
        ($w.Log -join ' ') | Should -Match 'WARNING: IX_Finding_RaFindingKey on sidata\.Finding: the build in an idle window failed \(Could not allocate space'
    }
    It 'STOPPED FROM OUTSIDE (a flow-control exit that no catch sees -- what left the old run at "the lock is released" with no outcome): the finally still logs the outcome, sets the row back and releases the lock' {
        $w = New-W; $w.Break = $true
        foreach ($once in 1) { $null = Invoke-Job $w }
        $t = $w.Log -join "`n"
        $t | Should -Match 'WARNING: the run ended at "build" without an outcome \(the job was stopped\) -- the index row is set back to waiting, the next idle window builds it again'
        @($w.Saves) | Should -Be @('building', 'waiting')
        $w.Exit | Should -Be 1
        $t | Should -Match 'the install''s lock is released'
        $w.Log[$w.Log.Count - 1] | Should -Be 'INDEX-BUILD outcome=stopped index=sidata.Finding/IX_Finding_RaFindingKey'
    }
    It 'STATIC: the job''s steps run in one inner block inside try / catch / finally, so a step''s return never skips the outcome' {
        $f = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\index-build\SI-IndexBuildJob.ps1'))
        $f | Should -Match ([regex]::Escape('try { $null = & {'))
        $f | Should -Match ([regex]::Escape("('INDEX-BUILD outcome={0} index={1}' -f `$siIxJobCtx.Outcome, `$ixName)"))
    }
}

Describe '#1111 the statements: pure' {
    It 'the run statement: RESUME a paused one, CREATE resumable, a filtered one ONLINE only; unsafe names or a second statement = nothing' {
        $row = [pscustomobject]@{ Table = 'sidata.Finding'; Name = 'IX_P'; Statement = 'CREATE INDEX IX_P ON sidata.Finding (CollectionId) INCLUDE (AssetKey);' }
        (Get-SIIndexBuildRunSql -Row $row -Minutes 30).Sql | Should -Be 'CREATE INDEX IX_P ON sidata.Finding (CollectionId) INCLUDE (AssetKey) WITH (ONLINE = ON, RESUMABLE = ON, MAX_DURATION = 30 MINUTES)'
        (Get-SIIndexBuildRunSql -Row $row -ResumableState 'PAUSED' -Minutes 0).Sql | Should -Be 'ALTER INDEX [IX_P] ON [sidata].[Finding] RESUME WITH (MAX_DURATION = 1 MINUTES)'
        $fr = [pscustomobject]@{ Table = 'sidata.Finding'; Name = 'IX_Finding_RaFindingKey'; Statement = $script:Filtered }
        $f = Get-SIIndexBuildRunSql -Row $fr -Minutes 30
        $f.Sql | Should -Be $script:Filtered; $f.Resumable | Should -BeFalse
        (Get-SIIndexBuildRunSql -Row ([pscustomobject]@{ Table = 'sidata.Finding;DROP'; Name = 'IX_P'; Statement = 'CREATE INDEX IX_P ON sidata.Finding (x)' })).Sql | Should -Be ''
        (Get-SIIndexBuildRunSql -Row ([pscustomobject]@{ Table = 'sidata.Finding'; Name = 'IX_P'; Statement = 'CREATE INDEX IX_P ON sidata.Finding (x); DROP TABLE sidata.Finding' })).Sql | Should -Be ''
        (Get-SIIndexBuildRunSql -Row ([pscustomobject]@{ Table = 'sidata.Finding'; Name = 'IX_P'; Statement = 'CREATE INDEX IX_OTHER ON sidata.Finding (x)' })).Sql | Should -Be ''
        Get-SIIndexBuildPauseSql -Table 'sidata.Finding' -Index 'IX_P' | Should -Be 'ALTER INDEX [IX_P] ON [sidata].[Finding] PAUSE'
        Test-SIIndexBuildFiltered -Statement $script:Filtered | Should -BeTrue
        Test-SIIndexBuildFiltered -Statement $script:Plain | Should -BeFalse
    }
    It 'the job''s inputs: the install''s from its job, the runner''s choice per start; an unsafe index name is dropped' {
        $in = Read-SIIndexBuildJobInput -Env @{ SI_INDEXBUILD_SERVER = 'server.database.windows.net'; SI_INDEXBUILD_DATABASE = 'sqldb-si-pro'; SI_INDEXBUILD_MI_CLIENT_ID = '11111111-1111-1111-1111-111111111111'
                                               SI_INDEXBUILD_TABLE = 'sidata.Finding'; SI_INDEXBUILD_INDEX = 'IX_X'; SI_INDEXBUILD_MINUTES = '75'; SI_INDEXBUILD_FORCE = '1'; CONTAINER_APP_JOB_EXECUTION_NAME = 'caj-si-index-build-ab12' }
        $in.Ok | Should -BeTrue; $in.Request.Minutes | Should -Be 75; $in.Request.Force | Should -BeTrue; $in.UpdaterJob | Should -Be 'caj-si-updater'
        Get-SIIndexBuildJobHolder -Execution $in.Execution | Should -Be 'caj-si-index-build:caj-si-index-build-ab12'
        (Read-SIIndexBuildJobInput -Env @{ SI_INDEXBUILD_SERVER = 'server.database.windows.net'; SI_INDEXBUILD_DATABASE = 'db'; SI_INDEXBUILD_TABLE = 'x;y'; SI_INDEXBUILD_INDEX = 'IX' }).Request.Table | Should -Be ''
        (Read-SIIndexBuildJobInput -Env @{ SI_INDEXBUILD_SERVER = 'bad server'; SI_INDEXBUILD_DATABASE = 'db' }).Ok | Should -BeFalse
    }
}

Describe '#1111 the updater: no index-build mode; it takes the job''s lock at once' {
    It 'NEGATIVE: nothing under container\updater has an index-build mode, the old window run, or builds an index itself' {
        $hits = foreach ($f in @(Get-ChildItem -LiteralPath (Join-Path $script:SIRoot 'container\updater') -Recurse -File -Include *.ps1, Dockerfile)) {
            $t = [IO.File]::ReadAllText($f.FullName)
            foreach ($m in [regex]::Matches($t, "(?i)SI_UPDATER_MODE[^\r\n]{0,60}index-build|updMode\s*-eq\s*'index-build'|Invoke-SIUpdaterIndexWindow|Invoke-SIIndexBuildCommand|\bInvoke-SIIndexBuildJob\b|IndexBuildContract\)\.Mode")) { '{0}: {1}' -f $f.Name, $m.Value }
        }
        @($hits) | Should -BeNullOrEmpty
        $s = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\updater\Start-SIUpdater.ps1'))
        $s | Should -Not -Match "'index-build'"
    }
    It 'the run gate TAKES a lock held by the index build job (never waits for it); the job itself takes nothing from anyone' {
        $sql = Get-SIUpdaterRunGateSql
        $sql | Should -Match ([regex]::Escape('OR (@TakeFrom IS NOT NULL AND Holder LIKE @TakeFrom)'))
        $cap = [pscustomobject]@{ P = $null }
        $store = [pscustomobject]@{ Invoke = { param($q, $p, $mode) $cap.P = $p; , @(@{ Verdict = 'Go'; RunId = $null }) }.GetNewClosure() }
        (Invoke-SIUpdaterRunGate -Store $store -Holder 'caj-si-updater:u1').Go | Should -BeTrue
        $cap.P['TakeFrom'] | Should -Be 'caj-si-index-build:%'
        $null = Invoke-SIUpdaterRunGate -Store $store -Holder 'caj-si-index-build:e1' -TakeFrom '' -BusyRetries 0
        $cap.P.Contains('TakeFrom') | Should -BeTrue; $cap.P['TakeFrom'] | Should -BeNullOrEmpty
        [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\index-build\SI-IndexBuildJob.ps1')) | Should -Match ([regex]::Escape("-BusyRetries 0 -TakeFrom ''"))
    }
    It 'the stop tool never counts the index build job as a step of a run, nor as the updater -- "the updater runs" means an update' {
        . (Join-Path $script:SIRoot 'setup\_shared\SI-StopRunAndUpdate.ps1')
        $jobs = @('caj-si-flow', 'caj-si-updater', 'caj-si-index-build', 'caj-si-asset-datasync') | ForEach-Object { [pscustomobject]@{ name = $_ } }
        $arm = { param($m, $p, $b) [pscustomobject]@{ value = $jobs } }.GetNewClosure()
        $i = Read-SIStopRunInstall -Arm $arm -SubscriptionId 's' -ResourceGroup 'rg'
        [string]$i.Updater.name | Should -Be 'caj-si-updater'
        @($i.StepJobs) | Should -Be @('caj-si-asset-datasync')
    }
}

Describe '#1111 every install gets the job from the updater (made, kept, read back)' {
    BeforeAll {
        $script:Pull = '/subscriptions/s/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/uami-securityinsight'
        $script:UpdMi = '/subscriptions/s/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-si-updater'
        $script:UpdCid = '22222222-2222-2222-2222-222222222222'
        function script:New-Arm([switch]$Certificate) {
            $eng = [pscustomobject]@{ name = 'caj-si-asset-datasync'; location = 'westeurope'; tags = [pscustomobject]@{}
                properties = [pscustomobject]@{ environmentId = '/subscriptions/s/resourceGroups/rg/providers/Microsoft.App/managedEnvironments/cae-si'
                    configuration = [pscustomobject]@{ registries = @([pscustomobject]@{ server = 'acrsi.azurecr.io'; identity = $script:Pull }) }
                    template = [pscustomobject]@{ containers = @([pscustomobject]@{ name = 'main'; image = 'acrsi.azurecr.io/si-orchestrator:3.0.41'; env = @() }) } } }
            $ua = if ($Certificate) { $null } else { [pscustomobject]@{ type = 'UserAssigned'; userAssignedIdentities = [pscustomobject]@{ $script:Pull = [pscustomobject]@{ clientId = 'pull-cid' }; $script:UpdMi = [pscustomobject]@{ clientId = $script:UpdCid } } } }
            $upd = [pscustomobject]@{ name = 'caj-si-updater'; identity = $ua
                properties = [pscustomobject]@{ template = [pscustomobject]@{ containers = @([pscustomobject]@{ name = 'u'; image = 'acrsi.azurecr.io/si-updater:3.0.41'
                    env = @([pscustomobject]@{ name = 'SI_UPDATER_CLIENT_ID'; value = $script:UpdCid }, [pscustomobject]@{ name = 'SI_UPDATER_AUTH'; value = $(if ($Certificate) { 'Certificate' } else { 'ManagedIdentity' }) }) }) } } }
            $w = [pscustomobject]@{ Job = $null; Puts = 0; Body = $null; Jobs = @($eng, $upd); NoTag = $false }
            $w | Add-Member -NotePropertyName Arm -NotePropertyValue ({
                param($m, $p, $b)
                if ($m -eq 'PUT') {
                    $w.Puts++; $w.Body = $b
                    $j = $b | ConvertTo-Json -Depth 30 | ConvertFrom-Json
                    $j | Add-Member -NotePropertyName name -NotePropertyValue 'caj-si-index-build' -Force
                    $j.properties | Add-Member -NotePropertyName provisioningState -NotePropertyValue 'Succeeded' -Force
                    if ($w.NoTag) { $j.tags = [pscustomobject]@{} }
                    $w.Job = $j; return $j
                }
                if ($p -match '/jobs/caj-si-index-build\?') { return $w.Job }
                if ($p -match '/jobs/caj-si-updater\?') { return $upd }
                $null
            }.GetNewClosure())
            $w | Add-Member -NotePropertyName Lists -NotePropertyValue ({ param($k) $w.Jobs }.GetNewClosure())
            $w
        }
        $script:Ens = { param($w) Invoke-SIIndexBuildJobEnsure -Arm $w.Arm -Lists $w.Lists -SubscriptionId 's' -ResourceGroup 'rg' -Server 'server.database.windows.net' -Database 'sqldb-si-pro' -Sleep { param($s) } -Polls 2 }
    }
    It 'an install without the job: it is MADE as the updater''s identity, with SI''s image and its default entry point, and read back' {
        $w = New-Arm
        $r = & $script:Ens $w
        $r.Ok | Should -BeTrue; $r.Action | Should -Be 'made'; $w.Puts | Should -Be 1
        $b = $w.Body
        @($b.identity.userAssignedIdentities.Keys) | Should -Be @($script:UpdMi, $script:Pull) -Because 'the updater''s identity signs in; the pull identity only pulls the image'
        $c = $b.properties.template.containers[0]
        $c.image | Should -Be 'acrsi.azurecr.io/si-orchestrator:3.0.41'
        $c.Contains('command') | Should -BeFalse -Because 'the image''s own entry point: container\Start-SIInContainer.ps1'
        $env = @{}; foreach ($e in $c.env) { $env[$e.name] = $e.value }
        $env['SI_ROLE'] | Should -Be 'index-build'; $env['SI_INDEXBUILD_MI_CLIENT_ID'] | Should -Be $script:UpdCid
        $env['SI_INDEXBUILD_SERVER'] | Should -Be 'server.database.windows.net'; $env['SI_INDEXBUILD_UPDATER_JOB'] | Should -Be 'caj-si-updater'
        $b.properties.configuration.triggerType | Should -Be 'Manual'; $b.properties.configuration.replicaRetryLimit | Should -Be 0
        $r.Reason | Should -Match 'made and read back'
    }
    It 'a job that is as it must be is KEPT (no PUT); one that drifted is brought back and read back' {
        $w = New-Arm
        $null = & $script:Ens $w
        $r2 = & $script:Ens $w
        $r2.Action | Should -Be 'kept'; $w.Puts | Should -Be 1
        $w.Job.tags.'si-index-build-spec' = 'something-else'
        $r3 = & $script:Ens $w
        $r3.Action | Should -Be 'updated'; $w.Puts | Should -Be 2
    }
    It 'a read-back that does not match is a WARNING (Ok false), never silently "made"' {
        $w = New-Arm; $w.NoTag = $true
        $r = & $script:Ens $w
        $r.Ok | Should -BeFalse; $r.Action | Should -Be 'failed'; $r.Reason | Should -Match 'did not read back right'
    }
    It 'an updater that signs in by certificate has no identity to give: not made, said plainly, nothing PUT' {
        $w = New-Arm -Certificate
        $r = & $script:Ens $w
        $r.Action | Should -Be 'not-ready'; $w.Puts | Should -Be 0
        $r.Reason | Should -Match 'the updater has no managed identity \(it signs in by certificate\)'
    }
    It 'the updater runs it on EVERY Pro run (after the support queue, before the update): its wrapper and the call' {
        . (Join-Path $script:SIRoot 'container\updater\_shared\SI-UpdaterDatabase.ps1')
        $script:UpdLines = New-Object System.Collections.Generic.List[string]
        function script:Write-UpdLog { param([string]$m) $script:UpdLines.Add($m) }
        $w = New-Arm
        $r = Invoke-SIUpdaterIndexBuildJob -SIRoot $script:SIRoot -Store ([pscustomobject]@{ Server = 'server.database.windows.net'; Database = 'sqldb-si-pro'; Invoke = {} }) -SubscriptionId 's' -ResourceGroup 'rg' -Arm $w.Arm -Lists $w.Lists -Sleep { param($s) }
        $r.Action | Should -Be 'made'
        ($script:UpdLines -join ' ') | Should -Match 'the index build job caj-si-index-build was made and read back'
        (Invoke-SIUpdaterIndexBuildJob -SIRoot $script:SIRoot -Store $null -SubscriptionId 's' -ResourceGroup 'rg').Action | Should -Be 'skipped'
        $s = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\updater\Start-SIUpdater.ps1'))
        $call = $s.IndexOf('Invoke-SIUpdaterIndexBuildJob -SIRoot $siAutoRoot -Store $proStore')
        $call | Should -BeGreaterThan 0
        $call | Should -BeGreaterThan $s.IndexOf('Invoke-SIUpdaterSupportQueue -SubscriptionId $sub')
        $call | Should -BeLessThan $s.IndexOf("if (`$updMode -eq 'apply-settings') {") -Because 'every Pro run keeps it, before any update path'
    }
    It 'the database setup job never takes its image from the index build job' {
        $jobs = @([pscustomobject]@{ name = 'caj-si-index-build'; properties = [pscustomobject]@{ environmentId = 'e'; configuration = [pscustomobject]@{ registries = @([pscustomobject]@{ server = 'a'; identity = $script:Pull }) }; template = [pscustomobject]@{ containers = @([pscustomobject]@{ image = 'acrsi.azurecr.io/si-orchestrator:1' }) } } })
        (Get-SIDbInitTemplateJob -Jobs $jobs).Ok | Should -BeFalse
    }
}

Describe '#1111 the wiring: the container, the runner, the grants list, the release scopes' {
    It 'the container hands SI_ROLE = index-build to the job''s entry IN process, before any engine sign-in or storage step' {
        $c = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\Start-SIInContainer.ps1'))
        $c | Should -Match ([regex]::Escape("`$ixScript = '/app/engine/index-build/Invoke-SIIndexBuildJob.ps1'"))
        $c | Should -Match ([regex]::Escape('& $ixScript'))
        $c.IndexOf("'index-build' {") | Should -BeLessThan $c.IndexOf("`$global:SI_StorageAccount = Get-RequiredEnv 'SI_STORAGE_ACCOUNT'")
        Test-Path -LiteralPath (Join-Path $script:SIRoot 'engine\index-build\Invoke-SIIndexBuildJob.ps1') | Should -BeTrue
    }
    It 'the runner starts caj-si-index-build with the index and the window -- it never starts the updater for an index' {
        $w = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\flow\Invoke-SIJobFlowRun.ps1'))
        $a = $w.IndexOf('$ixRows = @(Read-SIIndexBuildRows'); $z = $w.IndexOf('# ---- a CANCELLED run is final')
        $a | Should -BeGreaterThan 0; $z | Should -BeGreaterThan $a
        $block = $w.Substring($a, $z - $a)
        $block | Should -Match ([regex]::Escape("('{0}/{1}/start' -f `$armSeams.Base, `$ixJobName)"))
        $block | Should -Not -Match ([regex]::Escape("/start' -f `$armSeams.Base, `$updaterJobName"))
        $block | Should -Not -Match 'New-SIUpdateNowStartTemplate'
        $block | Should -Match 'SI_INDEXBUILD_MINUTES = \[string\]\[int\]\$ixDec\.Minutes'
        $block | Should -Match 'is not there yet -- the next update makes it'
    }
    It 'the job''s files run as the updater''s identity (left out of the engine''s least-privilege inventory); its code is no release component' {
        . (Join-Path $script:SIRoot 'engine\pro-settings\SI-EngineGrants.ps1')
        Test-SIEngineNotEngineCode -File 'engine/index-build/SI-IndexBuildJob.ps1' -Function 'Invoke-SIIndexBuildJob' | Should -BeTrue
        Test-SIEngineNotEngineCode -File 'engine/index-build/Invoke-SIIndexBuildJob.ps1' -Function '' | Should -BeTrue
        $rs = Get-Content -LiteralPath (Join-Path $script:SIRoot 'config\release-scopes.locked.json') -Raw | ConvertFrom-Json
        @($rs.none) | Should -Contain 'engine/index-build/**'
    }
}

Describe '#1111 REAL SQL: the updater takes the index build job''s lock at once; the job sees it is gone' -Skip:(-not $script:HasSql) {
    BeforeAll {
        $script:Db = 'si_test_ixjob_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
        $m = New-Object System.Data.SqlClient.SqlConnection 'Server=.\SQLEXPRESS;Database=master;Integrated Security=SSPI;Connection Timeout=30'
        $m.Open(); try { $c = $m.CreateCommand(); $c.CommandText = "CREATE DATABASE [$script:Db]"; $c.CommandTimeout = 300; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
        $cs = "Server=.\SQLEXPRESS;Database=$script:Db;Integrated Security=SSPI;Connection Timeout=30"
        $script:Q = {
            param([string]$sql, $p, [string]$mode)
            $cn = New-Object System.Data.SqlClient.SqlConnection($cs)
            try {
                $cn.Open(); $cmd = $cn.CreateCommand(); $cmd.CommandText = $sql; $cmd.CommandTimeout = 120
                if ($p) { foreach ($k in $p.Keys) { [void]$cmd.Parameters.AddWithValue('@' + $k, $(if ($null -eq $p[$k]) { [System.DBNull]::Value } else { $p[$k] })) } }
                if ($mode -eq 'reader') {
                    $rd = $cmd.ExecuteReader(); $out = New-Object System.Collections.Generic.List[object]
                    while ($rd.Read()) { $h = @{}; for ($i = 0; $i -lt $rd.FieldCount; $i++) { $h[$rd.GetName($i)] = $(if ($rd.IsDBNull($i)) { $null } else { $rd.GetValue($i) }) }; $out.Add($h) }
                    $rd.Close(); , $out.ToArray()
                } elseif ($mode -eq 'scalar') { $cmd.ExecuteScalar() } else { [void]$cmd.ExecuteNonQuery() }
            } finally { $cn.Dispose() }
        }.GetNewClosure()
        $set = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'sql\si-pro-settings.sql'))
        & $script:Q "IF SCHEMA_ID('cfg') IS NULL EXEC (N'CREATE SCHEMA cfg');" @{} 'nonquery'
        foreach ($t in 'cfg.FlowRun', 'cfg.FlowStepRun', 'cfg.PipelineLock') {
            $mm = [regex]::Match($set, "(?s)IF OBJECT_ID\('" + [regex]::Escape($t) + "'\) IS NULL\s+CREATE TABLE .*?\n\);")
            if (-not $mm.Success) { throw "$t not found in the shipped settings schema" }
            & $script:Q $mm.Value @{} 'nonquery'
        }
        $script:Store = [pscustomobject]@{ Invoke = $script:Q }
        $script:Holder = { [string](& $script:Q "SELECT Holder FROM cfg.PipelineLock WHERE LockId = N'install'" @{} 'scalar') }
    }
    AfterAll {
        [System.Data.SqlClient.SqlConnection]::ClearAllPools()
        $m = New-Object System.Data.SqlClient.SqlConnection 'Server=.\SQLEXPRESS;Database=master;Integrated Security=SSPI;Connection Timeout=30'
        $m.Open(); try { $c = $m.CreateCommand(); $c.CommandTimeout = 300; $c.CommandText = "ALTER DATABASE [$script:Db] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$script:Db]"; [void]$c.ExecuteNonQuery() } catch { } finally { $m.Dispose() }
    }
    It 'the job takes the free lock; a second job does NOT take it from the first; the updater DOES, at once; the job''s beat then answers 0 and its release leaves the updater''s lock alone' {
        $g1 = Invoke-SIUpdaterRunGate -Store $script:Store -Holder 'caj-si-index-build:e1' -TakeFrom '' -BusyRetries 0
        $g1.Go | Should -BeTrue; $g1.LockTaken | Should -BeTrue
        (& $script:Holder) | Should -Be 'caj-si-index-build:e1'
        $g2 = Invoke-SIUpdaterRunGate -Store $script:Store -Holder 'caj-si-index-build:e2' -TakeFrom '' -BusyRetries 0
        $g2.Go | Should -BeFalse -Because 'one index build at a time; the job never takes another''s lock'
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $u = Invoke-SIUpdaterRunGate -Store $script:Store -Holder 'caj-si-updater:u1' -Sleep { param($s) throw 'the updater must never wait for an index build' }
        $sw.Stop()
        $u.Go | Should -BeTrue; $u.LockTaken | Should -BeTrue
        $sw.Elapsed.TotalSeconds | Should -BeLessThan 10
        (& $script:Holder) | Should -Be 'caj-si-updater:u1'
        $n = @(& $script:Q (Get-SIIndexBuildLockBeatSql) ([ordered]@{ Holder = 'caj-si-index-build:e1'; What = 'building' }) 'reader')[0]['N']
        [int]$n | Should -Be 0 -Because 'the job sees it no longer holds the lock -- it pauses and ends'
        $null = Exit-SIUpdaterRunGate -Store $script:Store -Holder 'caj-si-index-build:e1'
        (& $script:Holder) | Should -Be 'caj-si-updater:u1' -Because 'the job''s release never frees the updater''s lock'
        $null = Exit-SIUpdaterRunGate -Store $script:Store -Holder 'caj-si-updater:u1'
    }
    It 'a pipeline runner (no TakeFrom match) still waits for the index build: a run never starts under it' {
        $null = Invoke-SIUpdaterRunGate -Store $script:Store -Holder 'caj-si-index-build:e3' -TakeFrom '' -BusyRetries 0
        $r = Invoke-SIUpdaterRunGate -Store $script:Store -Holder 'caj-si-flow-x1' -TakeFrom '' -BusyRetries 0
        $r.Go | Should -BeFalse
        (& $script:Holder) | Should -Be 'caj-si-index-build:e3'
    }
}
