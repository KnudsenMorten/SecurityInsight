#Requires -Version 5.1
<#
    THE COLLECTION CLEAN-UP ONLY AS BACKGROUND HOUSEKEEPING (REQUIREMENTS #1038 part 3, owner 2026-11-01: "servicenow is most
    critical" / "cleanup is low prio" / "3 is also important"). The pilot install's ServiceNow push waited hours behind a data
    sync that removed old collections in its own path, on a database it saturated.

    What these tests keep true (engine\_shared\data-sql\SI-DataSql.ps1 Invoke-SIDataStoppedRunCleanup -- the pipeline runner's
    wake-up, THE one housekeeping path -- Get-SIDataHousekeepingBusy, Remove-SIDataCollectionRows, Write-SIDataHousekeepingProgress;
    engine\flow\Invoke-SIJobFlowRun.ps1):
      * a removal does not START while a pipeline run, an open step, a run holding the install's lock, a data sync or a data
        out is going -- not one statement on the data database (a run only gets the #882 marks; no row is removed);
      * the question is asked again before EVERY range and batch: the moment a data sync starts, the removal stops between two
        ranges, the collection stays marked with its rows left, and the next wake-up with nothing going resumes and finishes;
      * the newest two complete collections (#717) and the published one are never removed;
      * every removal goes through ONE function, Remove-SIDataCollectionRows (the seam a partition truncate takes over);
      * the progress -- state, collections left, rows left, why it waits -- is recorded in cfg.InstallState 'Housekeeping'
        (under 400 characters) and said in the flow log;
      * FAIL SAFE: run records or a job's executions that cannot be read = nothing removed.
    Offline (fakes) plus one run against a local SQL Server (.\SQLEXPRESS on the test VM). Pro path.
#>

BeforeDiscovery {
    $script:LocalSql = $false
    try {
        $script:LocalSql = [bool]$env:SI_TEST_LOCALSQL -and $null -ne ('System.Data.SqlClient.SqlConnection' -as [type])
    } catch { $script:LocalSql = $false }
}

BeforeAll {
    $script:Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:Root 'engine\_shared\SI-KqlError.ps1')
    . (Join-Path $script:Root 'engine\_shared\SI-SchemaGate.ps1')
    . (Join-Path $script:Root 'engine\_shared\data-sql\SI-DataModel.ps1')
    . (Join-Path $script:Root 'engine\_shared\data-sql\SI-DataSql.ps1')
    $script:Schema = Get-Content -Raw -LiteralPath (Join-Path $script:Root 'sql\si-data-schema.sql')
    $script:Runner = Get-Content -Raw -LiteralPath (Join-Path $script:Root 'engine\flow\Invoke-SIJobFlowRun.ps1')
    $script:Quiet = { param($l, $m) }
    function script:T([int]$Day, [int]$Hour = 8) { [datetime]::SpecifyKind((Get-Date -Year 2026 -Month 10 -Day $Day -Hour $Hour -Minute 0 -Second 0 -Millisecond 0), 'Utc') }
    function script:Row($Id, [datetime]$Time, [string]$Status, [switch]$Retired, $RetiredAt = $null, [switch]$Published) {
        @{ Grain = 'Detailed'; CollectionId = $Id; CollectionTime = $Time; Status = $Status
           RetiredAt = $(if ($Retired) { if ($null -ne $RetiredAt) { $RetiredAt } else { (T 20) } } else { [System.DBNull]::Value })
           RetiredWhy = $(if ($Retired) { 'superseded' } else { [System.DBNull]::Value }); HasRows = $(if ($Retired) { 1 } else { 0 })
           Pending = 0; Published = $(if ($Published) { 1 } else { 0 }) }
    }
    # the settings database: pipeline runs running (-Runs), open steps / a run's lock (-Open), what was recorded
    function script:New-Settings([int]$Runs = 0, [int]$Open = 0, [switch]$Throw, $RunStart = $null, [string]$Previous = '') {
        $rec = New-Object System.Collections.ArrayList
        $inv = { param([string]$sql, $p, [string]$mode)
            if ($Throw) { throw 'the settings database does not answer' }
            if ($sql -match "N'Housekeeping'" -and $mode -eq 'nonquery') { [void]$rec.Add([string]$p['Value']); return 1 }
            if ($sql -match "Name = N'Housekeeping'") { if ($rec.Count) { return [string]$rec[$rec.Count - 1] }; if ($Previous) { return $Previous }; return $null }
            if ($sql -match 'FROM cfg\.FlowStepRun AS s') { return , @(@{ Open = 0; Since = $null; Unknown = 0 }) }
            if ($sql -match 'FROM cfg\.FlowStepRun WHERE State IN') { return $Open }
            if ($sql -match 'MIN\(StartedUtc\)') { return $RunStart }
            if ($sql -match 'FROM cfg\.FlowRun') { return $Runs }
            if ($sql -match "N'StoppedRuns'") { return 1 }
            0 }.GetNewClosure()
        [pscustomobject]@{ Invoke = $inv; Recorded = $rec }
    }
    # the data database: the collections' state, and each collection's finding rows (ids) behind the range statement (-Cap rows
    # a range); answers what is left; records every statement
    function script:New-HkData([object[]]$State, [hashtable]$Rows = @{}, [int]$Cap = 2) {
        $left = @{}
        foreach ($k in $Rows.Keys) { $l = New-Object System.Collections.Generic.List[long]; for ($i = 1L; $i -le [long]$Rows[$k]; $i++) { $l.Add([long]$k * 100000 + $i) }; $left[[string]$k] = $l }
        $sent = New-Object System.Collections.ArrayList
        $inv = { param([string]$sql, $p, [string]$mode)
            [void]$sent.Add([pscustomobject]@{ Sql = $sql; P = $(if ($p) { $p.Clone() } else { @{} }) })
            if ($sql -match 'AS HasRows') { return , @($State) }
            if ($sql -match 'CollectionReportCarry') { return , @() }
            if ($sql -match 'SET RetiredAt = SYSUTCDATETIME\(\)') { return 1 }
            if ($sql -match 'AS Refused') {
                $id = [string]$p['CollectionId']
                if ($sql -notmatch 'FROM sidata\.Finding WHERE CollectionId = @c' -or -not $left.ContainsKey($id)) { return , @(@{ N = 0; Hi = $null; Refused = 0; Cap = $Cap }) }
                $after = [long]$p['After']; $take = [Math]::Min([long]$Cap, [long]$p['Batch'])
                $mine = @($left[$id] | Where-Object { $_ -gt $after } | Select-Object -First $take)
                if (-not $mine.Count) { return , @(@{ N = 0; Hi = $null; Refused = 0; Cap = $Cap }) }
                foreach ($x in $mine) { [void]$left[$id].Remove($x) }
                return , @(@{ N = $mine.Count; Hi = $mine[-1]; Refused = 0; Cap = $Cap })
            }
            if ($sql -match 'AS Collections') {
                $marked = @($State | Where-Object { -not ($_.RetiredAt -is [System.DBNull]) } | ForEach-Object { [string]$_.CollectionId })
                $c = @($left.Keys | Where-Object { $marked -contains $_ -and $left[$_].Count -gt 0 }).Count
                $r = 0L; foreach ($k in $left.Keys) { if ($marked -contains $k) { $r += $left[$k].Count } }
                return , @(@{ Collections = $c; Rows = $r })
            }
            if ($mode -eq 'scalar') { return 0 }
            , @() }.GetNewClosure()
        [pscustomobject]@{ Invoke = $inv; Sent = $sent; Left = $left }
    }
    function script:Removals($Sent) { @($Sent | Where-Object { $_.Sql -match 'AS Refused|DELETE TOP' }) }
    # a job that starts running after -After answers (each answer counted; -Sent: where the data database was when it started)
    function script:New-Job([int]$After = 0, [string]$Job = 'asset-datasync', $Sent = $null) {
        $st = @{ Calls = 0; StartedAt = -1 }; $at = T 7 8
        $fn = { param($j)
            if ($j -ne $Job) { return $null }
            $st.Calls++
            if ($st.Calls -le $After) { return $null }
            if ($st.StartedAt -lt 0) { $st.StartedAt = $(if ($Sent) { $Sent.Count } else { 0 }) }
            [pscustomobject]@{ Execution = ('caj-si-{0}-x1' -f $Job); StartedUtc = $at } }.GetNewClosure()
        [pscustomobject]@{ Fn = $fn; State = $st }
    }
    # 2026-11-10 the data database for several key ranges at once (Get-SIDataRetireBoundsSql / Get-SIDataRetireSpanSql): each
    # collection's finding ids; -Marked collections may be removed, -Published never; -SpanMs: each range takes that long
    function script:New-WideData([hashtable]$Rows = @{}, [long]$Cap = 3, [string[]]$Marked = @(), [string]$Published = '', [int]$SpanMs = 0, [object[]]$State = @()) {
        $left = @{}
        foreach ($k in $Rows.Keys) { $l = New-Object System.Collections.Generic.List[long]; for ($i = 1L; $i -le [long]$Rows[$k]; $i++) { $l.Add([long]$k * 100000 + $i) }; $left[[string]$k] = $l }
        $sent = New-Object System.Collections.ArrayList; $gone = New-Object System.Collections.Generic.List[long]
        $inv = { param([string]$sql, $p, [string]$mode)
            [void]$sent.Add([pscustomobject]@{ Sql = $sql; P = $(if ($p) { $p.Clone() } else { @{} }) })
            $id = if ($p -and $p.ContainsKey('CollectionId')) { [string]$p['CollectionId'] } else { '' }
            if ($sql -match 'AS Lo') {
                if ($Marked -notcontains $id) { return , @(@{ Hi = $null; Refused = 1; Cap = 0; Lo = 0 }) }
                if ($sql -notmatch 'FindingId > @lo' -or -not $left.ContainsKey($id) -or -not $left[$id].Count) { return , @() }
                $after = [long]$p['After']; $take = [long][Math]::Min([long]$Cap, [Math]::Max(1L, [long]$p['Batch'])); $n = [long][Math]::Max(1, [int]$p['Ranges'])
                $lo = if ($after -le 0) { [long]($left[$id] | Measure-Object -Minimum).Minimum - 1 } else { $after }
                $mine = @($left[$id] | Where-Object { $_ -gt $lo } | Select-Object -First ([int]($n * $take)))
                $o = New-Object System.Collections.Generic.List[object]
                for ($i = 0; $i -lt $mine.Count; $i++) { if ((($i + 1) % $take) -eq 0 -or $i -eq $mine.Count - 1) { $o.Add(@{ Hi = $mine[$i]; Refused = 0; Cap = $Cap; Lo = $lo }) } }
                return , $o.ToArray()
            }
            if ($sql -match 'CONVERT\(bigint, @Upto\)') {
                if ($Marked -notcontains $id -or $id -eq $Published) { return [long]-1 }
                if ($sql -notmatch 'FindingId <= @hi' -or -not $left.ContainsKey($id)) { return 0L }
                if ($SpanMs -gt 0) { Start-Sleep -Milliseconds $SpanMs }
                $mine = @($left[$id] | Where-Object { $_ -gt [long]$p['After'] -and $_ -le [long]$p['Upto'] } | Select-Object -First ([int]$Cap))
                foreach ($x in $mine) { [void]$left[$id].Remove($x); $gone.Add($x) }
                return [long]$mine.Count
            }
            if ($sql -match 'AS HasRows') { return , @($State) }
            if ($sql -match 'CollectionReportCarry') { return , @() }
            if ($sql -match 'SET RetiredAt = SYSUTCDATETIME\(\)') { return 1 }
            if ($sql -match 'AS Collections') {
                $c = @($left.Keys | Where-Object { $Marked -contains $_ -and $left[$_].Count -gt 0 }).Count
                $r = 0L; foreach ($k in $left.Keys) { if ($Marked -contains $k) { $r += $left[$k].Count } }
                return , @(@{ Collections = $c; Rows = $r })
            }
            if ($mode -eq 'scalar') { return 0 }
            , @() }.GetNewClosure()
        [pscustomobject]@{ Invoke = $inv; Sent = $sent; Left = $left; Gone = $gone }
    }
}

Describe 'is anything going? (Get-SIDataHousekeepingBusy)' {
    It 'a pipeline run, an open step or a run holding the lock, a data sync, a data out: busy, and says which' {
        $b = Get-SIDataHousekeepingBusy -SettingsInvoke (New-Settings -Runs 1).Invoke
        $b.Busy | Should -BeTrue; $b.Run | Should -BeTrue; $b.Known | Should -BeTrue
        (Get-SIDataHousekeepingBusy -SettingsInvoke (New-Settings -Open 1).Invoke).Why | Should -Match 'step'
        $ds = Get-SIDataHousekeepingBusy -SettingsInvoke (New-Settings).Invoke -JobRunning (New-Job -Job 'asset-datasync').Fn -Jobs @('asset-datasync', 'data-out')
        $ds.Busy | Should -BeTrue; $ds.Why | Should -Match '^a data sync is running \(caj-si-asset-datasync-x1\)'
        $do = Get-SIDataHousekeepingBusy -SettingsInvoke (New-Settings).Invoke -JobRunning (New-Job -Job 'data-out').Fn -Jobs @('asset-datasync', 'data-out')
        $do.Busy | Should -BeTrue; $do.Why | Should -Match '^a data out is running'
    }
    It 'nothing going: not busy; a job that is not installed (not found) is not running' {
        $none = { param($j) $null }
        (Get-SIDataHousekeepingBusy -SettingsInvoke (New-Settings).Invoke -JobRunning $none -Jobs @('asset-datasync', 'data-out')).Busy | Should -BeFalse
        $nf = { param($j) if ($j -eq 'data-out') { throw 'ResourceNotFound: the job caj-si-data-out was not found' }; $null }
        (Get-SIDataHousekeepingBusy -SettingsInvoke (New-Settings).Invoke -JobRunning $nf -Jobs @('asset-datasync', 'data-out')).Busy | Should -BeFalse
    }
    It 'FAIL SAFE: run records or a job''s executions that cannot be read = busy, not known' {
        $x = Get-SIDataHousekeepingBusy -SettingsInvoke (New-Settings -Throw).Invoke
        $x.Busy | Should -BeTrue; $x.Known | Should -BeFalse
        $y = Get-SIDataHousekeepingBusy -SettingsInvoke (New-Settings).Invoke -JobRunning { param($j) throw 'ARM is down' } -Jobs @('asset-datasync')
        $y.Busy | Should -BeTrue; $y.Known | Should -BeFalse
        (Get-SIDataHousekeepingBusy -SettingsInvoke $null).Busy | Should -BeTrue
        Get-SIDataHousekeepingOpenWorkSql | Should -Match "cfg\.FlowStepRun WHERE State IN \(N'Starting', N'Running'\)"
        Get-SIDataHousekeepingOpenWorkSql | Should -Match "cfg\.PipelineLock WHERE LockId = N'install' AND FlowRunId IS NOT NULL"
    }
}

Describe 'a removal does not start while a run, a data sync or a data out is going' {
    BeforeAll {
        $script:State = @((Row 1 (T 1) Complete -Retired), (Row 2 (T 2) Complete -Retired), (Row 3 (T 3) Complete), (Row 4 (T 4) Complete))
    }
    It 'a data sync started on its own: not one statement on the data database; recorded as paused, and why' {
        foreach ($job in 'asset-datasync', 'data-out') {
            $d = New-HkData -State $script:State -Rows @{ 1 = 5; 2 = 5 }
            $s = New-Settings
            $r = Invoke-SIDataStoppedRunCleanup -Invoke $d.Invoke -SettingsInvoke $s.Invoke -JobRunning (New-Job -Job $job).Fn -Jobs @('asset-datasync', 'data-out') -NowUtc (T 7 8) -Log $script:Quiet
            $r.Status | Should -Be 'skipped'
            $d.Sent.Count | Should -Be 0 -Because "$job is running: the clean-up gives way at once"
            $rec = $s.Recorded[$s.Recorded.Count - 1] | ConvertFrom-Json
            $rec.state | Should -Be 'paused'
            $rec.why | Should -Match $(if ($job -eq 'data-out') { 'a data out is running' } else { 'a data sync is running' })
        }
    }
    It 'an open step, or a run holding the install''s lock (no run row): nothing on the data database' {
        $d = New-HkData -State $script:State -Rows @{ 1 = 5 }
        (Invoke-SIDataStoppedRunCleanup -Invoke $d.Invoke -SettingsInvoke (New-Settings -Open 1).Invoke -JobRunning { param($j) $null } -NowUtc (T 7 8) -Log $script:Quiet).Status | Should -Be 'skipped'
        $d.Sent.Count | Should -Be 0
    }
    It '#1063: a pipeline run is going -- the rows of collections marked BEFORE the run started ARE removed during it (paced), the newest two stay' {
        $d = New-HkData -State $script:State -Rows @{ 1 = 5; 2 = 5; 3 = 4; 4 = 4 }
        $s = New-Settings -Runs 1 -RunStart (T 25)
        # nothing else going (owner 2026-11-10: the data sync and a data out each stop it -- the cases below)
        $r = Invoke-SIDataStoppedRunCleanup -Invoke $d.Invoke -SettingsInvoke $s.Invoke -RaRunning { $null } -JobRunning { param($j) $null } -NowUtc (T 7 8) -TimeBudgetSeconds 60 -Log $script:Quiet
        $r.Status | Should -Be 'ok'
        $r.Finished | Should -Not -BeNullOrEmpty
        $d.Left['1'].Count | Should -Be 0; $d.Left['2'].Count | Should -Be 0
        $d.Left['3'].Count | Should -Be 4; $d.Left['4'].Count | Should -Be 4
        @($d.Sent | Where-Object { $_.Sql -match 'AS Refused|DELETE TOP' -and @('3', '4') -contains [string]$_.P['CollectionId'] }).Count | Should -Be 0
        $rec = $s.Recorded[$s.Recorded.Count - 1] | ConvertFrom-Json
        $rec.state | Should -Be 'done' -Because 'nothing is left after this wake-up'
        $rec.removedRows | Should -BeGreaterThan 0; $rec.rowsLeft | Should -Be 0
    }
    It '#1063: a collection marked AFTER the running run started keeps its rows until that run is over' {
        $state = @((Row 1 (T 1) Complete -Retired -RetiredAt (T 26)), (Row 3 (T 3) Complete), (Row 4 (T 4) Complete))
        $d = New-HkData -State $state -Rows @{ 1 = 5 }
        $r = Invoke-SIDataStoppedRunCleanup -Invoke $d.Invoke -SettingsInvoke (New-Settings -Runs 1 -RunStart (T 25)).Invoke -RaRunning { $null } -JobRunning { param($j) $null } -NowUtc (T 7 8) -TimeBudgetSeconds 60 -Log $script:Quiet
        $r.Status | Should -Be 'ok'
        $d.Left['1'].Count | Should -Be 5
        @(Removals $d.Sent).Count | Should -Be 0
    }
    It '#1063: during a run it gives way to a data out at once, and removes nothing when the run start cannot be read' {
        $d = New-HkData -State $script:State -Rows @{ 1 = 5; 2 = 5 }
        $s = New-Settings -Runs 1 -RunStart (T 25)
        $r = Invoke-SIDataStoppedRunCleanup -Invoke $d.Invoke -SettingsInvoke $s.Invoke -RaRunning { $null } -JobRunning (New-Job -Job 'data-out').Fn -NowUtc (T 7 8) -TimeBudgetSeconds 60 -Log $script:Quiet
        @(Removals $d.Sent).Count | Should -Be 0 -Because 'the ServiceNow send comes first'
        $rec = $s.Recorded[$s.Recorded.Count - 1] | ConvertFrom-Json
        $rec.state | Should -Be 'paused'; $rec.why | Should -Match 'a data out is running'
        $d2 = New-HkData -State $script:State -Rows @{ 1 = 5; 2 = 5 }
        $r2 = Invoke-SIDataStoppedRunCleanup -Invoke $d2.Invoke -SettingsInvoke (New-Settings -Runs 1).Invoke -RaRunning { $null } -JobRunning { param($j) $null } -NowUtc (T 7 8) -TimeBudgetSeconds 60 -Log $script:Quiet
        $r2.Status | Should -Be 'ok'
        @(Removals $d2.Sent).Count | Should -Be 0 -Because 'FAIL SAFE: no run start = nothing removed'
        $r2.Why | Should -Match 'when the run started could not be read'
    }
    It 'owner 2026-11-10 "data sync is prio 1, and data clean-up happens when idle": during a run nothing is removed while the data sync runs, nor on a host that cannot read the jobs' {
        $d = New-HkData -State $script:State -Rows @{ 1 = 5; 2 = 5 }
        $s = New-Settings -Runs 1 -RunStart (T 25)
        $r = Invoke-SIDataStoppedRunCleanup -Invoke $d.Invoke -SettingsInvoke $s.Invoke -RaRunning { $null } -JobRunning (New-Job -Job 'asset-datasync').Fn -NowUtc (T 7 8) -TimeBudgetSeconds 60 -Log $script:Quiet
        @(Removals $d.Sent).Count | Should -Be 0 -Because 'the data sync goes first: no row is removed while it runs'
        $rec = $s.Recorded[$s.Recorded.Count - 1] | ConvertFrom-Json
        $rec.state | Should -Be 'paused'; $rec.why | Should -Match 'the data sync is running'
        $r.Why | Should -Match 'no row is removed now: the data sync is running'
        $d2 = New-HkData -State $script:State -Rows @{ 1 = 5; 2 = 5 }
        $null = Invoke-SIDataStoppedRunCleanup -Invoke $d2.Invoke -SettingsInvoke (New-Settings -Runs 1 -RunStart (T 25)).Invoke -RaRunning { $null } -NowUtc (T 7 8) -TimeBudgetSeconds 60 -Log $script:Quiet
        @(Removals $d2.Sent).Count | Should -Be 0 -Because 'a host that cannot say whether the data sync runs removes nothing during a run'
        # nothing going (no data sync, no data out): the removal during the run goes on as before
        $d3 = New-HkData -State $script:State -Rows @{ 1 = 5; 2 = 5 }
        $null = Invoke-SIDataStoppedRunCleanup -Invoke $d3.Invoke -SettingsInvoke (New-Settings -Runs 1 -RunStart (T 25)).Invoke -RaRunning { $null } -JobRunning { param($j) $null } -NowUtc (T 7 8) -TimeBudgetSeconds 60 -Log $script:Quiet
        @(Removals $d3.Sent).Count | Should -BeGreaterThan 0
    }
    It 'the executions of a job that cannot be read: nothing removed (fail safe)' {
        $d = New-HkData -State $script:State -Rows @{ 1 = 5 }
        (Invoke-SIDataStoppedRunCleanup -Invoke $d.Invoke -SettingsInvoke (New-Settings).Invoke -JobRunning { param($j) throw 'ARM is down' } -Jobs @('asset-datasync') -NowUtc (T 7 8) -Log $script:Quiet).Status | Should -Be 'skipped'
        $d.Sent.Count | Should -Be 0
    }
}

Describe 'it stops between ranges when a job starts, and resumes on the next wake-up' {
    It 'a data sync starts part way: no range after it; the collection stays marked with its rows left; the next wake-up finishes; the newest two stay' {
        $state = @((Row 1 (T 1) Complete -Retired), (Row 2 (T 2) Complete -Retired), (Row 3 (T 3) Complete), (Row 4 (T 4) Complete))
        $d = New-HkData -State $state -Rows @{ 1 = 9; 2 = 9; 3 = 4; 4 = 4 } -Cap 2
        $s = New-Settings
        # the data sync starts after the first few questions
        $job = New-Job -After 6 -Job 'asset-datasync' -Sent $d.Sent
        $r = Invoke-SIDataStoppedRunCleanup -Invoke $d.Invoke -SettingsInvoke $s.Invoke -JobRunning $job.Fn -Jobs @('asset-datasync') -NowUtc (T 7 8) -TimeBudgetSeconds 60 -Log $script:Quiet
        $r.Status | Should -Be 'ok'
        $job.State.StartedAt | Should -BeGreaterThan 0 -Because 'the job started during the removal'
        $removedBefore = 18 - ($d.Left['1'].Count + $d.Left['2'].Count)
        $removedBefore | Should -BeGreaterThan 0 -Because 'ranges ran before the data sync started'
        $removedBefore | Should -BeLessThan 18 -Because 'the removal stopped part way'
        @($d.Sent | Select-Object -Skip $job.State.StartedAt | Where-Object { $_.Sql -match 'AS Refused|DELETE TOP' }).Count | Should -Be 0 -Because 'no range or batch after the job started'
        $r.Retention.Paused | Should -Match 'a data sync is running'
        $r.Retention.Text | Should -Match 'Paused part way'
        $rec = $s.Recorded[$s.Recorded.Count - 1] | ConvertFrom-Json
        $rec.state | Should -Be 'paused'
        $rec.rowsLeft | Should -Be (18 - $removedBefore)
        $rec.collectionsLeft | Should -BeGreaterThan 0
        # the next wake-up, nothing going: resumes and finishes
        $r2 = Invoke-SIDataStoppedRunCleanup -Invoke $d.Invoke -SettingsInvoke $s.Invoke -JobRunning { param($j) $null } -Jobs @('asset-datasync') -NowUtc (T 7 8) -TimeBudgetSeconds 60 -Log $script:Quiet
        $r2.Status | Should -Be 'ok'
        $d.Left['1'].Count | Should -Be 0; $d.Left['2'].Count | Should -Be 0
        $rec2 = $s.Recorded[$s.Recorded.Count - 1] | ConvertFrom-Json
        $rec2.state | Should -Be 'done'; $rec2.collectionsLeft | Should -Be 0; $rec2.rowsLeft | Should -Be 0
        # the newest two complete collections: never a range, never a mark, every row
        $d.Left['3'].Count | Should -Be 4; $d.Left['4'].Count | Should -Be 4
        @($d.Sent | Where-Object { $_.Sql -match 'AS Refused|SET RetiredAt = SYSUTCDATETIME\(\)|DELETE TOP' -and @('3', '4') -contains [string]$_.P['CollectionId'] }).Count | Should -Be 0
    }
    It 'the batched deletes ask before every batch too (Invoke-SIDataBatchedDelete -ShouldStop)' {
        $n = [ref]0
        $inv = { param($s, $p, $m) [long]$p['Batch'] }
        $why = [ref]''; $stopped = [ref]$false; $size = [long]100
        $ask = { $n.Value++; if ($n.Value -gt 2) { 'a data out is running' } else { '' } }.GetNewClosure()
        $total = Invoke-SIDataBatchedDelete -Invoke $inv -Sql 'DELETE TOP (@Batch) FROM x; SELECT @@ROWCOUNT;' -BatchSize ([ref]$size) -Housekeeping -LockBound 100 -Stopped $stopped -ShouldStop $ask -StopWhy $why
        $total | Should -Be 200
        $stopped.Value | Should -BeTrue; $why.Value | Should -Be 'a data out is running'
    }
}

Describe 'it keeps the newest two complete collections and the published one' {
    It 'five complete collections, nothing going: only the older three are removed; the newest two keep every row' {
        $state = @((Row 1 (T 1) Complete), (Row 2 (T 2) Complete), (Row 3 (T 3) Complete), (Row 4 (T 4) Complete), (Row 5 (T 5) Complete))
        $d = New-HkData -State $state -Rows @{ 1 = 3; 2 = 3; 3 = 3; 4 = 3; 5 = 3 }
        $r = Invoke-SIDataStoppedRunCleanup -Invoke $d.Invoke -SettingsInvoke (New-Settings).Invoke -JobRunning { param($j) $null } -NowUtc (T 7 8) -TimeBudgetSeconds 60 -Log $script:Quiet
        @($r.Retention.Removed | ForEach-Object { $_.CollectionId } | Sort-Object) | Should -Be @(1, 2, 3)
        $d.Left['4'].Count | Should -Be 3; $d.Left['5'].Count | Should -Be 3
        @($d.Sent | Where-Object { @('4', '5') -contains [string]$_.P['CollectionId'] -and $_.Sql -match 'AS Refused|SET RetiredAt' }).Count | Should -Be 0
    }
    It 'the published run''s collection, marked or not, is never removed' {
        $state = @((Row 1 (T 1) Complete -Retired -Published), (Row 2 (T 2) Complete), (Row 3 (T 3) Complete))
        $d = New-HkData -State $state -Rows @{ 1 = 3 }
        $null = Invoke-SIDataStoppedRunCleanup -Invoke $d.Invoke -SettingsInvoke (New-Settings).Invoke -JobRunning { param($j) $null } -NowUtc (T 7 8) -Log $script:Quiet
        $d.Left['1'].Count | Should -Be 3
    }
}

Describe 'every removal goes through the one function (Remove-SIDataCollectionRows)' {
    It 'the retention removes each collection through it -- and sends no removal statement of its own' {
        Mock Remove-SIDataCollectionRows { [pscustomobject]@{ Rows = [ordered]@{ Finding = 7L; Recommendation = 1L }; Done = $true; Refused = $false; Stopped = $false; Paused = $false; StopWhy = '' } }
        $state = @((Row 1 (T 1) Complete -Retired), (Row 2 (T 2) Complete), (Row 3 (T 3) Complete), (Row 4 (T 4) Complete))
        $d = New-HkData -State $state
        $r = Invoke-SIDataCollectionRetention -Invoke $d.Invoke -Log $script:Quiet -NowUtc (T 7 8)
        Should -Invoke Remove-SIDataCollectionRows -Times 2 -Exactly
        Should -Invoke Remove-SIDataCollectionRows -Times 1 -Exactly -ParameterFilter { $Grain -eq 'Detailed' -and $CollectionId -eq '1' }
        Should -Invoke Remove-SIDataCollectionRows -Times 1 -Exactly -ParameterFilter { $Grain -eq 'Detailed' -and $CollectionId -eq '2' }
        @(Removals $d.Sent).Count | Should -Be 0
        $r.Rows['findings'] | Should -Be 14
        @($r.Removed | ForEach-Object { $_.CollectionId } | Sort-Object) | Should -Be @(1, 2)
    }
    It 'a pause the function reports stops the retention there, and says why' {
        Mock Remove-SIDataCollectionRows { [pscustomobject]@{ Rows = [ordered]@{ Finding = 2L }; Done = $false; Refused = $false; Stopped = $true; Paused = $true; StopWhy = 'a data sync is running' } }
        $state = @((Row 1 (T 1) Complete -Retired), (Row 2 (T 2) Complete -Retired), (Row 3 (T 3) Complete), (Row 4 (T 4) Complete))
        $r = Invoke-SIDataCollectionRetention -Invoke (New-HkData -State $state).Invoke -Log $script:Quiet -NowUtc (T 7 8) -ShouldStop { '' }
        Should -Invoke Remove-SIDataCollectionRows -Times 1 -Exactly
        $r.Stopped | Should -BeTrue; $r.Paused | Should -Be 'a data sync is running'
        @($r.Removed).Count | Should -Be 0
    }
    It 'no other function in the engine calls the range or batch removal of a collection' {
        $calls = foreach ($file in Get-ChildItem -Path (Join-Path $script:Root 'engine') -Recurse -Filter '*.ps1') {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$null, [ref]$null)
            foreach ($c in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -in 'Invoke-SIDataRetireRangeDelete', 'Invoke-SIDataRetireRangesWide', 'Get-SIDataRetireSpanSql', 'Get-SIDataRetireBatchSql', 'Remove-SIDataCollectionRows' }, $true)) {
                $fn = $c.Parent; while ($fn -and -not ($fn -is [System.Management.Automation.Language.FunctionDefinitionAst])) { $fn = $fn.Parent }
                '{0}>{1}' -f $(if ($fn) { $fn.Name } else { '' }), $c.GetCommandName()
            }
        }
        @($calls | Sort-Object -Unique) | Should -Be @('Invoke-SIDataCollectionRetention>Remove-SIDataCollectionRows', 'Invoke-SIDataRetireRangesWide>Get-SIDataRetireSpanSql', 'Remove-SIDataCollectionRows>Get-SIDataRetireBatchSql', 'Remove-SIDataCollectionRows>Invoke-SIDataRetireRangeDelete', 'Remove-SIDataCollectionRows>Invoke-SIDataRetireRangesWide')
    }
}

Describe 'the progress is reported' {
    It 'the recorded value: state, collections and rows left, why -- under 400 characters, the why cut' {
        $v = Get-SIDataHousekeepingValue -State paused -CollectionsLeft 6 -RowsLeft 3750000 -RemovedRows 0 -LastRemovedAtUtc (T 22) -Why ('a data sync is running ' * 20) -AtUtc (T 23)
        $v.Length | Should -BeLessThan 400
        $o = $v | ConvertFrom-Json
        $o.state | Should -Be 'paused'; $o.collectionsLeft | Should -Be 6; $o.rowsLeft | Should -Be 3750000
        $o.why.Length | Should -BeLessOrEqual 160
        Get-SIDataHousekeepingRecordSql | Should -Match "UPDATE cfg\.InstallState SET Value = @Value, UpdatedAt = SYSUTCDATETIME\(\), UpdatedBy = @By WHERE Name = N'Housekeeping'"
    }
    It 'a paused wake-up keeps the counts of the record before (it never reads the data database) and says one line on the hour' {
        $prev = Get-SIDataHousekeepingValue -State removing -CollectionsLeft 3 -RowsLeft 1200 -RemovedRows 400 -LastRemovedAtUtc (T 7 7) -AtUtc (T 7 7)
        $s = New-Settings -Previous $prev
        $lines = New-Object System.Collections.ArrayList
        $d = New-HkData -State @()
        $say = { param($l, $m) [void]$lines.Add("$l $m") }.GetNewClosure()
        $null = Invoke-SIDataStoppedRunCleanup -Invoke $d.Invoke -SettingsInvoke $s.Invoke -JobRunning (New-Job -Job 'asset-datasync').Fn -Jobs @('asset-datasync') -NowUtc (T 7 9) -Log $say
        $d.Sent.Count | Should -Be 0
        $o = $s.Recorded[0] | ConvertFrom-Json
        $o.state | Should -Be 'paused'; $o.collectionsLeft | Should -Be 3; $o.rowsLeft | Should -Be 1200
        $o.lastRemovedAt | Should -Not -BeNullOrEmpty
        @($lines | Where-Object { $_ -match '^OK housekeeping: old collections paused -- a data sync is running .*3 collection\(s\), about 1,200 row\(s\) left' }).Count | Should -Be 1
    }
    It 'the rows left are read with index reads only (key spans), never a COUNT over sidata.Finding' {
        $q = Get-SIDataHousekeepingLeftSql
        $q | Should -Match 'SELECT TOP \(1\) f\.FindingId FROM sidata\.Finding AS f WHERE f\.CollectionId = c\.CollectionId ORDER BY f\.FindingId DESC'
        $q | Should -Not -Match 'COUNT(_BIG)?\(\*\) FROM sidata\.Finding'
    }
}

Describe 'the wiring: the pipeline runner''s wake-up' {
    It 'hands the data sync''s and the data out''s running executions to the housekeeping' {
        $script:Runner | Should -Match ([regex]::Escape("`$cleanJobs = @('asset-datasync', 'data-out')"))
        $script:Runner | Should -Match ([regex]::Escape("`$cleanJob = { param(`$j) `$seams.Running(`$j) }"))
        $script:Runner | Should -Match 'Invoke-SIDataStoppedRunCleanup -Invoke \$cleanSql -SettingsInvoke \$proStore\.Invoke -IdleStaleHours \$idleHours -Log \$cleanLog -RaRunning \$cleanRa -JobRunning \$cleanJob -Jobs \$cleanJobs'
    }
    It '#1063: the wake-up removes rows while a run goes through exactly ONE -FinishOnly call, in Invoke-SIDataStoppedRunCleanup, with the floor, the run start, a budget and the data-out stop' {
        $f = Get-Content -Raw -LiteralPath (Join-Path $script:Root 'engine\_shared\data-sql\SI-DataSql.ps1')
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($f, [ref]$null, [ref]$null)
        $fin = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Invoke-SIDataCollectionRetention' -and @($n.CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] -and $_.ParameterName -eq 'FinishOnly' }).Count }, $true))
        $fin.Count | Should -Be 1
        $fn = $fin[0].Parent; while ($fn -and -not ($fn -is [System.Management.Automation.Language.FunctionDefinitionAst])) { $fn = $fn.Parent }
        $fn.Name | Should -Be 'Invoke-SIDataStoppedRunCleanup'
        $fin[0].Extent.Text | Should -Match '-FinishFloorUtc \$own\.Before -FinishMarkedBeforeUtc \$runStart -TimeBudgetSeconds \$left -ShouldStop \$doStop'
    }
}

Describe '#1063 (3.0.30): one clean-up at a time -- the lease' {
    It 'held by another wake-up: this one does nothing on the data database and records nothing; free / ours / run out: taken, and freed at the end' {
        $state = @((Row 1 (T 1) Complete -Retired), (Row 3 (T 3) Complete), (Row 4 (T 4) Complete))
        $base = New-Settings
        $sent = New-Object System.Collections.ArrayList
        $answer = @{ Take = 'held:caj-si-flow-other since 2026-11-04T10:00:00Z' }
        $inv = { param([string]$sql, $p, [string]$mode)
            if ($sql -match "N'HousekeepingLease'") { [void]$sent.Add([pscustomobject]@{ Sql = $sql; P = $p.Clone(); Mode = $mode }); if ($sql -match "SELECT N'taken'") { return $answer.Take }; return 1 }
            & $base.Invoke $sql $p $mode }.GetNewClosure()
        $d = New-HkData -State $state -Rows @{ 1 = 5 }
        $r = Invoke-SIDataStoppedRunCleanup -Invoke $d.Invoke -SettingsInvoke $inv -JobRunning { param($j) $null } -NowUtc (T 7 8) -TimeBudgetSeconds 60 -Holder 'caj-si-flow-me' -Log $script:Quiet
        $r.Status | Should -Be 'skipped'; $r.LeaseHeld | Should -BeTrue
        $r.Why | Should -Match '^another wake-up is removing old collections \(caj-si-flow-other since 2026-11-04T10:00:00Z\)'
        $d.Sent.Count | Should -Be 0 -Because 'one clean-up at a time'
        $base.Recorded.Count | Should -Be 0 -Because 'the holder records the progress'
        @($sent | Where-Object { $_.Sql -match "SET Value = N''" }).Count | Should -Be 0 -Because 'a lease that is not ours is never freed'
        # free: taken, the removal runs, the lease is freed (only when ours), the hold is the budget + 15 min
        $answer.Take = 'taken'; $sent.Clear()
        $r2 = Invoke-SIDataStoppedRunCleanup -Invoke $d.Invoke -SettingsInvoke $inv -JobRunning { param($j) $null } -NowUtc (T 7 8) -TimeBudgetSeconds 60 -Holder 'caj-si-flow-me' -Log $script:Quiet
        $r2.Status | Should -Be 'ok'; $r2.LeaseHeld | Should -BeFalse
        $d.Left['1'].Count | Should -Be 0
        $sent.Count | Should -Be 2
        $sent[0].P['Holder'] | Should -Be 'caj-si-flow-me'; $sent[0].P['LeaseSeconds'] | Should -Be 960; $sent[0].Mode | Should -Be 'scalar'
        $sent[1].Sql | Should -Match "SET Value = N''.*WHERE Name = N'HousekeepingLease' AND Value = @Holder"
        $sent[1].P['Holder'] | Should -Be 'caj-si-flow-me'
    }
    It 'FAIL SAFE: a lease that cannot be read = nothing removed; a failure inside the clean-up still frees the lease' {
        $base = New-Settings
        $inv = { param([string]$sql, $p, [string]$mode) if ($sql -match "SELECT N'taken'") { throw 'the settings database does not answer' }; & $base.Invoke $sql $p $mode }.GetNewClosure()
        $d = New-HkData -State @((Row 1 (T 1) Complete -Retired), (Row 3 (T 3) Complete), (Row 4 (T 4) Complete)) -Rows @{ 1 = 5 }
        $r = Invoke-SIDataStoppedRunCleanup -Invoke $d.Invoke -SettingsInvoke $inv -JobRunning { param($j) $null } -NowUtc (T 7 8) -Log $script:Quiet
        $r.Status | Should -Be 'skipped'; $r.Why | Should -Match 'whether another clean-up is going could not be read'
        $d.Sent.Count | Should -Be 0
        $freed = New-Object System.Collections.ArrayList
        $inv2 = { param([string]$sql, $p, [string]$mode) if ($sql -match "SET Value = N''") { [void]$freed.Add($p['Holder']); return 1 }; & $base.Invoke $sql $p $mode }.GetNewClosure()
        $boom = { param([string]$sql, $p, [string]$mode) throw 'the data database fell over' }
        $r2 = Invoke-SIDataStoppedRunCleanup -Invoke $boom -SettingsInvoke $inv2 -JobRunning { param($j) $null } -NowUtc (T 7 8) -Holder 'h1' -Log $script:Quiet
        $r2.Status | Should -Be 'failed'
        @($freed) | Should -Be @('h1')
    }
    It 'the lease statement: one row in cfg.InstallState, taken under an update lock, run out after @LeaseSeconds, freed only by its holder' {
        $t = Get-SIDataHousekeepingLeaseSql -Action Take
        $t | Should -Match "WITH \(UPDLOCK, HOLDLOCK\) WHERE Name = N'HousekeepingLease'"
        $t | Should -Match "@h = N'' OR @h = @Holder OR @at < DATEADD\(second, -@LeaseSeconds, SYSUTCDATETIME\(\)\)"
        $t | Should -Match "SELECT CONCAT\(N'held:'"
        Get-SIDataHousekeepingLeaseSql -Action Release | Should -Match "WHERE Name = N'HousekeepingLease' AND Value = @Holder"
    }
}

Describe '#1063 (3.0.30): a flow wake-up DURING a run (FlowBusy) reaches the clean-up -- the container entry''s guard, then the runner, end to end' {
    BeforeAll {
        . (Join-Path $script:Root 'container\_shared\SI-ContainerConfig.ps1')
        $src = [IO.File]::ReadAllText((Join-Path $script:Root 'container\Start-SIInContainer.ps1'))
        $a = $src.IndexOf('$guardJob = [Environment]::GetEnvironmentVariable(''CONTAINER_APP_JOB_NAME'')'); $b = $src.IndexOf('# #211 (2)')
        $a | Should -BeGreaterThan 0; $b | Should -BeGreaterThan $a
        $script:GuardBlock = $src.Substring($a, $b - $a) -replace '\bexit 0\b', 'return ''exited-0'''
        $script:RunnerPath = Join-Path $script:Root 'engine\flow\Invoke-SIJobFlowRun.ps1'
        # the running run's runner (01:00) and this wake-up (01:05) -- both executions of caj-si-flow
        $script:FlowExecs = @([pscustomobject]@{ name = 'caj-si-flow-29852960'; properties = [pscustomobject]@{ status = 'Running'; startTime = '2026-11-04T01:00:00Z' } },
                              [pscustomobject]@{ name = 'caj-si-flow-29853040'; properties = [pscustomobject]@{ status = 'Running'; startTime = '2026-11-04T01:05:00Z' } })
        $script:EnvNames = @('CONTAINER_APP_JOB_NAME', 'CONTAINER_APP_JOB_EXECUTION_NAME', 'SI_JOBS_SUBSCRIPTIONID', 'SI_JOBS_RESOURCEGROUP', 'SI_TRIGGER_FROM_QUEUE',
                             'SI_COLLECT_PHASE', 'SI_FLOW_FORCE', 'SI_FLOW_STAGE', 'SI_FLOW_STEP', 'SI_FLOW_FROM_STEP', 'SI_FLOW_CANCEL', 'SI_FLOW_DRAIN',
                             'SI_FLOW_HOUSEKEEPING_ONLY', 'SI_FLOW_SUBSCRIPTIONID', 'SI_FLOW_RESOURCEGROUP', 'SI_FLOW_TRIGGER')
        $script:GlobalNames = @('SI_ProSqlServer', 'SI_ProSqlDatabase', 'SI_Pro_DataSqlServer', 'SI_Pro_DataSqlDatabase', 'SI_StorageAccount', 'SI_SPN_AppId', 'SI_SPN_TenantId', 'SI_SPN_CertThumbprint')
        # the seams: Azure Resource Manager (the guard's execution list, the runner's job list and running executions), the
        # settings store, the data database -- dot-sourced INTO the test itself (the nearest scope: no other definition of
        # these names, loaded anywhere else in the test process, can shadow them; never global)
        $script:WakeStubs = {
        function Get-OptionalEnv { param([string]$Name, $Default = $null) $v = [Environment]::GetEnvironmentVariable($Name); if ([string]::IsNullOrWhiteSpace($v)) { $Default } else { $v } }
        function Invoke-SIArm {
            param([string]$Method = 'GET', [string]$Path, [string]$ApiVersion, $Body, [switch]$List, [switch]$AllowNotFound)
            [void]$SIv3WakeArm.Add(('{0} {1}' -f $Method, $Path))
            if ($List) { return $SIv3WakeExecs }
            if ($Method -ne 'GET') { throw ('the wake-up must start or stop nothing: {0} {1}' -f $Method, $Path) }
            if ($Path -match '/jobs$') { return [pscustomobject]@{ value = @('caj-si-flow', 'caj-si-asset-datasync', 'caj-si-data-out', 'caj-si-risk-analysis-detailed' | ForEach-Object { [pscustomobject]@{ name = $_ } }) } }
            if ($Path -match '/executions$') { return [pscustomobject]@{ value = @() } }
            $null
        }
        function Send-SIRunHealthRow { param($Phase, $ExitReason, $ErrorMessage, [switch]$NoTelemetry, $RunContext) [void]$SIv3WakeHealth.Add($ExitReason) }
        function Send-SIGuardEvent { param($GuardId, $Outcome, $Engine, $Subject, $RunId, $Detail) [void]$SIv3WakeHealth.Add($GuardId) }
        function New-SIProSettingsStore { param($Server, $Database, $AppId, $TenantId, $CertThumbprint) [pscustomobject]@{ Invoke = $SIv3WakeSettings } }
        function New-SIDataSqlInvoke { param($Server, $Database, $AppId, $TenantId, $CertThumbprint) $SIv3WakeData.Invoke }
        function Write-SIAuditEvent { param() }
        }
    }
    It 'the guard says FlowBusy, the entry goes on in housekeeping-only mode, the runner removes the retired rows of collections marked before the run began -- paced, under the lease -- and starts nothing' {
        $savedEnv = @{}; foreach ($n in $script:EnvNames) { $savedEnv[$n] = [Environment]::GetEnvironmentVariable($n) }
        $savedGlobal = @{}; foreach ($n in $script:GlobalNames) { $savedGlobal[$n] = (Get-Variable -Name $n -Scope Global -ErrorAction SilentlyContinue) }
        # the seams' state: plain names, found by the stubs through the caller's scopes (a stub called from the runner script
        # has the RUNNER's script scope as $script:)
        $SIv3WakeExecs = $script:FlowExecs; $SIv3WakeArm = New-Object System.Collections.ArrayList; $SIv3WakeHealth = New-Object System.Collections.ArrayList
        $SIv3WakeData = $null; $SIv3WakeSettings = $null
        . $script:WakeStubs
        try {
            foreach ($n in $script:EnvNames) { [Environment]::SetEnvironmentVariable($n, $null) }
            foreach ($n in $script:GlobalNames) { Remove-Variable -Name $n -Scope Global -ErrorAction SilentlyContinue }
            [Environment]::SetEnvironmentVariable('CONTAINER_APP_JOB_NAME', 'caj-si-flow'); [Environment]::SetEnvironmentVariable('CONTAINER_APP_JOB_EXECUTION_NAME', 'caj-si-flow-29853040')
            [Environment]::SetEnvironmentVariable('SI_JOBS_SUBSCRIPTIONID', 'sub'); [Environment]::SetEnvironmentVariable('SI_JOBS_RESOURCEGROUP', 'rg')
            # 1. the container entry's execution guard, run as it is (exit -> return)
            $engine = 'flow'
            $g = @(. ([scriptblock]::Create($script:GuardBlock)) 3>&1 6>&1)
            $g -contains 'exited-0' | Should -BeFalse -Because 'a busy flow wake-up no longer ends at the guard'
            ($g | ForEach-Object { "$_" }) -join "`n" | Should -Match 'this wake-up starts nothing -- it only does the paced housekeeping'
            [Environment]::GetEnvironmentVariable('SI_FLOW_HOUSEKEEPING_ONLY') | Should -Be '1'
            $SIv3WakeHealth.Count | Should -Be 0 -Because 'normal operation: no run-health row, no guard event'
            # 2. the runner, as the entry dispatches it (-HostKind Container), with the settings the Pro layer loaded
            [Environment]::SetEnvironmentVariable('SI_FLOW_SUBSCRIPTIONID', 'sub'); [Environment]::SetEnvironmentVariable('SI_FLOW_RESOURCEGROUP', 'rg')
            $global:SI_ProSqlServer = 'sql.example'; $global:SI_ProSqlDatabase = 'sidb'
            # a run is going (started 25 Oct); collections 1 and 2 were marked on 20 Oct, before it; 3 and 4 are the newest two
            $state = @((Row 1 (T 1) Complete -Retired), (Row 2 (T 2) Complete -Retired), (Row 3 (T 3) Complete), (Row 4 (T 4) Complete))
            $SIv3WakeData = New-HkData -State $state -Rows @{ 1 = 5; 2 = 5; 3 = 4; 4 = 4 }
            $set = New-Settings -Runs 1 -RunStart (T 25)
            $settingsSql = New-Object System.Collections.ArrayList
            $SIv3WakeSettings = { param([string]$sql, $p, [string]$mode) [void]$settingsSql.Add($sql); & $set.Invoke $sql $p $mode }.GetNewClosure()
            # dot-sourced: in a container the runner loads the data layer into ITS OWN script scope, and that layer's tables are
            # $script: variables; here the test loaded it, so the runner runs in the test's scope chain to see the same tables
            $eap = $ErrorActionPreference
            try { $out = @(. $script:RunnerPath -HostKind Container 6>&1 3>&1) } finally { $ErrorActionPreference = $eap }
            $text = ($out | ForEach-Object { "$_" }) -join "`n"
            $LASTEXITCODE | Should -Be 0
            # the clean-up was reached and removed the rows during the run
            $SIv3WakeData.Left['1'].Count | Should -Be 0 -Because ("the clean-up removes them during the run; the runner said: " + (($out | ForEach-Object { "$_" }) -join ' || ')); $SIv3WakeData.Left['2'].Count | Should -Be 0
            $SIv3WakeData.Left['3'].Count | Should -Be 4; $SIv3WakeData.Left['4'].Count | Should -Be 4
            $rec = $set.Recorded[$set.Recorded.Count - 1] | ConvertFrom-Json
            $rec.removedRows | Should -BeGreaterOrEqual 10
            # under the lease (taken as this execution, freed at the end)
            @($settingsSql | Where-Object { $_ -match "SELECT N'taken'" }).Count | Should -Be 1
            @($settingsSql | Where-Object { $_ -match "SET Value = N''" }).Count | Should -Be 1
            # the running run's executions were asked (the data out gives way; Risk Analysis owns its collection)
            @($SIv3WakeArm | Where-Object { $_ -match 'caj-si-data-out/executions$' }).Count | Should -BeGreaterThan 0
            @($SIv3WakeArm | Where-Object { $_ -match 'caj-si-risk-analysis-detailed/executions$' }).Count | Should -BeGreaterThan 0
            # and it started nothing: no lock, no queue, no run, no start
            $text | Should -Match 'a wake-up during a run: the housekeeping is done for this wake-up; it starts nothing'
            @($settingsSql | Where-Object { $_ -match 'PipelineQueue|INSERT\s+(INTO\s+)?cfg\.FlowRun\b' }).Count | Should -Be 0
            @($SIv3WakeArm | Where-Object { $_ -notmatch '^GET ' }).Count | Should -Be 0
        } finally {
            foreach ($n in $script:EnvNames) { [Environment]::SetEnvironmentVariable($n, $savedEnv[$n]) }
            foreach ($n in $script:GlobalNames) { Remove-Variable -Name $n -Scope Global -ErrorAction SilentlyContinue; if ($savedGlobal[$n]) { Set-Variable -Name $n -Scope Global -Value $savedGlobal[$n].Value } }
        }
    }
    It 'the runner in housekeeping-only mode: the clean-up comes before its exit, and nothing that changes the install comes before the clean-up' {
        $r = [IO.File]::ReadAllText($script:RunnerPath)
        $clean = $r.IndexOf('$null = Invoke-SIDataStoppedRunCleanup -Invoke $cleanSql')
        $exit = $r.IndexOf("if (`$housekeepingOnly) {`n") ; if ($exit -lt 0) { $exit = $r.IndexOf("if (`$housekeepingOnly) {`r`n") }
        $clean | Should -BeGreaterThan 0; $exit | Should -BeGreaterThan $clean
        $exit | Should -BeLessThan $r.IndexOf("Mode -eq 'schedules' -and -not `$pipeRequest")
        $r | Should -Match ([regex]::Escape("if (`$HostKind -eq 'Container' -and `$proStore -and `$armSeams -and -not `$housekeepingOnly)"))
        $r | Should -Match ([regex]::Escape("if (`$proStore -and -not `$housekeepingOnly)"))
        $r | Should -Match ([regex]::Escape("[string]`$global:SI_ProSqlDatabase -and -not `$housekeepingOnly)"))
        # a request (Run now, a stage, a step, from a step, a cancel) is never housekeeping-only
        $r | Should -Match ([regex]::Escape('-and -not ($Cancel -or $Force -or $Stage -or $Step -or $FromStep)'))
    }
}

Describe 'on a real SQL Server' {
    BeforeAll {
        function script:New-LocalInvoke([string]$Db) {
            $cs = "Server=$($env:SI_TEST_LOCALSQL);Database=$Db;$($env:SI_TEST_SQL_AUTH);TrustServerCertificate=True"
            {
                param([string]$sql, $p, [string]$mode)
                $cn = New-Object System.Data.SqlClient.SqlConnection($cs); $cn.Open()
                try {
                    $c = $cn.CreateCommand(); $c.CommandTimeout = 600; $c.CommandText = $sql
                    if ($p) { foreach ($k in $p.Keys) { [void]$c.Parameters.AddWithValue('@' + $k, $(if ($null -eq $p[$k]) { [DBNull]::Value } else { $p[$k] })) } }
                    if ($mode -eq 'scalar') { return $c.ExecuteScalar() }
                    if ($mode -eq 'nonquery') { return $c.ExecuteNonQuery() }
                    $r = $c.ExecuteReader(); $rows = New-Object System.Collections.Generic.List[object]
                    while ($r.Read()) { $h = @{}; for ($i = 0; $i -lt $r.FieldCount; $i++) { $h[$r.GetName($i)] = $(if ($r.IsDBNull($i)) { $null } else { $r.GetValue($i) }) }; $rows.Add($h) }
                    $r.Close(); return , $rows.ToArray()
                } finally { $cn.Close() }
            }.GetNewClosure()
        }
    }
    It 'a data sync starting part way stops the removal between ranges; the next wake-up finishes; the published, the newest two and the counts stay right' -Skip:(-not $script:LocalSql) {
        $db = 'si1038hk_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
        $master = New-LocalInvoke 'master'
        [void](& $master "CREATE DATABASE [$db]" @{} 'nonquery')
        try {
            $inv = New-LocalInvoke $db
            [void](& $inv $script:Schema @{} 'nonquery')
            $add = { param([int]$Id, [string]$At, [int]$Rows)
                [void](& $inv ("SET IDENTITY_INSERT sidata.Collection ON; INSERT sidata.Collection (CollectionId, CollectionTime, Kind, Status) VALUES ({0}, '{1}', 'Detailed', 'Complete'); SET IDENTITY_INSERT sidata.Collection OFF;" -f $Id, $At) @{} 'nonquery')
                [void](& $inv ("INSERT sidata.Finding (CollectionId, AssetKey, ReportName, Severity, Tier, RiskScore) SELECT TOP ({1}) {0}, CONCAT(N'a', ROW_NUMBER() OVER (ORDER BY (SELECT NULL))), N'R', N'High', 1, 5 FROM sys.all_objects AS a CROSS JOIN sys.all_objects AS b" -f $Id, $Rows) @{} 'nonquery') }
            & $add 1 '2026-10-01T08:00:00' 4000
            & $add 2 '2026-10-02T08:00:00' 300
            & $add 3 '2026-10-03T08:00:00' 300
            & $add 4 '2026-10-04T08:00:00' 300
            [void](& $inv "UPDATE sidata.Collection SET RetiredAt = '2026-10-06T09:00:00', RetiredWhy = N'superseded' WHERE CollectionId = 1; INSERT sidata.PublishedRun (Name, DetailedCollectionId, Source, PublishedAt) VALUES (N'current', 2, N'run', '2026-10-02T12:00:00')" @{} 'nonquery')
            $cnt = { param($q) [long](& $inv $q @{} 'scalar') }
            $s = New-Settings
            # the data sync starts after six questions: the first (nothing going), the three batched tables, the empty
            # Recommendation range, ONE Finding range (at most its cap, below 4000) -- then none
            $job = New-Job -After 6 -Job 'asset-datasync'
            $r = Invoke-SIDataStoppedRunCleanup -Invoke $inv -SettingsInvoke $s.Invoke -JobRunning $job.Fn -Jobs @('asset-datasync') -NowUtc (T 7 8) -TimeBudgetSeconds 120 -Log $script:Quiet
            $r.Status | Should -Be 'ok'
            $left1 = & $cnt 'SELECT COUNT_BIG(*) FROM sidata.Finding WHERE CollectionId = 1'
            $left1 | Should -BeGreaterThan 0 -Because 'the removal stopped when the data sync started'
            $left1 | Should -BeLessThan 4000 -Because 'ranges ran before it started'
            ($s.Recorded[$s.Recorded.Count - 1] | ConvertFrom-Json).rowsLeft | Should -Be $left1
            # the next wake-up with nothing going finishes it
            $null = Invoke-SIDataStoppedRunCleanup -Invoke $inv -SettingsInvoke $s.Invoke -JobRunning { param($j) $null } -Jobs @('asset-datasync') -NowUtc (T 7 8) -TimeBudgetSeconds 120 -Log $script:Quiet
            & $cnt 'SELECT COUNT_BIG(*) FROM sidata.Finding WHERE CollectionId = 1' | Should -Be 0
            ($s.Recorded[$s.Recorded.Count - 1] | ConvertFrom-Json).state | Should -Be 'done'
            # the published (2) and the newest two (3, 4): every row, never marked
            foreach ($id in 2, 3, 4) { & $cnt "SELECT COUNT_BIG(*) FROM sidata.Finding WHERE CollectionId = $id" | Should -Be 300 }
            & $cnt 'SELECT COUNT_BIG(*) FROM sidata.Collection WHERE CollectionId IN (2, 3, 4) AND RetiredAt IS NULL' | Should -Be 3
        } finally {
            [void](& $master "ALTER DATABASE [$db] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$db]" @{} 'nonquery')
        }
    }
}

# =====================================================================================================================
#  2026-11-10 (owner: "data sync is prio 1, and data clean-up happens when idle" / "the data clean-up can be millions of rows" /
#  "just make sure that it finishes before next runs so we dont get to far behind"): the budget up to almost the next wake-up,
#  several key ranges at once, the deadline and its warning (si-data-1405) -- inside the runner's own wake-ups, no new job.
# =====================================================================================================================
Describe 'the clean-up finishes before the next run: the budget' {
    It 'a wake-up removes up to almost the NEXT wake-up of the runner''s own schedule, ending two range aims (and the last tail) before it' {
        $w = Get-SIDataHousekeepingWindow -Cron '*/5 * * * *' -NowUtc ([datetime]::SpecifyKind([datetime]'2026-11-10T10:02:30', 'Utc')) -ReserveSeconds 10
        $w.IntervalSeconds | Should -Be 300; $w.Source | Should -Be 'schedule'
        $w.NextWakeUtc | Should -Be ([datetime]::SpecifyKind([datetime]'2026-11-10T10:05:00', 'Utc'))
        $w.BudgetSeconds | Should -Be 140 -Because '150 s to the next wake-up, less the reserve'
        (Get-SIDataHousekeepingWindow -Cron '*/10 * * * *' -NowUtc ([datetime]::SpecifyKind([datetime]'2026-11-10T10:00:05', 'Utc')) -ReserveSeconds 10).BudgetSeconds | Should -Be 585
        (Get-SIDataHousekeepingWindow -Cron '0 * * * *' -NowUtc ([datetime]::SpecifyKind([datetime]'2026-11-10T10:59:00', 'Utc'))).IntervalSeconds | Should -Be 3600
        (Get-SIDataHousekeepingWindow -Cron '0,10,40 * * * *' -NowUtc ([datetime]::SpecifyKind([datetime]'2026-11-10T10:41:00', 'Utc'))).NextWakeUtc | Should -Be ([datetime]::SpecifyKind([datetime]'2026-11-10T11:00:00', 'Utc'))
        (Get-SIDataHousekeepingWindow -Cron '0,10,40 * * * *' -NowUtc ([datetime]::SpecifyKind([datetime]'2026-11-10T10:41:00', 'Utc'))).IntervalSeconds | Should -Be 600
        # a cron that does not wake every hour, or none: the schedule a new install gets
        $d = Get-SIDataHousekeepingWindow -Cron '0 2 * * *' -NowUtc ([datetime]::SpecifyKind([datetime]'2026-11-10T10:02:30', 'Utc'))
        $d.Source | Should -Be 'default'; $d.IntervalSeconds | Should -Be 300
        # the first range always runs: never a budget of 0 (0 would mean "no budget")
        (Get-SIDataHousekeepingWindow -Cron '*/5 * * * *' -NowUtc ([datetime]::SpecifyKind([datetime]'2026-11-10T10:04:58', 'Utc')) -ReserveSeconds 10).BudgetSeconds | Should -Be 1
        (Get-SIDataCronMinutes -Cron '*/15 * * * *') -join ',' | Should -Be '0,15,30,45'
        (Get-SIDataCronMinutes -Cron '5-20/5 * * * *') -join ',' | Should -Be '5,10,15,20'
        Get-SIDataCronMinutes -Cron 'x * * * *' | Should -BeNullOrEmpty
    }
    It 'wired: with the runner''s schedule the removal gets that budget -- idle and during a run -- and the lease outlasts it; without it, 120 s as before' {
        $script:Budgets = New-Object System.Collections.ArrayList
        Mock Invoke-SIDataCollectionRetention {
            [void]$script:Budgets.Add([pscustomobject]@{ Budget = $TimeBudgetSeconds; FinishOnly = [bool]$FinishOnly; Pace = $Pace })
            [pscustomobject]@{ Status = 'ok'; Plan = @(); Removed = @(); Refused = @(); Stopped = $false; Paused = ''; Text = ''; Error = ''
                               Rows = [ordered]@{ findings = 0L; recommendations = 0L; issueRows = 0L; stagedRows = 0L; defenderKeys = 0L; summaryRows = 0L; summaryAssets = 0L } }
        }
        $leases = New-Object System.Collections.ArrayList
        $base = New-Settings
        $inv = { param([string]$sql, $p, [string]$mode) if ($sql -match "SELECT N'taken'") { [void]$leases.Add([int]$p['LeaseSeconds']); return 'taken' }; & $base.Invoke $sql $p $mode }.GetNewClosure()
        $d = New-HkData -State @()
        $e1 = (Get-SIDataHousekeepingWindow -Cron '*/5 * * * *' -NowUtc ([datetime]::UtcNow)).BudgetSeconds
        $null = Invoke-SIDataStoppedRunCleanup -Invoke $d.Invoke -SettingsInvoke $inv -JobRunning { param($j) $null } -NowUtc (T 7 8) -WakeCron '*/5 * * * *' -Log $script:Quiet
        $e2 = (Get-SIDataHousekeepingWindow -Cron '*/5 * * * *' -NowUtc ([datetime]::UtcNow)).BudgetSeconds
        $script:Budgets.Count | Should -Be 1
        $script:Budgets[0].Budget | Should -BeGreaterOrEqual ([Math]::Min($e1, $e2) - 2)
        $script:Budgets[0].Budget | Should -BeLessOrEqual ([Math]::Max($e1, $e2) + 1)
        $script:Budgets[0].Pace | Should -Not -BeNullOrEmpty -Because 'a wake-up with nothing going hands its pace to the removal'
        $leases[0] | Should -Be 1200 -Because 'the wake-up interval + 15 min: longer than any budget'
        # without the runner's schedule: the fixed budget, no pace, the old lease
        $script:Budgets.Clear(); $leases.Clear()
        $null = Invoke-SIDataStoppedRunCleanup -Invoke $d.Invoke -SettingsInvoke $inv -JobRunning { param($j) $null } -NowUtc (T 7 8) -Log $script:Quiet
        $script:Budgets[0].Budget | Should -Be 120; $script:Budgets[0].Pace | Should -BeNullOrEmpty; $leases[0] | Should -Be 1020
        # during a run (no data sync, no data out): the removal of what was marked before the run gets the same budget
        $script:Budgets.Clear()
        $run = New-Settings -Runs 1 -RunStart (T 25)
        $e1 = (Get-SIDataHousekeepingWindow -Cron '*/5 * * * *' -NowUtc ([datetime]::UtcNow)).BudgetSeconds
        $null = Invoke-SIDataStoppedRunCleanup -Invoke $d.Invoke -SettingsInvoke $run.Invoke -RaRunning { $null } -JobRunning { param($j) $null } -NowUtc (T 7 8) -WakeCron '*/5 * * * *' -Log $script:Quiet
        $e2 = (Get-SIDataHousekeepingWindow -Cron '*/5 * * * *' -NowUtc ([datetime]::UtcNow)).BudgetSeconds
        $fin = @($script:Budgets | Where-Object FinishOnly)
        $fin.Count | Should -Be 1
        $fin[0].Budget | Should -BeGreaterOrEqual ([Math]::Min($e1, $e2) - 3)
        $fin[0].Budget | Should -BeLessOrEqual ([Math]::Max($e1, $e2) + 1)
        $fin[0].Pace | Should -BeNullOrEmpty -Because 'while a run goes it removes one range at a time, as before'
    }
    It 'the runner hands its own schedule (one GET of its job), the next scheduled run and its beat to the clean-up' {
        $script:Runner | Should -Match ([regex]::Escape('-WakeCron $cleanCron -NextRunUtc $cleanNext -Beat $Beat'))
        $script:Runner | Should -Match ([regex]::Escape("& `$armSeams.Arm 'GET'"))
        $script:Runner | Should -Match ([regex]::Escape('Get-SIJobFlowDue -Definition $cleanDef -Previous $cleanFlow.Load()'))
        $script:Runner | Should -Match ([regex]::Escape('$cleanCron = [string]$script:SIJobFlow.TickCron'))
    }
}

Describe 'the clean-up finishes before the next run: the width and the deadline (pure)' {
    It 'the width: the ranges the deadline asks for, from the pace reached -- never above the database''s cores; no deadline = one range' {
        Get-SIDataHousekeepingPacePlan -Max 8 -PrevRanges 3 -PrevRate 100 -NeedPerMin $null | Should -Be 1 -Because 'no scheduled run: today''s pace'
        Get-SIDataHousekeepingPacePlan -Max 8 -PrevRanges 3 -PrevRate 100 -NeedPerMin 0 | Should -Be 1
        Get-SIDataHousekeepingPacePlan -Max 8 -PrevRanges 2 -PrevRate 100 -NeedPerMin 200 | Should -Be 4 -Because 'the same pace per range'
        Get-SIDataHousekeepingPacePlan -Max 8 -PrevRanges 2 -PrevRate 100 -NeedPerMin 900 | Should -Be 8 -Because 'never above the cores'
        Get-SIDataHousekeepingPacePlan -Max 8 -PrevRanges 4 -PrevRate 400 -NeedPerMin 90 | Should -Be 1 -Because 'ahead: narrower, less load on the database'
        Get-SIDataHousekeepingPacePlan -Max 8 -PrevRanges 3 -PrevRate $null -NeedPerMin 90 | Should -Be 3 -Because 'not measured yet: the ranges of last time'
        Get-SIDataHousekeepingPacePlan -Max 1 -PrevRanges 6 -PrevRate 10 -NeedPerMin 90 | Should -Be 1 -Because 'a seam without connections: one at a time'
    }
    It 'the deadline: short and not at its widest = wider next time; short at its widest, held back by the load or on the last wake-up = behind; ahead = narrower' {
        # 6,000 rows left, 60 minutes to the run: 100 a minute needed; 1,000 removed over a 5-minute interval = 200 a minute
        $ok = Get-SIDataHousekeepingVerdict -Removed 1000 -IntervalSeconds 300 -RowsLeft 6000 -MinutesToNext 60 -Width 4 -Max 8 -RanFull $true
        $ok.Rate | Should -Be 200; $ok.Need | Should -Be 100; $ok.Short | Should -BeFalse; $ok.Behind | Should -BeFalse; $ok.Ranges | Should -Be 2
        $short = Get-SIDataHousekeepingVerdict -Removed 250 -IntervalSeconds 300 -RowsLeft 6000 -MinutesToNext 60 -Width 2 -Max 8 -RanFull $true
        $short.Short | Should -BeTrue; $short.Behind | Should -BeFalse; $short.Ranges | Should -Be 4 -Because '50 a minute at 2 ranges, 100 needed'
        $atMax = Get-SIDataHousekeepingVerdict -Removed 250 -IntervalSeconds 300 -RowsLeft 6000 -MinutesToNext 60 -Width 8 -Max 8 -RanFull $true
        $atMax.Behind | Should -BeTrue; $atMax.Ranges | Should -Be 8
        (Get-SIDataHousekeepingVerdict -Removed 250 -IntervalSeconds 300 -RowsLeft 6000 -MinutesToNext 60 -Width 2 -Max 8 -HeldBack $true -RanFull $true).Behind | Should -BeTrue -Because 'the load held it back: it cannot go wider'
        (Get-SIDataHousekeepingVerdict -Removed 250 -IntervalSeconds 300 -RowsLeft 6000 -MinutesToNext 4 -Width 2 -Max 8 -RanFull $true).Behind | Should -BeTrue -Because 'no wake-up is left before the run'
        # not judged: paused / not a full wake-up, no deadline, nothing left
        (Get-SIDataHousekeepingVerdict -Removed 10 -IntervalSeconds 300 -RowsLeft 6000 -MinutesToNext 60 -Width 8 -Max 8 -RanFull $false).Behind | Should -BeNullOrEmpty
        $nod = Get-SIDataHousekeepingVerdict -Removed 10 -IntervalSeconds 300 -RowsLeft 6000 -MinutesToNext $null -Width 1 -Max 8 -RanFull $true
        $nod.Behind | Should -BeFalse; $nod.Need | Should -BeNullOrEmpty
        (Get-SIDataHousekeepingVerdict -Removed 10 -IntervalSeconds 300 -RowsLeft 0 -MinutesToNext 60 -Width 8 -Max 8 -RanFull $true -Done $true).Behind | Should -BeFalse
    }
    It 'the record carries the pace and stays under 400 characters; behind keeps its first time and goes once nothing is left' {
        $v = Get-SIDataHousekeepingValue -State removing -CollectionsLeft 12 -RowsLeft 123456789012 -RemovedRows 1234567890 -LastRemovedAtUtc (T 22) -Why ('a data sync is running ' * 20) -AtUtc (T 23) `
                -Ranges 12 -RatePerMin 1234567 -NeedPerMin 1234567 -BehindSinceUtc (T 22) -TailSeconds 12
        $v.Length | Should -BeLessThan 400
        $o = $v | ConvertFrom-Json
        $o.ranges | Should -Be 12; $o.rate | Should -Be 1234567; $o.need | Should -Be 1234567; $o.tail | Should -Be 12
        $o.behind | Should -Not -BeNullOrEmpty
        $prev = Get-SIDataHousekeepingValue -State removing -CollectionsLeft 2 -RowsLeft 900 -Ranges 3 -RatePerMin 50 -BehindSinceUtc (T 7 6) -AtUtc (T 7 7)
        $s = New-Settings -Previous $prev
        $null = Write-SIDataHousekeepingProgress -SettingsInvoke $s.Invoke -State removing -Left @{ Collections = 2; Rows = 800 } -RemovedRows 100 -Log $script:Quiet -NowUtc (T 7 8) -Pace @{ Behind = $true; Need = 80 }
        $r = $s.Recorded[0] | ConvertFrom-Json
        ([datetime]$r.behind).ToUniversalTime() | Should -Be (T 7 6) -Because 'behind keeps its first time'
        $r.ranges | Should -Be 3; $r.rate | Should -Be 50; $r.need | Should -Be 80
        $null = Write-SIDataHousekeepingProgress -SettingsInvoke $s.Invoke -State done -Left @{ Collections = 0; Rows = 0 } -RemovedRows 800 -Log $script:Quiet -NowUtc (T 7 9)
        ($s.Recorded[1] | ConvertFrom-Json).PSObject.Properties['behind'] | Should -BeNullOrEmpty -Because 'nothing left: never behind'
    }
    It 'the statements of several ranges: the bounds and each range carry the one mark, the range refuses the published run under its lock and is cut to the cap' {
        $b = Get-SIDataRetireBoundsSql -Table Finding
        $s = Get-SIDataRetireSpanSql -Table Finding
        $mark = "EXISTS (SELECT 1 FROM sidata.Collection AS m WHERE m.CollectionId = @c AND m.Kind = N'Detailed' AND m.RetiredAt IS NOT NULL AND (@mb IS NULL OR (m.RetiredAt < @mb AND m.RetiredWhy IN (N'superseded', N'abandoned', N'stopped run', N'untrusted'))))"
        $b | Should -Match ([regex]::Escape($mark)); $s | Should -Match ([regex]::Escape($mark))
        (Get-SIDataRetireRangeSql -Table Finding) | Should -Match ([regex]::Escape($mark)) -Because 'the range driver carries the same mark'
        $s | Should -Match ([regex]::Escape("sp_getapplock @Resource = N'sidata.PublishedRun', @LockMode = N'Shared'"))
        $s | Should -Match ([regex]::Escape("AND NOT EXISTS (SELECT 1 FROM sidata.PublishedRun AS p WHERE p.Name = N''current'' AND p.DetailedCollectionId = @c)"))
        $s | Should -Match ([regex]::Escape('SELECT TOP (@cap) FindingId AS k FROM sidata.Finding WHERE CollectionId = @c AND FindingId > @lo AND FindingId <= @hi ORDER BY FindingId'))
        $s | Should -Match 'SELECT CAST\(-1 AS bigint\)'
        $b | Should -Match ([regex]::Escape('SELECT TOP (@n * @take) FindingId AS k'))
        { Get-SIDataRetireSpanSql -Table SummaryRow } | Should -Throw
    }
}

Describe 'several key ranges at once (Invoke-SIDataRetireRangesWide)' {
    BeforeAll {
        # the parallel helper's seam: each range of a wave through the fake, the waves recorded
        if (-not (Get-Command -Name Invoke-SIDataParallelRanges -ErrorAction SilentlyContinue)) {
            function Invoke-SIDataParallelRanges { param($ConnectionInfo, $Sql, $CollectionId, $Ranges, $Params, $UpperName, $Log, $StallSeconds, $WatchSeconds, $What, $Watch) }
        }
        $script:Waves = New-Object System.Collections.ArrayList
        $script:WaveData = $null
        Mock Invoke-SIDataParallelRanges {
            [void]$script:Waves.Add(@($Ranges).Count)
            , @(foreach ($r in @($Ranges)) {
                $sw = [Diagnostics.Stopwatch]::StartNew()
                $n = & $script:WaveData.Invoke $Sql @{ CollectionId = [string]$CollectionId; After = [long]$r[0]; Upto = [long]$r[1]; MarkedBefore = $Params['MarkedBefore'] } 'scalar'
                [pscustomobject]@{ N = [long]$n; Ms = [long]$sw.ElapsedMilliseconds } })
        }
    }
    BeforeEach { $script:Waves.Clear() }
    It 'removes exactly the rows one range at a time removes -- in waves as wide as asked, never wider than the cores' {
        $serial = New-WideData -Rows @{ 1 = 40 } -Marked @('1')
        $one = [long]3
        $rs = Invoke-SIDataRetireRangesWide -Invoke $serial.Invoke -Table Finding -CollectionId '1' -BatchSize ([ref]$one) -Pace @{ Width = 1; Target = 1; Max = 1 }
        $rs.Done | Should -BeTrue; $rs.Rows | Should -Be 40
        $script:Waves.Count | Should -Be 0 -Because 'one range at a time goes through the seam itself'
        $wide = New-WideData -Rows @{ 1 = 40 } -Marked @('1'); $script:WaveData = $wide
        $pace = @{ Width = 3; Target = 3; Max = 3; ConnectionInfo = { @{ ConnectionString = 'x'; AccessToken = '' } }; Log = $script:Quiet }
        $three = [long]3
        $rw = Invoke-SIDataRetireRangesWide -Invoke $wide.Invoke -Table Finding -CollectionId '1' -BatchSize ([ref]$three) -Pace $pace
        $rw.Done | Should -BeTrue; $rw.Refused | Should -BeFalse; $rw.Rows | Should -Be 40
        @($wide.Gone | Sort-Object) | Should -Be @($serial.Gone | Sort-Object) -Because 'the same rows, whatever the width'
        $pace.WidthUsed | Should -Be 3
        @($script:Waves | Where-Object { $_ -gt 3 }).Count | Should -Be 0
        # never more ranges than the cores, whatever the deadline asks
        $script:Waves.Clear(); $w2 = New-WideData -Rows @{ 1 = 40 } -Marked @('1'); $script:WaveData = $w2
        $p2 = @{ Width = 9; Target = 9; Max = 2; ConnectionInfo = { @{} }; Log = $script:Quiet }
        $null = Invoke-SIDataRetireRangesWide -Invoke $w2.Invoke -Table Finding -CollectionId '1' -BatchSize ([ref]$three) -Pace $p2
        @($script:Waves | Where-Object { $_ -gt 2 }).Count | Should -Be 0; $w2.Left['1'].Count | Should -Be 0
    }
    It 'gives way to the data sync between two waves: no range after it starts, the rows left stay for the next wake-up' {
        $d = New-WideData -Rows @{ 1 = 60 } -Marked @('1'); $script:WaveData = $d
        $asked = [ref]0
        $stop = { $asked.Value++; if ($asked.Value -gt 2) { 'the data sync is running -- it goes first' } else { '' } }.GetNewClosure()
        $three = [long]3
        $r = Invoke-SIDataRetireRangesWide -Invoke $d.Invoke -Table Finding -CollectionId '1' -BatchSize ([ref]$three) -ShouldStop $stop -Pace @{ Width = 2; Target = 2; Max = 2; ConnectionInfo = { @{} }; Log = $script:Quiet }
        $r.Stopped | Should -BeTrue; $r.StopWhy | Should -Be 'the data sync is running -- it goes first'; $r.Done | Should -BeFalse
        $script:Waves.Count | Should -Be 2 -Because 'two waves before the data sync started, none after'
        $r.Rows | Should -Be 12; $d.Left['1'].Count | Should -Be 48
    }
    It 'never the published run''s collection, never an unmarked one: refused and said, nothing counted as removed' {
        $d = New-WideData -Rows @{ 2 = 9; 3 = 9 } -Marked @('2') -Published '2'; $script:WaveData = $d
        $three = [long]3
        $r = Invoke-SIDataRetireRangesWide -Invoke $d.Invoke -Table Finding -CollectionId '2' -BatchSize ([ref]$three) -Pace @{ Width = 3; Target = 3; Max = 3; ConnectionInfo = { @{} }; Log = $script:Quiet }
        $r.Refused | Should -BeTrue; $r.Rows | Should -Be 0; $d.Left['2'].Count | Should -Be 9
        $r3 = Invoke-SIDataRetireRangesWide -Invoke $d.Invoke -Table Finding -CollectionId '3' -BatchSize ([ref]$three) -Pace @{ Width = 3; Target = 3; Max = 3; ConnectionInfo = { @{} }; Log = $script:Quiet }
        $r3.Refused | Should -BeTrue; $d.Left['3'].Count | Should -Be 9
    }
    It 'several ranges at once that fail: said, and the rest of the wake-up goes one range at a time from the last whole wave -- every row still goes' {
        $d = New-WideData -Rows @{ 1 = 30 } -Marked @('1'); $script:WaveData = $d
        Mock Invoke-SIDataParallelRanges { throw 'a connection was refused' }
        $lines = New-Object System.Collections.ArrayList
        $pace = @{ Width = 3; Target = 3; Max = 3; ConnectionInfo = { @{} }; Log = { param($l, $m) [void]$lines.Add("$l $m") }.GetNewClosure() }
        $three = [long]3
        $r = Invoke-SIDataRetireRangesWide -Invoke $d.Invoke -Table Finding -CollectionId '1' -BatchSize ([ref]$three) -Pace $pace
        $r.Done | Should -BeTrue; $r.Rows | Should -Be 30; $d.Left['1'].Count | Should -Be 0
        $pace.Max | Should -Be 1
        @($lines | Where-Object { $_ -match '^WARN housekeeping: several key ranges at once did not work \(a connection was refused\) -- this wake-up goes on one range at a time' }).Count | Should -Be 1
    }
    It 'the database''s load holds it back: the next wave is a range narrower, and it is said as held back' {
        if (-not (Get-Command -Name Invoke-SISqlPacing -ErrorAction SilentlyContinue)) { function Invoke-SISqlPacing { param($Invoke, $LastBatchMs, $Log, [switch]$Housekeeping, $DeadlineUtc) } }
        $script:PaceCalls = 0
        Mock Invoke-SISqlPacing { $script:PaceCalls++; [pscustomobject]@{ WaitedMs = 0L; Shrink = ($script:PaceCalls -eq 2); State = $(if ($script:PaceCalls -eq 2) { 'waited' } else { 'normal' }); Load = $null; Deadline = $false; Calm = ($script:PaceCalls -ne 2) } }
        $d = New-WideData -Rows @{ 1 = 60 } -Marked @('1'); $script:WaveData = $d
        $pace = @{ Width = 3; Target = 3; Max = 3; ConnectionInfo = { @{} }; Log = $script:Quiet }
        $three = [long]3
        $r = Invoke-SIDataRetireRangesWide -Invoke $d.Invoke -Table Finding -CollectionId '1' -BatchSize ([ref]$three) -Pace $pace
        $r.Done | Should -BeTrue; $d.Left['1'].Count | Should -Be 0
        $pace.HeldBack | Should -BeTrue
        $script:Waves[0] | Should -Be 3; $script:Waves[1] | Should -Be 2 -Because 'one range fewer after the load held it back'
        ($script:Waves | Measure-Object -Maximum).Maximum | Should -Be 3 -Because 'back up to the width the deadline asks once it is calm'
        $script:Waves[2] | Should -Be 3
    }
    It 'support ticket 2026-11-10 (database at its limit): from ONE range it widens one a wave only on a calm database -- an unknown or middling load keeps it at one' {
        if (-not (Get-Command -Name Invoke-SISqlPacing -ErrorAction SilentlyContinue)) { function Invoke-SISqlPacing { param($Invoke, $LastBatchMs, $Log, [switch]$Housekeeping, $DeadlineUtc) } }
        $three = [long]3
        # not calm (unknown, or between the marks): it stays at one range -- through the seam itself, no wave
        Mock Invoke-SISqlPacing { [pscustomobject]@{ WaitedMs = 0L; Shrink = $false; State = 'normal'; Load = $null; Deadline = $false; Calm = $false } }
        $d = New-WideData -Rows @{ 1 = 30 } -Marked @('1'); $script:WaveData = $d
        $pace = @{ Width = 1; Target = 3; Max = 3; ConnectionInfo = { @{} }; Log = $script:Quiet }
        $r = Invoke-SIDataRetireRangesWide -Invoke $d.Invoke -Table Finding -CollectionId '1' -BatchSize ([ref]$three) -Pace $pace
        $r.Done | Should -BeTrue; $d.Left['1'].Count | Should -Be 0
        $script:Waves.Count | Should -Be 0 -Because 'never wider than one range on a database that is not calm'
        $pace.Width | Should -Be 1
        # calm: one range wider a wave, up to the target
        $script:Waves.Clear()
        Mock Invoke-SISqlPacing { [pscustomobject]@{ WaitedMs = 0L; Shrink = $false; State = 'normal'; Load = $null; Deadline = $false; Calm = $true } }
        $d2 = New-WideData -Rows @{ 1 = 60 } -Marked @('1'); $script:WaveData = $d2
        $p2 = @{ Width = 1; Target = 3; Max = 3; ConnectionInfo = { @{} }; Log = $script:Quiet }
        $null = Invoke-SIDataRetireRangesWide -Invoke $d2.Invoke -Table Finding -CollectionId '1' -BatchSize ([ref]$three) -Pace $p2
        $d2.Left['1'].Count | Should -Be 0
        $script:Waves[0] | Should -Be 2 -Because 'one wider than the start, never straight to the target'
        $script:Waves[1] | Should -Be 3
    }
    It 'every wake-up starts the clean-up at ONE range, never at the planned width' {
        $src = Get-Content -Raw -LiteralPath (Join-Path $script:Root 'engine\_shared\data-sql\SI-DataSql.ps1')
        $src | Should -Match '\$pace = @\{ Width = 1; Target = \$target;'
    }
}

Describe 'the deadline end to end: a clean-up that cannot keep up says so (the heartbeat''s si-data-1405: SIv3-HeartbeatFields)' {
    It 'falls short at its widest before the next run: a WARN line, behind recorded (what the heartbeat raises as si-data-1405)' {
        $state = @((Row 1 (T 1) Complete -Retired), (Row 3 (T 3) Complete), (Row 4 (T 4) Complete))
        $d = New-WideData -Rows @{ 1 = 600; 3 = 4; 4 = 4 } -Cap 2 -Marked @('1') -SpanMs 150 -State $state
        # the last wake-up measured little and needed a long time after its removal: this one has a budget of one second
        $prev = Get-SIDataHousekeepingValue -State removing -CollectionsLeft 1 -RowsLeft 600 -Ranges 1 -RatePerMin 1 -TailSeconds 100000 -AtUtc ([datetime]::UtcNow.AddMinutes(-5))
        $s = New-Settings -Previous $prev
        $lines = New-Object System.Collections.ArrayList
        $say = { param($l, $m) [void]$lines.Add("$l $m") }.GetNewClosure()
        $r = Invoke-SIDataStoppedRunCleanup -Invoke $d.Invoke -SettingsInvoke $s.Invoke -JobRunning { param($j) $null } -NowUtc ([datetime]::UtcNow) -WakeCron '*/5 * * * *' -NextRunUtc { [datetime]::UtcNow.AddMinutes(10) } -Log $say
        $r.Status | Should -Be 'ok'
        $r.Window.BudgetSeconds | Should -Be 1
        $r.Verdict.Short | Should -BeTrue; $r.Verdict.Behind | Should -BeTrue -Because 'one range is all this seam has (no connections): it cannot go wider'
        $d.Left['1'].Count | Should -BeGreaterThan 0; $d.Left['1'].Count | Should -BeLessThan 600
        $d.Left['3'].Count | Should -Be 4; $d.Left['4'].Count | Should -Be 4 -Because 'the newest two keep every row'
        @($lines | Where-Object { $_ -match '^WARN housekeeping: the clean-up of old data cannot keep up -- about [\d,]+ row\(s\) are left and the next run starts .*Support is told\.$' }).Count | Should -Be 1
        $rec = $s.Recorded[$s.Recorded.Count - 1]
        $o = $rec | ConvertFrom-Json
        $o.state | Should -Be 'removing'; $o.behind | Should -Not -BeNullOrEmpty; $o.need | Should -BeGreaterThan 0; $o.ranges | Should -Be 1
    }
    It 'nothing scheduled after it (no deadline): never behind, one range at a time' {
        $state = @((Row 1 (T 1) Complete -Retired), (Row 3 (T 3) Complete), (Row 4 (T 4) Complete))
        $d = New-WideData -Rows @{ 1 = 30 } -Cap 2 -Marked @('1') -State $state
        $s = New-Settings
        $r = Invoke-SIDataStoppedRunCleanup -Invoke $d.Invoke -SettingsInvoke $s.Invoke -JobRunning { param($j) $null } -NowUtc ([datetime]::UtcNow) -WakeCron '*/5 * * * *' -NextRunUtc { $null } -Log $script:Quiet
        $r.Status | Should -Be 'ok'; $d.Left['1'].Count | Should -Be 0
        $o = $s.Recorded[$s.Recorded.Count - 1] | ConvertFrom-Json
        $o.state | Should -Be 'done'; $o.PSObject.Properties['behind'] | Should -BeNullOrEmpty
    }
}

Describe 'several key ranges at once on a real SQL Server' {
    BeforeAll {
        # the parallel helper and the database's cores (the discovery's flag is not there at run time: the environment is asked)
        if ($env:SI_TEST_LOCALSQL) { . (Join-Path $script:Root 'engine\pro-data\_shared\SI-DataViewContext.ps1') }
        function script:New-LocalSeam([string]$Db) {
            $cs = "Server=$($env:SI_TEST_LOCALSQL);Database=$Db;$($env:SI_TEST_SQL_AUTH);TrustServerCertificate=True"
            $inv = {
                param([string]$sql, $p, [string]$mode)
                $cn = New-Object System.Data.SqlClient.SqlConnection($cs); $cn.Open()
                try {
                    $c = $cn.CreateCommand(); $c.CommandTimeout = 600; $c.CommandText = $sql
                    if ($p) { foreach ($k in $p.Keys) { [void]$c.Parameters.AddWithValue('@' + $k, $(if ($null -eq $p[$k]) { [DBNull]::Value } else { $p[$k] })) } }
                    if ($mode -eq 'scalar') { return $c.ExecuteScalar() }
                    if ($mode -eq 'nonquery') { return $c.ExecuteNonQuery() }
                    $r = $c.ExecuteReader(); $rows = New-Object System.Collections.Generic.List[object]
                    while ($r.Read()) { $h = @{}; for ($i = 0; $i -lt $r.FieldCount; $i++) { $h[$r.GetName($i)] = $(if ($r.IsDBNull($i)) { $null } else { $r.GetValue($i) }) }; $rows.Add($h) }
                    $r.Close(); return , $rows.ToArray()
                } finally { $cn.Close() }
            }.GetNewClosure()
            $inv | Add-Member -NotePropertyName SIConnectionInfo -NotePropertyValue ({ @{ ConnectionString = $cs; AccessToken = '' } }.GetNewClosure())
            $inv
        }
    }
    It 'the same rows as one range at a time; the newest two and the published one keep every row; the published one is refused; a data sync stops it between waves' -Skip:(-not $script:LocalSql) {
        $db = 'si1174hk_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
        $master = New-LocalSeam 'master'
        [void](& $master "CREATE DATABASE [$db]" @{} 'nonquery')
        try {
            $inv = New-LocalSeam $db
            [void](& $inv $script:Schema @{} 'nonquery')
            $add = { param([int]$Id, [string]$At, [int]$Rows)
                [void](& $inv ("SET IDENTITY_INSERT sidata.Collection ON; INSERT sidata.Collection (CollectionId, CollectionTime, Kind, Status) VALUES ({0}, '{1}', 'Detailed', 'Complete'); SET IDENTITY_INSERT sidata.Collection OFF;" -f $Id, $At) @{} 'nonquery')
                [void](& $inv ("INSERT sidata.Finding (CollectionId, AssetKey, ReportName, Severity, Tier, RiskScore) SELECT TOP ({1}) {0}, CONCAT(N'a', ROW_NUMBER() OVER (ORDER BY (SELECT NULL))), N'R', N'High', 1, 5 FROM sys.all_objects AS a CROSS JOIN sys.all_objects AS b" -f $Id, $Rows) @{} 'nonquery') }
            # 1 and 5: twins, marked; 6: marked, for the give-way; 2: marked AND published; 3, 4: the newest two
            & $add 1 '2026-10-01T08:00:00' 5000
            & $add 5 '2026-10-01T09:00:00' 5000
            & $add 6 '2026-10-01T10:00:00' 5000
            & $add 2 '2026-10-02T08:00:00' 300
            & $add 3 '2026-10-03T08:00:00' 300
            & $add 4 '2026-10-04T08:00:00' 300
            [void](& $inv "UPDATE sidata.Collection SET RetiredAt = '2026-10-06T09:00:00', RetiredWhy = N'superseded' WHERE CollectionId IN (1, 2, 5, 6); INSERT sidata.PublishedRun (Name, DetailedCollectionId, Source, PublishedAt) VALUES (N'current', 2, N'run', '2026-10-02T12:00:00')" @{} 'nonquery')
            $cnt = { param($q) [long](& $inv $q @{} 'scalar') }
            $keep = @(& $inv 'SELECT FindingId FROM sidata.Finding WHERE CollectionId IN (2, 3, 4) ORDER BY FindingId' @{} 'reader' | ForEach-Object { [long]$_['FindingId'] })
            # one range at a time (the range driver) and several at once (the cores of this server, at least 2)
            $b1 = [long]5000
            $serial = Invoke-SIDataRetireRangeDelete -Invoke $inv -Table Finding -CollectionId '1' -BatchSize ([ref]$b1)
            $cores = [Math]::Max(2, (Get-SIDataFillWorkers -Invoke $inv))
            $pace = @{ Width = $cores; Target = $cores; Max = $cores; ConnectionInfo = $inv.SIConnectionInfo; Log = $script:Quiet }
            $b2 = [long]5000
            $wide = Invoke-SIDataRetireRangesWide -Invoke $inv -Table Finding -CollectionId '5' -BatchSize ([ref]$b2) -Pace $pace
            $serial.Done | Should -BeTrue; $wide.Done | Should -BeTrue
            $wide.Rows | Should -Be $serial.Rows; $wide.Rows | Should -Be 5000
            $pace.WidthUsed | Should -BeGreaterThan 1 -Because 'several ranges ran at once'
            & $cnt 'SELECT COUNT_BIG(*) FROM sidata.Finding WHERE CollectionId IN (1, 5)' | Should -Be 0
            # the published one: refused by the database, every row stays
            $b3 = [long]5000
            (Invoke-SIDataRetireRangesWide -Invoke $inv -Table Finding -CollectionId '2' -BatchSize ([ref]$b3) -Pace @{ Width = $cores; Target = $cores; Max = $cores; ConnectionInfo = $inv.SIConnectionInfo; Log = $script:Quiet }).Refused | Should -BeTrue
            # the data sync starts after two waves: nothing after it, the rest stays for the next wake-up
            $asked = [ref]0
            $stop = { $asked.Value++; if ($asked.Value -gt 2) { 'the data sync is running -- it goes first' } else { '' } }.GetNewClosure()
            $b4 = [long]100
            $gw = Invoke-SIDataRetireRangesWide -Invoke $inv -Table Finding -CollectionId '6' -BatchSize ([ref]$b4) -ShouldStop $stop -Pace @{ Width = 2; Target = 2; Max = 2; ConnectionInfo = $inv.SIConnectionInfo; Log = $script:Quiet }
            $gw.StopWhy | Should -Be 'the data sync is running -- it goes first'
            $left6 = & $cnt 'SELECT COUNT_BIG(*) FROM sidata.Finding WHERE CollectionId = 6'
            $left6 | Should -Be (5000 - $gw.Rows); $left6 | Should -BeGreaterThan 0
            # the published and the newest two: exactly the same rows
            @(& $inv 'SELECT FindingId FROM sidata.Finding WHERE CollectionId IN (2, 3, 4) ORDER BY FindingId' @{} 'reader' | ForEach-Object { [long]$_['FindingId'] }) | Should -Be $keep
        } finally {
            [System.Data.SqlClient.SqlConnection]::ClearAllPools()
            [void](& $master "ALTER DATABASE [$db] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$db]" @{} 'nonquery')
        }
    }
}
