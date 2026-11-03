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
        $svc = Get-Service -Name 'MSSQL$SQLEXPRESS' -ErrorAction Stop
        if ($svc.Status -ne 'Running' -and [string]$svc.StartType -ne 'Disabled') { try { $svc.WaitForStatus('Running', [TimeSpan]::FromMinutes(5)) } catch { }; $svc.Refresh() }
        $script:LocalSql = $svc.Status -eq 'Running' -and $null -ne ('System.Data.SqlClient.SqlConnection' -as [type])
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
        # a data sync running does not stop it (the data out does, below)
        $r = Invoke-SIDataStoppedRunCleanup -Invoke $d.Invoke -SettingsInvoke $s.Invoke -RaRunning { $null } -JobRunning (New-Job -Job 'asset-datasync').Fn -NowUtc (T 7 8) -TimeBudgetSeconds 60 -Log $script:Quiet
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
            foreach ($c in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -in 'Invoke-SIDataRetireRangeDelete', 'Get-SIDataRetireBatchSql', 'Remove-SIDataCollectionRows' }, $true)) {
                $fn = $c.Parent; while ($fn -and -not ($fn -is [System.Management.Automation.Language.FunctionDefinitionAst])) { $fn = $fn.Parent }
                '{0}>{1}' -f $(if ($fn) { $fn.Name } else { '' }), $c.GetCommandName()
            }
        }
        @($calls | Sort-Object -Unique) | Should -Be @('Invoke-SIDataCollectionRetention>Remove-SIDataCollectionRows', 'Remove-SIDataCollectionRows>Get-SIDataRetireBatchSql', 'Remove-SIDataCollectionRows>Invoke-SIDataRetireRangeDelete')
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

Describe 'on a real SQL Server' {
    BeforeAll {
        function script:New-LocalInvoke([string]$Db) {
            $cs = "Server=.\SQLEXPRESS;Database=$Db;Integrated Security=True;TrustServerCertificate=True"
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
