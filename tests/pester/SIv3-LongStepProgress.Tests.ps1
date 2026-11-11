#Requires -Version 7.0
<#
    #1180 -- A LONG PHASE SHOWS IT IS MOVING (Invardia 2026-11-11: six false "a step is not moving" tickets in one night; every
    step was moving, but a long phase said nothing until it ended). Progress only: nothing here may change a result.

    What these tests keep true (offline, fake clocks and fake databases):
      * THE TICKER (engine\_shared\SI-StepPhase.ps1 New-SIStepProgressTicker / Step-SIStepProgressTicker): on a fake long run it
        says done / total in ONE plain line and writes it as the step's progress record (cfg.StepProgress: phase + done / total,
        which also moves the step's newest sign of progress) AT MOST every few minutes -- never twice inside its interval,
        never when the count did not move (a phase that stands still still shows as still), never throws;
      * (a) the risk analysis scale-out wait: the query slices of the reports still running are in its line and in the step's
        progress record, which moves only when reports or slices moved; a record of a report that has ended is left out;
        without the new seams the line and the wait are exactly as before;
      * (b) the key figures' read of the rows (Invoke-RAKpiPass -Progress) says rows read of all every few minutes and gives
        the SAME result with and without it; the AI summary's pass is wired to the same ticker;
      * (c) the data sync's long parts: the views' prepared context (rows filled of all) and the grouped Summary rows
        (collections done of all) write the step's progress record at the cadence on a fake long run, with the same result;
        key figures and the findings per CI are wired to the ticker;
      * (d) the CI build steps the ticker at every batch (batches done of all) -- a fake 266-batch build at ~2.7 min a batch
        records its progress every batch, and the build loads the ticker by its own path.
    NO EMOJI IN THIS FILE.
#>

BeforeAll {
    $script:Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:Root 'engine\_shared\SI-StepPhase.ps1')
    $script:T0 = [datetime]::SpecifyKind([datetime]'2026-11-11T01:00:00', 'Utc')
    # a fake settings database: records every statement; the progress record is the MERGE
    function script:New-ProgDb {
        $calls = New-Object System.Collections.Generic.List[object]
        $inv = { param($sql, $p, $mode) $calls.Add([pscustomobject]@{ Sql = [string]$sql; P = $p; Mode = $mode }); 1 }.GetNewClosure()
        [pscustomobject]@{ Calls = $calls; Invoke = $inv }
    }
    function script:Get-Merges($Db) { @($Db.Calls | Where-Object { $_.Sql -match 'MERGE cfg\.StepProgress' }) }
    $script:SavedExec = $env:CONTAINER_APP_JOB_EXECUTION_NAME
}
AfterAll {
    $env:CONTAINER_APP_JOB_EXECUTION_NAME = $script:SavedExec
    $global:SI_StepProgressTickerNow = $null
}

Describe 'the progress ticker' {
    BeforeEach { $env:CONTAINER_APP_JOB_EXECUTION_NAME = 'caj-si-risk-analysis-detailed-t1'; $script:now = $script:T0 }
    It 'words done / total plainly, with thousands separators whatever the host culture' {
        $old = [System.Threading.Thread]::CurrentThread.CurrentCulture
        try {
            [System.Threading.Thread]::CurrentThread.CurrentCulture = 'da-DK'
            Format-SIStepProgressText -Unit 'rows' -Done 1203400 -Total 1703142 | Should -Be 'rows 1,203,400 of 1,703,142'
            Format-SIStepProgressText -Unit 'batch' -Done 161 -Total 266 | Should -Be 'batch 161 of 266'
            Format-SIStepProgressText -Unit 'query slices' -Done 412 -Total 544 | Should -Be 'query slices 412 of 544'
            Format-SIStepProgressText -Unit 'rows' -Done 5000 | Should -Be 'rows 5,000'
        } finally { [System.Threading.Thread]::CurrentThread.CurrentCulture = $old }
    }
    It 'a fake 2-hour read: one line and one progress record every 3 minutes at most, with the phase, done and total' {
        $db = New-ProgDb
        $log = New-Object System.Collections.Generic.List[string]
        $t = New-SIStepProgressTicker -What 'the AI summary and key figures read the rows' -Unit 'rows' -Total 1703142 -Invoke $db.Invoke -Job 'risk-analysis-detailed' `
                -Log { param($l, $m) $log.Add("$l $m") }.GetNewClosure() -Now { $script:now }
        $done = 0L; $said = New-Object System.Collections.Generic.List[datetime]
        # a page every 20 s, 240 rows a page (2 h)
        for ($i = 0; $i -lt 360; $i++) {
            $script:now = $script:now.AddSeconds(20); $done += 240
            if (Step-SIStepProgressTicker -Ticker $t -Done $done) { $said.Add($script:now) }
        }
        $said.Count | Should -Be 40 -Because '7200 s / 180 s'
        for ($k = 1; $k -lt $said.Count; $k++) { ($said[$k] - $said[$k - 1]).TotalSeconds | Should -BeGreaterOrEqual 180 }
        $log.Count | Should -Be 40
        $log[0] | Should -Be 'INFO the AI summary and key figures read the rows: rows 2,160 of 1,703,142 done (3 min so far)'
        foreach ($l in $log) { $l | Should -Not -Match '#\d|\[|audit' -Because 'plain words, nothing internal' }
        $m = @(Get-Merges $db)
        $m.Count | Should -Be 40
        $m[0].P.Phase | Should -Be 'the AI summary and key figures read the rows: rows 2,160 of 1,703,142'
        $m[0].P.Done | Should -Be 2160; $m[0].P.Total | Should -Be 1703142
        $m[0].P.Job | Should -Be 'risk-analysis-detailed'
        $m[0].P.Execution | Should -Be 'caj-si-risk-analysis-detailed-t1'
        $m[0].Mode | Should -Be 'nonquery'
        $t.Marks | Should -Be 40
    }
    It 'a count that does not move says nothing and writes nothing -- a phase that stands still stays still' {
        $db = New-ProgDb
        $t = New-SIStepProgressTicker -What 'x' -Unit 'rows' -Total 100 -Invoke $db.Invoke -Now { $script:now }
        $script:now = $script:now.AddMinutes(5); Step-SIStepProgressTicker -Ticker $t -Done 10 | Should -BeTrue
        for ($i = 0; $i -lt 30; $i++) { $script:now = $script:now.AddMinutes(5); Step-SIStepProgressTicker -Ticker $t -Done 10 | Should -BeFalse }
        @(Get-Merges $db).Count | Should -Be 1
        # nothing done yet: nothing to say
        $t2 = New-SIStepProgressTicker -What 'x' -Unit 'rows' -Invoke $db.Invoke -Now { $script:now }
        $script:now = $script:now.AddMinutes(10); Step-SIStepProgressTicker -Ticker $t2 -Done 0 | Should -BeFalse
    }
    It 'never throws: a database that refuses, no ticker, no execution (a run outside a job writes no record)' {
        $bad = { param($sql, $p, $mode) throw 'database gone' }
        $t = New-SIStepProgressTicker -What 'x' -Unit 'rows' -Invoke $bad -Log { param($l, $m) } -Now { $script:now }
        $script:now = $script:now.AddMinutes(4)
        { Step-SIStepProgressTicker -Ticker $t -Done 5 } | Should -Not -Throw
        $t.Marks | Should -Be 0
        Step-SIStepProgressTicker -Ticker $null -Done 5 | Should -BeFalse
        $env:CONTAINER_APP_JOB_EXECUTION_NAME = ''
        $db = New-ProgDb
        $t3 = New-SIStepProgressTicker -What 'x' -Unit 'rows' -Invoke $db.Invoke -Now { $script:now }
        $script:now = $script:now.AddMinutes(4)
        Step-SIStepProgressTicker -Ticker $t3 -Done 5 | Should -BeTrue
        $db.Calls.Count | Should -Be 0
    }
    It 'reads the workers'' progress records through the settings seam, never throwing' {
        $q = Get-SIStepProgressRowsSql
        $q | Should -Match "IF OBJECT_ID\(N'cfg\.StepProgress'\) IS NOT NULL"
        $q | Should -Match 'WHERE Job = @Job AND LastUtc >= TRY_CONVERT\(datetime2\(3\), @SinceUtc, 126\) AND Phase LIKE @PhasePrefix'
        $q | Should -Not -Match 'UPDATE|INSERT|DELETE|MERGE'
        $inv = { param($sql, $p, $mode) $script:gotP = $p; @(@{ Execution = 'w1'; Phase = 'report A'; Done = 3; Total = 10 }, @{ Execution = 'w2'; Phase = 'report B'; Done = [DBNull]::Value; Total = $null }) }
        $r = @(Get-SIStepProgressRows -Invoke $inv -Job 'risk-analysis-detailed' -SinceUtc $script:T0 -PhasePrefix 'report ')
        $r.Count | Should -Be 2
        $r[0].Done | Should -Be 3; $r[1].Done | Should -Be -1; $r[1].Total | Should -Be -1
        $script:gotP.PhasePrefix | Should -Be 'report '
        $script:gotP.SinceUtc | Should -Be '2026-11-11T01:00:00.000'
        @(Get-SIStepProgressRows -Invoke { throw 'no' } -Job 'x' -SinceUtc $script:T0).Count | Should -Be 0
    }
}

Describe '(a) the risk analysis scale-out wait shows the query slices of the running reports' {
    BeforeAll {
        . (Join-Path $script:Root 'engine\risk-analysis\_shared\RA-ScaleOut.ps1')
        . (Join-Path $script:Root 'container\_shared\SI-ContainerConfig.ps1')
        function script:New-MemStore {
            $docs = [hashtable]::Synchronized(@{})
            [pscustomobject]@{
                Docs   = $docs
                Read   = { param($p) if ($docs.ContainsKey($p)) { $docs[$p] } else { $null } }.GetNewClosure()
                Write  = { param($p, $t) $docs[$p] = $t }.GetNewClosure()
                List   = { param($pre) @($docs.Keys | Where-Object { $_.StartsWith($pre) } | Sort-Object) }.GetNewClosure()
                Claim  = { param($p, $t) if ($docs.ContainsKey($p)) { $false } else { $docs[$p] = $t; $true } }.GetNewClosure()
                Remove = { param($p) $docs.Remove($p) }.GetNewClosure()
            }
        }
        $script:Plan = New-RAScaleOutPlan -Reports @([pscustomobject]@{ Name = 'Small_Detailed'; HasEntry = $true }, [pscustomobject]@{ Name = 'Device_Missing_CVEs_Detailed'; HasEntry = $true }, [pscustomobject]@{ Name = 'Other_Detailed'; HasEntry = $true })
    }
    BeforeEach {
        $script:st = New-MemStore
        $script:m = New-RAScaleOutManifest -Grain Detailed -TimeText '2026-11-11T01:00:00.000' -CollectionTime $script:T0 -CollectionId 7 -Items $script:Plan -Now $script:T0
        $script:now = $script:T0; $script:N = { $script:now }
        $script:log = New-Object System.Collections.Generic.List[string]; $script:L = { param($l, $t) $script:log.Add($t) }
        $script:mark = { param($i) Write-SICollectPartMarker -Store $script:st -Engine 'ra-detailed' -RunId $script:m.RunId -Marker (New-SICollectPartMarker -Part $i -State done) }
        foreach ($i in 0..2) { & $script:st.Write (Get-RAScaleOutPath -Engine 'ra-detailed' -RunId $script:m.RunId -Kind started -Item $i) '{"Worker":"w"}' }
    }
    It 'the line: unchanged without slices; with them, the running reports'' query slices done of all' {
        Format-RAScaleOutProgress -Items 72 -Done 4 -Failed 0 -Started 6 | Should -Be '[scale-out] 4 of 72 report(s) done, 2 running, 66 waiting for a worker'
        Format-RAScaleOutProgress -Items 72 -Done 4 -Failed 0 -Started 6 -SlicesDone 412 -SlicesTotal 544 | Should -Be '[scale-out] 4 of 72 report(s) done, 2 running, 66 waiting for a worker; the running reports: query slices 412 of 544 done'
        Format-RAScaleOutProgress -Items 72 -Done 4 -Failed 0 -Started 6 -SlicesDone 0 -SlicesTotal 0 | Should -Be '[scale-out] 4 of 72 report(s) done, 2 running, 66 waiting for a worker'
    }
    It 'counts only the records of reports still open, as ''report <name>'' (never the producer''s own ''reports ...'')' {
        $open = @(Get-RAScaleOutOpenReports -Manifest $script:m -Markers @([pscustomobject]@{ Part = 0 }))
        ($open | Sort-Object) -join ',' | Should -Be 'Device_Missing_CVEs_Detailed,Other_Detailed'
        $rows = @(@{ Phase = 'report Device_Missing_CVEs_Detailed'; Done = 20; Total = 34 }, @{ Phase = 'report Device_Missing_CVEs_Detailed'; Done = 7; Total = 34 },
                  @{ Phase = 'report Small_Detailed'; Done = 0; Total = 1 }, @{ Phase = 'reports 1 of 3 done'; Done = 1; Total = 3 }, @{ Phase = 'report Other_Detailed'; Done = -1; Total = -1 })
        $p = Get-RAScaleOutSliceProgress -Rows $rows -OpenReports $open
        $p.Done | Should -Be 27; $p.Total | Should -Be 68
        Get-RAScaleOutSliceProgress -Rows @() -OpenReports $open | Should -BeNullOrEmpty
    }
    It 'a fake 3-hour run of one huge report: the record moves with its slices every 5 minutes, and not while nothing moves' {
        # Small done early, Other done at 30 min, the huge one (4 parts x 34 slices) a slice every ~80 s, then stands still 40 min, then ends
        $script:slices = 0L; $script:polls = 0
        $script:S = {
            param($s)
            $script:now = $script:now.AddSeconds($s); $script:polls++
            $min = ($script:now - $script:T0).TotalMinutes
            if ($script:polls -eq 3) { & $script:mark 0 }
            if ($script:polls -eq 90) { & $script:mark 2 }
            if ($min -lt 140) { if ($script:polls % 3 -eq 0) { $script:slices = [Math]::Min(135, $script:slices + 1) } }
            if ($min -ge 180) { & $script:mark 1 }
        }
        $slice = { param($open) if ($open -contains 'Device_Missing_CVEs_Detailed') { @{ Done = $script:slices; Total = 136 } } else { $null } }
        $script:calls = New-Object System.Collections.Generic.List[object]
        $on = { param($rd, $rn, $sd, $st) $script:calls.Add([pscustomobject]@{ At = $script:now; Reports = $rd; Of = $rn; Slices = $sd; Total = $st }) }
        $w = Wait-RAScaleOutItems -Store $script:st -Manifest $script:m -UseKeda $true -LocalWorker { throw 'not expected' } -Sleep $script:S -Now $script:N -Log $script:L -SliceProgress $slice -OnProgress $on
        $w.State | Should -Be 'succeeded'
        $lines = @($script:log | Where-Object { $_ -match 'query slices' })
        $lines.Count | Should -BeGreaterThan 20
        $lines[-1] | Should -Match '; the running reports: query slices 135 of 136 done$'
        $script:calls.Count | Should -BeGreaterThan 20
        for ($k = 1; $k -lt $script:calls.Count; $k++) {
            ($script:calls[$k].At - $script:calls[$k - 1].At).TotalSeconds | Should -BeGreaterOrEqual 300
            ($script:calls[$k].Slices -gt $script:calls[$k - 1].Slices -or $script:calls[$k].Reports -gt $script:calls[$k - 1].Reports) | Should -BeTrue -Because 'a record only when something moved'
        }
        # the 40 minutes in which nothing moved wrote no record
        @($script:calls | Where-Object { ($_.At - $script:T0).TotalMinutes -gt 142 -and ($_.At - $script:T0).TotalMinutes -lt 180 }).Count | Should -Be 0
        $script:calls[-1].Of | Should -Be 3
    }
    It 'a seam that throws never stops the wait; without the seams the wait is as before' {
        $script:polls = 0
        $script:S = { param($s) $script:now = $script:now.AddSeconds($s); $script:polls++; if ($script:polls -eq 30) { foreach ($i in 0..2) { & $script:mark $i } } }
        $w = Wait-RAScaleOutItems -Store $script:st -Manifest $script:m -UseKeda $true -LocalWorker { throw 'x' } -Sleep $script:S -Now $script:N -Log $script:L -SliceProgress { throw 'db gone' } -OnProgress { throw 'db gone' }
        $w.State | Should -Be 'succeeded'
        $script:log.Clear(); $script:polls = 0; $script:st = New-MemStore
        foreach ($i in 0..2) { & $script:st.Write (Get-RAScaleOutPath -Engine 'ra-detailed' -RunId $script:m.RunId -Kind started -Item $i) '{"Worker":"w"}' }
        $w2 = Wait-RAScaleOutItems -Store $script:st -Manifest $script:m -UseKeda $true -LocalWorker { throw 'x' } -Sleep $script:S -Now $script:N -Log $script:L
        $w2.State | Should -Be 'succeeded'
        @($script:log | Where-Object { $_ -match 'query slices' }).Count | Should -Be 0
    }
    It 'the wiring: the producer passes the workers'' records and writes the step''s progress record' {
        $ra = [IO.File]::ReadAllText((Join-Path $script:Root 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'))
        $ra | Should -Match ([regex]::Escape('-SliceProgress { param($open) Get-RAScaleOutSliceProgress -Rows (Get-RAWorkerSliceRows -Stream $script:RAStream -SinceUtc $__soSince) -OpenReports $open }'))
        $ra | Should -Match ([regex]::Escape('-OnProgress { param($rd, $rn, $sd, $st) Write-RAStepProgressRow -Stream $script:RAStream -Phase'))
        $s = [IO.File]::ReadAllText((Join-Path $script:Root 'engine\risk-analysis\_shared\RA-SqlStream.ps1'))
        $s | Should -Match ([regex]::Escape("Get-SIStepProgressRows -Invoke `$Stream.Invoke -Job (Get-RAStepPhaseJob -Stream `$Stream) -SinceUtc `$SinceUtc -PhasePrefix 'report '"))
    }
}

Describe '(b) the key figures'' read of the rows says how far it is' {
    BeforeAll {
        . (Join-Path $script:Root 'engine\risk-analysis\_shared\RA-RiskScore.ps1')
        . (Join-Path $script:Root 'engine\risk-analysis\_shared\RA-AISummaryMode.ps1')
        . (Join-Path $script:Root 'engine\risk-analysis\_shared\RA-KpiTally.ps1')
        function Write-Info { param($m) }
        function Write-Warn2 { param($m) }
        $script:Saved = @{}; foreach ($g in 'ReportTemplate', 'RA_CiIndex', 'RA_CiIndexProblem', 'SI_ProSettingsVersion') { $script:Saved[$g] = (Get-Variable -Name $g -Scope Global -ValueOnly -ErrorAction SilentlyContinue) }
        $global:ReportTemplate = 'RiskAnalysis_Detailed'; $global:RA_CiIndex = $null; $global:RA_CiIndexProblem = $null; $global:SI_ProSettingsVersion = $null
        $script:RAStreamOn = $false
        $sevs = @('Critical', 'High', 'Medium', 'Low')
        $script:Rows = @(for ($i = 0; $i -lt 3000; $i++) { [pscustomobject]@{ Report = 'Device_Vulnerabilities_Detailed'; SecurityDomain = 'Endpoint'; SecuritySeverity = $sevs[$i % 4]; CriticalityTier = ($i % 4); RiskScoreKPI = [string]($i % 101); ConfigurationId = 'scid-' + ($i % 17) } })
        function script:New-ClockPager {
            param([object[]]$Rows, [int]$PageSize)
            $o = [pscustomobject]@{ State = @{ Rows = $Rows; At = 0; Size = $PageSize; Done = $false; FetchSec = 1.0; DecodeSec = 0.5 } }
            $o | Add-Member -MemberType ScriptMethod -Name Next -Value {
                $s = $this.State
                if ($s.Done) { return $null }
                $script:now = $script:now.AddSeconds(30)   # a page every 30 s
                $end = [Math]::Min($s.At + $s.Size, $s.Rows.Count) - 1
                $p = @($s.Rows[$s.At..$end]); $s.At = $end + 1
                if ($s.At -ge $s.Rows.Count) { $s.Done = $true }
                return , $p
            }
            $o
        }
    }
    AfterAll { foreach ($g in $script:Saved.Keys) { Set-Variable -Name $g -Scope Global -Value $script:Saved[$g] } }
    It 'a fake 50-minute read: rows read of all every 3 minutes, and the same key figures as without it' {
        $env:CONTAINER_APP_JOB_EXECUTION_NAME = 'caj-si-risk-analysis-detailed-t2'
        $script:now = $script:T0
        $db = New-ProgDb
        $log = New-Object System.Collections.Generic.List[string]
        $tick = New-SIStepProgressTicker -What 'the key figures read the rows' -Unit 'rows' -Total 3000 -Invoke $db.Invoke -Job 'risk-analysis-detailed' -Log { param($l, $m) $log.Add($m) }.GetNewClosure() -Now { $script:now }
        $with = Invoke-RAKpiPass -FromAiPass $null -NewPager { New-ClockPager -Rows $script:Rows -PageSize 30 } -Now $script:T0 -Progress $tick
        $without = Invoke-RAKpiPass -FromAiPass $null -NewPager { New-ClockPager -Rows $script:Rows -PageSize 30 } -Now $script:T0
        $with.Rows | Should -Be 3000
        (ConvertTo-Json (Complete-RAKpiState -State $with.State) -Depth 8 -Compress) | Should -Be (ConvertTo-Json (Complete-RAKpiState -State $without.State) -Depth 8 -Compress)
        $log.Count | Should -Be 16 -Because '100 pages x 30 s = 50 min, a word every 3 min'
        $log[0] | Should -Be 'the key figures read the rows: rows 150 of 3,000 done (3 min so far)'
        @(Get-Merges $db).Count | Should -Be 16
    }
    It 'the wiring: the AI summary''s pass and the key figures'' own pass step the ticker per page, from the stream only' {
        $ra = [IO.File]::ReadAllText((Join-Path $script:Root 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'))
        $ra | Should -Match ([regex]::Escape("`$__aiTick = if (`$script:RAStreamOn) { New-RAProgressTicker -Stream `$script:RAStream -What 'the AI summary and key figures read the rows' -Unit 'rows' -Total ([long]`$script:RAViewCount)"))
        $ra | Should -Match '(?s)\$__aiPage = \$null\s+if \(\$null -ne \$__aiTick\) \{ \$null = Step-SIStepProgressTicker -Ticker \$__aiTick -Done \$__aiRows \}\s+\}'
        $ra | Should -Match ([regex]::Escape("-Progress `$(if (`$script:RAStreamOn) { New-RAProgressTicker -Stream `$script:RAStream -What 'the key figures read the rows'"))
    }
}

Describe '(c) the data sync''s long parts write the step''s progress record' {
    BeforeAll {
        . (Join-Path $script:Root 'engine\_shared\SI-SchemaGate.ps1')
        . (Join-Path $script:Root 'engine\_shared\data-sql\SI-DataModel.ps1')
        . (Join-Path $script:Root 'engine\_shared\data-sql\SI-DataSql.ps1')
        . (Join-Path $script:Root 'engine\pro-data\_shared\SI-DataViewContext.ps1')
        . (Join-Path $script:Root 'engine\pro-data\_shared\SI-DataSummaryGroups.ps1')
        # SI-DataSql may load the SQL pacing; a fake database has no load to read -- keep it out of these tests
        if (Get-Command -Name Invoke-SISqlPacing -ErrorAction SilentlyContinue) { function script:Invoke-SISqlPacing { [pscustomobject]@{ WaitedMs = 0L; Shrink = $false; State = 'off'; Load = $null } } }
        . (Join-Path $script:Root 'engine\_shared\SI-StepPhase.ps1')
        function script:New-FakeDb {
            param([hashtable]$Answers = @{})
            $calls = New-Object System.Collections.Generic.List[object]
            $invoke = {
                param($sql, $p, $mode)
                $calls.Add([pscustomobject]@{ Sql = [string]$sql; P = $p; Mode = $mode })
                foreach ($k in $Answers.Keys) { if ([string]$sql -match $k) { $a = $Answers[$k]; if ($a -is [scriptblock]) { return (& $a $p) }; return $a } }
                if ($mode -eq 'reader') { return @() }
                return 0
            }.GetNewClosure()
            [pscustomobject]@{ Calls = $calls; Invoke = $invoke }
        }
    }
    BeforeEach {
        $env:CONTAINER_APP_JOB_EXECUTION_NAME = 'caj-si-asset-datasync-t3'
        $script:now = $script:T0; $global:SI_StepProgressTickerNow = { $script:now }
    }
    AfterEach { $global:SI_StepProgressTickerNow = $null }
    It 'the views'' prepared context: a fake 40-minute fill records rows filled of all every 3 minutes; the result is the same' {
        $script:mergeAt = New-Object System.Collections.Generic.List[datetime]
        $db = New-FakeDb -Answers ([ordered]@{
            'MERGE cfg\.StepProgress'     = { $script:mergeAt.Add($script:now); 1 }
            'SELECT CASE WHEN COL_LENGTH' = 1
            'ContextAt IS NULL'           = { @(@{ CollectionId = 9; CollectionTime = [datetime]'2026-11-10' }) }
            'MIN\(FindingId\) AS Lo'      = { @(@{ Lo = 1; Hi = 400000; N = 400000 }) }
            # a fake fill of 100 rows a second (about 67 minutes in all)
            'UPDATE f SET'                = { param($p) $n = [long]$p['Upto'] - [long]$p['After']; $script:now = $script:now.AddSeconds($n / 100); $n }
            'INSERT sidata\.IssueContext' = 7
        })
        $r = Invoke-SIDataViewContext -Invoke $db.Invoke -Log { param($l, $m) } -List (Get-SIViewStoredColumns) -Workers 1
        $r.Status | Should -Be 'ok'
        $r.Findings | Should -Be 400000
        $m = @($db.Calls | Where-Object { $_.Sql -match 'MERGE cfg\.StepProgress' })
        $m.Count | Should -BeGreaterOrEqual 3
        for ($k = 1; $k -lt $script:mergeAt.Count; $k++) { ($script:mergeAt[$k] - $script:mergeAt[$k - 1]).TotalSeconds | Should -BeGreaterOrEqual 180 }
        @($m | ForEach-Object { [long]$_.P.Done }) | Should -Be @($m | ForEach-Object { [long]$_.P.Done } | Sort-Object)
        $m[0].P.Phase | Should -Match "^the views' prepared context of collection 9: rows [0-9,]+ of 400,000$"
        $m[0].P.Total | Should -Be 400000
        $m[0].P.Execution | Should -Be 'caj-si-asset-datasync-t3'
    }
    It 'the grouped Summary rows: collections done of all, recorded per collection (a collection is one statement); the same result' {
        Mock Get-SIDataSummaryGroupsSql { 'SELECT 1 /*grouping*/' }
        $db = New-FakeDb -Answers ([ordered]@{
            'MERGE cfg\.StepProgress' = 1
            'SELECT CASE WHEN OBJECT_ID' = 1
            'LEFT JOIN sidata\.SummaryGroupState' = { @(1..5 | ForEach-Object { @{ CollectionId = $_; CollectionTime = [datetime]'2026-11-10' } }) }
            'SELECT 1 /\*grouping' = { param($p) $script:now = $script:now.AddMinutes(20); 12 }
        })
        $log = New-Object System.Collections.Generic.List[string]
        $r = Invoke-SIDataSummaryGroups -Invoke $db.Invoke -Log { param($l, $m) $log.Add("$l $m") }.GetNewClosure() -Plan @{ Hash = 'h' } -BudgetSeconds 100000
        $r.Status | Should -Be 'ok'; $r.Collections | Should -Be 5; $r.Groups | Should -Be 60
        $m = @($db.Calls | Where-Object { $_.Sql -match 'MERGE cfg\.StepProgress' })
        @($m | ForEach-Object { $_.P.Done }) -join ',' | Should -Be '1,2,3,4'
        $m[0].P.Phase | Should -Be 'groupings   : the grouped Summary rows: collections 1 of 5'
        @($log | Where-Object { $_ -match 'collections \d of 5 done' }).Count | Should -Be 4
    }
    It 'the wiring: key figures (findings read of all) and the findings per CI (rows read of all) step the ticker' {
        $kf = [IO.File]::ReadAllText((Join-Path $script:Root 'engine\pro-data\_shared\SI-DataKeyFigures.ps1'))
        $kf | Should -Match ([regex]::Escape("New-SIStepProgressTicker -What ('key figures of collection {0}' -f `$cid) -Unit 'findings read'"))
        $kf | Should -Match ([regex]::Escape('$null = Step-SIStepProgressTicker -Ticker $kfTick -Done ($from - [long]$lo + 1)'))
        $ci = [IO.File]::ReadAllText((Join-Path $script:Root 'engine\pro-data\_shared\SI-DataCi.ps1'))
        $ci | Should -Match ([regex]::Escape("New-SIStepProgressTicker -What 'v3 model    : the findings per CI read from the collection' -Unit 'rows' -Total ([long]`$expected)"))
        $ci | Should -Match ([regex]::Escape('$null = Step-SIStepProgressTicker -Ticker $fpcTick -Done ([long]$state.Read)'))
    }
}

Describe '(d) the CI build records batches done of all' {
    It 'a fake 266-batch build at ~2.7 minutes a batch records its progress at every batch' {
        $env:CONTAINER_APP_JOB_EXECUTION_NAME = 'caj-si-asset-correlation-t4'
        $script:now = $script:T0
        $db = New-ProgDb
        $t = New-SIStepProgressTicker -What 'the CI build' -Unit 'batch' -Total 266 -Invoke $db.Invoke -EverySeconds 60 -Now { $script:now }
        for ($b = 1; $b -le 266; $b++) { $null = Step-SIStepProgressTicker -Ticker $t -Done ($b - 1); $script:now = $script:now.AddSeconds(162) }
        $m = @(Get-Merges $db)
        $m.Count | Should -Be 265
        $m[160].P.Phase | Should -Be 'the CI build: batch 161 of 266'
    }
    It 'the wiring: the build loads the ticker by its own path and steps it at every batch start' {
        $run = [IO.File]::ReadAllText((Join-Path $script:Root 'engine\data-model\SI-CiBuildRun.ps1'))
        $run | Should -Match ([regex]::Escape("'_shared', 'SI-StepPhase.ps1'"))
        $run | Should -Match ([regex]::Escape("New-SIStepProgressTicker -What 'the CI build' -Unit 'batch' -Total ([long]`$nBatches) -Invoke `$sql -EverySeconds 60"))
        $run | Should -Match '(?s)\$bw\.Restart\(\)\s+if \(\$ciTick\) \{ \$null = Step-SIStepProgressTicker -Ticker \$ciTick -Done \(\$b - 1\) \}\s+& \$Log ''INFO'' \("CIs: batch \{0\} of \{1\} started'
    }
}
