#Requires -Version 7.0
<#
    #1274 -- A SLOW BUT WORKING RISK ANALYSIS REPORT KEEPS SHOWING IT IS MOVING (SUP-2026-00610, 2026-11-16). A worker asked
    advanced hunting every few seconds for hours (smaller slices after 504 Gateway Timeout) while the run step's progress
    record stood still -- so the step was reported as not moving. Progress only: nothing here may change a query, a split, a
    timeout or a row.

    What the not-moving check reads (Get-SIStepProgressLastSql / the heartbeat's 'prog' rows): the newest LastUtc of
    cfg.StepProgress for the STEP'S OWN execution (plus rows whose Job is caj-si-<step> or caj-si-<step>-<suffix>; the
    workers write Job 'risk-analysis-detailed', which is neither) and the newest cfg.StepPhaseTime row of that execution.
    So the step only reads as moving when the PRODUCER's own record moves -- these tests drive both halves through one fake
    cfg.StepProgress (MERGE by execution, the database's time = the fake clock) and read the producer's LastUtc back.

    What these tests keep true (offline, fake clocks and a fake database):
      (a) the report's beat: many advanced-hunting calls with no finished slice move the worker's record ('report <name>',
          the same done / total), at most every 15 s; nothing before the slice loop wrote a count; never throws;
      (b) the producer's record moves while a running report's worker record moves, even when no slice finished -- at most
          every 5 minutes (ProgressSeconds);
      (c) workers that truly stand still: the producer's record does NOT move (the not-moving check still fires); the
          producer's own record and a recovery line's record never count as a worker's beat;
      (d) the query slices done / total the producer computes are the same with the beats as without them;
      plus the wiring: the beat follows every recovery call (late retries and smaller slices) and takes the slice loop's count.
    State lives in $script: variables, never in GetNewClosure (a closure cannot see this file's functions or script scope).
    NO EMOJI IN THIS FILE.
#>

BeforeAll {
    $script:Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:Root 'engine\_shared\SI-StepPhase.ps1')
    . (Join-Path $script:Root 'engine\risk-analysis\_shared\RA-ScaleOut.ps1')
    . (Join-Path $script:Root 'container\_shared\SI-ContainerConfig.ps1')
    # only the progress functions of the stream (the file itself loads the whole SQL stream)
    $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:Root 'engine\risk-analysis\_shared\RA-SqlStream.ps1'), [ref]$null, [ref]$null)
    foreach ($fn in 'Get-RAStepPhaseJob', 'Write-RAStepProgressRow', 'Get-RAWorkerSliceRows', 'New-RAReportProgressBeat', 'Set-RAReportProgressSlice', 'Step-RAReportProgressBeat') {
        $def = $ast.Find({ param($x) $x -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $x.Name -eq $fn }, $true)
        if (-not $def) { throw "function $fn not found in RA-SqlStream.ps1" }
        . ([scriptblock]::Create($def.Extent.Text))
    }
    $script:T0 = [datetime]::SpecifyKind([datetime]'2026-11-16T01:00:00', 'Utc')
    $script:now = $script:T0
    $script:Clock = { $script:now }
    # a fake cfg.StepProgress: one row per execution (MERGE), its LastUtc the fake clock (the database's own time)
    $script:FakeRows = [ordered]@{}
    $script:FakeMerges = New-Object System.Collections.Generic.List[object]
    $script:FakeInvoke = {
        param($sql, $p, $mode)
        if ([string]$sql -match 'MERGE cfg\.StepProgress') {
            $e = [string]$p.Execution
            $b = if ($script:FakeRows.Contains($e)) { [long]$script:FakeRows[$e].Beats + 1 } else { 1L }
            $script:FakeRows[$e] = [pscustomobject]@{ Execution = $e; Job = [string]$p.Job; Phase = [string]$p.Phase; Done = $p.Done; Total = $p.Total; LastUtc = $script:now; Beats = $b }
            $script:FakeMerges.Add([pscustomobject]@{ At = $script:now; Execution = $e; Phase = [string]$p.Phase; Done = $p.Done; Total = $p.Total })
            return 1
        }
        if ([string]$sql -match 'SELECT Execution, Phase, Done, Total, LastUtc FROM cfg\.StepProgress') {
            $since = [datetime]::ParseExact([string]$p.SinceUtc, 'yyyy-MM-ddTHH:mm:ss.fff', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AssumeUniversal,AdjustToUniversal')
            return @($script:FakeRows.Values | Where-Object { $_.Job -eq [string]$p.Job -and $_.LastUtc -ge $since -and $_.Phase.StartsWith([string]$p.PhasePrefix, [StringComparison]::Ordinal) } |
                     ForEach-Object { @{ Execution = $_.Execution; Phase = $_.Phase; Done = $_.Done; Total = $_.Total; LastUtc = [datetime]::SpecifyKind($_.LastUtc, 'Unspecified') } })
        }
        $null
    }
    function script:Reset-FakeTable { $script:FakeRows.Clear(); $script:FakeMerges.Clear() }
    $script:Stream = [pscustomobject]@{ Invoke = $script:FakeInvoke; Grain = 'Detailed'; Log = $null }
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
    $script:SavedExec = $env:CONTAINER_APP_JOB_EXECUTION_NAME
}
AfterAll {
    $env:CONTAINER_APP_JOB_EXECUTION_NAME = $script:SavedExec
    $global:SI_StepProgressTickerNow = $null
}

Describe '(a) the report''s beat: every advanced-hunting call of a long recovery moves the worker''s record, at most every 15 s' {
    BeforeEach { $script:now = $script:T0; Reset-FakeTable }
    It 'a 3-hour split-finer loop (a call every 1.5 s, no slice finished) writes the record about every 15 s with the same done / total' {
        $env:CONTAINER_APP_JOB_EXECUTION_NAME = 'caj-si-raworker-detailed-a1'
        $beat = New-RAReportProgressBeat -Stream $script:Stream -Report 'Device_Missing_CVEs_Detailed' -Now $script:Clock
        # the slice loop wrote its last slice: 33 of 34 (as Invoke-RiskAnalysis does at a slice's start)
        Write-RAStepProgressRow -Stream $script:Stream -Phase 'report Device_Missing_CVEs_Detailed' -Done 33 -Total 34 -Now $script:now
        Set-RAReportProgressSlice -Beat $beat -Done 33 -Total 34
        for ($i = 0; $i -lt 7200; $i++) { $script:now = $script:now.AddSeconds(1.5); Step-RAReportProgressBeat -Beat $beat }
        $beat.Calls | Should -Be 7200
        $m = @($script:FakeMerges | Where-Object { $_.Execution -eq 'caj-si-raworker-detailed-a1' })
        $m.Count | Should -BeGreaterThan 700 -Because '10800 s / 15 s = 720'
        $m.Count | Should -BeLessOrEqual 721
        for ($k = 1; $k -lt $m.Count; $k++) { ($m[$k].At - $m[$k - 1].At).TotalSeconds | Should -BeGreaterOrEqual 15 }
        foreach ($x in $m) { $x.Phase | Should -Be 'report Device_Missing_CVEs_Detailed'; $x.Done | Should -Be 33; $x.Total | Should -Be 34 }
        $row = $script:FakeRows['caj-si-raworker-detailed-a1']
        ($script:now - $row.LastUtc).TotalSeconds | Should -BeLessThan 16
        $row.Job | Should -Be 'risk-analysis-detailed'
    }
    It 'nothing is written before the slice loop wrote a count; no stream, no beat or a refusing database never throws' {
        $env:CONTAINER_APP_JOB_EXECUTION_NAME = 'caj-si-raworker-detailed-a2'
        $beat = New-RAReportProgressBeat -Stream $script:Stream -Report 'R' -Now $script:Clock
        for ($i = 0; $i -lt 50; $i++) { $script:now = $script:now.AddSeconds(20); Step-RAReportProgressBeat -Beat $beat }
        $script:FakeMerges.Count | Should -Be 0
        $beat.Calls | Should -Be 50
        { Step-RAReportProgressBeat -Beat $null } | Should -Not -Throw
        $nb = New-RAReportProgressBeat -Stream $null -Report 'R' -Now $script:Clock
        Set-RAReportProgressSlice -Beat $nb -Done 1 -Total 2
        { Step-RAReportProgressBeat -Beat $nb } | Should -Not -Throw
        $bad = New-RAReportProgressBeat -Stream ([pscustomobject]@{ Invoke = { param($s, $p, $m) throw 'database gone' }; Grain = 'Detailed' }) -Report 'R' -Now $script:Clock
        Set-RAReportProgressSlice -Beat $bad -Done 1 -Total 2
        { Step-RAReportProgressBeat -Beat $bad } | Should -Not -Throw
    }
}

Describe 'the producer''s record follows the workers'' beats (b, c, d)' {
    BeforeAll {
        $script:Plan = New-RAScaleOutPlan -Reports @([pscustomobject]@{ Name = 'Small_Detailed'; HasEntry = $true }, [pscustomobject]@{ Name = 'Device_Missing_CVEs_Detailed'; HasEntry = $true }, [pscustomobject]@{ Name = 'Other_Detailed'; HasEntry = $true })
        $script:RunNo = 0
        # the fake worker and the producer's not-moving read, between two polls of the wait
        $script:FakeSleep = {
            param($s)
            $script:R.Polls++
            $env:CONTAINER_APP_JOB_EXECUTION_NAME = $script:Worker
            $steps = [int][Math]::Round([double]$s / 1.5)
            for ($k = 0; $k -lt $steps; $k++) {
                $script:now = $script:now.AddSeconds(1.5)
                $min = ($script:now - $script:T0).TotalMinutes
                if ($min -lt 10) {
                    # the slice loop: a slice every ~18 s, 34 slices (the last one starts at about 10 min)
                    $sl = [Math]::Min(33, [int][Math]::Floor(($script:now - $script:T0).TotalSeconds / 18))
                    if ($sl -ne $script:R.Slice) {
                        $script:R.Slice = $sl
                        Write-RAStepProgressRow -Stream $script:Stream -Phase 'report Device_Missing_CVEs_Detailed' -Done $sl -Total 34 -Now $script:now
                        Set-RAReportProgressSlice -Beat $script:R.Beat -Done $sl -Total 34
                    }
                } elseif ($script:R.Working -and $min -lt 195) {
                    Step-RAReportProgressBeat -Beat $script:R.Beat
                }
            }
            $env:CONTAINER_APP_JOB_EXECUTION_NAME = $script:Producer
            if ($script:R.Polls -eq 3) { & $script:R.Mark 0 }
            if ($script:R.Polls -eq 20) { & $script:R.Mark 2 }
            if (($script:now - $script:T0).TotalMinutes -ge 200) { & $script:R.Mark 1 }
            # what the not-moving check reads: the producer's own record's LastUtc
            $pr = if ($script:FakeRows.Contains($script:Producer)) { $script:FakeRows[$script:Producer].LastUtc } else { $null }
            $script:R.Gaps.Add([pscustomobject]@{ At = $script:now; Gap = $(if ($pr) { ($script:now - $pr).TotalSeconds } else { -1 }) })
        }
        $script:FakeSlice = {
            param($open)
            $rows = @(Get-RAWorkerSliceRows -Stream $script:Stream -SinceUtc $script:T0.AddMinutes(-5))
            # (d) the same rows without the beat's time: the counts must not differ
            $plain = @($rows | ForEach-Object { @{ Execution = $_.Execution; Phase = $_.Phase; Done = $_.Done; Total = $_.Total } })
            $with = Get-RAScaleOutSliceProgress -Rows $rows -OpenReports $open
            $without = Get-RAScaleOutSliceProgress -Rows $plain -OpenReports $open
            $script:R.Compared.Add([pscustomobject]@{ WithDone = $(if ($with) { $with.Done } else { $null }); WithTotal = $(if ($with) { $with.Total } else { $null })
                                                      WithoutDone = $(if ($without) { $without.Done } else { $null }); WithoutTotal = $(if ($without) { $without.Total } else { $null }) })
            $with
        }
        # the producer's record exactly as Invoke-RiskAnalysis writes it (the fake clock for the 15 s spacing)
        $script:FakeOn = {
            param($rd, $rn, $sd, $st)
            $script:R.Calls.Add([pscustomobject]@{ At = $script:now; Reports = $rd; Slices = $sd; Total = $st })
            Write-RAStepProgressRow -Stream $script:Stream -Phase $(if ($st -gt 0) { 'reports {0} of {1} done; the running reports: query slices {2} of {3} done' -f $rd, $rn, $sd, $st } else { 'reports {0} of {1} done' -f $rd, $rn }) -Done $rd -Total $rn -Now $script:now
        }
        # one fake run: the huge report's worker reaches its last slice at 10 min, then (-Working) asks advanced hunting every
        # 1.5 s until 195 min without finishing a slice, or (not -Working) stands still; its marker comes at 200 min
        function script:Invoke-FakeRun {
            param([switch]$Working)
            $script:now = $script:T0
            Reset-FakeTable
            # each run its own executions (the 15 s spacing remembers an execution's last write across runs)
            $script:RunNo++
            $script:Producer = 'caj-si-risk-analysis-detailed-p{0}' -f $script:RunNo
            $script:Worker = 'caj-si-raworker-detailed-w{0}' -f $script:RunNo
            $store = New-MemStore
            $man = New-RAScaleOutManifest -Grain Detailed -TimeText '2026-11-16T01:00:00.000' -CollectionTime $script:T0 -CollectionId 7 -Items $script:Plan -Now $script:T0
            foreach ($i in 0..2) { & $store.Write (Get-RAScaleOutPath -Engine 'ra-detailed' -RunId $man.RunId -Kind started -Item $i) '{"Worker":"w"}' }
            $script:R = @{ Working = [bool]$Working; Polls = 0; Slice = -1; Store = $store; Manifest = $man
                           Beat = (New-RAReportProgressBeat -Stream $script:Stream -Report 'Device_Missing_CVEs_Detailed' -Now $script:Clock)
                           Gaps = (New-Object System.Collections.Generic.List[object]); Calls = (New-Object System.Collections.Generic.List[object])
                           Compared = (New-Object System.Collections.Generic.List[object]) }
            $script:R.Mark = { param($i) Write-SICollectPartMarker -Store $script:R.Store -Engine 'ra-detailed' -RunId $script:R.Manifest.RunId -Marker (New-SICollectPartMarker -Part $i -State done) }
            $env:CONTAINER_APP_JOB_EXECUTION_NAME = $script:Producer
            $script:R.Wait = Wait-RAScaleOutItems -Store $store -Manifest $man -UseKeda $true -LocalWorker { throw 'not expected' } -Sleep $script:FakeSleep -Now $script:Clock -Log { param($l, $t) } -SliceProgress $script:FakeSlice -OnProgress $script:FakeOn
            $script:R
        }
    }
    It '(b) a worker that keeps asking moves the producer''s record every 5 minutes for 3 hours, though no slice finished' {
        $r = Invoke-FakeRun -Working
        $r.Wait.State | Should -Be 'succeeded'
        # between 20 min and 195 min (only the beat moves) the producer's record is never older than one progress interval and a poll
        $mid = @($r.Gaps | Where-Object { ($_.At - $script:T0).TotalMinutes -ge 20 -and ($_.At - $script:T0).TotalMinutes -le 195 })
        $mid.Count | Should -BeGreaterThan 400
        ($mid | Measure-Object -Property Gap -Maximum).Maximum | Should -BeLessOrEqual 330
        ($mid | Measure-Object -Property Gap -Minimum).Minimum | Should -BeGreaterOrEqual 0
        $beatCalls = @($r.Calls | Where-Object { ($_.At - $script:T0).TotalMinutes -gt 20 -and ($_.At - $script:T0).TotalMinutes -lt 195 })
        $beatCalls.Count | Should -BeGreaterThan 30 -Because '175 min / 5 min'
        for ($k = 1; $k -lt $r.Calls.Count; $k++) { ($r.Calls[$k].At - $r.Calls[$k - 1].At).TotalSeconds | Should -BeGreaterOrEqual 300 }
        # (d) the counts stay what the slices say: 33 of 34 the whole time
        foreach ($c in $beatCalls) { $c.Slices | Should -Be 33; $c.Total | Should -Be 34; $c.Reports | Should -Be 2 }
    }
    It '(c) a worker that stands still leaves the producer''s record still -- the not-moving check still sees it' {
        $r = Invoke-FakeRun
        $r.Wait.State | Should -Be 'succeeded'
        # no record from the producer while nothing moved (after the last slice and the second report's end)
        @($r.Calls | Where-Object { ($_.At - $script:T0).TotalMinutes -gt 20 -and ($_.At - $script:T0).TotalMinutes -lt 199 }).Count | Should -Be 0
        $late = @($r.Gaps | Where-Object { [Math]::Abs(($_.At - $script:T0).TotalMinutes - 195) -lt 0.5 })[0]
        $late | Should -Not -BeNullOrEmpty
        $late.Gap | Should -BeGreaterThan (170 * 60) -Because 'the producer''s record is as old as the last real movement'
    }
    It '(d) the producer''s slice counts are the same with the beats as without them, at every poll of a working run' {
        $r = Invoke-FakeRun -Working
        $cmp = [object[]]$r.Compared.ToArray()
        $cmp.Count | Should -BeGreaterThan 30
        foreach ($c in $cmp) {
            if ($null -eq $c.WithoutDone) { ($null -eq $c.WithDone -or [long]$c.WithDone -eq -1) | Should -BeTrue; continue }
            $c.WithDone | Should -Be $c.WithoutDone
            $c.WithTotal | Should -Be $c.WithoutTotal
        }
        $rows = @(@{ Phase = 'report A'; Done = 20; Total = 34; LastUtc = $script:T0.AddMinutes(9) }, @{ Phase = 'report A'; Done = 7; Total = 34; LastUtc = $script:T0.AddMinutes(3) },
                  @{ Phase = 'report B'; Done = 1; Total = 1; LastUtc = $script:T0.AddMinutes(99) })
        $with = Get-RAScaleOutSliceProgress -Rows $rows -OpenReports @('A')
        $without = Get-RAScaleOutSliceProgress -Rows @($rows | ForEach-Object { @{ Phase = $_.Phase; Done = $_.Done; Total = $_.Total } }) -OpenReports @('A')
        $with.Done | Should -Be $without.Done; $with.Total | Should -Be $without.Total
        $with.Done | Should -Be 27; $with.Total | Should -Be 68
        $with.LastUtc | Should -Be $script:T0.AddMinutes(9) -Because 'only the open reports'' records are a beat'
        $without.LastUtc | Should -BeNullOrEmpty
    }
    It '(c) the producer''s own record and a recovery line''s record never count as a worker''s beat' {
        $rows = @(@{ Phase = 'reports 71 of 72 done; the running reports: query slices 33 of 34 done'; Done = 71; Total = 72; LastUtc = $script:T0.AddMinutes(50) },
                  @{ Phase = "recovery of report 'A': query slices asked again 40"; Done = 40; Total = -1; LastUtc = $script:T0.AddMinutes(60) },
                  @{ Phase = 'report A'; Done = 33; Total = 34; LastUtc = $script:T0.AddMinutes(10) })
        $p = Get-RAScaleOutSliceProgress -Rows $rows -OpenReports @('A')
        $p.LastUtc | Should -Be $script:T0.AddMinutes(10)
        $p.Done | Should -Be 33; $p.Total | Should -Be 34
        # a record with a time but no count: a beat, with no counts
        $q = Get-RAScaleOutSliceProgress -Rows @(@{ Phase = 'report A'; Done = -1; Total = -1; LastUtc = $script:T0 }) -OpenReports @('A')
        $q.Done | Should -Be -1; $q.Total | Should -Be -1; $q.LastUtc | Should -Be $script:T0
    }
    It 'a beat that does not move after it was seen once writes no further record (fixed counts, fixed beat)' {
        $script:B = @{ Store = (New-MemStore); Polls = 0; Calls = (New-Object System.Collections.Generic.List[datetime]); Beat = $script:T0.AddMinutes(1) }
        $script:B.Manifest = New-RAScaleOutManifest -Grain Detailed -TimeText '2026-11-16T01:00:00.000' -CollectionTime $script:T0 -CollectionId 7 -Items $script:Plan -Now $script:T0
        foreach ($i in 0..2) { & $script:B.Store.Write (Get-RAScaleOutPath -Engine 'ra-detailed' -RunId $script:B.Manifest.RunId -Kind started -Item $i) '{"Worker":"w"}' }
        $script:now = $script:T0
        $sleep = { param($s) $script:now = $script:now.AddSeconds($s); $script:B.Polls++; if ($script:B.Polls -ge 600) { foreach ($i in 0..2) { Write-SICollectPartMarker -Store $script:B.Store -Engine 'ra-detailed' -RunId $script:B.Manifest.RunId -Marker (New-SICollectPartMarker -Part $i -State done) } } }
        $w = Wait-RAScaleOutItems -Store $script:B.Store -Manifest $script:B.Manifest -UseKeda $true -LocalWorker { throw 'x' } -Sleep $sleep -Now $script:Clock -Log { param($l, $t) } `
                -SliceProgress { param($open) @{ Done = 5L; Total = 10L; LastUtc = $script:B.Beat } } -OnProgress { param($rd, $rn, $sd, $st) $script:B.Calls.Add($script:now) }
        $w.State | Should -Be 'succeeded'
        $script:B.Calls.Count | Should -Be 1 -Because 'the first sight of the slices and the beat; then nothing moved'
    }
}

Describe 'the wiring' {
    It 'the beat takes the slice loop''s count and follows every recovery call (late retries and smaller slices)' {
        $ra = [IO.File]::ReadAllText((Join-Path $script:Root 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'))
        $ra | Should -Match ([regex]::Escape('New-RAReportProgressBeat -Stream $script:RAStream -Report $ReportName'))
        $ra | Should -Match ([regex]::Escape('if ($null -ne $__rpBeat) { Set-RAReportProgressSlice -Beat $__rpBeat -Done ($b - $__soFrom) -Total ($__soTo - $__soFrom) }'))
        ([regex]::Matches($ra, 'Step-RARecoveryBudgetCall -Budget \$__rb   # #1200[^\r\n]*\r?\n\s*if \(\$null -ne \$__rpBeat\) \{ Step-RAReportProgressBeat -Beat \$__rpBeat \}')).Count | Should -Be 2
        ([regex]::Matches($ra, 'Step-RAReportProgressBeat')).Count | Should -Be 2
        # the slice loop's own record is unchanged
        $ra | Should -Match ([regex]::Escape("Write-RAStepProgressRow -Stream `$script:RAStream -Phase ('report {0}' -f `$ReportName) -Done (`$b - `$__soFrom) -Total (`$__soTo - `$__soFrom)"))
    }
    It 'the progress records read back carry when they last moved' {
        $inv = { param($sql, $p, $mode) @(@{ Execution = 'w1'; Phase = 'report A'; Done = 3; Total = 10; LastUtc = [datetime]'2026-11-16T02:00:00' }, [pscustomobject]@{ Execution = 'w2'; Phase = 'report B'; Done = 1; Total = 2 }) }
        $r = @(Get-SIStepProgressRows -Invoke $inv -Job 'risk-analysis-detailed' -SinceUtc $script:T0 -PhasePrefix 'report ')
        $r.Count | Should -Be 2
        $r[0].LastUtc | Should -Be ([datetime]::SpecifyKind([datetime]'2026-11-16T02:00:00', 'Utc'))
        $r[0].LastUtc.Kind | Should -Be 'Utc'
        $r[1].LastUtc | Should -BeNullOrEmpty
        $r[1].Done | Should -Be 1
    }
}
