#Requires -Version 5.1
<#
    DATA HEALTH NEVER DEPENDS ON A FINISHED RUN (#1201; engine/data-health/_shared/SI-DataHealthOnOwn.ps1).
    The check runs in the verification job, the pipeline's last step; an install whose runs end earlier never reported.
    The pipeline runner's wake-up starts the verification job ONCE with SI_DATAHEALTH_ON_OWN=1 (only the data health check,
    on the stored data) when the last report is older than 24 h and the install is idle, no update runs or waits, and the
    verification job neither runs nor started in the last 6 hours. It says which collection it judged. Never throws.
    Offline: fake database, ARM and clock seams (stubs in script scope). PS 5.1 + 7.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\data-health\_shared\SI-DataHealthOnOwn.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-OutsidePipeline.ps1')
    $script:Now = [datetime]::new(2026, 11, 11, 12, 0, 0, [DateTimeKind]::Utc)
    $script:Idle = [pscustomobject]@{ Busy = $false; Known = $true; Run = $false; Why = '' }
    function script:Exec([string]$Name, [string]$Status, [datetime]$Start) { [pscustomobject]@{ name = $Name; properties = [pscustomobject]@{ status = $Status; startTime = $Start.ToString('o') } } }
    # one wake-up's ask over fake seams; returns @{ R (the result); Starts (the env of each start); Lines; Asked (which seams were read) }
    function script:Ask {
        param($LastReport, [int]$HasTables = 1, $Busy = $script:Idle, [string]$Updater = '', $Waits = $null, [object[]]$Execs = @(),
              [switch]$ExecsThrow, [switch]$NoJob, [switch]$DbThrows, $Enabled = $null)
        $st = [pscustomobject]@{ Starts = (New-Object System.Collections.Generic.List[object]); Lines = (New-Object System.Collections.Generic.List[string]); Asked = (New-Object System.Collections.Generic.List[string]) }
        $inv = { param($s, $p, $m) if ($DbThrows) { throw 'login failed' }; if ($s -match 'cfg\.DataHealthCycle') { , @([pscustomobject]@{ HasTables = $HasTables; LastReport = $LastReport }) } else { , @() } }.GetNewClosure()
        $r = Invoke-SIDataHealthOnOwnCheck -Invoke $inv -Enabled $Enabled -Now { $script:Now } `
            -Busy { $st.Asked.Add('busy'); $Busy }.GetNewClosure() `
            -UpdaterRunning { $st.Asked.Add('updater'); $Updater }.GetNewClosure() `
            -UpdateWaits { $Waits }.GetNewClosure() `
            -Executions { $st.Asked.Add('executions'); if ($ExecsThrow) { throw 'HTTP 500' }; if ($NoJob) { throw 'HTTP 404 ResourceNotFound' }; $Execs }.GetNewClosure() `
            -Start { param($E) $st.Starts.Add($E); 'caj-si-verification-abc12' }.GetNewClosure() `
            -Log { param($l, $m) $st.Lines.Add(('{0} {1}' -f $l, $m)) }.GetNewClosure()
        [pscustomobject]@{ R = $r; Starts = $st.Starts.ToArray(); Lines = $st.Lines.ToArray(); Asked = $st.Asked.ToArray() }
    }
}

Describe 'the data health check runs on its own when the last report is older than 24 h' {
    It 'a run stopped before verification: the last report goes over 24 h -> started once, only the check, with why' {
        # the run stopped yesterday before its verification step: the last report (from the run before) is 25 h old
        $x = Ask -LastReport $script:Now.AddHours(-25) -Execs @((Exec 'caj-si-verification-old' 'Succeeded' $script:Now.AddHours(-25.5)))
        $x.R.Started | Should -BeTrue
        @($x.Starts).Count | Should -Be 1
        $x.Starts[0]['SI_DATAHEALTH_ON_OWN'] | Should -Be '1'
        $x.Starts[0]['SI_DATAHEALTH_ON_OWN_WHY'] | Should -Match 'the last data health report is 25 h old \(2026-11-10 11:00 UTC\)'
        $x.Lines[-1] | Should -Match 'the check runs now on its own on the stored data \(verification job execution caj-si-verification-abc12\)'
    }
    It 'a report within 24 h: a run stopped with a fresh report waits, the same install 24 h after the report is started' {
        $last = $script:Now.AddHours(-10)
        (Ask -LastReport $last).R.Started | Should -BeFalse
        $script:Now = $last.AddHours(24).AddMinutes(5)
        try { (Ask -LastReport $last).R.Started | Should -BeTrue } finally { $script:Now = [datetime]::new(2026, 11, 11, 12, 0, 0, [DateTimeKind]::Utc) }
    }
    It 'no report at all yet: started' {
        $x = Ask -LastReport $null
        $x.R.Started | Should -BeTrue
        $x.Starts[0]['SI_DATAHEALTH_ON_OWN_WHY'] | Should -Be 'there is no data health report yet'
    }
    It 'a normal run that reached verification: the report is fresh -> nothing started, nothing else read, nothing said' {
        $x = Ask -LastReport $script:Now.AddHours(-2)
        $x.R.Started | Should -BeFalse
        @($x.Starts).Count | Should -Be 0
        @($x.Asked).Count | Should -Be 0
        @($x.Lines).Count | Should -Be 0
    }
}

Describe 'it never competes with a run, a data sync, a data out or an update' {
    It 'a running database-heavy step: it waits, and says it runs once nothing works the database' {
        foreach ($why in 'a pipeline run is running', 'a pipeline step is still running', 'a data sync runs (caj-si-asset-datasync, execution x)') {
            $x = Ask -LastReport $script:Now.AddHours(-30) -Busy ([pscustomobject]@{ Busy = $true; Known = $true; Run = $true; Why = $why })
            $x.R.Started | Should -BeFalse
            @($x.Starts).Count | Should -Be 0
            $x.Lines[-1] | Should -Match ([regex]::Escape("it runs on its own once nothing works the database ($why)"))
        }
    }
    It 'the run records cannot be read (Busy, not known): it waits' {
        (Ask -LastReport $script:Now.AddHours(-30) -Busy ([pscustomobject]@{ Busy = $true; Known = $false; Run = $false; Why = 'the run records could not be read' })).R.Started | Should -BeFalse
    }
    It 'an update runs or waits: the update goes first' {
        $x = Ask -LastReport $script:Now.AddHours(-30) -Updater 'caj-si-updater execution u-1'
        $x.R.Started | Should -BeFalse; $x.Lines[-1] | Should -Match 'after the update \(caj-si-updater execution u-1\)'
        $x = Ask -LastReport $script:Now.AddHours(-30) -Waits ([pscustomobject]@{ Reason = 'version 3.1.7 waits' })
        $x.R.Started | Should -BeFalse; $x.Lines[-1] | Should -Match 'an update waits and goes first \(version 3.1.7 waits\)'
    }
    It 'the verification job runs now, or started in the last 6 hours: not started again; 7 hours ago: started' {
        $x = Ask -LastReport $script:Now.AddHours(-30) -Execs @((Exec 'v-run' 'Running' $script:Now.AddMinutes(-20)))
        $x.R.Started | Should -BeFalse; $x.Lines[-1] | Should -Match 'the verification job runs now \(v-run\)'
        $x = Ask -LastReport $script:Now.AddHours(-30) -Execs @((Exec 'v-failed' 'Failed' $script:Now.AddHours(-2)))
        $x.R.Started | Should -BeFalse; $x.Lines[-1] | Should -Match 'started again at the earliest 6 h after that'
        (Ask -LastReport $script:Now.AddHours(-30) -Execs @((Exec 'v-failed' 'Failed' $script:Now.AddHours(-7)))).R.Started | Should -BeTrue
    }
}

Describe 'never fails or blocks anything' {
    It 'the database cannot be read: nothing started, one warning, nothing thrown' {
        { $script:X = Ask -LastReport $null -DbThrows } | Should -Not -Throw
        $script:X.R.Started | Should -BeFalse
        $script:X.Lines[-1] | Should -Match '^WARN data health: whether it must run on its own could not be decided \(login failed\)'
    }
    It 'the executions cannot be read: nothing started; the job is not there: said, nothing started' {
        $x = Ask -LastReport $script:Now.AddHours(-30) -ExecsThrow
        $x.R.Started | Should -BeFalse; $x.Lines[-1] | Should -Match 'whether the verification job runs could not be read'
        $x = Ask -LastReport $script:Now.AddHours(-30) -NoJob
        $x.R.Started | Should -BeFalse; $x.Lines[-1] | Should -Match 'the verification job is not there -- the next update makes it'
    }
    It 'switched off, or no data health tables yet: quiet, nothing started' {
        foreach ($off in $false, 'false', '0') { $x = Ask -LastReport $null -Enabled $off; $x.R.Started | Should -BeFalse; @($x.Lines).Count | Should -Be 0 }
        $x = Ask -LastReport $null -HasTables 0
        $x.R.Started | Should -BeFalse; @($x.Lines).Count | Should -Be 0
    }
    It 'reads the request flag only as 1 / true / yes' {
        foreach ($v in '1', 'true', 'YES') { Test-SIDataHealthOnOwnRequested -Value $v | Should -BeTrue }
        foreach ($v in '', '0', 'no', $null) { Test-SIDataHealthOnOwnRequested -Value $v | Should -BeFalse }
    }
}

Describe 'it says which collection it judged' {
    It 'names the newest complete collection and why it ran' {
        $j = Get-SIDataHealthJudged -Row ([pscustomobject]@{ CollectionId = 412; CollectionTime = [datetime]::new(2026, 11, 10, 3, 15, 0, [DateTimeKind]::Utc) }) -OnOwn $true -Why 'the last data health report is 30 h old'
        $j.Trigger | Should -Be 'on-its-own'; $j.CollectionId | Should -Be 412
        $j.Line | Should -Be 'data health judges the newest complete collection 412 of 2026-11-10 03:15 UTC; each source against its newest good collection -- run on its own (the last data health report is 30 h old)'
        (Get-SIDataHealthJudged -Row $null).Line | Should -Match 'no complete collection .* -- run after the run''s verification$'
        (Get-SIDataHealthJudged -Row $null -ReadError 'timeout').Line | Should -Match 'which one could not be read: timeout'
    }
    It 'the cycle keeps it in its summary' {
        . (Join-Path $script:SIRoot 'engine\data-health\_shared\SI-DataHealth.ps1')
        . (Join-Path $script:SIRoot 'engine\data-health\_shared\SI-DataHealthStore.ps1')
        . (Join-Path $script:SIRoot 'engine\data-health\_shared\SI-DataHealthRun.ps1')
        $cap = @{}
        $inv = {
            param($s, $p, $m)
            if ($s -match 'INSERT cfg\.DataHealthCycle') { return 7 }
            if ($s -match 'UPDATE cfg\.DataHealthCycle') { $cap.Summary = [string]$p.SummaryJson; return 1 }
            if ($s -match 'AS HasTables') { return , @([pscustomobject]@{ HasTables = 1; HasDrift = 1 }) }
            if ($s -match 'RecordCollection') { return , @([pscustomobject]@{ CollectionTime = $null; Records = 0 }) }
            if ($m -eq 'reader') { return , @() }
            1
        }.GetNewClosure()
        $j = Get-SIDataHealthJudged -Row ([pscustomobject]@{ CollectionId = 412; CollectionTime = [datetime]::new(2026, 11, 10, 3, 15, 0, [DateTimeKind]::Utc) }) -OnOwn $true -Why 'x'
        $r = Invoke-SIDataHealthCycle -Sources @{ 'entra-users' = { } } -Invoke $inv -NowUtc $script:Now -Judged $j -Log { param($l, $m) }
        $r.Written | Should -BeTrue
        $cap.Summary | Should -Match '"trigger":"on-its-own"'
        $cap.Summary | Should -Match '"collectionId":412'
        $cap.Summary | Should -Match '"collectionTime":"2026-11-10T03:15:00Z"'
    }
}

Describe 'wired: the runner asks after the queue, the verification job runs only the check, the pipeline check knows the start' {
    BeforeAll {
        $script:Runner = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\flow\Invoke-SIJobFlowRun.ps1'))
        $script:Ver = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\verification\Invoke-SIVerification.ps1'))
    }
    It 'the runner asks after the queue and the upkeep, never on a wake-up that holds no run of its own (Busy / Blocked)' {
        $a = $script:Runner.IndexOf('$null = Invoke-SIDataHealthOnOwnCheck')
        $a | Should -BeGreaterThan $script:Runner.IndexOf('$drain = Invoke-SIPipelineDrain')
        $a | Should -BeGreaterThan $script:Runner.IndexOf('$upkeepDo = Get-SIPipelineUpkeepDecision -Drain $drain')
        $a | Should -BeLessThan $script:Runner.IndexOf("if (`$drain.Outcome -in @('Busy', 'Blocked')) {")
        $script:Runner | Should -Match ([regex]::Escape("`$drain -and [string]`$drain.Outcome -notin @('Busy', 'Blocked')"))
        $script:Runner | Should -Match ([regex]::Escape('-Busy { Get-SIDataHousekeepingBusy -SettingsInvoke $proStore.Invoke -JobRunning $dhJobRunning -Jobs $dhJobs }'))
        $script:Runner | Should -Match ([regex]::Escape('-UpdaterRunning $updateRunning -UpdateWaits $updateWaits'))
        $script:Runner | Should -Match ([regex]::Escape("New-SIJobStartTemplate -Job `$dhJob -Env `$StartEnv -What 'the verification job'"))
        # the housekeeping-only wake-up (during a run) exits before it
        $script:Runner.IndexOf("& `$say 'INFO' 'a wake-up during a run: the housekeeping is done") | Should -BeLessThan $a
    }
    It 'the verification job, started for it, runs only the data health check and ends' {
        $i = $script:Ver.IndexOf('if (Test-SIDataHealthOnOwnRequested) {')
        $i | Should -BeGreaterThan 0
        $i | Should -BeLessThan $script:Ver.IndexOf('$catalog = Get-SIVerificationCatalog')
        $block = $script:Ver.Substring($i, $script:Ver.IndexOf('$catalog = Get-SIVerificationCatalog') - $i)
        $block | Should -Match 'try \{ \. \$dhScript -DryRun:\$DryRun \}'
        $block | Should -Match '(?m)^\s*return\s*$'
        $block | Should -Not -Match 'Invoke-SIVerificationCore|Invoke-SISnowChecks|Invoke-SIOutsidePipelineCheck'
    }
    It 'the pipeline check does not count the runner''s start of the check as a run outside the pipeline; any other start it does' {
        $mk = { param($n, [string]$Val) [pscustomobject]@{ name = $n; properties = [pscustomobject]@{ status = 'Succeeded'; startTime = $script:Now.AddHours(-3).ToString('o')
                    template = [pscustomobject]@{ containers = @([pscustomobject]@{ name = 'c'; env = @($(if ($Val) { [pscustomobject]@{ name = 'SI_DATAHEALTH_ON_OWN'; value = $Val } }), [pscustomobject]@{ name = 'X'; value = '1' }) }) } } } }
        $ex = @{ 'caj-si-verification' = @((& $mk 'own-1' '1'), (& $mk 'hand-1' '')) }
        $found = @(Get-SIOutsidePipelineExecutions -StepJobs @([pscustomobject]@{ Key = 'verification'; Job = 'caj-si-verification' }) -Executions $ex -NowUtc $script:Now)
        @($found | ForEach-Object Execution) | Should -Be @('hand-1')
        Test-SIOutsidePipelineDataHealthOnOwn -Execution (& $mk 'x' 'true') | Should -BeTrue
        Test-SIOutsidePipelineDataHealthOnOwn -Execution (& $mk 'x' '0') | Should -BeFalse
        Test-SIOutsidePipelineDataHealthOnOwn -Execution ([pscustomobject]@{ name = 'x'; properties = [pscustomobject]@{ status = 'Running' } }) | Should -BeFalse
    }
}
