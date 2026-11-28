#Requires -Version 5.1
<#
    FLEET-STATUS-1 (framework, owner 2026-11-27: "when i ask solutions for fleet status why dont they use telemetry by def";
    Invardia's values 2026-11-27). Three things the heartbeat must tell from its own data, so a fleet status is read from
    telemetry and not from each install:

      1. THE VERSION A RUN RUNS ON. Pipeline.version = the version the run shown STARTED on, LastRun.version = the version the
         last finished run started on -- both from the run record (cfg.FlowRun.Version, written once by the runner at the
         start), never the install's current version (a run can outlive an update). Unknown = null (Pipeline) / left out
         (LastRun). Both are in Invardia's contract (FLEET-TELEMETRY-1, live 9f8e838).
      2. A KILLED RUN. A run whose record still says Running but whose runner has not beaten for KilledRunMinutes (30) reads
         Pipeline 'failed' with lastEndedUtc = its last beat + 30 min, and is LastRun with result 'failed' and its own runId /
         startedUtc / endedUtc -- never 'running' with a stale beat, never 'idle' with the previous run's result. It can flip
         back: a runner that resumes the run later beats it again, and it reads 'running' until it ends. 'stopped' /
         'cancelled' only for a run cancelled the product's way (State Cancelled); a run the runner ended Stopped is 'failed'.
      3. THE UPDATE RESULT BEFORE THE NEW VERSION'S FIRST HEARTBEAT. The updater marks "installing <version>" in the state row
         BEFORE its roll swaps the jobs (the heartbeat sends no result for it -- never the previous run's "nothing-to-do") and
         writes the result the moment the install is decided, before the rest of its run.
    Offline only: rows are handed in, the updater runs against seams and mocks, no network.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\_shared\SI-HeartbeatJob.ps1')
    if (-not (Get-Command -Name Test-SIHeartbeatField -ErrorAction SilentlyContinue)) { . (Join-Path $script:SIRoot 'engine\_shared\SI-HeartbeatFields.ps1') }
    . (Join-Path $script:SIRoot 'engine\_shared\SI-InvardiaUpdate.ps1')
    function script:U([string]$s) { [datetime]::SpecifyKind([datetime]::Parse($s, [Globalization.CultureInfo]::InvariantCulture), [DateTimeKind]::Utc) }
    $script:Now = U '2026-11-27T18:00:00'
    $script:C = Get-SIHeartbeatFieldsContract
    # a cfg row (Get-SIHeartbeatFieldsCfgSql): K, Name, S, T1 = start, T2 = end, T3 = the runner's beat, T4, N1 = order, N2 = group, Txt, Txt2
    function script:Row([string]$K, [string]$Name, [string]$S = $null, $T1 = $null, $T2 = $null, $T3 = $null, $N1 = $null, $N2 = $null, $Txt = $null, $Txt2 = $null) {
        [pscustomobject]@{ K = $K; Name = $Name; S = $S; T1 = $T1; T2 = $T2; T3 = $T3; T4 = $null; N1 = $N1; N2 = $N2; Txt = $Txt; Txt2 = $Txt2 }
    }
    # the newest run 'r-now' (State, its beat) with a version, the run before it 'r-prev' (Succeeded, on 3.1.54), two steps
    function script:Cfg([string]$State = 'Running', $Beat = $script:Now.AddMinutes(-2), [string]$Version = '3.1.55', $End = $null) {
        $start = $script:Now.AddHours(-3)
        $rows = @(
            (Row 'run' 'r-now' $State $start $End $Beat),
            (Row 'run' 'r-prev' 'Succeeded' $start.AddDays(-1) $start.AddDays(-1).AddHours(2) $start.AddDays(-1).AddHours(2)),
            (Row 'step' 'caj-si-identity' 'Success' $start $start.AddMinutes(40) $null 1 1 'r-now'),
            (Row 'step' 'caj-si-endpoint' $(if ($State -in 'Running', 'Starting') { 'Running' } else { 'Interrupted' }) $start.AddMinutes(40) $null $null 2 2 'r-now' $(if ($State -eq 'Stopped') { 'stopped' } else { $null })),
            (Row 'step' 'caj-si-risk-analysis-detailed' 'Waiting' $null $null $null 3 3 'r-now'),
            (Row 'step' 'caj-si-identity' 'Success' $start.AddDays(-1) $start.AddDays(-1).AddMinutes(30) $null 1 1 'r-prev'),
            (Row 'step' 'caj-si-endpoint' 'Success' $start.AddDays(-1).AddMinutes(30) $start.AddDays(-1).AddHours(1) $null 2 2 'r-prev'),
            (Row 'step' 'caj-si-risk-analysis-detailed' 'Success' $start.AddDays(-1).AddHours(1) $start.AddDays(-1).AddHours(2) $null 3 3 'r-prev'),
            (Row 'runver' 'r-prev' '3.1.54'))
        if ($Version) { $rows += (Row 'runver' 'r-now' $Version) }
        , $rows
    }
    # a LastRun read (Get-SIHeartbeatLastRunSql): the run row (T3 = its beat, Ver = its version) and its steps
    function script:LrRun([string]$State = 'Succeeded', $Beat = $null, $Ver = '3.1.55', $End = $script:Now.AddHours(-1)) {
        [pscustomobject]@{ K = 'run'; Id = 'r-now'; S = $State; Trg = 'schedule'; FromStep = $null; Scope = 'pipeline'; T1 = $script:Now.AddHours(-3); T2 = $End; T3 = $Beat; N1 = $null; N2 = $null; Job = $null; Txt = $null; Ver = $Ver }
    }
    function script:LrStep([int]$O, [string]$Job, [string]$S, $T1 = $null, $T2 = $null, [string]$Cls = $null) {
        [pscustomobject]@{ K = 'step'; Id = 'r-now'; S = $S; Trg = $null; FromStep = $null; Scope = $null; T1 = $T1; T2 = $T2; T3 = $null; N1 = $O; N2 = 1; Job = $Job; Txt = $Cls; Ver = $null }
    }
    $script:Sw = @{ Pipeline = $true; PipelineEta = $true; Jobs = $false; Sources = $false; Database = $false; Update = $false; Mail = $false; Warnings = $false; Security = $false; Published = $false; DataOut = $false; BuildPool = $false; UplinkBacklog = $false }
}

Describe 'Pipeline.version -- the version the run shown STARTED on' {
    It 'a running run: its own recorded version; the key is in the agreed shape on every build of Pipeline' {
        $p = Get-SIHeartbeatPipeline -Rows (Cfg) -NowUtc $script:Now -Eta
        $p.state | Should -BeExactly 'running'
        $p.version | Should -BeExactly '3.1.55'
        @($p.PSObject.Properties.Name)[0..7] | Should -Be @('runId', 'state', 'startedUtc', 'step', 'stepSinceUtc', 'lastEndedUtc', 'nextStartUtc', 'version')
        Test-SIHeartbeatField -Name 'Pipeline' -Value $p | Should -BeNullOrEmpty
        (Get-SIHeartbeatPipeline -Rows (Cfg) -NowUtc $script:Now).version | Should -BeExactly '3.1.55' -Because 'the agreed keys alone carry it too'
    }
    It 'a run that outlived an update keeps the version it STARTED on -- never the install''s current one' {
        $f = New-SIHeartbeatFields -Ring 1 -NowUtc $script:Now -Switch $script:Sw -CfgRows (Cfg -Version '3.1.54') -Installed '3.1.55' -Log { param($l) }
        $f['Pipeline'].version | Should -BeExactly '3.1.54'
    }
    It 'not recorded (an older schema, a run started before the runner wrote it): null, never guessed' {
        $p = Get-SIHeartbeatPipeline -Rows (Cfg -Version '') -NowUtc $script:Now
        $p.PSObject.Properties['version'] | Should -Not -BeNullOrEmpty
        $p.version | Should -BeNullOrEmpty -Because 'the previous run''s version is not this run''s'
        ($p | ConvertTo-Json -Compress) | Should -Match '"version":null'
        Test-SIHeartbeatField -Name 'Pipeline' -Value $p | Should -BeNullOrEmpty
        (Get-SIHeartbeatPipeline -Rows (Cfg -Version 'not a version!') -NowUtc $script:Now).version | Should -BeNullOrEmpty
        (Get-SIHeartbeatPipeline -Rows @((Row 'def' 'flow' -Txt '{}')) -NowUtc $script:Now).version | Should -BeNullOrEmpty -Because 'no run, no version'
    }
    It 'the validator refuses a version that is not one' {
        $p = Get-SIHeartbeatPipeline -Rows (Cfg) -NowUtc $script:Now
        $p.version = 'x y'
        Test-SIHeartbeatField -Name 'Pipeline' -Value $p | Should -Match 'Pipeline.version'
    }
    It 'the settings read takes the version per run, guarded for a schema without it' {
        $q = Get-SIHeartbeatFieldsCfgSql
        $q | Should -Match ([regex]::Escape("IF COL_LENGTH(N'cfg.FlowRun', N'Version') IS NOT NULL"))
        $q | Should -Match "N''runver'', FlowRunId, LEFT\(Version, 32\)"
    }
}

Describe 'LastRun.version -- the version the last finished run STARTED on (Invardia FLEET-TELEMETRY-1, live 9f8e838)' {
    It 'it is part of the agreed keys, the LAST one -- no switch is left' {
        @($script:C.Fields.LastRun) | Should -Be @('runId', 'kind', 'startedUtc', 'endedUtc', 'totalSec', 'result', 'collectionUtc', 'steps', 'version')
        $script:C.ContainsKey('LastRunSendVersion') | Should -BeFalse
        Get-Command -Name Get-SIHeartbeatLastRunFieldNames -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
        [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\_shared\SI-HeartbeatFields.ps1')) | Should -Not -Match 'LastRunSendVersion'
    }
    It 'a run that outlived an update: LastRun carries the version it STARTED on, never the installed one' {
        $f = New-SIHeartbeatFields -Ring 1 -NowUtc $script:Now -Switch @{ LastRun = $true } -LastRunRows @((LrRun -Ver '3.1.54'), (LrStep 1 'identity' 'Success' $script:Now.AddHours(-3) $script:Now.AddHours(-2))) -LastRunPublishedRows @() -Installed '3.1.55' -Log { param($l) }
        $f['LastRun'].version | Should -BeExactly '3.1.54'
        ($f['LastRun'] | ConvertTo-Json -Depth 5 -Compress) | Should -Match '"version":"3\.1\.54"\}$' -Because 'the last key on the wire'
    }
    It 'known: version is the LAST key, the run''s own recorded version; not recorded = left out' {
        $v = Get-SIHeartbeatLastRun -Rows @((LrRun -Ver '3.1.54'), (LrStep 1 'identity' 'Success' $script:Now.AddHours(-3) $script:Now.AddHours(-2))) -PublishedRows @() -NowUtc $script:Now
        @($v.PSObject.Properties.Name)[-1] | Should -BeExactly 'version'
        $v.version | Should -BeExactly '3.1.54'
        Test-SIHeartbeatField -Name 'LastRun' -Value $v | Should -BeNullOrEmpty
        $none = Get-SIHeartbeatLastRun -Rows @((LrRun -Ver $null)) -PublishedRows @() -NowUtc $script:Now
        $none.PSObject.Properties['version'] | Should -BeNullOrEmpty -Because 'a LastRun value that is not known is left out (#1423), never null'
        Test-SIHeartbeatField -Name 'LastRun' -Value $none | Should -BeNullOrEmpty
        $v.version = 'not ok!'
        Test-SIHeartbeatField -Name 'LastRun' -Value $v | Should -Match 'LastRun.version'
    }
    It 'the LastRun read carries the version and the beat, guarded for a schema without the version' {
        $q = Get-SIHeartbeatLastRunSql
        $q | Should -Match 'r.HeartbeatUtc AS T3'
        $q | Should -Match ([regex]::Escape("COL_LENGTH(N'cfg.FlowRun', N'Version') IS NOT NULL THEN N'r.Version' ELSE N'CAST(NULL AS nvarchar(32))' END + N' AS Ver"))
    }
}

Describe 'a KILLED run (its executions stopped or crashed, no runner closed it)' {
    It 'no beat for 30 minutes: Pipeline failed, its OWN end = last beat + 30 min, the step it died in, no estimate, no stalled steps' {
        $beat = $script:Now.AddMinutes(-45)
        $f = New-SIHeartbeatFields -Ring 1 -NowUtc $script:Now -Switch $script:Sw -CfgRows (Cfg -Beat $beat) -Log { param($l) }
        $p = $f['Pipeline']
        $p.state | Should -BeExactly 'failed' -Because 'never "running" with a stale beat'
        $p.runId | Should -BeExactly 'r-now'
        $p.lastEndedUtc | Should -BeExactly (ConvertTo-SIHeartbeatUtc $beat.AddMinutes(30)) -Because 'its own end, never the previous run''s'
        $p.step | Should -BeExactly 'endpoint'
        $p.version | Should -BeExactly '3.1.55'
        @($p.runningSteps).Count | Should -Be 0
        $p.estimatedEndUtc | Should -BeNullOrEmpty
        $p.PSObject.Properties['stalledSteps'] | Should -BeNullOrEmpty
        Test-SIHeartbeatField -Name 'Pipeline' -Value $p | Should -BeNullOrEmpty
        # the end is fixed: a later heartbeat says the same
        (Get-SIHeartbeatPipeline -Rows (Cfg -Beat $beat) -NowUtc $script:Now.AddHours(5)).lastEndedUtc | Should -BeExactly $p.lastEndedUtc
    }
    It 'a run that still beats (or beat 29 minutes ago -- the runner resumes a dead one after 15) is running; no beat recorded is not judged' {
        (Get-SIHeartbeatPipeline -Rows (Cfg -Beat $script:Now.AddMinutes(-29)) -NowUtc $script:Now).state | Should -BeExactly 'running'
        (Get-SIHeartbeatPipeline -Rows (Cfg -Beat $script:Now.AddMinutes(-2)) -NowUtc $script:Now).state | Should -BeExactly 'running'
        (Get-SIHeartbeatPipeline -Rows (Cfg -Beat $null) -NowUtc $script:Now).state | Should -BeExactly 'running' -Because 'never a guess'
        Test-SIHeartbeatRunKilled -State 'Running' -BeatUtc $script:Now.AddMinutes(-30) -NowUtc $script:Now | Should -Be $script:Now
        Test-SIHeartbeatRunKilled -State 'Starting' -BeatUtc $script:Now.AddHours(-1) -NowUtc $script:Now | Should -Be $script:Now.AddMinutes(-30)
        Test-SIHeartbeatRunKilled -State 'Succeeded' -BeatUtc $script:Now.AddHours(-9) -NowUtc $script:Now | Should -BeNullOrEmpty
        $script:C.KilledRunMinutes | Should -Be 30
    }
    It 'LastRun takes the killed run: result failed, its own runId / startedUtc / endedUtc, the step it died in failed, the rest skipped' {
        $beat = $script:Now.AddMinutes(-50)
        $rows = @((LrRun -State 'Running' -Beat $beat -End $null),
                  (LrStep 1 'identity' 'Success' $script:Now.AddHours(-3) $script:Now.AddHours(-2)),
                  (LrStep 2 'endpoint' 'Running' $script:Now.AddHours(-2)),
                  (LrStep 3 'risk-analysis-detailed' 'Waiting'))
        $v = Get-SIHeartbeatLastRun -Rows $rows -PublishedRows @() -NowUtc $script:Now
        $v.runId | Should -BeExactly 'r-now'
        $v.result | Should -BeExactly 'failed'
        $v.startedUtc | Should -BeExactly (ConvertTo-SIHeartbeatUtc $script:Now.AddHours(-3))
        $v.endedUtc | Should -BeExactly (ConvertTo-SIHeartbeatUtc $beat.AddMinutes(30))
        $v.totalSec | Should -Be ([long](($beat.AddMinutes(30) - $script:Now.AddHours(-3)).TotalSeconds))
        @($v.steps | ForEach-Object { $_.result }) | Should -Be @('ok', 'failed', 'skipped')
        Test-SIHeartbeatField -Name 'LastRun' -Value $v | Should -BeNullOrEmpty
    }
    It 'a run still beating is never LastRun' {
        Get-SIHeartbeatLastRun -Rows @((LrRun -State 'Running' -Beat $script:Now.AddMinutes(-3) -End $null)) -PublishedRows @() -NowUtc $script:Now | Should -BeNullOrEmpty
        Get-SIHeartbeatLastRun -Rows @((LrRun -State 'Running' -Beat $null -End $null)) -PublishedRows @() -NowUtc $script:Now | Should -BeNullOrEmpty
    }
    It 'the LastRun read picks a killed run (no beat for 30 min) beside the finished ones' {
        (Get-SIHeartbeatLastRunSql) | Should -Match ([regex]::Escape("OR (State IN (N''Running'', N''Starting'') AND HeartbeatUtc < DATEADD(minute, -30, SYSUTCDATETIME()))"))
    }
}

Describe 'how an early end reads -- Invardia''s values only' {
    It 'cancelled the product''s way (State Cancelled): Pipeline stopped, LastRun cancelled, with its own end' {
        $end = $script:Now.AddMinutes(-20)
        $p = Get-SIHeartbeatPipeline -Rows (Cfg -State 'Cancelled' -End $end) -NowUtc $script:Now -Stopped
        $p.state | Should -BeExactly 'stopped'
        $p.lastEndedUtc | Should -BeExactly (ConvertTo-SIHeartbeatUtc $end)
        $v = Get-SIHeartbeatLastRun -Rows @((LrRun -State 'Cancelled' -End $end)) -PublishedRows @() -NowUtc $script:Now
        $v.result | Should -BeExactly 'cancelled'; $v.endedUtc | Should -BeExactly (ConvertTo-SIHeartbeatUtc $end)
    }
    It 'ended Stopped by the runner (its executions stopped from outside): Pipeline failed, LastRun failed -- never stopped / cancelled / idle' {
        $end = $script:Now.AddMinutes(-20)
        $p = Get-SIHeartbeatPipeline -Rows (Cfg -State 'Stopped' -End $end) -NowUtc $script:Now -Stopped
        $p.state | Should -BeExactly 'failed'
        $p.lastEndedUtc | Should -BeExactly (ConvertTo-SIHeartbeatUtc $end)
        $p.step | Should -BeExactly 'endpoint'
        (Get-SIHeartbeatPipeline -Rows (Cfg -State 'Stopped' -End $end) -NowUtc $script:Now).state | Should -BeExactly 'failed' -Because 'with the stopped switch off too'
        ConvertTo-SIHeartbeatLastRunResult -State 'Stopped' | Should -BeExactly 'failed'
        ConvertTo-SIHeartbeatLastRunResult -State 'Cancelled' | Should -BeExactly 'cancelled'
        ConvertTo-SIHeartbeatLastRunResult -State 'Failed' -StepRows @((LrStep 1 'x' 'Interrupted' -Cls 'stopped')) | Should -BeExactly 'failed'
        ConvertTo-SIHeartbeatLastRunResult -State 'Failed' -StepRows @((LrStep 1 'x' 'Interrupted' -Cls 'cancelled')) | Should -BeExactly 'cancelled'
        ConvertTo-SIHeartbeatLastRunResult -State 'Running' -Killed | Should -BeExactly 'failed'
    }
}

Describe 'the update result is in the state row before the new version''s first heartbeat' {
    It 'an install in progress: lastUpdaterResult null (no "in progress" value in the contract), never the previous run''s; its start as the run time' {
        $st = ConvertFrom-SIInvardiaUpdateState -Json ''
        Set-SIInvardiaUpdateCheck -State $st -Result ([pscustomobject]@{ Kind = 'code'; Action = 'current'; Reason = ''; Manifest = $true; Version = '3.1.54'; Sequence = 6; Ring = 1 }) -NowUtc $script:Now.AddDays(-1)
        $st.code.appliedSequence = 6
        $before = ConvertTo-SIInvardiaUpdateStateJson -State $st -Compact
        $row = { param($j) @((Row 'state' 'UpdateState' -T1 $script:Now -Txt $j)) }
        (Get-SIHeartbeatUpdate -Rows (& $row $before) -Installed '3.1.55' -UpdaterCron '' -NowUtc $script:Now).lastUpdaterResult | Should -BeExactly 'nothing-to-do' -Because 'the old row: what the heartbeat sent 17:31-18:16Z'
        Set-SIInvardiaUpdateInProgress -State $st -Version '3.1.55' -NowUtc $script:Now.AddMinutes(-10)
        $during = ConvertTo-SIInvardiaUpdateStateJson -State $st -Compact
        $during | Should -Match '"updating":"2026-11-27T17:50:00Z"' -Because 'the mark is its start time only (short: the row keeps to 400)'
        $during.Length | Should -BeLessOrEqual 400
        $u = Get-SIHeartbeatUpdate -Rows (& $row $during) -Installed '3.1.55' -UpdaterCron '' -NowUtc $script:Now
        $u.lastUpdaterResult | Should -BeNullOrEmpty
        $u.lastUpdaterRunUtc | Should -BeExactly '2026-11-27T17:50:00Z'
        Test-SIHeartbeatField -Name 'Update' -Value $u | Should -BeNullOrEmpty
        (ConvertTo-SIInvardiaUpdateStateJson -State $st) | Should -Not -Match 'updating' -Because 'the Key Vault state never keeps the mark'
        # decided: applied -> succeeded, the mark gone
        Set-SIInvardiaUpdateCheck -State $st -Result ([pscustomobject]@{ Kind = 'code'; Action = 'update'; Reason = ''; Manifest = $true; Version = '3.1.55'; Sequence = 7; Ring = 1 }) -NowUtc $script:Now
        Set-SIInvardiaUpdateApplied -State $st -Result ([pscustomobject]@{ Kind = 'code'; Version = '3.1.55'; Sequence = 7 }) -NowUtc $script:Now
        Set-SIInvardiaUpdateInProgress -State $st -Clear
        $after = ConvertTo-SIInvardiaUpdateStateJson -State $st -Compact
        $after | Should -Not -Match 'updating'
        (Get-SIHeartbeatUpdate -Rows (& $row $after) -Installed '3.1.55' -UpdaterCron '' -NowUtc $script:Now).lastUpdaterResult | Should -BeExactly 'succeeded'
    }
    It 'a mark older than UpdateInProgressMaxHours was never cleared: that update died part-way -- failed' {
        $j = '{"source":"invardia","lastCheckUtc":"2026-11-27T08:00:00Z","code":{"version":"3.1.54","sequence":6,"ring":1,"action":"current","applied":6,"hold":""},"error":"","updating":"2026-11-27T08:00:00Z"}'
        $u = Get-SIHeartbeatUpdate -Rows @((Row 'state' 'UpdateState' -T1 $script:Now -Txt $j)) -Installed '3.1.55' -UpdaterCron '' -NowUtc $script:Now
        $u.lastUpdaterResult | Should -BeExactly 'failed'
        $script:C.UpdateInProgressMaxHours | Should -Be 6
        # an object mark { since } reads the same
        $o = $j.Replace('"updating":"2026-11-27T08:00:00Z"', '"updating":{"since":"2026-11-27T17:00:00Z"}')
        (Get-SIHeartbeatUpdate -Rows @((Row 'state' 'UpdateState' -T1 $script:Now -Txt $o)) -Installed '3.1.55' -UpdaterCron '' -NowUtc $script:Now).lastUpdaterResult | Should -BeNullOrEmpty
    }
    It 'a LARGE state with the mark stays within the row''s 400 characters -- and the mark is never what gives way' {
        $st = ConvertFrom-SIInvardiaUpdateState -Json ''
        $long = 'x' * 300
        foreach ($kind in 'code', 'templates') {
            Set-SIInvardiaUpdateCheck -State $st -Result ([pscustomobject]@{ Kind = $kind; Action = 'hold'; Reason = $long; Manifest = $true; Version = '3.1.155-rc.12'; Sequence = 1234567; Ring = 2; Wave = 'wave-ring2-early' }) -NowUtc $script:Now
            $st[$kind].appliedSequence = 1234566; $st[$kind].appliedVersion = '3.1.154-rc.11'; $st[$kind].appliedRing = 2; $st[$kind].appliedWave = 'wave-ring2-early'
        }
        $st.lastError = $long; $st.claimResult = 'failed'; $st.claimAgainResult = 'refused'; $st.claimAgainUtc = $script:Now
        $st.waitsSinceUtc = $script:Now; $st.waitsReason = $long; $st.waitsKind = 'store'
        Set-SIInvardiaUpdateInProgress -State $st -Version '3.1.155-rc.12' -NowUtc $script:Now
        $j = ConvertTo-SIInvardiaUpdateStateJson -State $st -Compact
        $j.Length | Should -BeLessOrEqual 400 -Because "the row holds 400 on an install whose column is not widened yet ($($j.Length): $j)"
        $j | Should -Match '"updating":"2026-11-27T18:00:00Z"'
        $j | Should -Match '"code":\{"version":"3\.1\.155-rc\.12"' -Because 'the code''s record stays; the templates'' wave, claim-again, wait, templates, claim give way first'
        $j | Should -Match '"code":\{[^}]*"wave":\{"name":"wave-ring2-early"' -Because 'the code''s wave is never dropped: the heartbeat and the web header read it from this row alone'
        # a state that fits keeps everything (nothing is dropped that did not have to be)
        $small = ConvertFrom-SIInvardiaUpdateState -Json ''
        Set-SIInvardiaUpdateCheck -State $small -Result ([pscustomobject]@{ Kind = 'code'; Action = 'update'; Reason = ''; Manifest = $true; Version = '3.1.55'; Sequence = 7; Ring = 1 }) -NowUtc $script:Now
        $small.waitsSinceUtc = $script:Now; $small.waitsReason = 'run r-1'; $small.waitsKind = 'run'
        Set-SIInvardiaUpdateInProgress -State $small -Version '3.1.55' -NowUtc $script:Now
        $sj = ConvertTo-SIInvardiaUpdateStateJson -State $small -Compact
        $sj | Should -Match '"waits":\{'; $sj | Should -Match '"updating":"2026-11-27T18:00:00Z"'
        (Get-SIHeartbeatUpdate -Rows @((Row 'state' 'UpdateState' -T1 $script:Now -Txt $j)) -Installed '3.1.154' -UpdaterCron '' -NowUtc $script:Now).lastUpdaterResult | Should -BeNullOrEmpty
    }
    It 'the code''s pre-release wave is NEVER dropped: a 60-character wave name + a claim-again + the mark keeps the wave whole and stays <= 400' {
        if (-not (Get-Command -Name ConvertFrom-SIGuardStrictJson -ErrorAction SilentlyContinue)) { . (Join-Path $script:SIRoot 'engine\_shared\SI-GuardStrict.ps1') }
        if (-not (Get-Command -Name Get-SIReleaseWaveFromUpdateState -ErrorAction SilentlyContinue)) { . (Join-Path $script:SIRoot 'engine\_shared\SI-ReleaseControl.ps1') }
        $wave = 'wave-' + ('a' * 55)
        $wave.Length | Should -Be 60
        $mk = {
            $st = ConvertFrom-SIInvardiaUpdateState -Json ''
            Set-SIInvardiaUpdateCheck -State $st -Result ([pscustomobject]@{ Kind = 'code'; Action = 'update'; Reason = ''; Manifest = $true; Version = '3.1.155-rc.12'; Sequence = 1234567; Ring = 1; Wave = $wave }) -NowUtc $script:Now
            $st.code.appliedSequence = 1234566; $st.code.appliedVersion = '3.1.154-rc.11'; $st.code.appliedRing = 1; $st.code.appliedWave = $wave
            $st.claimAgainResult = 'refused'; $st.claimAgainUtc = $script:Now
            Set-SIInvardiaUpdateInProgress -State $st -Version '3.1.155-rc.12' -NowUtc $script:Now
            $st
        }
        $st = & $mk
        $j = ConvertTo-SIInvardiaUpdateStateJson -State $st -Compact
        $j.Length | Should -BeLessOrEqual 400
        $j | Should -Match '"updating":"2026-11-27T18:00:00Z"'
        $w = Get-SIReleaseWaveFromUpdateState -Json $j
        $w.Known | Should -BeTrue
        $w.Wave.name | Should -BeExactly $wave -Because 'the heartbeat and the web header must not read "no wave"'
        # the worst case too: both kinds held in waves with long reasons, a long error, a wait, a claim -- the code's wave stays
        $big = & $mk
        $long = 'x' * 300
        Set-SIInvardiaUpdateCheck -State $big -Result ([pscustomobject]@{ Kind = 'templates'; Action = 'hold'; Reason = $long; Manifest = $true; Version = '3.1.155-rc.12'; Sequence = 1234567; Ring = 1; Wave = $wave }) -NowUtc $script:Now
        $big.templates.appliedSequence = 1234566; $big.templates.appliedWave = $wave; $big.code.hold = $long
        $big.lastError = $long; $big.claimResult = 'failed'; $big.waitsSinceUtc = $script:Now; $big.waitsReason = $long; $big.waitsKind = 'store'
        $bj = ConvertTo-SIInvardiaUpdateStateJson -State $big -Compact
        $bj.Length | Should -BeLessOrEqual 400 -Because "($($bj.Length)): $bj"
        (Get-SIReleaseWaveFromUpdateState -Json $bj).Wave.name | Should -Not -BeNullOrEmpty -Because 'at most its name is shortened, never the wave dropped'
        $bj | Should -Match '"updating":"2026-11-27T18:00:00Z"'
    }
    It 'the updater: the mark BEFORE the roll, the result right after the install is decided -- before old images, sizes and templates' {
        $inv = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\updater\_shared\SI-UpdaterInvardia.ps1'))
        $mark = $inv.IndexOf('Set-SIInvardiaUpdateInProgress -State $state -Version')
        $roll = $inv.IndexOf('$roll = Invoke-SIUpdaterRoll ')
        $mark | Should -BeGreaterThan 0
        $mark | Should -BeLessThan $roll
        $inv.Substring($mark, 200) | Should -Match '& \$save' -Because 'the mark is saved, not only set'
        $post = $inv.IndexOf('$pro = Get-SIUpdaterPostRollOutcome')
        $res = $inv.IndexOf('& $saveResult', $post)
        $res | Should -BeGreaterThan $post
        $res | Should -BeLessThan $inv.IndexOf('Invoke-SIUpdaterImagePruneStep', $post) -Because 'the result goes out before the old-image clean-up'
        $res | Should -BeLessThan $inv.IndexOf('Invoke-SIUpdaterSizingPass', $post)
        # held and failed rolls write their result at once too
        $held = $inv.IndexOf('if ($roll.Held) {')
        $inv.IndexOf('& $saveResult', $held) | Should -BeLessThan $inv.IndexOf('elseif ($roll.Code -eq 0) {', $held)
        $fail = $inv.IndexOf('$rc = [int]$roll.Code;')
        $inv.IndexOf('& $saveResult', $fail) | Should -BeLessThan $inv.IndexOf('#756: NO NEW CODE THIS RUN', $fail)
    }
}

Describe 'the updater run against seams: the state is saved before the roll and the result before the run''s tail' {
    BeforeAll {
        . (Join-Path $script:SIRoot 'container\updater\Start-SIUpdater.ps1') -DefineOnly
        . (Join-Path $script:SIRoot 'container\updater\_shared\SI-UpdaterInvardia.ps1')
        . (Join-Path $script:SIRoot 'engine\_shared\SI-InvardiaUpdate.ps1')
        if (-not (Get-Command -Name Test-SICommunityChannelEntry -ErrorAction SilentlyContinue)) { . (Join-Path $script:SIRoot 'engine\_shared\SI-CommunityUpdate.ps1') }
        Add-Type -AssemblyName System.IO.Compression -ErrorAction SilentlyContinue
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
        Mock Invoke-WebRequest { throw 'no network in tests' }
        Mock Invoke-RestMethod { throw 'no network in tests' }
        Mock Invoke-SIUpdaterTrackHook { }
        function script:B64Url([byte[]]$b) { [Convert]::ToBase64String($b).TrimEnd('=').Replace('+', '-').Replace('/', '_') }
        $script:Rsa = [System.Security.Cryptography.RSA]::Create(2048)
        $pub = $script:Rsa.ExportParameters($false)
        $script:Keys = @(@{ keyId = 'test-update-key'; n = (B64Url $pub.Modulus); e = (B64Url $pub.Exponent) })
        $need = @(@($script:SICommunityUpdateClientFiles) + @($script:SIUpdaterCommunityRequiredFiles) | Where-Object { $_ } | Sort-Object -Unique)
        if ($need.Count -lt 5) { $need = @('engine/_shared/SI-CommunityUpdate.ps1', 'engine/_shared/InvardiaUpdate.verify.ps1', 'engine/_shared/SI-InvardiaUpdate.ps1', 'setup/Invoke-SIContainerUpdate.ps1', 'container/updater/Start-SIUpdater.ps1', 'container/updater/_shared/SI-UpdaterInvardia.ps1', 'container/updater/_shared/SI-UpdaterCommunity.ps1') }
        $dir = Join-Path $TestDrive 'rel-3.0.1'; New-Item -ItemType Directory -Force -Path $dir | Out-Null
        [IO.File]::WriteAllText((Join-Path $dir 'VERSION'), '3.0.1')
        [IO.File]::WriteAllText((Join-Path $dir 'BUILD.json'), '{"display":"3.0.1","commit":"A1B2C3D4E5F60718293A4B5C6D7E8F9012345678"}')
        foreach ($f in $need) { $p = Join-Path $dir $f; New-Item -ItemType Directory -Force -Path (Split-Path -Parent $p) | Out-Null; [IO.File]::WriteAllText($p, "# $f") }
        $script:Zip = "$dir.zip"; [System.IO.Compression.ZipFile]::CreateFromDirectory($dir, $script:Zip)
        $script:Url = 'https://github.com/KnudsenMorten/SecurityInsight/releases/download/v3.0.1/SecurityInsight-v3.0.1.zip'
        $m = [ordered]@{ product = 'securityinsight'; kind = 'community'; ring = 3; sequence = 7; version = '3.0.1'
                         sha256 = (Get-FileHash -LiteralPath $script:Zip -Algorithm SHA256).Hash.ToLowerInvariant(); size = (Get-Item -LiteralPath $script:Zip).Length; minFromVersion = $null; manualStep = $null }
        $raw = [Text.Encoding]::UTF8.GetBytes(($m | ConvertTo-Json -Compress))
        $sig = $script:Rsa.SignData($raw, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $script:Entry = [ordered]@{ manifestB64 = [Convert]::ToBase64String($raw); signature = [Convert]::ToBase64String($sig); keyId = 'test-update-key'; downloadUrl = $script:Url }
    }
    It 'at the roll the state is already saved; at the old-image clean-up the result (applied) is saved' {
        $w = @{ Vault = @{}; AtRoll = $null; AtPost = $null; AtPrune = $null }
        $script:W = $w
        Mock Invoke-SIUpdaterRoll { $script:W.AtRoll = [string]$script:W.Vault['SI-Update-State']; [pscustomobject]@{ Code = 0; Held = $false; Reason = '' } }
        $seams = @{
            GetManifest = { param($u) [pscustomobject]@{ Status = 200; Body = ($script:Entry | ConvertTo-Json -Depth 6) } }
            Http        = { param($u, $b, $k, $hn, $id) [pscustomobject]@{ Status = 204; Body = ''; RetryAfter = 0; Error = '' } }
            Download    = { param($u, $f) Copy-Item -LiteralPath $script:Zip -Destination $f -Force; [pscustomobject]@{ Status = 200; Error = '' } }
            ReadSecret  = { param($n) if ($script:W.Vault.ContainsKey($n)) { $script:W.Vault[$n] } else { $null } }
            WriteSecret = { param($n, $v) $script:W.Vault[$n] = $v }
            TenantId    = { '11111111-2222-3333-4444-555555555555' }
            ClaimHttp   = { param($u, $b) [pscustomobject]@{ Status = 0; Body = ''; RetryAfter = 0; Error = 'offline in tests' } }
            ReadEdition = { 'community' }
            ReadCommunityState = { '' }
            Now         = { [datetime]'2026-11-27T17:31:00Z' }
            CommunityTrustedKeys = { $script:Keys }
            PreRoll     = { [pscustomobject]@{ Go = $true; Reason = ''; Environment = $null } }
            PostRoll    = { param($r, $v, $c) $script:W.AtPost = [string]$script:W.Vault['SI-Update-State']; [pscustomobject]@{ Code = 0; Text = "this environment now runs SecurityInsight $v" } }
            ImagePrune  = { param($b) $script:W.AtPrune = [string]$script:W.Vault['SI-Update-State'] }
            SizingPass  = { param($why) }
            SelfRetry   = { $null }
            RunGate     = { param($h) [pscustomobject]@{ Go = $true; Verdict = 'Go'; Kind = ''; Reason = 'no pipeline run is going'; RunId = ''; LockTaken = $false; Holder = '' } }
            ReadWaits   = { $null }
            WriteWaits  = { param($v) }
        }
        $null = @(Invoke-SIUpdaterFromInvardia -Env @{} -SubscriptionId 'sub' -ResourceGroup 'rg' -AcrName 'acr' -Store $null -Deployed '3.0.0' -SIRoot $script:SIRoot -Seams $seams -Work (Join-Path $TestDrive 'work') 6>&1)
        $w.AtRoll | Should -Not -BeNullOrEmpty -Because 'the state is saved BEFORE the roll swaps the jobs (the mark goes with it into the row)'
        (ConvertFrom-SIInvardiaUpdateState -Json $w.AtRoll).code.appliedSequence | Should -Be -1 -Because 'nothing is claimed as applied before it is'
        $w.AtPrune | Should -Not -BeNullOrEmpty
        (ConvertFrom-SIInvardiaUpdateState -Json $w.AtPrune).code.appliedSequence | Should -Be 7 -Because 'the result is saved the moment the install is decided -- before the run''s long tail'
        (ConvertFrom-SIInvardiaUpdateState -Json ([string]$w.Vault['SI-Update-State'])).code.appliedSequence | Should -Be 7
    }
    Context 'the state ROW (a Pro database): the mark is in it at the roll and never outlives the run' {
        BeforeAll {
            $script:Store = [pscustomobject]@{ Invoke = { param($a, $b, $c) $null }; Server = ''; Database = '' }
            # the seams of the run above, with PostRoll as -Post
            $script:MkSeams = { param([scriptblock]$Post = { param($r, $v, $c) [pscustomobject]@{ Code = 0; Text = "this environment now runs SecurityInsight $v" } })
                @{  GetManifest = { param($u) [pscustomobject]@{ Status = 200; Body = ($script:Entry | ConvertTo-Json -Depth 6) } }
                    Http        = { param($u, $b, $k, $hn, $id) [pscustomobject]@{ Status = 204; Body = ''; RetryAfter = 0; Error = '' } }
                    Download    = { param($u, $f) Copy-Item -LiteralPath $script:Zip -Destination $f -Force; [pscustomobject]@{ Status = 200; Error = '' } }
                    ReadSecret  = { param($n) if ($script:W.Vault.ContainsKey($n)) { $script:W.Vault[$n] } else { $null } }
                    WriteSecret = { param($n, $v) $script:W.Vault[$n] = $v }
                    TenantId    = { '11111111-2222-3333-4444-555555555555' }
                    ClaimHttp   = { param($u, $b) [pscustomobject]@{ Status = 0; Body = ''; RetryAfter = 0; Error = 'offline in tests' } }
                    ReadEdition = { 'community' }
                    ReadCommunityState = { '' }
                    Now         = { [datetime]'2026-11-27T17:31:00Z' }
                    CommunityTrustedKeys = { $script:Keys }
                    PreRoll     = { [pscustomobject]@{ Go = $true; Reason = ''; Environment = $null } }
                    PostRoll    = $Post
                    ImagePrune  = { param($b) }
                    SizingPass  = { param($why) }
                    SelfRetry   = { $null }
                    RunGate     = { param($h) [pscustomobject]@{ Go = $true; Verdict = 'Go'; Kind = ''; Reason = 'no pipeline run is going'; RunId = ''; LockTaken = $false; Holder = '' } }
                    ReadWaits   = { $null }
                    WriteWaits  = { param($v) } } }
            $script:RunWithRow = { param($Seams, [string]$Work)
                $null = @(Invoke-SIUpdaterFromInvardia -Env @{} -SubscriptionId 'sub' -ResourceGroup 'rg' -AcrName 'acr' -Store $script:Store -Deployed '3.0.0' -SIRoot $script:SIRoot -Seams $Seams -Work (Join-Path $TestDrive $Work) 6>&1) }
            $script:HbOf = { param([string]$Json) Get-SIHeartbeatUpdate -Rows @((Row 'state' 'UpdateState' -T1 $script:Now -Txt $Json)) -Installed '3.0.0' -UpdaterCron '' -NowUtc (U '2026-11-27T17:40:00') }
        }
        BeforeEach {
            $script:W = @{ Vault = @{}; Rows = New-Object System.Collections.Generic.List[string]; AtRoll = $null }
            Mock Save-SIUpdaterInvardiaStateRow { $script:W.Rows.Add([string]$Json) }
            Mock Resolve-SIUpdaterInvardiaRing { [pscustomobject]@{ Ring = 3; Reason = 'test' } }
            Mock Receive-SIUpdaterClaimAgain { [pscustomobject]@{ Asked = $false; Reason = ''; By = '' } }
        }
        It 'a good install: the row carries the mark at the roll (heartbeat: no result yet), and not after it (succeeded)' {
            Mock Invoke-SIUpdaterRoll { $script:W.AtRoll = @($script:W.Rows)[-1]; [pscustomobject]@{ Code = 0; Held = $false; Reason = '' } }
            & $script:RunWithRow (& $script:MkSeams) 'rowA'
            $script:W.AtRoll | Should -Match '"updating":"2026-11-27T17:31:00Z"'
            (& $script:HbOf $script:W.AtRoll).lastUpdaterResult | Should -BeNullOrEmpty
            @($script:W.Rows)[-1] | Should -Not -Match '"updating"'
            (& $script:HbOf @($script:W.Rows)[-1]).lastUpdaterResult | Should -BeExactly 'succeeded'
        }
        It 'the roll THROWS: the run''s last row has no mark -- the heartbeat reads failed at once (never null for hours)' {
            Mock Invoke-SIUpdaterRoll { throw 'ARM answered 500 during the roll' }
            & $script:RunWithRow (& $script:MkSeams) 'rowB'
            $last = @($script:W.Rows)[-1]
            $last | Should -Not -Match '"updating"'
            $last | Should -Match 'ARM answered 500'
            (& $script:HbOf $last).lastUpdaterResult | Should -BeExactly 'failed'
        }
        It 'the post-roll THROWS: the same -- no mark, failed' {
            Mock Invoke-SIUpdaterRoll { [pscustomobject]@{ Code = 0; Held = $false; Reason = '' } }
            & $script:RunWithRow (& $script:MkSeams -Post { param($r, $v, $c) throw 'the web app did not answer' }) 'rowC'
            $last = @($script:W.Rows)[-1]
            $last | Should -Not -Match '"updating"'
            (& $script:HbOf $last).lastUpdaterResult | Should -BeExactly 'failed'
        }
        It 'the source: the mark is cleared before the run''s final save, after its catch' {
            $inv = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\updater\_shared\SI-UpdaterInvardia.ps1'))
            $catch = $inv.IndexOf('updates from Invardia FAILED')
            $clear = $inv.IndexOf('Set-SIInvardiaUpdateInProgress -State $state -Clear }', $catch)
            $clear | Should -BeGreaterThan $catch
            $inv.IndexOf('& $save', $clear) | Should -BeGreaterThan $clear
        }
    }
}
