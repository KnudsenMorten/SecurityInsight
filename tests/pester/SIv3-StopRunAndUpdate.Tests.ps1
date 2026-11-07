#Requires -Version 5.1
<#
    #1101 STOP THE RUNNING RUN, THEN UPDATE (setup\Stop-SIRunAndUpdate.ps1 + setup\_shared\SI-StopRunAndUpdate.ps1).
    Live 2026-11-04: a support session cancelled the running run and started the updater at the same moment; the cancel took
    minutes to stop the run's executions, the updater saw the run still going and stepped aside. Proven here on a fake
    install (ARM, the Pro database, the update state, the clock -- all stubs in SCRIPT scope):
      * the plan, with and without a running run (only output without -Apply; nothing started);
      * THE ORDER: the updater is never started before the stop is confirmed (executions stay Running for N polls);
      * the limit: not confirmed in time = stop, say what still runs, no updater;
      * -SkipUpdate; the version read back (updated / stepped aside); no run running = straight to the update;
      * it never starts a pipeline step (only caj-si-flow with SI_FLOW_CANCEL=1 and the updater are ever started);
      * the one start-body builder (New-SIJobStartTemplate) and the updater's body unchanged.
    Offline; PS 5.1 and 7.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . ([IO.Path]::Combine($script:SIRoot, 'setup', '_shared', 'SI-StopRunAndUpdate.ps1'))
    $script:Sub = '22222222-2222-2222-2222-222222222222'
    $script:Rg = 'rg-si-test'
    $script:T0 = [datetime]::SpecifyKind([datetime]'2026-11-04T10:00:00', 'Utc')

    # the update client's reader (Pro; not loaded here): the stub reads the fake state JSON
    function Get-SIInvardiaUpdateStatus {
        param([AllowNull()][string]$Json)
        $o = $Json | ConvertFrom-Json
        [pscustomobject]@{ Code = $o.code; LastCheckUtc = $o.lastCheckUtc; LastError = ''; Summary = 'state'; Holds = @() }
    }

    function New-TestJob {
        param([string]$Name, [hashtable]$Env = @{}, [hashtable]$Tags = @{})
        $envList = @([pscustomobject]@{ name = 'SI_KEEP'; value = 'kept' }, [pscustomobject]@{ name = 'SI_SECRET'; secretRef = 'a-secret' })
        foreach ($k in $Env.Keys) { $envList += [pscustomobject]@{ name = $k; value = $Env[$k] } }
        [pscustomobject]@{ name = $Name; id = ('/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.App/jobs/{2}' -f $script:Sub, $script:Rg, $Name)
            tags = [pscustomobject]$Tags
            properties = [pscustomobject]@{ configuration = [pscustomobject]@{ replicaTimeout = 3600 }
                template = [pscustomobject]@{ containers = @([pscustomobject]@{ name = 'main'; image = 'acr.azurecr.io/si:1'; env = $envList; resources = [pscustomobject]@{ cpu = 1; memory = '2Gi' } }) } } }
    }
    function New-TestExec { param([string]$Name, [string]$Status = 'Running', [datetime]$Start)
        [pscustomobject]@{ name = $Name; properties = [pscustomobject]@{ status = $Status; startTime = $Start.ToString('o'); endTime = $null } } }
    function Stop-TestExec { param($Exec, [string]$Status = 'Stopped') $Exec.properties.status = $Status; $Exec.properties.endTime = $script:W.Clock.ToString('o') }

    # THE FAKE INSTALL. -Running: a run is going (runner + the identity step + a worker). After the cancel starts, the cancel
    # execution ends after -CancelPolls polls (the run then reads Cancelled, the runner stops) and the run's executions after
    # -StepPolls more (-NeverStop: never). The updater ends after -UpdPolls polls: installs -UpdTo, or steps aside (-UpdSkips).
    function New-TestWorld {
        param([bool]$Running = $true, [int]$CancelPolls = 1, [int]$StepPolls = 3, [switch]$NeverStop, [int]$UpdPolls = 2, [string]$UpdTo = '3.0.41', [switch]$UpdSkips)
        $jobs = @(
            (New-TestJob 'caj-si-flow' @{ SI_ProSqlServer = 'server.database.windows.net'; SI_ProSqlDatabase = 'sqldb-x' })
            (New-TestJob 'caj-si-identity'); (New-TestJob 'caj-si-azure-producer'); (New-TestJob 'caj-si-azure-worker'); (New-TestJob 'caj-si-asset-datasync')
            (New-TestJob 'caj-si-heartbeat')
            (New-TestJob 'caj-si-updater' @{ SI_UPDATER_RING = '2'; SI_UPDATER_KEY_VAULT = 'kv-x' } @{ 'si-installed' = '3.0.40'; 'si-installed-utc' = '2026-11-01T18:30:00Z' })
        )
        $ex = @{}; foreach ($j in $jobs) { $ex[[string]$j.name] = New-Object System.Collections.Generic.List[object] }
        $ex['caj-si-heartbeat'].Add((New-TestExec 'caj-si-heartbeat-h1' 'Running' $script:T0.AddMinutes(-1)))   # never a step
        $ex['caj-si-flow'].Add((New-TestExec 'caj-si-flow-old' 'Succeeded' $script:T0.AddDays(-1)))
        $run = [ordered]@{ FlowRunId = 'run-7'; State = 'Succeeded'; Trg = 'schedule'; StartedUtc = $script:T0.AddDays(-1); Step = '' }
        if ($Running) {
            $ex['caj-si-flow'].Add((New-TestExec 'caj-si-flow-runner' 'Running' $script:T0.AddHours(-2)))
            $ex['caj-si-identity'].Add((New-TestExec 'caj-si-identity-s1' 'Running' $script:T0.AddMinutes(-40)))
            $ex['caj-si-azure-worker'].Add((New-TestExec 'caj-si-azure-worker-w1' 'Running' $script:T0.AddMinutes(-30)))
            $run = [ordered]@{ FlowRunId = 'run-8'; State = 'Running'; Trg = 'schedule'; StartedUtc = $script:T0.AddHours(-2); Step = 'identity' }
        }
        $script:W = @{ Jobs = $jobs; Ex = $ex; Run = $run; Clock = $script:T0; Calls = (New-Object System.Collections.Generic.List[object]); Audit = (New-Object System.Collections.Generic.List[string])
                       CancelPolls = $CancelPolls; StepPolls = $StepPolls; NeverStop = [bool]$NeverStop; UpdPolls = $UpdPolls; UpdTo = $UpdTo; UpdSkips = [bool]$UpdSkips
                       CancelExec = $null; CancelAge = 0; UpdExec = $null; UpdAge = 0; AtUpdaterStart = $null; StateCheckUtc = $script:T0.AddHours(-20); StateAction = 'update' }
    }

    # one poll of time: the fake install moves on
    $script:Tick = {
        $w = $script:W
        if ($w.CancelExec) {
            $w.CancelAge++
            if ($w.CancelAge -eq $w.CancelPolls) {
                Stop-TestExec $w.CancelExec 'Succeeded'
                $w.Run.State = 'Cancelled'
                foreach ($e in @($w.Ex['caj-si-flow'] | Where-Object { $_.name -eq 'caj-si-flow-runner' })) { Stop-TestExec $e }
            }
            if (-not $w.NeverStop -and $w.CancelAge -ge ($w.CancelPolls + $w.StepPolls)) {
                foreach ($j in 'caj-si-identity', 'caj-si-azure-worker') { foreach ($e in @($w.Ex[$j] | Where-Object { $_.properties.status -eq 'Running' })) { Stop-TestExec $e } }
            }
        }
        if ($w.UpdExec) {
            $w.UpdAge++
            if ($w.UpdAge -eq $w.UpdPolls) {
                Stop-TestExec $w.UpdExec 'Succeeded'
                $u = @($w.Jobs | Where-Object { $_.name -eq 'caj-si-updater' })[0]
                $w.StateCheckUtc = $w.Clock
                if ($w.UpdSkips) { $u.tags | Add-Member -NotePropertyName 'si-update-waits' -NotePropertyValue ('{0:yyyy-MM-ddTHH:mm:ssZ}|{0:yyyy-MM-ddTHH:mm:ssZ}|run|a pipeline run is going (run-9)' -f $w.Clock) -Force; $w.StateAction = 'waiting' }
                else { $u.tags.'si-installed' = $w.UpdTo; $w.StateAction = 'applied' }
            }
        }
    }
    $script:Sleep = { param($s) $script:W.Clock = $script:W.Clock.AddSeconds($s); & $script:Tick }
    $script:Now = { $script:W.Clock }

    $script:Arm = {
        param([string]$Method, [string]$Path, $Body)
        $w = $script:W
        $w.Calls.Add([pscustomobject]@{ Method = $Method; Path = $Path; Body = $Body; At = $w.Clock })
        $p = $Path -replace '\?.*$', ''
        if ($Method -eq 'GET' -and $p -match '/providers/Microsoft\.App/jobs$') { return [pscustomobject]@{ value = @($w.Jobs) } }
        if ($Method -eq 'GET' -and $p -match '/jobs/([^/]+)/executions$') { $k = [string]$Matches[1]; $list = $w['Ex'][$k]; return [pscustomobject]@{ value = $(if ($null -ne $list) { $list.ToArray() } else { @() }) } }
        if ($Method -eq 'GET' -and $p -match '/jobs/([^/]+)$') { return @($w.Jobs | Where-Object { $_.name -eq $Matches[1] })[0] }
        if ($Method -eq 'POST' -and $p -match '/jobs/([^/]+)/start$') {
            $job = $Matches[1]
            $name = '{0}-z{1}' -f $job, ($w.Calls.Count)
            $e = New-TestExec $name 'Running' $w.Clock
            if ($job -eq 'caj-si-updater') {
                # what runs at the moment the updater is started (the run's jobs and the runner; the heartbeat is not one)
                $w.AtUpdaterStart = @(foreach ($k in @($w.Ex.Keys)) { if ($k -notin 'caj-si-heartbeat', 'caj-si-updater') { foreach ($x in @($w.Ex[$k] | Where-Object { $_.properties.status -eq 'Running' })) { '{0} {1}' -f $k, $x.name } } })
                $w.UpdExec = $e
            } elseif ($job -eq 'caj-si-flow') { $w.CancelExec = $e }
            $w.Ex[$job].Add($e)
            return [pscustomobject]@{ name = $name; id = ('{0}/executions/{1}' -f $p, $name) }
        }
        throw ('unexpected ARM call: {0} {1}' -f $Method, $Path)
    }

    $script:Sql = {
        param([string]$Query, $Params, [string]$Mode)
        $w = $script:W
        if ($Query -match 'INSERT cfg\.AuditEvent') { $w.Audit.Add([string]$Params['Action']); return 'Saved' }
        if ($Query -match 'FROM cfg\.FlowStepRun WHERE FlowRunId = @FlowRunId') {
            if (-not $w.Run.Step) { return , @() }
            return , @(@{ StepOrder = 2; GroupNo = 2; Job = $w.Run.Step; Stage = 'collect'; State = $(if ($w.Run.State -eq 'Running') { 'Running' } else { 'Interrupted' }); Execution = 'caj-si-identity-s1'
                          StartedUtc = $script:T0.AddMinutes(-40); EndedUtc = $null; ErrorClass = ''; Error = ''; Attempts = 1; RetryReason = '' })
        }
        if ($Query -match 'SELECT TOP \(1\) \* FROM cfg\.FlowRun') {
            return , @(@{ FlowRunId = $w.Run.FlowRunId; Day = '2026-11-04'; Trg = $w.Run.Trg; FromStep = ''; State = $w.Run.State; StartedUtc = $w.Run.StartedUtc; EndedUtc = $null; HeartbeatUtc = $null
                          StopReason = ''; SlotUtc = $null; LastSlotUtc = $null; Note = ''; Scope = 'pipeline'; Target = ''; RequestedBy = ''; RequestId = 0; Version = '3.0.40'; CancelledBy = '' })
        }
        throw ('unexpected SQL: ' + $Query)
    }
    $script:ReadState = { '{{"code":{{"lastVersion":"3.0.41","lastSequence":41,"lastRing":"2","lastAction":"{0}","hold":""}},"lastCheckUtc":"{1:o}"}}' -f $script:W.StateAction, $script:W.StateCheckUtc }

    function Invoke-TestRun {
        param([switch]$Apply, [switch]$SkipUpdate, [int]$TimeoutMinutes = 30, [string]$RunId = '', [switch]$NoSql)
        $script:Said = New-Object System.Collections.Generic.List[string]
        $a = @{ Arm = $script:Arm; SubscriptionId = $script:Sub; ResourceGroup = $script:Rg; Reason = 'the run hangs on the old release'; RunId = $RunId
                SkipUpdate = $SkipUpdate; Apply = $Apply; TimeoutMinutes = $TimeoutMinutes; PollSeconds = 30; By = 'support (test)'
                ReadUpdateState = $script:ReadState; Sleep = $script:Sleep; Now = $script:Now; Say = { param($l, $c) $script:Said.Add($l) } }
        if ($NoSql) { $a.SqlWhy = 'the database does not answer from here (test)' } else { $a.Sql = $script:Sql }
        Invoke-SIStopRunAndUpdate @a
    }
    function Get-StartCalls { @($script:W.Calls | Where-Object { $_.Method -eq 'POST' -and $_.Path -match '/start' }) }
    function Get-BodyEnv { param($Body) $h = @{}; foreach ($e in @($Body.containers[0].env)) { $h[[string]$e.name] = $(if ($e.PSObject.Properties['value']) { [string]$e.value } else { '@' + [string]$e.secretRef }) }; $h }
}

Describe '0. the plan (the only output without -Apply)' {
    It 'a running run: its id, trigger, step and age, every running execution, the versions, what will happen -- nothing started' {
        New-TestWorld -Running $true
        $r = Invoke-TestRun
        $r.Mode | Should -Be 'plan'; $r.Outcome | Should -Be 'plan'; $r.ExitCode | Should -Be 0
        $txt = $script:Said -join "`n"
        $txt | Should -Match 'running run    : run-8 -- trigger schedule, step identity, started 2026-11-04 08:00Z \(2 h 0 min ago\)'
        $txt | Should -Match 'executing      : caj-si-identity' -Because ($script:Said -join ' || ')
        $txt | Should -Match 'executing      : caj-si-flow caj-si-flow-runner \(2 h 0 min\)  \[the pipeline runner\]'
        $txt | Should -Match 'executing      : caj-si-identity caj-si-identity-s1 \(40 min\)'
        $txt | Should -Match 'executing      : caj-si-azure-worker caj-si-azure-worker-w1 \(30 min\)'
        $txt | Should -Not -Match 'heartbeat' -Because 'the heartbeat is never a step of a run'
        $txt | Should -Match 'installed      : 3\.0\.40'
        $txt | Should -Match 'ring serves    : 3\.0\.41 \(sequence 41, ring 2'
        $txt | Should -Match 'will           : 1\. cancel: start caj-si-flow once with SI_FLOW_CANCEL=1, SI_FLOW_CANCEL_RUN=run-8'
        $txt | Should -Match 'will           : 2\. wait up to 30 min'
        $txt | Should -Match 'will           : 3\. start caj-si-updater once'
        $txt | Should -Match 'limit          : 30 min'
        $txt | Should -Match 'PLAN ONLY -- nothing was started'
        @(Get-StartCalls).Count | Should -Be 0
        $script:W.Audit.Count | Should -Be 0
    }
    It 'no running run: says none, steps 1-2 will be skipped -- nothing started' {
        New-TestWorld -Running $false
        $r = Invoke-TestRun
        $txt = $script:Said -join "`n"
        $txt | Should -Match 'running run    : none -- the last run run-7 is succeeded'
        $txt | Should -Match 'executing      : nothing'
        $txt | Should -Match 'will           : 1-2\. skipped: no pipeline run is running'
        @(Get-StartCalls).Count | Should -Be 0
        $r.Outcome | Should -Be 'plan'
    }
    It 'the run record cannot be read here: what runs is read from Azure, and said' {
        New-TestWorld -Running $true
        $null = Invoke-TestRun -NoSql
        ($script:Said -join "`n") | Should -Match 'running run    : the run record is not read here \(the database does not answer from here \(test\)\) -- what runs is read from Azure: a run is going'
    }
    It '-RunId of another run than the running one: refused, nothing started' {
        New-TestWorld -Running $true
        $r = Invoke-TestRun -RunId 'run-5' -Apply
        $r.Outcome | Should -Be 'refused'; $r.ExitCode | Should -Be 1
        $r.Summary | Should -Match 'run run-5 is not the running run \(run-8 is\)'
        @(Get-StartCalls).Count | Should -Be 0
    }
}

Describe 'THE ORDER: the updater is never started before the stop is confirmed' {
    It 'the run''s executions stay Running for 3 polls after the cancel: the updater starts only once nothing of the run executes' {
        New-TestWorld -Running $true -CancelPolls 1 -StepPolls 3 -UpdPolls 2
        $r = Invoke-TestRun -Apply
        $starts = @(Get-StartCalls)
        $starts.Count | Should -Be 2
        $starts[0].Path | Should -Match '/jobs/caj-si-flow/start'
        $starts[1].Path | Should -Match '/jobs/caj-si-updater/start'
        @($script:W.AtUpdaterStart) | Should -BeNullOrEmpty -Because 'nothing of the run may execute when the updater starts'
        $script:W.CancelExec.properties.status | Should -Be 'Succeeded'
        $script:W.Run.State | Should -Be 'Cancelled'
        # it waited: at least the 4 polls the run needed to stop (1 for the cancel + 3 for the executions)
        ($starts[1].At - $starts[0].At).TotalSeconds | Should -BeGreaterOrEqual (4 * 30)
        ($script:Said -join "`n") | Should -Match '   waiting \(\d+ of 30 min\): cancel execution .*still executing: .*caj-si-identity caj-si-identity-s1'
        ($script:Said -join "`n") | Should -Match '2\. WAIT: confirmed stopped -- the cancel execution caj-si-flow-z\d+ ended Succeeded; run run-8 reads Cancelled; no job of the run executing \(read back\)'
        $r.Outcome | Should -Be 'updated'
    }
    It 'the cancel is the product''s: caj-si-flow once, its own environment kept, SI_FLOW_CANCEL=1 + the reason + who + the run' {
        New-TestWorld -Running $true
        $null = Invoke-TestRun -Apply
        $c = @(Get-StartCalls)[0]
        $env = Get-BodyEnv $c.Body
        $env['SI_FLOW_CANCEL'] | Should -Be '1'
        $env['SI_FLOW_CANCEL_REASON'] | Should -Be 'the run hangs on the old release'
        $env['SI_AUDIT_STARTED_BY'] | Should -Be 'support (test)'
        $env['SI_FLOW_CANCEL_RUN'] | Should -Be 'run-8'
        $env['SI_KEEP'] | Should -Be 'kept'; $env['SI_SECRET'] | Should -Be '@a-secret'
        $env['SI_ProSqlServer'] | Should -Be 'server.database.windows.net'
        ($script:Said -join "`n") | Should -Match '1\. CANCEL: caj-si-flow started once with SI_FLOW_CANCEL=1 for run run-8 -- execution caj-si-flow-z\d+ \(read back: Running\); audit: job\.flowrun\.cancel written'
    }
    It 'each step has its line, and both starts are on the audit trail' {
        New-TestWorld -Running $true
        $null = Invoke-TestRun -Apply
        foreach ($s in '== 0. PLAN', '1. CANCEL:', '2. WAIT:', '3. START:', '4. WAIT:', '5. SUMMARY:') { @($script:Said | Where-Object { $_.StartsWith($s) }).Count | Should -Be 1 -Because $s }
        @($script:W.Audit) | Should -Be @('job.flowrun.cancel', 'job.execution.start')
    }
    It 'the audit row cannot be written where the database does not answer: said, the run goes on' {
        New-TestWorld -Running $true
        $r = Invoke-TestRun -Apply -NoSql
        ($script:Said -join "`n") | Should -Match 'audit: not written from here \(the database does not answer from here \(test\)\) -- the cancel execution writes job\.flowrun\.stop itself'
        $r.Outcome | Should -Be 'updated'
        @($script:W.AtUpdaterStart) | Should -BeNullOrEmpty
    }
}

Describe 'the limit: not confirmed in time = stop, say what still runs, never the updater' {
    It 'executions that never stop: after -TimeoutMinutes the run stops here and the updater is NOT started' {
        New-TestWorld -Running $true -NeverStop
        $r = Invoke-TestRun -Apply -TimeoutMinutes 3
        $r.Outcome | Should -Be 'timeout'; $r.ExitCode | Should -Be 1
        @(Get-StartCalls | Where-Object { $_.Path -match 'caj-si-updater' }).Count | Should -Be 0
        $line = @($script:Said | Where-Object { $_ -like '2. WAIT:*' })[0]
        $line | Should -Match 'NOT confirmed stopped after 3 min -- still: '
        $line | Should -Match 'caj-si-identity caj-si-identity-s1'
        $line | Should -Match 'caj-si-azure-worker caj-si-azure-worker-w1'
        $line | Should -Match 'the updater was NOT started'
        $r.Summary | Should -Match 'the updater was not started'
        @($r.Started | ForEach-Object Job) | Should -Be @('caj-si-flow')
    }
}

Describe '-SkipUpdate, no run running, the version read back' {
    It '-SkipUpdate: stops and confirms, never starts the updater' {
        New-TestWorld -Running $true
        $r = Invoke-TestRun -Apply -SkipUpdate
        $r.Outcome | Should -Be 'stopped'; $r.ExitCode | Should -Be 0
        @(Get-StartCalls | Where-Object { $_.Path -match 'caj-si-updater' }).Count | Should -Be 0
        $r.Summary | Should -Match '^stopped run run-8 at step identity; update not started \(-SkipUpdate\); nothing else was started$'
    }
    It 'no run running: steps 1-2 skipped and said, straight to the update -- caj-si-flow is never started' {
        New-TestWorld -Running $false
        $r = Invoke-TestRun -Apply
        @(Get-StartCalls | Where-Object { $_.Path -match 'caj-si-flow' }).Count | Should -Be 0
        @(Get-StartCalls | Where-Object { $_.Path -match 'caj-si-updater' }).Count | Should -Be 1
        ($script:Said -join "`n") | Should -Match '1-2\. skipped: no pipeline run is running -- nothing was cancelled'
        $r.Outcome | Should -Be 'updated'
    }
    It '-RunId of a run that is not running: never touched, straight to the update' {
        New-TestWorld -Running $false
        $r = Invoke-TestRun -Apply -RunId 'run-7'
        @(Get-StartCalls | Where-Object { $_.Path -match 'caj-si-flow' }).Count | Should -Be 0
        ($script:Said -join "`n") | Should -Match '1-2\. skipped: no pipeline run is running \(run run-7 is not running\)'
        $r.Outcome | Should -Be 'updated'
    }
    It 'updated: "updated a -> b" read back from the updater job''s si-installed' {
        New-TestWorld -Running $true -UpdTo '3.0.41'
        $r = Invoke-TestRun -Apply
        $r.Outcome | Should -Be 'updated'; $r.ExitCode | Should -Be 0
        $r.Summary | Should -Match '^stopped run run-8 at step identity; updated 3\.0\.40 -> 3\.0\.41 \(read back: the updater job''s si-installed\); nothing else was started$'
        ($script:Said -join "`n") | Should -Match '3\. START: caj-si-updater started once \(update now\) -- execution caj-si-updater-z\d+ \(read back: Running\); audit: job\.execution\.start written'
    }
    It 'not updated: the updater''s own outcome (it stepped aside, its check) -- never "updated"' {
        New-TestWorld -Running $true -UpdSkips
        $r = Invoke-TestRun -Apply
        $r.Outcome | Should -Be 'not-updated'; $r.ExitCode | Should -Be 1
        $r.Summary | Should -Match 'not updated -- still 3\.0\.40: it stepped aside: a pipeline run is going \(run-9\)'
        $r.Summary | Should -Match 'its check of ring 2: waiting 3\.0\.41'
    }
    It 'the updater body is the update-now start: its own environment kept, SI_UPDATER_MODE = update-now' {
        New-TestWorld -Running $false
        $null = Invoke-TestRun -Apply
        $env = Get-BodyEnv (@(Get-StartCalls)[0].Body)
        $env['SI_UPDATER_MODE'] | Should -Be 'update-now'
        $env['SI_UPDATER_RING'] | Should -Be '2'; $env['SI_SECRET'] | Should -Be '@a-secret'
    }
}

Describe 'it never starts a pipeline step' {
    It 'in every case only caj-si-flow WITH SI_FLOW_CANCEL=1 and the updater are started' {
        $cases = @(@{ R = $true; S = $false }, @{ R = $true; S = $true }, @{ R = $false; S = $false })
        foreach ($c in $cases) {
            New-TestWorld -Running $c.R
            $null = Invoke-TestRun -Apply -SkipUpdate:$c.S
            foreach ($s in @(Get-StartCalls)) {
                $job = [regex]::Match($s.Path, '/jobs/([^/]+)/start').Groups[1].Value
                $job | Should -BeIn @('caj-si-flow', 'caj-si-updater')
                if ($job -eq 'caj-si-flow') { (Get-BodyEnv $s.Body)['SI_FLOW_CANCEL'] | Should -Be '1' -Because 'the runner is only ever started to cancel' }
                foreach ($k in 'SI_FLOW_FORCE', 'SI_FLOW_STAGE', 'SI_FLOW_STEP', 'SI_FLOW_FROM_STEP', 'SI_FLOW_DRAIN') { (Get-BodyEnv $s.Body).ContainsKey($k) | Should -BeFalse -Because "$k would start a run or a step" }
            }
            @($script:W.Calls | Where-Object { $_.Method -ne 'GET' -and $_.Path -notmatch '/start' }) | Should -BeNullOrEmpty -Because 'nothing else is written (no stop, no PATCH)'
        }
    }
    It 'STATIC: the engine file starts exactly two jobs, and never names a run / step start variable' {
        $src = [IO.File]::ReadAllText([IO.Path]::Combine($script:SIRoot, 'setup', '_shared', 'SI-StopRunAndUpdate.ps1'))
        ([regex]::Matches($src, "& \`$Arm 'POST'")).Count | Should -Be 2
        $src | Should -Not -Match 'SI_FLOW_(FORCE|STAGE|STEP|FROM_STEP|DRAIN)'
        $src | Should -Not -Match "'(PUT|PATCH|DELETE)'"
    }
}

Describe 'the one start-body builder (engine\_shared\SI-UpdaterStart.ps1)' {
    It 'New-SIJobStartTemplate keeps every variable (secret references too), replaces a same-named one, adds the rest last' {
        $j = New-TestJob 'caj-si-flow' @{ SI_FLOW_CANCEL = '0' }
        $b = New-SIJobStartTemplate -Job $j -Env ([ordered]@{ SI_FLOW_CANCEL = '1'; SI_FLOW_CANCEL_REASON = 'why' })
        @($b.containers[0].env | ForEach-Object name) | Should -Be @('SI_KEEP', 'SI_SECRET', 'SI_FLOW_CANCEL', 'SI_FLOW_CANCEL_REASON')
        @($b.containers[0].env | Where-Object name -eq 'SI_FLOW_CANCEL').Count | Should -Be 1
        $b.containers[0].env[1].secretRef | Should -Be 'a-secret'
        $b.containers[0].image | Should -Be 'acr.azurecr.io/si:1'
        $b.containers[0].resources.memory | Should -Be '2Gi'
    }
    It 'New-SIUpdateNowStartTemplate is unchanged: SI_UPDATER_MODE last, an earlier one replaced, the same JSON as before' {
        $j = New-TestJob 'caj-si-updater' @{ SI_UPDATER_MODE = 'old' }
        $b = New-SIUpdateNowStartTemplate -Job $j -Mode 'second-pass'
        ($b | ConvertTo-Json -Depth 10 -Compress) | Should -Be '{"containers":[{"name":"main","image":"acr.azurecr.io/si:1","env":[{"name":"SI_KEEP","value":"kept"},{"name":"SI_SECRET","secretRef":"a-secret"},{"name":"SI_UPDATER_MODE","value":"second-pass"}],"resources":{"cpu":1,"memory":"2Gi"}}]}'
        { New-SIUpdateNowStartTemplate -Job ([pscustomobject]@{ properties = [pscustomobject]@{ template = [pscustomobject]@{ containers = @() } } }) } | Should -Throw '*the updater job has no container to start*'
    }
}

Describe 'the database seams (no parameters on Invardia''s audited SQL path)' {
    It 'Get-SIStopRunDatabase reads the jobs'' SI_CFG_ names (live 2026-11-04) and the plain names' {
        $cfg = New-TestJob -Name 'caj-si-flow' -Env @{ SI_CFG_SI_ProSqlServer = 'server.database.windows.net'; SI_CFG_SI_ProSqlDatabase = 'sqldb-si-pro' }
        $d = Get-SIStopRunDatabase -Jobs @($cfg) -Flow $cfg
        $d.Server | Should -Be 'server.database.windows.net'
        $d.Database | Should -Be 'sqldb-si-pro'
        $plain = New-TestJob -Name 'caj-si-flow' -Env @{ SI_ProSqlServer = 'server'; SI_ProSqlDatabase = 'db-b' }
        $p = Get-SIStopRunDatabase -Jobs @($plain) -Flow $plain
        $p.Server | Should -Be 'server.database.windows.net'
        $p.Database | Should -Be 'db-b'
    }
    It 'STATIC: the script''s ARM and update-state seams call captured functions (a GetNewClosure block does not see the script''s functions)' {
        $src = Get-Content -LiteralPath ([IO.Path]::Combine($script:SIRoot, 'setup', 'Stop-SIRunAndUpdate.ps1')) -Raw
        $src | Should -Match '\$siArm = \$\{function:Invoke-SIArm\}'
        $src | Should -Match '\$siKvRead = \$\{function:Get-SIKeyVaultSecretValue\}'
        $src | Should -Not -Match '\{\s*Invoke-SIArm -Method'
    }
    It 'ConvertTo-SIStopRunInlineSql: text quoted, numbers, bit, time, NULL; a bad name refused' {
        $q = ConvertTo-SIStopRunInlineSql -Query 'SELECT @A, @B, @C, @D, @E;' -Params ([ordered]@{ A = "it's"; B = 42; C = $true; D = [datetime]::SpecifyKind([datetime]'2026-11-04T10:00:00', 'Utc'); E = $null })
        $q | Should -Match ([regex]::Escape("DECLARE @A nvarchar(max) = N'it''s';"))
        $q | Should -Match 'DECLARE @B bigint = 42;'
        $q | Should -Match 'DECLARE @C bit = 1;'
        $q | Should -Match "DECLARE @D datetime2\(7\) = '2026-11-04T10:00:00\.0000000';"
        $q | Should -Match 'DECLARE @E nvarchar\(max\) = NULL;'
        $q | Should -Match 'SELECT @A, @B, @C, @D, @E;$'
        { ConvertTo-SIStopRunInlineSql -Query 'x' -Params @{ 'a;drop' = 1 } } | Should -Throw
    }
    It 'New-SIStopRunSupportSql: reads go read-only with the reason, the run record loads through it' {
        $script:SupportCalls = New-Object System.Collections.Generic.List[object]
        $inv = { param($Server, $Database, $Query, $Reason, [bool]$ReadOnly)
            $script:SupportCalls.Add([pscustomobject]@{ Server = $Server; Query = $Query; ReadOnly = $ReadOnly; Reason = $Reason })
            if ($Query -match 'cfg\.FlowStepRun') { return [pscustomobject]@{ Rows = @() } }
            [pscustomobject]@{ Rows = @([pscustomobject]@{ FlowRunId = 'run-1'; Day = '2026-11-04'; Trg = 'manual'; FromStep = ''; State = 'Running'; StartedUtc = [datetime]'2026-11-04T09:00:00Z'; EndedUtc = $null; HeartbeatUtc = $null; StopReason = ''; SlotUtc = $null; LastSlotUtc = $null; Note = '' }) } }
        $sql = New-SIStopRunSupportSql -Server 'server.database.windows.net' -Database 'db' -Reason 'Stop-SIRunAndUpdate: test' -Invoke $inv
        $v = (Read-SIStopRunRun -Sql $sql).View
        $v.Id | Should -Be 'run-1'; $v.Running | Should -BeTrue; $v.Trigger | Should -Be 'manual'
        @($script:SupportCalls | Where-Object { -not $_.ReadOnly }) | Should -BeNullOrEmpty
        $script:SupportCalls[1].Query | Should -Match "DECLARE @FlowRunId nvarchar\(max\) = N'run-1';"
        $script:SupportCalls[0].Reason | Should -Be 'Stop-SIRunAndUpdate: test'
    }
}

Describe 'the script (setup\Stop-SIRunAndUpdate.ps1) with its seams' {
    It 'plan by default; -WhatIf beats -Apply; it reaches the engine with the reason and who' {
        New-TestWorld -Running $true
        $script:Said = New-Object System.Collections.Generic.List[string]
        # dot-sourced: the stubs read the fake install from THIS file's script scope (a script run gets its own)
        $p = [IO.Path]::Combine($script:SIRoot, 'setup', 'Stop-SIRunAndUpdate.ps1')
        $r = @(. $p -ResourceGroupName $script:Rg -SubscriptionId $script:Sub -Reason 'the run hangs on the old release' -Arm $script:Arm -Sql $script:Sql -ReadUpdateState $script:ReadState -Sleep $script:Sleep -Now $script:Now -By 'support (test)' -Apply -WhatIf 6>$null) | Where-Object { $_ -and $_.PSObject.Properties['Outcome'] } | Select-Object -Last 1
        $r.Mode | Should -Be 'plan'
        @(Get-StartCalls).Count | Should -Be 0
        $r2 = @(. $p -ResourceGroupName $script:Rg -SubscriptionId $script:Sub -Reason 'the run hangs on the old release' -Arm $script:Arm -Sql $script:Sql -ReadUpdateState $script:ReadState -Sleep $script:Sleep -Now $script:Now -By 'support (test)' -Apply 6>$null) | Where-Object { $_ -and $_.PSObject.Properties['Outcome'] } | Select-Object -Last 1
        $r2.Outcome | Should -Be 'updated'
        $r2.Summary | Should -Match 'updated 3\.0\.40 -> 3\.0\.41'
    }
}
