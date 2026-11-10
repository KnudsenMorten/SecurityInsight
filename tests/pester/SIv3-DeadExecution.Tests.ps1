#Requires -Version 5.1
<#
    SecurityInsight -- NO FRESH BEAT = DEAD (agreed with Invardia 2026-11-06). Live: an updater execution that never started
    its container held an install's daily run back for 6 hours; a hung flow execution held another install for 47 hours.

    What must hold (engine\_shared\SI-ExecutionLiveness.ps1 and its three callers):
      * an execution counts as running only while a lock row that names it was beaten less than 15 minutes ago; one that
        never beat counts for 30 minutes after its start; without readable lock rows the old rule holds;
      * a DEAD execution is stopped (ARM executions/<name>/stop), one plain WARNING line, the alert si.execution.stopped-dead
        to Invardia (its closed shape, exactly), and the waiting work goes on in the same wake-up; a failed stop holds the work
        back unless the execution started more than 6 hours ago;
      * updater: the pipeline's update check and the updater's own step-aside; flow: the container entry's execution guard;
        housekeeping: the clean-up pass beats a lock of its own (SQL row or storage document).
    Offline: every ARM / SQL / storage call is a seam.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\_shared\SI-ExecutionLiveness.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-JobFlow.ps1')
    . (Join-Path $script:SIRoot 'container\_shared\SI-ContainerConfig.ps1')
    $global:SIv3DeadUpdLines = New-Object System.Collections.Generic.List[string]
    $script:UpdLines = $global:SIv3DeadUpdLines
    function global:Write-UpdLog { param([string]$m) [void]$global:SIv3DeadUpdLines.Add($m) }
    . (Join-Path $script:SIRoot 'container\updater\_shared\SI-UpdaterRunGate.ps1')
    $script:Now = [datetime]::SpecifyKind([datetime]'2026-11-06T20:00:00', 'Utc')
    function script:Exec([string]$Name, [int]$StartedMinAgo, [string]$Status = 'Running') {
        [pscustomobject]@{ name = $Name; properties = [pscustomobject]@{ status = $Status; startTime = $script:Now.AddMinutes(-$StartedMinAgo).ToString('yyyy-MM-ddTHH:mm:ssZ') } }
    }
    function script:Lock([string]$LockName, [string]$Holder, [int]$BeatMinAgo) {
        [pscustomobject]@{ LockName = $LockName; Holder = $Holder; HeartbeatUtc = $script:Now.AddMinutes(-$BeatMinAgo) }
    }
    $script:Ctx = [pscustomobject]@{ Mode = 'identified'; Endpoint = 'https://invardia.example/api/uplink'; AccessCode = 'code'; Version = '3.0.57'; Ring = 1; Edition = 'pro'
                                     TenantId = '11111111-2222-3333-4444-555555555555'; LastingInstallId = ''; LicenceId = ''; EnvironmentName = 'install-a' }
}
AfterAll { Remove-Item -Path Function:\Write-UpdLog -ErrorAction SilentlyContinue; $global:SIv3DeadUpdLines = $null; $global:SI_UpdaterExecBeat = $null; $global:SI_UpdaterLockBeat = $null; $global:SI_ExecutionStopped = $null }

Describe 'the rule: 15 minutes after the last beat, 30 minutes when it never beat' {
    It 'the numbers are the agreed ones' {
        $c = Get-SIExecutionLivenessContract
        $c.BeatStaleMinutes | Should -Be 15; $c.NeverBeatGraceMinutes | Should -Be 30; $c.FallbackHours | Should -Be 6
        $c.AlertId | Should -Be 'si.execution.stopped-dead'
    }
    It 'a never-beaten execution started 20 minutes ago is NOT dead; started 45 minutes ago it is' {
        (Get-SIExecutionLiveness -Execution (Exec 'caj-si-updater-1' 20) -Kind updater -NowUtc $script:Now).Alive | Should -BeTrue
        $d = Get-SIExecutionLiveness -Execution (Exec 'caj-si-updater-1' 45) -Kind updater -NowUtc $script:Now
        $d.Alive | Should -BeFalse; $d.LastBeatUtc | Should -BeNullOrEmpty; $d.AgeMin | Should -Be 45
    }
    It 'one that beat, but not for more than 15 minutes, is dead -- even 10 minutes after its start' {
        $d = Get-SIExecutionLiveness -Execution (Exec 'caj-si-updater-2' 40) -Kind updater -Locks @(Lock 'updater' 'caj-si-updater:caj-si-updater-2' 16) -NowUtc $script:Now
        $d.Alive | Should -BeFalse; $d.MinutesSinceBeat | Should -Be 16; $d.LockName | Should -Be 'updater'
    }
    It 'a live long updater (fresh beat, running 3 hours) is NOT dead; the freshest of its beats counts' {
        $l = Get-SIExecutionLiveness -Execution (Exec 'caj-si-updater-3' 180) -Kind updater -Locks @((Lock 'updater' 'caj-si-updater:caj-si-updater-3' 40), (Lock 'install' 'caj-si-updater:caj-si-updater-3' 2)) -NowUtc $script:Now
        $l.Alive | Should -BeTrue; $l.LockName | Should -Be 'install'; $l.MinutesSinceBeat | Should -Be 2
    }
    It 'a lock held by ANOTHER execution is no beat of this one' {
        (Get-SIExecutionLiveness -Execution (Exec 'caj-si-flow-1' 60) -Locks @(Lock 'install' 'caj-si-flow-2' 1) -NowUtc $script:Now).Alive | Should -BeFalse
        Test-SIExecutionHolder -Holder 'caj-si-updater:caj-si-updater-9' -Name 'caj-si-updater-9' | Should -BeTrue
        Test-SIExecutionHolder -Holder 'caj-si-updater-99' -Name 'caj-si-updater-9' | Should -BeFalse
    }
    It 'lock rows that cannot be read keep the old rule: every running execution counts, nothing is dead' {
        $s = Select-SIExecutionLiveness -Executions @((Exec 'u-1' 300)) -Kind updater -LocksKnown $false -NowUtc $script:Now
        @($s.Live).Count | Should -Be 1; @($s.Dead).Count | Should -Be 0
    }
}

Describe '(a) the pipeline and the updater: a dead update no longer holds the daily run' {
    It 'a dead updater execution (no beat, started 4 h 31 min ago) does not count; it is STOPPED, said, raised -- and the queued run starts' {
        $ex = @((Exec 'caj-si-updater-29899710' 271), (Exec 'caj-si-updater-old' 600 'Succeeded'))
        $u = Get-SIPipelineUpdateLiveness -Executions $ex -Locks @() -LocksKnown $true -NowUtc $script:Now
        $u.Running | Should -Be '' -Because 'nothing beats for it: the drain goes on'
        @($u.Dead).Count | Should -Be 1
        $stops = New-Object System.Collections.Generic.List[string]; $lines = New-Object System.Collections.Generic.List[object]; $alerts = New-Object System.Collections.Generic.List[object]
        $mem = @{}
        $st = Invoke-SIExecutionDeadStop -Dead @($u.Dead) -OthersLive ([bool]$u.Running) -Stopped $mem -NowUtc $script:Now `
                  -Stop { param($n) $stops.Add((Get-SIExecutionStopPath -Base '/subscriptions/s/resourceGroups/r/providers/Microsoft.App/jobs' -Job 'caj-si-updater' -Execution $n)) } `
                  -Log { param($l, $m) $lines.Add([pscustomobject]@{ L = $l; M = $m }) } -Alert { param($ev) $alerts.Add($ev) }
        $stops[0] | Should -Be '/subscriptions/s/resourceGroups/r/providers/Microsoft.App/jobs/caj-si-updater/executions/caj-si-updater-29899710/stop?api-version=2024-03-01'
        @($st.Blocking).Count | Should -Be 0
        $lines[0].L | Should -Be 'WARN'
        $lines[0].M | Should -Match '^an update of SecurityInsight showed no sign of life and was stopped: caj-si-updater-29899710 \(started 2026-11-06 15:29Z\) never reported that it was working, 271 minutes after it started -- the waiting work goes on now$'
        $lines[0].M | Should -Not -Match '#\d+|lock|beat'
        $alerts[0].QueuedRunStarted | Should -BeTrue
        $mem.Contains('caj-si-updater-29899710') | Should -BeTrue
        # the same wake-up asks again: the stopped execution (still Running at Azure for a moment) neither counts nor is stopped twice
        $again = Get-SIPipelineUpdateLiveness -Executions $ex -Locks @() -LocksKnown $true -NowUtc $script:Now -Stopped $mem
        $again.Running | Should -Be ''; @($again.Dead).Count | Should -Be 0
    }
    It 'an updater that beat but not for more than 15 minutes is dead; a live long one (fresh beat, 3 h) still holds the run' {
        $u = Get-SIPipelineUpdateLiveness -Executions @((Exec 'u-stale' 50)) -Locks @(Lock 'install' 'caj-si-updater:u-stale' 20) -LocksKnown $true -NowUtc $script:Now
        $u.Running | Should -Be ''; @($u.Dead).Name | Should -Be 'u-stale'
        $l = Get-SIPipelineUpdateLiveness -Executions @((Exec 'u-live' 180)) -Locks @(Lock 'install' 'caj-si-updater:u-live' 3) -LocksKnown $true -NowUtc $script:Now
        $l.Running | Should -Match '^caj-si-updater execution u-live'; @($l.Dead).Count | Should -Be 0
    }
    It 'a never-beaten execution started 20 minutes ago still holds the run (the image may still be pulled)' {
        (Get-SIPipelineUpdateRunning -Executions @((Exec 'u-new' 20)) -Locks @() -LocksKnown $true -NowUtc $script:Now) | Should -Match 'u-new'
    }
    It 'a stop that fails holds the run back -- unless the execution is past the 6-hour fallback' {
        $mk = { param($age) Get-SIExecutionLiveness -Execution (Exec 'u-x' $age) -Kind updater -NowUtc $script:Now }
        $lines = New-Object System.Collections.Generic.List[string]
        $st = Invoke-SIExecutionDeadStop -Dead @((& $mk 60)) -Stop { throw 'HTTP 403 AuthorizationFailed' } -Log { param($l, $m) $lines.Add($m) } -NowUtc $script:Now
        @($st.Blocking).Count | Should -Be 1; @($st.Events).Count | Should -Be 0
        $lines[0] | Should -Match 'could not be stopped \(HTTP 403 AuthorizationFailed\).*nothing new starts beside it'
        $old = Invoke-SIExecutionDeadStop -Dead @((& $mk 400)) -Stop { throw 'HTTP 500' } -NowUtc $script:Now
        @($old.Blocking).Count | Should -Be 0
        # an execution that ended between the list and the stop is stopped, not a failure
        (Invoke-SIExecutionDeadStop -Dead @((& $mk 60)) -Stop { throw 'job execution caj-si-updater-x not found' } -NowUtc $script:Now).Stopped.Count | Should -Be 1
    }
    It 'the runner wires it: executions + lock rows, the stop through its ARM seam, the alert' {
        $c = ((Get-Content -LiteralPath (Join-Path $script:SIRoot 'engine\flow\Invoke-SIJobFlowRun.ps1')) | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
        $c | Should -Match '\$updLockStore = if \(\$proStore\) \{ New-SIExecutionLockStore -Invoke \$proStore\.Invoke \}'
        $c | Should -Match 'Get-SIPipelineUpdateLiveness -Executions @\(\$r\.value\) -Locks \$updLocks -LocksKnown \$updKnown'
        $c | Should -Match "& \`$armSeams\.Arm 'POST' \(Get-SIExecutionStopPath -Base \`$armSeams\.Base -Job \`$updaterJobName -Execution \`$n\)"
        $c | Should -Match 'Send-SIExecutionStoppedAlert -Event \$ev'
    }
}

Describe '(a) the updater''s own step-aside' {
    BeforeEach { $global:SI_ExecutionStopped = @{}; $script:UpdLines.Clear() }
    It 'an earlier update that is dead is stopped and this update goes on' {
        $ex = @((Exec 'caj-si-updater-1630' 90), (Exec 'caj-si-updater-1730' 1))
        $stops = New-Object System.Collections.Generic.List[string]; $alerts = New-Object System.Collections.Generic.List[object]
        $e = Get-SIUpdaterEarlierLiveness -Executions $ex -Self 'caj-si-updater-1730' -NowUtc $script:Now -Locks @(Lock 'install' 'caj-si-updater:caj-si-updater-1630' 25) -LocksKnown $true `
                 -Stop { param($n) $stops.Add($n) } -Alert { param($ev) $alerts.Add($ev) }
        $e | Should -BeNullOrEmpty
        @($stops) | Should -Be @('caj-si-updater-1630')
        $alerts[0].Kind | Should -Be 'updater'; $alerts[0].LockName | Should -Be 'install'; $alerts[0].MinutesSinceBeat | Should -Be 25
        ($script:UpdLines -join "`n") | Should -Match 'WARNING: an update of SecurityInsight showed no sign of life and was stopped'
    }
    It 'a live earlier update (fresh beat on its own row) is stepped aside for, as before; nothing is stopped' {
        $ex = @((Exec 'caj-si-updater-1630' 90), (Exec 'caj-si-updater-1730' 1))
        $stops = New-Object System.Collections.Generic.List[string]
        $e = Get-SIUpdaterEarlierLiveness -Executions $ex -Self 'caj-si-updater-1730' -NowUtc $script:Now -Locks @(Lock 'updater' 'caj-si-updater:caj-si-updater-1630' 1) -LocksKnown $true -Stop { param($n) $stops.Add($n) }
        $e.Name | Should -Be 'caj-si-updater-1630'; $stops.Count | Should -Be 0
    }
    It 'a dead earlier update that cannot be stopped is still stepped aside for (never two updates at once)' {
        $ex = @((Exec 'caj-si-updater-1630' 90), (Exec 'caj-si-updater-1730' 1))
        (Get-SIUpdaterEarlierLiveness -Executions $ex -Self 'caj-si-updater-1730' -NowUtc $script:Now -Locks @() -LocksKnown $true -Stop { throw 'HTTP 403' } -Alert { }).Name | Should -Be 'caj-si-updater-1630'
    }
    It 'without lock rows the old rule decides (Select-SIUpdaterEarlierRunning)' {
        $ex = @((Exec 'caj-si-updater-1630' 90), (Exec 'caj-si-updater-1730' 1))
        (Get-SIUpdaterEarlierLiveness -Executions $ex -Self 'caj-si-updater-1730' -NowUtc $script:Now -Locks @() -LocksKnown $false -Stop { throw 'never' }).Name | Should -Be 'caj-si-updater-1630'
    }
    It '(d) the update beats its own row from its first moment -- with every log line, without the install lock' {
        $beats = New-Object System.Collections.Generic.List[string]
        $global:SI_UpdaterLockBeat = $null
        Register-SIUpdaterExecutionBeat -Holder 'caj-si-updater:caj-si-updater-1730' -Beat { param($h, $w) $beats.Add("$h|$w"); $true } | Should -BeTrue
        $t0 = [datetime]::UtcNow.AddMinutes(5)
        Invoke-SIUpdaterLockBeat -What 'claim' -NowUtc $t0 | Should -BeFalse -Because 'the install lock is not held (the answer is about that lock)'
        Invoke-SIUpdaterLockBeat -What 'claim' -NowUtc $t0.AddSeconds(10) | Out-Null
        Invoke-SIUpdaterLockBeat -What 'manifest' -NowUtc $t0.AddSeconds(70) | Out-Null
        @($beats) | Should -Be @('caj-si-updater:caj-si-updater-1730|start', 'caj-si-updater:caj-si-updater-1730|claim', 'caj-si-updater:caj-si-updater-1730|manifest')
        Unregister-SIUpdaterExecutionBeat
        $global:SI_UpdaterExecBeat | Should -BeNullOrEmpty
    }
    It 'the updater wires it: the database opened before the overlap check, the stop through its ARM seam, its own beat after it' {
        $c = ((Get-Content -LiteralPath (Join-Path $script:SIRoot 'container\updater\Start-SIUpdater.ps1')) | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
        $c.IndexOf('$proStore = New-SIUpdaterProStore -Server $proSql') | Should -BeLessThan $c.IndexOf('Get-SIUpdaterEarlierLiveness -Executions $execs')
        $c | Should -Match 'Get-SIUpdaterEarlierLiveness -Executions \$execs .{0,200}-Store \$proStore'
        $c | Should -Match 'Invoke-SIUpdaterArm -Method POST -Path \(Get-SIExecutionStopPath'
        $c.IndexOf('Register-SIUpdaterExecutionBeat -Store (New-SIUpdaterProStore') | Should -BeGreaterThan $c.IndexOf('Get-SIUpdaterStepAsideText -Earlier $earlier')
        $c.IndexOf('Register-SIUpdaterExecutionBeat -Store') | Should -BeLessThan $c.IndexOf('Invoke-SIUpdaterSecretHandover -Rest')
        $c | Should -Match '-SubscriptionId \$sub -FreshToken'
        $c | Should -Match 'Unregister-SIUpdaterExecutionBeat \}\s+exit \$rc'
    }
}

Describe '(b) (c) the flow job''s execution guard' {
    It 'a dead flow runner (its install-lock beat 20 minutes old) is dead; nothing holds the wake-up back' {
        $ex = @((Exec 'caj-si-flow-old' 2820), (Exec 'caj-si-flow-me' 0))
        $g = Select-SIFlowGuardOther -Executions $ex -Self 'caj-si-flow-me' -Locks @(Lock 'install' 'caj-si-flow-old' 20) -LocksKnown $true -NowUtc $script:Now
        $g.Other | Should -BeNullOrEmpty
        @($g.Dead).Name | Should -Be 'caj-si-flow-old'; @($g.Dead)[0].Kind | Should -Be 'flow'
    }
    It 'a live flow runner holding the pipeline lock with a fresh beat is NOT stopped: FlowBusy, as before' {
        $ex = @((Exec 'caj-si-flow-run' 300), (Exec 'caj-si-flow-me' 0))
        $g = Select-SIFlowGuardOther -Executions $ex -Self 'caj-si-flow-me' -Locks @(Lock 'install' 'caj-si-flow-run' 1) -LocksKnown $true -NowUtc $script:Now
        $g.Other.name | Should -Be 'caj-si-flow-run'; @($g.Dead).Count | Should -Be 0
        (Get-SIExecutionGuardDecision -Engine 'flow' -Job 'caj-si-flow' -Other $g.Other -Self 'caj-si-flow-me').Action | Should -Be 'FlowBusy'
    }
    It 'a hung housekeeping pass (its own lock stale) is dead, kind housekeeping; a live one never holds a wake-up back' {
        $ex = @((Exec 'caj-si-flow-hk' 40), (Exec 'caj-si-flow-me' 0))
        $g = Select-SIFlowGuardOther -Executions $ex -Self 'caj-si-flow-me' -Locks @(Lock 'housekeeping' 'caj-si-flow-hk' 17) -LocksKnown $true -NowUtc $script:Now
        @($g.Dead)[0].Kind | Should -Be 'housekeeping'; $g.Other | Should -BeNullOrEmpty
        $l = Select-SIFlowGuardOther -Executions $ex -Self 'caj-si-flow-me' -Locks @(Lock 'housekeeping' 'caj-si-flow-hk' 1) -LocksKnown $true -NowUtc $script:Now
        $l.Other | Should -BeNullOrEmpty; @($l.Live).Count | Should -Be 1
    }
    It 'without lock rows every earlier running execution holds it back (the old rule)' {
        $ex = @((Exec 'caj-si-flow-old' 2820), (Exec 'caj-si-flow-me' 0))
        (Select-SIFlowGuardOther -Executions $ex -Self 'caj-si-flow-me' -LocksKnown $false -NowUtc $script:Now).Other.name | Should -Be 'caj-si-flow-old'
    }
    It 'the entry''s guard, run as it is: a dead flow execution is stopped and the wake-up goes on (not FlowBusy); a live runner makes it a clean-up pass that takes its own lock' {
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\Start-SIInContainer.ps1'))
        $a = $src.IndexOf('$guardJob = [Environment]::GetEnvironmentVariable(''CONTAINER_APP_JOB_NAME'')'); $b = $src.IndexOf('# #211 (2)')
        $block = $src.Substring($a, $b - $a) -replace '\bexit 0\b', 'return ''exited-0'''
        $names = 'CONTAINER_APP_JOB_NAME', 'CONTAINER_APP_JOB_EXECUTION_NAME', 'SI_JOBS_SUBSCRIPTIONID', 'SI_JOBS_RESOURCEGROUP', 'SI_TRIGGER_FROM_QUEUE', 'SI_COLLECT_PHASE', 'SI_FLOW_FORCE', 'SI_FLOW_STAGE', 'SI_FLOW_STEP', 'SI_FLOW_FROM_STEP', 'SI_FLOW_CANCEL', 'SI_FLOW_HOUSEKEEPING_ONLY'
        $saved = @{}; foreach ($n in $names) { $saved[$n] = [Environment]::GetEnvironmentVariable($n) }
        $savedSql = $global:SI_ProSqlServer; $savedDb = $global:SI_ProSqlDatabase; $savedSa = $global:SI_StorageAccount
        try {
            foreach ($n in $names) { [Environment]::SetEnvironmentVariable($n, $null) }
            [Environment]::SetEnvironmentVariable('CONTAINER_APP_JOB_NAME', 'caj-si-flow'); [Environment]::SetEnvironmentVariable('CONTAINER_APP_JOB_EXECUTION_NAME', 'caj-si-flow-me')
            [Environment]::SetEnvironmentVariable('SI_JOBS_SUBSCRIPTIONID', 'sub'); [Environment]::SetEnvironmentVariable('SI_JOBS_RESOURCEGROUP', 'rg')
            # SI_ProSqlServer is set but no Pro database seam opens (the start request + collection gate read it too): keep those
            # parts quiet -- the guard's lock rows come from the stubbed Get-SIGuardProInvoke
            $global:SI_ProSqlServer = 'sql.example'; $global:SI_ProSqlDatabase = 'sidb'; $global:SI_StorageAccount = $null
            $engine = 'flow'
            $arm = New-Object System.Collections.Generic.List[string]; $sql = New-Object System.Collections.Generic.List[string]; $alerts = New-Object System.Collections.Generic.List[object]
            $exs = @((Exec 'caj-si-flow-old' 2820), (Exec 'caj-si-flow-me' 0)); $lockRows = @(@{ LockId = 'install'; Holder = 'caj-si-flow-old'; HeartbeatUtc = [datetime]::UtcNow.AddMinutes(-20) })
            function Get-OptionalEnv { param([string]$Name, $Default = $null) $v = [Environment]::GetEnvironmentVariable($Name); if ([string]::IsNullOrWhiteSpace($v)) { $Default } else { $v } }
            function Invoke-SIArm { param([string]$Method = 'GET', [string]$Path, [string]$ApiVersion, $Body, [switch]$List, [switch]$AllowNotFound) $arm.Add(('{0} {1}' -f $Method, $Path)); if ($List) { return $exs }; $null }
            function Get-SIGuardProInvoke { { param($q, $p, $m) $sql.Add($q); if ($q -match 'SELECT LockId, Holder, HeartbeatUtc') { return , @($lockRows) }; if ($q -match 'AS Mine') { return , @(@{ Mine = 1 }) }; $null } }
            function Send-SIExecutionStoppedAlert { param($Event, $Context, $Transport, $Log) $alerts.Add($Event) }
            function Send-SIRunHealthRow { param() }
            function Send-SIGuardEvent { param() }
            function Invoke-SIJobStartRequestIsolated { param() @{ Claimed = $false } }
            $out = @(. ([scriptblock]::Create($block)) 3>&1 6>&1)
            $text = ($out | ForEach-Object { "$_" }) -join "`n"
            $out -contains 'exited-0' | Should -BeFalse
            [Environment]::GetEnvironmentVariable('SI_FLOW_HOUSEKEEPING_ONLY') | Should -BeNullOrEmpty -Because 'the dead runner was stopped: this wake-up runs the queue'
            @($arm | Where-Object { $_ -like 'POST *' }) | Should -Be @('POST /subscriptions/sub/resourceGroups/rg/providers/Microsoft.App/jobs/caj-si-flow/executions/caj-si-flow-old/stop?api-version=2024-03-01')
            $text | Should -Match '\[flow\] a pipeline runner showed no sign of life and was stopped: caj-si-flow-old .* -- the waiting work goes on now'
            $alerts.Count | Should -Be 1; $alerts[0].Kind | Should -Be 'flow'; $alerts[0].QueuedRunStarted | Should -BeTrue
            # a LIVE runner: FlowBusy, a clean-up pass, which takes the housekeeping lock as its first act
            $lockRows = @(@{ LockId = 'install'; Holder = 'caj-si-flow-old'; HeartbeatUtc = [datetime]::UtcNow.AddMinutes(-1) }); $arm.Clear(); $sql.Clear(); $global:SI_ExecutionStopped = @{}
            $out2 = @(. ([scriptblock]::Create($block)) 3>&1 6>&1)
            $out2 -contains 'exited-0' | Should -BeFalse
            [Environment]::GetEnvironmentVariable('SI_FLOW_HOUSEKEEPING_ONLY') | Should -Be '1'
            @($arm | Where-Object { $_ -like 'POST *' }).Count | Should -Be 0
            @($sql | Where-Object { $_ -match 'AS Mine' }).Count | Should -Be 1 -Because 'the clean-up takes its own lock'
        } finally {
            foreach ($n in $names) { [Environment]::SetEnvironmentVariable($n, $saved[$n]) }
            $global:SI_ProSqlServer = $savedSql; $global:SI_ProSqlDatabase = $savedDb; $global:SI_StorageAccount = $savedSa; $global:SI_ExecutionStopped = $null
        }
    }
    It 'the runner beats the clean-up''s own lock and releases it at the end' {
        $c = ((Get-Content -LiteralPath (Join-Path $script:SIRoot 'engine\flow\Invoke-SIJobFlowRun.ps1')) | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
        # live 2026-11-09/10: one beat for every wake-up -- the clean-up's row during a run, the wake-up's own row otherwise
        $c | Should -Match "\`$wkLock = if \(\`$housekeepingOnly\) \{ 'housekeeping' \} else \{ 'wakeup' \}"
        $c | Should -Match "& \`$wkBeatFn -Store \`$wkState\.Store -Lock \`$wkLock -Holder \`$wkHolder -What \`$wkWhat"
        $c | Should -Match "(?s)if \(\`$housekeepingOnly\) \{\s+\`$null = Invoke-SIPipelineUpkeep -Beat \`$wkBeat -Cleanup \`$upkeepCleanup -Log \`$say\s+& \`$wkRelease"
        $c | Should -Match "Exit-SIExecutionLock -Store \`$wkState\.Store -Lock \`$wkLock -Holder \`$wkHolder"
    }
}

Describe 'the clean-up''s own lock: a row (Pro) or a document (Community)' {
    It 'SQL: taken, beaten, released by its holder; the install lock is never taken through it' {
        $calls = New-Object System.Collections.Generic.List[object]
        $inv = { param($q, $p, $m) $calls.Add([pscustomobject]@{ Q = $q; P = $p }); if ($q -match 'AS Mine') { return , @(@{ Mine = 1 }) }; if ($q -match 'AS Held') { return , @(@{ Held = 1 }) }; $null }
        $s = New-SIExecutionLockStore -Invoke $inv
        Enter-SIExecutionLock -Store $s -Lock 'housekeeping' -Holder 'caj-si-flow-hk' | Should -BeTrue
        $calls[0].P.LockId | Should -Be 'housekeeping'; $calls[0].P.StaleMinutes | Should -Be 15
        Update-SIExecutionLockBeat -Store $s -Lock 'housekeeping' -Holder 'caj-si-flow-hk' | Should -BeTrue
        Exit-SIExecutionLock -Store $s -Lock 'housekeeping' -Holder 'caj-si-flow-hk'
        $calls[2].Q | Should -Match 'SET Holder = NULL'
        Enter-SIExecutionLock -Store $s -Lock 'install' -Holder 'x' | Should -BeFalse
        Get-SIExecutionLockSql 'Take' | Should -Match "@LockId = N'install'"
    }
    It 'SQL: no lock table = not known (the old rule)' {
        $r = Read-SIExecutionLocks -Store (New-SIExecutionLockStore -Invoke { param($q, $p, $m) , @(@{ LockId = '-'; Holder = $null; HeartbeatUtc = $null }) })
        $r.Known | Should -BeFalse
    }
    It 'documents: the same rule over the install''s storage (free, stale, own), read back with the install lock' {
        $store = @{}
        $docs = [pscustomobject]@{ S = $store }
        $docs | Add-Member -MemberType ScriptMethod -Name Read -Value { param($n) $this.S[$n] }
        $docs | Add-Member -MemberType ScriptMethod -Name Write -Value { param($n, $t) $this.S[$n] = $t }
        $docs | Add-Member -MemberType ScriptMethod -Name Delete -Value { param($n) $this.S.Remove($n) }
        $script:DocNow = $script:Now
        $s = New-SIExecutionLockStore -Docs $docs -Now { $script:DocNow }
        Enter-SIExecutionLock -Store $s -Lock 'housekeeping' -Holder 'hk-1' | Should -BeTrue
        Enter-SIExecutionLock -Store $s -Lock 'housekeeping' -Holder 'hk-2' | Should -BeFalse -Because 'held by a live clean-up'
        $store['pipeline.lock'] = '{"Holder":"caj-si-flow-run","What":"run","FlowRunId":"r1","HeartbeatUtc":"2026-11-06T19:58:00Z"}'
        $rows = (Read-SIExecutionLocks -Store $s).Rows
        @($rows | ForEach-Object { '{0}={1}' -f $_.LockName, $_.Holder }) -join ',' | Should -Be 'install=caj-si-flow-run,housekeeping=hk-1'
        $script:DocNow = $script:Now.AddMinutes(16)
        Enter-SIExecutionLock -Store $s -Lock 'housekeeping' -Holder 'hk-2' | Should -BeTrue -Because 'a lock 16 minutes old is free'
        Exit-SIExecutionLock -Store $s -Lock 'housekeeping' -Holder 'hk-2'
        $store.ContainsKey('housekeeping.lock') | Should -BeFalse
    }
}

Describe '(f) the uplink alert si.execution.stopped-dead -- Invardia''s closed shape, exactly' {
    It 'carries exactly the agreed fields; minutesSinceBeat only when it beat; whole numbers; the stop time' {
        $dead = Get-SIExecutionLiveness -Execution (Exec 'caj-si-updater-29899710' 271) -Kind updater -NowUtc $script:Now
        $ev = New-SIExecutionStoppedEvent -Dead $dead -StoppedUtc $script:Now -QueuedRunStarted $true
        $ev.Id | Should -Be 'si.execution.stopped-dead'; $ev.Execution | Should -Be 'caj-si-updater-29899710'; $ev.Kind | Should -Be 'updater'
        $ev.AgeMin | Should -Be 271; $ev.LastBeatUtc | Should -BeNullOrEmpty; $ev.LockName | Should -Be ''; $ev.StoppedUtc | Should -Be $script:Now; $ev.QueuedRunStarted | Should -BeTrue
        $r = ConvertTo-SIExecutionStoppedAlert -Event $ev -Context $script:Ctx
        @($r.PSObject.Properties.Name) | Should -Be @('Schema', 'Kind', 'Product', 'Version', 'Ring', 'Edition', 'ClaimedTenantId', 'EnvironmentName', 'AlertId', 'Severity', 'Measured', 'FirstSeenUtc', 'Count', 'Area', 'Job', 'ActionText')
        $allowed = 'Schema', 'Kind', 'Product', 'InstallId', 'LicenceId', 'Version', 'Ring', 'ClaimedTenantId', 'Edition', 'LastSeenUtc', 'EnvironmentName', 'AlertId', 'Severity', 'Measured', 'FirstSeenUtc', 'Count', 'Area', 'Job', 'ActionText', 'Link'
        foreach ($n in $r.PSObject.Properties.Name) { $allowed | Should -Contain $n }
        $r.Kind | Should -Be 'alert'; $r.Product | Should -Be 'securityinsight'; $r.AlertId | Should -Be 'si.execution.stopped-dead'
        $r.Severity | Should -Be 'warning'; $r.Area | Should -Be 'execution'; $r.Job | Should -Be 'updater'; $r.Count | Should -Be 1
        $r.FirstSeenUtc | Should -Be '2026-11-06T20:00:00Z'
        @($r.Measured.PSObject.Properties.Name) | Should -Be @('ageMin', 'queuedRunStarted') -Because 'it never beat: minutesSinceBeat is left out entirely'
        $r.Measured.ageMin | Should -BeOfType [int]; $r.Measured.queuedRunStarted | Should -Be 1
        $r.ActionText | Should -Match 'caj-si-updater-29899710'; $r.ActionText | Should -Match 'never beat a lock'; $r.ActionText.Length | Should -BeLessOrEqual 500
        $r.ActionText | Should -Not -Match '[\x00-\x1F]'
        # one that beat: minutesSinceBeat, the lock in plain words; queuedRunStarted 0
        $d2 = Get-SIExecutionLiveness -Execution (Exec 'caj-si-flow-old' 2820) -Locks @(Lock 'housekeeping' 'caj-si-flow-old' 17) -NowUtc $script:Now
        $r2 = ConvertTo-SIExecutionStoppedAlert -Event (New-SIExecutionStoppedEvent -Dead $d2 -StoppedUtc $script:Now -QueuedRunStarted $false) -Context $script:Ctx
        @($r2.Measured.PSObject.Properties.Name) | Should -Be @('ageMin', 'minutesSinceBeat', 'queuedRunStarted')
        $r2.Measured.minutesSinceBeat | Should -Be 17; $r2.Measured.queuedRunStarted | Should -Be 0; $r2.Job | Should -Be 'housekeeping'
        $r2.ActionText | Should -Match 'caj-si-flow-old.*clean-up''s own lock'
        ($r2 | ConvertTo-Json -Depth 5 -Compress) | Should -Match '"Measured":\{"ageMin":2820,"minutesSinceBeat":17,"queuedRunStarted":0\}'
    }
    It 'identified only: an anonymous install sends nothing; the transport gets the record' {
        $dead = Get-SIExecutionLiveness -Execution (Exec 'caj-si-flow-old' 60) -NowUtc $script:Now
        $ev = New-SIExecutionStoppedEvent -Dead $dead -StoppedUtc $script:Now -QueuedRunStarted $true
        ConvertTo-SIExecutionStoppedAlert -Event $ev -Context ([pscustomobject]@{ Mode = 'anonymous' }) | Should -BeNullOrEmpty
        (Send-SIExecutionStoppedAlert -Event $ev -Context ([pscustomobject]@{ Mode = 'anonymous' }) -Transport { throw 'never' }).State | Should -Be 'anonymous'
        $sent = New-Object System.Collections.Generic.List[object]
        $s = Send-SIExecutionStoppedAlert -Event $ev -Context $script:Ctx -Transport { param($Record, $Endpoint, $AccessCode, $TimeoutSec) $sent.Add(@($Record, $Endpoint)); [pscustomobject]@{ Status = 'ok' } }
        $s.State | Should -Be 'sent'; $sent[0][0].AlertId | Should -Be 'si.execution.stopped-dead'; $sent[0][1] | Should -Be 'https://invardia.example/api/uplink'
        (Send-SIExecutionStoppedAlert -Event $ev).State | Should -BeIn @('test-session', 'off') -Because 'a test session never sends'
    }
}
