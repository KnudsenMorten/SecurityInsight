#Requires -Version 5.1
<#
    THE HEARTBEAT'S Pipeline.state FOLLOWS THE RUN RECORD (live 2026-11-13, a large install: run a5860865 closed Succeeded at
    05:44:33Z with every step Success / Disabled; an update took the install right after and refreshed the published copies
    under the refresher's lock -- and the heartbeat at 06:38Z still said "running, step 12/12, run age 34.6 h, queued 1").

    The cause was in engine\_shared\SI-HeartbeatFields.ps1 Get-SIHeartbeatPipeline: since 2026-10-24 a run that had ended
    read 'running' while the published copies were written (the refresher's lock tested, Stale, published at or after the
    run's start) -- whoever wrote them, so also the update's own catch-up of the copies (Invoke-SIContainerUpdate 9j).

    What these tests keep true:
      * a run whose record is Succeeded / Failed / Stopped / Cancelled is never 'running' -- also while an update holds the
        install and writes the copies; its step / stepSinceUtc are empty, lastEndedUtc its own end, the counts its own;
      * the update holding the install is said by the field the contract already has: Jobs, the updater's newest execution,
        lastResult 'running' (no new key, no new value: Invardia's wire contract is closed);
      * a live run reads 'running' with its running step; no run reads 'idle'; nothing at all = no field;
      * queuedRuns is the waiting pipeline requests, the same in every case.
    Offline only.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\_shared\SI-HeartbeatJob.ps1')
    if (-not (Get-Command -Name Test-SIHeartbeatField -ErrorAction SilentlyContinue)) { . (Join-Path $script:SIRoot 'engine\_shared\SI-HeartbeatFields.ps1') }
    function script:U([string]$s) { [datetime]::SpecifyKind([datetime]::Parse($s, [Globalization.CultureInfo]::InvariantCulture), [DateTimeKind]::Utc) }
    $script:Now = U '2026-11-13T06:38:00'
    $script:Start = U '2026-11-11T20:02:00'
    $script:End = U '2026-11-13T05:44:33'
    $script:Def = ConvertTo-SIJobFlowJson -Definition (New-SIDefaultJobFlow -Installed @('identity', 'endpoint', 'risk-analysis-detailed'))
    $script:Jobs = @('privilege-tier-classifier', 'identity', 'endpoint', 'azure', 'publicip', 'asset-correlation', 'correlation',
                     'risk-analysis-summary', 'risk-analysis-detailed', 'data-sync', 'close-loop', 'close-loop-mail')
    function script:Row([string]$K, [string]$Name, [string]$S = $null, $T1 = $null, $T2 = $null, $N1 = $null, $N2 = $null, $Txt = $null) {
        [pscustomobject]@{ K = $K; Name = $Name; S = $S; T1 = $T1; T2 = $T2; T3 = $T2; T4 = $T1; N1 = $N1; N2 = $N2; Txt = $Txt; Txt2 = $null }
    }
    # the run record of the fault: 12 steps that ran to their end (Success), one switched off (Disabled); -Live = the same run
    # still going, the 9th step running and the rest waiting
    function script:Cfg([string]$State = 'Succeeded', [switch]$Live, $Queued = 1) {
        $rid = 'a5860865'
        $rows = New-Object System.Collections.Generic.List[object]
        $rows.Add((Row 'run' $rid $State $script:Start $(if ($Live) { $null } else { $script:End })))
        $rows.Add((Row 'run' 'r-prev' 'Succeeded' $script:Start.AddDays(-1) $script:Start.AddDays(-1).AddHours(30)))
        $o = 0
        foreach ($j in $script:Jobs) {
            $o++
            $st = $script:Start.AddHours($o); $en = $st.AddMinutes(50)
            $s = 'Success'
            if ($Live -and $o -eq 9) { $s = 'Running'; $en = $null } elseif ($Live -and $o -gt 9) { $s = 'Waiting'; $st = $null; $en = $null }
            $rows.Add((Row 'step' ('caj-si-' + $j) $s $st $en $o $o $rid))
            $rows.Add((Row 'step' ('caj-si-' + $j) 'Success' $script:Start.AddDays(-1).AddHours($o) $script:Start.AddDays(-1).AddHours($o).AddMinutes(45) $o $o 'r-prev'))
        }
        $rows.Add((Row 'step' 'caj-si-asset-tagging' 'Disabled' $null $null 13 13 $rid))
        $rows.Add((Row 'def' 'flow' -Txt $script:Def))
        if ($null -ne $Queued) { $rows.Add((Row 'queue' 'Queued' -N1 $Queued)) }
        , $rows.ToArray()
    }
    # the published copies as the update leaves them while it refreshes them: the refresher's lock held, older than the
    # publish, which is this run's own (at its end)
    $copyRow = [pscustomobject]@{ PublishedAt = $script:End; CopiedAt = $script:Start.AddDays(-1); Stale = $true; Refreshing = $true; RefreshMs = [long](20 * 60000) }
    $script:Data = { param($s, $p, $m) if ($s -match 'si-published-copy-refresh') { return , @($copyRow) }; throw 'not this read' }.GetNewClosure()
    $script:Sw = @{ Pipeline = $true; PipelineEta = $true; Jobs = $false; Sources = $false; Database = $false; Update = $false; Mail = $false; Warnings = $true; Security = $false; Published = $false; DataOut = $false; BuildPool = $false; UplinkBacklog = $false }
    function script:Beat($Rows) { (New-SIHeartbeatFields -Ring 1 -NowUtc $script:Now -Switch $script:Sw -CfgRows $Rows -DataInvoke $script:Data -Log { param($l) })['Pipeline'] }
}

Describe 'a closed run while an update holds the install (the fault of 2026-11-13)' {
    It 'Succeeded with an update writing the copies: succeeded -- never running; its own end, no step, 12 of 12, queued 1' {
        $p = Beat (Cfg)
        $p.state | Should -Be 'succeeded' -Because 'the run record says Succeeded; the update holding the install is not the run'
        $p.runId | Should -Be 'a5860865'
        $p.startedUtc | Should -Be '2026-11-11T20:02:00Z'
        $p.lastEndedUtc | Should -Be '2026-11-13T05:44:33Z'
        $p.step | Should -BeNullOrEmpty
        $p.stepSinceUtc | Should -BeNullOrEmpty
        $p.stepsDone | Should -Be 12
        $p.stepsTotal | Should -Be 12
        @($p.runningSteps).Count | Should -Be 0
        @($p.remainingSteps).Count | Should -Be 0
        $p.estimatedEndUtc | Should -BeNullOrEmpty
        $p.queuedRuns | Should -Be 1
        Test-SIHeartbeatField -Name 'Pipeline' -Value $p | Should -BeNullOrEmpty
    }
    It 'the seven agreed keys alone (no estimate) say the same' {
        $p = Get-SIHeartbeatPipeline -Rows (Cfg) -NowUtc $script:Now
        $p.state | Should -Be 'succeeded'
        @($p.PSObject.Properties.Name) | Should -Be @((Get-SIHeartbeatFieldsContract).Fields.Pipeline)
    }
    It 'Failed / Stopped / Cancelled with the copies written: their own state, never running' {
        (Beat (Cfg -State 'Failed')).state | Should -Be 'failed'
        (Beat (Cfg -State 'Stopped')).state | Should -Be 'idle' -Because "'stopped' is behind its own switch (not yet agreed): idle"
        (Beat (Cfg -State 'Cancelled')).state | Should -Be 'idle'
    }
    It 'the copies being written leave the state exactly as without them' {
        $without = New-SIHeartbeatFields -Ring 1 -NowUtc $script:Now -Switch $script:Sw -CfgRows (Cfg) -Log { param($l) }
        ((Beat (Cfg)) | ConvertTo-Json -Compress -Depth 5) | Should -Be ($without['Pipeline'] | ConvertTo-Json -Compress -Depth 5)
    }
    It 'the update is said by the field that already exists: Jobs, the updater''s newest execution, running' {
        $ex = @{ updater = @([pscustomobject]@{ properties = [pscustomobject]@{ startTime = '2026-11-13T05:46:10Z'; status = 'Running' } },
                             [pscustomobject]@{ properties = [pscustomobject]@{ startTime = '2026-11-12T05:30:00Z'; endTime = '2026-11-12T05:41:00Z'; status = 'Succeeded' } }) }
        $j = @(Get-SIHeartbeatJobs -Rows (Cfg) -Executions $ex | Where-Object { $_.name -eq 'updater' })
        $j.Count | Should -Be 1
        $j[0].lastResult | Should -Be 'running'
        $j[0].lastStartUtc | Should -Be '2026-11-13T05:46:10Z'
        $j[0].lastEndUtc | Should -BeNullOrEmpty
        Test-SIHeartbeatField -Name 'Jobs' -Value ([object[]]$j) | Should -BeNullOrEmpty
    }
}

Describe 'a live run, no run, the queue' {
    It 'a live run: running, with its running step and since when' {
        $p = Beat (Cfg -State 'Running' -Live)
        $p.state | Should -Be 'running'
        $p.step | Should -Be 'risk-analysis-detailed'
        $p.stepSinceUtc | Should -Be (ConvertTo-SIHeartbeatUtc $script:Start.AddHours(9))
        $p.stepsDone | Should -Be 8
        $p.stepsTotal | Should -Be 12
        @($p.runningSteps | ForEach-Object step) | Should -Be @('risk-analysis-detailed')
        $p.queuedRuns | Should -Be 1
        Test-SIHeartbeatField -Name 'Pipeline' -Value $p | Should -BeNullOrEmpty
    }
    It 'no run recorded: idle (the pipeline only); nothing at all: no field' {
        $p = Get-SIHeartbeatPipeline -Rows @((Row 'def' 'flow' -Txt $script:Def)) -NowUtc $script:Now -Eta
        $p.state | Should -Be 'idle'
        $p.runId | Should -BeNullOrEmpty
        $p.step | Should -BeNullOrEmpty
        Test-SIHeartbeatField -Name 'Pipeline' -Value $p | Should -BeNullOrEmpty
        Get-SIHeartbeatPipeline -Rows @() -NowUtc $script:Now | Should -BeNullOrEmpty
    }
    It 'queuedRuns is the waiting requests in every case; none read = null' {
        (Beat (Cfg -Queued 3)).queuedRuns | Should -Be 3
        (Beat (Cfg -State 'Running' -Live -Queued 3)).queuedRuns | Should -Be 3
        (Beat (Cfg -Queued 0)).queuedRuns | Should -Be 0
        (Beat (Cfg -Queued $null)).queuedRuns | Should -BeNullOrEmpty
    }
    It 'the closed list of states is unchanged' {
        (Get-SIHeartbeatFieldsContract).PipelineStates | Should -Be @('running', 'idle', 'failed', 'succeeded')
    }
}
