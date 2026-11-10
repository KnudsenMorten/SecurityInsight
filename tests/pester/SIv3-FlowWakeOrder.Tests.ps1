#Requires -Version 5.1
<#
    SecurityInsight -- A RUN'S END AND A WAKE-UP NEVER WORK SILENTLY BEFORE THE QUEUE (live 2026-11-09/10, four large installs).
    The runner logged "flow run ...: succeeded" and then nothing: the copies the pages show were refreshed in ONE database call
    that never beat (the runner's seam handed out no connections, so the range driver never ran), and the watchdog stopped it
    as dead 15 minutes later. Every later wake-up ran the same call BEFORE the queue and the waiting update, never beat, and was
    stopped 30 minutes after its start -- one install took no run and no update for 19 hours.

    What must hold:
      * the run's end moves only the pointer (-SkipCopyCatchUp); the drain hands a waiting update over and releases the lock;
        only THEN the wake-up's upkeep -- the copies, the statistics after a run, the clean-up -- each part beaten; with the
        updater started there is no upkeep at all (the next wake-up does it, after the update);
      * a seam without connections refreshes the copies in one call (the defect, reproduced); a seam with them goes range by
        range and beats; the runner and the updater both hand connections out now;
      * a full wake-up beats its own row 'wakeup': alive while beaten, judged as a clean-up (never holds the next wake-up back);
      * the watchdog frees the install lock of the runner it stopped -- only that runner's; the next drain closes the request
        of a run that ended (a plain line) and resumes only a run that did not.
    Offline; script-scoped helpers and fakes; no Azure, no database.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . ([IO.Path]::Combine($script:SIRoot, 'engine', '_shared', 'SI-JobFlow.ps1'))
    . ([IO.Path]::Combine($script:SIRoot, 'engine', '_shared', 'SI-ExecutionLiveness.ps1'))
    . ([IO.Path]::Combine($script:SIRoot, 'engine', '_shared', 'data-sql', 'SI-DataPublishedRun.ps1'))
    $script:Now = [datetime]::SpecifyKind([datetime]'2026-11-10T06:00:00', 'Utc')
    function script:New-Mark { [pscustomobject]@{ SinceUtc = $script:Now.AddHours(-3); SetUtc = $script:Now.AddMinutes(-5); Kind = 'run'; Reason = 'update waits: run r1 is running' } }
    # an in-memory document store (the Community lock / queue documents)
    function script:New-MemDocs {
        $d = [pscustomobject]@{ Map = @{} }
        $d | Add-Member -MemberType ScriptMethod -Name Read -Value { param($n) if ($this.Map.ContainsKey($n)) { $this.Map[$n] } else { $null } }
        $d | Add-Member -MemberType ScriptMethod -Name Write -Value { param($n, $t) $this.Map[$n] = [string]$t }
        $d | Add-Member -MemberType ScriptMethod -Name CreateNew -Value { param($n, $t) if ($this.Map.ContainsKey($n) -and $this.Map[$n]) { $false } else { $this.Map[$n] = [string]$t; $true } }
        $d | Add-Member -MemberType ScriptMethod -Name Delete -Value { param($n) $null = $this.Map.Remove($n) }
        $d
    }
    function script:Exec([string]$Name, [int]$StartedMinAgo) {
        [pscustomobject]@{ name = $Name; properties = [pscustomobject]@{ status = 'Running'; startTime = $script:Now.AddMinutes(-$StartedMinAgo).ToString('yyyy-MM-ddTHH:mm:ssZ') } }
    }
    function script:Lock([string]$LockName, [string]$Holder, [int]$BeatMinAgo) {
        [pscustomobject]@{ LockName = $LockName; Holder = $Holder; HeartbeatUtc = $script:Now.AddMinutes(-$BeatMinAgo) }
    }
}

Describe 'the order of a wake-up: the queue and the update hand-off first, then the upkeep' {
    BeforeEach {
        $script:Docs = New-MemDocs
        $script:Ctl = New-SIPipelineDocControl -Docs $script:Docs -Now { $script:Now } -Kind 'blob'
        $script:Def = New-SIDefaultJobFlow -Installed @('ptc', 'identity') -Map (Get-SIJobFlowMap) -StartTime '01:00' -TimeZone 'UTC'
        $script:Events = New-Object System.Collections.Generic.List[string]
        $script:Beats = 0
        $script:One = { param($Req, $Prev, $Fid) $script:Events.Add('run-end: pointer only'); [pscustomobject]@{ FlowRunId = $Fid; State = 'Succeeded'; Outcome = 'New'; Steps = @(); StartedUtc = $script:Now; EndedUtc = $script:Now } }
        $script:Start = { param($W, $BeforeStart) if ($BeforeStart) { & $BeforeStart }; $script:Events.Add(('updater started (lock free: {0})' -f [bool](-not $script:Ctl.LockHolder()))); [pscustomobject]@{ Started = $true; Text = 'caj-si-updater execution u1' } }
        $script:Upkeep = {
            param($Drain)
            $d = Get-SIPipelineUpkeepDecision -Drain $Drain
            if (-not $d.Run) { return $d }
            $null = Invoke-SIPipelineUpkeep -Beat { $script:Beats++ } -Stats ([bool]$d.Stats) `
                -CatchUp { param($Beat) $script:Events.Add(('copies (lock free: {0})' -f [bool](-not $script:Ctl.LockHolder()))) } `
                -Statistics { param($Beat) $script:Events.Add('statistics') } -Cleanup { param($Beat) $script:Events.Add('clean-up') }
            $d
        }
    }
    It 'a run ends while an update waits: the lock is released and the updater started BEFORE any copy refresh; no upkeep in this wake-up' {
        $null = $script:Ctl.Enqueue((New-SIPipelineRequest -Scope pipeline -Trigger manual -RequestedBy 'a'))
        $waits = { if ($script:Events.Count -ge 1) { New-Mark } else { $null } }
        $drain = Invoke-SIPipelineDrain -Definition $script:Def -Control $script:Ctl -LoadLast { $null } -RunOne $script:One -Holder 'caj-si-flow-w1' -Now { $script:Now } -Log { param($l, $m) } -UpdateWaits $waits -StartUpdate $script:Start
        $d = & $script:Upkeep $drain
        @($script:Events) | Should -Be @('run-end: pointer only', 'updater started (lock free: True)')
        $d.Run | Should -BeFalse
        $d.Why | Should -Match 'brought up to date by the next wake-up, after the update'
    }
    It 'no update waits: the drain ends and releases the lock, then the copies, the statistics (a run ended) and the clean-up -- each beaten' {
        $null = $script:Ctl.Enqueue((New-SIPipelineRequest -Scope pipeline -Trigger manual -RequestedBy 'a'))
        $drain = Invoke-SIPipelineDrain -Definition $script:Def -Control $script:Ctl -LoadLast { $null } -RunOne $script:One -Holder 'caj-si-flow-w1' -Now { $script:Now } -Log { param($l, $m) } -UpdateWaits { $null } -StartUpdate $script:Start
        $null = & $script:Upkeep $drain
        @($script:Events) | Should -Be @('run-end: pointer only', 'copies (lock free: True)', 'statistics', 'clean-up')
        $script:Beats | Should -Be 3
    }
    It 'nothing to run: the copies and the clean-up, no statistics' {
        $drain = Invoke-SIPipelineDrain -Definition ([pscustomobject]@{ Name = 'p'; Mode = 'schedules'; Steps = @() }) -Control $script:Ctl -LoadLast { $null } -RunOne $script:One -Holder 'caj-si-flow-w1' -Now { $script:Now } -Log { param($l, $m) }
        $null = & $script:Upkeep $drain
        @($script:Events) | Should -Be @('copies (lock free: True)', 'clean-up')
    }
    It 'the install is held (an update runs, a live run holds the lock): no upkeep, nothing said' {
        foreach ($o in 'Busy', 'Blocked') {
            $d = Get-SIPipelineUpkeepDecision -Drain ([pscustomobject]@{ Outcome = $o; Runs = @(); UpdateStarted = '' })
            $d.Run | Should -BeFalse; $d.Why | Should -Be ''
        }
        (Get-SIPipelineUpkeepDecision -Drain $null).Run | Should -BeFalse
    }
    It 'a part that fails is said once and the next part still runs; the upkeep never throws' {
        $lines = New-Object System.Collections.Generic.List[string]
        $done = Invoke-SIPipelineUpkeep -CatchUp { param($b) throw 'the database answered nothing' } -Cleanup { param($b) $script:Events.Add('clean-up') } -Log { param($l, $m) $lines.Add("$l $m") }
        @($done) | Should -Be @('clean-up')
        @($lines) | Should -HaveCount 1
        $lines[0] | Should -Match '^WARN the wake-up''s upkeep \(copies\) did not finish \(the database answered nothing\) -- the next wake-up does it again'
    }
}

Describe 'the copies the pages show: one silent call (the defect) vs range by range, beaten' {
    BeforeEach {
        $script:Sql = New-Object System.Collections.Generic.List[string]
        $script:Fake = {
            param($sql, $p, $mode)
            $script:Sql.Add($sql)
            if ($sql -match 'EXEC sidata\.PublishedRunSet') { return , @(@{ Published = $true; Reason = ''; CollectionId = 7; CollectionTime = $script:Now; Partial = $false; CopiesCaughtUp = $false; CopiesNote = $null }) }
            if ($sql -match 'sidata\.PublishedCopyCatchUp') { $ask = ([string]$p['WhatIf'] -eq '1'); return , @(@{ Ready = $true; Stale = $ask; Refreshed = (-not $ask); PublishedAt = $script:Now; CopiedAt = $script:Now.AddDays(-1); Ranged = $true; Now = ''; CiFindingSwapOpen = $null }) }
            if ($sql -match 'RiskExecViewSnapshot') { return 0 }
            , @()
        }
    }
    It 'a seam WITHOUT connections: the database''s procedure refreshes every copy in one call and nothing beats (the live defect)' {
        $script:Beat = 0
        $script:Fake.PSObject.Properties.Remove('SIConnectionInfo')
        $r = Invoke-SIPublishedCopyCatchUp -Invoke $script:Fake -Beat { $script:Beat++ }
        @($script:Sql | Where-Object { $_ -match 'sidata\.PublishedCopyCatchUp' }).Count | Should -Be 2 -Because 'ask, then the whole refresh as ONE call'
        $script:Beat | Should -Be 0
        $r.Action | Should -Be 'refreshed'
    }
    It 'a seam WITH connections: the engine''s range driver refreshes (every copy table, re-checked each time) and beats; the claim follows only when all are done' {
        $script:Beat = 0
        $inv = $script:Fake
        $inv | Add-Member -NotePropertyName SIConnectionInfo -NotePropertyValue { @{ ConnectionString = 'Server=x'; AccessToken = 't' } } -Force
        Mock Invoke-SIPublishedCopyRefresh { $null = & $Beat; [pscustomobject]@{ Ok = $true; Held = $false; Tables = 10; Rows = 5L; Ranges = 12L; Seconds = 3.0; Missing = @() } }
        $r = Invoke-SIPublishedCopyCatchUp -Invoke $inv -Beat { $script:Beat++ }
        Should -Invoke Invoke-SIPublishedCopyRefresh -Times 1 -Exactly
        $script:Beat | Should -Be 1
        $r.Action | Should -Be 'refreshed'
        @($script:SIPublishedCopyTables).Count | Should -Be 10 -Because 'the driver walks all ten copies on every refresh; CopiedAt moves only after all of them'
    }
    It 'the run''s end moves only the pointer: -SkipCopyCatchUp sends no catch-up' {
        $r = Invoke-SIDataPublishRun -Invoke $script:Fake -Source schedules -SkipCopyCatchUp
        $r.Published | Should -BeTrue
        @($script:Sql | Where-Object { $_ -match 'PublishedCopyCatchUp' }).Count | Should -Be 0
    }
    It 'the update''s catch-up passes the beat on (a long catch-up of an update that waited is never taken for a dead wake-up)' {
        Mock Invoke-SIPublishedCopyCatchUp { $null = & $Beat; [pscustomobject]@{ Action = 'current' } }
        $script:Beat = 0
        $inv = { param($sql, $p, $mode) , @(@{ N = 1 }) }
        $null = Invoke-SIDataPublishRun -Invoke $inv -Source update -Beat { $script:Beat++ }
        $script:Beat | Should -Be 1
    }
    It 'wiring: the runner''s publish seam and the updater''s copy step hand out connections and beat' {
        $flow = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\flow\Invoke-SIJobFlowRun.ps1'))
        $flow | Should -Match ([regex]::Escape('$publishSql = New-SIDataSqlInvoke -Server $pubSrv -Database $pubDb -AppId $global:SI_SPN_AppId -TenantId $global:SI_SPN_TenantId -CertThumbprint $global:SI_SPN_CertThumbprint'))
        $flow | Should -Match ([regex]::Escape('-Beat $pipeBeat -SkipCopyCatchUp }'))
        $flow.IndexOf('$upkeepDo = Get-SIPipelineUpkeepDecision -Drain $drain') | Should -BeGreaterThan $flow.IndexOf('$drain = Invoke-SIPipelineDrain')
        $upd = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'setup\Invoke-SIContainerUpdate.ps1'))
        $upd | Should -Match ([regex]::Escape('$dataSql | Add-Member -NotePropertyName SIConnectionInfo -NotePropertyValue $dataInfo'))
        $upd | Should -Match ([regex]::Escape('Invoke-SIPublishedCopyCatchUp -Invoke $dataSql -WhatIf:(-not $Apply -or $DetectOnly) -Beat $copyBeat'))
    }
}

Describe 'a full wake-up beats its own row; a dead runner''s lock and request are closed at once' {
    It 'a wake-up beating its row ''wakeup'' is alive, judged as a clean-up, and never holds the next wake-up back; 16 minutes without a beat = dead' {
        $exs = @((Exec 'caj-si-flow-a' 40), (Exec 'caj-si-flow-b' 0))
        $g = Select-SIFlowGuardOther -Executions $exs -Self 'caj-si-flow-b' -Locks @(Lock 'wakeup' 'caj-si-flow-a' 1) -NowUtc $script:Now
        $g.Other | Should -BeNullOrEmpty; @($g.Live).Count | Should -Be 1; @($g.Live)[0].Kind | Should -Be 'housekeeping'
        $g2 = Select-SIFlowGuardOther -Executions $exs -Self 'caj-si-flow-b' -Locks @(Lock 'wakeup' 'caj-si-flow-a' 16) -NowUtc $script:Now
        @($g2.Dead).Count | Should -Be 1
        $ev = New-SIExecutionStoppedEvent -Dead @($g2.Dead)[0] -StoppedUtc $script:Now -QueuedRunStarted $true
        $ctx = [pscustomobject]@{ Mode = 'identified'; Endpoint = 'https://x'; AccessCode = 'c'; Version = '3.0.77'; Ring = 0; Edition = 'pro'; TenantId = ''; LastingInstallId = ''; LicenceId = ''; EnvironmentName = 'i' }
        (ConvertTo-SIExecutionStoppedAlert -Event $ev -Context $ctx).Job | Should -Be 'housekeeping' -Because 'the alert keeps Invardia''s closed set of kinds'
    }
    It 'a wake-up runs its queue part beating the install lock: then it holds the next wake-up back as a runner' {
        $g = Select-SIFlowGuardOther -Executions @((Exec 'caj-si-flow-a' 40), (Exec 'caj-si-flow-b' 0)) -Self 'caj-si-flow-b' -Locks @((Lock 'wakeup' 'caj-si-flow-a' 30), (Lock 'install' 'caj-si-flow-a' 1)) -NowUtc $script:Now
        $g.Other.name | Should -Be 'caj-si-flow-a'
    }
    It 'the Community store reads the wake-up''s document too' {
        $d = New-MemDocs
        $d.Write('wakeup.lock', '{"Holder":"caj-si-flow-a","HeartbeatUtc":"2026-11-10T05:59:00Z"}')
        @((Read-SIExecutionLocks -Store (New-SIExecutionLockStore -Docs $d)).Rows | Where-Object { $_.LockName -eq 'wakeup' }).Count | Should -Be 1
    }
    It 'the watchdog frees the install lock of the runner it stopped -- only while that runner holds it' {
        $sent = New-Object System.Collections.Generic.List[object]
        $store = New-SIExecutionLockStore -Invoke { param($q, $p, $m) $sent.Add($p); , @(@{ Released = $(if ($p.Holder -eq 'caj-si-flow-dead') { 1 } else { 0 }) }) }.GetNewClosure()
        Exit-SIExecutionInstallLockOf -Store $store -Holder 'caj-si-flow-dead' | Should -BeTrue
        Exit-SIExecutionInstallLockOf -Store $store -Holder 'caj-si-flow-other' | Should -BeFalse
        Exit-SIExecutionInstallLockOf -Store $store -Holder '' | Should -BeFalse
        Get-SIExecutionInstallReleaseSql | Should -Match "WHERE LockId = N'install' AND Holder = @Holder"
        $d = New-MemDocs; $d.Write('pipeline.lock', '{"Holder":"caj-si-flow-live","HeartbeatUtc":"2026-11-10T05:59:00Z"}')
        Exit-SIExecutionInstallLockOf -Store (New-SIExecutionLockStore -Docs $d) -Holder 'caj-si-flow-dead' | Should -BeFalse
        $d.Read('pipeline.lock') | Should -Not -BeNullOrEmpty -Because 'a lock another runner holds is never touched'
        Exit-SIExecutionInstallLockOf -Store (New-SIExecutionLockStore -Docs $d) -Holder 'caj-si-flow-live' | Should -BeTrue
        $d.Read('pipeline.lock') | Should -BeNullOrEmpty
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\Start-SIInContainer.ps1'))
        $src | Should -Match ([regex]::Escape('foreach ($gs in @($guardStop.Stopped)) {'))
        $src | Should -Match ([regex]::Escape('Exit-SIExecutionInstallLockOf -Store $guardLockStore -Holder ([string]$gs.Name)'))
    }
    It 'the next drain closes the request of a run that ENDED (a plain line) and does not run it again; an unfinished run is resumed' {
        $ctl = New-SIPipelineDocControl -Docs (New-MemDocs) -Now { $script:Now } -Kind 'blob'
        $def = New-SIDefaultJobFlow -Installed @('ptc', 'identity') -Map (Get-SIJobFlowMap) -StartTime '01:00' -TimeZone 'UTC'
        $q = $ctl.Enqueue((New-SIPipelineRequest -Scope pipeline -Trigger manual -RequestedBy 'a'))
        $null = $ctl.MarkRunning($q.Id, 'run-3e5a', 'caj-si-flow-dead')
        $lines = New-Object System.Collections.Generic.List[string]; $ran = New-Object System.Collections.Generic.List[object]
        $one = { param($Req, $Prev, $Fid) $ran.Add($Req); [pscustomobject]@{ FlowRunId = $Fid; State = 'Succeeded'; Outcome = 'New'; Steps = @() } }.GetNewClosure()
        $null = Invoke-SIPipelineDrain -Definition ([pscustomobject]@{ Name = 'p'; Mode = 'schedules'; Steps = @() }) -Control $ctl -LoadLast { [pscustomobject]@{ FlowRunId = 'run-3e5a'; State = 'Succeeded'; Steps = @() } } -RunOne $one -Holder 'caj-si-flow-new' -Now { $script:Now } -Log { param($l, $m) $lines.Add($m) }.GetNewClosure()
        $ran.Count | Should -Be 0
        @($ctl.List() | Where-Object { $_.State -eq 'Running' }).Count | Should -Be 0
        @($lines | Where-Object { $_ -match '^run run-3e5a had ended \(succeeded\), but its runner stopped before it closed the request -- the request is closed now$' }).Count | Should -Be 1
        # an unfinished run is resumed by the runner that takes the lock (its request is closed with the run's own outcome)
        $null = Invoke-SIPipelineDrain -Definition ([pscustomobject]@{ Name = 'p'; Mode = 'schedules'; Steps = @() }) -Control $ctl -LoadLast { [pscustomobject]@{ FlowRunId = 'run-9'; State = 'Running'; Steps = @() } } -RunOne $one -Holder 'caj-si-flow-new' -Now { $script:Now } -Log { param($l, $m) }
        $ran.Count | Should -Be 1; $ran[0] | Should -BeNullOrEmpty -Because 'a resume carries no request'
    }
}
