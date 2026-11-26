#Requires -Version 5.1
<#
    SecurityInsight -- #1357 A FINISHED UPDATE IS NEVER STOPPED AS DEAD WHILE ITS CONTAINER STOPS (engine\_shared\SI-ExecutionLiveness.ps1,
    container\updater\_shared\SI-UpdaterRunGate.ps1 Unregister-SIUpdaterExecutionBeat).

    Live 2026-11-25 at the largest install: caj-si-updater-nd0t0o9 finished, started its successor, let its own 'updater' row go
    at its end -- and 27 s later, while Azure still showed it Running, the pipeline stopped it: "showed no sign of life and was
    stopped ... never reported that it was working, 121 minutes after it started" (a si.execution.stopped-dead alert). No row
    named it any more, so the rule read it as an execution that never beat.
    What must hold:
      * at its end the update writes the END MARK of its run (row 'updater-ended', Holder = it) BEFORE it lets its row go;
      * the live sequence (mark written, row let go, Azure still Running, the rule judged 27 s later) = alive (finishing): not
        stopped, no alert -- by the pipeline's update check and by a later update's step-aside;
      * past the 10-minute grace after the mark, a still-running execution is stopped as before (its line says it had ended);
      * a real never-beat execution is still stopped and still raises si.execution.stopped-dead;
      * the Community document store carries the mark too; a support start of the database job is not held back by a mark.
    Offline: the lock table is an in-memory seam behind the product's own statements.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\_shared\SI-ExecutionLiveness.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-JobFlow.ps1')
    . (Join-Path $script:SIRoot 'container\_shared\SI-ContainerConfig.ps1')
    $global:SIv3EndedUpdLines = New-Object System.Collections.Generic.List[string]
    function global:Write-UpdLog { param([string]$m) [void]$global:SIv3EndedUpdLines.Add($m) }
    . (Join-Path $script:SIRoot 'container\updater\_shared\SI-UpdaterRunGate.ps1')
    . (Join-Path $script:SIRoot 'setup\_shared\SI-DbInitJob.ps1')

    # cfg.PipelineLock in memory, behind the product's own statements (each one recognised by its text); every call recorded
    function script:New-LockTable {
        $t = [pscustomobject]@{ Rows = @{}; Calls = (New-Object System.Collections.Generic.List[string]) }
        $sql = @{ Read = (Get-SIExecutionLockSql 'Read'); Take = (Get-SIExecutionLockSql 'Take'); Beat = (Get-SIExecutionLockSql 'Beat'); Release = (Get-SIExecutionLockSql 'Release'); Ended = (Get-SIExecutionLockSql 'Ended') }
        $inv = {
            param([string]$Q, $P, [string]$Mode)
            $kind = @($sql.Keys | Where-Object { $sql[$_] -eq $Q })[0]
            $t.Calls.Add("$kind $($P.LockId)")
            $now = [datetime]::UtcNow
            switch ($kind) {
                'Read' { , @($t.Rows.Values | Where-Object { $_.Holder } | ForEach-Object { [pscustomobject]@{ LockId = $_.LockId; Holder = $_.Holder; HeartbeatUtc = $_.HeartbeatUtc } }) }
                'Take' {
                    $r = $t.Rows[$P.LockId]
                    if (-not $r -or -not $r.Holder -or $r.Holder -eq $P.Holder) { $t.Rows[$P.LockId] = [pscustomobject]@{ LockId = $P.LockId; Holder = $P.Holder; What = $P.What; HeartbeatUtc = $now } }
                    , @([pscustomobject]@{ Mine = [int]($t.Rows[$P.LockId].Holder -eq $P.Holder) }) }
                'Beat' { $r = $t.Rows[$P.LockId]; $h = 0; if ($r -and $r.Holder -eq $P.Holder) { $r.HeartbeatUtc = $now; $r.What = $P.What; $h = 1 }; , @([pscustomobject]@{ Held = $h }) }
                'Release' { $r = $t.Rows[$P.LockId]; if ($r -and $r.Holder -eq $P.Holder) { $r.Holder = $null; $r.HeartbeatUtc = $null } }
                'Ended' { $t.Rows['updater-ended'] = [pscustomobject]@{ LockId = 'updater-ended'; Holder = $P.Holder; What = $P.What; HeartbeatUtc = $now }; $t.Calls[$t.Calls.Count - 1] = 'Ended updater-ended'; , @([pscustomobject]@{ Held = 1 }) }
                default { throw "unexpected statement: $Q" }
            }
        }.GetNewClosure()
        $t | Add-Member -NotePropertyName Invoke -NotePropertyValue $inv
        $t
    }
    function script:Exec([string]$Name, [datetime]$StartedUtc, [string]$Status = 'Running') {
        [pscustomobject]@{ name = $Name; properties = [pscustomobject]@{ status = $Status; startTime = $StartedUtc.ToString('yyyy-MM-ddTHH:mm:ssZ') } }
    }
    # the live sequence: nd0t0o9 registers its row, beats, ends its run (Unregister) -- the lock rows read right after
    function script:Invoke-LiveEnd {
        param([switch]$OldEnd)
        $lt = New-LockTable
        $store = [pscustomobject]@{ Invoke = $lt.Invoke }
        Register-SIUpdaterExecutionBeat -Store $store -Holder 'caj-si-updater:caj-si-updater-nd0t0o9' | Should -BeTrue
        $null = Invoke-SIUpdaterLockBeat -What '9j. PUBLISHED COPIES' -Force
        if ($OldEnd) { $x = $global:SI_UpdaterExecBeat; $global:SI_UpdaterExecBeat = $null; Exit-SIExecutionLock -Store $x.Store -Lock 'updater' -Holder $x.Holder }   # the end before #1357
        else { Unregister-SIUpdaterExecutionBeat }
        $endUtc = [datetime]::UtcNow
        $rows = @((Read-SIExecutionLocks -Store (New-SIExecutionLockStore -Invoke $lt.Invoke)).Rows)
        [pscustomobject]@{ Table = $lt; Rows = $rows; EndUtc = $endUtc; Exec = (Exec 'caj-si-updater-nd0t0o9' $endUtc.AddMinutes(-121)) }
    }
}
AfterAll { Remove-Item -Path Function:\Write-UpdLog -ErrorAction SilentlyContinue; $global:SIv3EndedUpdLines = $null; $global:SI_UpdaterExecBeat = $null; $global:SI_UpdaterLockBeat = $null; $global:SI_ExecutionStopped = $null }

Describe 'the end of an update''s run: the mark first, then its row let go' {
    It 'Unregister writes the end mark BEFORE it releases the update''s own row; the mark names the execution' {
        $o = Invoke-LiveEnd
        $calls = @($o.Table.Calls | Where-Object { $_ -match '^(Ended|Release)' })
        $calls | Should -Be @('Ended updater-ended', 'Release updater')
        @($o.Rows | Where-Object { $_.LockName -eq 'updater' }).Count | Should -Be 0 -Because 'the row is let go -- a successor takes it at once'
        $m = @($o.Rows | Where-Object { $_.LockName -eq 'updater-ended' })[0]
        $m.Holder | Should -Be 'caj-si-updater:caj-si-updater-nd0t0o9'
        $o.Table.Rows['updater-ended'].What | Should -Be 'an update of SecurityInsight: ended'
        $global:SI_UpdaterExecBeat | Should -BeNullOrEmpty
    }
    It 'the statement: one upsert of the one end-mark row, no take rule; the contract holds its name and the 10-minute grace' {
        $s = Get-SIExecutionLockSql 'Ended'
        $s | Should -Match ([regex]::Escape("INSERT cfg.PipelineLock (LockId) VALUES (N'updater-ended')"))
        $s | Should -Match ([regex]::Escape("SET Holder = @Holder, What = @What, FlowRunId = NULL, AcquiredUtc = SYSUTCDATETIME(), HeartbeatUtc = SYSUTCDATETIME() WHERE LockId = N'updater-ended'"))
        $s | Should -Not -Match "LockId = N'install'|LockId = N'updater'(?!-)"
        $c = Get-SIExecutionLivenessContract
        $c.UpdaterEndedLock | Should -Be 'updater-ended'; $c.EndedGraceMinutes | Should -Be 10
        $c.BeatStaleMinutes | Should -Be 15; $c.NeverBeatGraceMinutes | Should -Be 30; $c.FallbackHours | Should -Be 6
    }
}

Describe 'the live sequence (2026-11-25): ended, Azure still Running, judged 27 s later' {
    BeforeEach { $global:SI_ExecutionStopped = @{}; $global:SIv3EndedUpdLines.Clear() }
    It 'BEFORE #1357 (the row let go, no mark): the rule read it as never beaten and it was stopped -- the live defect' {
        $o = Invoke-LiveEnd -OldEnd
        $u = Get-SIPipelineUpdateLiveness -Executions @($o.Exec) -Locks $o.Rows -LocksKnown $true -NowUtc $o.EndUtc.AddSeconds(27)
        @($u.Dead).Count | Should -Be 1
        Get-SIExecutionStoppedText -Dead @($u.Dead)[0] | Should -Match 'never reported that it was working, 121 minutes after it started'
    }
    It 'with the mark: the pipeline''s update check sees it FINISHING -- not dead, nothing stopped, no si.execution.stopped-dead' {
        $o = Invoke-LiveEnd
        $u = Get-SIPipelineUpdateLiveness -Executions @($o.Exec) -Locks $o.Rows -LocksKnown $true -NowUtc $o.EndUtc.AddSeconds(27)
        @($u.Dead).Count | Should -Be 0
        $u.Running | Should -Match 'caj-si-updater-nd0t0o9' -Because 'it still runs for a moment; the run waits seconds, never stops it'
        $lv = Get-SIExecutionLiveness -Execution $o.Exec -Kind updater -Locks $o.Rows -NowUtc $o.EndUtc.AddSeconds(27)
        $lv.Alive | Should -BeTrue; $lv.Ended | Should -BeTrue; $lv.LockName | Should -Be 'updater-ended'
        $stops = New-Object System.Collections.Generic.List[string]; $alerts = New-Object System.Collections.Generic.List[object]
        $st = Invoke-SIExecutionDeadStop -Dead @($u.Dead) -Stop { param($n) $stops.Add($n) } -Alert { param($ev) $alerts.Add($ev) } -Stopped $global:SI_ExecutionStopped
        $stops.Count | Should -Be 0; $alerts.Count | Should -Be 0; @($st.Events).Count | Should -Be 0
        # the whole grace: still finishing 9 minutes after the mark
        (Get-SIExecutionLiveness -Execution $o.Exec -Kind updater -Locks $o.Rows -NowUtc $o.EndUtc.AddMinutes(9)).Alive | Should -BeTrue
    }
    It 'with the mark: a later update''s step-aside stops nothing and raises nothing (it waits for it, as for any live one)' {
        $o = Invoke-LiveEnd
        $later = Exec 'caj-si-updater-qs0an5m' $o.EndUtc.AddSeconds(-30)
        $stops = New-Object System.Collections.Generic.List[string]; $alerts = New-Object System.Collections.Generic.List[object]
        $e = Get-SIUpdaterEarlierLiveness -Executions @($o.Exec, $later) -Self 'caj-si-updater-qs0an5m' -NowUtc $o.EndUtc.AddSeconds(27) -Locks $o.Rows -LocksKnown $true `
                 -Stop { param($n) $stops.Add($n) } -Alert { param($ev) $alerts.Add($ev) }
        $stops.Count | Should -Be 0; $alerts.Count | Should -Be 0
        $e.Name | Should -Be 'caj-si-updater-nd0t0o9'
        ($global:SIv3EndedUpdLines -join "`n") | Should -Not -Match 'showed no sign of life'
    }
    It 'past the 10-minute grace a still-running execution is stopped as before -- its line says it had ended; the alert is raised' {
        $o = Invoke-LiveEnd
        $at = $o.EndUtc.AddMinutes(11)
        $u = Get-SIPipelineUpdateLiveness -Executions @($o.Exec) -Locks $o.Rows -LocksKnown $true -NowUtc $at
        @($u.Dead).Count | Should -Be 1
        $alerts = New-Object System.Collections.Generic.List[object]; $lines = New-Object System.Collections.Generic.List[string]
        $null = Invoke-SIExecutionDeadStop -Dead @($u.Dead) -Stop { param($n) } -Log { param($l, $m) $lines.Add($m) } -Alert { param($ev) $alerts.Add($ev) } -NowUtc $at
        $lines[0] | Should -Match '^an update of SecurityInsight showed no sign of life and was stopped: caj-si-updater-nd0t0o9 \(started [^)]+\) reported that it had ended at \d{4}-\d\d-\d\d \d\d:\d\dZ, 11 minutes ago, but still showed as running -- '
        $alerts.Count | Should -Be 1; $alerts[0].LockName | Should -Be 'updater-ended'
        $ctx = [pscustomobject]@{ Mode = 'identified'; Endpoint = 'https://invardia.example/api/uplink'; AccessCode = 'c'; Version = '3.1.46'; Ring = 1; Edition = 'pro'; TenantId = ''; LastingInstallId = ''; LicenceId = ''; EnvironmentName = 'install-a' }
        $rec = ConvertTo-SIExecutionStoppedAlert -Event $alerts[0] -Context $ctx
        $rec.AlertId | Should -Be 'si.execution.stopped-dead'
        $rec.ActionText | Should -Match 'its run had ended \(its end mark\) but its container did not stop'
    }
}

Describe 'a real dead update is still stopped and raised' {
    BeforeEach { $global:SI_ExecutionStopped = @{} }
    It 'never beaten, started 45 minutes ago, no row and no mark: dead, stopped, si.execution.stopped-dead' {
        $now = [datetime]::UtcNow
        $ex = Exec 'caj-si-updater-dead' $now.AddMinutes(-45)
        $u = Get-SIPipelineUpdateLiveness -Executions @($ex) -Locks @() -LocksKnown $true -NowUtc $now
        @($u.Dead).Count | Should -Be 1
        $stops = New-Object System.Collections.Generic.List[string]; $alerts = New-Object System.Collections.Generic.List[object]
        $null = Invoke-SIExecutionDeadStop -Dead @($u.Dead) -Stop { param($n) $stops.Add($n) } -Alert { param($ev) $alerts.Add($ev) } -NowUtc $now
        @($stops) | Should -Be @('caj-si-updater-dead')
        $alerts.Count | Should -Be 1; $alerts[0].Id | Should -Be 'si.execution.stopped-dead'
    }
    It 'the end mark of ANOTHER execution is no sign of life of this one' {
        $now = [datetime]::UtcNow
        $rows = @([pscustomobject]@{ LockName = 'updater-ended'; Holder = 'caj-si-updater:caj-si-updater-other'; HeartbeatUtc = $now.AddMinutes(-1) })
        (Get-SIExecutionLiveness -Execution (Exec 'caj-si-updater-dead' $now.AddMinutes(-45)) -Kind updater -Locks $rows -NowUtc $now).Alive | Should -BeFalse
    }
    It 'a hung update that BEAT (stale 16 minutes, no mark) is still dead as before' {
        $now = [datetime]::UtcNow
        $rows = @([pscustomobject]@{ LockName = 'updater'; Holder = 'caj-si-updater:caj-si-updater-hung'; HeartbeatUtc = $now.AddMinutes(-16) })
        $lv = Get-SIExecutionLiveness -Execution (Exec 'caj-si-updater-hung' $now.AddMinutes(-90)) -Kind updater -Locks $rows -NowUtc $now
        $lv.Alive | Should -BeFalse; $lv.Ended | Should -BeFalse
    }
}

Describe 'the other readers of the lock rows' {
    It 'the Community document store writes and reads the mark' {
        $docs = @{}
        $d = [pscustomobject]@{ Store = $docs }
        $d | Add-Member -MemberType ScriptMethod -Name Read -Value { param($n) $this.Store[$n] }
        $d | Add-Member -MemberType ScriptMethod -Name Write -Value { param($n, $t) $this.Store[$n] = $t }
        $d | Add-Member -MemberType ScriptMethod -Name Delete -Value { param($n) $this.Store.Remove($n) }
        $s = New-SIExecutionLockStore -Docs $d
        Set-SIExecutionLockEnded -Store $s -Holder 'caj-si-updater:caj-si-updater-c1' | Should -BeTrue
        $docs.Contains('updater-ended.lock') | Should -BeTrue
        $r = @((Read-SIExecutionLocks -Store $s).Rows | Where-Object { $_.LockName -eq 'updater-ended' })
        $r.Count | Should -Be 1; $r[0].Holder | Should -Be 'caj-si-updater:caj-si-updater-c1'
    }
    It 'a mark never throws (no store, a failing store)' {
        Set-SIExecutionLockEnded -Store $null -Holder 'h' | Should -BeFalse
        Set-SIExecutionLockEnded -Store (New-SIExecutionLockStore -Invoke { throw 'no database' }) -Holder 'h' | Should -BeFalse
    }
    It 'a support start of the database job is not held back by an end mark (only a live updater row counts)' {
        Get-SIDbInitUpdaterLockSql | Should -Match ([regex]::Escape("WHERE LockId <> N'updater-ended' AND Holder LIKE N'caj-si-updater%'"))
    }
    It 'a data reset is not "busy" because of an end mark: its lock scan (check and claim) leaves the updater-ended row out' {
        . (Join-Path $script:SIRoot 'setup\_shared\SI-DataReset.ps1')
        foreach ($claim in $false, $true) {
            $s = Get-SIDataResetSql -Name Gate -Claim:$claim
            $s | Should -Match "(?s)WHERE Holder IS NOT NULL AND Holder <> @Holder\s+AND LockId <> N'updater-ended'"
        }
    }
}
