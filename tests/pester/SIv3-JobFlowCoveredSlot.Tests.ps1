#Requires -Version 5.1
<#
    A MANUAL RUN THAT SPANS THE DAILY SLOT IS THAT DAY'S RUN (2026-10-24, seen on internal: a manual / queued run still going
    at the daily time, then a catch-up right after it -- a second full run back to back, and its load raised tickets).

    What these tests keep true (engine\_shared\SI-JobFlow.ps1 Get-SIJobFlowCoveredSlot / Get-SIJobFlowSlotRun /
    Get-SIJobFlowDue, the run start's carried LastSlotUtc; SI-Pipeline.ps1 Get-SIPipelinePendingSlot and the queue -- the
    queue's own test is in SIv3-Pipeline):
      * a WHOLE run with no slot of its own (manual / queued) that was RUNNING at the slot and ended SUCCEEDED covers it: no
        catch-up, the schedule waits for the next slot and says why;
      * a run that failed, was cancelled or stopped, a step / stage / re-run-from-step run: the catch-up as before;
      * a scheduled or catch-up run (its own slot) that outlasts the next slot keeps "start when the last one ends";
      * a run that ended before the slot: the slot on time; an interval cadence: unchanged;
      * the next run carries the covered slot (a second manual run after it never brings the catch-up back).
    Offline.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . ([IO.Path]::Combine($script:SIRoot, 'engine', '_shared', 'SI-JobFlow.ps1'))
    $script:Map = Get-SIJobFlowMap
    $script:Def = New-SIDefaultJobFlow -Installed @('ptc') -Map $script:Map -StartTime '01:00' -TimeZone 'UTC'   # daily 01:00 UTC
    $script:S = [datetime]::SpecifyKind([datetime]'2026-10-05T01:00:00', 'Utc')
    function script:Run([string]$State = 'Succeeded', $Start = $script:S.AddMinutes(-10), $End = $script:S.AddMinutes(70), $Slot = $null, [string]$Scope = 'pipeline', [string]$FromStep = '', [string]$Trigger = 'manual') {
        [pscustomobject]@{ FlowRunId = 'm1'; Trigger = $Trigger; State = $State; Scope = $Scope; FromStep = $FromStep; StartedUtc = $Start; EndedUtc = $End; HeartbeatUtc = $End
                           SlotUtc = $Slot; LastSlotUtc = $script:S.AddDays(-1); Steps = @() }
    }
}

Describe 'the covered slot (Get-SIJobFlowCoveredSlot)' {
    It 'a manual or queued WHOLE run running at the slot that SUCCEEDED covers it' {
        foreach ($t in 'manual', 'queued') { Get-SIJobFlowCoveredSlot -Definition $script:Def -Previous (Run -Trigger $t) | Should -Be $script:S }
        Get-SIJobFlowCoveredSlot -Definition $script:Def -Previous (Run -End $script:S) | Should -Be $script:S -Because 'ending exactly at the slot: it was running then'
    }
    It 'NEGATIVE: failed / cancelled / stopped, a step / stage / re-run-from-step run, a run with its own slot, a run that ended before the slot, an interval cadence' {
        foreach ($st in 'Failed', 'Cancelled', 'Stopped', 'Running') { Get-SIJobFlowCoveredSlot -Definition $script:Def -Previous (Run -State $st) | Should -BeNullOrEmpty -Because $st }
        foreach ($sc in 'step', 'stage') { Get-SIJobFlowCoveredSlot -Definition $script:Def -Previous (Run -Scope $sc) | Should -BeNullOrEmpty -Because $sc }
        Get-SIJobFlowCoveredSlot -Definition $script:Def -Previous (Run -FromStep 'ptc') | Should -BeNullOrEmpty
        Get-SIJobFlowCoveredSlot -Definition $script:Def -Previous (Run -Slot $script:S.AddDays(-1) -Trigger 'schedule' -Start $script:S.AddDays(-1) -End $script:S.AddHours(6)) | Should -BeNullOrEmpty -Because 'a scheduled run is its own slot''s run'
        Get-SIJobFlowCoveredSlot -Definition $script:Def -Previous (Run -Start $script:S.AddHours(-3) -End $script:S.AddMinutes(-5)) | Should -BeNullOrEmpty
        Get-SIJobFlowCoveredSlot -Definition $script:Def -Previous (Run -Start $script:S -End $script:S.AddHours(2)) | Should -BeNullOrEmpty -Because 'started AT the slot: not running before it'
        $iv = New-SIDefaultJobFlow -Installed @('ptc') -Map $script:Map; $iv.Cadence = 'interval'; $iv.IntervalMinutes = 60
        Get-SIJobFlowCoveredSlot -Definition $iv -Previous (Run) | Should -BeNullOrEmpty
        Get-SIJobFlowCoveredSlot -Definition $script:Def -Previous $null | Should -BeNullOrEmpty
    }
    It 'a manual run spanning two slots covers the latest one' {
        Get-SIJobFlowCoveredSlot -Definition $script:Def -Previous (Run -Start $script:S.AddHours(-2) -End $script:S.AddDays(1).AddHours(3)) | Should -Be $script:S.AddDays(1)
    }
}

Describe 'the schedule (Get-SIJobFlowDue)' {
    It 'covered: no catch-up -- it waits for the next slot and says which run covered it; the next slot starts on time' {
        $w = Get-SIJobFlowDue -Definition $script:Def -Previous (Run) -NowUtc $script:S.AddMinutes(75)
        $w.Action | Should -Be 'Wait'
        $w.NextUtc | Should -Be $script:S.AddDays(1)
        $w.Reason | Should -Be ('the {0:u} slot was covered by flow run m1: it was running at that time and succeeded; next slot {1:u}' -f $script:S, $script:S.AddDays(1))
        $n = Get-SIJobFlowDue -Definition $script:Def -Previous (Run) -NowUtc $script:S.AddDays(1).AddMinutes(1)
        $n.Action | Should -Be 'Start'; $n.Trigger | Should -Be 'schedule'; $n.SlotUtc | Should -Be $script:S.AddDays(1)
    }
    It 'NOT covered (failed, cancelled, stopped, a stage run): the catch-up as before' {
        foreach ($p in @((Run -State 'Failed'), (Run -State 'Cancelled'), (Run -State 'Stopped'), (Run -Scope 'stage'), (Run -FromStep 'ptc'))) {
            $c = Get-SIJobFlowDue -Definition $script:Def -Previous $p -NowUtc $script:S.AddMinutes(75)
            $c.Action | Should -Be 'Start' -Because ('{0} / {1}' -f $p.State, $p.Scope)
            $c.Trigger | Should -Be 'catch-up'; $c.SlotUtc | Should -Be $script:S
        }
    }
    It 'a SCHEDULED run that outlasts the next slot keeps "start when the last one ends" (a large install stays refreshed every run)' {
        $long = Run -Trigger 'schedule' -Slot $script:S.AddDays(-1) -Start $script:S.AddDays(-1) -End $script:S.AddHours(7)
        $long.LastSlotUtc = $script:S.AddDays(-1)
        $c = Get-SIJobFlowDue -Definition $script:Def -Previous $long -NowUtc $script:S.AddHours(7).AddMinutes(3)
        $c.Action | Should -Be 'Start'; $c.Trigger | Should -Be 'catch-up'; $c.SlotUtc | Should -Be $script:S
    }
    It 'a run that ended before the slot: the slot starts on time, as before' {
        $p = Run -Start $script:S.AddHours(-3) -End $script:S.AddMinutes(-20)
        $on = Get-SIJobFlowDue -Definition $script:Def -Previous $p -NowUtc $script:S.AddMinutes(2)
        $on.Action | Should -Be 'Start'; $on.Trigger | Should -Be 'schedule'
    }
}

Describe 'what the next run carries (Get-SIJobFlowSlotRun) and the queue''s slot (Get-SIPipelinePendingSlot)' {
    It 'the covered slot is carried: a second manual run after the covering one never brings the catch-up back' {
        Get-SIJobFlowSlotRun -Definition $script:Def -Previous (Run) | Should -Be $script:S
        Get-SIJobFlowSlotRun -Definition $script:Def -Previous (Run -State 'Failed') | Should -Be $script:S.AddDays(-1) -Because 'not covered: its own LastSlotUtc'
        # the second manual run: started after the slot, carries the covered slot (what the run start records)
        $m2 = Run -Start $script:S.AddHours(2) -End $script:S.AddHours(3)
        $m2.LastSlotUtc = Get-SIJobFlowSlotRun -Definition $script:Def -Previous (Run)
        $w = Get-SIJobFlowDue -Definition $script:Def -Previous $m2 -NowUtc $script:S.AddHours(3).AddMinutes(5)
        $w.Action | Should -Be 'Wait' -Because 'the slot has run'
        $w.NextUtc | Should -Be $script:S.AddDays(1)
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\_shared\SI-JobFlow.ps1'))
        $src | Should -Match ([regex]::Escape('-LastSlotUtc $(if ($Previous) { Get-SIJobFlowSlotRun -Definition $Definition -Previous $Previous } else { $null })'))
    }
    It 'the pending slot reads the same: a slot a covering run took is never queued again; one it did not take is' {
        . ([IO.Path]::Combine($script:SIRoot, 'engine', '_shared', 'SI-Pipeline.ps1'))
        Get-SIPipelinePendingSlot -Definition $script:Def -Previous (Run) -NowUtc $script:S.AddMinutes(75) | Should -BeNullOrEmpty
        (Get-SIPipelinePendingSlot -Definition $script:Def -Previous (Run -State 'Failed') -NowUtc $script:S.AddMinutes(75)).SlotUtc | Should -Be $script:S
        $drain = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\_shared\SI-Pipeline.ps1'))
        $drain | Should -Match ([regex]::Escape("if (`$req.Id) { `$Control.MarkDone(`$req.Id, 'Covered') }"))
    }
}
