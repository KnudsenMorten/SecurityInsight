#Requires -Version 5.1
<#
    A BUSY INSTALL GETS ITS UPDATE (REQUIREMENTS #947, owner 2026-10-29: "why is it it is so hard to get them updated" / "kill
    all running and get them to latest version NOW"):
      (a) A WAITING UPDATE GOES FIRST -- while the updater's wait mark is set, a run that ends starts no new run (the updater
          is started first), and a scheduled collection collects nothing (it is not the pipeline's own step); while the
          updater installs (it holds the install's lock) a scheduled collection collects nothing either. No mark = as today.
      (b) A BOUND ON THE WAIT -- after 6 hours the update cancels the run that started on an OLDER version (#700's cancel)
          and installs; a run that started on the version being installed is never cancelled; the pipeline runner starts
          the updater for it on a busy wake-up too (at most once an hour).
    Offline; PS 7. No Azure, no database (fakes and the file store).
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . ([IO.Path]::Combine($script:SIRoot, 'engine', '_shared', 'SI-JobFlow.ps1'))
    . ([IO.Path]::Combine($script:SIRoot, 'engine', '_shared', 'SI-CollectionRunGate.ps1'))
    . ([IO.Path]::Combine($script:SIRoot, 'container', 'updater', '_shared', 'SI-UpdaterRunGate.ps1'))
    . ([IO.Path]::Combine($script:SIRoot, 'container', 'updater', '_shared', 'SI-UpdaterWaitBound.ps1'))
    $script:Now = [datetime]::SpecifyKind([datetime]'2026-10-29T12:00:00', 'Utc')
    function script:New-Mark([double]$HoursAgo, [string]$Kind = 'run') {
        [pscustomobject]@{ SinceUtc = $script:Now.AddHours(-$HoursAgo); SetUtc = $script:Now.AddMinutes(-5); Kind = $Kind; Reason = 'update waits: run r1 is running' }
    }
    function script:New-GateRow([string]$Holder = '', [string]$Run = '', [int]$Age = 30, [string]$RunState = 'Running', [string]$StepState = '', [string]$StepExec = '', [int]$Rows = 0) {
        @{ HasStore = $true; Holder = $Holder; FlowRunId = $Run; LockAgeSeconds = $Age; RunState = $RunState; RunStartedUtc = $script:Now.AddHours(-2); StepState = $StepState; StepExecution = $StepExec; StepRows = $Rows }
    }
}

Describe '#947 (a) a scheduled collection holds while an update waits or installs' {
    It 'the hold: a run mark within 12 hours holds; none, a store mark, or an older mark holds nothing' {
        Get-SICollectionUpdateHold -Waits $null -NowUtc $script:Now | Should -Be ''
        Get-SICollectionUpdateHold -Waits (New-Mark 1 'store') -NowUtc $script:Now | Should -Be ''
        Get-SICollectionUpdateHold -Waits (New-Mark 13) -NowUtc $script:Now | Should -Be ''
        Get-SICollectionUpdateHold -Waits (New-Mark 2) -NowUtc $script:Now | Should -Match '^an update of SecurityInsight waits for this install \(since 2026-10-29 10:00Z\) and goes first -- this scheduled collection collected nothing'
    }
    It 'the mark is read as the updater writes it (the same tag the pipeline runner obeys)' {
        $v = ConvertTo-SIUpdateWaitsTag -SinceUtc $script:Now.AddHours(-2) -SetUtc $script:Now -Kind run -Reason 'update waits: run r1 is running'
        $m = ConvertFrom-SICollectionUpdateWaitsTag -Value $v
        $m.Kind | Should -Be 'run'; $m.SinceUtc | Should -Be $script:Now.AddHours(-2)
        ConvertFrom-SICollectionUpdateWaitsTag -Value '' | Should -BeNullOrEmpty
    }
    It 'no pipeline run, an update waits -> SKIP (nothing collected); no mark -> RUN as today; a mark that cannot be read -> RUN' {
        $inv = { param($sql, $p, $mode) , @((New-GateRow)) }
        $rec = { param($a, $r) }
        (Invoke-SICollectionRunGate -Invoke $inv -Job identity -Self 'caj-si-identity-producer-x' -Record $rec -Log { param($l, $m) } -Now { $script:Now } -UpdateWaits { New-Mark 2 }).Action | Should -Be 'Skip'
        (Invoke-SICollectionRunGate -Invoke $inv -Job identity -Self 'caj-si-identity-producer-x' -Record $rec -Log { param($l, $m) } -Now { $script:Now } -UpdateWaits { $null }).Action | Should -Be 'Run'
        (Invoke-SICollectionRunGate -Invoke $inv -Job identity -Self 'caj-si-identity-producer-x' -Record $rec -Log { param($l, $m) } -Now { $script:Now }).Action | Should -Be 'Run'
        (Invoke-SICollectionRunGate -Invoke $inv -Job identity -Self 'caj-si-identity-producer-x' -Record $rec -Log { param($l, $m) } -Now { $script:Now } -UpdateWaits { throw 'HTTP 403' }).Action | Should -Be 'Run'
    }
    It 'a run that does not include the job would make it WAIT -- with an update waiting it SKIPS at once (no execution held open on the old version)' {
        $inv = { param($sql, $p, $mode) , @((New-GateRow -Holder 'caj-si-flow-1' -Run 'r1' -Rows 0)) }
        $script:Slept = 0
        $g = Invoke-SICollectionRunGate -Invoke $inv -Job identity -Self 'caj-si-identity-producer-x' -Record { param($a, $r) } -Log { param($l, $m) } -Now { $script:Now } -Sleep { param($s) $script:Slept++ } -UpdateWaits { New-Mark 1 }
        $g.Action | Should -Be 'Skip'; $script:Slept | Should -Be 0
    }
    It 'the PIPELINE''S OWN collection step is never held by a waiting update (the run that is going must end for the update to land)' {
        $starting = { param($sql, $p, $mode) , @((New-GateRow -Holder 'caj-si-flow-1' -Run 'r1' -StepState 'Starting' -Rows 1)) }
        $running = { param($sql, $p, $mode) , @((New-GateRow -Holder 'caj-si-flow-1' -Run 'r1' -StepState 'Running' -StepExec 'caj-si-identity-producer-x' -Rows 1)) }
        (Invoke-SICollectionRunGate -Invoke $starting -Job identity -Self 'caj-si-identity-producer-x' -Record { param($a, $r) } -Log { param($l, $m) } -Now { $script:Now } -UpdateWaits { New-Mark 1 }).Action | Should -Be 'Run'
        (Invoke-SICollectionRunGate -Invoke $running -Job identity -Self 'caj-si-identity-producer-x' -Record { param($a, $r) } -Log { param($l, $m) } -Now { $script:Now } -UpdateWaits { New-Mark 1 }).Action | Should -Be 'Run'
    }
    It 'the UPDATER holds the install''s lock (it installs now): a scheduled collection collects nothing; a stale updater lock holds nothing' {
        (Get-SICollectionRunGateDecision -Row (New-GateRow -Holder 'caj-si-updater:upd-x1' -Age 30) -Job identity).Action | Should -Be 'Skip'
        (Get-SICollectionRunGateDecision -Row (New-GateRow -Holder 'caj-si-updater:upd-x1' -Age 3600) -Job identity).Action | Should -Be 'Run'
        (Get-SICollectionRunGateDecision -Row (New-GateRow) -Job identity).Action | Should -Be 'Run'
    }
    It 'wiring: the container entry reads the updater''s mark and hands it to the gate' {
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\Start-SIInContainer.ps1'))
        $src | Should -Match "Get-SIInstallName -Role updater"
        $src | Should -Match "ConvertFrom-SICollectionUpdateWaitsTag -Value \(\[string\]\`$updJob\.tags\.'si-update-waits'\)"
        $src | Should -Match '-UpdateWaits \$gateUpdateWaits'
    }
}

Describe '#947 (a) the pipeline: a run that ends while an update waits starts no new run' {
    BeforeEach {
        $script:Dir = Join-Path ([IO.Path]::GetTempPath()) ('si947-' + [guid]::NewGuid().ToString('N').Substring(0, 8)); New-Item -ItemType Directory -Path $script:Dir | Out-Null
        $script:Ctl = New-SIPipelineDocControl -Docs (New-SIPipelineFileDocs -Folder $script:Dir) -Now { $script:Now }
        $script:Def = New-SIDefaultJobFlow -Installed @('ptc', 'identity') -Map (Get-SIJobFlowMap) -StartTime '01:00' -TimeZone 'UTC'
        $script:Ran = New-Object System.Collections.Generic.List[string]
        $script:Updates = New-Object System.Collections.Generic.List[string]
        $script:One = { param($Req, $Prev, $Fid) $script:Ran.Add((Get-SIPipelineRequestKey $Req)); [pscustomobject]@{ FlowRunId = $Fid; State = 'Succeeded'; Outcome = 'New'; Steps = @(); StartedUtc = $script:Now; EndedUtc = $script:Now } }
        $script:Start = { param($W) $script:Updates.Add('started'); [pscustomobject]@{ Started = $true; Text = 'caj-si-updater execution u1' } }
    }
    AfterEach { Remove-Item -LiteralPath $script:Dir -Recurse -Force -ErrorAction SilentlyContinue }
    It 'two queued runs; the update starts waiting while the first runs -> the first ends, the updater is started, the second does NOT start' {
        $null = $script:Ctl.Enqueue((New-SIPipelineRequest -Scope stage -Target collect -RequestedBy 'a'))
        $null = $script:Ctl.Enqueue((New-SIPipelineRequest -Scope pipeline -Trigger manual -RequestedBy 'b'))
        $script:Asked = 0
        $waits = { $script:Asked++; if ($script:Ran.Count -ge 1) { New-Mark 0.5 } else { $null } }
        $out = Invoke-SIPipelineDrain -Definition $script:Def -Control $script:Ctl -LoadLast { $null } -RunOne $script:One -Holder 'caj-si-flow-w1' -Now { $script:Now } -Log { param($l, $m) } -UpdateWaits $waits -StartUpdate $script:Start
        @($script:Ran) | Should -Be @('stage|collect')
        @($script:Updates).Count | Should -Be 1
        @($script:Ctl.List() | Where-Object { $_.State -eq 'Queued' }).Count | Should -Be 1 -Because 'the second run waits in the queue and starts after the update, on the new version'
    }
    It 'no update waiting: behaviour as today -- both runs' {
        $null = $script:Ctl.Enqueue((New-SIPipelineRequest -Scope stage -Target collect -RequestedBy 'a'))
        $null = $script:Ctl.Enqueue((New-SIPipelineRequest -Scope pipeline -Trigger manual -RequestedBy 'b'))
        $null = Invoke-SIPipelineDrain -Definition $script:Def -Control $script:Ctl -LoadLast { $null } -RunOne $script:One -Holder 'caj-si-flow-w1' -Now { $script:Now } -Log { param($l, $m) } -UpdateWaits { $null } -StartUpdate $script:Start
        @($script:Ran).Count | Should -Be 2
        @($script:Updates).Count | Should -Be 0
    }
}

Describe '#947 (b) a bound on the wait: after 6 hours the update cancels an OLD-version run, never a new-version one' {
    It 'overdue only for a WAIT on a named run, with a version to install, after 6 hours' {
        $w = [pscustomobject]@{ Go = $false; Verdict = 'Wait'; Kind = 'run'; Reason = 'update waits: run r1 is running'; RunId = 'r1' }
        Test-SIUpdaterWaitOverdue -Gate $w -SinceUtc $script:Now.AddHours(-6) -NowUtc $script:Now -TargetVersion '3.0.8' | Should -BeTrue
        Test-SIUpdaterWaitOverdue -Gate $w -SinceUtc $script:Now.AddHours(-5.9) -NowUtc $script:Now -TargetVersion '3.0.8' | Should -BeFalse
        Test-SIUpdaterWaitOverdue -Gate $w -SinceUtc $null -NowUtc $script:Now -TargetVersion '3.0.8' | Should -BeFalse
        Test-SIUpdaterWaitOverdue -Gate $w -SinceUtc $script:Now.AddHours(-9) -NowUtc $script:Now -TargetVersion '' | Should -BeFalse
        Test-SIUpdaterWaitOverdue -Gate ([pscustomobject]@{ Go = $false; Verdict = 'Unreadable'; Kind = 'store'; RunId = '' }) -SinceUtc $script:Now.AddHours(-9) -NowUtc $script:Now -TargetVersion '3.0.8' | Should -BeFalse
        Test-SIUpdaterWaitOverdue -Gate ([pscustomobject]@{ Go = $false; Verdict = 'Wait'; Kind = 'run'; RunId = '' }) -SinceUtc $script:Now.AddHours(-9) -NowUtc $script:Now -TargetVersion '3.0.8' | Should -BeFalse -Because 'a wait for a step or a held lock names no run to cancel'
        Test-SIUpdaterWaitOverdue -Gate ([pscustomobject]@{ Go = $true; Verdict = 'Go'; Kind = ''; RunId = '' }) -SinceUtc $script:Now.AddHours(-9) -NowUtc $script:Now -TargetVersion '3.0.8' | Should -BeFalse
    }
    It 'under 6 hours nothing is cancelled; at 6 hours the run is cancelled and the gate is asked again until the install is free' {
        $w = [pscustomobject]@{ Go = $false; Verdict = 'Wait'; Kind = 'run'; Reason = 'update waits'; RunId = 'r1' }
        $script:Cancels = New-Object System.Collections.Generic.List[string]
        $cancel = { param($id, $v, $why) $script:Cancels.Add(('{0}|{1}' -f $id, $v)); [pscustomobject]@{ Outcome = 'Cancelled'; Text = 'pipeline run r1 cancelled' } }
        $script:Asks = 0
        $again = { $script:Asks++; if ($script:Asks -lt 2) { [pscustomobject]@{ Go = $false; Verdict = 'Wait'; Kind = 'run'; Reason = 'still beating'; RunId = 'r1' } } else { [pscustomobject]@{ Go = $true; Verdict = 'Go'; Kind = ''; Reason = 'the lock is held by this update'; RunId = '' } } }
        $r = Invoke-SIUpdaterOverdueCancel -Gate $w -SinceUtc $script:Now.AddHours(-2) -NowUtc $script:Now -TargetVersion '3.0.8' -Cancel $cancel -GateAgain $again -Sleep { param($s) } -Log { param($m) }
        $r.Go | Should -BeFalse; $script:Cancels.Count | Should -Be 0
        $r = Invoke-SIUpdaterOverdueCancel -Gate $w -SinceUtc $script:Now.AddHours(-7) -NowUtc $script:Now -TargetVersion '3.0.8' -Cancel $cancel -GateAgain $again -Sleep { param($s) } -Log { param($m) }
        $r.Go | Should -BeTrue
        @($script:Cancels) | Should -Be @('r1|3.0.8')
        $script:Asks | Should -Be 2
    }
    It 'a run of the version being installed (SameVersion) is left alone: the update keeps waiting, the gate is not asked again' {
        $w = [pscustomobject]@{ Go = $false; Verdict = 'Wait'; Kind = 'run'; Reason = 'update waits'; RunId = 'r1' }
        $script:Asks = 0
        $r = Invoke-SIUpdaterOverdueCancel -Gate $w -SinceUtc $script:Now.AddHours(-7) -NowUtc $script:Now -TargetVersion '3.0.8' -Sleep { param($s) } -Log { param($m) } `
                 -Cancel { param($id, $v, $why) [pscustomobject]@{ Outcome = 'SameVersion'; Text = 'started on this version' } } -GateAgain { $script:Asks++; [pscustomobject]@{ Go = $true } }
        $r.Go | Should -BeFalse; $script:Asks | Should -Be 0
        # a cancel that throws is the same: nothing changes
        (Invoke-SIUpdaterOverdueCancel -Gate $w -SinceUtc $script:Now.AddHours(-7) -NowUtc $script:Now -TargetVersion '3.0.8' -Sleep { param($s) } -Log { param($m) } -Cancel { throw 'HTTP 403' } -GateAgain { [pscustomobject]@{ Go = $true } }).Go | Should -BeFalse
    }
    It 'the #700 cancel the update runs: an OLD-version run is cancelled; a run of the NEW version, or of another run id, never' {
        $dir = Join-Path ([IO.Path]::GetTempPath()) ('si947c-' + [guid]::NewGuid().ToString('N').Substring(0, 8)); New-Item -ItemType Directory -Path $dir | Out-Null
        try {
            $store = New-SIJobFlowFileStore -Path (Join-Path $dir 'flow-run.json')
            $ctl = New-SIPipelineDocControl -Docs (New-SIPipelineFileDocs -Folder $dir) -Now { $script:Now }
            $def = New-SIDefaultJobFlow -Installed @('ptc', 'identity') -Map (Get-SIJobFlowMap)
            $mk = { param($ver) $r = New-SIJobFlowRunState -Definition $def -NowUtc $script:Now.AddHours(-8) -FlowRunId 'r1' -Version $ver; $r.Steps[0].State = 'Running'; $r.Steps[0].Execution = 'caj-si-ptc-e1'; $r }
            $script:Stops = New-Object System.Collections.Generic.List[string]
            $args0 = @{ Store = $store; Control = $ctl; By = 'the update to 3.0.8'; Reason = 'waited 7 hours'; Self = 'caj-si-updater:u1'; Stop = { param($j, $e) $script:Stops.Add($e) }; Log = { param($l, $m) }; Now = { $script:Now } }
            $store.Save((& $mk '3.0.8'))
            (Invoke-SIPipelineCancelRun @args0 -FlowRunId 'r1' -OtherVersionThan '3.0.8').Outcome | Should -Be 'SameVersion'
            $store.Load().State | Should -Be 'Running'; $script:Stops.Count | Should -Be 0
            $store.Save((& $mk '3.0.5'))
            (Invoke-SIPipelineCancelRun @args0 -FlowRunId 'another' -OtherVersionThan '3.0.8').Outcome | Should -Be 'NotThatRun'
            $x = Invoke-SIPipelineCancelRun @args0 -FlowRunId 'r1' -OtherVersionThan '3.0.8'
            $x.Outcome | Should -Be 'Cancelled'
            $store.Load().State | Should -Be 'Cancelled'
            $store.Load().CancelledBy | Should -Be 'the update to 3.0.8'
            @($script:Stops) | Should -Be @('caj-si-ptc-e1')
        } finally { Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue }
    }
    It 'the updater''s real cancel names the run and the version (only that run, only another version)' {
        $fn = (Get-Command Invoke-SIUpdaterCancelOldRun).Definition
        $fn | Should -Match 'Invoke-SIPipelineCancelRun .*-FlowRunId \$RunId -OtherVersionThan \$TargetVersion'
        $fn | Should -Match ([regex]::Escape('^caj-si-flow-[a-z0-9\-]+$'))
    }
    It 'both updaters ask for the bound at the gate, with the mark''s first time and the version being installed' {
        # every updater edition this copy carries (the Community copy has its own only): each one with a run gate asks for the bound
        $gated = @(Get-ChildItem -LiteralPath (Join-Path $script:SIRoot 'container\updater\_shared') -Filter '*.ps1' | Where-Object { ([IO.File]::ReadAllText($_.FullName)).Contains('$passGate = {') })
        $gated.Count | Should -BeGreaterThan 0
        foreach ($g in $gated) {
            $src = [IO.File]::ReadAllText($g.FullName)
            $src | Should -Match 'Invoke-SIUpdaterOverdueCancel -Gate \$r -SinceUtc \$odSince -NowUtc \$now -TargetVersion \$odTarget -GateAgain \$askGate'
            $src | Should -Match '\$odSince = if \(\$gate\.Tag\) \{ \$gate\.Tag\.SinceUtc \}'
        }
    }
    It 'the runner starts a 6-hour-waiting updater on a busy wake-up too -- at most once an hour, never beside a running updater' {
        $old = [pscustomobject]@{ name = 'u0'; properties = [pscustomobject]@{ status = 'Succeeded'; startTime = $script:Now.AddHours(-8).ToString('o'); endTime = $script:Now.AddHours(-7.9).ToString('o') } }
        (Get-SIPipelineUpdateOverdueStart -Waits (New-Mark 7) -Executions @($old) -NowUtc $script:Now).Start | Should -BeTrue
        (Get-SIPipelineUpdateOverdueStart -Waits (New-Mark 5) -Executions @($old) -NowUtc $script:Now).Start | Should -BeFalse
        (Get-SIPipelineUpdateOverdueStart -Waits (New-Mark 7 'store') -Executions @($old) -NowUtc $script:Now).Start | Should -BeFalse
        (Get-SIPipelineUpdateOverdueStart -Waits $null -Executions @($old) -NowUtc $script:Now).Start | Should -BeFalse
        $running = [pscustomobject]@{ name = 'u1'; properties = [pscustomobject]@{ status = 'Running'; startTime = $script:Now.AddMinutes(-90).ToString('o') } }
        (Get-SIPipelineUpdateOverdueStart -Waits (New-Mark 7) -Executions @($running) -NowUtc $script:Now).Start | Should -BeFalse
        $recent = [pscustomobject]@{ name = 'u2'; properties = [pscustomobject]@{ status = 'Succeeded'; startTime = $script:Now.AddMinutes(-30).ToString('o'); endTime = $script:Now.AddMinutes(-20).ToString('o') } }
        (Get-SIPipelineUpdateOverdueStart -Waits (New-Mark 7) -Executions @($recent) -NowUtc $script:Now).Start | Should -BeFalse
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\flow\Invoke-SIJobFlowRun.ps1'))
        $src.IndexOf('Get-SIPipelineUpdateOverdueStart') | Should -BeGreaterThan 0
        $src.IndexOf('Get-SIPipelineUpdateOverdueStart') | Should -BeLessThan $src.IndexOf('$drain = Invoke-SIPipelineDrain')
    }
}
