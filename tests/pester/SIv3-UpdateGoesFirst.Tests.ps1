#Requires -Version 5.1
<#
    A BUSY INSTALL GETS ITS UPDATE (REQUIREMENTS #947, owner 2026-10-29: "why is it it is so hard to get them updated" / "kill
    all running and get them to latest version NOW"):
      (a) A WAITING UPDATE GOES FIRST -- while the updater's wait mark is set, a run that ends starts no new run (the updater
          is started first), and a scheduled collection collects nothing (it is not the pipeline's own step); while the
          updater installs (it holds the install's lock) a scheduled collection collects nothing either. No mark = as today.
      (b) NO BOUND THAT CANCELS (owner 2026-11-05: "it must not auto cancel a running job due to missing upd" / "it is
          always controlled by operator owner"): an update waits for the run; only the operator or owner stops a run.
    Offline; PS 7. No Azure, no database (fakes and the file store).
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . ([IO.Path]::Combine($script:SIRoot, 'engine', '_shared', 'SI-JobFlow.ps1'))
    . ([IO.Path]::Combine($script:SIRoot, 'engine', '_shared', 'SI-CollectionRunGate.ps1'))
    . ([IO.Path]::Combine($script:SIRoot, 'container', 'updater', '_shared', 'SI-UpdaterRunGate.ps1'))
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

Describe 'An update never cancels a running pipeline -- only the operator or owner stops a run (owner 2026-11-05)' {
    It 'no updater edition cancels a run or carries the wait bound' {
        $files = @(Get-ChildItem -LiteralPath (Join-Path $script:SIRoot 'container\updater') -Recurse -Filter '*.ps1')
        $files.Count | Should -BeGreaterThan 0
        foreach ($g in $files) {
            $src = [IO.File]::ReadAllText($g.FullName)
            $src | Should -Not -Match 'Invoke-SIUpdaterOverdueCancel|Invoke-SIUpdaterCancelOldRun|SI-UpdaterWaitBound|Invoke-SIPipelineCancelRun' -Because "$($g.Name): an update waits for the run, it never cancels one"
        }
        Test-Path -LiteralPath (Join-Path $script:SIRoot 'container\updater\_shared\SI-UpdaterWaitBound.ps1') | Should -BeFalse
    }
    It 'the pipeline runner never starts the updater to cut a running run short' {
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\flow\Invoke-SIJobFlowRun.ps1'))
        $src | Should -Not -Match 'Get-SIPipelineUpdateOverdueStart' -Because 'the updater is started only between runs (when a run has ended), never to cut one short'
        Get-Command -Name Get-SIPipelineUpdateOverdueStart -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
    }
    It 'the operator''s cancel (#700, Stop-SIRunAndUpdate): -OtherVersionThan cancels an OLD-version run, never a run of the new version or another run id' {
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
}