#Requires -Version 5.1
<#
    #1395 LAST-RUN-1 -- the heartbeat's LastRun (engine/_shared/SI-HeartbeatFields.ps1). Owner 2026-11-26: "complete last run
    time" / "also time for each phase and total" / "why dont we have this in telemetry" / "if missing add to next build".
    Invardia accepted the shape (soft; its wire contract is closed) and its parser carries it live (heartbeatstate.ts
    SI_HEARTBEAT_CONTRACT.LastRun, steps max 40 since 844f8562) -- #1423 (3.1.53) sends it on every ring:

      LastRun { runId, kind, startedUtc, endedUtc, totalSec, result, collectionUtc, steps[<= 40] { step, startedUtc, sec, result } }

    What must hold:
      - the shape: only the contract's keys, in its order, EACH ONLY WHEN KNOWN (never null -- #1423); the closed lists and
        the patterns are Invardia's (pinned below against a copy of its contract); steps capped at 40 -- over it the most
        relevant (failed, cancelled, the newest that ran, skipped last), sent in run order, the others named;
      - a cancelled run, a failed step, a partial run, each kind of start;
      - no finished run / a read that fails = the field is LEFT OUT (never made-up values), never the heartbeat;
      - the send gate: auto = every ring; SI_Uplink_SendLastRun off / a ring list;
      - Published is unchanged;
      - REAL SQL (when the runner has one): the read against the shipped schema and an older one.
#>

BeforeDiscovery {
    # the REAL SQL part sets its SQL up itself (review 2026-11-27): on the Linux test runner TEST_SQL_* name the SQL sidecar
    # (_SITestSql.ps1 Initialize-SITestSqlEnv, as the gate's shard does) -- a plain Invoke-Pester of this file runs it too. A
    # SI_TEST_LOCALSQL set by hand is kept; without either the part is skipped (said by Pester as skipped, never green).
    if (-not $env:SI_TEST_LOCALSQL) {
        $sqlHelper = Join-Path $PSScriptRoot '_SITestSql.ps1'
        if (Test-Path -LiteralPath $sqlHelper) { . $sqlHelper; $null = Initialize-SITestSqlEnv }
    }
    $script:HasSql = [bool]($env:SI_TEST_LOCALSQL)
}

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\_shared\SI-HeartbeatJob.ps1')
    $script:Now = [datetime]::SpecifyKind([datetime]'2026-11-26T10:00:00', [DateTimeKind]::Utc)
    $script:T0 = $script:Now.AddHours(-9)
    function script:RunRow([string]$Id = 'flow-20261126-0100', [string]$State = 'Succeeded', [string]$Trg = 'schedule', [string]$Scope = 'pipeline', [string]$FromStep = $null, $Start = $script:T0, $End = $script:T0.AddHours(7).AddMinutes(30)) {
        [pscustomobject]@{ K = 'run'; Id = $Id; S = $State; Trg = $Trg; FromStep = $FromStep; Scope = $Scope; T1 = $Start; T2 = $End; N1 = $null; Job = $null; Txt = $null }
    }
    function script:StepRow([int]$Order, [string]$Job, [string]$State = 'Success', $Start = $null, $End = $null, [string]$Cls = $null, [string]$Id = 'flow-20261126-0100', $Attempts = 1) {
        [pscustomobject]@{ K = 'step'; Id = $Id; S = $State; Trg = $null; FromStep = $null; Scope = $null; T1 = $Start; T2 = $End; N1 = $Order; N2 = $Attempts; Job = $Job; Txt = $Cls }
    }
    $t = $script:T0
    $script:Rows = @(
        (RunRow),
        # deliberately NOT in run order: the read gives the run first, its steps after, in any order
        (StepRow 3 'risk-analysis-detailed' 'Success' $t.AddHours(2) $t.AddHours(6)),
        (StepRow 1 'caj-si-identity' 'Success' $t $t.AddMinutes(40)),
        (StepRow 2 'endpoint' 'Success' $t.AddMinutes(40) $t.AddHours(2)),
        (StepRow 4 'close-loop-mail' 'Disabled'),
        (StepRow 5 'asset-datasync' 'Success' $t.AddHours(6) $t.AddHours(7).AddMinutes(30)))
    $script:Pub = @([pscustomobject]@{ FlowRunId = 'flow-20261126-0100'; CollectionTime = $t.AddHours(2).AddMinutes(5) })
}

AfterAll { Remove-Variable -Name SI_Uplink_SendLastRun -Scope Global -ErrorAction SilentlyContinue; [Environment]::SetEnvironmentVariable('SI_UPLINK_SENDLASTRUN', $null) }

Describe '#1395 LastRun -- the last finished pipeline run on the heartbeat' {
AfterEach {
    Remove-Variable -Name SI_Uplink_SendLastRun -Scope Global -ErrorAction SilentlyContinue; [Environment]::SetEnvironmentVariable('SI_UPLINK_SENDLASTRUN', $null)
    $global:SI_HeartbeatFieldProblemsSaid = $null; $global:SI_HeartbeatJobWarned = $null; $global:SI_UplinkCausesWarned = $null
}

Describe 'the shape is exactly the one Invardia accepted' {
    It 'the keys, in order; the run and every step' {
        $v = Get-SIHeartbeatLastRun -Rows $script:Rows -PublishedRows $script:Pub
        @($v.PSObject.Properties.Name) | Should -Be @('runId', 'kind', 'startedUtc', 'endedUtc', 'totalSec', 'result', 'collectionUtc', 'steps')
        $v.runId | Should -BeExactly 'flow-20261126-0100'
        $v.kind | Should -BeExactly 'scheduled'
        $v.startedUtc | Should -BeExactly '2026-11-26T01:00:00Z'
        $v.endedUtc | Should -BeExactly '2026-11-26T08:30:00Z'
        $v.totalSec | Should -Be 27000
        $v.totalSec | Should -BeOfType [long]
        $v.result | Should -BeExactly 'complete' -Because 'a disabled step is not a failure'
        $v.collectionUtc | Should -BeExactly '2026-11-26T03:05:00Z' -Because 'this run published the collection customers see'
        ($v.steps -is [array]) | Should -BeTrue
        @($v.steps).Count | Should -Be 5
        @($v.steps | ForEach-Object { $_.step }) | Should -Be @('identity', 'endpoint', 'risk-analysis-detailed', 'close-loop-mail', 'asset-datasync') -Because 'run order (StepOrder), the job as its short key'
        foreach ($i in 0, 1, 2, 4) { @($v.steps[$i].PSObject.Properties.Name) | Should -Be @('step', 'startedUtc', 'sec', 'result') }
        @($v.steps[3].PSObject.Properties.Name) | Should -Be @('step', 'result') -Because '#1423: a disabled step never started -- its start and seconds are LEFT OUT, never null, never made up'
        $v.steps[0].startedUtc | Should -BeExactly '2026-11-26T01:00:00Z'
        $v.steps[0].sec | Should -Be 2400
        $v.steps[0].result | Should -BeExactly 'ok'
        $v.steps[3].result | Should -BeExactly 'skipped'
        Test-SIHeartbeatField -Name 'LastRun' -Value $v | Should -BeNullOrEmpty
    }
    It 'the JSON on the wire: steps stay an array (also with one step), every value its type, nothing null' {
        $one = @((RunRow), (StepRow 1 'identity' 'Success' $script:T0 $script:T0.AddMinutes(1)))
        $v = Get-SIHeartbeatLastRun -Rows $one -PublishedRows @()
        $j = $v | ConvertTo-Json -Depth 6 -Compress
        $j | Should -BeExactly '{"runId":"flow-20261126-0100","kind":"scheduled","startedUtc":"2026-11-26T01:00:00Z","endedUtc":"2026-11-26T08:30:00Z","totalSec":27000,"result":"complete","steps":[{"step":"identity","startedUtc":"2026-11-26T01:00:00Z","sec":60,"result":"ok"}]}' -Because 'nothing published by this run: collectionUtc is LEFT OUT'
        $j | Should -Not -Match 'null'
    }
    It '#1423: a run with nothing known but its steps: only steps; a run without step rows: steps []' {
        $v = Get-SIHeartbeatLastRun -Rows @((RunRow -Id 'bad id!' -State 'Weird' -Trg 'unknown-trigger' -Start $null -End $null)) -PublishedRows @()
        @($v.PSObject.Properties.Name) | Should -Be @('steps')
        ($v | ConvertTo-Json -Depth 6 -Compress) | Should -BeExactly '{"steps":[]}'
        Test-SIHeartbeatField -Name 'LastRun' -Value $v | Should -BeNullOrEmpty
    }
    It '#1423: the key set is EXACTLY Invardia''s contract (a copy of SI_HEARTBEAT_CONTRACT.LastRun, heartbeatstate.ts)' {
        # Invardia packages/core/src/heartbeatstate.ts (read 2026-11-26, 844f8562):
        #   LastRun: soft({ t: 'obj', fields: { runId: str<=80 /^[A-Za-z0-9._:-]{1,80}$/, kind: oneOf(full|manual|scheduled|resume),
        #     startedUtc: iso, endedUtc: iso, totalSec: int, result: oneOf(complete|cancelled|failed|partial), collectionUtc: iso,
        #     steps: arr max 40 of { step: str<=60 /^[A-Za-z0-9._-]{1,60}$/ req, startedUtc: iso, sec: int, result: oneOf(ok|failed|skipped|cancelled) } } })
        $c = Get-SIHeartbeatFieldsContract
        #   + version: soft(version) (FLEET-TELEMETRY-1, Invardia 9f8e838, live 2026-11-27)
        $c.Fields.LastRun | Should -Be @('runId', 'kind', 'startedUtc', 'endedUtc', 'totalSec', 'result', 'collectionUtc', 'steps', 'version')
        $c.LastRunStepFields | Should -Be @('step', 'startedUtc', 'sec', 'result')
        $c.LastRunKinds | Should -Be @('full', 'manual', 'scheduled', 'resume')
        $c.LastRunResults | Should -Be @('complete', 'cancelled', 'failed', 'partial')
        $c.LastRunStepResults | Should -Be @('ok', 'failed', 'skipped', 'cancelled')
        $c.MaxLastRunSteps | Should -Be 40
        $c.LastRunIdMax | Should -Be 80
        # every value SI can produce matches Invardia's patterns (its parser re-checks each; a bad one drops LastRun)
        $iso = '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d{1,7})?)?(Z|[+-]\d{2}:\d{2})$'
        $v = Get-SIHeartbeatLastRun -Rows $script:Rows -PublishedRows $script:Pub
        $v.runId | Should -Match '^[A-Za-z0-9._:-]{1,80}$'
        foreach ($t in 'startedUtc', 'endedUtc', 'collectionUtc') { $v.$t | Should -Match $iso }
        foreach ($s in $v.steps) { $s.step | Should -Match '^[A-Za-z0-9._-]{1,60}$'; if ($s.PSObject.Properties['startedUtc']) { $s.startedUtc | Should -Match $iso }; if ($s.PSObject.Properties['sec']) { $s.sec | Should -BeGreaterOrEqual 0 } }
        ($v.totalSec -is [long] -or $v.totalSec -is [int]) | Should -BeTrue
    }
    It 'the validator refuses what Invardia refuses' {
        # a fresh value per case (a JSON round trip would turn the time strings into [datetime] on PowerShell 7)
        $bad = { param([scriptblock]$Change) $x = Get-SIHeartbeatLastRun -Rows $script:Rows -PublishedRows $script:Pub; & $Change $x; Test-SIHeartbeatField -Name 'LastRun' -Value $x }
        & $bad { param($x) $x.kind = 'daily' } | Should -Match 'kind'
        & $bad { param($x) $x.result = 'succeeded' } | Should -Match 'result'
        & $bad { param($x) $x.startedUtc = '2026-11-26 01:00' } | Should -Match 'startedUtc'
        & $bad { param($x) $x.totalSec = -1 } | Should -Match 'totalSec'
        & $bad { param($x) $x.runId = ('x' * 81) } | Should -Match 'runId'
        & $bad { param($x) $x.steps[0].result = 'success' } | Should -Match 'steps.result'
        & $bad { param($x) $x.steps[0].step = 'Caj_Identity' } | Should -Match 'job key'
        & $bad { param($x) $x | Add-Member -NotePropertyName extra -NotePropertyValue 1 } | Should -Match 'agreed'
        & $bad { param($x) $x.steps = @(1..41 | ForEach-Object { [pscustomobject][ordered]@{ step = "s$_"; result = 'ok' } }) } | Should -Match 'at most 40'
        & $bad { param($x) $x.kind = $null } | Should -Match 'kind is null' -Because '#1423: a value that is not known is left out, never null'
        & $bad { param($x) $x.steps[0].sec = $null } | Should -Match 'sec is null'
        & $bad { param($x) $x.PSObject.Properties.Remove('steps') } | Should -Match 'steps is missing'
        & $bad { param($x) $x.steps[0].PSObject.Properties.Remove('step') } | Should -Match 'step is missing'
        # the agreed order: a key out of order is refused
        & $bad { param($x) $r = $x.runId; $x.PSObject.Properties.Remove('runId'); $x | Add-Member -NotePropertyName runId -NotePropertyValue $r } | Should -Match 'agreed'
        Test-SIHeartbeatField -Name 'LastRun' -Value $null | Should -Match 'leave the field out'
    }
}

Describe 'how the run ended and how it was started' {
    It 'a cancelled run: result cancelled, its not-run steps cancelled, the steps that ran keep their result' {
        $t = $script:T0
        $rows = @((RunRow -State 'Cancelled' -Trg 'manual' -End $t.AddHours(3)),
                  (StepRow 1 'identity' 'Success' $t $t.AddMinutes(40)),
                  # what the cancel paths write (SI-JobFlow Stop / SI-Pipeline cancel): Interrupted, class 'cancelled'
                  (StepRow 2 'endpoint' 'Interrupted' $t.AddMinutes(40) $t.AddHours(3) 'cancelled'),
                  (StepRow 3 'risk-analysis-detailed' 'Skipped' $null $null 'cancelled'),
                  (StepRow 4 'asset-datasync' 'Waiting'))
        $v = Get-SIHeartbeatLastRun -Rows $rows -PublishedRows $script:Pub
        $v.result | Should -BeExactly 'cancelled'
        $v.kind | Should -BeExactly 'full' -Because 'a person started the whole pipeline'
        $v.totalSec | Should -Be 10800
        @($v.steps | ForEach-Object { $_.result }) | Should -Be @('ok', 'cancelled', 'cancelled', 'cancelled') -Because 'a step the cancel closed did not fail'
        Test-SIHeartbeatField -Name 'LastRun' -Value $v | Should -BeNullOrEmpty
    }
    It 'a step stopped from outside the pipeline (Interrupted, class stopped) is cancelled; FLEET-STATUS-1: a run whose only failures are such is FAILED (killed, not cancelled the product''s way)' {
        $t = $script:T0
        ConvertTo-SIHeartbeatLastRunStepResult -State 'Interrupted' -ErrorClass 'stopped' -RunState 'Failed' | Should -BeExactly 'cancelled'
        ConvertTo-SIHeartbeatLastRunStepResult -State 'Interrupted' -ErrorClass 'interrupted' -RunState 'Failed' | Should -BeExactly 'failed' -Because 'the runner stopped while starting it -- not on purpose'
        ConvertTo-SIHeartbeatLastRunStepResult -State 'TimedOut' -ErrorClass '' -RunState 'Failed' | Should -BeExactly 'failed'
        $rows = @((RunRow -State 'Failed'), (StepRow 1 'identity' 'Success' $t $t.AddMinutes(40)),
                  (StepRow 2 'endpoint' 'Interrupted' $t.AddMinutes(40) $t.AddHours(1) 'stopped'), (StepRow 3 'risk-analysis-detailed' 'Skipped' $null $null 'flow-stopped'))
        $v = Get-SIHeartbeatLastRun -Rows $rows -PublishedRows @()
        $v.result | Should -BeExactly 'failed' -Because 'FLEET-STATUS-1 (Invardia 2026-11-27): cancelled only for a run cancelled the product''s way; executions stopped from outside = a killed run = failed'
        @($v.steps | ForEach-Object { $_.result }) | Should -Be @('ok', 'cancelled', 'cancelled')
        # one real failure beside it: failed
        $rows2 = $rows + @((StepRow 4 'close-loop-mail' 'Failed' $t $t.AddMinutes(2) 'graph-403'))
        (Get-SIHeartbeatLastRun -Rows $rows2 -PublishedRows @()).result | Should -BeExactly 'failed'
    }
    It 'a failed run: result failed, the failed step says failed with its own start and seconds' {
        $t = $script:T0
        $rows = @((RunRow -State 'Failed'), (StepRow 1 'identity' 'Success' $t $t.AddMinutes(40)),
                  (StepRow 2 'endpoint' 'Failed' $t.AddMinutes(40) $t.AddMinutes(55) 'graph-403'),
                  (StepRow 3 'risk-analysis-detailed' 'Skipped' $null $null 'needs-failed'))
        $v = Get-SIHeartbeatLastRun -Rows $rows -PublishedRows @()
        $v.result | Should -BeExactly 'failed'
        $v.steps[1].result | Should -BeExactly 'failed'
        $v.steps[1].startedUtc | Should -BeExactly '2026-11-26T01:40:00Z'
        $v.steps[1].sec | Should -Be 900
        $v.steps[2].result | Should -BeExactly 'skipped'
        Test-SIHeartbeatField -Name 'LastRun' -Value $v | Should -BeNullOrEmpty
    }
    It 'a run the runner called succeeded while a step failed or was held back: partial' {
        $t = $script:T0
        (Get-SIHeartbeatLastRun -Rows @((RunRow), (StepRow 1 'identity'), (StepRow 2 'close-loop-mail' 'Failed' $t $t)) -PublishedRows @()).result | Should -BeExactly 'partial'
        (Get-SIHeartbeatLastRun -Rows @((RunRow), (StepRow 1 'identity'), (StepRow 2 'data-out' 'Skipped' $null $null 'source-too-old')) -PublishedRows @()).result | Should -BeExactly 'partial'
        (Get-SIHeartbeatLastRun -Rows @((RunRow), (StepRow 1 'identity' 'Skipped' $null $null 'before-rerun'), (StepRow 2 'endpoint')) -PublishedRows @()).result | Should -BeExactly 'complete'
    }
    It 'kind: schedule / catch-up = scheduled, a re-run from a step = resume, a person: whole pipeline = full, a stage / step = manual' {
        ConvertTo-SIHeartbeatLastRunKind -Trigger 'schedule' -Scope 'pipeline' | Should -BeExactly 'scheduled'
        ConvertTo-SIHeartbeatLastRunKind -Trigger 'catch-up' -Scope $null | Should -BeExactly 'scheduled'
        ConvertTo-SIHeartbeatLastRunKind -Trigger 'interval' -Scope 'pipeline' | Should -BeExactly 'scheduled' -Because 'the interval cadence (Get-SIJobFlowDue) is the schedule too'
        ConvertTo-SIHeartbeatLastRunKind -Trigger 'rerun' -Scope 'pipeline' -FromStep 'risk-analysis-detailed' | Should -BeExactly 'resume'
        ConvertTo-SIHeartbeatLastRunKind -Trigger 'manual' -Scope 'from-step' | Should -BeExactly 'resume'
        ConvertTo-SIHeartbeatLastRunKind -Trigger 'manual' -Scope 'pipeline' | Should -BeExactly 'full'
        ConvertTo-SIHeartbeatLastRunKind -Trigger 'manual' -Scope $null | Should -BeExactly 'full' -Because 'an older schema has no Scope: the whole pipeline'
        ConvertTo-SIHeartbeatLastRunKind -Trigger 'manual' -Scope 'stage' | Should -BeExactly 'manual'
        ConvertTo-SIHeartbeatLastRunKind -Trigger 'manual' -Scope 'step' | Should -BeExactly 'manual'
        ConvertTo-SIHeartbeatLastRunKind -Trigger 'something-new' -Scope 'pipeline' | Should -BeNullOrEmpty -Because 'never a guessed kind'
    }
    It 'a person''s run of ONE stage or step is never the last run (the whole pipeline only)' {
        Get-SIHeartbeatLastRun -Rows @((RunRow -Trg 'manual' -Scope 'stage'), (StepRow 1 'identity')) -PublishedRows @() | Should -BeNullOrEmpty
        Get-SIHeartbeatLastRun -Rows @((RunRow -Trg 'manual' -Scope 'step'), (StepRow 1 'identity')) -PublishedRows @() | Should -BeNullOrEmpty
        (Get-SIHeartbeatLastRun -Rows @((RunRow -Trg 'rerun' -Scope 'from-step' -FromStep 'endpoint'), (StepRow 1 'endpoint')) -PublishedRows @()).kind | Should -BeExactly 'resume'
        (Get-SIHeartbeatLastRun -Rows @((RunRow -Trg 'manual' -Scope $null), (StepRow 1 'identity')) -PublishedRows @()).kind | Should -BeExactly 'full'
    }
    It 'a step started AGAIN (Attempts > 1): startedUtc and sec NULL; its result and the run''s totalSec unchanged; Attempts NULL / missing = kept' {
        $t = $script:T0
        $rows = @((RunRow), (StepRow 1 'identity' 'Success' $t $t.AddMinutes(40)),
                  (StepRow 2 'endpoint' 'Success' $t.AddHours(2) $t.AddHours(3) -Attempts 2),
                  (StepRow 3 'risk-analysis-detailed' 'Failed' $t.AddHours(3) $t.AddHours(4) 'graph-403' -Attempts 3),
                  (StepRow 4 'asset-datasync' 'Success' $t.AddHours(4) $t.AddHours(5) -Attempts $null),
                  (StepRow 5 'close-loop-mail' 'Success' $t.AddHours(5) $t.AddHours(5).AddMinutes(1) -Attempts ([DBNull]::Value)))
        $v = Get-SIHeartbeatLastRun -Rows $rows -PublishedRows @()
        $v.steps[0].startedUtc | Should -BeExactly '2026-11-26T01:00:00Z'; $v.steps[0].sec | Should -Be 2400
        @($v.steps[1].PSObject.Properties.Name) | Should -Be @('step', 'result') -Because '#1423: not known = left out'
        $v.steps[1].result | Should -BeExactly 'ok'
        @($v.steps[2].PSObject.Properties.Name) | Should -Be @('step', 'result')
        $v.steps[2].result | Should -BeExactly 'failed'
        $v.steps[3].startedUtc | Should -BeExactly '2026-11-26T05:00:00Z' -Because 'Attempts not recorded: the times are kept'
        $v.steps[3].sec | Should -Be 3600
        $v.steps[4].sec | Should -Be 60
        $v.totalSec | Should -Be 27000
        $v.result | Should -BeExactly 'partial'
        # rows without the column at all (an older schema's read): kept
        $old = @((RunRow), ([pscustomobject]@{ K = 'step'; Id = 'x'; S = 'Success'; T1 = $t; T2 = $t.AddMinutes(5); N1 = 1; Job = 'identity'; Txt = $null }))
        (Get-SIHeartbeatLastRun -Rows $old -PublishedRows @()).steps[0].sec | Should -Be 300
        Test-SIHeartbeatField -Name 'LastRun' -Value $v | Should -BeNullOrEmpty
        $j = $v | ConvertTo-Json -Depth 6 -Compress
        $j | Should -Match '\{"step":"endpoint","result":"ok"\}'
        $j | Should -Not -Match 'null'
    }
    It 'a job name that is not a key is MADE one, never dropped' {
        ConvertTo-SIHeartbeatStepSlug -Job 'caj-si-Risk_Analysis Detailed' | Should -BeExactly 'risk-analysis-detailed'
        ConvertTo-SIHeartbeatStepSlug -Job ('x' * 70) | Should -BeExactly ('x' * 60)
        ConvertTo-SIHeartbeatStepSlug -Job '__' -Order 4 | Should -BeExactly 'step-4'
        ConvertTo-SIHeartbeatStepSlug -Job 'identity' | Should -BeExactly 'identity'
        $v = Get-SIHeartbeatLastRun -Rows @((RunRow), (StepRow 1 'Identity_Sync'), (StepRow 2 'endpoint')) -PublishedRows @()
        @($v.steps | ForEach-Object { $_.step }) | Should -Be @('identity-sync', 'endpoint')
        Test-SIHeartbeatField -Name 'LastRun' -Value $v | Should -BeNullOrEmpty
    }
    It 'collectionUtc only when THIS run published the shown collection' {
        (Get-SIHeartbeatLastRun -Rows $script:Rows -PublishedRows @([pscustomobject]@{ FlowRunId = 'flow-older'; CollectionTime = $script:T0 })).collectionUtc | Should -BeNullOrEmpty
        (Get-SIHeartbeatLastRun -Rows $script:Rows -PublishedRows $null).collectionUtc | Should -BeNullOrEmpty -Because 'the data database was not read: not known'
        (Get-SIHeartbeatLastRun -Rows $script:Rows -PublishedRows @([pscustomobject]@{ FlowRunId = [DBNull]::Value; CollectionTime = $script:T0 })).collectionUtc | Should -BeNullOrEmpty
    }
}

Describe '#1423 more than 40 steps: the most relevant 40, in run order' {
    It 'all ran fine: the NEWEST 40 go, in run order; the oldest are named' {
        $t = $script:T0
        $rows = @((RunRow)) + @(45..1 | ForEach-Object { StepRow $_ ('step-{0:00}' -f $_) 'Success' $t.AddMinutes($_) $t.AddMinutes($_ + 1) })
        $left = New-Object System.Collections.Generic.List[string]
        $v = Get-SIHeartbeatLastRun -Rows $rows -PublishedRows @() -LeftOut $left
        @($v.steps).Count | Should -Be 40
        $v.steps[0].step | Should -BeExactly 'step-06'
        $v.steps[39].step | Should -BeExactly 'step-45'
        @($left) | Should -Be @('step-01', 'step-02', 'step-03', 'step-04', 'step-05')
        Test-SIHeartbeatField -Name 'LastRun' -Value $v | Should -BeNullOrEmpty
    }
    It 'a failed and a cancelled OLD step are kept before newer ok steps; skipped steps go first; the order stays the run''s' {
        $t = $script:T0
        $rows = @((RunRow -State 'Failed')) + @(1..44 | ForEach-Object {
            $st = switch ($_) { 1 { 'Failed' } 2 { 'Interrupted' } { $_ -in 40, 41, 42 } { 'Skipped' } default { 'Success' } }
            $cls = switch ($_) { 1 { 'graph-403' } 2 { 'cancelled' } { $_ -in 40, 41, 42 } { 'needs-failed' } default { $null } }
            StepRow $_ ('step-{0:00}' -f $_) $st $t.AddMinutes($_) $t.AddMinutes($_ + 1) $cls })
        $left = New-Object System.Collections.Generic.List[string]
        $v = Get-SIHeartbeatLastRun -Rows $rows -PublishedRows @() -LeftOut $left
        @($v.steps).Count | Should -Be 40
        $v.steps[0].step | Should -BeExactly 'step-01'; $v.steps[0].result | Should -BeExactly 'failed'
        $v.steps[1].step | Should -BeExactly 'step-02'; $v.steps[1].result | Should -BeExactly 'cancelled'
        @($left) | Should -Be @('step-03', 'step-40', 'step-41', 'step-42') -Because 'the three skipped steps first, then the oldest ok step'
        $orders = @($v.steps | ForEach-Object { [int]($_.step -replace 'step-', '') })
        ($orders -join ',') | Should -BeExactly ((@($orders | Sort-Object)) -join ',') -Because 'sent in run order'
        Test-SIHeartbeatField -Name 'LastRun' -Value $v | Should -BeNullOrEmpty
    }
    It '40 steps or fewer: nothing left out, every step in run order' {
        $t = $script:T0
        $left = New-Object System.Collections.Generic.List[string]
        $v = Get-SIHeartbeatLastRun -Rows (@((RunRow)) + @(40..1 | ForEach-Object { StepRow $_ ('step-{0:00}' -f $_) 'Success' $t $t })) -PublishedRows @() -LeftOut $left
        @($v.steps).Count | Should -Be 40
        $v.steps[0].step | Should -BeExactly 'step-01'
        $left.Count | Should -Be 0
    }
    It 'the steps left out are SAID once a day (the 00:00 half hour), never dropped silently' {
        $t = $script:T0
        $rows = @((RunRow)) + @(1..42 | ForEach-Object { StepRow $_ ('step-{0:00}' -f $_) 'Success' $t $t })
        $say = { param([datetime]$At) $l = New-Object System.Collections.Generic.List[string]
                 $f = New-SIHeartbeatFields -Ring 0 -NowUtc $At -Switch @{ LastRun = $true } -LastRunRows $rows -Log { param($x) $l.Add($x) }.GetNewClosure(); @{ F = $f; Lines = $l } }
        $global:SI_HeartbeatLastRunCapSaid = $null
        # the shared once-per-process problems line is already taken: the cap line is its OWN line and still comes
        $global:SI_HeartbeatFieldProblemsSaid = $true
        $a = & $say ([datetime]::SpecifyKind([datetime]'2026-11-26T00:07:00', [DateTimeKind]::Utc))
        @($a.F['LastRun'].steps).Count | Should -Be 40
        $a.Lines.Count | Should -Be 1
        $a.Lines[0] | Should -Match 'LastRun has room for 40 steps -- not in it: step-01, step-02'
        $a2 = & $say ([datetime]::SpecifyKind([datetime]'2026-11-26T00:22:00', [DateTimeKind]::Utc))
        $a2.Lines.Count | Should -Be 0 -Because 'once per UTC day'
        $b = & $say ([datetime]::SpecifyKind([datetime]'2026-11-26T10:07:00', [DateTimeKind]::Utc))
        @($b.F['LastRun'].steps).Count | Should -Be 40
        $b.Lines.Count | Should -Be 0 -Because 'said once a day, not on every heartbeat'
        $c = & $say ([datetime]::SpecifyKind([datetime]'2026-11-27T00:07:00', [DateTimeKind]::Utc))
        $c.Lines.Count | Should -Be 1 -Because 'the next UTC day says it again'
        $global:SI_HeartbeatLastRunCapSaid = $null
    }
}

Describe 'no finished run or a read that fails: LastRun is LEFT OUT, never the heartbeat' {
    It 'no rows (no finished run yet) / not read: null -- left out' {
        Get-SIHeartbeatLastRun -Rows @() -PublishedRows @() | Should -BeNullOrEmpty
        Get-SIHeartbeatLastRun -Rows $null -PublishedRows @() | Should -BeNullOrEmpty
        Get-SIHeartbeatLastRun -Rows @((StepRow 1 'identity')) -PublishedRows @() | Should -BeNullOrEmpty -Because 'steps without their run are not a run'
        $f = New-SIHeartbeatFields -Ring 0 -NowUtc $script:Now -Switch @{ LastRun = $true } -LastRunRows @() -Log { param($l) }
        $f.Contains('LastRun') | Should -BeFalse
    }
    It 'the read fails: LastRun is left out and said once; the other fields and the heartbeat still go' {
        Mock Get-SIHeartbeatLastRun { throw 'database down' }
        $lines = New-Object System.Collections.Generic.List[string]
        $f = New-SIHeartbeatFields -Ring 0 -NowUtc $script:Now -Switch @{ LastRun = $true; UplinkBacklog = $true } -LastRunRows $script:Rows -UplinkBacklogRows @([pscustomobject]@{ Pending = 0; OldestUtc = $null }) -Log { param($l) $lines.Add($l) }.GetNewClosure()
        $f.Contains('LastRun') | Should -BeFalse
        $f.Contains('UplinkBacklog') | Should -BeTrue
        $lines.Count | Should -Be 1
        $lines[0] | Should -Match 'LastRun could not be read \(database down\)'
        $global:SI_HeartbeatFieldProblemsSaid = $null
        $t = New-Object System.Collections.Generic.List[string]
        $tr = { param($Record, $Endpoint, $AccessCode, $TimeoutSec) $t.Add(($Record | ConvertTo-Json -Depth 10 -Compress)); [pscustomobject]@{ Status = 'ok'; Reason = 'ok'; SupersededBy = '' } }.GetNewClosure()
        $ctx = [pscustomobject]@{ Mode = 'identified'; Endpoint = 'https://stub.example.test/report'; AccessCode = 'inv-TESTKEYabcdefghijklmnopqrstuvwxyz'; Edition = 'pro'; LicenceState = 'valid'
                   Version = '3.1.52'; Hosting = 'container'; RuntimeIdentity = 'mi-container'; Ring = 0; InstallId = ''; TenantId = '7f3e2a10-4b5c-4d6e-8f90-a1b2c3d4e5f6'; StateDirectory = ''
                   EnvironmentName = 'Contoso'; LicenceId = ''; Endpoints = @(); AnonymousReason = '' }
        $r = Send-SIHeartbeatTick -Context $ctx -Transport $tr -Now $script:Now -HeartbeatCounts { @{} } -FieldSwitch @{ LastRun = $true } -LastRunRows $script:Rows 6>$null
        $r.Status | Should -Be 'sent'
        $t.Count | Should -Be 1
        $t[0] | Should -Not -Match '"LastRun":'
        $t[0] | Should -Match '"Kind":"heartbeat"'
    }
    It 'the settings database is not reachable in production: the read throws inside the field''s own try, never past it' {
        # outside a test session LastRun reads through -CfgInvoke; the read sits inside the field loop's try (the source)
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\_shared\SI-HeartbeatFields.ps1'))
        $src | Should -Match ([regex]::Escape("`$lr = @(& `$CfgInvoke (Get-SIHeartbeatLastRunSql) @{} 'reader'"))
        $src | Should -Match ([regex]::Escape("`$lp = @(& `$DataInvoke (Get-SIHeartbeatLastRunPublishedSql) @{} 'rows'"))
    }
    It 'the data read of the published collection throws: LastRun still goes, collectionUtc null' {
        # (the pure builder takes $null = not read)
        $v = Get-SIHeartbeatLastRun -Rows $script:Rows -PublishedRows $null
        $v.collectionUtc | Should -BeNullOrEmpty
        $v.runId | Should -BeExactly 'flow-20261126-0100'
    }
}

Describe '#1423 the send gate: Invardia''s parser has it live -- sent on every ring' {
    It 'auto = EVERY ring; off / a ring list per install' {
        @((Get-SIHeartbeatFieldsContract).ConfirmedRings['LastRun']) | Should -Be @(0, 1, 2, 3)
        foreach ($r in 0, 1, 2, 3) { (Resolve-SIUplinkHeartbeatFieldSwitch -Field 'LastRun' -Ring $r -Value $null -EnvValue '').On | Should -BeTrue }
        (Resolve-SIUplinkHeartbeatFieldSwitch -Field 'LastRun' -Ring $null -Value $null -EnvValue '').On | Should -BeFalse -Because 'an unknown ring sends only on an explicit on'
        (Resolve-SIUplinkHeartbeatFieldSwitch -Field 'LastRun' -Ring 2 -Value 'off').On | Should -BeFalse
        (Resolve-SIUplinkHeartbeatFieldSwitch -Field 'LastRun' -Ring 0 -Value $null -EnvValue '0').On | Should -BeTrue
        (Resolve-SIUplinkHeartbeatFieldSwitch -Field 'LastRun' -Ring 1 -Value $null -EnvValue '0').On | Should -BeFalse
    }
    It 'the tick: on by default (LastRun on the record, exactly the shape); off = no LastRun' {
        $mk = { $t = New-Object System.Collections.Generic.List[string]; $tr = { param($Record, $Endpoint, $AccessCode, $TimeoutSec) $t.Add(($Record | ConvertTo-Json -Depth 10 -Compress)); [pscustomobject]@{ Status = 'ok'; Reason = 'ok'; SupersededBy = '' } }.GetNewClosure(); @{ Sent = $t; Tr = $tr } }
        $ctx = [pscustomobject]@{ Mode = 'identified'; Endpoint = 'https://stub.example.test/report'; AccessCode = 'inv-TESTKEYabcdefghijklmnopqrstuvwxyz'; Edition = 'pro'; LicenceState = 'valid'
                   Version = '3.1.52'; Hosting = 'container'; RuntimeIdentity = 'mi-container'; Ring = 0; InstallId = ''; TenantId = '7f3e2a10-4b5c-4d6e-8f90-a1b2c3d4e5f6'; StateDirectory = ''
                   EnvironmentName = 'Contoso'; LicenceId = ''; Endpoints = @(); AnonymousReason = '' }
        $a = & $mk
        $r = Send-SIHeartbeatTick -Context $ctx -Transport $a.Tr -Now $script:Now -HeartbeatCounts { @{} } -LastRunRows $script:Rows -LastRunPublishedRows $script:Pub 6>$null
        $r.Status | Should -Be 'sent'
        $a.Sent[0] | Should -Match '"LastRun":\{"runId":"flow-20261126-0100","kind":"scheduled","startedUtc":"2026-11-26T01:00:00Z","endedUtc":"2026-11-26T08:30:00Z","totalSec":27000,"result":"complete","collectionUtc":"2026-11-26T03:05:00Z","steps":\[' -Because '#1423: auto = every ring'
        Test-SIHeartbeatField -Name 'LastRun' -Value $r.Record.LastRun | Should -BeNullOrEmpty
        $global:SI_Uplink_SendLastRun = 'off'
        $b = & $mk
        $r = Send-SIHeartbeatTick -Context $ctx -Transport $b.Tr -Now $script:Now -HeartbeatCounts { @{} } -LastRunRows $script:Rows -LastRunPublishedRows $script:Pub 6>$null
        $r.Status | Should -Be 'sent'
        $b.Sent[0] | Should -Not -Match '"LastRun":' -Because 'off turns it off per install'
    }
    It 'a heartbeat refused WITH it goes again WITHOUT it; it is dropped early when the record is too big' {
        Get-SITelemetryOptionalFields | Should -Contain 'LastRun'
        (Get-SIHeartbeatFieldDropOrder) | Should -Contain 'LastRun'
        @((Get-SIHeartbeatFieldsContract).Names) | Should -Contain 'LastRun'
    }
}

Describe 'Published is unchanged' {
    It 'its keys, its switch (every ring) and its value from the same rows' {
        $c = Get-SIHeartbeatFieldsContract
        $c.Fields.Published | Should -Be @('collectionId', 'collectionUtc', 'publishedUtc', 'copiedUtc', 'newestCompleteUtc')
        @($c.ConfirmedRings['Published']) | Should -Be @(0, 1, 2, 3)
        $row = [pscustomobject]@{ CollectionId = 41; CollectionTime = $script:T0; PublishedAt = $script:T0.AddHours(8); CopiedAt = $script:T0.AddHours(8).AddMinutes(4); NewestComplete = $script:T0 }
        $p = Get-SIHeartbeatPublished -Rows @($row)
        ($p | ConvertTo-Json -Compress) | Should -BeExactly '{"collectionId":41,"collectionUtc":"2026-11-26T01:00:00Z","publishedUtc":"2026-11-26T09:00:00Z","copiedUtc":"2026-11-26T09:04:00Z","newestCompleteUtc":"2026-11-26T01:00:00Z"}'
        Test-SIHeartbeatField -Name 'Published' -Value $p | Should -BeNullOrEmpty
        (Get-SIHeartbeatPublishedSql) | Should -Not -Match 'FlowRunId' -Because 'Published keeps its own read'
        # the order of the record: LastRun right after Published, nothing before it moved
        $i = [array]::IndexOf(@($c.Names), 'Published'); @($c.Names)[$i + 1] | Should -BeExactly 'LastRun'
        @($c.Names)[0..$i] | Should -Be @('Pipeline', 'Jobs', 'Sources', 'Database', 'Update', 'Mail', 'Warnings', 'Security', 'Published')
    }
}

Describe 'cheap: index reads only, never a big table' {
    It 'the settings read: the newest finished run by IX_FlowRun_Started, its steps by the primary key -- guarded' {
        $q = Get-SIHeartbeatLastRunSql
        $q | Should -Match "IF OBJECT_ID\(N'cfg.FlowRun'\) IS NOT NULL"
        $q | Should -Match "IF OBJECT_ID\(N'cfg.FlowStepRun'\) IS NOT NULL"
        $q | Should -Match ([regex]::Escape("SELECT TOP (1) @id = FlowRunId FROM cfg.FlowRun WHERE ' + @w + N' ORDER BY StartedUtc DESC;"))
        # FLEET-STATUS-1: the finished runs -- and a KILLED one (still Running / Starting, no beat for KilledRunMinutes)
        $q | Should -Match ([regex]::Escape("FlowId = N''daily'' AND (State IN (N''Succeeded'', N''Failed'', N''Stopped'', N''Cancelled'') OR (State IN (N''Running'', N''Starting'') AND HeartbeatUtc < DATEADD(minute, -30, SYSUTCDATETIME())))"))
        $q | Should -Match 'WHERE s.FlowRunId = @id'
        $q | Should -Match ([regex]::Escape("SET @w = @w + N' AND (Scope IS NULL OR Scope IN (N''pipeline'', N''from-step''))'"))
        $q | Should -Match ([regex]::Escape("COL_LENGTH(N'cfg.FlowRun', N'Version') IS NOT NULL THEN N'r.Version'")) -Because 'the version the run started on, guarded for an older schema'
        $q | Should -Match "COL_LENGTH\(N'cfg.FlowRun', N'Scope'\)"
        $q | Should -Not -Match 'sidata\.'
        $p = Get-SIHeartbeatLastRunPublishedSql
        $p | Should -Match "WHERE Name = N''current''"
        $p | Should -Match "COL_LENGTH\(N'sidata.PublishedRun', N'FlowRunId'\)"
        $p | Should -Not -Match 'sidata\.(Finding|Collection)\b'
        # the closed lists match the runner's own states
        @((Get-SIHeartbeatFieldsContract).PipelineStoppedRunStates) | Should -Be @('Stopped', 'Cancelled')
    }
}
}

Describe 'REAL SQL: the read against the shipped schema and an older one' -Skip:(-not $script:HasSql) {
    BeforeAll {
        $script:Server = $env:SI_TEST_LOCALSQL
        $script:Db = 'si_lastrun_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
        $script:OldDb = $script:Db + '_old'
        function script:Exec([string]$Database, [string]$Sql, $P, [string]$Mode = 'nonquery') {
            $cn = New-Object System.Data.SqlClient.SqlConnection ("Server={0};Database={1};$($env:SI_TEST_SQL_AUTH);TrustServerCertificate=true;Pooling=false" -f $script:Server, $Database)
            $cn.Open()
            try {
                $cmd = $cn.CreateCommand(); $cmd.CommandText = $Sql; $cmd.CommandTimeout = 120
                if ($P) { foreach ($k in $P.Keys) { [void]$cmd.Parameters.AddWithValue('@' + $k, $(if ($null -eq $P[$k]) { [DBNull]::Value } else { $P[$k] })) } }
                switch ($Mode) {
                    'reader' { $t = New-Object System.Data.DataTable; $t.Load($cmd.ExecuteReader()); , @($t.Rows | ForEach-Object { $row = $_; $h = @{}; foreach ($c in $t.Columns) { $h[$c.ColumnName] = $row[$c] }; [pscustomobject]$h }) }
                    default { [void]$cmd.ExecuteNonQuery() }
                }
            } finally { $cn.Dispose() }
        }
        Exec 'master' ("CREATE DATABASE [{0}]" -f $script:Db)
        $ddl = [System.IO.File]::ReadAllText((Join-Path $script:SIRoot 'sql\si-pro-settings.sql'))
        foreach ($b in ($ddl -split '(?m)^\s*$') | Where-Object { ($_ -replace '(?m)^\s*--.*$', '').Trim() }) { Exec $script:Db $b }
        # the data side: sidata.PublishedRun as shipped (the columns this read uses)
        Exec $script:Db "IF SCHEMA_ID(N'sidata') IS NULL EXEC (N'CREATE SCHEMA sidata');"
        Exec $script:Db "IF OBJECT_ID(N'sidata.PublishedRun') IS NULL CREATE TABLE sidata.PublishedRun (Name NVARCHAR(16) NOT NULL PRIMARY KEY, DetailedCollectionId INT NULL, DetailedCollectionTime DATETIME2(3) NULL, FlowRunId NVARCHAR(64) NULL, Source NVARCHAR(16) NOT NULL, PublishedAt DATETIME2(0) NOT NULL DEFAULT SYSUTCDATETIME());"
        # an OLDER schema: the two run tables as first shipped (no Scope); no PublishedRun at all
        Exec 'master' ("CREATE DATABASE [{0}]" -f $script:OldDb)
        Exec $script:OldDb "CREATE SCHEMA cfg;"
        Exec $script:OldDb @'
CREATE TABLE cfg.FlowRun (FlowRunId NVARCHAR(64) NOT NULL PRIMARY KEY, FlowId NVARCHAR(32) NOT NULL DEFAULT N'daily', Day NVARCHAR(10) NOT NULL, Trg NVARCHAR(16) NOT NULL, FromStep NVARCHAR(64) NULL,
    State NVARCHAR(16) NOT NULL, StartedUtc DATETIME2(0) NOT NULL, EndedUtc DATETIME2(0) NULL, HeartbeatUtc DATETIME2(0) NULL, StopReason NVARCHAR(1000) NULL, SlotUtc DATETIME2(0) NULL, LastSlotUtc DATETIME2(0) NULL, Note NVARCHAR(1000) NULL);
CREATE TABLE cfg.FlowStepRun (FlowRunId NVARCHAR(64) NOT NULL, StepOrder INT NOT NULL, GroupNo INT NOT NULL, Job NVARCHAR(64) NOT NULL, State NVARCHAR(16) NOT NULL, Execution NVARCHAR(128) NULL,
    StartedUtc DATETIME2(0) NULL, EndedUtc DATETIME2(0) NULL, ErrorClass NVARCHAR(64) NULL, Error NVARCHAR(1000) NULL, CONSTRAINT PK_FlowStepRun PRIMARY KEY (FlowRunId, StepOrder));
'@
        function script:Seed([string]$Database, [switch]$WithScope) {
            Exec $Database "DELETE FROM cfg.FlowStepRun; DELETE FROM cfg.FlowRun;"
            $t = [datetime]'2026-11-26T01:00:00'
            $ins = { param($Id, $State, $Trg, $S, $E, $From) Exec $Database "INSERT cfg.FlowRun (FlowRunId, FlowId, Day, Trg, FromStep, State, StartedUtc, EndedUtc) VALUES (@Id, N'daily', N'2026-11-26', @Trg, @F, @St, @S, @E);" @{ Id = $Id; Trg = $Trg; F = $From; St = $State; S = $S; E = $E } }
            & $ins 'older' 'Succeeded' 'schedule' $t.AddDays(-1) $t.AddDays(-1).AddHours(7) $null
            & $ins 'last' 'Cancelled' 'manual' $t $t.AddHours(3) $null
            & $ins 'now' 'Running' 'schedule' $t.AddHours(8) $null $null
            # its runner beats now: a run going on, never "the last run" (FLEET-STATUS-1: only a run with no beat for 30 min is)
            Exec $Database "UPDATE cfg.FlowRun SET HeartbeatUtc = SYSUTCDATETIME() WHERE FlowRunId = N'now';"
            # another pipeline's run is never read
            Exec $Database "INSERT cfg.FlowRun (FlowRunId, FlowId, Day, Trg, State, StartedUtc, EndedUtc) VALUES (N'other', N'weekly', N'2026-11-26', N'schedule', N'Succeeded', @S, @S);" @{ S = $t.AddHours(9) }
            $st = { param($Run, $O, $Job, $State, $S, $E, $Cls) Exec $Database "INSERT cfg.FlowStepRun (FlowRunId, StepOrder, GroupNo, Job, State, StartedUtc, EndedUtc, ErrorClass) VALUES (@R, @O, @O, @J, @St, @S, @E, @C);" @{ R = $Run; O = $O; J = $Job; St = $State; S = $S; E = $E; C = $Cls } }
            & $st 'last' 2 'endpoint' 'Failed' $t.AddMinutes(40) $t.AddMinutes(55) 'graph-403'
            & $st 'last' 1 'identity' 'Success' $t $t.AddMinutes(40) $null
            & $st 'last' 3 'risk-analysis-detailed' 'Skipped' $null $null 'cancelled'
            & $st 'older' 1 'identity' 'Success' $t.AddDays(-1) $t.AddDays(-1).AddMinutes(30) $null
            & $st 'now' 1 'identity' 'Running' $t.AddHours(8) $null $null
            if ($WithScope) {
                Exec $Database "UPDATE cfg.FlowRun SET Scope = N'pipeline' WHERE FlowRunId = N'last';"
                # a person's run of ONE stage, finished after it: never the last run (the whole pipeline only)
                & $ins 'stagerun' 'Succeeded' 'manual' $t.AddHours(5) $t.AddHours(6) $null
                Exec $Database "UPDATE cfg.FlowRun SET Scope = N'stage' WHERE FlowRunId = N'stagerun';"
                & $st 'stagerun' 1 'risk-analysis-detailed' 'Success' $t.AddHours(5) $t.AddHours(6) $null
            }
        }
    }
    AfterAll {
        [System.Data.SqlClient.SqlConnection]::ClearAllPools()
        foreach ($d in $script:Db, $script:OldDb) { try { Exec 'master' ("ALTER DATABASE [{0}] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [{0}]" -f $d) } catch { } }
    }
    It 'the shipped schema: the newest FINISHED run (not the running one, not another pipeline), its steps in order, the collection it published' {
        Seed $script:Db -WithScope
        Exec $script:Db "DELETE FROM sidata.PublishedRun; INSERT sidata.PublishedRun (Name, DetailedCollectionId, DetailedCollectionTime, FlowRunId, Source) VALUES (N'current', 7, '2026-11-26T01:35:00', N'last', N'run');"
        $rows = @(Exec $script:Db (Get-SIHeartbeatLastRunSql) $null 'reader' | ForEach-Object { $_ })
        $pub = @(Exec $script:Db (Get-SIHeartbeatLastRunPublishedSql) $null 'reader' | ForEach-Object { $_ })
        $v = Get-SIHeartbeatLastRun -Rows $rows -PublishedRows $pub
        $v.runId | Should -BeExactly 'last'
        $v.kind | Should -BeExactly 'full' -Because 'a person started the whole pipeline; the later one-stage run is not the last run'
        $v.result | Should -BeExactly 'cancelled'
        $v.startedUtc | Should -BeExactly '2026-11-26T01:00:00Z'
        $v.endedUtc | Should -BeExactly '2026-11-26T04:00:00Z'
        $v.totalSec | Should -Be 10800
        $v.collectionUtc | Should -BeExactly '2026-11-26T01:35:00Z'
        @($v.steps | ForEach-Object { $_.step }) | Should -Be @('identity', 'endpoint', 'risk-analysis-detailed')
        @($v.steps | ForEach-Object { $_.result }) | Should -Be @('ok', 'failed', 'cancelled')
        $v.steps[1].sec | Should -Be 900
        Test-SIHeartbeatField -Name 'LastRun' -Value $v | Should -BeNullOrEmpty
        # the read the job makes (through the seams of the tick's -ClaimInvoke / -DataInvoke shape)
        $f = New-SIHeartbeatFields -Ring 0 -NowUtc ([datetime]::UtcNow) -Switch @{ LastRun = $true } -LastRunRows $rows -LastRunPublishedRows $pub -Log { param($l) }
        $f['LastRun'].runId | Should -BeExactly 'last'
        # a step the runner started again (Attempts 2, the shipped column): its times are unknown -- null; Attempts 1: kept
        Exec $script:Db "UPDATE cfg.FlowStepRun SET Attempts = 2 WHERE FlowRunId = N'last' AND StepOrder = 2; UPDATE cfg.FlowStepRun SET Attempts = 1 WHERE FlowRunId = N'last' AND StepOrder = 1;"
        $rows = @(Exec $script:Db (Get-SIHeartbeatLastRunSql) $null 'reader' | ForEach-Object { $_ })
        $v = Get-SIHeartbeatLastRun -Rows $rows -PublishedRows $pub
        $v.steps[1].startedUtc | Should -BeNullOrEmpty; $v.steps[1].sec | Should -BeNullOrEmpty
        $v.steps[1].result | Should -BeExactly 'failed'
        $v.steps[0].sec | Should -Be 2400
        $v.totalSec | Should -Be 10800
    }
    It 'an older schema (no Scope column, no PublishedRun): still read, Scope null = the whole pipeline, collectionUtc null' {
        Seed $script:OldDb
        $rows = @(Exec $script:OldDb (Get-SIHeartbeatLastRunSql) $null 'reader' | ForEach-Object { $_ })
        $pub = @(Exec $script:OldDb (Get-SIHeartbeatLastRunPublishedSql) $null 'reader' | ForEach-Object { $_ })
        $pub.Count | Should -Be 0
        $v = Get-SIHeartbeatLastRun -Rows $rows -PublishedRows $pub
        $v.runId | Should -BeExactly 'last'
        $v.kind | Should -BeExactly 'full'
        $v.collectionUtc | Should -BeNullOrEmpty
        $v.steps[1].sec | Should -Be 900 -Because 'no Attempts column: the times are kept, nothing fails'
        Test-SIHeartbeatField -Name 'LastRun' -Value $v | Should -BeNullOrEmpty
    }
    It 'no finished run yet: no rows -- LastRun is left out' {
        Exec $script:Db "DELETE FROM cfg.FlowStepRun; DELETE FROM cfg.FlowRun; INSERT cfg.FlowRun (FlowRunId, FlowId, Day, Trg, State, StartedUtc) VALUES (N'first', N'daily', N'2026-11-26', N'schedule', N'Running', SYSUTCDATETIME());"
        $rows = @(Exec $script:Db (Get-SIHeartbeatLastRunSql) $null 'reader' | ForEach-Object { $_ })
        $rows.Count | Should -Be 0
        Get-SIHeartbeatLastRun -Rows $rows -PublishedRows @() | Should -BeNullOrEmpty
    }
    It 'FLEET-STATUS-1: a KILLED run (Running, no beat for 30 min) is read as the last run with its version; a beating run is not' {
        Exec $script:Db "DELETE FROM cfg.FlowStepRun; DELETE FROM cfg.FlowRun;"
        Exec $script:Db "INSERT cfg.FlowRun (FlowRunId, FlowId, Day, Trg, State, StartedUtc, EndedUtc, Version) VALUES (N'prev', N'daily', N'2026-11-26', N'schedule', N'Succeeded', DATEADD(hour, -10, SYSUTCDATETIME()), DATEADD(hour, -4, SYSUTCDATETIME()), N'3.1.54');"
        Exec $script:Db "INSERT cfg.FlowRun (FlowRunId, FlowId, Day, Trg, State, StartedUtc, HeartbeatUtc, Version) VALUES (N'killed', N'daily', N'2026-11-27', N'schedule', N'Running', DATEADD(hour, -3, SYSUTCDATETIME()), DATEADD(minute, -45, SYSUTCDATETIME()), N'3.1.55');"
        Exec $script:Db "INSERT cfg.FlowStepRun (FlowRunId, StepOrder, GroupNo, Job, State, StartedUtc) VALUES (N'killed', 1, 1, N'identity', N'Running', DATEADD(hour, -3, SYSUTCDATETIME()));"
        $rows = @(Exec $script:Db (Get-SIHeartbeatLastRunSql) $null 'reader' | ForEach-Object { $_ })
        $v = Get-SIHeartbeatLastRun -Rows $rows -PublishedRows @() -NowUtc ([datetime]::UtcNow)
        $v.runId | Should -BeExactly 'killed'
        $v.result | Should -BeExactly 'failed'
        $v.steps[0].result | Should -BeExactly 'failed'
        @($rows | Where-Object { $_.K -eq 'run' })[0].Ver | Should -BeExactly '3.1.55'
        $v.version | Should -BeExactly '3.1.55' -Because 'LastRun carries the version the run started on'
        # the runner beats it again (resumed): not finished -- the run before it is the last run
        Exec $script:Db "UPDATE cfg.FlowRun SET HeartbeatUtc = SYSUTCDATETIME() WHERE FlowRunId = N'killed';"
        $rows = @(Exec $script:Db (Get-SIHeartbeatLastRunSql) $null 'reader' | ForEach-Object { $_ })
        (Get-SIHeartbeatLastRun -Rows $rows -PublishedRows @() -NowUtc ([datetime]::UtcNow)).runId | Should -BeExactly 'prev'
    }
    It 'a database without the run tables: nothing, no error' {
        Exec 'master' ("CREATE DATABASE [{0}_empty]" -f $script:Db)
        try { @(Exec ($script:Db + '_empty') (Get-SIHeartbeatLastRunSql) $null 'reader' | ForEach-Object { $_ }).Count | Should -Be 0 }
        finally { [System.Data.SqlClient.SqlConnection]::ClearAllPools(); Exec 'master' ("ALTER DATABASE [{0}_empty] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [{0}_empty]" -f $script:Db) }
    }
}
