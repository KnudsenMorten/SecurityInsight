#Requires -Version 5.1
<#
    #931: A JOB START'S OWN VALUES WITHOUT A START OVERRIDE (Azure Container Apps: a start that carries containers needs
    Microsoft.App/jobs/write, which the web app must not hold). The web app writes a start-env row, starts with no body and
    binds the row to the execution; the job claims it (engine\_shared\SI-JobStartRequest.ps1). What must hold, on a fake
    database:
      * only the row bound to THIS execution is claimed (or one a skipped execution handed back) -- never another's;
      * only the names allowed for the job are set; anything else (a sign-in, a target, a secret) is dropped and said;
      * a start in flight (written, not yet bound) is waited for, bounded; no row and nothing in flight = no wait;
      * a database that cannot be read = the run goes on as configured (never throws);
      * a skipped run hands its row back; the runner's trigger pass never reads start-env rows;
      * the container entrypoint claims BEFORE the execution guard and hands back on every skip;
      * the security cut-over keeps the web app's Jobs Contributor before the release that has this.
    OFFLINE. PS 5.1 + pwsh 7.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\_shared\SI-JobStartRequest.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-JobTriggerRequests.ps1')
    . (Join-Path $script:SIRoot 'setup\_shared\SI-SecurityBaseline.ps1')

    function New-FakeDb([object[]]$Claim = @(), [int[]]$InFlight = @(0), [switch]$Throws) {
        $db = [pscustomobject]@{ Calls = New-Object System.Collections.Generic.List[object]; Claim = @($Claim); InFlight = @($InFlight); Reads = 0; Polls = 0 }
        $t = [bool]$Throws
        $inv = { param($sql, $p, $mode)
            $db.Calls.Add([pscustomobject]@{ Sql = $sql; P = $p; Mode = $mode })
            if ($t) { throw "Invalid column name 'EnvJson'." }
            if ($mode -eq 'reader') { $i = $db.Reads; $db.Reads++; if ($i -lt $db.Claim.Count) { return $db.Claim[$i] }; return @() }
            if ($mode -eq 'scalar') { $i = $db.Polls; $db.Polls++; if ($i -lt $db.InFlight.Count) { return $db.InFlight[$i] }; return 0 }
            1 }.GetNewClosure()
        $db | Add-Member -NotePropertyName Invoke -NotePropertyValue $inv
        $db
    }
    function Row($id, [string]$json) { [pscustomobject]@{ RequestId = $id; EnvJson = $json; RequestedBy = 'admin@example.test' } }
    $script:Names = @('SI_FLOW_DRAIN', 'SI_FLOW_TRIGGER', 'SI_EXEMPTION_MAIL_ONLY', 'SI_AUDIT_CID', 'SI_SPN_APPID', 'SI_TEMPLATES_MODE')
}

Describe 'SIv3-JobStartRequest: the job takes its own start request' {
    AfterEach { foreach ($n in $script:Names) { [Environment]::SetEnvironmentVariable($n, $null) } }

    It 'claims the row bound to this execution and sets only the names allowed for the job' {
        $db = New-FakeDb -Claim @(, @(Row 7 '{"SI_FLOW_DRAIN":"1","SI_FLOW_TRIGGER":"manual","SI_AUDIT_CID":"c1","SI_SPN_APPID":"evil","SI_EXEMPTION_MAIL_ONLY":"1"}'))
        $r = Invoke-SIJobStartRequestClaim -Invoke $db.Invoke -Job 'caj-si-flow' -Execution 'caj-si-flow-abc12' -Sleep { }
        $r.Claimed | Should -BeTrue
        $r.RequestId | Should -Be 7
        @($r.Names | Sort-Object) | Should -Be @('SI_AUDIT_CID', 'SI_FLOW_DRAIN', 'SI_FLOW_TRIGGER')
        $env:SI_FLOW_DRAIN | Should -Be '1'
        $env:SI_AUDIT_CID | Should -Be 'c1'
        $env:SI_SPN_APPID | Should -BeNullOrEmpty
        $env:SI_EXEMPTION_MAIL_ONLY | Should -BeNullOrEmpty          # a mail job's name, not the runner's
        $r.Line | Should -Match 'started by admin@example\.test'
        $r.Line | Should -Match 'not allowed for this job, not set: .*SI_SPN_APPID'
        $db.Calls[0].P.Exec | Should -Be 'caj-si-flow-abc12'
        $db.Calls[0].P.Job | Should -Be 'caj-si-flow'
        $db.Calls[0].Sql | Should -Match 'q\.ExecutionName = @Exec'
        $db.Calls[0].Sql | Should -Match "q\.Action = N'start-env'"
        $db.Calls[0].Sql | Should -Match 'READPAST'
    }

    It 'never takes another execution''s row: the claim matches this execution or a handed-back row only' {
        $sql = Get-SIJobStartRequestClaimSql
        $sql | Should -Match "q\.ExecutionName = @Exec OR \(q\.ExecutionName IS NULL AND q\.Outcome = N'handed-back'\)"
        $sql | Should -Match 'DATEADD\(MINUTE, -@MaxAge'
    }

    It 'nothing for this execution and no start in flight: no wait, the run goes on as configured' {
        $db = New-FakeDb -InFlight @(0)
        $slept = New-Object System.Collections.Generic.List[int]
        $r = Invoke-SIJobStartRequestClaim -Invoke $db.Invoke -Job 'caj-si-risk-analysis' -Execution 'e1' -Sleep { param($s) $slept.Add($s) }.GetNewClosure()
        $r.Claimed | Should -BeFalse
        $slept.Count | Should -Be 0
        $db.Reads | Should -Be 1
    }

    It 'a start in flight (written, not yet bound) is waited for, then claimed' {
        $db = New-FakeDb -Claim @(@(), @(), , @(Row 9 '{"SI_EXEMPTION_MAIL_ONLY":"1"}')) -InFlight @(1, 1)
        $slept = New-Object System.Collections.Generic.List[int]
        $r = Invoke-SIJobStartRequestClaim -Invoke $db.Invoke -Job 'caj-si-close-loop-mail' -Execution 'e2' -Sleep { param($s) $slept.Add($s) }.GetNewClosure()
        $r.Claimed | Should -BeTrue
        $env:SI_EXEMPTION_MAIL_ONLY | Should -Be '1'
        $slept.Count | Should -Be 2
    }

    It 'the wait for a bind is bounded' {
        $db = New-FakeDb -InFlight @(1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1)
        $slept = New-Object System.Collections.Generic.List[int]
        $r = Invoke-SIJobStartRequestClaim -Invoke $db.Invoke -Job 'caj-si-templates' -Execution 'e3' -BindWaitSeconds 9 -Sleep { param($s) $slept.Add($s) }.GetNewClosure()
        $r.Claimed | Should -BeFalse
        ($slept | Measure-Object -Sum).Sum | Should -Be 9
    }

    It 'a database one schema behind (or unreadable) never throws: the run goes on as configured' {
        $db = New-FakeDb -Throws
        $r = Invoke-SIJobStartRequestClaim -Invoke $db.Invoke -Job 'caj-si-flow' -Execution 'e4' -Sleep { }
        $r.Claimed | Should -BeFalse
        $r.Line | Should -Match 'goes on as configured'
        (Invoke-SIJobStartRequestRelease -Invoke $db.Invoke -RequestId 1 -Execution 'e4') | Should -BeFalse
    }

    It 'no database, no execution name: nothing is read' {
        (Invoke-SIJobStartRequestClaim -Invoke $null -Job 'caj-si-flow' -Execution 'e5').Claimed | Should -BeFalse
        $db = New-FakeDb
        (Invoke-SIJobStartRequestClaim -Invoke $db.Invoke -Job 'caj-si-flow' -Execution '').Claimed | Should -BeFalse
        $db.Calls.Count | Should -Be 0
    }

    It 'a skipped run hands its row back, unbound, for the next execution of the job' {
        $db = New-FakeDb
        (Invoke-SIJobStartRequestRelease -Invoke $db.Invoke -RequestId 7 -Execution 'e6') | Should -BeTrue
        $db.Calls[0].Mode | Should -Be 'nonquery'
        $db.Calls[0].P.Id | Should -Be 7
        $db.Calls[0].Sql | Should -Match "Outcome = N'handed-back', ExecutionName = NULL"
        $db.Calls[0].Sql | Should -Match 'WHERE RequestId = @Id AND ExecutionName = @Exec'
    }

    It 'the allow-list: every job may carry who started it; each job only its own values' {
        @(Get-SIJobStartRequestAllowed -Job 'caj-si-asset-trend') | Should -Be @('SI_AUDIT_CID', 'SI_AUDIT_STARTED_BY')
        @(Get-SIJobStartRequestAllowed -Job 'caj-si-risk-analysis-detailed') | Should -Contain 'SI_RA_REPORT_TEMPLATE'   # a certification run
        @(Get-SIJobStartRequestAllowed -Job 'caj-si-risk-analysis-detailed') | Should -Not -Contain 'SI_RA_EXPORT_DESTINATION'
        @(Get-SIJobStartRequestAllowed -Job 'caj-si-templates') | Should -Contain 'SI_TEMPLATES_MODE'
        @(Get-SIJobStartRequestAllowed -Job 'close-loop-mail') | Should -Contain 'SI_SNOW_VERIFY'
        (ConvertFrom-SIJobStartRequestEnv -EnvJson '[1,2]' -Job 'caj-si-flow').Env.Count | Should -Be 0
        (ConvertFrom-SIJobStartRequestEnv -EnvJson 'not json' -Job 'caj-si-flow').Dropped | Should -Match 'not valid JSON'
        (ConvertFrom-SIJobStartRequestEnv -EnvJson '{"si_flow_drain":"1"}' -Job 'caj-si-flow').Env.Count | Should -Be 0   # names are exact
    }

    It 'the pipeline runner''s trigger pass never applies a start-env row and expires the old ones' {
        $sql = Get-SIJobTriggerPendingSql
        $sql | Should -Match "AND Action <> N'start-env' ORDER BY RequestId"
        $sql | Should -Match "WHERE Action = N'start-env' AND AppliedUtc IS NULL AND RequestedUtc < DATEADD\(HOUR, -24"
    }
}

Describe 'SIv3-JobStartRequest: wiring' {
    It 'the container entrypoint claims before the execution guard and hands back on every skip' {
        $src = Get-Content -Raw (Join-Path $script:SIRoot 'container\Start-SIInContainer.ps1')
        $claim = $src.IndexOf('Invoke-SIJobStartRequestIsolated'); $guard = $src.IndexOf('$guardFlowRequest = ')
        $claim | Should -BeGreaterThan 0
        $claim | Should -BeLessThan $guard
        ([regex]::Matches($src, 'Undo-SIStartRequestClaim')).Count | Should -BeGreaterOrEqual 4   # the function + FlowBusy + Skip + no-overlap
    }

    It 'both entrypoints claim and hand back only through the isolated call, never with the guard file in their own scope' {
        foreach ($f in 'Start-SIInContainer.ps1', 'Start-RiskAnalysisInContainer.ps1') {
            $src = Get-Content -Raw (Join-Path $script:SIRoot "container\$f")
            $src | Should -Match 'Invoke-SIJobStartRequestIsolated -GuardPath'
            $src | Should -Not -Match 'Invoke-SIJobStartRequestClaim|Invoke-SIJobStartRequestRelease'
        }
        $ra = Get-Content -Raw (Join-Path $script:SIRoot 'container\Start-RiskAnalysisInContainer.ps1')
        $ra | Should -Not -Match "\.\s*\(Join-Path \`$PSScriptRoot '\.\./engine/_shared/SI-Guard\.ps1'\)"
    }
}

Describe 'SIv3-JobStartRequest: the claim leaves the engine''s start untouched (live 3.0.5: the status report stopped)' {
    BeforeAll {
        $script:Pwsh = (Get-Process -Id $PID).Path
        $script:Work = Join-Path ([System.IO.Path]::GetTempPath()) ('si-startreq-' + [guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path $script:Work
        # the engine, started from the entrypoint as its own script: loads the telemetry code the way every engine does
        $script:Engine = Join-Path $script:Work 'engine.ps1'
        Set-Content -LiteralPath $script:Engine -Encoding UTF8 -Value @"
. '$(Join-Path $script:SIRoot 'engine\_shared\SI-TelemetrySend.ps1')'
'editions=' + (@(`$script:SITelemetry.Editions) -join ',')
"@
        function Invoke-Entrypoint([string]$Claim) {
            $host1 = Join-Path $script:Work ('host-' + [guid]::NewGuid().ToString('N') + '.ps1')
            Set-Content -LiteralPath $host1 -Encoding UTF8 -Value @"
`$ErrorActionPreference = 'Continue'
. '$(Join-Path $script:SIRoot 'engine\_shared\SI-JobStartRequest.ps1')'
`$guardPath = '$(Join-Path $script:SIRoot 'engine\_shared\SI-Guard.ps1')'
$Claim
'seam=' + [string](`$global:SI_GuardProInvoke -is [scriptblock])
'guardFn=' + [string][bool](Get-Command -Name Get-SIGuardProInvoke -ErrorAction SilentlyContinue)
'telemetryFn=' + [string][bool](Get-Command -Name New-SITelemetryRunRecord -ErrorAction SilentlyContinue)
& '$script:Engine'
"@
            @(& $script:Pwsh -NoProfile -NonInteractive -File $host1 2>&1 | ForEach-Object { [string]$_ })
        }
    }
    AfterAll { Remove-Item -LiteralPath $script:Work -Recurse -Force -ErrorAction SilentlyContinue }

    It 'the real guard file, loaded for the claim, leaves nothing behind: the engine loads its own telemetry and finds its lists' {
        $out = Invoke-Entrypoint '$r = Invoke-SIJobStartRequestIsolated -GuardPath $guardPath -Job ''caj-si-heartbeat'' -Execution ''caj-si-heartbeat-1''; ''claimed='' + [string]$r.Claimed'
        $out | Should -Contain 'claimed=False'
        $out | Should -Contain 'guardFn=False'
        $out | Should -Contain 'telemetryFn=False'
        $out | Should -Contain 'editions=community,pro,trial'
    }

    It 'control: the guard file dot-sourced in the entrypoint''s scope (3.0.5) leaves the engine without its lists' {
        $out = Invoke-Entrypoint '. $guardPath'
        $out | Should -Contain 'telemetryFn=True'
        $out | Should -Contain 'editions='
    }

    It 'the database seam the guard file remembers for the process is put back as it was; the claim itself still works' {
        $fakeGuard = Join-Path $script:Work 'fake-guard.ps1'
        Set-Content -LiteralPath $fakeGuard -Encoding UTF8 -Value @'
function Get-SIGuardProInvoke { $inv = { param($sql, $p, $mode) if ($mode -eq 'reader') { ,@([pscustomobject]@{ RequestId = 3; EnvJson = '{"SI_AUDIT_CID":"c9"}'; RequestedBy = 'a@example.test' }) } else { 0 } }; $global:SI_GuardProInvoke = $inv; $global:SI_GuardInvoke = $inv; $inv }
'@
        $out = Invoke-Entrypoint ('$r = Invoke-SIJobStartRequestIsolated -GuardPath ''{0}'' -Job ''caj-si-flow'' -Execution ''e1''; ''claimed='' + [string]$r.Claimed + '' id='' + [string]$r.RequestId + '' cid='' + $env:SI_AUDIT_CID' -f $fakeGuard)
        $out | Should -Contain 'claimed=True id=3 cid=c9'
        $out | Should -Contain 'seam=False'
        $out | Should -Contain 'guardFn=False'
    }

    It 'a hand-back goes through the same isolated call and never throws' {
        (Invoke-SIJobStartRequestIsolated -Invoke { param($sql, $p, $mode) 1 } -RequestId 5 -Execution 'e1') | Should -BeTrue
        (Invoke-SIJobStartRequestIsolated -Invoke { param($sql, $p, $mode) throw 'gone' } -RequestId 5 -Execution 'e1') | Should -BeFalse
        (Invoke-SIJobStartRequestIsolated -GuardPath (Join-Path $script:Work 'no-such-file.ps1') -Job 'caj-si-flow' -Execution 'e1').Line | Should -Match 'goes on as configured'
    }

    It 'the schema allows start-env and carries the values and the execution' {
        $sql = Get-Content -Raw (Join-Path $script:SIRoot 'sql\si-pro-settings.sql')
        $sql | Should -Match "COL_LENGTH\('cfg\.JobTriggerRequest', 'EnvJson'\) IS NULL"
        $sql | Should -Match "COL_LENGTH\('cfg\.JobTriggerRequest', 'ExecutionName'\) IS NULL"
        $sql | Should -Match "CHECK \(Action IN \(N'to-manual', N'to-schedule', N'start-env'\)\)"
        $sql | Should -Match 'NOCHECK CONSTRAINT CK_JobTriggerRequest_Action;'     # widened without dropping anything
        $sql | Should -Not -Match 'DROP CONSTRAINT CK_JobTriggerRequest'
    }

    It 'the web app may bind its start request (INSERT + UPDATE on cfg.JobTriggerRequest)' {
        . (Join-Path $script:SIRoot 'pro-management\deploy\SI-ManagementGrants.ps1')
        (@($script:WebWriteGrants | Where-Object { $_.Object -eq 'cfg.JobTriggerRequest' })[0]).Verbs | Should -Be 'INSERT, UPDATE'
    }
}

Describe 'SIv3-JobStartRequest: the security cut-over keeps Jobs Contributor until the release has this' {
    BeforeAll { function Upd([string]$v) { [pscustomobject]@{ name = 'caj-si-updater'; tags = [pscustomobject]@{ 'si-installed' = $v } } } }
    It 'before 3.0.2: not ready, the role stays' {
        $r = Test-SIBaselineStartRequestReady -Jobs @((Upd '3.0.1.202610280512'), [pscustomobject]@{ name = 'caj-si-flow' })
        $r.Ready | Should -BeFalse
        $r.Line | Should -Match 'stays until 3\.0\.2'
    }
    It 'from 3.0.2: ready' {
        (Test-SIBaselineStartRequestReady -Jobs @(Upd '3.0.2.202611010000')).Ready | Should -BeTrue
        (Test-SIBaselineStartRequestReady -Jobs @(Upd '3.1.0')).Ready | Should -BeTrue
    }
    It 'an unknown release is not ready' {
        (Test-SIBaselineStartRequestReady -Jobs @([pscustomobject]@{ name = 'caj-si-updater'; tags = $null })).Ready | Should -BeFalse
        (Test-SIBaselineStartRequestReady -Jobs @()).Ready | Should -BeFalse
    }
    It 'the cut-over script asks it before planning the removal' {
        $src = Get-Content -Raw (Join-Path $script:SIRoot 'setup\Set-SISecurityBaseline.ps1')
        $src | Should -Match "Test-SIBaselineStartRequestReady -Jobs @\(\`$shape\.Jobs\)"
    }
}
