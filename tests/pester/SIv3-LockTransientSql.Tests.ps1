#Requires -Version 5.1
<#
    SecurityInsight -- #913 A TRANSIENT AZURE SQL ERROR IN THE RUNNER'S LOCK IS NOT A PRODUCT DEFECT (the ride test install
    2026-10-27 21:31Z: the wake-up failed in AcquireLock on "Exception calling "Close" ... Error code 9001" and went to Invardia
    as si-flow FailedStep "run", FixKind product-defect, a red live-feed alert -- with no run to start).

    What must hold:
      - the Azure SQL transients (9001, 40613, 40501, 40197, 49918-49920, 4060 in a failover, 10928 / 10929, a reset
        connection) are retried; a permission or a syntax error never is;
      - every lock call (acquire, beat, release, release of a run, read) goes again after 2, 4, 8, 16, 30 s (about a minute)
        and then fails tagged transient-sql -- the tag survives the script method's wrapping;
      - a call whose Close failed after the statement ran is sent again safely (the lock statements name their holder);
      - the runner: a transient-sql lock failure is one WARN, a run-health row success-partial with class transient-sql,
        exit 0 -- never 'error'; the class is nobody's fix (no FixKind on the wire: never a fix request, never a red alert).
    Offline: the database is a fake -Invoke seam; nothing sleeps.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\_shared\SI-JobFlow.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-TelemetrySend.ps1')
    $script:E9001 = 'Exception calling "Close" with "0" argument(s): "The service has encountered an error processing your request. Please try again. Error code 9001."'
    function script:New-FakeSql([int]$FailFirst, [string]$Text, [object[]]$Rows) {
        $st = [pscustomobject]@{ Calls = 0; Sql = New-Object System.Collections.Generic.List[string] }
        $inv = { param($s, $p, $m) $st.Calls++; $st.Sql.Add($s); if ($st.Calls -le $FailFirst) { throw $Text }; if ($m -eq 'reader') { , @($Rows) } }.GetNewClosure()
        [pscustomobject]@{ State = $st; Invoke = $inv }
    }
}

Describe '#913 which errors of a lock call are transient' {
    It 'the Azure SQL transients are, a refusal or a defect is not' {
        foreach ($t in $script:E9001, 'Database ''d'' on server ''s'' is not currently available. Please retry the connection later. (40613)', 'The service is currently busy. (40501)',
                       'A transport-level error has occurred when receiving results from the server. (provider: TCP Provider, error: 0 - An existing connection was forcibly closed by the remote host.)',
                       'Resource ID : 1. The request limit for the database is 30 and has been reached. (10928)', 'error 49918: cannot process request') {
            Test-SIPipelineLockTransient -ErrorRecord $t | Should -BeTrue -Because $t
        }
        foreach ($t in "Login failed for user '<token-identified principal>'.", "Incorrect syntax near 'FROM'.", 'The SELECT permission was denied on the object', 'Invalid object name ''cfg.PipelineLock''.') {
            Test-SIPipelineLockTransient -ErrorRecord $t | Should -BeFalse -Because $t
        }
        Test-SIPipelineLockTransient -ErrorRecord $null | Should -BeFalse
    }
}

Describe '#913 the lock calls retry, then fail as transient-sql' {
    It 'AcquireLock: 9001 on Close twice, then the lock -- waited 2 s and 4 s, the same holder sent again' {
        $f = New-FakeSql -FailFirst 2 -Text $script:E9001 -Rows @(@{ Holder = 'runner-1'; What = 'pipeline runner'; AcquiredUtc = [datetime]::UtcNow; HeartbeatUtc = [datetime]::UtcNow; PreviousHolder = [DBNull]::Value; Mine = 1 })
        $slept = New-Object System.Collections.Generic.List[int]; $lines = New-Object System.Collections.Generic.List[string]
        $c = New-SIPipelineSqlControl -Invoke $f.Invoke -LockSleep { param($s) $slept.Add($s) }.GetNewClosure() -LockLog { param($l, $m) $lines.Add("$l|$m") }.GetNewClosure()
        $lock = $c.AcquireLock('runner-1', 'pipeline runner', 15)
        $lock.Acquired | Should -BeTrue
        $lock.What | Should -Be 'pipeline runner' -Because 'the What of the lock, never the retry''s own name'
        @($slept) | Should -Be @(2, 4)
        $f.State.Calls | Should -Be 3
        @($f.State.Sql | Select-Object -Unique).Count | Should -Be 1 -Because 'the same idempotent statement, for the same holder'
        @($lines | Where-Object { $_ -like 'WARN|*not available for a moment*' }).Count | Should -Be 2
    }
    It 'a transient that outlasts about a minute: thrown tagged transient-sql after 2, 4, 8, 16, 30 s -- the tag survives the method''s wrapping' {
        $f = New-FakeSql -FailFirst 99 -Text $script:E9001 -Rows @()
        $slept = New-Object System.Collections.Generic.List[int]
        $c = New-SIPipelineSqlControl -Invoke $f.Invoke -LockSleep { param($s) $slept.Add($s) }.GetNewClosure()
        $err = $null
        try { $null = $c.AcquireLock('runner-1', 'pipeline runner', 15) } catch { $err = $_ }
        $err | Should -Not -BeNullOrEmpty
        @($slept) | Should -Be @(2, 4, 8, 16, 30)
        ($slept | Measure-Object -Sum).Sum | Should -Be 60
        Get-SIPipelineErrorClassTag -ErrorRecord $err | Should -Be 'transient-sql'
        "$($err.Exception.Message)" | Should -Match 'the pipeline lock \(acquire\) could not be reached.*9001.*transient-sql'
    }
    It 'beat, release, release of a run and the read retry the same way' {
        foreach ($call in @(
                @{ N = 'beat'; Rows = @(@{ Held = 1 }); Do = { param($c) $c.HeartbeatLock('runner-1', 'run-1', 'a run') } },
                @{ N = 'release'; Rows = @(); Do = { param($c) $c.ReleaseLock('runner-1') } },
                @{ N = 'release of a run'; Rows = @(@{ Released = 1 }); Do = { param($c) $c.ReleaseLockOfRun('run-1') } },
                @{ N = 'read'; Rows = @(@{ Holder = 'runner-1'; What = 'w'; FlowRunId = 'run-1' }); Do = { param($c) $c.LockHolder() } })) {
            $f = New-FakeSql -FailFirst 1 -Text 'A transport-level error has occurred (Connection reset by peer)' -Rows $call.Rows
            $slept = New-Object System.Collections.Generic.List[int]
            $c = New-SIPipelineSqlControl -Invoke $f.Invoke -LockSleep { param($s) $slept.Add($s) }.GetNewClosure()
            { & $call.Do $c } | Should -Not -Throw -Because $call.N
            @($slept) | Should -Be @(2) -Because $call.N
        }
    }
    It 'any other error is thrown at once, untagged, without a wait' {
        $f = New-FakeSql -FailFirst 99 -Text 'The SELECT permission was denied on the object ''PipelineLock''' -Rows @()
        $slept = New-Object System.Collections.Generic.List[int]
        $c = New-SIPipelineSqlControl -Invoke $f.Invoke -LockSleep { param($s) $slept.Add($s) }.GetNewClosure()
        $err = $null; try { $null = $c.AcquireLock('r', 'w', 15) } catch { $err = $_ }
        $err | Should -Not -BeNullOrEmpty
        $slept.Count | Should -Be 0
        $f.State.Calls | Should -Be 1
        Get-SIPipelineErrorClassTag -ErrorRecord $err | Should -Be ''
    }
}

Describe '#913 the runner: a transient lock failure is never a product defect, never a red alert' {
    It 'the wake-up says it in one WARN, records success-partial with class transient-sql and exits 0' {
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\flow\Invoke-SIJobFlowRun.ps1'))
        $src | Should -Match "(?s)Get-SIPipelineErrorClassTag -ErrorRecord \`$_.{0,200}if \(\`$lockClass -eq 'transient-sql'\) \{.{0,900}FailedStepErrorClass = 'transient-sql'.{0,300}-ExitReason 'success-partial'.{0,200}exit 0"
        $src | Should -Match 'New-SIPipelineSqlControl -Invoke \$proStore\.Invoke -LockLog'
    }
    It 'transient-sql is on the closed list and is nobody''s fix: no FixKind on the wire, Outcome warning' {
        @(Get-SIErrorClasses) | Should -Contain 'transient-sql'
        Get-SIErrorFixKind -ErrorClass 'transient-sql' | Should -Be ''
        $l = New-Object System.Collections.Generic.List[object]
        $t = { param($Record, $Endpoint, $AccessCode, $TimeoutSec) $l.Add($Record); [pscustomobject]@{ Status = 'ok' } }.GetNewClosure()
        $ctx = [pscustomobject]@{ Mode = 'identified'; Endpoint = 'https://uplink.test'; AccessCode = 'inv-TESTKEY-0123456789'; Edition = 'pro'; LicenceState = 'valid'
                                  Version = '3.0.1'; Hosting = 'container'; RuntimeIdentity = 'mi-container'; InstallId = ''; TenantId = '11111111-2222-3333-4444-555555555555'; StateDirectory = $TestDrive }
        $rc = [pscustomobject]@{ RunId = 'r'; Engine = 'flow'; ShardIndex = 0; ShardCount = 1; CollectionTime = [datetime]::UtcNow; StartedAt = [datetime]::UtcNow
                                 FailedStep = 'lock'; FailedStepError = 'the pipeline lock (acquire) could not be reached'; FailedStepErrorClass = 'transient-sql' }
        $global:SI_TelemetryHalted = $false; $global:SI_Telemetry_Enabled = $null
        $r = Send-SITelemetryRunEnd -RunContext $rc -ExitReason 'success-partial' -ErrorMessage 'x' -Context $ctx -Transport $t -HeartbeatCounts { @{} } -NoHeartbeat
        $r.Status | Should -Be 'ok'
        $w = @($l | Where-Object { $_.Kind -eq 'run' })[0]
        $w.ErrorClass | Should -Be 'transient-sql'
        $w.Outcome | Should -Be 'warning'
        $w.FailedStep | Should -Be 'lock'
        $w.PSObject.Properties['FixKind'] | Should -BeNullOrEmpty -Because 'never a fix request'
        $global:SI_TelemetryHalted = $null
    }
}
