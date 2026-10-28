#Requires -Version 5.1
<#
    SecurityInsight -- WHAT A FAILED RUN REPORT CARRIES (owner 2026-10-10: "fix issues from si telemetry"; Invardia saw most
    SI failed-run reports as ErrorClass 'unknown' with only the pipeline's summary, "Daily pipeline . failed; 1 failed, 7
    skipped, 4 success", and si-trend reports with no text at all).

    What must hold:
      - the pipeline's report (si-flow) NAMES the failed step and carries THAT step's error class and first error lines --
        read from the step's own run log -- not the summary line; the summary stays after the step's words;
      - a run with no error text never sends an empty text: it falls back to the run's last log lines (their first error
        lines); a caught exception without a message says its type;
      - secrets in those lines are redacted (the uplink's own redaction) before they leave;
      - the failed report carries the run-health Link when the install knows its web app.
    Offline; every post is a stub. PS 5.1 and 7.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\_shared\SI-TelemetrySend.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-JobFlow.ps1')
    $script:Id = [pscustomobject]@{ Mode = 'identified'; Endpoint = 'https://uplink.test'; AccessCode = 'inv-TESTKEY-0123456789'; Edition = 'pro'; LicenceState = 'valid'
                                    Version = '3.0.0'; Hosting = 'container'; RuntimeIdentity = 'mi-container'; InstallId = ''; TenantId = '11111111-2222-3333-4444-555555555555'; StateDirectory = $TestDrive
                                    Endpoints = @([pscustomobject]@{ kind = 'webapp'; url = 'https://si.contoso.example' }) }
    function script:New-Capture { $l = New-Object System.Collections.Generic.List[object]; [pscustomobject]@{ List = $l; Transport = { param($Record, $Endpoint, $AccessCode, $TimeoutSec) $l.Add($Record); [pscustomobject]@{ Status = 'ok' } }.GetNewClosure() } }
    $script:Now = [datetime]'2026-10-10T19:30:00Z'
    # a heartbeat is not due (sent today) -- the run report is the only record
    Set-SITelemetryLastHeartbeat -StateDirectory $TestDrive -NowUtc $script:Now
    $script:IdentityLog = @(
        '**********************', 'PowerShell transcript start', 'Start time: 20261010192000', '**********************',
        '[INFO] identity: signing in as the job''s managed identity',
        '[INFO] identity: 1.234 users read',
        '[ERROR] identity: Graph refused /users?$select=signInActivity: Response status code does not indicate success: 403 (Forbidden). Authorization_RequestDenied',
        'at Invoke-SIGraph, /app/engine/_shared/SI-AzRest.ps1: line 210',
        '**********************', 'PowerShell transcript end', 'End time: 20261010192500', '**********************')
}

AfterAll { $global:SI_TelemetryHalted = $null; $global:SI_TelemetryWarned = $null; $global:SI_TelemetryContext = $null; $global:SI_Telemetry_Enabled = $null }

Describe 'the failed step of the pipeline' {
    BeforeEach { $global:SI_TelemetryHalted = $false; $global:SI_TelemetryWarned = $false; $global:SI_Telemetry_Enabled = $null }
    It 'the step''s own run log gives its class and first error lines (Get-SIJobFlowStepFailure)' {
        $step = [pscustomobject]@{ Job = 'identity'; State = 'Failed'; ErrorClass = 'job-failed'; Error = 'the execution ended failed' }
        $f = Get-SIJobFlowStepFailure -Step $step -LogLines $script:IdentityLog
        $f.Step | Should -Be 'identity'
        $f.ErrorClass | Should -Be 'graph-403'
        $f.Text | Should -Match '^\[ERROR\] identity: Graph refused'
        $f.Text | Should -Not -Match 'transcript start|1\.234 users read'
        # no run log: the step's recorded error; a step timeout without a better class is platform-timeout
        (Get-SIJobFlowStepFailure -Step ([pscustomobject]@{ Job = 'ptc'; State = 'TimedOut'; ErrorClass = 'timeout'; Error = 'still running after 180 minutes (the step''s timeout)' }) -LogLines $null).ErrorClass | Should -Be 'platform-timeout'
        (Get-SIJobFlowStepFailure -Step ([pscustomobject]@{ Job = 'endpoint'; State = 'Failed'; ErrorClass = 'throttled'; Error = 'x' }) -LogLines $null).ErrorClass | Should -Be 'throttled'
    }
    It 'the pipeline report names the step and carries ITS class + lines (not the summary), with the Link' {
        $c = New-Capture
        $rc = [pscustomobject]@{ Engine = 'flow'; ShardIndex = 0; StartedAt = $script:Now.AddMinutes(-20); FailedStep = 'identity'
                                 FailedStepError = (Get-SIErrorLines -Lines $script:IdentityLog); FailedStepErrorClass = 'graph-403' }
        $r = Send-SITelemetryRunEnd -RunContext $rc -ExitReason 'error' -ErrorMessage 'Daily pipeline · failed; 1 failed, 7 skipped, 4 success' -Context $script:Id -Transport $c.Transport -Now $script:Now
        $r.Status | Should -Be 'ok'
        $run = @($c.List | Where-Object { $_.Kind -eq 'run' })[0]
        $run.Job | Should -Be 'si-flow'
        $run.FailedStep | Should -Be 'identity'
        $run.ErrorClass | Should -Be 'graph-403'
        $run.ErrorText | Should -Match '^\[ERROR\] identity: Graph refused'
        $run.ErrorText | Should -Match '1 failed, 7 skipped'   # the summary kept AFTER the step's words
        $run.FixKind | Should -Be 'customer-config'
        $run.Link | Should -Match '^https://si\.contoso\.example'
    }
    It 'a step class the store does not know is re-derived from the step''s words, never "unknown" for a recognisable error' {
        $c = New-Capture
        $rc = [pscustomobject]@{ Engine = 'flow'; ShardIndex = 0; StartedAt = $script:Now.AddMinutes(-20); FailedStep = 'verification'
                                 FailedStepError = "Login failed for user '<token-identified principal>'."; FailedStepErrorClass = 'job-failed' }
        $null = Send-SITelemetryRunEnd -RunContext $rc -ExitReason 'error' -ErrorMessage 'Daily pipeline · failed' -Context $script:Id -Transport $c.Transport -Now $script:Now
        @($c.List | Where-Object { $_.Kind -eq 'run' })[0].ErrorClass | Should -Be 'sql-login'
    }
}

Describe 'never an empty text' {
    BeforeEach { $global:SI_TelemetryHalted = $false; $global:SI_TelemetryWarned = $false; $global:SI_Telemetry_Enabled = $null }
    It 'an empty error text falls back to the run''s last log lines (its first error lines)' {
        $log = Join-Path $TestDrive 'asset-trend_container_20261010T192000Z.log'
        [IO.File]::WriteAllLines($log, [string[]]@('[INFO] trend: reading', '[INFO] trend: 12 rows', 'Exception calling "Post" with "1" argument(s): "The remote server returned an error: (503) Server Unavailable."', '[INFO] trend: done'))
        $saved = $global:SI_TranscriptPath
        try {
            $global:SI_TranscriptPath = $log
            $c = New-Capture
            $rc = [pscustomobject]@{ Engine = 'asset-trend'; ShardIndex = 0; StartedAt = $script:Now.AddMinutes(-2) }
            $null = Send-SITelemetryRunEnd -RunContext $rc -ExitReason 'error' -ErrorMessage '' -Context $script:Id -Transport $c.Transport -Now $script:Now
            $run = @($c.List | Where-Object { $_.Kind -eq 'run' })[0]
            $run.Job | Should -Be 'si-trend'
            $run.ErrorText | Should -Match '503'
            $run.ErrorText | Should -Not -Match 'reading'
            $run.ErrorClass | Should -Be 'platform-5xx'
        } finally { $global:SI_TranscriptPath = $saved }
    }
    It 'no log either: a sentence that says so, never an empty text; an exception without a message names its type' {
        $saved = $global:SI_TranscriptPath
        try {
            $global:SI_TranscriptPath = $null
            $d = Resolve-SITelemetryFailureDetail -RunContext ([pscustomobject]@{ Engine = 'asset-trend' }) -ErrorMessage '' -ExitReason 'error' -LogLines @()
            $d.Text | Should -BeNullOrEmpty
            $c = New-Capture
            $null = Send-SITelemetryRunEnd -RunContext ([pscustomobject]@{ Engine = 'asset-trend'; ShardIndex = 0 }) -ExitReason 'error' -ErrorMessage '' -Context $script:Id -Transport $c.Transport -Now $script:Now
            @($c.List | Where-Object { $_.Kind -eq 'run' })[0].ErrorText | Should -Match 'without an error message'
        } finally { $global:SI_TranscriptPath = $saved }
        try { throw [System.InvalidOperationException]::new('') } catch { $s = Get-SIErrorRecordSummary -ErrorRecord $_ }
        $s | Should -Match 'System.InvalidOperationException'
        Get-SIErrorRecordSummary -ErrorRecord ([System.Exception]::new('boom')) | Should -Be 'boom'
    }
}

Describe 'secrets never leave' {
    BeforeEach { $global:SI_TelemetryHalted = $false; $global:SI_TelemetryWarned = $false; $global:SI_Telemetry_Enabled = $null }
    It 'a token, a SAS signature and a password in the step''s lines are redacted' {
        # built at run time: a token-shaped literal in shipped code trips the publish sanitizer
        $script:FakeJwt = ('ey' + 'JhbGciOiJSUzI1NiJ9') + '.' + ('ey' + 'JhdWQiOiJ4In0') + '.c2lnbmF0dXJlc2lnbmF0dXJl'
        $lines = @('[ERROR] upload failed: https://st.blob.core.windows.net/c/x?sv=2024&sig=SECRETSIG123&se=2026 returned 403',
                   ('Authorization: Bearer ' + $script:FakeJwt), 'password=Hunter2Secret;')
        $c = New-Capture
        $rc = [pscustomobject]@{ Engine = 'flow'; ShardIndex = 0; StartedAt = $script:Now.AddMinutes(-5); FailedStep = 'asset-tagging'
                                 FailedStepError = (Get-SIErrorLines -Lines $lines); FailedStepErrorClass = '' }
        $null = Send-SITelemetryRunEnd -RunContext $rc -ExitReason 'error' -ErrorMessage 'Daily pipeline · failed' -Context $script:Id -Transport $c.Transport -Now $script:Now
        $t = @($c.List | Where-Object { $_.Kind -eq 'run' })[0].ErrorText
        $t | Should -Not -Match ('SECRETSIG123|Hunter2Secret|' + [regex]::Escape($script:FakeJwt.Substring(0, 30)))
        $t | Should -Match 'sig=\[redacted\]'
    }
}

Describe 'the step''s run log is found (container storage / VM folder)' {
    It 'the latest transcript of THAT engine inside the step''s window, a producer log counts, another engine does not' {
        $names = @('run-logs/identity/identity_container_20261010T190000Z.log', 'run-logs/identity/identity_container_20261010T192100Z.log',
                   'run-logs/identity-producer/identity-producer_container_20261010T192200Z.log', 'run-logs/endpoint/endpoint_container_20261010T192300Z.log',
                   'run-logs/identity/identity_container_20261011T010000Z.log')
        Select-SIJobFlowStepLog -Names $names -Engine 'identity' -Key 'identity' -StartedUtc ([datetime]'2026-10-10T19:20:00Z') -EndedUtc ([datetime]'2026-10-10T19:25:00Z') | Should -Be 'run-logs/identity-producer/identity-producer_container_20261010T192200Z.log'
        Select-SIJobFlowStepLog -Names $names -Engine 'privilege-tier-classifier' -Key 'ptc' -StartedUtc ([datetime]'2026-10-10T19:20:00Z') -EndedUtc ([datetime]'2026-10-10T19:25:00Z') | Should -Be ''
    }
    It 'the reader returns the lines through its seams, and never throws' {
        $rd = New-SIJobFlowStepLogReader -ListNames { param($e) @("run-logs/$e/${e}_container_20261010T192100Z.log") } -ReadText { param($n) "line one`n[ERROR] it broke" }
        $r = $rd.Read('caj-si-identity', [datetime]'2026-10-10T19:20:00Z', [datetime]'2026-10-10T19:25:00Z')
        $r.Name | Should -Be 'run-logs/identity/identity_container_20261010T192100Z.log'
        @($r.Lines)[-1] | Should -Be '[ERROR] it broke'
        $bad = New-SIJobFlowStepLogReader -ListNames { throw 'storage down' }
        $bad.Read('identity', [datetime]'2026-10-10T19:20:00Z', [datetime]'2026-10-10T19:25:00Z') | Should -BeNullOrEmpty
    }
    It 'the pipeline runner wires it: the failed step''s class + lines go on the run context it reports' {
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\flow\Invoke-SIJobFlowRun.ps1'))
        $src | Should -Match ([regex]::Escape('$pipeFail = Get-SIJobFlowStepFailure -Step $pipeBad[0]'))
        $src | Should -Match ([regex]::Escape('-NotePropertyName FailedStepError -NotePropertyValue'))
        $src | Should -Match ([regex]::Escape('-NotePropertyName FailedStepErrorClass -NotePropertyValue'))
        $src | Should -Match ([regex]::Escape('New-SIJobFlowStepLogReader -StorageAccount'))
    }
}
