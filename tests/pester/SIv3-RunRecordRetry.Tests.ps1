#Requires -Version 5.1
<#
    #1266 -- A TRANSIENT, RETRIED FAILURE IS NOT A CRITICAL TICKET (framework TRANSIENT-RETRY-1, Invardia 1.0.1093) and the run's
    own end on every run record (framework RUN-MONITOR-STALE-1).

    What must hold:
      - the run record carries Retry { transient, priorVersion, priorHealthy, willRetry, cause } ONLY on a failed step that
        changed nothing: the image build that failed on a registry timeout ("No job was changed") = image-pull-timeout, a build
        that could not be queued (timed out) = queue-start-timeout, the key ring's PATCH still 409 = arm-409 (named by its caller);
      - priorHealthy only from the read-back (latest ready revision = latest, Healthy); unreadable = left out, never assumed;
      - a real failure, a customer action and an ok run carry no Retry;
      - Retry and EndedUtc go through the REAL send path (Send-SITelemetryFailure / Send-SITelemetryRunEnd ->
        ConvertTo-SITelemetryWire -> the transport) -- the wire contract is closed, a field the builder does not add is lost;
      - EndedUtc: ISO 8601 UTC ending in Z, the run's end (not the send time), on every run record; a kept record goes again
        with the same EndedUtc.
    Offline (stub transports, no Azure); PS 5.1 and 7.
#>

BeforeAll {
    $script:SavedInvardiaConnect = $global:SI_Invardia_Connect; $global:SI_Invardia_Connect = 'on'
    $env:SI_Setup_NewInstallNames = 'false'
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\_shared\SI-TelemetrySend.ps1')
    . (Join-Path $script:SIRoot 'container\updater\Start-SIUpdater.ps1') -DefineOnly
    $script:Id = [pscustomobject]@{ Mode = 'identified'; Endpoint = 'https://uplink.test'; AccessCode = ('inv-TESTKEY-' + '0123456789'); Edition = 'pro'; LicenceState = 'valid'
                                    Version = '3.1.23'; Hosting = 'container'; RuntimeIdentity = 'mi-container'; InstallId = ''; TenantId = '11111111-2222-3333-4444-555555555555'; StateDirectory = $TestDrive }
    $script:Anon = [pscustomobject]@{ Mode = 'anonymous'; Endpoint = 'https://uplink.test'; AccessCode = 'community'; Edition = 'community'; LicenceState = 'none'
                                      Version = '3.1.23'; Hosting = 'container'; RuntimeIdentity = 'mi-container'; InstallId = '0f0e0d0c-0b0a-4908-8706-050403020100'; TenantId = ''; StateDirectory = $TestDrive }
    function script:New-Capture {
        $l = New-Object System.Collections.Generic.List[object]
        # the record as handed to the transport (no JSON round trip: PS 7's ConvertFrom-Json would turn a time string into a date)
        [pscustomobject]@{ List = $l; Transport = { param($Record, $Endpoint, $AccessCode, $TimeoutSec) $l.Add($Record); [pscustomobject]@{ Status = 'ok' } }.GetNewClosure() }
    }
    $script:PullTimeout = 'The image build did not succeed (Failed: Get "https://mcr.microsoft.com/v2/": net/http: request canceled while waiting for connection (Client.Timeout exceeded while awaiting headers)). No job was changed.'
    $script:Retry = [pscustomobject]@{ transient = $true; priorVersion = '3.1.23'; priorHealthy = $true; willRetry = $true; cause = 'image-pull-timeout' }
}

AfterAll {
    $global:SI_Invardia_Connect = $script:SavedInvardiaConnect
    $global:SI_TelemetryHalted = $null; $global:SI_TelemetryWarned = $null; $global:SI_UpdaterFailures = $null; $global:SI_UpdaterEngineVersion = $null
}

Describe 'the Retry object: Invardia''s closed shape' {
    It 'exactly the agreed keys, in order; a key outside them is dropped' {
        $w = ConvertTo-SITelemetryRetryWire ([ordered]@{ transient = $true; priorVersion = '3.1.23'; priorHealthy = $false; willRetry = $true; cause = 'arm-409'; attempt = 2; secret = 'x' })
        @($w.PSObject.Properties.Name) | Should -Be @('transient', 'priorVersion', 'priorHealthy', 'willRetry', 'cause', 'attempt')
        $w.priorHealthy | Should -BeFalse
        $w.attempt | Should -Be 2
    }
    It 'transient is required and must be true -- otherwise there is no Retry at all' {
        ConvertTo-SITelemetryRetryWire @{ cause = 'arm-409' } | Should -BeNullOrEmpty
        ConvertTo-SITelemetryRetryWire @{ transient = 'true'; cause = 'arm-409' } | Should -BeNullOrEmpty
        ConvertTo-SITelemetryRetryWire @{ transient = $false; cause = 'arm-409' } | Should -BeNullOrEmpty
        ConvertTo-SITelemetryRetryWire $null | Should -BeNullOrEmpty
    }
    It 'a cause outside the list is other; priorHealthy / willRetry only as booleans; a bad version or attempt is left out' {
        $w = ConvertTo-SITelemetryRetryWire @{ transient = $true; cause = 'whatever'; priorHealthy = 'yes'; willRetry = 1; priorVersion = 'not a version!'; attempt = 0 }
        $w.cause | Should -Be 'other'
        @($w.PSObject.Properties.Name) | Should -Be @('transient', 'cause')
        foreach ($c in (Get-SITelemetryRetryCauses)) { (ConvertTo-SITelemetryRetryWire @{ transient = $true; cause = $c }).cause | Should -Be $c }
    }
}

Describe 'the real send path carries Retry (wiring)' {
    BeforeEach { $global:SI_TelemetryHalted = $false; $global:SI_Telemetry_Enabled = $null }
    It 'identified: Send-SITelemetryFailure -Retry -> the run record on the wire has Retry, exactly as shaped' {
        $c = New-Capture
        $r = Send-SITelemetryFailure -Job updater -Step 'build' -ErrorMessage $script:PullTimeout -Context $script:Id -Transport $c.Transport -Retry $script:Retry
        $r.Status | Should -Be 'ok'
        $c.List.Count | Should -Be 1
        $w = $c.List[0]
        $w.Kind | Should -Be 'run'; $w.Outcome | Should -Be 'failed'; $w.FailedStep | Should -Be 'build'
        @($w.Retry.PSObject.Properties.Name) | Should -Be @('transient', 'priorVersion', 'priorHealthy', 'willRetry', 'cause')
        $w.Retry.transient | Should -BeTrue
        $w.Retry.cause | Should -Be 'image-pull-timeout'
        $w.Retry.priorVersion | Should -Be '3.1.23'
        $w.Retry.priorHealthy | Should -BeTrue
        $w.Retry.willRetry | Should -BeTrue
    }
    It 'anonymous too (a version and an enum identify nobody)' {
        $c = New-Capture
        $null = Send-SITelemetryFailure -Job updater -Step 'post-roll' -ErrorMessage 'busy' -Context $script:Anon -Transport $c.Transport -Retry ([pscustomobject]@{ transient = $true; willRetry = $true; cause = 'arm-409' })
        $c.List[0].Retry.cause | Should -Be 'arm-409'
        $c.List[0].PSObject.Properties['ErrorText'] | Should -BeNullOrEmpty
    }
    It 'a real failure (no -Retry) carries no Retry' {
        $c = New-Capture
        $null = Send-SITelemetryFailure -Job updater -Step 'roll' -ErrorMessage 'si-upd-0803: 2 of 22 job(s) not rolled' -Context $script:Id -Transport $c.Transport
        $c.List[0].PSObject.Properties['Retry'] | Should -BeNullOrEmpty
    }
    It 'a customer action never carries Retry, even when one is handed in' {
        $c = New-Capture
        $null = Send-SITelemetryFailure -Job updater -Step 'secret-handover' -ErrorMessage 'grant the role' -Context $script:Id -Transport $c.Transport -ErrorClass 'kv-403' -CustomerAction -Retry $script:Retry
        $c.List[0].PSObject.Properties['Retry'] | Should -BeNullOrEmpty
    }
    It 'an ok run record never carries Retry' {
        $rec = New-SITelemetryRunRecord -Job 'si-updater' -ExitReason 'success' -DurationMs 5 -Edition pro -Version '3.1.23' -Hosting container -RuntimeIdentity mi-container -LicenceState valid -TenantId 't' -Now ([datetime]'2026-11-15T10:00:00Z')
        $w = ConvertTo-SITelemetryWire -Record $rec -Mode identified -Retry $script:Retry -Build ''
        $w.PSObject.Properties['Retry'] | Should -BeNullOrEmpty
    }
    It 'Retry is on the list of fields a refused record goes again without -- a validator that does not know it never costs the failure' {
        Get-SITelemetryOptionalFields | Should -Contain 'Retry'
        $script:refusals = @()
        $t = { param($Record, $Endpoint, $AccessCode, $TimeoutSec)
               $has = $null -ne $Record.PSObject.Properties['Retry']
               $script:refusals += $(if ($has) { 'with' } else { 'without' })
               if ($has) { [pscustomobject]@{ Status = 'failed'; Reason = '422 unknown field Retry' } } else { [pscustomobject]@{ Status = 'ok' } } }
        $r = Send-SITelemetryFailure -Job updater -Step 'build' -ErrorMessage $script:PullTimeout -Context $script:Id -Transport $t -Retry $script:Retry
        $r.Status | Should -Be 'ok'
        ($script:refusals -join ',') | Should -Be 'with,without'
    }
}

Describe 'EndedUtc: the run''s own end on every run record (RUN-MONITOR-STALE-1)' {
    BeforeEach { $global:SI_TelemetryHalted = $false; $global:SI_Telemetry_Enabled = $null }
    It 'an ok engine run: EndedUtc in Z format, the run''s end' {
        $c = New-Capture
        $rc = [pscustomobject]@{ Engine = 'endpoint'; ShardIndex = 0; StartedAt = [datetime]'2026-11-15T06:00:00Z' }
        $null = Send-SITelemetryRunEnd -RunContext $rc -ExitReason 'success' -AssetCount 10 -Context $script:Id -Transport $c.Transport -Now ([datetime]'2026-11-15T06:42:17Z') -NoHeartbeat
        $run = @($c.List | Where-Object { $_.Kind -eq 'run' })[0]
        [string]$run.EndedUtc | Should -Match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$'
        [string]$run.EndedUtc | Should -Be '2026-11-15T06:42:17Z'
    }
    It 'a run context that recorded its end: that time, not the send time' {
        $c = New-Capture
        $rc = [pscustomobject]@{ Engine = 'endpoint'; ShardIndex = 0; StartedAt = [datetime]'2026-11-15T06:00:00Z'; EndedUtc = [datetime]'2026-11-15T06:30:00Z' }
        $null = Send-SITelemetryRunEnd -RunContext $rc -ExitReason 'error' -ErrorMessage 'x failed' -Context $script:Id -Transport $c.Transport -Now ([datetime]'2026-11-15T06:42:17Z') -NoHeartbeat
        [string]$c.List[0].EndedUtc | Should -Be '2026-11-15T06:30:00Z'
    }
    It 'a failure report (the updater) carries it too' {
        $c = New-Capture
        $null = Send-SITelemetryFailure -Job updater -Step 'roll' -ErrorMessage 'refused' -Context $script:Anon -Transport $c.Transport -Now ([datetime]'2026-11-15T07:01:02Z')
        [string]$c.List[0].EndedUtc | Should -Be '2026-11-15T07:01:02Z'
    }
    It 'the end not known = left out, never the send time; only a run record gets it' {
        ConvertTo-SITelemetryEndedUtc $null | Should -Be ''
        ConvertTo-SITelemetryEndedUtc 'soon' | Should -Be ''
        ConvertTo-SITelemetryEndedUtc ([datetime]'2026-11-15T07:01:02Z') | Should -Be '2026-11-15T07:01:02Z'
        $rec = New-SITelemetryRunRecord -Job 'si-updater' -ExitReason 'success' -DurationMs 5 -Edition pro -Version '3.1.23' -Hosting container -RuntimeIdentity mi-container -LicenceState valid -TenantId 't' -Now ([datetime]'2026-11-15T10:00:00Z')
        (ConvertTo-SITelemetryWire -Record $rec -Mode identified -Build '').PSObject.Properties['EndedUtc'] | Should -BeNullOrEmpty
        $hb = New-SITelemetryHeartbeat -Edition pro -Version '3.1.23' -Hosting container -RuntimeIdentity mi-container -LicenceState valid -TenantId 't' -Now ([datetime]'2026-11-15T10:00:00Z')
        (ConvertTo-SITelemetryWire -Record $hb -Mode identified -Build '' -EndedUtc ([datetime]'2026-11-15T10:00:00Z')).PSObject.Properties['EndedUtc'] | Should -BeNullOrEmpty
    }
    It 'a kept record goes again with the SAME EndedUtc (the stored end, never the resend time)' {
        $rc = [pscustomobject]@{ Engine = 'endpoint'; ShardIndex = 0; StartedAt = [datetime]'2026-11-15T06:00:00Z' }
        $first = New-Capture
        $null = Send-SITelemetryRunEnd -RunContext $rc -ExitReason 'error' -ErrorMessage 'x failed' -Context $script:Id -Transport $first.Transport -Now ([datetime]'2026-11-15T06:42:17Z') -NoHeartbeat
        $json = ConvertTo-SIUplinkOutboxJson -Record $first.List[0]
        $again = ConvertFrom-SIUplinkOutboxJson -Json $json
        $sent = New-Capture
        $null = Send-SITelemetryRecordWithFallback -Record $again -Transport $sent.Transport -Context $script:Id -NowUtc ([datetime]'2026-11-16T09:00:00Z')
        [string]$sent.List[0].EndedUtc | Should -Be '2026-11-15T06:42:17Z'
        [string]$sent.List[0].EndedUtc | Should -Be ([string]$first.List[0].EndedUtc)
    }
    It 'EndedUtc is added by the closed builder itself (the framework client does not know it)' {
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\_shared\SI-TelemetrySend.ps1'))
        $src | Should -Match "Add-Member -NotePropertyName 'EndedUtc'"
        $src | Should -Match '-Retry \$retryIn -EndedUtc \$endedIn'
    }
}

Describe 'the updater: which failure is transient' {
    It 'image-pull-timeout: the build''s own "No job was changed" with a registry timeout' {
        Get-SIUpdaterTransientCause -Step 'build' -Text $script:PullTimeout | Should -Be 'image-pull-timeout'
        Get-SIUpdaterTransientCause -Step 'build' -Text 'The base image build did not succeed (Failed: failed to resolve source metadata for mcr.microsoft.com/powershell: TLS handshake timeout). No job was changed.' | Should -Be 'image-pull-timeout'
        Get-SIUpdaterTransientCause -Step 'build' -Text 'The image build did not succeed (Error: dial tcp: lookup https://acrx.azurecr.io/v2/: i/o timeout). No job was changed.' | Should -Be 'image-pull-timeout'
    }
    It 'queue-start-timeout: the build could not be queued in time -- nothing ran' {
        Get-SIUpdaterTransientCause -Step 'build' -Text 'The image build could not be queued (the scheduleRun request timed out after 100 s). No job was changed.' | Should -Be 'queue-start-timeout'
    }
    It 'real failures: a broken build, a roll, a restore, a timeout without "No job was changed", a queue refusal' {
        Get-SIUpdaterTransientCause -Step 'build' -Text 'The image build did not succeed (Failed). No job was changed.' | Should -Be ''
        Get-SIUpdaterTransientCause -Step 'roll' -Text $script:PullTimeout | Should -Be ''
        Get-SIUpdaterTransientCause -Step 'restore' -Text 'si-upd-0804: caj-si-x could not be put back: i/o timeout on https://acrx.azurecr.io/v2/' | Should -Be ''
        Get-SIUpdaterTransientCause -Step 'build' -Text 'Get "https://mcr.microsoft.com/v2/": Client.Timeout exceeded' | Should -Be ''
        Get-SIUpdaterTransientCause -Step 'build' -Text 'The image build could not be queued (HTTP 403 AuthorizationFailed). No job was changed.' | Should -Be ''
    }
    It 'the build failure line: the registry timeout from the log, nothing for another failure' {
        . (Join-Path $script:SIRoot 'setup\_shared\SI-FastRoll.ps1')
        $b = [pscustomobject]@{ Status = 'Failed'; LogTail = @('Step 1/9 : FROM mcr.microsoft.com/powershell:7.6', 'Get "https://mcr.microsoft.com/v2/": net/http: request canceled (Client.Timeout exceeded while awaiting headers)') }
        Get-SIAcrBuildFailureLine -Build $b | Should -Match '^Get "https://mcr\.microsoft\.com/v2/".*Client\.Timeout exceeded'
        Get-SIAcrBuildFailureLine -Build ([pscustomobject]@{ Status = 'Failed'; LogTail = @('error: exit code 1') }) | Should -Be ''
        Get-SIAcrBuildFailureLine -Build ([pscustomobject]@{ Status = 'Failed' }) | Should -Be ''
    }
    It 'the release''s build step puts that line into its failure, and says "could not be queued" for a queue failure (wiring)' {
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'setup\Invoke-SIContainerUpdate.ps1'))
        $src | Should -Match 'Get-SIAcrBuildFailureLine -Build \$eb'
        $src | Should -Match 'Get-SIAcrBuildFailureLine -Build \$b\b'
        $src | Should -Match 'The image build could not be queued \(\{0\}\)\. No job was changed\.'
    }
}

Describe 'priorHealthy only from the read-back' {
    BeforeAll {
        function script:New-App([string]$Latest = 'web--r2', [string]$Ready = 'web--r2') { [pscustomobject]@{ properties = [pscustomobject]@{ latestRevisionName = $Latest; latestReadyRevisionName = $Ready } } }
        function script:New-Rev([string]$Name = 'web--r2', [string]$Health = 'Healthy') { [pscustomobject]@{ name = $Name; properties = [pscustomobject]@{ healthState = $Health } } }
    }
    It 'ready = latest and Healthy = $true' { Test-SIUpdaterPriorHealthy -App (New-App) -Revision (New-Rev) | Should -BeTrue }
    It 'ready behind latest = $false; Unhealthy = $false' {
        Test-SIUpdaterPriorHealthy -App (New-App -Ready 'web--r1') -Revision (New-Rev) | Should -BeFalse
        Test-SIUpdaterPriorHealthy -App (New-App) -Revision (New-Rev -Health 'Unhealthy') | Should -BeFalse
    }
    It 'not readable = $null (no app, no revision name, no revision, no health, another revision)' {
        Test-SIUpdaterPriorHealthy -App $null -Revision (New-Rev) | Should -BeNullOrEmpty
        Test-SIUpdaterPriorHealthy -App (New-App -Latest '' -Ready '') -Revision (New-Rev) | Should -BeNullOrEmpty
        Test-SIUpdaterPriorHealthy -App (New-App) -Revision $null | Should -BeNullOrEmpty
        Test-SIUpdaterPriorHealthy -App (New-App) -Revision (New-Rev -Health '') | Should -BeNullOrEmpty
        Test-SIUpdaterPriorHealthy -App (New-App) -Revision (New-Rev -Name 'web--r9') | Should -BeNullOrEmpty
    }
    It 'Read-SIUpdaterPriorHealth reads the web app and its latest revision over ARM; a read that fails = $null' {
        $script:paths = New-Object System.Collections.Generic.List[string]
        $arm = { param($Path) $script:paths.Add($Path); if ($Path -like '*/revisions/*') { New-Rev } else { New-App } }
        $e = @{ SI_UPDATER_SUBSCRIPTION_ID = 's'; SI_UPDATER_RESOURCE_GROUP = 'rg'; SI_UPDATER_WEB_APP = 'ca-si-management' }
        Read-SIUpdaterPriorHealth -Env $e -Arm $arm | Should -BeTrue
        $script:paths[0] | Should -Be '/subscriptions/s/resourceGroups/rg/providers/Microsoft.App/containerApps/ca-si-management'
        $script:paths[1] | Should -Be '/subscriptions/s/resourceGroups/rg/providers/Microsoft.App/containerApps/ca-si-management/revisions/web--r2'
        Read-SIUpdaterPriorHealth -Env $e -Arm { param($Path) throw 'HTTP 503' } | Should -BeNullOrEmpty
        Read-SIUpdaterPriorHealth -Env @{} -Arm $arm | Should -BeNullOrEmpty
    }
}

Describe 'the updater''s failure reports: Retry only where nothing changed' {
    BeforeEach {
        $global:SI_UpdaterFailures = $null
        $global:SI_UpdaterEngineVersion = '3.1.23'
        $script:sent = New-Object System.Collections.Generic.List[object]
        $script:send = { param($Step, $Text, $f, $Retry) $script:sent.Add([pscustomobject]@{ Step = $Step; Retry = $Retry }); [pscustomobject]@{ Status = 'ok' } }
        $script:healthAsked = 0
    }
    It 'a build that failed on a registry timeout: Retry image-pull-timeout, the version that stays, priorHealthy as read back' {
        Add-SIUpdaterFailure -Step 'build' -Text $script:PullTimeout
        $null = Send-SIUpdaterFailureReports -ExitCode 1 -Send $script:send -PriorHealth { $script:healthAsked++; $true }
        $script:sent.Count | Should -Be 1
        $r = $script:sent[0].Retry
        $r.transient | Should -BeTrue
        $r.cause | Should -Be 'image-pull-timeout'
        $r.priorVersion | Should -Be '3.1.23'
        $r.priorHealthy | Should -BeTrue
        $r.willRetry | Should -BeTrue
        $r.PSObject.Properties['attempt'] | Should -BeNullOrEmpty -Because 'Invardia counts the attempts of a job + step'
        $script:healthAsked | Should -Be 1
    }
    It 'the key ring''s 409 named by its caller: Retry arm-409; the read-back says not healthy = priorHealthy false' {
        Add-SIUpdaterFailure -Step 'post-roll' -Text 'ca-si-management: its sign-in keys were NOT moved -- busy (409)' -Transient 'arm-409'
        $null = Send-SIUpdaterFailureReports -ExitCode 0 -Send $script:send -PriorHealth { $false }
        $script:sent[0].Retry.cause | Should -Be 'arm-409'
        $script:sent[0].Retry.priorHealthy | Should -BeFalse
    }
    It 'the read-back not readable ($null) or throwing: priorHealthy is LEFT OUT, never assumed' {
        Add-SIUpdaterFailure -Step 'post-roll' -Text 'busy' -Transient 'arm-409'
        $null = Send-SIUpdaterFailureReports -ExitCode 0 -Send $script:send -PriorHealth { $null }
        $script:sent[0].Retry.PSObject.Properties['priorHealthy'] | Should -BeNullOrEmpty
        $script:sent.Clear()
        $null = Send-SIUpdaterFailureReports -ExitCode 0 -Send $script:send -PriorHealth { throw 'ARM 503' }
        $script:sent[0].Retry.PSObject.Properties['priorHealthy'] | Should -BeNullOrEmpty
        $script:sent.Clear()
        $null = Send-SIUpdaterFailureReports -ExitCode 0 -Send $script:send
        $script:sent[0].Retry.PSObject.Properties['priorHealthy'] | Should -BeNullOrEmpty
    }
    It 'a real failure gets no Retry -- and the web app is not even read' {
        Add-SIUpdaterFailure -Step 'roll' -Text 'si-upd-0803: 2 of 22 job(s) not rolled' -Code 'si-upd-0803'
        Add-SIUpdaterFailure -Step 'build' -Text 'The image build did not succeed (Failed). No job was changed.'
        $null = Send-SIUpdaterFailureReports -ExitCode 1 -Send $script:send -PriorHealth { $script:healthAsked++; $true }
        $script:sent.Count | Should -Be 2
        @($script:sent | Where-Object { $_.Retry }).Count | Should -Be 0
        $script:healthAsked | Should -Be 0
    }
    It 'a customer action gets no Retry' {
        Add-SIUpdaterCustomerAction -Step 'post-roll' -Text 'Support-app step: remove the role' -Class 'arm-403'
        $null = Send-SIUpdaterFailureReports -ExitCode 0 -Send $script:send -PriorHealth { $true }
        $script:sent[0].Retry | Should -BeNullOrEmpty
    }
    It 'two transient failures in one run: the web app is read once' {
        Add-SIUpdaterFailure -Step 'build' -Text $script:PullTimeout
        Add-SIUpdaterFailure -Step 'post-roll' -Text 'busy' -Transient 'arm-409'
        $null = Send-SIUpdaterFailureReports -ExitCode 1 -Send $script:send -PriorHealth { $script:healthAsked++; $true }
        @($script:sent | Where-Object { $_.Retry }).Count | Should -Be 2
        $script:healthAsked | Should -Be 1
    }
    It 'the real path hands Retry to Send-SITelemetryFailure only when it takes -Retry (wiring)' {
        (Get-Command -Name Send-SITelemetryFailure).Parameters.ContainsKey('Retry') | Should -BeTrue
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\updater\_shared\SI-UpdaterTelemetry.ps1'))
        $src | Should -Match "\`$sc\.Parameters\.ContainsKey\('Retry'\)\) \{ \`$codeArgs\.Retry = \`$retry \}"
        $src | Should -Match 'else \{ Send-SITelemetryFailure -Job updater -Step \$f\.Step -ErrorMessage \$f\.Text -Context \$ctx -StartedAt \$StartedAt @codeArgs \}'
        $upd = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\updater\Start-SIUpdater.ps1'))
        $upd | Should -Match '\$PriorHealth = \{ Read-SIUpdaterPriorHealth \}'
        $upd | Should -Match "Add-SIUpdaterFailureIf 'post-roll' \(\(@\(\`$k\.Lines\) \| Select-Object -Last 1\) -join ''\) '' \`$kt"
    }
}
