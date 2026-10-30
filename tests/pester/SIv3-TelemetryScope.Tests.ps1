#Requires -Version 5.1
<#
    SecurityInsight -- THE RUN REPORT IS BUILT WHATEVER SCRIPT LOADED THE TELEMETRY CODE (2026-10-29: every collection
    execution logged "The status report to Invardia could not be prepared (si-upl-0601: telemetry: 'si-ptc' is not a valid
    Job ())", so no collection run reached Invardia).

    The cause: the container entrypoint loads Send-SIRunHealthRow (and with it the telemetry code) in ITS script; the engine
    is started from it as its own script and loads the same file, whose guards see the functions defined and skip the
    load. The functions then read their lists from the engine's script scope, where they were never set.

    What must hold, in a SEPARATE process that loads the code exactly that way:
      - the engine's script scope really has no telemetry lists of its own before the report (the faulty path is taken);
      - each engine kind -- a collection (si-ptc, si-identity), the pipeline (si-flow), Risk Analysis (si-ra-detailed) and
        the data sync (si-datasync) -- builds and hands over a valid run record: its Job, Edition, Outcome and Product are
        on the wire record, and no "could not be prepared" warning is written;
      - an anonymous report keeps its Edition and its endpoint (the framework client's lists, read the same way).
    Offline: the transport is a stub inside the child process; nothing is sent.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:Pwsh = (Get-Process -Id $PID).Path
    $script:Work = Join-Path ([System.IO.Path]::GetTempPath()) ('si-telscope-' + [guid]::NewGuid().ToString('N'))
    $null = New-Item -ItemType Directory -Path $script:Work
    $script:RunHealth = Join-Path $script:SIRoot 'engine\asset-profiling\shared\Send-SIRunHealthRow.ps1'

    function script:Invoke-ContainerShaped([string]$Mode = 'identified') {
        # the engine: started by the entrypoint as its own script, loads the run-health file as Invoke-SIEngineRun does,
        # then reports one ok run per engine kind through a stub transport and prints what went on the wire
        $engine = Join-Path $script:Work ('engine-' + [guid]::NewGuid().ToString('N') + '.ps1')
        $ctx = if ($Mode -eq 'anonymous') {
            "[pscustomobject]@{ Mode = 'anonymous'; Endpoint = 'https://uplink.test'; AccessCode = 'community-code'; Edition = 'community'; LicenceState = 'none'; Version = '3.0.0'; Hosting = 'container'; RuntimeIdentity = 'mi-container'; InstallId = '0f8fad5b-d9cb-469f-a165-70867728950e'; TenantId = ''; StateDirectory = '$($script:Work)' }"
        } else {
            "[pscustomobject]@{ Mode = 'identified'; Endpoint = 'https://uplink.test'; AccessCode = 'inv-TESTKEY-0123456789'; Edition = 'pro'; LicenceState = 'valid'; Version = '3.0.0'; Hosting = 'container'; RuntimeIdentity = 'mi-container'; InstallId = ''; TenantId = '11111111-2222-3333-4444-555555555555'; Endpoints = @(); StateDirectory = '$($script:Work)' }"
        }
        Set-Content -LiteralPath $engine -Encoding UTF8 -Value @"
`$ErrorActionPreference = 'Continue'
. '$script:RunHealth'
'engineScopeLists=' + [string](`$null -ne `$script:SITelemetry)
`$global:SI_Telemetry_Enabled = `$true
`$cap = New-Object System.Collections.Generic.List[object]
`$tr = { param(`$Record, `$Endpoint, `$AccessCode, `$TimeoutSec) `$cap.Add([pscustomobject]@{ R = `$Record; E = `$Endpoint }); [pscustomobject]@{ Status = 'ok' } }.GetNewClosure()
`$ctx = $ctx
foreach (`$k in @(@('privilege-tier-classifier', ''), @('identity', ''), @('flow', ''), @('risk-analysis', 'RiskAnalysis_Detailed'), @('asset-datasync', ''))) {
    `$global:ReportTemplate = `$k[1]
    `$rc = [pscustomobject]@{ Engine = `$k[0]; ShardIndex = 0; StartedAt = [datetime]::UtcNow.AddMinutes(-5) }
    `$r = Send-SITelemetryRunEnd -RunContext `$rc -ExitReason 'success' -ErrorMessage '' -Context `$ctx -Transport `$tr -NoHeartbeat
    'status ' + `$k[0] + '=' + [string]`$r.Status + '|' + [string]`$r.Reason
}
'sender=' + [string](& { Initialize-SIAitUplinkScope; (Resolve-AitUplinkSender -Enabled `$true -InstallKey '' -Endpoint '').Endpoint })
foreach (`$c in `$cap) { 'wire=' + [string]`$c.R.Job + '|' + [string]`$c.R.Edition + '|' + [string]`$c.R.Outcome + '|' + [string]`$c.R.Product + '|' + [string]`$c.R.Kind + '|' + [string]`$c.E }
"@
        # the entrypoint: loads the run-health file in ITS script (as the container does before the engine), then starts the engine
        $entry = Join-Path $script:Work ('entry-' + [guid]::NewGuid().ToString('N') + '.ps1')
        Set-Content -LiteralPath $entry -Encoding UTF8 -Value @"
`$ErrorActionPreference = 'Continue'
. '$script:RunHealth'
'entryFn=' + [string][bool](Get-Command -Name Send-SITelemetryRunEnd -ErrorAction SilentlyContinue)
& '$engine'
"@
        @(& $script:Pwsh -NoProfile -NonInteractive -File $entry 2>&1 | ForEach-Object { [string]$_ })
    }
}

AfterAll { Remove-Item -LiteralPath $script:Work -Recurse -Force -ErrorAction SilentlyContinue }

Describe 'SIv3-TelemetryScope: the run report of every engine kind, telemetry loaded by the entrypoint first' {
    BeforeAll { $script:Out = Invoke-ContainerShaped -Mode identified }

    It 'takes the faulty path: the entrypoint defined the functions, the engine''s own script has no lists of its own' {
        $script:Out | Should -Contain 'entryFn=True'
        $script:Out | Should -Contain 'engineScopeLists=False'
    }

    It 'every engine kind''s report is handed over (status ok), none "could not be prepared"' {
        foreach ($e in 'privilege-tier-classifier', 'identity', 'flow', 'risk-analysis', 'asset-datasync') {
            @($script:Out | Where-Object { $_ -like "status $e=ok|*" }).Count | Should -Be 1 -Because $e
        }
        @($script:Out | Where-Object { $_ -match 'could not be prepared|si-upl-0601|is not a valid' }) | Should -BeNullOrEmpty
    }

    It 'the wire record carries the Job, Edition, Outcome and Product of each kind' {
        foreach ($j in 'si-ptc', 'si-identity', 'si-flow', 'si-ra-detailed', 'si-datasync') {
            $script:Out | Should -Contain "wire=$j|pro|ok|securityinsight|run|https://uplink.test"
        }
    }

    It 'an anonymous report keeps its Edition and the community endpoint (the framework client''s lists)' {
        $a = Invoke-ContainerShaped -Mode anonymous
        $a | Should -Contain 'engineScopeLists=False'
        $w = @($a | Where-Object { $_ -like 'wire=si-ptc|*' })[0]
        $w | Should -Be 'wire=si-ptc|community|ok|securityinsight|run|https://uplink.test'
        @($a | Where-Object { $_ -like 'sender=*' })[0] | Should -Match '^sender=https://'
    }
}

Describe 'SIv3-TelemetryScope: a list getter makes its value in the scope that reads it' {
    It 'Get-SITelemetryState answers the lists in a script that never loaded the file' {
        $f = Join-Path $script:Work 'reader.ps1'
        Set-Content -LiteralPath $f -Encoding UTF8 -Value "'jobs=' + (@((Get-SITelemetryState).Jobs) -contains 'si-ptc'); 'classes=' + (@(Get-SIErrorClasses) -contains 'unknown'); 'counts=' + (@(Get-SITelemetryHeartbeatCountNames) -contains 'users')"
        $p = Join-Path $script:Work 'loader.ps1'
        Set-Content -LiteralPath $p -Encoding UTF8 -Value ". '$(Join-Path $script:SIRoot 'engine\_shared\SI-TelemetrySend.ps1')'`n& '$f'"
        $o = @(& $script:Pwsh -NoProfile -NonInteractive -File $p 2>&1 | ForEach-Object { [string]$_ })
        $o | Should -Contain 'jobs=True'
        $o | Should -Contain 'classes=True'
        $o | Should -Contain 'counts=True'
    }
}
