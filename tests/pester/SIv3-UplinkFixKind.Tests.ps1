#Requires -Version 5.1
<#
    SecurityInsight -- WHO FIXES A FAILURE: FixKind on the run reports (framework DOCS/REQUIREMENTS.md §8.5 CLOSE-LOOP,
    Invardia live 2026-10-09, migration 046).

    What must hold:
      - every run report that did not end ok and carries an ErrorClass also carries FixKind, one of Invardia's closed list
        (customer-config | product-defect);
      - customer-config ONLY for the classes whose definition is the customer's configuration: the five missing-permission
        classes (graph / defender / arm / kv / storage -403), licence-invalid, config-missing, settings-error -- every
        other class (unknown included) is product-defect, never guessed from free text;
      - an ok run and a heartbeat carry no FixKind; a failure report from the install or the updater carries it like an
        engine run; anonymous reports carry it too (an enum identifies nobody) but still no text;
      - nothing here contacts Invardia: every post is a stub.
    Offline; PS 5.1 and 7.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\_shared\SI-TelemetrySend.ps1')
    $script:FixKinds = @('customer-config', 'product-defect')   # Invardia packages/core/src/fixrequests.ts REPORT_FIX_KINDS
    $script:Id = [pscustomobject]@{ Mode = 'identified'; Endpoint = 'https://uplink.test'; AccessCode = 'inv-TESTKEY-0123456789'; Edition = 'pro'; LicenceState = 'valid'
                                    Version = '3.0.0'; Hosting = 'container'; RuntimeIdentity = 'mi-container'; InstallId = ''; TenantId = '11111111-2222-3333-4444-555555555555'; StateDirectory = $TestDrive }
    $script:Anon = [pscustomobject]@{ Mode = 'anonymous'; Endpoint = 'https://uplink.test'; AccessCode = 'community'; Edition = 'community'; LicenceState = 'none'
                                      Version = '3.0.0'; Hosting = 'vm'; RuntimeIdentity = 'spn-certificate'; InstallId = '0f0e0d0c-0b0a-4908-8706-050403020100'; TenantId = ''; StateDirectory = $TestDrive }
    function script:New-Capture { $l = New-Object System.Collections.Generic.List[object]; [pscustomobject]@{ List = $l; Transport = { param($Record, $Endpoint, $AccessCode, $TimeoutSec) $l.Add($Record); [pscustomobject]@{ Status = 'ok' } }.GetNewClosure() } }
    function script:New-RunWire([string]$ExitReason, [string]$Message, [string]$Mode = 'identified') {
        $a = @{ Job = 'si-ptc'; ExitReason = $ExitReason; Edition = 'pro'; Version = '3.0.0'; Hosting = 'container'; RuntimeIdentity = 'mi-container'; LicenceState = 'valid'
                DurationMs = 1000; Now = [datetime]'2026-10-10T06:00:00Z' }
        if ($ExitReason -ne 'success') { $a.FailedStep = 'collect'; $a.ErrorMessage = $Message }
        if ($Mode -eq 'anonymous') { $a.Anonymous = $true; $a.InstallId = '0f0e0d0c-0b0a-4908-8706-050403020100' } else { $a.TenantId = '11111111-2222-3333-4444-555555555555' }
        ConvertTo-SITelemetryWire -Record (New-SITelemetryRunRecord @a) -Mode $Mode -Now ([datetime]'2026-10-10T06:00:00Z')
    }
}

AfterAll { $global:SI_TelemetryHalted = $null; $global:SI_TelemetryWarned = $null; $global:SI_TelemetryContext = $null; $global:SI_Telemetry_Enabled = $null }

Describe 'Get-SIErrorFixKind -- from the closed error-class list only' {
    It 'every class of the closed list maps to one of Invardia''s two values -- but transient-sql, which is nobody''s fix (#913)' {
        foreach ($c in @(Get-SIErrorClasses | Where-Object { $_ -ne 'transient-sql' })) { $script:FixKinds | Should -Contain (Get-SIErrorFixKind -ErrorClass $c) }
        Get-SIErrorFixKind -ErrorClass 'transient-sql' | Should -Be '' -Because 'an Azure SQL transient that outlasted its retry is never a fix request (no FixKind on the wire)'
        Get-SIErrorFixKind -ErrorClass 'database-full' | Should -Be 'product-defect' -Because '#904: a full database opens a ticket'
    }
    It 'customer-config is exactly the permission, licence and setting classes' {
        @(Get-SICustomerConfigClasses | Sort-Object) | Should -Be @('arm-403', 'config-missing', 'defender-403', 'graph-403', 'kv-403', 'licence-invalid', 'settings-error', 'storage-403')
        foreach ($c in @(Get-SICustomerConfigClasses)) { Get-SIErrorClasses | Should -Contain $c }
    }
    It 'everything else is a product defect -- unknown, throttling, timeouts, a missing table, sign-in and guard refusals' {
        foreach ($c in 'unknown', 'throttled', 'platform-timeout', 'platform-5xx', 'table-missing', 'graph-401', 'sql-login', 'mi-unavailable', 'kql-query-defect', 'ingest-4xx', 'ingest-short-count', 'ai-error', 'guard-refused') {
            Get-SIErrorFixKind -ErrorClass $c | Should -Be 'product-defect'
        }
    }
    It 'a class outside the list is a product defect; no class = no FixKind; case does not matter' {
        Get-SIErrorFixKind -ErrorClass 'something-new' | Should -Be 'product-defect'
        Get-SIErrorFixKind -ErrorClass '' | Should -Be ''
        Get-SIErrorFixKind -ErrorClass $null | Should -Be ''
        Get-SIErrorFixKind -ErrorClass 'KV-403' | Should -Be 'customer-config'
    }
}

Describe 'the wire record' {
    It 'a failed run whose identity lacks a permission -> customer-config' {
        $w = New-RunWire 'error' 'GET https://graph.microsoft.com/v1.0/users failed: 403 Forbidden Authorization_RequestDenied Insufficient privileges'
        $w.ErrorClass | Should -Be 'graph-403'
        $w.FixKind | Should -Be 'customer-config'
    }
    It 'a settings error -> customer-config' {
        $w = New-RunWire 'settings-error' 'SI_WorkspaceId is not set'
        $w.ErrorClass | Should -Be 'settings-error'
        $w.FixKind | Should -Be 'customer-config'
    }
    It 'throttling and an unknown failure -> product-defect' {
        (New-RunWire 'error' 'Response status code does not indicate success: 429 (Too Many Requests)').FixKind | Should -Be 'product-defect'
        (New-RunWire 'error' 'something nobody classified').FixKind | Should -Be 'product-defect'
    }
    It 'a partial run (warning) with a class carries it too' {
        $w = New-RunWire 'success-partial' 'AuthorizationFailed: the client does not have authorization to perform action Microsoft.Resources/subscriptions/read over management.azure.com'
        $w.Outcome | Should -Be 'warning'
        $w.FixKind | Should -Be 'customer-config'
    }
    It 'an ok run carries no FixKind' {
        $w = New-RunWire 'success' ''
        $w.PSObject.Properties['FixKind'] | Should -BeNullOrEmpty
    }
    It 'anonymous: FixKind is carried, the text is not' {
        $w = New-RunWire 'error' 'https://kv-x.vault.azure.net/secrets/a 403 Forbidden ForbiddenByRbac' -Mode anonymous
        $w.FixKind | Should -Be 'customer-config'
        ($w | ConvertTo-Json -Depth 5) | Should -Not -Match 'ForbiddenByRbac'
    }
}

Describe 'the send path' {
    BeforeEach { $global:SI_TelemetryHalted = $false; $global:SI_TelemetryWarned = $false; $global:SI_Telemetry_Enabled = $null }
    It 'an updater failure that is a missing Key Vault permission is reported as customer-config' {
        $c = New-Capture
        $null = Send-SITelemetryFailure -Job updater -Step 'licence' -ErrorMessage 'Key Vault secret SI-License could not be written: (Forbidden) ForbiddenByRbac on https://kv-si.vault.azure.net' -Context $script:Id -Transport $c.Transport
        $c.List.Count | Should -Be 1
        $c.List[0].FixKind | Should -Be 'customer-config'
        $script:FixKinds | Should -Contain $c.List[0].FixKind
    }
    It 'an engine run with a heartbeat due: the heartbeat has no FixKind, the failed run has one' {
        $c = New-Capture
        $rc = [pscustomobject]@{ Engine = 'endpoint'; ShardIndex = 0; StartedAt = [datetime]'2026-10-10T05:50:00Z'; FailedStep = 'collect' }
        $r = Send-SITelemetryRunEnd -RunContext $rc -ExitReason 'error' -ErrorMessage 'The operation has timed out' -Context $script:Anon -Transport $c.Transport -Now ([datetime]'2026-10-10T06:00:00Z')
        $r.Status | Should -Be 'ok'
        $hb = @($c.List | Where-Object { $_.Kind -eq 'heartbeat' })
        $run = @($c.List | Where-Object { $_.Kind -eq 'run' })
        $hb.Count | Should -Be 1
        $hb[0].PSObject.Properties['FixKind'] | Should -BeNullOrEmpty
        $run[0].ErrorClass | Should -Be 'platform-timeout'
        $run[0].FixKind | Should -Be 'product-defect'
    }
}
