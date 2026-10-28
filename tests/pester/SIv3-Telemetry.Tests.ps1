#Requires -Version 5.1
<#
    SecurityInsight -- SENDING THE TELEMETRY (#226): the daily heartbeat and one `run` report per engine run, at the
    run-health END moment, through SI's own copy of the framework uplink client.

    What must hold:
      - engine/_shared/AitUplink.ps1 is the framework's sync/_AitUplink.ps1, byte for byte (containers and Pro installs
        have no sync/ folder, so SI carries its own copy -- the same pattern as AitLicense.ps1);
      - Community = anonymous: the record on the wire carries NO tenant id, NO host name and NO error text, only an
        error class and bucketed counts, plus a random install id kept on the machine;
      - Pro / trial = identified by the install key (SI-Invardia-InstallKey), the error text redacted;
      - SI_Telemetry_Enabled = $false sends NOTHING (no transport call, no file written, no context resolved);
      - an endpoint that is down, slow or refusing never fails or slows the run: one short attempt, one warning, then
        nothing more from the process;
      - a test session never sends (every case below hands in its own stub transport; NOTHING here contacts Invardia).
#>

BeforeAll {
    $script:SIRoot   = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:RepoRoot = Split-Path -Parent (Split-Path -Parent $script:SIRoot)
    # Belt and braces: even a real send that slipped through would go to a closed local port, never to Invardia.
    $script:SavedEndpointEnv = $env:SI_TELEMETRY_ENDPOINT
    $env:SI_TELEMETRY_ENDPOINT = 'https://127.0.0.1:9/api/uplink/v1/report'
    . (Join-Path $script:SIRoot 'engine\_shared\SI-TelemetrySend.ps1')

    $script:Tenant  = '7f3e2a10-4b5c-4d6e-8f90-a1b2c3d4e5f6'
    $script:HostX   = 'HOST-MUST-NOT-LEAVE-01'
    $script:Secret  = 'client_secret=SuperSecretValue123456'
    $script:ErrText = "Response status code does not indicate success: 403 (Forbidden). graph.microsoft.com Authorization_RequestDenied for tenant $script:Tenant on $script:HostX -- $script:Secret"
    $script:Allowed = @('Schema', 'Kind', 'Product', 'Version', 'Ring', 'Edition', 'Hosting', 'RuntimeIdentity', 'LicenceState', 'Job', 'Outcome',
                        'DurationMs', 'FailedStep', 'ErrorClass', 'ErrorText', 'Counts', 'InstallId', 'ClaimedTenantId', 'Host', 'LastSeenUtc',
                        # framework §8.5 CLOSE-LOOP + §12.6b: both in Invardia's allowed set (packages/core/src/uplink.ts)
                        'FixKind', 'LicenceId',
                        # framework §8.9: the install's own links (identified heartbeat, behind SI_Telemetry_SendEndpoints) and the deep link (identified failed run)
                        'endpoints', 'Link')
    $script:Buckets = @('0', '1-100', '100-1k', '1k-10k', '10k-100k', '100k+')

    function script:New-Ctx([string]$Mode = 'anonymous', [string]$Dir) {
        [pscustomobject]@{ Mode = $Mode; Endpoint = 'https://stub.example.test/report'
                           AccessCode = $(if ($Mode -eq 'anonymous') { 'invardia-community-telemetry-v1' } else { 'inv-TESTKEYabcdefghijklmnopqrstuvwxyz' })
                           Edition = $(if ($Mode -eq 'anonymous') { 'community' } else { 'pro' }); LicenceState = $(if ($Mode -eq 'anonymous') { 'none' } else { 'valid' })
                           Version = '3.0.0'; Hosting = 'vm'; RuntimeIdentity = 'mi-vm'
                           InstallId = $(if ($Mode -eq 'anonymous') { '0f3c9a2e-5b7d-4c1a-9e8f-1a2b3c4d5e6f' } else { '' })
                           TenantId = $(if ($Mode -eq 'anonymous') { '' } else { $script:Tenant }); StateDirectory = $Dir }
    }
    function script:New-RunCtx([string]$Engine = 'endpoint', [int]$Shard = 0) {
        [pscustomobject]@{ RunId = [guid]::NewGuid().ToString(); Engine = $Engine; ShardIndex = $Shard; ShardCount = 1
                           StartedAt = [datetime]'2026-10-04T06:00:00Z'; CollectionTime = [datetime]'2026-10-04T06:00:00Z' }
    }
    # The stub endpoint: records every POST it would have received.
    $script:Posts = New-Object System.Collections.Generic.List[object]
    $script:StubOk = { param($Record, $Endpoint, $AccessCode, $TimeoutSec) $script:Posts.Add([pscustomobject]@{ Record = $Record; Endpoint = $Endpoint; Code = $AccessCode; Timeout = $TimeoutSec; Json = ($Record | ConvertTo-Json -Depth 6 -Compress) }); [pscustomobject]@{ Status = 'ok'; Reason = 'accepted' } }
    function script:Reset-Telemetry { $global:SI_TelemetryHalted = $null; $global:SI_TelemetryWarned = $null; $global:SI_TelemetryContext = $null; $global:SI_Telemetry_Enabled = $null; $script:Posts.Clear() }
}

AfterAll {
    $env:SI_TELEMETRY_ENDPOINT = $script:SavedEndpointEnv
    $global:SI_TelemetryHalted = $null; $global:SI_TelemetryWarned = $null; $global:SI_TelemetryContext = $null; $global:SI_Telemetry_Enabled = $null
}

Describe 'SI''s uplink client is the framework''s, byte for byte' {
    It 'engine/_shared/AitUplink.ps1 is identical to sync/_AitUplink.ps1 (the checkout''s, or main''s when this branch''s sync/ predates Schema 2)' {
        $copy = Join-Path $script:SIRoot 'engine\_shared\AitUplink.ps1'
        $sync = Join-Path $script:RepoRoot 'sync\_AitUplink.ps1'
        if ((Test-Path -LiteralPath $sync) -and ((Get-Content -Raw -LiteralPath $sync) -match 'function New-AitUplinkReport')) {
            (Get-FileHash -LiteralPath $copy).Hash | Should -Be (Get-FileHash -LiteralPath $sync).Hash
            return
        }
        # This checkout's sync/ is older than Schema 2 (a branch behind main): compare git BLOBS with main's, so line-ending
        # conversion cannot hide or invent a difference.
        $git = Get-Command -Name git -ErrorAction SilentlyContinue
        $want = $null
        if ($git -and (Test-Path -LiteralPath (Join-Path $script:RepoRoot '.git'))) {
            $want = (& git -C $script:RepoRoot rev-parse --verify -q 'origin/main:sync/_AitUplink.ps1' 2>$null)
        }
        if (-not $want) { Set-ItResult -Skipped -Because 'no Schema 2 sync/_AitUplink.ps1 in this checkout and origin/main is not available (customer tree / shallow clone)'; return }
        $have = (& git -C $script:RepoRoot hash-object --path=sync/_AitUplink.ps1 $copy)
        $have | Should -Be $want -Because 'the copy must be the framework client exactly -- re-copy it with: git cat-file --filters origin/main:sync/_AitUplink.ps1'
    }
    It 'SI loads ITS copy (never sync/), and the copy has the Schema 2 builder, the sender resolver and the redactor' {
        $src = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'engine\_shared\SI-TelemetrySend.ps1')
        $src | Should -Match "Combine\(\`$PSScriptRoot, 'AitUplink\.ps1'\)"
        # No string in the CODE (comments do not count) points at the framework's sync/ copy.
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($src, [ref]$null, [ref]$null)
        @($ast.FindAll({ param($x) $x -is [System.Management.Automation.Language.StringConstantExpressionAst] -and $x.Value -match '_AitUplink|^sync$|[\\/]sync[\\/]' }, $true)) | Should -BeNullOrEmpty
        foreach ($f in 'New-AitUplinkReport', 'Resolve-AitUplinkSender', 'Send-AitUplink', 'ConvertTo-AitUplinkRedacted') { Get-Command $f -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty -Because $f }
    }
}

Describe 'the switch' {
    It 'ON by default; the setting wins over the environment variable; false / 0 / off / no turn it off' {
        Test-SITelemetryEnabled -Value $null -EnvValue $null | Should -BeTrue
        Test-SITelemetryEnabled -Value $false -EnvValue 'true' | Should -BeFalse
        Test-SITelemetryEnabled -Value $true -EnvValue 'false' | Should -BeTrue
        Test-SITelemetryEnabled -Value $null -EnvValue 'false' | Should -BeFalse
        foreach ($v in 'false', 'FALSE', '$false', '0', 'off', 'no') { Test-SITelemetryEnabled -Value $v -EnvValue $null | Should -BeFalse -Because $v }
        foreach ($v in 'true', '1', 'on', 'yes') { Test-SITelemetryEnabled -Value $v -EnvValue $null | Should -BeTrue -Because $v }
    }
}

Describe 'what this install reports as' {
    It 'every engine that records run health maps to its agreed Job id; Risk Analysis is two jobs; an unknown engine is not reported' {
        Resolve-SITelemetryJob 'privilege-tier-classifier' | Should -Be 'si-ptc'
        foreach ($e in 'endpoint', 'identity', 'azure', 'publicip') { Resolve-SITelemetryJob $e | Should -Be "si-$e" }
        Resolve-SITelemetryJob 'schema-discovery' | Should -Be 'si-schema-discovery'
        Resolve-SITelemetryJob 'risk-analysis' 'RiskAnalysis_Summary' | Should -Be 'si-ra-summary'
        Resolve-SITelemetryJob 'risk-analysis' 'RiskAnalysis_Detailed' | Should -Be 'si-ra-detailed'
        Resolve-SITelemetryJob 'nope' | Should -BeNullOrEmpty
        $agreed = @((Get-SITelemetryContract).Jobs)
        foreach ($j in @($script:SITelemetrySend.Jobs.Values)) { $agreed | Should -Contain $j }
    }
    It 'ExitReason: the four run-health values pass, the tier classifier''s failure is error, anything else is not reported' {
        ConvertTo-SITelemetryExitReason 'success-partial' | Should -Be 'success-partial'
        ConvertTo-SITelemetryExitReason 'failure' | Should -Be 'error'
        ConvertTo-SITelemetryExitReason '' | Should -BeNullOrEmpty
    }
    It 'hosting: container (Container Apps), arc (the Arc agent), vm otherwise' {
        $env1 = @{ CONTAINER_APP_JOB_NAME = 'job' }; Get-SITelemetryHosting -GetEnv ({ param($n) $env1[$n] }.GetNewClosure()) | Should -Be 'container'
        $env3 = @{ IDENTITY_ENDPOINT = 'http://x'; IDENTITY_HEADER = 'h' }; Get-SITelemetryHosting -GetEnv ({ param($n) $env3[$n] }.GetNewClosure()) | Should -Be 'container'
        $env2 = @{ IDENTITY_ENDPOINT = 'http://localhost:40342/x'; IMDS_ENDPOINT = 'http://localhost:40342' }; Get-SITelemetryHosting -GetEnv ({ param($n) $env2[$n] }.GetNewClosure()) | Should -Be 'arc'
        Get-SITelemetryHosting -GetEnv { param($n) $null } | Should -Be 'vm'
    }
    It 'runtime identity is a KIND only: mi-<hosting>, spn-certificate, spn-secret' {
        Get-SITelemetryRuntimeIdentity -Hosting arc -Vars @{ UseMi = $true } | Should -Be 'mi-arc'
        Get-SITelemetryRuntimeIdentity -Hosting container -Vars @{ PreferUami = $true; UamiClientId = 'x' } | Should -Be 'mi-container'
        Get-SITelemetryRuntimeIdentity -Hosting vm -Vars @{ Thumbprint = 'AB'; Secret = 's' } | Should -Be 'spn-certificate'
        Get-SITelemetryRuntimeIdentity -Hosting vm -Vars @{ Secret = 's' } | Should -Be 'spn-secret'
    }
    It 'licence: valid / grace = pro (trial when the sku says so); expired / missing = community' {
        (Get-SITelemetryLicenceInfo ([pscustomobject]@{ Status = 'Valid'; Sku = 'Pro' })).Edition | Should -Be 'pro'
        (Get-SITelemetryLicenceInfo ([pscustomobject]@{ Status = 'Grace'; Sku = 'Trial' })) | ForEach-Object { $_.Edition | Should -Be 'trial'; $_.LicenceState | Should -Be 'grace' }
        (Get-SITelemetryLicenceInfo ([pscustomobject]@{ Status = 'Expired'; Sku = 'Pro' })) | ForEach-Object { $_.Edition | Should -Be 'community'; $_.LicenceState | Should -Be 'expired' }
        (Get-SITelemetryLicenceInfo $null).LicenceState | Should -Be 'none'
    }
    It 'Community: anonymous with the public community code -- and the install key is NEVER looked up' {
        Mock Get-SITelemetryInstallKey { throw 'a Community install must not read a Key Vault for telemetry' }
        $c = Get-SITelemetryContext -License $null -StateDirectory (Join-Path $TestDrive 'c1') -Vars @{ UseMi = $true } -GetEnv { param($n) $null } -Version '3.0.0'
        $c.Mode | Should -Be 'anonymous'; $c.AccessCode | Should -Be 'invardia-community-telemetry-v1'; $c.Edition | Should -Be 'community'
        $c.TenantId | Should -Be ''
        $c.InstallId | Should -Match '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        Should -Invoke Get-SITelemetryInstallKey -Times 0 -Exactly
    }
    It 'Pro with its install key: identified, the key is the credential; Pro without a key (or a malformed one) reports anonymously' {
        $lic = [pscustomobject]@{ Status = 'Valid'; Sku = 'Pro' }
        $p = Get-SITelemetryContext -License $lic -InstallKey 'inv-ABCDEFGHIJKLMNOPQRSTUVWXYZ012345' -TenantId $script:Tenant -StateDirectory (Join-Path $TestDrive 'p1') -GetEnv { param($n) $null } -Version '3.0.0'
        $p.Mode | Should -Be 'identified'; $p.AccessCode | Should -Be 'inv-ABCDEFGHIJKLMNOPQRSTUVWXYZ012345'; $p.TenantId | Should -Be $script:Tenant; $p.InstallId | Should -Be ''
        (Get-SITelemetryContext -License $lic -InstallKey '' -StateDirectory (Join-Path $TestDrive 'p2') -GetEnv { param($n) $null }).Mode | Should -Be 'anonymous'
        (Get-SITelemetryContext -License $lic -InstallKey 'not-a-key' -StateDirectory (Join-Path $TestDrive 'p3') -GetEnv { param($n) $null }).Mode | Should -Be 'anonymous'
    }
    It 'the endpoint defaults to Invardia''s and can be overridden (https enforced by the framework client)' {
        $saved = $env:SI_TELEMETRY_ENDPOINT
        try {
            $env:SI_TELEMETRY_ENDPOINT = $null
            (Get-SITelemetryContext -License $null -StateDirectory (Join-Path $TestDrive 'e1') -GetEnv { param($n) $null }).Endpoint | Should -Be 'https://invardia.com/api/uplink/v1/report'
        } finally { $env:SI_TELEMETRY_ENDPOINT = $saved }
        (Send-AitUplink -Record @{ a = 1 } -Endpoint 'http://plain.example.test/x' -AccessCode 'c').Status | Should -Be 'refused'
    }
}

Describe 'the install id' {
    It 'is created ONCE and kept; a damaged file gets a new one; an unwritable folder still yields an id' {
        $d = Join-Path $TestDrive 'iid'
        $a = Get-SITelemetryInstallId -StateDirectory $d
        $a | Should -Match '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        Get-SITelemetryInstallId -StateDirectory $d | Should -Be $a
        Set-Content -LiteralPath (Join-Path $d 'install-id') -Value 'garbage'
        $b = Get-SITelemetryInstallId -StateDirectory $d
        $b | Should -Not -Be $a
        $b | Should -Match '^[0-9a-f]{8}-'
        Get-SITelemetryInstallId -StateDirectory $d | Should -Be $b   # the damaged file was replaced: one id again
        $f = Join-Path $TestDrive 'a-file'; Set-Content -LiteralPath $f -Value 'x'
        Get-SITelemetryInstallId -StateDirectory (Join-Path $f 'sub') | Should -Match '^[0-9a-f]{8}-'
    }
    It 'in a container (no file survives a run) it is the same every run: derived from the install''s storage account' {
        $e1 = @{ SI_ENGINE = 'asset-tagging'; SI_STORAGE_ACCOUNT = 'stsiprodproca558014' }
        $a = Get-SITelemetryInstallId -StateDirectory (Join-Path $TestDrive 'ct1') -GetEnv ({ param($n) $e1[$n] }.GetNewClosure())
        $b = Get-SITelemetryInstallId -StateDirectory (Join-Path $TestDrive 'ct2') -GetEnv ({ param($n) $e1[$n] }.GetNewClosure())
        $a | Should -Match '^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
        $b | Should -Be $a -Because 'two runs of one install (6 installs were reported for 3, fix request 85bd728f)'
        $e2 = @{ SI_ENGINE = 'asset-tagging'; SI_STORAGE_ACCOUNT = 'stsiprodproca01' }
        Get-SITelemetryInstallId -StateDirectory (Join-Path $TestDrive 'ct3') -GetEnv ({ param($n) $e2[$n] }.GetNewClosure()) | Should -Not -Be $a
        $a | Should -Not -Match 'stsiprodproca' -Because 'it identifies nothing'
    }
}

Describe 'a Pro install that could not read its licence (fix request 85bd728f)' {
    AfterEach { Remove-Variable -Name SI_ProSqlServer, SI_ProSqlDatabase -Scope Global -ErrorAction SilentlyContinue }
    It 'reports as Pro (licence state as found), never as an anonymous Community install' {
        $pro = @{ SI_CFG_SI_ProSqlServer = 'pro-db.example.invalid'; SI_CFG_SI_ProSqlDatabase = 'sqldb-si-pro' }
        $c = Get-SITelemetryContext -License $null -InstallKey '' -StateDirectory (Join-Path $TestDrive 'pr1') -GetEnv ({ param($n) $pro[$n] }.GetNewClosure()) -Version '3.0.0'
        $c.Edition | Should -Be 'pro'
        $c.LicenceState | Should -Be 'none'
        Test-SITelemetryProInstall -GetEnv ({ param($n) $pro[$n] }.GetNewClosure()) | Should -BeTrue
    }
    It 'an install without a Pro database stays Community' {
        Test-SITelemetryProInstall -GetEnv { param($n) $null } | Should -BeFalse
        (Get-SITelemetryContext -License $null -StateDirectory (Join-Path $TestDrive 'pr2') -GetEnv { param($n) $null }).Edition | Should -Be 'community'
    }
}

Describe 'the anonymous run report (Community)' {
    BeforeEach { Reset-Telemetry }
    It 'NEGATIVE PROOF -- no tenant id, no host name, no free-text error on the wire; only an error class, bucketed counts and the install id' {
        $global:SI_SPN_TenantId_Saved = $global:SI_SPN_TenantId; $global:SI_SPN_TenantId = $script:Tenant
        try {
            $r = Send-SITelemetryRunEnd -RunContext (New-RunCtx 'identity') -ExitReason 'error' -ErrorMessage $script:ErrText -AssetCount 12345 `
                -Context (New-Ctx anonymous (Join-Path $TestDrive 'a1')) -Transport $script:StubOk -Now ([datetime]'2026-10-04T06:10:00Z')
        } finally { $global:SI_SPN_TenantId = $global:SI_SPN_TenantId_Saved }
        $r.Status | Should -Be 'ok'
        $script:Posts.Count | Should -Be 2   # the day's heartbeat, then the run
        foreach ($p in $script:Posts) {
            $p.Json | Should -Not -Match ([regex]::Escape($script:Tenant))
            $p.Json | Should -Not -Match ([regex]::Escape($script:HostX))
            $p.Json | Should -Not -Match ([regex]::Escape([string]$env:COMPUTERNAME))
            $p.Json | Should -Not -Match 'SuperSecretValue|Forbidden|Authorization_RequestDenied|graph\.microsoft'
            $names = @($p.Record.PSObject.Properties.Name)
            foreach ($n in 'ClaimedTenantId', 'Host', 'ErrorText') { $names | Should -Not -Contain $n }
            foreach ($n in $names) { $script:Allowed | Should -Contain $n }
            $p.Record.InstallId | Should -Be '0f3c9a2e-5b7d-4c1a-9e8f-1a2b3c4d5e6f'
            $p.Code | Should -Be 'invardia-community-telemetry-v1'
        }
        $run = $script:Posts[1].Record
        $run.Schema | Should -Be 2; $run.Kind | Should -Be 'run'; $run.Product | Should -Be 'securityinsight'
        $run.Job | Should -Be 'si-identity'; $run.Outcome | Should -Be 'failed'; $run.ErrorClass | Should -Be 'graph-403'
        $run.DurationMs | Should -Be 600000
        $run.Counts.identities | Should -Be '10k-100k'
        $script:Buckets | Should -Contain $run.Counts.identities
        $hb = $script:Posts[0].Record
        $hb.Kind | Should -Be 'heartbeat'; $hb.Edition | Should -Be 'community'; $hb.Hosting | Should -Be 'vm'; $hb.RuntimeIdentity | Should -Be 'mi-vm'; $hb.LicenceState | Should -Be 'none'; $hb.Version | Should -Be '3.0.0'
    }
    It 'outcomes: success = ok (no class, no step), success-partial = warning, settings-error = failed / settings' {
        $c = New-Ctx anonymous (Join-Path $TestDrive 'a2')
        Set-SITelemetryLastHeartbeat -StateDirectory $c.StateDirectory -NowUtc ([datetime]'2026-10-04T00:00:00Z')
        $null = Send-SITelemetryRunEnd -RunContext (New-RunCtx 'endpoint') -ExitReason 'success' -AssetCount 5 -Context $c -Transport $script:StubOk -Now ([datetime]'2026-10-04T07:00:00Z')
        $null = Send-SITelemetryRunEnd -RunContext (New-RunCtx 'risk-analysis') -ExitReason 'success-partial' -ErrorMessage '3 bucket(s) produced no rows' -Context $c -Transport $script:StubOk -Now ([datetime]'2026-10-04T07:00:00Z')
        $null = Send-SITelemetryRunEnd -RunContext (New-RunCtx 'azure') -ExitReason 'settings-error' -ErrorMessage 'x' -Context $c -Transport $script:StubOk -Now ([datetime]'2026-10-04T07:00:00Z')
        $script:Posts.Count | Should -Be 3
        $ok = $script:Posts[0].Record; $ok.Outcome | Should -Be 'ok'; @($ok.PSObject.Properties.Name) | Should -Not -Contain 'ErrorClass'; @($ok.PSObject.Properties.Name) | Should -Not -Contain 'FailedStep'
        $ok.Counts.assets | Should -Be '1-100'
        $script:Posts[1].Record.Outcome | Should -Be 'warning'; $script:Posts[1].Record.FailedStep | Should -Be 'ra-query'; $script:Posts[1].Record.Job | Should -Be 'si-ra-detailed'
        $script:Posts[2].Record.Outcome | Should -Be 'failed'; $script:Posts[2].Record.ErrorClass | Should -Be 'settings-error'; $script:Posts[2].Record.FailedStep | Should -Be 'settings'
    }
    It 'the stage the engine recorded is the FailedStep; the tier classifier''s "failure" is reported as failed' {
        $c = New-Ctx anonymous (Join-Path $TestDrive 'a3'); Set-SITelemetryLastHeartbeat -StateDirectory $c.StateDirectory -NowUtc ([datetime]'2026-10-04T00:00:00Z')
        $rc = New-RunCtx 'endpoint'; $rc | Add-Member -NotePropertyName FailedStep -NotePropertyValue 'collect'
        $null = Send-SITelemetryRunEnd -RunContext $rc -ExitReason 'error' -ErrorMessage 'The operation has timed out.' -Context $c -Transport $script:StubOk -Now ([datetime]'2026-10-04T07:00:00Z')
        $null = Send-SITelemetryRunEnd -RunContext (New-RunCtx 'privilege-tier-classifier') -ExitReason 'failure' -ErrorMessage 'boom' -Context $c -Transport $script:StubOk -Now ([datetime]'2026-10-04T07:00:00Z')
        $script:Posts[0].Record.FailedStep | Should -Be 'collect'; $script:Posts[0].Record.ErrorClass | Should -Be 'platform-timeout'
        $script:Posts[1].Record.Job | Should -Be 'si-ptc'; $script:Posts[1].Record.Outcome | Should -Be 'failed'; $script:Posts[1].Record.ErrorClass | Should -Be 'unknown'
    }
    It 'every field value the receiver checks is in its closed list (mirrors Invardia''s validateUplinkReport rules)' {
        $c = New-Ctx anonymous (Join-Path $TestDrive 'a4')
        $null = Send-SITelemetryRunEnd -RunContext (New-RunCtx 'publicip') -ExitReason 'error' -ErrorMessage 'Too Many Requests (429)' -AssetCount 0 -Context $c -Transport $script:StubOk -Now ([datetime]'2026-10-04T07:00:00Z')
        foreach ($p in $script:Posts) {
            $r = $p.Record
            @('heartbeat', 'run') | Should -Contain $r.Kind
            $r.InstallId | Should -Match '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
            if ($r.Job) { $r.Job | Should -Match '^[a-z0-9][a-z0-9.-]{0,59}$' }
            if ($r.ErrorClass) { $r.ErrorClass | Should -Match '^[a-z0-9-]{1,40}$' }
            if ($r.Counts) { foreach ($cp in $r.Counts.PSObject.Properties) { $cp.Name | Should -Match '^[a-z][A-Za-z0-9]{0,30}$'; $script:Buckets | Should -Contain $cp.Value } }
            $p.Json.Length | Should -BeLessThan 16384
        }
        foreach ($cls in @(Get-SIErrorClasses)) { $cls | Should -Match '^[a-z0-9-]{1,40}$' }
        foreach ($j in @((Get-SITelemetryContract).Jobs)) { $j | Should -Match '^[a-z0-9][a-z0-9.-]{0,59}$' }
    }
}

Describe 'the identified run report (Pro / trial)' {
    BeforeEach { Reset-Telemetry }
    It 'carries the tenant, the host and the error text -- with the secret redacted -- and the install key as the credential' {
        $c = New-Ctx identified (Join-Path $TestDrive 'i1'); Set-SITelemetryLastHeartbeat -StateDirectory $c.StateDirectory -NowUtc ([datetime]'2026-10-04T00:00:00Z')
        $r = Send-SITelemetryRunEnd -RunContext (New-RunCtx 'azure') -ExitReason 'error' -ErrorMessage $script:ErrText -AssetCount 4321 -Context $c -Transport $script:StubOk -Now ([datetime]'2026-10-04T07:00:00Z')
        $r.Status | Should -Be 'ok'; $script:Posts.Count | Should -Be 1
        $rec = $script:Posts[0].Record
        $rec.ClaimedTenantId | Should -Be $script:Tenant
        $rec.Host | Should -Not -BeNullOrEmpty
        $rec.ErrorText | Should -Match 'Forbidden'
        $rec.ErrorText | Should -Not -Match 'SuperSecretValue'
        $rec.Counts.assets | Should -Be 4321
        @($rec.PSObject.Properties.Name) | Should -Not -Contain 'InstallId'
        $script:Posts[0].Code | Should -Be 'inv-TESTKEYabcdefghijklmnopqrstuvwxyz'
    }
}

Describe 'the heartbeat: once per UTC day' {
    BeforeEach { Reset-Telemetry }
    It 'the first run of a day sends the heartbeat first; later runs that day do not; the next day it is due again' {
        $c = New-Ctx anonymous (Join-Path $TestDrive 'h1')
        $null = Send-SITelemetryRunEnd -RunContext (New-RunCtx) -ExitReason 'success' -Context $c -Transport $script:StubOk -Now ([datetime]'2026-10-04T01:00:00Z')
        $null = Send-SITelemetryRunEnd -RunContext (New-RunCtx) -ExitReason 'success' -Context $c -Transport $script:StubOk -Now ([datetime]'2026-10-04T23:00:00Z')
        $null = Send-SITelemetryRunEnd -RunContext (New-RunCtx) -ExitReason 'success' -Context $c -Transport $script:StubOk -Now ([datetime]'2026-10-05T00:30:00Z')
        @($script:Posts | ForEach-Object { $_.Record.Kind }) -join ',' | Should -Be 'heartbeat,run,run,heartbeat,run'
    }
    It 'a sharded run is ONE report: a successful shard other than the first is not reported; a failed one is' {
        $c = New-Ctx anonymous (Join-Path $TestDrive 'h2'); Set-SITelemetryLastHeartbeat -StateDirectory $c.StateDirectory -NowUtc ([datetime]'2026-10-04T00:00:00Z')
        (Send-SITelemetryRunEnd -RunContext (New-RunCtx 'endpoint' 3) -ExitReason 'success' -Context $c -Transport $script:StubOk -Now ([datetime]'2026-10-04T07:00:00Z')).Status | Should -Be 'skipped'
        (Send-SITelemetryRunEnd -RunContext (New-RunCtx 'endpoint' 3) -ExitReason 'error' -ErrorMessage 'x' -Context $c -Transport $script:StubOk -Now ([datetime]'2026-10-04T07:00:00Z')).Status | Should -Be 'ok'
        $script:Posts.Count | Should -Be 1
    }
}

Describe 'OPT-OUT sends nothing' {
    BeforeEach { Reset-Telemetry }
    AfterEach { $global:SI_Telemetry_Enabled = $null }
    It 'SI_Telemetry_Enabled = $false: no transport call, no context resolved, no file written' {
        $global:SI_Telemetry_Enabled = $false
        Mock Get-SITelemetryContext { throw 'must not be resolved when telemetry is off' }
        $script:calls = 0
        $count = { param($Record, $Endpoint, $AccessCode, $TimeoutSec) $script:calls++; [pscustomobject]@{ Status = 'ok' } }
        $dir = Join-Path $TestDrive 'off'
        $r = Send-SITelemetryRunEnd -RunContext (New-RunCtx) -ExitReason 'error' -ErrorMessage 'x' -Transport $count
        $r.Status | Should -Be 'disabled'; @($r.Sent).Count | Should -Be 0
        $script:calls | Should -Be 0
        Should -Invoke Get-SITelemetryContext -Times 0 -Exactly
        Test-Path -LiteralPath $dir | Should -BeFalse
    }
    It 'the environment variable SI_TELEMETRY_ENABLED=false does the same when the setting is not set' {
        $saved = $env:SI_TELEMETRY_ENABLED; $savedGate = $env:SI_TEST_GATE
        try {
            # (#918: the gate's own marker is taken away for this test -- it asks what an install does with the variable)
            $env:SI_TELEMETRY_ENABLED = 'false'; $env:SI_TEST_GATE = $null
            (Send-SITelemetryRunEnd -RunContext (New-RunCtx) -ExitReason 'success' -Context (New-Ctx anonymous (Join-Path $TestDrive 'off2')) -Transport $script:StubOk).Status | Should -Be 'disabled'
            $script:Posts.Count | Should -Be 0
        } finally { $env:SI_TELEMETRY_ENABLED = $saved; $env:SI_TEST_GATE = $savedGate }
    }
}

Describe 'an endpoint that is down never fails or slows the run' {
    BeforeEach { Reset-Telemetry }
    AfterAll { Reset-Telemetry }
    It 'a REAL post to a closed local port: failed, no throw, under the time budget, ONE warning, then nothing more from the process' {
        $c = New-Ctx anonymous (Join-Path $TestDrive 'down'); $c.Endpoint = 'https://127.0.0.1:9/api/uplink/v1/report'
        $real = { param($Record, $Endpoint, $AccessCode, $TimeoutSec) Send-AitUplink -Record $Record -Endpoint $Endpoint -AccessCode $AccessCode -TimeoutSec $TimeoutSec }
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $r = Send-SITelemetryRunEnd -RunContext (New-RunCtx) -ExitReason 'error' -ErrorMessage 'x' -Context $c -Transport $real -WarningVariable w -WarningAction SilentlyContinue
        $sw.Stop()
        $r.Status | Should -Be 'failed'
        @($r.Sent).Count | Should -Be 0                      # stopped at the heartbeat -- the run report was not attempted
        $sw.Elapsed.TotalSeconds | Should -BeLessThan 12
        @($w).Count | Should -Be 1
        "$($w[0])" | Should -Match '(?s)not sent.*run is not affected'
        $global:SI_TelemetryHalted | Should -BeTrue
        $r2 = Send-SITelemetryRunEnd -RunContext (New-RunCtx) -ExitReason 'success' -Context $c -Transport $script:StubOk -WarningVariable w2 -WarningAction SilentlyContinue
        $r2.Status | Should -Be 'halted'; $script:Posts.Count | Should -Be 0; @($w2).Count | Should -Be 0
    }
    It 'one short attempt: the transport gets a 5-second timeout and is called once per record, never retried' {
        $c = New-Ctx anonymous (Join-Path $TestDrive 'once'); Set-SITelemetryLastHeartbeat -StateDirectory $c.StateDirectory -NowUtc ([datetime]'2026-10-04T00:00:00Z')
        $script:tries = 0; $script:to = 0
        $refuse = { param($Record, $Endpoint, $AccessCode, $TimeoutSec) $script:tries++; $script:to = $TimeoutSec; [pscustomobject]@{ Status = 'failed'; Reason = 'uplink POST failed: 503' } }
        $null = Send-SITelemetryRunEnd -RunContext (New-RunCtx) -ExitReason 'success' -Context $c -Transport $refuse -Now ([datetime]'2026-10-04T07:00:00Z') -WarningAction SilentlyContinue
        $script:tries | Should -Be 1
        $script:to | Should -Be 5
    }
    It 'a transport that THROWS (or a broken context) never reaches the caller' {
        $boom = { param($Record, $Endpoint, $AccessCode, $TimeoutSec) throw 'socket exploded' }
        { $script:res = Send-SITelemetryRunEnd -RunContext (New-RunCtx) -ExitReason 'error' -ErrorMessage 'x' -Context (New-Ctx anonymous (Join-Path $TestDrive 'boom')) -Transport $boom -WarningAction SilentlyContinue } | Should -Not -Throw
        $script:res.Status | Should -Be 'error'
        Reset-Telemetry
        $bad = New-Ctx anonymous (Join-Path $TestDrive 'bad'); $bad.InstallId = ''
        { $script:res = Send-SITelemetryRunEnd -RunContext (New-RunCtx) -ExitReason 'success' -Context $bad -Transport $script:StubOk -WarningAction SilentlyContinue } | Should -Not -Throw
        $script:res.Status | Should -Be 'error'; $script:Posts.Count | Should -Be 0
    }
    It 'a test session without its own transport never sends (Pester is loaded)' {
        (Send-SITelemetryRunEnd -RunContext (New-RunCtx) -ExitReason 'success').Status | Should -Be 'skipped'
    }
}

Describe 'wiring: the run-health END moment' {
    BeforeAll {
        . (Join-Path $script:SIRoot 'engine\asset-profiling\shared\Send-SIRunHealthRow.ps1')
        $script:Saved = @($global:SI_WorkspaceResourceId, $global:SI_DceName, $global:SI_DcrResourceGroup)
        $global:SI_WorkspaceResourceId = $null; $global:SI_DceName = $null; $global:SI_DcrResourceGroup = $null
    }
    AfterAll { $global:SI_WorkspaceResourceId, $global:SI_DceName, $global:SI_DcrResourceGroup = $script:Saved }
    It 'Send-SIRunHealthRow reports on End only -- also when the Log Analytics record itself is not saved -- with what it was given' {
        Mock Send-SITelemetryRunEnd { [pscustomobject]@{ Status = 'ok' } }
        $rc = New-RunCtx 'identity'
        Send-SIRunHealthRow -RunContext $rc -Phase Start
        Should -Invoke Send-SITelemetryRunEnd -Times 0 -Exactly
        Send-SIRunHealthRow -RunContext $rc -Phase End -AssetCount 7 -ExitReason 'error' -ErrorMessage 'why'
        Should -Invoke Send-SITelemetryRunEnd -Times 1 -Exactly -ParameterFilter { $ExitReason -eq 'error' -and $ErrorMessage -eq 'why' -and $AssetCount -eq 7 -and $RunContext.Engine -eq 'identity' }
    }
    It 'a telemetry failure cannot reach the run' {
        Mock Send-SITelemetryRunEnd { throw 'telemetry exploded' }
        { Send-SIRunHealthRow -RunContext (New-RunCtx) -Phase End -ExitReason 'success' } | Should -Not -Throw
    }
    It 'the profiling engine records the failing stage on the run context (FailedStep)' {
        $src = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'engine\asset-profiling\Invoke-SIEngineRun.ps1')
        $src | Should -Match "Add-Member -NotePropertyName 'FailedStep'"
    }
}

Describe 'UPLINK-FIX: every run report that does not end ok carries FailedStep + ErrorClass (+ ErrorText when identified)' {
    # Invardia, 2026-10-07: a fix request's signature is errorClass + failedStep + the normalised error text. customer G's
    # first run raised two requests with NONE of the three -- nothing to act on. No SI run report that ends "failed"
    # (or "warning") may leave one of them empty, for ANY job, whatever the engine recorded.
    BeforeEach { Reset-Telemetry }
    It 'every job, every non-ok ExitReason, no FailedStep recorded and NO message: all three are still there' {
        $engines = @($script:SITelemetrySend.Jobs.Keys) + @('risk-analysis')
        foreach ($mode in 'identified', 'anonymous') {
            $c = New-Ctx $mode (Join-Path $TestDrive ('uf-' + $mode))
            Set-SITelemetryLastHeartbeat -StateDirectory $c.StateDirectory -NowUtc ([datetime]'2026-10-04T00:00:00Z')
            foreach ($e in $engines) {
                foreach ($x in 'error', 'failure', 'settings-error', 'success-partial') {
                    $script:Posts.Clear(); $global:SI_TelemetryHalted = $null
                    $r = Send-SITelemetryRunEnd -RunContext (New-RunCtx $e) -ExitReason $x -ErrorMessage '' -Context $c -Transport $script:StubOk -Now ([datetime]'2026-10-04T07:00:00Z')
                    $r.Status | Should -Be 'ok' -Because "$e / $x / $mode"
                    $run = @($script:Posts | Where-Object { $_.Record.Kind -eq 'run' })[0].Record
                    $run.Outcome | Should -Not -Be 'ok'
                    "$($run.FailedStep)" | Should -Not -BeNullOrEmpty -Because "$e / $x / $mode FailedStep"
                    "$($run.ErrorClass)" | Should -Not -BeNullOrEmpty -Because "$e / $x / $mode ErrorClass"
                    if ($mode -eq 'identified') { "$($run.ErrorText)" | Should -Not -BeNullOrEmpty -Because "$e / $x ErrorText" }
                    else { @($run.PSObject.Properties.Name) | Should -Not -Contain 'ErrorText' }
                }
            }
        }
    }
    It 'a recorded step and message win over the fallback; a guard refusal is its own class' {
        $c = New-Ctx identified (Join-Path $TestDrive 'uf2'); Set-SITelemetryLastHeartbeat -StateDirectory $c.StateDirectory -NowUtc ([datetime]'2026-10-04T00:00:00Z')
        $rc = New-RunCtx 'datasync'; $rc | Add-Member -NotePropertyName FailedStep -NotePropertyValue 'correlation-map'
        $null = Send-SITelemetryRunEnd -RunContext $rc -ExitReason 'error' -ErrorMessage 'cmdb.sql.no-correlation-map refused: the correlation map (SI_ObjectMap_CL) is empty' -Context $c -Transport $script:StubOk -Now ([datetime]'2026-10-04T07:00:00Z')
        $run = @($script:Posts | Where-Object { $_.Record.Kind -eq 'run' })[0].Record
        $run.Job | Should -Be 'si-datasync'; $run.Outcome | Should -Be 'failed'
        $run.FailedStep | Should -Be 'correlation-map'; $run.ErrorClass | Should -Be 'guard-refused'
        $run.ErrorText | Should -Match '^cmdb\.sql\.no-correlation-map refused: '
    }
    It 'a failure outside an engine run (install / updater) carries the three as well' {
        $c = New-Ctx identified (Join-Path $TestDrive 'uf3')
        $null = Send-SITelemetryFailure -Job updater -Step '' -ErrorMessage '' -Context $c -Transport $script:StubOk -Now ([datetime]'2026-10-04T07:00:00Z')
        $run = $script:Posts[0].Record
        $run.Outcome | Should -Be 'failed'; "$($run.FailedStep)" | Should -Not -BeNullOrEmpty; "$($run.ErrorClass)" | Should -Not -BeNullOrEmpty; "$($run.ErrorText)" | Should -Not -BeNullOrEmpty
    }
}
