#Requires -Version 5.1
<#
    SecurityInsight -- #427 EVERY FAILURE REACHES INVARDIA'S UPLINK (framework UPLINK-FIX, owner 2026-10-07; PIM's check that
    night: its guided install, MSP build and in-cloud updater failures never reached the uplink, only scheduled job runs did --
    SI had the same gap).

    What must hold:
      - Send-SITelemetryFailure: ONE `run` report, Job si-install / si-updater, Outcome failed, FailedStep = the step,
        ErrorClass from the text, the version; NO heartbeat; identified = the error text (redacted), anonymous = no text, no
        tenant; the telemetry switch off = nothing built or sent;
      - the guided install: a failed step is reported (step id + message), a step that succeeds is not; a reporter that
        throws never fails the step's result; the session's SI_Telemetry_Enabled survives the install's isolation;
      - the updater: each failure recorded with its step; the engine roll's stage (build / roll / restore) and first warning
        (the 400 "imageType" of 2026-10-06) come from the release's Invoke-SIContainerUpdate.ps1; the database step's
        failure (the byte[] SID) is recorded as 'database' and nothing is rolled; claim / licence refusals are failures;
        the Settings page's switch wins over the job's; at most 5 reports; an exit code with nothing recorded is one report.
    Offline; PS 5.1 and 7.
#>

BeforeAll {
    # CR5 (#655): new installs get the new names by default (SI_Setup_NewInstallNames ON since 2026-10-18). This suite's fake
    # installs pin TODAY's names; the default itself is proven in SIv3-GuidedInstall (CR5 step 2) and SIv3-InstallNames.
    $env:SI_Setup_NewInstallNames = 'false'
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\_shared\SI-TelemetrySend.ps1')
    . (Join-Path $script:SIRoot 'container\updater\Start-SIUpdater.ps1') -DefineOnly
    $script:Id = [pscustomobject]@{ Mode = 'identified'; Endpoint = 'https://uplink.test'; AccessCode = 'inv-TESTKEY-0123456789'; Edition = 'pro'; LicenceState = 'valid'
                                    Version = '3.0.0+abc1234'; Hosting = 'container'; RuntimeIdentity = 'mi-container'; InstallId = ''; TenantId = '11111111-2222-3333-4444-555555555555'; StateDirectory = $TestDrive }
    $script:Anon = [pscustomobject]@{ Mode = 'anonymous'; Endpoint = 'https://uplink.test'; AccessCode = 'community'; Edition = 'community'; LicenceState = 'none'
                                      Version = '3.0.0'; Hosting = 'vm'; RuntimeIdentity = 'spn-certificate'; InstallId = '0f0e0d0c-0b0a-4908-8706-050403020100'; TenantId = ''; StateDirectory = $TestDrive }
    function script:New-Capture { $l = New-Object System.Collections.Generic.List[object]; [pscustomobject]@{ List = $l; Transport = { param($Record, $Endpoint, $AccessCode, $TimeoutSec) $l.Add($Record); [pscustomobject]@{ Status = 'ok' } }.GetNewClosure() } }
}

Describe 'Send-SITelemetryFailure: one failed run report, no heartbeat' {
    BeforeEach { $global:SI_TelemetryHalted = $false; $global:SI_Telemetry_Enabled = $null }
    It 'identified: Job si-install, FailedStep the step id, failed, an error class, the text, the version -- and no heartbeat even when one is due' {
        $c = New-Capture
        $r = Send-SITelemetryFailure -Job install -Step 'container-jobs' -ErrorMessage 'az containerapp job create failed: (AuthorizationFailed) the client does not have authorization' -Context $script:Id -Transport $c.Transport
        $r.Status | Should -Be 'ok'
        $c.List.Count | Should -Be 1
        $w = $c.List[0]
        $w.Kind | Should -Be 'run'
        $w.Job | Should -Be 'si-install'
        $w.FailedStep | Should -Be 'container-jobs'
        $w.Outcome | Should -Be 'failed'
        "$($w.ErrorClass)" | Should -Not -BeNullOrEmpty
        $w.Version | Should -Be '3.0.0+abc1234'
        ($w | ConvertTo-Json -Depth 5) | Should -Match 'AuthorizationFailed'
    }
    It 'anonymous: no error text and no tenant leave the machine' {
        $c = New-Capture
        $null = Send-SITelemetryFailure -Job updater -Step 'roll' -ErrorMessage 'caj-si-ptc: 400 Unknown properties imageType in tenant 11111111-2222-3333-4444-555555555555' -Context $script:Anon -Transport $c.Transport
        $c.List.Count | Should -Be 1
        $j = $c.List[0] | ConvertTo-Json -Depth 5
        $c.List[0].Job | Should -Be 'si-updater'
        $c.List[0].FailedStep | Should -Be 'roll'
        $j | Should -Not -Match 'imageType'
        $j | Should -Not -Match '11111111-2222'
    }
    It 'the telemetry switch off: nothing is sent' {
        $c = New-Capture
        $global:SI_Telemetry_Enabled = $false
        (Send-SITelemetryFailure -Job install -Step 'key-vault' -ErrorMessage 'x' -Context $script:Id -Transport $c.Transport).Status | Should -Be 'disabled'
        $c.List.Count | Should -Be 0
    }
    It 'a step id is made a valid step name; an empty one is "unknown"' {
        $c = New-Capture
        $null = Send-SITelemetryFailure -Job updater -Step 'Post Roll!' -ErrorMessage 'x' -Context $script:Id -Transport $c.Transport
        $global:SI_TelemetryHalted = $false
        $null = Send-SITelemetryFailure -Job updater -Step '' -ErrorMessage 'x' -Context $script:Id -Transport $c.Transport
        $c.List[0].FailedStep | Should -Be 'post-roll-'
        $c.List[1].FailedStep | Should -Be 'unknown'
    }
    It 'si-install is on the agreed job list, and the install maps to it' {
        @((Get-SITelemetryContract).Jobs) | Should -Contain 'si-install'
        Resolve-SITelemetryJob -Engine 'install' | Should -Be 'si-install'
        Resolve-SITelemetryJob -Engine 'updater' | Should -Be 'si-updater'
    }
    It 'NEGATIVE: an engine run still sends its heartbeat (only -NoHeartbeat leaves it out)' {
        $c = New-Capture
        $rc = [pscustomobject]@{ Engine = 'identity'; ShardIndex = 0; StartedAt = [datetime]::UtcNow }
        $null = Send-SITelemetryRunEnd -RunContext $rc -ExitReason 'success' -Context $script:Anon -Transport $c.Transport -Now ([datetime]'2026-10-07T03:00:00Z')
        @($c.List | ForEach-Object { $_.Kind }) | Should -Contain 'heartbeat'
    }
}

Describe 'the guided install: a failed step reaches the uplink' {
    BeforeAll {
        . (Join-Path $script:SIRoot 'setup\_shared\SI-GuidedInstall.ps1')
        function script:New-InstallCtx([scriptblock]$Telemetry) {
            $seams = @{ Now = { [datetime]::UtcNow }; Print = { param($t, $c) } }
            if ($Telemetry) { $seams['Telemetry'] = $Telemetry }
            @{ InstallId = 'test-install'; Seams = $seams; State = [ordered]@{ seq = 0; pending = [ordered]@{} }; Events = New-Object System.Collections.Generic.List[object]
               ResumeCommand = './setup/Install-SecurityInsight.ps1 -Resume'; Reporter = $null; StateDirectory = $TestDrive; Values = [ordered]@{ tenantId = 't' }; InstallKey = ''; Pro = $false }
        }
    }
    It 'a failed step is reported once: Job install, the step id, the message' {
        $sent = New-Object System.Collections.Generic.List[object]
        $ctx = New-InstallCtx -Telemetry { param($Job, $Step, $Text, $Context) $sent.Add([pscustomobject]@{ Job = $Job; Step = $Step; Text = $Text }) }.GetNewClosure()
        $state = Invoke-SIInstallStep -Ctx $ctx -StepId 'container-jobs' -Body { throw 'the job could not be created: (AuthorizationFailed)' }
        $state | Should -Be 'failed'
        $sent.Count | Should -Be 1
        $sent[0].Job | Should -Be 'install'; $sent[0].Step | Should -Be 'container-jobs'; $sent[0].Text | Should -Match 'AuthorizationFailed'
    }
    It 'NEGATIVE: a step that succeeds (or warns) is not reported' {
        $sent = New-Object System.Collections.Generic.List[object]
        $ctx = New-InstallCtx -Telemetry { param($Job, $Step, $Text, $Context) $sent.Add($Step) }.GetNewClosure()
        Invoke-SIInstallStep -Ctx $ctx -StepId 'key-vault' -Body { New-SIInstallResult -State 'ok' } | Should -Be 'ok'
        Invoke-SIInstallStep -Ctx $ctx -StepId 'key-vault' -Body { New-SIInstallResult -State 'warning' -Message 'grant pending' } | Should -Be 'warning'
        $sent.Count | Should -Be 0
    }
    It 'a refused configuration (exit 3) is reported as step config' {
        $sent = New-Object System.Collections.Generic.List[object]
        $seams = @{ Print = { param($t, $c) }; Telemetry = { param($Job, $Step, $Text, $Context) $sent.Add([pscustomobject]@{ Step = $Step }) }.GetNewClosure() }
        $code = Invoke-SIGuidedInstall -SIRoot $script:SIRoot -ConfigPath (Join-Path $TestDrive 'no-such-config.json') -Seams $seams
        $code | Should -Be 3
        $sent.Count | Should -Be 1
        $sent[0].Step | Should -Be 'config'
    }
    It 'a reporter that throws never changes the step''s result' {
        $ctx = New-InstallCtx -Telemetry { param($Job, $Step, $Text, $Context) throw 'uplink down' }
        Invoke-SIInstallStep -Ctx $ctx -StepId 'web-app' -Body { throw 'boom' } | Should -Be 'failed'
    }
    It 'a test session without the seam never builds a context or sends (no install id written)' {
        $ctx = New-InstallCtx
        Send-SIInstallFailureTelemetry -Ctx $ctx -StepId 'web-app' -Message 'x' | Should -BeNullOrEmpty
    }
    It 'the session''s telemetry switch is kept through the install''s isolation' {
        $global:SI_Telemetry_Enabled = $false
        try { @(Get-SIInstallIsolatedGlobalNames) | Should -Not -Contain 'SI_Telemetry_Enabled' } finally { $global:SI_Telemetry_Enabled = $null }
    }
}

Describe 'the updater: every failure recorded with its step, reported at the end' {
    BeforeEach { $global:SI_UpdaterFailures = New-Object System.Collections.Generic.List[object]; $global:SI_UpdaterStep = '' }
    It 'the engine roll''s stage gives the step: build / roll / restore (nothing announced = roll)' {
        ConvertTo-SIUpdaterRollStep -Stage '2. BUILD' | Should -Be 'build'
        ConvertTo-SIUpdaterRollStep -Stage '3. ROLL (all jobs at once)' | Should -Be 'roll'
        ConvertTo-SIUpdaterRollStep -Stage '4. VERIFY' | Should -Be 'roll'
        ConvertTo-SIUpdaterRollStep -Stage '5. ROLLBACK' | Should -Be 'restore'
        ConvertTo-SIUpdaterRollStep -Stage '' | Should -Be 'roll'
    }
    It 'claim and licence REFUSALS are failures; waiting / network / held / claimed / installed are not' {
        foreach ($a in 'forbidden', 'conflict', 'invalid', 'error') { Get-SIUpdaterClaimFailure -Claim ([pscustomobject]@{ Action = $a; Reason = 'r' }) | Should -Match "install key claim $a" }
        foreach ($a in 'bundle', 'present', 'claimed', 'held', 'off', 'waiting', 'network') { Get-SIUpdaterClaimFailure -Claim ([pscustomobject]@{ Action = $a; Reason = 'r' }) | Should -Be '' }
        foreach ($a in 'refused', 'rejected', 'invalid', 'error') { Get-SIUpdaterLicenceFailure -Result ([pscustomobject]@{ Action = $a; Message = 'm' }) | Should -Match "licence request $a" }
        foreach ($a in 'none', 'waiting', 'knocked', 'pending', 'installed', 'network') { Get-SIUpdaterLicenceFailure -Result ([pscustomobject]@{ Action = $a; Message = 'm' }) | Should -Be '' }
        Get-SIUpdaterLicenceFailure -Result $null | Should -Be ''
    }
    It 'the switch: the Settings page wins over the job''s environment; nothing set = on' {
        Test-SIUpdaterTelemetryOn -Settings $null -EnvValue '' | Should -BeTrue
        Test-SIUpdaterTelemetryOn -Settings $null -EnvValue 'false' | Should -BeFalse
        Test-SIUpdaterTelemetryOn -Settings ([pscustomobject]@{ Values = @{ SI_Telemetry_Enabled = $true } }) -EnvValue 'false' | Should -BeTrue
        Test-SIUpdaterTelemetryOn -Settings ([pscustomobject]@{ Values = @{ SI_Telemetry_Enabled = $false } }) -EnvValue 'true' | Should -BeFalse
    }
    It 'the database step''s failure (live: the byte[] SID) is recorded as database, and nothing is rolled' {
        # the database step is Pro (absent from the Community copy): a stand-in where it is missing, then the fake answer
        $made = $false
        if (-not (Get-Command -Name Invoke-SIUpdaterDatabase -ErrorAction SilentlyContinue)) { function global:Invoke-SIUpdaterDatabase { param($SIRoot, $Store, $ResourceGroup, $SubscriptionId) }; $made = $true }
        Mock Invoke-SIUpdaterDatabase { [pscustomobject]@{ Ok = $false; Reason = 'grants: Cannot convert value "System.Byte[]" to type "System.String"' } }
        try {
            $r = Invoke-SIUpdaterRoll -SIRoot $TestDrive -ResourceGroup 'rg' -AcrName 'acr' -SubscriptionId 'sub' -Store ([pscustomobject]@{ Name = 's' }) 6>$null
            $r.Code | Should -Be 1
            @(Get-SIUpdaterFailures).Count | Should -Be 1
            (Get-SIUpdaterFailures)[0].Step | Should -Be 'database'
            (Get-SIUpdaterFailures)[0].Text | Should -Match 'Byte\[\]'
        } finally { if ($made) { Remove-Item -Path Function:\global:Invoke-SIUpdaterDatabase -ErrorAction SilentlyContinue } }
    }
    It 'a failed engine roll (live: 16 PATCH 400 imageType) is recorded with the release''s stage and first warning' {
        $root = Join-Path $TestDrive 'rel'; New-Item -ItemType Directory -Force -Path (Join-Path $root 'setup') | Out-Null
        Set-Content -LiteralPath (Join-Path $root 'setup\Invoke-SIContainerUpdate.ps1') -Encoding ascii -Value @'
param([switch]$Apply, $ResourceGroupName, $AcrName, $SubscriptionId)
$global:SI_UpdateStage = '2. BUILD'
$global:SI_UpdateStage = '3. ROLL (all jobs at once)'
if (-not "$global:SI_UpdateFirstWarn".Trim()) { $global:SI_UpdateFirstWarn = 'caj-si-ptc: 400 Unknown properties imageType in ContainerAppContainer are not supported' }
$global:LASTEXITCODE = 1
'@
        Mock Start-SIUpdaterPrebuilds { }
        $r = Invoke-SIUpdaterRoll -SIRoot $root -ResourceGroup 'rg' -AcrName 'acr' -SubscriptionId 'sub' -TemplatesFollowChannel 6>$null
        $r.Code | Should -Be 1
        $f = @(Get-SIUpdaterFailures)
        $f.Count | Should -Be 1
        $f[0].Step | Should -Be 'roll'
        $f[0].Text | Should -Match 'imageType'
    }
    It 'reports: each recorded failure once (the same twice = once), at most 5; switched off = none' {
        $sent = New-Object System.Collections.Generic.List[object]
        $send = { param($Step, $Text) $sent.Add("$Step|$Text"); [pscustomobject]@{ Status = 'ok' } }.GetNewClosure()
        Add-SIUpdaterFailure -Step 'database' -Text 'a'; Add-SIUpdaterFailure -Step 'database' -Text 'a'; Add-SIUpdaterFailure -Step 'claim' -Text 'b'
        $r = @(Send-SIUpdaterFailureReports -ExitCode 1 -On $true -Send $send)
        $r.Count | Should -Be 2; $sent.Count | Should -Be 2
        $sent[0] | Should -Be 'database|a'
        foreach ($i in 1..8) { Add-SIUpdaterFailure -Step 'roll' -Text "r$i" }
        $sent.Clear(); $null = Send-SIUpdaterFailureReports -ExitCode 1 -On $true -Send $send
        $sent.Count | Should -Be 5
        $sent.Clear(); $null = Send-SIUpdaterFailureReports -ExitCode 1 -On $false -Send $send
        $sent.Count | Should -Be 0
    }
    It 'a non-zero exit with nothing recorded is ONE report, in the step the run was in; a clean run sends nothing' {
        $sent = New-Object System.Collections.Generic.List[object]
        $send = { param($Step, $Text) $sent.Add($Step); [pscustomobject]@{ Status = 'ok' } }.GetNewClosure()
        @(Send-SIUpdaterFailureReports -ExitCode 0 -On $true -Send $send).Count | Should -Be 0
        $global:SI_UpdaterStep = 'signin'
        $r = @(Send-SIUpdaterFailureReports -ExitCode 1 -On $true -Send $send)
        $r.Count | Should -Be 1
        $r[0].Step | Should -Be 'signin'
    }
    It 'Invoke-SIUpdaterFailureReport: the job''s SI_TELEMETRY_ENABLED=false sends nothing; on, the install key is read only then' {
        $sent = New-Object System.Collections.Generic.List[object]; $reads = @{ N = 0 }
        $send = { param($Step, $Text) $sent.Add($Step); [pscustomobject]@{ Status = 'ok' } }.GetNewClosure()
        $read = { $reads.N++; 'inv-TESTKEY-0123456789' }.GetNewClosure()
        Add-SIUpdaterFailure -Step 'download' -Text 'code REFUSED: sha256 mismatch'
        $null = Invoke-SIUpdaterFailureReport -ExitCode 1 -Env @{ SI_TELEMETRY_ENABLED = 'false' } -ReadKey $read -Send $send
        $sent.Count | Should -Be 0; $reads.N | Should -Be 0
        $null = Invoke-SIUpdaterFailureReport -ExitCode 1 -Env @{} -ReadKey $read -Send $send
        $sent.Count | Should -Be 1; $reads.N | Should -Be 1
    }
    It 'WIRING: the release''s update script leaves its stage and first warning; the updater reports at the end of every run' {
        $cu = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'setup\Invoke-SIContainerUpdate.ps1')
        $cu | Should -Match 'function Step\(\[string\]\$m\) \{ \$global:SI_UpdateStage = \$m'
        $cu | Should -Match 'function Warn\(\[string\]\$m\) \{ if \(-not "\$global:SI_UpdateFirstWarn"\.Trim\(\)\) \{ \$global:SI_UpdateFirstWarn = \$m \}'
        $su = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'container\updater\Start-SIUpdater.ps1')
        $su | Should -Match '\$null = Invoke-SIUpdaterFailureReport -ExitCode \$rc -StartedAt \$updStarted\s+exit \$rc'
        $su | Should -Match "Add-SIUpdaterFailureIf 'licence' \`$lf"
        $df = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'container\updater\Dockerfile')
        $df | Should -Match 'COPY container/updater/_shared/ \./_shared/'
        $df | Should -Match 'COPY engine/_shared/ /si/engine/_shared/'
        # #521: the install key for an identified report is read over REST (the Key Vault data plane), never with az
        $su | Should -Match "Get-SIKeyVaultSecretValue -VaultName \(& \`$get 'SI_UPDATER_KEY_VAULT'\) -Name 'SI-Invardia-InstallKey'"
    }
}
