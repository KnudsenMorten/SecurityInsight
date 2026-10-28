#Requires -Version 5.1
# SI-TestScope: PrivateRepo
#   the updater's only source is Invardia, whose client ships with Pro only -- a public (Community) copy has nothing to run
<#
    #350 -- caj-si-updater runs DAILY, like every ring and like PIM4EntraPS's ca-pim-update. Since 2026-10-06 its ONLY source
    is Invardia's update platform (operator: "one solution: invardia"; framework UPDATE-1.7): the ring channel this suite
    used to test -- channel.json in SI's own storage feed -- is RETIRED.

    What stays from #350 and is tested here: the manual-deploy mark (an updater never rolls under a running manual deploy),
    the managed-identity sign-in, and the proof that the retired ring channel cannot be reached any more: a job still set up
    for it (SI_UPDATER_RING + a feed link) changes nothing. The Invardia path's use of the same guards is tested in
    SIv3-InvardiaUpdate.Tests.ps1 ("ring 1 can move from the feed to Invardia without losing a step").
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'container\updater\Start-SIUpdater.ps1') -DefineOnly
    . (Join-Path $script:SIRoot 'container\updater\_shared\SI-UpdaterInvardia.ps1')
    $script:Source = 'https://feedacct.blob.core.windows.net/si-src-internal?sv=2024-01-01&si=srcread&sr=c&sig=TOPSECRETSIG'
    $script:Env = { param([hashtable]$Extra = @{})
        $e = @{ SI_UPDATER_TENANT_ID = '11111111-2222-3333-4444-555555555555'; SI_UPDATER_CLIENT_ID = 'cid'; SI_UPDATER_SUBSCRIPTION_ID = 'sub'
                SI_UPDATER_RESOURCE_GROUP = 'rg'; SI_UPDATER_ACR = 'acr'; SI_UPDATER_CERT_PFX_B64 = 'pfx'; SI_UPDATER_KEY_VAULT = 'kv-test'
                SI_UPDATER_RING = '1' }
        foreach ($k in $Extra.Keys) { $e[$k] = $Extra[$k] }
        $e
    }
}

Describe 'the manual-deploy mark (pure)' {
    It 'a manual-deploy mark: fresh = locked; older than 3 h = a deploy that died, ignored and said so; none = free' {
        $now = [datetime]::new(2026, 10, 5, 17, 0, 0, [DateTimeKind]::Utc)
        (Test-SIUpdaterDeployLock -Value '2026-10-05T16:30:00Z fast-deploy-r1' -NowUtc $now).Locked | Should -BeTrue
        $old = Test-SIUpdaterDeployLock -Value '2026-10-05T12:00:00Z fast-deploy-r1' -NowUtc $now
        $old.Locked | Should -BeFalse; $old.Reason | Should -Match 'older than 3 h'
        (Test-SIUpdaterDeployLock -Value '' -NowUtc $now).Locked | Should -BeFalse
        (Test-SIUpdaterDeployLock -Value 'garbage' -NowUtc $now).Locked | Should -BeTrue
    }
    It 'the Invardia path checks it before every roll (a running pipeline does not hold the update; a release that needs quiet waits)' {
        # the pre-roll lives in SI-UpdaterRollSteps.ps1 since 2026-10-27 (#750 (b): shared with the Community updater)
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\updater\_shared\SI-UpdaterInvardia.ps1')) + "`n" + [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\updater\_shared\SI-UpdaterRollSteps.ps1'))
        $src | Should -Match 'Test-SIUpdaterDeployLock -Value \$envNow\.DeployLock'
        $src | Should -Match 'Get-SIUpdaterNeedsQuiet -SIRoot \$SIRoot'
    }
}

Describe 'the ring channel is RETIRED: a job still set up for it changes nothing' {
    BeforeEach {
        $script:Calls = New-Object System.Collections.Generic.List[string]
        # #521: the ONE sign-in is SecurityInsight's REST client -- the identity is recorded (Connect-SIAzAccountRest), no az
        Mock Get-SIAzRestState { $script:FreshState }
        Mock Connect-SIAzAccountRest { $script:Calls.Add($(if ($Identity) { 'signin-mi:' + $AccountId } else { 'signin-cert:' + $ApplicationId })) }
        Mock Invoke-SIUpdaterArm { $script:Calls.Add('arm') }
        $script:FreshState = @{ Connection = $null; SubscriptionId = $null; TenantId = $null; Cache = @{} }
        Mock Invoke-WebRequest { $script:Calls.Add('http ' + $Uri); throw 'no network in tests' }
        Mock Invoke-RestMethod { $script:Calls.Add('http ' + $Uri); throw 'no network in tests' }
        Mock Invoke-SIUpdaterLicenceRequest { $script:Calls.Add('licence') }
    }
    It 'SI_UPDATER_RING with a feed link (the old ring-1 job): exit 0, no sign-in, no Azure call, no HTTP; the log says how to move' {
        $out = @(Invoke-SIUpdater -Env (& $script:Env @{ SI_UPDATER_SOURCE = 'feed'; SI_UPDATER_SOURCE_URL = $script:Source }) 6>&1 | ForEach-Object { "$_" })
        @($out | Where-Object { $_ -match '^\d+$' })[-1] | Should -Be '0'
        $script:Calls.Count | Should -Be 0
        ($out -join "`n") | Should -Match 'RETIRED'
        ($out -join "`n") | Should -Not -Match 'TOPSECRETSIG'
    }
    It 'nothing that read or wrote channel.json exists any more' {
        foreach ($n in 'Invoke-SIUpdaterFromChannel', 'Get-SIUpdaterChannelDecision', 'Get-SIRingVersion', 'Set-SIUpdateChannelEntry', 'Get-SIFeedChannelName', 'Save-SIUpdaterChannelState', 'Invoke-SIUpdaterSelfRetry') {
            Get-Command -Name $n -ErrorAction SilentlyContinue | Should -BeNullOrEmpty -Because "$n belonged to the retired ring channel"
        }
    }
    It 'signs in as the job''s managed identity when SI_UPDATER_AUTH=ManagedIdentity -- no certificate needed (Invardia path)' {
        Mock Invoke-SIUpdaterFromInvardia { $script:Calls.Add('invardia'); 0 }
        Mock Get-SIUpdaterDeployed { '3.0.0' }
        Mock Get-SIUpdaterAutoSwitches { $null }
        $e = & $script:Env @{ SI_UPDATER_AUTH = 'ManagedIdentity' }; $e.Remove('SI_UPDATER_CERT_PFX_B64')
        (Invoke-SIUpdater -Env $e 6>$null) | Should -Be 0
        $script:Calls | Should -Contain 'signin-mi:cid'
        @($script:Calls | Where-Object { $_ -like 'signin-cert*' }) | Should -BeNullOrEmpty
        $script:Calls | Should -Contain 'invardia'
    }
    It 'signs in as the SPN by certificate by default -- the PFX recorded for the REST client, the temporary file removed at once' {
        Mock Invoke-SIUpdaterFromInvardia { $script:Calls.Add('invardia'); 0 }
        Mock Get-SIUpdaterDeployed { '3.0.0' }
        Mock Get-SIUpdaterAutoSwitches { $null }
        Mock Connect-SIAzAccountRest { $script:Calls.Add('signin-cert:' + $ApplicationId + ':' + $Tenant); $script:PfxSeen = $CertificatePath; $script:PfxExisted = (Test-Path -LiteralPath $CertificatePath) }
        (Invoke-SIUpdater -Env (& $script:Env @{ SI_UPDATER_CERT_PFX_B64 = [Convert]::ToBase64String([byte[]](1, 2, 3)) }) 6>$null) | Should -Be 0
        $script:Calls | Should -Contain 'signin-cert:cid:11111111-2222-3333-4444-555555555555'
        $script:PfxExisted | Should -BeTrue
        Test-Path -LiteralPath $script:PfxSeen | Should -BeFalse -Because 'the key never stays on disk'
    }
}
