#Requires -Version 5.1
<#
    FRAMEWORK INSTALLER RULE 11b + RULE 11 (general) -- 3.0.31, from a customer's private install that was stopped before its
    image build (2026-11-04): the bootstrap made the container registry Basic, PUBLIC, admin user ON, and only the install's
    LAST step made it Premium + private (admin user left on). What must hold now:
      * a private install's registry is CREATED private (Premium, public access Disabled, trusted Azure services allowed,
        admin user off) -- or, FOUND as an earlier release left it, CONVERGED to that shape; ABSENT (deleted) = created private;
      * right after it: its private endpoint + privatelink.azurecr.io (+ link, zone group), its names (login server AND data
        endpoint) in the DNS check from the install machine, its records on the hub hand-off; its agent pool in the network;
      * image builds run on that agent pool from the FIRST build; pulls stay by managed identity;
      * a FOUND environment that is not internal in the subnet: replaced only when EMPTY (half-made / failed = empty), the
        plan otherwise; one Azure is still making internal ("Waiting") is waited for, never replaced;
      * existing private installs converge through the updater (setup\Invoke-SIContainerUpdate.ps1 step 1b), never closing
        a registry whose names do not resolve privately from inside;
      * console text: the product + released version (never v2.2), no release-candidate label in a release, no cost figure.
    OFFLINE (the fake ARM store, a fake Invoke-SIArm). Stubs in SCRIPT scope. PS 5.1 + pwsh 7.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'tests\fixtures\SIArmStoreFake.ps1')
    . (Join-Path $script:SIRoot 'setup\_shared\SI-PrivateNetwork.ps1')
    $script:Sub = '11111111-1111-1111-1111-111111111111'
    $script:Rg = '/subscriptions/{0}/resourceGroups/rg-si-x' -f $script:Sub
    $script:Vnet = '/subscriptions/{0}/resourceGroups/rg-si-x/providers/Microsoft.Network/virtualNetworks/vnet-si' -f $script:Sub
    $script:PeSubnet = "$script:Vnet/subnets/snet-si-endpoints"
    $script:AppsSubnet = "$script:Vnet/subnets/snet-si-apps"
    $script:RegId = "$script:Rg/providers/Microsoft.ContainerRegistry/registries/acrsix"
    $script:EnvId = "$script:Rg/providers/Microsoft.App/managedEnvironments/cae-si-prod-pro-ca"
    $script:NoSleep = { param($s) }
    $script:Arm = { param($m, $p, $b) & $global:SIArmStoreFake $m $p $b }
    $script:Private = { param([string]$Name) @('10.20.0.40') }
    $script:Public = { param([string]$Name) @('20.50.1.2') }

    function script:New-RegWorld {
        param([ValidateSet('absent', 'stopped', 'private')][string]$Registry = 'absent', [switch]$PrivateEnv, [switch]$PasswordJob, [switch]$VaultEndpoint)
        New-SIArmStore
        Set-SIArmStoreItem @{ id = $script:Vnet; location = 'westeurope'; properties = @{ provisioningState = 'Succeeded'; addressSpace = @{ addressPrefixes = @('10.20.0.0/24') } } }
        Set-SIArmStoreItem @{ id = $script:AppsSubnet; properties = @{ addressPrefix = '10.20.0.0/26'; provisioningState = 'Succeeded' } }
        Set-SIArmStoreItem @{ id = $script:PeSubnet; properties = @{ addressPrefix = '10.20.0.64/26'; provisioningState = 'Succeeded' } }
        switch ($Registry) {
            # exactly what the stopped install's bootstrap left: Basic, public, admin user on
            'stopped' { Set-SIArmStoreItem @{ id = $script:RegId; name = 'acrsix'; location = 'westeurope'; sku = @{ name = 'Basic' }; properties = @{ loginServer = 'acrsix.azurecr.io'; adminUserEnabled = $true; publicNetworkAccess = 'Enabled'; networkRuleBypassOptions = 'AzureServices'; provisioningState = 'Succeeded' } } }
            'private' { Set-SIArmStoreItem @{ id = $script:RegId; name = 'acrsix'; location = 'westeurope'; sku = @{ name = 'Premium' }; properties = @{ loginServer = 'acrsix.azurecr.io'; adminUserEnabled = $false; publicNetworkAccess = 'Disabled'; networkRuleBypassOptions = 'AzureServices'; provisioningState = 'Succeeded' } } }
        }
        if ($PrivateEnv) {
            Set-SIArmStoreItem @{ id = $script:EnvId; location = 'westeurope'; properties = @{ provisioningState = 'Succeeded'; defaultDomain = 'x.westeurope.azurecontainerapps.io'; vnetConfiguration = @{ infrastructureSubnetId = $script:AppsSubnet; internal = $true } } }
        } else {
            Set-SIArmStoreItem @{ id = $script:EnvId; location = 'westeurope'; properties = @{ provisioningState = 'Succeeded'; defaultDomain = 'x.westeurope.azurecontainerapps.io' } }
        }
        $reg = if ($PasswordJob) { @{ server = 'acrsix.azurecr.io'; username = 'acrsix'; passwordSecretRef = 'acr-password' } } else { @{ server = 'acrsix.azurecr.io'; identity = 'mi' } }
        Set-SIArmStoreItem @{ id = "$script:Rg/providers/Microsoft.App/jobs/caj-si-flow"; location = 'westeurope'; properties = @{ environmentId = $script:EnvId; provisioningState = 'Succeeded'; configuration = @{ registries = @($reg) } } }
        if ($VaultEndpoint) {
            Set-SIArmStoreItem @{ id = "$script:Rg/providers/Microsoft.Network/privateEndpoints/pe-si-vault"; location = 'westeurope'; properties = @{ provisioningState = 'Succeeded'; subnet = @{ id = $script:PeSubnet }; privateLinkServiceConnections = @(@{ properties = @{ privateLinkServiceId = 'kv'; groupIds = @('vault'); privateLinkServiceConnectionState = @{ status = 'Approved' } } }) } }
        }
        $global:SIArmStore.Writes.Clear()
    }
    function script:Writes { @($global:SIArmStore.Writes) }
    function script:Target { Get-SIInstallPrivateNetworkTarget -Values ([ordered]@{ vnetId = $script:Vnet }) -ResourceGroupId $script:Rg }
    function script:Invoke-Reg([scriptblock]$Resolve = $script:Private) {
        Invoke-SIPrivateNetworkRegistry -Target (Target) -Location 'westeurope' -RegistryLocation 'westeurope' -RegistryId $script:RegId -EndpointsSubnetId $script:PeSubnet -Resolve $Resolve -Arm $script:Arm -Sleep $script:NoSleep
    }
}

AfterAll { Remove-SIArmStore }

Describe 'the registry of a private install: its create body (rule 11b)' {
    It 'Premium, public access Disabled, trusted Azure services allowed, admin user OFF -- from the first create' {
        $b = Get-SIPrivateRegistryBody -Location 'westeurope'
        $b.sku.name | Should -Be 'Premium'
        $b.properties.publicNetworkAccess | Should -Be 'Disabled'
        $b.properties.networkRuleBypassOptions | Should -Be 'AzureServices'
        $b.properties.adminUserEnabled | Should -BeFalse
    }
    It 'the gap of a registry: what keeps it from the private shape' {
        @(Get-SIRegistryPrivateGap ([pscustomobject]@{ sku = @{ name = 'Basic' }; properties = @{ adminUserEnabled = $true; publicNetworkAccess = 'Enabled' } })) | Should -Be @('sku', 'public', 'bypass', 'admin')
        @(Get-SIRegistryPrivateGap ([pscustomobject]@{ sku = @{ name = 'Premium' }; properties = @{ adminUserEnabled = $false; publicNetworkAccess = 'Disabled'; networkRuleBypassOptions = 'AzureServices' } })).Count | Should -Be 0
    }
    It 'its names for the DNS check: the login server AND the data endpoint of its region' {
        @(Get-SIRegistryDnsNames -Registry ([pscustomobject]@{ name = 'acrsix'; location = 'westeurope'; properties = @{ loginServer = 'acrsix.azurecr.io' } })) | Should -Be @('acrsix.azurecr.io', 'acrsix.westeurope.data.azurecr.io')
        @(Get-SIRegistryDnsNames -Registry ([pscustomobject]@{ name = 'acrsix'; location = 'westeurope'; properties = @{ loginServer = 'acrsix.azurecr.io'; dataEndpointHostNames = @('acrsix.swedencentral.data.azurecr.io') } })) | Should -Contain 'acrsix.swedencentral.data.azurecr.io'
        @(Get-SIInsideCheckNames -Registry ([pscustomobject]@{ name = 'acrsix'; location = 'westeurope'; properties = @{ loginServer = 'acrsix.azurecr.io' } })) | Should -Contain 'acrsix.azurecr.io'
    }
}

Describe 'the private-network-registry step: ABSENT, FOUND as the stopped install left it, already private' {
    It 'ABSENT (the owner deleted it): created private, its endpoint + zone + link, its agent pool in the network, the DNS check passes' {
        New-RegWorld -Registry absent
        $r = Invoke-Reg
        $r.Ok | Should -BeTrue
        $reg = Get-SIArmStoreItem $script:RegId
        $reg.sku.name | Should -Be 'Premium'
        $reg.properties.publicNetworkAccess | Should -Be 'Disabled'
        $reg.properties.networkRuleBypassOptions | Should -Be 'AzureServices'
        $reg.properties.adminUserEnabled | Should -BeFalse
        @(Writes | Where-Object { $_ -like "PUT $script:RegId" }).Count | Should -Be 1 -Because 'one create, already private: never a public moment'
        # the registry itself is never patched (its agent pool is: made at 1 agent, then scaled to 0 -- Azure refuses a pool made at 0)
        @(Writes | Where-Object { $_ -like "PATCH $script:RegId*" -and $_ -notlike "*/agentPools/*" }).Count | Should -Be 0
        (Get-SIArmStoreItem "$script:Rg/providers/Microsoft.Network/privateEndpoints/pe-si-registry").properties.subnet.id | Should -Be $script:PeSubnet
        (Get-SIArmStoreItem "$script:Rg/providers/Microsoft.Network/privateDnsZones/privatelink.azurecr.io/virtualNetworkLinks/vnet-si").properties.virtualNetwork.id | Should -Be $script:Vnet
        Get-SIArmStoreItem "$script:Rg/providers/Microsoft.Network/privateEndpoints/pe-si-registry/privateDnsZoneGroups/default" | Should -Not -BeNullOrEmpty
        (Get-SIArmStoreItem "$script:RegId/agentPools/si-vnet-pool").properties.virtualNetworkSubnetResourceId | Should -Be $script:PeSubnet
        $r.AgentPool | Should -Be 'si-vnet-pool'
        @($r.Gate.Names) | Should -Be @('acrsix.azurecr.io', 'acrsix.westeurope.data.azurecr.io')
    }
    It 'FOUND Basic / public / admin user on (the stopped install): converged -- Premium FIRST, then closed + admin off, read back' {
        New-RegWorld -Registry stopped
        $r = Invoke-Reg
        $r.Ok | Should -BeTrue
        $reg = Get-SIArmStoreItem $script:RegId
        $reg.sku.name | Should -Be 'Premium'
        $reg.properties.publicNetworkAccess | Should -Be 'Disabled'
        $reg.properties.adminUserEnabled | Should -BeFalse
        $patches = @(Writes | Where-Object { $_ -like "PATCH $script:RegId" })
        $patches.Count | Should -Be 2 -Because 'the tier first (Disabled needs Premium), then the network + the admin user'
        ($r.Lines -join ' ') | Should -Match 'made private: Premium, public access Disabled, admin user off'
        @(Writes | Where-Object { $_ -like "PUT $script:RegId" }) | Should -BeNullOrEmpty -Because 'a found registry is never replaced'
    }
    It 'FOUND with a job that still pulls with the password: the network shape is set, the admin user STAYS on, named' {
        New-RegWorld -Registry stopped -PasswordJob
        $r = Invoke-Reg
        $r.NetworkShapeOk | Should -BeTrue
        $r.RegistryOk | Should -BeFalse
        (Get-SIArmStoreItem $script:RegId).properties.adminUserEnabled | Should -BeTrue
        (Get-SIArmStoreItem $script:RegId).properties.publicNetworkAccess | Should -Be 'Disabled'
        ($r.Lines -join ' ') | Should -Match 'admin user STAYS ON: caj-si-flow'
    }
    It 'already private: nothing is written the second time' {
        New-RegWorld -Registry absent
        $null = Invoke-Reg
        $global:SIArmStore.Writes.Clear()
        (Invoke-Reg).Ok | Should -BeTrue
        @(Writes) | Should -BeNullOrEmpty
    }
    It 'the DNS check FROM THIS MACHINE: names not private yet -> NOT passed, the exact record for the hub hand-off' {
        New-RegWorld -Registry absent
        $r = Invoke-Reg -Resolve $script:Public
        $r.Ok | Should -BeFalse
        $r.Gate.Ok | Should -BeFalse
        @($r.Gate.Failed) | Should -Contain 'acrsix.azurecr.io'
        @($r.Gate.Records | ForEach-Object { $_.Zone }) | Should -Contain 'privatelink.azurecr.io'
        ($r.Lines -join ' ') | Should -Match 'ADD THESE A RECORDS'
    }
    It 'the hand-off list carries the registry''s record (Get-SIPrivateLinkRecords reads pe-si-registry)' {
        New-RegWorld -Registry absent
        $null = Invoke-Reg
        @(Get-SIPrivateLinkRecords -Arm $script:Arm -ResourceGroupId $script:Rg | Where-Object { $_.Zone -eq 'privatelink.azurecr.io' }).Count | Should -BeGreaterThan 0
    }
}

Describe 'the guided install: the registry step before the first image build' {
    BeforeAll {
        . (Join-Path $script:SIRoot 'setup\_shared\SI-GuidedInstall.ps1')
        $script:Gi = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'setup\_shared\SI-GuidedInstall.ps1'))
    }
    It 'ORDER: private-network-registry right before container-registry-image; not in a public install' {
        $ids = @(Get-SIInstallStepPlan -Edition 'pro' -Options (Get-SIInstallChosenOptions -Values ([ordered]@{ privateNetwork = $true })) | ForEach-Object Id)
        [array]::IndexOf($ids, 'private-network-registry') | Should -Be ([array]::IndexOf($ids, 'container-registry-image') - 1)
        [array]::IndexOf($ids, 'private-network-registry') | Should -BeGreaterThan ([array]::IndexOf($ids, 'private-network-subnets'))
        @(Get-SIInstallStepPlan -Edition 'pro' | ForEach-Object Id) | Should -Not -Contain 'private-network-registry'
    }
    It 'the step stops with the hub record when this machine does not resolve the registry yet; the resume passes, nothing made twice' {
        New-RegWorld -Registry absent
        $ctx = @{ Values = [ordered]@{ subscriptionId = $script:Sub; vnetId = $script:Vnet; privateNetwork = $true; location = 'westeurope' }; Names = @{ ResourceGroup = 'rg-si-x'; Acr = 'acrsix' }
                  Facts = [ordered]@{ endpointsSubnetId = $script:PeSubnet; vnetLocation = 'westeurope' }; Cache = [ordered]@{}
                  ResumeCommand = 'resume-cmd'; ScriptLog = (New-Object System.Collections.Generic.List[object])
                  Seams = @{ Az = { param($Command, $Arguments) $a = @{}; foreach ($k in $Arguments.Keys) { $a[$k] = $Arguments[$k] }; $a['Arm'] = $script:Arm; $a['Sleep'] = $script:NoSleep; & $Command @a }
                             Resolve = $script:Public; Print = { param($t, $c) } } }
        $err = $null
        try { $null = & (Get-SIInstallStepTable)['private-network-registry'] $ctx } catch { $err = $_ }
        $err | Should -Not -BeNullOrEmpty
        $err.Exception.Message | Should -Match 'no image is built before it can'
        $err.Exception.Data['SIInstallAction'].text | Should -Match 'acrsix\.azurecr\.io  A  10\.'
        $global:SIArmStore.Writes.Clear()
        $ctx.Seams.Resolve = $script:Private
        $ok = & (Get-SIInstallStepTable)['private-network-registry'] $ctx
        $ok.State | Should -Be 'ok'
        $ctx.Facts['acrAgentPool'] | Should -Be 'si-vnet-pool'
        @(Writes | Where-Object { $_ -like 'PUT *' }) | Should -BeNullOrEmpty -Because 'the resume makes nothing twice'
    }
    It 'ONE setting decides internal vs. external: privateNetwork (the vault''s / storage''s / SQL''s / environment''s) -- private -> private registry, public -> public; a resume reads the first run''s saved answer' {
        $dir = Join-Path $TestDrive 'state'
        $tid = '11111111-1111-1111-1111-111111111111'
        $run = {
            param([System.Collections.IDictionary]$Bound, [switch]$Resume)
            $r = Resolve-SIInstallDirectConfig -Bound $Bound -InstallId 'si-reg' -StatePath $dir -Resume:$Resume
            $r.Ok | Should -BeTrue
            $v = ConvertTo-SIInstallHashtable ([IO.File]::ReadAllText($r.ConfigPath) | ConvertFrom-Json)
            $script:Seen = $null
            $ctx = @{ Values = $v; Names = (Get-SIInstallNames -Values $v -Edition 'pro'); Engines = @(); Facts = [ordered]@{ appsSubnetId = $script:AppsSubnet }; Cache = [ordered]@{}
                      ImageTag = 't'; ConfigPath = $r.ConfigPath; SIRoot = $script:SIRoot; ResumeCommand = 'resume'; ScriptLog = (New-Object System.Collections.Generic.List[object])
                      Seams = @{ Script = { param($Path, $Arguments) $script:Seen = $Arguments; [pscustomobject]@{ ExitCode = 0; Error = ''; Text = @() } } } }
            $null = Invoke-SIInstallBootstrap -Ctx $ctx
            [pscustomobject]@{ Values = $v; Args = $script:Seen
                               Steps = @(Get-SIInstallStepPlan -Edition 'pro' -Options (Get-SIInstallChosenOptions -Values $v) | ForEach-Object Id) }
        }
        # first run, PRIVATE: the registry step is planned, the container setup gets -PrivateRegistry and the agent pool
        $p = & $run @{ TenantId = $tid; SubscriptionId = $script:Sub; PrivateNetwork = [switch]$true; VnetId = $script:Vnet }
        [bool]$p.Values['privateNetwork'] | Should -BeTrue
        $p.Steps | Should -Contain 'private-network-registry'
        [bool]$p.Args['PrivateRegistry'] | Should -BeTrue
        $p.Args['AcrAgentPool'] | Should -Be 'si-vnet-pool'
        [bool]$p.Args['EnvironmentInternal'] | Should -BeTrue -Because 'the same answer makes the environment internal'
        # the RESUME with no new parameter (the stopped install): the saved answer -> private again
        $r1 = & $run @{ Resume = [switch]$true } -Resume
        [bool]$r1.Args['PrivateRegistry'] | Should -BeTrue
        $r1.Steps | Should -Contain 'private-network-registry'
        # ... and a resume that repeats the tenant and subscription keeps the saved private answer too
        $r2 = & $run @{ TenantId = $tid; SubscriptionId = $script:Sub; Resume = [switch]$true } -Resume
        [bool]$r2.Args['PrivateRegistry'] | Should -BeTrue
        # a PUBLIC install: no registry step, no -PrivateRegistry (Basic, as before)
        Remove-Item -LiteralPath $dir -Recurse -Force
        $pub = & $run @{ TenantId = $tid; SubscriptionId = $script:Sub }
        $pub.Steps | Should -Not -Contain 'private-network-registry'
        $pub.Args.Contains('PrivateRegistry') | Should -BeFalse
        $pub.Args.Contains('AcrAgentPool') | Should -BeFalse
    }
    It 'no separate switch: the registry follows privateNetwork only (static)' {
        $script:Gi | Should -Match "if \(\[bool\]\`$v\['privateNetwork'\]\) \{\s+\`$a\.PrivateRegistry = \`$true"
        $script:Gi | Should -Match "'private-network-registry' = 'privateNetwork'"
    }
    It 'the step runs on EVERY run of a private install (rule 11: enforce it every run)' {
        $script:Gi | Should -Match "if \(\`$s\.Id -eq 'private-network-registry'\) \{ \`$notStarted = \`$true \}"
    }
    It 'the container setup gets -PrivateRegistry and the agent pool; builds pass it; Bootstrap never creates a public registry for a private install' {
        $script:Gi | Should -Match "\`$a\.PrivateRegistry = \`$true"
        $script:Gi | Should -Match "\`$a\.AcrAgentPool = "
        $bs = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'Bootstrap-ContainerAppJob.ps1'))
        $bs | Should -Match '(?s)if \(-not \$acr -and \$PrivateRegistry\) \{\s+throw'
        $bs | Should -Match "-AgentPoolName `"\`$AcrAgentPool`"\.Trim\(\)"
        $ab = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'setup\_shared\SI-AcrBuild.ps1'))
        $ab | Should -Match 'if \("\$AgentPoolName"\.Trim\(\)\) \{ "\$AgentPoolName"\.Trim\(\) \} else \{ Resolve-SIAcrAgentPool'
    }
    It 'a private install''s region probe carries the private registry (Premium, Disabled)' {
        $needs = @([pscustomobject]@{ Namespace = 'Microsoft.ContainerRegistry'; Type = 'registries'; Label = 'the container registry'; Location = 'westeurope' })
        $p = Get-SIInstallRegionProbeResources -Needs $needs -Names ([pscustomobject]@{ Acr = 'acrsix' }) -Region 'westeurope' -PrivateNetwork $true
        $res = @($p.Resources)[0]
        if (-not $res) { $res = @($p)[0] }
        $res.sku.name | Should -Be 'Premium'
        $res.properties.publicNetworkAccess | Should -Be 'Disabled'
    }
}

Describe 'the existing private install: the updater converges the registry (step 1b)' {
    It 'a PUBLIC install is not touched' {
        New-RegWorld -Registry stopped
        $r = Invoke-SIUpdatePrivateRegistry -Arm $script:Arm -ResourceGroupId $script:Rg -RegistryId $script:RegId -Resolve $script:Private -Sleep $script:NoSleep
        $r.Private | Should -BeFalse
        @(Writes) | Should -BeNullOrEmpty
    }
    It 'a PRIVATE install with the old registry: Premium, admin off, endpoint, pool -- and CLOSED only because its names resolve privately inside' {
        New-RegWorld -Registry stopped -PrivateEnv -VaultEndpoint
        $r = Invoke-SIUpdatePrivateRegistry -Arm $script:Arm -ResourceGroupId $script:Rg -RegistryId $script:RegId -Resolve $script:Private -Sleep $script:NoSleep
        $r.Private | Should -BeTrue
        $r.Ok | Should -BeTrue
        $r.Closed | Should -BeTrue
        $reg = Get-SIArmStoreItem $script:RegId
        $reg.sku.name | Should -Be 'Premium'
        $reg.properties.adminUserEnabled | Should -BeFalse
        $reg.properties.publicNetworkAccess | Should -Be 'Disabled'
        (Get-SIArmStoreItem "$script:RegId/agentPools/si-vnet-pool").properties.virtualNetworkSubnetResourceId | Should -Be $script:PeSubnet
        Get-SIArmStoreItem "$script:Rg/providers/Microsoft.Network/privateEndpoints/pe-si-registry" | Should -Not -BeNullOrEmpty
    }
    It 'names NOT private inside yet: the registry STAYS open (never a closed registry the jobs cannot reach), said' {
        New-RegWorld -Registry stopped -PrivateEnv -VaultEndpoint
        $r = Invoke-SIUpdatePrivateRegistry -Arm $script:Arm -ResourceGroupId $script:Rg -RegistryId $script:RegId -Resolve $script:Public -Sleep $script:NoSleep
        $r.Ok | Should -BeFalse
        $r.Closed | Should -BeFalse
        (Get-SIArmStoreItem $script:RegId).properties.publicNetworkAccess | Should -Be 'Enabled'
        ($r.Lines -join ' ') | Should -Match 'stays open for now -- its names do not resolve to private addresses'
    }
    It 'a job still pulling with the password keeps the admin user on (named); -WhatIf writes nothing' {
        New-RegWorld -Registry stopped -PrivateEnv -VaultEndpoint -PasswordJob
        $w = Invoke-SIUpdatePrivateRegistry -Arm $script:Arm -ResourceGroupId $script:Rg -RegistryId $script:RegId -Resolve $script:Private -WhatIf -Sleep $script:NoSleep
        @(Writes) | Should -BeNullOrEmpty
        ($w.Lines -join ' ') | Should -Match 'admin user stays on \(caj-si-flow'
        $r = Invoke-SIUpdatePrivateRegistry -Arm $script:Arm -ResourceGroupId $script:Rg -RegistryId $script:RegId -Resolve $script:Private -Sleep $script:NoSleep
        (Get-SIArmStoreItem $script:RegId).properties.adminUserEnabled | Should -BeTrue
        ($r.Lines -join ' ') | Should -Match 'admin user STAYS ON'
    }
    It 'the update runs step 1b before the build, and re-reads the registry so the build picks the agent pool' {
        $u = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'setup\Invoke-SIContainerUpdate.ps1'))
        $i = $u.IndexOf("Step '1b. PRIVATE REGISTRY'"); $j = $u.IndexOf("Step '2. BUILD'")
        $i | Should -BeGreaterThan 0; $i | Should -BeLessThan $j
        $u | Should -Match '\$script:SIAcrRegistryCache = @\{\}'
    }
}

Describe 'the Container Apps environment of a PRIVATE install (rule 11: found resources end private)' {
    BeforeAll {
        function script:Get-SISetupSubscriptionId { param([string]$SubscriptionId) if ($SubscriptionId) { $SubscriptionId } else { '00000000-0000-0000-0000-000000000001' } }
        $script:EPath = '/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-x/providers/Microsoft.App/managedEnvironments/cae-x'
        $script:Snet = '/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-x/providers/Microsoft.Network/virtualNetworks/vnet-si/subnets/snet-si-apps'
        function script:New-Env([string]$State, [switch]$Internal, [switch]$Public) {
            $p = [ordered]@{ provisioningState = $State; appLogsConfiguration = [pscustomobject]@{ destination = 'azure-monitor' } }
            if (-not $Public) { $p['vnetConfiguration'] = [pscustomobject]@{ infrastructureSubnetId = $script:Snet; internal = [bool]$Internal } }
            [pscustomobject]@{ id = $script:EPath; name = 'cae-x'; location = 'westeurope'; properties = [pscustomobject]$p }
        }
        function script:Invoke-SIArm {
            param([string]$Method = 'GET', [string]$Path, [string]$ApiVersion, $Body, [switch]$AllowNotFound, [switch]$List)
            $m = $Method.ToUpperInvariant()
            $script:ArmCalls.Add([pscustomobject]@{ Method = $m; Path = $Path; Body = $Body; List = [bool]$List })
            if ($List) { if ($Path -like '*/Microsoft.App/jobs') { return $script:Jobs }; return @() }
            if ($m -eq 'DELETE') { return $null }
            if ($m -ne 'GET') { return $null }
            if ($script:EnvReads.Count -gt 1) { $next = $script:EnvReads[0]; $script:EnvReads.RemoveAt(0); return $next }
            if ($script:EnvReads.Count -eq 1) { return $script:EnvReads[0] }
            $null
        }
        . ([IO.Path]::Combine($script:SIRoot, 'setup', '_shared', 'SI-SetupArm.ps1'))
        function script:Reset-Env([object[]]$Reads, [object[]]$Jobs = @()) {
            $script:ArmCalls = New-Object System.Collections.Generic.List[object]
            $script:EnvReads = New-Object System.Collections.Generic.List[object]; foreach ($x in $Reads) { $script:EnvReads.Add($x) }
            $script:Jobs = $Jobs
        }
        function script:W([string]$M) { @($script:ArmCalls | Where-Object { $_.Method -eq $M }) }
        function script:Invoke-Env { Initialize-SIManagedEnvironment -ResourceGroupName 'rg-x' -Name 'cae-x' -Location 'westeurope' -InfrastructureSubnetId $script:Snet -Internal -Sleep { param($s) } 6>$null }
    }
    It 'internal in the subnet and still being made ("Waiting", the stopped install): WAITED for, never replaced' {
        Reset-Env @((New-Env 'Waiting' -Internal), (New-Env 'Succeeded' -Internal))
        (Invoke-Env).properties.provisioningState | Should -Be 'Succeeded'
        (W 'DELETE').Count | Should -Be 0
        (W 'PUT').Count | Should -Be 0
    }
    It 'FOUND public and EMPTY: removed, created internal in the subnet, read back, recorded' {
        Reset-Env @((New-Env 'Succeeded' -Public), $null, (New-Env 'Succeeded' -Internal))
        $said = (Initialize-SIManagedEnvironment -ResourceGroupName 'rg-x' -Name 'cae-x' -Location 'westeurope' -InfrastructureSubnetId $script:Snet -Internal -Sleep { param($s) } 6>&1 | Where-Object { $_ -is [System.Management.Automation.InformationRecord] } | ForEach-Object { [string]$_ }) -join "`n"
        (W 'DELETE').Count | Should -Be 1
        (W 'PUT').Count | Should -Be 1
        (W 'PUT')[0].Body.properties.vnetConfiguration.internal | Should -BeTrue
        (W 'PUT')[0].Body.properties.vnetConfiguration.infrastructureSubnetId | Should -Be $script:Snet
        $said | Should -Match 'ENVIRONMENT REPLACED: cae-x was public \(not in a virtual network\) and empty'
        $said | Should -Not -Match '\$\d|~\$|/mo\b|idle\)' -Because 'no cost figure in install output'
        $said | Should -Match 'internal, in your virtual network'
    }
    It 'FOUND half-made / Failed and public: counts as empty -- replaced' {
        Reset-Env @((New-Env 'Failed' -Public), $null, (New-Env 'Succeeded' -Internal))
        $null = Invoke-Env
        (W 'DELETE').Count | Should -Be 1
        (W 'PUT').Count | Should -Be 1
    }
    It 'FOUND public with a JOB in it: NOT removed -- it stops with the plan' {
        Reset-Env @((New-Env 'Succeeded' -Public)) -Jobs @([pscustomobject]@{ name = 'caj-si-flow'; properties = [pscustomobject]@{ environmentId = $script:EPath } })
        { Invoke-Env } | Should -Throw '*holds the job caj-si-flow, so it is NOT removed. The plan*'
        (W 'DELETE').Count | Should -Be 0
        (W 'PUT').Count | Should -Be 0
    }
    It 'a public install keeps its public environment as it is (no subnet asked)' {
        Reset-Env @((New-Env 'Succeeded' -Public))
        $null = Initialize-SIManagedEnvironment -ResourceGroupName 'rg-x' -Name 'cae-x' -Location 'westeurope' -Sleep { param($s) } 6>$null
        (W 'DELETE').Count | Should -Be 0
    }
}

Describe 'console text: the product and its released version, no cost figure' {
    It 'the bootstrap banner names the product and the build -- never v2.2' {
        $bs = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'Bootstrap-ContainerAppJob.ps1'))
        $bs | Should -Not -Match "Write-Host '=== SecurityInsight v2\.2"
        $bs | Should -Match "Write-Host \('=== SecurityInsight \{0\} -- container setup ===' -f \`$siBuild\.display\)"
        $bs.IndexOf('$siBuild = Get-SIBuildInfo') | Should -BeLessThan $bs.IndexOf('=== SecurityInsight {0}')
    }
    It 'no cost figure in the install''s console output (no framework wording names one)' {
        foreach ($f in 'Bootstrap-ContainerAppJob.ps1', 'setup\_shared\SI-SetupArm.ps1', 'setup\_shared\SI-GuidedInstall.ps1', 'setup\_shared\SI-PrivateNetwork.ps1') {
            foreach ($line in [IO.File]::ReadAllLines((Join-Path $script:SIRoot $f))) {
                if ($line -match 'Write-Host' -and $line -match '~\$\d|\$\d+(\.\d+)?/mo|idle\)') { throw ('{0} prints a cost figure: {1}' -f $f, $line.Trim()) }
            }
        }
    }
    It 'a RELEASED package shows its released version, never a release-candidate label' {
        . (Join-Path $script:SIRoot 'engine\_shared\SI-BuildInfo.ps1')
        Get-SIReleasedDisplay -Release '3.0.31' | Should -Be '3.0.31'
        Get-SIReleasedDisplay -Release '3.0.0.202610160500' | Should -Be '3.0.0.202610160500'
        Get-SIReleasedDisplay -Release '3.0.29-rc.9' | Should -Be ''
        $d = Join-Path ([IO.Path]::GetTempPath()) ('si-rel-' + [guid]::NewGuid().ToString('N').Substring(0, 8)); New-Item -ItemType Directory -Force -Path $d | Out-Null
        try {
            [IO.File]::WriteAllText((Join-Path $d 'VERSION'), "3.0.31`n")
            # what the customer's install showed: a package stamped as the release, its display an rc label
            [IO.File]::WriteAllText((Join-Path $d 'BUILD.json'), '{"version":"3.0.29","display":"3.0.29-rc.9","commit":"fb46aacbb8c1aaaaaaaaaaaaaaaaaaaaaaaaaaaa","shortCommit":"fb46aac","builtUtc":"2026-11-04T08:00:00Z","rc":9,"channel":null,"ring":null,"release":"3.0.31"}')
            $b = Read-SIBuildInfo -SolutionRoot $d
            $b.display | Should -Be '3.0.31'
            $b.rc | Should -BeNullOrEmpty
            Format-SIBuildLine $b | Should -Match '^3\.0\.31 \(build fb46aac'
            # a build that is NOT a release (no release stamp) keeps its rc label -- only releases are relabelled
            [IO.File]::WriteAllText((Join-Path $d 'BUILD.json'), '{"version":"3.0.31","display":"3.0.31-rc.2","commit":"","shortCommit":"","builtUtc":"","rc":2}')
            (Read-SIBuildInfo -SolutionRoot $d).display | Should -Be '3.0.31-rc.2'
        } finally { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\_shared\SI-BuildInfo.ps1'))
        $src | Should -Match '(?s)function New-SIBuildArchiveArgs.{0,2500}if \(\$rel\) \{ \$info\.version = \$rel; \$info\.display = \$rel; \$info\.rc = \$null \}'
    }
}

Describe 'the agent pool in the network: setup WAITS for Azure to make it (3.0.32)' {
    # LIVE, a private install on 3.0.31: the registry private, its endpoint, zone and DNS check read back fine -- then the
    # step FAILED with "the agent pool si-vnet-pool does not read back as ready (Azure shows: Creating)" while Azure was
    # still making it (a pool in a network takes several minutes). Now: a bounded, said wait on the pool alone.
    BeforeAll {
        # a scripted ARM: GET of the pool answers the next state of -States (the last one repeats); every call is recorded
        function script:New-PoolArm {
            param([string[]]$States, [string]$Reason = '', [switch]$Exists)
            $script:PoolCalls = New-Object System.Collections.Generic.List[string]
            $script:PoolStates = New-Object System.Collections.Generic.Queue[string]
            foreach ($s in $States) { $script:PoolStates.Enqueue($s) }
            $script:PoolLast = ''; $script:PoolPut = [bool]$Exists; $script:PoolReason = $Reason
            {
                param($m, $p, $b)
                $script:PoolCalls.Add(('{0} {1}' -f $m, ($p -replace '\?.*$', '')))
                if ($m -eq 'PUT') { $script:PoolPut = $true; return $null }
                if (-not $script:PoolPut) { return $null }
                if ($script:PoolStates.Count) { $script:PoolLast = $script:PoolStates.Dequeue() }
                $props = @{ provisioningState = $script:PoolLast; virtualNetworkSubnetResourceId = $script:PeSubnet }
                if ($script:PoolLast -eq 'Failed' -and $script:PoolReason) { $props['error'] = [pscustomobject]@{ message = $script:PoolReason } }
                [pscustomobject]@{ properties = [pscustomobject]$props }
            }
        }
        # a fake clock: every pause moves it on by the seconds asked for -- nothing waits
        function script:New-PoolClock { $script:PoolNow = [datetime]'2026-11-04T10:00:00Z'; $script:PoolSlept = 0 }
        $script:PoolSleep = { param($s) $script:PoolSlept += [int]$s; $script:PoolNow = $script:PoolNow.AddSeconds([int]$s) }
        $script:PoolNowSb = { $script:PoolNow }
        $script:PoolSay = { param($t) $script:PoolSaid.Add([string]$t) }
        function script:Invoke-Pool([scriptblock]$Arm) {
            $script:PoolSaid = New-Object System.Collections.Generic.List[string]
            Set-SIAcrAgentPool -Arm $Arm -RegistryId $script:RegId -Name 'si-vnet-pool' -Location 'westeurope' -SubnetId $script:PeSubnet -Sleep $script:PoolSleep -Now $script:PoolNowSb -Say $script:PoolSay
        }
    }

    It 'the limit is 30 min -- twice the 15 min of read-backs that failed live' {
        $script:SIAcrAgentPoolWaitMinutes | Should -Be 30
    }

    It 'Creating -> Creating -> Succeeded: it waits, says so with its limit, and continues as soon as Azure reads Succeeded' {
        New-PoolClock
        $r = Invoke-Pool (New-PoolArm -States @('Creating', 'Creating', 'Succeeded'))
        $r.Ok | Should -BeTrue
        $r.State | Should -Be 'Succeeded'
        $r.Created | Should -BeTrue
        $r.Line | Should -Match 'image builds run inside it \(read back'
        @($script:PoolCalls | Where-Object { $_ -like 'PUT *' }).Count | Should -Be 1
        @($script:PoolCalls | Where-Object { $_ -like 'GET *' }).Count | Should -Be 4 -Because 'the first look, then Creating, Creating, Succeeded -- no read after Succeeded'
        $script:PoolSaid[0] | Should -Be '  waiting for the build agent pool si-vnet-pool (Azure: Creating) -- up to 30 min; Azure takes several minutes to place it in the network'
        $script:PoolSlept | Should -Be 30 -Because 'two pauses of 15 s: it stops waiting on Succeeded'
    }

    It 'a long Creating: one progress line about every minute, with the minutes and the limit' {
        New-PoolClock
        $r = Invoke-Pool (New-PoolArm -States (@('Creating') * 25 + @('Succeeded')))
        $r.Ok | Should -BeTrue
        $prog = @($script:PoolSaid | Where-Object { $_ -like '  still waiting*' })
        $prog.Count | Should -BeIn 5, 6 -Because '~6 min of 15 s pauses = one line a minute, never one per read'
        $prog[0] | Should -Be '  still waiting for the build agent pool si-vnet-pool (Azure: Creating) -- 1 of up to 30 min'
    }

    It 'Failed: it stops at once, with Azure''s error text' {
        New-PoolClock
        $r = Invoke-Pool (New-PoolArm -States @('Creating', 'Failed') -Reason 'The subnet has no free address for the agent.')
        $r.Ok | Should -BeFalse
        $r.TimedOut | Should -BeFalse
        $r.State | Should -Be 'Failed'
        $r.Line | Should -Be 'Azure could not make the agent pool si-vnet-pool (Azure shows: Failed: The subnet has no free address for the agent.)'
        $script:PoolSlept | Should -Be 15
    }

    It 'Canceled without a reason on the pool: it stops, and says where the reason is' {
        New-PoolClock
        $r = Invoke-Pool (New-PoolArm -States @('Canceled'))
        $r.Ok | Should -BeFalse
        $r.Line | Should -Match '^Azure could not make the agent pool si-vnet-pool \(Azure shows: Canceled; .*Activity log'
    }

    It 'a pool Azure left Failed on an earlier run is asked for again (a re-run is not a dead end)' {
        New-PoolClock
        $r = Invoke-Pool (New-PoolArm -States @('Failed', 'Creating', 'Succeeded') -Exists)
        $r.Ok | Should -BeTrue
        @($script:PoolCalls | Where-Object { $_ -like 'PUT *' }).Count | Should -Be 1
    }

    It 'the limit passes while Azure still reads Creating: it stops, and the step says to run the install command again' {
        New-PoolClock
        $r = Invoke-Pool (New-PoolArm -States @('Creating'))
        $r.Ok | Should -BeFalse
        $r.TimedOut | Should -BeTrue
        $r.Line | Should -Be 'the agent pool si-vnet-pool does not read back as ready after 30 min of waiting (Azure shows: Creating) -- Azure is still making it'
        $script:PoolSlept | Should -BeGreaterOrEqual (30 * 60)
        $script:PoolSlept | Should -BeLessOrEqual (30 * 60 + 15)
        $gi = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'setup\_shared\SI-GuidedInstall.ps1'))
        $gi | Should -Match '(?s)-not \$r\.Value\.PoolOk\).{0,400}Run the install command again: it continues from this step'
    }

    It 'only the pool waits longer: the other read-backs keep their own bounds' {
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'setup\_shared\SI-PrivateNetwork.ps1'))
        $src | Should -Match '(?s)function Set-SIAcrAgentPool .{0,8000}Wait-SIAcrAgentPool -Arm'
        $src | Should -Not -Match 'Read-SIPnBack[^\r\n]*-Tries 60 -PauseSeconds 15'
        $src | Should -Match 'Read-SIPnBack -Arm \$Arm -Path \$path -Sleep \$Sleep -Tries 120 -PauseSeconds 15'
    }

    It 'the updater (step 1b) gets the same wait: it calls the same Set-SIAcrAgentPool (through the outbound check, #1087)' {
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'setup\_shared\SI-PrivateNetwork.ps1'))
        $src | Should -Match '(?s)function Invoke-SIUpdatePrivateRegistry .{0,20000}Invoke-SIAcrAgentPoolStep -Arm \$Arm'
        $src | Should -Match '(?s)function Invoke-SIAcrAgentPoolStep .{0,4000}Set-SIAcrAgentPool -Arm \$Arm'
    }
}
