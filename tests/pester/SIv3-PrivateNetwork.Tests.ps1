#Requires -Version 5.1
<#
    PRIVATE NETWORKING AS AN OPTION (#681): setup\_shared\SI-PrivateNetwork.ps1, its guided-install steps, and the cut-over
    of an existing install (setup\Set-SIPrivateNetworking.ps1) -- against a fake ARM store (tests\fixtures\SIArmStoreFake.ps1).
      * the subnet decisions, the private endpoints, the DNS zones, the public endpoints, each idempotent and READ BACK;
      * the environment body with and without a subnet (without: exactly as before);
      * moving jobs and apps: the definition, what refuses a move, the role assignments made again;
      * the cut-over: PLAN by default, the steps, the record, the rollback;
      * the guided install: the option's steps only when it is chosen (the default plan is unchanged), its answers checked.
    OFFLINE. PS 5.1 + pwsh 7.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'tests\fixtures\SIArmStoreFake.ps1')
    . (Join-Path $script:SIRoot 'setup\_shared\SI-PrivateNetwork.ps1')
    $script:Cut = Join-Path $script:SIRoot 'setup\Set-SIPrivateNetworking.ps1'
    $script:Sub = '11111111-1111-1111-1111-111111111111'
    $script:Rg = '/subscriptions/{0}/resourceGroups/rg-si-x' -f $script:Sub
    $script:Vnet = '/subscriptions/{0}/resourceGroups/rg-net/providers/Microsoft.Network/virtualNetworks/vnet-hub' -f $script:Sub
    # #866: the inside check before any close -- these tests run 'inside': every name resolves to a private address
    $script:Inside = { param([string]$Name) @('10.20.0.40') }
    $script:NoSleep = { param($s) }
    $script:Arm = { param($m, $p, $b) & $global:SIArmStoreFake $m $p $b }

    function script:New-World {
        param([switch]$WithSubnets, [switch]$PlainSecret)
        New-SIArmStore
        Set-SIArmStoreItem @{ id = $script:Vnet; location = 'westeurope'; properties = @{ provisioningState = 'Succeeded' } }
        if ($WithSubnets) {
            Set-SIArmStoreItem @{ id = "$script:Vnet/subnets/snet-si-apps"; properties = @{ addressPrefix = '10.20.0.0/27'; provisioningState = 'Succeeded' } }
            Set-SIArmStoreItem @{ id = "$script:Vnet/subnets/snet-si-endpoints"; properties = @{ addressPrefix = '10.20.0.32/28'; provisioningState = 'Succeeded' } }
        }
        $mi = "$script:Rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-si-engine"
        Set-SIArmStoreItem @{ id = $mi; properties = @{ clientId = 'cid-engine'; principalId = 'pid-engine' } }
        Set-SIArmStoreItem @{ id = "$script:Rg/providers/Microsoft.KeyVault/vaults/kv-si-x"; location = 'westeurope'; properties = @{ publicNetworkAccess = 'Enabled'; networkAcls = @{ defaultAction = 'Allow'; bypass = 'AzureServices' }; provisioningState = 'Succeeded' } }
        Set-SIArmStoreItem @{ id = "$script:Rg/providers/Microsoft.Storage/storageAccounts/stsix"; location = 'westeurope'; properties = @{ publicNetworkAccess = 'Enabled'; provisioningState = 'Succeeded' } }
        Set-SIArmStoreItem @{ id = "$script:Rg/providers/Microsoft.ContainerRegistry/registries/acrsix"; location = 'westeurope'; sku = @{ name = 'Standard' }; properties = @{ loginServer = 'acrsix.azurecr.io'; publicNetworkAccess = 'Enabled'; provisioningState = 'Succeeded' } }
        Set-SIArmStoreItem @{ id = "$script:Rg/providers/Microsoft.Sql/servers/sql-si-x"; location = 'swedencentral'; properties = @{ fullyQualifiedDomainName = 'sql-si-x.example.test'; publicNetworkAccess = 'Enabled'; provisioningState = 'Succeeded' } }
        $oldEnv = "$script:Rg/providers/Microsoft.App/managedEnvironments/cae-si-prod-pro-ca"
        Set-SIArmStoreItem @{ id = $oldEnv; location = 'westeurope'; properties = @{ defaultDomain = 'old.westeurope.azurecontainerapps.io'; provisioningState = 'Succeeded' } }
        Set-SIArmStoreItem @{ id = "$oldEnv/providers/Microsoft.Insights/diagnosticSettings/si-environment-logs"; properties = @{ workspaceId = '/x/log-si-x'; logs = @(@{ categoryGroup = 'allLogs'; enabled = $true }) } }
        $envVars = @(@{ name = 'SI_UAMI_ClientId'; value = 'cid-engine' }, @{ name = 'SI_ProSqlServer'; value = 'sql-si-x.example.test' }, @{ name = 'SI_ProSqlDatabase'; value = 'sqldb-si-pro' },
                     @{ name = 'SI_KeyVaultName'; value = 'kv-si-x' }, @{ name = 'SI_StorageAccount'; value = 'stsix' }, @{ name = 'SI_WorkspaceResourceId'; value = '/x/log-si-x' })
        $secrets = if ($PlainSecret) { @(@{ name = 'smtp-password' }) } else { @(@{ name = 'openai-key'; keyVaultUrl = 'https://kv-si-x.vault.azure.net/secrets/OpenAI-ApiKey'; identity = $mi }) }
        $ua = @{}; $ua[$mi] = @{ principalId = 'pid-engine'; clientId = 'cid-engine' }
        $job = "$script:Rg/providers/Microsoft.App/jobs/caj-si-flow"
        Set-SIArmStoreItem @{ id = $job; location = 'westeurope'; identity = @{ type = 'UserAssigned'; userAssignedIdentities = $ua }
            properties = @{ environmentId = $oldEnv; provisioningState = 'Succeeded'; configuration = @{ triggerType = 'Schedule'; scheduleTriggerConfig = @{ cronExpression = '30 21 * * *' }; secrets = $secrets; registries = @(@{ server = 'acrsix.azurecr.io'; identity = $mi }) }
                            template = @{ containers = @(@{ name = 'si'; image = 'acrsix.azurecr.io/si-orchestrator:3'; env = $envVars }) } } }
        Set-SIArmStoreItem @{ id = "$job/providers/Microsoft.Authorization/roleAssignments/ra-1"; properties = @{ scope = $job; roleDefinitionId = '/subscriptions/x/providers/Microsoft.Authorization/roleDefinitions/operator'; principalId = 'pid-web'; principalType = 'ServicePrincipal' } }
        $wua = @{}; $wua["$script:Rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-si-web"] = @{ principalId = 'pid-web'; clientId = 'cid-web' }
        Set-SIArmStoreItem @{ id = "$script:Rg/providers/Microsoft.App/containerApps/ca-si-web"; location = 'westeurope'; identity = @{ type = 'UserAssigned'; userAssignedIdentities = $wua }
            properties = @{ managedEnvironmentId = $oldEnv; environmentId = $oldEnv; provisioningState = 'Succeeded'; configuration = @{ ingress = @{ external = $true; targetPort = 8080; fqdn = 'ca-si-web.old.westeurope.azurecontainerapps.io' }; registries = @(@{ server = 'acrsix.azurecr.io'; identity = 'x' }) }
                            template = @{ containers = @(@{ name = 'web'; image = 'acrsix.azurecr.io/si-management:3'; env = @(@{ name = 'AzureAd__ClientId'; value = 'app-web' }) }) } } }
        $global:SIArmStore.Graph['obj-web'] = [ordered]@{ id = 'obj-web'; appId = 'app-web'; web = [ordered]@{ redirectUris = @('https://ca-si-web.old.westeurope.azurecontainerapps.io/signin-oidc'); logoutUrl = 'https://ca-si-web.old.westeurope.azurecontainerapps.io/signout-callback-oidc'; implicitGrantSettings = [ordered]@{ enableIdTokenIssuance = $true } } }
        $global:SIArmStore.Writes.Clear()
    }
    function script:Writes { @($global:SIArmStore.Writes) }
    function script:Run { param([hashtable]$More = @{}) $a = @{ ResourceGroup = 'rg-si-x'; SubscriptionId = $script:Sub; VnetId = $script:Vnet; Arm = $script:Arm; Sql = { param($a, $b, $c, $d, $e) , @() }; Graph = { param($m, $u, $b) & $global:SIArmStoreGraph $m $u $b }; Sleep = $script:NoSleep; RecordDirectory = (Join-Path $TestDrive 'rec'); Environment = 'pester'; ObserveMinutes = 0; Resolve = $script:Inside }; foreach ($k in $More.Keys) { $a[$k] = $More[$k] }; & $script:Cut @a 6> $null }
}

AfterAll { Remove-SIArmStore }

Describe 'names: what the option creates (framework 12.11c)' {
    It 'carries no ring, environment or edition in a name' {
        $n = Get-SIPrivateNetworkNames
        foreach ($v in @($n.Values)) { $v | Should -Not -Match '(?i)prod|community|\bpro\b|r0|r1|r2|-ca\b|ring' }
        @(Get-SIPrivateEndpointTargets -SqlServerId 'a' -KeyVaultId 'b' -StorageAccountId 'c' -RegistryId 'd' | ForEach-Object Name) | Should -Be @('pe-si-sql', 'pe-si-vault', 'pe-si-blob', 'pe-si-queue', 'pe-si-table', 'pe-si-registry')
    }
    It 'a Community install (no database server) gets no database endpoint' {
        @(Get-SIPrivateEndpointTargets -KeyVaultId 'b' -StorageAccountId 'c' -RegistryId 'd' | ForEach-Object Kind) | Should -Not -Contain 'sql'
    }
}

Describe 'subnets: decided, kept, never taken from someone else' {
    It 'a missing subnet needs an address range; the environment''s needs at least a /27' {
        (Get-SISubnetDecision -Subnet $null -Prefix '' -Name 's' -Delegate).Action | Should -Be 'fail'
        (Get-SISubnetDecision -Subnet $null -Prefix '10.0.0.0/28' -Name 's' -Delegate).Action | Should -Be 'fail'
        (Get-SISubnetDecision -Subnet $null -Prefix '10.0.0.0/27' -Name 's' -Delegate).Action | Should -Be 'create'
        (Get-SISubnetDecision -Subnet $null -Prefix '10.0.0.0/28' -Name 's').Action | Should -Be 'create'
    }
    It 'an empty subnet is delegated; one in use or delegated elsewhere is refused; a delegated one is left alone' {
        (Get-SISubnetDecision -Subnet ([pscustomobject]@{ properties = [pscustomobject]@{ addressPrefix = '10.0.0.0/27' } }) -Name 's' -Delegate).Action | Should -Be 'delegate'
        (Get-SISubnetDecision -Subnet ([pscustomobject]@{ properties = [pscustomobject]@{ addressPrefix = '10.0.0.0/27'; ipConfigurations = @([pscustomobject]@{ id = 'nic' }) } }) -Name 's' -Delegate).Action | Should -Be 'fail'
        (Get-SISubnetDecision -Subnet ([pscustomobject]@{ properties = [pscustomobject]@{ addressPrefix = '10.0.0.0/27'; delegations = @([pscustomobject]@{ properties = [pscustomobject]@{ serviceName = 'Microsoft.Web/serverFarms' } }) } }) -Name 's' -Delegate).Action | Should -Be 'fail'
        (Get-SISubnetDecision -Subnet ([pscustomobject]@{ properties = [pscustomobject]@{ addressPrefix = '10.0.0.0/27'; delegations = @([pscustomobject]@{ properties = [pscustomobject]@{ serviceName = 'Microsoft.App/environments' } }) } }) -Name 's' -Delegate).Action | Should -Be 'none'
    }
    It 'delegating keeps the subnet''s network security group and route table (a subnet PUT replaces the subnet)' {
        $s = [pscustomobject]@{ properties = [pscustomobject]@{ addressPrefix = '10.0.0.0/27'; networkSecurityGroup = [pscustomobject]@{ id = 'nsg-1' }; routeTable = [pscustomobject]@{ id = 'rt-1' }; provisioningState = 'Succeeded' } }
        $b = Get-SISubnetBody -Subnet $s -Delegate
        $b.properties.networkSecurityGroup.id | Should -Be 'nsg-1'
        $b.properties.routeTable.id | Should -Be 'rt-1'
        $b.properties.delegations[0].properties.serviceName | Should -Be 'Microsoft.App/environments'
        $b.properties.Contains('provisioningState') | Should -BeFalse
    }
    It 'creates both subnets, read back; a second run writes nothing' {
        New-World
        $r = Invoke-SIPrivateNetworkSubnets -Target ([ordered]@{ VnetId = $script:Vnet; AppsSubnetName = 'snet-si-apps'; AppsSubnetPrefix = '10.20.0.0/27'; EndpointsSubnetName = 'snet-si-endpoints'; EndpointsSubnetPrefix = '10.20.0.32/28' }) -Arm $script:Arm -Sleep $script:NoSleep
        $r.Ok | Should -BeTrue
        $r.AppsSubnetId | Should -Be "$script:Vnet/subnets/snet-si-apps"
        @((Get-SIArmStoreItem "$script:Vnet/subnets/snet-si-apps").properties.delegations)[0].properties.serviceName | Should -Be 'Microsoft.App/environments'
        $global:SIArmStore.Writes.Clear()
        $null = Invoke-SIPrivateNetworkSubnets -Target ([ordered]@{ VnetId = $script:Vnet; AppsSubnetName = 'snet-si-apps'; AppsSubnetPrefix = '10.20.0.0/27'; EndpointsSubnetName = 'snet-si-endpoints'; EndpointsSubnetPrefix = '10.20.0.32/28' }) -Arm $script:Arm -Sleep $script:NoSleep
        @(Writes) | Should -BeNullOrEmpty
    }
    It 'a subnet that cannot be used stops with the reason and changes nothing' {
        New-World
        { Invoke-SIPrivateNetworkSubnets -Target ([ordered]@{ VnetId = $script:Vnet; AppsSubnetName = 'snet-si-apps'; AppsSubnetPrefix = ''; EndpointsSubnetName = 'snet-si-endpoints'; EndpointsSubnetPrefix = '' }) -Arm $script:Arm -Sleep $script:NoSleep } | Should -Throw '*no address range*'
        @(Writes) | Should -BeNullOrEmpty
    }
}

Describe 'private endpoints, DNS and the public endpoints (setup''s call)' {
    BeforeEach {
        New-World -WithSubnets
        $script:EpArgs = @{ Target = (Get-SIInstallPrivateNetworkTarget -Values ([ordered]@{ vnetId = $script:Vnet }) -ResourceGroupId $script:Rg); Location = 'westeurope'; EndpointsSubnetId = "$script:Vnet/subnets/snet-si-endpoints"
                          SqlServerId = "$script:Rg/providers/Microsoft.Sql/servers/sql-si-x"; KeyVaultId = "$script:Rg/providers/Microsoft.KeyVault/vaults/kv-si-x"; StorageAccountId = "$script:Rg/providers/Microsoft.Storage/storageAccounts/stsix"
                          RegistryId = "$script:Rg/providers/Microsoft.ContainerRegistry/registries/acrsix"; Arm = $script:Arm; Sleep = $script:NoSleep; Resolve = $script:Inside }
    }
    It 'makes the registry Premium, six endpoints approved, their zones linked, and closes the public endpoints -- but not the registry''s' {
        $ea = $script:EpArgs; $r = Invoke-SIPrivateNetworkEndpoints @ea
        $r.Ok | Should -BeTrue
        (Get-SIArmStoreItem $script:EpArgs.RegistryId).sku.name | Should -Be 'Premium'
        foreach ($n in 'sql', 'vault', 'blob', 'queue', 'table', 'registry') {
            $pe = Get-SIArmStoreItem "$script:Rg/providers/Microsoft.Network/privateEndpoints/pe-si-$n"
            $pe | Should -Not -BeNullOrEmpty
            $pe.properties.subnet.id | Should -Be "$script:Vnet/subnets/snet-si-endpoints"
            (Get-SIArmStoreItem "$script:Rg/providers/Microsoft.Network/privateEndpoints/pe-si-$n/privateDnsZoneGroups/default") | Should -Not -BeNullOrEmpty
        }
        foreach ($z in 'privatelink.database.windows.net', 'privatelink.vaultcore.azure.net', 'privatelink.blob.core.windows.net', 'privatelink.queue.core.windows.net', 'privatelink.table.core.windows.net', 'privatelink.azurecr.io') {
            (Get-SIArmStoreItem "$script:Rg/providers/Microsoft.Network/privateDnsZones/$z/virtualNetworkLinks/vnet-hub").properties.virtualNetwork.id | Should -Be $script:Vnet
        }
        (Get-SIArmStoreItem $script:EpArgs.SqlServerId).properties.publicNetworkAccess | Should -Be 'Disabled'
        (Get-SIArmStoreItem $script:EpArgs.StorageAccountId).properties.publicNetworkAccess | Should -Be 'Disabled'
        $kv = Get-SIArmStoreItem $script:EpArgs.KeyVaultId
        $kv.properties.networkAcls.defaultAction | Should -Be 'Deny'
        $kv.properties.networkAcls.bypass | Should -Be 'AzureServices' -Because 'a customer-managed key is reached as a trusted Microsoft service'
        $kv.properties.publicNetworkAccess | Should -Be 'Disabled' -Because '#866 (owner: no firewall option, no exceptions): the end state is public access disabled'
        (Get-SIArmStoreItem $script:EpArgs.RegistryId).properties.publicNetworkAccess | Should -Be 'Enabled' -Because 'the registry is closed only on its own step'
    }
    It 'is idempotent: a second run writes nothing' {
        $ea = $script:EpArgs; $null = Invoke-SIPrivateNetworkEndpoints @ea
        $global:SIArmStore.Writes.Clear()
        (Invoke-SIPrivateNetworkEndpoints @ea).Ok | Should -BeTrue
        @(Writes) | Should -BeNullOrEmpty
    }
    It 'closes NO public endpoint when a private endpoint does not read back approved' {
        $global:SIArmStore.PendingEndpoints = $true
        $ea = $script:EpArgs; $r = Invoke-SIPrivateNetworkEndpoints @ea
        $r.Ok | Should -BeFalse
        (Get-SIArmStoreItem $script:EpArgs.SqlServerId).properties.publicNetworkAccess | Should -Be 'Enabled'
        (Get-SIArmStoreItem $script:EpArgs.StorageAccountId).properties.publicNetworkAccess | Should -Be 'Enabled'
        ($r.Lines -join ' ') | Should -Match 'NOT closed'
    }
    It 'never replaces an endpoint of the same name that points elsewhere' {
        Set-SIArmStoreItem @{ id = "$script:Rg/providers/Microsoft.Network/privateEndpoints/pe-si-sql"; properties = @{ provisioningState = 'Succeeded'; subnet = @{ id = 'other' }; privateLinkServiceConnections = @(@{ properties = @{ privateLinkServiceId = 'other'; groupIds = @('sqlServer') } }) } }
        $global:SIArmStore.Writes.Clear()
        $ea = $script:EpArgs; $r = Invoke-SIPrivateNetworkEndpoints @ea
        @(Writes) | Should -Not -Contain "PUT $script:Rg/providers/Microsoft.Network/privateEndpoints/pe-si-sql"
        ($r.Lines -join ' ') | Should -Match 'pe-si-sql exists but connects to something else'
    }
    It 'uses the customer''s central DNS zones when their resource group is given -- and NEVER makes one there (#866)' {
        $hub = '/subscriptions/{0}/resourceGroups/rg-dns' -f $script:Sub
        foreach ($z in 'privatelink.database.windows.net', 'privatelink.vaultcore.azure.net', 'privatelink.blob.core.windows.net', 'privatelink.queue.core.windows.net', 'privatelink.table.core.windows.net') {
            Set-SIArmStoreItem @{ id = "$hub/providers/Microsoft.Network/privateDnsZones/$z"; location = 'global'; properties = @{ provisioningState = 'Succeeded' } }
        }
        $global:SIArmStore.Writes.Clear()
        $script:EpArgs.Target = Get-SIInstallPrivateNetworkTarget -Values ([ordered]@{ vnetId = $script:Vnet; privateDnsZonesResourceGroupId = $hub }) -ResourceGroupId $script:Rg
        $ea = $script:EpArgs; $r = Invoke-SIPrivateNetworkEndpoints @ea
        (Get-SIArmStoreItem "$script:Rg/providers/Microsoft.Network/privateEndpoints/pe-si-vault/privateDnsZoneGroups/default").properties.privateDnsZoneConfigs[0].properties.privateDnsZoneId | Should -Be "$hub/providers/Microsoft.Network/privateDnsZones/privatelink.vaultcore.azure.net"
        Get-SIArmStoreItem "$script:Rg/providers/Microsoft.Network/privateDnsZones/privatelink.vaultcore.azure.net" | Should -BeNullOrEmpty
        # the registry's zone is not in the central resource group: it is NOT made there -- a hand-off line, nothing closed
        @(Writes | Where-Object { $_ -like "PUT $hub/providers/Microsoft.Network/privateDnsZones/privatelink.azurecr.io*" }) | Should -BeNullOrEmpty
        Get-SIArmStoreItem "$hub/providers/Microsoft.Network/privateDnsZones/privatelink.azurecr.io" | Should -BeNullOrEmpty
        ($r.HandOff -join ' ') | Should -Match 'privatelink\.azurecr\.io is NOT in your central resource group rg-dns -- SecurityInsight never makes a zone there'
        $r.Closed | Should -BeFalse
    }
}

Describe 'the Container Apps environment' {
    It 'without a subnet the body is exactly as before (no virtual network)' {
        . (Join-Path $script:SIRoot 'setup\_shared\SI-SetupArm.ps1')
        $b = Get-SIManagedEnvironmentBody -Location 'westeurope'
        $b.properties.Contains('vnetConfiguration') | Should -BeFalse
        ($b | ConvertTo-Json -Depth 10 -Compress) | Should -Be '{"location":"westeurope","properties":{"appLogsConfiguration":{"destination":"azure-monitor"},"workloadProfiles":[{"name":"Consumption","workloadProfileType":"Consumption"}]}}'
        $p = Get-SIManagedEnvironmentBody -Location 'westeurope' -InfrastructureSubnetId 'sub-1' -Internal
        $p.properties.vnetConfiguration.infrastructureSubnetId | Should -Be 'sub-1'
        $p.properties.vnetConfiguration.internal | Should -BeTrue
    }
    It 'Bootstrap and the guided install pass the subnet on, only for private networking (static)' {
        $boot = Get-Content -Raw (Join-Path $script:SIRoot 'Bootstrap-ContainerAppJob.ps1')
        $boot | Should -Match 'Initialize-SIManagedEnvironment [^\r\n]*-InfrastructureSubnetId \$InfrastructureSubnetId -Internal:\$EnvironmentInternal'
        $gi = Get-Content -Raw (Join-Path $script:SIRoot 'setup\_shared\SI-GuidedInstall.ps1')
        $gi | Should -Match "if \(\[bool\]\`$v\['privateNetwork'\] -and \[string\]\`$Ctx\.Facts\['appsSubnetId'\]\) \{ \`$a\.InfrastructureSubnetId"
    }
    It 'the private environment is created internal in the subnet, its logs where the old one''s go, and its DNS zone' {
        New-World -WithSubnets
        $x = Set-SIPrivateEnvironment -Arm $script:Arm -ResourceGroupId $script:Rg -Name 'cae-si-private' -Location 'westeurope' -SubnetId "$script:Vnet/subnets/snet-si-apps" -LogsLikeId "$script:Rg/providers/Microsoft.App/managedEnvironments/cae-si-prod-pro-ca" -Sleep $script:NoSleep
        $x.Ok | Should -BeTrue
        (Get-SIArmStoreItem "$script:Rg/providers/Microsoft.App/managedEnvironments/cae-si-private").properties.vnetConfiguration.internal | Should -BeTrue
        Get-SIArmStoreItem "$script:Rg/providers/Microsoft.App/managedEnvironments/cae-si-private/providers/Microsoft.Insights/diagnosticSettings/si-environment-logs" | Should -Not -BeNullOrEmpty
        $d = Set-SIEnvironmentDns -Arm $script:Arm -ZoneResourceGroupId $script:Rg -Environment $x.Environment -VnetId $script:Vnet -Sleep $script:NoSleep
        $d.Ok | Should -BeTrue
        (Get-SIArmStoreItem "$script:Rg/providers/Microsoft.Network/privateDnsZones/cae-si-private.westeurope.azurecontainerapps.io/A/*").properties.aRecords[0].ipv4Address | Should -Be '10.20.0.10'
    }
}

Describe 'moving a job or an app to another environment' {
    It 'the definition keeps identities, configuration and template; drops what Azure fills in; sets the new environment' {
        New-World
        $job = & $script:Arm 'GET' "$script:Rg/providers/Microsoft.App/jobs/caj-si-flow?api-version=x" $null
        $b = Get-SIContainerMoveBody -Resource $job -EnvironmentId 'env-new' -Kind job
        $b.properties.environmentId | Should -Be 'env-new'
        $b.properties.configuration.scheduleTriggerConfig.cronExpression | Should -Be '30 21 * * *'
        $b.properties.template.containers[0].image | Should -Be 'acrsix.azurecr.io/si-orchestrator:3'
        $b.properties.Contains('provisioningState') | Should -BeFalse
        @($b.identity.userAssignedIdentities.Keys).Count | Should -Be 1
        $app = & $script:Arm 'GET' "$script:Rg/providers/Microsoft.App/containerApps/ca-si-web?api-version=x" $null
        $a = Get-SIContainerMoveBody -Resource $app -EnvironmentId 'env-new' -Kind app -External $true
        $a.properties.managedEnvironmentId | Should -Be 'env-new'
        $a.properties.configuration.ingress.Contains('fqdn') | Should -BeFalse
        $a.properties.configuration.ingress.external | Should -BeTrue
    }
    It 'refuses (nothing removed) a plain secret, a password pull or a run that is going' {
        Get-SIContainerMoveProblem -Resource ([pscustomobject]@{ name = 'j'; properties = [pscustomobject]@{ configuration = [pscustomobject]@{ secrets = @([pscustomobject]@{ name = 'pw' }) } } }) | Should -Match 'not Key Vault references'
        Get-SIContainerMoveProblem -Resource ([pscustomobject]@{ name = 'j'; properties = [pscustomobject]@{ configuration = [pscustomobject]@{ registries = @([pscustomobject]@{ server = 'x'; passwordSecretRef = 'p' }) } } }) | Should -Match 'password'
        Get-SIContainerMoveProblem -Resource ([pscustomobject]@{ name = 'j'; properties = [pscustomobject]@{ configuration = [pscustomobject]@{} } }) -Executions @([pscustomobject]@{ name = 'e1'; properties = [pscustomobject]@{ status = 'Running' } }) | Should -Match 'running now'
        Get-SIContainerMoveProblem -Resource ([pscustomobject]@{ name = 'j'; properties = [pscustomobject]@{ configuration = [pscustomobject]@{ secrets = @([pscustomobject]@{ name = 'k'; keyVaultUrl = 'https://v/secrets/k' }) } } }) | Should -BeNullOrEmpty
        New-World -PlainSecret
        $job = & $script:Arm 'GET' "$script:Rg/providers/Microsoft.App/jobs/caj-si-flow?api-version=x" $null
        $x = Move-SIContainerResource -Arm $script:Arm -Resource $job -EnvironmentId 'env-new' -Kind job -Sleep $script:NoSleep
        $x.Ok | Should -BeFalse
        @(Writes) | Should -BeNullOrEmpty
    }
    It 'removes and creates it again in the new environment, read back, and makes its role assignments again' {
        New-World -WithSubnets
        $null = Set-SIPrivateEnvironment -Arm $script:Arm -ResourceGroupId $script:Rg -Name 'cae-si-private' -Location 'westeurope' -SubnetId "$script:Vnet/subnets/snet-si-apps" -Sleep $script:NoSleep
        $env = "$script:Rg/providers/Microsoft.App/managedEnvironments/cae-si-private"
        $job = & $script:Arm 'GET' "$script:Rg/providers/Microsoft.App/jobs/caj-si-flow?api-version=x" $null
        $x = Move-SIContainerResource -Arm $script:Arm -Resource $job -EnvironmentId $env -Kind job -Sleep $script:NoSleep
        $x.Ok | Should -BeTrue
        (Get-SIArmStoreItem "$script:Rg/providers/Microsoft.App/jobs/caj-si-flow").properties.environmentId | Should -Be $env
        $w = @(Writes)
        [array]::IndexOf($w, "DELETE $script:Rg/providers/Microsoft.App/jobs/caj-si-flow") | Should -BeLessThan ([array]::IndexOf($w, "PUT $script:Rg/providers/Microsoft.App/jobs/caj-si-flow"))
        @($x.Roles).Count | Should -Be 1
        (Get-SIArmStoreItem $x.Roles[0]).properties.principalId | Should -Be 'pid-web'
    }
}

Describe 'setup\Set-SIPrivateNetworking.ps1 -- the cut-over of an existing install' {
    It 'PLAN by default: the shape and every step, nothing written' {
        New-World
        $r = Run
        $r.Mode | Should -Be 'plan'
        @(Writes) | Should -BeNullOrEmpty
        foreach ($k in 'subnets', 'registry-premium', 'private-endpoints', 'private-dns', 'private-environment', 'move-jobs', 'move-apps', 'sql-identity', 'support-sql', 'public-access-off', 'registry-agent-pool', 'registry-public-off') { $r.Plan.Contains($k) | Should -BeTrue }
        $r.Plan['move-jobs'].Action | Should -Be 'change'
        $r.Plan['registry-premium'].Action | Should -Be 'change'
    }
    It '-Apply without -Steps and an unknown step are refused, nothing written' {
        New-World
        { Run @{ Apply = $true } } | Should -Throw '*-Apply needs -Steps*'
        { Run @{ Apply = $true; Steps = @('everything') } } | Should -Throw '*Unknown step*'
        @(Writes) | Should -BeNullOrEmpty
    }
    It 'without -VnetId the network steps are skipped, never guessed' {
        New-World
        $r = Run @{ VnetId = '' }
        $r.Plan['subnets'].Action | Should -Be 'skip'
        $r.Plan['subnets'].Reason | Should -Match '-VnetId'
    }
    It 'the whole move: jobs and web app in cae-si-private, the sign-in address added, public endpoints closed, one record; the rollback puts it back' {
        New-World
        $more = @{ Apply = $true; AppsSubnetPrefix = '10.20.0.0/27'; EndpointsSubnetPrefix = '10.20.0.32/28'; WithoutSupportSqlAccess = $true
                   Steps = @('subnets', 'registry-premium', 'private-endpoints', 'private-dns', 'private-environment', 'move-jobs', 'move-apps', 'public-access-off') }
        $r = Run $more
        @($r.Results | Where-Object { -not $_.Ok } | ForEach-Object { $_.Step + ': ' + ($_.Lines -join '; ') }) | Should -BeNullOrEmpty
        $priv = "$script:Rg/providers/Microsoft.App/managedEnvironments/cae-si-private"
        (Get-SIArmStoreItem "$script:Rg/providers/Microsoft.App/jobs/caj-si-flow").properties.environmentId | Should -Be $priv
        $web = Get-SIArmStoreItem "$script:Rg/providers/Microsoft.App/containerApps/ca-si-web"
        $web.properties.managedEnvironmentId | Should -Be $priv
        $web.properties.configuration.ingress.external | Should -BeTrue -Because 'in an internal environment that means: from the virtual network'
        @($global:SIArmStore.Graph['obj-web'].web.redirectUris) | Should -Contain 'https://ca-si-web.cae-si-private.westeurope.azurecontainerapps.io/signin-oidc'
        @($global:SIArmStore.Graph['obj-web'].web.redirectUris) | Should -Contain 'https://ca-si-web.old.westeurope.azurecontainerapps.io/signin-oidc' -Because 'add before remove'
        (Get-SIArmStoreItem "$script:Rg/providers/Microsoft.Sql/servers/sql-si-x").properties.publicNetworkAccess | Should -Be 'Disabled'
        Get-SIArmStoreItem "$script:Rg/providers/Microsoft.App/managedEnvironments/cae-si-prod-pro-ca" | Should -Not -BeNullOrEmpty -Because 'the old environment is never removed'
        $r.RecordPath | Should -Not -BeNullOrEmpty
        $rec = [IO.File]::ReadAllText($r.RecordPath) | ConvertFrom-Json
        @($rec.applied) | Should -Be @('subnets', 'registry-premium', 'private-endpoints', 'private-dns', 'private-environment', 'move-jobs', 'move-apps', 'public-access-off')
        @($rec.before.'move-jobs'.moved)[0].environmentId | Should -Be "$script:Rg/providers/Microsoft.App/managedEnvironments/cae-si-prod-pro-ca"
        ($rec | ConvertTo-Json -Depth 40) | Should -Not -Match 'secretValue|"value":\s*"[^"]*password'

        # owner 2026-10-19 "when we say it is private, it stays that way": without the customer's own -ReopenPublicAccess the
        # rollback of a record that closed public endpoints is REFUSED -- nothing at all is changed
        $global:SIArmStore.Writes.Clear()
        $refused = Run @{ Rollback = $r.RecordPath; Apply = $true }
        $refused.Mode | Should -Be 'rollback-refused'
        @(Writes) | Should -BeNullOrEmpty
        (Get-SIArmStoreItem "$script:Rg/providers/Microsoft.Sql/servers/sql-si-x").properties.publicNetworkAccess | Should -Be 'Disabled'
        (Get-SIArmStoreItem "$script:Rg/providers/Microsoft.App/jobs/caj-si-flow").properties.environmentId | Should -Be $priv

        $null = Run @{ Rollback = $r.RecordPath; Apply = $true; ReopenPublicAccess = $true }
        (Get-SIArmStoreItem "$script:Rg/providers/Microsoft.App/jobs/caj-si-flow").properties.environmentId | Should -Be "$script:Rg/providers/Microsoft.App/managedEnvironments/cae-si-prod-pro-ca"
        (Get-SIArmStoreItem "$script:Rg/providers/Microsoft.App/containerApps/ca-si-web").properties.managedEnvironmentId | Should -Be "$script:Rg/providers/Microsoft.App/managedEnvironments/cae-si-prod-pro-ca"
        (Get-SIArmStoreItem "$script:Rg/providers/Microsoft.Sql/servers/sql-si-x").properties.publicNetworkAccess | Should -Be 'Enabled'
        Get-SIArmStoreItem "$script:Rg/providers/Microsoft.Network/privateEndpoints/pe-si-sql" | Should -BeNullOrEmpty
        Get-SIArmStoreItem $priv | Should -BeNullOrEmpty
        Get-SIArmStoreItem "$script:Vnet/subnets/snet-si-apps" | Should -BeNullOrEmpty
        (Get-SIArmStoreItem "$script:Rg/providers/Microsoft.ContainerRegistry/registries/acrsix").sku.name | Should -Be 'Standard'
    }
    It 'public-access-off before the endpoints are there closes nothing' {
        New-World
        $r = Run @{ Apply = $true; Steps = @('public-access-off') }
        @($r.Results)[0].Ok | Should -BeFalse
        (Get-SIArmStoreItem "$script:Rg/providers/Microsoft.Sql/servers/sql-si-x").properties.publicNetworkAccess | Should -Be 'Enabled'
    }
    It 'move-jobs before the private environment is there moves nothing' {
        New-World
        $r = Run @{ Apply = $true; Steps = @('move-jobs') }
        @($r.Results)[0].Lines -join ' ' | Should -Match 'not ready'
        @(Writes | Where-Object { $_ -like 'DELETE*' }) | Should -BeNullOrEmpty
    }
    It 'refuses without a Support session' {
        { & $script:Cut -ResourceGroup 'rg-si-x' -SubscriptionId $script:Sub 6> $null } | Should -Throw '*Refused*Support session*'
    }
}

Describe 'the guided install: an option, off by default' {
    BeforeAll {
        . (Join-Path $script:SIRoot 'setup\_shared\SI-GuidedInstall.ps1')
        $proLib = Join-Path $script:SIRoot 'setup\_shared\SI-GuidedInstallPro.ps1'; if (Test-Path $proLib) { . $proLib }
        $script:Spec = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'setup\install-parameters.json')) | ConvertFrom-Json
    }
    It 'the default plan has none of the option''s steps' {
        @(Get-SIInstallStepPlan -Edition 'pro' | ForEach-Object Id) | Should -Not -Contain 'private-network'
        @(Get-SIInstallStepPlan -Edition 'pro' | ForEach-Object Id) | Should -Not -Contain 'private-network-subnets'
        @(Get-SIInstallChosenOptions -Values ([ordered]@{ privateNetwork = $false })).Count | Should -Be 0
    }
    It 'chosen: the subnets right after the resource group, the storage''s and vault''s endpoints + DNS check before the vault is written, the rest after mail and before the first run (#866)' {
        $ids = @(Get-SIInstallStepPlan -Edition 'pro' -Options (Get-SIInstallChosenOptions -Values ([ordered]@{ privateNetwork = $true })) | ForEach-Object Id)
        [array]::IndexOf($ids, 'private-network-subnets') | Should -Be ([array]::IndexOf($ids, 'resource-group') + 1)
        [array]::IndexOf($ids, 'private-network-subnets') | Should -BeLessThan ([array]::IndexOf($ids, 'workspace'))
        [array]::IndexOf($ids, 'private-network-data') | Should -Be ([array]::IndexOf($ids, 'storage') + 1)
        [array]::IndexOf($ids, 'private-network-data') | Should -BeLessThan ([array]::IndexOf($ids, 'key-vault'))
        [array]::IndexOf($ids, 'private-network') | Should -BeGreaterThan ([array]::IndexOf($ids, 'mail'))
        [array]::IndexOf($ids, 'private-network') | Should -BeLessThan ([array]::IndexOf($ids, 'first-run'))
        $ids | Should -Not -Contain 'customer-managed-keys'
    }
    It 'the answers: off by default; on needs the virtual network; a bad range is refused' {
        $base = @{ installId = 'i1'; tenantId = '22222222-2222-2222-2222-222222222222'; subscriptionId = $script:Sub; mailMode = 'none' }
        $c = Test-SIInstallConfig -Config ([pscustomobject]$base) -Spec $script:Spec -Edition 'pro'
        $c.Ok | Should -BeTrue
        [bool]$c.Values['privateNetwork'] | Should -BeFalse
        $c.Values.Contains('vnetId') | Should -BeFalse
        $on = $base.Clone(); $on.privateNetwork = $true
        $c2 = Test-SIInstallConfig -Config ([pscustomobject]$on) -Spec $script:Spec -Edition 'pro'
        $c2.Errors -join ' ' | Should -Match 'vnetId: required'
        $on.vnetId = $script:Vnet; $on.appsSubnetPrefix = '10.20.0.0'
        $c3 = Test-SIInstallConfig -Config ([pscustomobject]$on) -Spec $script:Spec -Edition 'pro'
        $c3.Errors -join ' ' | Should -Match 'appsSubnetPrefix'
        $on.appsSubnetPrefix = '10.20.0.0/27'
        (Test-SIInstallConfig -Config ([pscustomobject]$on) -Spec $script:Spec -Edition 'pro').Ok | Should -BeTrue
    }
    It 'the subnets step records the subnets for the container setup; the web app is reachable from the network (static)' {
        $ctx = @{ Values = [ordered]@{ subscriptionId = $script:Sub; vnetId = $script:Vnet; privateNetwork = $true }; Names = @{ ResourceGroup = 'rg-si-x' }; Facts = [ordered]@{}; Cache = [ordered]@{}; ResumeCommand = 'resume'
                  Seams = @{ Az = { param($Command, $Arguments) [pscustomobject]@{ Ok = $true; Lines = @('a', 'b'); AppsSubnetId = 'apps-id'; EndpointsSubnetId = 'pe-id'; Location = 'westeurope' } } } }
        $r = & (Get-SIInstallStepTable)['private-network-subnets'] $ctx
        $r.State | Should -Be 'ok'
        $ctx.Facts['appsSubnetId'] | Should -Be 'apps-id'
        $proFile = Join-Path $script:SIRoot 'setup\_shared\SI-GuidedInstallData.ps1'
        if (-not (Test-Path $proFile)) { return }   # the database and web app steps (both editions since 2026-10-18)
        $pro = Get-Content -Raw $proFile
        $pro | Should -Match "Ingress = \`$\(if \(\[bool\]\`$v\['privateNetwork'\]\) \{ 'External' \}"
    }
}

Describe 'NEVER RE-OPENED: when we say it is private, it stays that way (owner 2026-10-19)' {
    It 'putting an open endpoint back is refused without -AllowReopen -- nothing is sent' {
        New-World
        $sql = "$script:Rg/providers/Microsoft.Sql/servers/sql-si-x"
        $null = Set-SIPublicAccess -Arm $script:Arm -ResourceId $sql -Sleep $script:NoSleep
        (Get-SIArmStoreItem $sql).properties.publicNetworkAccess | Should -Be 'Disabled'
        $global:SIArmStore.Writes.Clear()
        $x = Set-SIPublicAccess -Arm $script:Arm -ResourceId $sql -Before ([ordered]@{ publicNetworkAccess = 'Enabled' }) -Sleep $script:NoSleep
        $x.Ok | Should -BeFalse
        $x.Action | Should -Be 'refused'
        $x.Line | Should -Match 'STAYS CLOSED'
        @(Writes) | Should -BeNullOrEmpty
        (Get-SIArmStoreItem $sql).properties.publicNetworkAccess | Should -Be 'Disabled'
        (Set-SIPublicAccess -Arm $script:Arm -ResourceId $sql -Before ([ordered]@{ publicNetworkAccess = 'Enabled' }) -AllowReopen -Sleep $script:NoSleep).Action | Should -Be 'restore'
        (Get-SIArmStoreItem $sql).properties.publicNetworkAccess | Should -Be 'Enabled'
    }
    It 'what counts as opening: Enabled or not set; a vault firewall that allows by default' {
        Test-SIPublicAccessReopen -Kind sql -Before ([ordered]@{ publicNetworkAccess = 'Enabled' }) | Should -BeTrue
        Test-SIPublicAccessReopen -Kind storage -Before ([ordered]@{ publicNetworkAccess = '' }) | Should -BeTrue -Because 'Azure''s default is Enabled'
        Test-SIPublicAccessReopen -Kind sql -Before ([ordered]@{ publicNetworkAccess = 'Disabled' }) | Should -BeFalse
        Test-SIPublicAccessReopen -Kind vault -Before ([ordered]@{ publicNetworkAccess = 'Enabled'; networkAcls = [ordered]@{ defaultAction = 'Allow' } }) | Should -BeTrue
        Test-SIPublicAccessReopen -Kind vault -Before ([ordered]@{ publicNetworkAccess = 'Enabled'; networkAcls = [ordered]@{ defaultAction = 'Deny' } }) | Should -BeTrue -Because '#866: a vault is closed only with its public access disabled'
        Test-SIPublicAccessReopen -Kind registry -Before ([ordered]@{ publicNetworkAccess = 'Enabled' }) | Should -BeTrue
    }
    It 'static: only the cut-over''s rollback passes -AllowReopen, and only on the customer''s -ReopenPublicAccess' {
        $hits = @(Get-ChildItem -Path $script:SIRoot -Recurse -File -Include *.ps1 | Where-Object { $_.FullName -notmatch '\\tests\\' } |
                  Select-String -Pattern '-AllowReopen\b' | ForEach-Object { '{0}: {1}' -f $_.Path.Substring($script:SIRoot.Length + 1), $_.Line.Trim() })
        @($hits | Where-Object { $_ -notmatch '^setup\\Set-SIPrivateNetworking\.ps1: .*-AllowReopen:\$ReopenPublicAccess' -and $_ -notmatch '^setup\\_shared\\SI-PrivateNetwork\.ps1: ' }) | Should -BeNullOrEmpty
        @($hits | Where-Object { $_ -match '^setup\\Set-SIPrivateNetworking\.ps1' }).Count | Should -Be 1
    }
    It 'static: no SecurityInsight code writes an open public endpoint except the create-only bodies it is known for' {
        # an install resource (database server, storage, Key Vault, registry) is never PUT/PATCHed open: the only literal
        # "Enabled" bodies are the database server's CREATE (sent only when Azure says it is not there, twice) and data
        # collection endpoints / a customer's own OpenAI resource (not part of the private set)
        $allowed = @('setup\_shared\SI-SetupArm.ps1', 'setup\ConfigWizard\backend\Initialize-SIInfra.ps1', 'engine\_shared\SI-AzRest.ps1', 'setup\Validate-SIOpenAI.ps1')
        $hits = @(Get-ChildItem -Path $script:SIRoot -Recurse -File -Include *.ps1, *.psm1, *.bicep | Where-Object { $_.FullName -notmatch '\\tests\\' } |
                  Select-String -Pattern "(?i)publicNetworkAccess\s*=\s*['""]Enabled['""]|defaultAction\s*=\s*['""]Allow['""]|networkRuleBypassOptions\s*=\s*['""]None['""]" |
                  ForEach-Object { $_.Path.Substring($script:SIRoot.Length + 1) } | Sort-Object -Unique)
        @($hits | Where-Object { $allowed -notcontains $_ }) | Should -BeNullOrEmpty
        $arm = Get-Content -Raw (Join-Path $script:SIRoot 'setup\_shared\SI-SetupArm.ps1')
        $arm | Should -Match '(?s)\$absent = Test-SIArmResourceAbsent[^\r\n]*\r?\n\s*if \(\$absent\) \{\r?\n\s*\$null = Invoke-SIArm -Method PUT[^\r\n]*Get-SISqlServerEntraOnlyBody' -Because 'the open-at-create body is sent only to a server that is not there'
    }
}

Describe 'PIM''s support path: the in-network SQL identity, the Support app''s access before the close, builds inside the network' {
    BeforeEach {
        New-World
        $srv = "$script:Rg/providers/Microsoft.Sql/servers/sql-si-x"
        $s = Get-SIArmStoreItem $srv; $s['properties']['administrators'] = [ordered]@{ principalType = 'Group'; sid = 'gid-admins'; login = 'grp-si-sql-admins' }
        Set-SIArmStoreItem @{ id = "$srv/databases/sqldb-si-pro"; properties = @{ provisioningState = 'Succeeded' } }
        Set-SIArmStoreItem @{ id = "$srv/databases/master"; properties = @{ provisioningState = 'Succeeded' } }
        $global:SIArmStore.ServicePrincipals['0a0a0a0a-1111-2222-3333-444455556666'] = 'sp-support'
        $global:SIArmStore.Members['gid-admins'] = @()
        $global:SIPnTestUsers = @{}
        $script:SqlFake = { param($srv, $db, $q, $why, $ro)
            if ($q -match 'CREATE USER') { if ($ro) { throw 'a read-only call sent a statement' }; $global:SIPnTestUsers[$db] = $true }
            , @([pscustomobject]@{ Value = $(if ($global:SIPnTestUsers[$db]) { 'invardia-support-app|1' } else { '' }) }) }
        $global:SIArmStore.Writes.Clear()
        $script:Full = @{ Apply = $true; AppsSubnetPrefix = '10.20.0.0/27'; EndpointsSubnetPrefix = '10.20.0.32/28'; SupportAppId = '0a0a0a0a-1111-2222-3333-444455556666'; Sql = $script:SqlFake }
    }
    AfterAll { Remove-Variable -Scope Global -Name SIPnTestUsers -ErrorAction SilentlyContinue }
    It 'the plan names the new steps and reads only' {
        $r = Run @{ SupportAppId = '0a0a0a0a-1111-2222-3333-444455556666'; Sql = $script:SqlFake }
        $r.Plan['sql-identity'].Action | Should -Be 'change'
        $r.Plan['support-sql'].Action | Should -Be 'change'
        $r.Plan['registry-agent-pool'].Action | Should -Be 'change'
        $r.Plan['registry-public-off'].Reason | Should -Match 'NOT YET'
        @(Writes) | Should -BeNullOrEmpty
        $global:SIPnTestUsers.Count | Should -Be 0
    }
    It 'public-access-off is REFUSED while the Support app''s database access does not read back -- nothing closed' {
        $a = $script:Full.Clone(); $a.Steps = @('subnets', 'registry-premium', 'private-endpoints', 'private-dns', 'public-access-off')
        $r = Run $a
        $pa = @($r.Results | Where-Object { $_.Step -eq 'public-access-off' })[0]
        $pa.Ok | Should -BeFalse
        ($pa.Lines -join ' ') | Should -Match 'Support app''s database access does not read back'
        (Get-SIArmStoreItem "$script:Rg/providers/Microsoft.Sql/servers/sql-si-x").properties.publicNetworkAccess | Should -Be 'Enabled'
    }
    It 'sql-identity + support-sql, then the close: id-si-sql and the Support app members of the admin group, its own user, closed' {
        $a = $script:Full.Clone(); $a.Steps = @('subnets', 'registry-premium', 'private-endpoints', 'private-dns', 'sql-identity', 'support-sql', 'public-access-off')
        $r = Run $a
        @($r.Results | Where-Object { -not $_.Ok } | ForEach-Object { $_.Step + ': ' + ($_.Lines -join '; ') }) | Should -BeNullOrEmpty
        Get-SIArmStoreItem "$script:Rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-si-sql" | Should -Not -BeNullOrEmpty
        @($global:SIArmStore.Members['gid-admins']) | Should -Contain 'pid-id-si-sql'
        @($global:SIArmStore.Members['gid-admins']) | Should -Contain 'sp-support'
        $global:SIPnTestUsers['sqldb-si-pro'] | Should -BeTrue
        $global:SIPnTestUsers.ContainsKey('master') | Should -BeFalse
        (Get-SIArmStoreItem "$script:Rg/providers/Microsoft.Sql/servers/sql-si-x").properties.publicNetworkAccess | Should -Be 'Disabled'
        @((Get-SIArmStoreItem "$script:Rg/providers/Microsoft.App/jobs/caj-si-flow").identity.userAssignedIdentities.Keys) -join ' ' | Should -Not -Match 'id-si-sql' -Because 'no standing job carries the in-network SQL identity'
        # the rollback of this record is refused (it closed the database); the Support app's access is never taken away
        $global:SIArmStore.Writes.Clear()
        (Run @{ Rollback = $r.RecordPath; Apply = $true }).Mode | Should -Be 'rollback-refused'
        @(Writes) | Should -BeNullOrEmpty
        $null = Run @{ Rollback = $r.RecordPath; Apply = $true; ReopenPublicAccess = $true }
        @($global:SIArmStore.Members['gid-admins']) | Should -Not -Contain 'pid-id-si-sql'
        @($global:SIArmStore.Members['gid-admins']) | Should -Contain 'sp-support' -Because 'framework 4.1b: never removed'
        Get-SIArmStoreItem "$script:Rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-si-sql" | Should -BeNullOrEmpty
    }
    It 'registry-public-off is REFUSED until its builds run on an agent pool in the network; then it closes' {
        $a = $script:Full.Clone(); $a.Steps = @('subnets', 'registry-premium', 'private-endpoints', 'private-dns', 'registry-public-off')
        $r = Run $a
        $rp = @($r.Results | Where-Object { $_.Step -eq 'registry-public-off' })[0]
        $rp.Ok | Should -BeFalse
        ($rp.Lines -join ' ') | Should -Match 'agent pool'
        (Get-SIArmStoreItem "$script:Rg/providers/Microsoft.ContainerRegistry/registries/acrsix").properties.publicNetworkAccess | Should -Be 'Enabled'
        $b = $script:Full.Clone(); $b.Steps = @('registry-agent-pool', 'registry-public-off')
        $r2 = Run $b
        @($r2.Results | Where-Object { -not $_.Ok } | ForEach-Object { $_.Step + ': ' + ($_.Lines -join '; ') }) | Should -BeNullOrEmpty
        (Get-SIArmStoreItem "$script:Rg/providers/Microsoft.ContainerRegistry/registries/acrsix/agentPools/si-vnet-pool").properties.virtualNetworkSubnetResourceId | Should -Be "$script:Vnet/subnets/snet-si-endpoints"
        (Get-SIArmStoreItem "$script:Rg/providers/Microsoft.ContainerRegistry/registries/acrsix").properties.publicNetworkAccess | Should -Be 'Disabled'
    }
    It 'the guided install makes id-si-sql (and its membership) BEFORE the endpoints step closes anything (static)' {
        $gi = Get-Content -Raw (Join-Path $script:SIRoot 'setup\_shared\SI-GuidedInstall.ps1')
        $i = $gi.IndexOf("'Invoke-SIPrivateNetworkSqlIdentity'"); $j = $gi.IndexOf("-Command 'Invoke-SIPrivateNetworkEndpoints'")
        $i | Should -BeGreaterThan 0
        $i | Should -BeLessThan $j
        $gi | Should -Match 'Set-SISupportAppGroupMember -Graph \$graph -GroupId \$gid -ServicePrincipalId \(\[string\]\$mi\.Value\.PrincipalId\) -Apply'
    }
}

Describe 'no module, no az, no native exe in the option''s code' {
    It '<_>' -ForEach @('setup\_shared\SI-PrivateNetwork.ps1', 'setup\Set-SIPrivateNetworking.ps1', 'setup\_shared\SI-SupportSqlJob.ps1', 'setup\Invoke-SISupportSqlAccessJob.ps1') {
        $p = Join-Path $script:SIRoot $_
        if (-not (Test-Path -LiteralPath $p)) { Set-ItResult -Skipped -Because 'a Pro file (not in the Community copy)'; return }
        $c = Get-Content -Raw $p
        $c | Should -Not -Match '(?im)^\s*Import-Module|\bInstall-Module\b|Connect-AzAccount|^\s*az\s|\baz (network|containerapp|acr|keyvault)\b|\.exe\b'
    }
}
