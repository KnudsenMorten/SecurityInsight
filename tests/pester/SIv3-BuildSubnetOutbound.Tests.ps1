#Requires -Version 5.1
<#
    #1087 (3.0.33) -- the build agent pool's subnet must have an OUTBOUND PATH. LIVE, a private install: the registry's agent
    pool (in the endpoints subnet, PIM's design) FAILED twice inside Azure's own deployment -- the endpoints subnet SI made
    read defaultOutboundAccess = false (Azure's default for NEW subnets since late 2025), no NAT gateway, no route table.
    What must hold now:
      * SI CREATES the endpoints subnet with defaultOutboundAccess = true, READ BACK true (framework rule 11b: stop with a
        plain message when it does not);
      * before the pool: the subnet is READ; no path (false + no NAT + no 0.0.0.0/0 route) on SI's OWN spoke -> set true,
        read back; on a CUSTOMER'S network -> nothing changed, no pool made, ONE customer step; NAT / route -> fine;
      * the updater does the same check and REPORTS a customer subnet, never failing the update.
    OFFLINE (the fake ARM store). Stubs in SCRIPT scope. PS 5.1 + pwsh 7.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'tests\fixtures\SIArmStoreFake.ps1')
    . (Join-Path $script:SIRoot 'setup\_shared\SI-PrivateNetwork.ps1')
    $script:Sub = '11111111-1111-1111-1111-111111111111'
    $script:Rg = '/subscriptions/{0}/resourceGroups/rg-si-x' -f $script:Sub
    $script:Vnet = "$script:Rg/providers/Microsoft.Network/virtualNetworks/vnet-si"
    $script:PeSubnet = "$script:Vnet/subnets/snet-si-endpoints"
    $script:AppsSubnet = "$script:Vnet/subnets/snet-si-apps"
    $script:CustRg = '/subscriptions/{0}/resourceGroups/rg-network' -f $script:Sub
    $script:CustVnet = "$script:CustRg/providers/Microsoft.Network/virtualNetworks/vnet-spoke"
    $script:CustSubnet = "$script:CustVnet/subnets/snet-pe"
    $script:RegId = "$script:Rg/providers/Microsoft.ContainerRegistry/registries/acrsix"
    $script:PoolId = "$script:RegId/agentPools/si-vnet-pool"
    $script:EnvId = "$script:Rg/providers/Microsoft.App/managedEnvironments/cae-si-prod-pro-ca"
    $script:NoSleep = { param($s) }
    $script:Arm = { param($m, $p, $b) & $global:SIArmStoreFake $m $p $b }
    # an ARM where the subnet NEVER reads back defaultOutboundAccess true (what the read-back must catch)
    $script:ArmNoOutbound = {
        param($m, $p, $b)
        $r = & $global:SIArmStoreFake $m $p $b
        if ($m -eq 'GET' -and $r -and $p -match '(?i)/subnets/[^/?]+\?' -and $r.properties.PSObject.Properties['defaultOutboundAccess']) { $r.properties.defaultOutboundAccess = $false }
        $r
    }
    $script:Private = { param([string]$Name) @('10.20.0.40') }

    function script:New-OutWorld {
        param([ValidateSet('own', 'customer')][string]$Network = 'own', [AllowNull()]$Outbound = $false, [switch]$Nat, [string]$RouteHop = '', [switch]$PoolRuns, [switch]$PrivateEnv)
        New-SIArmStore
        $vnet = if ($Network -eq 'own') { $script:Vnet } else { $script:CustVnet }
        $sn = if ($Network -eq 'own') { $script:PeSubnet } else { $script:CustSubnet }
        $v = @{ id = $vnet; location = 'westeurope'; properties = @{ provisioningState = 'Succeeded'; addressSpace = @{ addressPrefixes = @('10.20.0.0/24') } } }
        if ($Network -eq 'own') { $v['tags'] = @{ purpose = 'securityinsight-private-network' } }
        Set-SIArmStoreItem $v
        $props = @{ addressPrefix = '10.20.0.64/26'; provisioningState = 'Succeeded'; privateEndpointNetworkPolicies = 'Disabled'; networkSecurityGroup = @{ id = "$script:Rg/providers/Microsoft.Network/networkSecurityGroups/nsg-x" } }
        if ($null -ne $Outbound) { $props['defaultOutboundAccess'] = $Outbound }
        if ($Nat) { $props['natGateway'] = @{ id = "$script:CustRg/providers/Microsoft.Network/natGateways/ng-1" } }
        if ($RouteHop) {
            $rt = "$script:CustRg/providers/Microsoft.Network/routeTables/rt-1"
            $props['routeTable'] = @{ id = $rt }
            Set-SIArmStoreItem @{ id = $rt; properties = @{ provisioningState = 'Succeeded'; routes = @(@{ name = 'default'; properties = @{ addressPrefix = '0.0.0.0/0'; nextHopType = $RouteHop; nextHopIpAddress = '10.0.0.4' } }) } }
        }
        Set-SIArmStoreItem @{ id = $sn; properties = $props }
        Set-SIArmStoreItem @{ id = $script:RegId; name = 'acrsix'; location = 'westeurope'; sku = @{ name = 'Premium' }; properties = @{ loginServer = 'acrsix.azurecr.io'; adminUserEnabled = $false; publicNetworkAccess = 'Disabled'; networkRuleBypassOptions = 'AzureServices'; provisioningState = 'Succeeded' } }
        if ($PoolRuns) { Set-SIArmStoreItem @{ id = $script:PoolId; properties = @{ provisioningState = 'Succeeded'; virtualNetworkSubnetResourceId = $sn } } }
        if ($PrivateEnv) {
            Set-SIArmStoreItem @{ id = $script:EnvId; location = 'westeurope'; properties = @{ provisioningState = 'Succeeded'; defaultDomain = 'x.westeurope.azurecontainerapps.io'; vnetConfiguration = @{ infrastructureSubnetId = $script:AppsSubnet; internal = $true } } }
            Set-SIArmStoreItem @{ id = "$script:Rg/providers/Microsoft.App/jobs/caj-si-flow"; location = 'westeurope'; properties = @{ environmentId = $script:EnvId; provisioningState = 'Succeeded'; configuration = @{ registries = @(@{ server = 'acrsix.azurecr.io'; identity = 'mi' }) } } }
            Set-SIArmStoreItem @{ id = "$script:Rg/providers/Microsoft.Network/privateEndpoints/pe-si-vault"; location = 'westeurope'; properties = @{ provisioningState = 'Succeeded'; subnet = @{ id = $sn }; privateLinkServiceConnections = @(@{ properties = @{ privateLinkServiceId = 'kv'; groupIds = @('vault'); privateLinkServiceConnectionState = @{ status = 'Approved' } } }) } }
        }
        $global:SIArmStore.Writes.Clear()
    }
    function script:Writes { @($global:SIArmStore.Writes) }
    # SecurityInsight's own spoke: vnetAddressPrefix, no vnetId (CreateVnet); a customer's network: vnetId given
    function script:OwnTarget { Get-SIInstallPrivateNetworkTarget -Values ([ordered]@{ vnetAddressPrefix = '10.20.0.0/24' }) -ResourceGroupId $script:Rg }
    function script:CustTarget { Get-SIInstallPrivateNetworkTarget -Values ([ordered]@{ vnetId = $script:CustVnet; endpointsSubnetName = 'snet-pe' }) -ResourceGroupId $script:Rg }
    function script:Invoke-Reg([System.Collections.IDictionary]$Target, [string]$Subnet, [scriptblock]$Arm = $script:Arm) {
        Invoke-SIPrivateNetworkRegistry -Target $Target -Location 'westeurope' -RegistryLocation 'westeurope' -RegistryId $script:RegId -EndpointsSubnetId $Subnet -Resolve $script:Private -SkipDnsGate -Arm $Arm -Sleep $script:NoSleep
    }
}

AfterAll { Remove-SIArmStore }

Describe 'the endpoints subnet SI CREATES carries defaultOutboundAccess = true, read back' {
    It 'the create body: defaultOutboundAccess true (the endpoints subnet); the delegated apps subnet does not get it' {
        $b = Get-SISubnetBody -Subnet $null -Prefix '10.20.0.64/26'
        $b.properties.defaultOutboundAccess | Should -BeTrue
        $b.properties.privateEndpointNetworkPolicies | Should -Be 'Disabled'
        (Get-SISubnetBody -Subnet $null -Prefix '10.20.0.0/26' -Delegate).properties.Contains('defaultOutboundAccess') | Should -BeFalse
    }
    It 'an EXISTING subnet keeps its own value (a subnet PUT replaces it; never flipped by the body)' {
        $have = [pscustomobject]@{ properties = [pscustomobject]@{ addressPrefix = '10.0.0.0/26'; defaultOutboundAccess = $false } }
        (Get-SISubnetBody -Subnet $have -Delegate).properties.defaultOutboundAccess | Should -BeFalse
    }
    It 'created: it reads back true, the line says (read back)' {
        New-SIArmStore
        Set-SIArmStoreItem @{ id = $script:Vnet; location = 'westeurope'; properties = @{ provisioningState = 'Succeeded'; addressSpace = @{ addressPrefixes = @('10.20.0.0/24') } } }
        $s = Set-SISubnet -Arm $script:Arm -VnetId $script:Vnet -Name 'snet-si-endpoints' -Prefix '10.20.0.64/26' -Sleep $script:NoSleep
        $s.Ok | Should -BeTrue
        (Get-SIArmStoreItem $script:PeSubnet).properties.defaultOutboundAccess | Should -BeTrue
        $s.Line | Should -Match 'with default outbound access \(outbound only\) \(read back\)$'
    }
    It 'created, but it does NOT read back true: it stops with a plain message (framework rule 11b)' {
        New-SIArmStore
        Set-SIArmStoreItem @{ id = $script:Vnet; location = 'westeurope'; properties = @{ provisioningState = 'Succeeded'; addressSpace = @{ addressPrefixes = @('10.20.0.0/24') } } }
        { Set-SISubnet -Arm $script:ArmNoOutbound -VnetId $script:Vnet -Name 'snet-si-endpoints' -Prefix '10.20.0.64/26' -Sleep $script:NoSleep } |
            Should -Throw '*snet-si-endpoints was created with default outbound access, but it does not read back true (Azure shows: False)*'
    }
}

Describe 'the outbound path of a subnet (pure)' {
    It 'unset = the implicit outbound of an older subnet (PIM''s working pool subnet); true = default; false alone = none' {
        Get-SISubnetOutboundPath -Subnet ([pscustomobject]@{ properties = [pscustomobject]@{ addressPrefix = '10.0.0.0/26' } }) | Should -Be 'default'
        Get-SISubnetOutboundPath -Subnet ([pscustomobject]@{ properties = [pscustomobject]@{ defaultOutboundAccess = $true } }) | Should -Be 'default'
        Get-SISubnetOutboundPath -Subnet ([pscustomobject]@{ properties = [pscustomobject]@{ defaultOutboundAccess = $false } }) | Should -Be ''
    }
    It 'false + a NAT gateway = nat; false + a 0.0.0.0/0 route = route; a 0.0.0.0/0 route to None is no path' {
        Get-SISubnetOutboundPath -Subnet ([pscustomobject]@{ properties = [pscustomobject]@{ defaultOutboundAccess = $false; natGateway = [pscustomobject]@{ id = 'ng' } } }) | Should -Be 'nat'
        $sn = [pscustomobject]@{ properties = [pscustomobject]@{ defaultOutboundAccess = $false; routeTable = [pscustomobject]@{ id = 'rt' } } }
        Get-SISubnetOutboundPath -Subnet $sn -RouteTable ([pscustomobject]@{ properties = [pscustomobject]@{ routes = @([pscustomobject]@{ properties = [pscustomobject]@{ addressPrefix = '0.0.0.0/0'; nextHopType = 'VirtualAppliance' } }) } }) | Should -Be 'route'
        Get-SISubnetOutboundPath -Subnet $sn -RouteTable ([pscustomobject]@{ properties = [pscustomobject]@{ routes = @([pscustomobject]@{ properties = [pscustomobject]@{ addressPrefix = '0.0.0.0/0'; nextHopType = 'None' } }) } }) | Should -Be ''
        Get-SISubnetOutboundPath -Subnet $sn -RouteTable ([pscustomobject]@{ properties = [pscustomobject]@{ routes = @([pscustomobject]@{ properties = [pscustomobject]@{ addressPrefix = '10.0.0.0/8'; nextHopType = 'VirtualAppliance' } }) } }) | Should -Be ''
    }
    It 'SI''s own spoke = in the install''s resource group AND tagged by SI; anything else is the customer''s' {
        Test-SIOwnSpokeVnet -Vnet ([pscustomobject]@{ id = $script:Vnet; tags = [pscustomobject]@{ purpose = 'securityinsight-private-network' } }) -ResourceGroupId $script:Rg | Should -BeTrue
        Test-SIOwnSpokeVnet -Vnet ([pscustomobject]@{ id = $script:Vnet }) -ResourceGroupId $script:Rg | Should -BeFalse
        Test-SIOwnSpokeVnet -Vnet ([pscustomobject]@{ id = $script:CustVnet; tags = [pscustomobject]@{ purpose = 'securityinsight-private-network' } }) -ResourceGroupId $script:Rg | Should -BeFalse
    }
}

Describe 'the registry step: the build subnet is checked BEFORE the agent pool' {
    It 'SI''s OWN spoke, no outbound path: defaultOutboundAccess set true, read back, everything else kept -- then the pool' {
        New-OutWorld -Network own -Outbound $false
        $r = Invoke-Reg -Target (OwnTarget) -Subnet $script:PeSubnet
        $r.PoolOk | Should -BeTrue
        $r.PoolBlocked | Should -BeFalse
        $sn = Get-SIArmStoreItem $script:PeSubnet
        $sn.properties.defaultOutboundAccess | Should -BeTrue
        $sn.properties.networkSecurityGroup.id | Should -Match 'nsg-x' -Because 'the subnet PUT keeps what it has'
        ($r.Lines -join ' ') | Should -Match 'snet-si-endpoints \(SecurityInsight''s own network\) had no outbound path: default outbound access turned on \(outbound only; read back\)'
        $w = @(Writes)
        [array]::IndexOf($w, "PUT $script:PeSubnet") | Should -BeLessThan ([array]::IndexOf($w, "PUT $script:PoolId")) -Because 'the subnet first, the pool after'
    }
    It 'SI''s own spoke, the fix does NOT read back true: no pool is made, a plain message' {
        New-OutWorld -Network own -Outbound $false
        $r = Invoke-Reg -Target (OwnTarget) -Subnet $script:PeSubnet -Arm $script:ArmNoOutbound
        $r.PoolOk | Should -BeFalse
        $r.PoolBlocked | Should -BeTrue
        $r.OutboundStep | Should -Match 'run the install again'
        ($r.Lines -join ' ') | Should -Match 'does not read back with default outbound access after the change -- the agent pool is NOT made'
        @(Writes) | Should -Not -Contain "PUT $script:PoolId"
    }
    It 'a CUSTOMER''S network, no outbound path: NOTHING changed, no pool, the one customer step' {
        New-OutWorld -Network customer -Outbound $false
        $r = Invoke-Reg -Target (CustTarget) -Subnet $script:CustSubnet
        $r.PoolOk | Should -BeFalse
        $r.PoolBlocked | Should -BeTrue
        $r.OutboundStep | Should -Be 'the build subnet snet-pe has no outbound path; give it outbound access (defaultOutboundAccess, a NAT gateway or a route to your firewall that allows the Azure services an ACR agent pool needs), then run the install again'
        @(Writes | Where-Object { $_ -like "* $script:CustSubnet" -or $_ -like "* $script:CustVnet" }) | Should -BeNullOrEmpty
        @(Writes) | Should -Not -Contain "PUT $script:PoolId"
        (Get-SIArmStoreItem $script:CustSubnet).properties.defaultOutboundAccess | Should -BeFalse
    }
    It 'a customer''s network with a NAT gateway, or a 0.0.0.0/0 route to its firewall: fine, nothing written on it, the pool is made' {
        foreach ($w in @(@{ Nat = $true; RouteHop = '' }, @{ Nat = $false; RouteHop = 'VirtualAppliance' })) {
            New-OutWorld -Network customer -Outbound $false -Nat:$w.Nat -RouteHop $w.RouteHop
            $r = Invoke-Reg -Target (CustTarget) -Subnet $script:CustSubnet
            $r.PoolOk | Should -BeTrue
            $r.PoolBlocked | Should -BeFalse
            @(Writes | Where-Object { $_ -like "* $script:CustSubnet" }) | Should -BeNullOrEmpty
            @(Writes) | Should -Contain "PUT $script:PoolId"
        }
    }
    It 'an older subnet (defaultOutboundAccess unset, like PIM''s) is fine as it is' {
        New-OutWorld -Network customer -Outbound $null
        (Invoke-Reg -Target (CustTarget) -Subnet $script:CustSubnet).PoolOk | Should -BeTrue
        @(Writes | Where-Object { $_ -like "* $script:CustSubnet" }) | Should -BeNullOrEmpty
    }
    It 'a pool that already RUNS in the subnet is kept -- never blocked by the check' {
        New-OutWorld -Network customer -Outbound $false -PoolRuns
        $r = Invoke-Reg -Target (CustTarget) -Subnet $script:CustSubnet
        $r.PoolOk | Should -BeTrue
        @(Writes | Where-Object { $_ -like "* $script:CustSubnet" -or $_ -like "* $script:PoolId" }) | Should -BeNullOrEmpty
    }
    It 'the guided install stops with the customer step as the action' {
        . (Join-Path $script:SIRoot 'setup\_shared\SI-GuidedInstall.ps1')
        New-OutWorld -Network customer -Outbound $false
        $ctx = @{ Values = [ordered]@{ subscriptionId = $script:Sub; vnetId = $script:CustVnet; endpointsSubnetName = 'snet-pe'; privateNetwork = $true; location = 'westeurope' }; Names = @{ ResourceGroup = 'rg-si-x'; Acr = 'acrsix' }
                  Facts = [ordered]@{ endpointsSubnetId = $script:CustSubnet; vnetLocation = 'westeurope' }; Cache = [ordered]@{}
                  ResumeCommand = 'resume-cmd'; ScriptLog = (New-Object System.Collections.Generic.List[object])
                  Seams = @{ Az = { param($Command, $Arguments) $a = @{}; foreach ($k in $Arguments.Keys) { $a[$k] = $Arguments[$k] }; $a['Arm'] = $script:Arm; $a['Sleep'] = $script:NoSleep; & $Command @a }
                             Resolve = $script:Private; Print = { param($t, $c) } } }
        $err = $null
        try { $null = & (Get-SIInstallStepTable)['private-network-registry'] $ctx } catch { $err = $_ }
        $err | Should -Not -BeNullOrEmpty
        $err.Exception.Message | Should -Match 'its build agent pool is not made: the build subnet snet-pe has no outbound path'
        $err.Exception.Data['SIInstallAction'].text | Should -Match '^Your step: the build subnet snet-pe has no outbound path; give it outbound access'
        @(Writes) | Should -Not -Contain "PUT $script:PoolId"
    }
}

Describe 'the updater (step 1b): the same check, reported, never failing the update' {
    It 'a customer''s subnet without a path: reported with the step, nothing changed on it, no pool, no throw' {
        New-OutWorld -Network customer -Outbound $false -PrivateEnv
        $r = Invoke-SIUpdatePrivateRegistry -Arm $script:Arm -ResourceGroupId $script:Rg -RegistryId $script:RegId -Resolve $script:Private -Sleep $script:NoSleep
        $r.Private | Should -BeTrue
        $r.Ok | Should -BeFalse
        ($r.Lines -join ' ') | Should -Match 'give it outbound access \(defaultOutboundAccess, a NAT gateway or a route to your firewall'
        @(Writes | Where-Object { $_ -like "* $script:CustSubnet" }) | Should -BeNullOrEmpty
        @(Writes) | Should -Not -Contain "PUT $script:PoolId"
    }
    It 'SI''s own spoke (read from the network: its resource group + SI''s tag): set true, read back, then the pool' {
        New-OutWorld -Network own -Outbound $false -PrivateEnv
        $r = Invoke-SIUpdatePrivateRegistry -Arm $script:Arm -ResourceGroupId $script:Rg -RegistryId $script:RegId -Resolve $script:Private -Sleep $script:NoSleep
        (Get-SIArmStoreItem $script:PeSubnet).properties.defaultOutboundAccess | Should -BeTrue
        (Get-SIArmStoreItem $script:PoolId).properties.virtualNetworkSubnetResourceId | Should -Be $script:PeSubnet
        @($r.Changed) | Should -Contain 'build subnet outbound'
    }
    It 'a private registry whose pool runs: done as before -- nothing read further, nothing written' {
        New-OutWorld -Network customer -Outbound $false -PrivateEnv -PoolRuns
        $r = Invoke-SIUpdatePrivateRegistry -Arm $script:Arm -ResourceGroupId $script:Rg -RegistryId $script:RegId -Resolve $script:Private -Sleep $script:NoSleep
        $r.Ok | Should -BeTrue
        $r.Closed | Should -BeTrue
        @(Writes) | Should -BeNullOrEmpty
    }
}
