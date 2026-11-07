#Requires -Version 5.1
<#
    #1095 -- THE RETURN ROUTE OF A PRIVATE INSTALL (live 2026-11-04: a private install in a hub-and-spoke network with a
    firewall in the hub -- DNS resolved, the peering read Connected, and the browser still timed out: the apps subnet had NO
    route table, so the web app's replies to the customer's own ranges took Azure's default route and were dropped).
      * SecurityInsight's OWN spoke with both answers (returnRouteRanges + returnRouteNextHop): the route table rt-si (framework
        rule 11d) -- one route per range -> VirtualAppliance <next hop>, BGP route propagation off -- attached to the apps
        subnet; routes AND attachment read back;
      * idempotent: a second run writes nothing; a table already attached (a hand-made one) is reused, never a second one,
        never renamed; routes SecurityInsight did not make are kept, never removed or overwritten;
      * a CUSTOMER's network: nothing written -- the network hand-off's RETURN ROUTE item instead; the same item when the
        answers are missing on SecurityInsight's own spoke, with how to give them and run again;
      * the updater only REPORTS a private install whose apps subnet has no route table (never makes one);
      * the wizard asks the two answers only on a private install that names a hub;
      * the end check: answers set and the route not in place = a warning naming the fix.
    Against the fake ARM store (tests\fixtures\SIArmStoreFake.ps1). OFFLINE. PS 5.1 + pwsh 7. Example values only.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'tests\fixtures\SIArmStoreFake.ps1')
    . (Join-Path $script:SIRoot 'setup\_shared\SI-GuidedInstall.ps1')   # loads SI-PrivateNetwork.ps1 too
    $script:Sub = '11111111-1111-1111-1111-111111111111'
    $script:Rg = '/subscriptions/{0}/resourceGroups/rg-si-x' -f $script:Sub
    $script:OwnVnet = "$script:Rg/providers/Microsoft.Network/virtualNetworks/vnet-si"
    $script:CustVnet = '/subscriptions/{0}/resourceGroups/rg-net/providers/Microsoft.Network/virtualNetworks/vnet-spoke' -f $script:Sub
    $script:Hub = '/subscriptions/{0}/resourceGroups/rg-hub/providers/Microsoft.Network/virtualNetworks/vnet-hub' -f $script:Sub
    $script:RtSi = "$script:Rg/providers/Microsoft.Network/routeTables/rt-si"
    $script:NoSleep = { param($s) }
    $script:Arm = { param($m, $p, $b) & $global:SIArmStoreFake $m $p $b }
    $script:Fw = '10.1.0.4'

    function script:New-RouteWorld([string]$Vnet = $script:OwnVnet, [switch]$Customer) {
        New-SIArmStore
        $v = @{ id = $Vnet; location = 'westeurope'; properties = @{ provisioningState = 'Succeeded'; addressSpace = @{ addressPrefixes = @('10.20.0.0/24') } } }
        if (-not $Customer) { $v['tags'] = @{ purpose = 'securityinsight-private-network' } }
        Set-SIArmStoreItem $v
        Set-SIArmStoreItem @{ id = "$Vnet/subnets/snet-si-apps"; properties = @{ addressPrefix = '10.20.0.0/26'; provisioningState = 'Succeeded'; delegations = @(@{ name = 'Microsoft.App.environments'; properties = @{ serviceName = 'Microsoft.App/environments' } }) } }
        Set-SIArmStoreItem @{ id = "$Vnet/subnets/snet-si-endpoints"; properties = @{ addressPrefix = '10.20.0.64/26'; provisioningState = 'Succeeded'; privateEndpointNetworkPolicies = 'Disabled' } }
        $global:SIArmStore.Writes.Clear()
    }
    function script:New-Target([string]$Vnet = $script:OwnVnet, $Ranges = '10.0.0.0/16, 10.2.0.0/16', [string]$NextHop = $script:Fw, [switch]$Create) {
        $vals = [ordered]@{ hubVnetId = $script:Hub; returnRouteRanges = $Ranges; returnRouteNextHop = $NextHop }
        if ($Create) { $vals['vnetAddressPrefix'] = '10.20.0.0/24' } else { $vals['vnetId'] = $Vnet }
        Get-SIInstallPrivateNetworkTarget -Values $vals -ResourceGroupId $script:Rg
    }
    function script:Writes { @($global:SIArmStore.Writes) }
    function script:Item([string]$Id) { & $script:Arm 'GET' "$($Id)?api-version=x" $null }
}

AfterAll { Remove-SIArmStore }

Describe '#1095 the create body: one route per range -> VirtualAppliance, the next hop given, BGP route propagation off' {
    It 'a new table: rt-si, the install''s region, tagged as SecurityInsight''s, the routes named si-return-(range)' {
        $b = Get-SIReturnRouteTableBody -Existing $null -Ranges @('10.0.0.0/16', '10.2.0.0/16') -NextHop $script:Fw -Location 'westeurope'
        $b.Changed | Should -BeTrue
        $b.Body.location | Should -Be 'westeurope'
        $b.Body.tags.purpose | Should -Be 'securityinsight-private-network'
        $b.Body.properties.disableBgpRoutePropagation | Should -BeTrue
        @($b.Body.properties.routes).Count | Should -Be 2
        foreach ($r in $b.Body.properties.routes) { $r.properties.nextHopType | Should -Be 'VirtualAppliance'; $r.properties.nextHopIpAddress | Should -Be $script:Fw }
        @($b.Body.properties.routes | ForEach-Object { $_.name }) | Should -Be @('si-return-10.0.0.0-16', 'si-return-10.2.0.0-16')
        @($b.Added) | Should -Be @('10.0.0.0/16', '10.2.0.0/16')
        Get-SIReturnRouteTableName | Should -Be 'rt-si' -Because 'framework rule 11d'
    }
    It 'the answer is read as text or a list; a range in host form is its network; what is not a range is named' {
        $r = ConvertTo-SIReturnRouteRanges '10.0.0.5/16; 10.2.0.0/16 10.0.0.0/16, nonsense'
        @($r.Ranges) | Should -Be @('10.0.0.0/16', '10.2.0.0/16')
        @($r.Bad) | Should -Be @('nonsense')
        @((ConvertTo-SIReturnRouteRanges @('10.0.0.0/16', '10.3.0.0/24')).Ranges) | Should -Be @('10.0.0.0/16', '10.3.0.0/24')
        Test-SIIpv4Address '10.1.0.4' | Should -BeTrue
        Test-SIIpv4Address '10.1.0.400' | Should -BeFalse
    }
    It 'SecurityInsight''s own spoke: rt-si made, attached to the apps subnet, both READ BACK, said in the step line' {
        New-RouteWorld
        $x = Set-SIReturnRoute -Arm $script:Arm -Target (New-Target) -Sleep $script:NoSleep
        $x.Ok | Should -BeTrue -Because $x.Line
        $x.Created | Should -BeTrue; $x.Attached | Should -BeTrue; $x.AttachedNow | Should -BeTrue; $x.Changed | Should -BeTrue
        $x.RouteTableId | Should -Be $script:RtSi
        $rt = Item $script:RtSi
        [string]$rt.properties.disableBgpRoutePropagation | Should -Be 'True'
        @($rt.properties.routes | ForEach-Object { '{0}>{1}>{2}' -f $_.properties.addressPrefix, $_.properties.nextHopType, $_.properties.nextHopIpAddress }) | Should -Be @("10.0.0.0/16>VirtualAppliance>$script:Fw", "10.2.0.0/16>VirtualAppliance>$script:Fw")
        $sn = Item "$script:OwnVnet/subnets/snet-si-apps"
        $sn.properties.routeTable.id | Should -Be $script:RtSi
        @($sn.properties.delegations | ForEach-Object { $_.properties.serviceName }) | Should -Contain 'Microsoft.App/environments' -Because 'the subnet PUT keeps what the subnet has'
        (Item "$script:OwnVnet/subnets/snet-si-endpoints").properties.routeTable | Should -BeNullOrEmpty -Because 'private endpoints do not need it'
        $x.Line | Should -Match 'route table rt-si made in the install''s resource group: 10\.0\.0\.0/16 -> 10\.1\.0\.4, 10\.2\.0\.0/16 -> 10\.1\.0\.4 \(VirtualAppliance\), BGP route propagation off \(read back\)'
        $x.Line | Should -Match 'attached to the apps subnet snet-si-apps \(read back\)'
    }
    It 'the network SecurityInsight creates in this install (vnetAddressPrefix) is its own, before Azure has its tag read' {
        New-RouteWorld
        $t = New-Target -Create
        $t.CreateVnet | Should -BeTrue
        (Set-SIReturnRoute -Arm $script:Arm -Target $t -Sleep $script:NoSleep).Attached | Should -BeTrue
    }
    It 'a table that does not read back is NOT complete -- never "done" on what Azure does not show' {
        New-RouteWorld
        $lossy = { param($m, $p, $b) if ($m -eq 'PUT' -and $p -match '/routeTables/') { $null = & $global:SIArmStoreFake $m $p $b; $i = Get-SIArmStoreItem (($p -split '\?')[0]); $i['properties']['routes'] = @(); return $null }; & $global:SIArmStoreFake $m $p $b }
        $x = Set-SIReturnRoute -Arm $lossy -Target (New-Target) -Sleep $script:NoSleep
        $x.Ok | Should -BeFalse
        $x.Line | Should -Match 'NOT complete'
        $x.Attached | Should -BeFalse -Because 'a table without its routes is not attached'
    }
}

Describe '#1095 idempotent: converged, never a second table, routes SecurityInsight did not make are kept' {
    It 'a second run writes nothing' {
        New-RouteWorld
        $null = Set-SIReturnRoute -Arm $script:Arm -Target (New-Target) -Sleep $script:NoSleep
        $global:SIArmStore.Writes.Clear()
        $x = Set-SIReturnRoute -Arm $script:Arm -Target (New-Target) -Sleep $script:NoSleep
        $x.Ok | Should -BeTrue; $x.Changed | Should -BeFalse
        Writes | Should -BeNullOrEmpty
        $x.Line | Should -Match 'nothing to change'
    }
    It 'a table already attached (a hand-made one) is REUSED: its foreign routes kept, ours added, BGP off, no rt-si made' {
        New-RouteWorld
        $hand = "$script:Rg/providers/Microsoft.Network/routeTables/rt-si-apps"
        Set-SIArmStoreItem @{ id = $hand; location = 'westeurope'; tags = @{ owner = 'network-team' }; properties = @{ provisioningState = 'Succeeded'; disableBgpRoutePropagation = $false
            routes = @(@{ name = 'to-onprem'; properties = @{ addressPrefix = '10.0.0.0/16'; nextHopType = 'VirtualAppliance'; nextHopIpAddress = $script:Fw } },
                       @{ name = 'default'; properties = @{ addressPrefix = '0.0.0.0/0'; nextHopType = 'VirtualAppliance'; nextHopIpAddress = '10.1.0.5' } }) } }
        $sn = Get-SIArmStoreItem "$script:OwnVnet/subnets/snet-si-apps"; $sn['properties']['routeTable'] = [ordered]@{ id = $hand }
        $global:SIArmStore.Writes.Clear()
        $x = Set-SIReturnRoute -Arm $script:Arm -Target (New-Target) -Sleep $script:NoSleep
        $x.Ok | Should -BeTrue -Because $x.Line
        $x.RouteTableId | Should -Be $hand
        Item $script:RtSi | Should -BeNullOrEmpty -Because 'never a second table'
        $rt = Item $hand
        $rt.name | Should -Be 'rt-si-apps' -Because 'never renamed'
        @($rt.properties.routes | ForEach-Object { $_.name }) | Should -Be @('to-onprem', 'default', 'si-return-10.2.0.0-16') -Because 'the foreign routes stay; only the missing range is added'
        [string]$rt.properties.disableBgpRoutePropagation | Should -Be 'True'
        $rt.tags.owner | Should -Be 'network-team'
        @(Writes | Where-Object { $_ -match '/subnets/' }) | Should -BeNullOrEmpty -Because 'it is attached already'
        $x.Line | Should -Match 'reused as it is, never a second one'
        $x.Line | Should -Match 'routes it did not make kept: to-onprem, default'
    }
    It 'a foreign route that sends a range elsewhere is NOT overwritten (a conflict, said); our own wrong route is corrected' {
        New-RouteWorld
        Set-SIArmStoreItem @{ id = $script:RtSi; location = 'westeurope'; properties = @{ provisioningState = 'Succeeded'; disableBgpRoutePropagation = $true
            routes = @(@{ name = 'theirs'; properties = @{ addressPrefix = '10.0.0.0/16'; nextHopType = 'VnetLocal' } },
                       @{ name = 'si-return-10.2.0.0-16'; properties = @{ addressPrefix = '10.2.0.0/16'; nextHopType = 'VirtualAppliance'; nextHopIpAddress = '10.1.0.9' } }) } }
        $x = Set-SIReturnRoute -Arm $script:Arm -Target (New-Target) -Sleep $script:NoSleep
        $x.Ok | Should -BeFalse -Because 'one range is not routed to the firewall'
        @($x.Conflicts) | Should -HaveCount 1
        $x.Line | Should -Match 'did not make sends 10\.0\.0\.0/16 -> VnetLocal'
        $rt = Item $script:RtSi
        @($rt.properties.routes | Where-Object { $_.name -eq 'theirs' })[0].properties.nextHopType | Should -Be 'VnetLocal' -Because 'never overwritten'
        @($rt.properties.routes | Where-Object { $_.name -eq 'si-return-10.2.0.0-16' })[0].properties.nextHopIpAddress | Should -Be $script:Fw -Because 'its own route is corrected'
        (Item "$script:OwnVnet/subnets/snet-si-apps").properties.routeTable.id | Should -Be $script:RtSi -Because 'the other range works -- the table is attached'
    }
}

Describe '#1095 a customer''s network, or answers missing: nothing written -- the hand-off item instead' {
    It 'a customer''s network: no write at all, and the hand-off says RETURN ROUTE with the range and the firewall' {
        New-RouteWorld -Vnet $script:CustVnet -Customer
        $t = New-Target -Vnet $script:CustVnet
        $x = Set-SIReturnRoute -Arm $script:Arm -Target $t -Sleep $script:NoSleep
        $x.Ok | Should -BeTrue; $x.HandOff | Should -BeTrue; $x.Own | Should -BeFalse
        $x.Line | Should -Match 'is in YOUR network -- SecurityInsight changes nothing'
        Writes | Should -BeNullOrEmpty
        $h = Get-SINetworkHandOff -Facts (Get-SINetworkHandOffFacts -Arm $script:Arm -Target $t)
        $h.Text | Should -Match ([regex]::Escape('6. RETURN ROUTE: the apps subnet snet-si-apps needs a route for each range your people browse from (e.g. a route table: 10.0.0.0/16 -> your firewall 10.1.0.4 as VirtualAppliance), or replies time out.'))
        $h.Text | Should -Match '10\.2\.0\.0/16\s+-> VirtualAppliance 10\.1\.0\.4'
        $h.Text | Should -Match 'has NO route table now'
        $h.Text | Should -Not -Match 'Set-SIPrivateNetworking' -Because 'on the customer''s network SecurityInsight never makes it'
        @($h.Items | Where-Object { $_.Kind -eq 'return-route' }) | Should -HaveCount 1
        $h.Text | Should -Match '(?m)^7\. CHECK from a machine in your network'
        Writes | Should -BeNullOrEmpty -Because 'the hand-off only reads'
    }
    It 'answers missing on SecurityInsight''s own spoke: no write, the same item plus how to give them and run again' {
        New-RouteWorld
        $t = New-Target -Ranges '' -NextHop ''
        $x = Set-SIReturnRoute -Arm $script:Arm -Target $t -Sleep $script:NoSleep
        $x.Ok | Should -BeTrue; $x.HandOff | Should -BeTrue
        Writes | Should -BeNullOrEmpty
        $h = Get-SINetworkHandOff -Facts (Get-SINetworkHandOffFacts -Arm $script:Arm -Target $t)
        $h.Text | Should -Match ([regex]::Escape('6. RETURN ROUTE: the apps subnet snet-si-apps needs a route for each range your people browse from (e.g. a route table: <a range your people browse from> -> your firewall <its private IP> as VirtualAppliance), or replies time out.'))
        $h.Text | Should -Match '-ReturnRouteRanges .+ -ReturnRouteNextHop .+ -Resume'
        $h.Text | Should -Match ([regex]::Escape('./setup/Set-SIPrivateNetworking.ps1 -ResourceGroup rg-si-x -VnetId ' + $script:OwnVnet + ' -ReturnRouteRanges <range>[,<range>] -ReturnRouteNextHop <firewall private IP> -Apply -Steps return-route'))
        @($h.Items | Where-Object { $_.Kind -eq 'return-route' }) | Should -HaveCount 1
    }
    It 'made and read back: the hand-off item says done and is not open' {
        New-RouteWorld
        $t = New-Target
        $null = Set-SIReturnRoute -Arm $script:Arm -Target $t -Sleep $script:NoSleep
        $h = Get-SINetworkHandOff -Facts (Get-SINetworkHandOffFacts -Arm $script:Arm -Target $t)
        $h.Text | Should -Match '6\. RETURN ROUTE: done -- route table rt-si on the apps subnet snet-si-apps sends 10\.0\.0\.0/16, 10\.2\.0\.0/16 to 10\.1\.0\.4'
        @($h.Items | Where-Object { $_.Kind -eq 'return-route' }) | Should -BeNullOrEmpty
    }
    It 'a range that is not a range, or a next hop that is not an address: nothing written, said' {
        New-RouteWorld
        (Set-SIReturnRoute -Arm $script:Arm -Target (New-Target -Ranges '10.0.0.0/16, nonsense') -Sleep $script:NoSleep).Line | Should -Match 'not an address range \(nonsense\)'
        (Set-SIReturnRoute -Arm $script:Arm -Target (New-Target -NextHop 'fw.example') -Sleep $script:NoSleep).Line | Should -Match 'is not an IPv4 address'
        Writes | Should -BeNullOrEmpty
    }
}

Describe '#1095 the updater only REPORTS' {
    BeforeEach {
        New-RouteWorld
        $envId = "$script:Rg/providers/Microsoft.App/managedEnvironments/cae-si"
        Set-SIArmStoreItem @{ id = $envId; location = 'westeurope'; properties = @{ provisioningState = 'Succeeded'; vnetConfiguration = @{ infrastructureSubnetId = "$script:OwnVnet/subnets/snet-si-apps"; internal = $true } } }
        Set-SIArmStoreItem @{ id = "$script:Rg/providers/Microsoft.App/jobs/caj-si-flow"; location = 'westeurope'; properties = @{ environmentId = $envId; provisioningState = 'Succeeded' } }
        $global:SIArmStore.Writes.Clear()
    }
    It 'a private install whose apps subnet has no route table: a warning naming the fix -- and NOTHING written' {
        $r = Get-SIUpdateReturnRouteReport -Arm $script:Arm -ResourceGroupId $script:Rg
        $r.Private | Should -BeTrue; $r.Warn | Should -BeTrue
        $r.Line | Should -Match 'snet-si-apps of this private install: it has no route table'
        $r.Line | Should -Match 'NOT changed by the updater'
        $r.Line | Should -Match '-Steps return-route'
        Writes | Should -BeNullOrEmpty
    }
    It 'a route table with a VirtualAppliance route: no warning; a public install: nothing at all' {
        Set-SIArmStoreItem @{ id = $script:RtSi; location = 'westeurope'; properties = @{ provisioningState = 'Succeeded'; routes = @(@{ name = 'x'; properties = @{ addressPrefix = '10.0.0.0/16'; nextHopType = 'VirtualAppliance'; nextHopIpAddress = $script:Fw } }) } }
        $sn = Get-SIArmStoreItem "$script:OwnVnet/subnets/snet-si-apps"; $sn['properties']['routeTable'] = [ordered]@{ id = $script:RtSi }
        (Get-SIUpdateReturnRouteReport -Arm $script:Arm -ResourceGroupId $script:Rg).Warn | Should -BeFalse
        $env = Get-SIArmStoreItem "$script:Rg/providers/Microsoft.App/managedEnvironments/cae-si"; $env['properties']['vnetConfiguration']['internal'] = $false
        $p = Get-SIUpdateReturnRouteReport -Arm $script:Arm -ResourceGroupId $script:Rg
        $p.Private | Should -BeFalse; $p.Warn | Should -BeFalse
    }
    It 'the updater script calls the report in its own block, after the private registry, and has no write path for routes' {
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'setup\Invoke-SIContainerUpdate.ps1'))
        $src | Should -Match '(?s)1b\. PRIVATE REGISTRY.+1c\. RETURN ROUTE.+Get-SIUpdateReturnRouteReport -Arm \$rrArm'
        $src | Should -Match "if \(\`$Method -ne 'GET'\) \{ throw 'the return-route report only reads' \}"
        $src | Should -Not -Match 'Set-SIReturnRoute|Invoke-SIPrivateNetworkReturnRoute'
    }
}

Describe '#1095 the wizard asks only on a private install that names a hub' {
    BeforeAll {
        $script:Spec = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'setup\install-parameters.json')) | ConvertFrom-Json
        $script:P = @{}; foreach ($k in 'returnRouteRanges', 'returnRouteNextHop') { $script:P[$k] = @($script:Spec.parameters | Where-Object { $_.key -eq $k })[0] }
    }
    It 'both answers are optional strings on the target page, explained in plain words' {
        foreach ($k in 'returnRouteRanges', 'returnRouteNextHop') { $script:P[$k] | Should -Not -BeNullOrEmpty; $script:P[$k].type | Should -Be 'string'; $script:P[$k].page | Should -Be 'target'; $script:P[$k].required | Should -BeNullOrEmpty }
        $script:P['returnRouteRanges'].help | Should -Match 'address ranges your people browse from'
        $script:P['returnRouteRanges'].help | Should -Match 'your hub firewall''s private IP, so replies find their way back'
    }
    It 'shown on private + hub; hidden without the hub or without private networking' -ForEach @(
        @{ V = @{ privateNetwork = $true; hubVnetId = '/subscriptions/x/resourceGroups/rg-hub/providers/Microsoft.Network/virtualNetworks/vnet-hub' }; Shown = $true }
        @{ V = @{ privateNetwork = $true; hubVnetId = '' }; Shown = $false }
        @{ V = @{ privateNetwork = $true }; Shown = $false }
        @{ V = @{ privateNetwork = $false; hubVnetId = '/subscriptions/x/resourceGroups/rg-hub/providers/Microsoft.Network/virtualNetworks/vnet-hub' }; Shown = $false }
    ) {
        foreach ($k in 'returnRouteRanges', 'returnRouteNextHop') { Test-SIInstallShowIf -Param $script:P[$k] -Values $V | Should -Be $Shown -Because $k }
    }
    It 'a config with the answers validates; the patterns refuse what is not a range or an address; a hidden answer is dropped' {
        $base = [ordered]@{ installId = 'si-test'; tenantId = '11111111-1111-1111-1111-111111111111'; subscriptionId = $script:Sub; privateNetwork = $true; vnetAddressPrefix = '10.20.0.0/24'
                            hubVnetId = $script:Hub; returnRouteRanges = '10.0.0.0/16, 10.2.0.0/16'; returnRouteNextHop = $script:Fw }
        $ok = Test-SIInstallConfig -Config ([pscustomobject]$base) -Spec $script:Spec
        $ok.Errors | Should -BeNullOrEmpty
        $ok.Values['returnRouteRanges'] | Should -Be '10.0.0.0/16, 10.2.0.0/16'
        $bad = [ordered]@{}; foreach ($k in $base.Keys) { $bad[$k] = $base[$k] }; $bad['returnRouteRanges'] = '10.0.0.0'; $bad['returnRouteNextHop'] = 'fw'
        @((Test-SIInstallConfig -Config ([pscustomobject]$bad) -Spec $script:Spec).Errors | Where-Object { $_ -match '^returnRoute' }) | Should -HaveCount 2
        $noHub = [ordered]@{}; foreach ($k in $base.Keys) { $noHub[$k] = $base[$k] }; $noHub.Remove('hubVnetId')
        (Test-SIInstallConfig -Config ([pscustomobject]$noHub) -Spec $script:Spec).Values.Contains('returnRouteRanges') | Should -BeFalse
    }
    It 'the target carries the answers (as given), and the install entry points have both parameters' {
        $t = New-Target
        @($t.ReturnRouteRanges) | Should -Be @('10.0.0.0/16', '10.2.0.0/16'); $t.ReturnRouteNextHop | Should -Be $script:Fw
        foreach ($f in 'Install-SecurityInsight.ps1', 'Install-SecurityInsight.Launcher.ps1', 'Install-SecurityInsight.psm1') {
            $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot "setup\$f"))
            $src | Should -Match '\[string\]\$ReturnRouteRanges,' -Because $f
            $src | Should -Match '\[string\]\$ReturnRouteNextHop,' -Because $f
        }
    }
}

Describe '#1095 setup and support: the install step, the end check, Set-SIPrivateNetworking -Steps return-route' {
    It 'the end check: answers set and the route in place = ok; not in place = a warning naming the fix (own spoke and customer)' {
        New-RouteWorld
        $t = New-Target
        $c = Get-SIPrivateNetworkReturnRouteCheck -Arm $script:Arm -Target $t
        $c.Checked | Should -BeTrue; $c.Ok | Should -BeFalse
        $c.Line | Should -Match 'the apps subnet snet-si-apps has no route table'
        $c.Fix | Should -Match ([regex]::Escape('-ReturnRouteRanges 10.0.0.0/16,10.2.0.0/16 -ReturnRouteNextHop 10.1.0.4 -Apply -Steps return-route'))
        $null = Set-SIReturnRoute -Arm $script:Arm -Target $t -Sleep $script:NoSleep
        (Get-SIPrivateNetworkReturnRouteCheck -Arm $script:Arm -Target $t).Ok | Should -BeTrue
        New-RouteWorld -Vnet $script:CustVnet -Customer
        (Get-SIPrivateNetworkReturnRouteCheck -Arm $script:Arm -Target (New-Target -Vnet $script:CustVnet)).Fix | Should -Match 'your network team: the RETURN ROUTE item'
        (Get-SIPrivateNetworkReturnRouteCheck -Arm $script:Arm -Target (New-Target -Ranges '' -NextHop '')).Checked | Should -BeFalse -Because 'no answers = nothing to check'
    }
    It 'the guided install: the private-network step makes it every run until ok; the health check reads it back (static)' {
        $gi = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'setup\_shared\SI-GuidedInstall.ps1'))
        $i = $gi.IndexOf("`$t['private-network'] = {"); $i | Should -BeGreaterThan 0
        $body = $gi.Substring($i, $gi.IndexOf("`$t['customer-managed-keys']", $i) - $i)
        $body.IndexOf("'Invoke-SIPrivateNetworkReturnRoute'") | Should -BeLessThan $body.IndexOf("'Invoke-SIPrivateNetworkEndpoints'")
        $body | Should -Match 'if \(\$rrNote\) \{ return \(New-SIInstallResult -State ''warning'''
        $gi | Should -Match "(?s)\`$t\['health-check'\] = \{.+'Get-SIPrivateNetworkReturnRouteCheck'"
    }
    It 'Set-SIPrivateNetworking: the step return-route (the same function), its parameters, its rollback' {
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'setup\Set-SIPrivateNetworking.ps1'))
        $src | Should -Match "'peer-to-hub', 'return-route',"
        $src | Should -Match '\[string\[\]\]\$ReturnRouteRanges = @\(\)'
        $src | Should -Match '\[string\]\$ReturnRouteNextHop = '''''
        $src | Should -Match "(?s)'return-route' \{\s+\`$bf\['tableCreated'\].+Set-SIReturnRoute -Arm \`$A -Target \`$tgt"
        $src | Should -Match "(?s)'return-route' \{\s+# what THIS run made"
    }
    It 'Set-SIPrivateNetworking: the PLAN says what return-route would do and writes nothing; -Apply makes it; the rollback removes it' {
        New-RouteWorld
        Set-SIArmStoreItem @{ id = "$script:Rg/providers/Microsoft.App/jobs/caj-si-flow"; location = 'westeurope'; properties = @{ provisioningState = 'Succeeded'; configuration = @{ triggerType = 'Schedule' } } }
        $global:SIArmStore.Writes.Clear()
        $base = @{ ResourceGroup = 'rg-si-x'; SubscriptionId = $script:Sub; VnetId = $script:OwnVnet; ReturnRouteRanges = @('10.0.0.0/16'); ReturnRouteNextHop = $script:Fw; Arm = $script:Arm
                   Sql = { param($a, $b, $c, $d, $e) , @() }; Graph = { param($m, $u, $b) & $global:SIArmStoreGraph $m $u $b }; Sleep = $script:NoSleep
                   RecordDirectory = (Join-Path $TestDrive 'rec'); Environment = 'pester'; ObserveMinutes = 0 }
        $cut = Join-Path $script:SIRoot 'setup\Set-SIPrivateNetworking.ps1'
        $plan = & $cut @base 6> $null
        $plan.Plan['return-route'].Action | Should -Be 'change'
        $plan.Plan['return-route'].Reason | Should -Match 'route table rt-si made: 10\.0\.0\.0/16 -> 10\.1\.0\.4 \(VirtualAppliance\), BGP route propagation off; attached to snet-si-apps'
        Writes | Should -BeNullOrEmpty -Because 'the plan writes nothing'
        $a = $base.Clone(); $a.Apply = $true; $a.Steps = @('return-route')
        $r = & $cut @a 6> $null
        @($r.Results)[0].Ok | Should -BeTrue -Because (@(@($r.Results)[0].Lines) -join ' | ')
        (Item "$script:OwnVnet/subnets/snet-si-apps").properties.routeTable.id | Should -Be $script:RtSi
        $again = & $cut @base 6> $null
        $again.Plan['return-route'].Action | Should -Be 'none' -Because 'idempotent'
        $rb = $base.Clone(); $rb.Rollback = $r.RecordPath; $rb.Apply = $true
        $null = & $cut @rb 6> $null
        Item $script:RtSi | Should -BeNullOrEmpty
        (Item "$script:OwnVnet/subnets/snet-si-apps").properties.routeTable | Should -BeNullOrEmpty
    }
}
