#Requires -Version 5.1
<#
    ENRICHMENT MUST READ KEYS THAT EXIST (#124).

      * Azure "accessed by a T0/T1 identity" had NEVER run: Invoke-Enrich required `$r.Name`, which a
        Collect record does not carry. The access edges were fetched every run and never used, so the
        XENG_AccessedBy* columns and the CrossEngine_AccessedByTieredIdentity evidence never existed.
        It now matches on the Exposure Graph NODE ID first (exact) and falls back to the resource name
        from the ARM id. (These proofs carry no TargetTier -- evidence, not a tier decision.)
      * KQL posture hits were looked up by `$r.EgNodeId` (never present) while they are BUILT keyed by
        the row's DeviceId / AccountObjectId -- so none could attach to an endpoint.
      * Discover's second-pass (AadDeviceId) merge moved the id to the higher-priority source but not
        the name -- the operator rule "name and id come from the same source", which the first pass
        already follows.
      * Collect's identity join tried DisplayName BEFORE the service-principal object id, against a
        first-wins name map -- an SP could take a same-named other object's EG flags.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:Stages = Join-Path $script:SIRoot 'engine\asset-profiling\stages'
    function script:Get-CodeNoComments([string]$Path) {
        $t = [regex]::Replace((Get-Content -LiteralPath $Path -Raw), '(?s)<#.*?#>', '')
        (($t -split "`r?`n") | ForEach-Object { $_ -replace '(^|\s)#.*$', '' }) -join "`n"
    }
    $script:Enrich   = Get-CodeNoComments (Join-Path $script:Stages 'Invoke-Enrich.ps1')
    $script:Discover = Get-CodeNoComments (Join-Path $script:Stages 'Invoke-Discover.ps1')
    $script:Collect  = Get-CodeNoComments (Join-Path $script:Stages 'Invoke-Collect.ps1')
}

Describe 'Get-AzureExposureGraphAccessEdges indexes an edge by node id AND by name' {
    BeforeAll {
        # The real token helper is loaded so Pester has a command to mock; it is never called.
        . (Join-Path $script:SIRoot 'auth\Get-SIGraphToken.ps1')
        . (Join-Path $script:SIRoot 'engine\asset-profiling\discovery\Get-DiscoveryFromAzureExposureGraph.ps1')
    }
    It 'one edge row is reachable under the node-id key and under the lowercased name' {
        Mock Get-SIGraphToken { 'tok' }
        Mock Invoke-RestMethod {
            [pscustomobject]@{ results = @(
                [pscustomobject]@{ SourceNodeId = 's1'; SourceNodeName = 'AdminUser'; SourceNodeLabel = 'user'
                                   TargetNodeId = 'N-ABC'; TargetNodeName = 'KV-Prod'; TargetNodeLabel = 'microsoft.keyvault/vaults'; EdgeLabel = 'has permissions to' }
            ) }
        }
        $map = Get-AzureExposureGraphAccessEdges
        $map.ContainsKey('nodeid:n-abc') | Should -BeTrue
        $map.ContainsKey('kv-prod')      | Should -BeTrue
        @($map['nodeid:n-abc'])[0].SourceName | Should -Be 'AdminUser'
    }
}

Describe 'WIRING -- the enrich stage uses keys a Collect record actually has' {
    It 'the azure access-edge block no longer requires $r.Name' {
        $script:Enrich | Should -Not -Match "Engine -eq 'azure' -and \`$r\.Metadata\.AZ_ResourceId -and \`$r\.Name"
        $script:Enrich | Should -Not -Match '\(\[string\]\$r\.Name\)\.ToLowerInvariant\(\)'
    }
    It 'it matches the EG node id first, then the name from the ARM id' {
        $script:Enrich | Should -Match "'nodeid:' \+ \(\[string\]\`$r\.Metadata\.AZ_NodeId\)\.ToLowerInvariant\(\)"
        $script:Enrich | Should -Match "\(\(\[string\]\`$r\.Metadata\.AZ_ResourceId\)\.TrimEnd\('/'\) -split '/'\)\[-1\]"
    }
    It 'posture hits are looked up by MDE_DeviceId, not the non-existent $r.EgNodeId' {
        $script:Enrich | Should -Not -Match '\$r\.EgNodeId'
        $script:Enrich | Should -Match '\$assetKey = if \(\$r\.Metadata\.MDE_DeviceId\)'
    }
}

Describe 'WIRING -- name and id travel together, exact ids beat names' {
    It 'the second-pass AadDeviceId merge moves the Name with the AssetId' {
        $script:Discover | Should -Match '(?s)if \(\$newPri -gt \$oldPri\) \{\s*\$primary\.AssetId = \$rec\.AssetId.{0,300}\$primary\.Name = \$rec\.Name'
    }
    It 'Collect tries the SP object id and UPN BEFORE the display name' {
        # #642 the lookup lives in Find-SIIdentityEgHit: the exact ids (object id, UPN) are tried in a loop that returns
        # before the name loop (ENTRA_DisplayName, Name) is reached
        $m = [regex]::Match($script:Collect, '(?s)function Find-SIIdentityEgHit \{.*?\n\}')
        $m.Success | Should -BeTrue
        $f = $m.Value
        $iSp   = $f.IndexOf("'ENTRA_SPObjectId'")
        $iUpn  = $f.IndexOf("'ENTRA_UPN'")
        $iRet  = $f.IndexOf('Hit = $Map[$k]; ByName = $false }')
        $iDisp = $f.IndexOf("'ENTRA_DisplayName'")
        $iSp   | Should -BeGreaterThan 0
        $iUpn  | Should -BeGreaterThan 0
        $iRet  | Should -BeGreaterThan $iUpn -Because 'an exact-id hit returns before any name is tried'
        $iSp   | Should -BeLessThan $iDisp
        $iUpn  | Should -BeLessThan $iDisp
        $iRet  | Should -BeLessThan $iDisp
        $f | Should -Match "(?s)'ENTRA_DisplayName'.{0,400}ByName = \`$true"
        # and Collect uses it, handing the name flag on so a name hit never gives the node's ids
        $script:Collect | Should -Match 'Find-SIIdentityEgHit -Map \$identityEgMap -Asset \$a'
        $script:Collect | Should -Match 'Get-SIIdentityEgFields -Hit \$eh\.Hit -ByName \(\[bool\]\$eh\.ByName\)'
    }
    It 'a hit by name gives no id of the node (EG_NodeId / EG_AccountObjectId), an exact-id hit does' {
        $m = [regex]::Match($script:Collect, '(?s)function Get-SIIdentityEgFields \{.*?\n\}')
        $m.Success | Should -BeTrue
        $sb = [scriptblock]::Create($m.Value); . $sb
        $map = @{ 'shared name' = @{ EG_NodeId = 'n1'; EG_AccountObjectId = 'o1'; EG_Active = $true }; 'sp-1' = @{ EG_NodeId = 'n2'; EG_AccountObjectId = 'sp-1' } }
        $m2 = [regex]::Match($script:Collect, '(?s)function Find-SIIdentityEgHit \{.*?\n\}'); . ([scriptblock]::Create($m2.Value))
        $byName = Find-SIIdentityEgHit -Map $map -Asset @{ ENTRA_SPObjectId = 'sp-9'; ENTRA_DisplayName = 'Shared Name' }
        $byName.ByName | Should -BeTrue
        $fn = Get-SIIdentityEgFields -Hit $byName.Hit -ByName $byName.ByName
        $fn.Contains('EG_NodeId') | Should -BeFalse
        $fn.Contains('EG_AccountObjectId') | Should -BeFalse
        $fn['EG_Active'] | Should -BeTrue
        $byId = Find-SIIdentityEgHit -Map $map -Asset @{ ENTRA_SPObjectId = 'SP-1'; ENTRA_DisplayName = 'Shared Name' }
        $byId.ByName | Should -BeFalse
        (Get-SIIdentityEgFields -Hit $byId.Hit -ByName $byId.ByName)['EG_NodeId'] | Should -Be 'n2'
    }
}
