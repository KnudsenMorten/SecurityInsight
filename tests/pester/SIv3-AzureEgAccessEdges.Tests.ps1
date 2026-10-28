#Requires -Version 5.1
<#
    AZURE: THE EXPOSURE GRAPH ACCESS-EDGE QUERY MATCHES THE LABELS THE GRAPH ACTUALLY USES (#145).

    Found on the live chain 2026-09-28: the query filtered TargetNodeLabel by short names ('storageaccount',
    'keyvault', ...) while the live graph labels Azure resources by ARM TYPE ('microsoft.keyvault/vaults',
    ...). Every run reported "EG access-edges: 0" although hundreds of identity -> storage / key vault
    'has permissions to' edges exist, so XENG_AccessedBy* was always empty. The live edge label is also
    'can authenticate to', not '... as'. Invoke-RestMethod is mocked with rows shaped like the live ones.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\asset-profiling\discovery\Get-DiscoveryFromAzureExposureGraph.ps1')
    function script:Get-SIGraphToken { param($Resource) 'tok' }
    $script:LiveShaped = [pscustomobject]@{ results = @(
        [pscustomobject]@{ SourceNodeId = 's1'; SourceNodeName = 'Some Admin'; SourceNodeLabel = 'user'
                           TargetNodeId = 'E831B0466FDA412D91B212300A5A56D9'; TargetNodeName = 'kv-ait-lic-mfn'
                           TargetNodeLabel = 'microsoft.keyvault/vaults'; EdgeLabel = 'has permissions to' }
    ) }
}

Describe 'the access-edge query targets ARM-typed resources' {
    # The function dot-sources the real token helper into its own scope, which hides a plain stub function; a Mock wins
    # (Pester answers it before any function), so no sign-in is attempted.
    BeforeAll { Mock Get-SIGraphToken { 'tok' } }
    AfterEach { Remove-Variable -Scope Global -Name SI_AzureExposureGraph_ResourceLabels -ErrorAction SilentlyContinue }

    It 'the default query matches ARM-typed targets (not only short names) and excludes role assignments' {
        $script:body = $null
        $script:ask = { param($q) $script:body = $q; [pscustomobject]@{ Ok = $true; Rows = @($script:LiveShaped.results); Error = '' } }
        $null = Get-AzureExposureGraphAccessEdges -Ask $script:ask
        $q = $script:body
        $q | Should -Match "TargetNodeLabel startswith 'microsoft\.'"
        $q | Should -Match "TargetNodeLabel !startswith 'microsoft\.authorization/'"
        $q | Should -Match "'can authenticate to'"
    }
    It 'a live-shaped edge lands in the map under the resource name and the node id' {
        $script:ask = { param($q) [pscustomobject]@{ Ok = $true; Rows = @($script:LiveShaped.results); Error = '' } }
        $m = Get-AzureExposureGraphAccessEdges -Ask $script:ask
        $m.ContainsKey('kv-ait-lic-mfn') | Should -BeTrue
        $m.ContainsKey('nodeid:e831b0466fda412d91b212300a5a56d9') | Should -BeTrue
        @($m['kv-ait-lic-mfn'])[0].EdgeLabel | Should -Be 'has permissions to'
    }
    It 'a customer''s own resource label list is honoured exactly (no widening)' {
        $global:SI_AzureExposureGraph_ResourceLabels = @('microsoft.keyvault/vaults')
        $script:body = $null
        $script:ask = { param($q) $script:body = $q; [pscustomobject]@{ Ok = $true; Rows = @($script:LiveShaped.results); Error = '' } }
        $null = Get-AzureExposureGraphAccessEdges -Ask $script:ask
        $q = $script:body
        $q | Should -Not -Match "startswith 'microsoft\.'"
        $q | Should -Match "TargetNodeLabel in~ \('microsoft\.keyvault/vaults'\)"
    }
}
