#Requires -Version 7.0
<#
    Audit #78 -- ExposureGraph SCOPE nodes must report a real ARM asset id.

    Azure_Recommendations_Summary / _Detailed are the only two reports whose asset set admits
    `subscriptions` and `resourcegroups` nodes (see the NodeLabel filter in their _Assets let).
    The asset profiler enumerated RESOURCES, not scopes, so every id chain fell through and the
    reports published a name beside a BLANK id.

    That was originally closed as "not a bug, the empty value is the honest answer". The reasoning
    was sound about the resolver and wrong about the world: EG carries the scope's ARM identity
    itself. Probed live 2026-08-30:

        subscriptions  node -> rawData.hierarchyIdentifier = its OWN subscription guid
        resourcegroups node -> rawData.hierarchyIdentifier = the PARENT subscription guid,
                               with NodeName holding the group name

    🪤 rawData.hierarchyType is the string "subscriptionid" on BOTH kinds, so it CANNOT distinguish
    them. The derivation must switch on NodeLabel. A future edit that "simplifies" this to
    hierarchyType would give every resource group a subscription's id -- silently, and only on
    rows nobody checks. That is what this file exists to prevent.

    #505 (CI design, V3-DATA-MODEL 2.21.1). The scope's ARM id is now derived in the _Assets let
    (`_scopeArmId`, before the summarize) and does two jobs: it is the node's AssetArmId when the node
    carries no AzureResourceId of its own, and through AssetArmId it is the DeviceKey the finding is
    joined to its CI with (`_ciKey` == the lower-case ARM id the CI links). The reported AssetId is the
    CI's id when a CI links the key, else `az:` + the ARM id -- so a scope that no CI links still has a
    real id, and a real CI id always wins. Retired: AssetScopeArmId, AssetProps, and the profile
    coalesce chain (AssetId / AssetId_From_CL / AzureResourceId) it was ranked against.

    Source assertions: the derivation is a property of the catalog, and running the reports needs a
    live tenant. The live proof is recorded in REQUIREMENTS.md #78 (520 names / 520 ids, 0
    misaligned, three real subscription ids).
#>

BeforeDiscovery {
    $script:Grains = @('Azure_Recommendations_Summary', 'Azure_Recommendations_Detailed')
}

BeforeAll {
    $script:CatalogPath = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) `
                            'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'
    $script:Catalog = Get-Content -Path $script:CatalogPath -Raw
    function script:Get-ReportQuery([string]$Name) {
        $b = [regex]::Match($script:Catalog, '(?s)- ReportName: ' + [regex]::Escape($Name) + '\r?\n(.*?)(?=\r?\n    - ReportName: |\z)').Groups[1].Value
        $i = $b.IndexOf('ReportQuery:')
        if ($i -lt 0) { return '' }
        $b.Substring($i)
    }
}

Describe 'audit #78 -- EG scope nodes carry an ARM asset id' {

    It 'the catalog exists' {
        Test-Path $script:CatalogPath | Should -BeTrue
    }

    It 'derives the scope ARM id exactly twice -- once per Azure_Recommendations grain' {
        ([regex]::Matches($script:Catalog, '\|\s*extend\s+_scopeArmId\s*=\s*case\(')).Count | Should -Be 2
        foreach ($g in $script:Grains) { Get-ReportQuery $g | Should -Match '\|\s*extend\s+_scopeArmId\s*=\s*case\(' -Because $g }
    }

    It 'switches on the NODE LABEL, never on hierarchyType' {
        # hierarchyType is "subscriptionid" on both node kinds -- see the trap note above.
        $script:Catalog | Should -Not -Match 'hierarchyType\s*==\s*"subscriptionid"'
        $script:Catalog | Should -Not -Match 'hierarchyType'
    }
}

Describe 'audit #78 -- report <_>' -ForEach $script:Grains {
    BeforeAll { $script:Q = Get-ReportQuery $_ }

    It 'reads the identity from rawData.hierarchyIdentifier, lower-cased like the ARM ids the CI links' {
        $script:Q | Should -Match ([regex]::Escape('| extend _egHierarchyId = tolower(tostring(NodeProperties.rawData.hierarchyIdentifier))'))
    }

    It 'builds a subscription id as /subscriptions/<guid>, only on a subscriptions node' {
        $script:Q | Should -Match 'NodeLabel\s*==\s*"subscriptions"\s+and\s+isnotempty\(_egHierarchyId\),\s*strcat\("/subscriptions/",\s*_egHierarchyId\)'
    }

    It 'builds a resource-group id under its parent subscription, lower-cased, only on a resourcegroups node' {
        $script:Q | Should -Match 'NodeLabel\s*==\s*"resourcegroups"\s+and\s+isnotempty\(_egHierarchyId\),\s*strcat\("/subscriptions/",\s*_egHierarchyId,\s*"/resourcegroups/",\s*tolower\(tostring\(NodeName\)\)\)'
    }

    It 'the node''s own ARM id wins; the scope id fills in only where the node carries none' {
        $script:Q | Should -Match ([regex]::Escape('| extend AssetArmId = iff(isnotempty(_armId), _armId, _scopeArmId)'))
    }

    It 'the ARM id is the CI link key (DeviceKey), joined to _ciKey' {
        $script:Q | Should -Match ([regex]::Escape('| extend DeviceKey = case(isnotempty(AssetArmId), AssetArmId, isnotempty(_senseId), _senseId, tolower(NodeId))'))
        $script:Q | Should -Match ([regex]::Escape('| join kind=leftouter (_ciLink) on $left.DeviceKey == $right._ciKey'))
        $script:Q.IndexOf('| extend _scopeArmId = case(') | Should -BeLessThan $script:Q.IndexOf('| join kind=leftouter (_ciLink) on $left.DeviceKey == $right._ciKey')
    }

    It 'carries the derived id THROUGH the summarize that would otherwise drop it' {
        $script:Q | Should -Match 'AssetArmId\s*=\s*any\(AssetArmId\)'
        $script:Q | Should -Match 'DeviceKey\s*=\s*any\(DeviceKey\)'
    }

    It 'the AssetId is the CI id first, then az: + the ARM id -- never blank for a scope' {
        # A scope id is a fallback for assets no CI links. If it ever outranked the CI id, a resource would report its
        # resource GROUP as its identity.
        $m = [regex]::Match($script:Q, '(?s)\|\s*extend\s+AssetId\s*=\s*case\((.*?)\)\r?\n')
        $m.Success | Should -BeTrue
        $chain = $m.Groups[1].Value
        $iCi  = $chain.IndexOf('isnotempty(si_ci_id)')
        $iArm = $chain.IndexOf('isnotempty(AssetArmId), strcat("az:", AssetArmId)')
        $iCi  | Should -BeGreaterOrEqual 0
        $iArm | Should -BeGreaterThan $iCi
    }
}
