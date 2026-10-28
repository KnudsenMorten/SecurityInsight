#Requires -Version 5.1
<#
    #809 -- AN ATTACK PATH IS REPORTED ON THE RESOURCES, NEVER ON A SUBSCRIPTION OR RESOURCE GROUP (owner 2026-10-19, verbatim:
    "i dont think rg's and subs can be included in attack path findings. only the objects in the rg/subs. otherwise we will get
    3 same attack paths from the object + rg + sub").

    Every attack-path report whose final target can be a scope node (subscriptions / resourcegroups) replaces that target by the
    objects the scope contains -- the graph's own "contains" edges, subscription -> resource group -> resource, two levels -- and
    an object reached directly AND through its resource group AND its subscription is ONE path (one target id).

    Live on internal 2026-10-19 (read-only advanced hunting, the shipped queries before / after): Workload_ManagedIdentity
    Detailed 141 rows (9 with a resource-group target) -> 231 rows, 0 scope targets, every ConfigurationId unique; signin-front
    and ca-si-management reach the six / nine resources inside rg-si-r1-pro-ca. Device_with_high_severity Detailed 135 (23
    subscription targets) -> 1,217 resource rows; Identity_Group 1 row on an EMPTY resource group -> 0.

    Offline: source assertions on the shipped catalog (the queries need a live tenant), plus a model of the expansion's
    semantics -- the same steps in PowerShell -- that proves no duplicates and the resource-level expansion on a fixture.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\_shared\SI-Yaml.ps1')
    $script:Path = Join-Path $script:SIRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'
    $script:Catalog = ConvertFrom-SIYaml -Yaml ([IO.File]::ReadAllText($script:Path)) -SourceName $script:Path
    function script:CodeOf([string]$Name) {
        $r = @($script:Catalog.Reports | Where-Object { [string]$_.ReportName -eq $Name })[0]
        $r | Should -Not -BeNullOrEmpty -Because "$Name is in the catalog"
        ((@($r.ReportQuery) | ForEach-Object { [string]$_ }) -join "`n" -split "`r?`n" | Where-Object { $_.Trim() -notmatch '^//' }) -join "`n"
    }
    $script:ScopeLabels = @('subscriptions', 'resourcegroups', 'microsoft.resources/subscriptions', 'microsoft.resources/resourcegroups')

    # the expansion's semantics, step for step as the KQL: members = direct children + children of child resource groups,
    # distinct per (scope, member); a scope target joins its members (leftouter), is dropped when it has none, and the
    # report's final summarize is by (source, target) -- so object + RG + sub collapse to one path
    function script:Expand($Edges, $Contains) {
        $isScope = { param($l) $script:ScopeLabels -contains ([string]$l).ToLowerInvariant() }
        $members = @{}
        foreach ($c in $Contains) {
            if (-not (& $isScope $c.SourceLabel)) { continue }
            if (-not (& $isScope $c.ChildLabel) -and -not ([string]$c.ChildLabel).StartsWith('microsoft.authorization/')) {
                $members["$($c.Source)|$($c.Child)"] = [pscustomobject]@{ Scope = $c.Source; Id = $c.Child; Label = $c.ChildLabel }
            }
            if (@('resourcegroups', 'microsoft.resources/resourcegroups') -contains ([string]$c.ChildLabel).ToLowerInvariant()) {
                foreach ($g in @($Contains | Where-Object { $_.Source -eq $c.Child -and -not (& $isScope $_.ChildLabel) -and -not ([string]$_.ChildLabel).StartsWith('microsoft.authorization/') })) {
                    $members["$($c.Source)|$($g.Child)"] = [pscustomobject]@{ Scope = $c.Source; Id = $g.Child; Label = $g.ChildLabel }
                }
            }
        }
        $rows = foreach ($e in $Edges) {
            $m = @($members.Values | Where-Object { $_.Scope -eq $e.Target })
            if ($m.Count) { foreach ($x in $m) { [pscustomobject]@{ Source = $e.Source; Target = $x.Id; Label = $x.Label } } }
            elseif (-not (& $isScope $e.TargetLabel)) { [pscustomobject]@{ Source = $e.Source; Target = $e.Target; Label = $e.TargetLabel } }
        }
        @($rows | Group-Object Source, Target | ForEach-Object { $_.Group[0] })
    }
}

Describe '#809 every report with a scope target expands it to the objects inside (source)' -ForEach @(
    @{ Name = 'Attack_Paths_Summary_Github_to_Azure_Resources'; Anchor = 'extend DeviceKey = TargetNodeId' }
    @{ Name = 'Attack_Paths_Detailed_Github_to_Azure_Resources'; Anchor = 'extend DeviceKey = TargetNodeId' }
    @{ Name = 'Attack_Paths_Summary_Credential_Based_Lateral_Movement'; Anchor = 'extend DeviceKey = TargetNodeId' }
    @{ Name = 'Attack_Paths_Detailed_Credential_Based_Lateral_Movement'; Anchor = 'extend DeviceKey = TargetNodeId' }
    @{ Name = 'Attack_Paths_Summary_Identity_Group_Membership_to_Privileged_Resources'; Anchor = 'extend DeviceKey = FinalTargetId' }
    @{ Name = 'Attack_Paths_Detailed_Identity_Group_Membership_to_Privileged_Resources'; Anchor = 'extend DeviceKey = FinalTargetId' }
    @{ Name = 'Attack_Paths_Summary_Workload_ManagedIdentity_to_Azure_Resources'; Anchor = 'let Joined' }
    @{ Name = 'Attack_Paths_Detailed_Workload_ManagedIdentity_to_Azure_Resources'; Anchor = 'let Joined' }) {
    BeforeAll { $script:C = CodeOf $Name }
    It 'builds the scope members once, from the graph''s contains edges, two levels (subscription -> resource group -> resource)' {
        ([regex]::Matches($script:C, 'let _SI_ScopeMembers =')).Count | Should -Be 1
        $script:C | Should -Match 'let _SI_ScopeContains = ExposureGraphEdges\s*\|\s*where EdgeLabel =~ "contains" and SourceNodeLabel in~ \("subscriptions", "resourcegroups"'
        $script:C | Should -Match '_ChildLabel in~ \("resourcegroups", "microsoft\.resources/resourcegroups"\)[^\n]*\n\s*\|\s*join kind=inner \(_SI_ScopeContains'
        $script:C | Should -Match 'summarize _MemberName = take_any\(_MemberName\), _MemberLabel = take_any\(_MemberLabel\) by _ScopeNodeId, _MemberId;' -Because 'a resource is one member of a scope, however it is reached'
        $script:C | Should -Match 'not\(_ChildLabel startswith "microsoft\.authorization/"\)' -Because 'a lock or role assignment is not a resource'
    }
    It 'replaces a scope target by its members and drops a scope with none -- before the slice key, so the slice is the resource' {
        $i = $script:C.IndexOf('join kind=leftouter (_SI_ScopeMembers) on $left.TargetNodeId == $right._ScopeNodeId')
        $i | Should -BeGreaterThan 0
        $script:C.IndexOf($Anchor, $i) | Should -BeGreaterThan $i -Because "the expansion comes before '$Anchor'"
        $script:C | Should -Match 'where isnotempty\(_MemberId\) or not\(TargetNodeLabel in~ \("subscriptions", "resourcegroups", "microsoft\.resources/subscriptions", "microsoft\.resources/resourcegroups"\)\)'
        $script:C | Should -Match 'extend TargetNodeId = iff\(isnotempty\(_MemberId\), _MemberId, TargetNodeId\), TargetNodeName = iff\(isnotempty\(_MemberId\), _MemberName, TargetNodeName\), TargetNodeLabel = iff\(isnotempty\(_MemberId\), _MemberLabel, TargetNodeLabel\)'
    }
}

Describe '#809 the vulnerable-device reports reach the resources inside a subscription or resource group (source)' -ForEach @(
    @{ Name = 'Attack_Paths_Summary_Device_with_high_severity_vulnerabilities_allows_lateral_movement_Azure' }
    @{ Name = 'Attack_Paths_Detailed_Device_with_high_severity_vulnerabilities_allows_lateral_movement_Azure' }) {
    BeforeAll { $script:C = CodeOf $Name }
    It 'the graph walk ends on a resource -- never on a subscription or resource group' {
        $script:C | Should -Match 'RoleScope\.NodeLabel in~ \("subscriptions", "resourcegroups", "microsoft\.resources/subscriptions", "microsoft\.resources/resourcegroups"\) and AzureAsset\.NodeLabel startswith "microsoft\." and not\(AzureAsset\.NodeLabel startswith "microsoft\.resources/"\)'
        $script:C | Should -Not -Match 'AzureAsset\.NodeLabel in~ \("subscriptions"'
    }
}

Describe '#809 the Detailed device path is keyed by the resource id (no two resources share a key)' {
    It 'ConfigurationId names the device and the target''s id (the storage account keeps its unique name, so its key is unchanged)' {
        $c = CodeOf 'Attack_Paths_Detailed_Device_with_high_severity_vulnerabilities_allows_lateral_movement_Azure'
        $c | Should -Match 'extend ConfigurationId\s*= strcat\(EntryPointDevice, "->", iff\(TargetType == "Storage account", TargetAzureAsset, TargetAzureAssetId\)\)'
        $c | Should -Match 'by EntryPointDeviceId, EntryPointDevice, TargetAzureAssetId, TargetAzureAsset, TargetLabel'
    }
}

Describe '#809 the expansion semantics (model of the KQL steps)' {
    BeforeAll {
        $script:Contains = @(
            [pscustomobject]@{ Source = 'sub1'; SourceLabel = 'subscriptions'; Child = 'rg1'; ChildLabel = 'resourcegroups' }
            [pscustomobject]@{ Source = 'sub1'; SourceLabel = 'subscriptions'; Child = 'rgEmpty'; ChildLabel = 'resourcegroups' }
            [pscustomobject]@{ Source = 'rg1'; SourceLabel = 'resourcegroups'; Child = 'kv1'; ChildLabel = 'microsoft.keyvault/vaults' }
            [pscustomobject]@{ Source = 'rg1'; SourceLabel = 'resourcegroups'; Child = 'st1'; ChildLabel = 'microsoft.storage/storageaccounts' }
            [pscustomobject]@{ Source = 'rg1'; SourceLabel = 'resourcegroups'; Child = 'lock1'; ChildLabel = 'microsoft.authorization/locks' }
        )
    }
    It 'object + resource group + subscription is ONE path per resource -- no duplicates' {
        $edges = @(
            [pscustomobject]@{ Source = 'mi1'; Target = 'kv1'; TargetLabel = 'microsoft.keyvault/vaults' }
            [pscustomobject]@{ Source = 'mi1'; Target = 'rg1'; TargetLabel = 'resourcegroups' }
            [pscustomobject]@{ Source = 'mi1'; Target = 'sub1'; TargetLabel = 'subscriptions' }
        )
        $r = Expand $edges $script:Contains
        @($r | ForEach-Object { $_.Target } | Sort-Object) | Should -Be @('kv1', 'st1')
        @($r | Group-Object Source, Target | Where-Object Count -gt 1).Count | Should -Be 0
    }
    It 'a role on a subscription reaches the resources two levels down; no scope node is ever a target' {
        $r = Expand @([pscustomobject]@{ Source = 'mi2'; Target = 'sub1'; TargetLabel = 'subscriptions' }) $script:Contains
        @($r | ForEach-Object { $_.Target } | Sort-Object) | Should -Be @('kv1', 'st1')
        @($r | Where-Object { $script:ScopeLabels -contains $_.Label }).Count | Should -Be 0
        @($r | Where-Object { $_.Label -like 'microsoft.authorization/*' }).Count | Should -Be 0
    }
    It 'a role on an empty resource group is no finding (there is no object to report it on)' {
        @(Expand @([pscustomobject]@{ Source = 'g1'; Target = 'rgEmpty'; TargetLabel = 'resourcegroups' }) $script:Contains).Count | Should -Be 0
    }
    It 'a direct resource target is unchanged (control)' {
        $r = Expand @([pscustomobject]@{ Source = 'mi3'; Target = 'vm9'; TargetLabel = 'microsoft.compute/virtualmachines' }) $script:Contains
        $r.Target | Should -Be 'vm9'
    }
}
