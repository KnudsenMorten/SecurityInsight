#Requires -Version 5.1
<#
    AN ATTACK PATH TO AN AZURE RESOURCE NO CI LINKS STILL GETS A TIER -- FROM THE TARGET'S OWN RESOURCE TREE.

    Live 2026-10-23 (the largest install): the data sync warned "classification incomplete: 12,052 findings without a tier
    0-3", all from Attack_Paths_Detailed_Workload_ManagedIdentity_to_Azure_Resources (about 22,900 rows). The row's tier is
    the TARGET's CI tier (_ciPeer on the target's key); the report also expands a role on a subscription / resource group
    to every object inside it (the graph's contains edges), and many of those objects -- child resources (a key vault's
    secret, a storage account's container), resources no Azure profile row links -- have no CI. Their rows kept an empty
    tier, and the Pro data load could not fill it either: the row's asset is the WORKLOAD, not the target.

    The fix, from the rules the catalog already has (no constant): the target's CI tier, else the CI of the top-level
    resource it belongs to (#190 -- a child resource takes its parent's tier), else its subscription's most critical CI
    (#192 / #675 -- _subTierG, read whole once per run). A target none of them gives a tier keeps an empty level and stays
    counted by the data sync (the gap is said, never hidden).

    No KQL is run offline: (1) the tier chain is evaluated over real-shaped rows with the query's own key expression
    (split / array_slice semantics), old vs new; (2) the catalog text of both grains is asserted; (3) the engine's own
    inlining copies _subTierG whole into every slice of the report.
#>

BeforeDiscovery {
    $script:Names = 'Attack_Paths_Detailed_Workload_ManagedIdentity_to_Azure_Resources', 'Attack_Paths_Summary_Workload_ManagedIdentity_to_Azure_Resources'
}

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $y =[IO.File]::ReadAllText((Join-Path $script:SIRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'))
    $script:Catalog = $y.Substring(0, $y.IndexOf("`nReportTemplates:"))
    function script:Get-ReportBody([string]$Name) {
        $m = [regex]::Match($script:Catalog, '(?s)- ReportName: ' + [regex]::Escape($Name) + '\r?\n(.*?)(?=\r?\n    - ReportName: |\z)')
        if (-not $m.Success) { throw "no report $Name" }
        $m.Groups[1].Value
    }
    $script:Names = 'Attack_Paths_Detailed_Workload_ManagedIdentity_to_Azure_Resources', 'Attack_Paths_Summary_Workload_ManagedIdentity_to_Azure_Resources'

    # KQL: iff(k startswith "/subscriptions/" and array_length(split(k, "/")) > 9, strcat_array(array_slice(split(k, "/"), 0, 8), "/"), "")
    # (array_slice's end index is INCLUSIVE: elements 0..8 = "", subscriptions, <sub>, resourcegroups, <rg>, providers, <ns>, <type>, <name>)
    function script:Get-ParentKey([string]$Key) {
        $seg = $Key.Split('/')
        if ($Key.StartsWith('/subscriptions/') -and $seg.Count -gt 9) { return ($seg[0..8] -join '/') }
        ''
    }
    function script:Get-SubOfKey([string]$Key) { if ($Key.StartsWith('/subscriptions/')) { return $Key.Split('/')[2] }; '' }

    # real-shaped: lower-cased ARM ids as the graph's EntityIds give them, CI link keys as _ciPeer carries them
    $script:Sub = '0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0'
    $script:Vault = "/subscriptions/$($script:Sub)/resourcegroups/rg-app/providers/microsoft.keyvault/vaults/kv-app"
    $script:Peer = @{ $script:Vault = 1 }                                   # the vault has a CI (tier 1); its secret has none
    $script:SubTier = @{ $script:Sub = 0 }                                  # the subscription's most critical CI is tier 0
    $script:Rows = @(
        [pscustomobject]@{ T = 'ci';     TargetCiKey = $script:Vault }                                           # the target has a CI
        [pscustomobject]@{ T = 'parent'; TargetCiKey = "$($script:Vault)/secrets/app-secret" }                   # child resource
        [pscustomobject]@{ T = 'sub';    TargetCiKey = "/subscriptions/$($script:Sub)/resourcegroups/rg-data/providers/microsoft.storage/storageaccounts/stdata" }
        [pscustomobject]@{ T = 'none';   TargetCiKey = '9b1c0d6e5f4a3b2c1d0e9f8a7b6c5d4e' }                       # a graph node id only
    )
    function script:Get-OldTier($Row) { $t = $script:Peer[$Row.TargetCiKey]; if ($null -ne $t) { [int]$t } else { $null } }
    function script:Get-NewTier($Row) {
        $t = $script:Peer[$Row.TargetCiKey]; if ($null -ne $t) { return [int]$t }
        $p = Get-ParentKey $Row.TargetCiKey; if ($p -and $null -ne $script:Peer[$p]) { return [int]$script:Peer[$p] }
        $s = Get-SubOfKey $Row.TargetCiKey; if ($s -and $null -ne $script:SubTier[$s]) { return [int]$script:SubTier[$s] }
        $null
    }
}

Describe 'REPRODUCED -- a target no CI links gave the path no tier' {
    It 'with the CI-only rule three of four real-shaped paths have no tier' {
        @($script:Rows | Where-Object { $null -eq (Get-OldTier $_) }).Count | Should -Be 3
    }
}

Describe 'FIXED -- the target''s CI, else its top-level resource''s CI, else its subscription''s most critical CI' {
    It 'the key expression names the top-level resource of a child resource, and nothing for a top-level resource or a node id' {
        Get-ParentKey "$($script:Vault)/secrets/app-secret" | Should -Be $script:Vault
        Get-ParentKey "/subscriptions/$($script:Sub)/resourcegroups/rg/providers/microsoft.storage/storageaccounts/st/blobservices/default/containers/c" |
            Should -Be "/subscriptions/$($script:Sub)/resourcegroups/rg/providers/microsoft.storage/storageaccounts/st"
        Get-ParentKey $script:Vault | Should -Be ''
        Get-ParentKey '9b1c0d6e5f4a3b2c1d0e9f8a7b6c5d4e' | Should -Be ''
    }
    It 'each row takes the first tier its tree gives -- a CI tier is never second-guessed, and no constant fills the rest' {
        $got = @{}; foreach ($r in $script:Rows) { $got[$r.T] = Get-NewTier $r }
        $got['ci'] | Should -Be 1
        $got['parent'] | Should -Be 1
        $got['sub'] | Should -Be 0
        $got['none'] | Should -BeNullOrEmpty -Because 'a target nothing gives a tier stays empty and is counted by the data sync'
    }
    It 'every row is kept (never fewer rows than the source)' {
        @($script:Rows | ForEach-Object { Get-NewTier $_ }).Count | Should -Be $script:Rows.Count
    }
}

Describe 'the catalog: both grains carry the chain' {
    It '<_> -- the parent key is a needed key of _ciPeer and the query computes it with the SAME line' -ForEach $script:Names {
        $b = Get-ReportBody $_
        $line = '| extend TargetParentCiKey = iff(TargetCiKey startswith "/subscriptions/" and array_length(split(TargetCiKey, "/")) > 9, strcat_array(array_slice(split(TargetCiKey, "/"), 0, 8), "/"), "")'
        ([regex]::Matches($b, [regex]::Escape($line))).Count | Should -Be 2 -Because 'once under LookupNeededKeys, once in the query'
        $b | Should -Match ([regex]::Escape('| project __siNeeded = pack_array(SourceCiKey, TargetCiKey, TargetParentCiKey)'))
    }
    It '<_> -- the tier is the CI''s, else the parent''s, else the subscription''s, joined after the target''s CI' -ForEach $script:Names {
        $b = Get-ReportBody $_
        # the parent's CI is joined on a key that is never empty (#400: an empty key matches every other empty key)
        $b | Should -Match ([regex]::Escape('| join kind=leftouter (_ciPeer | where isnotempty(_peerKey) | project TargetParentCiKey = _peerKey, Tier_ByParent = peer_tier) on TargetParentCiKey'))
        $b | Should -Match ([regex]::Escape('| join kind=leftouter (_subTierG) on $left._tSub == $right._sub'))
        $b | Should -Match ([regex]::Escape('| extend TargetCriticalityTier = coalesce(toint(TargetCriticalityTier), toint(Tier_ByParent), toint(Tier_BySub))'))
        $iT = $b.IndexOf('Target_si_ci_id = peer_ci_id'); $iC = $b.IndexOf('coalesce(toint(TargetCriticalityTier)'); $iTier = $b.IndexOf('| extend CriticalityTier = toint(TargetCriticalityTier)')
        ($iT -lt $iC -and $iC -lt $iTier) | Should -BeTrue
        $b | Should -Match '(?s)//__SI_CI_SUBTIER_BEGIN__.*let _subTierG =.*//__SI_CI_SUBTIER_END__.*let WorkloadIdentity ='
        $b | Should -Not -Match 'coalesce\([^)]*TargetCriticalityTier[^)]*,\s*[0-3]\s*\)' -Because 'no static tier is invented'
    }
    It '<_> -- the subscription block is the canonical one (the engine regenerates it identically)' -ForEach $script:Names {
        . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-CiKql.ps1')
        $b = Get-ReportBody $_
        $blk = [regex]::Match($b, '(?ms)^[ \t]*//__SI_CI_SUBTIER_BEGIN__.*?//__SI_CI_SUBTIER_END__').Value
        $blk | Should -Not -BeNullOrEmpty
        ((Resolve-RACiBlocks -Query $blk -StaleDays 30) -replace "`r", '') | Should -Be ($blk -replace "`r", '')
    }
}

Describe 'the engine: _subTierG travels whole into every slice of the report' {
    BeforeAll {
        . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-ProfileAugment.ps1')
        . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-CiKql.ps1')
        function script:Write-Info  { param($m) }
        function script:Write-Diag  { param($m) }
        function script:Write-Warn2 { param($m) }
        function script:Write-Err2  { param($m) }
        function script:Invoke-LogAnalyticsKqlQuery { param($WorkspaceResourceId, $Query) }
    }
    BeforeEach {
        $script:_HybridRowsCache = @{}; $script:_HybridSnapshotCache = @{}; $script:_HybridBucketGroupsCache = @{}; $script:_HybridBucketGroupsWhole = @{}
        $script:_HybridColumnTypesCache = @{}; $script:_CrossDomainBucketCoalesce = @(); $script:_SkipEGBucketForCrossDomain = $false
        $script:_RALookupNeededKeySets = $null; $script:_LastHybridQueryBodyOverheadBytes = 0; $script:_LastHybridBytesPerRow = 0
        Mock Invoke-LogAnalyticsKqlQuery { if ($Query -match 'Tier_BySub') { @([pscustomobject]@{ _sub = $script:Sub; Tier_BySub = 0 }) } else { @() } }
    }
    It 'each of 4 slices inlines the subscription''s tier' {
        $b = Get-ReportBody $script:Names[0]
        $blk = [regex]::Match($b, '(?ms)//__SI_CI_SUBTIER_BEGIN__.*?//__SI_CI_SUBTIER_END__').Value
        $q = $blk + "`nExposureGraphNodes"
        foreach ($i in 0..3) {
            $out = Resolve-ProfileCLLetBlocks -Query $q -WorkspaceResourceId '/subscriptions/x/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/w' -BucketCount 4 -BucketIndex $i
            $out | Should -Match 'let _subTierG = datatable'
            $out | Should -Match ('"{0}",0' -f [regex]::Escape($script:Sub))
        }
    }
}
