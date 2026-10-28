#Requires -Version 5.1
<#
    #675 -- IS A SUBSCRIPTION-LEVEL AZURE RECOMMENDATION GIVEN TOO HIGH A TIER IN A SLICED RUN? PROVED HERE: YES, IT WAS.

    Azure_Recommendations_* gave a subscription-level row no CI links the tier of the subscription's most critical CI:
        let _subTierG = _ciLink | where _ciKey startswith "/subscriptions/" | ... | summarize Tier_BySub = min(si_tier) by _sub;
    In a sliced run the hybrid path inlines _ciLink CUT PER SLICE on _ciKey (Get-SICLBucketKey -> SHA-256 bucket, aligned
    with the graph rows' DeviceKey). The subscription's row is in the slice its own key "/subscriptions/<id>" hashes to,
    and that slice holds only the CIs whose keys hash there too -- so the minimum is taken over a share of the
    subscription's CIs. When its tier-0 CI hashes elsewhere, the row is reported at the share's tier (here 3).

    The first Describe reproduces that with the engine's own inlining (no KQL is run: the slice's inlined rows are read
    and the summarize is evaluated over them). The second shows the fix: _subTierG is its own lookup, read once per run
    from SI_CI_CL (the canonical block RA-CiKql.ps1 generates), and -- keyed on nothing the slices are cut on -- copied
    whole into every slice, so every slice sees the subscription's real minimum.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-ProfileAugment.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-CiKql.ps1')
    function script:Write-Info  { param($m) }
    function script:Write-Diag  { param($m) }
    function script:Write-Warn2 { param($m) }
    function script:Write-Err2  { param($m) }
    function script:Invoke-LogAnalyticsKqlQuery { param($WorkspaceResourceId, $Query) }
    $script:Ws = '/subscriptions/x/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/w'
    $script:N = 8
    $script:SubKey = '/subscriptions/11111111-2222-3333-4444-555555555555'
    $script:SubSlice = Get-SISha256Bucket -Key $script:SubKey -BucketCount $script:N

    # The subscription's CIs: one tier-0 VM whose key hashes to ANOTHER slice than the subscription row, the rest tier 3.
    $vmKey = { param($i) ('{0}/resourcegroups/rg/providers/microsoft.compute/virtualmachines/vm{1}' -f $script:SubKey, $i) }
    $crit = 1; while ((Get-SISha256Bucket -Key (& $vmKey $crit) -BucketCount $script:N) -eq $script:SubSlice) { $crit++ }
    $sameSlice = 100; while ((Get-SISha256Bucket -Key (& $vmKey $sameSlice) -BucketCount $script:N) -ne $script:SubSlice) { $sameSlice++ }
    $script:Ci = @(
        [pscustomobject]@{ _ciKey = (& $vmKey $crit); si_tier = 0 }
        [pscustomobject]@{ _ciKey = (& $vmKey $sameSlice); si_tier = 3 }
        @(1..30 | Where-Object { $_ -ne $crit } | ForEach-Object { [pscustomobject]@{ _ciKey = (& $vmKey (200 + $_)); si_tier = 3 } })
    )

    function script:Reset-State {
        $script:_HybridRowsCache = @{}; $script:_HybridSnapshotCache = @{}; $script:_HybridBucketGroupsCache = @{}; $script:_HybridBucketGroupsWhole = @{}
        $script:_HybridColumnTypesCache = @{}; $script:_CrossDomainBucketCoalesce = @(); $script:_SkipEGBucketForCrossDomain = $false
        $script:_RALookupNeededKeySets = $null; $script:_LastHybridQueryBodyOverheadBytes = 0; $script:_LastHybridBytesPerRow = 0
    }
    # The engine's inlined rows of one binding in one slice (what the slice's KQL reads), from its own caches.
    function script:Get-SliceRows { param([string]$Var)
        $k = @($script:_HybridRowsCache.Keys | Where-Object { $_ -like ($Var + '|*') })[0]
        $g = '{0}::{1}' -f $k, $script:N
        @($script:_HybridBucketGroupsCache[$g][$script:SubSlice])
    }
    function script:Get-SubMin { param([object[]]$Rows)   # | where _ciKey startswith "/subscriptions/<id>" | summarize min(si_tier)
        $t = @($Rows | Where-Object { ([string]$_._ciKey).StartsWith($script:SubKey + '/') -or [string]$_._ciKey -eq $script:SubKey } | ForEach-Object { [int]$_.si_tier })
        if ($t.Count -eq 0) { return $null }
        ($t | Measure-Object -Minimum).Minimum
    }
}

Describe 'REPRODUCED -- _subTierG computed from the sliced _ciLink takes the minimum over one slice''s share' {
    BeforeEach { Reset-State; Mock Invoke-LogAnalyticsKqlQuery { $script:Ci } }

    It 'the whole subscription''s most critical CI is tier 0 (control)' {
        Get-SubMin -Rows $script:Ci | Should -Be 0
    }
    It 'the slice that holds the subscription row sees tier 3 -- the tier-0 CI is in another slice' {
        $q = "let _ciLink = SI_CI_CL | project _ciKey, si_tier;`nlet _subTierG = _ciLink | where _ciKey startswith ""/subscriptions/"" | summarize Tier_BySub = min(si_tier) by _sub;`nExposureGraphNodes"
        $null = Resolve-ProfileCLLetBlocks -Query $q -WorkspaceResourceId $script:Ws -BucketCount $script:N -BucketIndex $script:SubSlice
        $slice = Get-SliceRows -Var '_ciLink'
        $slice.Count | Should -BeLessThan $script:Ci.Count
        Get-SubMin -Rows $slice | Should -Be 3 -Because 'the defect: the subscription row would be reported at tier 3 although the subscription has a tier-0 CI'
    }
}

Describe 'FIXED -- _subTierG is its own lookup, read once per run and copied whole into every slice' {
    BeforeEach {
        Reset-State
        # Log Analytics answers the subscription block with the whole run's minimum per subscription
        Mock Invoke-LogAnalyticsKqlQuery { if ($Query -match 'Tier_BySub') { @([pscustomobject]@{ _sub = '11111111-2222-3333-4444-555555555555'; Tier_BySub = 0 }) } else { $script:Ci } }
    }
    It 'every slice carries the subscription''s real tier' {
        $y = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml')
        $m = [regex]::Match($y, '(?ms)//__SI_CI_SUBTIER_BEGIN__.*?//__SI_CI_SUBTIER_END__')
        $m.Success | Should -BeTrue
        $q = "let _ciLink = SI_CI_CL | project _ciKey, si_tier;`n" + $m.Value + "`nExposureGraphNodes"
        foreach ($b in 0..($script:N - 1)) {
            $out = Resolve-ProfileCLLetBlocks -Query $q -WorkspaceResourceId $script:Ws -BucketCount $script:N -BucketIndex $b
            $out | Should -Match 'let _subTierG = datatable'
            $out | Should -Match '"11111111-2222-3333-4444-555555555555",0'
        }
        $sub = @($script:_RAHybridLookups | Where-Object { $_.Name -eq '_subTierG' })[0]
        $sub.Whole | Should -BeTrue
        $sub.Rows  | Should -Be 1
        @($script:_RAHybridLookups | Where-Object { $_.Name -eq '_ciLink' })[0].Whole | Should -BeFalse -Because '_ciLink itself is still cut per slice'
    }
    It 'the four Azure recommendation reports and the two managed-identity attack-path reports read the subscription tier from the block, not from _ciLink' {
        $y = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml')
        # #690 (14): the two Defender recommendation reports took it from _ciLink too (the same defect) -- now the same block
        # (+2: Attack_Paths_*_Workload_ManagedIdentity_to_Azure_Resources -- a target no CI links takes its subscription's tier)
        ([regex]::Matches($y, '//__SI_CI_SUBTIER_BEGIN__')).Count | Should -Be 6
        $y | Should -Not -Match 'let _subTierG = _ciLink'
        $y | Should -Not -Match 'let _subTier = _ciLink'
    }
    It 'the block is the canonical one and uses the same CI set and one-CI-per-key rule as _ciLink' {
        $b = Get-RACiKqlBlock -Kind subtier -Classes @('cloud_resource', 'device')
        $l = Get-RACiKqlBlock -Kind link -Classes @('cloud_resource', 'device')
        foreach ($line in @('| where _ciKind != "seen"', '| where _ciBuild == toscalar(SI_CI_CL', '| where tostring(si_class) in ("cloud_resource", "device")', '| summarize arg_max(_ciBuild, *) by _ciKey', '| mv-expand _ciKey = _ciKeys to typeof(string)')) {
            $b | Should -Match ([regex]::Escape($line))
            $l | Should -Match ([regex]::Escape($line))
        }
        $kb = ([regex]::Match($b, '\| extend _ciKeys = [^\r\n]+')).Value
        $kl = ([regex]::Match($l, '\| extend _ciKeys = [^\r\n]+')).Value
        $kb | Should -Be $kl
        $b | Should -Not -Match ';[\s\S]*;' -Because 'the hybrid pre-fetcher cuts a binding at its first semicolon'
        $q = "x`n" + (ConvertTo-RACiIndentedBlock -Block $b -Indent '          ') + "`ny"
        Resolve-RACiBlocks -Query $q -StaleDays 30 | Should -Be $q
        (Resolve-RACiBlocks -Query $q -StaleDays 45) | Should -Match 'ago\(45d\)'
    }
}
