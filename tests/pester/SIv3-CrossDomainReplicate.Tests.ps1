#Requires -Version 5.1
<#
    WITH THE EXPOSURE-GRAPH BUCKET FILTER OFF, EVERY BUCKET GETS EVERY CL LOOKUP ROW -- AND ONE BUCKET IS THE REPORT (#401).

    A report whose CL lookup is keyed on a column the Exposure-Graph side cannot partition on (a cross-domain
    key: Target_AzureResourceId_Guid, Source_AadDeviceId, _si_PrimaryEntityId, ...) runs with the EG-side
    bucket filter OFF, so every bucket query processes EVERY graph row. The CL lookups were still SPLIT per
    bucket, so a device's profile row was in ONE bucket: that bucket emitted its attack path with the SI
    asset id (AssetType Endpoint), the other seven with the Entra device id (AssetType Device), and the
    de-duplication kept both. Measured on rc6 2026-10-07:
    Attack_Paths_Detailed_Device_with_high_severity_vulnerabilities_allows_lateral_movement_Azure 189 rows
    for 147 real ones (7 devices x 21 paths), the doubled devices changing from run to run.

    Now: the filter off => every binding is REPLICATED (budget permitting), so every bucket query is the
    complete query, and the bucket loop keeps the first complete bucket and skips the rest.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-ProfileAugment.ps1')
    function script:Write-Info  { param($m) }
    function script:Write-Err2  { param($m) }
    function script:Write-Warn2 { param($m) $script:Warned += , [string]$m }
    function script:Invoke-LogAnalyticsKqlQuery { param($WorkspaceResourceId, $Query) }
    $script:Ws = '/subscriptions/x/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/w'

    # #505 -- the locked catalog no longer has a cross-domain LA binding: every report reads its assets through the CI
    # link block (`_ciLink`, keyed by `_ciKey`, an EG-aligned key). The engine mechanism stays (a custom report can
    # still bind a cross-domain key), so it is pinned on a SYNTHETIC fixture in the shape the defect had: two LA
    # bindings, each keyed on a cross-domain column. The mechanism keys on the binding's COLUMNS, not on the table.
    $script:LetTarget = @'
let _TargetCmdb = SI_CI_CL
    | where tostring(si_class) == "cloud_resource"
    | project Target_AzureResourceId_Guid = tolower(tostring(si_link_azure)), Target_cmdbName = tostring(si_cmdb_name), Target_cmdbId = tostring(si_cmdb_id),
              Target_cmdbCriticality = tostring(si_cmdb_criticality), Target_cmdbDataSensitivity = tostring(si_cmdb_data_sensitivity), Target_Tier_From_CL = toint(si_tier),
              Target_AssetName_From_CL = tostring(si_asset_name), Target_AssetId_From_CL = tostring(si_ci_id), Target_AssetType_From_CL = tostring(si_class)
    | where isnotempty(Target_AzureResourceId_Guid);
'@
    $script:LetSource = @'
let _SourceCmdb = SI_CI_CL
    | where tostring(si_class) == "device"
    | project Source_AadDeviceId = tolower(tostring(si_link_entra)), Source_AssetName = tostring(si_asset_name), Source_AssetId = tostring(si_ci_id), Source_AssetType = tostring(si_class),
              Source_Tier = toint(si_tier), Source_cmdbId = tostring(si_cmdb_id), Source_cmdbName = tostring(si_cmdb_name), Source_cmdbCriticality = tostring(si_cmdb_criticality),
              Source_cmdbDataSensitivity = tostring(si_cmdb_data_sensitivity)
    | where isnotempty(Source_AadDeviceId);
'@
    $script:Tail = @'
ExposureGraphNodes
| where 1 == 1
| join kind=leftouter (_TargetCmdb) on $left.NodeId == $right.Target_AzureResourceId_Guid
| join kind=leftouter (_SourceCmdb) on $left.NodeId == $right.Source_AadDeviceId
'@

    $script:TargetRows = @(1..20 | ForEach-Object {
        [pscustomobject]@{ Target_AzureResourceId_Guid = ('{0:x32}' -f (1000 + $_)); Target_cmdbName = "app$_"; Target_cmdbId = "c$_"; Target_cmdbCriticality = 'High'
                           Target_cmdbDataSensitivity = 'Internal'; Target_Tier_From_CL = 1; Target_AssetName_From_CL = "sa$_"; Target_AssetId_From_CL = "SI-AZ-$_"; Target_AssetType_From_CL = 'Azure' } })
    $script:SourceRows = @(1..8 | ForEach-Object {
        [pscustomobject]@{ Source_AadDeviceId = ('{0:d8}-0000-0000-0000-000000000000' -f $_); Source_AssetName = "dev$_"; Source_AssetId = "SI-EP-$_"; Source_AssetType = 'Endpoint'
                           Source_Tier = 0; Source_cmdbId = ''; Source_cmdbName = ''; Source_cmdbCriticality = ''; Source_cmdbDataSensitivity = '' } })

    function script:Reset-HybridState {
        $script:_HybridRowsCache = @{}; $script:_HybridSnapshotCache = @{}; $script:_HybridBucketGroupsCache = @{}
        $script:_CrossDomainBucketCoalesce = @(); $script:_SkipEGBucketForCrossDomain = $false; $script:_RACrossDomainReplicated = $false
        $script:_LastHybridQueryBodyOverheadBytes = 0; $script:Warned = @()
    }
}

Describe 'EG-side filter off: every bucket carries every row of every CL lookup (#401)' {
    BeforeEach {
        Reset-HybridState
        Mock Invoke-LogAnalyticsKqlQuery { if ($Query -match 'Source_AadDeviceId') { $script:SourceRows } else { $script:TargetRows } }
    }

    It 'both fixture bindings are pre-fetched and inlined, and the cross-domain key raises the flag (control)' {
        $q = $script:LetTarget + "`n" + $script:LetSource + "`n" + $script:Tail
        $r = Resolve-ProfileCLLetBlocks -Query $q -WorkspaceResourceId $script:Ws -BucketCount 8 -BucketIndex 0
        $r | Should -Not -Match 'SI_CI_CL' -Because 'both bindings must be replaced by inlined datatables'
        ([regex]::Matches($r, 'let _(Target|Source)Cmdb = datatable\(')).Count | Should -Be 2
        Should -Invoke Invoke-LogAnalyticsKqlQuery -Times 2 -Exactly
        $script:_SkipEGBucketForCrossDomain | Should -BeTrue
    }

    It 'no binding in the locked catalog is keyed on a cross-domain column any more (the CI link key is EG-aligned)' {
        $y = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'))
        $lets = @([regex]::Matches($y, '(?ms)\blet\s+(\w+)\s*=\s*([^;]*?\bSI_[A-Za-z]+(?:_Profile)?_CL\b[^;]*?);'))
        $lets.Count | Should -BeGreaterThan 100 -Because 'the scanner must see the catalog''s pre-fetched bindings'
        $bad = @($lets | Where-Object { $_.Groups[2].Value -match '\b(Target_AzureResourceId_Guid|Source_AadDeviceId|Source_AssetId|Target_AssetId_From_CL|_si_PrimaryEntityId)\s*=' } | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique)
        $bad | Should -BeNullOrEmpty
    }

    It 'all 8 buckets inline all 8 source devices and all 20 targets -- the pre-fix split gave each device to ONE bucket' {
        $q = $script:LetTarget + "`n" + $script:LetSource + "`n" + $script:Tail
        foreach ($b in 0..7) {
            $r = Resolve-ProfileCLLetBlocks -Query $q -WorkspaceResourceId $script:Ws -BucketCount 8 -BucketIndex $b
            foreach ($s in $script:SourceRows) { $r | Should -Match ([regex]::Escape($s.Source_AadDeviceId)) -Because "bucket $b must hold device $($s.Source_AssetName)" }
            foreach ($t in $script:TargetRows) { $r | Should -Match ([regex]::Escape($t.Target_AzureResourceId_Guid)) -Because "bucket $b must hold target $($t.Target_AssetName_From_CL)" }
        }
        $script:_SkipEGBucketForCrossDomain | Should -BeTrue
        $script:_RACrossDomainReplicated    | Should -BeTrue
    }

    It 'every bucket query is the SAME query -- so a path resolves to the same asset identity in every bucket' {
        $q = $script:LetTarget + "`n" + $script:LetSource + "`n" + $script:Tail
        $all = @(0..7 | ForEach-Object { Resolve-ProfileCLLetBlocks -Query $q -WorkspaceResourceId $script:Ws -BucketCount 8 -BucketIndex $_ })
        @($all | Select-Object -Unique).Count | Should -Be 1
        $all[0] | Should -Not -Match 'SI_CI_CL'
    }

    It 'a binding inlined BEFORE the flag goes up is replicated too (the decision is made over ALL bindings first)' {
        # Reversed order: the flag now goes up on the FIRST binding; every binding must still be replicated.
        $q = $script:LetSource + "`n" + $script:LetTarget + "`n" + $script:Tail
        foreach ($b in 0..7) {
            $r = Resolve-ProfileCLLetBlocks -Query $q -WorkspaceResourceId $script:Ws -BucketCount 8 -BucketIndex $b
            foreach ($s in $script:SourceRows) { $r | Should -Match ([regex]::Escape($s.Source_AadDeviceId)) }
        }
    }

    It 'when the full lookups do not fit the request budget it keeps splitting -- and says so' {
        $script:_LastHybridQueryBodyOverheadBytes = [int](1MB * 0.75)      # budget falls to its 64KB floor
        $script:Big = @(1..900 | ForEach-Object {
            [pscustomobject]@{ Target_AzureResourceId_Guid = ('{0:x32}' -f (5000 + $_)); Target_cmdbName = ('n' * 40) + $_; Target_cmdbId = "c$_"; Target_cmdbCriticality = 'High'
                               Target_cmdbDataSensitivity = 'Internal'; Target_Tier_From_CL = 1; Target_AssetName_From_CL = "sa$_"; Target_AssetId_From_CL = "SI-AZ-$_"; Target_AssetType_From_CL = 'Azure' } })
        Mock Invoke-LogAnalyticsKqlQuery { $script:Big }
        $q = $script:LetTarget + "`n" + $script:Tail
        $r = Resolve-ProfileCLLetBlocks -Query $q -WorkspaceResourceId $script:Ws -BucketCount 8 -BucketIndex 0
        $script:_RACrossDomainReplicated | Should -BeFalse
        @($script:Big | Where-Object { $r -match [regex]::Escape($_.Target_AzureResourceId_Guid) }).Count | Should -BeLessThan 900
        ($script:Warned -join "`n") | Should -Match 'exceed the request budget'
    }
}

Describe 'EG-aligned lookups are untouched -- still split, EG-side filter stays on' {
    BeforeEach { Reset-HybridState }
    It 'an EpJoinKey binding is partitioned and raises neither flag' {
        $script:EpRows = @(1..16 | ForEach-Object { [pscustomobject]@{ EpJoinKey = "dev$_"; Tier = 1 } })
        Mock Invoke-LogAnalyticsKqlQuery { $script:EpRows }
        $q = "let _ep = SI_Endpoint_Profile_CL | project EpJoinKey = tostring(AadDeviceId), Tier = toint(Tier) | where isnotempty(EpJoinKey);`nExposureGraphNodes | join kind=leftouter (_ep) on `$left.DeviceKey == `$right.EpJoinKey"
        $seen = 0
        foreach ($b in 0..3) {
            $r = Resolve-ProfileCLLetBlocks -Query $q -WorkspaceResourceId $script:Ws -BucketCount 4 -BucketIndex $b
            $seen += @($script:EpRows | Where-Object { $r -match ('"' + $_.EpJoinKey + '"') }).Count
        }
        $seen | Should -Be 16                                     # each row in exactly one bucket
        $script:_SkipEGBucketForCrossDomain | Should -BeFalse
        $script:_RACrossDomainReplicated    | Should -BeFalse
    }
}

Describe 'CATALOG -- a make-graph node set holds ONE row per NodeId (#401)' {
    # make-graph keeps an ARBITRARY one of two node rows with the same id. An Azure VM with a vulnerable device
    # record was in VulnerableDevices (with NodeProperties) AND in AzureNodes (without), so the graph-match test
    # on Device.NodeProperties failed at random: measured live, the same query returned 105 / 126 / 126 rows
    # (5 / 6 / 6 of 7 devices) on three runs; with the vulnerable-device row winning, 147 / 147 / 147.
    BeforeAll {
        $y = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'))
        $script:GraphReports = @([regex]::Matches($y, '(?s)- ReportName: (\S+)\r?\n(.*?)(?=\r?\n    - ReportName: |\z)') |
            Where-Object { $_.Groups[2].Value -match 'make-graph\b' } | ForEach-Object { @{ Name = $_.Groups[1].Value; Body = $_.Groups[2].Value } })
    }
    It 'both lateral-movement reports are found' {
        @($script:GraphReports | Where-Object { $_.Name -like '*Device_with_high_severity_vulnerabilities_allows_lateral_movement_Azure' }).Count | Should -Be 2
    }
    It '<Name>: the node set lets the vulnerable-device row win over its unenriched copy' -ForEach @(
        @{ Name = 'Attack_Paths_Summary_Device_with_high_severity_vulnerabilities_allows_lateral_movement_Azure' }
        @{ Name = 'Attack_Paths_Detailed_Device_with_high_severity_vulnerabilities_allows_lateral_movement_Azure' }
    ) {
        $body = @($script:GraphReports | Where-Object { $_.Name -eq $Name })[0].Body
        $body | Should -Match 'let RelevantNodes = union VulnerableDevices, \(union Credentials, Identities, AzureNodes \| join kind=leftanti \(VulnerableDevices \| project NodeId\) on NodeId\);'
        $body | Should -Not -Match 'let RelevantNodes = union VulnerableDevices, Credentials, Identities, AzureNodes;'
    }
}

Describe 'WIRING -- the bucket loop keeps ONE complete bucket (#401)' {
    BeforeAll {
        $script:Eng = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'))
        $i0 = $script:Eng.IndexOf('$completeBucketDone = $false')
        $script:Loop = $script:Eng.Substring($i0, $script:Eng.IndexOf('# LATE-RETRY PASS', $i0) - $i0)
    }
    It 'the companion flag is reset per report, next to the EG-filter flag' {
        $script:Eng | Should -Match '(?s)\$script:_SkipEGBucketForCrossDomain = \$false\s*\r?\n(\s*#[^\r\n]*\r?\n)*\s*\$script:_RACrossDomainReplicated = \$false'
    }
    It 'records whether the EG filter was off BEFORE the bucket query is built (the flag goes up during the call)' {
        $script:Loop | Should -Match '(?s)\$egFilterOffAtBuild = \[bool\]\$script:_SkipEGBucketForCrossDomain\s*\r?\n\s*\$thisQuery\s*= Replace-BucketFilterBlock'
    }
    It 'a complete bucket replaces earlier rows and stops the loop' {
        $script:Loop | Should -Match '\$bucketIsComplete = \(\$egFilterOffAtBuild -and \[bool\]\$script:_RACrossDomainReplicated\)'
        $script:Loop | Should -Match '(?s)if \(\$completeBucketDone\) \{.*?break'
        $script:Loop | Should -Match '(?s)if \(\$bucketIsComplete\) \{.*?\$ResultAll = @\(\).*?\$completeBucketDone = \$true'
    }
    It 'a complete bucket supersedes failed and deferred buckets (no sub-bucket pass, no loss caveat)' {
        $script:Loop | Should -Match '(?s)if \(\$completeBucketDone\) \{\s*\$failedBucketIndices\.Clear\(\)\s*\$deferredBucketIndices\.Clear\(\)\s*Reset-RABucketLoss'
    }
}
