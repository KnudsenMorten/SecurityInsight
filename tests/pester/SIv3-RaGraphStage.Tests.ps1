#Requires -Version 7.0
<#
    THE ATTACK-PATH REPORTS FROM VULNERABLE DEVICES TO AZURE, READ ONCE PER RUN AND JOINED IN SQL (REQUIREMENTS #1275 stage 2,
    engine\risk-analysis\_shared\RA-GraphPathStage.ps1) -- the parts that need no database:
      * THE SHAPE: the locked queries (read by the engine's own YAML reader) are the ones the port was written for (pinned
        hash); a changed query, a customer's own, a slice cut on another key, weights the generator did not write -> runs as
        before. Every form the engine sends is read: unsliced / a slice / a sub-slice, the excluded configuration ids, a row
        split, a count, a group count (the Summary's), the cross-domain slice key of the Summary.
      * THE WEIGHTS: the generated block read back equals its generator for product / max / sum-of-deltas / a cap / quotes,
        and the factor and detail equal what the generated KQL computes (hand-worked).
      * THE TAIL (Detailed, Summary): the CI joins, the in-scope rule, the target's CI, the asset fallbacks, the columns and
        their types, the excluded ids, the sort -- hand-worked rows.
      * THE READS: the part filter is the slices' hash-modulo; the two reads carry the query's node table and edge labels.
      * THE LOAD's failure rules with a fake database: a defect or a part refused every round fails the load and every report
        that needs it ("lookup unavailable", never retried, never split), the failure is remembered for the run, a worker
        never loads.
      * WIRING (asserted separately -- green units never prove reachability): the hook sits in Invoke-GraphHuntingQuery after
        the 504 stop is taken and before any route; the engine loads the file; the producer loads the graph before its
        workers and writes it in the manifest; a worker reads it and never loads; the run's end removes it.
#>

BeforeAll {
    . (Join-Path $PSScriptRoot '_RaGraphStageTest.ps1')
    $script:QD = Get-RAGsCatalogQuery Detailed
    $script:QS = Get-RAGsCatalogQuery Summary
    $script:SummaryCross = @(@{ ClColumn = 'Source_AadDeviceId'; EgNativeKey = 'AadDeviceId' }, @{ ClColumn = 'Target_AzureResourceId_Guid' })
}

Describe 'the query shape' {
    It 'pins both locked queries (a change to either needs the port changed with it)' {
        Get-RAGpsShapeHash -Query $script:QD | Should -Be $script:RAGpsShapeHash.Detailed
        Get-RAGpsShapeHash -Query $script:QS | Should -Be $script:RAGpsShapeHash.Summary
    }
    It 'reads every form the engine sends' {
        $s = Get-RAGpsQueryShape -Query (Get-RAGsRendered -Query $script:QD)
        $s.Ok | Should -BeTrue; $s.Grain | Should -Be 'Detailed'; $s.Count | Should -Be 1; $s.Kind | Should -Be 'rows'
        $s = Get-RAGpsQueryShape -Query (Get-RAGsRendered -Query $script:QD -Count 16 -Index 11)
        $s.Ok | Should -BeTrue; $s.Count | Should -Be 16; $s.Index | Should -Be 11
        $s = Get-RAGpsQueryShape -Query (Get-RAGsRendered -Query $script:QD -Count 512 -Index 300 -FinalIds @('PC-1->x', 'a"b') -RowCount 4 -RowIndex 3 -AsCount)
        $s.Ok | Should -BeTrue; $s.Count | Should -Be 512; $s.Index | Should -Be 300; $s.RowCount | Should -Be 4; $s.RowIndex | Should -Be 3; $s.Kind | Should -Be 'count'
        @($s.FinalIds) | Should -Be @('PC-1->x', 'a"b')
        $s = Get-RAGpsQueryShape -Query (Get-RAGsRendered -Query $script:QS -Count 8 -Index 2 -CrossDomain $script:SummaryCross -AsCount -GroupKeys @('SecurityDomain', 'CriticalityTier', 'cmdbId'))
        $s.Ok | Should -BeTrue; $s.Grain | Should -Be 'Summary'; $s.Kind | Should -Be 'groups'; @($s.GroupColumns) | Should -Be @('SecurityDomain', 'CriticalityTier', 'cmdbId')
        $s = Get-RAGpsQueryShape -Query (Get-RAGsRendered -Query $script:QS -Count 8 -Index 2 -CrossDomain $script:SummaryCross)
        $s.Ok | Should -BeTrue; $s.Count | Should -Be 8; $s.Index | Should -Be 2
    }
    It 'leaves every other query as it is' {
        (Get-RAGpsQueryShape -Query 'DeviceInfo | take 1').Ok | Should -BeFalse
        (Get-RAGpsQueryShape -Query (Get-RAGsRendered -Query ($script:QD -replace 'tolower\(TargetAzureAssetId\)', 'toupper(TargetAzureAssetId)'))).Why | Should -Match 'not the one'
        (Get-RAGpsQueryShape -Query (Get-RAGsRendered -Query ($script:QD -replace '\[bridge\*0\.\.3\]', '[bridge*0..4]'))).Ok | Should -BeFalse
        # a slice cut on another column than the device key
        $q = (Get-RAGsRendered -Query $script:QD -Count 4 -Index 1) -replace "tostring\(column_ifexists\('DeviceKey',''\)\)", "tostring(column_ifexists('MdeDeviceId','')), tostring(column_ifexists('DeviceKey',''))"
        (Get-RAGpsQueryShape -Query $q).Why | Should -Match 'MdeDeviceId'
        # the yaml's default weights block (not generated) is not read
        (Get-RAGpsQueryShape -Query $script:QD).Why | Should -Match 'weights'
        # a form nobody sends
        (Get-RAGpsQueryShape -Query ((Get-RAGsRendered -Query $script:QD) + "`n| take 5")).Ok | Should -BeFalse
    }
    It 'answers nothing without the result in the database, and says so once' {
        Reset-RAGsState
        $script:RAStreamOn = $false; $script:RAStream = $null
        Get-RAGraphStagePlan -Query (Get-RAGsRendered -Query $script:QD) | Should -BeNullOrEmpty
        Get-RAGraphStagePlan -Query (Get-RAGsRendered -Query $script:QD) | Should -BeNullOrEmpty
        @($script:RAGsLog | Where-Object { $_ -match 'keeps its result in memory' }).Count | Should -Be 1
    }
}

Describe 'the weights' {
    It 'reads back exactly what the generator writes, and computes what the KQL computes' -ForEach @(
        @{ Combine = 'product'; Max = 0; Row = @{ cmdbCriticality = ' High '; cmdbDataSensitivity = 'Confidential' }; Factor = 195; Detailed = 'cmdbCriticality= High ;cmdbDataSensitivity=Confidential' }
        @{ Combine = 'product'; Max = 180; Row = @{ cmdbCriticality = 'HIGH'; cmdbDataSensitivity = 'Confidential' }; Factor = 180; Detailed = 'cmdbCriticality=HIGH;cmdbDataSensitivity=Confidential' }
        @{ Combine = 'max'; Max = 0; Row = @{ cmdbCriticality = 'low'; cmdbDataSensitivity = 'x' }; Factor = 100; Detailed = 'cmdbCriticality=low' }
        @{ Combine = 'sum-of-deltas'; Max = 0; Row = @{ cmdbCriticality = 'Medium'; cmdbDataSensitivity = 'Confidential' }; Factor = 140; Detailed = 'cmdbCriticality=Medium;cmdbDataSensitivity=Confidential' }
        @{ Combine = 'product'; Max = 0; Row = @{ }; Factor = 100; Detailed = '' }
    ) {
        $cfg = [pscustomobject]@{ Path = ''; Engine = 'endpoint'; Combine = $Combine; MaxMultiplier = [double]$Max; Fields = @(
            [pscustomobject]@{ field = 'cmdbCriticality'; valueMap = [pscustomobject]@{ High = 150; Medium = 110; Low = 90; 'say "hi"' = 120 }; default = 100 },
            [pscustomobject]@{ field = 'cmdbDataSensitivity'; valueMap = [pscustomobject]@{ Confidential = 130 }; default = '' }) }
        $block = Build-WeightedFactorsKql -Config $cfg
        $back = ConvertFrom-RAGpsWeightBlock -Block $block
        $back | Should -Not -BeNullOrEmpty
        (Build-WeightedFactorsKql -Config $back) | Should -BeExactly $block
        $w = Get-RAGpsWeight -Row $Row -Config $back
        $w.Factor | Should -Be $Factor
        $w.Detailed | Should -BeExactly $Detailed
    }
    It 'the empty block (no weights) is factor 100 and no detail' {
        $b = Build-WeightedFactorsKql -Config ([pscustomobject]@{ Path = ''; Engine = 'x'; Combine = 'product'; MaxMultiplier = 0.0; Fields = @() })
        $cfg = ConvertFrom-RAGpsWeightBlock -Block $b
        (Build-WeightedFactorsKql -Config $cfg) | Should -BeExactly $b
        $w = Get-RAGpsWeight -Row @{ cmdbCriticality = 'High' } -Config $cfg
        $w.Factor | Should -Be 100; $w.Detailed | Should -Be ''
    }
}

Describe 'the reads' {
    It 'cuts a read into parts on the same hash the slices use, and halves a part losslessly' {
        Get-RAGpsPartFilter -Column 'NodeId' -Pages 1 -Page 0 | Should -Be ''
        Get-RAGpsPartFilter -Column 'SourceNodeId' -Pages 6 -Page 4 | Should -Be '| where (tolong(strcat("0x", substring(hash_sha256(SourceNodeId), 0, 8))) % 6) == 4'
        # a row in part 4 of 6 is in part 4 or 10 of 12, never elsewhere
        foreach ($t in 'a', 'b', 'node-17', 'x' * 40) { $h = Get-RAGsHash8 $t; if (($h % 6) -eq 4) { ($h % 12) | Should -BeIn @(4, 10) } }
        (Get-RAGsHash8 'abc') | Should -Be 3128432319   # tolong(strcat("0x", substring(hash_sha256("abc"), 0, 8))) in advanced hunting, 2026-11-18
    }
    It 'reads the query node table and the six edge labels' {
        $n = Get-RAGpsNodeKql -Pages 4 -Page 1
        foreach ($t in 'set_has_element(Categories, "device")', 'hasHighOrCritical', 'SenseDeviceId', 'mv-apply rf = RiskFactorsArray', 'maxCvssScore', '"identity"', '"secret"', '"environmentAzure"', '% 4) == 1', 'Bh = iff(V == 1') { $n | Should -Match ([regex]::Escape($t)) }
        $e = Get-RAGpsEdgeKql -Count
        $e | Should -Match ([regex]::Escape('"contains", "has credentials of", "frequently logged in by", "can authenticate as", "member of", "has role on"'))
        $e | Should -Match '\| count$'
        # the target / scope tests of the query, word for word, evaluated at read time
        $pairs = @(
            @('AzureAsset.NodeLabel =~ "microsoft.storage/storageaccounts"', 'NodeLabel =~ "microsoft.storage/storageaccounts"')
            @('RoleScope.NodeLabel in~ ("subscriptions", "resourcegroups", "microsoft.resources/subscriptions", "microsoft.resources/resourcegroups")', 'NodeLabel in~ ("subscriptions", "resourcegroups", "microsoft.resources/subscriptions", "microsoft.resources/resourcegroups")')
            @('AzureAsset.NodeLabel startswith "microsoft."', 'NodeLabel startswith "microsoft."')
            @('not(AzureAsset.NodeLabel startswith "microsoft.resources/")', 'not(NodeLabel startswith "microsoft.resources/")')
            @('not(AzureAsset.NodeLabel startswith "microsoft.authorization/")', 'not(NodeLabel startswith "microsoft.authorization/")'))
        foreach ($p in $pairs) {
            $script:QD | Should -Match ([regex]::Escape($p[0])); $script:QS | Should -Match ([regex]::Escape($p[0]))
            (Get-RAGpsNodeKql) | Should -Match ([regex]::Escape($p[1]))
        }
    }
}

Describe 'the rest of the query, row for row' {
    BeforeAll {
        $script:Link = New-RAGpsCiIndex -Key '_ciKey' -Columns @('_ciKey', 'si_ci_id', 'si_class', 'si_asset_name', 'si_tier', 'si_cmdb_id', 'si_cmdb_name', 'si_cmdb_criticality', 'si_cmdb_data_sensitivity', 'si_rf_p', 'si_rf_names_', 'si_in_scope_') -Rows @(
            [pscustomobject]@{ _ciKey = 'mde-a'; si_ci_id = 'CI-A'; si_class = 'device'; si_asset_name = 'Laptop A'; si_tier = '1'; si_cmdb_id = 'C1'; si_cmdb_name = 'Cmdb A'; si_cmdb_criticality = 'High'; si_cmdb_data_sensitivity = ''; si_rf_p = '["internet_exposed"]'; si_rf_names_ = '["InternetExposed"]'; si_in_scope_ = 'true' }
            [pscustomobject]@{ _ciKey = 'mde-out'; si_ci_id = 'CI-O'; si_class = 'device'; si_asset_name = 'Out'; si_tier = '0'; si_cmdb_id = ''; si_cmdb_name = ''; si_cmdb_criticality = ''; si_cmdb_data_sensitivity = ''; si_rf_p = '[]'; si_rf_names_ = '[]'; si_in_scope_ = 'false' })
        $script:Peer = New-RAGpsCiIndex -Key '_peerKey' -Columns @('_peerKey', 'peer_tier', 'peer_cmdb_id', 'peer_cmdb_name', 'peer_cmdb_criticality', 'peer_cmdb_data_sensitivity') -Rows @(
            [pscustomobject]@{ _peerKey = 'res-1'; peer_tier = '0'; peer_cmdb_id = 'T1'; peer_cmdb_name = 'Store'; peer_cmdb_criticality = 'High'; peer_cmdb_data_sensitivity = 'Confidential' })
        $script:Enrich = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($k in 'KA', 'KB', 'KO') { $script:Enrich[$k] = New-Object System.Collections.Generic.List[object] }
        $script:Enrich['KA'].Add(@{ DeviceKey = 'mde-a'; RiskFactorSet = '["b_rf","a_rf"]' })
        $script:Enrich['KB'].Add(@{ DeviceKey = 'node-b'; RiskFactorSet = '[]' })
        $script:Enrich['KO'].Add(@{ DeviceKey = 'mde-out'; RiskFactorSet = '[]' })
        $script:Paths = @(
            [ordered]@{ _K = 'KA'; EntryPointDeviceId = 'NODE-A'; EntryPointDevice = 'PC-A'; TargetAzureAssetId = 'RES-1'; TargetAzureAsset = 'store1'; TargetLabel = 'microsoft.storage/storageaccounts'
                        EntryVectors = @('Interactive logon'); DeviceEdges = @('frequently logged in by'); CredentialNodes = @(); FirstHopLabels = @('user'); ReachedIdentities = @('', 'Group 1')
                        ViaRoleScope = 'rg1'; ViaRoleScopeType = 'resourcegroups'; MaxCvssScore = 9.8; TargetType = 'Storage account'; AttackPathName = 'Device with high severity vulnerabilities allows lateral movement to Azure storage account' }
            [ordered]@{ _K = 'KB'; EntryPointDeviceId = 'Node-B'; EntryPointDevice = 'PC-B'; TargetAzureAssetId = 'res-2'; TargetAzureAsset = 'web2'; TargetLabel = 'microsoft.web/sites'
                        EntryVectors = @('SAS token'); DeviceEdges = @('contains'); CredentialNodes = @('s1'); FirstHopLabels = @('azure-storage-shared-access-signature'); ReachedIdentities = @('App')
                        ViaRoleScope = 'sub'; ViaRoleScopeType = 'subscriptions'; MaxCvssScore = $null; TargetType = 'Azure resource'; AttackPathName = 'Device with high severity vulnerabilities allows lateral movement to Azure resource' }
            [ordered]@{ _K = 'KO'; EntryPointDeviceId = 'node-o'; EntryPointDevice = 'PC-O'; TargetAzureAssetId = 'res-2'; TargetAzureAsset = 'web2'; TargetLabel = 'microsoft.web/sites'
                        EntryVectors = @(); DeviceEdges = @(); CredentialNodes = @(); FirstHopLabels = @(); ReachedIdentities = @(); ViaRoleScope = ''; ViaRoleScopeType = ''; MaxCvssScore = 5.0; TargetType = 'Azure resource'; AttackPathName = 'x' })
    }
    It 'Detailed: the CI joins, the in-scope rule, the target CI, the fallbacks, the types and the sort' {
        $rows = ConvertTo-RAGpsDetailedRows -Paths $script:Paths -Enrich $script:Enrich -Link $script:Link -Peer $script:Peer -Weights $null
        $rows.Count | Should -Be 2   # the out-of-scope CI's device is left out (si_in_scope_ false)
        $a = $rows[0]; $b = $rows[1]
        $a.EntryPointDevice | Should -Be 'PC-A'
        $a.ConfigurationId | Should -BeExactly 'PC-A->store1'               # a storage target by its name
        $b.ConfigurationId | Should -BeExactly 'PC-B->res-2'                # any other target by its id
        $a.AssetName | Should -Be 'Laptop A'; $a.AssetId | Should -Be 'CI-A'; $a.AssetType | Should -Be 'Endpoint'
        $b.AssetName | Should -Be 'PC-B'; $b.AssetId | Should -Be 'node-b'; $b.AssetType | Should -Be 'Device'
        $a.CriticalityTier | Should -BeOfType [int]; $a.CriticalityTier | Should -Be 0; $a.CriticalityTierLevel | Should -Be 'Critical - tier 0'
        $b.CriticalityTier | Should -BeNullOrEmpty; $b.CriticalityTierLevel | Should -Be ''
        $a.cmdbName | Should -Be 'Store'; $b.cmdbName | Should -Be ''
        $a.SecuritySeverity | Should -Be 'Very High'; $b.SecuritySeverity | Should -Be 'Low'; $b.Impact | Should -BeNullOrEmpty
        $a.RiskFactor_Probability | Should -BeOfType [long]; $a.RiskFactor_Probability | Should -Be 3
        $a.RiskFactor_Probability_Detailed | Should -BeExactly 'InternetExposed;a_rf;b_rf'
        $a.RiskFactorIds | Should -Be 'internet_exposed'
        $a.RiskScore_Weight_Factor | Should -Be 100; $a.RiskScore_Weight_Detailed | Should -Be ''
        @($a.PSObject.Properties.Name) | Should -Be @('SecurityDomain', 'Category', 'Subcategory', 'ConfigurationName', 'ConfigurationId', 'AssetName', 'AssetId', 'AssetType', 'Impact', 'SecuritySeverity',
            'CriticalityTier', 'CriticalityTierLevel', 'RiskFactor_Consequence', 'RiskFactor_Probability', 'RiskFactor_Probability_Detailed', 'RiskFactorIds',
            'RiskScore_Weight_Detailed', 'RiskScore_Weight_Factor', 'RiskFactor_Weight', 'cmdbId', 'cmdbName', 'cmdbCriticality', 'cmdbDataSensitivity',
            'EntryPointDevice', 'EntryVectors', 'ReachedIdentities', 'TargetAzureAsset', 'ViaRoleScope', 'ViaRoleScopeType', 'MaxCvssScore', 'CredentialNodes')
    }
    It 'Detailed: the weights read the row as the query has it at that point, and the excluded ids go' {
        $cfg = [pscustomobject]@{ Combine = 'product'; MaxMultiplier = 0.0; Fields = @([pscustomobject]@{ field = 'cmdbCriticality'; valueMap = [pscustomobject]@{ high = 150 }; default = 100 }) }
        $rows = ConvertTo-RAGpsDetailedRows -Paths $script:Paths -Enrich $script:Enrich -Link $script:Link -Peer $script:Peer -Weights $cfg -FinalIds @('PC-B->res-2')
        $rows.Count | Should -Be 1
        $rows[0].RiskScore_Weight_Factor | Should -Be 150; $rows[0].RiskFactor_Weight | Should -Be 150; $rows[0].RiskScore_Weight_Detailed | Should -Be 'cmdbCriticality=High'
    }
    It 'Summary: the groups, their sets and counts, and the columns after them' {
        $sp = @(
            [ordered]@{ _K = 'KA'; EntryPointDeviceId = 'NODE-A'; EntryPointDevice = 'PC-A'; MaxCvssScore = 7.5; FirstHopLabel = 'user'; DeviceEdge = 'frequently logged in by'; TargetAzureAssetId = 'res-1'; TargetAzureAsset = 'store1'; TargetLabel = 'microsoft.storage/storageaccounts'; TargetType = 'Storage account'; AttackPathName = 'P1' }
            [ordered]@{ _K = 'KA'; EntryPointDeviceId = 'NODE-A'; EntryPointDevice = 'PC-A'; MaxCvssScore = 7.5; FirstHopLabel = 'group'; DeviceEdge = 'contains'; TargetAzureAssetId = 'res-3'; TargetAzureAsset = 'store3'; TargetLabel = 'microsoft.storage/storageaccounts'; TargetType = 'Storage account'; AttackPathName = 'P1' }
            [ordered]@{ _K = 'KB'; EntryPointDeviceId = 'Node-B'; EntryPointDevice = 'PC-B'; MaxCvssScore = $null; FirstHopLabel = 'user'; DeviceEdge = 'contains'; TargetAzureAssetId = 'res-1'; TargetAzureAsset = 'store1'; TargetLabel = 'microsoft.storage/storageaccounts'; TargetType = 'Storage account'; AttackPathName = 'P1' })
        $rows = ConvertTo-RAGpsSummaryRows -Paths $sp -Enrich $script:Enrich -Link $script:Link -Weights $null
        $rows.Count | Should -Be 2   # tier 1 (PC-A's CI) and no tier (PC-B, no CI)
        $t1 = $rows | Where-Object { $_.CriticalityTier -eq 1 }
        $t1.UniqueIssues | Should -Be 2; $t1.ImpactedAssetCount | Should -Be 1; $t1.AssetName | Should -Be 'PC-A'; $t1.AssetId | Should -Be 'CI-A'
        @($t1.ImpactedAssetPairs) | Should -Be @('PC-A|CI-A'); @($t1.IssueList) | Should -Be @('store1', 'store3')
        $t1.Impact | Should -Be 7.5; $t1.SecuritySeverity | Should -Be 'High'; $t1.RiskFactor_Probability | Should -Be 3
        $nt = $rows | Where-Object { $null -eq $_.CriticalityTier }
        $nt.CriticalityTierLevel | Should -Be ''; $nt.AssetId | Should -Be 'node-b'; $nt.Impact | Should -BeNullOrEmpty; $nt.SecuritySeverity | Should -Be 'Low'
        @($rows[0].PSObject.Properties.Name)[-5..-1] | Should -Be @('ImpactedAssetCount', 'UniqueIssues', 'ImpactedAssetsList', 'ImpactedAssetPairs', 'IssueList')
    }
    It 'a slice split by row keeps every row in exactly one part' {
        $rows = ConvertTo-RAGpsDetailedRows -Paths $script:Paths -Enrich $script:Enrich -Link $script:Link -Peer $script:Peer -Weights $null
        $seen = 0
        for ($p = 0; $p -lt 3; $p++) { $seen += @($rows | Where-Object { (Get-RAGpsRowSplitPart -Row $_ -RowCount 3) -eq $p }).Count }
        $seen | Should -Be $rows.Count
    }
    It 'the entry vectors, as the query names them' {
        Get-RAGpsEntryVector -DeviceEdge 'Contains' -FirstHopLabel 'entra-userCookie' | Should -Be 'Entra session cookie'
        Get-RAGpsEntryVector -DeviceEdge 'contains' -FirstHopLabel 'Entra-userCookie' | Should -Be 'Other secret: Entra-userCookie'   # == is case-sensitive
        Get-RAGpsEntryVector -DeviceEdge 'HAS CREDENTIALS OF' -FirstHopLabel 'user' | Should -Be 'Owner / cached credential'
        Get-RAGpsEntryVector -DeviceEdge 'frequently logged in by' -FirstHopLabel 'user' | Should -Be 'Interactive logon'
    }
}

Describe 'the load fails closed (a fake database)' {
    BeforeAll {
        $script:Fake = {
            param($Sql, $Params, $Mode)
            if ($Mode -eq 'scalar' -and $Sql -match '^SELECT CASE WHEN OBJECT_ID') { return 1 }
            if ($Sql -match 'SCOPE_IDENTITY') { return 7 }
            if ($Sql -match 'OPENJSON\(@j\)') { return @(ConvertFrom-Json -InputObject ([string]$Params.j)).Count }
            if ($Mode -eq 'reader') { return , @() }
            0
        }
        $script:Fake | Add-Member -NotePropertyName SISqlSession -NotePropertyValue $true
        $script:Stream = @{ Invoke = $script:Fake; Grain = 'Detailed'; RunKey = 'Detailed|2026-11-18T01:00:00.000' }
        $script:G = New-RAGsGraph -Devices 6
    }
    BeforeEach { Reset-RAGsState }
    It 'a query defect on one part fails the load, the error is "lookup unavailable", remembered for the run' {
        $hunt = New-RAGsHunt -Graph $script:G -OnPart { param($s, $m, $i, $c) if ($s -eq 'Edges') { throw "Query could not be parsed: Syntax error" } }
        { Sync-RAGraphStage -Stream $script:Stream -Hunt $hunt -Pause { } } | Should -Throw
        $e = $null; try { Sync-RAGraphStage -Stream $script:Stream -Hunt $hunt -Pause { } } catch { $e = $_ }
        Test-RALookupUnavailableError -Err $e | Should -BeTrue
        Get-RABucketFailureAction -Err $e | Should -Be 'Fail'         # never retried, never split
        $script:RAGpsSetFailed | Should -Match 'could not be read'
        @($script:RAGsLog | Where-Object { $_ -match 'are not complete this run and keep their last complete result' }).Count | Should -Be 1
    }
    It 'a part refused as busy in every round fails the load (never a smaller graph)' {
        $hunt = New-RAGsHunt -Graph $script:G -OnPart { param($s, $m, $i, $c) if ($s -eq 'Nodes') { throw '429 Too Many Requests' } }
        { Sync-RAGraphStage -Stream $script:Stream -Hunt $hunt -Pause { } } | Should -Throw
        $script:RAGpsSetFailed | Should -Match 'still refused'
    }
    It 'a worker never loads (its producer did, or the report is not complete)' {
        $script:RAGpsWorker = $true
        $hunt = New-RAGsHunt -Graph $script:G
        $e = $null; try { Sync-RAGraphStage -Stream $script:Stream -Hunt $hunt } catch { $e = $_ }
        Test-RALookupUnavailableError -Err $e | Should -BeTrue
        $script:RAGsCalls.Count | Should -Be 0
    }
}

Describe 'wiring' {
    BeforeAll {
        $script:GH = Get-Content -Raw -LiteralPath (Join-Path $script:RAGsRoot 'engine\risk-analysis\_shared\RA-GraphHunting.ps1')
        $script:RA = Get-Content -Raw -LiteralPath (Join-Path $script:RAGsRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1')
        $script:Schema = Get-Content -Raw -LiteralPath (Join-Path $script:RAGsRoot 'sql\si-data-schema.sql')
    }
    It 'the hunting call asks the port first, after the 504 stop is taken and before any route' {
        $f = $script:GH.Substring($script:GH.IndexOf('function Invoke-GraphHuntingQuery'))
        $hook = $f.IndexOf('Get-RAGraphStagePlan -Query $Query')
        $hook | Should -BeGreaterThan 0
        $f.IndexOf('$script:RAGatewayTimeoutStopAt = 0') | Should -BeLessThan $hook
        $f.IndexOf('Add-DynamicGroupKeyCasts') | Should -BeGreaterThan $hook
        $f.IndexOf('Invoke-SISentinelLakeQuery') | Should -BeGreaterThan $hook
        $f.Substring($hook, 900) | Should -Match 'Invoke-RAGraphStageAnswer -Plan \$__gpsPlan'
        $f.Substring($hook, 900) | Should -Match 'Get-SIHuntingNotAheadText'
    }
    It 'the engine loads the port; the producer loads the graph before its workers and hands it over; a worker never loads; the run end removes it' {
        $script:RA | Should -Match ([regex]::Escape(". (Join-Path `$PSScriptRoot '_shared/RA-GraphPathStage.ps1')"))
        $script:RA | Should -Match '\$script:RAGpsWorker = \$true'
        $script:RA | Should -Match "\`$script:RAScaleManifest\['GraphStage'\]"
        $p = $script:RA.IndexOf('Test-RAGraphStageNeeded -Queries $queries'); $p | Should -BeGreaterThan 0
        $script:RA.IndexOf("`$m['GraphStage'] = `$gps") | Should -BeGreaterThan $p
        $script:RA.IndexOf('Write-RAScaleOutManifest -Store $store -Manifest $m') | Should -BeGreaterThan $script:RA.IndexOf("`$m['GraphStage'] = `$gps")
        $script:RA | Should -Match 'try \{ Complete-RAGraphStageRun \}'
    }
    It 'the schema carries the scratch tables (additive, keyed by the run)' {
        foreach ($t in 'RaGraphRun', 'RaGraphNode', 'RaGraphEdge', 'RaGraphCP', 'RaGraphST') { $script:Schema | Should -Match ("IF OBJECT_ID\('sidata.$t'\) IS NULL") }
    }
}
