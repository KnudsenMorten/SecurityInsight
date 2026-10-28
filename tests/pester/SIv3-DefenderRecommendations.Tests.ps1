#Requires -Version 5.1
<#
    EVERY DEFENDER FOR CLOUD RECOMMENDATION REACHES SI -- NONE LOST, NONE DOUBLED, NEVER A PARTIAL LIST (#147, #149).

    Measured on the internal tenant 2026-09-28: 9,618 unhealthy Defender for Cloud recommendations on 369
    resources; the Exposure Graph carried 46 of those resources, so the recommendation reports could never
    show the rest. The azure engine now collects them into SI_AzureRecommendation_CL:
      * container-image / cloud-posture sub-entities (8,819 of 9,618) roll up per (parent, recommendation),
        entities counted and listed -- conservation is exact;
      * the same assessment returned twice (a paging overlap) is ONE finding;
      * the query SORTS -- unsorted Resource Graph paging repeated ~226 rows per read and skipped as many;
      * an incomplete read publishes NOTHING (the previous snapshot stays the latest).
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $d = Join-Path $script:SIRoot 'engine\asset-profiling\discovery'
    . (Join-Path $d 'Invoke-SIArgPaged.ps1')
    . (Join-Path $d 'Get-SIDefenderRecommendations.ps1')
    $script:Sub = '/subscriptions/11111111-1111-1111-1111-111111111111'
    $reg = "$script:Sub/resourceGroups/rg/providers/Microsoft.ContainerRegistry/registries/acr1"
    function script:New-RawAssessment($id, $rid, $rec, $sev, $type = 'microsoft.keyvault/vaults', $img = '', $name = 'kv1', $cvss = '') {
        [pscustomobject]@{ AssessmentId = $id; AssessmentKey = ($id -split '/')[-1]; ResourceId = $rid; ResourceName = $name; ResourceType = $type
            ResourceSource = 'Azure'; SubscriptionId = '11111111-1111-1111-1111-111111111111'; ResourceGroup = 'rg'; Recommendation = $rec; Severity = $sev
            RecommendationCategory = 'x'; SecurityIssue = 'y'; Categories = ''; Tactics = ''; Threats = ''; Description = ''; Remediation = ''
            ImplementationEffort = ''; UserImpact = ''; PortalLink = 'portal.azure.com/#x'; RiskLevel = ''; RiskFactors = ''; FirstEvaluated = ''
            StatusChanged = ''; MaxCvssScore = $cvss; ImageUri = $img }
    }
    $script:Raw = @(
        (New-RawAssessment 'a1' "$script:Sub/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv1" 'Enable purge protection' 'Medium'),
        (New-RawAssessment 'a2' $script:Sub 'Enable Defender plans' 'High' '' '' 'sub'),
        (New-RawAssessment 'a3' "$reg/securityentitydata/img-a" 'Update gpgv' 'Medium' '.containerimage' 'acr1.azurecr.io/app@sha256:a' 'app' '6.7'),
        (New-RawAssessment 'a4' "$reg/securityentitydata/img-b" 'Update gpgv' 'High'   '.containerimage' 'acr1.azurecr.io/app@sha256:b' 'app' '8.1'),
        (New-RawAssessment 'a4' "$reg/securityentitydata/img-b" 'Update gpgv' 'High'   '.containerimage' 'acr1.azurecr.io/app@sha256:b' 'app' '8.1'),   # paging overlap
        (New-RawAssessment 'a5' "$script:Sub/providers/Microsoft.Security/pricings/CloudPosture/securityentitydata/guid-1" 'Revoke inactive permissions' 'Low' 'x' '' 'guid-1'),
        (New-RawAssessment 'a6' "$script:Sub/providers/Microsoft.Security/pricings/CloudPosture/securityentitydata/guid-2" 'Revoke inactive permissions' 'Low' 'x' '' 'guid-2')
    )
    $script:Rows = @(ConvertTo-SIDefenderRecommendationRows -Raw $script:Raw -CollectionTime ([datetime]'2026-09-28T20:00:00Z') -RunId 'r1')
}

Describe 'the roll-up keeps every recommendation and doubles none' {
    It 'resource and subscription rows pass through one-to-one' {
        @($script:Rows | Where-Object RowKind -eq 'Resource').Count     | Should -Be 1
        @($script:Rows | Where-Object RowKind -eq 'Subscription').Count | Should -Be 1
    }
    It 'container images roll up to the registry, counted and listed, highest severity and CVSS kept' {
        $img = @($script:Rows | Where-Object { $_.AffectedEntityKind -eq 'ContainerImage' })
        $img.Count | Should -Be 1
        $img[0].ResourceName        | Should -Be 'acr1'
        $img[0].AffectedEntityCount | Should -Be 2
        $img[0].AffectedEntities    | Should -Be 'acr1.azurecr.io/app@sha256:a; acr1.azurecr.io/app@sha256:b'
        $img[0].Severity            | Should -Be 'High'
        $img[0].MaxCvssScore        | Should -Be '8.1'
    }
    It 'cloud-posture identities roll up to the SUBSCRIPTION with every identity listed' {
        $cp = @($script:Rows | Where-Object { $_.AffectedEntityKind -eq 'CloudPostureEntity' })
        $cp.Count | Should -Be 1
        $cp[0].ResourceId          | Should -Be $script:Sub
        $cp[0].AffectedEntityCount | Should -Be 2
    }
    It 'conservation: every distinct assessment is represented exactly once' {
        $distinct = @($script:Raw | Select-Object -ExpandProperty AssessmentId -Unique).Count
        $represented = @($script:Rows | Where-Object RowKind -ne 'RolledUpEntities').Count +
                       (@($script:Rows | Where-Object RowKind -eq 'RolledUpEntities') | Measure-Object AffectedEntityCount -Sum).Sum
        $represented | Should -Be $distinct
    }
    It 'every row carries every column, CollectionTime a UTC datetime, the count an int (no schema drift)' {
        $cols = $script:Rows[0].PSObject.Properties.Name
        foreach ($r in $script:Rows) { ($r.PSObject.Properties.Name -join ',') | Should -Be ($cols -join ',') }
        $script:Rows[0].CollectionTime -is [datetime] | Should -BeTrue
        $script:Rows[0].CollectionTime.Kind | Should -Be 'Utc'
        @($script:Rows | Where-Object { $_.AffectedEntityCount -isnot [int] }).Count | Should -Be 0
        # a stable, unique key per (resource, recommendation) -- RA's CL shadow fetch keys on it
        @($script:Rows.PrimaryEntityId | Sort-Object -Unique).Count | Should -Be $script:Rows.Count
    }
}

Describe 'findings behind a recommendation (sub-assessments) are listed on it -- none lost, none doubled' {
    BeforeAll {
        $kv = "$script:Sub/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv1"
        $script:VmId = "$script:Sub/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1"
        $script:Base = @(
            (New-RawAssessment "$kv/providers/Microsoft.Security/assessments/a1" $kv 'Enable purge protection' 'Medium'),
            (New-RawAssessment "$script:VmId/providers/Microsoft.Security/assessments/vulnkey" $script:VmId 'Machines should have vulnerability findings resolved' 'High' 'microsoft.compute/virtualmachines' '' 'vm1')
        )
        function script:New-Sub($parentId, $n, $sev) {
            [pscustomobject]@{ SubAssessmentId = "$parentId/subAssessments/s$n"; ParentAssessmentId = $parentId.ToLowerInvariant()
                FindingName = "Finding $n"; FindingId = "F-$n"; FindingSeverity = $sev; FindingCategory = 'x'; ResourceId = $script:VmId
                SubscriptionId = '11111111-1111-1111-1111-111111111111'; ResourceGroup = 'rg' }
        }
        $vmParent = "$script:VmId/providers/Microsoft.Security/assessments/vulnkey"
        $orphanParent = "$script:VmId/providers/Microsoft.Security/assessments/otherkey"
        $script:Subs = @( (New-Sub $vmParent 1 'Low'), (New-Sub $vmParent 2 'High'), (New-Sub $vmParent 2 'High'),   # paging overlap
                          (New-Sub $orphanParent 3 'Medium') )
        $script:SR = @(ConvertTo-SIDefenderRecommendationRows -Raw $script:Base -SubAssessments $script:Subs -CollectionTime ([datetime]::UtcNow) -RunId r)
    }
    It 'attached to the parent recommendation row: counted, highest severity, every finding listed' {
        $vm = @($script:SR | Where-Object { $_.Recommendation -like 'Machines should*' })
        $vm.Count | Should -Be 1
        $vm[0].SubFindingCount       | Should -Be 2
        $vm[0].SubFindingMaxSeverity | Should -Be 'High'
        $vm[0].SubFindings           | Should -Be 'Finding 1 [F-1] (Low); Finding 2 [F-2] (High)'
    }
    It 'a recommendation without findings carries 0 and empty text' {
        $kvRow = @($script:SR | Where-Object Recommendation -eq 'Enable purge protection')[0]
        $kvRow.SubFindingCount | Should -Be 0
        $kvRow.SubFindings     | Should -Be ''
    }
    It 'a finding whose parent is not in the list gets its own row, never dropped' {
        $o = @($script:SR | Where-Object RowKind -eq 'SubAssessments')
        $o.Count | Should -Be 1
        $o[0].SubFindingCount | Should -Be 1
        $o[0].Recommendation  | Should -Be 'Defender for Cloud findings (otherkey)'
        $o[0].ResourceId      | Should -Be $script:VmId
        $o[0].Severity        | Should -Be 'Medium'
    }
    It 'conservation: every distinct finding counted exactly once across the rows' {
        ($script:SR | Measure-Object SubFindingCount -Sum).Sum | Should -Be 3
    }
    It 'rolled-up container images collect the findings of every image in the group' {
        $imgA = "$script:Sub/resourceGroups/rg/providers/Microsoft.ContainerRegistry/registries/acr1/securityentitydata/img-a"
        $raw = @((New-RawAssessment "$imgA/providers/Microsoft.Security/assessments/k" $imgA 'Update gpgv' 'Medium' '.containerimage' 'acr/app@a' 'app'))
        $raw[0].AssessmentId = "$imgA/providers/Microsoft.Security/assessments/k"
        $rows = @(ConvertTo-SIDefenderRecommendationRows -Raw $raw -SubAssessments @(New-Sub "$imgA/providers/Microsoft.Security/assessments/k" 9 'Low') -CollectionTime ([datetime]::UtcNow) -RunId r)
        $rows.Count | Should -Be 1
        $rows[0].RowKind | Should -Be 'RolledUpEntities'
        $rows[0].SubFindingCount | Should -Be 1
    }
    It 'a very long list stays under the workbook cell limit and says how many it did not print; the count stays exact' {
        $parent = "$script:VmId/providers/Microsoft.Security/assessments/vulnkey"
        $many = @(1..2000 | ForEach-Object { New-Sub $parent $_ 'Low' })
        $rows = @(ConvertTo-SIDefenderRecommendationRows -Raw @($script:Base[1]) -SubAssessments $many -CollectionTime ([datetime]::UtcNow) -RunId r)
        $rows[0].SubFindingCount    | Should -Be 2000
        $rows[0].SubFindings.Length | Should -BeLessThan 32767
        $rows[0].SubFindings        | Should -Match '\.\.\. \(\+\d+ more -- SubFindingCount is exact\)$'
    }
    It 'the findings query sorts and reads only unhealthy sub-assessments' {
        $q = Get-SIDefenderSubAssessmentKql
        $q | Should -Match "type == 'microsoft.security/assessments/subassessments'"
        $q | Should -Match "tostring\(properties\.status\.code\) == 'Unhealthy'"
        $q | Should -Match '(?m)^\| order by id asc'
    }
    It 'an incomplete findings read makes the whole result incomplete (nothing published)' {
        Mock Start-Sleep { }
        $r = Get-SIDefenderRecommendations -CollectionTime ([datetime]::UtcNow) -RunId x -PageFetcher { param($p)
            if ([string]$p['Query'] -match 'subassessments') { throw 'Forbidden' } else { [pscustomobject]@{ Data = $script:Raw; SkipToken = $null } } }
        $r.Complete | Should -BeFalse
    }
}

Describe 'timestamps are written culture-independent' {
    It 'a [datetime] from the JSON reader lands as ISO UTC, never "MM/dd/yyyy"' {
        $r = New-RawAssessment 'z1' "$script:Sub/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv9" 'x' 'Low'
        $r.FirstEvaluated = [datetime]::SpecifyKind([datetime]'2025-05-31T07:19:24', 'Utc')
        $r.StatusChanged  = '2025-06-01T00:00:00Z'
        $o = @(ConvertTo-SIDefenderRecommendationRows -Raw @($r) -CollectionTime ([datetime]::UtcNow) -RunId x)[0]
        $o.FirstEvaluated | Should -Be '2025-05-31T07:19:24Z'
        $o.StatusChanged  | Should -Be '2025-06-01T00:00:00Z'
    }
}

Describe 'reading Resource Graph' {
    It 'the query SORTS and projects the assessment id (#149)' {
        $q = Get-SIDefenderRecommendationKql
        $q | Should -Match '(?m)^\| order by id asc'
        $q | Should -Match 'AssessmentId\s+= tostring\(id\)'
        $q | Should -Match "tostring\(properties\.status\.code\) == 'Unhealthy'"
    }
    It 'a complete read returns Complete=$true; a failed page returns Complete=$false' {
        # the fetcher answers the recommendation query with the fixture and the findings query with nothing
        $ok = Get-SIDefenderRecommendations -CollectionTime ([datetime]::UtcNow) -RunId x -PageFetcher { param($p)
            $q = if ($p -is [hashtable] -or $p -is [System.Collections.IDictionary]) { [string]$p['query'] } else { [string]($p | Out-String) }
            if ($q -match 'subassessments') { [pscustomobject]@{ Data = @(); SkipToken = $null } } else { [pscustomobject]@{ Data = $script:Raw; SkipToken = $null } } }
        $ok.Complete | Should -BeTrue
        $ok.RawCount | Should -Be 7
        @($ok.Rows | Where-Object RowKind -eq 'SubAssessments').Count | Should -Be 0
        Mock Start-Sleep { }
        $bad = Get-SIDefenderRecommendations -CollectionTime ([datetime]::UtcNow) -RunId x -PageFetcher { param($p) throw 'Forbidden' }
        $bad.Complete | Should -BeFalse
    }
}

Describe 'the graph report''s Defender lookup is pre-fetched as ONE key column, never left to the whole-table shadow' {
    BeforeAll {
        . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-ProfileAugment.ps1')
        function script:Write-Info { param($m) }
        function script:Write-Err2 { param($m) }
        function script:Write-Warn2 { param($m) }
        function script:Invoke-LogAnalyticsKqlQuery { param($WorkspaceResourceId, $Query) }
        $y =[IO.File]::ReadAllText((Join-Path $script:SIRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'))
        $blk = [regex]::Match($y, '(?s)- ReportName: Azure_Recommendations_Detailed\r?\n(.*?)(?=\r?\n    - ReportName: |\z)').Groups[1].Value
        $let = [regex]::Match($blk, '(?s)let _dfcPairs = .*?;').Value
        $script:Q = $let + "`nExposureGraphNodes | extend _dfcKey = 'a' | join kind=leftanti (_dfcPairs) on _dfcKey"
    }
    BeforeEach { $script:_HybridRowsCache = @{}; $script:_HybridSnapshotCache = @{}; $script:_HybridBucketGroupsCache = @{}; $script:_CrossDomainBucketCoalesce = @() }
    It 'the lookup is replaced by its RESULT; the table name is gone, so the shadow never fetches it' {
        Mock Invoke-LogAnalyticsKqlQuery { @([pscustomobject]@{ _dfcKey = 'kv1|enable purge protection' }) }
        $r = Resolve-ProfileCLLetBlocks -Query $script:Q -WorkspaceResourceId '/subscriptions/x/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/w'
        $r | Should -Match 'let _dfcPairs = datatable\(_dfcKey:string\)'
        $r | Should -Match 'kv1\|enable purge protection'
        $r | Should -Not -Match 'SI_AzureRecommendation_CL'
    }
    It 'an empty table gives an empty, correctly-shaped lookup (removes nothing, fails nothing)' {
        Mock Invoke-LogAnalyticsKqlQuery { @() }
        $r = Resolve-ProfileCLLetBlocks -Query $script:Q -WorkspaceResourceId '/subscriptions/x/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/w'
        $r | Should -Match 'let _dfcPairs = datatable\(_dfcKey:string\) \[\];'
    }
    It 'bucketed: every bucket gets the WHOLE lookup (no key to partition on)' {
        Mock Invoke-LogAnalyticsKqlQuery { @([pscustomobject]@{ _dfcKey = 'a|x' }, [pscustomobject]@{ _dfcKey = 'b|y' }) }
        foreach ($i in 0, 1) {
            $r = Resolve-ProfileCLLetBlocks -Query $script:Q -WorkspaceResourceId '/subscriptions/x/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/w' -BucketCount 2 -BucketIndex $i
            $r | Should -Match 'a\|x'
            $r | Should -Match 'b\|y'
        }
    }
}

Describe 'WIRING -- the azure engine publishes, never a partial list' {
    It 'the Recommendations stage runs last, for azure only' {
        $src = Get-Content -LiteralPath (Join-Path $script:SIRoot 'engine\asset-profiling\Invoke-SIEngineRun.ps1') -Raw
        $src | Should -Match "if \(\`$Engine -eq 'azure'\) \{ \`$__st \+= 'Recommendations' \}"
    }
    It 'an incomplete read returns before publishing' {
        $src = Get-Content -LiteralPath (Join-Path $script:SIRoot 'engine\asset-profiling\stages\Invoke-Recommendations.ps1') -Raw
        $inc  = $src.IndexOf('if (-not $res.Complete)')
        $pub  = $src.IndexOf('Send-SIObjectMapRows')
        $inc | Should -BeGreaterThan 0
        $pub | Should -BeGreaterThan $inc
        $src.Substring($inc, $pub - $inc) | Should -Match 'return'
    }
    It 'the reports read the collected table and the graph report drops only pairs Defender carries' {
        $y = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'))
        $y | Should -Match '- ReportName: Azure_DefenderRecommendations_Summary'
        $y | Should -Match '- ReportName: Azure_DefenderRecommendations_Detailed'
        # Every template that carries the graph report carries the Defender report too -- the two main ones at least.
        ([regex]::Matches($y, '- Name: Azure_Recommendations_(Summary|Detailed)\r?\n\s*- Name: Azure_DefenderRecommendations_\1')).Count |
            Should -Be ([regex]::Matches($y, '- Name: Azure_Recommendations_(Summary|Detailed)\r?\n')).Count
        foreach ($tn in 'RiskAnalysis_Summary','RiskAnalysis_Detailed') {
            $grain = $tn -replace 'RiskAnalysis_',''
            [regex]::Match($y, "(?s)- ReportName: $tn\r?\n.*?(?=\r?\n    - ReportName: |\z)").Value | Should -Match "- Name: Azure_DefenderRecommendations_$grain"
        }
        ([regex]::Matches($y, 'join kind=leftanti \(_dfcPairs\) on _dfcKey')).Count | Should -Be 2
        ([regex]::Matches($y, 'union isfuzzy=true')).Count | Should -BeGreaterOrEqual 4
    }
}

Describe 'Defender''s HTML remediation text is stored as plain text (#189)' {
    It 'links keep their URL, list items become lines, breaks become new lines, entities are decoded' {
        $html = 'To enable it, visit <a target="_blank" href="https://learn.microsoft.com/x">EncryptionAtHost</a>.<br> Then:<ol><li>Remove the secret</li><li><b>Rotate</b> it</li></ol>&emsp;a. check &amp; verify'
        $t = ConvertFrom-SIDefenderHtml $html
        $t | Should -Not -Match '<|>|&emsp;|&amp;'
        $t | Should -Match 'EncryptionAtHost \(https://learn\.microsoft\.com/x\)'
        $t | Should -Match '(?m)^- Remove the secret$'
        $t | Should -Match '(?m)^- Rotate it$'
        $t | Should -Match '(?m)^a\. check & verify$'
    }
    It 'a link whose text is its URL is written once' {
        ConvertFrom-SIDefenderHtml '<a href="https://x.example/a">https://x.example/a</a>' | Should -Be 'https://x.example/a'
    }
    It 'plain text passes through; empty stays empty' {
        ConvertFrom-SIDefenderHtml 'Enable purge protection on the vault.' | Should -Be 'Enable purge protection on the vault.'
        ConvertFrom-SIDefenderHtml '' | Should -Be ''
        ConvertFrom-SIDefenderHtml $null | Should -BeNullOrEmpty
    }
    It 'the row builder applies it to Description and Remediation' {
        $raw = New-RawAssessment 'h1' "$script:Sub/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kvh" 'Fix it' 'High'
        $raw.Remediation = '<ol><li>Step one</li></ol>'
        $raw.Description = 'Why<br/>it matters'
        $row = @(ConvertTo-SIDefenderRecommendationRows -Raw @($raw) -CollectionTime ([datetime]'2026-10-01T00:00:00Z') -RunId 'r')[0]
        $row.Remediation | Should -Be '- Step one'
        $row.Description | Should -Be ("Why`nit matters")
    }
}

Describe 'a VM''s recommendation is reported once, not twice (#200)' {
    # Measured 2026-10-01: the graph names a VM by the machine (mgmt1.2linkit.local), Defender by its Azure name (MGMT1).
    # The (name, recommendation) drop never matched a VM, so the Top 50 listed each server twice.
    BeforeAll {
        $script:Y = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'))
        $script:Graph = foreach ($g in 'Summary', 'Detailed') {
            [regex]::Match($script:Y, "(?s)- ReportName: Azure_Recommendations_$g\r?\n.*?(?=\r?\n    - ReportName: |\z)").Value
        }
    }
    It 'the lookup carries the ARM id pair as well as the name pair' {
        foreach ($b in $script:Graph) {
            $let = [regex]::Match($b, '(?s)let _dfcPairs = .*?;').Value
            $let | Should -Match 'make_set_if\(strcat\("h", tostring\(hash\(strcat\(tolower\(tostring\(ResourceIdLower\)\)'
            $let | Should -Match 'array_concat\(_keys, _ids, _aks\)'   # #349 adds the (resource, assessment key) pair
        }
    }
    It 'both graph reports drop on the ARM id, AFTER the asset id is resolved' {
        foreach ($b in $script:Graph) {
            # #505 -- the asset id is the CI's (case(si_ci_id, az:<ARM id>, node id)), resolved after the CI join
            $id   = $b.IndexOf('| extend AssetId   = case(')
            $drop = $b.IndexOf('join kind=leftanti (_dfcPairs) on $left._dfcIdKey == $right._dfcKey')
            $id   | Should -BeGreaterThan 0
            $drop | Should -BeGreaterThan $id
        }
    }
    It 'a row with no ARM id cannot match (sentinel, not an empty key)' {
        foreach ($b in $script:Graph) { $b | Should -Match '_dfcIdKey = iff\(.*"\|", tolower\(tostring\(FindingName\)\)\)\)\)\), "-"\)' }
    }
}

Describe 'a VM in the Defender report carries the machine''s name (#200)' {
    # Measured 2026-10-01 after the de-duplication: the Top 50 still listed MGMT1 (Defender report, Azure name) and
    # mgmt1.2linkit.local (every other report) as two assets.
    # #505 -- the short-name bridge to the endpoint profile (_devNames / Name_ByDev) is gone by design: the CI links the
    # VM's ARM id AND its Defender device id, so the Defender row joined on the ARM id gets the ONE CI's name -- the same
    # name every other report shows for that machine. Azure's own name is only the fallback where no CI links it.
    It 'both Defender reports name a VM by its CI, joined on the ARM id; the Azure name only when no CI links it' {
        $y = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'))
        foreach ($g in 'Summary', 'Detailed') {
            $b = [regex]::Match($y, "(?s)- ReportName: Azure_DefenderRecommendations_$g\r?\n.*?(?=\r?\n    - ReportName: |\z)").Value
            $b | Should -Not -BeNullOrEmpty -Because "Azure_DefenderRecommendations_$g must be in the catalog"
            $join = $b.IndexOf('| join kind=leftouter (_ciLink) on $left._k == $right._ciKey')
            $name = $b.IndexOf('| extend AssetName = case(isnotempty(si_asset_name), si_asset_name, isnotempty(ResourceName), ResourceName, ResourceId)')
            $join | Should -BeGreaterThan 0
            $name | Should -BeGreaterThan $join
            $b | Should -Match '\| extend _k = tolower\(tostring\(ResourceIdLower\)\)' -Because 'the CI links lower-case ARM ids'
            $b | Should -Not -Match '_devNames|Name_ByDev' -Because 'the short-name bridge is retired with the profile'
        }
    }
}

Describe 'a subscription and a Defender plan are named, not shown as an id (#202)' {
    BeforeAll {
        $script:Names = @{ '11111111-1111-1111-1111-111111111111' = 'Production' }
        $script:Named = @(ConvertTo-SIDefenderRecommendationRows -Raw $script:Raw -CollectionTime ([datetime]'2026-09-28T20:00:00Z') -RunId 'r1' -SubscriptionNames $script:Names)
    }
    It 'a subscription-scoped recommendation carries the subscription''s display name; the id stays in ResourceId' {
        $r = @($script:Named | Where-Object RowKind -eq 'Subscription')
        $r.Count | Should -Be 1
        $r[0].ResourceName | Should -Be 'Production'
        $r[0].ResourceId   | Should -Be $script:Sub
    }
    It 'a Defender plan is "<subscription> - Defender plan <plan>"; cloud-posture entities roll up to the subscription and take its name' {
        $plan = New-RawAssessment 'p1' "$script:Sub/providers/Microsoft.Security/pricings/ai" 'Enable Defender for AI' 'High' 'microsoft.security/pricings' '' 'ai'
        $r = @(ConvertTo-SIDefenderRecommendationRows -Raw @($plan) -CollectionTime ([datetime]::UtcNow) -RunId x -SubscriptionNames $script:Names)
        $r[0].ResourceName | Should -Be 'Production - Defender plan ai'
        @($script:Named | Where-Object { $_.RowKind -eq 'RolledUpEntities' -and $_.ResourceId -eq $script:Sub })[0].ResourceName | Should -Be 'Production'
    }
    It 'a subscription whose name is not known keeps its id -- never blank' {
        Get-SIDefenderAssetLabel -ResourceId '/subscriptions/2222' -ResourceName '' -SubscriptionId '2222' -SubscriptionNames @{} | Should -Be '2222'
        Get-SIDefenderAssetLabel -ResourceId '/subscriptions/2222/providers/Microsoft.Security/pricings/ai' -ResourceName 'ai' -SubscriptionId '2222' -SubscriptionNames @{} | Should -Be '2222 - Defender plan ai'
    }
    It 'the lookup is case-insensitive on the id, and any other resource keeps its own name' {
        Get-SIDefenderAssetLabel -ResourceId '/subscriptions/ABCD' -ResourceName 'abcd' -SubscriptionId 'ABCD' -SubscriptionNames @{ 'abcd' = 'Dev' } | Should -Be 'Dev'
        Get-SIDefenderAssetLabel -ResourceId '/subscriptions/abcd/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv1' -ResourceName 'kv1' -SubscriptionId 'abcd' -SubscriptionNames @{ 'abcd' = 'Dev' } | Should -Be 'kv1'
    }
    It 'without names nothing changes for an ordinary resource, and nothing invents a name' {
        @($script:Rows | Where-Object { $_.ResourceId -like '*/vaults/kv1' })[0].ResourceName | Should -Be 'kv1'
    }
    It 'the collector reads the names from Resource Graph, and a failed read still publishes (ids kept)' {
        Mock Start-Sleep { }
        $all = @(Get-SIDefenderRecommendations -CollectionTime ([datetime]::UtcNow) -RunId x -PageFetcher { param($p)
            $q = [string]$p['Query']
            if ($q -match 'subassessments') { [pscustomobject]@{ Data = @(); SkipToken = $null } }
            elseif ($q -match 'resourcecontainers') { throw 'Forbidden' }
            else { [pscustomobject]@{ Data = $script:Raw; SkipToken = $null } } } 3>&1)
        # what reaches the console / transcript: only the warning that says what a missing name means
        $w = @($all | Where-Object { $_ -is [System.Management.Automation.WarningRecord] })
        $r = @($all | Where-Object { $_ -isnot [System.Management.Automation.WarningRecord] })[0]
        $r.Complete | Should -BeTrue
        @($r.Rows | Where-Object RowKind -eq 'Subscription')[0].ResourceName | Should -Be 'sub'
        @($w).Count | Should -Be 1
        [string]$w[0] | Should -Match 'shown by their id'
        [string]$w[0] | Should -Not -Match 'UNKNOWN'
        $ok = Get-SIDefenderRecommendations -CollectionTime ([datetime]::UtcNow) -RunId x -PageFetcher { param($p)
            $q = [string]$p['Query']
            if ($q -match 'subassessments') { [pscustomobject]@{ Data = @(); SkipToken = $null } }
            elseif ($q -match 'resourcecontainers') { [pscustomobject]@{ Data = @([pscustomobject]@{ subscriptionId = '11111111-1111-1111-1111-111111111111'; name = 'Production' }); SkipToken = $null } }
            else { [pscustomobject]@{ Data = $script:Raw; SkipToken = $null } } }
        @($ok.Rows | Where-Object RowKind -eq 'Subscription')[0].ResourceName | Should -Be 'Production'
    }
}