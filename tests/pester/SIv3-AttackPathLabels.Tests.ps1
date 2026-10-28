#Requires -Version 5.1
<#
    #690 items 1 + 2 -- THE TWO ATTACK-PATH REPORTS MATCH THE EXPOSURE GRAPH'S OWN LABELS, AND NOTHING IS NARROWED IN SILENCE.

    Found by the report certification (#688, ops\report-certification\reviews\review-ABD.md D1 / D2), counts read-only on
    internal 2026-10-15:
      * Attack_Paths_*_Device_with_high_severity_vulnerabilities_allows_lateral_movement_Azure matched the target label
        microsoft.resources/subscriptions -- the graph labels a subscription node "subscriptions", so every subscription path
        was lost (23 of 135). A target without a tier read as tier 3; the Detailed row named no target id and no device id.
      * Attack_Paths_*_Credential_Based_Lateral_Movement compared labels with the case-sensitive `in`: entra-usercookie
        never matched the graph's entra-userCookie (every session-cookie path lost); fixed lists of credential, source and
        target labels reached 32 of 97 targets. The Detailed report summarised its paths to one row per lateral-movement
        type (a Summary inside a Detailed report) and its AssetId was always empty.
    After the fix, read-only on internal: 135 rows (23 subscription), and 295 path rows reaching all 97 targets, AssetId
    filled on every row, no two rows of one asset share a ConfigurationId.

    Offline: reads the shipped YAML with SecurityInsight's own reader; the label matching is checked against the labels
    the graph really writes (the review's list), the way KQL's case-insensitive operators compare them.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\_shared\SI-Yaml.ps1')
    $script:Path = Join-Path $script:SIRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'
    $script:Catalog = ConvertFrom-SIYaml -Yaml ([IO.File]::ReadAllText($script:Path)) -SourceName $script:Path
    function script:Report([string]$Name) { @($script:Catalog.Reports | Where-Object { [string]$_.ReportName -eq $Name })[0] }
    # the report's own KQL, comment lines left out (a comment may name the old label to explain the fix)
    function script:CodeOf([string]$Name) {
        $r = Report $Name
        $r | Should -Not -BeNullOrEmpty -Because "$Name is in the catalog"
        ((@($r.ReportQuery) | ForEach-Object { [string]$_ }) -join "`n" -split "`r?`n" | Where-Object { $_.Trim() -notmatch '^//' }) -join "`n"
    }
    # the quoted values of the first `<Column> in~ (...)` after $Anchor (the list a filter compares with)
    function script:ListAfter([string]$Code, [string]$Anchor, [string]$Column) {
        $i = $Code.IndexOf($Anchor)
        $i | Should -BeGreaterOrEqual 0 -Because "the anchor '$Anchor' is in the query"
        $m = [regex]::Match($Code.Substring($i), [regex]::Escape($Column) + '\s+in~\s*\((?<v>[^)]*)\)')
        $m.Success | Should -BeTrue -Because "$Column is compared with in~ after '$Anchor'"
        @([regex]::Matches($m.Groups['v'].Value, '"([^"]*)"') | ForEach-Object { $_.Groups[1].Value })
    }
    # KQL in~ / =~ : equal ignoring case
    function script:InCi([string]$Value, [string[]]$List) { @($List | Where-Object { [string]::Equals($_, $Value, [StringComparison]::OrdinalIgnoreCase) }).Count -gt 0 }

    $script:D1 = @('Attack_Paths_Summary_Device_with_high_severity_vulnerabilities_allows_lateral_movement_Azure',
                   'Attack_Paths_Detailed_Device_with_high_severity_vulnerabilities_allows_lateral_movement_Azure')
    $script:D2 = @('Attack_Paths_Summary_Credential_Based_Lateral_Movement', 'Attack_Paths_Detailed_Credential_Based_Lateral_Movement')
    # the labels the Exposure Graph writes, as the review read them on internal (case as the graph spells it)
    $script:GraphCredentialLabels = @('entra-userCookie', 'lsa-secret', 'github-personal-access-token', 'azure-app-configuration-key',
        'certificate', 'openai-api-key', 'user-azure-cli-secret', 'azure-active-directory-app-secret')
    $script:GraphTargetLabels = @('subscriptions', 'resourcegroups', 'microsoft.storage/storageaccounts', 'microsoft.keyvault/vaults',
        'microsoft.containerregistry/registries', 'microsoft.network/networkinterfaces', 'microsoft.authorization/locks',
        'microsoft.compute/virtualmachines', 'device', 'BlobContainer')
}

Describe 'D1 -- vulnerable device to Azure: the target labels are the graph''s, an unknown tier stays unknown' -ForEach @(
    @{ Name = 'Attack_Paths_Summary_Device_with_high_severity_vulnerabilities_allows_lateral_movement_Azure' }
    @{ Name = 'Attack_Paths_Detailed_Device_with_high_severity_vulnerabilities_allows_lateral_movement_Azure' }) {
    BeforeAll { $script:C = CodeOf $Name }
    It 'the role scope takes the graph''s subscription label "subscriptions" (and resource groups), whatever its case -- the target is the resource inside it (#809)' {
        $l = ListAfter $script:C 'graph-match' 'RoleScope.NodeLabel'
        InCi 'subscriptions' $l | Should -BeTrue -Because 'the graph labels a subscription node "subscriptions" -- 23 of 135 paths were lost'
        InCi 'SUBSCRIPTIONS' $l | Should -BeTrue
        InCi 'resourcegroups' $l | Should -BeTrue
        InCi 'microsoft.resources/subscriptions' $l | Should -BeTrue -Because 'the ARM type is kept for a graph that writes it'
        $script:C | Should -Match 'AzureAsset\.NodeLabel =~ "microsoft\.storage/storageaccounts"'
        $script:C | Should -Match 'not\(AzureAsset\.NodeLabel startswith "microsoft\.resources/"\)' -Because 'a subscription or resource group is never the target (owner 2026-10-19)'
    }
    It 'the target type is read with case-insensitive operators; no target is a Subscription any more' {
        $script:C | Should -Not -Match 'TargetLabel\s*==\s*"' -Because 'a case-sensitive label compare is the defect this fixes'
        $script:C | Should -Not -Match '"Subscription"'
        $script:C | Should -Match 'TargetLabel =~ "microsoft\.storage/storageaccounts", "Storage account",\s*"Azure resource"\)'
    }
    It 'a tier the CI does not give stays empty -- never tier 3' {
        $script:C | Should -Not -Match 'coalesce\(toint\((si_tier|Target_Tier)\),\s*3\)'
        $script:C | Should -Match 'extend CriticalityTier\s*=\s*toint\((si_tier|Target_Tier)\)'
        $script:C | Should -Match 'CriticalityTierLevel = case\(\s*isnull\(CriticalityTier\), "",'
    }
}

Describe 'D1 Detailed -- no new columns (owner: new si fields only in the later consolidated change)' {
    It 'the final projection is the same column set as before the fix; the device is the row''s AssetId (its CI id, else its Defender / graph id)' {
        $c = CodeOf $script:D1[1]
        $last = $c.Substring($c.LastIndexOf('| project '))
        $last = $last.Substring(0, $last.IndexOf('| sort'))
        $cols = @([regex]::Matches(($last -replace '^\|\s*project', ''), '\b[A-Za-z_][A-Za-z0-9_]*\b') | ForEach-Object { $_.Value }) | Sort-Object -Unique
        $want = @('SecurityDomain', 'Category', 'Subcategory', 'ConfigurationName', 'ConfigurationId', 'AssetName', 'AssetId', 'AssetType', 'Impact',
                  'SecuritySeverity', 'CriticalityTier', 'CriticalityTierLevel', 'RiskFactor_Consequence', 'RiskFactor_Probability',
                  'RiskFactor_Probability_Detailed', 'RiskFactorIds', 'RiskScore_Weight_Detailed', 'RiskScore_Weight_Factor', 'RiskFactor_Weight',
                  'cmdbId', 'cmdbName', 'cmdbCriticality', 'cmdbDataSensitivity', 'EntryPointDevice', 'EntryVectors', 'ReachedIdentities',
                  'TargetAzureAsset', 'ViaRoleScope', 'ViaRoleScopeType', 'MaxCvssScore', 'CredentialNodes') | Sort-Object -Unique
        ($cols -join ',') | Should -Be ($want -join ',')
        $c | Should -Match 'extend AssetId\s*= iif\(isnotempty\(si_ci_id\), si_ci_id, coalesce\(DeviceKey, tolower\(EntryPointDeviceId\)\)\)'
    }
}

Describe 'D2 -- credential-based lateral movement: every label is the graph''s, compared ignoring case' -ForEach @(
    @{ Name = 'Attack_Paths_Summary_Credential_Based_Lateral_Movement' }
    @{ Name = 'Attack_Paths_Detailed_Credential_Based_Lateral_Movement' }) {
    BeforeAll { $script:C = CodeOf $Name }
    It 'no label is compared with the case-sensitive in (...)' {
        $script:C | Should -Not -Match '\b(EdgeLabel|SourceNodeLabel|TargetNodeLabel)\s+in\s*\(' -Because 'in is case-sensitive -- entra-usercookie never matched the graph''s entra-userCookie'
    }
    It 'a credential is a node of the secret category or one of the credential labels -- every label the graph writes matches' {
        $script:C | Should -Match 'where set_has_element\(TargetNodeCategories, "secret"\) or TargetNodeLabel in~ \('
        $l = ListAfter $script:C 'let CredentialEdges' 'TargetNodeLabel'
        foreach ($g in $script:GraphCredentialLabels) { InCi $g $l | Should -BeTrue -Because "the graph writes $g" }
        InCi 'entra-usercookie' $l | Should -BeTrue -Because 'the old lower-case spelling still matches (in~ ignores case)'
    }
    It 'no fixed list of source kinds narrows where a credential may sit' {
        $cred = [regex]::Match($script:C, '(?s)let CredentialEdges =.*?;').Value
        $cred | Should -Not -Match 'SourceNodeLabel\s+in'
    }
    It 'the final target is any Azure resource type or one of the scope / device labels -- every target label the graph writes matches' {
        $hop2 = [regex]::Match($script:C, '(?s)let Hop2Edges =.*?;').Value
        $hop2 | Should -Match 'where TargetNodeLabel startswith "microsoft\." or TargetNodeLabel in~ \('
        $l = ListAfter $hop2 'startswith "microsoft."' 'TargetNodeLabel'
        foreach ($g in $script:GraphTargetLabels) {
            ($g.StartsWith('microsoft.', [StringComparison]::OrdinalIgnoreCase) -or (InCi $g $l)) | Should -BeTrue -Because "the graph writes $g"
        }
    }
    It 'a node without a tier tag keeps no tier -- never tier 3' {
        $script:C | Should -Not -Match 'coalesce\(CriticalityTierFromTag,\s*3\)'
        $script:C | Should -Match 'extend CriticalityTier = toint\(CriticalityTierFromTag\)'
        $script:C | Should -Match 'SourceCriticalityTierLevel = case\(isnull\(SourceCriticalityTier\), "",'
        $script:C | Should -Match 'TargetCriticalityTierLevel = case\(isnull\(TargetCriticalityTier\), "",'
        $script:C | Should -Match 'isnull\(SourceCriticalityTier\) or isnull\(TargetCriticalityTier\), "Lateral movement, tier not known"' -Because 'an unknown tier is not "Direct access same tier"'
    }
}

Describe 'D2 Detailed -- one row per path, the asset is the path''s source with its CI id' {
    BeforeAll { $script:C = CodeOf $script:D2[1] }
    It 'keeps every asset a credential sits on (source x credential), not the first one' {
        $s4 = [regex]::Match($script:C, '(?s)let CredentialsOnAssets =.*?;').Value
        $s4 | Should -Match 'by\s+FirstSourceAssetId = SourceNodeId,\s*CredentialNodeId\s*= TargetNodeId'
        $s4 | Should -Not -Match 'min\(SourceNodeId\)'
    }
    It 'has no Summary grain: no summarize by the lateral-movement type, no impacted-asset list' {
        $script:C | Should -Not -Match '(?s)summarize\b[^;]*\bby\b[^;|]*\bConfigurationName\b'
        $script:C | Should -Not -Match '\bImpactedAssets\b|\bImpactedAssetPairs\b|\bCollapsedPaths\b'
        $script:C | Should -Not -Match 'column_ifexists\("TargetAssetId"' -Because 'the always-empty AssetId came from a column that did not exist at that step'
    }
    It 'names each path by its four graph node ids and takes the source''s CI id as AssetId' {
        $script:C | Should -Match 'extend PathKey = strcat\(FirstSourceAssetId, "->", CredentialNodeId, "->", IntermediateIdentityId, "->", FinalTargetId\)'
        $script:C | Should -Match 'extend ConfigurationId\s*= PathKey'
        $script:C | Should -Match 'extend SourceAssetId = iif\(isnotempty\(Source_si_ci_id\), Source_si_ci_id, tostring\(FirstSourceAssetId\)\)'
        $script:C | Should -Match 'extend AssetId\s*= tostring\(SourceAssetId\)'
        $script:C | Should -Match 'extend CriticalityTier\s*= toint\(TargetCriticalityTier\)'
    }
    It 'the final projection carries the report columns and the source tier only -- no raw graph columns, no new columns' {
        $last = $script:C.Substring($script:C.LastIndexOf('| project'))
        $last = $last.Substring(0, $last.IndexOf('| order by'))
        $cols = @([regex]::Matches(($last -replace '^\|\s*project', ''), '\b[A-Za-z_][A-Za-z0-9_]*\b') | ForEach-Object { $_.Value }) | Sort-Object -Unique
        $want = @('SecurityDomain', 'Category', 'SubCategory', 'ConfigurationName', 'ConfigurationId', 'AssetName', 'AssetId', 'AssetType',
                  'SecuritySeverity', 'CriticalityTier', 'CriticalityTierLevel', 'cmdbId', 'cmdbName', 'cmdbCriticality', 'cmdbDataSensitivity',
                  'RiskFactor_Consequence', 'RiskFactor_Probability', 'RiskFactor_Probability_Detailed', 'RiskFactor_Probability_DetailedScore',
                  'RiskScore_Weight_Detailed', 'RiskScore_Weight_Factor', 'RiskFactor_Weight', 'SourceCriticalityTier') | Sort-Object -Unique
        ($cols -join ',') | Should -Be ($want -join ',') -Because 'SourceCriticalityTier is the existing column the data load reads for a path row''s own tier (as the sibling attack-path reports)'
    }
}

Describe 'the label check itself (control)' {
    It 'tells a case-insensitive match from a missing label' {
        InCi 'entra-userCookie' @('entra-usercookie') | Should -BeTrue
        InCi 'lsa-secret' @('entra-usercookie') | Should -BeFalse
    }
    It 'reads the list of the right filter' {
        ListAfter 'x | where A in~ ("a", "B") | where T in~ ("c")' 'where' 'T' | Should -Be @('c')
    }
}
