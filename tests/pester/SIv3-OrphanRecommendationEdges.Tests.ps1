#Requires -Version 5.1
<#
    #349 -- A RECOMMENDATION EDGE WHOSE RECOMMENDATION NODE IS MISSING STILL REPORTS ITS FINDING.

    Measured on ring 1, 2026-10-05: ExposureGraphEdges held 3,891 "affecting" edges from 81 recommendations whose
    SOURCE node (the recommendation) is absent from ExposureGraphNodes -- e.g. "Public network access on Azure SQL
    Database should be disabled" on seven SQL servers and "Audit flow logs configuration for every virtual network"
    on the virtual networks, all still Unhealthy in Defender for Cloud. Azure_Recommendations_* joined every edge to
    its finding node, so those rows were dropped, and for resources outside the subscriptions the install reads the
    graph was the only source. The rows are now rebuilt from the edge itself (name, label, categories and the
    Defender assessment key it carries); severity and security issue come from Defender by assessment key and,
    where Defender has no row, from the edge's risk level. A third hand-off key -- (resource, assessment key) --
    keeps a recommendation Defender already reports from being counted twice.

    Live, read-only, ring 1 (Detailed 426 -> 588 rows, Summary 296 -> 430; the 2linkit-sql and vnet rows came back;
    two rows that Defender already carried under another spelling left). Offline here: the query shape, the
    engine's let pre-fetch over the new lookup, the hand-off substitution and the catalog's KQL rules.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $shared = Join-Path $script:SIRoot 'engine\risk-analysis\_shared'
    function script:Write-Info  { param($m) }
    function script:Write-Warn2 { param($m) }
    function script:Write-Err2  { param($m) }
    . (Join-Path $shared 'RA-ProfileAugment.ps1')
    . (Join-Path $shared 'RA-ReportHandoff.ps1')
    $script:Y = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'))
    function script:Get-ReportBlock([string]$name) {
        [regex]::Match($script:Y, "(?s)- ReportName: $name\r?\n.*?(?=\r?\n    - ReportName: |\z)").Value
    }
    $script:Graph = @{}
    foreach ($g in 'Summary', 'Detailed') { $script:Graph[$g] = Get-ReportBlock "Azure_Recommendations_$g" }
    $script:Hashed = 'strcat("h", tostring(hash(strcat('
}

Describe 'a recommendation edge whose recommendation node is missing is rebuilt from the edge' {
    It 'both report blocks are found' {
        foreach ($g in 'Summary', 'Detailed') { $script:Graph[$g].Length | Should -BeGreaterThan 1000 }
    }
    It 'the dangling edges are found by an anti-join on the node table, recommendation side only' {
        foreach ($g in 'Summary', 'Detailed') {
            $let = [regex]::Match($script:Graph[$g], '(?s)let _AssetFindingEdges_orphan =.*?;').Value
            $let | Should -Not -BeNullOrEmpty
            $let | Should -Match 'where EdgeLabel has "affecting"'
            $let | Should -Match 'tostring\(SourceNodeCategories\) contains "finding" and SourceNodeLabel !contains "cve"'
            $let | Should -Match ([regex]::Escape('join kind=leftanti (ExposureGraphNodes | project NodeId) on $left.SourceNodeId == $right.NodeId'))
            # the asset must still exist -- a dangling edge with no asset has nothing to report on
            $let | Should -Match ([regex]::Escape('join kind=inner (_Assets) on $left.TargetNodeId == $right.AssetNodeId'))
        }
    }
    It 'name, label and categories come from the edge, the assessment key from the Defender assessment it names' {
        foreach ($g in 'Summary', 'Detailed') {
            $let = [regex]::Match($script:Graph[$g], '(?s)let _AssetFindingEdges_orphan =.*?;').Value
            $let | Should -Match 'FindingName = SourceNodeName, FindingLabel = SourceNodeLabel, FindingCategories = SourceNodeCategories'
            $let | Should -Match ([regex]::Escape('extract(@"/assessments/([^/]+)$", 1, tostring(EdgeProps.rawData.recommendationAzureResourceId))'))
        }
    }
    It 'severity is Defender''s by assessment key first, the edge risk level only where Defender has no row' {
        foreach ($g in 'Summary', 'Detailed') {
            $let = [regex]::Match($script:Graph[$g], '(?s)let _AssetFindingEdges_orphan =.*?;').Value
            $let | Should -Match ([regex]::Escape('join kind=leftouter (_dfcRecByKey) on _akKey'))
            $let | Should -Match ([regex]::Escape('_akSeverity = iff(isnotempty(_akSeverity), _akSeverity, tostring(EdgeProps.rawData.risk.riskLevel))'))
            # the rebuilt row has the same shape the rest of the query reads (Properties.raw.severity / securityIssue)
            $let | Should -Match ([regex]::Escape('FindingProps = bag_pack("rawData", bag_pack("severity", _akSeverity, "securityIssue", bag_pack("securityIssue", _akIssue)'))
        }
    }
    It 'the rebuilt rows join the same pipeline (hand-off, exclusions, tier) as every other row' {
        foreach ($g in 'Summary', 'Detailed') {
            $script:Graph[$g] | Should -Match ([regex]::Escape('let _AssetFindingEdges = union _AssetFindingEdges_oneway, _AssetFindingEdges_otherway, _AssetFindingEdges_orphan;'))
            $script:Graph[$g] | Should -Match ([regex]::Escape('| extend Severity = tostring(Properties.raw.severity)'))
        }
    }
}

Describe 'Defender''s severity per assessment key is a lookup the engine pre-fetches, independent of the hand-off' {
    It 'the lookup reads the Defender base table, latest per key, with an empty typed stub' {
        foreach ($g in 'Summary', 'Detailed') {
            $let = [regex]::Match($script:Graph[$g], '(?s)let _dfcRecByKey = .*?;').Value
            $let | Should -Match ([regex]::Escape('union isfuzzy=true'))
            $let | Should -Match ([regex]::Escape('(datatable(_akKey:string, _akSeverity:string, _akIssue:string)[])'))
            $let | Should -Match ([regex]::Escape('tolower(tostring(column_ifexists("AssessmentKey", "")))'))
            $let | Should -Match ([regex]::Escape('summarize arg_max(CollectionTime, Severity, SecurityIssue) by _akKey'))
            # the last project stays outside the union -- the engine reads it for the columns of an empty result
            $let | Should -Match '\)\s*\| project _akKey, _akSeverity, _akIssue;$'
        }
    }
    It 'it sits outside the hand-off markers, so a run without the Defender report still has it' {
        foreach ($g in 'Summary', 'Detailed') {
            $q = $script:Graph[$g]
            $blk = [regex]::Match($q, '(?s)//__DEFENDER_HANDOFF_BEGIN__(?<body>.*?)//__DEFENDER_HANDOFF_END__').Groups['body'].Value
            $blk | Should -Not -Match '_dfcRecByKey'
            $out = Resolve-RADefenderHandoffBlock -Query $q -ReportName "Azure_Recommendations_$g" -IncludedReports @("Azure_Recommendations_$g")
            $out | Should -Match 'let _dfcPairs = datatable\(_dfcKey:string\)\[\];'
            $out | Should -Match 'let _dfcRecByKey = union isfuzzy=true'
            $out | Should -Match '_AssetFindingEdges_orphan;'
        }
    }
    It 'the engine''s hybrid path inlines it like every other Log Analytics lookup (no Defender table left for advanced hunting)' {
        $script:Fetched = New-Object System.Collections.Generic.List[string]
        function script:Invoke-LogAnalyticsKqlQuery {
            param([string]$WorkspaceResourceId, [string]$Query, [int]$TimeoutSec = 600)
            $script:Fetched.Add($Query)
            if ($Query -match '_akSeverity') { return , @([pscustomobject]@{ _akKey = '22e93e92-4a31-b4cd-d640-3ef908430aa6'; _akSeverity = 'Medium'; _akIssue = 'NetworkAccessPolicy' }) }
            return , @()
        }
        foreach ($g in 'Summary', 'Detailed') {
            $script:_HybridSnapshotCache = @{}; $script:_HybridRowsCache = @{}; $script:_HybridBucketGroupsCache = @{}
            $out = Resolve-ProfileCLLetBlocks -Query $script:Graph[$g] -WorkspaceResourceId '/subscriptions/0/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/ws'
            $out | Should -Match 'let _dfcRecByKey = datatable\(_akKey:string,_akSeverity:string,_akIssue:string\)'
            $out | Should -Match '22e93e92-4a31-b4cd-d640-3ef908430aa6'
            $out | Should -Not -Match 'let _dfcRecByKey = union'
            $code = (($out -split "`r?`n") | Where-Object { $_.TrimStart() -notmatch '^//' }) -join "`n"
            $code | Should -Not -Match '\bSI_AzureRecommendation_CL\b' -Because 'advanced hunting has no Log Analytics tables'
        }
    }
    It 'the lookup has no bucket key, so a bucketed run gives every bucket the whole lookup' {
        $script:_CrossDomainBucketCoalesce = @()
        Get-SICLBucketKey -Row ([pscustomobject]@{ _akKey = 'k'; _akSeverity = 'High'; _akIssue = 'x' }) | Should -BeNullOrEmpty
    }
}

Describe 'a recommendation Defender already reports is not counted twice -- by (resource, assessment key) too' {
    It 'the hand-off lookup carries the (resource, assessment key) pair as a hash' {
        foreach ($g in 'Summary', 'Detailed') {
            $let = [regex]::Match($script:Graph[$g], '(?s)let _dfcPairs = .*?;').Value
            $let | Should -Match ([regex]::Escape('_aks = make_set_if(' + $script:Hashed + 'tolower(tostring(ResourceIdLower)), "|", _akL))))'))
            $let | Should -Match ([regex]::Escape('extend _keys = array_concat(_keys, _ids, _aks)'))
        }
    }
    It 'the report side builds the same key from the assessment id the edge carries and drops a match' {
        foreach ($g in 'Summary', 'Detailed') {
            $b = $script:Graph[$g]
            $b | Should -Match ([regex]::Escape('| extend _egRecArm = tolower(tostring(EdgePropsAny.rawData.recommendationAzureResourceId))'))
            $b | Should -Match ([regex]::Escape('_dfcAkKey = iff(_egRecArm matches regex @"/providers/microsoft\.security/assessments/[^/]+$", ' + $script:Hashed + 'extract(@"^(.*)/providers/microsoft\.security/assessments/[^/]+$", 1, _egRecArm), "|", extract(@"/assessments/([^/]+)$", 1, _egRecArm))))), "-")'))
            $b | Should -Match ([regex]::Escape('| join kind=leftanti (_dfcPairs) on $left._dfcAkKey == $right._dfcKey'))
        }
    }
    It 'the two sides hash the same text -- resource id lower-cased, then the assessment key' {
        # An edge names <resource>/providers/Microsoft.Security/assessments/<key>; Defender's row has ResourceIdLower + AssessmentKey.
        $edge = '/subscriptions/S/resourcegroups/rg/providers/Microsoft.Sql/servers/2linkit-sql/providers/Microsoft.Security/assessments/22E93E92-4A31-B4CD-D640-3EF908430AA6'.ToLowerInvariant()
        $m = [regex]::Match($edge, '^(.*)/providers/microsoft\.security/assessments/([^/]+)$')
        $m.Success | Should -BeTrue
        ($m.Groups[1].Value + '|' + $m.Groups[2].Value) | Should -Be ('/subscriptions/s/resourcegroups/rg/providers/microsoft.sql/servers/2linkit-sql' + '|' + '22e93e92-4a31-b4cd-d640-3ef908430aa6')
    }
}

Describe 'the changed blocks keep the catalog''s KQL rules' {
    It 'no colon in the // comments this change added' {
        foreach ($g in 'Summary', 'Detailed') {
            $lines = $script:Graph[$g] -split "`r?`n"
            $added = New-Object System.Collections.Generic.List[string]
            $in = $false
            foreach ($l in $lines) {
                $isComment = $l -match '^\s*//'
                if ($isComment -and $l -match '#349') { $in = $true }
                elseif (-not $isComment) { $in = $false }
                if ($in) { $added.Add($l) }
            }
            $added.Count | Should -BeGreaterThan 10
            @($added | Where-Object { $_ -match ':' }) | Should -BeNullOrEmpty -Because 'a colon in a // comment inside the YAML block breaks the parse'
        }
    }
    It 'no comment inside an argument list of the new code, and no semicolon in a comment of the pre-fetched lookup' {
        foreach ($g in 'Summary', 'Detailed') {
            foreach ($name in '_AssetFindingEdges_orphan', '_dfcRecByKey') {
                $let = [regex]::Match($script:Graph[$g], "(?s)let $name = .*?;").Value
                $let | Should -Not -Match '//' -Because 'comments go above the binding, never between its arguments'
            }
            $hand = [regex]::Match($script:Graph[$g], '(?s)let _dfcPairs = .*?\| project _dfcKey;').Value
            @(($hand -split "`r?`n") | Where-Object { $_ -match '^\s*//' -and $_ -match ';' }) | Should -BeNullOrEmpty
        }
    }
}
