#Requires -Version 5.1
<#
    #691 -- NEW ATTACK PATH / LATERAL MOVEMENT REPORTS THAT HELP THE SOC (owner 2026-10-15: "another example could be new
    attack paths i dont cover. lateral movements that help soc").

    Four routes no report covered (the 2026-10-15 discovery, ops\report-certification\reviews\attackpath-discovery.md), each
    a Summary + Detailed pair built on the report standard (data in -> the CI -> data out):
      * ServicePrincipal_Impersonates_Users          graph  application -[can impersonate as]-> user
      * Workload_ManagedIdentity_to_Azure_Resources   graph  workload -[can authenticate as]-> managed identity -[has role on / has permissions to]-> resource
      * SignIn_Entitlement_to_Tier0_Servers           graph  user (-[member of]-> group) -[has role on / has permissions to]-> Tier 0 server
      * Owner_to_Privileged_Service_Principal         CI     owner -[owns]-> Tier 0 / 1 service principal (Entra ownership)
    What holds for every one of them: registered everywhere a report is (both templates, scope, severity, finding texts, the
    output contract, a certification spec naming the live reads still needed); the tier comes ONLY from the CI (si_tier /
    _ciPeer), never the Exposure Graph criticality; one slice filter, on the row's own source; the other end's CI from
    _ciPeer after the cut point with its reduction declared; no overlap with the sibling reports' edges.
    Offline: reads the shipped files with SecurityInsight's own YAML reader; nothing runs a query.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\_shared\SI-Yaml.ps1')
    $script:Path = Join-Path $script:SIRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'
    $script:Catalog = ConvertFrom-SIYaml -Yaml ([IO.File]::ReadAllText($script:Path)) -SourceName $script:Path
    function script:Report([string]$Name) { @($script:Catalog.Reports | Where-Object { [string]$_.ReportName -eq $Name })[0] }
    function script:QueryOf([string]$Name) { (@((Report $Name).ReportQuery) | ForEach-Object { [string]$_ }) -join "`n" }
    # the report's own KQL: the generated blocks and comment lines left out
    function script:CodeOf([string]$Name) {
        $out = New-Object System.Collections.Generic.List[string]; $skip = $false
        foreach ($l in ((QueryOf $Name) -split "`r?`n")) {
            if ($l -match '//__SI_(SCOPE|CI_\w+?)_BEGIN__') { $skip = $true; continue }
            if ($l -match '//__SI_(SCOPE|CI_\w+?)_END__') { $skip = $false; continue }
            if ($skip -or $l.Trim() -match '^//') { continue }
            $out.Add($l)
        }
        $out -join "`n"
    }
    $script:Routes = @('ServicePrincipal_Impersonates_Users', 'Workload_ManagedIdentity_to_Azure_Resources', 'SignIn_Entitlement_to_Tier0_Servers', 'Owner_to_Privileged_Service_Principal')
    $script:Graph = @('ServicePrincipal_Impersonates_Users', 'Workload_ManagedIdentity_to_Azure_Resources', 'SignIn_Entitlement_to_Tier0_Servers')
    $script:All = @(foreach ($r in $script:Routes) { foreach ($k in 'Summary', 'Detailed') { 'Attack_Paths_{0}_{1}' -f $k, $r } })
    $dm = Join-Path $script:SIRoot 'data-model'
    $script:Scope = ([IO.File]::ReadAllText((Join-Path $dm 'report-scope.locked.json')) | ConvertFrom-Json).reports
    $script:Severity = ([IO.File]::ReadAllText((Join-Path $dm 'severity-model.locked.json')) | ConvertFrom-Json).reports
    $script:Texts = ([IO.File]::ReadAllText((Join-Path $dm 'finding-texts.locked.json')) | ConvertFrom-Json).reports
    $script:Contract = ([IO.File]::ReadAllText((Join-Path $PSScriptRoot 'fixtures\report-output-contract.json')) | ConvertFrom-Json).reports
    $script:GraphOnly = @(([IO.File]::ReadAllText((Join-Path $script:SIRoot 'risk-analysis-detection\ra-ci-migration.locked.json')) | ConvertFrom-Json).graphOnly | ForEach-Object { [string]$_.report })
    $script:Specs = Join-Path $script:SIRoot 'ops\report-certification\specs'
}

Describe 'the four new routes are registered everywhere a report is' {
    It '<_> is in the catalog with the report fields' -ForEach @(
        'Attack_Paths_Summary_ServicePrincipal_Impersonates_Users', 'Attack_Paths_Detailed_ServicePrincipal_Impersonates_Users',
        'Attack_Paths_Summary_Workload_ManagedIdentity_to_Azure_Resources', 'Attack_Paths_Detailed_Workload_ManagedIdentity_to_Azure_Resources',
        'Attack_Paths_Summary_SignIn_Entitlement_to_Tier0_Servers', 'Attack_Paths_Detailed_SignIn_Entitlement_to_Tier0_Servers',
        'Attack_Paths_Summary_Owner_to_Privileged_Service_Principal', 'Attack_Paths_Detailed_Owner_to_Privileged_Service_Principal') {
        $r = Report $_
        $r | Should -Not -BeNullOrEmpty
        [string]$r.ReportPurpose | Should -Not -BeNullOrEmpty
        [string]$r.ReportPurpose | Should -Not -Match '#\d' -Because 'customer text carries no internal numbers'
        @($r.OutputPropertyOrder) | Should -Contain 'RiskScoreTotal_Weighted'
    }
    It 'every one is in its template (Detailed in RiskAnalysis_Detailed, Summary in RiskAnalysis_Summary)' {
        $det = @(@($script:Catalog.ReportTemplates | Where-Object { $_.ReportName -eq 'RiskAnalysis_Detailed' })[0].ReportsIncluded | ForEach-Object { [string]$_.Name })
        $sum = @(@($script:Catalog.ReportTemplates | Where-Object { $_.ReportName -eq 'RiskAnalysis_Summary' })[0].ReportsIncluded | ForEach-Object { [string]$_.Name })
        $det.Count | Should -BeGreaterThan 60 -Because 'control: the template was read'
        foreach ($n in $script:All) { if ($n -like '*_Detailed_*') { $det | Should -Contain $n } else { $sum | Should -Contain $n } }
    }
    It 'every one has a scope entry, a severity model (the attack-path bands) and finding texts with MITRE' {
        foreach ($n in $script:All) {
            @($script:Scope | Where-Object { $_.id -eq $n }).Count | Should -Be 1 -Because "$n scope"
            $sv = @($script:Severity | Where-Object { $_.id -eq $n })[0]
            $sv | Should -Not -BeNullOrEmpty -Because "$n severity"
            @($sv.order)[0] | Should -Be 'attack_path_priority'
            $t = @($script:Texts | Where-Object { $_.id -eq $n })[0]
            $t | Should -Not -BeNullOrEmpty -Because "$n finding texts"
            [string]$t.si_fix_remediation | Should -Not -BeNullOrEmpty
            @($t.si_mitre_techniques).Count | Should -BeGreaterThan 0
        }
    }
    It 'every one is pinned in the output contract, exactly as it declares its columns' {
        foreach ($n in $script:All) {
            $pin = @($script:Contract.$n)
            $pin.Count | Should -BeGreaterThan 20 -Because "$n is pinned"
            ($pin -join ',') | Should -Be (@((Report $n).OutputPropertyOrder) -join ',')
        }
    }
    It 'the graph routes are on the graph-only list with a reason; the owner route is not (it reads the CI only)' {
        foreach ($r in $script:Graph) { foreach ($k in 'Summary', 'Detailed') { $script:GraphOnly | Should -Contain ('Attack_Paths_{0}_{1}' -f $k, $r) } }
        $script:GraphOnly | Should -Not -Contain 'Attack_Paths_Detailed_Owner_to_Privileged_Service_Principal'
    }
    It 'every Detailed report has a certification spec that names the live reads still needed (not certified)' {
        if (-not (Test-Path -LiteralPath $script:Specs)) { Set-ItResult -Skipped -Because 'ops\report-certification is not in this copy (the Community payload has no report certification)'; return }
        foreach ($r in $script:Routes) {
            $p = Join-Path $script:Specs ('Attack_Paths_Detailed_{0}.json' -f $r)
            Test-Path -LiteralPath $p | Should -BeTrue -Because $p
            $s = [IO.File]::ReadAllText($p) | ConvertFrom-Json
            [string]$s.notes | Should -Match 'NOT CERTIFIED'
            [string]$s.notes | Should -Match 'LIVE READS BEFORE CERTIFICATION'
            [string]$s.siSql | Should -Match ("ReportName = 'Attack_Paths_Detailed_{0}'" -f $r)
            (@($s.sourceKql).Count + @($s.sourceGraph).Count) | Should -BeGreaterThan 0 -Because 'the independent source read is named'
        }
    }
}

Describe 'the report standard -- tier from the CI only, one slice filter, the other end from _ciPeer' {
    It '<_>: no tier from Exposure Graph criticality, a blank level for a target without a tier' -ForEach @(
        'Attack_Paths_Summary_ServicePrincipal_Impersonates_Users', 'Attack_Paths_Detailed_ServicePrincipal_Impersonates_Users',
        'Attack_Paths_Summary_Workload_ManagedIdentity_to_Azure_Resources', 'Attack_Paths_Detailed_Workload_ManagedIdentity_to_Azure_Resources',
        'Attack_Paths_Summary_SignIn_Entitlement_to_Tier0_Servers', 'Attack_Paths_Detailed_SignIn_Entitlement_to_Tier0_Servers',
        'Attack_Paths_Summary_Owner_to_Privileged_Service_Principal', 'Attack_Paths_Detailed_Owner_to_Privileged_Service_Principal') {
        $c = CodeOf $_
        $c | Should -Not -Match 'criticalityLevel|EgCriticality' -Because 'the tier comes from SI_CI_CL only'
        $c | Should -Match ([regex]::Escape('| extend CriticalityTierLevel = case(CriticalityTier == 0, "Critical - tier 0", CriticalityTier == 1, "High - tier 1", CriticalityTier == 2, "Medium - tier 2", CriticalityTier == 3, "Low - tier 3", "")'))
        $c | Should -Match ([regex]::Escape('| extend TargetFactorIds = coalesce(si_rf_p, dynamic([])), TargetFactorNames = coalesce(si_rf_names_, dynamic([]))'))
        $c | Should -Not -Match '\b(take|limit|sample)\b\s+\d' -Because 'nothing cuts the result'
        $c | Should -Not -Match '(?i)"[^"]*unknown[^"]*"' -Because 'no string literal says unknown'
    }
    It '<_>: ONE slice filter, the cut point once, and the declared key lines are the query''s own' -ForEach @(
        'Attack_Paths_Summary_ServicePrincipal_Impersonates_Users', 'Attack_Paths_Detailed_ServicePrincipal_Impersonates_Users',
        'Attack_Paths_Summary_Workload_ManagedIdentity_to_Azure_Resources', 'Attack_Paths_Detailed_Workload_ManagedIdentity_to_Azure_Resources',
        'Attack_Paths_Summary_SignIn_Entitlement_to_Tier0_Servers', 'Attack_Paths_Detailed_SignIn_Entitlement_to_Tier0_Servers',
        'Attack_Paths_Summary_Owner_to_Privileged_Service_Principal', 'Attack_Paths_Detailed_Owner_to_Privileged_Service_Principal') {
        $q = QueryOf $_
        ([regex]::Matches($q, '//__BUCKET_FILTER_BEGIN__')).Count | Should -Be 1
        ([regex]::Matches($q, '//__SI_LOOKUP_KEYS_HERE__')).Count | Should -Be 1
        ([regex]::Matches($q, '//__SI_CI_PEER_BEGIN__')).Count | Should -Be 1
        $decl = @((Report $_).LookupNeededKeys)[0]
        [string]$decl.Lookup | Should -Be '_ciPeer'
        [string]$decl.Column | Should -Be '_peerKey'
        $after = $q.Substring($q.IndexOf('//__SI_LOOKUP_KEYS_HERE__'))
        foreach ($k in @(([string]$decl.Keys) -split "`r?`n" | Where-Object { $_.Trim() -and $_.Trim() -notmatch '^\| project __siNeeded' })) {
            $after | Should -Match ([regex]::Escape($k.Trim())) -Because 'a key line the query does not have finds no key'
        }
        # every _ciPeer join comes after the cut point
        $q.IndexOf('join kind=leftouter (_ciPeer)') | Should -BeGreaterThan $q.IndexOf('//__SI_LOOKUP_KEYS_HERE__')
    }
    It '<_>: the graph route is sliced on the path''s SOURCE, in the edge set that names it' -ForEach @(
        @{ N = 'ServicePrincipal_Impersonates_Users'; Set = 'ImpersonationEdges' }
        @{ N = 'Workload_ManagedIdentity_to_Azure_Resources'; Set = 'WorkloadIdentity' }
        @{ N = 'SignIn_Entitlement_to_Tier0_Servers'; Set = 'Joined' }) {
        foreach ($k in 'Summary', 'Detailed') {
            $c = QueryOf ('Attack_Paths_{0}_{1}' -f $k, $N)
            $let = [regex]::Match($c, '(?s)let ' + $Set + ' =.*?;').Value
            $let | Should -Match 'extend DeviceKey = SourceNodeId\s*\r?\n\s*//__BUCKET_FILTER_BEGIN__'
        }
    }
    It 'the Summary counts what it is sliced on, under an asset-identity name the bucket merge ADDS up (never the max of the slices)' {
        $merge = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-SummaryBucketMerge.ps1'))
        $merge | Should -Match "RA_AssetIdentityColumns = @\([^)]*'DeviceKey'"
        foreach ($r in $script:Graph) {
            $c = CodeOf ('Attack_Paths_Summary_{0}' -f $r)
            $c | Should -Match 'AssetCount\s*= dcount\(DeviceKey\)'
            $c.LastIndexOf('| extend DeviceKey = SourceNodeId') | Should -BeLessThan $c.IndexOf('AssetCount') -Because 'the count key is the slice key, set again after the path is built'
        }
        (CodeOf 'Attack_Paths_Summary_Owner_to_Privileged_Service_Principal') | Should -Match 'AssetCount\s*= dcount\(DeviceKey\)'
        (CodeOf 'Attack_Paths_Summary_Owner_to_Privileged_Service_Principal') | Should -Match 'extend DeviceKey = si_ci_id'
        # the slice filter stays active on the graph side: the Summary re-keys off the EG-native DeviceKey (as the sibling Summaries)
        foreach ($r in $script:Routes) { [string](@((Report ('Attack_Paths_Summary_{0}' -f $r)).crossDomainBucketCoalesce)[0].EgNativeKey) | Should -Be 'DeviceKey' }
    }
    It '<_>: the Detailed row names its path by graph ids and projects the standard columns plus the source tier' -ForEach @(
        'Attack_Paths_Detailed_ServicePrincipal_Impersonates_Users', 'Attack_Paths_Detailed_Workload_ManagedIdentity_to_Azure_Resources',
        'Attack_Paths_Detailed_SignIn_Entitlement_to_Tier0_Servers', 'Attack_Paths_Detailed_Owner_to_Privileged_Service_Principal') {
        $c = CodeOf $_
        $last = $c.Substring($c.LastIndexOf('| project '))
        $last = $last.Substring(0, $last.IndexOf('| order by'))
        $cols = @([regex]::Matches(($last -replace '^\|\s*project', ''), '\b[A-Za-z_][A-Za-z0-9_]*\b') | ForEach-Object { $_.Value }) | Sort-Object -Unique
        $want = @('SecurityDomain', 'Category', 'Subcategory', 'ConfigurationName', 'ConfigurationId', 'AssetName', 'AssetId', 'AssetType', 'Impact',
                  'SecuritySeverity', 'CriticalityTier', 'CriticalityTierLevel', 'cmdbId', 'cmdbName', 'cmdbCriticality', 'cmdbDataSensitivity',
                  'RiskFactor_Consequence', 'RiskFactor_Probability', 'RiskFactor_Probability_Detailed', 'RiskFactor_Probability_DetailedScore',
                  'RiskScore_Weight_Detailed', 'RiskScore_Weight_Factor', 'RiskFactor_Weight', 'SourceCriticalityTier') | Sort-Object -Unique
        ($cols -join ',') | Should -Be ($want -join ',')
        if ($_ -like '*Owner_to_*') { $c | Should -Match 'extend ConfigurationId = strcat\(OwnerId, "->", si_ci_id\)' }
        else { $c | Should -Match 'extend ConfigurationId = PathKey'; $c | Should -Match 'extend PathKey = strcat\(SourceNodeId, "->"' }
    }
}

Describe 'each route asks its own question and stays out of the sibling reports' {
    It 'impersonation reads the can-impersonate-as edge and nothing else' {
        foreach ($k in 'Summary', 'Detailed') {
            $c = CodeOf "Attack_Paths_${k}_ServicePrincipal_Impersonates_Users"
            @([regex]::Matches($c, 'EdgeLabel\s*(=~|in~)\s*\(?"([^"]+)"') | ForEach-Object { $_.Groups[2].Value }) | Should -Be @('can impersonate as')
        }
    }
    It 'the workload route starts at a workload (no credential node -- that is the credential-based report) and ends on an Azure resource' {
        foreach ($k in 'Summary', 'Detailed') {
            $c = CodeOf "Attack_Paths_${k}_Workload_ManagedIdentity_to_Azure_Resources"
            $c | Should -Match 'where TargetNodeLabel =~ "managedidentity"'
            $c | Should -Match 'where not\(set_has_element\(SourceNodeCategories, "secret"\)\)'
            $c | Should -Match 'where SourceNodeId in \(WorkloadIdentity \| distinct IntermediateNodeId\)' -Because 'hop 2 is bound to hop 1 (the scan shrinks with the slice)'
        }
    }
    It 'the entitlement route reads the ENTITLEMENT only -- never the logon edges the admin logon reports read' {
        foreach ($k in 'Summary', 'Detailed') {
            $c = CodeOf "Attack_Paths_${k}_SignIn_Entitlement_to_Tier0_Servers"
            $c | Should -Not -Match 'can authenticate to|frequently logged in by|DeviceLogonEvents'
            $c | Should -Match 'EdgeLabel =~ "member of"'
            $c | Should -Match '\| where TargetCriticalityTier == 0'
            $c | Should -Match '\| where isnull\(SourceCriticalityTier\) or SourceCriticalityTier > 0'
        }
    }
    It 'the owner route reads Entra ownership from the CI: a privileged application, each owner, the owner on a less critical tier' {
        foreach ($k in 'Summary', 'Detailed') {
            $q = QueryOf "Attack_Paths_${k}_Owner_to_Privileged_Service_Principal"
            $c = CodeOf "Attack_Paths_${k}_Owner_to_Privileged_Service_Principal"
            $q | Should -Match '//__SI_CI_ASSET_BEGIN__' -Because 'the application is the CI row of the report'
            $c | Should -Not -Match 'ExposureGraph'
            $c | Should -Match 'mv-expand _ow = _owners to typeof\(dynamic\)'
            $c | Should -Match '\| where si_tier in \(0, 1\)'
            $c | Should -Match '\| where isnull\(SourceCriticalityTier\) or SourceCriticalityTier > si_tier'
            $c | Should -Match 'join kind=leftouter \(_ciPeer\) on \$left\.OwnerCiKey == \$right\._peerKey'
        }
    }
    It 'no new report repeats an existing report''s edge set: the impersonate / workload / entitlement edges were read by none before' {
        $before = @('Attack_Paths_Detailed_Credential_Based_Lateral_Movement', 'Identity_Admin_LogonTo_VulnerableDevice_Detailed',
                    'Attack_Paths_Detailed_Identity_Group_Membership_to_Privileged_Resources')
        foreach ($b in $before) { (CodeOf $b) | Should -Not -Match 'can impersonate as' }
    }
}

Describe 'KQL hygiene in the YAML block' {
    It '<_>: no colon in a // comment and no // comment inside an argument list' -ForEach @(
        'Attack_Paths_Summary_ServicePrincipal_Impersonates_Users', 'Attack_Paths_Detailed_ServicePrincipal_Impersonates_Users',
        'Attack_Paths_Summary_Workload_ManagedIdentity_to_Azure_Resources', 'Attack_Paths_Detailed_Workload_ManagedIdentity_to_Azure_Resources',
        'Attack_Paths_Summary_SignIn_Entitlement_to_Tier0_Servers', 'Attack_Paths_Detailed_SignIn_Entitlement_to_Tier0_Servers',
        'Attack_Paths_Summary_Owner_to_Privileged_Service_Principal', 'Attack_Paths_Detailed_Owner_to_Privileged_Service_Principal') {
        $depth = 0
        foreach ($l in ((QueryOf $_) -split "`r?`n")) {
            $t = $l.Trim()
            if ($t.StartsWith('//')) {
                if ($t -notmatch '^//__') { $t | Should -Not -Match ':' -Because 'a colon in a // comment breaks the YAML reader' }
                $depth | Should -Be 0 -Because "a // comment inside an argument list breaks Log Analytics ($t)"
                continue
            }
            $code = [regex]::Replace($t, '"[^"]*"|''[^'']*''', '""')
            $depth += ([regex]::Matches($code, '\(')).Count - ([regex]::Matches($code, '\)')).Count
        }
    }
}
