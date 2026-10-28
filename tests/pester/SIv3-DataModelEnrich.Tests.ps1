#Requires -Version 5.1
<#
    THE v3 CI ENRICHMENT (engine/data-model/SI-CiEnrich.ps1) -- V3-DATA-MODEL part 2, P3 + 2.19.2.

      * CONVERSION: every detection kind of the existing rule files becomes a condition over SI FIELDS (never a provider
        column); EVERY shipped detection converts (a new kind fails here until it does); disabled rules are skipped.
      * TIER: MIN over the deciding claims; the default rule only when nothing else decided; the trace names the winner.
      * STAGE + TRUST: a testing rule, an untrusted mechanism and evidence older than maxAgeDays are recorded with the
        reason and decide nothing -- the claims are still there for the deviation report.
      * RISK FACTORS (#559 model v2): enabled factors count their catalog impact 1..5, disabled ones are not evaluated; a CI-level coverage gap raises its
        factor and is listed.
      * CRITICALITY: the owning CMDB's vocabulary -> level + factor; data sensitivity combined; an unmapped value -> the
        default factor, said in the source.
      * CMDB JOIN: the service the rules named (si_cmdb_id) brings its name, criticality, data sensitivity, environment
        and owner, and a value a rule set wins; without a rule, a CMDB CI is found by Azure resource / Entra id (strong) or
        by FQDN (weak); no match leaves the CI alone.
      * DATA FOR RULES: Exposure Graph role flags reach si_device_roles (if_true + union items); the profiler's rule
        indexes become record parts (software, inherited tags, query hits); the logon tier comes from the profile rows.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordCapture.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-CiEnrich.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-DataModelTemplates.ps1')
    $script:Model = Get-SIDataModel -Root (Join-Path $script:SIRoot 'data-model')
    $script:Trust = Get-SICiTrustIndex $script:Model['trust']
    $script:Ctx = @{ Lists = (Get-SIDataModelListContext $script:Model); Now = [datetime]'2026-10-08T06:00:00Z' }
    function script:RuleObj([string]$id, $detect, $set, [string[]]$appliesTo = @('endpoint'), [string]$stage, [bool]$fallback = $false, [string[]]$os = @()) {
        $r = [pscustomobject]@{ Id = $id; AppliesTo = $appliesTo; Mode = 'merge'; osPlatformScope = $os; Purpose = $null; Category = $null; Description = $id
            Detections = @([pscustomobject]@{ Id = 'd1'; Detect = $detect; Set = $set; ExcludeAssets = @() }); File = "$id.yaml"; Folder = 'test'; Source = 'tree'; Fallback = $fallback }
        if ($stage) { $r | Add-Member -NotePropertyName Stage -NotePropertyValue $stage }
        $r
    }
    function script:Conv($rules) { (ConvertTo-SICiRules -RuleSet @($rules)).Rules }
}

Describe 'Converting the rule files to SI-field conditions' {
    It 'converts <kind>' -TestCases @(
        @{ kind = 'hasSoftwareInstalled'; spec = @{ kind = 'hasSoftwareInstalled'; tvmSoftwareNames = @('microsoft/active_directory_certificate_services') }; field = 'si_installed_software'; op = 'like' }
        @{ kind = 'osPlatform'; spec = @{ kind = 'osPlatform'; osPatterns = @('(?i)^Windows11$') }; field = 'si_os_name'; op = 'matches' }
        @{ kind = 'egDetectedRoles'; spec = @{ kind = 'egDetectedRoles'; egSignals = @('isDomainController') }; field = 'si_device_roles'; op = 'in' }
        @{ kind = 'groupMembership'; spec = @{ kind = 'groupMembership'; group = 'org-finance' }; field = 'si_group_memberships'; op = 'in' }
        @{ kind = 'mostFrequentUserTier'; spec = @{ kind = 'mostFrequentUserTier'; tierValues = @(0, 1) }; field = 'si_frequent_user_tier'; op = 'in' }
        @{ kind = 'egKustoQuery'; spec = @{ kind = 'egKustoQuery'; query = 'ExposureGraphNodes' }; field = 'si_eg_query_rules'; op = 'contains' }
        @{ kind = 'assetKind'; spec = @{ kind = 'assetKind'; kinds = @('endpoint', 'azure') }; field = 'si_class'; op = 'in' }
    ) {
        $c = ConvertTo-SICiKindCondition -Spec ([pscustomobject]$spec) -RuleId 'R1'
        $c.field | Should -Be $field
        $c.op | Should -Be $op
    }
    It 'keeps the old matching semantics of the trickier kinds' {
        $sw = ConvertTo-SICiKindCondition -Spec ([pscustomobject]@{ kind = 'hasSoftwareInstalled'; tvmSoftwareNames = @('ADCS') })
        @($sw.value) | Should -Be @('adcs', '*/adcs')
        (ConvertTo-SICiKindCondition -Spec ([pscustomobject]@{ kind = 'egDetectedRoles'; egSignals = @('isDomainController', 'isTaggedAsExchangeServer') })).value | Should -Be @('domain_controller', 'exchange')
        (ConvertTo-SICiKindCondition -Spec ([pscustomobject]@{ kind = 'assetKind'; kinds = @('endpoint', 'azure') })).value | Should -Be @('device', 'cloud_resource')
        $ext = ConvertTo-SICiKindCondition -Spec ([pscustomobject]@{ kind = 'hasEntraExtensionAttributeTag'; attribute = 'extensionAttribute6'; value = 'Internal_User'; match = 'exact' })
        Test-SICondition $ext @{ si_tags = @([ordered]@{ source = 'entra'; name = 'extensionAttribute6'; value = 'Internal_User' }) } | Should -BeTrue
        Test-SICondition $ext @{ si_tags = @([ordered]@{ source = 'entra'; name = 'extensionAttribute6'; value = 'External' }) } | Should -BeFalse
        $az = ConvertTo-SICiKindCondition -Spec ([pscustomobject]@{ kind = 'hasAzureTagDirectOrParent'; tag = 'cmdbId'; value = '5' })
        Test-SICondition $az @{ si_azure_parent_tags = @([ordered]@{ source = 'azure-parent'; name = 'cmdbId'; value = '5' }) } | Should -BeTrue
        Test-SICondition $az @{ si_tags = @([ordered]@{ source = 'azure'; name = 'cmdbId'; value = '15' }) } | Should -BeFalse
        $ip = ConvertTo-SICiKindCondition -Spec ([pscustomobject]@{ kind = 'ipInRange'; cidrs = @('10.100.1.0/24') })
        Test-SICondition $ip @{ si_ip_addresses = @('10.100.1.7') } | Should -BeTrue
        $nm = ConvertTo-SICiKindCondition -Spec ([pscustomobject]@{ kind = 'nameMatches'; namePatterns = @('(?i)^dc\d') })
        Test-SICondition $nm @{ si_hostname = 'dc01' } | Should -BeTrue
        Test-SICondition (ConvertTo-SICiKindCondition -Spec ([pscustomobject]@{ kind = 'hasSoftwareInstalled'; tvmSoftwareNames = @('active_directory*') })) @{ si_installed_software = @('microsoft/active_directory_domain_services') } | Should -BeTrue
    }
    It 'converts EVERY detection of the shipped rule files' {
        . (Join-Path $script:SIRoot 'engine\data-model\SI-CiBuildRun.ps1')
        $rs = @(Get-SICiRuleSetAll)
        $rs.Count | Should -BeGreaterThan 500
        $conv = ConvertTo-SICiRules -RuleSet $rs
        (@($conv.Unconverted) -join "`n") | Should -BeNullOrEmpty
        @($conv.Rules).Count | Should -BeGreaterThan 500
        @($conv.Rules | Where-Object { $_.fallback }).Count | Should -BeGreaterThan 0
        foreach ($r in @($conv.Rules)) {
            foreach ($f in (Get-SIConditionFields $r.when)) { $f | Should -Match '^si_' }
        }
    }
    It 'skips disabled rules and maps the OS scope' {
        $r1 = RuleObj 'off' ([pscustomobject]@{ any = @([pscustomobject]@{ kind = 'nameMatches'; namePatterns = @('x') }) }) @{ Tier = 1 }
        $r1.Mode = 'disable'
        $r2 = RuleObj 'srv' ([pscustomobject]@{ any = @([pscustomobject]@{ kind = 'nameMatches'; namePatterns = @('x') }) }) @{ Tier = 1 } -os @('WindowsServer')
        $c = Conv @($r1, $r2)
        @($c).Count | Should -Be 1
        @($c[0].osScope) | Should -Be @('windows_server')
        @($c[0].classes) | Should -Be @('device')
    }
    It 'reads a multi-engine appliesTo the loader joined into one string -- the rule reaches only the classes it names' {
        $r = RuleObj 'both' ([pscustomobject]@{ any = @([pscustomobject]@{ kind = 'nameMatches'; namePatterns = @('x') }) }) @{ Tier = 1 } -appliesTo @('endpoint,identity')
        @((Conv @($r))[0].classes) | Should -Be @('device', 'identity')
    }
}

Describe 'Rules grouped by class (the CI build walks only a CI''s own class''s rules)' {
    BeforeAll {
        $nm = [pscustomobject]@{ any = @([pscustomobject]@{ kind = 'nameMatches'; namePatterns = @('(?i)^srv') }) }
        $kind = [pscustomobject]@{ any = @([pscustomobject]@{ kind = 'assetKind'; kinds = @('endpoint', 'identity') }) }
        $script:MixRules = Conv @(
            (RuleObj 'dev' $nm @{ Tier = 1; Purpose = 'Server' })
            (RuleObj 'idn' $nm @{ Tier = 0; Purpose = 'Admin' } -appliesTo @('identity'))
            (RuleObj 'both' $nm @{ Tier = 2 } -appliesTo @('endpoint,identity'))
            (RuleObj 'off' $nm @{ Tier = 0 } -stage 'not_used')
            (RuleObj 'default' $kind @{ Tier = 3 } -fallback $true -appliesTo @('endpoint,identity'))
        )
    }
    It 'groups in rule order and leaves out rules not in use' {
        $g = Get-SICiRulesByClass -Rules $script:MixRules
        @($g['device'] | ForEach-Object { $_.id }) | Should -Be @('dev/d1', 'both/d1', 'default/d1')
        @($g['identity'] | ForEach-Object { $_.id }) | Should -Be @('idn/d1', 'both/d1', 'default/d1')
        $g.ContainsKey('cloud_resource') | Should -BeFalse
    }
    It 'gives every CI exactly the result of walking all the rules' {
        $mk = { @(
                [ordered]@{ si_class = 'device'; si_asset_name = 'srv01' }
                [ordered]@{ si_class = 'identity'; si_asset_name = 'srv-admin' }
                [ordered]@{ si_class = 'identity'; si_asset_name = 'jane' }
                [ordered]@{ si_class = 'cloud_resource'; si_asset_name = 'srv-kv' }
            ) }
        $plain = & $mk; $grouped = & $mk
        foreach ($ci in $plain) { $null = Invoke-SICiRules -Ci $ci -Rules $script:MixRules -Trust $script:Trust -Context $script:Ctx -Now $script:Ctx.Now }
        $g = Get-SICiRulesByClass -Rules $script:MixRules; $fc = @{}
        foreach ($ci in $grouped) { $null = Invoke-SICiRules -Ci $ci -Rules $script:MixRules -Trust $script:Trust -Context $script:Ctx -Now $script:Ctx.Now -RulesByClass $g -FieldCache $fc }
        for ($i = 0; $i -lt $plain.Count; $i++) {
            (ConvertTo-Json -InputObject $grouped[$i] -Depth 8 -Compress) | Should -Be (ConvertTo-Json -InputObject $plain[$i] -Depth 8 -Compress)
        }
        $plain[0].si_tier | Should -Be 1
        $plain[1].si_tier | Should -Be 0
        $plain[2].si_tier | Should -Be 3
        $plain[3].Contains('si_tier') | Should -BeFalse
    }
    It 'is wired: the enrichment groups the rules once and hands the groups and the field cache to every CI' {
        $code = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\data-model\SI-CiEnrich.ps1'))
        $code | Should -Match '\$byClass = Get-SICiRulesByClass -Rules \$Rules'
        $code | Should -Match 'Invoke-SICiRules -Ci \$ci -Rules \$Rules [^\r\n]*-RulesByClass \$byClass -FieldCache \$fieldCache'
    }
}

Describe 'Rules on a CI: tier, stage and trust' {
    BeforeAll {
        $sw = [pscustomobject]@{ any = @([pscustomobject]@{ kind = 'hasSoftwareInstalled'; tvmSoftwareNames = @('microsoft/adcs') }) }
        $tag = [pscustomobject]@{ any = @([pscustomobject]@{ kind = 'hasMdeMachineGroupTag'; machineTagPatterns = @('(?i)^tier1(-servers)?$') }) }
        $kind = [pscustomobject]@{ any = @([pscustomobject]@{ kind = 'assetKind'; kinds = @('endpoint') }) }
        $script:Rules = Conv @(
            (RuleObj 'ca' $sw @{ Tier = 0; Purpose = 'Certificate authority'; Tags = @('PKI') })
            (RuleObj 'tag1' $tag @{ Tier = 1; Purpose = 'Tagged tier 1' })
            (RuleObj 'default' $kind @{ Tier = 3 } -fallback $true)
        )
    }
    It 'takes the MIN of the deciding claims and traces the winner' {
        $ci = [ordered]@{ si_class = 'device'; si_installed_software = @('microsoft/adcs'); si_machine_groups = @('Tier1-Servers') }
        $null = Invoke-SICiRules -Ci $ci -Rules $script:Rules -Trust $script:Trust -Context $script:Ctx -Now $script:Ctx.Now
        $ci.si_tier | Should -Be 0
        $ci.si_tier_set_by | Should -Be 'rule'
        $ci.si_tier_reason | Should -Match 'Certificate authority'
        $ci.si_purpose | Should -Be 'Certificate authority'
        @($ci.si_tier_claims).Count | Should -Be 3
        @($ci.si_tier_claims | Where-Object { $_.winner }).Count | Should -Be 1
        @($ci.si_tags | Where-Object { $_.name -eq 'PKI' -and $_.source -eq 'rule' }).Count | Should -Be 1
    }
    It 'uses the default rule only when nothing else decided' {
        $ci = [ordered]@{ si_class = 'device' }
        $null = Invoke-SICiRules -Ci $ci -Rules $script:Rules -Trust $script:Trust -Context $script:Ctx
        $ci.si_tier | Should -Be 3
        $ci.si_tier_set_by | Should -Be 'default'
    }
    It 'records a testing rule and an untrusted mechanism without letting them decide' {
        $tr = Conv @((RuleObj 'tst' ([pscustomobject]@{ any = @([pscustomobject]@{ kind = 'nameMatches'; namePatterns = @('(?i)^srv') }) }) @{ Tier = 0 } -stage 'testing'))
        $ci = [ordered]@{ si_class = 'device'; si_asset_name = 'srv1' }
        $null = Invoke-SICiRules -Ci $ci -Rules @($tr) -Trust $script:Trust -Context $script:Ctx
        $ci.Contains('si_tier') | Should -BeFalse
        @($ci.si_tier_claims)[0].admissible | Should -BeFalse
        @($ci.si_tier_claims)[0].reason | Should -Be 'stage: testing'
        $trust = Get-SICiTrustIndex ([pscustomobject]@{ order = @([pscustomobject]@{ id = 'mde.machine_tag'; trusted = $false }) })
        $ci2 = [ordered]@{ si_class = 'device'; si_machine_groups = @('tier1') }
        $null = Invoke-SICiRules -Ci $ci2 -Rules $script:Rules -Trust $trust -Context $script:Ctx
        @($ci2.si_tier_claims | Where-Object { $_.rule -eq 'tag1/d1' })[0].reason | Should -Match 'not trusted'
        $ci2.si_tier | Should -Be 3          # only the default decided
    }
    It 'stops a mechanism deciding when its evidence is older than maxAgeDays' {
        $trust = Get-SICiTrustIndex ([pscustomobject]@{ order = @([pscustomobject]@{ id = 'mde.machine_tag'; trusted = $true; maxAgeDays = 30 }) })
        $ci = [ordered]@{ si_class = 'device'; si_machine_groups = @('tier1'); si_field_sources = [ordered]@{ si_machine_groups = [ordered]@{ provider = 'mde'; observed_at = [datetime]'2026-06-01T00:00:00Z' } } }
        $null = Invoke-SICiRules -Ci $ci -Rules $script:Rules -Trust $trust -Context $script:Ctx -Now $script:Ctx.Now
        @($ci.si_tier_claims | Where-Object { $_.rule -eq 'tag1/d1' })[0].reason | Should -Match '^stale'
    }
}

Describe 'Risk factors, coverage and criticality on a CI' {
    It 'counts enabled factors with their catalog impact (#559), and raises a coverage gap''s factor' {
        $ci = [ordered]@{ si_class = 'device'; si_internet_exposed = $true; si_os_name = 'WindowsServer2012R2'; si_has_leaked_credentials = $true
            si_link_azure = '/subscriptions/s/vm1'; si_azure_resource_type = 'microsoft.compute/virtualmachines' }
        $null = Invoke-SICiRiskFactors -Ci $ci -Factors $script:Model['risk-factors'] -Checks $script:Model['coverage-checks'] -Context $script:Ctx
        $f = @{}; foreach ($x in $ci.si_risk_factors) { $f[$x.id] = $x }
        $imp = @{}; foreach ($x in @($script:Model['risk-factors'].factors)) { $imp[[string]$x.id] = [int]$x.impact }
        $f['internet_exposed'].impact | Should -Be $imp['internet_exposed']
        $f['internet_exposed'].axis | Should -Be 'probability'
        $f['internet_exposed'].side | Should -Be 'asset'
        $f['internet_exposed'].shortName | Should -Be 'InternetExposed'
        $f['unsupported_os'].impact | Should -Be $imp['unsupported_os']
        $f['leaked_credentials'].impact | Should -Be $imp['leaked_credentials']
        $f['leaked_credentials'].state | Should -Be 'enabled'
        $f['leaked_credentials'].stage | Should -Be 'production'
        $f['not_onboarded'].coverage | Should -Be 'azure_vm_not_onboarded'
        @($ci.si_coverage_gaps.id) | Should -Contain 'azure_vm_not_onboarded'
    }
    It 'maps the owning CMDB''s criticality to a level and factor' {
        $ci = [ordered]@{ si_cmdb_criticality = 'High'; si_cmdb_data_sensitivity = 'Restricted' }
        $null = Set-SICiCriticality -Ci $ci -Mapping $script:Model['criticality-mapping'] -CmdbOwner 'cmdb'
        $ci.si_cmdb_criticality_level | Should -Be 'high'
        $ci.si_criticality_factor | Should -Be 1.3          # max(1.25, restricted 1.3)
        $ci.si_criticality_source.data_sensitivity | Should -Be 'Restricted'
        $sn = [ordered]@{ si_cmdb_criticality = '1 - most critical' }
        $null = Set-SICiCriticality -Ci $sn -Mapping $script:Model['criticality-mapping'] -CmdbOwner 'servicenow'
        $sn.si_criticality_factor | Should -Be 1.5
        $sn.si_cmdb_criticality_level | Should -Be 'critical'
        $un = [ordered]@{ si_cmdb_criticality = 'Gold' }
        $null = Set-SICiCriticality -Ci $un -Mapping $script:Model['criticality-mapping'] -CmdbOwner 'cmdb'
        $un.si_criticality_factor | Should -Be 1.0
        $un.si_criticality_source.mapping | Should -Match 'unmapped'
    }
}

Describe 'The owning CMDB''s record on a CI' {
    BeforeAll {
        $script:CmdbIdx = New-SICiCmdbIndex -Services @(
            [pscustomobject]@{ RowKey = 'svc-1'; id = 'SVC-1'; name = 'Payroll'; criticality = 'High'; dataSensitivity = 'Restricted'; environment = 'prod'; owner = 'owner@contoso.com' }
        ) -CmdbCis @(
            [pscustomobject]@{ id = 'SVC-2'; azure_resource_id = '/subscriptions/s/vm9'; name = 'Web'; criticality = 'Low' }
            [pscustomobject]@{ id = 'SVC-3'; fqdn = 'app01.contoso.local'; name = 'App'; criticality = 'Medium' }
        )
    }
    It 'joins the service the rules named; a value a rule set wins' {
        $ci = [ordered]@{ si_cmdb_id = 'svc-1'; si_cmdb_criticality = 'Medium' }
        $null = Set-SICiCmdb -Ci $ci -Index $script:CmdbIdx -CmdbOwner 'cmdb'
        ($ci.si_cmdb_name, $ci.si_cmdb_criticality, $ci.si_cmdb_data_sensitivity, $ci.si_cmdb_environment) | Should -Be @('Payroll', 'Medium', 'restricted', 'prod')
        ($ci.si_cmdb_source, $ci.si_cmdb_match_rule, $ci.si_cmdb_match_confidence) | Should -Be @('cmdb', 'rule', 'strong')
    }
    It 'finds a CMDB CI by identifier (strong) or by FQDN (weak) when no rule named one' {
        $a = [ordered]@{ si_link_azure = '/Subscriptions/S/VM9' }
        $null = Set-SICiCmdb -Ci $a -Index $script:CmdbIdx
        ($a.si_cmdb_id, $a.si_cmdb_name, $a.si_cmdb_match_confidence) | Should -Be @('SVC-2', 'Web', 'strong')
        $f = [ordered]@{ si_fqdn = 'APP01.contoso.local' }
        $null = Set-SICiCmdb -Ci $f -Index $script:CmdbIdx
        ($f.si_cmdb_id, $f.si_cmdb_match_rule, $f.si_cmdb_match_confidence) | Should -Be @('SVC-3', 'name', 'weak')
    }
    It 'leaves a CI alone when nothing matches, and feeds the criticality in the enrichment' {
        $n = [ordered]@{ si_cmdb_id = 'unknown' }
        $null = Set-SICiCmdb -Ci $n -Index $script:CmdbIdx
        $n.Contains('si_cmdb_source') | Should -BeFalse
        $ci = [ordered]@{ si_ci_id = 'c'; si_class = 'device'; si_cmdb_id = 'SVC-1' }
        $null = Invoke-SICiEnrichment -Cis @($ci) -Model $script:Model -CmdbIndex $script:CmdbIdx -Now $script:Ctx.Now
        $ci.si_cmdb_criticality_level | Should -Be 'high'
        $ci.si_criticality_factor | Should -Be 1.3
    }
}

Describe 'Data the rules read' {
    It 'brings Exposure Graph role flags into si_device_roles' {
        $o = [pscustomobject]@{ node = [pscustomobject]@{ NodeId = 'n'; NodeLabel = 'device'; NodeProperties = [pscustomobject]@{ rawData = [pscustomobject]@{ deviceRole = @('DnsServer'); isDomainController = $true; isTaggedAsExchangeServer = 'true' } } } }
        $r = (ConvertTo-SIRecord -Object $o -Mapping $script:Model.Mappings['eg'] -RecordType 'device' -Catalog $script:Model['field-catalog'] -ValueMaps $script:Model['value-maps'].maps).Record
        @($r.si_device_roles | Sort-Object) | Should -Be @('dns_server', 'domain_controller', 'exchange')
    }
    It 'turns the profiler''s rule indexes and profile rows into record parts' {
        $null = Reset-SIRecordCapture -Engine 'endpoint' -Clear
        Add-SIRecordPart -Provider mde -RecordType device -Key 'dev1' -Part machine -Object ([pscustomobject]@{ id = 'dev1' })
        Add-SIRecordPart -Provider azure -RecordType azure_resource -Key '/subscriptions/s1/resourcegroups/rg1/providers/x/y' -Part resource -Object ([pscustomobject]@{ id = '/x' })
        $idx = @{ tvmSoftware = @{ dev1 = @('microsoft/adcs') }
            parentChain = @{ '/subscriptions/s1' = @(@{ tag = 'env'; value = 'prod' }, @{ tag = 'cmdbId'; value = '1' }); '/subscriptions/s1/resourcegroups/rg1' = @(@{ tag = 'cmdbId'; value = '5' }) }
            kustoSets = @{ 'AdcsRule' = (New-Object 'System.Collections.Generic.HashSet[string]' (, [string[]]@('dev1'))) } }
        Add-SIRecordPartsFromRuleIndexes -Indexes $idx
        Add-SIRecordPartsFromProfileRows -Rows @([pscustomobject]@{ MdeDeviceId = 'DEV1'; MostFrequentUserTier = 0 })
        $recs = @{}; foreach ($c in @(Get-SICapturedRecords)) { $recs[$c.Provider] = $c.Object }
        @($recs['mde'].software) | Should -Be @('microsoft/adcs')
        @($recs['mde'].egQueryRules) | Should -Be @('AdcsRule')
        $recs['mde'].logon.MostFrequentUserTier | Should -Be 0
        $recs['azure'].parentTags['cmdbId'] | Should -Be '5'           # the resource group is nearer than the subscription
        $recs['azure'].parentTags['env'] | Should -Be 'prod'
    }
    It 'loads every rule in a clean runspace -- nothing the profilers define is assumed (ring 1: Write-SIInfo stopped the CI build)' {
        $ps = [powershell]::Create()
        try {
            $null = $ps.AddScript("`$ErrorActionPreference = 'Stop'; . '$((Join-Path $script:SIRoot 'engine\data-model\SI-CiBuildRun.ps1').Replace("'", "''"))'; @(Get-SICiRuleSetAll).Count")
            $out = @($ps.Invoke())
            $errs = @($ps.Streams.Error | ForEach-Object { $_.ToString() })
            $errs | Should -BeNullOrEmpty
            [int]$out[-1] | Should -BeGreaterThan 0
        } finally { $ps.Dispose() }
    }
    It 'is wired: the indexes are handed over, Output passes the profile rows, the CI build enriches' {
        [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\shared\RuleIndexes.ps1')) | Should -Match '\$global:SIRuleIndexesForRecords = \$script:SIRuleIndexes'
        [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\stages\Invoke-Output.ps1')) | Should -Match 'Publish-SIRecords -RunContext \$RunContext -ProfileRows @\(\$flat\)'
        [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\data-model\SI-CiBuildRun.ps1')) | Should -Match 'Invoke-SICiEnrichment -Cis'
    }
}

Describe 'Parallel enrichment on PowerShell 7 (one thread per CPU; 5.1 and one CPU keep the loop)' {
    It 'decides the threads: <why>' -TestCases @(
        @{ why = 'PowerShell 5.1 -> the loop';           a = @{ Count = 9000; PsMajor = 5; Cpus = 4 };  n = 1 }
        @{ why = 'too few CIs -> the loop';              a = @{ Count = 100; PsMajor = 7; Cpus = 4 };   n = 1 }
        @{ why = 'one CPU -> the loop';                  a = @{ Count = 9000; PsMajor = 7; Cpus = 1 };  n = 1 }
        @{ why = 'switched off -> the loop';             a = @{ Count = 9000; PsMajor = 7; Cpus = 4; Setting = 'off' }; n = 1 }
        @{ why = 'the job''s CPUs';                      a = @{ Count = 9000; PsMajor = 7; Cpus = 4 };  n = 4 }
        @{ why = 'a number set wins';                    a = @{ Count = 9000; PsMajor = 7; Cpus = 4; Setting = '6' }; n = 6 }
        @{ why = 'never more than 16';                   a = @{ Count = 9000; PsMajor = 7; Cpus = 64 }; n = 16 }
    ) {
        $p = @{ Setting = $null }; foreach ($k in $a.Keys) { $p[$k] = $a[$k] }
        Get-SICiParallelism @p | Should -Be $n
    }
    It 'gives every CI exactly the result of the loop (PowerShell 7)' -Skip:($PSVersionTable.PSVersion.Major -lt 7) {
        $nm = [pscustomobject]@{ any = @([pscustomobject]@{ kind = 'nameMatches'; namePatterns = @('(?i)^srv') }) }
        $kind = [pscustomobject]@{ any = @([pscustomobject]@{ kind = 'assetKind'; kinds = @('endpoint', 'identity') }) }
        $rules = Conv @(
            (RuleObj 'dev' $nm @{ Tier = 1; Purpose = 'Server' })
            (RuleObj 'idn' $nm @{ Tier = 0; Purpose = 'Admin' } -appliesTo @('identity'))
            (RuleObj 'default' $kind @{ Tier = 3 } -fallback $true -appliesTo @('endpoint,identity'))
        )
        $mk = { foreach ($i in 1..700) {
                $cls = @('device', 'identity', 'cloud_resource')[$i % 3]
                [ordered]@{ si_class = $cls; si_asset_name = $(if ($i % 2) { "srv$i" } else { "user$i" }) }
            } }
        $loop = @(& $mk); $par = @(& $mk)
        $saved = $global:SI_CiParallel
        try {
            $global:SI_CiParallel = 'off'
            $null = Invoke-SICiEnrichment -Cis $loop -Model $script:Model -Rules $rules -Now $script:Ctx.Now
            $global:SI_CiParallel = '4'
            $null = Invoke-SICiEnrichment -Cis $par -Model $script:Model -Rules $rules -Now $script:Ctx.Now
        } finally { $global:SI_CiParallel = $saved }
        for ($i = 0; $i -lt $loop.Count; $i++) {
            (ConvertTo-Json -InputObject $par[$i] -Depth 8 -Compress) | Should -Be (ConvertTo-Json -InputObject $loop[$i] -Depth 8 -Compress)
        }
        @($par | Where-Object { $_['si_tier'] -eq 0 }).Count | Should -BeGreaterThan 0
    }
    It 'is built so PowerShell 5.1 never parses the parallel block, and a failed chunk fails the enrichment' {
        $code = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\data-model\SI-CiEnrich.ps1'))
        $code | Should -Match ([regex]::Escape('$body = [scriptblock]::Create(@'''))
        $code | Should -Match ([regex]::Escape('ForEach-Object -ThrottleLimit $threads -Parallel $body'))
        $code | Should -Match 'CI enrichment failed on \{0\} of \{1\} chunk'
        # outside the text block, no $using: anywhere in the file
        ($code -replace "(?s)\[scriptblock\]::Create\(@'.*?'@\)", '') | Should -Not -Match '\$using:'
    }
}
