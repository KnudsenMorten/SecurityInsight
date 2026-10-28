#Requires -Version 5.1
<#
    #389 -- A PROFILE RULE'S CMDB OVERRIDE WINS OVER THE CMDB RECORD, FIELD BY FIELD.

    Operator (2026-10-05), asked "should the rule's override win?": "yes". Found live on ring 1: a custom
    ADDomainController rule (cmdbId 1, cmdbDataSensitivity 'Restricted') and a custom VisualCron rule (cmdbId 6,
    cmdbDataSensitivity 'Confidential') matched dc1 / dc3 / mgmt1, yet the profile rows carried the CMDB record's values
    (Confidential for the DCs, Restricted for mgmt1): Stage Profile copied only cmdbId and cmdbName from a rule.

    What these tests keep true:
      * PRECEDENCE: rule override > CMDB record > nothing, for cmdbName / cmdbCriticality / cmdbDataSensitivity; the
        source of each is recorded (CmdbNameSource / CmdbCriticalitySource / CmdbDataSensitivitySource = 'rule:<RuleId>'
        | 'cmdb' | '');
      * THE LIVE CASE, end to end through the REAL Stage Profile (Invoke-Profile.ps1, run from a scratch tree whose rule
        loader and evaluator are stand-ins), the REAL Stage Reconcile over a CMDB.csv cache built by the REAL refresh, and
        the REAL endpoint row builder: dc1 / dc3 Restricted (rule) over Confidential (CMDB), mgmt1 Confidential (rule)
        over Restricted (CMDB), and an asset with no override keeps the CMDB value, sourced 'cmdb';
      * WEIGHTING follows the effective values (the case() Build-WeightedFactorsKql generates from the shipped sample
        weights): dc 180 -> 195, mgmt1 143 -> 132;
      * the SQL CMDB connector writes the same precedence into cmdbsync.ConfigurationItem (Criticality, DataSensitivity),
        so the ServiceNow hand-off's criticality is the effective one;
      * the schemas declare the source columns and the CI table gains DataSensitivity in place.
    Offline: Mock storage, fake Log Analytics and SQL. PS 5.1 + pwsh 7.
#>

BeforeDiscovery {
    # The SQL CMDB connector is SecurityInsight Pro: a Community copy does not carry it, so its block is skipped there.
    $script:HasProCmdb = Test-Path -LiteralPath (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'engine\asset-cmdb\_shared\SI-CmdbSqlSync.ps1')
}

BeforeAll {
    $script:Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:Root 'engine\asset-profiling\_shared\Write-SIStyle.ps1')
    . (Join-Path $script:Root 'engine\asset-profiling\shared\CmdbSource.ps1')
    . (Join-Path $script:Root 'engine\asset-profiling\shared\CmdbFieldPrecedence.ps1')
    . (Join-Path $script:Root 'engine\asset-profiling\storage\StorageContext.ps1')
    . (Join-Path $script:Root 'engine\asset-profiling\storage\CmdbCache.ps1')
    . (Join-Path $script:Root 'engine\asset-profiling\storage\StagingBlob.ps1')
    . (Join-Path $script:Root 'engine\asset-profiling\stages\Invoke-Reconcile.ps1')
    . (Join-Path $script:Root 'engine\risk-analysis\_shared\RA-WeightedFactors.ps1')
    if (-not (Get-Command Write-SIInfo -ErrorAction SilentlyContinue)) { function script:Write-SIInfo { param($m) } }
    if (-not (Get-Command Reset-SIProgress -ErrorAction SilentlyContinue)) { function script:Reset-SIProgress { param($Label) } }
    if (-not (Get-Command Write-SIProgress -ErrorAction SilentlyContinue)) { function script:Write-SIProgress { param($Label, $Index, $Total) } }

    $script:SavedGlobals = @{}
    foreach ($n in 'SI_EnableCmdbProvider', 'SI_CmdbCsvPath', 'SI_SingleProcess', 'SI_ProSqlServer', 'SI_ProSqlDatabase', 'SITest_Rules') {
        $v = Get-Variable -Name $n -Scope Global -ErrorAction SilentlyContinue
        $script:SavedGlobals[$n] = if ($v) { , @($true, $v.Value) } else { , @($false, $null) }
    }
    $global:SI_EnableCmdbProvider = $true
    $global:SI_SingleProcess = $false
    $global:SI_ProSqlServer = $null; $global:SI_ProSqlDatabase = $null

    # THE LIVE CMDB (ring 1, 2026-10-05), names generic: service 1 Confidential / Critical, service 6 Restricted / Medium.
    $script:CsvText = @(
        'cmdbID;cmdbName;DataSensitivity;Criticality;Owner;OwnerMail'
        '1;Active Directory;Confidential;Critical;Identity Team;id@example.com'
        '6;Automation;Restricted;Medium;Automation Team;auto@example.com'
    ) -join "`r`n"
    # THE LIVE RULES: what the two custom rules set (ADDomainController.custom.yaml / VisualCron.custom.yaml)
    $script:Rules = @(
        [pscustomobject]@{ Id = 'ADDomainController'; Hits = @('dc1', 'dc3'); Set = @{ Tier = 0; Purpose = 'Domain Controller'; Category = 'Server Roles'; cmdbId = 1; cmdbDataSensitivity = 'Restricted' } }
        [pscustomobject]@{ Id = 'VisualCron'; Hits = @('mgmt1'); Set = @{ Tier = 1; Purpose = 'Automation'; Category = 'Application Service'; cmdbId = 6; cmdbDataSensitivity = 'Confidential' } }
        [pscustomobject]@{ Id = 'AdNoOverride'; Hits = @('dc9'); Set = @{ Tier = 0; cmdbId = 1 } }
    )

    function script:New-TempDir {
        $d = Join-Path ([IO.Path]::GetTempPath()) ('si-ruleoverride-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Force -Path $d | Out-Null
        $d
    }

    # A scratch tree that runs the REAL Invoke-Profile.ps1: the stage dot-sources its helpers from its own folder, so the
    # rule loader / evaluator / index builder there are stand-ins (the live rules above), and storage + the precedence
    # helper dot-source the real files.
    function script:New-ProfileTree {
        $t = New-TempDir
        $stages = Join-Path $t 'engine\asset-profiling\stages'; $shared = Join-Path $t 'engine\asset-profiling\shared'; $storage = Join-Path $t 'engine\asset-profiling\storage'
        foreach ($d in $stages, $shared, $storage) { New-Item -ItemType Directory -Force -Path $d | Out-Null }
        Copy-Item (Join-Path $script:Root 'engine\asset-profiling\stages\Invoke-Profile.ps1') $stages
        $real = Join-Path $script:Root 'engine\asset-profiling'
        Set-Content -Path (Join-Path $shared 'Get-SIRuleSet.ps1') -Value 'function Get-SIRuleSet { param($Engine) @($global:SITest_Rules) }'
        Set-Content -Path (Join-Path $shared 'RuleIndexes.ps1') -Value 'function Build-SIRuleIndexes { param($Engine, $Rules, $Assets, $RunContext) @{} }'
        Set-Content -Path (Join-Path $shared 'RuleEval.ps1') -Value @'
function Get-SIAssetOsClass { param($Asset) 'WindowsServer' }
function Get-SIAssetField { param($Asset, $Name) '' }
function Invoke-SIRuleEval { param($Asset, $Rule) if (@($Rule.Hits) -contains [string]$Asset.AssetName) { [pscustomobject]@{ RuleId = $Rule.Id; DetectionId = $Rule.Id; Set = $Rule.Set } } }
'@
        Set-Content -Path (Join-Path $shared 'CmdbFieldPrecedence.ps1') -Value (". '{0}'" -f (Join-Path $real 'shared\CmdbFieldPrecedence.ps1'))
        Set-Content -Path (Join-Path $storage 'StagingBlob.ps1') -Value (". '{0}'" -f (Join-Path $real 'storage\StagingBlob.ps1'))
        $t
    }

    # Profile -> Reconcile -> rows, the way a run does it, over the Mock staging blob and a CMDB.csv cache
    function script:Invoke-LiveCase {
        param([object[]]$Assets)
        $ctx = New-SIStorageContext -Mock
        $csv = Join-Path (New-TempDir) 'CMDB.csv'
        [IO.File]::WriteAllText($csv, $script:CsvText, (New-Object System.Text.UTF8Encoding($true)))
        $null = & (Join-Path $script:Root 'asset-profiling-providers\generic-cmdb\Refresh-CmdbCache.ps1') -Source 'generic-csv' -CsvPath $csv -Context $ctx 6>$null
        $ctx.MockState.Blobs['stg'] = @{}
        $recs = @($Assets | ForEach-Object { [pscustomobject]@{ AssetName = $_; PrimaryEntityId = $_; Verdict = [pscustomobject]@{ SI_Tier = 3 }; Metadata = [pscustomobject]@{ MDE_DeviceName = $_ } } })
        $null = Write-SIStageShard -Context $ctx -ContainerName 'stg' -RunId 'run1' -Stage 'Classify' -ShardIndex 0 -Records $recs
        $rc = [pscustomobject]@{ Engine = 'endpoint'; StorageContext = $ctx; StagingContainer = 'stg'; RunId = 'run1'; ShardIndex = 0; CmdbSource = 'generic-csv'; CollectionTime = '2026-10-05T00:00:00Z' }
        $global:SITest_Rules = $script:Rules
        $tree = New-ProfileTree
        . (Join-Path $tree 'engine\asset-profiling\stages\Invoke-Profile.ps1')
        $null = Invoke-SIProfile -RunContext $rc 6>$null
        $null = Invoke-SIReconcile -RunContext $rc 6>$null 3>$null
        $out = @{}
        foreach ($r in @(Read-SIStageShards -Context $ctx -ContainerName 'stg' -RunId 'run1' -Stage 'Classify' -ReplicaIndex 0)) { $out[[string]$r.AssetName] = $r }
        $out
    }

    # The CMDB weight factor (combine product, basis 100) the case() Build-WeightedFactorsKql GENERATES from the shipped
    # sample weights, read back from the generated KQL and applied as KQL applies it.
    function script:Get-WeightFactor([string]$Criticality, [string]$Sensitivity) {
        $sample = Get-Content -Raw -Encoding UTF8 (Join-Path $script:Root 'risk-analysis-detection\riskscore_weighted.schema.custom.sample.json') | ConvertFrom-Json
        $ep = $sample.weightedRiskFactors.endpoint
        $kql = Build-WeightedFactorsKql -Config ([pscustomobject]@{ Fields = @($ep.fields); Combine = [string]$ep.combine; MaxMultiplier = [int]$ep.maxMultiplier })
        $maps = @{}
        foreach ($m in [regex]::Matches($kql, '\| extend RF_W_(\w+) = case\((?<body>.*?)\n\s*(?<def>\d+)\s*\n\)', [Text.RegularExpressions.RegexOptions]::Singleline)) {
            $map = @{}
            foreach ($c in [regex]::Matches($m.Groups['body'].Value, 'column_ifexists\("(?<f>[^"]+)", ""\)\)\)\) == "(?<k>[^"]*)", (?<v>\d+),')) { $map[$c.Groups['k'].Value] = [int]$c.Groups['v'].Value }
            $maps[$m.Groups[1].Value] = @{ Map = $map; Default = [int]$m.Groups['def'].Value }
        }
        $kql | Should -Match 'RiskScore_Weight_Factor = min_of\(500, \(RF_W_cmdbCriticality \* RF_W_cmdbDataSensitivity\) / 100\)'
        $w = { param($f, $v) $k = ([string]$v).Trim().ToLowerInvariant(); if ($maps[$f].Map.ContainsKey($k)) { $maps[$f].Map[$k] } else { $maps[$f].Default } }
        [int][Math]::Floor((& $w 'cmdbCriticality' $Criticality) * (& $w 'cmdbDataSensitivity' $Sensitivity) / 100)
    }
}

AfterAll {
    foreach ($n in $script:SavedGlobals.Keys) {
        $s = $script:SavedGlobals[$n]
        if ($s[0]) { Set-Variable -Name $n -Scope Global -Value $s[1] } else { Remove-Variable -Name $n -Scope Global -ErrorAction SilentlyContinue }
    }
}

Describe 'PRECEDENCE -- which rule answers, field by field' {
    It 'the rule that supplied cmdbId wins for every field it sets; a field it does not set comes from the first rule that sets it' {
        $m = @(
            [pscustomobject]@{ RuleId = 'NoKey'; cmdbId = $null; cmdbCriticality = 'Low' }
            [pscustomobject]@{ RuleId = 'Owner'; cmdbId = '1'; cmdbDataSensitivity = 'Restricted' }
            [pscustomobject]@{ RuleId = 'Later'; cmdbId = '2'; cmdbDataSensitivity = 'Public'; cmdbName = 'Later name' }
        )
        $o = Get-SIRuleCmdbOverrides -RuleMatches $m
        $o['cmdbDataSensitivity'].Value | Should -Be 'Restricted'; $o['cmdbDataSensitivity'].RuleId | Should -Be 'Owner'
        $o['cmdbCriticality'].Value | Should -Be 'Low'; $o['cmdbCriticality'].RuleId | Should -Be 'NoKey'
        $o['cmdbName'].Value | Should -Be 'Later name'; $o['cmdbName'].RuleId | Should -Be 'Later'
    }
    It 'no rule sets a field -> it is absent; no matches -> nothing' {
        (Get-SIRuleCmdbOverrides -RuleMatches @([pscustomobject]@{ RuleId = 'r'; cmdbId = '1' })).Count | Should -Be 0
        (Get-SIRuleCmdbOverrides -RuleMatches @()).Count | Should -Be 0
        (Get-SIRuleCmdbOverrides -RuleMatches $null).Count | Should -Be 0
    }
    It 'a rule override is kept by Reconcile; an empty field takes the CMDB value with source cmdb; no value stays empty' {
        $r = [pscustomobject]@{ AssetName = 'x' }
        [void](Set-SIRuleCmdbOverrides -Record $r -RuleMatches @([pscustomobject]@{ RuleId = 'R1'; cmdbId = '1'; cmdbDataSensitivity = 'Restricted' }))
        Merge-SICmdbRecordField -Record $r -Field 'cmdbDataSensitivity' -CmdbValue 'Confidential' | Should -Be 'kept'
        Merge-SICmdbRecordField -Record $r -Field 'cmdbCriticality' -CmdbValue 'Critical' | Should -Be 'filled'
        Merge-SICmdbRecordField -Record $r -Field 'cmdbName' -CmdbValue '' | Should -Be 'none'
        $r.cmdbDataSensitivity | Should -Be 'Restricted'; $r.CmdbDataSensitivitySource | Should -Be 'rule:R1'
        $r.cmdbCriticality | Should -Be 'Critical'; $r.CmdbCriticalitySource | Should -Be 'cmdb'
        $r.PSObject.Properties['cmdbName'] | Should -BeNullOrEmpty
    }
    It 'a value already there WITHOUT a recorded source is labelled cmdb only when it equals the CMDB value -- never invented' {
        $a = [pscustomobject]@{ cmdbCriticality = 'High' }
        [void](Merge-SICmdbRecordField -Record $a -Field 'cmdbCriticality' -CmdbValue 'High')
        $a.CmdbCriticalitySource | Should -Be 'cmdb'
        $b = [pscustomobject]@{ cmdbCriticality = 'High' }
        [void](Merge-SICmdbRecordField -Record $b -Field 'cmdbCriticality' -CmdbValue 'Low')
        $b.cmdbCriticality | Should -Be 'High'
        $b.PSObject.Properties['CmdbCriticalitySource'] | Should -BeNullOrEmpty
    }
}

Describe 'THE LIVE CASE -- real Profile -> Reconcile -> row (ring 1, 2026-10-05)' {
    BeforeAll { $script:Out = Invoke-LiveCase -Assets @('dc1', 'dc3', 'mgmt1', 'dc9', 'pc1') }
    It 'dc1 / dc3: the DC rule''s Restricted wins over the CMDB record''s Confidential; criticality stays the CMDB''s Critical' {
        foreach ($n in 'dc1', 'dc3') {
            $r = $script:Out[$n]
            $r.cmdbId | Should -Be '1'
            $r.cmdbDataSensitivity | Should -Be 'Restricted'; $r.CmdbDataSensitivitySource | Should -Be 'rule:ADDomainController'
            $r.cmdbCriticality | Should -Be 'Critical'; $r.CmdbCriticalitySource | Should -Be 'cmdb'
            $r.cmdbName | Should -Be 'Active Directory'; $r.CmdbNameSource | Should -Be 'cmdb'
        }
    }
    It 'mgmt1: the VisualCron rule''s Confidential wins over the CMDB record''s Restricted' {
        $r = $script:Out['mgmt1']
        $r.cmdbId | Should -Be '6'
        $r.cmdbDataSensitivity | Should -Be 'Confidential'; $r.CmdbDataSensitivitySource | Should -Be 'rule:VisualCron'
        $r.cmdbCriticality | Should -Be 'Medium'; $r.CmdbCriticalitySource | Should -Be 'cmdb'
    }
    It 'an asset whose rule sets no override keeps the CMDB value, sourced cmdb; an unmatched asset has none' {
        $r = $script:Out['dc9']
        $r.cmdbDataSensitivity | Should -Be 'Confidential'; $r.CmdbDataSensitivitySource | Should -Be 'cmdb'
        $p = $script:Out['pc1']
        [string]$p.cmdbDataSensitivity | Should -Be ''; [string]$p.CmdbDataSensitivitySource | Should -Be ''
    }
    It 'the rule match records the override, so the SIRules evidence shows why' {
        $m = @($script:Out['dc1'].Verdict.SI_RuleMatches)[0]
        $m.RuleId | Should -Be 'ADDomainController'; $m.cmdbDataSensitivity | Should -Be 'Restricted'
        @($script:Out['dc9'].Verdict.SI_RuleMatches)[0].PSObject.Properties['cmdbDataSensitivity'] | Should -BeNullOrEmpty -Because 'a rule that sets no override leaves SIRules as it was'
    }
    It 'the endpoint profile row carries the effective values and their sources' {
        . (Join-Path $script:Root 'engine\asset-profiling\shared\Build-EndpointProfileRow.ps1')
        $rc = [pscustomobject]@{ Engine = 'endpoint'; RunId = 't'; CollectionTime = '2026-10-05T00:00:00Z' }
        $row = Build-SIEndpointProfileRow -Record $script:Out['dc1'] -RunContext $rc
        [string]$row.cmdbDataSensitivity | Should -Be 'Restricted'
        [string]$row.CmdbDataSensitivitySource | Should -Be 'rule:ADDomainController'
        [string]$row.cmdbCriticality | Should -Be 'Critical'
        [string]$row.CmdbCriticalitySource | Should -Be 'cmdb'
    }
    It 'WEIGHTING follows the effective values: dc 180 -> 195, mgmt1 143 -> 132 (shipped sample weights, product)' {
        Get-WeightFactor 'Critical' 'Confidential' | Should -Be 180     # before: the CMDB record's value
        Get-WeightFactor $script:Out['dc1'].cmdbCriticality $script:Out['dc1'].cmdbDataSensitivity | Should -Be 195
        Get-WeightFactor $script:Out['dc3'].cmdbCriticality $script:Out['dc3'].cmdbDataSensitivity | Should -Be 195
        Get-WeightFactor 'Medium' 'Restricted' | Should -Be 143
        Get-WeightFactor $script:Out['mgmt1'].cmdbCriticality $script:Out['mgmt1'].cmdbDataSensitivity | Should -Be 132
    }
    It 'with CMDB off, a rule''s override is ignored exactly like its cmdbId' {
        $global:SI_EnableCmdbProvider = $false
        try { $o = Invoke-LiveCase -Assets @('dc1') } finally { $global:SI_EnableCmdbProvider = $true }
        [string]$o['dc1'].cmdbDataSensitivity | Should -Not -Be 'Restricted'
        [string]$o['dc1'].CmdbDataSensitivitySource | Should -Not -Match '^rule:'
    }
}

Describe 'THE SCHEMAS -- the source columns are declared, the same in all three engines' {
    It '<_> declares CmdbNameSource / CmdbCriticalitySource / CmdbDataSensitivitySource as derived strings' -ForEach @('endpoint', 'identity', 'azure') {
        $j = Get-Content -Raw (Join-Path $script:Root ("asset-profiling-schema\{0}.schema.locked.json" -f $_)) | ConvertFrom-Json
        foreach ($c in 'CmdbNameSource', 'CmdbCriticalitySource', 'CmdbDataSensitivitySource') {
            $f = @($j.fields | Where-Object { $_.name -ceq $c })
            $f.Count | Should -Be 1 -Because "$_ must declare $c"
            $f[0].source | Should -Be 'derived'; $f[0].type | Should -Be 'string'
        }
    }
    It 'every row builder emits them (endpoint, identity, azure)' {
        foreach ($b in 'Build-EndpointProfileRow.ps1', 'Build-IdentityProfileRow.ps1', 'Build-AzureProfileRow.ps1') {
            $src = Get-Content -Raw (Join-Path $script:Root ("engine\asset-profiling\shared\{0}" -f $b))
            $src | Should -Match "'CmdbNameSource','CmdbCriticalitySource','CmdbDataSensitivitySource'\)" -Because "$b must emit the source columns"
        }
    }
}

Describe 'THE SQL CMDB CONNECTOR -- the same precedence in cmdbsync.ConfigurationItem' -Skip:(-not $script:HasProCmdb) {
    BeforeAll {
        . (Join-Path $script:Root 'engine\_shared\SI-KqlError.ps1')
        . (Join-Path $script:Root 'engine\_shared\data-sql\SI-DataModel.ps1')
        . (Join-Path $script:Root 'engine\pro-data\_shared\SI-DataKql.ps1')
        . (Join-Path $script:Root 'engine\_shared\data-sql\SI-DataSql.ps1')
        . (Join-Path $script:Root 'engine\asset-cmdb\_shared\SI-CmdbSqlSync.ps1')
        $script:Now = [datetime]::SpecifyKind([datetime]'2026-10-05T06:00:00', [DateTimeKind]::Utc)
        $t = $script:Now.ToString('o')
        $script:Profiles = @(
            [pscustomobject]@{ Kind = 'endpoint'; SI_AssetId = 'dc1'; SI_AssetName = 'dc1'; Tier = 0; CollectionTime = $t }
            [pscustomobject]@{ Kind = 'endpoint'; SI_AssetId = 'mgmt1'; SI_AssetName = 'mgmt1'; Tier = 1; CollectionTime = $t }
            [pscustomobject]@{ Kind = 'endpoint'; SI_AssetId = 'dc9'; SI_AssetName = 'dc9'; Tier = 0; CollectionTime = $t }
            [pscustomobject]@{ Kind = 'azure'; SI_AssetId = 'vm-dc1'; SI_AssetName = 'dc1-vm'; Tier = 0; CollectionTime = $t }
        )
        $script:MapRows = @(
            [pscustomobject]@{ SI_AssetId = 'dc1'; SI_CorrelationId = 'corr-dc1'; SI_IdSource = 'ledger'; SI_MemberEngine = 'endpoint'; SI_IdentifierType = 'MdeDeviceId'; SI_IdentifierValue = 'mde-dc1' }
            [pscustomobject]@{ SI_AssetId = 'vm-dc1'; SI_CorrelationId = 'corr-dc1'; SI_IdSource = 'ledger'; SI_MemberEngine = 'azure'; SI_IdentifierType = 'AzureResourceId'; SI_IdentifierValue = '/subscriptions/s/vm-dc1' }
        )
        # the Pro database's services: AD (Critical / Confidential) for dc1 + dc9, Automation (Medium / Restricted) for mgmt1
        $script:Enrichment = Merge-SICmdbSqlEnrichment -ServiceRows @(
            @{ AssetKey = 'corr-dc1'; ServiceKey = 'SVC-0001'; ServiceName = 'Active Directory'; Criticality = 'Critical'; CriticalityRank = 1; DataSensitivity = 'Confidential'; Source = 'cmdb-si' }
            @{ AssetKey = 'dc9'; ServiceKey = 'SVC-0001'; ServiceName = 'Active Directory'; Criticality = 'Critical'; CriticalityRank = 1; DataSensitivity = 'Confidential'; Source = 'cmdb-si' }
            @{ AssetKey = 'mgmt1'; ServiceKey = 'SVC-0006'; ServiceName = 'Automation'; Criticality = 'Medium'; CriticalityRank = 3; DataSensitivity = 'Restricted'; Source = 'cmdb-si' })
        # what Log Analytics answers for the rule-override read: the profile rows' effective values and sources
        $script:OverrideRows = @(
            [pscustomobject]@{ SI_AssetId = 'dc1'; cmdbCriticality = 'Critical'; CmdbCriticalitySource = 'cmdb'; cmdbDataSensitivity = 'Restricted'; CmdbDataSensitivitySource = 'rule:ADDomainController' }
            [pscustomobject]@{ SI_AssetId = 'mgmt1'; cmdbCriticality = 'Medium'; CmdbCriticalitySource = 'cmdb'; cmdbDataSensitivity = 'Confidential'; CmdbDataSensitivitySource = 'rule:VisualCron' }
        )
    }
    It 'reads the overrides with its own query: newest row per asset, only rule-sourced values' {
        $k = Get-SICmdbSqlRuleOverrideKql -TableName 'SI_Endpoint_Profile_CL'
        $k | Should -Match 'summarize arg_max\(CollectionTime, cmdbCriticality, CmdbCriticalitySource, cmdbDataSensitivity, CmdbDataSensitivitySource\) by SI_AssetId'
        $k | Should -Match 'where CmdbCriticalitySource startswith "rule:" or CmdbDataSensitivitySource startswith "rule:"'
        $k | Should -Match 'column_ifexists\("CmdbDataSensitivitySource", ""\)'
        $o = ConvertTo-SICmdbSqlRuleOverrides -Rows $script:OverrideRows
        $o['dc1'].DataSensitivity | Should -Be 'Restricted'; $o['dc1'].DataSensitivityRule | Should -Be 'ADDomainController'
        $o['dc1'].Criticality | Should -Be '' -Because 'a CMDB-sourced value is not an override'
    }
    It 'rule override > the Pro database''s service record, field by field; no override falls back to the record' {
        $d = ConvertTo-SICmdbSqlDesired -Profiles $script:Profiles -MapRows $script:MapRows -Enrichment $script:Enrichment -Kinds @('endpoint', 'azure') -SeenAt $script:Now `
                -RuleOverrides (ConvertTo-SICmdbSqlRuleOverrides -Rows $script:OverrideRows)
        $dc = $d.Items['corr-dc1']
        $dc.DataSensitivity | Should -Be 'Restricted'; $dc.DataSensitivitySource | Should -Be 'rule:ADDomainController'
        $dc.Criticality | Should -Be 'Critical'; $dc.CriticalitySource | Should -Be 'cmdb'
        $d.Items['mgmt1'].DataSensitivity | Should -Be 'Confidential'
        $d.Items['dc9'].DataSensitivity | Should -Be 'Confidential'; $d.Items['dc9'].DataSensitivitySource | Should -Be 'cmdb'
    }
    It 'members of one CI with different overrides: the most critical / most sensitive wins' {
        $ov = ConvertTo-SICmdbSqlRuleOverrides -Rows @(
            [pscustomobject]@{ SI_AssetId = 'dc1'; cmdbCriticality = 'Low'; CmdbCriticalitySource = 'rule:A'; cmdbDataSensitivity = 'Internal'; CmdbDataSensitivitySource = 'rule:A' }
            [pscustomobject]@{ SI_AssetId = 'vm-dc1'; cmdbCriticality = 'High'; CmdbCriticalitySource = 'rule:B'; cmdbDataSensitivity = 'Restricted'; CmdbDataSensitivitySource = 'rule:B' })
        $d = ConvertTo-SICmdbSqlDesired -Profiles $script:Profiles -MapRows $script:MapRows -Enrichment $script:Enrichment -Kinds @('endpoint', 'azure') -SeenAt $script:Now -RuleOverrides $ov
        $d.Items['corr-dc1'].Criticality | Should -Be 'High'; $d.Items['corr-dc1'].DataSensitivity | Should -Be 'Restricted'
    }
    It 'the plan updates DataSensitivity with a history row; the apply writes it only where the column exists' {
        $d = ConvertTo-SICmdbSqlDesired -Profiles $script:Profiles -MapRows $script:MapRows -Enrichment $script:Enrichment -Kinds @('endpoint', 'azure') -SeenAt $script:Now `
                -RuleOverrides (ConvertTo-SICmdbSqlRuleOverrides -Rows $script:OverrideRows)
        $actual = ConvertTo-SICmdbSqlActual -Rows @(@{ CiKey = 'corr-dc1'; KeySource = 'ledger'; Name = 'dc1'; Kind = 'endpoint'; Tier = 0; Criticality = 'Critical'; Services = 'Active Directory'; Sources = 'azure; endpoint'; State = 'active'; AbsentRuns = 0 }) `
                     -DataSensitivityRows @(@{ CiKey = 'corr-dc1'; DataSensitivity = 'Confidential' })
        $ch = Get-SICmdbSqlFieldChanges -Actual $actual['corr-dc1'] -Desired $d.Items['corr-dc1']
        $s = @($ch | Where-Object Field -eq 'DataSensitivity')
        $s.Count | Should -Be 1; $s[0].Old | Should -Be 'Confidential'; $s[0].New | Should -Be 'Restricted'
        $j = ConvertTo-SICmdbSqlOpJson -Op ([pscustomobject]@{ Op = 'update'; CiKey = 'corr-dc1'; Desired = $d.Items['corr-dc1']; AbsentRuns = 0; Changes = $ch }) | ConvertFrom-Json
        $j.dataSensitivity | Should -Be 'Restricted'
        $apply = Get-SICmdbSqlApplySql
        $apply | Should -Match "DataSensitivity nvarchar\(32\) '\`$\.dataSensitivity'"
        $apply | Should -Match "IF COL_LENGTH\('cmdbsync\.ConfigurationItem', 'DataSensitivity'\) IS NOT NULL"
        Get-SICmdbSqlActualDataSensitivitySql | Should -Match "IF COL_LENGTH\('cmdbsync\.ConfigurationItem', 'DataSensitivity'\) IS NULL"
    }
    It 'the run wires it: overrides read per kind, and with no DataSensitivity column nothing is planned for it (no perpetual change)' {
        $world = @{ Overrides = $script:OverrideRows }
        $snapT = $script:Now.AddHours(-1).ToString('o'); $mapLocal = $script:MapRows; $profLocal = @($script:Profiles | Where-Object Kind -eq 'endpoint')
        $query = {
            param([string]$kql)
            if ($kql -match 'SI_RunHealth_CL') { return @([pscustomobject]@{ Engine = 'endpoint'; RunId = 'r'; CollectionTime = $snapT; ShardIndex = 0; ShardCount = 1; ExitReason = 'success' }) }
            if ($kql -match 'summarize Rows = count\(\)') { return @([pscustomobject]@{ SnapshotTime = $snapT; Rows = 3; RunIds = @('r') }) }
            if ($kql -match 'SI_ObjectMap_CL') { return @($mapLocal) }
            if ($kql -match 'startswith "rule:"') { return @($world.Overrides) }
            @($profLocal)
        }.GetNewClosure()
        foreach ($hasCol in 0, 1) {
            $calls = New-Object System.Collections.ArrayList
            $hc = $hasCol
            $inv = {
                param([string]$sql, $p, [string]$mode)
                [void]$calls.Add($sql)
                if ($sql -match "OBJECT_ID\('cmdbsync\.ConfigurationItem'\) IS NOT NULL") { return 1 }
                if ($sql -match "COL_LENGTH\('cmdbsync\.ConfigurationItem', 'DataSensitivity'\) IS NULL THEN 0") { return $hc }
                if ($sql -match 'DECLARE @useCmdb') { return , @(@{ AssetKey = 'corr-dc1'; ServiceKey = 'SVC-0001'; ServiceName = 'Active Directory'; Criticality = 'Critical'; CriticalityRank = 1; DataSensitivity = 'Confidential'; Source = 'cmdb-si' }) }
                if ($mode -eq 'reader') { return , @() }
                $null
            }.GetNewClosure()
            $settings = Resolve-SICmdbSqlSettings -Globals @{ SI_ProSqlServer = 's'; SI_ProSqlDatabase = 'd'; SI_Pro_CmdbSql_Kinds = 'endpoint' }
            $res = Invoke-SICmdbSqlSyncCore -Query $query -Invoke $inv -Settings $settings -WhatIf -Now $script:Now -Log { param($l, $m) }
            $res.Outcome | Should -Be 'planned' -Because $res.Reason
            $ci = @($res.Plan.Ops | Where-Object CiKey -eq 'corr-dc1')[0].Desired
            if ($hasCol) { $ci.DataSensitivity | Should -Be 'Restricted' } else { $ci.DataSensitivity | Should -Be '' }
            @($calls | Where-Object { $_ -match "COL_LENGTH\('cmdbsync\.ConfigurationItem', 'DataSensitivity'\) IS NULL THEN 0" }).Count | Should -Be 1
        }
    }
    It 'the CI table gains DataSensitivity IN PLACE (guarded, additive), and the hand-off criticality reads the CI''s' {
        $sql = Get-Content -Raw (Join-Path $script:Root 'sql\si-cmdbsync-schema.sql')
        $sql | Should -Match "IF COL_LENGTH\('cmdbsync\.ConfigurationItem', 'DataSensitivity'\) IS NULL\s+ALTER TABLE cmdbsync\.ConfigurationItem ADD DataSensitivity NVARCHAR\(32\) NULL;"
        $sql | Should -Match 'COALESCE\(h\.Criticality, c\.Criticality\) AS u_criticality'
        . (Join-Path $script:Root 'engine\_shared\SI-SchemaGate.ps1')
        (Test-SISchemaIsAdditive -Sql $sql).IsAdditive | Should -BeTrue
    }
}
