#Requires -Version 7.0
<#
    THE TAGS A RESOURCE INHERITS ARE STORED ON ITS CI, WHATEVER THE RULES SAY (owner 2026-11-04: "fix issue so it stores
    tags found on parent on mg/sub/rg").

    Measured: an install whose rule set has no tag rule (no hasAzureTagDirectOrParent / hasTag) stored its Azure CIs
    with NO parentTags at all, and logged nothing -- the parent-chain index was built only for a tag rule, and the record
    parts come from that index. Management-group tags were never indexed (left for later).

    What these keep true:
      1. ALWAYS BUILT   the azure engine builds the parent chain with a rule set that has no tag rule (and with no rule at
                        all); the resources' own tags are read only for a tag rule; other engines stay rule-driven
      2. EVERY LEVEL    a resource gets parentTags / parentTagScopes from its resource group, subscription and management
                        groups, each with its level and container name; nearest wins (rg -> sub -> leaf MG -> root MG);
                        parentTagScopes keeps every level's tag (effective on the winner); si_tags_inherited says
                        '(management group)'
      3. FAILURE SAID   a management-group read that fails warns, naming the level, and the subscription / resource group
                        tags are still attached; an azure run without the index says so at record capture
      4. WIRING         the REAL Stage Profile (Invoke-Profile.ps1) with a non-tag rule set, and with none, reaches
                        Build-SIParentResourceChainIndex; the REAL Publish-SIRecords reaches Add-SIRecordPartsFromRuleIndexes
                        and the azure record carries the parts
      5. SCALE          one paged ARG read per level, no per-resource call, tenant-wide (no subscription filter), no page cap
    Offline; fictional names and ids only.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\asset-profiling\shared\RuleIndexes.ps1')      # + SI-AzRest.ps1 + AzureParentScopeCache.ps1
    . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordCapture.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-DataModelTemplates.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-CiEnrich.ps1')

    $script:Sub  = '11111111-0000-0000-0000-000000001089'
    $script:Sub2 = '22222222-0000-0000-0000-000000001089'
    $script:RgId = "/subscriptions/$($script:Sub)/resourceGroups/rg-app"
    $script:VmId = "$($script:RgId)/providers/Microsoft.Compute/virtualMachines/vm1"
    $script:ArgFail = @{}
    $script:ArgQueries = New-Object System.Collections.Generic.List[object]

    # Azure Resource Graph as every parent-chain read sees it (defined AFTER the engine files, in the same scope, so it is
    # the one Get-SIArgPaged and the management-group cache call). Tenant: Tenant Root Group > Landing Zones > Sub.
    function Search-SIAzGraph {
        param($Query, $First, $Skip, $Subscription, $ManagementGroup, $SkipToken)
        $q = [string]$Query
        $script:ArgQueries.Add([pscustomobject]@{ Query = $q; Subscription = $Subscription; ManagementGroup = $ManagementGroup })
        $rows = @()
        if ($q -match 'microsoft\.management/managementgroups') {
            if ($script:ArgFail['managementGroup']) { throw 'AuthorizationFailed: the identity cannot read the management groups' }
            $rows = @(
                [pscustomobject]@{ name = 'mg-root'; displayName = 'Tenant Root Group'; parentName = ''; tags = [pscustomobject]@{ 'Used for' = 'Root default'; 'Org' = 'Contoso'; 'Landing' = 'root' } }
                [pscustomobject]@{ name = 'mg-lz'; displayName = 'Landing Zones'; parentName = 'mg-root'; tags = [pscustomobject]@{ 'Used for' = 'Landing zone'; 'Landing' = 'corp' } }
            )
        } elseif ($q -match 'managementGroupAncestorsChain') {
            if ($script:ArgFail['managementGroup']) { throw 'AuthorizationFailed: the identity cannot read the management groups' }
            # ARG order: child first
            $rows = @(
                [pscustomobject]@{ subscriptionId = $script:Sub; parentMg = 'mg-lz'; ancestors = @([pscustomobject]@{ name = 'mg-lz'; displayName = 'Landing Zones' }, [pscustomobject]@{ name = 'mg-root'; displayName = 'Tenant Root Group' }) }
                [pscustomobject]@{ subscriptionId = $script:Sub2; parentMg = 'mg-root'; ancestors = @([pscustomobject]@{ name = 'mg-root'; displayName = 'Tenant Root Group' }) }
            )
        } elseif ($q -match 'subscriptions/resourcegroups') {
            if ($script:ArgFail['resourceGroup']) { throw 'resource groups: throttled' }
            $rows = @([pscustomobject]@{ id = $script:RgId; name = 'rg-app'; subscriptionId = $script:Sub; tags = [pscustomobject]@{ 'Team' = 'blue'; 'used for' = 'App' } })
        } elseif ($q -match "microsoft\.resources/subscriptions'") {
            if ($script:ArgFail['subscription']) { throw 'subscriptions: throttled' }
            $rows = @(
                [pscustomobject]@{ subscriptionId = $script:Sub; name = 'Contoso Production'; tags = [pscustomobject]@{ 'Used for' = 'Prod'; 'CostCenter' = '4711'; 'Landing' = 'sub' } }
                [pscustomobject]@{ subscriptionId = $script:Sub2; name = 'Contoso Sandbox'; tags = $null }
            )
        } elseif ($q -match '^\s*Resources') {
            $rows = @([pscustomobject]@{ id = $script:VmId; subscriptionId = $script:Sub; resourceGroup = 'rg-app'; tags = [pscustomobject]@{ 'Own' = 'yes' } })
        }
        return , (New-SIAzGraphPage -Rows $rows)
    }
    function script:Reset-Arg { $script:ArgFail = @{}; $script:ArgQueries.Clear() }
    function script:NonTagRules {
        @([pscustomobject]@{ Id = 'NameOnly'; Detections = @([pscustomobject]@{ Detect = [pscustomobject]@{ any = @([pscustomobject]@{ kind = 'nameMatches'; pattern = 'x' }) } }) })
    }
    function script:TagRules {
        @([pscustomobject]@{ Id = 'TagRule'; Detections = @([pscustomobject]@{ Detect = [pscustomobject]@{ any = @([pscustomobject]@{ kind = 'hasAzureTagDirectOrParent'; tag = 'x' }) } }) })
    }
    function script:VmRecord {
        $null = Reset-SIRecordCapture -Engine 'azure' -Clear
        Add-SIRecordPart -Provider azure -RecordType azure_resource -Key $script:VmId -Part resource -ResourceType 'microsoft.compute/virtualmachines' `
            -Object ([pscustomobject]@{ id = $script:VmId; name = 'vm1'; type = 'microsoft.compute/virtualmachines'; subscriptionId = $script:Sub; resourceGroup = 'rg-app'; tags = [pscustomobject]@{ 'CostCenter' = '9999' } })
        @($global:SIRecordCaptureState.Records.Values)[0]
    }
}

AfterAll {
    $global:SIRuleIndexesForRecords = $null
    if (Get-Command Reset-SIRecordCapture -ErrorAction SilentlyContinue) { $null = Reset-SIRecordCapture -Clear }
    $global:SIRecordCaptureState = $null
}

Describe '1. the azure engine always builds the parent chain' {
    BeforeEach { Reset-Arg }
    It 'with a rule set that has NO tag rule -- and without the resources read' {
        $stats = Build-SIRuleIndexes -Engine 'azure' -Rules (NonTagRules)
        $stats['parentChain'].Built | Should -BeTrue
        $global:SIRuleIndexesForRecords.parentChain.ContainsKey($script:RgId.ToLower()) | Should -BeTrue
        @($script:ArgQueries | Where-Object { $_.Query -match '^\s*Resources' }).Count | Should -Be 0 -Because 'a record brings its own tags; only a tag rule needs every resource''s'
    }
    It 'with no rule at all' {
        (Build-SIRuleIndexes -Engine 'azure' -Rules @())['parentChain'].Built | Should -BeTrue
    }
    It 'a tag rule also reads the resources'' own tags (the rule kinds keep working)' {
        $null = Build-SIRuleIndexes -Engine 'azure' -Rules (TagRules)
        @($script:ArgQueries | Where-Object { $_.Query -match '^\s*Resources' }).Count | Should -Be 1
        $e = @($global:SIRuleIndexesForRecords.parentChain[$script:VmId.ToLower()])
        $e[0].level | Should -Be 'resource'
    }
    It 'another engine stays rule-driven: no tag rule, no index' {
        $stats = Build-SIRuleIndexes -Engine 'endpoint' -Rules (NonTagRules)
        $stats.ContainsKey('parentChain') | Should -BeFalse
        $script:ArgQueries.Count | Should -Be 0
        (Build-SIRuleIndexes -Engine 'endpoint' -Rules (TagRules))['parentChain'].Built | Should -BeTrue
    }
}

Describe '2. a resource carries its resource group''s, subscription''s and management groups'' tags' {
    BeforeAll {
        Reset-Arg
        $null = Build-SIRuleIndexes -Engine 'azure' -Rules (NonTagRules)
        $script:Rec = VmRecord
        Add-SIRecordPartsFromRuleIndexes
        $script:Scopes = @($script:Rec.Parts['parentTagScopes'])
        $script:Tags = $script:Rec.Parts['parentTags']
    }
    It 'the index orders the chain nearest first: resource group, subscription, then the MGs from the nearest up' {
        $levels = @($global:SIRuleIndexesForRecords.parentChain[$script:RgId.ToLower()] | ForEach-Object { $_.level }) | Select-Object -Unique
        $levels | Should -Be @('resourceGroup', 'subscription', 'managementGroup')
        $mgFrom = @($global:SIRuleIndexesForRecords.parentChain[$script:RgId.ToLower()] | Where-Object { $_.level -eq 'managementGroup' } | ForEach-Object { $_.from }) | Select-Object -Unique
        $mgFrom | Should -Be @('Landing Zones', 'Tenant Root Group')
    }
    It 'parentTags: the nearest container wins, every level reaches the CI' {
        $script:Tags['used for'] | Should -Be 'App' -Because 'the resource group is nearer than the subscription and both MGs'
        $script:Tags['CostCenter'] | Should -Be '4711' -Because 'from the subscription (the resource''s own tag is not a parent tag)'
        $script:Tags['Landing'] | Should -Be 'sub' -Because 'the subscription is nearer than its management groups'
        $script:Tags['Org'] | Should -Be 'Contoso' -Because 'set only on the root management group'
        $script:Tags['Team'] | Should -Be 'blue'
    }
    It 'parentTagScopes: EVERY level''s tag with its level and container, the winner marked' {
        $land = @($script:Scopes | Where-Object { $_.name -eq 'Landing' })
        @($land | ForEach-Object { '{0}:{1}:{2}:{3}' -f $_.scope, $_.from, $_.value, $_.effective }) |
            Should -Be @('subscription:Contoso Production:sub:True', 'managementGroup:Landing Zones:corp:False', 'managementGroup:Tenant Root Group:root:False')
        $org = @($script:Scopes | Where-Object { $_.name -eq 'Org' })[0]
        ($org.scope, $org.from, $org.effective) | Should -Be @('managementGroup', 'Tenant Root Group', $true)
        $usedFor = @($script:Scopes | Where-Object { $_.name -eq 'used for' })
        @($usedFor).Count | Should -Be 4 -Because 'resource group, subscription, Landing Zones and the root each set it'
        @($usedFor | Where-Object { $_.effective }).Count | Should -Be 1
        @($usedFor | Where-Object { $_.effective })[0].scope | Should -Be 'resourceGroup'
    }
    It 'si_tags_inherited / si_tags_all carry the level -- one entry per tag, the MG ones say (management group)' {
        $d = Get-SIAzureInheritedTagDerived -Tags ([pscustomobject]@{ CostCenter = '9999' }) -Scopes $script:Scopes
        $inh = @($d['tagsInherited'])
        @($inh | ForEach-Object { $_.name }) | Should -Be @('Team', 'used for', 'Landing', 'Org') -Because 'nearest first, once per name, the resource''s own CostCenter wins'
        $o = @($inh | Where-Object { $_.name -eq 'Org' })[0]
        ($o.scope, $o.from) | Should -Be @('managementGroup', 'Tenant Root Group')
        ConvertTo-SITagEntryText $o | Should -Be 'Org = Contoso (management group)'
    }
    It 'a subscription without tags of its own still carries its management groups'' tags' {
        $sub2 = @($global:SIRuleIndexesForRecords.parentChain["/subscriptions/$($script:Sub2)"])
        @($sub2 | ForEach-Object { '{0}={1}@{2}' -f $_.tag, $_.value, $_.from }) | Sort-Object | Should -Be @('Landing=root@Tenant Root Group', 'Org=Contoso@Tenant Root Group', 'Used for=Root default@Tenant Root Group')
    }
}

Describe '3. a read that fails is said, and the other levels are still attached' {
    It 'management groups cannot be read: a warning that names the level; subscription and resource group tags attached' {
        Reset-Arg; $script:ArgFail['managementGroup'] = $true
        $stats = Build-SIRuleIndexes -Engine 'azure' -Rules @() -WarningVariable w -WarningAction SilentlyContinue
        $stats['parentChain'].Built | Should -BeTrue
        $stats['parentChain'].Levels['managementGroup'] | Should -BeFalse
        @($w | Where-Object { "$_" -like 'management group tags could not be read: *AuthorizationFailed*' }).Count | Should -BeGreaterOrEqual 1
        $rec = VmRecord
        $null = Add-SIRecordPartsFromRuleIndexes 3>&1
        $rec.Parts['parentTags']['used for'] | Should -Be 'App'
        $rec.Parts['parentTags']['CostCenter'] | Should -Be '4711'
        $rec.Parts['parentTags'].Contains('Org') | Should -BeFalse
        @($rec.Parts['parentTagScopes'] | Where-Object { $_.scope -eq 'managementGroup' }).Count | Should -Be 0
    }
    It 'subscriptions or resource groups cannot be read: each warns by name, the rest still indexed' {
        Reset-Arg; $script:ArgFail['subscription'] = $true
        $null = Build-SIRuleIndexes -Engine 'azure' -Rules @() -WarningVariable w1 -WarningAction SilentlyContinue
        @($w1 | Where-Object { "$_" -like 'subscription tags could not be read: *' }).Count | Should -Be 1
        $rg = @($global:SIRuleIndexesForRecords.parentChain[$script:RgId.ToLower()])
        @($rg | Where-Object { $_.level -eq 'resourceGroup' }).Count | Should -Be 2
        @($rg | Where-Object { $_.level -eq 'managementGroup' }).Count | Should -BeGreaterThan 0 -Because 'the MG walk places the subscription itself'
        Reset-Arg; $script:ArgFail['resourceGroup'] = $true
        $null = Build-SIRuleIndexes -Engine 'azure' -Rules @() -WarningVariable w2 -WarningAction SilentlyContinue
        @($w2 | Where-Object { "$_" -like 'resource group tags could not be read: *' }).Count | Should -Be 1
        $rec = VmRecord
        Add-SIRecordPartsFromRuleIndexes
        $rec.Parts['parentTags']['Used for'] | Should -Be 'Prod' -Because 'without the resource group, the subscription is the nearest'
    }
    It 'an azure run whose parent chain was not built says so at record capture' {
        $null = VmRecord
        $w = @(Add-SIRecordPartsFromRuleIndexes -Indexes @{ parentChain = @{}; BuildStats = @{ parentChain = @{ Built = $false; Error = 'boom' } } } 3>&1)
        @($w | Where-Object { "$_" -like '*parent tags*were not read*boom*' }).Count | Should -Be 1
    }
}

Describe '4. WIRING: the real run path reaches the index and the record parts' {
    BeforeAll {
        . (Join-Path $script:SIRoot 'engine\asset-profiling\storage\StorageContext.ps1')
        . (Join-Path $script:SIRoot 'engine\asset-profiling\storage\StagingBlob.ps1')
        if (-not (Get-Command Write-SIInfo -ErrorAction SilentlyContinue)) { function script:Write-SIInfo { param($m) } }
        if (-not (Get-Command Reset-SIProgress -ErrorAction SilentlyContinue)) { function script:Reset-SIProgress { param($Label) } }
        if (-not (Get-Command Write-SIProgress -ErrorAction SilentlyContinue)) { function script:Write-SIProgress { param($Label, $Index, $Total) } }
        # A scratch tree that runs the REAL Invoke-Profile.ps1 with the REAL RuleIndexes.ps1 + AzureParentScopeCache.ps1
        # (the stage dot-sources its helpers from its own folder); only the rule loader (the rule set under test) and the
        # per-asset evaluator are stand-ins.
        $t = Join-Path ([IO.Path]::GetTempPath()) ('si-parenttags-' + [guid]::NewGuid().ToString('N'))
        $stages = Join-Path $t 'engine\asset-profiling\stages'; $shared = Join-Path $t 'engine\asset-profiling\shared'; $storage = Join-Path $t 'engine\asset-profiling\storage'
        foreach ($d in $stages, $shared, $storage) { New-Item -ItemType Directory -Force -Path $d | Out-Null }
        $real = Join-Path $script:SIRoot 'engine\asset-profiling'
        Copy-Item (Join-Path $real 'stages\Invoke-Profile.ps1') $stages
        Copy-Item (Join-Path $real 'shared\RuleIndexes.ps1') $shared
        Copy-Item (Join-Path $real 'shared\AzureParentScopeCache.ps1') $shared
        Set-Content -Path (Join-Path $shared 'Get-SIRuleSet.ps1') -Value 'function Get-SIRuleSet { param($Engine) @($global:SITest_ParentRules) }'
        Set-Content -Path (Join-Path $shared 'RuleEval.ps1') -Value @'
function Get-SIAssetOsClass { param($Asset) 'Other' }
function Get-SIAssetField { param($Asset, $Name) '' }
function Invoke-SIRuleEval { param($Asset, $Rule) $null }
'@
        Set-Content -Path (Join-Path $shared 'CmdbFieldPrecedence.ps1') -Value (". '{0}'" -f (Join-Path $real 'shared\CmdbFieldPrecedence.ps1'))
        Set-Content -Path (Join-Path $storage 'StagingBlob.ps1') -Value (". '{0}'" -f (Join-Path $real 'storage\StagingBlob.ps1'))
        $script:Tree = $t
        function script:Invoke-RealProfile([object[]]$Rules) {
            $ctx = New-SIStorageContext -Mock
            $ctx.MockState.Blobs['stg'] = @{}
            $recs = @([pscustomobject]@{ AssetName = 'vm1'; PrimaryEntityId = $script:VmId; Verdict = [pscustomobject]@{ SI_Tier = 3 }; Metadata = [pscustomobject]@{ AZ_ResourceId = $script:VmId } })
            $null = Write-SIStageShard -Context $ctx -ContainerName 'stg' -RunId 'run1' -Stage 'Classify' -ShardIndex 0 -Records $recs
            $rc = [pscustomobject]@{ Engine = 'azure'; StorageContext = $ctx; StagingContainer = 'stg'; RunId = 'run1'; ShardIndex = 0; CollectionTime = '2026-11-04T00:00:00Z' }
            $global:SITest_ParentRules = $Rules
            $global:SIRuleIndexesForRecords = $null
            . (Join-Path $script:Tree 'engine\asset-profiling\stages\Invoke-Profile.ps1')
            Invoke-SIProfile -RunContext $rc 6>$null
        }
    }
    AfterAll {
        $global:SITest_ParentRules = $null
        if ($script:Tree -and (Test-Path $script:Tree)) { Remove-Item -Recurse -Force $script:Tree -ErrorAction SilentlyContinue }
    }
    It 'Stage Profile with a rule set without a tag rule builds the parent chain (Build-SIParentResourceChainIndex is reached)' {
        Reset-Arg
        $res = Invoke-RealProfile -Rules (NonTagRules)
        $res.IndexStats['parentChain'].Built | Should -BeTrue
        @($script:ArgQueries | Where-Object { $_.Query -match 'managementgroups' }).Count | Should -Be 1
        $global:SIRuleIndexesForRecords.parentChain.ContainsKey($script:RgId.ToLower()) | Should -BeTrue
    }
    It 'Stage Profile with NO rule still builds it for the azure engine' {
        Reset-Arg
        $null = Invoke-RealProfile -Rules @()
        $global:SIRuleIndexesForRecords | Should -Not -BeNullOrEmpty
        $global:SIRuleIndexesForRecords.BuildStats['parentChain'].Built | Should -BeTrue
    }
    It 'the real Publish-SIRecords attaches the parts from the index Stage Profile handed over' {
        Reset-Arg
        $null = Invoke-RealProfile -Rules (NonTagRules)
        $rec = VmRecord
        $o = @{}
        try { $null = Publish-SIRecords -RunContext ([pscustomobject]@{ RunId = 'run1'; CollectionTime = '2026-11-04T00:00:00Z' }) -Engine 'azure' -SqlInvoke { param($Sql, $Params, $Mode) @() } -Outcome $o -WarningAction SilentlyContinue 6>$null } catch { }
        $rec.Parts['parentTags']['Org'] | Should -Be 'Contoso'
        @($rec.Parts['parentTagScopes'] | Where-Object { $_.scope -eq 'managementGroup' }).Count | Should -BeGreaterThan 0
    }
    It 'the engine runs Profile before Output, and Output publishes the records' {
        $run = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\Invoke-SIEngineRun.ps1'))
        $run | Should -Match "\`$__st = @\('Schedule','Discover','Collect','Enrich','Classify','Profile','Reconcile','Output','Tagging'\)"
        [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\stages\Invoke-Output.ps1')) | Should -Match 'Publish-SIRecords -RunContext \$RunContext -ProfileRows'
    }
}

Describe '5. scale: one paged read per level, tenant-wide, no cap' {
    It 'every read is a paged ARG read without a subscription / management group filter; no per-resource read' {
        Reset-Arg
        $null = Build-SIRuleIndexes -Engine 'azure' -Rules @()
        $script:ArgQueries.Count | Should -Be 4 -Because 'management groups, the subscription -> MG chain, subscriptions, resource groups'
        @($script:ArgQueries | Where-Object { $_.Subscription -or $_.ManagementGroup }).Count | Should -Be 0
    }
    It 'Get-SIArgPaged follows every page token (no 100-page stop) and stops on a repeated token' {
        $script:Pg = 0
        function Search-SIAzGraph { param($Query, $First, $Skip, $Subscription, $ManagementGroup, $SkipToken)
            $script:Pg++
            $tok = if ($script:Pg -lt 150) { "t$($script:Pg)" } else { $null }
            return , (New-SIAzGraphPage -Rows @([pscustomobject]@{ n = $script:Pg }) -SkipToken $tok) }
        @(Get-SIArgPaged -Query 'x').Count | Should -Be 150
        $script:Pg = 0
        function Search-SIAzGraph { param($Query, $First, $Skip, $Subscription, $ManagementGroup, $SkipToken)
            $script:Pg++
            return , (New-SIAzGraphPage -Rows @([pscustomobject]@{ n = $script:Pg }) -SkipToken 'same') }
        @(Get-SIArgPaged -Query 'x' -WarningAction SilentlyContinue).Count | Should -Be 2
    }
}
