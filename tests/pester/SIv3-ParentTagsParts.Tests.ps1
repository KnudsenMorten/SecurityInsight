#Requires -Version 7.0
<#
    THE INHERITED TAGS IN A RUN COLLECTED IN PARTS (#1089, live 3.0.35: an install that collects azure in parts stored 1247
    azure records, not one with an inherited tag, and nothing was logged).

    Why the single-job wiring test (SIv3-ParentTagsStored) missed it: there Stage Profile and Publish-SIRecords run in ONE
    process that holds every record. In parts, three processes share the run: the PRODUCER discovers and captures the
    records (streamed, handed over), a WORKER runs Profile over its part but holds none of discovery's records, and the MERGE
    (Publish-SIRecordHandover) publishes them with no Profile run at all -- so the index was built where there were no
    records, and absent where the records were.

    What these keep true:
      1. PRODUCER  reads the parent chain ONCE (tenant-wide) and hands it over beside the records; one INFO line says what
                   was read; Invoke-Discover calls it in the discover phase of an azure run
      2. WORKER    a worker (SI_COLLECT_PHASE = parts) does not re-read the tenant for it (only for a tag rule of its own)
                   and does not warn about the missing index
      3. MERGE     the real Publish-SIRecordHandover over the handed-over buckets attaches parentTags / parentTagScopes with
                   the resource group, subscription and management-group levels to discovery's azure record; the other
                   indexes the process holds are kept and restored
      4. MISSING   no hand-over from the producer: said, the records still published
    Offline; fictional names and ids only.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\_shared\SI-CollectParts.ps1')
    . (Join-Path $script:SIRoot 'engine\asset-profiling\shared\RuleIndexes.ps1')      # + SI-AzRest.ps1 + AzureParentScopeCache.ps1
    . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordCapture.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordHandover.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-DataModelTemplates.ps1')

    $script:Sub  = '11111111-0000-0000-0000-000000001089'
    $script:RgId = "/subscriptions/$($script:Sub)/resourceGroups/rg-app"
    $script:VmId = "$($script:RgId)/providers/Microsoft.Compute/virtualMachines/vm1"
    $script:ArgQueries = New-Object System.Collections.Generic.List[string]
    # Azure Resource Graph (defined AFTER the engine files, in the same scope: the one every read calls)
    function Search-SIAzGraph {
        param($Query, $First, $Skip, $Subscription, $ManagementGroup, $SkipToken)
        $q = [string]$Query; $script:ArgQueries.Add($q)
        $rows = @()
        if ($q -match 'microsoft\.management/managementgroups') {
            $rows = @(
                [pscustomobject]@{ name = 'mg-root'; displayName = 'Tenant Root Group'; parentName = ''; tags = [pscustomobject]@{ 'Org' = 'Contoso' } }
                [pscustomobject]@{ name = 'mg-lz'; displayName = 'Landing Zones'; parentName = 'mg-root'; tags = [pscustomobject]@{ 'Landing' = 'corp' } }
            )
        } elseif ($q -match 'managementGroupAncestorsChain') {
            $rows = @([pscustomobject]@{ subscriptionId = $script:Sub; parentMg = 'mg-lz'; ancestors = @([pscustomobject]@{ name = 'mg-lz'; displayName = 'Landing Zones' }, [pscustomobject]@{ name = 'mg-root'; displayName = 'Tenant Root Group' }) })
        } elseif ($q -match 'subscriptions/resourcegroups') {
            $rows = @([pscustomobject]@{ id = $script:RgId; name = 'rg-app'; subscriptionId = $script:Sub; tags = [pscustomobject]@{ 'Team' = 'blue' } })
        } elseif ($q -match "microsoft\.resources/subscriptions'") {
            $rows = @([pscustomobject]@{ subscriptionId = $script:Sub; name = 'Contoso Production'; tags = [pscustomobject]@{ 'CostCenter' = '4711' } })
        }
        return , (New-SIAzGraphPage -Rows $rows)
    }
    function script:MemStore {
        $m = @{}
        [pscustomobject]@{
            Data  = $m
            Write = { param($Path, $Text) $m[$Path] = [string]$Text }.GetNewClosure()
            Read  = { param($Path) $m[$Path] }.GetNewClosure()
            List  = { param($Prefix) @($m.Keys | Where-Object { $_.StartsWith($Prefix) } | Sort-Object) }.GetNewClosure()
        }
    }
    function script:NonTagRules {
        @([pscustomobject]@{ Id = 'NameOnly'; Detections = @([pscustomobject]@{ Detect = [pscustomobject]@{ any = @([pscustomobject]@{ kind = 'nameMatches'; pattern = 'x' }) } }) })
    }
    # the producer's discovery: the azure record, handed over as 'discover'
    function script:HandOverDiscovery($Store, [string]$RunId) {
        $null = Reset-SIRecordCapture -Engine 'azure' -Clear
        Add-SIRecordPart -Provider azure -RecordType azure_resource -Key $script:VmId -Part resource -ResourceType 'microsoft.compute/virtualmachines' `
            -Object ([pscustomobject]@{ id = $script:VmId; name = 'vm1'; type = 'microsoft.compute/virtualmachines'; subscriptionId = $script:Sub; resourceGroup = 'rg-app'; tags = [pscustomobject]@{ 'Own' = 'yes' } })
        $null = Save-SIRecordHandover -Store $Store -Engine azure -RunId $RunId -Who 'discover' -Buckets 1
    }
    # the merge: the REAL Publish-SIRecordHandover -> Publish-SIRecords -> Add-SIRecordPartsFromRuleIndexes; the records are
    # read right after the rule-index parts are attached (the next call Publish-SIRecords makes), the database is a stub
    function Add-SIRecordPartsFromProfileRows { param($Rows, $InParts) $script:Published = @($global:SIRecordCaptureState.Records.Values) }
    function script:Merge($Store, [string]$RunId) {
        $script:Published = @()
        $old = [Environment]::GetEnvironmentVariable('SI_COLLECT_PHASE')
        [Environment]::SetEnvironmentVariable('SI_COLLECT_PHASE', 'records')
        try {
            $w = @(Publish-SIRecordHandover -Store $Store -Engine azure -RunId $RunId -RunContext ([pscustomobject]@{ RunId = $RunId; CollectionTime = '2026-11-04T15:20:00Z' }) `
                -SqlInvoke { param($Sql, $Params, $Mode) @() } 3>&1 6>$null)
        } finally { [Environment]::SetEnvironmentVariable('SI_COLLECT_PHASE', $old) }
        , @($w | Where-Object { $_ -is [System.Management.Automation.WarningRecord] } | ForEach-Object { "$_" })
    }
}

AfterAll {
    [Environment]::SetEnvironmentVariable('SI_COLLECT_PHASE', $null)
    $global:SIRuleIndexesForRecords = $null; $global:SIRecordCaptureState = $null
}

Describe '1. the producer reads the parent chain once and hands it over' {
    It 'one read per level, kept beside the records, one INFO line with the counts' {
        $s = MemStore; $script:ArgQueries.Clear()
        $info = @(Save-SIParentChainForParts -Engine azure -RunId 'run-p1' -Store $s 6>&1 | ForEach-Object { "$_" })
        $script:ArgQueries.Count | Should -Be 4 -Because 'management groups, the subscription -> MG chain, subscriptions, resource groups -- no resource read'
        $s.Data.ContainsKey('collect/azure/run-p1/parent-chain.json') | Should -BeTrue
        ($info -join "`n") | Should -Match 'inherited tags: 2 management group\(s\), 1 subscription\(s\), 1 resource group\(s\) read \(tenant-wide\)'
        $idx = Read-SIParentChainHandover -Store $s -Engine azure -RunId 'run-p1'
        @($idx["/subscriptions/$($script:Sub)"] | ForEach-Object { $_.level }) | Should -Be @('subscription', 'managementGroup', 'managementGroup')
        @($idx[$script:RgId.ToLower()] | ForEach-Object { $_.level }) | Should -Be @('resourceGroup') -Because 'a resource group keeps its own tags; its subscription''s are in the subscription''s entry'
    }
    It 'Invoke-Discover hands it over in the discover phase of an azure run (after the parts are written)' {
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\stages\Invoke-Discover.ps1'))
        $i = $src.IndexOf('$partsWritten = Write-SIDiscoverParts')
        $j = $src.IndexOf('Save-SIParentChainForParts -Engine ''azure'' -RunId ([string]$RunContext.RunId)')
        $i | Should -BeGreaterThan 0
        $j | Should -BeGreaterThan $i
        $src.Substring($i, $j - $i) | Should -Match "if \(\`$RunContext\.Engine -eq 'azure'\)"
        $src.IndexOf('} else {', $i) | Should -BeGreaterThan $j -Because 'inside the discover-phase branch'
    }
}

Describe '2. a worker does not re-read the tenant for it' {
    AfterEach { [Environment]::SetEnvironmentVariable('SI_COLLECT_PHASE', $null) }
    It 'SI_COLLECT_PHASE = parts: no parent-chain read without a tag rule, and no false warning on its own records' {
        [Environment]::SetEnvironmentVariable('SI_COLLECT_PHASE', 'parts')
        $script:ArgQueries.Clear()
        $stats = Build-SIRuleIndexes -Engine azure -Rules (NonTagRules)
        $stats.ContainsKey('parentChain') | Should -BeFalse
        $script:ArgQueries.Count | Should -Be 0
        $null = Reset-SIRecordCapture -Engine 'azure' -Clear
        $w = @(Add-SIRecordPartsFromRuleIndexes 3>&1)
        @($w | Where-Object { "$_" -like '*parent tags*' }).Count | Should -Be 0
    }
}

Describe '3. the merge attaches the producer''s parent chain to discovery''s records' {
    It 'producer -> worker -> merge: the published azure record carries parentTagScopes with the RG / subscription / MG levels' {
        $s = MemStore
        # PRODUCER: discovery's record + the parent chain
        HandOverDiscovery $s 'run-w1'
        $null = Save-SIParentChainForParts -Engine azure -RunId 'run-w1' -Store $s 6>$null
        # WORKER: its Profile (no parent chain in a part), its record parts handed over (none of discovery's records)
        [Environment]::SetEnvironmentVariable('SI_COLLECT_PHASE', 'parts')
        try {
            $null = Build-SIRuleIndexes -Engine azure -Rules (NonTagRules)
            $null = Reset-SIRecordCapture -Engine 'azure' -Clear
            Add-SIRecordPartsFromRuleIndexes
            $null = Save-SIRecordHandover -Store $s -Engine azure -RunId 'run-w1' -Who 'part-00000' -Buckets 1
        } finally { [Environment]::SetEnvironmentVariable('SI_COLLECT_PHASE', $null) }
        # MERGE (another process: no index of its own)
        $global:SIRuleIndexesForRecords = $null
        $null = Merge $s 'run-w1'
        $rec = @($script:Published | Where-Object { $_.Provider -eq 'azure' })[0]
        $rec | Should -Not -BeNullOrEmpty
        $sc = @($rec.Parts['parentTagScopes'])
        @($sc | ForEach-Object { '{0}:{1}={2}@{3}' -f $_.scope, $_.name, $_.value, $_.from }) |
            Should -Be @('resourceGroup:Team=blue@rg-app', 'subscription:CostCenter=4711@Contoso Production', 'managementGroup:Landing=corp@Landing Zones', 'managementGroup:Org=Contoso@Tenant Root Group')
        $rec.Parts['parentTags']['Org'] | Should -Be 'Contoso'
        $global:SIRuleIndexesForRecords | Should -BeNullOrEmpty -Because 'the merge restores what the process held'
    }
    It 'the other indexes the merging process holds are kept (a last worker''s software / query hits) and restored' {
        $s = MemStore
        HandOverDiscovery $s 'run-w2'
        $null = Save-SIParentChainForParts -Engine azure -RunId 'run-w2' -Store $s 6>$null
        $held = @{ tvmSoftware = @{ 'dev1' = @('contoso/app') }; parentChain = @{}; kustoSets = @{}; BuildStats = @{ tvmSoftware = @{ Built = $true } } }
        $global:SIRuleIndexesForRecords = $held
        $null = Merge $s 'run-w2'
        @($script:Published)[0].Parts['parentTags']['Team'] | Should -Be 'blue'
        [object]::ReferenceEquals($global:SIRuleIndexesForRecords, $held) | Should -BeTrue
        $global:SIRuleIndexesForRecords = $null
    }
}

Describe '4. no hand-over from the producer: said, the records still published' {
    It 'warns that the azure records carry no inherited tags' {
        $s = MemStore
        HandOverDiscovery $s 'run-m1'
        $global:SIRuleIndexesForRecords = $null
        $w = Merge $s 'run-m1'
        @($script:Published).Count | Should -Be 1
        @($w | Where-Object { $_ -like '*parent tags*were not read*producer handed over no parent chain*' }).Count | Should -BeGreaterOrEqual 1
    }
}
