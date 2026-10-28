#Requires -Version 5.1
<#
    A DIRECTORY GROUP FROM THE EXPOSURE GRAPH BECOMES A GROUP CI -- end to end, and with full asset metadata on.

    Measured on a live install 2026-10-12: ~5,100 identity CIs known only from the Exposure Graph (directory groups) were
    asset type Other / subtype General with no identity type and no display name, although the mapping, the value map and
    the classification rows for them had been installed. The cause was not in the data model: with full asset metadata on
    for the identity run, the Exposure Graph identity fetch stopped at the first node it kept ("Select-SIEgRawFields is not
    recognized" -- the file that defines it was loaded only when the raw fields are trimmed, and full asset metadata keeps
    them whole), both identity sources returned nothing, and no identity record was captured again -- so no record was ever
    mapped with the new items.

    What these tests keep true, through the REAL functions (the fetch, the record capture, the shipped mapping + value maps,
    the CI build and the shipped classification rows) over nodes shaped as the hunting query returns them (NodeLabel in
    lower case, EntityIds a JSON text array of JSON texts, NodeProperties JSON text with rawData):
      * the fetch completes with full asset metadata ON (it threw) and OFF, and every kept node is a record;
      * a group node's record carries identity type group, the source asset type group and its name; its CI is asset type
        Group, subtype Group, with the display name;
      * a managed identity only the graph knows is asset type Managed identity (it was Other).
      * a discovery source that throws marks the pulls registered so far as not complete: the records of that run never
        count as a complete collection, so a record the failed run did not reach is frozen, not "no longer seen" (the
        failed runs had left the graph's identity feed complete with almost nothing in it).
    Offline: the hunting query is replaced by a function of the same name. pwsh 7.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\asset-profiling\_shared\Write-SIStyle.ps1')
    . (Join-Path $script:SIRoot 'engine\asset-profiling\shared\SI-FullAssetProperties.ps1')
    . (Join-Path $script:SIRoot 'engine\asset-profiling\shared\IdentityRoleFetcher.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordCapture.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-DataModelTemplates.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-CiBuild.ps1')

    $script:GroupOid = '11111111-2222-4333-8444-555555555555'
    $script:MiOid = '66666666-7777-4888-8999-aaaaaaaaaaaa'
    $script:GroupNode = '2239201f239e4857bd271c53b5b699b5'
    $script:MiNode = '7c1d0f5e9a3b4c2d8e6f1a2b3c4d5e6f'
    # the rows as the hunting query returns them: one per label, text columns as JSON text
    $script:FakeRows = @{
        group           = @([pscustomobject]@{
                NodeId = $script:GroupNode; NodeLabel = 'group'; NodeName = 'ROLE-InfrastructureArchitect-IT'; Categories = '["identity","group"]'
                EntityIds = ('["{{\"type\":\"SecurityIdentifier\",\"id\":\"S-1-12-1-1-2-3-4\"}}","{{\"type\":\"AadObjectId\",\"id\":\"tenantid=00000000-0000-0000-0000-000000000001;objectid={0}\"}}"]' -f $script:GroupOid)
                NodeProperties = (ConvertTo-Json -Compress -Depth 6 -InputObject @{ rawData = @{ aadId = $script:GroupOid; displayName = 'ROLE-InfrastructureArchitect-IT'; isSecurityGroup = $true } })
            })
        managedidentity = @([pscustomobject]@{
                NodeId = $script:MiNode; NodeLabel = 'managedidentity'; NodeName = 'id-app-prod'; Categories = '["identity"]'
                EntityIds = ('["{{\"type\":\"AadObjectId\",\"id\":\"objectid={0}\"}}"]' -f $script:MiOid)
                NodeProperties = (ConvertTo-Json -Compress -Depth 6 -InputObject @{ rawData = @{ accountObjectId = $script:MiOid } })
            })
    }
    # the hunting query, replaced (same name, defined after the real one): a count probe and the rows of one label
    function Invoke-SIEgIdentityQuery {
        param($Query)
        $label = ''; if ([string]$Query -match "NodeLabel == '([a-z]+)'") { $label = $Matches[1] }
        $r = @(); if ($script:FakeRows.ContainsKey($label)) { $r = @($script:FakeRows[$label]) }
        if ([string]$Query -match '\| count$') { return [pscustomobject]@{ Ok = $true; Rows = @([pscustomobject]@{ Count = $r.Count }); Error = '' } }
        [pscustomobject]@{ Ok = $true; Rows = $r; Error = '' }
    }
    $script:Model = Get-SIDataModel -Root (Join-Path $script:SIRoot 'data-model')

    # One identity run's graph fetch -> the captured records -> their mapped rows -> one classified CI per record.
    function script:Invoke-GraphIdentityRun {
        param([switch]$FullMetadata)
        $script:_SICache = @{}
        $null = Reset-SIRecordCapture -Engine 'identity' -Clear
        $null = Reset-SIFullAssetProperties -Engine 'identity'
        if ($FullMetadata) { Set-SIFullAssetPropertiesLevel -Level full }
        $threw = ''
        try { $null = Get-SIExposureGraphIdentities 6>$null 3>$null } catch { $threw = [string]$_.Exception.Message }
        $captured = @(Get-SICapturedRecords -Engine 'identity')
        $now = [datetime]::UtcNow
        $out = ConvertTo-SIRecordRows -Captured $captured -Model $script:Model -CollectionTime $now -Pulls $global:SIRecordCaptureState.Pulls
        $rows = @($out.Rows)
        $feed = Get-SIFeedLatest -Records $rows
        $plan = @(Get-SICiFieldPlan -Catalog $script:Model['field-catalog'])
        $cis = @{}
        foreach ($r in $rows) {
            $cis[[string]$r.si_record_key] = New-SICiDocument -CiId ([guid]::NewGuid().ToString()) -Records @($r) -Catalog $script:Model['field-catalog'] -FeedLatest $feed -Now $now -FieldPlan $plan
        }
        $null = Invoke-SICiClassification -Cis @($cis.Values) -Model $script:Model
        $byKey = @{}; foreach ($r in $rows) { $byKey[[string]$r.si_record_key] = $r }
        [pscustomobject]@{ Threw = $threw; Captured = $captured; Errors = @($out.Errors); Rows = $byKey; Cis = $cis }
    }
}

AfterAll {
    $global:SIRecordCaptureState = $null
    $global:SIFullAssetPropertiesState = $null
}

Describe 'a directory group the Exposure Graph knows becomes a Group CI' {
    It 'full asset metadata <Name>: the graph fetch completes and every kept node is a record' -ForEach @(
        @{ Name = 'on'; Full = $true }, @{ Name = 'off'; Full = $false }
    ) {
        $run = Invoke-GraphIdentityRun -FullMetadata:$Full
        $run.Threw | Should -BeNullOrEmpty -Because 'a fetch that stops here leaves the identity run with no identity at all'
        (Test-SIFullAssetPropertiesOn -Engine 'identity') | Should -Be $Full
        @($run.Captured | ForEach-Object { '{0}|{1}|{2}' -f $_.Provider, $_.RecordType, $_.Key } | Sort-Object) |
            Should -Be @("eg|service_principal|$($script:MiNode)", "eg|user|$($script:GroupNode)")
        $run.Errors | Should -BeNullOrEmpty
    }
    It 'full asset metadata <Name>: the group''s record says group and carries its name; its CI is Group / Group' -ForEach @(
        @{ Name = 'on'; Full = $true }, @{ Name = 'off'; Full = $false }
    ) {
        $run = Invoke-GraphIdentityRun -FullMetadata:$Full
        $key = 'eg:' + $script:GroupNode
        $rec = $run.Rows[$key]
        $rec | Should -Not -BeNullOrEmpty
        $rec.si_class | Should -Be 'identity'
        $rec.si_identity_type | Should -Be 'group'
        $rec.si_asset_type | Should -Be 'group' -Because 'the source value the classification rows read'
        $rec.si_display_name | Should -Be 'ROLE-InfrastructureArchitect-IT'
        $ci = $run.Cis[$key]
        $ci['si_class'] | Should -Be 'identity'
        $ci['si_asset_type'] | Should -Be 'Group'
        $ci['si_asset_subtype'] | Should -Be 'Group'
        $ci['si_asset_type_source'] | Should -Be 'group'
        $ci['si_identity_type'] | Should -Be 'group'
        $ci['si_display_name'] | Should -Be 'ROLE-InfrastructureArchitect-IT'
    }
    It 'a managed identity only the graph knows is asset type Managed identity, never Other' {
        $run = Invoke-GraphIdentityRun -FullMetadata
        $key = 'eg:' + $script:MiNode
        $run.Rows[$key].si_identity_type | Should -Be 'managed_identity'
        $ci = $run.Cis[$key]
        $ci['si_asset_type'] | Should -Be 'Managed identity'
        $ci['si_asset_type_source'] | Should -Be 'managed_identity'
        $ci['si_display_name'] | Should -Be 'id-app-prod'
    }
}

Describe 'a discovery source that fails part-way never leaves a complete collection behind' {
    BeforeAll {
        # one graph node captured as the identity fetch captures it, then the rows of that capture
        function script:Get-PartialRunRows {
            param([switch]$SourceFailed)
            $null = Reset-SIRecordCapture -Engine 'identity' -Clear
            Set-SIRecordPull -Provider 'eg' -Complete $true        # the fetch registers its pull before it reads the nodes
            $node = ConvertTo-SIFullExposureGraphNode -Row $script:FakeRows['managedidentity'][0]
            Add-SIRecordPartFromSource -SourceSystem 'exposure-graph' -Object $node
            $marked = @()
            if ($SourceFailed) { $marked = @(Set-SIRecordPullsIncomplete -Reason "discovery source 'EntraUsers' failed") }
            $out = ConvertTo-SIRecordRows -Captured @(Get-SICapturedRecords -Engine 'identity') -Model $script:Model -CollectionTime ([datetime]'2026-10-12T08:49:00Z') -Pulls $global:SIRecordCaptureState.Pulls
            [pscustomobject]@{ Marked = $marked; Rows = @($out.Rows) }
        }
        # a record of the same feed from the run before, which the failed run did not reach
        $script:Earlier = [pscustomobject]@{ si_provider = 'eg'; si_record_type = 'service_principal'; si_record_key = 'eg:0000000000000000000000000000beef'
            si_collection_time = [datetime]'2026-10-11T06:25:00Z'; si_collection_complete = $true }
    }
    It 'the records of a run whose source failed say the collection was not complete, and an earlier record is not read as gone' {
        $r = Get-PartialRunRows -SourceFailed
        $r.Marked | Should -Be @('eg')
        @($r.Rows).Count | Should -Be 1
        $r.Rows[0].si_collection_complete | Should -BeFalse
        $global:SIRecordCaptureState.Pulls['eg'].Error | Should -Match 'EntraUsers'
        $feed = Get-SIFeedLatest -Records (@($r.Rows) + @($script:Earlier))
        Get-SIRecordLinkState -Record $script:Earlier -FeedLatest $feed | Should -Be 'frozen' -Because 'the failed run never looked for it'
    }
    It 'control: a run whose sources all completed still reads an earlier record it did not find as not seen' {
        $r = Get-PartialRunRows
        $r.Rows[0].si_collection_complete | Should -BeTrue
        $feed = Get-SIFeedLatest -Records (@($r.Rows) + @($script:Earlier))
        Get-SIRecordLinkState -Record $script:Earlier -FeedLatest $feed | Should -Be 'not_seen'
    }
    It 'a pull that was not complete stays so, and with nothing captured there is nothing to mark' {
        $null = Reset-SIRecordCapture -Engine 'identity' -Clear
        @(Set-SIRecordPullsIncomplete -Reason 'x').Count | Should -Be 0
        $null = Set-SIRecordPullsIncomplete -Reason 'x'
        Set-SIRecordPull -Provider 'eg' -Complete $true
        $null = Set-SIRecordPullsIncomplete -Reason 'the source failed'
        Set-SIRecordPull -Provider 'eg' -Complete $true            # a later call of the same provider cannot make it complete again
        $global:SIRecordCaptureState.Pulls['eg'].Complete | Should -BeFalse
    }
    It 'GUARD: the Discover stage marks the pulls when a source throws; OUT OF MEMORY stops the collection, any other failure never blocks the rest (#702)' {
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\stages\Invoke-Discover.ps1'))
        $src | Should -Not -Match 'Continuing with 0 from this source' -Because 'unknown is not zero (customer B 2026-10-15)'
        $c = $src.IndexOf('$srcErr = $_')
        $j = $src.IndexOf('Set-SIRecordPullsIncomplete -Reason')
        $o = $src.IndexOf('if ($oom) {')
        $k = $src.IndexOf('this {1} collection is NOT COMPLETE and stays on its last good collection')
        $n = $src.IndexOf("Its objects are NOT COMPLETE in this run: nothing from this source is read as removed.")
        $c | Should -BeGreaterThan 0
        # #876: a source whose product is not in the tenant (no licence) is information, not a failure -- it holds nothing, so it
        # is counted 0 and skipped BEFORE the mark; every other failed source marks its pulls not complete first
        $between = $src.Substring($c, [Math]::Max(0, $j - $c))
        ($j -gt $c -and ($j - $c) -lt 1400) | Should -BeTrue -Because 'every failed source marks its pulls not complete first'
        $between | Should -Match '(?s)if \(\$srcAbsent\) \{.{0,300}\$perSourceCounts\[\$pair\.Name\] = 0\s+continue\s+\}'
        ([regex]::Replace($between, '(?s)if \(\$srcAbsent\) \{.*?continue\s+\}', '')) | Should -Not -Match '\bcontinue\b|\breturn\b|\bthrow\b' -Because 'nothing else leaves before the mark'
        ($o -gt $j -and $k -gt $o -and ($k - $o) -lt 800) | Should -BeTrue -Because 'out of memory stops the collection (a throw): the process cannot be trusted'
        ($n -gt $k) | Should -BeTrue -Because 'any other failed source keeps the run going (owner: a field problem never blocks)'
    }
}
