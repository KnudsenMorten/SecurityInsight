#Requires -Version 7.0
<#
    THE TAGS AN AZURE RESOURCE INHERITS (owner 2026-11-03: "many resources dont have any tags defined ... store parent tags
    on the object and we can see which were stored on the actual object and which comes from parent"; "customer wants to
    send tags to servicenow"; "but can we also include parents tags on the field").

    What these keep true:
      1. CAPTURE WITH SCOPE   the parentTagScopes part says, per tag, which container it came from (resource group or
                              subscription, with its name); the resource group wins over the subscription -- also when the
                              resource group's index entry carries the subscription's tags after its own; case-insensitive
      2. parentTags UNCHANGED tag -> value as before (the nearest wins), so tagOwner / tagEnvironment read the same
      3. THE TWO FIELDS       si_tags_inherited = only the parent tags the resource does not set itself (own wins, names
                              compared case-insensitively); si_tags_all = own first, then inherited; on azure_resource and
                              public_ip records through the shipped mapping
      4. THE CI               si_tags_all is every tag of the CI (each source's, the rules') then the inherited ones, and a
                              rule can match it like si_tags
      5. DATA OUT             Excel and the ServiceNow row carry 'name = value; ...' with ' (resource group)' /
                              ' (subscription)' on an inherited tag -- never JSON; other object lists keep their form; the
                              shipped ServiceNow CI map appends u_tags_all / u_tags / u_tags_inherited
      6. REGISTERED           both fields in the field catalog (both copies), the mapping, the CI table's columns
    Offline; fictional names and ids only.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordCapture.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-DataModelTemplates.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-CiEnrich.ps1')
    . (Join-Path $script:SIRoot 'engine\data-out\SI-DataOut.ps1')
    $script:Model = Get-SIDataModel
    $script:Sub = '11111111-0000-0000-0000-000000001068'
    $script:RgKey = "/subscriptions/$($script:Sub)/resourcegroups/rg-app"
    $script:SubKey = "/subscriptions/$($script:Sub)"
    # the profiler's index as Build-SIParentResourceChainIndex writes it: the resource group's entry carries its own tags
    # (level resourceGroup) and then the subscription's (level subscription)
    $script:Chain = @{
        $script:SubKey = @(@{ tag = 'Used for'; value = 'Prod'; level = 'subscription'; from = 'Contoso Production' }
                           @{ tag = 'Business Application'; value = 'Azure Local'; level = 'subscription'; from = 'Contoso Production' }
                           @{ tag = 'owner'; value = 'ops@contoso.test'; level = 'subscription'; from = 'Contoso Production' })
        $script:RgKey  = @(@{ tag = 'used for'; value = 'Ukendt'; level = 'resourceGroup'; from = 'rg-app' }
                           @{ tag = 'Used for'; value = 'Prod'; level = 'subscription'; from = 'Contoso Production' }
                           @{ tag = 'Business Application'; value = 'Azure Local'; level = 'subscription'; from = 'Contoso Production' }
                           @{ tag = 'owner'; value = 'ops@contoso.test'; level = 'subscription'; from = 'Contoso Production' })
    }
    function script:Res([string]$Type, [string]$Name, $Tags = $null) {
        $id = '{0}/providers/{1}/{2}' -f $script:RgKey, $Type, $Name
        $o = [ordered]@{ id = $id; name = $Name; type = $Type; subscriptionId = $script:Sub; resourceGroup = 'rg-app'; location = 'westeurope'; properties = [pscustomobject]@{} }
        if ($null -ne $Tags) { $o['tags'] = $Tags }
        $rt = 'azure_resource'; if ($Type -eq 'microsoft.network/publicipaddresses') { $rt = 'public_ip' }
        Add-SIRecordPart -Provider azure -RecordType $rt -Key $id -Part resource -Object ([pscustomobject]$o) -ResourceType $Type
        $id
    }
    function script:Row([string]$Key) {
        $res = ConvertTo-SIRecordRows -Captured @(Get-SICapturedRecords) -Model $script:Model
        @($res.Errors) | Should -BeNullOrEmpty
        @(@($res.Rows) | Where-Object { $_.si_provider -eq 'azure' -and $_.si_record_key -like "*$Key*" })[0]
    }
    function script:Texts($List) { @(@($List) | ForEach-Object { ConvertTo-SITagEntryText $_ }) }
}

Describe '1. capture: every inherited tag with the container it came from' {
    It 'the resource group wins over the subscription (by level, not by the order of the index entry), names compared case-insensitively' {
        $s = Get-SIParentTagScopes -Key "$($script:RgKey)/providers/microsoft.hybridcompute/machines/arc1" -ParentChain $script:Chain
        @($s).Count | Should -Be 3 -Because "'used for' and 'Used for' are ONE Azure tag name"
        $u = @($s | Where-Object { $_.name -eq 'used for' })[0]
        $u.value | Should -Be 'Ukendt'
        $u.scope | Should -Be 'resourceGroup'
        $u.from | Should -Be 'rg-app'
        $b = @($s | Where-Object { $_.name -eq 'Business Application' })[0]
        ($b.scope, $b.from, $b.value) | Should -Be @('subscription', 'Contoso Production', 'Azure Local')
        $s[0].scope | Should -Be 'resourceGroup' -Because 'the nearer container comes first'
    }
    It 'an index without the container name: the resource group''s name from the id; a subscription''s left for the derived part' {
        $chain = @{ $script:SubKey = @(@{ tag = 'env'; value = 'prod'; level = 'subscription' }); $script:RgKey = @(@{ tag = 'team'; value = 'blue'; level = 'resourceGroup' }) }
        $s = Get-SIParentTagScopes -Key "$($script:RgKey)/providers/x/y" -ParentChain $chain
        @($s | Where-Object { $_.name -eq 'team' })[0].from | Should -Be 'rg-app'
        @($s | Where-Object { $_.name -eq 'env' })[0].from | Should -Be ''
        # an entry without a level takes the level of the container it is listed under
        $s2 = Get-SIParentTagScopes -Key "$($script:RgKey)/providers/x/y" -ParentChain @{ $script:RgKey = @(@{ tag = 'a'; value = '1' }) }
        $s2[0].scope | Should -Be 'resourceGroup'
        # a resource's own tags in the index are never inherited
        $none = Get-SIParentTagScopes -Key "$($script:RgKey)/providers/x/y" -ParentChain @{ $script:RgKey = @(@{ tag = 'a'; value = '1'; level = 'resource' }) }
        $none.Count | Should -Be 0   # assigned first: the list comes back wrapped (an empty list is one value)
    }
    It 'the record gets parentTags (tag -> value, as before) AND parentTagScopes' {
        $null = Reset-SIRecordCapture -Engine 'azure' -Clear
        $id = Res 'microsoft.hybridcompute/machines' 'arc1'
        Add-SIRecordPartsFromRuleIndexes -Indexes @{ parentChain = $script:Chain }
        $obj = @(Get-SICapturedRecords | Where-Object { $_.Provider -eq 'azure' })[0].Object
        $obj.parentTags['Used for'] | Should -Be 'Ukendt' -Because 'the resource group is nearer than the subscription (the old code let the subscription win here)'
        $obj.parentTags['owner'] | Should -Be 'ops@contoso.test'
        @($obj.parentTagScopes).Count | Should -Be 3
    }
    It 'the new part is an attached part (a record of only attached parts is not published) and not a source of its own' {
        . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordHandover.ps1')
        $script:SIRecordAttachedParts | Should -Contain 'parentTagScopes'
        $script:SIRecordOwnlessParts | Should -Contain 'parentTagScopes'
    }
    It 'the profiler''s index carries each container''s name' {
        $t = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\shared\RuleIndexes.ps1'))
        $t | Should -Match "level = 'subscription'; from = \[string\]\`$s\.name"
        $t | Should -Match "level = 'resourceGroup'; from = \[string\]\`$r\.name"
        $t | Should -Match '\| project id, name, tags, subscriptionId'
    }
}

Describe '2 + 3. the derived tags and the two fields' {
    BeforeEach { $null = Reset-SIRecordCapture -Engine 'azure' -Clear; Set-SITagKeyMap -Map (Get-SITagKeyMapDefault) }
    AfterAll { Set-SITagKeyMap -Map $null }
    It 'own vs inherited: an own tag wins over the parent''s (case-insensitive), own first in the all-list' {
        $scopes = Get-SIParentTagScopes -Key "$($script:RgKey)/providers/x/y" -ParentChain $script:Chain
        $d = Get-SIAzureInheritedTagDerived -Tags ([pscustomobject]@{ ASRv2 = 'AzStackHCI'; OWNER = 'me@contoso.test' }) -Scopes $scopes -SubscriptionName 'ignored'
        $names = @($d['tagsInherited'] | ForEach-Object { $_.name })
        $names | Should -Not -Contain 'owner' -Because 'the resource sets OWNER itself'
        $names | Should -Be @('used for', 'Business Application')
        (Texts $d['tagsAll']) | Should -Be @('ASRv2 = AzStackHCI', 'OWNER = me@contoso.test', 'used for = Ukendt (resource group)', 'Business Application = Azure Local (subscription)')
        @($d['tagsInherited'])[1].from | Should -Be 'Contoso Production' -Because 'the index named it'
    }
    It 'a subscription tag without a name takes the subscription''s name, else its id; an empty value is left out; nothing = no field' {
        $sc = @([ordered]@{ name = 'env'; value = 'prod'; scope = 'subscription'; from = '' }, [ordered]@{ name = 'blank'; value = ''; scope = 'resourceGroup'; from = 'rg' })
        (Get-SIAzureInheritedTagDerived -Tags $null -Scopes $sc -SubscriptionName 'Contoso Production')['tagsInherited'][0].from | Should -Be 'Contoso Production'
        (Get-SIAzureInheritedTagDerived -Tags $null -Scopes $sc -SubscriptionId $script:Sub)['tagsInherited'][0].from | Should -Be $script:Sub
        @((Get-SIAzureInheritedTagDerived -Tags $null -Scopes $sc)['tagsInherited']).Count | Should -Be 1
        # an own tag without a value still overrides the container's tag
        (Get-SIAzureInheritedTagDerived -Tags ([pscustomobject]@{ ENV = '' }) -Scopes $sc).Contains('tagsInherited') | Should -BeFalse
        (Get-SIAzureInheritedTagDerived -Tags $null -Scopes $null).Count | Should -Be 0
    }
    It 'reaches si_tags_inherited and si_tags_all on an azure_resource and a public_ip record; si_tags stays the resource''s own' {
        $null = Res 'microsoft.hybridcompute/machines' 'arc1' ([pscustomobject]@{ ASRv2 = 'AzStackHCI' })
        $null = Res 'microsoft.network/publicipaddresses' 'pip1'
        Add-SIRecordPartsFromRuleIndexes -Indexes @{ parentChain = $script:Chain }
        $r = Row 'machines/arc1'
        (Texts $r.si_tags) | Should -Be @('ASRv2 = AzStackHCI')
        (Texts $r.si_tags_inherited) | Should -Be @('used for = Ukendt (resource group)', 'Business Application = Azure Local (subscription)', 'owner = ops@contoso.test (subscription)')
        (Texts $r.si_tags_all)[0] | Should -Be 'ASRv2 = AzStackHCI'
        @($r.si_tags_all).Count | Should -Be 4
        $p = Row 'publicipaddresses/pip1'
        @($p.si_tags_inherited).Count | Should -Be 3
        @($p.si_tags_all).Count | Should -Be 3 -Because 'no own tags: every tag is inherited'
    }
    It 'the tag-key fields read the parent tags exactly as before (tagOwner from the subscription)' {
        $null = Res 'microsoft.web/sites' 'app1' ([pscustomobject]@{ env = 'Test' })
        Add-SIRecordPartsFromRuleIndexes -Indexes @{ parentChain = $script:Chain }
        $r = Row 'sites/app1'
        $r.si_owner | Should -Be 'ops@contoso.test'
        $r.si_environment | Should -Be 'Test' -Because 'the resource''s own tag wins'
    }
}

Describe '4. the CI: every tag in one list, and rules can match it' {
    It 'si_tags_all = si_tags (every source, the rules'' tags) then si_tags_inherited; a CI without tags gets none' {
        $ci = [ordered]@{ si_class = 'device'; si_tags = @([ordered]@{ source = 'mde'; name = 'PAW'; value = '' }, [ordered]@{ source = 'azure'; name = 'env'; value = 'prod' })
            si_tags_inherited = @([ordered]@{ source = 'azure'; name = 'Used for'; value = 'Ukendt'; scope = 'resourceGroup'; from = 'rg-app' }) }
        Set-SICiTagsAll -Ci $ci
        (Texts $ci.si_tags_all) | Should -Be @('PAW', 'env = prod', 'Used for = Ukendt (resource group)')
        $none = [ordered]@{ si_class = 'identity'; si_tags_all = @('stale') }
        Set-SICiTagsAll -Ci $none
        $none.Contains('si_tags_all') | Should -BeFalse
    }
    It 'the enrichment sets it with the rules'' tags, and a rule matches si_tags_all like si_tags' {
        $ci = [ordered]@{ si_ci_id = 'c1'; si_class = 'cloud_resource'; si_asset_name = 'arc1'; si_tags_inherited = @([ordered]@{ source = 'azure'; name = 'Used for'; value = 'Prod'; scope = 'subscription'; from = 'Contoso Production' }) }
        $null = Invoke-SICiEnrichment -Cis @($ci) -Model $script:Model -Now ([datetime]'2026-11-03T06:00:00Z')
        @(Texts $ci.si_tags_all)[-1] | Should -Be 'Used for = Prod (subscription)' -Because 'the inherited tags come after every own and rule tag'
        Test-SICondition @{ field = 'si_tags_all'; op = 'matches'; value = '^Used for=Prod$' } $ci | Should -BeTrue
        Test-SICondition @{ field = 'si_tags_all'; op = 'contains'; value = 'Used for=Prod' } $ci | Should -BeTrue
        Test-SICondition @{ field = 'si_tags_all'; op = 'contains'; value = 'Prod' } $ci | Should -BeTrue
        Test-SICondition @{ field = 'si_tags'; op = 'contains'; value = 'Prod' } $ci | Should -BeFalse -Because 'si_tags holds the own tags only'
        ConvertTo-SICiEvidenceText -Field 'si_tags_all' -Value @($ci.si_tags_all)[-1] | Should -Be 'Azure tag (inherited from the subscription) Used for=Prod'
    }
}

Describe '5. data out: tags as text, never JSON' {
    BeforeAll {
        $script:Tags = @([ordered]@{ source = 'azure'; name = 'ASRv2'; value = 'AzStackHCI' }, [ordered]@{ source = 'mde'; name = 'PAW'; value = '' },
            [ordered]@{ source = 'azure'; name = 'Used for'; value = 'Ukendt'; scope = 'resourceGroup'; from = 'rg-app' },
            [ordered]@{ source = 'azure'; name = 'Business Application'; value = 'Azure Local'; scope = 'subscription'; from = 'Contoso Production' })
        $script:Want = 'ASRv2 = AzStackHCI; PAW; Used for = Ukendt (resource group); Business Application = Azure Local (subscription)'
    }
    It 'an Excel cell' {
        $cells = ConvertTo-SIDataOutCells -Row ([pscustomobject]@{ t = $script:Tags; l = @([pscustomobject]@{ provider = 'mde'; id = 'abc' }); s = @('a', 'b') }) -Header @('t', 'l', 's')
        $cells[0] | Should -BeExactly $script:Want
        $cells[1] | Should -Be '{"provider":"mde","id":"abc"}' -Because 'a list of other objects keeps its form'
        $cells[2] | Should -Be 'a; b'
        # a tag list the CI document kept as JSON text
        (ConvertTo-SIDataOutCells -Row ([pscustomobject]@{ t = ($script:Tags | ConvertTo-Json -Compress) }) -Header @('t'))[0] | Should -BeExactly $script:Want
    }
    It 'the ServiceNow wire value' {
        ConvertTo-SIDataOutWireValue $script:Tags | Should -BeExactly $script:Want
        ConvertTo-SIDataOutWireValue ($script:Tags | ConvertTo-Json -Compress) | Should -BeExactly $script:Want
        $linked = ConvertTo-SIDataOutWireValue -Value @([ordered]@{ id = 'x'; name = 'n'; value = 'v' })
        ($linked -is [string]) | Should -BeFalse -Because 'an object with an id is never a tag: the list is sent as it was'
        # a list of ONE tag reaches the writer unrolled (the entry itself): still its text, never JSON
        ConvertTo-SIDataOutWireValue $script:Tags[2] | Should -BeExactly 'Used for = Ukendt (resource group)'
        (ConvertTo-SIDataOutCells -Row ([pscustomobject]@{ t = $script:Tags[0] }) -Header @('t'))[0] | Should -BeExactly 'ASRv2 = AzStackHCI'
        ConvertTo-SIDataOutWireValue 'plain' | Should -Be 'plain'
        ConvertTo-SIDataOutWireValue '["a","b"]' | Should -Be '["a","b"]'
    }
    It 'the shipped ServiceNow CI map appends u_tags_all, u_tags and u_tags_inherited, and a CI row carries them as text' {
        $cols = @($script:Model.Outputs['servicenow-ci'].columns)
        @($cols | Select-Object -Last 3 | ForEach-Object { '{0}<-{1}' -f $_.target, $_.from }) | Should -Be @('u_tags_all<-si_tags_all', 'u_tags<-si_tags', 'u_tags_inherited<-si_tags_inherited')
        $cols[-4].target | Should -Be 'u_si_replaces' -Because 'append only: nothing before them moved'
        $own = @($script:Tags[0], $script:Tags[1]); $inh = @($script:Tags[2], $script:Tags[3])
        $it = [pscustomobject]@{ si_ci_id = 'c1'; si_class = 'cloud_resource'; si_asset_name = 'arc1'; si_tags = $own; si_tags_inherited = $inh; si_tags_all = $script:Tags }
        $row = ConvertTo-SIDataOutContractRow -Output 'servicenow-ci' -Map $script:Model.Outputs['servicenow-ci'] -Item $it -ValueMaps $script:Model['value-maps'].maps -Context @{ RunId = 'r'; RunTime = [datetime]'2026-11-03T04:00:00Z'; ChangedAt = [datetime]'2026-11-03T04:00:00Z' } -Action new -BatchId 'r:servicenow-ci'
        $row['u_tags_all'] | Should -BeExactly $script:Want
        $row['u_tags'] | Should -BeExactly 'ASRv2 = AzStackHCI; PAW'
        $row['u_tags_inherited'] | Should -BeExactly 'Used for = Ukendt (resource group); Business Application = Azure Local (subscription)'
        # ONE tag (the map's read hands a one-item list back as the item): text, never a JSON object
        $one = [pscustomobject]@{ si_ci_id = 'c2'; si_class = 'cloud_resource'; si_asset_name = 'kv7'; si_tags = @($script:Tags[0]); si_tags_all = @($script:Tags[0]) }
        $row1 = ConvertTo-SIDataOutContractRow -Output 'servicenow-ci' -Map $script:Model.Outputs['servicenow-ci'] -Item $one -ValueMaps $script:Model['value-maps'].maps -Context @{ RunId = 'r'; RunTime = [datetime]'2026-11-03T04:00:00Z' } -Action new -BatchId 'r:servicenow-ci'
        $row1['u_tags'] | Should -BeExactly 'ASRv2 = AzStackHCI'
        $row1['u_tags_all'] | Should -BeExactly 'ASRv2 = AzStackHCI'
    }
}

Describe '6. registered everywhere a CI field is' {
    It 'both fields are in the field catalog -- the two copies identical -- with a plain description' {
        $a = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'data-model\field-catalog.locked.json'))
        $b = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'pro-management\src\SI.Management.Core\ProData\DataModel\field-catalog.locked.json'))
        $b | Should -BeExactly $a
        foreach ($f in 'si_tags_inherited', 'si_tags_all') {
            $e = @($script:Model['field-catalog'].fields | Where-Object { $_.name -eq $f })[0]
            $e.type | Should -Be 'dynamic'
            @($e.classes) | Should -Contain 'cloud_resource'
            $e.description | Should -Not -Match '#\d'
        }
    }
    It 'mapped from the derived part on azure_resource and public_ip, and posted to the CI table' {
        foreach ($p in @(@('si_tags_inherited', 'derived.tagsInherited'), @('si_tags_all', 'derived.tagsAll'))) {
            $m = @($script:Model.Mappings['azure'].mappings | Where-Object { $_.field -eq $p[0] })[0]
            @($m.sources) | Should -Be @($p[1])
            @($m.recordTypes) | Should -Be @('azure_resource', 'public_ip')
        }
        . (Join-Path $script:SIRoot 'engine\data-model\SI-CiBuildSql.ps1')
        $script:SICiPostFields | Should -Contain 'si_tags_inherited'
        $script:SICiPostFields | Should -Contain 'si_tags_all'
        $script:SICiBuildVersion | Should -BeGreaterOrEqual 13 -Because 'CIs change: every CI is rebuilt once after the update'
    }
}
