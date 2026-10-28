#Requires -Version 5.1
<#
    THE MAPPING MERGE KEEPS EVERY ITEM (engine/data-model/SI-DataModelTemplates.ps1, Merge-SIDataModelItems).

    A field mapping may hold several items for ONE field and record type -- eg.locked.json has four si_device_roles|device
    items (deviceRole[*], isDomainController, the Exchange flags, isAdfsServer), unioned by the mapper. They shared one
    merge key, so as soon as a customer file existed for the provider only the LAST survived (a domain controller lost its
    role). Now each repeat has its own key ('<key>#<n>'; the first keeps the plain key), and the mapper merges the items by
    the field's own rule.

      * no mapping file loses an item through the merge (every shipped mapping, with a custom file present);
      * the four si_device_roles items all contribute (union);
      * a custom item overrides only the shipped item at the same position; a custom file with the plain key still
        overrides the first;
      * a single-value field with several items stays first-wins.
#>

BeforeDiscovery {
    $mapNames = @(Get-ChildItem -LiteralPath (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'data-model\mappings') -Filter '*.locked.json' | Sort-Object Name | ForEach-Object { $_.Name.Replace('.locked.json', '') })
}

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\data-model\SI-DataModelTemplates.ps1')
    $script:DmRoot = Join-Path $script:SIRoot 'data-model'
    $script:MapFiles = @(Get-ChildItem -LiteralPath (Join-Path $script:DmRoot 'mappings') -Filter '*.locked.json' | Sort-Object Name)
    function script:New-Overlay([hashtable]$CustomByName) {
        $dir = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path (Join-Path $dir 'mappings') -Force | Out-Null
        foreach ($k in $CustomByName.Keys) { [IO.File]::WriteAllText((Join-Path $dir ("mappings\{0}.custom.json" -f $k)), (ConvertTo-Json -InputObject $CustomByName[$k] -Depth 20)) }
        $dir
    }
    $script:EgDevice = [pscustomobject]@{ node = [pscustomobject]@{ NodeId = 'n1'; NodeLabel = 'device'; NodeName = 'dc01'
        NodeProperties = [pscustomobject]@{ rawData = [pscustomobject]@{ deviceRole = @('DomainController'); isDomainController = $true; isTaggedAsExchangeServer = $true; isAdfsServer = $true } } } }
}

Describe 'no mapping file loses an item in the merge' {
    It 'keeps every item of <name> when the provider has a custom file' -TestCases @($mapNames | ForEach-Object { @{ name = $_ } }) {
        $locked = [IO.File]::ReadAllText((Join-Path $script:DmRoot "mappings\$name.locked.json")) | ConvertFrom-Json
        $ov = New-Overlay @{ $name = [ordered]@{ kind = 'field-mapping'; provider = [string]$locked.provider; mappings = @() } }
        $t = Get-SIDataModelTemplate -Name "mappings/$name" -Root $script:DmRoot -OverlayRoot $ov
        @($t.Document.mappings).Count | Should -Be @($locked.mappings).Count
        # the same items, in the shipped order
        @($t.Document.mappings | ForEach-Object { ConvertTo-Json -InputObject $_ -Compress -Depth 20 }) | Should -Be @($locked.mappings | ForEach-Object { ConvertTo-Json -InputObject $_ -Compress -Depth 20 })
    }
    It 'found at least one mapping file with repeated field items (so the test above is not vacuous)' {
        $rep = foreach ($f in $script:MapFiles) {
            $m = [IO.File]::ReadAllText($f.FullName) | ConvertFrom-Json
            @($m.mappings | Group-Object { Get-SIDataModelItemKey 'field-mapping' $_ } | Where-Object Count -gt 1).Count
        }
        ($rep | Measure-Object -Sum).Sum | Should -BeGreaterThan 0
    }
}

Describe 'repeated items merge by the field''s rule' {
    It 'unions all four si_device_roles items with a custom eg file present' {
        $ov = New-Overlay @{ eg = [ordered]@{ kind = 'field-mapping'; provider = 'eg'; mappings = @() } }
        $model = Get-SIDataModel -Root $script:DmRoot -OverlayRoot $ov
        @($model.Mappings['eg'].mappings | Where-Object { $_.field -eq 'si_device_roles' }).Count | Should -Be 4
        $r = ConvertTo-SIRecord -Object $script:EgDevice -Mapping $model.Mappings['eg'] -RecordType 'device' -Catalog $model['field-catalog'] -ValueMaps $model['value-maps'].maps
        foreach ($role in 'domain_controller', 'exchange', 'adfs') { @($r.Record.si_device_roles) | Should -Contain $role }
    }
    It 'overrides only the shipped item at the same position; the plain key still overrides the first' {
        $locked = [IO.File]::ReadAllText((Join-Path $script:DmRoot 'mappings\eg.locked.json')) | ConvertFrom-Json
        $roles = @($locked.mappings | Where-Object { $_.field -eq 'si_device_roles' })
        # the customer's file: the 1st item as shipped, the 2nd (isDomainController) removed
        $c1 = $roles[0] | ConvertTo-Json -Depth 10 | ConvertFrom-Json
        $c2 = $roles[1] | ConvertTo-Json -Depth 10 | ConvertFrom-Json; $c2 | Add-Member -NotePropertyName remove -NotePropertyValue $true
        $ov = New-Overlay @{ eg = [ordered]@{ kind = 'field-mapping'; provider = 'eg'; mappings = @($c1, $c2) } }
        $t = Get-SIDataModelTemplate -Name 'mappings/eg' -Root $script:DmRoot -OverlayRoot $ov
        $left = @($t.Document.mappings | Where-Object { $_.field -eq 'si_device_roles' })
        $left.Count | Should -Be 3
        @($left | ForEach-Object { @($_.sources)[0] }) | Should -Not -Contain 'node.NodeProperties.rawData.isDomainController'
        @($t.States | Where-Object State -eq 'Disabled').Key | Should -Be 'si_device_roles|device|#2'
        @($t.States | Where-Object State -eq 'Overridden').Key | Should -Be 'si_device_roles|device|'
    }
    It 'keeps a single-value field first-wins across its items' {
        $mapping = [pscustomobject]@{ kind = 'field-mapping'; provider = 'x'
            objects = @([pscustomobject]@{ recordType = 'device'; class = 'device'; key = 'o.id' })
            mappings = @(
                [pscustomobject]@{ field = 'si_os_version'; recordTypes = @('device'); sources = @('o.a'); normalize = @('trim') }
                [pscustomobject]@{ field = 'si_os_version'; recordTypes = @('device'); sources = @('o.b'); normalize = @('trim') }) }
        $m = Merge-SIDataModelItems -Kind 'field-mapping' -Locked $mapping.mappings -Custom @()
        @($m.Items).Count | Should -Be 2
        $mapping.mappings = $m.Items
        $model = Get-SIDataModel -Root $script:DmRoot
        $r = ConvertTo-SIRecord -Object ([pscustomobject]@{ o = [pscustomobject]@{ id = '1'; a = 'first'; b = 'second' } }) -Mapping $mapping -RecordType 'device' -Catalog $model['field-catalog'] -ValueMaps $model['value-maps'].maps
        $r.Record.si_os_version | Should -Be 'first'
        $r2 = ConvertTo-SIRecord -Object ([pscustomobject]@{ o = [pscustomobject]@{ id = '1'; b = 'second' } }) -Mapping $mapping -RecordType 'device' -Catalog $model['field-catalog'] -ValueMaps $model['value-maps'].maps
        $r2.Record.si_os_version | Should -Be 'second'
    }
    It 'still keeps one item per key for other template kinds' {
        $m = Merge-SIDataModelItems -Kind 'list' -Locked @([pscustomobject]@{ id = 'a'; v = 1 }, [pscustomobject]@{ id = 'a'; v = 2 }) -Custom @()
        @($m.Items).Count | Should -Be 1
    }
}
