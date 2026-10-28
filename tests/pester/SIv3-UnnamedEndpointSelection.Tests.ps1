#Requires -Version 5.1
<#
    #348 -- WHICH devices the endpoint engine profiles must not depend on the order a query returns its rows.

    Measured on ring 1 2026-10-05: 26 Exposure Graph device nodes share the name `DummyDeviceName`, each with its own
    Defender device id. Discovery merged records by lowercased NAME, so the 26 collapsed into one asset whose id came
    from whichever row arrived first -- and advanced hunting does not guarantee row order. The kept device changed run
    to run (10:58 `357483ba...`, 14:01 `acb6ef0b...`) and ENDPOINT-EXCLUDED-BY-TAG-001 flipped between "new" and "no
    longer reported". The collect stage's DeviceInfo join had the same shape (by name, last write wins).

    The functions are lifted from the engine files by AST, so the test runs the shipped code, not a copy.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    foreach ($pair in @(
        @('engine\asset-profiling\stages\Invoke-Discover.ps1', @('Merge-SIDiscoverRecordsByName', 'Get-SIOrdinalSortedEntries', 'Merge-SIDiscoverRecordsByMdeId')),
        @('engine\asset-profiling\stages\Invoke-Collect.ps1',  @('ConvertTo-SIDeviceInfoIndex', 'Find-SIDeviceInfo'))
    )) {
        $src = [System.IO.File]::ReadAllText((Join-Path $script:SIRoot $pair[0]))
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($src, [ref]$null, [ref]$null)
        foreach ($name in $pair[1]) {
            $fn = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name }, $true)
            if (-not $fn) { throw "function $name not found in $($pair[0])" }
            . ([scriptblock]::Create($fn.Extent.Text))
        }
    }

    $script:Pri = @{ 'ExposureGraph' = 5; 'EndpointExposureGraph' = 5; 'EntraDevice' = 4; 'MDEDevice' = 2; 'AzureVM' = 1; 'ARCMachine' = 1; 'AzureResource' = 1 }
    $script:Res = @('AssetId', 'Source', 'Hint', 'Name', 'NormalizedKey', 'Sources', 'Raw')

    # The ring-1 shape: N devices named DummyDeviceName, each seen by the two graph sources (one carrying the Defender
    # id via SenseDeviceId, one not) and by Defender itself -- plus ordinary named devices around them.
    function script:New-DummyEstate([int]$Count) {
        $rows = New-Object System.Collections.Generic.List[object]
        for ($i = 0; $i -lt $Count; $i++) {
            $node = ('{0:x32}' -f (1000 + $i)); $mde = ('{0:x40}' -f (5000 + $i))
            $rows.Add(@{ AssetId = "eg:dev:$node"; Source = 'EndpointExposureGraph'; Hint = 'endpoint'; Name = 'DummyDeviceName'; NormalizedKey = 'dummydevicename'; EG_NodeId = $node; EG_MdeDeviceId = $mde; EG_LastSeen = "2026-10-0$((($i % 5) + 1))" })
            $rows.Add(@{ AssetId = "eg:$node"; Source = 'ExposureGraph'; Hint = 'windows'; Name = 'DummyDeviceName'; NormalizedKey = 'dummydevicename'; EgNodeId = $node })
            $rows.Add(@{ AssetId = "mde:$mde"; Source = 'MDEDevice'; Hint = 'windows'; Name = 'DummyDeviceName'; NormalizedKey = 'dummydevicename'; MDE_DeviceId = $mde; MDE_DeviceName = 'DummyDeviceName' })
        }
        foreach ($h in 'pc-a', 'pc-b', 'srv-c') {
            $rows.Add(@{ AssetId = "eg:dev:n-$h"; Source = 'EndpointExposureGraph'; Hint = 'endpoint'; Name = $h; NormalizedKey = $h; EG_NodeId = "n-$h"; EG_MdeDeviceId = "m-$h"; EG_AadDeviceId = "aad-$h" })
            $rows.Add(@{ AssetId = "entra:e-$h"; Source = 'EntraDevice'; Hint = 'windows'; Name = $h.ToUpperInvariant(); NormalizedKey = $h; ENTRA_AadDeviceId = "aad-$h"; ENTRA_DisplayName = $h.ToUpperInvariant() })
            $rows.Add(@{ AssetId = "mde:m-$h"; Source = 'MDEDevice'; Hint = 'windows'; Name = $h; NormalizedKey = $h; MDE_DeviceId = "m-$h" })
        }
        return ,$rows.ToArray()
    }
    function script:Get-Orders([object[]]$Rows) {
        $out = New-Object System.Collections.Generic.List[object]
        $out.Add($Rows)
        $rev = $Rows.Clone(); [Array]::Reverse($rev); $out.Add($rev)
        foreach ($seed in 7, 348, 2026) {
            $rnd = New-Object System.Random($seed)
            $keys = New-Object 'double[]' $Rows.Count
            for ($i = 0; $i -lt $Rows.Count; $i++) { $keys[$i] = $rnd.NextDouble() }
            $copy = $Rows.Clone(); [Array]::Sort([Array]$keys, [Array]$copy); $out.Add($copy)
        }
        return $out.ToArray()
    }
    # The whole discovery merge as the engine runs it: name pass, then the Defender id pass.
    function script:Invoke-Merge([object[]]$Rows) {
        $m = Merge-SIDiscoverRecordsByName -RawAssets $Rows -SourcePriority $script:Pri -ReservedKeys $script:Res
        $by = $m.ByKey
        $null = Merge-SIDiscoverRecordsByMdeId -ByKey $by -ReservedKeys $script:Res -SourcePriority $script:Pri
        return @{ ByKey = $by; Name = $m }
    }
    function script:Get-Fingerprint($ByKey) {
        $lines = foreach ($e in (Get-SIOrdinalSortedEntries -Table $ByKey)) {
            $v = $e.Value
            '{0}|{1}|{2}|{3}|{4}|{5}|{6}' -f $e.Key, $v.AssetId, $v.Name, $v.Source, $v.EG_MdeDeviceId, $v.MDE_DeviceId, $v.EG_LastSeen
        }
        return ($lines -join "`n")
    }
}

Describe '#348 discovery: the same input in any order gives the same assets' {
    It 'every order of the ring-1 shape yields the SAME kept set -- keys, ids, names, sources and promoted fields' {
        $rows = New-DummyEstate -Count 26
        $prints = @(Get-Orders $rows | ForEach-Object { Get-Fingerprint (Invoke-Merge $_).ByKey })
        $prints.Count | Should -Be 5
        foreach ($p in $prints) { $p | Should -BeExactly $prints[0] }
    }
    It 'RED CASE -- 26 devices sharing one name are 26 assets, each under its own Defender id -- none is chosen, none dropped' {
        $r = Invoke-Merge (New-DummyEstate -Count 26)
        $dummy = @($r.ByKey.Values | Where-Object { $_.Name -eq 'DummyDeviceName' })
        $dummy.Count | Should -Be 26
        @($dummy | ForEach-Object { [string]$_.EG_MdeDeviceId } | Sort-Object -Unique).Count | Should -Be 26
        # each Defender device kept its own three records (graph node with the id, graph node without, Defender record)
        foreach ($d in $dummy) { @($d.Raw).Count | Should -Be 3; ([string]$d.MDE_DeviceId) | Should -BeExactly ([string]$d.EG_MdeDeviceId) }
        $r.Name.AmbiguousNames | Should -Be @('dummydevicename')
        $r.Name.SplitRecords | Should -Be 78
    }
    It 'NO CAP: 500 unnamed devices sharing a name are all kept' {
        $r = Invoke-Merge (New-DummyEstate -Count 500)
        @($r.ByKey.Values | Where-Object { $_.Name -eq 'DummyDeviceName' }).Count | Should -Be 500
        $r.ByKey.Count | Should -Be 503
    }
    It 'NEGATIVE: one device under one name still merges across sources (graph, Entra, Defender -> one asset)' {
        $r = Invoke-Merge (New-DummyEstate -Count 3)
        $pc = @($r.ByKey.Values | Where-Object { $_.NormalizedKey -eq 'pc-a' })
        $pc.Count | Should -Be 1
        @($pc[0].Sources | Sort-Object) | Should -Be @('EndpointExposureGraph', 'EntraDevice', 'MDEDevice')
        $pc[0].AssetId | Should -BeExactly 'eg:dev:n-pc-a'
    }
    It 'NEGATIVE: a device node and a VM node of ONE machine under one name are still one asset' {
        $rows = @(
            @{ AssetId = 'eg:dev:dev1'; Source = 'EndpointExposureGraph'; Hint = 'endpoint'; Name = 'dc1'; NormalizedKey = 'dc1'; EG_NodeId = 'dev1'; EG_MdeDeviceId = 'mdc1' },
            @{ AssetId = 'eg:dev:vm1';  Source = 'EndpointExposureGraph'; Hint = 'endpoint'; Name = 'dc1'; NormalizedKey = 'dc1'; EG_NodeId = 'vm1' }
        )
        $r = Merge-SIDiscoverRecordsByName -RawAssets $rows -SourcePriority $script:Pri -ReservedKeys $script:Res
        $r.ByKey.Count | Should -Be 1
        @($r.AmbiguousNames).Count | Should -Be 0
        $r2 = Merge-SIDiscoverRecordsByName -RawAssets @($rows[1], $rows[0]) -SourcePriority $script:Pri -ReservedKeys $script:Res
        (@($r2.ByKey.Values)[0]).AssetId | Should -BeExactly (@($r.ByKey.Values)[0]).AssetId
    }
    It 'equal-priority sources: the representative is decided by source and id, not arrival' {
        $a = @{ AssetId = 'eg:dev:zz'; Source = 'EndpointExposureGraph'; Hint = 'endpoint'; Name = 'h1'; NormalizedKey = 'h1'; EG_NodeId = 'zz' }
        $b = @{ AssetId = 'eg:zz';     Source = 'ExposureGraph';         Hint = 'windows';  Name = 'h1'; NormalizedKey = 'h1'; EgNodeId = 'zz' }
        $one = (Merge-SIDiscoverRecordsByName -RawAssets @($a, $b) -SourcePriority $script:Pri -ReservedKeys $script:Res).ByKey['h1']
        $two = (Merge-SIDiscoverRecordsByName -RawAssets @($b, $a) -SourcePriority $script:Pri -ReservedKeys $script:Res).ByKey['h1']
        $one.AssetId | Should -BeExactly $two.AssetId
        $one.Hint | Should -BeExactly $two.Hint
    }
    It 'the Defender id pass picks the same primary whatever order the table was filled in' {
        $mk = { param($k, $src, $fields) $raw = @{ Source = $src; Name = $k } + $fields; @{ AssetId = "${src}:$k"; Source = $src; Hint = 'endpoint'; Name = $k; NormalizedKey = $k; Sources = @($src); Raw = @($raw) } + $fields }
        $x = & $mk 'b-host' 'MDEDevice' @{ MDE_DeviceId = 'same' }
        $y = & $mk 'a-host.fqdn' 'MDEDevice' @{ MDE_DeviceId = 'same' }
        $t1 = @{}; $t1['b-host'] = $x.Clone(); $t1['a-host.fqdn'] = $y.Clone()
        $t2 = @{}; $t2['a-host.fqdn'] = $y.Clone(); $t2['b-host'] = $x.Clone()
        $null = Merge-SIDiscoverRecordsByMdeId -ByKey $t1 -ReservedKeys $script:Res -SourcePriority $script:Pri
        $null = Merge-SIDiscoverRecordsByMdeId -ByKey $t2 -ReservedKeys $script:Res -SourcePriority $script:Pri
        @($t1.Keys) | Should -Be @('a-host.fqdn')
        @($t2.Keys) | Should -Be @('a-host.fqdn')
    }
}

Describe '#348 collect: DeviceInfo joins on the Defender id, never on a shared name' {
    BeforeAll {
        $script:DiRows = @(
            [pscustomobject]@{ DeviceId = 'AAA1'; DeviceName = 'DummyDeviceName'; PublicIP = '1.1.1.1' },
            [pscustomobject]@{ DeviceId = 'bbb2'; DeviceName = 'DummyDeviceName'; PublicIP = '2.2.2.2' },
            [pscustomobject]@{ DeviceId = 'ccc3'; DeviceName = 'PC-A';            PublicIP = '3.3.3.3' }
        )
    }
    It 'a name two devices carry is not a join key; each device is found by its own id, in any order' {
        foreach ($rows in @($script:DiRows, @($script:DiRows[2], $script:DiRows[1], $script:DiRows[0]))) {
            $idx = ConvertTo-SIDeviceInfoIndex -Rows $rows
            $idx.ContainsKey('dummydevicename') | Should -BeFalse
            (Find-SIDeviceInfo -Index $idx -DeviceIds @('aaa1') -NameKey 'dummydevicename').PublicIP | Should -Be '1.1.1.1'
            (Find-SIDeviceInfo -Index $idx -DeviceIds @('', 'BBB2') -NameKey 'dummydevicename').PublicIP | Should -Be '2.2.2.2'
            Find-SIDeviceInfo -Index $idx -DeviceIds @() -NameKey 'dummydevicename' | Should -BeNullOrEmpty
        }
    }
    It 'NEGATIVE: a name only one device carries still joins by name' {
        $idx = ConvertTo-SIDeviceInfoIndex -Rows $script:DiRows
        (Find-SIDeviceInfo -Index $idx -DeviceIds @($null) -NameKey 'pc-a').PublicIP | Should -Be '3.3.3.3'
        Find-SIDeviceInfo -Index @{} -DeviceIds @('aaa1') -NameKey 'pc-a' | Should -BeNullOrEmpty
    }
}

Describe '#348 WIRING' {
    It 'discovery runs the name pass through the function, and every later pass walks the table in ordinal order' {
        $d = Get-Content -Raw (Join-Path $script:SIRoot 'engine\asset-profiling\stages\Invoke-Discover.ps1')
        # the name pass runs inside Merge-SIDiscoveredAssets -- the one merge the one-process path and every streamed part call (#475)
        $d | Should -Match '\$nameMerge = Merge-SIDiscoverRecordsByName -RawAssets \$RawAssets '
        $d | Should -Match '\$byKey = Merge-SIDiscoveredAssets -RawAssets \$rawAssets\.ToArray\(\)'
        $d | Should -Match 'foreach \(\$entry in \(Get-SIOrdinalSortedEntries -Table \$byKey\)\)'
        $d | Should -Match '\$assets = @\(\(Get-SIOrdinalSortedEntries -Table \$byKey\)'
        $d | Should -Not -Match '\$byKey\.GetEnumerator\(\)'
        $d | Should -Not -Match '\$ByKey\.GetEnumerator\(\)'
        $d.IndexOf('$nameMerge = Merge-SIDiscoverRecordsByName') | Should -BeLessThan $d.IndexOf('Merge-SIDiscoverRecordsByMdeId -ByKey $byKey')
    }
    It 'both collect branches look DeviceInfo up through Find-SIDeviceInfo, with the asset''s Defender ids' {
        $c = Get-Content -Raw (Join-Path $script:SIRoot 'engine\asset-profiling\stages\Invoke-Collect.ps1')
        ([regex]::Matches($c, '\$di = Find-SIDeviceInfo -Index \$deviceInfoByName -DeviceIds')).Count | Should -Be 2
        $c | Should -Not -Match '\$deviceInfoByName\[\$nameKey\]'
        $c | Should -Match 'return \(ConvertTo-SIDeviceInfoIndex -Rows \$allRows\.ToArray\(\)\)' -Because 'every chunk''s rows are indexed TOGETHER'
    }
}

Describe 'collect: the Defender device rows are asked in chunks; one refused chunk costs only its own names' {
    BeforeAll {
        $src = [System.IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\stages\Invoke-Collect.ps1'))
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($src, [ref]$null, [ref]$null)
        foreach ($name in 'Get-SIDeviceInfoByName', 'Invoke-SIDeviceInfoChunk') {
            . ([scriptblock]::Create(($ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name }, $true)).Extent.Text))
        }
        # a fake hunting service: one Defender device per name in the query; -Fail names a chunk (by a name in it) that is refused
        function script:New-FakeHunt([string]$Fail = '') {
            $w = @{ Calls = (New-Object System.Collections.Generic.List[string]) }
            $w.Run = {
                param($q)
                $w.Calls.Add($q)
                if ($Fail -and $q -match [regex]::Escape("'$Fail'")) { throw 'the query was refused (400)' }
                foreach ($m in [regex]::Matches($q, "'(pc-\d+|dummydevicename)'")) {
                    $n = $m.Groups[1].Value
                    if ($n -eq 'dummydevicename') { [pscustomobject]@{ DeviceId = 'd1'; DeviceName = 'DummyDeviceName' }; [pscustomobject]@{ DeviceId = 'd2'; DeviceName = 'DummyDeviceName' } }
                    else { [pscustomobject]@{ DeviceId = "id-$n"; DeviceName = $n.ToUpperInvariant(); PublicIP = "ip-$n" } }
                }
            }.GetNewClosure()
            $w
        }
    }
    It '2,500 names go 1,000 at a time; every device is indexed; a name two devices carry is still no join key' {
        $names = @(1..2499 | ForEach-Object { 'PC-{0}' -f $_ }) + @('DummyDeviceName', 'pc-1')
        $f = New-FakeHunt
        $idx = Get-SIDeviceInfoByName -DeviceNames $names -RunQuery $f.Run
        $f.Calls.Count | Should -Be 3
        $f.Calls[0] | Should -Not -Match '__SI_DEVICE_NAMES__'
        $idx['pc-2499'].PublicIP | Should -Be 'ip-pc-2499'
        $idx['pc-1'].PublicIP | Should -Be 'ip-pc-1'
        $idx.ContainsKey('id:id-pc-1500') | Should -BeTrue
        $idx.ContainsKey('dummydevicename') | Should -BeFalse
        $idx.ContainsKey('id:d2') | Should -BeTrue
    }
    It 'a refused chunk loses only its names, says so, and the other chunks are kept; every chunk refused = nothing' {
        $names = @(1..2500 | ForEach-Object { 'PC-{0}' -f $_ })
        $f = New-FakeHunt -Fail 'pc-2000'
        $idx = Get-SIDeviceInfoByName -DeviceNames $names -RunQuery $f.Run -WarningVariable w -WarningAction SilentlyContinue
        $f.Calls.Count | Should -Be 3
        @($w | Where-Object { "$_" -match 'chunk 2 of 3' }).Count | Should -Be 1
        $idx['pc-1'].PublicIP | Should -Be 'ip-pc-1' -Because 'the chunks before and after the refused one are kept'
        $idx.ContainsKey('pc-2000') | Should -BeFalse
        (Get-SIDeviceInfoByName -DeviceNames @('PC-1') -RunQuery { throw 'down' } -WarningAction SilentlyContinue).Count | Should -Be 0
    }
}
