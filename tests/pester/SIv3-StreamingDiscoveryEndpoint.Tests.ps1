#Requires -Version 5.1
<#
    STREAMING DISCOVERY FOR ENDPOINTS (#475) -- the hard engine: one device is seen by Defender (MDE), the Exposure Graph
    and Entra under DIFFERENT names, and one process folds its rows by name, then by AadDeviceId, then by the Defender
    device id. Streaming is only correct if every merge of one device happens inside one part.
    What these tests keep true:
      * 6,000 devices (~16,000 rows) with graph nodes named differently (joined only by the Defender id), Entra devices
        named differently (joined only by AadDeviceId), 26 devices sharing one name with their own Defender ids (kept
        apart), and records whose AadDeviceIds disagree (not merged): the streamed assets are EXACTLY the one-process
        assets -- the same keys, the same rows in each asset, every tenth asset compared in full -- and merges across
        names do happen (the test proves it covers them); every asset is in exactly one part;
      * the paged sources (Entra devices) stream page by page; the graph sources read in buckets by the node id's hash;
        the hunting count reads one number;
      * all five endpoint sources and Discover are wired (one builder per source for both paths; devices counted first).
    The test store round-trips every chunk through JSON, as staging does. Offline. PS 5.1 and pwsh 7.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $ap = Join-Path $script:SIRoot 'engine\asset-profiling'
    . (Join-Path $ap '_shared\Write-SIStyle.ps1')
    . (Join-Path $ap 'stages\Invoke-Discover.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-CollectParts.ps1')
    . (Join-Path $ap 'shared\SI-DiscoverStream.ps1')
    . (Join-Path $ap 'shared\Invoke-SIPagedRest.ps1')
    . (Join-Path $script:SIRoot 'auth\Get-SIGraphToken.ps1')      # a command is mocked only once it exists
    . (Join-Path $ap 'discovery\Get-DiscoveryFromEntra.ps1')
    . (Join-Path $ap 'discovery\Get-DiscoveryFromExposureGraph.ps1')
    . (Join-Path $ap 'shared\HuntingQuery.ps1')      # the shared hunting request the Exposure Graph discovery uses (mocked below)
    $script:Prio = @{ 'ExposureGraph' = 5; 'EndpointExposureGraph' = 5; 'EntraDevice' = 4; 'MDEDevice' = 2; 'AzureVM' = 1; 'ARCMachine' = 1; 'AzureResource' = 1 }
    $script:Reserved = @('AssetId', 'Source', 'Hint', 'Name', 'NormalizedKey', 'Sources', 'Raw')
    function script:DeviceRows([int]$i) {
        $name = "dev$i"
        $aad = if ($i % 3) { ('{0:x8}-aaaa-4000-8000-{1:x12}' -f $i, $i) } else { $null }      # every third device is not Entra-joined
        $rows = New-Object System.Collections.Generic.List[object]
        # Defender: the short name, its own id, the Entra device id
        $rows.Add(@{ AssetId = "mde:m$i"; Source = 'MDEDevice'; Hint = 'windows'; Name = "$name.corp.example"; NormalizedKey = $name; MDE_DeviceId = "m$i"; MDE_AadDeviceId = $aad; MDE_OSPlatform = 'Windows11' })
        # the graph: every fifth node goes by its FQDN -- only the Defender id joins it to the machine
        $egName = if ($i % 5 -eq 0) { "$name.corp.example" } else { $name }
        $egAad = $aad; if ($i % 97 -eq 0 -and $aad) { $egAad = ('{0:x8}-bbbb-4000-8000-{1:x12}' -f $i, $i) }    # a few disagree about the Entra id
        $rows.Add(@{ AssetId = "eg:n$i"; Source = 'ExposureGraph'; Hint = 'windows'; Name = $egName; NormalizedKey = $egName; EG_NodeId = "n$i"; EG_MdeDeviceId = "m$i"; EG_AadDeviceId = $egAad })
        # Entra: joined devices only; every seventh is named differently -- only the AadDeviceId joins it
        if ($aad) {
            $enName = if ($i % 7 -eq 0) { "laptop-$i" } else { $name }
            $rows.Add(@{ AssetId = "entra:e$i"; Source = 'EntraDevice'; Hint = 'windows'; Name = $enName; NormalizedKey = $enName; ENTRA_ObjectId = "e$i"; ENTRA_AadDeviceId = $aad; ENTRA_OS = 'Windows' })
        }
        $rows.ToArray()
    }
    function script:MemStore {
        $m = @{}
        [pscustomobject]@{
            Data  = $m
            Write = { param($Stage, $Part, $Chunk, $Records)
                $k = "$Stage|$Part"; if (-not $m.ContainsKey($k)) { $m[$k] = New-Object System.Collections.Generic.List[object] }
                $m[$k].Add(@(ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject @($Records) -Depth 8 -Compress) | ForEach-Object { $_ })) }.GetNewClosure()
            Read  = { param($Stage, $Part) $k = "$Stage|$Part"; if ($m.ContainsKey($k)) { foreach ($c in $m[$k]) { foreach ($r in $c) { $r } } } }.GetNewClosure()
        }
    }
    function script:Norm($rec) {
        $o = ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $rec -Depth 8 -Compress)
        $sort = $null
        $sort = { param($x)
            if ($null -eq $x) { return $null }
            if ($x -is [System.Management.Automation.PSCustomObject]) { $h = [ordered]@{}; foreach ($n in @($x.PSObject.Properties.Name | Sort-Object)) { $h[$n] = & $sort $x.$n }; return $h }
            if ($x -is [array]) { return , @($x | ForEach-Object { & $sort $_ }) }
            return $x }
        ConvertTo-Json -InputObject (& $sort $o) -Depth 10 -Compress
    }
    function script:RowIds($rec) { (@($rec.Raw | ForEach-Object { [string]$_.AssetId }) | Sort-Object) -join ',' }
}

Describe '6,000 devices from three sources, streamed and merged per part' {
    BeforeAll {
        $all = New-Object System.Collections.Generic.List[object]
        for ($i = 0; $i -lt 6000; $i++) { foreach ($r in (DeviceRows $i)) { $all.Add($r) } }
        # 26 devices that share one name, each with its own Defender id (excluded devices): one process keeps them apart
        for ($j = 0; $j -lt 26; $j++) { $all.Add(@{ AssetId = "eg:dummy$j"; Source = 'ExposureGraph'; Hint = 'unknown'; Name = 'DummyDeviceName'; NormalizedKey = 'dummydevicename'; EG_NodeId = "dummy$j"; EG_MdeDeviceId = "dm$j" }) }
        $script:Rows = $all.ToArray()
        $script:One = Merge-SIDiscoveredAssets -RawAssets $script:Rows -SourcePriority $script:Prio -ReservedKeys $script:Reserved 6>$null
        $script:Store = MemStore
        $st = New-SIDiscoverStream -RunContext ([pscustomobject]@{}) -Parts 2 -SourcePriority $script:Prio -ReservedKeys $script:Reserved -Store $script:Store
        for ($s = 0; $s -lt $script:Rows.Count; $s += 999) { $null = Add-SIDiscoverStreamAssets -Stream $st -Assets @($script:Rows[$s..([Math]::Min($s + 999, $script:Rows.Count) - 1)]) }
        $script:Done = Complete-SIDiscoverStream -Stream $st 6>$null
        $script:Got = @{}; $script:Dup = 0
        for ($p = 0; $p -lt 2; $p++) { foreach ($r in @(& $script:Store.Read 'Discover' $p)) { $k = [string]$r.NormalizedKey; if ($script:Got.ContainsKey($k)) { $script:Dup++ }; $script:Got[$k] = $r } }
    }
    It 'merges across names (the test covers it): FQDN graph nodes by the Defender id, renamed Entra devices by AadDeviceId' {
        $cross = @($script:One.Values | Where-Object { @($_.Raw | ForEach-Object { [string]$_.NormalizedKey } | Sort-Object -Unique).Count -gt 1 })
        $cross.Count | Should -BeGreaterThan 1000 -Because 'every fifth graph node and every seventh joined Entra device merge across names'
        @($script:One.Values | Where-Object { $_.NormalizedKey -like 'dummydevicename*' }).Count | Should -Be 26 -Because 'one name, 26 Defender ids: kept apart'
    }
    It 'gives exactly the one-process assets: the same keys, the same rows in every asset, every tenth in full' {
        $script:Dup | Should -Be 0 -Because 'an asset is in exactly one part'
        @($script:Got.Keys | Sort-Object) | Should -Be @($script:One.Keys | Sort-Object)
        $script:Done.Written | Should -Be $script:One.Count
        foreach ($k in $script:One.Keys) { RowIds $script:Got[$k] | Should -Be (RowIds $script:One[$k]) -Because "the rows of $k" }
        $i = 0
        foreach ($k in @($script:One.Keys | Sort-Object)) { if (($i++ % 10) -eq 0) { Norm $script:Got[$k] | Should -Be (Norm $script:One[$k]) -Because "asset $k" } }
        $script:Done.RawRows | Should -Be $script:Rows.Count
        $script:Done.LargestGroup | Should -BeLessOrEqual 30 -Because 'the index joins a device''s rows, not the estate (the 26 shared-name devices are one group)'
    }
}

Describe 'the endpoint sources stream' {
    It 'Entra devices: every page into the stream, nothing back to the caller' {
        Mock Get-SIGraphToken { 't' }
        Mock Invoke-RestMethod {
            if ($Uri -match 'skip=(\d+)') { $n = [int]$matches[1] } else { $n = 0 }
            $next = $null; if ($n -lt 2) { $next = "https://graph.example.invalid/devices?skip=$($n + 1)" }
            [pscustomobject]@{ value = @(1..4 | ForEach-Object { [pscustomobject]@{ id = "o$n$_"; deviceId = "d$n$_"; displayName = "pc$n$_"; operatingSystem = 'Windows' } }); '@odata.nextLink' = $next }
        }
        $global:SI_DiscoverStream = New-SIDiscoverStream -RunContext ([pscustomobject]@{}) -Parts 2 -SourcePriority $script:Prio -ReservedKeys $script:Reserved -Store (MemStore)
        $global:SI_DiscoverStreamCounts = @{}
        try {
            @(Get-DiscoveryFromEntra).Count | Should -Be 0
            $global:SI_DiscoverStream.RawRows | Should -Be 12
            $global:SI_DiscoverStreamCounts['Entra'] | Should -Be 12
        } finally { $global:SI_DiscoverStream = $null; $global:SI_DiscoverStreamCounts = $null }
    }
    It 'the Exposure Graph''s device nodes: counted, then read in buckets by the node id''s hash' {
        Mock Get-SIGraphToken { 't' }
        $script:Queries = New-Object System.Collections.Generic.List[string]
        # every hunting request goes through the shared retrying request (Invoke-SIHuntingGraphRequest: @{ Ok; Rows; Error })
        Mock Invoke-SIHuntingGraphRequest {
            $q = [string]$Query
            $script:Queries.Add($q)
            if ($q -match '\| count$') { return [pscustomobject]@{ Ok = $true; Rows = @([pscustomobject]@{ Count = 41000 }); Error = '' } }
            $b = [int]([regex]::Match($q, 'hash\(NodeId, 3\) == (\d+)').Groups[1].Value)
            [pscustomobject]@{ Ok = $true; Error = ''; Rows = @(1..2 | ForEach-Object { [pscustomobject]@{ NodeId = "n$b$_"; NodeName = "pc$b$_"; NodePropertiesJson = '{"rawData":{"osPlatform":"Windows11"}}' } }) }
        }
        $global:SI_DiscoverStream = New-SIDiscoverStream -RunContext ([pscustomobject]@{}) -Parts 2 -SourcePriority $script:Prio -ReservedKeys $script:Reserved -Store (MemStore)
        $global:SI_DiscoverStreamCounts = @{}
        try {
            @(Get-DiscoveryFromExposureGraph).Count | Should -Be 0
            @($script:Queries | Where-Object { $_ -match 'hash\(NodeId, 3\) == [0-2]$' }).Count | Should -Be 3
            $global:SI_DiscoverStream.RawRows | Should -Be 6
        } finally { $global:SI_DiscoverStream = $null; $global:SI_DiscoverStreamCounts = $null }
    }
    It 'the hunting count reads one number, and nothing it cannot read' {
        Get-SIHuntingCount -Token 't' -Query 'x | count' -Invoke { param($Q, $T) @([pscustomobject]@{ Count = 1500000 }) } | Should -Be 1500000
        Get-SIHuntingCount -Token 't' -Query 'x | count' -Invoke { param($Q, $T) throw 'timeout' } | Should -BeNullOrEmpty
        Get-SIHuntingCount -Token 't' -Query 'x | count' -Invoke { param($Q, $T) @() } | Should -BeNullOrEmpty
    }
}

Describe 'the endpoint sources and Discover are wired' {
    It 'every endpoint source: one builder for both paths and a streaming branch of its kind' -TestCases @(
        @{ f = 'Get-DiscoveryFromEntra.ps1'; b = 'buildDevice'; kind = '-OnPage \$onPage' }
        @{ f = 'Get-DiscoveryFromMDE.ps1'; b = 'buildMachine'; kind = '-OnPage \$onPage' }
        @{ f = 'Get-DiscoveryFromEndpointViaEG.ps1'; b = 'buildEgDevice'; kind = 'hash\(NodeId, \{0\}\) == \{1\}' }
        @{ f = 'Get-DiscoveryFromExposureGraph.ps1'; b = 'buildEgNode'; kind = 'hash\(NodeId, \{0\}\) == \{1\}' }
        @{ f = 'Get-DiscoveryFromARG.ps1'; b = 'buildVm'; kind = 'if \(\$batch\.Count -ge 1000\)' }
    ) {
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot "engine\asset-profiling\discovery\$f"))
        ([regex]::Matches($src, [regex]::Escape("& `$$b ")).Count) | Should -BeGreaterOrEqual 2
        $src | Should -Match ([regex]::Escape('$stream = $global:SI_DiscoverStream'))
        $src | Should -Match $kind
        $src.IndexOf("`$$b = {") | Should -BeLessThan $src.IndexOf('$stream = $global:SI_DiscoverStream')
    }
    It 'Discover counts devices (Entra $count, the graph''s endpoint nodes) before any source runs' {
        $d = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\stages\Invoke-Discover.ps1'))
        $d | Should -Match ([regex]::Escape("if (`$RunContext.Engine -in 'identity', 'azure', 'endpoint') {"))
        $d | Should -Match ([regex]::Escape("`$entraN = Get-SIGraphObjectCount -Collection 'devices' -Token `$gt"))
        $d | Should -Match ([regex]::Escape('$egN = Get-SIHuntingCount -Token $gt -Query'))
    }
}
