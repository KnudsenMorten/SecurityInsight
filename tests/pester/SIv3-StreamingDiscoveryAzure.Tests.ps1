#Requires -Version 5.1
<#
    STREAMING DISCOVERY FOR AZURE (#475) -- an Azure estate can hold millions of resources.
    What these tests keep true:
      * 12,000 resources from Resource Graph + 7,500 Exposure Graph nodes (7,000 of them the same resources): every
        resource in exactly ONE part, both sources' rows of one resource merged into ONE asset in that part, and the
        streamed assets equal the one-process merge (Merge-SIDiscoveredAssets) on the same rows;
      * the Resource Graph source streams page by page (nothing kept) and counts with the same filters (-CountOnly);
      * the Exposure Graph source reads its Azure nodes in buckets of ~20,000 (hash of the node id) -- one query for every
        node is cut off at the hunting row limit on a large estate -- each bucket streamed; a failed bucket is said;
      * Discover takes the larger of the two counts for the part count before any source runs.
    The test store round-trips every chunk through JSON, as staging does. Offline. PS 5.1 and pwsh 7.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $ap = Join-Path $script:SIRoot 'engine\asset-profiling'
    . (Join-Path $ap '_shared\Write-SIStyle.ps1')
    . (Join-Path $ap 'stages\Invoke-Discover.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-CollectParts.ps1')
    . (Join-Path $ap 'shared\SI-DiscoverStream.ps1')
    . (Join-Path $script:SIRoot 'auth\Get-SIGraphToken.ps1')      # a command is mocked only once it exists
    . (Join-Path $ap 'discovery\Get-DiscoveryFromAzureResources.ps1')
    . (Join-Path $ap 'discovery\Get-DiscoveryFromAzureViaEG.ps1')
    $script:Prio = @{ 'ExposureGraph' = 5; 'EndpointExposureGraph' = 5; 'EntraDevice' = 4; 'MDEDevice' = 2; 'AzureVM' = 1; 'ARCMachine' = 1; 'AzureResource' = 1 }
    $script:Reserved = @('AssetId', 'Source', 'Hint', 'Name', 'NormalizedKey', 'Sources', 'Raw')
    function script:ResId([int]$i) { '/subscriptions/{0:x8}-0000-4000-8000-000000000000/resourcegroups/rg{1}/providers/microsoft.storage/storageaccounts/st{2}' -f ($i % 40), ($i % 300), $i }
    function script:ArgAsset([int]$i) {
        $id = ResId $i
        @{ AssetId = "az:$id"; Source = 'AzureResource'; Hint = 'storage-account'; Name = "st$i"; NormalizedKey = $id; AZ_ResourceId = $id; AZ_Type = 'microsoft.storage/storageaccounts'; AZ_RG = "rg$($i % 300)" }
    }
    function script:EgAsset([int]$i) {
        $id = ResId $i
        @{ AssetId = "eg:az:$id"; Source = 'ExposureGraph'; Hint = 'storageaccounts'; Name = "st$i"; NormalizedKey = $id; AZ_ResourceId = $id; AZ_NodeId = "node-$i"; EG_Criticality = $(if ($i % 9 -eq 0) { 'High' } else { $null }) }
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
}

Describe '12,000 Azure resources from two sources, streamed and merged per part' {
    BeforeAll {
        # graph nodes 5,000..12,499: 7,000 of them are Resource Graph resources too, 500 (12,000..12,499) only the graph has
        $script:Rows = @(for ($i = 0; $i -lt 7500; $i++) { EgAsset ($i + 5000) }) + @(for ($i = 0; $i -lt 12000; $i++) { ArgAsset $i })
        $script:Parts = 3
        $script:Store = MemStore
        $st = New-SIDiscoverStream -RunContext ([pscustomobject]@{}) -Parts $script:Parts -SourcePriority $script:Prio -ReservedKeys $script:Reserved -Store $script:Store
        for ($s = 0; $s -lt $script:Rows.Count; $s += 1000) { $null = Add-SIDiscoverStreamAssets -Stream $st -Assets @($script:Rows[$s..([Math]::Min($s + 1000, $script:Rows.Count) - 1)]) }
        $script:Done = Complete-SIDiscoverStream -Stream $st
        $script:Got = @{}; $script:PartOf = @{}
        for ($p = 0; $p -lt $script:Parts; $p++) { foreach ($r in @(& $script:Store.Read 'Discover' $p)) { $k = [string]$r.NormalizedKey; if ($script:Got.ContainsKey($k)) { $script:PartOf["dup:$k"] = $p }; $script:Got[$k] = $r; $script:PartOf[$k] = $p } }
    }
    It 'puts every resource in exactly one part, both sources'' rows of one resource merged into one asset' {
        $script:Done.RawRows | Should -Be 19500
        $script:Got.Count | Should -Be 12500 -Because '12,000 Resource Graph resources + 500 only the graph has'
        @($script:PartOf.Keys | Where-Object { $_ -like 'dup:*' }).Count | Should -Be 0
        $both = $script:Got[(ResId 6000)]
        @($both.Sources | Sort-Object) | Should -Be @('AzureResource', 'ExposureGraph')
        @($both.Raw).Count | Should -Be 2
        $both.Source | Should -Be 'ExposureGraph' -Because 'the graph is the higher-priority source, as in one process'
        @($script:Got[(ResId 100)].Sources) | Should -Be @('AzureResource')
        @($script:Got[(ResId 12100)].Sources) | Should -Be @('ExposureGraph')
    }
    It 'gives every resource the asset one process builds from the same rows (every tenth compared in full, all keys)' {
        $one = Merge-SIDiscoveredAssets -RawAssets $script:Rows -SourcePriority $script:Prio -ReservedKeys $script:Reserved 6>$null
        @($one.Keys | Sort-Object) | Should -Be @($script:Got.Keys | Sort-Object)
        $i = 0
        foreach ($k in @($one.Keys | Sort-Object)) { if (($i++ % 10) -eq 0) { Norm $script:Got[$k] | Should -Be (Norm $one[$k]) -Because "asset $k" } }
    }
}

Describe 'the Resource Graph source streams page by page and counts with the same filters' {
    It 'streams every page into the run''s stream and keeps none of them' {
        $script:Pg = 0
        Mock Search-SIAzGraph {
            $script:Pg++
            $rows = @(1..3 | ForEach-Object { [pscustomobject]@{ ResourceId = ('/subscriptions/s/resourcegroups/rg/providers/microsoft.web/sites/app{0}{1}' -f $script:Pg, $_); Type = 'microsoft.web/sites'; Name = "app$_"; Location = 'westeurope'; RG = 'rg'; Subscription = 's'; PropertiesJson = '{}'; TagsJson = '{}'; IdentityJson = ''; SkuJson = ''; Kind = ''; EnvTag = ''; OwnerTag = '' } })
            $tok = $null; if ($script:Pg -lt 3) { $tok = "tok$($script:Pg)" }
            , (New-SIAzGraphPage -Rows $rows -SkipToken $tok)
        }
        $store = MemStore
        $global:SI_DiscoverStream = New-SIDiscoverStream -RunContext ([pscustomobject]@{}) -Parts 2 -SourcePriority $script:Prio -ReservedKeys $script:Reserved -Store $store
        $global:SI_DiscoverStreamCounts = @{}
        try {
            $out = @(Get-DiscoveryFromAzureResources)
            $out.Count | Should -Be 0 -Because 'a streaming source hands its pages to the stream, not to the caller'
            $global:SI_DiscoverStream.RawRows | Should -Be 9
            $global:SI_DiscoverStreamCounts['AzureResources'] | Should -Be 9
        } finally { $global:SI_DiscoverStream = $null; $global:SI_DiscoverStreamCounts = $null }
    }
    It 'counts with the same filters (-CountOnly), and says nothing it cannot read' {
        $script:Q = $null
        Mock Search-SIAzGraph { $script:Q = $Query; , (New-SIAzGraphPage -Rows @([pscustomobject]@{ Count = 1234567 }) -SkipToken $null) }
        Get-DiscoveryFromAzureResources -CountOnly | Should -Be 1234567
        $script:Q | Should -Match '\| where type !in~ \('
        $script:Q | Should -Match '\| count$'
        Mock Search-SIAzGraph { throw 'throttled' }
        Get-DiscoveryFromAzureResources -CountOnly | Should -BeNullOrEmpty
    }
}

Describe 'the Exposure Graph source reads its Azure nodes in buckets when streaming' {
    It 'counts, splits into buckets of ~20,000 by the node id''s hash, and streams every bucket' {
        Mock Get-EGAzureTypeAllowlist { @('microsoft.compute/virtualmachines') }
        Mock Get-SIGraphToken { 't' }
        $script:Queries = New-Object System.Collections.Generic.List[string]
        Mock Invoke-RestMethod {
            $q = ($Body | ConvertFrom-Json).Query
            $script:Queries.Add($q)
            if ($q -match '\| count$') { return [pscustomobject]@{ results = @([pscustomobject]@{ Count = 45000 }) } }
            $b = [int]([regex]::Match($q, 'hash\(NodeId, 3\) == (\d+)').Groups[1].Value)
            [pscustomobject]@{ results = @(1..4 | ForEach-Object { [pscustomobject]@{ NodeId = "n$b-$_"; NodeName = "vm$b$_"; NodeLabel = 'microsoft.compute/virtualmachines'; NodePropertiesJson = ('{{"rawData":{{"resourceId":"/subscriptions/s/resourcegroups/rg/providers/microsoft.compute/virtualmachines/vm{0}{1}"}}}}' -f $b, $_) } }) }
        }
        $global:SI_DiscoverStream = New-SIDiscoverStream -RunContext ([pscustomobject]@{}) -Parts 3 -SourcePriority $script:Prio -ReservedKeys $script:Reserved -Store (MemStore)
        $global:SI_DiscoverStreamCounts = @{}
        try {
            @(Get-DiscoveryFromAzureViaEG).Count | Should -Be 0
            @($script:Queries | Where-Object { $_ -match 'hash\(NodeId, 3\) == [0-2]$' }).Count | Should -Be 3 -Because '45,000 nodes -> 3 buckets of ~20,000'
            $global:SI_DiscoverStream.RawRows | Should -Be 12
            $global:SI_DiscoverStreamCounts['ExposureGraph'] | Should -Be 12
        } finally { $global:SI_DiscoverStream = $null; $global:SI_DiscoverStreamCounts = $null }
    }
    It 'says a failed bucket and keeps the others' {
        Mock Get-EGAzureTypeAllowlist { @('microsoft.compute/virtualmachines') }
        Mock Get-SIGraphToken { 't' }
        Mock Invoke-RestMethod {
            $q = ($Body | ConvertFrom-Json).Query
            if ($q -match '\| count$') { return [pscustomobject]@{ results = @([pscustomobject]@{ Count = 30000 }) } }
            if ($q -match '== 1$') { throw 'timeout' }
            [pscustomobject]@{ results = @([pscustomobject]@{ NodeId = 'n0'; NodeName = 'vm0'; NodeLabel = 'microsoft.compute/virtualmachines'; NodePropertiesJson = '{"rawData":{"resourceId":"/subscriptions/s/x/vm0"}}' }) }
        }
        $global:SI_DiscoverStream = New-SIDiscoverStream -RunContext ([pscustomobject]@{}) -Parts 2 -SourcePriority $script:Prio -ReservedKeys $script:Reserved -Store (MemStore)
        $global:SI_DiscoverStreamCounts = @{}
        try {
            $w = $null
            $null = Get-DiscoveryFromAzureViaEG -WarningVariable w 3>$null
            "$w" | Should -Match 'bucket 2 of 2 failed'
            "$w" | Should -Match 'UNKNOWN this run, not removed'
            $global:SI_DiscoverStream.RawRows | Should -Be 1
        } finally { $global:SI_DiscoverStream = $null; $global:SI_DiscoverStreamCounts = $null }
    }
}

Describe 'Discover counts Azure before any source runs' {
    It 'takes the larger of the Resource Graph and Exposure Graph counts for the part count' {
        $d = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\stages\Invoke-Discover.ps1'))
        $d | Should -Match ([regex]::Escape("if (`$RunContext.Engine -in 'identity', 'azure', 'endpoint') {"))
        $d | Should -Match ([regex]::Escape('$argN = Get-DiscoveryFromAzureResources -CountOnly'))
        $d | Should -Match ([regex]::Escape('$egN = Get-DiscoveryFromAzureViaEG -CountOnly'))
        $d | Should -Match ([regex]::Escape('$streamObjects = [Math]::Max([long]$argN'))
    }
}
