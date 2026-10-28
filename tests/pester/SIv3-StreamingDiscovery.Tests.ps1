#Requires -Version 5.1
<#
    STREAMING DISCOVERY (engine/asset-profiling/shared/SI-DiscoverStream.ps1) -- #475.
    customer H 2026-10-08: Discover held 23,142 identities (3.85 GB in use, 4.96 GB peak) before splitting them; ~45,000 is the
    ceiling of an 8 GiB job, and a tenant can have 512,000 users. What these tests keep true:
      * the pager hands each page over and keeps nothing (-OnPage);
      * 60,000 users in pages of 999: every object in exactly ONE part (its group's part), the part count decided before
        writing, chunks numbered 0..n-1 per part and stage, none above the shard size;
      * the streamed records are EXACTLY the records one process builds from the same rows (Merge-SIDiscoveredAssets, all
        three passes), key by key -- a row repeated on another page merges as one process merges it;
      * the part count from the directory's $count (users + service principals); no streaming when it cannot be read;
      * which runs stream (only the discover phase of a run in parts; never with an asset limit or full properties);
      * memory does not grow with the number of pages (only the index of ids does);
      * the identity sources and Invoke-SIDiscover are wired: one record builder per source, one merge for both paths.
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
    $script:Prio = @{ 'ExposureGraph' = 5; 'EndpointExposureGraph' = 5; 'EntraDevice' = 4; 'MDEDevice' = 2; 'AzureVM' = 1; 'ARCMachine' = 1; 'AzureResource' = 1 }
    $script:Reserved = @('AssetId', 'Source', 'Hint', 'Name', 'NormalizedKey', 'Sources', 'Raw')
    function script:FakeUser([int]$i) {
        $id = '{0:x8}-0000-4000-8000-{1:x12}' -f $i, $i
        @{ AssetId = "entra-user:$id"; Source = 'EntraUser'; Hint = 'cloud-only'; Name = "user$i@contoso.example"; NormalizedKey = $id
           ENTRA_UserId = $id; ENTRA_UPN = "user$i@contoso.example"; ENTRA_Enabled = $true; ENTRA_DirectoryRolesPermanent = @('Reader'); ENTRA_Groups = @("g$($i % 7)", 'all') }
    }
    function script:FakeSp([int]$i) {
        $id = 'aaaa{0:x4}-0000-4000-8000-{1:x12}' -f $i, $i
        @{ AssetId = "entra-sp:$id"; Source = 'EntraServicePrincipal'; Hint = 'app-registration'; Name = "app $($i % 50)"; NormalizedKey = $id; ENTRA_SPObjectId = $id }
    }
    # the staging seam: chunks kept per stage and part, each round-tripped through JSON like a staging blob
    function script:MemStore([switch]$Discard) {
        $m = @{}
        $d = [bool]$Discard
        [pscustomobject]@{
            Data  = $m
            Write = { param($Stage, $Part, $Chunk, $Records)
                if ($d) { return }
                $k = "$Stage|$Part"; if (-not $m.ContainsKey($k)) { $m[$k] = New-Object System.Collections.Generic.List[object] }
                $back = @(ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject @($Records) -Depth 8 -Compress) | ForEach-Object { $_ })
                $m[$k].Add([pscustomobject]@{ Chunk = $Chunk; Records = $back }) }.GetNewClosure()
            Read  = { param($Stage, $Part) $k = "$Stage|$Part"; if ($m.ContainsKey($k)) { foreach ($c in $m[$k]) { foreach ($r in $c.Records) { $r } } } }.GetNewClosure()
        }
    }
    function script:Norm($rec) {
        # one record as sorted JSON (key order and hashtable-vs-object do not matter, values do)
        $j = ConvertTo-Json -InputObject $rec -Depth 8 -Compress
        $o = ConvertFrom-Json -InputObject $j
        $sort = $null
        $sort = { param($x)
            if ($null -eq $x) { return $null }
            if ($x -is [System.Management.Automation.PSCustomObject]) { $h = [ordered]@{}; foreach ($n in @($x.PSObject.Properties.Name | Sort-Object)) { $h[$n] = & $sort $x.$n }; return $h }
            if ($x -is [array]) { return , @($x | ForEach-Object { & $sort $_ }) }
            return $x }
        ConvertTo-Json -InputObject (& $sort $o) -Depth 10 -Compress
    }
    function script:RunStream($rows, [int]$Parts, $Store, [int]$Page = 999, [int]$ShardSize = 2000, [int]$FlushTotal = 10000) {
        $st = New-SIDiscoverStream -RunContext ([pscustomobject]@{}) -Parts $Parts -SourcePriority $script:Prio -ReservedKeys $script:Reserved -Store $Store -ShardSize $ShardSize -FlushTotal $FlushTotal
        for ($s = 0; $s -lt $rows.Count; $s += $Page) { $null = Add-SIDiscoverStreamAssets -Stream $st -Assets @($rows[$s..([Math]::Min($s + $Page, $rows.Count) - 1)]) }
        Complete-SIDiscoverStream -Stream $st
    }
}

Describe 'the pager hands every page over and keeps nothing (-OnPage)' {
    It 'calls the block once per page with that page''s rows; Rows is empty and Count says how many came' {
        $script:Pages = New-Object System.Collections.Generic.List[int]
        Mock Invoke-RestMethod {
            if ($Uri -match 'skip=(\d+)') { $n = [int]$matches[1] } else { $n = 0 }
            $next = $null; if ($n -lt 2) { $next = "https://graph.example.invalid/users?skip=$($n + 1)" }
            [pscustomobject]@{ value = @(1..5 | ForEach-Object { [pscustomobject]@{ id = "$n-$_" } }); '@odata.nextLink' = $next }
        }
        $r = Invoke-SIPagedRest -Url 'https://graph.example.invalid/users' -Token 't' -SourceLabel 'test' -OnPage { param($PageRows) $script:Pages.Add(@($PageRows).Count) }
        @($script:Pages) | Should -Be @(5, 5, 5)
        $r.Count | Should -Be 15
        @($r.Rows).Count | Should -Be 0
        $r.Complete | Should -BeTrue
        $r2 = Invoke-SIPagedRest -Url 'https://graph.example.invalid/users' -Token 't' -SourceLabel 'test'
        @($r2.Rows).Count | Should -Be 15 -Because 'without -OnPage the rows are kept, as before'
    }
}

Describe 'streaming 60,000 users into parts' {
    BeforeAll {
        $script:Parts = Get-SICollectPartCount -Objects 60000
        $script:Store60 = MemStore
        $rows = @(for ($i = 0; $i -lt 60000; $i++) { FakeUser $i })
        $script:Done = RunStream $rows $script:Parts $script:Store60
    }
    It 'decides the part count before writing (60,000 -> 6) and writes every object into exactly one part' {
        $script:Parts | Should -Be 6
        ($script:Done.Parts, $script:Done.RawRows, $script:Done.Written) | Should -Be @(6, 60000, 60000)
        $seen = @{}
        for ($p = 0; $p -lt 6; $p++) {
            foreach ($r in @(& $script:Store60.Read 'Discover' $p)) {
                $seen.ContainsKey([string]$r.NormalizedKey) | Should -BeFalse
                $seen[[string]$r.NormalizedKey] = $p
                Get-SICollectPartIndex -Key ('n:' + [string]$r.NormalizedKey) -Parts 6 | Should -Be $p -Because 'an identity is its own group'
            }
        }
        $seen.Count | Should -Be 60000
        $script:Done.EmptyParts | Should -Be 0
        $script:Done.LargestGroup | Should -Be 1
    }
    It 'numbers the chunks 0..n-1 per part and stage, none above the shard size' {
        $bad = New-Object System.Collections.Generic.List[string]
        foreach ($k in @($script:Store60.Data.Keys)) {
            $cs = $script:Store60.Data[$k]
            for ($i = 0; $i -lt $cs.Count; $i++) {
                if ([int]$cs[$i].Chunk -ne $i) { $bad.Add("$k chunk $i is numbered $($cs[$i].Chunk)") }
                if (@($cs[$i].Records).Count -gt 2000) { $bad.Add("$k chunk $i holds $(@($cs[$i].Records).Count)") }
            }
        }
        $bad.Count | Should -Be 0 -Because ($bad -join '; ')
    }
}

Describe 'the streamed records are the records one process builds' {
    It 'gives every key the same merged record as Merge-SIDiscoveredAssets over every row -- a repeated row included' {
        $rows = @(foreach ($i in 0..2999) { FakeUser $i }) + @(foreach ($i in 0..199) { FakeSp $i }) + @((FakeUser 17), (FakeUser 2500))   # two rows repeated
        $one = Merge-SIDiscoveredAssets -RawAssets $rows -SourcePriority $script:Prio -ReservedKeys $script:Reserved 6>$null
        $st = MemStore
        $d = RunStream $rows 3 $st -ShardSize 500 -FlushTotal 1200
        $got = @{}
        for ($p = 0; $p -lt 3; $p++) { foreach ($r in @(& $st.Read 'Discover' $p)) { $got[[string]$r.NormalizedKey] = $r } }
        $got.Count | Should -Be $one.Count
        $d.Written | Should -Be $one.Count
        foreach ($k in $one.Keys) { Norm $got[$k] | Should -Be (Norm $one[$k]) -Because "record $k" }
        @($got[(FakeUser 17).NormalizedKey].Raw).Count | Should -Be 2 -Because 'one process folds the repeated row into the record'
    }
}

Describe 'the part count and which runs stream' {
    It 'counts users + service principals with $count (ConsistencyLevel: eventual); nothing when one cannot be read' {
        $script:Hdr = $null
        $ok = { param($Uri, $Headers) $script:Hdr = $Headers; if ($Uri -match '/users/\$count$') { '512000' } elseif ($Uri -match '/servicePrincipals/\$count$') { '3400' } else { throw 'unexpected' } }
        $c = Get-SIIdentityDiscoverCount -Token 't' -Invoke $ok
        ($c.Users, $c.ServicePrincipals, $c.Objects) | Should -Be @(512000, 3400, 515400)
        $script:Hdr.ConsistencyLevel | Should -Be 'eventual'
        Get-SICollectPartCount -Objects $c.Objects | Should -Be 52
        Get-SIIdentityDiscoverCount -Token 't' -Invoke { param($Uri, $Headers) if ($Uri -match 'servicePrincipals') { throw '403' }; '10' } | Should -BeNullOrEmpty
        Get-SIIdentityDiscoverCount -Token 't' -Invoke { param($Uri, $Headers) '<html>' } | Should -BeNullOrEmpty
    }
    It 'streams only the discover phase of a run in parts: <why>' -TestCases @(
        @{ why = 'discover phase -> streams'; ctx = @{ Phase = 'discover'; AssetLimit = 0 }; set = $null; full = $false; want = $true }
        @{ why = 'one-process run -> whole set'; ctx = @{ Phase = 'all'; AssetLimit = 0 }; set = $null; full = $false; want = $false }
        @{ why = 'a part -> whole set'; ctx = @{ Phase = 'parts'; AssetLimit = 0 }; set = $null; full = $false; want = $false }
        @{ why = 'an asset limit -> whole set'; ctx = @{ Phase = 'discover'; AssetLimit = 50 }; set = $null; full = $false; want = $false }
        @{ why = 'full asset properties -> whole set'; ctx = @{ Phase = 'discover'; AssetLimit = 0 }; set = $null; full = $true; want = $false }
        @{ why = 'SI_DiscoverStreaming = off -> whole set'; ctx = @{ Phase = 'discover'; AssetLimit = 0 }; set = 'off'; full = $false; want = $false }
    ) {
        (Test-SIDiscoverStreamWanted -RunContext ([pscustomobject]$ctx) -Setting $set -FullProperties $full).Stream | Should -Be $want
    }
}

Describe 'memory does not grow with the number of pages' {
    It 'holds about the same after 60 pages as after 10 (the buffers are bounded; only the index of ids grows)' {
        $st = New-SIDiscoverStream -RunContext ([pscustomobject]@{}) -Parts 6 -SourcePriority $script:Prio -ReservedKeys $script:Reserved -Store (MemStore -Discard)
        $at = @{}
        for ($pg = 1; $pg -le 60; $pg++) {
            $s = ($pg - 1) * 999
            $null = Add-SIDiscoverStreamAssets -Stream $st -Assets @(for ($i = $s; $i -lt $s + 999; $i++) { FakeUser $i })
            if ($pg -in 10, 60) { $at[$pg] = [System.GC]::GetTotalMemory($true) }
        }
        $growMb = ($at[60] - $at[10]) / 1MB
        $growMb | Should -BeLessThan 64 -Because ('a whole-set Discover keeps every user; streaming keeps only their ids (measured +{0:N1} MB for 49,950 more users)' -f $growMb)
    }
}

Describe 'the identity sources and Discover are wired' {
    BeforeAll {
        $d = Join-Path $script:SIRoot 'engine\asset-profiling'
        $script:Users = [IO.File]::ReadAllText((Join-Path $d 'discovery\Get-DiscoveryFromEntraUsers.ps1'))
        $script:Sps   = [IO.File]::ReadAllText((Join-Path $d 'discovery\Get-DiscoveryFromEntraServicePrincipals.ps1'))
        $script:Disc  = [IO.File]::ReadAllText((Join-Path $d 'stages\Invoke-Discover.ps1'))
        $script:Strm  = [IO.File]::ReadAllText((Join-Path $d 'shared\SI-DiscoverStream.ps1'))
    }
    It 'one record builder per source, used by the whole-set loop AND the streaming pages' {
        foreach ($pair in @(@($script:Users, 'buildUser'), @($script:Sps, 'buildSp'))) {
            $src = $pair[0]; $b = $pair[1]
            ([regex]::Matches($src, [regex]::Escape("& `$$b ")).Count) | Should -BeGreaterOrEqual 2
            $src | Should -Match ([regex]::Escape('$stream = $global:SI_DiscoverStream'))
            $src | Should -Match 'Add-SIDiscoverStreamAssets -Stream \$stream -Assets \$batch\.ToArray\(\)'
            $src | Should -Match '-OnPage \$on'
        }
        # the first-party skip returns from the builder (a 'continue' in a block would reach the caller's loop)
        $script:Sps | Should -Not -Match '(?m)^\s+continue\s*$'
    }
    It 'one merge for both paths, and Discover decides the parts before any source runs' {
        $script:Disc | Should -Match ([regex]::Escape('$byKey = Merge-SIDiscoveredAssets -RawAssets $rawAssets.ToArray() -SourcePriority $sourcePriority -ReservedKeys $reservedKeys'))
        $script:Strm | Should -Match ([regex]::Escape('$byKey = Merge-SIDiscoveredAssets -RawAssets $rows -SourcePriority $Stream.SourcePriority -ReservedKeys $Stream.ReservedKeys'))
        $i = $script:Disc.IndexOf('$global:SI_DiscoverStream = New-SIDiscoverStream')
        $j = $script:Disc.IndexOf('foreach ($pair in $sources)')
        $k = $script:Disc.IndexOf('$streamDone = Complete-SIDiscoverStream')
        ($i -gt 0 -and $j -gt $i -and $k -gt $j) | Should -BeTrue
        $script:Disc | Should -Match ([regex]::Escape('if ($global:SI_CollectRunInfo) { $global:SI_CollectRunInfo.Parts = $streamDone.Parts }'))
    }
}
