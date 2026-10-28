#Requires -Version 5.1
<#
    ONE TRANSIENT ERROR NO LONGER LOSES A PART'S DATA.

    Found in live runs: the Defender device details and finding summaries were one bare hunting query for EVERY device
    ("Defender device details ... not read for ~1,250 device(s)"), a DeviceInfo chunk lost its names after three 502s, the
    Azure Exposure Graph access edges were one bare call (a failure = 0 edges), and one bad MSRC document address aborted
    the whole KB release-date read so the cache was never saved.
    Now: pages of devices, each through the product's hunting request (retried), a failed page / chunk asked once more at
    the END, a refused query (400) never asked again, a page that still fails said and its devices left UNKNOWN (never
    "no data"); one MSRC document fails alone and the rest is saved.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\asset-profiling\shared\HuntingQuery.ps1')
    . (Join-Path $script:SIRoot 'engine\asset-profiling\shared\SI-HuntingPages.ps1')
    . (Join-Path $script:SIRoot 'engine\asset-profiling\discovery\Get-SIDefenderFindingSummary.ps1')
    . (Join-Path $script:SIRoot 'engine\asset-profiling\discovery\Get-DiscoveryFromAzureExposureGraph.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-KbReleaseDates.ps1')
    function New-HexId([int]$i) { ('{0:x40}' -f $i) }
}

Describe 'Read-SIHuntingPages -- pages, a last try at the end, a refused query never again' {
    It 'reads every page and keeps the ids of each page read' {
        $ids = 1..5 | ForEach-Object { New-HexId $_ }
        $r = Read-SIHuntingPages -Ids $ids -PageSize 2 -Kql { param($p) ($p -join ',') } -Query { param($q) $q.Split(',') | ForEach-Object { [pscustomobject]@{ DeviceId = $_ } } }
        $r.Pages | Should -Be 3
        @($r.Rows).Count | Should -Be 5
        $r.ReadIds.Count | Should -Be 5
        @($r.Failed).Count | Should -Be 0
    }
    It 'a page that failed once (a 502) is asked again at the END and its rows are kept' {
        $script:calls = [System.Collections.Generic.List[string]]::new(); $script:seen = @{}
        $ids = 1..4 | ForEach-Object { New-HexId $_ }
        $r = Read-SIHuntingPages -Ids $ids -PageSize 2 -Kql { param($p) ($p -join ',') } -Query {
            param($q) $script:calls.Add($q)
            if (-not $script:seen.ContainsKey($q) -and $q -like ('*' + (New-HexId 1) + '*')) { $script:seen[$q] = 1; throw 'Response status code does not indicate success: 502 (Bad Gateway).' }
            $q.Split(',') | ForEach-Object { [pscustomobject]@{ DeviceId = $_ } } }
        @($r.Failed).Count | Should -Be 0
        $r.ReadIds.Count | Should -Be 4
        # page 1 failed, page 2 read, THEN page 1 again (the end)
        $script:calls.Count | Should -Be 3
        $script:calls[2] | Should -Be $script:calls[0]
    }
    It 'a page that still fails is in Failed with its device count, and its ids are NOT read' {
        $ids = 1..3 | ForEach-Object { New-HexId $_ }
        $r = Read-SIHuntingPages -Ids $ids -PageSize 2 -Kql { param($p) ($p -join ',') } -Query { param($q) if ($q -like ('*' + (New-HexId 1) + '*')) { throw '503 Service Unavailable' }; $q.Split(',') | ForEach-Object { [pscustomobject]@{ DeviceId = $_ } } }
        @($r.Failed).Count | Should -Be 1
        $r.Failed[0].Count | Should -Be 2
        $r.Failed[0].Defect | Should -BeFalse
        $r.ReadIds.Contains((New-HexId 1)) | Should -BeFalse
        $r.ReadIds.Contains((New-HexId 3)) | Should -BeTrue
    }
    It 'a refused query (400) is asked ONCE, never again' {
        $script:n = 0
        $r = Read-SIHuntingPages -Ids @((New-HexId 1)) -Kql { param($p) 'q' } -Query { param($q) $script:n++; throw 'BadRequest: Semantic error' }
        $script:n | Should -Be 1
        $r.Failed[0].Defect | Should -BeTrue
    }
    It '-OnRows hands each page over (the caller''s own variables stay visible)' {
        $res = @{ Devices = 0 }
        $null = Read-SIHuntingPages -Ids (1..3 | ForEach-Object { New-HexId $_ }) -PageSize 1 -Kql { param($p) [string]$p[0] } -Query { param($q) [pscustomobject]@{ DeviceId = $q } } -OnRows { param($rows) $res.Devices += @($rows).Count }
        $res.Devices | Should -Be 3
    }
}

Describe 'Invoke-SIHuntingQueryResult -- a failure is a result, never an empty answer' {
    It 'a failed request is Ok = false with the error; a 400 is a Defect' {
        $r = Invoke-SIHuntingQueryResult -Query 'q' -Ask { param($q) [pscustomobject]@{ Ok = $false; Rows = @(); Error = 'HTTP 400 BadRequest' } }
        $r.Ok | Should -BeFalse; $r.Defect | Should -BeTrue
        $r = Invoke-SIHuntingQueryResult -Query 'q' -Ask { param($q) [pscustomobject]@{ Ok = $false; Rows = @(); Error = 'HTTP 502 Bad Gateway' } }
        $r.Ok | Should -BeFalse; $r.Defect | Should -BeFalse
    }
    It 'the hunting request it uses retries a 502 and never a 400' {
        $script:n = 0
        $one = Invoke-SIHuntingGraphRequest -Query 'q' -Token { param($f) 't' } -Sleep { param($s) } -Send { param($t, $q) $script:n++; if ($script:n -lt 3) { throw 'Response status code does not indicate success: 502 (Bad Gateway).' }; [pscustomobject]@{ results = @([pscustomobject]@{ a = 1 }) } }
        $one.Ok | Should -BeTrue; $script:n | Should -Be 3
        $script:n = 0
        $one = Invoke-SIHuntingGraphRequest -Query 'q' -Token { param($f) 't' } -Sleep { param($s) } -Send { param($t, $q) $script:n++; throw 'The remote server returned an error: (400) Bad Request.' }
        $one.Ok | Should -BeFalse; $script:n | Should -Be 1
    }
}

Describe 'Defender device details and summaries -- in pages, a failed page alone, unknown never "no data"' {
    It 'the device context is read page by page (never one query for every device)' {
        $script:q = 0
        $ids = 1..5 | ForEach-Object { New-HexId $_ }
        $null = Get-SIDefenderDeviceContext -DeviceIds $ids -PageDevices 2 -Query { param($k) $script:q++; @() }
        $script:q | Should -Be 3
    }
    It 'a failed page is said with its count, and its devices get NO "no data" mark (only devices of read pages do)' {
        $ids = 1..3 | ForEach-Object { New-HexId $_ }
        $w = $null
        $out = Get-SIDefenderDeviceContext -DeviceIds $ids -PageDevices 2 -WarningVariable w -WarningAction SilentlyContinue -Query {
            param($k) if ($k -match (New-HexId 1)) { throw '503 Service Unavailable' }
            [pscustomobject]@{ DeviceId = (New-HexId 3); HasHardeningData = $false; HasHardwareData = $false } }
        (@($w) -join ' ') | Should -Match 'not read for 2 device\(s\)'
        $out.ContainsKey((New-HexId 1)) | Should -BeFalse
        $out.ContainsKey((New-HexId 2)) | Should -BeFalse
    }
    It 'the finding summary: a device of a failed page stays unknown; the read pages keep theirs' {
        $ids = 1..3 | ForEach-Object { New-HexId $_ }
        $out = Get-SIDefenderFindingSummary -DeviceIds $ids -PageDevices 2 -WarningAction SilentlyContinue -Query {
            param($k) if ($k -match (New-HexId 1)) { throw '502 Bad Gateway' }
            [pscustomobject]@{ DeviceId = 'zz'; HasVulnerabilityData = $false; HasConfigurationData = $false } }
        $out.ContainsKey((New-HexId 1)) | Should -BeFalse
        $out.ContainsKey((New-HexId 3)) | Should -BeTrue
    }
    It 'no bare runHuntingQuery call is left in the device context, the summary, the collect chunks or the access edges' {
        foreach ($rel in 'engine\asset-profiling\discovery\Get-SIDefenderDeviceContext.ps1', 'engine\asset-profiling\discovery\Get-SIDefenderFindingSummary.ps1', 'engine\asset-profiling\stages\Invoke-Collect.ps1') {
            [IO.File]::ReadAllText((Join-Path $script:SIRoot $rel)) | Should -Not -Match 'Invoke-RestMethod' -Because $rel
        }
        $eg = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\discovery\Get-DiscoveryFromAzureExposureGraph.ps1'))
        $eg | Should -Match 'Invoke-SIHuntingQueryResult'
    }
}

Describe 'Get-SIDeviceInfoByName -- a failed chunk gets a last try at the end of the read' {
    BeforeAll { . (Join-Path $script:SIRoot 'engine\asset-profiling\stages\Invoke-Collect.ps1') }
    It 'a chunk that failed (502) is asked again after the others and its names are kept' {
        $script:seen = @{}; $script:order = [System.Collections.Generic.List[string]]::new()
        $idx = Get-SIDeviceInfoByName -DeviceNames @('alpha', 'bravo') -ChunkSize 1 -WarningAction SilentlyContinue -RunQuery {
            param($q) $n = if ($q -match "'alpha'") { 'alpha' } else { 'bravo' }; $script:order.Add($n)
            if ($n -eq 'alpha' -and -not $script:seen.ContainsKey($n)) { $script:seen[$n] = 1; throw '502 Bad Gateway' }
            [pscustomobject]@{ DeviceId = ('{0:x40}' -f $n.Length); DeviceName = $n } }
        ($script:order -join ',') | Should -Be 'alpha,bravo,alpha'
        @($idx.Keys | Where-Object { $_ -match 'alpha' }).Count | Should -BeGreaterThan 0
    }
    It 'a refused chunk (400) is not asked again' {
        $script:n = 0
        $null = Get-SIDeviceInfoByName -DeviceNames @('alpha') -WarningAction SilentlyContinue -RunQuery { param($q) $script:n++; throw 'BadRequest: Failed to resolve column' }
        $script:n | Should -Be 1
    }
}

Describe 'Azure Exposure Graph access edges -- retried, a failure said as unknown' {
    It 'a failed read is said as unknown (not "none") and returns no map' {
        $w = $null
        $m = Get-AzureExposureGraphAccessEdges -WarningVariable w -WarningAction SilentlyContinue -Ask { param($q) [pscustomobject]@{ Ok = $false; Rows = @(); Error = 'HTTP 502 Bad Gateway' } }
        $m.Count | Should -Be 0
        (@($w) -join ' ') | Should -Match 'not known this run'
    }
}

Describe 'MSRC KB release dates -- one bad document fails alone, the rest is saved' {
    It 'builds a whole address from a relative / blank / host-less CvrfUrl' {
        Get-SIMsrcDocumentUrl -Id '2026-Oct' -CvrfUrl 'https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Oct' | Should -Be 'https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Oct'
        Get-SIMsrcDocumentUrl -Id '2026-Oct' -CvrfUrl '/cvrf/v3.0/cvrf/2026-Oct' | Should -Be 'https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Oct'
        Get-SIMsrcDocumentUrl -Id '2026-Oct' -CvrfUrl '  ' | Should -Be 'https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Oct'
        Get-SIMsrcDocumentUrl -Id '2026-Oct' -CvrfUrl 'https:///cvrf/2026-Oct' | Should -Be 'https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Oct'
        Get-SIMsrcDocumentUrl -Id '2026-Oct' -CvrfUrl $null | Should -Be 'https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Oct'
    }
    It 'a document that throws (Invalid URI) is skipped, the good ones are merged AND saved, the bad one is asked next run' {
        $now = [datetime]'2026-10-23T08:00:00Z'
        $list = [pscustomobject]@{ value = @(
            [pscustomobject]@{ ID = '2026-Sep'; InitialReleaseDate = '2026-09-08T07:00:00Z'; CurrentReleaseDate = '2026-09-08T07:00:00Z'; CvrfUrl = 'https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Sep' }
            [pscustomobject]@{ ID = '2026-Oct'; InitialReleaseDate = '2026-10-13T07:00:00Z'; CurrentReleaseDate = '2026-10-13T07:00:00Z'; CvrfUrl = 'https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Oct' }) }
        $doc = [pscustomobject]@{ Vulnerability = @([pscustomobject]@{ Remediations = @([pscustomobject]@{ Type = 2; Description = [pscustomobject]@{ Value = '5000001' } }) }) }
        $script:saved = $null
        $store = [pscustomobject]@{ Kind = 'mem' }
        $store | Add-Member -MemberType ScriptMethod -Name Load -Value { @{ FetchedAt = $null; Documents = @{}; Kbs = @{} } }
        $store | Add-Member -MemberType ScriptMethod -Name Save -Value { param($c) $script:saved = $c }
        $fetch = { param($u) if ($u -like '*/updates') { return $list }; if ($u -like '*2026-Oct') { throw 'Invalid URI: The hostname could not be parsed.' }; $doc }
        $n = Initialize-SIKbReleaseDates -Store $store -Fetch $fetch -Now $now
        $n | Should -Be 1
        $script:saved | Should -Not -BeNullOrEmpty
        $script:saved.Kbs.ContainsKey('KB5000001') | Should -BeTrue
        $script:saved.Documents.ContainsKey('2026-Sep') | Should -BeTrue
        $script:saved.Documents.ContainsKey('2026-Oct') | Should -BeFalse
        # the cache is left a day old so the next run asks for the document that was not read
        ($now - [datetime]$script:saved.FetchedAt).TotalHours | Should -BeGreaterOrEqual 24
    }
}
