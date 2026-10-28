#Requires -Version 7.0
<#
    THE DEFENDER CVE DETAILS ARE READ FOR THE REPORT'S OWN CVEs ONLY (#666, measured live 2026-10-15 on internal: the
    whole vulnerability catalogue -- 351,176 CVEs, paged by position -- took 27-71 minutes of a 35-78 minute
    Device_Missing_CVEs_Detailed report to keep 6,661).

    What these tests keep true:
      * the rows are enriched EXACTLY as the whole-list read enriches them (the same values for the same CVEs, the same
        unknowns), over several slices of one report;
      * an id is never asked for twice in a run; a later slice asks only for the ids not asked yet;
      * the requests are cut by the length of their address (never above the limit, every id once, in order), and a
        request the service says is too long is split and sent again;
      * a service that refuses the filter on the run's first request, or ignores it, gets the whole-list read as before
        -- said once in plain words;
      * a request that fails after the pager's retries makes the read not complete: said once, the rows go on unchanged;
      * a CVE the service does not return stays unknown (never false / 0);
      * through a real HTTP exchange (a local server): the filter reaches the server as written and next links are followed.
    Offline, pwsh 7.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CodePath = Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-DefenderCveContext.ps1'
    . $script:CodePath

    # a catalogue of the shapes the API hands: exposed or not, booleans as bool or text, types, EPSS as number or text
    function New-FakeCatalogue {
        param([int]$Count = 400)
        $rnd = [System.Random]::new(17)
        $list = [System.Collections.Generic.List[object]]::new()
        for ($i = 1; $i -le $Count; $i++) {
            $o = [ordered]@{ id = ('CVE-20{0:00}-{1}' -f (10 + ($i % 16)), (1000 + $i)) }
            $o.exposedMachines = @(0, 0, 1, 3, 17, 250)[$rnd.Next(6)]
            switch ($rnd.Next(4)) { 0 { $o.exploitVerified = $true } 1 { $o.exploitVerified = 'False' } 2 { $o.exploitVerified = $false } default { } }
            switch ($rnd.Next(3)) { 0 { $o.exploitInKit = $true } 1 { $o.exploitInKit = 'true' } default { } }
            if ($rnd.Next(2) -eq 0) { $o.exploitTypes = @(@('Remote', 'PrivilegeEscalation', 'Dos', 'LocalPrivilegeEscalation')[0..$rnd.Next(4)]) }
            if ($rnd.Next(3) -ne 0) { $o.epss = $rnd.NextDouble() } elseif ($rnd.Next(2) -eq 0) { $o.epss = '0.12345678' }
            if ($rnd.Next(2) -eq 0) { $o.cvssVector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N' }
            if ($rnd.Next(2) -eq 0) { $o.publishedOn = [datetime]::new(2024, 1 + ($i % 12), 1 + ($i % 27), 0, 0, 0, [System.DateTimeKind]::Utc) }
            $list.Add([pscustomobject]$o)
        }
        $list.ToArray()
    }
    function Get-FilterIds { param([string]$Url)
        # both forms: id in ('a','b') and id eq 'a' or id eq 'b'
        $u = [uri]::UnescapeDataString($Url)
        $m = [regex]::Match($u, "id in \(([^)]*)\)")
        if ($m.Success) { return @($m.Groups[1].Value -split ',' | ForEach-Object { $_.Trim().Trim("'") } | Where-Object { $_ }) }
        @([regex]::Matches($u, "id eq '([^']+)'") | ForEach-Object { $_.Groups[1].Value }) }
    # rows of a report: several per CVE, some naming CVEs the catalogue does not have, some not CVE rows at all
    function New-ReportRows { param([string[]]$Ids)
        $rows = [System.Collections.Generic.List[object]]::new()
        $n = 0
        foreach ($id in $Ids) { foreach ($dev in 'srv01', 'srv02') { $n++; $rows.Add([pscustomobject]@{ ConfigurationId = $(if ($n % 3 -eq 0) { $id.ToLowerInvariant() } else { $id }); AssetName = $dev; si_epss = $(if ($n % 5 -eq 0) { 0.5 } else { $null }); si_cvss_vector = '' }) } }
        $rows.Add([pscustomobject]@{ ConfigurationId = 'scid-2010'; AssetName = 'srv01' })
        $rows.ToArray()
    }
    $script:Cat = New-FakeCatalogue -Count 400
    $script:CatById = @{}; foreach ($c in $script:Cat) { $script:CatById[$c.id.ToUpperInvariant()] = $c }
    $script:Asked = [System.Collections.Generic.List[string]]::new()
    $script:Urls = [System.Collections.Generic.List[string]]::new()
    # the API: the whole list for $top reads, the matching CVEs for a filter
    $script:Api = { param($url)
        $script:Urls.Add([string]$url)
        if ($url -match '\$filter=') {
            $ids = Get-FilterIds $url
            foreach ($i in $ids) { $script:Asked.Add($i.ToUpperInvariant()) }
            $rows = @($ids | ForEach-Object { $script:CatById[$_.ToUpperInvariant()] } | Where-Object { $_ })
            return @{ Complete = $true; Error = $null; Rows = $rows }
        }
        @{ Complete = $true; Error = $null; Rows = $script:Cat }
    }
    # report CVE ids: 220 of the catalogue's (exposed or not) and 15 the catalogue does not have
    $script:ReportIds = @(@($script:Cat[0..219] | ForEach-Object { $_.id }) + @(1..15 | ForEach-Object { "CVE-2099-$_" }))
    # the API read is opt-in (SI_RA_DefenderCveApi); these tests are about the read itself, so it is on
    function Reset-Run { Remove-Variable -Scope Global -Name RA_DefenderCveIndex, RA_DefenderCveSaid, SI_RA_DefenderCveContext, SI_RA_DefenderCveRead, SI_RA_DefenderCveFilterUrlMax -ErrorAction SilentlyContinue
        $global:SI_RA_DefenderCveApi = 'on'
        $script:Asked.Clear(); $script:Urls.Clear(); $global:CveSaid = [System.Collections.Generic.List[string]]::new() }
    function global:Write-Info { param($m) $global:CveSaid.Add([string]$m) }
    function Get-RowsText { param($Rows) (@($Rows) | ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 4 }) -join "`n" }
}
AfterAll {
    Remove-Variable -Scope Global -Name RA_DefenderCveIndex, RA_DefenderCveSaid, SI_RA_DefenderCveContext, SI_RA_DefenderCveRead, SI_RA_DefenderCveFilterUrlMax, SI_RA_DefenderCveApi, CveSaid, CveErr -ErrorAction SilentlyContinue
    Remove-Item -Path Function:\global:Write-Info -ErrorAction SilentlyContinue
}

Describe 'by default the CVE report''s own query carries the context and no Defender API call is made' {
    BeforeAll {
        $yaml = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'))
        $parts = [regex]::Split($yaml, '(?m)^\s*- ReportName:\s*')
        $script:Detailed = @($parts | Where-Object { $_ -match '^Device_Missing_CVEs_Detailed\s' })[0]
    }
    BeforeEach { Reset-Run; Remove-Variable -Scope Global -Name SI_RA_DefenderCveApi -ErrorAction SilentlyContinue }
    It 'the setting is off by default; on / true / 1 turn it on' {
        Test-RADefenderCveApiOn -Setting $null | Should -BeFalse
        Test-RADefenderCveApiOn -Setting '' | Should -BeFalse
        Test-RADefenderCveApiOn -Setting 'off' | Should -BeFalse
        foreach ($v in 'on', 'ON', 'true', '1') { Test-RADefenderCveApiOn -Setting $v | Should -BeTrue }
    }
    It 'a default run makes no Defender API call; the rows keep what the query gave them' {
        Mock Invoke-RestMethod { throw 'no Defender API call on the default path' }
        function Get-SIGraphToken { param($Resource) throw 'no Defender token on the default path' }
        $rows = @(
            [pscustomobject]@{ ConfigurationId = 'CVE-2010-1016'; AssetName = 'srv01'; si_exposed_devices = 12; si_exploit_verified = $true; si_in_exploit_kit = $null },
            [pscustomobject]@{ ConfigurationId = 'CVE-2099-1'; AssetName = 'srv02'; si_exposed_devices = $null })
        $before = Get-RowsText $rows
        $out = Add-RADefenderCveContext -Rows $rows -Fetch { throw 'no Defender API call on the default path' } -Log { param($m) throw "said: $m" }
        Get-RowsText $out | Should -BeExactly $before
        $global:RA_DefenderCveIndex | Should -BeNullOrEmpty
        $global:CveSaid.Count | Should -Be 0
        Should -Invoke Invoke-RestMethod -Times 0 -Exactly
    }
    It 'neither grain calls the API by default: Summary rows and Detailed rows alike, and no other caller exists' {
        Mock Invoke-RestMethod { throw 'no Defender API call on the default path' }
        $summary = @([pscustomobject]@{ ConfigurationId = 'CVE'; IssueList = @('CVE-2010-1016', 'CVE-2010-1017'); ImpactedAssetCount = 4 },
                     [pscustomobject]@{ ConfigurationId = 'CVE-2010-1016'; ImpactedAssetCount = 2 })
        $detailed = New-ReportRows $script:ReportIds[0..49]
        foreach ($rows in @(, $summary) + @(, $detailed)) {
            $before = Get-RowsText $rows
            $out = Add-RADefenderCveContext -Rows $rows -Fetch { throw 'no Defender API call on the default path' } -Log { param($m) throw "said: $m" }
            Get-RowsText $out | Should -BeExactly $before
        }
        $global:RA_DefenderCveIndex | Should -BeNullOrEmpty
        Should -Invoke Invoke-RestMethod -Times 0 -Exactly
        # the only way to the API: Get-RADefenderCveIndex is called only by Add-RADefenderCveContext, and that only from
        # Risk Analysis' one per-slice step (which runs for every report, Summary and Detailed)
        $eng = Join-Path $script:SIRoot 'engine'
        $idxCallers = @(Get-ChildItem $eng -Recurse -Filter *.ps1 | Where-Object { (Get-Content $_.FullName -Raw) -match 'Get-RADefenderCveIndex' } | ForEach-Object Name)
        $idxCallers | Should -Be @('RA-DefenderCveContext.ps1')
        $addCallers = @(Get-ChildItem $eng -Recurse -Filter *.ps1 | Where-Object { $_.Name -ne 'RA-DefenderCveContext.ps1' -and (Get-Content $_.FullName -Raw) -match 'Add-RADefenderCveContext' } | ForEach-Object Name)
        $addCallers | Should -Be @('Invoke-RiskAnalysis.ps1')
        $ra = Get-Content (Join-Path $eng 'risk-analysis\Invoke-RiskAnalysis.ps1') -Raw
        ([regex]::Matches($ra, 'Add-RADefenderCveContext -Rows')).Count | Should -Be 1
        ([regex]::Matches($ra, '\$global:SI_RA_DefenderCveApi\s*=')).Count | Should -Be 0 -Because 'nothing in the engine turns the API on by itself'
    }
    It 'the Detailed query counts the exposed devices per CVE over the whole tenant and carries them as si_exposed_devices' {
        $q = $script:Detailed
        $q | Should -Match '(?s)let _cveExposedDevices = DeviceTvmSoftwareVulnerabilities\s*\|\s*summarize by _expCve = toupper\(tostring\(CveId\)\), _expDevice = tolower\(tostring\(DeviceId\)\)'
        $q | Should -Match '(?s)_cveExposedDevices.*?join kind=leftanti \(DeviceInfo.*?isnotempty\(ExclusionReason\).*?\) on _expDevice\s*\|\s*summarize _expDevices = count\(\) by _expCve\s*\|\s*where isnotempty\(_expCve\);' -Because 'an excluded device is not counted, as in the report''s own rows'
        # tenant scope: the count is defined before the bucket filter and never under it
        $letAt = $q.IndexOf('let _cveExposedDevices'); $unionAt = $q.IndexOf('union _AssetFindingEdges, _TvmOnly')
        $letAt | Should -BeGreaterThan 0; $letAt | Should -BeLessThan $unionAt
        $q.Substring($letAt, $unionAt - $letAt) | Should -Not -Match '__BUCKET_FILTER'
        $q | Should -Match ([regex]::Escape('| join kind=leftouter (_cveExposedDevices) on $left._cveUpper == $right._expCve'))
        $q | Should -Match ([regex]::Escape('si_exposed_devices = toint(_expDevices)'))
        $q | Should -Match '(?s)\| project.*si_exposed_devices, si_exploit_verified, si_in_exploit_kit\s*\r?\n\s*\| order by'
    }
    It 'verified exploit and exploit kit come from the graph node; a row the graph does not carry leaves them unknown, never false' {
        $q = $script:Detailed
        $q | Should -Match ([regex]::Escape('FindingIsExploitVerified = tobool(NodeProperties.rawData.isExploitVerified)'))
        $q | Should -Match ([regex]::Escape('FindingIsInExploitKit    = tobool(NodeProperties.rawData.isInExploitKit)'))
        $q | Should -Match ([regex]::Escape('CVELastModified, FindingDescription, FindingReferenceUrl, _fromGraph = true;'))
        $q | Should -Match '_fromGraph\s+= false;'
        $q | Should -Match ([regex]::Escape('si_exploit_verified = iff(_fromGraph == true, FindingIsExploitVerified, bool(null))'))
        $q | Should -Match ([regex]::Escape('si_in_exploit_kit = iff(_fromGraph == true, FindingIsInExploitKit, bool(null))'))
        $q | Should -Not -Match 'si_exploit_types' -Because 'advanced hunting does not carry the exploit types: unknown, never invented'
        # EPSS, CVSS vector and the published date were already from the knowledge base and stay so
        $q | Should -Match ([regex]::Escape('si_published = _kbPublished, si_epss = round(_kbEpss, 5), si_cvss_vector = _kbVector'))
    }
    It 'no colon in a // comment of the new lines' {
        $new = @($script:Detailed -split "`n" | Where-Object { $_ -match '^\s*//.*#666' -or $_ -match '^\s*// (graph does not carry|management, every device)' })
        $new.Count | Should -BeGreaterOrEqual 2
        foreach ($l in $new) { $l | Should -Not -Match '//.*:' }
    }
}

Describe 'the CVE details are read for the report''s own CVEs, with the same result as the whole list' {
    BeforeEach { Reset-Run }
    It 'the same enrichment of every row as the whole-list read, over three slices of one report' {
        $slices = @($script:ReportIds[0..79], $script:ReportIds[60..169], $script:ReportIds[150..234])
        # the whole list, as it was
        $full = Get-RADefenderCveIndex -Fetch $script:Api
        $full.Mode | Should -Be 'full'
        $expected = foreach ($s in $slices) { , (Add-RADefenderCveContext -Rows (New-ReportRows $s) -Index $full -Log { param($m) throw "said: $m" }) }
        Reset-Run
        # the report's own CVEs, slice by slice, through the engine's own path
        $actual = foreach ($s in $slices) { , (Add-RADefenderCveContext -Rows (New-ReportRows $s) -Fetch $script:Api -Log { param($m) throw "said: $m" }) }
        for ($i = 0; $i -lt 3; $i++) { Get-RowsText $actual[$i] | Should -BeExactly (Get-RowsText $expected[$i]) }
        $ix = $global:RA_DefenderCveIndex
        $ix.Mode | Should -Be 'ids'
        $ix.Complete | Should -BeTrue
        # the index is the whole list's for every id asked (present and absent alike)
        foreach ($id in $script:ReportIds) {
            $id = $id.ToUpperInvariant()
            $ix.Index.ContainsKey($id) | Should -Be $full.Index.ContainsKey($id) -Because $id
            if ($full.Index.ContainsKey($id)) { ($ix.Index[$id] | ConvertTo-Json -Compress) | Should -BeExactly ($full.Index[$id] | ConvertTo-Json -Compress) }
        }
        @($script:Urls | Where-Object { $_ -notmatch '\$filter=' }).Count | Should -Be 0 -Because 'the whole list is never read'
        @($actual[0] | Where-Object { $_.PSObject.Properties['si_exploit_verified'] -or $_.PSObject.Properties['si_exposed_devices'] }).Count | Should -BeGreaterThan 10 -Because 'the fixture really enriches rows'
    }
    It 'an id is never asked for twice in a run; a slice with only known ids makes no request' {
        $null = Add-RADefenderCveContext -Rows (New-ReportRows $script:ReportIds[0..99]) -Fetch $script:Api
        $first = $script:Urls.Count
        $null = Add-RADefenderCveContext -Rows (New-ReportRows $script:ReportIds[50..149]) -Fetch $script:Api
        $null = Add-RADefenderCveContext -Rows (New-ReportRows $script:ReportIds[0..149]) -Fetch $script:Api
        $script:Asked.Count | Should -Be 150
        @($script:Asked | Sort-Object -Unique).Count | Should -Be 150 -Because 'every id once'
        $script:Urls.Count | Should -BeGreaterThan $first
        $before = $script:Urls.Count
        $null = Add-RADefenderCveContext -Rows (New-ReportRows $script:ReportIds[10..40]) -Fetch $script:Api
        $script:Urls.Count | Should -Be $before
        $global:RA_DefenderCveIndex.Asked.Count | Should -Be 150
    }
    It 'a CVE the service does not return stays unknown -- nothing written as false or 0 -- and is not asked again' {
        $rows = New-ReportRows @('CVE-2099-1', 'CVE-2099-2')
        $out = Add-RADefenderCveContext -Rows $rows -Fetch $script:Api
        foreach ($r in $out) { foreach ($n in 'si_exploit_verified', 'si_in_exploit_kit', 'si_exploit_types', 'si_exposed_devices') { $r.PSObject.Properties[$n] | Should -BeNullOrEmpty } }
        $global:RA_DefenderCveIndex.Complete | Should -BeTrue
        $n = $script:Urls.Count
        $null = Add-RADefenderCveContext -Rows (New-ReportRows @('CVE-2099-2')) -Fetch $script:Api
        $script:Urls.Count | Should -Be $n
    }
    It 'the start and end lines are plain words (no internal numbers or jargon)' {
        $null = Add-RADefenderCveContext -Rows (New-ReportRows $script:ReportIds[0..29]) -Fetch $script:Api
        $global:CveSaid.Count | Should -Be 2
        $global:CveSaid[0] | Should -Match 'reading the details of 30 vulnerabilities from Defender'
        $global:CveSaid[1] | Should -Match 'details of 30 vulnerabilities read in 1 request\(s\) and \d+ s: 30 found, \d+ concern this tenant''s devices$'
        ($global:CveSaid -join "`n") | Should -Not -Match '#\d|odata|\$filter|\[\w+\]'
    }
    It 'SI_RA_DefenderCveRead = full reads the whole list as before' {
        $global:SI_RA_DefenderCveRead = 'full'
        $null = Add-RADefenderCveContext -Rows (New-ReportRows $script:ReportIds[0..9]) -Fetch $script:Api
        $global:RA_DefenderCveIndex.Mode | Should -Be 'full'
        @($script:Urls | Where-Object { $_ -match '\$filter=' }).Count | Should -Be 0
    }
}

Describe 'the requests are cut by the length of their address' {
    BeforeEach { Reset-Run }
    It 'every address at most the limit, every id once and in order, as many ids as fit' {
        $ids = @(1..1000 | ForEach-Object { 'CVE-2024-{0}' -f (10000 + $_) })
        foreach ($form in 'in', 'or') { foreach ($max in 600, 2000, 6000) {
            $got = [System.Collections.Generic.List[string]]::new(); $pos = 0; $n = 0
            while ($pos -lt $ids.Count) {
                $b = New-RADefenderCveFilterBatch -Ids $ids -Start $pos -MaxLength $max -Form $form
                $b.Url.Length | Should -BeLessOrEqual $max
                @(Get-FilterIds $b.Url) | Should -Be @($b.Ids)
                if ($pos + $b.Ids.Count -lt $ids.Count) {
                    # one more id would not have fitted
                    (New-RADefenderCveFilterBatch -Ids $ids[$pos..($pos + $b.Ids.Count)] -MaxLength 100000 -Form $form).Url.Length | Should -BeGreaterThan $max
                }
                foreach ($i in $b.Ids) { $got.Add($i) }
                $pos += $b.Ids.Count; $n++
            }
            @($got) | Should -Be $ids
            if ($max -eq 6000 -and $form -eq 'or') { $n | Should -BeLessOrEqual 8 -Because 'about 150 ids per request at the default' }
            if ($max -eq 6000 -and $form -eq 'in') { $n | Should -BeLessOrEqual 5 -Because 'about 250 ids per request at the default' }
        } }
        (Get-RADefenderCveFilterUrlMax -Setting $null) | Should -Be 6000
        (Get-RADefenderCveFilterUrlMax -Setting '3000') | Should -Be 3000
        (Get-RADefenderCveFilterUrlMax -Setting '10') | Should -Be 6000
        (New-RADefenderCveFilterBatch -Ids @('CVE-2024-1') -MaxLength 20).Ids | Should -Be @('CVE-2024-1') -Because 'one id goes alone whatever its length'
        (New-RADefenderCveFilterBatch -Ids @('CVE-2024-1', 'CVE-2024-2') -Form or).Url | Should -BeExactly ('https://api.securitycenter.microsoft.com/api/vulnerabilities?$filter=id%20eq%20%27CVE-2024-1%27%20or%20id%20eq%20%27CVE-2024-2%27')
        [uri]::UnescapeDataString((New-RADefenderCveFilterBatch -Ids @('CVE-2024-1', 'CVE-2024-2')).Url) | Should -BeExactly ("https://api.securitycenter.microsoft.com/api/vulnerabilities?`$filter=id in ('CVE-2024-1','CVE-2024-2')") -Because 'the in form is the default'
    }
    It 'a request the service says is too long is split and sent again; nothing is lost' {
        $script:Refused = 0
        $api = { param($url)
            if ($url.Length -gt 1500) { $script:Refused++; return @{ Complete = $false; Error = 'Defender vulnerabilities: page 1 failed after 1 attempt(s) -- HTTP 414 URI Too Long'; Rows = @() } }
            & $script:Api $url }
        $out = Add-RADefenderCveContext -Rows (New-ReportRows $script:ReportIds) -Fetch $api -Log { param($m) throw "said: $m" }
        $script:Refused | Should -BeGreaterOrEqual 1
        $script:Refused | Should -BeLessOrEqual 3 -Because 'halved per refusal, and the limit learnt is kept for the rest of the read'
        $global:RA_DefenderCveIndex.Complete | Should -BeTrue
        @($script:Asked | Sort-Object -Unique).Count | Should -Be $script:ReportIds.Count
        $script:Asked.Count | Should -Be $script:ReportIds.Count -Because 'a refused request read nothing, so no id is read twice'
        @($out).Count | Should -Be ($script:ReportIds.Count * 2 + 1)
    }
}

Describe 'never fewer: the whole list when the filter is not taken, said once' {
    BeforeEach { Reset-Run }
    It 'the filter refused on the first request (400 Invalid filter, every size): the whole list, as before' {
        $api = { param($url)
            if ($url -match '\$filter=') { $script:Urls.Add($url); return @{ Complete = $false; Error = 'Defender vulnerabilities: page 1 failed after 1 attempt(s) -- HTTP 400 {"error":{"code":"InvalidRequestBody","message":"Invalid filter"}}'; Rows = @() } }
            & $script:Api $url }
        $full = Get-RADefenderCveIndex -Fetch $script:Api
        Reset-Run
        $out = Add-RADefenderCveContext -Rows (New-ReportRows $script:ReportIds[0..199]) -Fetch $api -Log { param($m) throw "said: $m" }
        $ix = $global:RA_DefenderCveIndex
        $ix.Mode | Should -Be 'full'
        $ix.Complete | Should -BeTrue
        @($ix.Index.Keys | Sort-Object) | Should -Be @($full.Index.Keys | Sort-Object)
        @($script:Urls | Where-Object { $_ -match '\$filter=' }).Count | Should -BeLessOrEqual 10 -Because 'the in form, then the or form split down to one id, then the whole list'
        @($global:CveSaid | Where-Object { $_ -match 'whole vulnerability list once for this run instead' }).Count | Should -Be 1
        # a later slice: the whole list stands for the run, no request
        $n = $script:Urls.Count
        $null = Add-RADefenderCveContext -Rows (New-ReportRows $script:ReportIds[200..234]) -Fetch $api
        $script:Urls.Count | Should -Be $n
        @($global:CveSaid | Where-Object { $_ -match 'instead' }).Count | Should -Be 1
    }
    It '501 / "not supported" on a one-id first request: the whole list straight away' {
        $api = { param($url)
            if ($url -match '\$filter=') { $script:Urls.Add($url); return @{ Complete = $false; Error = 'Defender vulnerabilities: page 1 failed after 1 attempt(s) -- HTTP 501 The query option is not supported'; Rows = @() } }
            & $script:Api $url }
        $null = Add-RADefenderCveContext -Rows (New-ReportRows @('CVE-2010-1016')) -Fetch $api
        @($script:Urls | Where-Object { $_ -match '\$filter=' }).Count | Should -Be 2 -Because 'the in form, then the or form'
        $global:RA_DefenderCveIndex.Mode | Should -Be 'full'
    }
    It 'the in form refused ("Filter parameter is invalid"), the or form taken: every id read once, no whole list' {
        $api = { param($url)
            if ([uri]::UnescapeDataString($url) -match 'id in \(') { $script:Urls.Add($url); return @{ Complete = $false; Error = 'Defender vulnerabilities: page 1 failed after 1 attempt(s) -- HTTP 400 {"error":{"message":"Filter parameter is invalid"}}'; Rows = @() } }
            & $script:Api $url }
        $full = Get-RADefenderCveIndex -Fetch $script:Api
        Reset-Run
        $out = Add-RADefenderCveContext -Rows (New-ReportRows $script:ReportIds) -Fetch $api -Log { param($m) throw "said: $m" }
        $ix = $global:RA_DefenderCveIndex
        $ix.Mode | Should -Be 'ids'
        $ix.Complete | Should -BeTrue
        $ix.Form | Should -Be 'or'
        $script:Asked.Count | Should -Be $script:ReportIds.Count
        @($script:Urls | Where-Object { [uri]::UnescapeDataString($_) -match 'id in \(' }).Count | Should -Be 1 -Because 'the form learnt is kept for the run'
        @($script:Urls | Where-Object { $_ -notmatch '\$filter=' }).Count | Should -Be 0
        $expected = Add-RADefenderCveContext -Rows (New-ReportRows $script:ReportIds) -Index $full
        Get-RowsText $out | Should -BeExactly (Get-RowsText $expected)
    }
    It 'a service that ignores the filter (answers with CVEs not asked for): the whole list, once' {
        $api = { param($url) $script:Urls.Add($url); @{ Complete = $true; Error = $null; Rows = $script:Cat } }
        $null = Add-RADefenderCveContext -Rows (New-ReportRows $script:ReportIds[0..9]) -Fetch $api -Log { param($m) throw "said: $m" }
        $global:RA_DefenderCveIndex.Mode | Should -Be 'full'
        $global:RA_DefenderCveIndex.Complete | Should -BeTrue
        @($script:Urls | Where-Object { $_ -match '\$filter=' }).Count | Should -Be 1
        @($global:CveSaid | Where-Object { $_ -match 'instead' }).Count | Should -Be 1
    }
}

Describe 'a request that fails after the retries makes the read not complete' {
    BeforeEach { Reset-Run }
    It 'said once, the rows go on unchanged, no later request in the run' {
        $global:SI_RA_DefenderCveFilterUrlMax = 1000
        $script:N = 0
        $api = { param($url) $script:N++
            if ($script:N -eq 2) { $script:Urls.Add($url); return @{ Complete = $false; Error = 'Defender vulnerabilities: page 1 failed after 4 attempt(s) -- HTTP 503 Service Unavailable'; Rows = @() } }
            & $script:Api $url }
        $said = [System.Collections.Generic.List[string]]::new()
        $rows = New-ReportRows $script:ReportIds[0..99]
        $out = Add-RADefenderCveContext -Rows $rows -Fetch $api -Log { param($m) $said.Add([string]$m) }
        $global:RA_DefenderCveIndex.Complete | Should -BeFalse
        $global:RA_DefenderCveIndex.Mode | Should -Be 'ids' -Because 'a passing failure later in the read is not a refused filter'
        @($out | Where-Object { $_.PSObject.Properties['si_exploit_verified'] -or $_.PSObject.Properties['si_exposed_devices'] }).Count | Should -Be 0
        $n = $script:N
        $null = Add-RADefenderCveContext -Rows (New-ReportRows $script:ReportIds[100..150]) -Fetch $api -Log { param($m) $said.Add([string]$m) }
        $script:N | Should -Be $n
        $said.Count | Should -Be 1
        $said[0] | Should -Match 'could not be read from Defender in this run'
        @($global:CveSaid | Where-Object { $_ -match 'NOT complete' }).Count | Should -Be 1
    }
    It 'a 503 or a refused permission on the FIRST request is not a refused filter: no whole-list read' {
        foreach ($e in 'HTTP 503 Service Unavailable', 'HTTP 403 {"error":{"code":"Forbidden"}}') {
            Reset-Run
            $global:CveErr = $e
            $api = { param($url) $script:Urls.Add($url); @{ Complete = $false; Error = "Defender vulnerabilities: page 1 failed after 4 attempt(s) -- $($global:CveErr)"; Rows = @() } }
            $said = [System.Collections.Generic.List[string]]::new()
            $null = Add-RADefenderCveContext -Rows (New-ReportRows @('CVE-2010-1016')) -Fetch $api -Log { param($m) $said.Add([string]$m) }
            $global:RA_DefenderCveIndex.Complete | Should -BeFalse
            @($script:Urls | Where-Object { $_ -notmatch '\$filter=' }).Count | Should -Be 0
            if ($e -match '403') { $said[0] | Should -Match 'Vulnerability\.Read\.All' }
        }
    }
}

Describe 'through a real HTTP exchange' {
    BeforeAll {
        $script:Listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
        $script:Listener.Start()
        $script:Base = 'http://127.0.0.1:{0}/api/vulnerabilities' -f $script:Listener.LocalEndpoint.Port
        $script:Served = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()
        $script:ServerMode = [hashtable]::Synchronized(@{ Filter = $true })
        $catJson = $script:Cat | ConvertTo-Json -Depth 4 -Compress
        $script:Server = [powershell]::Create()
        $null = $script:Server.AddScript({
            param($Listener, $CatJson, $Base, $Served, $Mode)
            $cat = $CatJson | ConvertFrom-Json
            $byId = @{}; foreach ($c in $cat) { $byId[$c.id.ToUpperInvariant()] = $c }
            while ($true) {
                $client = $Listener.AcceptTcpClient()
                try {
                    $stream = $client.GetStream(); $reader = [System.IO.StreamReader]::new($stream)
                    $line = $reader.ReadLine()
                    while ($true) { $h = $reader.ReadLine(); if ([string]::IsNullOrEmpty($h)) { break } }
                    $target = $line.Split(' ')[1]
                    $Served.Enqueue($target)
                    $status = '200 OK'; $body = $null
                    $query = [uri]::UnescapeDataString(($target -split '\?', 2)[1])
                    if ($query -match '\$filter=') {
                        if (-not $Mode.Filter) { $status = '400 Bad Request'; $body = '{"error":{"code":"InvalidRequestBody","message":"Invalid filter"}}' }
                        else {
                            $inForm = [regex]::Match($query, "id in \(([^)]*)\)")
                            if ($inForm.Success) { $ids = @($inForm.Groups[1].Value -split ',' | ForEach-Object { $_.Trim().Trim("'").ToUpperInvariant() } | Where-Object { $_ }) }
                            else { $ids = @([regex]::Matches($query, "id eq '([^']+)'") | ForEach-Object { $_.Groups[1].Value.ToUpperInvariant() }) }
                            $rows = @($ids | ForEach-Object { $byId[$_] } | Where-Object { $_ })
                            # two pages: the first half with a next link
                            $half = [Math]::Ceiling($rows.Count / 2)
                            if ($query -match '&page=2') { $body = @{ value = @($rows | Select-Object -Skip $half) } | ConvertTo-Json -Depth 5 -Compress }
                            else { $body = @{ value = @($rows | Select-Object -First $half); '@odata.nextLink' = ($Base + '?' + ($target -split '\?', 2)[1] + '&page=2') } | ConvertTo-Json -Depth 5 -Compress }
                        }
                    } else { $body = @{ value = @($cat) } | ConvertTo-Json -Depth 5 -Compress }
                    $bytes = [System.Text.Encoding]::UTF8.GetBytes($body)
                    $head = [System.Text.Encoding]::ASCII.GetBytes(("HTTP/1.1 {0}`r`nContent-Type: application/json`r`nContent-Length: {1}`r`nConnection: close`r`n`r`n" -f $status, $bytes.Length))
                    $stream.Write($head, 0, $head.Length); $stream.Write($bytes, 0, $bytes.Length); $stream.Flush()
                } catch { } finally { $client.Close() }
            }
        }).AddArgument($script:Listener).AddArgument($catJson).AddArgument($script:Base).AddArgument($script:Served).AddArgument($script:ServerMode)
        $script:ServerRun = $script:Server.BeginInvoke()
        $script:ReadIn = {
            param([string]$CodePath, [string]$Paged, [string]$Url, [string[]]$Ids)
            $ps = [powershell]::Create()
            $null = $ps.AddScript({
                param($CodePath, $Paged, $Url, $Ids)
                $lines = [System.Collections.Generic.List[string]]::new()
                function Write-Info { param($m) $lines.Add([string]$m) }
                function Get-SIGraphToken { param($Resource) 'token' }
                . $Paged
                . $CodePath
                $script:RADefenderCveUrl = $Url
                $global:SI_RA_DefenderReadTimeoutSec = 20
                $s = Get-RADefenderCveIndex -Ids $Ids -Refresh
                [pscustomobject]@{ State = $s; Lines = $lines.ToArray() }
            }).AddArgument($CodePath).AddArgument($Paged).AddArgument($Url).AddArgument($Ids)
            $r = $ps.Invoke(); $ps.Dispose(); @($r)[-1]
        }
        $script:Paged = Join-Path $script:SIRoot 'engine\asset-profiling\shared\Invoke-SIPagedRest.ps1'
    }
    AfterAll { try { $script:Listener.Stop() } catch { }; try { $null = $script:Server.BeginStop($null, $null) } catch { } }

    It 'the filter reaches the server as written, the next links are followed, the index is the whole list''s' {
        $script:ServerMode.Filter = $true
        $ids = @($script:Cat[0..39] | ForEach-Object { $_.id })
        $r = & $script:ReadIn $script:CodePath $script:Paged $script:Base $ids
        $r.State.Complete | Should -BeTrue
        $r.State.Mode | Should -Be 'ids'
        $r.State.Read | Should -Be 40
        $expect = @($script:Cat[0..39] | Where-Object { [int]$_.exposedMachines -gt 0 } | ForEach-Object { $_.id } | Sort-Object)
        @($r.State.Index.Keys | Sort-Object) | Should -Be $expect
        $served = @($script:Served.ToArray()); $script:Served.Clear()
        $served.Count | Should -Be 2 -Because 'one filtered request and its next page'
        (Get-FilterIds $served[0]) | Should -Be $ids
    }
    It 'a server that refuses the filter (400): the whole list over HTTP, said in plain words' {
        $script:ServerMode.Filter = $false
        $r = & $script:ReadIn $script:CodePath $script:Paged $script:Base @('CVE-2010-1016')
        $r.State.Mode | Should -Be 'full'
        $r.State.Complete | Should -BeTrue
        $r.State.Index.Count | Should -Be @($script:Cat | Where-Object { [int]$_.exposedMachines -gt 0 }).Count
        ($r.Lines -join "`n") | Should -Match 'whole vulnerability list once for this run instead'
        $served = @($script:Served.ToArray()); $script:Served.Clear()
        $served[0] | Should -Match 'filter='
        $served[-1] | Should -Match '\$top=8000'
    }
}
