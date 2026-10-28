#Requires -Version 5.1
<#
    #770 -- Identity_Admin_LogonTo_LowTierDevice_DETAILED ended NotComplete in a Risk Analysis Detailed run (a large install,
    owner 2026-10-19): "its query could not be sent: the lookup _deviceTierOwn (12,580 rows, 1.4 MB) is needed whole in every
    part of the query -- with the query text that is 1.4 MB in every part, more than a query to Microsoft [Defender] takes".
    The report then showed its last complete result (2026-10-17). Owner: "full flow success for every install -- a report
    must not fail at any tenant size".

    CAUSE: the #751 defect, met by the DETAILED report this time. That install ran rc7 (its run started 2026-10-18 10:45Z and
    was still running when rc12 went to ring 0, V3-HANDOFF section 19); the #751 fix (340f85142) is in rc11 and later. In a
    Detailed run an earlier Detailed report that declares _ciPeer with the same device-key lines (seven do) proved _ciPeer too
    large first; this report's first part then asked the graph for _ciPeer's keys with _deviceTierOwn WHOLE in that key query,
    whose own size check refused it before the step that cuts _deviceTierOwn was reached. #751 made the key query carry every
    declared lookup empty; the Detailed declares the same two lookups with the same key lines as the Summary, so the one fix
    covers both. Same method at every size: _deviceTierOwn is cut per query part to the devices of that part (LookupNeededKeys,
    #741 (2)), so more parts always make each part smaller -- no cap, no row dropped.

    THIS SUITE runs the REAL Detailed report text through the REAL Invoke-GraphHuntingQuery at the REAL request limit (1 MB,
    no scaled cap), with Log Analytics a stub and advanced hunting a stand-in that answers each request from what is INSIDE it
    (the inlined _ciPeer and _deviceTierOwn rows):
      * 12,580 _deviceTierOwn rows (the live size): whole it does not fit one request; the old key query is refused exactly as
        the live run was; with the fix every part and every key query fits and the rows are IDENTICAL to the unsliced answer,
        in both orders (_ciPeer cut by an earlier report first -- the live order -- and a fresh run).
      * 100,000 _deviceTierOwn rows: the same, on a first, a middle and a last part of the query (every request under the
        limit, each part's rows identical to that part's answer worked out with the whole lookups).
    OFFLINE. NO EMOJI IN THIS FILE.
#>

BeforeAll { . (Join-Path $PSScriptRoot '_LowTierCutHarness.ps1') }

AfterAll {
    $global:SI_HuntingRequestCapBytes = $null
    if ($script:Sha1) { $script:Sha1.Dispose() }
}

Describe '#770 the Detailed report as the engine loads it' {
    BeforeEach { Reset-State }

    It 'declares _ciPeer and _deviceTierOwn with the same device-key lines as the Summary, and both apply to its query' {
        $script:Report | Should -Match '(?m)^      - Lookup: _ciPeer\n        Column: _peerKey\n        Keys: \|-\n          \| extend DeviceCiKey = iif\(isnotempty\(MdeDeviceId\), MdeDeviceId, tolower\(DeviceNodeId\)\)\n          \| project __siNeeded = pack_array\(DeviceCiKey\)$'
        $script:Report | Should -Match '(?m)^      - Lookup: _deviceTierOwn\n        Column: _dtKey\n        Keys: \|-\n          \| extend DeviceCiKey = iif\(isnotempty\(MdeDeviceId\), MdeDeviceId, tolower\(DeviceNodeId\)\)\n          \| project __siNeeded = pack_array\(DeviceCiKey\)$'
        @(Get-RALookupNeededKeyDeclarations -Query $script:Q).Count | Should -Be 2
        # the cut point comes before either lookup is read, and _deviceTierOwn carries only the three columns the query uses
        $script:Q.IndexOf('//__SI_LOOKUP_KEYS_HERE__') | Should -BeLessThan $script:Q.IndexOf('join kind=leftouter (_ciPeer)')
        $script:Q.IndexOf('//__SI_LOOKUP_KEYS_HERE__') | Should -BeLessThan $script:Q.IndexOf('join kind=leftouter (_deviceTierOwn')
        $script:Q | Should -Match '\| project _dtKey, _dtCiId, _dtTier;'
    }
}

Describe '#770 12,580 _deviceTierOwn rows (the live size), at the real 1 MB request limit' {
    BeforeAll {
        $script:F = New-Fixture -Devices 4193
        $script:SliceCache = @{}
        $script:Expected = Invoke-DeviceSide -Pairs $script:F.Pairs -Peer $script:F.PeerRows -Own $script:F.OwnOld
    }
    BeforeEach {
        Reset-State
        Mock Invoke-LogAnalyticsKqlQuery { if ($Query -match '_dtKey') { $script:F.OwnNew } elseif ($Query -match '_peerKey') { $script:F.PeerRows } else { @() } }
        Mock Resolve-ProfileAugmentPlan { @{ Query = $Query; Plans = @() } }
        Mock Invoke-SIHuntingQueryRest { Invoke-FakeHunting -Query $Query }
    }

    It 'the fixture is the live size: 12,580 rows, and whole they are more than one request can carry' {
        $script:F.OwnNew.Count | Should -Be 12580
        $whole = Convert-RowsToKqlDatatable -LetVarName '_deviceTierOwn' -Rows $script:F.OwnNew -BodyKqlForSchemaHint '| project _dtKey, _dtCiId, _dtTier'
        [long](Get-RARequestWireBytes -Text $whole) | Should -BeGreaterThan $script:Cap
    }

    It 'the key query of rc7 (_ciPeer asked for, _deviceTierOwn WHOLE in it) is refused at the real limit with the live message' {
        $script:_RALookupNeededKeySets = @{ '_ciPeer' = @{ Column = '_peerKey'; KeySet = (New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)) } }
        $script:_RALookupKeyQueryBuilding = $true
        try { $res = Resolve-ProfileCLLetBlocks -Query $script:Q -WorkspaceResourceId $script:Ws -BucketCount 8 -BucketIndex 0 } finally { $script:_RALookupKeyQueryBuilding = $false }
        $script:_RALookupNeededKeySets = $null
        $old = Get-RALookupKeyQuery -ResolvedQuery $res -KeysKql $script:DeviceKeys
        # 659fb78a (decide before building): that rc7 request can no longer be built -- the declared lookup over the budget is
        # measured, never built whole; a typed empty placeholder stands in (never sent) and its cut is wanted
        [long](Get-RARequestWireBytes -Text $old) | Should -BeLessThan $script:Cap
        $script:_RALookupCutWanted.ContainsKey('_deviceTierOwn') | Should -BeTrue
        @(@($script:_RAHybridLookups) | Where-Object { $_.Name -eq '_deviceTierOwn' -and [bool]$_.Placeholder }).Count | Should -Be 1
    }

    It '_ciPeer already cut by an earlier report (the live order), 8 parts: no part is refused, every request fits, the rows are IDENTICAL' {
        Set-CiPeerCutByEarlierReport
        $got = New-Object System.Collections.Generic.List[string]
        foreach ($b in 0..7) { foreach ($row in (Invoke-Part -Slices 8 -Index $b)) { $got.Add($row) } }
        @($got.ToArray() | Sort-Object) | Should -Be $script:Expected
        $script:Requests.Count | Should -Be 8
        foreach ($rq in $script:Requests) { $rq.Bytes | Should -BeLessThan $script:Cap }
        foreach ($kq in $script:KeyQueries) { $kq | Should -BeLessThan $script:Cap }
        $script:KeyQueries.Count | Should -Be 8 -Because 'each part is asked for its keys once (both lookups have the same key lines)'
        $script:_RALookupReductionOn.ContainsKey((Get-OwnCutId)) | Should -BeTrue -Because "_deviceTierOwn's cut is on for the rest of the run"
        # over all parts only the keys the graph has travel: fewer rows than the whole lookup, never every key of every CI
        ($script:Requests | Measure-Object -Property OwnRows -Sum).Sum | Should -BeLessThan $script:F.OwnNew.Count
    }

    It 'a fresh run (nothing cut yet), 8 parts: both are cut on the first part, the rows are IDENTICAL' {
        $got = New-Object System.Collections.Generic.List[string]
        foreach ($b in 0..7) { foreach ($row in (Invoke-Part -Slices 8 -Index $b)) { $got.Add($row) } }
        @($got.ToArray() | Sort-Object) | Should -Be $script:Expected
        $script:_RALookupReductionOn.Count | Should -Be 2
        foreach ($rq in $script:Requests) { $rq.Bytes | Should -BeLessThan $script:Cap }
    }
}

Describe '#770 100,000 _deviceTierOwn rows, at the real 1 MB request limit -- the same method' {
    BeforeAll {
        $script:F = New-Fixture -Devices 33333
        $script:SliceCache = @{}
    }
    BeforeEach {
        Reset-State
        Mock Invoke-LogAnalyticsKqlQuery { if ($Query -match '_dtKey') { $script:F.OwnNew } elseif ($Query -match '_peerKey') { $script:F.PeerRows } else { @() } }
        Mock Resolve-ProfileAugmentPlan { @{ Query = $Query; Plans = @() } }
        Mock Invoke-SIHuntingQueryRest { Invoke-FakeHunting -Query $Query }
    }

    It 'the fixture has 100,000 rows' {
        $script:F.OwnNew.Count | Should -Be 100000
    }

    It '_ciPeer already cut (the live order), 32 parts: the first, a middle and the last part each fit and give exactly their rows' {
        Set-CiPeerCutByEarlierReport
        foreach ($b in 0, 15, 31) {
            $got = Invoke-Part -Slices 32 -Index $b
            $exp = Get-PartExpected -Slices 32 -Index $b
            @($exp).Count | Should -BeGreaterThan 500
            $got | Should -Be $exp
        }
        $script:Requests.Count | Should -Be 3
        foreach ($rq in $script:Requests) { $rq.Bytes | Should -BeLessThan $script:Cap; $rq.OwnRows | Should -BeLessThan 5000 }
        foreach ($kq in $script:KeyQueries) { $kq | Should -BeLessThan $script:Cap }
        $script:_RALookupReductionOn.ContainsKey((Get-OwnCutId)) | Should -BeTrue
    }

    It 'more parts make every part smaller (the part that does not shrink stays far under the limit)' {
        Set-CiPeerCutByEarlierReport
        $null = Invoke-Part -Slices 32 -Index 0
        $at32 = [long]$script:Requests[-1].Bytes
        $null = Invoke-Part -Slices 64 -Index 0
        $at64 = [long]$script:Requests[-1].Bytes
        $at64 | Should -BeLessThan $at32
        [long]$script:_RAHybridLastRequest.FixedBytes | Should -BeLessThan ([long](Get-RAHuntingPlanningBudgetBytes) / 4)
    }
}

Describe '659fb78a: a declared lookup over the budget is never built whole; the cut also for an UNSLICED query; each part identical' {
    BeforeAll {
        $script:F = New-Fixture -Devices 4193
        $script:SliceCache = @{}
        $script:Expected = Invoke-DeviceSide -Pairs $script:F.Pairs -Peer $script:F.PeerRows -Own $script:F.OwnOld
        # the same graph with lookups that match NOTHING of it: another tenant's devices (no key of this graph in them)
        $script:G = New-Fixture -Devices 300
        $script:NoMatch = [pscustomobject]@{ Peer = @($script:G.PeerRows | ForEach-Object { [pscustomobject]@{ _peerKey = 'x-' + $_._peerKey; peer_ci_id = $_.peer_ci_id; peer_tier = $_.peer_tier } })
                                             Own = @($script:G.OwnNew | ForEach-Object { [pscustomobject]@{ _dtKey = 'x-' + $_._dtKey; _dtCiId = $_._dtCiId; _dtTier = $_._dtTier } })
                                             OwnOld = $script:G.OwnOld }
    }
    BeforeEach {
        Reset-State
        $script:UseNoMatch = $false
        Mock Invoke-LogAnalyticsKqlQuery {
            if ($script:UseNoMatch) { if ($Query -match '_dtKey') { return $script:NoMatch.Own } elseif ($Query -match '_peerKey') { return $script:NoMatch.Peer } else { return @() } }
            if ($Query -match '_dtKey') { $script:F.OwnNew } elseif ($Query -match '_peerKey') { $script:F.PeerRows } else { @() }
        }
        Mock Resolve-ProfileAugmentPlan { @{ Query = $Query; Plans = @() } }
        Mock Invoke-SIHuntingQueryRest { Invoke-FakeHunting -Query $Query }
    }

    It 'decide before building: over the budget the whole text is not built -- a typed empty placeholder, the cut wanted, the build bounded' {
        $res = Resolve-ProfileCLLetBlocks -Query $script:Q -WorkspaceResourceId $script:Ws -BucketCount 8 -BucketIndex 0
        $script:_RALookupCutWanted.ContainsKey('_deviceTierOwn') | Should -BeTrue
        (Read-Datatable $res '_deviceTierOwn').Count | Should -Be 0 -Because 'a placeholder, never the whole lookup'
        [long](Get-RARequestWireBytes -Text $res) | Should -BeLessThan ([long](Get-RAHuntingPlanningBudgetBytes))
        @($script:Info | Where-Object { $_ -match "'_deviceTierOwn' bucket 1/8: 12580/12580 row\(s\) inlined" }).Count | Should -Be 0
        @($script:Info | Where-Object { $_ -match "'_deviceTierOwn': 12,580 row\(s\) would go whole into this part and are over the request budget -- not built" }).Count | Should -Be 1
    }
    It 'FIXTURE keys spread across ALL parts (8 parts): every part has lookup rows, each part identical to its answer with the whole lookups' {
        foreach ($b in 0..7) {
            (Invoke-Part -Slices 8 -Index $b) | Should -Be (Get-PartExpected -Slices 8 -Index $b) -Because "part $b"
        }
        $script:Requests.Count | Should -Be 8
        foreach ($rq in $script:Requests) { $rq.Bytes | Should -BeLessThan $script:Cap; $rq.OwnRows | Should -BeGreaterThan 0 }
        foreach ($kq in $script:KeyQueries) { $kq | Should -BeLessThan $script:Cap }
        @($script:Info | Where-Object { $_ -match 'does not fit whole in every part of the query -- its whole text is not built' }).Count | Should -BeGreaterThan 0
    }
    It 'FIXTURE matches in every part, UNSLICED (one part): the cut applies, nothing is refused, the rows are IDENTICAL to the whole lookups' {
        $got = Invoke-Part -Slices 1 -Index 0
        $got | Should -Be $script:Expected
        $script:Requests.Count | Should -Be 1 -Because 'one request, never a whole lookup refused for its size first'
        $script:Requests[0].Bytes | Should -BeLessThan $script:Cap
        $script:KeyQueries.Count | Should -Be 1
        $script:_RALookupReductionOn.ContainsKey((Get-OwnCutId)) | Should -BeTrue
    }
    It 'FIXTURE no matches at all (8 parts and unsliced): every part sends an empty lookup ONLY because its keys match nothing -- identical to the whole lookups' {
        $script:UseNoMatch = $true
        # (this lookup is small enough to go whole; its cut is turned on as an earlier report of the run would have)
        Set-CiPeerCutByEarlierReport; $script:_RALookupReductionOn[(Get-OwnCutId)] = $true
        foreach ($b in 0..7) {
            $exp = $(
                $script:_CurrentBucketCount = 8; $script:_CurrentBucketIndex = $b; $mine = @(Get-SlicePairs); $script:_CurrentBucketCount = 0; $script:_CurrentBucketIndex = 0
                Invoke-DeviceSide -Pairs $mine -Peer $script:NoMatch.Peer -Own $script:NoMatch.Own
            )
            (Invoke-Part -Slices 8 -Index $b) | Should -Be $exp -Because "part $b"
        }
        foreach ($rq in $script:Requests) { $rq.OwnRows | Should -Be 0 }
        (Invoke-Part -Slices 1 -Index 0) | Should -Be (Invoke-DeviceSide -Pairs $script:F.Pairs -Peer $script:NoMatch.Peer -Own $script:NoMatch.Own)
    }
    It 'a FAILED or CAPPED key query is the part''s failure -- never an empty lookup sent' {
        $script:Requests.Clear()
        Mock Invoke-SIHuntingQueryRest { if ($Query -match 'summarize by __siNeeded') { throw 'Response status code does not indicate success: 503 (Service Unavailable)' }; Invoke-FakeHunting -Query $Query }
        { Invoke-Part -Slices 8 -Index 0 } | Should -Throw '*503*'
        $script:Requests.Count | Should -Be 0 -Because 'the part was not sent'
        Reset-State
        Mock Invoke-SIHuntingQueryRest { if ($Query -match 'summarize by __siNeeded') { return [pscustomobject]@{ Results = @(1..100000 | ForEach-Object { [pscustomobject]@{ AdditionalProperties = @{ '__siNeeded' = "k$_" } } }) } }; Invoke-FakeHunting -Query $Query }
        { Invoke-Part -Slices 8 -Index 0 } | Should -Throw '*exceeded the allowed result size*'
        $script:Requests.Count | Should -Be 0
    }
    It 'WIRING: a placeholder is never sent; the cut is applied to an unsliced query' {
        $gh = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-GraphHunting.ps1'))
        $gh | Should -Match ([regex]::Escape("was not cut to this part of the query and is too large to send whole -- this part is not sent"))
        $gh | Should -Not -Match ([regex]::Escape('if ($_bk -gt 1 -and (Get-Command -Name Get-RALookupNeededKeyDeclarations'))
    }
}
