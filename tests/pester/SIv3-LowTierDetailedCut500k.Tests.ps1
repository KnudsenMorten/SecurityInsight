#Requires -Version 5.1
<#
    659fb78a at the owner's scale target: 500,000 _deviceTierOwn rows through the REAL Detailed report text and the REAL
    Invoke-GraphHuntingQuery at the REAL 1 MB request limit -- every request and key query under 1 MB, each part's rows
    identical to its answer with the whole lookups, and the 500,000-row whole text never built. Split from
    SIv3-LowTierDetailedCut.Tests.ps1 (2026-10-22) so this case has its own process and its own gate time; same harness
    (_LowTierCutHarness.ps1), same assertions. OFFLINE. NO EMOJI IN THIS FILE.
#>

BeforeAll { . (Join-Path $PSScriptRoot '_LowTierCutHarness.ps1') }

AfterAll {
    $global:SI_HuntingRequestCapBytes = $null
    if ($script:Sha1) { $script:Sha1.Dispose() }
}
Describe '659fb78a: 500,000 lookup rows (the owner''s scale target) -- every request under 1 MB, the whole text never built' {
    BeforeAll {
        # the graph: the 4,193-device fixture; the lookup: its rows plus 495,000 rows of devices no account of this graph uses
        $script:F = New-Fixture -Devices 4193
        $script:SliceCache = @{}
        # (built in one typed pass: the same 495,000+ rows and values as before -- three keys per device of devices no account of
        # this graph uses -- without a format call per row; only the FIXTURE is built faster, the code under test is unchanged)
        $need = 500000 - $script:F.OwnNew.Count
        $all = [System.Collections.Generic.List[object]]::new(500000)
        $all.AddRange([object[]]@($script:F.OwnNew))
        for ($i = 0; $i -lt $need; $i++) {
            $all.Add([pscustomobject]@{ _dtKey = 'zz' + $i.ToString('d12'); _dtCiId = 'ci-device-x' + ([int]($i / 3)).ToString('d9'); _dtTier = ($i % 4) })
        }
        $script:Own500k = $all.ToArray()
    }
    BeforeEach {
        Reset-State
        Mock Invoke-LogAnalyticsKqlQuery { if ($Query -match '_dtKey') { $script:Own500k } elseif ($Query -match '_peerKey') { $script:F.PeerRows } else { @() } }
        Mock Resolve-ProfileAugmentPlan { @{ Query = $Query; Plans = @() } }
        Mock Invoke-SIHuntingQueryRest { Invoke-FakeHunting -Query $Query }
    }
    It 'the lookup has 500,000 rows; unsliced and at 8 parts every request is under 1 MB and each part gives exactly its rows' {
        $script:Own500k.Count | Should -Be 500000
        (Invoke-Part -Slices 1 -Index 0) | Should -Be (Invoke-DeviceSide -Pairs $script:F.Pairs -Peer $script:F.PeerRows -Own $script:F.OwnOld)
        foreach ($b in 0, 3, 7) { (Invoke-Part -Slices 8 -Index $b) | Should -Be (Get-PartExpected -Slices 8 -Index $b) -Because "part $b" }
        foreach ($rq in $script:Requests) { $rq.Bytes | Should -BeLessThan $script:Cap }
        foreach ($kq in $script:KeyQueries) { $kq | Should -BeLessThan $script:Cap }
        @($script:Info | Where-Object { $_ -match "'_deviceTierOwn' snapshot: 500000 row\(s\) inlined" -or $_ -match "'_deviceTierOwn' bucket \d+/\d+: 500000/500000" }).Count | Should -Be 0 -Because 'the whole text is never built'
    }
}
