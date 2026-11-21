#Requires -Version 7.0
<#
    THE DRIFT RULE OF CHECK (b) JUDGES BY WHEN DEFENDER FIRST SAW THE CVE ON THE DEVICE (2026-11-20, priority 1 --
    engine/data-health/_shared/SI-DataHealth.ps1 Compare-SIDataHealthVulnerabilities, SI-DataHealthStore.ps1
    Get-SIDataHealthRaNewerFindingsSql, SI-DataHealthRun.ps1).

    Live 2026-11-19 (one install): Device_Missing_CVEs_Detailed judged collection 49 with 12,288 "missing" against 3,873
    allowed. The missing ones were a browser CVE batch (Chrome + Firefox) Defender attached to the devices AFTER collection
    49; collection 50 holds every one of them. The rule counted a missing CVE as drift only by its PUBLICATION date, and a
    batch can be published before Defender attaches it to a device.

    What these tests keep true (offline):
      * a missing CVE Defender FIRST SAW on the device after the collection is drift -- whatever its publication date;
      * a missing CVE Defender first saw BEFORE the collection is a real miss -- even when its publication is later;
      * no first sighting on Defender's answer: the first sighting a NEWER collection stored (SourceFirstDetected) is used;
      * a missing CVE a NEWER complete collection already holds on that device is drift;
      * neither known: the publication date decides, as before (after = drift, before = miss);
      * the newer collection's read is best effort: when it fails the check still runs, by first sighting / publication;
      * the margin and threshold are unchanged.
    pwsh 7.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\data-health\_shared\SI-DataHealth.ps1')
    . (Join-Path $script:SIRoot 'engine\data-health\_shared\SI-DataHealthStore.ps1')
    . (Join-Path $script:SIRoot 'engine\data-health\_shared\SI-DataHealthRun.ps1')
    $script:Quiet = { param($l, $m) }
    $script:Now = [datetime]::new(2026, 11, 19, 3, 17, 0, [DateTimeKind]::Utc)
    $script:Coll = [datetime]::new(2026, 11, 17, 22, 58, 0, [DateTimeKind]::Utc)
    $script:Asset = @([pscustomobject]@{ MdeId = 'm1'; Name = 'pc1' })
    $script:Stored = @([pscustomobject]@{ MdeId = 'm1'; Report = 'R'; Cve = 'CVE-2020-0001' })
    function script:D([string]$Cve, $Published, $FirstSeen = $null) {
        [pscustomobject]@{ Cve = $Cve; LastModified = $Published; Published = $Published; FirstSeen = $FirstSeen }
    }
    function script:Cmp([object[]]$Items, [object[]]$Newer = @()) {
        $def = @{ 'm1' = @(@(D 'CVE-2020-0001' $script:Coll.AddDays(-400)) + @($Items)) }
        Compare-SIDataHealthVulnerabilities -Assets $script:Asset -Defender $def -Stored $script:Stored -CollectionTime $script:Coll -Newer $Newer
    }
}

Describe 'drift by first sighting on the device' {
    It 'first seen AFTER the collection = drift, though published before it (the browser batch)' {
        $c = Cmp @(D 'CVE-2026-1001' $script:Coll.AddDays(-2) $script:Coll.AddHours(4))
        $rp = @($c.Reports)[0]
        $rp.Missing | Should -Be 1; $rp.NewSince | Should -Be 1; $rp.Drift | Should -Be 1
        $c.Source.Missing | Should -Be 1; $c.Source.Drift | Should -Be 1
    }
    It 'first seen BEFORE the collection = a real miss, though published after it' {
        $c = Cmp @(D 'CVE-2026-1002' $script:Coll.AddHours(3) $script:Coll.AddDays(-3))
        $rp = @($c.Reports)[0]
        $rp.Missing | Should -Be 1; $rp.Drift | Should -Be 0
        $c.Source.Drift | Should -Be 0
        @($c.Problems | Where-Object { $_.Problem -match 'are not in any report$' }).Count | Should -Be 1
    }
    It 'no first sighting from Defender: the newer collection''s stored first sighting is used' {
        $after = Cmp @(D 'CVE-2026-1003' $script:Coll.AddDays(-2)) @([pscustomobject]@{ MdeId = 'M1'; Cve = 'cve-2026-1003'; FirstSeen = $script:Coll.AddHours(5) })
        @($after.Reports)[0].Drift | Should -Be 1
        # a newer collection holding it is drift on its own, whatever its first sighting
        $held = Cmp @(D 'CVE-2026-1004' $script:Coll.AddDays(-2)) @([pscustomobject]@{ MdeId = 'm1'; Cve = 'CVE-2026-1004'; FirstSeen = $script:Coll.AddDays(-5) })
        @($held.Reports)[0].Drift | Should -Be 1
    }
}

Describe 'drift by a newer complete collection' {
    It 'a missing CVE a newer collection already holds on that device is drift (no dates at all)' {
        $c = Cmp @([pscustomobject]@{ Cve = 'CVE-2026-2001' }) @([pscustomobject]@{ MdeId = 'm1'; Cve = 'CVE-2026-2001'; FirstSeen = $null })
        @($c.Reports)[0].Drift | Should -Be 1; $c.Source.Drift | Should -Be 1
    }
    It 'held for ANOTHER device in the newer collection is not drift for this one' {
        $c = Cmp @(D 'CVE-2026-2002' $script:Coll.AddDays(-30)) @([pscustomobject]@{ MdeId = 'm2'; Cve = 'CVE-2026-2002'; FirstSeen = $script:Coll.AddHours(1) })
        @($c.Reports)[0].Drift | Should -Be 0
    }
}

Describe 'the publication date is the fallback, unchanged' {
    It 'no first sighting, no newer collection: published after = drift, published before = miss' {
        @((Cmp @(D 'CVE-2026-3001' $script:Coll.AddHours(2))).Reports)[0].Drift | Should -Be 1
        @((Cmp @(D 'CVE-2026-3002' $script:Coll.AddDays(-2))).Reports)[0].Drift | Should -Be 0
        @((Cmp @([pscustomobject]@{ Cve = 'CVE-2026-3003' })).Reports)[0].Drift | Should -Be 0 -Because 'no date at all and no newer collection = a real miss'
    }
}

Describe 'the cycle reads the newer collection and judges by it' {
    BeforeAll {
        $script:Ids = @(1..40 | ForEach-Object { 'mde{0:000}' -f $_ })
        $script:Cycle = {
            param([scriptblock]$NewerAnswer)
            $ids = $script:Ids; $coll = $script:Coll
            $stored = @(foreach ($id in $ids) { foreach ($k in 1..10) { @{ MdeId = $id; Report = 'Device_Missing_CVEs_Detailed'; Cve = ('CVE-2020-{0}{1:00}' -f $id.Substring(3), $k) } } })
            $na = $NewerAnswer
            $inv = {
                param($s, $p, $m)
                if ($s -match 'AS HasTables') { return , @(@{ HasTables = 0 }) }
                if ($s -match 'GROUP BY x\.MdeId') { return , @($ids | ForEach-Object { @{ CollectionId = 49; CollectionTime = $coll; MdeId = $_; Name = $_ } }) }
                if ($s -match 'INSERT @ids') { return , $stored }
                if ($s -match 'NewerCollectionId') { return , @(& $na $p) }
                , @()
            }.GetNewClosure()
            # every device: its 10 stored CVEs + 5 browser CVEs published BEFORE the collection, attached by Defender after it
            $def = { param($MdeIds) $o = @{}; foreach ($i in $MdeIds) { $d = $i.Substring(3)
                    $o[$i] = @(@(1..10 | ForEach-Object { [pscustomobject]@{ Cve = ('CVE-2020-{0}{1:00}' -f $d, $_); LastModified = $coll.AddDays(-400); Published = $coll.AddDays(-400) } }) +
                               @(1..5 | ForEach-Object { [pscustomobject]@{ Cve = ('CVE-2026-{0}{1:00}' -f $d, $_); LastModified = $coll.AddDays(-400); Published = $coll.AddDays(-1) } })) }; $o }.GetNewClosure()
            Invoke-SIDataHealthCycle -Sources @{} -Defender $def -Invoke $inv -NowUtc $script:Now -Log $script:Quiet -Seed 1
        }
        $script:Rep = { param($r) @($r.Results | Where-Object { $_.Kind -eq 'report' -and $_.Name -eq 'Device_Missing_CVEs_Detailed' })[0] }
    }
    It 'the newer collection holds the batch: drift, the report stays ok and says so (the margin unchanged)' {
        $r = & $script:Cycle { param($p) foreach ($i in @($p.MdeIds | ConvertFrom-Json)) { foreach ($k in 1..5) { @{ MdeId = $i; Cve = ('CVE-2026-{0}{1:00}' -f $i.Substring(3), $k); FirstSeen = $script:Coll.AddHours(4); NewerCollectionId = 50 } } } }
        $rep = & $script:Rep $r
        $rep.Missing | Should -Be 200; $rep.Drift | Should -Be 200
        $rep.Allowed | Should -Be 18 -Because 'the margin is unchanged: 3 % of 600'
        $rep.Verdict | Should -Be 'ok'
        $rep.Reason | Should -Be '200 new on the device after the collection -- drift'
    }
    It 'no newer collection (or its read fails): judged by the publication -- the batch published before stays a miss' {
        $none = & $script:Cycle { param($p) }
        (& $script:Rep $none).Verdict | Should -Be 'anomalous'
        $fails = & $script:Cycle { param($p) throw 'the database said no' }
        $rep = & $script:Rep $fails
        $rep.Verdict | Should -Be 'anomalous' -Because 'a failed newer read can only call FEWER things drift, never more'
        $rep.Drift | Should -Be 0
    }
    It 'the newer collection''s read: the newest COMPLETE Detailed collection made AFTER the judged one, its first sightings, the same device record' {
        $q = Get-SIDataHealthRaNewerFindingsSql
        $q | Should -Match ([regex]::Escape("Kind = N'Detailed' AND Status = N'Complete' AND @jt IS NOT NULL AND CollectionTime > @jt ORDER BY CollectionTime DESC"))
        $q | Should -Match 'MIN\(f\.SourceFirstDetected\) AS FirstSeen'
        $q | Should -Match ([regex]::Escape((Get-SIDataHealthMdeRecordApply)))
        $q | Should -Match 'f\.CarriedFrom IS NULL'
        $q | Should -Not -Match 'INSERT @ids' -Because 'a different statement from the stored-findings read'
        $t = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\data-health\_shared\SI-DataHealthRun.ps1'))
        $t | Should -Match ([regex]::Escape('-CollectionTime $collAt -Newer @($nw.Rows)'))
        $t.IndexOf('$nw = Read-SIDataHealthNewerFindings') | Should -BeGreaterThan $t.IndexOf('$def = & $Defender $ids') -Because 'read after the Defender reads, so a collection that completed meanwhile counts'
    }
    It 'Defender''s own first sighting is passed on when its answer carries one' {
        $t = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\data-health\Invoke-SIDataHealth.ps1'))
        $t | Should -Match ([regex]::Escape("foreach (`$fn in 'firstSeenTimestamp', 'firstSeen', 'firstDetected')"))
        $t | Should -Match ([regex]::Escape('Published = $_.publishedOn; FirstSeen = $fs'))
    }
}
