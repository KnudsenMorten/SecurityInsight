#Requires -Version 5.1
<#
    SI v3 Phase 7 -- the narrow trend table (§60.4b) and the weekly rate view (§47.5c).

    🔑 PHASE 7 IS TWO CAPABILITIES, NOT A DASHBOARD PROGRAMME. §47.5c checked before building and found
    the dashboards, the score timeline, TopMovers, PeriodComparison, SnapshotDiff's Closed/ClosedCount
    and AgingAnalysis already written. What was missing was long-term history and rate-over-time.

    🔴 THE ASSERTION THAT CARRIES THE MOST WEIGHT is that the weekly view is a SET DIFFERENCE, not a
    sum of snapshot diffs. Summing double-counts a flapping finding -- closed Tuesday, reopened
    Wednesday, closed Friday sums to TWO while the estate ended the week having closed ONE. A future
    edit reaching for `bin(TimeGenerated, 7d)` would look simpler and be wrong.
#>

BeforeAll {
    $root = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
    $script:SIRootDir = (Resolve-Path (Join-Path $root '..')).Path
    . (Join-Path $script:SIRootDir 'engine\asset-trend\_shared\SI-TrendRollup.ps1')
    # #416 the sharded gate runs suites in another order: a Write-SIInfo / Write-SIWarn another suite left behind (a no-op,
    # or one writing to the host) must not swallow the report this suite reads -- these two write where the test reads
    function Write-SIInfo { param([string]$Message) Write-Host $Message }
    function Write-SIWarn { param([string]$Message) Write-Warning $Message }
}

Describe 'the rollup is narrow, which is what makes multi-year retention affordable' {
    It 'emits a LONG shape -- one row per dimension value, not a wide row' {
        # §60.4b's retention argument rests entirely on this table staying narrow. A wide shape would
        # also make every new dimension a schema change, and schema changes on ~30 customers are the
        # thing SCHEMA-1 exists to avoid.
        $r = New-SITrendRow -CollectionTime ([datetime]::UtcNow) -RunId 'r1' -Dimension 'severity' -DimensionValue 'High' -Findings 12 -Assets 5 -ScoreTotal 340.5
        $names = @($r.PSObject.Properties.Name)
        $names | Should -Contain 'Dimension'
        $names | Should -Contain 'DimensionValue'
        # Deliberately small. If this grows past a handful the narrowness claim needs re-examining.
        $names.Count | Should -BeLessThan 12
    }
    It 'stamps SolutionVersion, because v2.2 and v3 share this workspace' {
        $r = New-SITrendRow -CollectionTime ([datetime]::UtcNow) -RunId 'r1' -Dimension 'global' -DimensionValue 'all' -SolutionVersion '2.2.460'
        $r.SolutionVersion | Should -BeExactly '2.2.460'
    }
    It 'declares a retention that outlives the profile tables' {
        # 🔒 Operator 2026-08-31: ONE YEAR, not seven -- "i dont want to save longer". A narrow table
        # makes multi-year retention cheap, but cheap is not the same as wanted. What the assertion
        # has to protect is the RELATIONSHIP, not the old number: this table must outlive the profile
        # tables (the internal workspace defaults to 90) and cover a full year-over-year comparison.
        Get-SITrendRetentionDays | Should -BeGreaterOrEqual 365
    }
    It 'declares a retention AZURE WILL ACTUALLY ACCEPT' {
        # 🪤 This read 2555 (7 x 365) and Azure rejects it outright:
        #   InvalidParameter -- "The value beyond two years is restricted to full years. Allowed
        #   values are: [4-730], 1095, 1460, 1826, 2191, 2556, 2922, 3288, 3653, 4018, 4383"
        # The engine printed that number as an instruction to the customer, so the instruction could
        # not be followed. It was reviewable, plausible, and never once executed. A number that is
        # only ever printed is not a verified number -- pin it to the allowed set, BOTH halves of it,
        # so a future move in either direction still lands on a legal value.
        $days     = Get-SITrendRetentionDays
        $fullYear = @(1095, 1460, 1826, 2191, 2556, 2922, 3288, 3653, 4018, 4383)
        $legal    = ($days -ge 4 -and $days -le 730) -or ($fullYear -contains $days)
        $legal | Should -BeTrue -Because "$days is not an Azure-accepted total retention value"
    }
    It 'keeps interactive retention within the 730-day cap and never above the total' {
        # Two settings, not one. Asking for the full total as INTERACTIVE is also rejected once the
        # total passes 730, so a single-number instruction is wrong twice over. At 365 the two are
        # equal and there is no archive tier -- that is a valid state, not a missing one.
        $i = Get-SITrendInteractiveRetentionDays
        $i | Should -BeGreaterThan 3
        $i | Should -BeLessOrEqual 730
        $i | Should -BeLessOrEqual (Get-SITrendRetentionDays)
    }
    It 'prints a RUNNABLE command, not a bare number' {
        # The failure this whole cluster came from: the operator ran the printed instruction and it
        # errored. Assert the cmdlet and both parameters actually appear in the output the user sees.
        $src = Get-Content (Join-Path $script:SIRootDir 'engine\asset-trend\Invoke-SITrend.ps1') -Raw
        $src | Should -Match 'Update-AzOperationalInsightsTable'
        $src | Should -Match '-RetentionInDays'
        $src | Should -Match '-TotalRetentionInDays'
    }
    It 'rolls up global, severity, tier and domain' {
        $dims = @(ConvertTo-SITrendRollup -Rows @([pscustomobject]@{ SecuritySeverity = 'High'; CriticalityTier = '0'; SecurityDomain = 'Endpoint'; SI_ExemptionId = ''; RiskScoreTotal = 1; ImpactedAssetIds = '["a"]'; AssetId = ''; SI_AssetId = '' }) | ForEach-Object { $_.Dimension })
        foreach ($d in @('global','severity','tier','domain')) { $dims | Should -Contain $d }
    }
    It 'filters to the snapshot BEFORE summarising -- finding #83' {
        # arg_max then filter is not the same query as filter then arg_max, and both editions write
        # these tables. This has now bitten in four places.
        $k = Get-SITrendRollupKql
        $snapPos = $k.IndexOf('let snap = toscalar(')
        $curPos  = $k.IndexOf('let cur = src | where CollectionTime == snap')
        $snapPos | Should -BeGreaterThan -1
        $curPos  | Should -BeGreaterThan $snapPos
    }
    It 'reads every source column through column_ifexists' {
        # The RA grains do not carry identical columns, and a plain project against a missing one fails
        # the WHOLE query rather than degrading.
        $k = Get-SITrendRollupKql
        foreach ($c in @('RiskScoreTotal','SecuritySeverity','CriticalityTier','SecurityDomain','SI_ExemptionId','ImpactedAssetIds','AssetId','SI_AssetId')) {
            $k | Should -BeLike ('*column_ifexists("{0}"*' -f $c)
        }
    }
}

Describe 'the weekly rate is a SET DIFFERENCE, not a sum of diffs' {
    It 'compares the FIRST snapshot of the week against the LAST' {
        # 🔴 The definition §47.5c argues for at length: closed-in-week = present in the first snapshot
        # and absent from the last. Anything else counts flapping as throughput.
        $k = Get-SIWeeklyRateKql
        $k | Should -Match 'FirstSnap\s*=\s*min\(CollectionTime\)'
        $k | Should -Match 'LastSnap\s*=\s*max\(CollectionTime\)'
        # only the first and last snapshot's rows reach the set difference -- anything in between is flapping
        $k | Should -Match 'where CollectionTime == FirstSnap or CollectionTime == LastSnap'
        $w = [datetime]'2026-09-20T00:00:00Z'
        $rows = @(
            [pscustomobject]@{ Week = $w; RowKind = 'row'; Snapshots = 3; IsFirst = 1; IsLast = 0; Key = 'K1'; ImpactedAssetIds = '["a"]' }
            [pscustomobject]@{ Week = $w; RowKind = 'row'; Snapshots = 3; IsFirst = 1; IsLast = 0; Key = 'K0'; ImpactedAssetIds = '["a"]' }
            [pscustomobject]@{ Week = $w; RowKind = 'row'; Snapshots = 3; IsFirst = 0; IsLast = 1; Key = 'K0'; ImpactedAssetIds = '["a"]' })
        $r = @(ConvertTo-SIWeeklyRate -Rows $rows)[0]
        $r.Closed | Should -Be 1
        $r.Opened | Should -Be 0
    }
    It 'never sums snapshot-to-snapshot diffs' {
        # The naive implementation. It looks simpler and double-counts a finding that flaps.
        $k = Get-SIWeeklyRateKql
        $k | Should -Not -Match 'bin\(TimeGenerated'
        $k | Should -Not -Match 'sum\(Closed'
    }
    It 'emits EVERY week in the window, so a week with no snapshot still has a row' {
        # Without the range join, a missed week simply vanishes from the chart -- which reads as
        # continuity across a gap that was never measured.
        $k = Get-SIWeeklyRateKql
        $k | Should -Match 'range W from startofweek'
    }
    It 'marks a snapshot-less week as a GAP rather than as zero closed' {
        # 🔴 C14's failure mode wearing a chart: "we closed nothing" and "we did not measure" are
        # completely different conversations and produce the same number otherwise.
        $r = @(ConvertTo-SIWeeklyRate -Rows @([pscustomobject]@{ Week = '2026-09-13T00:00:00Z'; RowKind = 'week'; Snapshots = 0 }))[0]
        $r.HasData | Should -BeFalse
        $r.Snapshots | Should -Be 0
        $r.Opened | Should -BeNullOrEmpty
        $r.Closed | Should -BeNullOrEmpty
        $r.ComparedAssets | Should -BeNullOrEmpty
    }
    It 'keys on ConfigurationId -- the FINDING, not the asset' {
        # Audit #25 exists because those two were confused once already.
        Get-SIWeeklyRateKql | Should -BeLike '*ConfigurationId*'
    }
    It 'honours the requested window' {
        (Get-SIWeeklyRateKql -Weeks 4) | Should -Match 'let lookback = 4 \* 7d'
    }
}

Describe 'SAME SCOPE ALWAYS -- one workspace, two editions' {
    It 'pins the edition in BOTH trend queries' {
        # 🔒 Operator 2026-08-31: "same scope always so we can track progress" / "this la has both
        # v3 and v2.2 runs" / "version is in rows".
        # 🔴 The two editions run DIFFERENT report sets, so a comparison spanning them measures
        # WHICH EDITION RAN rather than what changed. Both queries must pin it, not just the weekly
        # one -- the rollup feeds the same charts.
        Get-SIWeeklyRateKql   | Should -Match 'SolutionVersion.*endswith "\+v3"'
        Get-SITrendRollupKql  | Should -Match 'SolutionVersion.*endswith "\+v3"'
    }
    It 'filters BEFORE the snapshot is chosen, not after' {
        # 🪤 Finding #83's whole point, in its fifth place. `arg_max` over the raw table frequently
        # selects the other edition's snapshot; filtering afterwards then returns nothing and looks
        # like an empty estate rather than a mis-selected snapshot.
        $k = Get-SITrendRollupKql
        $k.IndexOf('endswith "+v3"') | Should -BeLessThan $k.IndexOf('let snap = toscalar(')
    }
    It 'the marker is a SUFFIX so the VERSION file never has to move' {
        # The VERSION file is the customer-sync contract -- customers pull on a VERSION check, so
        # bumping it for v3 work would ship v3 to ~30 customers. The stamped VALUE is data in an
        # existing column: no schema change, no ingest wait, no per-customer approval.
        Get-SITrendEditionFilter | Should -Match 'endswith'
        Get-SITrendEditionFilter | Should -Not -Match '=='
    }
    It 'the RA engine actually stamps the marker it is filtered on' {
        # 🔴 ASSERT THE WIRING, NOT JUST THE READER. A filter for a marker nothing writes returns
        # zero rows forever and renders as "no history yet" -- the exact shape of the five
        # declared-but-never-wired defects this codebase has already paid for.
        $ra = Get-Content (Join-Path $script:SIRootDir 'engine\risk-analysis\Invoke-RiskAnalysis.ps1') -Raw
        $ra | Should -Match "\{0\}\+v3"
        # ...and only on v3, keyed off a file that exists nowhere in a v2.2 install
        $ra | Should -Match 'SI-V3Snapshot\.ps1'
    }
}

Describe 'the set difference compares LIKE WITH LIKE, or reports nothing' {
    It 'restricts the comparison to assets BOTH snapshots examined' {
        # 🪤 THE DEFECT THIS EXISTS FOR, and it was found only by running it against real data:
        # June and July reported ~1,250-1,550 findings OPENED per week on an estate that holds 593
        # findings in total. The arithmetic was right. The inputs were not comparable -- the week's
        # first snapshot had examined 19 assets and its last 64, so every finding on the 45 assets
        # nobody looked at the first time counted as newly opened. Restricting to the 14 assets in
        # both turned that week into 18 opened / 29 closed.
        $w = [datetime]'2026-09-20T00:00:00Z'
        $rows = @(
            # the first snapshot examined only asset a; the last examined a and b
            [pscustomobject]@{ Week = $w; RowKind = 'row'; Snapshots = 2; IsFirst = 1; IsLast = 0; Key = 'K1'; ImpactedAssetIds = '["a"]' }
            [pscustomobject]@{ Week = $w; RowKind = 'row'; Snapshots = 2; IsFirst = 0; IsLast = 1; Key = 'K1'; ImpactedAssetIds = '["a","b"]' }
            [pscustomobject]@{ Week = $w; RowKind = 'row'; Snapshots = 2; IsFirst = 0; IsLast = 1; Key = 'K2'; ImpactedAssetIds = '["b"]' })
        $r = @(ConvertTo-SIWeeklyRate -Rows $rows)[0]
        # b was not looked at the first time, so neither of its findings counts as opened
        $r.Opened | Should -Be 0
        $r.ComparedAssets | Should -Be 1
        $r.ObservedAssets | Should -Be 2
    }
    It 'emits the denominator alongside the counts' {
        # 🔑 The quiet half of the same defect. The comparable population is routinely a FRACTION
        # (11-14 of 58-65 measured live), and a throughput figure over a fifth of the estate that
        # reads as the whole is wrong in the same direction, just less visibly.
        $r = @(ConvertTo-SIWeeklyRate -Rows @([pscustomobject]@{ Week = '2026-09-20T00:00:00Z'; RowKind = 'row'; Snapshots = 2; IsFirst = 1; IsLast = 1; Key = 'K'; AssetId = 'a' }))[0]
        (@($r.PSObject.Properties.Name) -join ',') | Should -Be 'Week,HasData,Snapshots,Opened,Closed,Net,ComparedAssets,ObservedAssets'
    }
    It 'reports UNKNOWN, not zero, when nothing is comparable' {
        # A week whose two snapshots share no asset yields no evidence either way. Publishing 0/0
        # would assert a quiet week on the strength of having measured two different things --
        # "absence is not remediation" in its most literal form.
        $w = '2026-09-20T00:00:00Z'
        $r = @(ConvertTo-SIWeeklyRate -Rows @(
            [pscustomobject]@{ Week = $w; RowKind = 'row'; Snapshots = 2; IsFirst = 1; IsLast = 0; Key = 'K'; AssetId = 'a' }
            [pscustomobject]@{ Week = $w; RowKind = 'row'; Snapshots = 2; IsFirst = 0; IsLast = 1; Key = 'K'; AssetId = 'b' }))[0]
        $r.HasData | Should -BeTrue
        $r.ComparedAssets | Should -Be 0
        $r.Opened | Should -BeNullOrEmpty
        $r.Closed | Should -BeNullOrEmpty
        $r.Net | Should -BeNullOrEmpty
    }
    It 'writes the denominator even for a week with nothing comparable' {
        # That week is precisely the one a reader must be able to identify, so the denominator rows
        # are written even though the counts are not.
        $rows = @(New-SITrendWeeklyRows -CollectionTime ([datetime]'2026-08-31') -RunId 'r' `
                    -Week ([datetime]'2026-08-24') -HasData $true -Snapshots 9 `
                    -ComparedAssets 0 -ObservedAssets 51)
        $dims = @($rows | ForEach-Object { $_.Dimension })
        $dims | Should -Contain 'weekly-compared-assets'
        $dims | Should -Contain 'weekly-observed-assets'
        # ...and NOT the counts, because there are none to state
        $dims | Should -Not -Contain 'weekly-opened'
        $dims | Should -Not -Contain 'weekly-closed'
    }
    It 'a genuinely unmeasured week carries no denominator at all' {
        # The three states must stay distinguishable end to end: no snapshot / measured but not
        # comparable / comparable. The reader keys "was this measured" off the denominator row.
        $rows = @(New-SITrendWeeklyRows -CollectionTime ([datetime]'2026-08-31') -RunId 'r' `
                    -Week ([datetime]'2026-08-17') -HasData $false -Snapshots 0)
        $dims = @($rows | ForEach-Object { $_.Dimension })
        $dims | Should -Be @('weekly-snapshots')
    }
}

Describe 'the GUI reads stored rows, because it cannot recompute them' {
    It 'assembles the window with a per-key arg_max, not the latest snapshot' {
        # 🔴 The weekly rows can only be recomputed while their week is inside the RA source's
        # ~90-day retention (measured: RA is 90/90, the trend table is 365/365). Reading the newest
        # snapshot alone returns ~13 weeks and silently truncates a year to a quarter.
        $k = Get-SITrendHistoryKql
        $k | Should -Match 'arg_max\(CollectionTime'
        $k | Should -Match 'by Dimension, DimensionValue'
    }
    It 'defaults to the retention window and honours a shorter one' {
        (Get-SITrendHistoryKql) | Should -Match 'ago\(365d\)'
        (Get-SITrendHistoryKql -Days 90) | Should -Match 'ago\(90d\)'
    }
}

Describe 'the gap branch survives contact with Log Analytics types' {
    It 'never casts a Log Analytics bool with [bool]' {
        # 🪤 LA returns a KQL bool as the STRING "False", and in PS 5.1 EVERY non-empty string casts
        # to $true -- so `[bool]$r.HasData` is $true for a week with no data. The gap branch could
        # therefore never be reached, and the moment real gaps appeared it announced twelve
        # zero-snapshot weeks as "only one run this week". Third defect found in this one branch,
        # after the {2,>8} format string and the leaked variable below: the branch that exists for
        # the important case is the one no green run exercises.
        # 🪤 Comments must be stripped first -- the trap notes ABOVE the fix quote the broken code
        # verbatim, so a raw-text assertion matches the explanation and fails on a correct file.
        $code = (Get-Content (Join-Path $script:SIRootDir 'engine\asset-trend\Invoke-SITrend.ps1') |
                 Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
        $code | Should -Not -Match '\[bool\]\$r\.HasData'
        # Snapshots is a NUMBER and is the authority for "did this week run at all".
        $code | Should -Match '\$wSnaps\s*=\s*if \(\$null -eq \$r\.Snapshots\)'
    }
    It 'the display loop reads its own row, not a variable left over from another loop' {
        # 🪤 `$snaps` was assigned in the PERSISTENCE loop and read in the DISPLAY loop, so every
        # printed row showed the LAST value from the other loop -- 13 weeks all reporting "1".
        # PowerShell scopes both loops to the same function body, so nothing failed; the numbers were
        # simply all the same and all wrong.
        # Comments stripped for the same reason as above: the trap note names the old variable.
        $code = (Get-Content (Join-Path $script:SIRootDir 'engine\asset-trend\Invoke-SITrend.ps1') |
                 Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
        # The display block is everything after the -ShowWeeklyRate guard.
        $display = $code.Substring($code.IndexOf('if ($ShowWeeklyRate -and $weeklyOk)'))
        # `$snaps` belongs to the persistence loop only; `$wSnaps` is the display loop's own.
        $display | Should -Not -Match '\$snaps\b'
        $display | Should -Match '\$wSnaps'
    }
    It 'names the THREE reasons a week has no throughput, because they have different fixes' {
        # no snapshot -> run it; one snapshot -> run it more often; nothing shared -> make the runs
        # cover the same scope. One message for all three sends the reader to fix the wrong thing.
        $src = Get-Content (Join-Path $script:SIRootDir 'engine\asset-trend\Invoke-SITrend.ps1') -Raw
        $src | Should -Match 'NO SNAPSHOT THIS WEEK'
        $src | Should -Match 'ONLY ONE RUN THIS WEEK'
        $src | Should -Match 'NOTHING COMPARABLE'
    }
    It 'one snapshot is UNKNOWN, never a quiet week' {
        # A week with a single run has first == last, so the set difference is trivially empty and
        # would publish a confident 0/0 on the strength of having looked exactly once.
        $r = @(ConvertTo-SIWeeklyRate -Rows @([pscustomobject]@{ Week = '2026-09-20T00:00:00Z'; RowKind = 'row'; Snapshots = 1; IsFirst = 1; IsLast = 1; Key = 'K'; AssetId = 'a' }))[0]
        $r.ComparedAssets | Should -Be 1
        $r.Opened | Should -BeNullOrEmpty
        $r.Closed | Should -BeNullOrEmpty
    }
}

Describe 'the gap-week line can actually be formatted' {
    It 'formats a no-snapshot week without throwing' {
        # 🪤 THIS LINE READ `{2,>8}` -- `>` is not valid .NET alignment syntax, so the branch would have
        # thrown a FormatException the FIRST time a week genuinely had no snapshot. The branch that
        # exists solely to handle the important case was the one that could not run, and any estate
        # with unbroken runs keeps that hidden indefinitely. Same species as every "declared but never
        # exercised" defect in this codebase, and only a format check catches it before a customer does.
        $line = Get-Content (Join-Path $script:SIRootDir 'engine\asset-trend\Invoke-SITrend.ps1') |
                Where-Object { $_ -match 'NO SNAPSHOT THIS WEEK' } | Select-Object -First 1
        $line | Should -Not -BeNullOrEmpty
        $line | Should -Not -Match '\{\d+,>'
        # And prove the real format string binds, rather than only that the bad one is gone.
        { "   {0,-12} {1,9} {2,8} {3,8} {4,6} -- NO SNAPSHOT" -f '2026-08-31', 0, '-', '-', '-' } | Should -Not -Throw
    }
}

Describe 'an empty source is reported, not published as a zero' {
    It 'says an empty snapshot is not the same as an estate with no findings' {
        # A trend point of zero, published because RA had not run, is a lie the chart cannot recover
        # from -- and nothing downstream can tell it from a genuinely clean estate.
        $out = Write-SITrendReport -Rows @() 3>&1 | Out-String -Width 4096
        $out | Should -Match 'NOT the same'
        $out | Should -Match 'Risk Analysis has run'
    }
    It 'reports the row count, because narrowness is the assumption retention rests on' {
        $rows = @(
            (New-SITrendRow -CollectionTime ([datetime]::UtcNow) -RunId 'r' -Dimension 'global'   -DimensionValue 'all'  -Findings 10 -Assets 4 -ScoreTotal 99)
            (New-SITrendRow -CollectionTime ([datetime]::UtcNow) -RunId 'r' -Dimension 'severity' -DimensionValue 'High' -Findings 6  -Assets 3 -ScoreTotal 70)
        )
        $out = Write-SITrendReport -Rows $rows 6>&1 | Out-String -Width 4096
        $out | Should -Match 'stays narrow by design'
        # printed before the weekly rows are added: it counts the ROLLUP rows and says so (it said "this run")
        $out | Should -Match '2 rollup row\(s\)'
        $out | Should -Not -Match 'row\(s\) this run'
        $out | Should -Match 'severity\s+1 value\(s\): High=6' -Because 'the value list is plain ASCII'
    }
}

Describe '#303 -- "assets" counts ASSETS, not finding types' {
    BeforeAll {
        # 🔑 THE FIXTURE THE DEFECT NEEDS. Asset "dc01" carries THREE finding types; finding type
        # "CVE" spans THREE assets (one Summary row, its asset list in ImpactedAssetIds). Distinct
        # finding types (the old dcount(ConfigurationId)) and distinct assets differ in BOTH directions.
        $mk = {
            param($cid, $sev, $tier, $dom, $ids, $asset, $ex, $score)
            [pscustomobject]@{ ConfigurationId = $cid; SecuritySeverity = $sev; CriticalityTier = $tier; SecurityDomain = $dom
                               SI_ExemptionId = $ex; RiskScoreTotal = $score; ImpactedAssetIds = $ids; AssetId = $asset; SI_AssetId = '' }
        }
        $script:Fixture = @(
            (& $mk 'CVE'           'High'   '0' 'Endpoint' '["dc01","dc02","srv03"]' 'dc01' ''   10)
            (& $mk 'BITLOCKER-001' 'Medium' '0' 'Endpoint' '["dc01"]'                'dc01' ''   4)
            (& $mk 'LAPS-001'      'Medium' '0' 'Endpoint' '["dc02"]'                'dc02' ''   3)
            (& $mk 'IDENTITY-MFA'  'High'   '0' 'Identity' 'dc01'                    'dc01' ''   6)   # #82: a one-element list as a bare string
            (& $mk 'AZ-REC-7'      'Low'    '1' 'Azure'    ''                        'vm09' ''   1)   # no list: the scalar is the asset
            (& $mk 'AZ-REC-8'      'Low'    '1' 'Azure'    '["vm09","VM10"]'         'vm09' '14' 2)   # exempted
        )
        $script:Roll = ConvertTo-SITrendRollup -Rows $script:Fixture
        $script:Get = { param($d, $v) @($script:Roll | Where-Object { $_.Dimension -eq $d -and $_.DimensionValue -eq $v })[0] }
    }
    It 'Tier-0 assets with findings = 3 assets from 4 finding types: the CVE row spans three, dc01 and dc02 carry several' {
        $t0 = & $script:Get 'tier' '0'
        $t0.Findings | Should -Be 4 -Because 'four finding types'
        $t0.Assets   | Should -Be 3 -Because 'dc01, dc02, srv03'
    }
    It 'one asset with several finding types counts ONCE' {
        $ep = & $script:Get 'domain' 'Endpoint'
        $ep.Findings | Should -Be 3
        $ep.Assets   | Should -Be 3
        (& $script:Get 'domain' 'Identity').Assets | Should -Be 1 -Because 'dc01 is one asset whatever it is wrong with'
        $hi = & $script:Get 'severity' 'High'
        $hi.Findings | Should -Be 2
        $hi.Assets   | Should -Be 3 -Because 'two finding types (CVE, IDENTITY-MFA), three assets'
    }
    It 'global counts each asset once, and the counted twin leaves the exempted row out' {
        $g = & $script:Get 'global' 'all'
        $g.Findings | Should -Be 6
        $g.Assets   | Should -Be 5 -Because 'dc01, dc02, srv03, vm09, VM10'
        $gc = & $script:Get 'global-counted' 'all'
        $gc.Findings | Should -Be 5
        $gc.Assets   | Should -Be 4 -Because 'VM10 is hit only by the exempted row'
        (& $script:Get 'global' 'all').ScoreTotal | Should -Be 26
    }
    It 'NEGATIVE: on a Tier-0 set where three finding types sit on ONE asset, the old count says 3 and the new one says 1' {
        $same = foreach ($c in 'A', 'B', 'C') {
            [pscustomobject]@{ ConfigurationId = $c; CriticalityTier = '0'; SecuritySeverity = 'High'; SecurityDomain = 'Endpoint'; SI_ExemptionId = ''; RiskScoreTotal = 1; ImpactedAssetIds = '["dc01"]'; AssetId = 'dc01'; SI_AssetId = '' }
        }
        @($same | ForEach-Object { $_.ConfigurationId } | Sort-Object -Unique).Count | Should -Be 3
        @(ConvertTo-SITrendRollup -Rows @($same) | Where-Object { $_.Dimension -eq 'tier' -and $_.DimensionValue -eq '0' })[0].Assets | Should -Be 1
    }
    It 'reads a row''s assets from its list first, then AssetId, then SI_AssetId -- never ConfigurationId' {
        @(Get-SITrendRowAssetIds -Row ([pscustomobject]@{ ImpactedAssetIds = '["a","b",""]'; AssetId = 'z'; ConfigurationId = 'CVE' })) -join ',' | Should -BeExactly 'a,b'
        @(Get-SITrendRowAssetIds -Row ([pscustomobject]@{ ImpactedAssetIds = '';            AssetId = 'z'; ConfigurationId = 'CVE' })) -join ',' | Should -BeExactly 'z'
        @(Get-SITrendRowAssetIds -Row ([pscustomobject]@{ AssetId = '';  SI_AssetId = 'y'; ConfigurationId = 'CVE' })) -join ',' | Should -BeExactly 'y'
        @(Get-SITrendRowAssetIds -Row ([pscustomobject]@{ ConfigurationId = 'CVE' })).Count | Should -Be 0
        @(Get-SITrendRowAssetIds -Row ([pscustomobject]@{ ImpactedAssetIds = @('p', 'q') })) -join ',' | Should -BeExactly 'p,q'
    }
    It 'the query no longer counts ConfigurationId, and the engine aggregates through ConvertTo-SITrendRollup (wiring)' {
        $k = Get-SITrendRollupKql
        $k | Should -Not -Match 'dcount\('
        $k | Should -Not -Match 'ConfigurationId'
        $src = Get-Content (Join-Path $script:SIRootDir 'engine\asset-trend\Invoke-SITrend.ps1') -Raw
        # #306: from the rows Risk Analysis passes, else the snapshot read from Log Analytics
        $src | Should -Match 'ConvertTo-SITrendRollup -Rows \$srcRows'
        # #639 lane 4: the snapshot read in parts (Read-SILaParts), each part added to the rollup -- never all held
        $src | Should -Match 'Read-SILaParts -WorkspaceId \$ws -Query \(Get-SITrendRollupKql'
        $src | Should -Match 'Add-SITrendRollupRows -State \$rollState -Rows \$partRows'
        $src | Should -Match 'Complete-SITrendRollup -State \$rollState'
    }
    It 'an empty snapshot rolls up to nothing, so the empty-source report still fires' {
        @(ConvertTo-SITrendRollup -Rows @()).Count | Should -Be 0
    }
}

Describe 'the weekly opened/closed compares EVERY affected asset, not one per row' {
    BeforeAll {
        # 🔒 Operator 2026-10-05. A Summary row stands for every asset in ImpactedAssetIds; its scalar
        # AssetId is ONE representative (#97). The old axis was that scalar, so a CVE on 3 assets counted
        # once. Fixture: a persistent finding BASE keeps assets a, b, c examined in every snapshot; the
        # CVE row appears on a, b, c in week N and is left on c only by the end of week N+1. Each row's
        # scalar AssetId is a single representative, as at the Summary grain.
        $wN  = '2026-09-13T00:00:00Z'
        $wN1 = '2026-09-20T00:00:00Z'
        $mk = { param($w, $first, $last, $key, $ids, $rep)
            [pscustomobject]@{ Week = $w; RowKind = 'row'; Snapshots = 2; IsFirst = $first; IsLast = $last; Key = $key; ImpactedAssetIds = $ids; AssetId = $rep; SI_AssetId = '' } }
        $script:WeeklyFixture = @(
            [pscustomobject]@{ Week = $wN;  RowKind = 'week'; Snapshots = 0 }
            [pscustomobject]@{ Week = $wN1; RowKind = 'week'; Snapshots = 0 }
            (& $mk $wN  1 0 'BASE' '["a","b","c"]' 'a')
            (& $mk $wN  0 1 'BASE' '["a","b","c"]' 'a')
            (& $mk $wN  0 1 'CVE'  '["a","b","c"]' 'a')
            (& $mk $wN1 1 0 'BASE' '["a","b","c"]' 'a')
            (& $mk $wN1 1 0 'CVE'  '["a","b","c"]' 'a')
            (& $mk $wN1 0 1 'BASE' '["a","b","c"]' 'a')
            (& $mk $wN1 0 1 'CVE'  'c'             'c')   # #82: a one-element list as a bare string
        )
        $script:Weekly = @(ConvertTo-SIWeeklyRate -Rows $script:WeeklyFixture)
    }
    It 'a CVE on 3 assets opened in week N counts 3 opened' {
        $script:Weekly.Count | Should -Be 2
        $script:Weekly[0].Opened | Should -Be 3
        $script:Weekly[0].Closed | Should -Be 0
    }
    It 'closed on 2 of them in week N+1 counts 2 closed, and 1 stays open' {
        $n1 = $script:Weekly[1]
        $n1.Closed | Should -Be 2
        $n1.Opened | Should -Be 0
        $n1.Net    | Should -Be -2
        # the one still open: the CVE pairs in the week's last snapshot
        $lastCve = @($script:WeeklyFixture | Where-Object { $_.Key -eq 'CVE' -and $_.Week -eq '2026-09-20T00:00:00Z' -and $_.IsLast -eq 1 })
        @($lastCve | ForEach-Object { Get-SITrendRowAssetIds -Row $_ }).Count | Should -Be 1
    }
    It 'the compared-assets count equals the distinct affected assets' {
        foreach ($w in $script:Weekly) {
            $w.ComparedAssets | Should -Be 3 -Because 'a, b, c were examined at the start and the end of the week'
            $w.ObservedAssets | Should -Be 3
        }
    }
    It 'the week key is the UTC week start, sorted' {
        $script:Weekly[0].Week.ToString('yyyy-MM-dd') | Should -Be '2026-09-13'
        $script:Weekly[1].Week.ToString('yyyy-MM-dd') | Should -Be '2026-09-20'
    }
    It 'the query returns the rows the asset rule needs, and the engine takes the difference through ConvertTo-SIWeeklyRate (wiring)' {
        $k = Get-SIWeeklyRateKql
        $k | Should -Match 'ImpactedAssetIds = tostring\(column_ifexists\("ImpactedAssetIds"'
        $k | Should -Match 'SI_AssetId'
        $k | Should -Match 'toint\(CollectionTime == FirstSnap\)'
        $src = (Get-Content (Join-Path $script:SIRootDir 'engine\asset-trend\Invoke-SITrend.ps1') | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
        # #639 lane 4: the weekly rows read in parts, each part added to the weekly state (Get-SITrendWeeklyRates)
        ([regex]::Matches($src, 'Get-SITrendWeeklyRates -Weeks')).Count | Should -Be 2 -Because 'both the stored rows and the printed table'
        $src | Should -Match 'Add-SIWeeklyRateRows -State \$wState -Rows \$partRows'
        $src | Should -Match 'Complete-SIWeeklyRate -State \$wState'
        $src | Should -Not -Match 'foreach \(\$r in @\(\$resp\.Results\)\) \{\s*\r?\n\s*# 🪤 NEVER'
    }
    It 'a row with no asset id is compared but never counted as an asset' {
        $w = '2026-09-20T00:00:00Z'
        $r = @(ConvertTo-SIWeeklyRate -Rows @(
            [pscustomobject]@{ Week = $w; RowKind = 'row'; Snapshots = 2; IsFirst = 1; IsLast = 1; Key = 'BASE'; ImpactedAssetIds = '["a"]' }
            [pscustomobject]@{ Week = $w; RowKind = 'row'; Snapshots = 2; IsFirst = 1; IsLast = 0; Key = 'TENANT-1'; ImpactedAssetIds = '' }
            [pscustomobject]@{ Week = $w; RowKind = 'row'; Snapshots = 2; IsFirst = 1; IsLast = 1; Key = 'TENANT-2'; ImpactedAssetIds = '' }))[0]
        $r.ComparedAssets | Should -Be 1
        $r.Closed | Should -Be 1
    }
}

Describe 'an empty dimension value is empty on both paths (the trend job and Risk Analysis'' own trend row)' {
    BeforeAll {
        $script:EmptyRow = {
            param($tier)
            [pscustomobject]@{ SecuritySeverity = 'High'; CriticalityTier = $tier; SecurityDomain = 'Identity'; SI_ExemptionId = ''
                               RiskScoreTotal = 2; ImpactedAssetIds = '["a"]'; AssetId = ''; SI_AssetId = '' }
        }
    }
    It 'Log Analytics'' text "<_>" for an empty dynamic adds no tier value' -ForEach @('{}', '[]', 'null', ' {} ') {
        $roll = @(ConvertTo-SITrendRollup -Rows @((& $script:EmptyRow $_), (& $script:EmptyRow '1')))
        @($roll | Where-Object { $_.Dimension -eq 'tier' } | ForEach-Object { $_.DimensionValue }) | Should -Be @('1')
        @($roll | Where-Object { $_.Dimension -eq 'global' })[0].Findings | Should -Be 2 -Because 'the finding still counts in the global row'
    }
    It 'the in-memory empty object Risk Analysis passes reads the same as the text' {
        $fromText = @(ConvertTo-SITrendRollup -Rows @((& $script:EmptyRow '{}')) | Where-Object { $_.Dimension -like 'tier*' })
        $fromText.Count | Should -Be 0
        foreach ($obj in @([pscustomobject]@{}, @{}, $null)) {
            @(ConvertTo-SITrendRollup -Rows @((& $script:EmptyRow $obj)) | Where-Object { $_.Dimension -like 'tier*' }).Count | Should -Be 0
        }
        @(ConvertTo-SITrendRollup -Rows @((& $script:EmptyRow (, @()))) | Where-Object { $_.Dimension -like 'tier*' }).Count | Should -Be 0
    }
    It 'a real value is kept as it was, including tier 0 as a number' {
        ConvertTo-SITrendDimensionValue 0 | Should -BeExactly '0'
        ConvertTo-SITrendDimensionValue 'Medium - tier 2' | Should -BeExactly 'Medium - tier 2'
        ConvertTo-SITrendDimensionValue '' | Should -BeExactly ''
    }
}
