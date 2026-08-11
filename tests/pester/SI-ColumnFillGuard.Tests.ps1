#Requires -Version 5.1
<#
    AUDIT #57.1(d) -- unit tests for the run-over-run column-population guard.

    The row-count guard (#57.1(a)) notices when a report loses its ROWS. This one notices when the
    rows are all still present and the CONTENT drains out of them -- the defect v2.2.422 found
    (#58.5: 0 of 1,810 rows carried cmdbName while the row count was unchanged) and the oldest one
    in the solution (#48: 82 of 151 columns dropped at ingest, rows posted, run logged SUCCESS).

    These tests pin the three behaviours that make it useful, and -- at least as important -- the
    four that stop it becoming noise. A guard that cries wolf gets switched off, and then it
    protects nothing.
#>

BeforeAll {
    $shared = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'engine\risk-analysis\_shared'
    . (Join-Path $shared 'RA-ColumnFillGuard.ps1')
}

Describe 'column-fill guard -- audit #57.1(d)' {

    Context 'the snapshot' {

        It 'records a present-but-blank column as 0 rather than omitting it' {
            # THE distinction the whole guard rests on: a column that is present and empty must be
            # tellable from a column that is GONE. If a blank column were simply missing from the
            # snapshot, COLUMN-EMPTIED and COLUMN-VANISHED would collapse into each other.
            $rows = @(
                [pscustomobject]@{ AssetName = 'srv01'; cmdbName = '' }
                [pscustomobject]@{ AssetName = 'srv02'; cmdbName = $null }
            )
            $s = Get-RAColumnFillSnapshot -Rows $rows
            $s['__rows']    | Should -Be 2
            $s.ContainsKey('cmdbName') | Should -BeTrue -Because 'the column IS in the schema, it just has no values'
            $s['cmdbName']  | Should -Be 0
            $s['AssetName'] | Should -Be 2
        }

        It 'counts a numeric 0 and a boolean $false as POPULATED, not as absence' {
            # RiskScoreTotal = 0 and IsInternetExposed = $false are real, meaningful values. Reading
            # them as "empty" would make the guard fire on healthy data every time a tenant improved.
            $rows = @([pscustomobject]@{ RiskScoreTotal = 0; IsExposed = $false; Blank = '   ' })
            $s = Get-RAColumnFillSnapshot -Rows $rows
            $s['RiskScoreTotal'] | Should -Be 1
            $s['IsExposed']      | Should -Be 1
            $s['Blank']          | Should -Be 0 -Because 'whitespace-only is absence'
        }

        It 'returns a zero-row snapshot without inventing columns' {
            $s = Get-RAColumnFillSnapshot -Rows @()
            $s['__rows']  | Should -Be 0
            $s.Keys.Count | Should -Be 1
        }
    }

    Context 'what it must CATCH' {

        It 'flags a column that still ships but is blank on every row (the #58.5 / CMDB signature)' {
            # Measured before the v2.2.422 fix: cmdbName populated on 0 of 1,810 rows while the row
            # count itself never moved. #57.1(a) saw 1810 -> 1810 and correctly said nothing.
            $prev = @{ R = @{ '__rows' = 1810; 'cmdbName' = 1810; 'AssetName' = 1810 } }
            $curr = @{ R = @{ '__rows' = 1810; 'cmdbName' = 0;    'AssetName' = 1810 } }
            $f = @(Get-RAColumnFillRegressions -Previous $prev -Current $curr)
            $f.Count           | Should -Be 1
            $f[0].Kind         | Should -Be 'COLUMN-EMPTIED'
            $f[0].Column       | Should -Be 'cmdbName'
            $f[0].PreviousRows | Should -Be 1810
            $f[0].CurrentRows  | Should -Be 1810
        }

        It 'flags a column that disappeared from the schema entirely (the #48 signature)' {
            # 🪤 THE TRAP THIS PINS. A vanished column has NO entry in the current snapshot, so an
            # implementation that loops over the CURRENT columns skips it in silence -- blind to the
            # most severe case it exists for. The guard must iterate what it HAD.
            $prev = @{ R = @{ '__rows' = 100; 'cmdbCriticality' = 66; 'AssetName' = 100 } }
            $curr = @{ R = @{ '__rows' = 100; 'AssetName' = 100 } }
            $f = @(Get-RAColumnFillRegressions -Previous $prev -Current $curr)
            $f.Count     | Should -Be 1
            $f[0].Kind   | Should -Be 'COLUMN-VANISHED'
            $f[0].Column | Should -Be 'cmdbCriticality'
        }

        It 'flags a large fill drop that does not reach zero' {
            $prev = @{ R = @{ '__rows' = 100; 'cmdbId' = 66 } }
            $curr = @{ R = @{ '__rows' = 100; 'cmdbId' = 3  } }
            $f = @(Get-RAColumnFillRegressions -Previous $prev -Current $curr -DropFraction 0.8)
            $f.Count   | Should -Be 1
            $f[0].Kind | Should -Be 'FILL-DROP'
        }

        It 'reports every affected column, not just the first' {
            $prev = @{ R = @{ '__rows' = 100; 'cmdbName' = 100; 'cmdbCriticality' = 100; 'AssetName' = 100 } }
            $curr = @{ R = @{ '__rows' = 100; 'cmdbName' = 0;   'cmdbCriticality' = 0;   'AssetName' = 100 } }
            $f = @(Get-RAColumnFillRegressions -Previous $prev -Current $curr)
            $f.Count | Should -Be 2
            (@($f | ForEach-Object { $_.Column }) -join ',') | Should -Be 'cmdbCriticality,cmdbName'
        }
    }

    Context 'what it must stay SILENT about' {

        It 'stays SILENT when rows drift but the fill FRACTION holds -- the measurement trap' {
            # 🔑 THE MOST IMPORTANT TEST IN THIS FILE. Row counts move on their own in the reference
            # tenant (a control run with unchanged code showed 5 -> 3 -> 5). A column that stays 100%
            # populated while its report legitimately halves is NOT a loss. Compared by raw COUNT it
            # looks like a 50% drop, and DropFraction 0.4 below would fire on it; compared by
            # FRACTION, 1.0 -> 1.0, it is correctly silent.
            $prev = @{ R = @{ '__rows' = 1397; 'AssetName' = 1397 } }
            $curr = @{ R = @{ '__rows' = 700;  'AssetName' = 700  } }
            @(Get-RAColumnFillRegressions -Previous $prev -Current $curr -DropFraction 0.4).Count |
                Should -Be 0 -Because 'the fraction is unchanged at 100%; only the raw count fell'
        }

        It 'stays SILENT on a report that produced NO rows -- #57.1(a) owns that transition' {
            # If a report goes to zero rows, every column in it is trivially empty. Emitting 50
            # COLUMN-EMPTIED findings for one event the row-count guard already reports ONCE and
            # accurately is exactly how a guard gets muted.
            $prev = @{ R = @{ '__rows' = 500; 'cmdbName' = 500; 'AssetName' = 500 } }
            $curr = @{ R = @{ '__rows' = 0 } }
            @(Get-RAColumnFillRegressions -Previous $prev -Current $curr).Count | Should -Be 0
        }

        It 'stays SILENT when a column GAINS population' {
            # The v2.2.422 fix itself took cmdbName 0 -> 3 on unchanged rows. An improvement must
            # never read as a regression.
            $prev = @{ R = @{ '__rows' = 72; 'cmdbName' = 0 } }
            $curr = @{ R = @{ '__rows' = 72; 'cmdbName' = 3 } }
            @(Get-RAColumnFillRegressions -Previous $prev -Current $curr).Count | Should -Be 0
        }

        It 'stays SILENT on a small dip that is ordinary data movement' {
            $prev = @{ R = @{ '__rows' = 100; 'cmdbName' = 60 } }
            $curr = @{ R = @{ '__rows' = 100; 'cmdbName' = 55 } }
            @(Get-RAColumnFillRegressions -Previous $prev -Current $curr -DropFraction 0.8).Count | Should -Be 0
        }

        It 'ignores a report with no prior history rather than inventing a baseline' {
            @(Get-RAColumnFillRegressions -Previous @{} -Current @{ New = @{ '__rows' = 10; 'C' = 0 } }).Count |
                Should -Be 0
        }

        It 'ignores a column that was ALREADY empty -- there is nothing to lose' {
            $prev = @{ R = @{ '__rows' = 100; 'cmdbName' = 0 } }
            $curr = @{ R = @{ '__rows' = 100; 'cmdbName' = 0 } }
            @(Get-RAColumnFillRegressions -Previous $prev -Current $curr).Count | Should -Be 0
        }
    }

    Context 'persistence' {

        It 'survives a corrupt history file instead of breaking the run' {
            $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("si-cfg-{0}.json" -f ([guid]::NewGuid().ToString('N')))
            Set-Content -LiteralPath $tmp -Value '{ this is not json' -Encoding UTF8
            try {
                (Read-RAColumnFillHistory -Path $tmp -TemplateName 'RiskAnalysis_Summary').Count | Should -Be 0
            } finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
        }

        It 'round-trips history per TEMPLATE, so Summary and Detailed cannot overwrite each other' {
            # The same report legitimately yields different shapes under Summary vs Detailed.
            $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("si-cfg-{0}.json" -f ([guid]::NewGuid().ToString('N')))
            try {
                Write-RAColumnFillHistory -Path $tmp -TemplateName 'RiskAnalysis_Summary'  -Snapshots @{ R = @{ '__rows' = 334; 'cmdbName' = 334 } }
                Write-RAColumnFillHistory -Path $tmp -TemplateName 'RiskAnalysis_Detailed' -Snapshots @{ R = @{ '__rows' = 507; 'cmdbName' = 55  } }
                (Read-RAColumnFillHistory -Path $tmp -TemplateName 'RiskAnalysis_Summary')['R']['__rows']    | Should -Be 334
                (Read-RAColumnFillHistory -Path $tmp -TemplateName 'RiskAnalysis_Detailed')['R']['cmdbName'] | Should -Be 55
            } finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
        }

        It 'CARRIES FORWARD the baseline of a report that recorded nothing this run' {
            # A report that throws inside the engine's per-report catch produces no snapshot.
            # Replacing the template node wholesale would delete its baseline, so the next
            # successful run would have nothing to compare against -- the guard would go quiet for
            # exactly the report that just misbehaved. A stale baseline beats no baseline.
            $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("si-cfg-{0}.json" -f ([guid]::NewGuid().ToString('N')))
            try {
                Write-RAColumnFillHistory -Path $tmp -TemplateName 'T' -Snapshots @{
                    Good = @{ '__rows' = 10; 'C' = 10 }
                    Flaky = @{ '__rows' = 20; 'C' = 20 }
                }
                # second run: Flaky failed and reported nothing
                Write-RAColumnFillHistory -Path $tmp -TemplateName 'T' -Snapshots @{ Good = @{ '__rows' = 11; 'C' = 11 } }
                $h = Read-RAColumnFillHistory -Path $tmp -TemplateName 'T'
                $h.ContainsKey('Flaky') | Should -BeTrue -Because 'its baseline must survive a run it missed'
                $h['Flaky']['C']        | Should -Be 20
                $h['Good']['__rows']    | Should -Be 11
            } finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
        }
    }

    Context 'engine wiring' {

        It 'the ENGINE snapshots from $Shaped, AFTER shaping and BEFORE the export pool' {
            # 🪤 REGRESSION GUARD, and the direct descendant of #57.1(a)'s lesson: that guard's first
            # cut captured at a site the defect never reached, so all its unit tests passed while the
            # feature was inert. The tests above would do exactly the same if the engine snapshotted
            # the wrong collection.
            #
            # $ResultFiltered and $RiskScoreArray are both PRE-shaping. A column dropped by the
            # `Select-Object -Property $DesiredColumns` -- audit #26, which really did lose AssetName
            # and AssetType from a delivered workbook -- would still read as fully populated there.
            # Only $Shaped is what enters the export pool the customer opens.
            $engine = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'
            $src    = [System.IO.File]::ReadAllText($engine)

            $src | Should -Match '_shared/RA-ColumnFillGuard\.ps1' -Because 'the module must be dot-sourced'

            $mSnap = [regex]::Match($src, 'Get-RAColumnFillSnapshot\s+-Rows\s+@\(\$Shaped\)')
            $mSnap.Success | Should -BeTrue -Because 'the snapshot must be taken from $Shaped, not from a pre-shaping collection'

            $idxShape = $src.IndexOf('$Shaped = $RiskScoreArray | Select-Object')
            $idxPool  = $src.IndexOf('$global:AllShapedRows.Add($row)')
            $idxShape | Should -BeGreaterThan 0
            $idxPool  | Should -BeGreaterThan 0
            $mSnap.Index | Should -BeGreaterThan $idxShape -Because 'snapshotting before the shaping Select-Object would miss a dropped column'
            $mSnap.Index | Should -BeLessThan   $idxPool  -Because 'the snapshot belongs with the rows it describes'
        }

        It 'the ENGINE isolates the snapshot so a guard fault cannot DROP a report' {
            # 🔴 The capture sits INSIDE the per-report try, whose catch writes "report failed --
            # skipping" and moves on. Unguarded, an exception in the snapshot would not just lose a
            # measurement -- it would remove that report from the customer's export entirely, in the
            # name of a feature built to prevent silent loss. Pinned because it is invisible on a
            # healthy run: nothing about a passing run tells you the wrapper is missing.
            $engine = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'
            $src    = [System.IO.File]::ReadAllText($engine)

            $mSnap = [regex]::Match($src, 'Get-RAColumnFillSnapshot\s+-Rows\s+@\(\$Shaped\)')
            $mSnap.Success | Should -BeTrue

            # walk back from the call to the nearest preceding `try {` and `catch {`; the try must
            # be closer, i.e. the call is inside a try that opened after the last catch closed.
            $before   = $src.Substring(0, $mSnap.Index)
            $lastTry  = $before.LastIndexOf('try {')
            $idxAfter = $mSnap.Index
            $after    = $src.Substring($idxAfter, [Math]::Min(400, $src.Length - $idxAfter))

            $lastTry | Should -BeGreaterThan 0 -Because 'the snapshot must sit inside a try'
            ($idxAfter - $lastTry) | Should -BeLessThan 700 -Because 'the enclosing try must be the guards own, not the distant per-report one'
            $after | Should -Match 'catch' -Because 'the snapshot needs its own catch, not the per-report one'
            $after | Should -Match '\[ColumnFillGuard\] snapshot skipped'
        }

        It 'the ENGINE runs the guard in its own try, separate from the row-count guard' {
            # A fault in either guard must not take the other one down -- they answer different
            # questions and #58.5 showed one can be silent while the other is loud.
            $engine = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'
            $src    = [System.IO.File]::ReadAllText($engine)
            ([regex]::Matches($src, 'Invoke-RARowCountGuard')).Count   | Should -BeGreaterOrEqual 1
            ([regex]::Matches($src, 'Invoke-RAColumnFillGuard')).Count | Should -BeGreaterOrEqual 1
            $src | Should -Match '\[ColumnFillGuard\] skipped'
        }
    }
}
