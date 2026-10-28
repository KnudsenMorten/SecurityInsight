#Requires -Version 5.1
<#
    #833 THE BUCKET LEARNING SIZES A REPORT TO WHAT IT MEASURED -- after a query change too -- AND SAYS WHAT IT KEPT.

    Measured at internal 2026-10-20 (one Detailed run): 58 of 69 reports returned under 100 rows (18 none) and every one ran
    2 or more buckets (170 in all); the largest bucket of the run held 11,031 rows (37 % of 30,000) and 25.5 MB (40 % of
    64 MB). Credential_Based_Lateral_Movement started its changed query at 16 buckets ("the count it used before its query
    changed" -- its remembered count was 2; the 16 was a count proved under its EARLIER queries) for at most 80 rows a
    bucket: 372 s instead of 36 s. The log said "16 bucket(s) kept for the next run" (the early save) while the state and
    the history held 8 (the end of the report halved it). Identity_Group_Membership: 8 buckets for 0 rows -- an empty slice
    was never measured, so nothing could bring it down. Old fingerprints and a test template's row stayed in the state.

    What these tests keep true (offline; the database is an in-memory fake behind the ONE -Invoke seam; stubs in script
    scope):
      * a changed query starts from its MEASURED need -- rows, bytes, the request AND the slice time against half of every
        limit -- not from its earlier query's count; nothing measured = the first-run behaviour (the configured count);
      * a report far inside every limit comes down to 1 (the configured 2 was never a safety rule, #56.1); the slice time
        keeps a compute-heavy report up; a count the report's template sets stays its floor; a count a failure proved for
        the CURRENT query stays;
      * an empty slice is measured;
      * the overflow path still splits a 1-slice report, losslessly;
      * the history row and the log line say the count the state keeps; a count kept lower is recorded 'down';
      * the earlier fingerprints are removed once the current one ran complete, the current one and its stamp kept; the
        certification's test template rows are removed only through the guarded product statement.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-AutoBucketing.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-BucketStore.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-BucketFilters.ps1')
    function script:Write-Info { param($msg) $script:Logged += ,[string]$msg }
    function script:Write-Warn2 { param($msg) $script:Logged += ,[string]$msg }
    $script:AutoBucketConfirmedKey = '__confirmed'

    # THE FAKE DATABASE: state + history in memory, answering exactly the statements of Get-SIRaBucketSql (both shapes).
    function script:New-FakeBucketDb {
        param([bool]$HasTime = $true)
        $db = [pscustomobject]@{ State = New-Object System.Collections.Generic.List[object]; History = New-Object System.Collections.Generic.List[object]
                                 Calls = New-Object System.Collections.Generic.List[object]; NextId = 100; HasTime = $HasTime }
        $sql = @{}
        foreach ($n in 'Exists', 'State', 'Upsert', 'Delete', 'DeleteTemplate', 'ConsumeResets', 'History', 'HistoryAdd', 'Imported', 'ImportMark', 'PruneTestTemplates') { $sql[$n] = Get-SIRaBucketSql $n }
        $sql['History+T'] = Get-SIRaBucketSql 'History' -WithTime
        $sql['HistoryAdd+T'] = Get-SIRaBucketSql 'HistoryAdd' -WithTime
        $invoke = {
            param([string]$s, $p, [string]$mode)
            $name = @($sql.Keys | Where-Object { $sql[$_] -eq $s })[0]
            $db.Calls.Add([pscustomobject]@{ Name = [string]$name; Params = $p })
            switch ($name) {
                'Exists' { return ,@(@{ HasTables = 1; HasTime = $(if ($db.HasTime) { 1 } else { 0 }) }) }
                'State' { return ,@($db.State | Where-Object { $_.Template -eq $p.Template } | ForEach-Object { @{ ReportName = $_.ReportName; Fingerprint = $_.Fingerprint; BucketCount = $_.BucketCount; ConfirmedUtc = $_.ConfirmedUtc } }) }
                'Upsert' {
                    $row = @($db.State | Where-Object { $_.Template -eq $p.Template -and $_.ReportName -eq $p.ReportName -and $_.Fingerprint -eq $p.Fingerprint })[0]
                    if ($row) { $row.BucketCount = $p.BucketCount; $row.ConfirmedUtc = $p.ConfirmedUtc }
                    else { $db.State.Add([pscustomobject]@{ Template = $p.Template; ReportName = $p.ReportName; Fingerprint = $p.Fingerprint; BucketCount = $p.BucketCount; ConfirmedUtc = $p.ConfirmedUtc; UpdatedUtc = [datetime]::UtcNow }) }
                    return
                }
                'Delete' { foreach ($r in @($db.State | Where-Object { $_.Template -eq $p.Template -and $_.ReportName -eq $p.ReportName -and $_.Fingerprint -eq $p.Fingerprint })) { [void]$db.State.Remove($r) }; return }
                'ConsumeResets' { return ,@() }
                { $_ -in 'History', 'History+T' } {
                    if ($name -eq 'History+T' -and -not $db.HasTime) { throw "Invalid column name 'MaxBucketSeconds'." }
                    return ,@($db.History | Where-Object { $_.Template -eq $p.Template } | Sort-Object Id -Descending | ForEach-Object { $h = @{}; foreach ($q in $_.PSObject.Properties) { if ($name -eq 'History' -and $q.Name -in 'MaxBucketSeconds', 'RanCount') { continue }; $h[$q.Name] = $q.Value }; $h })
                }
                { $_ -in 'HistoryAdd', 'HistoryAdd+T' } {
                    if ($name -eq 'HistoryAdd+T' -and -not $db.HasTime) { throw "Invalid column name 'MaxBucketSeconds'." }
                    $o = [pscustomobject]@{ Id = $db.NextId; RunUtc = [datetime]::UtcNow }; $db.NextId++
                    foreach ($k in $p.Keys) { $o | Add-Member -NotePropertyName $k -NotePropertyValue $p[$k] -Force }
                    $db.History.Add($o); return
                }
                'PruneTestTemplates' {
                    # T-SQL LIKE 'Test[0-9]%[_]%' (case-insensitive collation), the run's own template never, idle = no history row in IdleDays
                    $like = '^(?i)' + ([regex]::Escape([string]$p.Like) -replace '\\\[0-9]', '[0-9]' -replace '\\\[_]', '_' -replace '%', '.*') + '$'
                    $gone = @($db.State | Where-Object { $_.Template -match $like -and $_.Template -ne $p.Template } |
                        Where-Object { $t = $_.Template; -not @($db.History | Where-Object { $_.Template -eq $t -and $_.RunUtc -ge [datetime]::UtcNow.AddDays(-[int]$p.IdleDays) }).Count })
                    foreach ($r in $gone) { [void]$db.State.Remove($r) }
                    return ,@(@{ N = $gone.Count })
                }
                default { throw "unexpected statement: $s" }
            }
        }.GetNewClosure()
        $db | Add-Member -NotePropertyName Invoke -NotePropertyValue $invoke
        $db
    }
    function script:Reset-BucketState {
        $script:Logged = @()
        $script:AutoBucketMemo = @{}
        $script:AutoBucketSql = $null
        $script:AutoBucketJumps = $null
        $script:SIRaBucketHistoryHasTime = $false
        $global:AutoBucketCache = $true
        $global:SettingsPath = Join-Path ([IO.Path]::GetTempPath()) ('si-bucket-833-' + [guid]::NewGuid().ToString('N'))
    }
    # one history row: the count kept (c) and started with, how it was decided, what was measured
    function script:Hist {
        param([int]$c, [string]$d = 'cache', [long]$rows = 0, [long]$maxRows = 0, [long]$maxBytes = 0, $secs = $null, $ran = $null, [string]$fp = '', [int]$start = 0, [string]$report = 'R', [string]$template = 'RiskAnalysis_Detailed', [int]$id = 1)
        [pscustomobject]@{ Id = $id; Template = $template; ReportName = $report; Fingerprint = $fp; BucketCount = $c; StartCount = $(if ($start) { $start } else { $c }); Decided = $d
                           ResultRows = $rows; MaxBucketRows = $maxRows; MaxBucketBytes = $maxBytes; MaxRequestBytes = $null; RequestRows = $null; RequestBytesPerRow = $null; RequestOverheadBytes = $null
                           MaxBucketSeconds = $secs; RanCount = $ran; RunUtc = [datetime]::UtcNow.AddMinutes(-$id) }
    }
}

AfterAll { $global:SettingsPath = $null }

Describe 'a changed query starts from its MEASURED need, not from its earlier query''s count' {
    BeforeEach { Reset-BucketState }

    It 'the live case: 644 rows, at most 80 a slice, 33 s at 16 slices -> 2 buckets, not the 16 its earlier queries proved' {
        $db = New-FakeBucketDb
        $db.State.Add([pscustomobject]@{ Template = 'RiskAnalysis_Detailed'; ReportName = 'R'; Fingerprint = '111'; BucketCount = 2; ConfirmedUtc = $null })
        $db.History.Add((Hist 8 'down' -rows 644 -maxRows 80 -maxBytes 72312 -secs 33 -ran 16 -fp '111' -start 16 -id 3))
        $db.History.Add((Hist 16 'raised' -rows 500 -maxRows 278 -maxBytes 260250 -fp '000' -start 2 -id 2))
        $null = Initialize-AutoBucketSqlStore -Invoke $db.Invoke -Template 'RiskAnalysis_Detailed' -RunId 'r'
        # the old path: the earlier query's count raised to the count proved under the EARLIER queries
        Get-AutoBucketPreviousCount -QueryKey 'R|222' -Floor 2 -Cap 4096 | Should -Be 16
        # the measured path the engine now asks first: 33 s x 16 / 450 s = 1.2 -> 2; rows and bytes need 1
        $plan = Get-AutoBucketStartPlan -ReportName 'R' -QueryKey 'R|222' -Floor 1 -Cap 4096 -Start 2
        $plan.Measured | Should -Be 2
        $plan.MinCount | Should -Be 2 -Because 'a count proved under another query proves nothing for this one when the time was measured'
    }

    It 'a report that returned nothing quickly starts its changed query at 1' {
        $db = New-FakeBucketDb
        $db.History.Add((Hist 8 'cache' -rows 0 -secs 4 -ran 8 -fp '111'))
        $null = Initialize-AutoBucketSqlStore -Invoke $db.Invoke -Template 'RiskAnalysis_Detailed' -RunId 'r'
        $plan = Get-AutoBucketStartPlan -ReportName 'R' -QueryKey 'R|222' -Floor 1 -Cap 4096 -Start 2
        $plan.Measured | Should -Be 1
        $plan.MinCount | Should -Be 1
    }

    It 'the slice time keeps a compute-heavy report up: 600 s at 4 slices -> 8 (600 x 4 / 450 = 5.3)' {
        $db = New-FakeBucketDb
        $db.History.Add((Hist 4 'cache' -rows 12 -maxRows 5 -maxBytes 5000 -secs 600 -ran 4 -fp '111'))
        $null = Initialize-AutoBucketSqlStore -Invoke $db.Invoke -Template 'RiskAnalysis_Detailed' -RunId 'r'
        (Get-AutoBucketStartPlan -ReportName 'R' -QueryKey 'R|222' -Floor 1 -Cap 4096 -Start 2).MinCount | Should -Be 8
    }

    It 'a measurement WITHOUT the slice time (written before #833) still keeps the counts the earlier queries proved' {
        $db = New-FakeBucketDb
        $db.History.Add((Hist 2 'cache' -rows 25 -maxRows 3 -maxBytes 3000 -fp '111' -id 1))
        $db.History.Add((Hist 32 'raised' -rows 25 -maxRows 3 -maxBytes 3000 -fp '000' -start 16 -id 2))
        $null = Initialize-AutoBucketSqlStore -Invoke $db.Invoke -Template 'RiskAnalysis_Detailed' -RunId 'r'
        (Get-AutoBucketStartPlan -ReportName 'R' -QueryKey 'R|222' -Floor 1 -Cap 4096 -Start 2).MinCount | Should -Be 32
    }

    It 'nothing measured: the first-run behaviour -- the configured count, and the earlier count is asked as before' {
        $db = New-FakeBucketDb
        $db.State.Add([pscustomobject]@{ Template = 'RiskAnalysis_Detailed'; ReportName = 'R'; Fingerprint = '111'; BucketCount = 4; ConfirmedUtc = $null })
        $null = Initialize-AutoBucketSqlStore -Invoke $db.Invoke -Template 'RiskAnalysis_Detailed' -RunId 'r'
        $plan = Get-AutoBucketStartPlan -ReportName 'R' -QueryKey 'R|222' -Floor 1 -Cap 4096 -Start 2
        $plan.Measured | Should -BeNullOrEmpty
        $plan.MinCount | Should -Be 2
        Get-AutoBucketPreviousCount -QueryKey 'R|222' -Floor 2 -Cap 4096 | Should -Be 4
        # a brand-new report: the probe starts at the configured count
        (Get-AutoBucketStartPlan -ReportName 'New' -QueryKey 'New|1' -Floor 1 -Cap 4096 -Start 2).MinCount | Should -Be 2
    }

    It 'a remembered count is taken down to the floor (a cached 1 is used, not re-probed from 2)' {
        $db = New-FakeBucketDb
        $db.State.Add([pscustomobject]@{ Template = 'RiskAnalysis_Detailed'; ReportName = 'R'; Fingerprint = '111'; BucketCount = 1; ConfirmedUtc = $null })
        $null = Initialize-AutoBucketSqlStore -Invoke $db.Invoke -Template 'RiskAnalysis_Detailed' -RunId 'r'
        $plan = Get-AutoBucketStartPlan -ReportName 'R' -QueryKey 'R|111' -Floor 1 -Cap 4096 -Start 2
        $plan.MinCount | Should -Be 1
        $global:Probed = @()
        Get-OptimalBucketCount -QueryKey 'R|111' -MaxBucketCount 4096 -MinBucketCount $plan.MinCount -ProbeScript { param([int]$BucketCount) $global:Probed += $BucketCount } | Should -Be 1
        $script:_AutoBucketSource | Should -Be 'cache'
        @($global:Probed).Count | Should -Be 0
    }
}

Describe 'a report far inside every limit comes down to 1' {
    BeforeEach { Reset-BucketState }

    It 'the 2 floor was the configured START used as the floor (#56.1), not a safety rule: the learn floor is 1' {
        Get-AutoBucketLearnFloor -Configured 2 -Measured | Should -Be 1
        # a count the report's template sets stays its floor (v2.2.281: "you don't need to try less than 64")
        Get-AutoBucketLearnFloor -Configured 64 -TemplateCount 64 -Measured | Should -Be 64
        # without the Pro database (nothing measured, nothing kept in history) the configured count as before
        Get-AutoBucketLearnFloor -Configured 2 | Should -Be 2
    }

    It 'an empty report: 8 -> 4 -> 2 -> 1, half per run, then it stays at 1' {
        $c = 8; $seen = @(); $h = @((Hist 8 'cache' -rows 0 -secs 3 -ran 8 -fp '111'))
        foreach ($i in 1..6) {
            $s = Get-SIRaBucketShrinkCount -Count $c -Floor 1 -ProbeFloor 2 -History $h -Fingerprint '111'
            if (-not $s.Down) { break }
            $c = $s.Count; $seen += $c
            $h = @((Hist $c 'down' -rows 0 -secs 3 -ran $c -fp '111')) + $h
        }
        $seen | Should -Be @(4, 2, 1)
        (Get-SIRaBucketShrinkCount -Count 1 -Floor 1 -History $h).Down | Should -BeFalse
    }

    It 'the engine-side halving of a far-below run goes to 1 too, and never below a template''s count' {
        Get-RACountAfterSmallRun -BucketCount 2 -Floor 1 | Should -Be 1
        Get-RACountAfterSmallRun -BucketCount 1 -Floor 1 | Should -Be 1
        Get-RACountAfterSmallRun -BucketCount 8 -Floor 8 | Should -Be 8
        # an empty slice IS measured now (Slices > 0), so a run of empty slices can be "far below"
        Reset-AutoBucketMeasure
        Add-AutoBucketMeasure -Rows 0 -Seconds 2.5
        Add-AutoBucketMeasure -Rows 0 -Seconds 1.0
        $script:AutoBucketMeasure.Slices | Should -Be 2
        Test-RABucketRunFarBelow -Measure $script:AutoBucketMeasure | Should -BeTrue
    }

    It 'the slice time stops it: a report with few rows whose slice took 400 s at 2 stays at 2' {
        $h = @((Hist 2 'cache' -rows 3 -maxRows 2 -maxBytes 900 -secs 400 -ran 2 -fp '111'))
        (Get-SIRaBucketShrinkCount -Count 2 -Floor 1 -ProbeFloor 2 -History $h -Fingerprint '111').Down | Should -BeFalse
        $m = [pscustomobject]@{ ResultRows = 3; MaxBucketRows = 2; MaxBucketBytes = 900; MaxRequestBytes = 0; MaxFixedBytes = 0; Slices = 2; MaxBucketSeconds = 400.0 }
        Test-RABucketRunFarBelow -Measure $m | Should -BeFalse
    }

    It 'a count a failure proved for the CURRENT query stays; one proved for an earlier query does not hold it up' {
        $now = Hist 16 'cache' -rows 25 -maxRows 3 -maxBytes 3000 -secs 10 -ran 16 -fp '222' -id 1
        $raisedNow = Hist 16 'raised' -rows 25 -maxRows 3 -maxBytes 3000 -fp '222' -start 8 -id 2
        $raisedOld = Hist 16 'raised' -rows 25 -maxRows 3 -maxBytes 3000 -fp '111' -start 8 -id 2
        (Get-SIRaBucketShrinkCount -Count 16 -Floor 1 -ProbeFloor 2 -History @($now, $raisedNow) -Fingerprint '222').Down | Should -BeFalse
        $s = Get-SIRaBucketShrinkCount -Count 16 -Floor 1 -ProbeFloor 2 -History @($now, $raisedOld) -Fingerprint '222'
        $s.Down | Should -BeTrue
        $s.Count | Should -Be 8
        $s.Why | Should -Match 'its longest slice took 10 s'
        # a probe at the configured count proves nothing, one that climbed above it does
        Get-SIRaBucketProvenCount -History @((Hist 2 'probe' -fp '222')) -Floor 2 -Fingerprint '222' | Should -Be 0
        Get-SIRaBucketProvenCount -History @((Hist 8 'probe' -fp '222')) -Floor 2 -Fingerprint '222' | Should -Be 8
    }

    It 'the report loop''s down plan reads the time from the database history and keeps the proof to the current query' {
        $db = New-FakeBucketDb
        $db.History.Add((Hist 2 'cache' -rows 0 -secs 2 -ran 2 -fp '222' -id 2))
        $db.History.Add((Hist 8 'raised' -rows 0 -fp '111' -start 2 -id 1))
        $null = Initialize-AutoBucketSqlStore -Invoke $db.Invoke -Template 'RiskAnalysis_Detailed' -RunId 'r'
        $p = Get-AutoBucketDownPlan -ReportName 'R' -Count 2 -Floor 1 -ProbeFloor 2 -QueryKey 'R|222'
        $p.Down | Should -BeTrue
        $p.Count | Should -Be 1
    }
}

Describe 'the overflow path still splits, losslessly -- also from 1 slice' {
    It 'a too-large answer is split, never retried at the same size' {
        Get-RABucketFailureAction -Err 'Query exceeded the allowed result size' | Should -Be 'Split'
        Get-RABucketFailureAction -Err 'Response payload too large' | Should -Be 'Split'
    }

    It 'the 4 sub-slices of a 1-slice report are together exactly that slice (every residue of 4 once)' {
        $idx = @(0..3 | ForEach-Object { $k = New-SubBucketFilterKql -ParentBucketCount 1 -ParentBucketIndex 0 -SubBucketCount 4 -SubBucketIndex $_; if ($k -match '% (\d+)\s*\r?\n\| where __bucket == (\d+)') { '{0}/{1}' -f $matches[2], $matches[1] } })
        $idx | Should -Be @('0/4', '1/4', '2/4', '3/4')
        New-BucketFilterKql -BucketCount 1 -BucketIndex 0 | Should -Match '% 1\s*\r?\n\| where __bucket == 0'
    }

    It 'a 1-slice report whose slice the service called too large starts its next run higher' {
        Get-RACountAfterSplit -BucketCount 1 -Slices @([pscustomobject]@{ Rows = 40000; Bytes = 0; Seconds = 20; TooLarge = $true; Lost = $false }) -WorkingCount 4 -FanOut 4 | Should -Be 3
        Get-RACountAfterSplit -BucketCount 1 -Slices @([pscustomobject]@{ Rows = 10; Bytes = 0; Seconds = 2; TooLarge = $true; Lost = $false }) -WorkingCount 4 -FanOut 4 | Should -Be 2
    }
}

Describe 'the log line and the stored state say the same count' {
    BeforeEach { Reset-BucketState }

    It 'the history row keeps the count the state keeps; kept lower = ''down''; the slice time and the count it ran at are written' {
        $db = New-FakeBucketDb
        $null = Initialize-AutoBucketSqlStore -Invoke $db.Invoke -Template 'RiskAnalysis_Detailed' -RunId 'r1'
        Reset-AutoBucketMeasure
        foreach ($i in 1..16) { Add-AutoBucketMeasure -Rows 40 -Sample @([pscustomobject]@{ a = 'x' }) -Seconds 32.2 }
        $null = Complete-AutoBucketReport -ReportName 'R' -QueryKey 'R|222' -StartCount 16 -FinalCount 8 -Source 'hint' -RanCount 16
        $h = @($db.History | Where-Object { $_.RunId -eq 'r1' })[0]
        $h.BucketCount | Should -Be 8
        $h.StartCount | Should -Be 16
        $h.Decided | Should -Be 'down' -Because 'sized down from this run''s measurement, not taken from the cache'
        $h.MaxBucketSeconds | Should -Be 33
        $h.RanCount | Should -Be 16
        @($db.Calls | Where-Object Name -eq 'HistoryAdd+T').Count | Should -Be 1
        # read back by the next run as the time measurement
        $null = Initialize-AutoBucketSqlStore -Invoke $db.Invoke -Template 'RiskAnalysis_Detailed' -RunId 'r2'
        $r = @($script:AutoBucketSql.History['R'])[0]
        [int]$r.MaxBucketSeconds | Should -Be 33
        [int]$r.RanCount | Should -Be 16
        $r.Fingerprint | Should -Be '222'
    }

    It 'a database one schema version behind: the history is written and read without the time, as before' {
        $db = New-FakeBucketDb -HasTime $false
        $null = Initialize-AutoBucketSqlStore -Invoke $db.Invoke -Template 'RiskAnalysis_Detailed' -RunId 'r1'
        $script:AutoBucketSql.Offline | Should -BeFalse
        Reset-AutoBucketMeasure; Add-AutoBucketMeasure -Rows 1 -Seconds 3
        $null = Complete-AutoBucketReport -ReportName 'R' -QueryKey 'R|1' -StartCount 2 -FinalCount 2 -Source 'cache' -RanCount 2
        @($db.Calls | Where-Object Name -eq 'HistoryAdd').Count | Should -Be 1
        @($db.Calls | Where-Object Name -eq 'HistoryAdd+T').Count | Should -Be 0
        $db.History.Count | Should -Be 1
        (@($db.History[0].PSObject.Properties | ForEach-Object Name) -contains 'MaxBucketSeconds') | Should -BeFalse
    }

    It 'WIRING: one line names the count kept for the next run, the same value the store and the history get; the early save says it is only kept in case the run stops' {
        $eng = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'))
        $eng | Should -Match '\$cache2\[\$queryKey\] = \[int\]\$__abRemember'
        $eng | Should -Match "(?s)Write-AutoBucketCache -Path \`$cachePath2 -CacheObject \`$cache2.{0,800}?bucket\(s\) kept for the next run \(this run: \{2\}\)"" -f \`$ReportName, \`$__abRemember, \`$bucketCountToUse"
        $eng | Should -Match 'Complete-AutoBucketReport -ReportName \$ReportName -QueryKey \$queryKey -StartCount \$__abStartCount -FinalCount \(\[int\]\$__abRemember\)'
        $eng | Should -Match '-RanCount \(\[int\]\$bucketCountToUse\)'
        # "kept for the next run" is said ONCE -- where the count for the next run is written
        ([regex]::Matches($eng, 'Write-Info \("[^"]*kept for the next run')).Count | Should -Be 1
        $eng | Should -Match 'bucket\(s\) kept in case the run stops part-way'
    }

    It 'WIRING: an empty slice is measured; the learn floor is used by every way down; the measured start is asked first' {
        $eng = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'))
        ([regex]::Matches($eng, 'Add-AutoBucketMeasure -Rows 0 ')).Count | Should -Be 2
        $eng | Should -Match '\$__abLearnFloor = Get-AutoBucketLearnFloor -Configured \(\[int\]\$effectiveBucketCount\) -TemplateCount \(\[int\]\$__abTemplateCount\) -Measured:\(Test-AutoBucketSqlActive\)'
        $eng | Should -Match 'Get-AutoBucketStartPlan -ReportName \$ReportName -QueryKey \$queryKey -Floor \$__abLearnFloor -Cap \$capBucket -Start \$effectiveBucketCount'
        $eng | Should -Match 'Get-AutoBucketDownPlan -ReportName \$ReportName -Count \(\[int\]\$bucketCountToUse\) -Floor \(\[int\]\$__abLearnFloor\) -ProbeFloor \(\[int\]\$effectiveBucketCount\) -QueryKey \$queryKey'
        # #880: the halving floor is the learn floor, or the count the report ran complete at before (never below the learn floor)
        $eng | Should -Match '\$__abHalfFloor = if \(\$__abFar\) \{ \[int\]\$__abLearnFloor \} else \{ \[int\]\[Math\]::Max\(\[int\]\$__abLearnFloor, \$__abLower\) \}'
        $eng | Should -Match '\$__abHalf = Get-RACountAfterSmallRun -BucketCount \(\[int\]\$bucketCountToUse\) -Floor \$__abHalfFloor'
        # the bucketing gate itself is unchanged: a report is bucketed when its configured count is above 1
        $eng | Should -Match '\$effectiveUseBucket -and \$querySupportsBucket -and \$effectiveBucketCount -gt 1'
    }
}

Describe 'stale fingerprints and test rows are pruned -- only through the product''s own code' {
    BeforeEach { Reset-BucketState }

    It 'once the current query ran complete: its earlier fingerprints go, the current count and its stamp stay' {
        $db = New-FakeBucketDb
        foreach ($f in '111', '333') { $db.State.Add([pscustomobject]@{ Template = 'RiskAnalysis_Detailed'; ReportName = 'R'; Fingerprint = $f; BucketCount = 8; ConfirmedUtc = $null }) }
        $db.State.Add([pscustomobject]@{ Template = 'RiskAnalysis_Detailed'; ReportName = 'R_Other'; Fingerprint = '111'; BucketCount = 4; ConfirmedUtc = $null })
        $null = Initialize-AutoBucketSqlStore -Invoke $db.Invoke -Template 'RiskAnalysis_Detailed' -RunId 'r'
        # the end-of-report write, as the engine does it
        $path = Get-AutoBucketCachePath -SettingsPath $global:SettingsPath
        $cache2 = Read-AutoBucketCache -Path $path
        $cache2['R|222'] = 2
        $ref = [ref]$cache2
        Remove-AutoBucketStaleSiblings -Cache $ref -QueryKey 'R|222' | Should -Be 2
        $cache2 = $ref.Value
        Set-AutoBucketConfirmed -Cache $ref -QueryKey 'R|222'
        $db.Calls.Clear()
        Write-AutoBucketCache -Path $path -CacheObject $ref.Value
        @($db.Calls | Where-Object Name -eq 'Delete' | ForEach-Object { $_.Params.Fingerprint } | Sort-Object) | Should -Be @('111', '333')
        @($db.State | Where-Object ReportName -eq 'R' | ForEach-Object Fingerprint) | Should -Be @('222')
        @($db.State | Where-Object ReportName -eq 'R')[0].ConfirmedUtc | Should -Not -BeNullOrEmpty
        @($db.State | Where-Object ReportName -eq 'R_Other').Count | Should -Be 1 -Because 'a report whose name starts the same is another report'
    }

    It 'WIRING: the stale fingerprints are removed at the end-of-report write, after a complete run' {
        $eng = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'))
        $i = $eng.IndexOf('if ($bucketRunSucceeded -and [bool]$global:AutoBucketCount) {')
        $j = $eng.IndexOf('$__abStale = Remove-AutoBucketStaleSiblings -Cache $_cacheRefStale -QueryKey $queryKey')
        $k = $eng.IndexOf('Write-AutoBucketCache -Path $cachePath2 -CacheObject $cache2')
        $i | Should -BeGreaterThan 0
        $j | Should -BeGreaterThan $i
        $k | Should -BeGreaterThan $j
    }

    It 'the certification''s test template is removed by a run of another template once idle a week -- nothing else' {
        $db = New-FakeBucketDb
        $db.State.Add([pscustomobject]@{ Template = 'Test688_Detailed'; ReportName = 'Device_Missing_CVEs_Detailed'; Fingerprint = '3499429858'; BucketCount = 2; ConfirmedUtc = $null })
        $db.State.Add([pscustomobject]@{ Template = 'Test701_Summary'; ReportName = 'A'; Fingerprint = '1'; BucketCount = 2; ConfirmedUtc = $null })
        $db.State.Add([pscustomobject]@{ Template = 'Testing_Detailed'; ReportName = 'A'; Fingerprint = '1'; BucketCount = 2; ConfirmedUtc = $null })
        $db.State.Add([pscustomobject]@{ Template = 'RiskAnalysis_Detailed'; ReportName = 'A'; Fingerprint = '1'; BucketCount = 2; ConfirmedUtc = $null })
        # Test701 ran yesterday: it is in use, it stays
        $db.History.Add((Hist 2 'cache' -template 'Test701_Summary' -report 'A' -id 5))
        $r = Initialize-AutoBucketSqlStore -Invoke $db.Invoke -Template 'RiskAnalysis_Detailed' -RunId 'r'
        $r.TestRowsRemoved | Should -Be 1
        @($db.State | ForEach-Object Template | Sort-Object) | Should -Be @('RiskAnalysis_Detailed', 'Test701_Summary', 'Testing_Detailed')
        $p = @($db.Calls | Where-Object Name -eq 'PruneTestTemplates')[0].Params
        $p.Template | Should -Be 'RiskAnalysis_Detailed'
        $p.Like | Should -Be 'Test[0-9]%[_]%'
        $p.IdleDays | Should -Be 7
    }

    It 'guarded: a run OF a test template prunes nothing; a failed statement never stops the run' {
        $db = New-FakeBucketDb
        $db.State.Add([pscustomobject]@{ Template = 'Test688_Detailed'; ReportName = 'A'; Fingerprint = '1'; BucketCount = 2; ConfirmedUtc = $null })
        $r = Initialize-AutoBucketSqlStore -Invoke $db.Invoke -Template 'Test688_Detailed' -RunId 'r'
        $r.TestRowsRemoved | Should -Be 0
        @($db.Calls | Where-Object Name -eq 'PruneTestTemplates').Count | Should -Be 0
        Invoke-SIRaBucketTestTemplatePrune -Invoke { param($s, $p, $m) throw 'denied' } -Template 'RiskAnalysis_Detailed' | Should -Be 0
    }

    It 'the statement deletes state rows of that name shape only -- never the run''s own template, never a history row' {
        $s = Get-SIRaBucketSql 'PruneTestTemplates'
        $s | Should -Match 'DELETE s FROM cfg\.RaBucketState AS s'
        $s | Should -Match 's\.Template LIKE @Like AND s\.Template <> @Template'
        $s | Should -Not -Match 'DELETE\s+(\w+\s+)?FROM\s+cfg\.RaBucketHistory'
        ([regex]::Matches($s, '\bDELETE\b')).Count | Should -Be 1
    }
}

Describe 'the schema carries the slice time' {
    It 'two nullable columns added in place; the engine checks for them before it reads or writes them' {
        # the schema file is Pro: the free edition has no cfg.RaBucketHistory table to check
        $schemaFile = Join-Path $script:SIRoot 'sql\si-pro-settings.sql'
        if (-not (Test-Path -LiteralPath $schemaFile)) { Set-ItResult -Skipped -Because 'the Pro settings schema is not in this edition'; return }
        $sql = [IO.File]::ReadAllText($schemaFile)
        $sql | Should -Match "IF COL_LENGTH\('cfg\.RaBucketHistory', 'MaxBucketSeconds'\) IS NULL\s+ALTER TABLE cfg\.RaBucketHistory ADD MaxBucketSeconds INT NULL;"
        $sql | Should -Match "IF COL_LENGTH\('cfg\.RaBucketHistory', 'RanCount'\) IS NULL\s+ALTER TABLE cfg\.RaBucketHistory ADD RanCount INT NULL;"
        Get-SIRaBucketSql 'Exists' | Should -Match "COL_LENGTH\(N'cfg\.RaBucketHistory', N'MaxBucketSeconds'\)"
        Get-SIRaBucketSql 'History' | Should -Not -Match 'MaxBucketSeconds'
        Get-SIRaBucketSql 'History' -WithTime | Should -Match 'h\.MaxBucketSeconds, h\.RanCount'
        Get-SIRaBucketSql 'HistoryAdd' -WithTime | Should -Match '@MaxBucketSeconds, @RanCount'
    }
}
