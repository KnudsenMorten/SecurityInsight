#Requires -Version 5.1
<#
    #640 BUCKET SIZING -- THE CORE OF RISK ANALYSIS (owner 2026-10-13: "we must this one right, as it is the core of si";
    "also config about sizing should of course be in sql only"; "better to small than too big so they breaks").

    What these tests keep true (offline; the database is an in-memory fake behind the ONE -Invoke seam):
      * with the Pro database the counts are read from and written to the DATABASE ONLY -- never a file;
      * the counts an install learned before are imported ONCE, never over a count the database already has;
      * a one-time reset is consumed ONCE (the next run forgets that report's count; the run after it does not);
      * "Reset query split memory" (ResetCache) still forgets every count;
      * a count taken unchanged from what was remembered is NOT re-confirmed (the defect that kept a rogue count forever);
        a probed, raised or sized count is; a successful LOWER count after a reset / challenger replaces the old one;
      * step 2: the jump warning (4 x usual with 3 earlier runs, or above 256) -> one guard event in the catalog;
      * step 3: half the count only after 3 runs far below every limit, never right after a raise, never down to the
        count that last overflowed;
      * step 4: the count from a measured result -- half the limits, next power of two, at least 1;
      * without the Pro database the file cache works exactly as before.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-AutoBucketing.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-BucketStore.ps1')
    function Write-Info { param($msg) $script:Logged += ,[string]$msg }
    function Write-Warn2 { param($msg) $script:Logged += ,[string]$msg }
    $script:AutoBucketConfirmedKey = '__confirmed'

    # THE FAKE DATABASE: the four tables in memory, answering exactly the statements of Get-SIRaBucketSql.
    function New-FakeBucketDb {
        $db = [pscustomobject]@{ State = New-Object System.Collections.Generic.List[object]; History = New-Object System.Collections.Generic.List[object]
                                 Resets = New-Object System.Collections.Generic.List[object]; Imports = New-Object System.Collections.Generic.List[object]
                                 Calls = New-Object System.Collections.Generic.List[string]; NextId = 1; Tables = $true }
        $sql = @{}; foreach ($n in 'Exists', 'State', 'Upsert', 'Delete', 'DeleteTemplate', 'ConsumeResets', 'History', 'HistoryAdd', 'Imported', 'ImportMark') { $sql[$n] = Get-SIRaBucketSql $n }
        $invoke = {
            param([string]$s, $p, [string]$mode)
            $name = @($sql.Keys | Where-Object { $sql[$_] -eq $s })[0]
            $db.Calls.Add([string]$name)
            switch ($name) {
                'Exists' { return ,@(@{ HasTables = $(if ($db.Tables) { 1 } else { 0 }) }) }
                'State' { return ,@($db.State | Where-Object { $_.Template -eq $p.Template } | ForEach-Object { @{ ReportName = $_.ReportName; Fingerprint = $_.Fingerprint; BucketCount = $_.BucketCount; ConfirmedUtc = $_.ConfirmedUtc } }) }
                'Upsert' {
                    $row = @($db.State | Where-Object { $_.Template -eq $p.Template -and $_.ReportName -eq $p.ReportName -and $_.Fingerprint -eq $p.Fingerprint })[0]
                    if ($row) { $row.BucketCount = $p.BucketCount; $row.ConfirmedUtc = $p.ConfirmedUtc }
                    else { $db.State.Add([pscustomobject]@{ Template = $p.Template; ReportName = $p.ReportName; Fingerprint = $p.Fingerprint; BucketCount = $p.BucketCount; ConfirmedUtc = $p.ConfirmedUtc }) }
                    return
                }
                'Delete' { foreach ($r in @($db.State | Where-Object { $_.Template -eq $p.Template -and $_.ReportName -eq $p.ReportName -and $_.Fingerprint -eq $p.Fingerprint })) { [void]$db.State.Remove($r) }; return }
                'DeleteTemplate' { foreach ($r in @($db.State | Where-Object { $_.Template -eq $p.Template })) { [void]$db.State.Remove($r) }; return }
                'ConsumeResets' {
                    $pend = @($db.Resets | Where-Object { $_.Template -eq $p.Template -and -not $_.AppliedUtc })
                    $all = @($pend | Where-Object { -not $_.ReportName }).Count -gt 0
                    $names = @($pend | Where-Object { $_.ReportName } | ForEach-Object { $_.ReportName })
                    foreach ($r in @($db.State | Where-Object { $_.Template -eq $p.Template -and ($all -or $names -contains $_.ReportName) })) { [void]$db.State.Remove($r) }
                    foreach ($x in $pend) { $x.AppliedUtc = [datetime]::UtcNow; $x.AppliedRunId = $p.RunId }
                    return ,@($pend | ForEach-Object { @{ ResetId = $_.ResetId; ReportName = $(if ($_.ReportName) { $_.ReportName } else { '*' }) } })
                }
                'History' { return ,@($db.History | Where-Object { $_.Template -eq $p.Template } | Sort-Object Id -Descending | ForEach-Object { $h = @{}; foreach ($q in $_.PSObject.Properties) { $h[$q.Name] = $q.Value }; $h }) }
                'HistoryAdd' { $o = [pscustomobject]@{ Id = $db.NextId }; $db.NextId++; foreach ($k in $p.Keys) { $o | Add-Member -NotePropertyName $k -NotePropertyValue $p[$k] -Force }; $db.History.Add($o); return }
                'Imported' { return ,@(@{ N = @($db.Imports | Where-Object { $_.Template -eq $p.Template }).Count }) }
                'ImportMark' { if (-not @($db.Imports | Where-Object { $_.Template -eq $p.Template }).Count) { $db.Imports.Add([pscustomobject]@{ Template = $p.Template; Entries = $p.Entries }) }; return }
                default { throw "unexpected statement: $s" }
            }
        }.GetNewClosure()
        $db | Add-Member -NotePropertyName Invoke -NotePropertyValue $invoke
        $db
    }
    function Add-FakeReset { param($Db, [string]$Template, [string]$Report) $Db.Resets.Add([pscustomobject]@{ ResetId = $Db.Resets.Count + 1; Template = $Template; ReportName = $Report; AppliedUtc = $null; AppliedRunId = $null }) }

    function Reset-BucketState {
        $script:Logged = @()
        $script:AutoBucketMemo = @{}
        $script:AutoBucketSql = $null
        $script:AutoBucketJumps = $null
        $global:AutoBucketCache = $true
        $global:SettingsPath = Join-Path ([IO.Path]::GetTempPath()) ('si-bucket-test-' + [guid]::NewGuid().ToString('N'))
        $global:AutoBucketMaxRampDoublings = $null
        $global:AutoBucketChallenger_MedianMultiplier = $null; $global:AutoBucketChallenger_MinEntries = $null; $global:AutoBucketChallenger_ConfirmDays = $null
    }
    function New-FitProbe { param([int]$SucceedAt)
        return { param([int]$BucketCount) $global:BucketProbeAttempts += ,[int]$BucketCount; if ($BucketCount -lt $SucceedAt) { throw 'Request Entity Too Large' }; 'ok' }.GetNewClosure() }
}

AfterAll { $global:SettingsPath = $null; $global:AutoBucketMaxRampDoublings = $null }

Describe 'the counts live in the database only' {
    BeforeEach { Reset-BucketState }

    It 'reads the template''s counts from the database and writes only what changed -- no file is created' {
        $db = New-FakeBucketDb
        $db.State.Add([pscustomobject]@{ Template = 'RiskAnalysis_Summary'; ReportName = 'A'; Fingerprint = '111'; BucketCount = 8; ConfirmedUtc = $null })
        $db.State.Add([pscustomobject]@{ Template = 'RiskAnalysis_Detailed'; ReportName = 'A'; Fingerprint = '111'; BucketCount = 64; ConfirmedUtc = $null })
        $r = Initialize-AutoBucketSqlStore -Invoke $db.Invoke -Template 'RiskAnalysis_Summary' -RunId 'run-1'
        $r.Offline | Should -BeFalse
        $r.Entries | Should -Be 1
        $path = Get-AutoBucketCachePath -SettingsPath $global:SettingsPath
        $c = Read-AutoBucketCache -Path $path
        $c['A|111'] | Should -Be 8
        $c['B|222'] = 4
        $db.Calls.Clear()
        Write-AutoBucketCache -Path $path -CacheObject $c
        @($db.Calls) | Should -Be @('Upsert')
        @($db.State | Where-Object { $_.ReportName -eq 'B' }).Count | Should -Be 1
        Test-Path -LiteralPath $path | Should -BeFalse
        # unchanged: nothing is sent
        $db.Calls.Clear(); Write-AutoBucketCache -Path $path -CacheObject (Read-AutoBucketCache -Path $path); $db.Calls.Count | Should -Be 0
    }

    It 'a cache hit is served from the database state and tagged "cache"' {
        $db = New-FakeBucketDb
        $db.State.Add([pscustomobject]@{ Template = 'T'; ReportName = 'A'; Fingerprint = '111'; BucketCount = 16; ConfirmedUtc = $null })
        $null = Initialize-AutoBucketSqlStore -Invoke $db.Invoke -Template 'T' -RunId 'r'
        $global:BucketProbeAttempts = @()
        Get-OptimalBucketCount -QueryKey 'A|111' -MaxBucketCount 1024 -MinBucketCount 2 -ProbeScript (New-FitProbe 4) | Should -Be 16
        $script:_AutoBucketSource | Should -Be 'cache'
        $global:BucketProbeAttempts.Count | Should -Be 0
    }

    It 'a database that cannot be read: the run keeps nothing and never falls back to a file' {
        $bad = { param($s, $p, $m) throw 'login failed' }
        $r = Initialize-AutoBucketSqlStore -Invoke $bad -Template 'T' -RunId 'r'
        $r.Offline | Should -BeTrue
        $path = Get-AutoBucketCachePath -SettingsPath $global:SettingsPath
        Write-AutoBucketCache -Path $path -CacheObject @{ 'A|1' = 4 }
        Test-Path -LiteralPath $path | Should -BeFalse
        (Read-AutoBucketCache -Path $path)['A|1'] | Should -Be 4
    }

    It 'without the Pro database the file cache works as before' {
        $path = Get-AutoBucketCachePath -SettingsPath $global:SettingsPath
        Write-AutoBucketCache -Path $path -CacheObject @{ 'A|1' = 4 }
        Test-Path -LiteralPath $path | Should -BeTrue
        (Read-AutoBucketCache -Path $path)['A|1'] | Should -Be 4
    }
}

Describe 'the one-time import of the counts learned before' {
    BeforeEach { Reset-BucketState }

    It 'imports once, never over a count the database already has, and the next run skips it' {
        $db = New-FakeBucketDb
        $db.State.Add([pscustomobject]@{ Template = 'T'; ReportName = 'A'; Fingerprint = '111'; BucketCount = 32; ConfirmedUtc = $null })
        $old = @{ 'A|111' = 4; 'B|222' = 128; '__confirmed' = @{ 'B|222' = '2026-10-01T06:00:00.0000000Z' } }
        $r = Initialize-AutoBucketSqlStore -Invoke $db.Invoke -Template 'T' -RunId 'r1' -ImportCache $old
        $r.Imported | Should -Be 1
        @($db.State | Where-Object { $_.ReportName -eq 'A' })[0].BucketCount | Should -Be 32      # the database wins
        $b = @($db.State | Where-Object { $_.ReportName -eq 'B' })[0]
        $b.BucketCount | Should -Be 128
        $b.ConfirmedUtc | Should -Not -BeNullOrEmpty
        $r2 = Initialize-AutoBucketSqlStore -Invoke $db.Invoke -Template 'T' -RunId 'r2' -ImportCache @{ 'C|333' = 2 }
        $r2.Imported | Should -Be -1
        @($db.State | Where-Object { $_.ReportName -eq 'C' }).Count | Should -Be 0
    }

    It 'the container reads the earlier counts in every shape they were kept' {
        . (Join-Path $script:SIRoot 'container\_shared\SI-ContainerRunState.ps1')
        $h = ConvertFrom-SIRaAutoBucketCacheJson -Json '{"A|1":8,"__confirmed":{"A|1":"2026-10-01T06:00:00Z"}}'
        $h['A|1'] | Should -Be 8
        $h['__confirmed']['A|1'] | Should -Match '2026-10-01'
        (ConvertFrom-SIRaAutoBucketCacheJson -Json '{"Entries":{"B|2":4}}')['B|2'] | Should -Be 4
        (ConvertFrom-SIRaAutoBucketCacheJson -Json 'not json').Count | Should -Be 0
    }
}

Describe 'the one-time reset' {
    BeforeEach { Reset-BucketState }

    It 'is consumed ONCE: that report is sized again on this run, the next run keeps the new count' {
        $db = New-FakeBucketDb
        $db.State.Add([pscustomobject]@{ Template = 'T'; ReportName = 'A'; Fingerprint = '111'; BucketCount = 10000; ConfirmedUtc = $null })
        $db.State.Add([pscustomobject]@{ Template = 'T'; ReportName = 'B'; Fingerprint = '222'; BucketCount = 8; ConfirmedUtc = $null })
        Add-FakeReset -Db $db -Template 'T' -Report 'A'
        Add-FakeReset -Db $db -Template 'Other' -Report 'A'
        $r = Initialize-AutoBucketSqlStore -Invoke $db.Invoke -Template 'T' -RunId 'run-1'
        @($r.Resets) | Should -Be @('A')
        $db.Resets[0].AppliedRunId | Should -Be 'run-1'
        $db.Resets[1].AppliedUtc | Should -BeNullOrEmpty                 # another template's reset is left for its own run
        $global:BucketProbeAttempts = @()
        $n = Get-OptimalBucketCount -QueryKey 'A|111' -MaxBucketCount 131072 -MinBucketCount 2 -ProbeScript (New-FitProbe 512)
        $n | Should -Be 512                                               # 10000 is gone: probed from the start, the lower count found
        $script:_AutoBucketSource | Should -Be 'probe'
        @($db.State | Where-Object { $_.ReportName -eq 'A' })[0].BucketCount | Should -Be 512
        @($db.State | Where-Object { $_.ReportName -eq 'B' })[0].BucketCount | Should -Be 8
        # the next run: nothing to consume, the new count is used
        $script:AutoBucketMemo = @{}
        $r2 = Initialize-AutoBucketSqlStore -Invoke $db.Invoke -Template 'T' -RunId 'run-2'
        @($r2.Resets).Count | Should -Be 0
        Get-OptimalBucketCount -QueryKey 'A|111' -MaxBucketCount 131072 -MinBucketCount 2 -ProbeScript (New-FitProbe 512) | Should -Be 512
        $script:_AutoBucketSource | Should -Be 'cache'
    }

    It 'a reset of every report (NULL report) forgets them all; ResetCache does too' {
        $db = New-FakeBucketDb
        $db.State.Add([pscustomobject]@{ Template = 'T'; ReportName = 'A'; Fingerprint = '1'; BucketCount = 4; ConfirmedUtc = $null })
        $db.State.Add([pscustomobject]@{ Template = 'T'; ReportName = 'B'; Fingerprint = '2'; BucketCount = 4; ConfirmedUtc = $null })
        Add-FakeReset -Db $db -Template 'T' -Report $null
        $r = Initialize-AutoBucketSqlStore -Invoke $db.Invoke -Template 'T' -RunId 'r'
        @($r.Resets) | Should -Be @('*')
        $r.Entries | Should -Be 0
        $db.State.Add([pscustomobject]@{ Template = 'T'; ReportName = 'C'; Fingerprint = '3'; BucketCount = 4; ConfirmedUtc = $null })
        $r2 = Initialize-AutoBucketSqlStore -Invoke $db.Invoke -Template 'T' -RunId 'r2' -ResetAll
        $r2.Entries | Should -Be 0
    }

    It 'Remove-AutoBucketReportEntries removes a report''s keys and stamps, legacy keys too, and nothing else' {
        $c = @{ 'A|1' = 4; 'A|1|cap131072' = 9; 'AB|2' = 8; '__confirmed' = @{ 'A|1' = 'x'; 'AB|2' = 'y' } }
        $ref = [ref]$c
        @(Remove-AutoBucketReportEntries -Cache $ref -ReportNames @('A')) | Should -Be @('A')
        $c.ContainsKey('A|1') | Should -BeFalse
        $c.ContainsKey('A|1|cap131072') | Should -BeFalse
        $c['AB|2'] | Should -Be 8
        $c['__confirmed'].ContainsKey('AB|2') | Should -BeTrue
    }
}

Describe 'confirm only a count the run decided (the defect that kept a rogue count forever)' {
    It 'a count used unchanged from what was remembered is not re-confirmed' {
        Test-AutoBucketCountDecidedThisRun -Source 'cache' -StartCount 10000 -FinalCount 10000 | Should -BeFalse
        Test-AutoBucketCountDecidedThisRun -Source 'memo' -StartCount 8 -FinalCount 8 | Should -BeFalse
    }
    It 'a probed, sized, configured or raised count is' {
        Test-AutoBucketCountDecidedThisRun -Source 'probe' -StartCount 8 -FinalCount 8 | Should -BeTrue
        Test-AutoBucketCountDecidedThisRun -Source 'measured' -StartCount 8 -FinalCount 8 | Should -BeTrue
        Test-AutoBucketCountDecidedThisRun -Source 'down' -StartCount 4 -FinalCount 4 | Should -BeTrue
        Test-AutoBucketCountDecidedThisRun -Source 'cache' -StartCount 8 -FinalCount 16 | Should -BeTrue
    }
    It 'so a rogue count that is far above the others is re-tested once its pause is over, and the LOWER count replaces it' {
        Reset-BucketState
        $db = New-FakeBucketDb
        $old = [datetime]::UtcNow.AddDays(-8)
        foreach ($i in 1..10) { $db.State.Add([pscustomobject]@{ Template = 'T'; ReportName = "R$i"; Fingerprint = "$i"; BucketCount = 8; ConfirmedUtc = $null }) }
        $db.State.Add([pscustomobject]@{ Template = 'T'; ReportName = 'Rogue'; Fingerprint = '99'; BucketCount = 10000; ConfirmedUtc = $old })
        $null = Initialize-AutoBucketSqlStore -Invoke $db.Invoke -Template 'T' -RunId 'r'
        $global:BucketProbeAttempts = @()
        Get-OptimalBucketCount -QueryKey 'Rogue|99' -MaxBucketCount 131072 -MinBucketCount 2 -ProbeScript (New-FitProbe 512) | Should -Be 512
        @($db.State | Where-Object { $_.ReportName -eq 'Rogue' })[0].BucketCount | Should -Be 512
    }
}

Describe 'step 2: the jump warning' {
    It 'above 256, or 4 x the usual count with 3 earlier runs' {
        Test-SIRaBucketJump -Count 512 -Usual $null | Should -Match 'above 256'
        Test-SIRaBucketJump -Count 64 -Usual 16 | Should -Match '4 x'
        Test-SIRaBucketJump -Count 63 -Usual 16 | Should -Be ''
        Get-SIRaBucketUsual -Counts @(16, 16) | Should -BeNullOrEmpty
        Get-SIRaBucketUsual -Counts @(8, 16, 32) | Should -Be 16
    }
    It 'the run''s jumps become ONE warning event of a guard in the catalog, naming every report' {
        $c = @(Get-SIRaBucketJumpGuardCalls -Template 'RiskAnalysis_Detailed' -Jumps @([pscustomobject]@{ Report = 'A'; Count = 512; Usual = 32; Why = '512 buckets is above 256' }, [pscustomobject]@{ Report = 'B'; Count = 64; Usual = 16; Why = 'x' }))
        $c.Count | Should -Be 1
        $c[0].GuardId | Should -Be 'ra.bucket.count-jump'
        $c[0].Outcome | Should -Be 'warning'
        $c[0].Detail | Should -Match 'A: 512 buckets'
        $c[0].Detail | Should -Match 'B: x'
        $cat = Get-Content -Raw (Join-Path $script:SIRoot 'config\guard-catalog.locked.json') | ConvertFrom-Json
        @($cat.guards | Where-Object { $_.id -eq 'ra.bucket.count-jump' }).Count | Should -Be 1
        @(Get-SIRaBucketJumpGuardCalls -Template 'T' -Jumps @()).Count | Should -Be 0
    }
    It 'a report''s run records its history row with the usual count and the jump flag, and the jump is collected' {
        Reset-BucketState
        $db = New-FakeBucketDb
        foreach ($i in 1..3) { $db.History.Add([pscustomobject]@{ Id = $i; Template = 'T'; ReportName = 'A'; BucketCount = 32; StartCount = 32; Decided = 'cache'; RunUtc = [datetime]::UtcNow }) }
        $db.NextId = 10
        $null = Initialize-AutoBucketSqlStore -Invoke $db.Invoke -Template 'T' -RunId 'r9'
        Reset-AutoBucketMeasure
        Add-AutoBucketMeasure -Rows 100 -Sample @([pscustomobject]@{ a = 'x' })
        $why = Complete-AutoBucketReport -ReportName 'A' -QueryKey 'A|1' -StartCount 32 -FinalCount 128 -Source 'cache'
        $why | Should -Match '4 x'
        $h = @($db.History | Where-Object { $_.RunId -eq 'r9' })[0]
        $h.Decided | Should -Be 'raised'
        $h.UsualCount | Should -Be 32
        $h.Jump | Should -BeTrue
        $h.ResultRows | Should -Be 100
        $script:AutoBucketJumps.Count | Should -Be 1
    }
}

Describe 'step 3: sizing down, carefully' {
    BeforeAll {
        function Far { param([int]$c, [string]$d = 'cache') [pscustomobject]@{ BucketCount = $c; StartCount = $c; Decided = $d; MaxBucketRows = 1000; MaxBucketBytes = 500000; MaxRequestBytes = 0; RequestOverheadBytes = 0 } }
    }
    It 'halves only after 3 runs at this count far below every limit' {
        (Get-SIRaBucketDownCount -Count 64 -Floor 2 -History @((Far 64), (Far 64), (Far 64))).Count | Should -Be 32
        (Get-SIRaBucketDownCount -Count 64 -Floor 2 -History @((Far 64), (Far 64))).Down | Should -BeFalse
    }
    It 'never right after a raise or a resize, never with one run near a limit' {
        (Get-SIRaBucketDownCount -Count 64 -Floor 2 -History @((Far 64), (Far 64 'raised'), (Far 64))).Down | Should -BeFalse
        (Get-SIRaBucketDownCount -Count 64 -Floor 2 -History @((Far 64), (Far 64 'down'), (Far 64))).Down | Should -BeFalse
        $near = Far 64; $near.MaxBucketRows = 9000
        (Get-SIRaBucketDownCount -Count 64 -Floor 2 -History @((Far 64), $near, (Far 64))).Down | Should -BeFalse
    }
    It 'never down to the count that last overflowed, never below the floor' {
        $raised = [pscustomobject]@{ BucketCount = 64; StartCount = 32; Decided = 'raised'; MaxBucketRows = 100; MaxBucketBytes = 100 }
        (Get-SIRaBucketDownCount -Count 64 -Floor 2 -History @((Far 64), (Far 64), (Far 64), $raised)).Down | Should -BeFalse
        (Get-SIRaBucketDownCount -Count 2 -Floor 2 -History @((Far 2), (Far 2), (Far 2))).Down | Should -BeFalse
    }
}

Describe 'step 4: the count from a measured result' {
    It 'half the limits, the next power of two, at least 1' {
        # 1,000,000 rows / (30,000 / 2) = 66.7 -> 128
        Get-SIRaBucketCountFromMeasure -Measure ([pscustomobject]@{ ResultRows = 1000000; MaxBucketRows = 0; MaxBucketBytes = 0 }) | Should -Be 128
        # 600,000 rows x 1,000 bytes = 600 MB / 32 MB = 18.75 -> 32 (the bytes need more than the rows: 40 -> 64)
        Get-SIRaBucketCountFromMeasure -Measure ([pscustomobject]@{ ResultRows = 600000; MaxBucketRows = 1000; MaxBucketBytes = 1000000 }) | Should -Be 64
        Get-SIRaBucketCountFromMeasure -Measure ([pscustomobject]@{ ResultRows = 10; MaxBucketRows = 10; MaxBucketBytes = 1000 }) | Should -Be 1
        Get-SIRaBucketCountFromMeasure -Measure ([pscustomobject]@{ ResultRows = 0 }) | Should -BeNullOrEmpty
        # a request whose inlined lookup is 200,000 rows x 170 bytes with 150 KB around it: 39.1 MB / 362 KB = 108 -> 128
        Get-SIRaBucketCountFromMeasure -Measure ([pscustomobject]@{ ResultRows = 0; RequestRows = 200000; RequestBytesPerRow = 170; RequestOverheadBytes = 153600 }) | Should -Be 128
    }
    It 'is used as the start only when the report has no remembered count for its query' {
        Reset-BucketState
        $db = New-FakeBucketDb
        $db.History.Add([pscustomobject]@{ Id = 1; Template = 'T'; ReportName = 'A'; BucketCount = 4; StartCount = 4; Decided = 'cache'; ResultRows = 1000000; RunUtc = [datetime]::UtcNow })
        $db.State.Add([pscustomobject]@{ Template = 'T'; ReportName = 'B'; Fingerprint = '2'; BucketCount = 4; ConfirmedUtc = $null })
        $db.History.Add([pscustomobject]@{ Id = 2; Template = 'T'; ReportName = 'B'; BucketCount = 4; StartCount = 4; Decided = 'cache'; ResultRows = 1000000; RunUtc = [datetime]::UtcNow })
        $null = Initialize-AutoBucketSqlStore -Invoke $db.Invoke -Template 'T' -RunId 'r'
        (Get-AutoBucketStartPlan -ReportName 'A' -QueryKey 'A|1' -Floor 2 -Cap 131072).MinCount | Should -Be 128
        (Get-AutoBucketStartPlan -ReportName 'B' -QueryKey 'B|2' -Floor 2 -Cap 131072).Measured | Should -BeNullOrEmpty
        (Get-AutoBucketStartPlan -ReportName 'C' -QueryKey 'C|3' -Floor 2 -Cap 131072).MinCount | Should -Be 2
    }
}

Describe 'step 5 (#697): a count no failure proved comes back down, run over run -- a count a failure proved stays' {
    # The internal Detailed run of 2026-10-15: Attack_Paths_Detailed_Credential_Based_Lateral_Movement ran 16 buckets for
    # 25 rows (884 s). Its count came from a measured result whose REQUEST numbers were the run's largest (lookup rows,
    # row width, query text of all reports so far), while every request it sent was a few KB.
    BeforeAll {
        function Run { param([int]$c, [string]$d = 'cache', [long]$rows = 25, [long]$req = 40000, $reqRows = $null, $bpr = $null, $over = $null, [int]$start = 0)
            [pscustomobject]@{ BucketCount = $c; StartCount = $(if ($start) { $start } else { $c }); Decided = $d; ResultRows = $rows; MaxBucketRows = 3; MaxBucketBytes = 3000
                               MaxRequestBytes = $req; RequestRows = $reqRows; RequestBytesPerRow = $bpr; RequestOverheadBytes = $over } }
    }

    It 'the measured need is bounded by the request the report really sent (never more than before)' {
        # the 2026-10-15 history row: run-wide numbers 10,352 rows x 241 bytes beside 300 KB of query text -> 12.8 -> 16 ...
        Get-SIRaBucketCountFromMeasure -Measure (Run 16 'measured' -req 0 -reqRows 10352 -bpr 241 -over 300000) | Should -Be 16
        # ... while the largest request it sent at 16 buckets was 40 KB: 40 KB x 16 / 512 KB = 1.2 -> 2
        Get-SIRaBucketCountFromMeasure -Measure (Run 16 'measured' -reqRows 10352 -bpr 241 -over 300000) | Should -Be 2
        # a request that really was large keeps its need: 900 KB sent at 4 buckets = 7 -> 8
        Get-SIRaBucketCountFromMeasure -Measure (Run 4 'cache' -rows 10 -req 921600) | Should -Be 8
        # the bound never raises what the lookup numbers say (it is the smaller of the two)
        Get-SIRaBucketCountFromMeasure -Measure ([pscustomobject]@{ ResultRows = 0; RequestRows = 200000; RequestBytesPerRow = 170; RequestOverheadBytes = 153600; MaxRequestBytes = 1000000; BucketCount = 512 }) | Should -Be 128
    }

    It 'a report that measured many buckets for few rows goes back down -- half per run, to what it measured, not below the floor' {
        $c = 16; $h = @((Run 16 'measured' -reqRows 10352 -bpr 241 -over 300000))
        $seen = @()
        foreach ($i in 1..5) {
            $s = Get-SIRaBucketShrinkCount -Count $c -Floor 2 -History $h
            if (-not $s.Down) { break }
            $s.Why | Should -Match 'no failed query needed more'
            $c = $s.Count; $seen += $c
            $h = @((Run $c 'down')) + $h      # the next run, at the smaller count, measured the same few rows
        }
        $seen | Should -Be @(8, 4, 2)
        (Get-SIRaBucketShrinkCount -Count 2 -Floor 2 -History $h).Down | Should -BeFalse
    }

    It 'one whose bucket failed stays: a raise or a probe that climbed above the configured count is never gone below' {
        # a bucket of the run at 8 was refused / timed out and the run had to raise to 16
        (Get-SIRaBucketShrinkCount -Count 16 -Floor 2 -History @((Run 16 'cache'), (Run 16 'raised' -start 8))).Down | Should -BeFalse
        # the probe failed at 2 and 4 and chose 16 (a compute ceiling is invisible in rows and request size)
        (Get-SIRaBucketShrinkCount -Count 16 -Floor 2 -History @((Run 16 'cache'), (Run 16 'probe'))).Down | Should -BeFalse
        # a probe at the configured count proves nothing
        (Get-SIRaBucketShrinkCount -Count 16 -Floor 2 -History @((Run 16 'cache'), (Run 2 'probe'))).Count | Should -Be 8
        # a proven 8 under a count of 32: down to 16, then never below 8
        (Get-SIRaBucketShrinkCount -Count 32 -Floor 2 -History @((Run 32 'cache'), (Run 8 'raised' -start 4))).Count | Should -Be 16
        (Get-SIRaBucketShrinkCount -Count 16 -Floor 2 -History @((Run 16 'down'), (Run 32 'cache'), (Run 8 'raised' -start 4))).Count | Should -Be 8
        (Get-SIRaBucketShrinkCount -Count 8 -Floor 2 -History @((Run 8 'down'), (Run 16 'down'), (Run 8 'raised' -start 4))).Down | Should -BeFalse
        Get-SIRaBucketProvenCount -History @((Run 2 'probe'), (Run 64 'raised'), (Run 32 'probe')) -Floor 2 | Should -Be 64
    }

    It 'nothing measured, or a measure of another count, changes nothing' {
        (Get-SIRaBucketShrinkCount -Count 16 -Floor 2 -History @()).Down | Should -BeFalse
        (Get-SIRaBucketShrinkCount -Count 16 -Floor 2 -History @((Run 8 'cache'))).Down | Should -BeFalse
        (Get-SIRaBucketShrinkCount -Count 16 -Floor 2 -History @([pscustomobject]@{ BucketCount = 16; StartCount = 16; Decided = 'cache'; ResultRows = 0 })).Down | Should -BeFalse
        # many rows really need the count: 400,000 rows / 15,000 = 26.7 -> 32
        (Get-SIRaBucketShrinkCount -Count 32 -Floor 2 -History @((Run 32 'cache' -rows 400000))).Down | Should -BeFalse
    }

    It 'the report loop''s down plan applies it to a remembered count, from the database history' {
        Reset-BucketState
        $db = New-FakeBucketDb
        $db.History.Add([pscustomobject]@{ Id = 1; Template = 'T'; ReportName = 'A'; BucketCount = 16; StartCount = 16; Decided = 'measured'; ResultRows = 25; MaxBucketRows = 3; MaxBucketBytes = 3000; MaxRequestBytes = 40000; RequestRows = 10352; RequestBytesPerRow = 241; RequestOverheadBytes = 300000; RunUtc = [datetime]::UtcNow })
        $db.History.Add([pscustomobject]@{ Id = 2; Template = 'T'; ReportName = 'B'; BucketCount = 16; StartCount = 16; Decided = 'cache'; ResultRows = 25; MaxBucketRows = 3; MaxBucketBytes = 3000; MaxRequestBytes = 40000; RunUtc = [datetime]::UtcNow.AddMinutes(-1) })
        $db.History.Add([pscustomobject]@{ Id = 3; Template = 'T'; ReportName = 'B'; BucketCount = 16; StartCount = 16; Decided = 'cache'; ResultRows = 25; MaxBucketRows = 3; MaxBucketBytes = 3000; MaxRequestBytes = 40000; RunUtc = [datetime]::UtcNow })
        $db.History.Add([pscustomobject]@{ Id = 0; Template = 'T'; ReportName = 'B'; BucketCount = 16; StartCount = 8; Decided = 'raised'; ResultRows = 25; MaxBucketRows = 3; MaxBucketBytes = 3000; MaxRequestBytes = 40000; RunUtc = [datetime]::UtcNow.AddDays(-2) })
        $null = Initialize-AutoBucketSqlStore -Invoke $db.Invoke -Template 'T' -RunId 'r'
        $a = Get-AutoBucketDownPlan -ReportName 'A' -Count 16 -Floor 2
        $a.Down | Should -BeTrue
        $a.Count | Should -Be 8
        (Get-AutoBucketDownPlan -ReportName 'B' -Count 16 -Floor 2).Down | Should -BeFalse
    }

    It 'a changed query starts from the measure, never below a count a failure proved' {
        Reset-BucketState
        $db = New-FakeBucketDb
        $db.History.Add([pscustomobject]@{ Id = 1; Template = 'T'; ReportName = 'A'; BucketCount = 16; StartCount = 16; Decided = 'measured'; ResultRows = 25; MaxBucketRows = 3; MaxBucketBytes = 3000; MaxRequestBytes = 40000; RequestRows = 10352; RequestBytesPerRow = 241; RequestOverheadBytes = 300000; RunUtc = [datetime]::UtcNow })
        $db.History.Add([pscustomobject]@{ Id = 2; Template = 'T'; ReportName = 'B'; BucketCount = 16; StartCount = 16; Decided = 'cache'; ResultRows = 25; MaxBucketRows = 3; MaxBucketBytes = 3000; MaxRequestBytes = 40000; RunUtc = [datetime]::UtcNow })
        $db.History.Add([pscustomobject]@{ Id = 0; Template = 'T'; ReportName = 'B'; BucketCount = 32; StartCount = 16; Decided = 'raised'; ResultRows = 25; MaxBucketRows = 3; MaxBucketBytes = 3000; RunUtc = [datetime]::UtcNow.AddDays(-2) })
        $null = Initialize-AutoBucketSqlStore -Invoke $db.Invoke -Template 'T' -RunId 'r'
        (Get-AutoBucketStartPlan -ReportName 'A' -QueryKey 'A|9' -Floor 2 -Cap 131072).MinCount | Should -Be 2
        (Get-AutoBucketStartPlan -ReportName 'B' -QueryKey 'B|9' -Floor 2 -Cap 131072).MinCount | Should -Be 32
    }

    It 'the probe says whether a rung failed: only then is its count a proved one' {
        Reset-BucketState
        $global:AutoBucketCache = $false
        $global:BucketProbeAttempts = @()
        Get-OptimalBucketCount -QueryKey 'P|1' -MaxBucketCount 1024 -MinBucketCount 16 -ProbeScript (New-FitProbe 2) | Should -Be 16
        $script:_AutoBucketProbeFailed | Should -BeFalse
        $script:AutoBucketMemo = @{}
        Get-OptimalBucketCount -QueryKey 'P|2' -MaxBucketCount 1024 -MinBucketCount 2 -ProbeScript (New-FitProbe 3) | Should -Be 3
        $script:_AutoBucketProbeFailed | Should -BeTrue
    }

    It 'the history row carries the report''s OWN request numbers: the lookups it split, and the part no count shrinks' {
        Reset-AutoBucketMeasure
        # bucket 1/2 and 2/2 of a report: one lookup split per bucket (2,000 + 2,100 rows), one copied whole (520 rows)
        foreach ($s in @(@{ Body = 600000; Fixed = 120000; Split = 2000; SplitBytes = 480000 }, @{ Body = 620000; Fixed = 116000; Split = 2100; SplitBytes = 504000 })) {
            $shape = @{ BodyBytes = $s.Body; FixedBytes = $s.Fixed; BucketCount = 2
                        Lookups = @(@{ Name = '_ciLink'; Rows = $s.Split; WireBytes = $s.SplitBytes; Whole = $false }, @{ Name = '_ciPeer'; Rows = 520; WireBytes = 97000; Whole = $true }) }
            Add-AutoBucketMeasure -Rows 10 -Sample @([pscustomobject]@{ a = 1 }) -RequestBytes 999999 -RequestShape $shape
        }
        $script:AutoBucketMeasure.MaxRequestBytes | Should -Be 620000 -Because 'the request really sent, not the estimate'
        $r = Get-AutoBucketRequestMeasure -Measure $script:AutoBucketMeasure
        $r.Rows | Should -Be 4100
        $r.BytesPerRow | Should -Be 240
        $r.OverheadBytes | Should -Be 120000
        # no shape (not an inlined request): the estimate as before, and no request numbers
        Reset-AutoBucketMeasure
        Add-AutoBucketMeasure -Rows 5 -RequestBytes 1234
        $script:AutoBucketMeasure.MaxRequestBytes | Should -Be 1234
        (Get-AutoBucketRequestMeasure -Measure $script:AutoBucketMeasure).Rows | Should -Be 0
    }

    It 'WIRING: the report loop records its own request numbers and the shape of what each bucket sent' {
        $eng = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'))
        $eng | Should -Match '-RequestShape \$\(if \(\[long\]\$script:_LastHybridInlineBytes -gt 0\) \{ \$script:_RAHybridLastRequest \}'
        $eng | Should -Match '(?s)\$__abReq = Get-AutoBucketRequestMeasure -Measure \$script:AutoBucketMeasure\s*\r?\n\s*\$__abJump = Complete-AutoBucketReport'
        $eng | Should -Not -Match '-RequestRows \(\[long\]\$script:_LastHybridSnapshotRowCount\)'
        $eng | Should -Match '-and -not \[bool\]\$script:_AutoBucketProbeFailed\) \{ \$script:_AutoBucketSource = ''measured'' \}'
    }
}

# The schema, the web app's one grant (INSERT on the reset table) and that none of the tables is configuration are held by
# the web tests (WebWriteGrantsTests) and SIv3-ConfigJournal -- kept out of here so this free suite names no Pro file.
