#Requires -Version 7.0
<#
    A REPORT'S SLICE COUNT IS KEPT AS SOON AS IT WORKS -- and a changed query starts from the count it used before.

    Live 2026-10-16: Device_Missing_CVEs_Detailed takes ~8 hours in 64 slices, and two runs were stopped part-way. The
    count was written only when the whole report had succeeded, so it was never kept and every run paid the sizing again
    (failed and re-split requests). And a new build changes the report's query fingerprint, so the count the report ran
    complete with before (24 slices) was under another key -- and was evicted as stale -- and the report sized again.
    What these tests keep true (offline; the file store and the Pro database fake behind the ONE -Invoke seam):
      * Save-AutoBucketCountEarly writes the count after a slice succeeded at it, NOT stamped confirmed; a run stopped
        part-way therefore leaves it, and the next run takes it as a remembered count (no probe);
      * it only goes UP (a lower count tried this run never replaces a higher remembered one), and the same count twice
        writes once;
      * the same in the Pro database (an upsert without a confirmed time);
      * Get-AutoBucketPreviousCount: with nothing remembered for the current query, the largest count remembered for the
        same report under another fingerprint (never below a count a failure proved, within floor and cap); nothing when
        the current query has a count, or the report has no earlier one;
      * the engine wiring: the early save sits in the slice loop after a slice's rows are handed on, and the earlier
        count is asked before the measured / probed sizing.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-AutoBucketing.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-BucketStore.ps1')
    function Write-Info { param($msg) $script:Logged += ,[string]$msg }
    function Write-Warn2 { param($msg) $script:Logged += ,[string]$msg }
    $script:AutoBucketConfirmedKey = '__confirmed'
    function Reset-BucketState {
        $script:Logged = @()
        $script:AutoBucketMemo = @{}
        $script:AutoBucketSql = $null
        $global:AutoBucketCache = $true
        $global:SettingsPath = Join-Path ([IO.Path]::GetTempPath()) ('si-bucket-early-' + [guid]::NewGuid().ToString('N'))
    }
    # a minimal Pro database: the state table only, answering the statements the store sends
    function New-FakeStateDb {
        $db = [pscustomobject]@{ State = New-Object System.Collections.Generic.List[object]; Calls = New-Object System.Collections.Generic.List[object] }
        $sql = @{}; foreach ($n in 'Upsert', 'Delete') { $sql[$n] = Get-SIRaBucketSql $n }
        $invoke = {
            param([string]$s, $p, [string]$mode)
            $name = @($sql.Keys | Where-Object { $sql[$_] -eq $s })[0]
            $db.Calls.Add([pscustomobject]@{ Name = $name; Params = $p })
            if ($name -eq 'Upsert') {
                $row = @($db.State | Where-Object { $_.ReportName -eq $p.ReportName -and $_.Fingerprint -eq $p.Fingerprint })[0]
                if ($row) { $row.BucketCount = $p.BucketCount; $row.ConfirmedUtc = $p.ConfirmedUtc } else { $db.State.Add([pscustomobject]@{ ReportName = $p.ReportName; Fingerprint = $p.Fingerprint; BucketCount = $p.BucketCount; ConfirmedUtc = $p.ConfirmedUtc }) }
            }
        }.GetNewClosure()
        $db | Add-Member -NotePropertyName Invoke -NotePropertyValue $invoke
        $db
    }
}

AfterAll { $global:SettingsPath = $null }

Describe 'the count is kept as soon as a slice succeeded at it' {
    BeforeEach { Reset-BucketState }

    It 'a run stopped part-way leaves the count; the next run takes it without probing' {
        $key = 'Device_Missing_CVEs_Detailed|123456'
        Save-AutoBucketCountEarly -QueryKey $key -Count 64 | Should -BeTrue
        # ... the run is stopped here: the end-of-report write never happens
        $path = Get-AutoBucketCachePath -SettingsPath $global:SettingsPath
        $c = Read-AutoBucketCache -Path $path
        $c[$key] | Should -Be 64
        $c.ContainsKey('__confirmed') | Should -BeFalse -Because 'kept early is not confirmed'
        # the next run (a new process: nothing in memory)
        $script:AutoBucketMemo = @{}
        $global:Probed = @()
        $n = Get-OptimalBucketCount -QueryKey $key -MaxBucketCount 4096 -MinBucketCount 8 -ProbeScript { param([int]$BucketCount) $global:Probed += $BucketCount }
        $n | Should -Be 64
        $script:_AutoBucketSource | Should -Be 'cache'
        @($global:Probed).Count | Should -Be 0
    }

    It 'only ever goes up, and the same count is written once' {
        $key = 'R|1'
        Save-AutoBucketCountEarly -QueryKey $key -Count 64 | Should -BeTrue
        Save-AutoBucketCountEarly -QueryKey $key -Count 64 | Should -BeFalse
        Save-AutoBucketCountEarly -QueryKey $key -Count 32 | Should -BeFalse -Because 'a lower count tried this run never replaces a higher remembered one'
        (Read-AutoBucketCache -Path (Get-AutoBucketCachePath -SettingsPath $global:SettingsPath))[$key] | Should -Be 64
        Save-AutoBucketCountEarly -QueryKey $key -Count 128 | Should -BeTrue
        (Read-AutoBucketCache -Path (Get-AutoBucketCachePath -SettingsPath $global:SettingsPath))[$key] | Should -Be 128
    }

    It 'writes nothing when the store is off' {
        $global:AutoBucketCache = $false
        Save-AutoBucketCountEarly -QueryKey 'R|1' -Count 8 | Should -BeFalse
    }

    It 'with the Pro database: one upsert, no confirmed time, and a run stopped part-way leaves it there' {
        $db = New-FakeStateDb
        $script:AutoBucketSql = [pscustomobject]@{ Invoke = $db.Invoke; Template = 'RiskAnalysis_Detailed'; RunId = 'r1'; State = @{}; Saved = @{}; History = @{}; Offline = $false }
        Save-AutoBucketCountEarly -QueryKey 'Device_Missing_CVEs_Detailed|987' -Count 64 | Should -BeTrue
        @($db.Calls | Where-Object Name -eq 'Upsert').Count | Should -Be 1
        $db.State[0].BucketCount | Should -Be 64
        $db.State[0].ConfirmedUtc | Should -BeNullOrEmpty
        $db.Calls.Clear()
        Save-AutoBucketCountEarly -QueryKey 'Device_Missing_CVEs_Detailed|987' -Count 64 | Should -BeFalse
        $db.Calls.Count | Should -Be 0
    }
}

Describe 'a changed query starts from the count the report used before' {
    BeforeEach { Reset-BucketState }

    It 'the earlier fingerprint''s count, when nothing is remembered for the current one' {
        $path = Get-AutoBucketCachePath -SettingsPath $global:SettingsPath
        Write-AutoBucketCache -Path $path -CacheObject @{ 'Device_Missing_CVEs_Detailed|111' = 24; 'Other_Report|111' = 512 }
        Get-AutoBucketPreviousCount -QueryKey 'Device_Missing_CVEs_Detailed|222' -Floor 8 -Cap 4096 | Should -Be 24
        # within the floor and the cap
        Get-AutoBucketPreviousCount -QueryKey 'Device_Missing_CVEs_Detailed|222' -Floor 32 -Cap 4096 | Should -Be 32
        Get-AutoBucketPreviousCount -QueryKey 'Device_Missing_CVEs_Detailed|222' -Floor 1 -Cap 16 | Should -Be 16
        # another report's count is never borrowed
        Get-AutoBucketPreviousCount -QueryKey 'Third_Report|222' -Floor 1 -Cap 4096 | Should -BeNullOrEmpty
    }

    It 'nothing when the current query already has a count (store or memo)' {
        $path = Get-AutoBucketCachePath -SettingsPath $global:SettingsPath
        Write-AutoBucketCache -Path $path -CacheObject @{ 'R|111' = 24; 'R|222' = 8 }
        Get-AutoBucketPreviousCount -QueryKey 'R|222' -Floor 1 -Cap 4096 | Should -BeNullOrEmpty
        Write-AutoBucketCache -Path $path -CacheObject @{ 'R|111' = 24 }
        $script:AutoBucketMemo['R|222'] = 8
        Get-AutoBucketPreviousCount -QueryKey 'R|222' -Floor 1 -Cap 4096 | Should -BeNullOrEmpty
    }

    It 'never below a count a failed query proved necessary (Pro history)' {
        $script:AutoBucketSql = [pscustomobject]@{ Invoke = $null; Template = 'T'; RunId = 'r'; State = @{ 'R|111' = 24 }; Saved = @{}; History = @{ 'R' = @([pscustomobject]@{ BucketCount = 48; Decided = 'raised' }) }; Offline = $true }
        Get-AutoBucketPreviousCount -QueryKey 'R|222' -Floor 8 -Cap 4096 | Should -Be 48
    }
}

Describe 'the engine wiring' {
    BeforeAll { $script:Txt = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1')) }

    It 'keeps the count early inside the slice loop, after the slice''s rows are handed on' {
        $i1 = $script:Txt.IndexOf("Add-RAStreamBucketGuarded -Rows `$bucketResult -Bucket ('{0}/{1}' -f `$bucketNo, `$bucketCountToUse) -Complete:`$bucketIsComplete")
        $i2 = $script:Txt.IndexOf('Save-AutoBucketCountEarly -QueryKey $queryKey -Count ([int]$bucketCountToUse)')
        $i3 = $script:Txt.IndexOf('# No slice count can fit: leave the escalation loop too')
        $i1 | Should -BeGreaterThan 0
        $i2 | Should -BeGreaterThan $i1
        $i3 | Should -BeGreaterThan $i2
        # the end-of-report write is still there, and still confirms
        $script:Txt | Should -Match 'Set-AutoBucketConfirmed -Cache \$_cacheRefL3 -QueryKey \$queryKey'
    }

    It 'asks the measured sizing FIRST; the earlier count only when nothing was measured (#833)' {
        $p = $script:Txt.IndexOf('$__abPlan = Get-AutoBucketStartPlan -ReportName $ReportName')
        $h = $script:Txt.IndexOf('if ($null -eq $__abPlan.Measured) { $__abHint = Get-AutoBucketPreviousCount -QueryKey $queryKey -Floor $effectiveBucketCount -Cap $capBucket }')
        $p | Should -BeGreaterThan 0
        $h | Should -BeGreaterThan $p
    }
}
