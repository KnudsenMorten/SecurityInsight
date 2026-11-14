#Requires -Version 7.0
<#
    HOW MANY COLLECTIONS KEEP THEIR FINDINGS (REQUIREMENTS #1218, owner 2026-11-12, replaces #717's "newest complete + ONE
    before it"): "Last 7 runs" -- "If a database passes 70% full, SI keeps fewer and warns instead of hitting the limit."

    What these tests keep true (engine\_shared\data-sql\SI-DataSql.ps1, engine\pro-data\_shared\SI-DataSync.ps1,
    SI-DataSummaryGroups.ps1, SI-DataKeyFigures.ps1, engine\flow\Invoke-SIJobFlowRun.ps1):
      * SI_Data_KeepCollections: default 7, at least 2, a wrong value = 7 (never a refused run); the plan keeps the newest N
        complete collections per grain and marks 'superseded' only beyond N; the setting changes N;
      * NEGATIVE: never below 2 (whatever is given), never the newest complete collection, never the published one, never a
        run in progress, never a collection a kept one carries rows from;
      * the database at or above 70 % of its maximum: one fewer per run (one step per NEW complete collection, the same
        count for every call of the same run), never below 2, ONE plain warning line (how full, how many kept, what to do);
        below 70 % the setting again; unknown fill = the setting;
      * the pipeline runner's wake-up keeps what the data sync decided (never more removed);
      * the Summary groupings' shown set = the published one + TOP (N) at or before it + the newer ones; the key figures
        build every kept collection in the run (paced, never left to a later run);
      * wiring: the data sync decides once before its first mark and passes the count to both marks, the groupings and the
        key figures; the runner passes it to the wake-up; the setting is in the catalog (min 2).
    Offline (fakes) plus a run against a local SQL Server when SI_TEST_LOCALSQL is set (the test runner). Pro path.
#>

BeforeDiscovery {
    $script:LocalSql = $false
    try { $script:LocalSql = [bool]$env:SI_TEST_LOCALSQL -and $null -ne ('System.Data.SqlClient.SqlConnection' -as [type]) } catch { $script:LocalSql = $false }
}

BeforeAll {
    $script:Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:Root 'engine\_shared\SI-KqlError.ps1')
    . (Join-Path $script:Root 'engine\_shared\SI-SchemaGate.ps1')
    . (Join-Path $script:Root 'engine\_shared\data-sql\SI-DataModel.ps1')
    . (Join-Path $script:Root 'engine\_shared\data-sql\SI-DataSql.ps1')
    . (Join-Path $script:Root 'engine\pro-data\_shared\SI-DataSummaryGroups.ps1')
    . (Join-Path $script:Root 'engine\_shared\SI-ProtectionScore.ps1')
    . (Join-Path $script:Root 'engine\pro-data\_shared\SI-DataKeyFigures.ps1')
    $script:Schema = Get-Content -Raw -LiteralPath (Join-Path $script:Root 'sql\si-data-schema.sql')
    $script:Quiet = { param($l, $m) }
    function script:T([int]$Day, [int]$Hour = 8) { [datetime]::SpecifyKind((Get-Date -Year 2026 -Month 11 -Day $Day -Hour $Hour -Minute 0 -Second 0 -Millisecond 0), 'Utc') }
    function script:Row([string]$Grain, $Id, [datetime]$Time, [string]$Status, [switch]$Published) {
        @{ Grain = $Grain; CollectionId = $Id; CollectionTime = $Time; Status = $Status; RetiredAt = [System.DBNull]::Value; HasRows = 0; Published = $(if ($Published) { 1 } else { 0 }) }
    }
    function script:Act($Plan, [string]$Grain, $Key) {
        $m = @($Plan | Where-Object { $_.Grain -eq $Grain -and ($(if ($Grain -eq 'Summary') { $_.CollectionTime -eq $Key } else { $_.CollectionId -eq $Key })) })
        if ($m.Count) { $m[0].Action } else { '(none)' }
    }
    # nine complete Detailed collections, one a day (ids 1..9, day 1..9)
    function script:Nine([string]$Grain = 'Detailed') { @(1..9 | ForEach-Object { Row $Grain $(if ($Grain -eq 'Detailed') { $_ } else { $null }) (T $_) Complete }) }
    function script:New-LocalInvoke([string]$Db) {
        $cs = "Server=$($env:SI_TEST_LOCALSQL);Database=$Db;$($env:SI_TEST_SQL_AUTH);TrustServerCertificate=True;Connection Timeout=90"
        {
            param([string]$sql, $p, [string]$mode)
            $cn = New-Object System.Data.SqlClient.SqlConnection($cs); $cn.Open()
            try {
                $c = $cn.CreateCommand(); $c.CommandTimeout = 300; $c.CommandText = $sql
                if ($p) { foreach ($k in $p.Keys) { [void]$c.Parameters.AddWithValue('@' + $k, $(if ($null -eq $p[$k]) { [DBNull]::Value } else { $p[$k] })) } }
                if ($mode -eq 'scalar') { return $c.ExecuteScalar() }
                if ($mode -eq 'nonquery') { return $c.ExecuteNonQuery() }
                $r = $c.ExecuteReader(); $rows = New-Object System.Collections.Generic.List[object]
                while ($r.Read()) { $h = @{}; for ($i = 0; $i -lt $r.FieldCount; $i++) { $h[$r.GetName($i)] = $(if ($r.IsDBNull($i)) { $null } else { $r.GetValue($i) }) }; $rows.Add($h) }
                $r.Close(); return , $rows.ToArray()
            } finally { $cn.Close() }
        }.GetNewClosure()
    }
}

AfterAll { Set-SIDataRetiredReady -Ready $false }

Describe 'the setting SI_Data_KeepCollections' {
    It 'default 3 (owner 2026-11-12); a whole number at least 2; a wrong value is 3, never a refused run' {
        Get-SIDataKeepCollectionsSetting -Globals @{} | Should -Be 3
        Get-SIDataKeepCollectionsSetting -Globals @{ SI_Data_KeepCollections = '' } | Should -Be 3
        Get-SIDataKeepCollectionsSetting -Globals @{ SI_Data_KeepCollections = '10' } | Should -Be 10
        Get-SIDataKeepCollectionsSetting -Globals @{ SI_Data_KeepCollections = 4 } | Should -Be 4
        Get-SIDataKeepCollectionsSetting -Globals @{ SI_Data_KeepCollections = 'seven' } | Should -Be 3
        # NEGATIVE: never below 2
        Get-SIDataKeepCollectionsSetting -Globals @{ SI_Data_KeepCollections = '1' } | Should -Be 2
        Get-SIDataKeepCollectionsSetting -Globals @{ SI_Data_KeepCollections = '0' } | Should -Be 2
        Get-SIDataKeepCollectionsSetting -Globals @{ SI_Data_KeepCollections = '-4' } | Should -Be 2
    }
    It 'the data sync''s settings carry it (3 by default) and a wrong value is no Problem' {
        $base = @{ SI_ProSqlServer = 's'; SI_ProSqlDatabase = 'd' }
        $o = Resolve-SIDataSettings -Globals $base
        $o.KeepCollections | Should -Be 3
        @($o.Problems).Count | Should -Be 0
        $base['SI_Data_KeepCollections'] = '5'; (Resolve-SIDataSettings -Globals $base).KeepCollections | Should -Be 5
        $base['SI_Data_KeepCollections'] = 'lots'; $w = Resolve-SIDataSettings -Globals $base
        $w.KeepCollections | Should -Be 3; @($w.Problems).Count | Should -Be 0
    }
    It 'is in the settings catalog: an int, min 2, community, in "How long data is kept", confirmed when lowered' {
        $cat = Get-Content -Raw -LiteralPath (Join-Path $script:Root 'config\settings.catalog.locked.json') | ConvertFrom-Json
        $s = @($cat.settings | Where-Object { $_.name -eq 'SI_Data_KeepCollections' })
        $s.Count | Should -Be 1
        $s[0].type | Should -Be 'int'; $s[0].min | Should -Be 2; $s[0].edition | Should -Be 'community'
        $s[0].card | Should -Be 'How long data is kept'
        $s[0].info.confirmWhen | Should -Be 'lower'
        $s[0].defaultText | Should -Match '^3 collections'
        (Get-Content -Raw -LiteralPath (Join-Path $script:Root 'config\SecurityInsight.custom.reference.ps1')) | Should -Match '(?m)^# \$global:SI_Data_KeepCollections = 3\r?$'
    }
}

Describe 'the plan keeps the newest N complete collections per grain' {
    It 'keeps 7 when asked for 7: the two oldest of nine are superseded, in both grains' {
        $p = Get-SIDataCollectionRetentionPlan -Collections (@(Nine) + @(Nine Summary)) -KeepCollections 7
        foreach ($i in 3..9) { Act $p Detailed $i | Should -Be 'Keep' -Because "collection $i is one of the newest 7" }
        foreach ($i in 1..2) { Act $p Detailed $i | Should -Be 'Retire' }
        foreach ($i in 3..9) { Act $p Summary (T $i) | Should -Be 'Keep' }
        foreach ($i in 1..2) { Act $p Summary (T $i) | Should -Be 'Retire' }
        @($p | Where-Object { $_.Action -eq 'Retire' } | ForEach-Object { $_.Why } | Sort-Object -Unique) | Should -Be @('superseded')
        @($p | Where-Object { $_.CollectionId -eq 1 })[0].Reason | Should -Match 'older than the newest 7 complete collections'
        @($p | Where-Object { $_.CollectionId -eq 4 })[0].Reason | Should -Match 'one of the newest 7 complete collections'
    }
    It 'the setting changes it: 3 keeps three, 9 keeps all nine, 12 keeps all nine' {
        $p3 = Get-SIDataCollectionRetentionPlan -Collections (Nine) -KeepCollections 3
        @($p3 | Where-Object { $_.Action -eq 'Keep' } | ForEach-Object { $_.CollectionId } | Sort-Object) | Should -Be @(7, 8, 9)
        @($p3 | Where-Object { $_.Action -eq 'Retire' }).Count | Should -Be 6
        @((Get-SIDataCollectionRetentionPlan -Collections (Nine) -KeepCollections 9) | Where-Object { $_.Action -ne 'Keep' }).Count | Should -Be 0
        @((Get-SIDataCollectionRetentionPlan -Collections (Nine) -KeepCollections 12) | Where-Object { $_.Action -ne 'Keep' }).Count | Should -Be 0
    }
    It 'superseded ONLY beyond N: with fewer complete collections than N nothing complete is removed' {
        $p = Get-SIDataCollectionRetentionPlan -Collections @(1..5 | ForEach-Object { Row Detailed $_ (T $_) Complete }) -KeepCollections 7
        @($p | Where-Object { $_.Action -ne 'Keep' }).Count | Should -Be 0
    }
    It 'NEGATIVE: never below 2 -- 1, 0 or a negative count keeps the newest and the one before it; not given = 2 (the old rule)' {
        foreach ($n in 1, 0, -3) {
            $p = Get-SIDataCollectionRetentionPlan -Collections (Nine) -KeepCollections $n
            @($p | Where-Object { $_.Action -eq 'Keep' } | ForEach-Object { $_.CollectionId } | Sort-Object) | Should -Be @(8, 9) -Because "asked for $n"
        }
        @((Get-SIDataCollectionRetentionPlan -Collections (Nine)) | Where-Object { $_.Action -eq 'Keep' } | ForEach-Object { $_.CollectionId } | Sort-Object) | Should -Be @(8, 9)
    }
    It 'NEGATIVE: never the published one -- kept beyond N; never a run in progress; never what a kept one carries rows from' {
        $rows = @(Nine); $rows[0] = Row Detailed 1 (T 1) Complete -Published
        $p = Get-SIDataCollectionRetentionPlan -Collections ($rows + @(Row Detailed 10 (T 10 20) Loading)) -KeepCollections 7
        Act $p Detailed 1 | Should -Be 'Keep' -Because 'the published run is what every view shows'
        Act $p Detailed 2 | Should -Be 'Retire'
        Act $p Detailed 10 | Should -Be 'Keep' -Because 'a run in progress is never removed'
        $c = Get-SIDataCollectionRetentionPlan -Collections (Nine) -CarryLinks @(@{ CollectionId = 5; FromCollectionId = 1 }) -KeepCollections 7
        Act $c Detailed 1 | Should -Be 'Keep'; Act $c Detailed 2 | Should -Be 'Retire'
    }
    It 'NEGATIVE: the newest complete collection is never removed, whatever the count and the mix' {
        $rand = New-Object System.Random 1218
        for ($i = 0; $i -lt 150; $i++) {
            $n = $rand.Next(1, 14)
            $rows = @(1..$n | ForEach-Object { Row Detailed $_ (T $_ $rand.Next(0, 23)) $(if ($rand.Next(4)) { 'Complete' } else { 'Loading' }) })
            $k = $rand.Next(-1, 10)
            $p = Get-SIDataCollectionRetentionPlan -Collections $rows -KeepCollections $k -StaleDays 0
            $cc = @($rows | Where-Object { $_.Status -eq 'Complete' } | Sort-Object { $_.CollectionTime } -Descending)
            $keepN = [Math]::Max(2, $k)
            for ($j = 0; $j -lt [Math]::Min($keepN, $cc.Count); $j++) {
                @($p | Where-Object { $_.CollectionTime -eq $cc[$j].CollectionTime })[0].Action | Should -Be 'Keep' -Because "the $($j + 1). newest complete of $($cc.Count), keep $k"
            }
            @($p | Where-Object { $_.Status -eq 'Complete' -and $_.Action -eq 'Retire' }).Count | Should -Be ([Math]::Max(0, $cc.Count - $keepN))
        }
    }
    It 'the step passes the count on: nine complete, keep 7 = two marked, and the database''s own mark is still asked' {
        # the same fake as SIv3-CollectionRetention (a closure cannot see this file's functions -- the rows are made first)
        $calls = New-Object System.Collections.ArrayList
        $nine = @(Nine)
        $inv = {
            param([string]$sql, $p, [string]$mode)
            $copy = @{}; if ($p) { foreach ($k in $p.Keys) { $copy[$k] = $p[$k] } }
            [void]$calls.Add([pscustomobject]@{ Sql = $sql; Params = $copy; Mode = $mode })
            if ($sql -match 'AS HasRows') { return , @($nine) }
            if ($sql -match 'CollectionReportCarry') { return , @() }
            if ($sql -match 'SET RetiredAt = SYSUTCDATETIME\(\)') { return 1 }
            if ($mode -eq 'scalar') { return 0 }
        }.GetNewClosure()
        $marked = { @($calls | Where-Object { $_.Sql -match 'SET RetiredAt = SYSUTCDATETIME\(\)' } | ForEach-Object { [string]$_.Params['CollectionId'] }) }
        $r = Invoke-SIDataCollectionRetention -Invoke $inv -MarkOnly -KeepCollections 7 -Log $script:Quiet
        $r.Status | Should -Be 'ok'
        @(& $marked) | Should -Be @('1', '2')
        $calls.Clear()
        $null = Invoke-SIDataCollectionRetention -Invoke $inv -MarkOnly -Log $script:Quiet
        @(& $marked).Count | Should -Be 7 -Because 'not given = 2 kept (the old rule): every product caller passes the count'
    }
}

Describe 'the database''s fill adapts the count (no hard cap)' {
    It 'below 70 % (or unknown): the setting' {
        (Get-SIDataKeepCollectionsDecision -Setting 7 -FillPercent 69.9 -LiveComplete 8 -NewestMark 'm1').Keep | Should -Be 7
        $u = Get-SIDataKeepCollectionsDecision -Setting 7 -FillPercent $null -LiveComplete 8 -NewestMark 'm1'
        $u.Keep | Should -Be 7; $u.Full | Should -BeFalse; $u.Text | Should -BeNullOrEmpty
    }
    It 'at or above 70 %: one fewer per run, never below 2; back to the setting below 70 %' {
        $stored = [pscustomobject]@{ Keep = 7; Mark = 'run0' }; $kept = 7; $seen = @()
        foreach ($r in 1..7) {
            $d = Get-SIDataKeepCollectionsDecision -Setting 7 -FillPercent 75 -Stored $stored -NewestMark "run$r" -LiveComplete ($kept + 1)
            $d.Full | Should -BeTrue
            # a second call of the SAME run (the data sync marks twice; a wake-up) takes no further step
            (Get-SIDataKeepCollectionsDecision -Setting 7 -FillPercent 75 -Stored ([pscustomobject]@{ Keep = $d.Keep; Mark = "run$r" }) -NewestMark "run$r" -LiveComplete $d.Keep).Keep | Should -Be $d.Keep
            $kept = $d.Keep; $stored = [pscustomobject]@{ Keep = $kept; Mark = "run$r" }; $seen += $kept
        }
        $seen | Should -Be @(6, 5, 4, 3, 2, 2, 2)
        (Get-SIDataKeepCollectionsDecision -Setting 7 -FillPercent 70 -Stored ([pscustomobject]@{ Keep = 7; Mark = 'a' }) -NewestMark 'b' -LiveComplete 8).Keep | Should -Be 6 -Because 'exactly 70 % counts as full'
        $back = Get-SIDataKeepCollectionsDecision -Setting 7 -FillPercent 55 -Stored $stored -NewestMark 'run8' -LiveComplete 3
        $back.Keep | Should -Be 7; $back.Reduced | Should -BeFalse; $back.Text | Should -BeNullOrEmpty
    }
    It 'steps down from what is really kept (an install still filling up to N), not from the setting' {
        (Get-SIDataKeepCollectionsDecision -Setting 7 -FillPercent 80 -Stored ([pscustomobject]@{ Keep = 7; Mark = 'a' }) -NewestMark 'b' -LiveComplete 4).Keep | Should -Be 2
        (Get-SIDataKeepCollectionsDecision -Setting 7 -FillPercent 80 -Stored $null -NewestMark 'b' -LiveComplete 6).Keep | Should -Be 4
    }
    It 'NEGATIVE: never below 2, also with the setting at 2 -- and says it is the fewest' {
        $d = Get-SIDataKeepCollectionsDecision -Setting 2 -FillPercent 95 -NewestMark 'x' -LiveComplete 3
        $d.Keep | Should -Be 2; $d.Reduced | Should -BeFalse
        $d.Text | Should -Match 'the fewest it keeps'
        (Get-SIDataKeepCollectionsDecision -Setting 0 -FillPercent 95 -NewestMark 'x' -LiveComplete 1).Keep | Should -Be 2
    }
    It 'ONE plain warning line: how full, how many kept instead of how many, what the customer can do' {
        $d = Get-SIDataKeepCollectionsDecision -Setting 7 -FillPercent 72 -Stored ([pscustomobject]@{ Keep = 7; Mark = 'a' }) -NewestMark 'b' -LiveComplete 8 -UsedMb 184320 -MaxMb 256000
        $d.Text | Should -Match '^the Pro database is 72 % full \(180 of 250 GB\): SecurityInsight now keeps the findings of the newest 6 complete collections instead of 7'
        $d.Text | Should -Match 'larger database tier'
        $d.Text | Should -Match 'SI_Data_KeepCollections'
        $d.Text | Should -Not -Match '#\d'
    }
    It 'the data sync''s call: reads the fill, the last decision and the collections, says one WARN line, stores the count' {
        $writes = New-Object System.Collections.Generic.List[string]
        $state = @(1..8 | ForEach-Object { Row Detailed $_ (T $_) Complete })
        $stored = @{ V = '7|2026-11-07T08:00:00.000' }
        $inv = {
            param([string]$sql, $p, [string]$mode)
            if ($sql -match 'FILEPROPERTY') { return '184320|256000' }
            if ($sql -match 'UPDATE sidata\.ViewState') { $writes.Add([string]$p['Value']); $stored.V = [string]$p['Value']; return 1 }
            if ($sql -match "Name = N'keep-collections'") { return $stored.V }
            if ($sql -match 'AS HasRows') { return , $state }
            if ($mode -eq 'scalar') { return 0 }
        }.GetNewClosure()
        $lines = New-Object System.Collections.Generic.List[string]
        $d = Resolve-SIDataKeepCollections -Invoke $inv -Setting 7 -Log { param($l, $m) $lines.Add("[$l] $m") }.GetNewClosure()
        $d.Keep | Should -Be 6
        @($writes) | Should -Be @('6|2026-11-08T08:00:00.000')
        @($lines | Where-Object { $_ -match '^\[WARN\]' }).Count | Should -Be 1
        $lines[0] | Should -Match '^\[WARN\] collections : the Pro database is 72 % full'
        # the same newest collection again (the second mark of the run, or the next call): no further step
        (Resolve-SIDataKeepCollections -Invoke $inv -Setting 7 -Log $script:Quiet).Keep | Should -Be 6
        # a dry run stores nothing
        $writes.Clear(); $null = Resolve-SIDataKeepCollections -Invoke $inv -Setting 7 -DryRun -Log $script:Quiet
        $writes.Count | Should -Be 0
    }
    It 'NEVER throws: nothing readable = the setting' {
        $bad = { param($sql, $p, $mode) throw 'the database did not answer' }
        { $script:D = Resolve-SIDataKeepCollections -Invoke $bad -Setting 7 -Log $script:Quiet } | Should -Not -Throw
        $script:D.Keep | Should -Be 7
        Get-SIDataKeepCollectionsForWakeUp -Invoke $bad -Setting 7 | Should -Be 7
    }
    It 'the wake-up keeps what the data sync decided, never more removed than the setting asks' {
        $mk = { param($v) { param($sql, $p, $mode) $v }.GetNewClosure() }
        Get-SIDataKeepCollectionsForWakeUp -Invoke (& $mk '4|2026-11-08T08:00:00.000') -Setting 7 | Should -Be 4
        Get-SIDataKeepCollectionsForWakeUp -Invoke (& $mk '') -Setting 7 | Should -Be 7
        Get-SIDataKeepCollectionsForWakeUp -Invoke (& $mk '9|x') -Setting 7 | Should -Be 7
        Get-SIDataKeepCollectionsForWakeUp -Invoke (& $mk 'garbage') -Setting 5 | Should -Be 5
        ConvertFrom-SIDataKeepState -Value '1|x' | Should -BeNullOrEmpty -Because 'a stored count below 2 is never used'
    }
}

Describe 'what the web app can show is built: the Summary groupings and the key figures' {
    It 'the shown set = the published one + TOP (N) complete at or before it + the newer ones' {
        Get-SIDataSummaryGroupsPendingSql -Keep 7 | Should -Match 'OR c\.CollectionId IN \(SELECT TOP \(7\) k\.CollectionId FROM sidata\.Collection AS k'
        Get-SIDataSummaryGroupsPendingSql | Should -Match 'SELECT TOP \(2\) k\.CollectionId' -Because 'not given = the old rule'
        Get-SIDataSummaryGroupsPendingSql -Keep 1 | Should -Match 'SELECT TOP \(2\) k\.CollectionId' -Because 'never below 2'
        $seen = New-Object System.Collections.Generic.List[string]
        $inv = { param($sql, $p, $mode) $seen.Add([string]$sql); if ($sql -match "OBJECT_ID\('sidata\.SummaryGroup'\)") { return 1 }; if ($mode -eq 'reader') { return @() }; 0 }.GetNewClosure()
        $null = Invoke-SIDataSummaryGroups -Invoke $inv -Keep 7 -Plan @{ Hash = 'h' } -Log $script:Quiet
        @($seen | Where-Object { $_ -match 'LEFT JOIN sidata\.SummaryGroupState' })[0] | Should -Match 'TOP \(7\)'
    }
    It 'the key figures: the newest N kept collections, retired ones never take a place' {
        Get-SIDataUnfiguredSql -Newest 7 | Should -Match 'SELECT TOP \(7\) n\.CollectionId'
        Set-SIDataRetiredReady -Ready $true
        try { Get-SIDataUnfiguredSql -Newest 7 | Should -Match "n\.Status = 'Complete' AND n\.RetiredAt IS NULL ORDER BY" } finally { Set-SIDataRetiredReady -Ready $false }
    }
    It 'the key figures: with -Keep every pending kept collection is built in the run (paced, never left over); without, the budget paces as before' {
        $pend = @(@{ CollectionId = 9 }, @{ CollectionId = 8 }, @{ CollectionId = 7 })
        $built = New-Object System.Collections.Generic.List[int]
        $topAsked = New-Object System.Collections.Generic.List[string]
        $inv = {
            param($sql, $p, $mode)
            if ($sql -match "OBJECT_ID\('sidata\.KeyFigure'\)") { return 1 }
            if ($sql -match 'SELECT TOP \((\d+)\) n\.CollectionId') { $topAsked.Add($Matches[1]); return , $pend }
            if ($mode -eq 'scalar' -and $p -and $p['CollectionId']) { Start-Sleep -Milliseconds 30; $built.Add([int]$p['CollectionId']); return 5 }
            0
        }.GetNewClosure()
        $r = Invoke-SIDataKeyFigures -Invoke $inv -Keep 7 -BudgetSeconds 0 -Log $script:Quiet
        @($built) | Should -Be @(9, 8, 7)
        $r.Pending | Should -Be 0
        @($topAsked)[-1] | Should -Be '7'
        $built.Clear()
        $r0 = Invoke-SIDataKeyFigures -Invoke $inv -BudgetSeconds 0 -Log $script:Quiet
        @($built) | Should -Be @(9) -Because 'without -Keep the budget still paces the older ones'
        $r0.Pending | Should -Be 2
        @($topAsked)[-1] | Should -Be '4'
    }
}

Describe 'wiring: one count per run, passed everywhere' {
    BeforeAll {
        $strip = { param($t) [regex]::Replace([regex]::Replace($t, '(?s)<#.*?#>', ''), '(?m)^\s*#.*$', '') }
        $script:Core = & $strip (Get-Content -Raw -LiteralPath (Join-Path $script:Root 'engine\pro-data\_shared\SI-DataSync.ps1'))
        $script:Job = & $strip (Get-Content -Raw -LiteralPath (Join-Path $script:Root 'engine\pro-data\Invoke-SIDataSync.ps1'))
        $script:Runner = & $strip (Get-Content -Raw -LiteralPath (Join-Path $script:Root 'engine\flow\Invoke-SIJobFlowRun.ps1'))
        $script:Sql = Get-Content -Raw -LiteralPath (Join-Path $script:Root 'engine\_shared\data-sql\SI-DataSql.ps1')
    }
    It 'the data sync decides once, before its first mark, and passes the count to both marks, the dry run, the groupings and the key figures' {
        $resolve = $script:Core.IndexOf('Resolve-SIDataKeepCollections -Invoke $Invoke -Setting $keepSet')
        $resolve | Should -BeGreaterThan 0
        $resolve | Should -BeLessThan $script:Core.IndexOf('Invoke-SIDataCollectionRetention -Invoke')
        ([regex]::Matches($script:Core, 'Resolve-SIDataKeepCollections -Invoke')).Count | Should -Be 1
        $calls = @([regex]::Matches($script:Core, 'Invoke-SIDataCollectionRetention -Invoke[^\r\n]*') | ForEach-Object { $_.Value })
        $calls.Count | Should -Be 3
        foreach ($c in $calls) { $c | Should -Match '-KeepCollections \$keepNow' }
        $script:Core | Should -Match 'Invoke-SIDataSummaryGroups -Invoke \$Invoke -DryRun:\$DryRun -Log \$Log -Keep \$keepNow'
        $script:Core | Should -Match 'Invoke-SIDataKeyFigures -Invoke \$Invoke -DryRun:\$DryRun -Log \$Log -Keep \$keepNow'
        $script:Job | Should -Match "'SI_Data_KeepCollections'"
    }
    It 'the runner''s wake-up gets the data sync''s count, and the clean-up passes it to its retention' {
        $script:Runner | Should -Match 'Get-SIDataKeepCollectionsForWakeUp -Invoke \$cleanSql'
        $script:Runner | Should -Match 'Invoke-SIDataStoppedRunCleanup -Invoke \$cleanSql [^\r\n]*-KeepCollections \$cleanKeep'
        $script:Sql | Should -Match 'Invoke-SIDataCollectionRetention -Invoke \$Invoke -Log \$Log -NowUtc \$NowUtc -IdleStaleHours \$IdleStaleHours [^\r\n]*-KeepCollections \$KeepCollections'
        $script:Sql | Should -Match 'Get-SIDataCollectionRetentionPlan -Collections \$state [^\r\n]*-KeepCollections \$KeepCollections'
    }
}

Describe 'on a real SQL Server: 7 kept, the shown set = 7, the count stored for the wake-up' {
    It 'nine complete per grain: the two oldest lose their rows, the newest 7 keep every row; the shown set is the published one + 7 at or before it + the newer ones' -Skip:(-not $script:LocalSql) {
        $db = 'sikeep_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
        $master = New-LocalInvoke 'master'
        [void](& $master "CREATE DATABASE [$db]" @{} 'nonquery')
        try {
            $inv = New-LocalInvoke $db
            [void](& $inv $script:Schema @{} 'nonquery')
            [void](& $inv (Get-SIDataRetiredColumnsSql) @{} 'scalar')
            foreach ($d in 1..9) {
                [void](& $inv ("SET IDENTITY_INSERT sidata.Collection ON; INSERT sidata.Collection (CollectionId, CollectionTime, Kind, Status, ViewsReadyAt, DerivedAt, ContextAt) VALUES ({0}, '2026-11-{0:00}T08:00:00', 'Detailed', 'Complete', SYSUTCDATETIME(), SYSUTCDATETIME(), SYSUTCDATETIME()); SET IDENTITY_INSERT sidata.Collection OFF;" -f $d) @{} 'nonquery')
                foreach ($i in 1..3) { [void](& $inv ("INSERT sidata.Finding (CollectionId, AssetKey, ReportName, Severity, Tier, RiskScore) VALUES ({0}, N'a{1}', N'R', N'High', 1, 5)" -f $d, $i) @{} 'nonquery') }
                [void](& $inv ("INSERT sidata.SummaryLoad (CollectionTime, Status) VALUES ('2026-11-{0:00}T09:00:00', 'Complete'); INSERT sidata.SummaryRow (CollectionTime, RowNo, RatingRank) VALUES ('2026-11-{0:00}T09:00:00', 1, 1)" -f $d) @{} 'nonquery')
            }
            # the published collection is the one of the 7th (the runs of the 8th and 9th are newer)
            [void](& $inv "INSERT sidata.PublishedRun (Name, DetailedCollectionId, DetailedCollectionTime, Source) VALUES (N'current', 7, '2026-11-07T08:00:00', N'run');" @{} 'nonquery')
            $cnt = { param($q) [int](& $inv $q @{} 'scalar') }

            # the count of this run: a local SQL Server has no maximum size -- the fill is unknown, so the setting applies
            $d = Resolve-SIDataKeepCollections -Invoke $inv -Setting 7 -Log $script:Quiet
            $d.Keep | Should -Be 7
            [string](& $inv (Get-SIDataKeepStateReadSql) @{} 'scalar') | Should -Be '7|2026-11-09T08:00:00.000'
            Get-SIDataKeepCollectionsForWakeUp -Invoke $inv -Setting 7 | Should -Be 7

            $r = Invoke-SIDataCollectionRetention -Invoke $inv -KeepCollections $d.Keep -BatchSize 2 -Log $script:Quiet
            $r.Status | Should -Be 'ok'
            @($r.Removed | Where-Object { $_.Grain -eq 'Detailed' } | ForEach-Object { $_.CollectionId } | Sort-Object) | Should -Be @(1, 2)
            & $cnt 'SELECT COUNT(*) FROM sidata.Finding WHERE CollectionId IN (1, 2)' | Should -Be 0
            & $cnt 'SELECT COUNT(*) FROM sidata.Finding WHERE CollectionId BETWEEN 3 AND 9' | Should -Be 21
            & $cnt "SELECT COUNT(*) FROM sidata.Collection WHERE RetiredAt IS NOT NULL AND RetiredWhy = N'superseded'" | Should -Be 2
            & $cnt "SELECT COUNT(*) FROM sidata.SummaryRow WHERE CollectionTime < '2026-11-03T00:00:00'" | Should -Be 0
            & $cnt "SELECT COUNT(*) FROM sidata.SummaryRow" | Should -Be 7
            # IDEMPOTENT: the same count again removes nothing
            @((Invoke-SIDataCollectionRetention -Invoke $inv -KeepCollections 7 -Log $script:Quiet).Removed).Count | Should -Be 0
            # NEGATIVE: the database itself still refuses the newest complete collection and the one before it
            foreach ($id in 9, 8) { (& $inv (Get-SIDataRetireMarkSql -Grain Detailed) @{ CollectionId = [string]$id; CollectionTime = ''; Why = 'test'; StaleBefore = '' } 'scalar') | Should -Be 0 }

            # the shown set on the real schema: the newer ones (8th, 9th), the published one (7th) and the 6 kept before it
            Set-SIDataRetiredReady -Ready $true
            try {
                [void](& $inv 'UPDATE sidata.Collection SET ContextAt = SYSUTCDATETIME(), DerivedAt = SYSUTCDATETIME() WHERE RetiredAt IS NULL' @{} 'nonquery')
                $p = @(& $inv (Get-SIDataSummaryGroupsPendingSql -Keep 7) @{ Hash = 'h' } 'reader' | ForEach-Object { $_ })
                @($p | ForEach-Object { [int]$_['CollectionId'] }) | Should -Be @(9, 8, 7, 6, 5, 4, 3)
                @($p | ForEach-Object { [int]$_['Shown'] }) | Should -Be @(1, 1, 1, 1, 1, 1, 1) -Because 'every kept collection is one the web app can show'
                $p2 = @(& $inv (Get-SIDataSummaryGroupsPendingSql -Keep 2) @{ Hash = 'h' } 'reader' | ForEach-Object { $_ })
                @($p2 | ForEach-Object { [int]$_['Shown'] }) | Should -Be @(1, 1, 1, 1, 0, 0, 0) -Because 'with 2: the newer ones, the published one and the one before it'
            } finally { Set-SIDataRetiredReady -Ready $false }

            # the wake-up keeps what the data sync decided: a stored 3 removes down to 3, never further
            [void](& $inv (Get-SIDataKeepStateWriteSql) @{ Value = '3|2026-11-09T08:00:00.000' } 'nonquery')
            $wk = Get-SIDataKeepCollectionsForWakeUp -Invoke $inv -Setting 7
            $wk | Should -Be 3
            $r3 = Invoke-SIDataCollectionRetention -Invoke $inv -KeepCollections $wk -Log $script:Quiet
            @($r3.Removed | Where-Object { $_.Grain -eq 'Detailed' } | ForEach-Object { $_.CollectionId } | Sort-Object) | Should -Be @(3, 4, 5, 6) -Because 'the published one (7) and the newest three (7, 8, 9) stay'
            & $cnt 'SELECT COUNT(*) FROM sidata.Finding WHERE CollectionId IN (7, 8, 9)' | Should -Be 9
        } finally {
            [System.Data.SqlClient.SqlConnection]::ClearAllPools()
            try { [void](& $master "IF DB_ID(N'$db') IS NOT NULL BEGIN ALTER DATABASE [$db] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$db]; END" @{} 'nonquery') } catch { Write-Warning ("the test database {0} was not dropped: {1}" -f $db, $_.Exception.Message) }
        }
    }
}
