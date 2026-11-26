#Requires -Version 7.0
<#
    THE FINDING LIFECYCLE'S CHANGE SIGNAL (REQUIREMENTS #1334; owner 2026-11-23) -- sql\si-data-schema.sql
    TR_CiFindingState_Changed / TR_CiFindingState_Gone and sidata.CiFindingStateGone.

    What these tests keep true (the signal is proven ON ITS OWN before anything is built on it):
      * EVERY write path of the lifecycle (engine\pro-data\_shared\SI-DataCiLifecycle.ps1 Invoke-SIDataCiLifecycle: the freeze
        repair, the lifecycle statement -- open, seen, absent, close, reopen, frozen, retired, rekeyed --, the stale-open repair,
        the finding model, the retention) run over fixtures, and after EACH step the table compared with a before / after
        diff: a row whose read columns (OwnerKey, FindingKey, CiId, State, FirstDetected, ClosedAt, CloseReason) changed has a
        NEW ChangedAt, a row whose read columns did not change keeps its ChangedAt EXACTLY (LastSeen / LastSnapshot /
        AbsentRuns and the model's columns never set it), a new row has one, a row that left is in sidata.CiFindingStateGone;
      * ON DEMAND (tag Scale): the marks' cost at a large install's size (1,000,000 lifecycle rows), the lifecycle statement's
        every-run path with the marks off and on, measured and said.
    Runs on the Azure test runner (TEST_SQL_*: _SITestSql.ps1).
#>

BeforeDiscovery {
    $script:HasSql = [bool]($env:SI_TEST_LOCALSQL)
}

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    foreach ($f in 'engine\_shared\SI-KqlError.ps1', 'engine\_shared\data-sql\SI-DataModel.ps1', 'engine\_shared\data-sql\SI-DataSql.ps1',
                   'engine\pro-data\_shared\SI-DataCiLifecycle.ps1', 'engine\pro-data\_shared\SI-DataCi.ps1', 'engine\_shared\SI-SourceState.ps1') {
        . (Join-Path $script:SIRoot $f)
    }
    $script:Quiet = { param($l, $m) }
    $script:Schema = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'sql\si-data-schema.sql'))
}

Describe 'the guard: every statement that writes a read column of the lifecycle carries its mark' {
    BeforeAll {
        $script:LcText = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\pro-data\_shared\SI-DataCiLifecycle.ps1'))
        $script:ReadCols = 'OwnerKey', 'FindingKey', 'CiId', 'State', 'FirstDetected', 'ClosedAt', 'CloseReason'
        # every write statement on sidata.CiFindingState in a text: its target (direct, or an alias the FROM gives the table)
        function script:Get-LcWrites([string]$Text) {
            $out = New-Object System.Collections.Generic.List[object]
            # every start of a statement, each read to its own end -- a ';' inside a quoted text is not an end (overlapping: a word in a
            # comment never swallows the statement after it)
            foreach ($m in [regex]::Matches($Text, '(?is)\b(?=((UPDATE|DELETE|INSERT)\b(?:''[^'']*''|(?!;)[^''])*?;))')) {
                $s = $m.Groups[1].Value; $kind = $m.Groups[2].Value.ToUpperInvariant()
                $hit = $false
                if ($kind -eq 'INSERT') { $hit = $s -match '(?is)^INSERT\s+(INTO\s+)?sidata\.CiFindingState\s*\(' }
                elseif ($kind -eq 'UPDATE') {
                    $tg = [regex]::Match($s, '(?is)^UPDATE\s+(TOP\s*\([^)]*\)\s+)?([\w\.\[\]]+)\s+SET\b')
                    if ($tg.Success) { $n = $tg.Groups[2].Value; $hit = ($n -ieq 'sidata.CiFindingState') -or ($s -match ('(?is)\bsidata\.CiFindingState\s+(AS\s+)?{0}\b' -f [regex]::Escape($n))) }
                } else {
                    $tg = [regex]::Match($s, '(?is)^DELETE\s+(TOP\s*\([^)]*\)\s+)?(FROM\s+)?([\w\.\[\]@#]+)')
                    if ($tg.Success) { $n = $tg.Groups[3].Value; $hit = ($n -ieq 'sidata.CiFindingState') -or ($s -match ('(?is)\bFROM\s+sidata\.CiFindingState\s+(AS\s+)?{0}\b' -f [regex]::Escape($n))) }
                }
                if ($hit) { $out.Add([pscustomobject]@{ Kind = $kind; Text = $s }) }
            }
            # (the statements themselves, one by one -- callers collect them with @( ))
            $out.ToArray()
        }
        function script:Test-SetsReadColumn([string]$Stmt) {
            $set = [regex]::Match($Stmt, '(?is)\bSET\b(.*?)(\bOUTPUT\b|\bFROM\b|\bWHERE\b|;|$)').Groups[1].Value
            foreach ($c in $script:ReadCols) { if ($set -match ('(?i)(^|[\s,\.])' + $c + '\s*=')) { return $true } }
            $false
        }
    }
    It 'finds the lifecycle''s write statements (the guard is not empty)' {
        $w = @(Get-LcWrites $script:LcText)
        @($w | Where-Object Kind -eq 'INSERT').Count | Should -BeGreaterOrEqual 3
        @($w | Where-Object Kind -eq 'DELETE').Count | Should -BeGreaterOrEqual 2
        @($w | Where-Object Kind -eq 'UPDATE').Count | Should -BeGreaterOrEqual 8
    }
    It 'every INSERT, every DELETE and every UPDATE that sets one of the 7 read columns carries the mark (/*M{*/ ... /*}M*/)' {
        $miss = @(Get-LcWrites $script:LcText | Where-Object { ($_.Kind -ne 'UPDATE' -or (Test-SetsReadColumn $_.Text)) -and $_.Text -notmatch [regex]::Escape('/*M{*/') } |
                  ForEach-Object { ($_.Text -replace '\s+', ' ').Substring(0, [Math]::Min(160, ($_.Text -replace '\s+', ' ').Length)) })
        ($miss -join "`n") | Should -BeNullOrEmpty -Because 'a statement that changes what the key figures read must say so in the same statement'
        # a DELETE (and a key move) writes the tombstone by its OUTPUT
        foreach ($d in @(Get-LcWrites $script:LcText | Where-Object Kind -eq 'DELETE')) { $d.Text | Should -Match 'INTO sidata\.CiFindingStateGone' }
        # the every-run updates (seen again, absent counted) set no read column -- they carry no unconditional mark
        $seen = @(Get-LcWrites $script:LcText | Where-Object { $_.Text -match '^UPDATE s SET LastSeen = @t, LastSnapshot = @t, AbsentRuns = 0\s' })
        $seen.Count | Should -Be 1
        $seen[0].Text | Should -Not -Match 'ChangedAt'
    }
    It 'the CI build''s merge notes every lifecycle row it moves or changes, and marks them where the database has the mark' {
        $b = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\data-model\SI-CiBuildSql.ps1'))
        $w = @(Get-LcWrites $b | Where-Object { $_.Kind -ne 'UPDATE' -or (Test-SetsReadColumn $_.Text) })
        $w.Count | Should -BeGreaterOrEqual 2
        foreach ($x in $w) { $x.Text | Should -Match 'INTO @lcm' }
        $b | Should -Match ([regex]::Escape('INSERT sidata.CiFindingStateGone (OwnerKey, FindingKey, CiId) SELECT x.oo, x.k, x.oc FROM OPENJSON(@j)'))
        # (the merged-CI retire never creates or removes anything: the noted rows go to the marks as JSON, no temporary table)
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:SIRoot 'engine\data-model\SI-CiBuildSql.ps1'), [ref]$null, [ref]$null)
        $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-SICiMergedRetireSql' }, $true).Extent.Text | Should -Not -Match '(?i)\bDELETE\b|\bTRUNCATE\b|\bDROP\b'
    }
    It 'marks off (a database without the column yet): every statement is exactly the one of before' {
        $script:SIDataLifecycleMarks = $false
        foreach ($s in (Get-SIDataFindingStateSql -WithDisabledOwners -WithEquivalence -FromStage), (Get-SIDataCiRetentionSql), (Get-SIDataFindingFreezeRepairSql), (Get-SIDataLifecycleStaleOpenRepairSql)) {
            $s | Should -Not -Match 'CiFindingStateGone|/\*M\{|\bChangedAt = |, ChangedAt\b'   # (CiChange has a ChangedAt of its own)
        }
        $script:SIDataLifecycleMarks = $true
        (Get-SIDataFindingStateSql -WithDisabledOwners -WithEquivalence -FromStage) | Should -Match 'ChangedAt = SYSUTCDATETIME\(\)'
        $script:SIDataLifecycleMarks = $false
    }
    It 'the schema keeps the mark and the tombstone and makes no trigger (it stays additive)' {
        $script:Schema | Should -Match ([regex]::Escape("ALTER TABLE sidata.CiFindingState ADD ChangedAt DATETIME2(3) NULL"))
        $script:Schema | Should -Match 'CREATE TABLE sidata\.CiFindingStateGone'
        $script:Schema | Should -Not -Match 'CREATE OR ALTER TRIGGER sidata\.TR_(CiFindingState|Ci)_'
    }
}
Describe 'every lifecycle write path sets the mark exactly when a read column changes (real SQL)' -Skip:(-not $script:HasSql) {
    BeforeAll {
        $script:Db = 'si_test_lcsig_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
        $m = New-Object System.Data.SqlClient.SqlConnection "Server=$($env:SI_TEST_LOCALSQL);Database=master;$($env:SI_TEST_SQL_AUTH);Connection Timeout=30"
        $m.Open(); try { $c = $m.CreateCommand(); $c.CommandText = "CREATE DATABASE [$($script:Db)]"; $c.CommandTimeout = 300; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
        $cn = New-Object System.Data.SqlClient.SqlConnection ("Server=$($env:SI_TEST_LOCALSQL);Database=$($script:Db);$($env:SI_TEST_SQL_AUTH);Connection Timeout=30;Pooling=false")
        $cn.Open()
        foreach ($f in 'sql\si-data-schema.sql', 'sql\si-identity-schema.sql') { $c = $cn.CreateCommand(); $c.CommandTimeout = 300; $c.CommandText = [IO.File]::ReadAllText((Join-Path $script:SIRoot $f)); [void]$c.ExecuteNonQuery() }
        $c = $cn.CreateCommand(); $c.CommandText = 'CREATE USER si_engine WITHOUT LOGIN; ALTER ROLE db_datareader ADD MEMBER si_engine; ALTER ROLE db_datawriter ADD MEMBER si_engine;'; [void]$c.ExecuteNonQuery()
        $script:AdminConn = $cn
        $e = New-Object System.Data.SqlClient.SqlConnection ($cn.ConnectionString); $e.Open()
        $c = $e.CreateCommand(); $c.CommandText = "EXECUTE AS USER = N'si_engine';"; [void]$c.ExecuteNonQuery()
        $script:Conn = $e
        $script:Seam = {
            param($Sql, $Params, $Mode)
            $c = $script:Conn.CreateCommand(); $c.CommandText = $Sql; $c.CommandTimeout = 600
            if ($Params) { foreach ($k in $Params.Keys) { $v = $Params[$k]; if ($null -eq $v) { $v = [System.DBNull]::Value }; [void]$c.Parameters.AddWithValue('@' + $k, $v) } }
            switch ($Mode) {
                { $_ -in 'reader', 'rows' } {
                    $rd = $c.ExecuteReader(); $out = New-Object System.Collections.Generic.List[object]
                    try { while ($rd.Read()) { $h = @{}; for ($i = 0; $i -lt $rd.FieldCount; $i++) { $h[$rd.GetName($i)] = $rd.GetValue($i) }; $out.Add($h) } } finally { $rd.Close() }
                    , $out.ToArray()
                }
                'scalar' { $c.ExecuteScalar() }
                default { [void]$c.ExecuteNonQuery() }
            }
        }
        function script:Admin([string]$Sql) { $c = $script:AdminConn.CreateCommand(); $c.CommandText = $Sql; $c.CommandTimeout = 600; [void]$c.ExecuteNonQuery() }
        function script:AdminScalar([string]$Sql) { $c = $script:AdminConn.CreateCommand(); $c.CommandText = $Sql; $c.CommandTimeout = 600; $c.ExecuteScalar() }
        function script:It2([string]$Ci, [string]$Asset, [string]$Key, [string]$Sev = 'high') { [pscustomobject]@{ CiId = $Ci; AssetId = $Asset; FindingKey = $Key; Severity = $Sev; DetectedBy = 'R1'; ExemptionId = '' } }
        # the table as it is: every row, its read columns (bytes), its ChangedAt; and the tombstones so far
        function script:Snap {
            $rows = @{}
            $c = $script:AdminConn.CreateCommand(); $c.CommandTimeout = 600
            $c.CommandText = "SELECT OwnerKey, FindingKey, CONVERT(nvarchar(max), CONCAT(CONVERT(varbinary(900), OwnerKey), N'|', CONVERT(varbinary(512), FindingKey), N'|', CONVERT(varbinary(200), CiId), N'|', CONVERT(varbinary(64), State), N'|', CONVERT(nvarchar(30), FirstDetected, 126), N'|', CONVERT(nvarchar(30), ClosedAt, 126), N'|', CONVERT(varbinary(128), CloseReason))) AS R, CONVERT(nvarchar(30), ChangedAt, 126) AS Ch FROM sidata.CiFindingState"
            $rd = $c.ExecuteReader(); try { while ($rd.Read()) { $rows[('{0}|{1}' -f $rd.GetString(0), $rd.GetString(1))] = [pscustomobject]@{ R = [string]$rd.GetValue(2); Ch = $(if ($rd.IsDBNull(3)) { $null } else { $rd.GetString(3) }) } } } finally { $rd.Close() }
            [pscustomobject]@{ Rows = $rows; Gone = [long](AdminScalar 'SELECT COUNT_BIG(*) FROM sidata.CiFindingStateGone') }
        }
        # the before / after diff of one step: returns @{ Changed; Unchanged; New; Left; Bad = the rows the mark got wrong }
        function script:Compare-Step($A, $B, [string]$Step) {
            $bad = New-Object System.Collections.Generic.List[string]; $chg = 0; $same = 0; $new = 0
            foreach ($k in $B.Rows.Keys) {
                $nb = $B.Rows[$k]
                if (-not $A.Rows.ContainsKey($k)) { $new++; if ($null -eq $nb.Ch) { $bad.Add("$Step new row without a mark: $k") }; continue }
                $na = $A.Rows[$k]   # ($na / $nb: PowerShell names are case-insensitive -- $a would be $A)
                if ($na.R -cne $nb.R) { $chg++; if ($null -eq $nb.Ch -or $nb.Ch -eq $na.Ch) { $bad.Add("$Step read column changed, mark not moved: $k") } }
                else { $same++; if ($nb.Ch -ne $na.Ch) { $bad.Add("$Step nothing read changed, the mark moved: $k") } }
            }
            $left = @($A.Rows.Keys | Where-Object { -not $B.Rows.ContainsKey($_) }).Count
            if (($B.Gone - $A.Gone) -lt $left) { $bad.Add("$Step $left row(s) left, $($B.Gone - $A.Gone) tombstone(s)") }
            [pscustomobject]@{ Changed = $chg; Unchanged = $same; New = $new; Left = $left; Bad = $bad.ToArray() }
        }
        function script:Step([string]$Name, [scriptblock]$Do) {
            $a = Snap; & $Do; Start-Sleep -Milliseconds 20; $b = Snap
            $r = Compare-Step $a $b $Name; $r | Add-Member -NotePropertyName Step -NotePropertyValue $Name; $script:Steps.Add($r); $r
        }
        $script:Steps = New-Object System.Collections.Generic.List[object]
        try {
        $base = @((It2 'ci-a' '' 'CVE-2026-1'), (It2 'ci-a' '' 'CVE-2026-2'), (It2 'ci-b' '' 'CVE-2026-3'), (It2 '' 'A9' 'CVE-2026-4'), (It2 'ci-c' '' 'REC-1'), (It2 'ci-d' '' 'CVE-2026-5'))
        $global:SI_VulnSync_CloseAfterRuns = 2
        $null = Step 'open (first collection)' { $null = Invoke-SIDataCiLifecycle -Invoke $script:Seam -Items $base -SnapshotTime '2026-11-01T05:00:00.000' -Complete $true -Log $script:Quiet }
        # seen again, a severity and a detection change only (columns no aggregate reads), the model's columns rewritten
        $sev = @($base | ForEach-Object { $x = $_.PSObject.Copy(); if ($x.FindingKey -eq 'CVE-2026-1') { $x.Severity = 'critical' }; $x })
        $null = Step 'seen again (LastSeen / severity / model only)' { $null = Invoke-SIDataCiLifecycle -Invoke $script:Seam -Items $sev -SnapshotTime '2026-11-02T05:00:00.000' -Complete $true -Log $script:Quiet }
        $less = @($base | Where-Object { $_.FindingKey -ne 'CVE-2026-2' })
        $null = Step 'absent once (AbsentRuns only)' { $null = Invoke-SIDataCiLifecycle -Invoke $script:Seam -Items $less -SnapshotTime '2026-11-03T05:00:00.000' -Complete $true -Log $script:Quiet }
        $null = Step 'absent twice (closed)' { $null = Invoke-SIDataCiLifecycle -Invoke $script:Seam -Items $less -SnapshotTime '2026-11-04T05:00:00.000' -Complete $true -Log $script:Quiet }
        $null = Step 'back (reopened)' { $null = Invoke-SIDataCiLifecycle -Invoke $script:Seam -Items $base -SnapshotTime '2026-11-05T05:00:00.000' -Complete $true -Log $script:Quiet }
        # a disabled owner's absent findings freeze (nothing read changes)
        $noD = @($base | Where-Object { $_.CiId -ne 'ci-d' })
        $null = Step 'frozen (disabled owner)' { $null = Invoke-SIDataCiLifecycle -Invoke $script:Seam -Items $noD -SnapshotTime '2026-11-06T05:00:00.000' -Complete $true -Log $script:Quiet -DisabledOwners @('ci-d') }
        # an incomplete run: absent findings stay open (nothing read changes)
        $null = Step 'incomplete run (nothing closes)' { $null = Invoke-SIDataCiLifecycle -Invoke $script:Seam -Items $noD -SnapshotTime '2026-11-07T05:00:00.000' -Complete $false -Log $script:Quiet -DisabledOwners @('ci-d') }
        # new findings and a CI that leaves the collection entirely
        $more = @($base | Where-Object { $_.CiId -ne 'ci-c' }) + @((It2 'ci-e' '' 'CVE-2026-9'), (It2 'ci-a' '' 'CVE-2026-8'))
        $null = Step 'new findings, a CI gone' { $null = Invoke-SIDataCiLifecycle -Invoke $script:Seam -Items $more -SnapshotTime '2026-11-08T05:00:00.000' -Complete $true -Log $script:Quiet }
        $null = Step 'gone twice' { $null = Invoke-SIDataCiLifecycle -Invoke $script:Seam -Items $more -SnapshotTime '2026-11-09T05:00:00.000' -Complete $true -Log $script:Quiet }
        # the retention: an old closed row leaves (a DELETE -> a tombstone)
        Admin "UPDATE sidata.CiFindingState SET ClosedAt = DATEADD(day, -900, SYSUTCDATETIME()) WHERE State = N'closed' AND FindingKey = N'REC-1';"
        $global:SI_Pro_FindingStateRetentionDays = 365
        $null = Step 'retention (old closed rows removed)' { $null = Invoke-SIDataCiLifecycle -Invoke $script:Seam -Items $more -SnapshotTime '2026-11-10T05:00:00.000' -Complete $true -Log $script:Quiet }
        # a key moved by an UPDATE (as the equivalence carry and a re-key do): the old key is a tombstone, the new key marked
        # a key moved by the lifecycle itself: the recommendation equivalence carries the row under its alias onto the canonical key
        $eq = @($more | ForEach-Object { if ($_.FindingKey -eq 'CVE-2026-8') { $x = $_.PSObject.Copy(); $x.FindingKey = 'REC-CANON-8'; $x | Add-Member -NotePropertyName Aliases -NotePropertyValue 'CVE-2026-8'; $x } else { $_ } })
        $null = Step 'a key moved by an update' { $null = Invoke-SIDataCiLifecycle -Invoke $script:Seam -Items $eq -SnapshotTime '2026-11-11T05:00:00.000' -Complete $true -Log $script:Quiet }
        # a write of nothing that is read (the CMDB / ticket / owner columns) by another writer
        $null = Step 'an unread column written' { Admin "UPDATE sidata.CiFindingState SET Owner = N'someone', TicketState = N'open', LastSeen = SYSUTCDATETIME(), AbsentRuns = AbsentRuns + 1;" }
        } catch { Write-Host ('SETUP FAILED: ' + $_.Exception.Message + ' AT ' + $_.ScriptStackTrace); throw }
    }
    AfterAll {
        foreach ($x in $script:Conn, $script:AdminConn) { if ($x) { try { $x.Dispose() } catch { } } }
        [System.Data.SqlClient.SqlConnection]::ClearAllPools()
        try {
            $m = New-Object System.Data.SqlClient.SqlConnection "Server=$($env:SI_TEST_LOCALSQL);Database=master;$($env:SI_TEST_SQL_AUTH);Connection Timeout=30"
            $m.Open(); try { $c = $m.CreateCommand(); $c.CommandTimeout = 300; $c.CommandText = "ALTER DATABASE [$($script:Db)] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$($script:Db)]"; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
        } catch { }
        Remove-Variable -Name SI_VulnSync_CloseAfterRuns, SI_Pro_FindingStateRetentionDays -Scope Global -ErrorAction SilentlyContinue
    }
    It 'every step: the mark is new exactly where a read column changed, and the same everywhere else; every row that left is a tombstone' {
        $all = @($script:Steps | ForEach-Object { $_.Bad } | Where-Object { $_ })
        $text = ($script:Steps | ForEach-Object { '{0}: changed {1}, unchanged {2}, new {3}, left {4}' -f $_.Step, $_.Changed, $_.Unchanged, $_.New, $_.Left }) -join "`n"
        Write-Host $text
        $all.Count | Should -Be 0 -Because (($all -join "`n") + "`n" + $text)
    }
    It 'the fixtures really moved what they claim (so the proof is not empty)' {
        $by = @{}; foreach ($s in $script:Steps) { $by[$s.Step] = $s }
        $by['open (first collection)'].New | Should -BeGreaterThan 4
        $by['seen again (LastSeen / severity / model only)'].Changed | Should -Be 0
        $by['absent once (AbsentRuns only)'].Changed | Should -Be 0
        $by['absent twice (closed)'].Changed | Should -BeGreaterThan 0
        $by['back (reopened)'].Changed | Should -BeGreaterThan 0
        $by['frozen (disabled owner)'].Changed | Should -Be 0
        $by['incomplete run (nothing closes)'].Changed | Should -Be 0
        $by['new findings, a CI gone'].New | Should -BeGreaterThan 0
        $by['gone twice'].Changed | Should -BeGreaterThan 0
        $by['retention (old closed rows removed)'].Left | Should -BeGreaterThan 0
        $by['a key moved by an update'].Left | Should -Be 1
        $by['a key moved by an update'].New | Should -Be 1
        $by['an unread column written'].Changed | Should -Be 0
        $by['an unread column written'].Unchanged | Should -BeGreaterThan 0
    }
}

# ON DEMAND ONLY (tag Scale, owner 2026-10-11: no gate runs a scale measurement): run with -Tag Scale when the owner asks
Describe 'the marks'' cost at a large install''s size: the lifecycle statement itself, marks off and on (real SQL)' -Tag 'Scale' -Skip:(-not $script:HasSql) {
    BeforeAll {
        $script:CDb = 'si_test_lccost_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
        $m = New-Object System.Data.SqlClient.SqlConnection "Server=$($env:SI_TEST_LOCALSQL);Database=master;$($env:SI_TEST_SQL_AUTH);Connection Timeout=30"
        $m.Open(); try { $c = $m.CreateCommand(); $c.CommandText = "CREATE DATABASE [$($script:CDb)]"; $c.CommandTimeout = 300; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
        $script:CCn = New-Object System.Data.SqlClient.SqlConnection ("Server=$($env:SI_TEST_LOCALSQL);Database=$($script:CDb);$($env:SI_TEST_SQL_AUTH);Connection Timeout=30;Pooling=false")
        $script:CCn.Open()
        # (each statement says its time: the gate ends a suite that prints nothing for 5 minutes)
        function script:C([string]$Sql, [hashtable]$P = @{}) {
            $c = $script:CCn.CreateCommand(); $c.CommandText = $Sql; $c.CommandTimeout = 1200
            foreach ($k in $P.Keys) { [void]$c.Parameters.AddWithValue('@' + $k, $P[$k]) }
            $sw = [Diagnostics.Stopwatch]::StartNew(); $rd = $c.ExecuteReader(); while ($rd.Read()) { }; while ($rd.NextResult()) { while ($rd.Read()) { } }; $rd.Close()
            Write-Host ('  cost step: {0:N0} ms' -f $sw.ElapsedMilliseconds); $sw.ElapsedMilliseconds
        }
        function script:Q([string]$Sql) { $c = $script:CCn.CreateCommand(); $c.CommandText = $Sql; $c.CommandTimeout = 600; $c.ExecuteScalar() }
        $null = C $script:Schema
        $script:N = 1000000
        # the collection's findings, staged as the data sync stages them
        $null = C @"
;WITH n AS (SELECT TOP ($($script:N)) ROW_NUMBER() OVER (ORDER BY (SELECT 1)) AS i FROM sys.all_objects a CROSS JOIN sys.all_objects b CROSS JOIN sys.all_objects c)
INSERT sidata.CiFindingLifecycleStage (Kind, OwnerKey, FindingKey, CiId, Severity, DetectedBy) SELECT N'f', CONCAT(N'ci-', i % 200000), CONCAT(N'CVE-2026-', i), CONCAT(N'ci-', i % 200000), N'high', N'R1' FROM n;
"@
        $run = {
            param([string]$Snap, [bool]$Marks)
            $script:SIDataLifecycleMarks = $Marks
            $sql = Get-SIDataFindingStateSql -WithDisabledOwners -WithEquivalence -FromStage
            $script:SIDataLifecycleMarks = $false
            C $sql @{ snap = $Snap; complete = '1'; closeAfter = '2'; disabledOwners = '[]' }
        }
        $script:Cost = [ordered]@{}
        $script:Cost['open (1,000,000 new), marks on'] = & $run '2026-11-01T05:00:00.000' $true
        $script:MarkedAfterOpen = [long](Q 'SELECT COUNT_BIG(*) FROM sidata.CiFindingState WHERE ChangedAt IS NOT NULL')
        $script:MarkAfterOpen = Q "SELECT CONVERT(nvarchar(30), MAX(ChangedAt), 126) FROM sidata.CiFindingState"
        $script:Cost['seen, marks off'] = & $run '2026-11-02T05:00:00.000' $false
        $script:Cost['seen, marks on']  = & $run '2026-11-03T05:00:00.000' $true
        $script:Cost['seen, marks off (again)'] = & $run '2026-11-04T05:00:00.000' $false
        $script:Cost['seen, marks on (again)']  = & $run '2026-11-05T05:00:00.000' $true
        $script:MaxMark = Q "SELECT CONVERT(nvarchar(30), MAX(ChangedAt), 126) FROM sidata.CiFindingState"
        $script:Gone = [long](Q 'SELECT COUNT_BIG(*) FROM sidata.CiFindingStateGone')
    }
    AfterAll {
        try { $script:CCn.Dispose() } catch { }
        [System.Data.SqlClient.SqlConnection]::ClearAllPools()
        try {
            $m = New-Object System.Data.SqlClient.SqlConnection "Server=$($env:SI_TEST_LOCALSQL);Database=master;$($env:SI_TEST_SQL_AUTH);Connection Timeout=30"
            $m.Open(); try { $c = $m.CreateCommand(); $c.CommandTimeout = 300; $c.CommandText = "ALTER DATABASE [$($script:CDb)] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$($script:CDb)]"; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
        } catch { }
    }
    It 'is measured and said; the every-run path writes no mark (nothing read changed), the open path marks every new row' {
        Write-Host ('MARK COST ({0:N0} lifecycle rows, the lifecycle statement): ' -f $script:N) + (($script:Cost.Keys | ForEach-Object { '{0} {1:N0} ms' -f $_, $script:Cost[$_] }) -join '; ')
        $script:MarkedAfterOpen | Should -Be $script:N
        $script:Gone | Should -Be 0
        # the seen runs changed nothing read: every mark is still the open run's
        $script:MaxMark | Should -Be $script:MarkAfterOpen
        $script:SIDataLifecycleMarks = $true; $on = Get-SIDataFindingStateSql -WithDisabledOwners -WithEquivalence -FromStage
        $script:SIDataLifecycleMarks = $false; $off = Get-SIDataFindingStateSql -WithDisabledOwners -WithEquivalence -FromStage
        $seen = 'UPDATE s SET LastSeen = @t, LastSnapshot = @t, AbsentRuns = 0'
        $on.Substring($on.IndexOf($seen), 400) | Should -Be $off.Substring($off.IndexOf($seen), 400) -Because 'the every-run update of LastSeen is the statement of before, marks on or off'
    }
}