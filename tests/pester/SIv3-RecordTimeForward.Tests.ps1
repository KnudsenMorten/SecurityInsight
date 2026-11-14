#Requires -Version 7.0
<#
    A RECORD'S COLLECTION TIME NEVER MOVES BACK (engine/data-model/SI-RecordSql.ps1 Get-SIRecordSqlWriteSql /
    Write-SIRecordsToSql). Two collections of the same source can write at once -- an older run's queue workers still going
    beside a newer run -- and the record write had no "only when newer" check: an older write set a record's collection time
    BACK and overwrote newer values with older ones. What these keep true:
      * a stored record is changed only by a write of the SAME or a NEWER collection time -- the check is in the UPDATE and
        the MERGE themselves, a plain comparison of the stored column (no function on it);
      * an older write leaves the record whole (time, values, identifiers), is counted (Older) and said in ONE plain line per
        write call -- never an error, never a failed batch;
      * the same time twice is written (idempotent); a newer time after an older one is written; a mixed batch skips only
        its older rows; a NEW record is always inserted, whatever its time.
    The real-SQL parts need SQL Express (the test VM: SI_TEST_LOCALSQL) and the Pro schemas.
#>

BeforeDiscovery {
    $script:HasSql = $false
    try { $script:HasSql = [bool]$env:SI_TEST_LOCALSQL } catch { $script:HasSql = $false }
    $sr = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    if (-not ((Test-Path -LiteralPath (Join-Path $sr 'sql\si-data-schema.sql')) -and (Test-Path -LiteralPath (Join-Path $sr 'sql\si-identity-schema.sql')))) { $script:HasSql = $false }
}

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordCapture.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordSql.ps1')
    $script:SIRecordWriteRetryMs = 1
    $script:T1 = [datetime]::SpecifyKind([datetime]'2026-11-10T06:00:00', 'Utc')
    $script:T2 = $script:T1.AddDays(1)
    $script:T3 = $script:T1.AddDays(2)
    function script:Row([string]$Key, [datetime]$At, [string]$Name = '', [string]$Oid = '') {
        if (-not $Name) { $Name = "name-$Key" }
        if (-not $Oid) { $Oid = "oid-$Key" }
        [pscustomobject][ordered]@{ si_record_key = $Key; si_provider = 'eg'; si_record_type = 'user'; si_class = 'identity'; si_asset_name = $Name
            si_collection_time = $At; si_collection_complete = $true; si_source_last_seen = $At.AddHours(-1); entra_object_id = $Oid }
    }
    function script:New-Db {
        $name = 'sitf_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
        $m = New-Object System.Data.SqlClient.SqlConnection "Server=$($env:SI_TEST_LOCALSQL);Database=master;$($env:SI_TEST_SQL_AUTH);Connection Timeout=60"
        $m.Open(); try { $c = $m.CreateCommand(); $c.CommandText = "CREATE DATABASE [$name]"; $c.CommandTimeout = 300; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
        $cn = New-Object System.Data.SqlClient.SqlConnection ("Server=$($env:SI_TEST_LOCALSQL);Database=$name;$($env:SI_TEST_SQL_AUTH);Connection Timeout=60;Pooling=false")
        $cn.Open()
        foreach ($f in 'sql\si-data-schema.sql', 'sql\si-identity-schema.sql') { $c = $cn.CreateCommand(); $c.CommandTimeout = 300; $c.CommandText = [IO.File]::ReadAllText((Join-Path $script:SIRoot $f)); [void]$c.ExecuteNonQuery() }
        [pscustomobject]@{ Name = $name; Conn = $cn }
    }
    function script:Close-Db($Db) {
        if (-not $Db) { return }
        try { $Db.Conn.Dispose() } catch { }
        [System.Data.SqlClient.SqlConnection]::ClearAllPools()
        $m = New-Object System.Data.SqlClient.SqlConnection "Server=$($env:SI_TEST_LOCALSQL);Database=master;$($env:SI_TEST_SQL_AUTH);Connection Timeout=60"
        $m.Open(); try { $c = $m.CreateCommand(); $c.CommandTimeout = 300; $c.CommandText = "ALTER DATABASE [$($Db.Name)] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$($Db.Name)]"; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
    }
    function script:Q($Conn, [string]$Sql) { $c = $Conn.CreateCommand(); $c.CommandText = $Sql; $c.CommandTimeout = 300; $c.ExecuteScalar() }
    $script:Conn = $null
    function script:Invoke-Real($Sql, $Params, $Mode) {
        $c = $script:Conn.CreateCommand(); $c.CommandText = $Sql; $c.CommandTimeout = 0
        if ($Params) { foreach ($k in $Params.Keys) { $pp = $c.Parameters.Add('@' + $k, [System.Data.SqlDbType]::NVarChar, -1); $pp.Value = [string]$Params[$k] } }
        if ($Mode -eq 'scalar') { return $c.ExecuteScalar() }
        if ($Mode -eq 'rows') { return @(Read-SISqlRows -Command $c) }
        $c.ExecuteNonQuery()
    }
    $script:Seam = { param($Sql, $Params, $Mode) Invoke-Real $Sql $Params $Mode }
    # one write: the result and the lines it said (Write-Host = the information stream)
    function script:Put([object[]]$Rows, [datetime]$At, [string]$What = '') {
        $all = @(Write-SIRecordsToSql -Rows $Rows -Invoke $script:Seam -Now $At -What $What 6>&1 3>$null)
        [pscustomobject]@{
            Result = @($all | Where-Object { $_ -isnot [System.Management.Automation.InformationRecord] })[-1]
            Said   = @($all | Where-Object { $_ -is [System.Management.Automation.InformationRecord] } | ForEach-Object { [string]$_.MessageData })
        }
    }
    function script:Stored([string]$Key) {
        $c = $script:Conn.CreateCommand()
        $c.CommandText = "SELECT r.Name, CONVERT(nvarchar(19), r.CollectionTime, 126) AS CT, r.DocJson FROM sidata.CiRecord r WHERE r.RecordKey = @k"
        $p = $c.Parameters.Add('@k', [System.Data.SqlDbType]::NVarChar, 450); $p.Value = $Key
        $row = @(Read-SISqlRows -Command $c)[0]
        $c2 = $script:Conn.CreateCommand()
        $c2.CommandText = 'SELECT IdValue FROM sidata.RecordIdentifier WHERE RecordKey = @k ORDER BY IdValue'
        $p2 = $c2.Parameters.Add('@k', [System.Data.SqlDbType]::NVarChar, 450); $p2.Value = $Key
        $ids = @(Read-SISqlRows -Command $c2 | ForEach-Object { [string](Get-SIItemValue $_ 'IdValue') })
        [pscustomobject]@{ Name = [string](Get-SIItemValue $row 'Name'); CT = [string](Get-SIItemValue $row 'CT')
                           DocName = [string]((ConvertFrom-Json -InputObject ([string](Get-SIItemValue $row 'DocJson'))).si_asset_name); Ids = ($ids -join ',') }
    }
    function script:Iso([datetime]$At) { $At.ToString('yyyy-MM-ddTHH:mm:ss') }
}

Describe 'the write statement keeps a record''s collection time moving forward' {
    It 'the UPDATE and the MERGE compare the incoming time with the stored one themselves; no function on the stored column' {
        $sql = Get-SIRecordSqlWriteSql
        $guard = '(t.CollectionTime IS NULL OR s.CollectionTime IS NULL OR s.CollectionTime >= t.CollectionTime)'
        $sql | Should -Not -Match '\{NOTOLDER\}'
        $sql | Should -Match ('WHEN MATCHED AND ' + [regex]::Escape($guard) + ' THEN UPDATE')
        $upd = $sql.Substring($sql.IndexOf('UPDATE t SET'), $sql.IndexOf('MERGE sidata.CiRecord') - $sql.IndexOf('UPDATE t SET'))
        $upd | Should -Match ([regex]::Escape($guard))
        $ins = $sql.Substring($sql.IndexOf('INSERT @changed'), $sql.IndexOf('UPDATE t SET') - $sql.IndexOf('INSERT @changed'))
        $ins | Should -Match ([regex]::Escape($guard)) -Because 'a record an older write skips keeps its identifiers too'
        $sql | Should -Not -Match '\w+\(\s*t\.CollectionTime' -Because 'the stored column is compared plainly, so its index can be used'
        $sql | Should -Match 'AS Older,'   # (followed by Stale -- see below)
        $sql.IndexOf('INSERT @older') | Should -BeGreaterThan $sql.IndexOf('sp_getapplock') -Because 'what is older is read under the record write lock'
        (Get-SIRecordSqlWriteSql -LockMs 0) | Should -Not -Match '\{NOTOLDER\}'
    }
    It 'the skipped records are said in ONE plain line per write, never as an error; none skipped -> nothing said' {
        $seam = { param($Sql, $Params, $Mode) if ($Sql -match 'DeltaAsked') { return $null }; [pscustomobject]@{ Seen = 3; Changed = 0; Identifiers = 0; Older = 2 } }
        $w = $null
        $all = @(Write-SIRecordsToSql -Rows @((Row 'k1' $script:T1), (Row 'k2' $script:T1), (Row 'k3' $script:T1)) -Invoke $seam -Now $script:T1 -What 'bucket 4' -WarningVariable w 6>&1 3>$null)
        $said = @($all | Where-Object { $_ -is [System.Management.Automation.InformationRecord] } | ForEach-Object { [string]$_.MessageData })
        $r = @($all | Where-Object { $_ -isnot [System.Management.Automation.InformationRecord] })[-1]
        ($r.Seen, $r.Older, $r.Failed) | Should -Be @(3, 2, 0)
        @($said | Where-Object { $_ -match 'not changed' }).Count | Should -Be 1
        $said | Should -Contain '[INFO] records: 2 record(s) of bucket 4 were not changed: a newer collection already wrote them.'
        @($w).Count | Should -Be 0 -Because 'an older write skipped is not a warning'
        $seam0 = { param($Sql, $Params, $Mode) if ($Sql -match 'DeltaAsked') { return $null }; [pscustomobject]@{ Seen = 1; Changed = 1; Identifiers = 0; Older = 0 } }
        $all = @(Write-SIRecordsToSql -Rows @((Row 'k1' $script:T1)) -Invoke $seam0 -Now $script:T1 6>&1 3>$null)
        @($all | Where-Object { $_ -is [System.Management.Automation.InformationRecord] }).Count | Should -Be 0
        @($all)[-1].Older | Should -Be 0
    }
    It 'NEVER OLDER CONTENT UNDER A NEWER TIME: the time-only UPDATE also needs the stored hash to equal the incoming one; a moved hash without a document is counted (Stale)' {
        $sql = Get-SIRecordSqlWriteSql
        $upd = $sql.Substring($sql.IndexOf('UPDATE t SET'), $sql.IndexOf('MERGE sidata.CiRecord') - $sql.IndexOf('UPDATE t SET'))
        $upd | Should -Match ([regex]::Escape('AND (t.ContentHash IS NULL OR t.ContentHash = s.Hash)'))
        $sql | Should -Match ([regex]::Escape('WHERE s.DocJson IS NULL AND t.ContentHash IS NOT NULL AND t.ContentHash <> s.Hash AND (t.CollectionTime IS NULL'))
        $sql | Should -Match 'AS Stale;'
        $sql.IndexOf('INSERT @stale') | Should -BeGreaterThan $sql.IndexOf('sp_getapplock') -Because 'what moved is read under the record write lock'
    }
    It 'a batch with Stale records is written again WHOLE (every document, every identifier), said in ONE plain line' {
        $calls = New-Object System.Collections.Generic.List[object]
        $seam = {
            param($Sql, $Params, $Mode)
            if ($Sql -match 'DeltaAsked') { return [pscustomobject]@{ DeltaAsked = 2; ChangedKeys = $null } }   # both unchanged at the read
            $calls.Add($Params)
            if ($calls.Count -eq 1) { return [pscustomobject]@{ Seen = 2; Changed = 0; Identifiers = 0; Older = 0; Stale = 1 } }
            [pscustomobject]@{ Seen = 2; Changed = 1; Identifiers = 1; Older = 0; Stale = 0 }
        }.GetNewClosure()
        $w = $null
        $all = @(Write-SIRecordsToSql -Rows @((Row 'k1' $script:T2), (Row 'k2' $script:T2)) -Invoke $seam -Now $script:T2 -What 'bucket 2' -WarningVariable w 6>&1 3>$null)
        $r = @($all | Where-Object { $_ -isnot [System.Management.Automation.InformationRecord] })[-1]
        $said = @($all | Where-Object { $_ -is [System.Management.Automation.InformationRecord] } | ForEach-Object { [string]$_.MessageData })
        $calls.Count | Should -Be 2
        @(ConvertFrom-Json $calls[0].r | Where-Object { $_.DocJson }).Count | Should -Be 0 -Because 'the first write went as a delta'
        @(ConvertFrom-Json $calls[1].r | Where-Object { $_.DocJson }).Count | Should -Be 2 -Because 'the second carries every document'
        @(ConvertFrom-Json $calls[0].i | Where-Object { $null -ne $_ }).Count | Should -Be 0
        @(ConvertFrom-Json $calls[1].i | Where-Object { $null -ne $_ } | ForEach-Object { $_.RecordKey } | Sort-Object -Unique) | Should -Be @('k1', 'k2') -Because 'and every identifier'
        ($r.Seen, $r.Changed, $r.Stale, $r.Failed) | Should -Be @(2, 1, 1, 0)
        $said | Should -Contain "[INFO] records: 1 record(s) of bucket 2 were changed by another collection while this one was written -- not stamped with this collection's time; written again with their whole content."
        @($w).Count | Should -Be 0
    }
}

Describe 'on a real SQL Server' {
    It 'a newer write, then an older one: the newer time AND values stay (document, identifiers); skipped = 1' -Skip:(-not $script:HasSql) {
        $db = New-Db
        try {
            $script:Conn = $db.Conn
            (Put @((Row 'eg|user|a1' $script:T2 'new-name' 'oid-new')) $script:T2).Result.Failed | Should -Be 0
            $p = Put @((Row 'eg|user|a1' $script:T1 'old-name' 'oid-old')) $script:T1 'bucket 1'
            ($p.Result.Failed, $p.Result.Older) | Should -Be @(0, 1)
            $p.Said | Should -Contain '[INFO] records: 1 record(s) of bucket 1 were not changed: a newer collection already wrote them.'
            $s = Stored 'eg|user|a1'
            $s.CT | Should -Be (Iso $script:T2)
            $s.Name | Should -Be 'new-name'
            $s.DocName | Should -Be 'new-name'
            $s.Ids | Should -Match 'oid-new'
            $s.Ids | Should -Not -Match 'oid-old'
        } finally { Close-Db $db }
    }
    It 'an older write of UNCHANGED content (the time-only update) does not move the time back either' -Skip:(-not $script:HasSql) {
        $db = New-Db
        try {
            $script:Conn = $db.Conn
            (Put @((Row 'eg|user|u1' $script:T2)) $script:T2).Result.Failed | Should -Be 0
            $p = Put @((Row 'eg|user|u1' $script:T1)) $script:T1
            $p.Result.Older | Should -Be 1
            (Stored 'eg|user|u1').CT | Should -Be (Iso $script:T2)
        } finally { Close-Db $db }
    }
    It 'the same time twice: written (a change at the same time is taken), and the same input again changes nothing' -Skip:(-not $script:HasSql) {
        $db = New-Db
        try {
            $script:Conn = $db.Conn
            (Put @((Row 'eg|user|s1' $script:T1 'first')) $script:T1).Result.Failed | Should -Be 0
            $p = Put @((Row 'eg|user|s1' $script:T1 'second' 'oid-second')) $script:T1
            ($p.Result.Older, $p.Result.Changed) | Should -Be @(0, 1)
            $s = Stored 'eg|user|s1'
            ($s.Name, $s.CT) | Should -Be @('second', (Iso $script:T1))
            $s.Ids | Should -Match 'oid-second'
            $p = Put @((Row 'eg|user|s1' $script:T1 'second' 'oid-second')) $script:T1
            ($p.Result.Older, $p.Result.Changed, $p.Result.Failed) | Should -Be @(0, 0, 0)
            @($p.Said | Where-Object { $_ -match 'not changed' }).Count | Should -Be 0
            (Stored 'eg|user|s1').Name | Should -Be 'second'
        } finally { Close-Db $db }
    }
    It 'a newer write after an older one: written' -Skip:(-not $script:HasSql) {
        $db = New-Db
        try {
            $script:Conn = $db.Conn
            (Put @((Row 'eg|user|f1' $script:T1 'old-name')) $script:T1).Result.Failed | Should -Be 0
            $p = Put @((Row 'eg|user|f1' $script:T2 'new-name' 'oid-new')) $script:T2
            ($p.Result.Older, $p.Result.Changed) | Should -Be @(0, 1)
            $s = Stored 'eg|user|f1'
            ($s.Name, $s.CT) | Should -Be @('new-name', (Iso $script:T2))
            $s.Ids | Should -Match 'oid-new'
        } finally { Close-Db $db }
    }
    It 'a mixed batch: only the rows older than what is stored are skipped; the others are written, the new one inserted' -Skip:(-not $script:HasSql) {
        $db = New-Db
        try {
            $script:Conn = $db.Conn
            (Put @((Row 'eg|user|m1' $script:T3 'm1-newest'), (Row 'eg|user|m4' $script:T3 'm4-newest')) $script:T3).Result.Failed | Should -Be 0
            (Put @((Row 'eg|user|m2' $script:T1 'm2-old'), (Row 'eg|user|m3' $script:T1 'm3-old')) $script:T1).Result.Failed | Should -Be 0
            # the batch at T2: m1 and m4 are older than what is stored (one changed, one not), m2 and m3 newer, m5 new
            $p = Put @((Row 'eg|user|m1' $script:T2 'm1-mid'), (Row 'eg|user|m2' $script:T2 'm2-mid'), (Row 'eg|user|m3' $script:T2 'm3-old'), (Row 'eg|user|m4' $script:T2 'm4-newest'), (Row 'eg|user|m5' $script:T2 'm5-new')) $script:T2
            ($p.Result.Seen, $p.Result.Older, $p.Result.Failed) | Should -Be @(5, 2, 0)
            ((Stored 'eg|user|m1').Name, (Stored 'eg|user|m1').CT) | Should -Be @('m1-newest', (Iso $script:T3))
            ((Stored 'eg|user|m4').Name, (Stored 'eg|user|m4').CT) | Should -Be @('m4-newest', (Iso $script:T3))
            ((Stored 'eg|user|m2').Name, (Stored 'eg|user|m2').CT) | Should -Be @('m2-mid', (Iso $script:T2))
            ((Stored 'eg|user|m3').Name, (Stored 'eg|user|m3').CT) | Should -Be @('m3-old', (Iso $script:T2))
            ((Stored 'eg|user|m5').Name, (Stored 'eg|user|m5').CT) | Should -Be @('m5-new', (Iso $script:T2))
        } finally { Close-Db $db }
    }
    It 'RACE: collection N reads "unchanged", O writes new content in between, N''s time-only write does NOT stamp O''s content -- N''s content lands whole' -Skip:(-not $script:HasSql) {
        $db = New-Db
        try {
            $script:Conn = $db.Conn
            (Put @((Row 'eg|user|r1' $script:T1 'name-a')) $script:T1).Result.Failed | Should -Be 0
            # N (T3) carries the stored content (name-a): its delta read says unchanged. Right after that read, O (T2) writes
            # new content (name-b) -- the gap between the read and N's write, outside the lock.
            $script:RaceDone = $false
            $race = {
                param($Sql, $Params, $Mode)
                $res = Invoke-Real $Sql $Params $Mode
                if (-not $script:RaceDone -and $Sql -match 'DeltaAsked') {
                    $script:RaceDone = $true
                    $o = @(Write-SIRecordsToSql -Rows @((Row 'eg|user|r1' $script:T2 'name-b')) -Invoke $script:Seam -Now $script:T2 6>$null 3>$null)[-1]
                    $o.Changed | Should -Be 1
                    ((Stored 'eg|user|r1').Name, (Stored 'eg|user|r1').CT) | Should -Be @('name-b', (Iso $script:T2))
                }
                $res
            }
            $all = @(Write-SIRecordsToSql -Rows @((Row 'eg|user|r1' $script:T3 'name-a')) -Invoke $race -Now $script:T3 -What 'bucket 9' 6>&1 3>$null)
            $script:RaceDone | Should -BeTrue
            $r = @($all | Where-Object { $_ -isnot [System.Management.Automation.InformationRecord] })[-1]
            $said = @($all | Where-Object { $_ -is [System.Management.Automation.InformationRecord] } | ForEach-Object { [string]$_.MessageData })
            ($r.Stale, $r.Failed) | Should -Be @(1, 0)
            @($said | Where-Object { $_ -match 'changed by another collection while this one was written' }).Count | Should -Be 1
            # never O's content under N's time: N's own content at N's time
            $s = Stored 'eg|user|r1'
            ($s.Name, $s.DocName, $s.CT) | Should -Be @('name-a', 'name-a', (Iso $script:T3))
        } finally { Close-Db $db }
    }
    It 'RACE, statement only: the time-only write of a record whose stored hash moved stamps nothing (Stale = 1)' -Skip:(-not $script:HasSql) {
        $db = New-Db
        try {
            $script:Conn = $db.Conn
            (Put @((Row 'eg|user|r2' $script:T1 'name-a')) $script:T1).Result.Failed | Should -Be 0
            (Put @((Row 'eg|user|r2' $script:T2 'name-b')) $script:T2).Result.Changed | Should -Be 1
            # N's batch as the delta built it: name-a's hash, no document
            $items = ConvertTo-SIRecordSqlItems -Rows @((Row 'eg|user|r2' $script:T3 'name-a')) -Now $script:T3 -DeferDoc
            $row = @(Invoke-Real (Get-SIRecordSqlWriteSql) @{ r = (ConvertTo-SIJsonArray $items.Records); i = '[]' } 'rows')[0]
            [int](Get-SIItemValue $row 'Stale') | Should -Be 1
            [int](Get-SIItemValue $row 'Changed') | Should -Be 0
            ((Stored 'eg|user|r2').Name, (Stored 'eg|user|r2').CT) | Should -Be @('name-b', (Iso $script:T2)) -Because 'name-b is not stamped with T3'
        } finally { Close-Db $db }
    }
    It 'NEGATIVE: a new record is always inserted, even with a time older than every stored record' -Skip:(-not $script:HasSql) {
        $db = New-Db
        try {
            $script:Conn = $db.Conn
            (Put @((Row 'eg|user|n1' $script:T3)) $script:T3).Result.Failed | Should -Be 0
            $p = Put @((Row 'eg|user|n2' $script:T1 'n2-name'), (Row 'eg|user|n3' $script:T1 'n3-name')) $script:T1
            ($p.Result.Seen, $p.Result.Changed, $p.Result.Older, $p.Result.Failed) | Should -Be @(2, 2, 0, 0)
            [int](Q $db.Conn 'SELECT COUNT(*) FROM sidata.CiRecord') | Should -Be 3
            ((Stored 'eg|user|n2').Name, (Stored 'eg|user|n2').CT) | Should -Be @('n2-name', (Iso $script:T1))
            (Stored 'eg|user|n3').Ids | Should -Match 'oid-eg\|user\|n3'
        } finally { Close-Db $db }
    }
}
