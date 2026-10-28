#Requires -Version 7.0
<#
    #882 (C5) ONLY WHAT CHANGED IS SENT WHOLE (engine/data-model/SI-RecordSql.ps1 Write-SIRecordsToSql): before a batch is
    written the database says which records are new or carry another content hash; only those go with their document and
    identifiers -- an unchanged record goes with its key and hash, its collection time, completeness and last-seen updated as
    before. MANDATORY PROOF (coordinator 2026-10-22): on a real SQL Server, the OLD path (every record sent whole) and the NEW
    path give the SAME rows -- every column of sidata.CiRecord and sidata.RecordIdentifier -- with no change, with some
    records changed (content, identifiers), with a record gone from a batch and with a pinned (not complete) record.
    Offline parts: the answer is trusted only when it counts every key asked; otherwise everything is sent whole.
#>

BeforeDiscovery {
    $script:HasSql = $false
    try { $script:HasSql = (Get-Service -Name 'MSSQL$SQLEXPRESS' -ErrorAction Stop).Status -eq 'Running' } catch { $script:HasSql = $false }
    # the Pro schemas (not in the Community copy): the real-SQL case runs only where they are
    $sr = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    if (-not ((Test-Path -LiteralPath (Join-Path $sr 'sql\si-data-schema.sql')) -and (Test-Path -LiteralPath (Join-Path $sr 'sql\si-identity-schema.sql')))) { $script:HasSql = $false }
}

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordCapture.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordSql.ps1')
    $script:T1 = [datetime]::SpecifyKind([datetime]'2026-10-20T06:00:00', 'Utc')
    function script:Row([string]$Key, [hashtable]$Extra = @{}, [datetime]$At = $script:T1) {
        $h = [ordered]@{ si_record_key = $Key; si_provider = 'eg'; si_record_type = 'user'; si_class = 'identity'; si_asset_name = "name-$Key"
                         si_collection_time = $At; si_collection_complete = $true; si_source_last_seen = $At.AddHours(-1); ad_sid = ('S-1-5-21-1-2-3-' + $Key.Length); entra_object_id = "oid-$Key" }
        foreach ($k in $Extra.Keys) { $h[$k] = $Extra[$k] }
        [pscustomobject]$h
    }
    function script:New-Db {
        $name = 'si882_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
        $m = New-Object System.Data.SqlClient.SqlConnection 'Server=.\SQLEXPRESS;Database=master;Integrated Security=SSPI;Connection Timeout=30'
        $m.Open(); try { $c = $m.CreateCommand(); $c.CommandText = "CREATE DATABASE [$name]"; $c.CommandTimeout = 300; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
        $cn = New-Object System.Data.SqlClient.SqlConnection ("Server=.\SQLEXPRESS;Database=$name;Integrated Security=SSPI;Connection Timeout=30;Pooling=false")
        $cn.Open()
        foreach ($f in 'sql\si-data-schema.sql', 'sql\si-identity-schema.sql') { $c = $cn.CreateCommand(); $c.CommandTimeout = 300; $c.CommandText = [IO.File]::ReadAllText((Join-Path $script:SIRoot $f)); [void]$c.ExecuteNonQuery() }
        [pscustomobject]@{ Name = $name; Conn = $cn }
    }
    function script:Close-Db($Db) {
        try { $Db.Conn.Dispose() } catch { }
        [System.Data.SqlClient.SqlConnection]::ClearAllPools()
        $m = New-Object System.Data.SqlClient.SqlConnection 'Server=.\SQLEXPRESS;Database=master;Integrated Security=SSPI;Connection Timeout=30'
        $m.Open(); try { $c = $m.CreateCommand(); $c.CommandTimeout = 300; $c.CommandText = "ALTER DATABASE [$($Db.Name)] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$($Db.Name)]"; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
    }
    $script:Asked = @{ N = 0 }
    # (no GetNewClosure: a closure cannot see the functions this file loaded -- Read-SISqlRows among them)
    $script:OldConn = $null; $script:NewConn = $null
    function script:Invoke-DbSeam($Conn, [bool]$Old, $Sql, $Params, $Mode) {
        # the OLD path: the database never answers which records changed -> every record is sent whole
        if ($Old -and $Sql -match 'DeltaAsked') { throw 'old path: no delta read' }
        if ($Sql -match 'DeltaAsked') { $script:Asked.N++ }
        $c = $Conn.CreateCommand(); $c.CommandText = $Sql; $c.CommandTimeout = 0
        if ($Params) { foreach ($k in $Params.Keys) { $pp = $c.Parameters.Add('@' + $k, [System.Data.SqlDbType]::NVarChar, -1); $pp.Value = [string]$Params[$k] } }
        if ($Mode -eq 'scalar') { return $c.ExecuteScalar() }
        if ($Mode -eq 'rows') { return @(Read-SISqlRows -Command $c) }
        $c.ExecuteNonQuery()
    }
    $script:OldSeam = { param($Sql, $Params, $Mode) Invoke-DbSeam $script:OldConn $true $Sql $Params $Mode }
    $script:NewSeam = { param($Sql, $Params, $Mode) Invoke-DbSeam $script:NewConn $false $Sql $Params $Mode }
    function script:Dump($Db) {
        $out = New-Object System.Collections.Generic.List[string]
        foreach ($q in @("SELECT RecordKey, Provider, RecordType, Class, Name, CONVERT(nvarchar(40), SourceLastSeen, 126) AS S, CONVERT(nvarchar(40), CollectionTime, 126) AS C, CAST(Complete AS int) AS K, CONVERT(nvarchar(80), ContentHash, 2) AS H, DocJson FROM sidata.CiRecord ORDER BY RecordKey",
                         "SELECT RecordKey, IdType, IdValue, CONVERT(nvarchar(40), SeenAt, 126) AS A FROM sidata.RecordIdentifier ORDER BY RecordKey, IdType, IdValue")) {
            $c = $Db.Conn.CreateCommand(); $c.CommandText = $q
            $r = $c.ExecuteReader()
            try { while ($r.Read()) { $v = for ($i = 0; $i -lt $r.FieldCount; $i++) { if ($r.IsDBNull($i)) { '<null>' } else { [string]$r.GetValue($i) } }; $out.Add(($v -join ' | ')) } } finally { $r.Close() }
            $out.Add('----')
        }
        $out.ToArray()
    }
}

Describe 'the delta answer is trusted only when it is whole' {
    It 'an answer without DeltaAsked, or one that counts fewer keys than asked, means: send everything whole' {
        $recs = @([ordered]@{ RecordKey = 'a'; Hash = 'AA' }, [ordered]@{ RecordKey = 'b'; Hash = 'BB' })
        Get-SIRecordSqlChangedKeys -Records $recs -Invoke { param($s, $p, $m) [pscustomobject]@{ Seen = 2 } } | Should -BeNullOrEmpty
        Get-SIRecordSqlChangedKeys -Records $recs -Invoke { param($s, $p, $m) [pscustomobject]@{ DeltaAsked = 1; ChangedKeys = '[]' } } | Should -BeNullOrEmpty
        Get-SIRecordSqlChangedKeys -Records $recs -Invoke { param($s, $p, $m) throw 'x' } | Should -BeNullOrEmpty
        $set = Get-SIRecordSqlChangedKeys -Records $recs -Invoke { param($s, $p, $m) [pscustomobject]@{ DeltaAsked = 2; ChangedKeys = '[{"RecordKey":"B"}]' } }
        $set.Contains('b') | Should -BeTrue -Because 'keys compare without case, as the database does'
        $set.Contains('a') | Should -BeFalse
    }
    It 'the write statement never writes a record without its document as changed' {
        Get-SIRecordSqlWriteSql | Should -Match ([regex]::Escape('t.ContentHash <> s.Hash) AND s.DocJson IS NOT NULL'))
        Get-SIRecordSqlChangedKeysSql | Should -Not -Match 'UPDATE|DELETE|INSERT sidata|MERGE'
    }
}

Describe 'OLD path and NEW path give the SAME rows on a real SQL Server' {
    It 'every column of CiRecord and RecordIdentifier is equal -- first load, unchanged run, changed records, a pinned record' -Skip:(-not $script:HasSql) {
        $old = New-Db; $new = New-Db
        try {
            $script:OldConn = $old.Conn; $script:NewConn = $new.Conn; $so = $script:OldSeam; $sn = $script:NewSeam
            $keys = @(1..60 | ForEach-Object { 'eg|user|k{0:d3}' -f $_ })
            $T2 = $script:T1.AddDays(1); $T3 = $script:T1.AddDays(2)
            $steps = @(
                # 1. the first load: every record new
                @{ At = $script:T1; Rows = { param($at) @($keys | ForEach-Object { Row $_ @{} $at }) } },
                # 2. the next run: nothing changed (only the per-run columns move)
                @{ At = $T2; Rows = { param($at) @($keys | ForEach-Object { Row $_ @{} $at }) } },
                # 3. some changed: a name, an identifier, an added field; one key missing from the batch; one not complete
                @{ At = $T3; Rows = { param($at) @($keys | Where-Object { $_ -ne 'eg|user|k007' } | ForEach-Object {
                        if ($_ -eq 'eg|user|k003') { Row $_ @{ si_asset_name = 'renamed' } $at }
                        elseif ($_ -eq 'eg|user|k004') { Row $_ @{ entra_object_id = 'oid-other' } $at }
                        elseif ($_ -eq 'eg|user|k005') { Row $_ @{ extra_field = 'x' } $at }
                        elseif ($_ -eq 'eg|user|k006') { Row $_ @{ si_collection_complete = $false } $at }
                        else { Row $_ @{} $at } }) } }
            )
            foreach ($s in $steps) {
                $rows = & $s.Rows $s.At
                $wo = Write-SIRecordsToSql -Rows $rows -Invoke $so -Now $s.At
                $wn = Write-SIRecordsToSql -Rows $rows -Invoke $sn -Now $s.At
                $wo.Failed | Should -Be 0; $wn.Failed | Should -Be 0
                $wn.Seen | Should -Be $wo.Seen
                $wn.Changed | Should -Be $wo.Changed
                $a = Dump $old; $b = Dump $new
                $b | Should -Be $a -Because ('step at {0:u}: the new path must store exactly what the old one did' -f $s.At)
            }
            $script:Asked.N | Should -BeGreaterThan 0 -Because 'the new path really asked which records changed'
        } finally { Close-Db $old; Close-Db $new }
    }
}
