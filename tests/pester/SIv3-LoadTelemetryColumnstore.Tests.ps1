#Requires -Version 5.1
<#
    #1306 / #1316 (SCALE-2, REQUIREMENTS #1314): THE INSTALL REPORTS ITS DATABASE LOAD, AND COLUMNSTORE ON THE READ-HEAVY TABLES.
    What must hold:
      (a) the heartbeat's Database field carries the load INSIDE its existing value -- two keys after the six and the
          statistics keys: tables [<= 15] { name, rows, reservedMb } and topQueries24h [<= 10] { queryHash, executions,
          durationMs, logicalReads } -- behind DatabaseSendLoad (off until Invardia accepts the keys: its wire contract is
          closed); NEVER a query's text; a part that is not read (a missing right) is left out on its own, a read that fails
          leaves both out -- never the rest of Database, never the heartbeat;
      (b) the columnstore indexes (SI_Data_ColumnstoreIndexes, ON by default since owner 2026-11-23) are recorded for the
          index build job ONLY when the setting is on (or not set), built ONLY by the index build job (online, never
          resumable), refused there while the setting is off, and undone (row removed, index dropped) when it is off again;
      (c) REAL SQL: the load read runs on a real database and answers only names, hashes and numbers; the columnstore path
          records, builds and drops on a real database, and an aggregate read through the columnstore index answers row for
          row what the same read through the table's own index answers (an index never changes a result -- prio 1).
#>

BeforeDiscovery {
    try { $script:HasSql = [bool]$env:SI_TEST_LOCALSQL -and $null -ne ('System.Data.SqlClient.SqlConnection' -as [type]) } catch { $script:HasSql = $false }
}

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\_shared\SI-HeartbeatJob.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-HeartbeatFields.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-IndexBuild.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-UpdaterStart.ps1')
    . (Join-Path $script:SIRoot 'setup\_shared\SI-DbInitJob.ps1')
    . (Join-Path $script:SIRoot 'container\updater\_shared\SI-UpdaterRunGate.ps1')
    . (Join-Path $script:SIRoot 'engine\index-build\SI-IndexBuildJob.ps1')
    $script:Now = [datetime]'2026-11-23T10:00:00Z'
    $script:OnlyDb = @{ Database = $true; Pipeline = $false; Jobs = $false; Sources = $false; Update = $false; Mail = $false; Warnings = $false; Security = $false
                        Published = $false; DataOut = $false; BuildPool = $false; UplinkBacklog = $false }
    $script:Six = @('tier', 'dtu', 'maxSizeMb', 'usedMb', 'peakLogWritePct1h', 'minutesAtLimit1h')
    $script:LoadRows = @(
        @{ K = 'table'; Name = 'sidata.Finding'; N1 = 1450000; N2 = 21000 }
        @{ K = 'table'; Name = 'sidata.CiFinding'; N1 = 1400000; N2 = 9000 }
        @{ K = 'query'; Hash = '0x1a2b3c4d5e6f7081'; N1 = 12; N2 = 360000; N3 = 98000000 }
        @{ K = 'query'; Hash = '0xFFEE000011112222'; N1 = 4000; N2 = 1200; N3 = 5000 }
    )
    function script:Get-DbField {
        param([object[]]$LoadRows, [scriptblock]$Log = { param($l) }, [bool]$Send = $true)
        $c = Get-SIHeartbeatFieldsContract
        $was = $c.DatabaseSendLoad
        try {
            $c.DatabaseSendLoad = $Send
            $a = @{ Ring = 0; NowUtc = $script:Now; Switch = $script:OnlyDb; Counts = @{ sqlUsedMb = 2007; sqlMaxMb = 4096 }; Log = $Log }
            if ($PSBoundParameters.ContainsKey('LoadRows')) { $a['DatabaseLoadRows'] = $LoadRows }
            (New-SIHeartbeatFields @a)['Database']
        } finally { $c.DatabaseSendLoad = $was }
    }
}

Describe '#1306 (a) the database load rides INSIDE the Database field, never a query text' {
    It 'the contract: two keys after the others, behind a switch that is ON since Invardia accepted them; the six unchanged' {
        $c = Get-SIHeartbeatFieldsContract
        @($c.DatabaseLoadFields) | Should -Be @('tables', 'topQueries24h')
        $c.DatabaseSendLoad | Should -BeTrue -Because 'Invardia accepted Database.tables and Database.topQueries24h (deploy 4f12c7d0, 2026-11-23)'
        @($c.Fields.Database) | Should -Be $script:Six
        @($c.DatabaseLoadTableFields) | Should -Be @('name', 'rows', 'reservedMb')
        @($c.DatabaseLoadQueryFields) | Should -Be @('queryHash', 'executions', 'durationMs', 'logicalReads')
        $c.Names | Should -Not -Contain 'DatabaseLoad' -Because 'no new top-level heartbeat key'
    }
    It 'switched on: Database = the six, then tables and topQueries24h, typed, passing the agreed schema' {
        $d = Get-DbField -LoadRows $script:LoadRows
        @($d.PSObject.Properties.Name) | Should -Be ($script:Six + @('tables', 'topQueries24h'))
        @($d.tables).Count | Should -Be 2
        $d.tables[0].name | Should -Be 'sidata.Finding'; $d.tables[0].rows | Should -Be 1450000; $d.tables[0].reservedMb | Should -Be 21000
        @($d.tables[0].PSObject.Properties.Name) | Should -Be @('name', 'rows', 'reservedMb')
        @($d.topQueries24h).Count | Should -Be 2
        $d.topQueries24h[0].queryHash | Should -Be '0x1A2B3C4D5E6F7081' -Because 'the hash, upper-case hex'
        @($d.topQueries24h[0].PSObject.Properties.Name) | Should -Be @('queryHash', 'executions', 'durationMs', 'logicalReads')
        $d.topQueries24h[0].logicalReads | Should -Be 98000000
        Test-SIHeartbeatField -Name 'Database' -Value $d | Should -BeNullOrEmpty
        $d.usedMb | Should -Be 2007 -Because 'the six stay as they were'
    }
    It 'a row that carries a query text never puts it on the wire: only the four agreed keys of a query leave' {
        $rows = @(@{ K = 'query'; Hash = '0x0000000000000001'; N1 = 1; N2 = 2; N3 = 3; Text = "SELECT * FROM sidata.Finding WHERE AssetName = N'customer-pc-42'"; QueryText = 'secret' })
        $d = Get-DbField -LoadRows $rows
        $json = $d | ConvertTo-Json -Depth 6 -Compress
        $json | Should -Not -Match 'customer-pc-42|secret|SELECT'
        @($d.topQueries24h[0].PSObject.Properties.Name) | Should -Be @('queryHash', 'executions', 'durationMs', 'logicalReads')
    }
    It 'the read never selects a text: the SQL reads query_hash only, catalog / DMV views only, no product table, no write' {
        $q = Get-SIHeartbeatDatabaseLoadSql
        $q | Should -Not -Match '(?i)query_sql_text|dm_exec_sql_text|query_text|statement_text|\.text\b|sql_handle'
        $q | Should -Match 'q\.query_hash'
        $q | Should -Match 'qs\.query_hash'
        $q | Should -Match 'sys\.dm_db_partition_stats'
        $q | Should -Match 'SET LOCK_TIMEOUT 5000'
        $q | Should -Not -Match '(?i)\b(sidata|cfg|vuln)\.' -Because 'never a product table'
        ($q -replace '(?i)INSERT @r', '') | Should -Not -Match '(?i)\b(INSERT|UPDATE|DELETE|MERGE|ALTER|DROP|CREATE|EXEC)\b' -Because 'one read, never a change'
        $q | Should -Match 'TOP \(15\)'
        $q | Should -Match 'TOP \(10\)'
    }
    It 'the tables part reads ONLY SI''s own schemas -- exactly the schemas SI''s sql files create, never dbo or another' {
        $c = Get-SIHeartbeatFieldsContract
        $created = New-Object System.Collections.Generic.List[string]
        foreach ($f in Get-ChildItem (Join-Path $script:SIRoot 'sql') -Filter '*.sql') {
            foreach ($m in [regex]::Matches((Get-Content -Raw $f.FullName), "(?i)CREATE SCHEMA \[?([a-z0-9_]+)\]?")) { $created.Add($m.Groups[1].Value.ToLowerInvariant()) }
        }
        foreach ($s in @($created | Sort-Object -Unique)) { @($c.DatabaseLoadSchemas) | Should -Contain $s -Because "SI creates schema $s" }
        @($c.DatabaseLoadSchemas) | Should -Not -Contain 'dbo'
        $q = Get-SIHeartbeatDatabaseLoadSql
        $q | Should -Match "s\.name IN \(N'sidata', N'cfg', N'vuln', N'cmdbsync', N'snowstage', N'si', N'signin'\)"
        $q | Should -Not -Match "(?i)is_ms_shipped = 0\s*JOIN sys\.schemas AS s ON s\.schema_id = t\.schema_id\s*GROUP" -Because 'never every schema'
    }
    It 'a schema name that is not a plain name is refused, never put into the read' {
        $c = Get-SIHeartbeatFieldsContract
        $was = $c.DatabaseLoadSchemas
        try { $c.DatabaseLoadSchemas = @('sidata', "x'); DROP TABLE t; --"); { Get-SIHeartbeatDatabaseLoadSql } | Should -Throw '*not a schema name*' }
        finally { $c.DatabaseLoadSchemas = $was }
    }
    It 'a part not read (a missing right): that key is left out on its own, the other goes, and it is said ONCE naming the right' {
        $global:SI_HeartbeatFieldProblemsSaid = $false
        $said = New-Object System.Collections.Generic.List[string]
        $rows = @($script:LoadRows | Where-Object { $_.K -eq 'table' }) + @(@{ K = 'denied'; Name = 'queries'; N1 = 300 })
        $d = Get-DbField -LoadRows $rows -Log { param($l) $said.Add($l) }.GetNewClosure()
        @($d.PSObject.Properties.Name) | Should -Be ($script:Six + @('tables'))
        $said.Count | Should -Be 1
        $said[0] | Should -Match 'queries \(SQL error 300\)'
        $said[0] | Should -Match 'VIEW DATABASE PERFORMANCE STATE'
    }
    It 'both parts denied: Database is the six only -- never a failed heartbeat' {
        $global:SI_HeartbeatFieldProblemsSaid = $false
        $d = Get-DbField -LoadRows @(@{ K = 'denied'; Name = 'tables'; N1 = 297 }, @{ K = 'denied'; Name = 'queries'; N1 = 297 })
        @($d.PSObject.Properties.Name) | Should -Be $script:Six
    }
    It 'a read that throws while it is taken apart: the six only, said once' {
        $global:SI_HeartbeatFieldProblemsSaid = $false
        $said = New-Object System.Collections.Generic.List[string]
        $bad = @([pscustomobject]@{ Name = 'sidata.Finding'; N1 = 1; N2 = 1 } | Add-Member -MemberType ScriptProperty -Name K -Value { throw 'VIEW DATABASE PERFORMANCE STATE permission denied' } -PassThru)
        $d = Get-DbField -LoadRows $bad -Log { param($l) $said.Add($l) }.GetNewClosure()
        @($d.PSObject.Properties.Name) | Should -Be $script:Six
        $said.Count | Should -Be 1
        $said[0] | Should -Match 'load could not be read'
    }
    It 'the switch off (the default): no load key, even with rows; nothing handed in (a test session reads nothing): the six' {
        @((Get-DbField -LoadRows $script:LoadRows -Send $false).PSObject.Properties.Name) | Should -Be $script:Six
        @((Get-DbField).PSObject.Properties.Name) | Should -Be $script:Six
    }
    It 'an empty part that WAS read is an empty array (never mistaken for not read); rows that are not whole are dropped' {
        $l = ConvertFrom-SIHeartbeatDatabaseLoad -Rows @(@{ K = 'table'; Name = 'bad name; DROP'; N1 = 1; N2 = 1 }, @{ K = 'query'; Hash = 'nothex'; N1 = 1; N2 = 1; N3 = 1 })
        , $l.Tables | Should -BeOfType [object[]]
        @($l.Tables).Count | Should -Be 0
        @($l.Queries).Count | Should -Be 0
        $null -eq $l.Tables | Should -BeFalse
    }
    It 'the validator refuses a text where a hash belongs, a wrong key, too many entries and a wrong order' {
        $ok = Get-DbField -LoadRows $script:LoadRows
        $x = $ok.PSObject.Copy(); $x.topQueries24h = [object[]]@([pscustomobject]@{ queryHash = 'SELECT 1'; executions = 1; durationMs = 1; logicalReads = 1 })
        Test-SIHeartbeatField -Name 'Database' -Value $x | Should -Match 'query hash'
        $x = $ok.PSObject.Copy(); $x.topQueries24h = [object[]]@([pscustomobject]@{ queryHash = '0x0000000000000001'; executions = 1; durationMs = 1; logicalReads = 1; text = 'x' })
        Test-SIHeartbeatField -Name 'Database' -Value $x | Should -Match 'has the fields'
        $x = $ok.PSObject.Copy(); $x.tables = [object[]]@(1..16 | ForEach-Object { [pscustomobject]@{ name = "sidata.T$_"; rows = 1; reservedMb = 1 } })
        Test-SIHeartbeatField -Name 'Database' -Value $x | Should -Match 'at most 15'
        $o = [ordered]@{}; foreach ($n in $script:Six) { $o[$n] = $ok.$n }; $o['topQueries24h'] = $ok.topQueries24h; $o['tables'] = $ok.tables
        Test-SIHeartbeatField -Name 'Database' -Value ([pscustomobject]$o) | Should -Match 'has the fields' -Because 'the agreed order'
    }
}

Describe '#1316 (b) columnstore: behind ONE setting, off by default, built only by the index build job' {
    BeforeAll {
        $script:Cs = Get-SIColumnstoreContract
        $script:Supported = [pscustomobject]@{ Ok = $true; Why = 'size S3' }
        function script:New-State { param([switch]$There, [int]$Missing = 0, $Supported = $script:Supported)
            $st = [pscustomobject]@{ Supported = $Supported; Exists = @{}; Missing = @{} }
            foreach ($ix in $script:Cs.Indexes) { $k = ('{0}|{1}' -f $ix.Table, $ix.Name).ToLowerInvariant(); $st.Exists[$k] = [bool]$There; $st.Missing[$k] = $Missing }
            $st }
        function script:New-FakeDb {
            $db = [pscustomobject]@{ Sql = (New-Object System.Collections.Generic.List[string]); Params = (New-Object System.Collections.Generic.List[object]) }
            $db | Add-Member -NotePropertyName Invoke -NotePropertyValue ({ param($s, $p, $m) $db.Sql.Add([string]$s); $db.Params.Add($p) }.GetNewClosure())
            $db }
    }
    It 'one setting, SI_Data_ColumnstoreIndexes, ON unless it says off (owner 2026-11-23: empty, not set, true or a typo = on)' {
        $script:Cs.Setting | Should -Be 'SI_Data_ColumnstoreIndexes'
        foreach ($v in @('false', '"off"', '0', 'no', $false, ' False ')) { Test-SIColumnstoreSettingOn -Value $v | Should -BeFalse -Because "value '$v'" }
        foreach ($v in @($null, [DBNull]::Value, '', 'ture', 'true', '"on"', '1', 'yes', $true, ' True ')) { Test-SIColumnstoreSettingOn -Value $v | Should -BeTrue -Because "value '$v'" }
        # not stored = the default (on); a stored false = off; unreadable = nothing on a guess
        (Read-SIColumnstoreSetting -Invoke { param($s, $p, $m) , @() }).On | Should -BeTrue
        (Read-SIColumnstoreSetting -Invoke { param($s, $p, $m) , @(@{ ValueJson = 'false' }) }).On | Should -BeFalse
        $u = Read-SIColumnstoreSetting -Invoke { param($s, $p, $m) throw 'no database' }
        $u.Known | Should -BeFalse; $u.On | Should -BeFalse
        $cat = Get-Content -Raw (Join-Path $script:SIRoot 'config\settings.catalog.locked.json') | ConvertFrom-Json
        $e = @($cat.settings | Where-Object { $_.name -eq 'SI_Data_ColumnstoreIndexes' })
        $e.Count | Should -Be 1
        $e[0].type | Should -Be 'bool'
        $e[0].defaultText | Should -Match '^On'
        "$($e[0].description) $($e[0].effect) $($e[0].whenToChange)" | Should -Not -Match 'REMOVE-ME|removed in a later release'
        $ref = Get-Content -Raw (Join-Path $script:SIRoot 'config\SecurityInsight.custom.sample.reference.ps1')
        $ref | Should -Match '(?m)^# \$global:SI_Data_ColumnstoreIndexes = \$true\s*$'
    }
    It 'the indexes: nonclustered COLUMNSTORE on the findings and the finding lifecycle, no MAX column, the phases'' columns' {
        @($script:Cs.Indexes | ForEach-Object { $_.Table }) | Should -Be @('sidata.Finding', 'sidata.CiFindingState')
        $f = Get-SIColumnstoreStatement -Index $script:Cs.Indexes[0]
        $f | Should -Match '^CREATE NONCLUSTERED COLUMNSTORE INDEX \[NCCI_Finding_Load\] ON \[sidata\]\.\[Finding\] \(\[CollectionId\], \[FindingId\], \[AssetKey\]'
        # every identifier bracket-quoted, a ']' doubled -- even for the constants of the list
        Get-SIColumnstoreStatement -Index ([pscustomobject]@{ Name = 'N]x'; Table = 'sidata.T]x'; Columns = @('a]b', 'c') }) | Should -Be 'CREATE NONCLUSTERED COLUMNSTORE INDEX [N]]x] ON [sidata].[T]]x] ([a]]b], [c])'
        Get-SIIndexQuotedName 'a]b' | Should -Be '[a]]b]'
        Get-SIIndexBuildQuotedTable -Table 'sidata.F]x' | Should -Be '[sidata].[F]]x]'
        $st = Get-SIColumnstoreStateSql
        $st | Should -Match ([regex]::Escape("OBJECT_ID(N'[sidata].[Finding]')"))
        $st | Should -Match ([regex]::Escape("COL_LENGTH(N'[sidata].[Finding]', N'CollectionId')"))
        foreach ($col in 'ExemptionId', 'RiskScore', 'Tier', 'ReportName', 'Cve', 'ConfigurationId', 'Title', 'CiLifecycle') { $script:Cs.Indexes[0].Columns | Should -Contain $col }
        foreach ($col in 'DetailJson', 'DescriptionFull', 'Evidence', 'RiskAssetFactors') { $script:Cs.Indexes[0].Columns | Should -Not -Contain $col -Because 'a MAX column cannot be in a nonclustered columnstore index' }
        $schema = Get-Content -Raw (Join-Path $script:SIRoot 'sql\si-data-schema.sql')
        foreach ($ix in $script:Cs.Indexes) { foreach ($col in $ix.Columns) {
            $schema | Should -Match ('(?m)(\b{0}\s+(BIGINT|INT|TINYINT|BIT|FLOAT|DATETIME2|NVARCHAR\((\d+)\)))|(ALTER TABLE {1} ADD {0} )' -f $col, [regex]::Escape($ix.Table)) -Because "$($ix.Table).$col is a column the schema has"
            $schema | Should -Not -Match ('(?i)ALTER TABLE {1} ADD {0} NVARCHAR\(MAX\)' -f $col, [regex]::Escape($ix.Table))
        } }
    }
    It 'the plan: off records nothing; on records a missing index; a size below S3 records nothing and says why' {
        $off = @(Get-SIColumnstorePlan -Setting @{ Known = $true; On = $false } -State (New-State) -Rows @())
        @($off | Where-Object { $_.Action -ne 'none' }).Count | Should -Be 0
        $on = @(Get-SIColumnstorePlan -Setting @{ Known = $true; On = $true } -State (New-State) -Rows @())
        @($on | ForEach-Object { $_.Action }) | Should -Be @('queue', 'queue')
        $s2 = Test-SIColumnstoreSupported -EngineEdition '5' -Objective 'S2'
        $s2.Ok | Should -BeFalse; $s2.Why | Should -Match 'Standard S3 or above'
        (Test-SIColumnstoreSupported -EngineEdition '5' -Objective 'S3').Ok | Should -BeTrue
        (Test-SIColumnstoreSupported -EngineEdition '5' -Objective 'GP_Gen5_2').Ok | Should -BeTrue
        $small = @(Get-SIColumnstorePlan -Setting @{ Known = $true; On = $true } -State (New-State -Supported $s2) -Rows @())
        @($small | ForEach-Object { $_.Action }) | Should -Be @('none', 'none')
        $small[0].Why | Should -Match 'S2 does not support'
        $miss = @(Get-SIColumnstorePlan -Setting @{ Known = $true; On = $true } -State (New-State -Missing 2) -Rows @())
        $miss[0].Action | Should -Be 'none'; $miss[0].Why | Should -Match 'columns are not there yet'
    }
    It 'the plan: off again drops an index that is there, removes a waiting row, never touches one that builds; unknown = nothing' {
        $row = [pscustomobject]@{ Table = 'sidata.Finding'; Name = 'NCCI_Finding_Load'; State = 'waiting'; Statement = 'x' }
        $p = @(Get-SIColumnstorePlan -Setting @{ Known = $true; On = $false } -State (New-State -There) -Rows @())
        @($p | ForEach-Object { $_.Action }) | Should -Be @('drop', 'drop')
        $p = @(Get-SIColumnstorePlan -Setting @{ Known = $true; On = $false } -State (New-State) -Rows @($row))
        $p[0].Action | Should -Be 'remove-row'
        $row.State = 'building'
        $p = @(Get-SIColumnstorePlan -Setting @{ Known = $true; On = $false } -State (New-State) -Rows @($row))
        $p[0].Action | Should -Be 'none'
        $p = @(Get-SIColumnstorePlan -Setting @{ Known = $false; On = $false } -State (New-State -There) -Rows @())
        @($p | Where-Object { $_.Action -ne 'none' }).Count | Should -Be 0 -Because 'a setting that cannot be read changes nothing on a guess'
        $row.State = 'waiting'
        $p = @(Get-SIColumnstorePlan -Setting @{ Known = $true; On = $true } -State (New-State) -Rows @($row))
        $p[0].Action | Should -Be 'none' -Because 'it waits for the job already'
        $p[1].Action | Should -Be 'queue'
    }
    It 'the updater''s step: off sends no CREATE and records nothing; on records two waiting rows -- and never builds one itself' {
        $db = New-FakeDb
        $r = Invoke-SIColumnstoreIndexStep -Invoke $db.Invoke -Setting @{ Known = $true; On = $false } -State (New-State) -Rows @() -Estimate { param($i) $null }
        @($db.Sql).Count | Should -Be 0
        $db = New-FakeDb
        $r = Invoke-SIColumnstoreIndexStep -Invoke $db.Invoke -Setting @{ Known = $true; On = $true } -State (New-State) -Rows @() -Estimate { param($i) [pscustomobject]@{ Known = $true; Minutes = 95; Pages = 2600000; Source = 'measured' } } `
                 -PartitionState ([pscustomobject]@{ Live = $true; OnScheme = $false; Scheme = $false; MoveTable = $false; MoveState = '' })
        @($db.Sql | Where-Object { $_ -match 'cfg\.IndexBuild' }).Count | Should -Be 2
        @($db.Params | ForEach-Object { $_['State'] }) | Should -Be @('waiting', 'waiting')
        @($db.Params | ForEach-Object { $_['Stmt'] }) | ForEach-Object { $_ | Should -Match '^CREATE NONCLUSTERED COLUMNSTORE INDEX \[NCCI_' }
        @($db.Params | ForEach-Object { $_['Est'] }) | Should -Be @(95, 95)
        @($db.Sql | Where-Object { $_ -match '(?i)^\s*CREATE\b.*COLUMNSTORE' }).Count | Should -Be 0 -Because 'the updater only records; the index build job builds'
        ($r.Lines -join ' ') | Should -Match 'NCCI_Finding_Load on sidata\.Finding recorded for the index build job \(about 1 h 35 min\)'
    }
    It 'the updater''s step drops only an index of its own list, under a lock timeout' {
        Get-SIColumnstoreDropSql -Table 'sidata.Finding' -Index 'IX_Finding_Drilldown' | Should -BeNullOrEmpty
        $d = Get-SIColumnstoreDropSql -Table 'sidata.Finding' -Index 'NCCI_Finding_Load'
        $d | Should -Match '^SET LOCK_TIMEOUT 10000; IF EXISTS \(.*type = 6\) DROP INDEX \[NCCI_Finding_Load\] ON \[sidata\]\.\[Finding\];$'
        $db = New-FakeDb
        $null = Invoke-SIColumnstoreIndexStep -Invoke $db.Invoke -Setting @{ Known = $true; On = $false } -State (New-State -There) -Rows @()
        @($db.Sql | Where-Object { $_ -match 'DROP INDEX' }).Count | Should -Be 2
    }
    It 'the index build path: a columnstore row is built ONLINE, never resumable; the window takes it like a filtered one' {
        $row = [pscustomobject]@{ Table = 'sidata.Finding'; Name = 'NCCI_Finding_Load'; Statement = (Get-SIColumnstoreStatement -Index $script:Cs.Indexes[0]); State = 'waiting'; EstMinutes = 300; SinceUtc = $script:Now.AddDays(-1); ForcedUtc = $null }
        $run = Get-SIIndexBuildRunSql -Row $row -Minutes 60
        $run.Sql | Should -Be ('{0} WITH (ONLINE = ON)' -f $row.Statement)
        $run.Resumable | Should -BeFalse
        Test-SIIndexBuildColumnstore -Statement $row.Statement | Should -BeTrue
        Test-SIIndexBuildColumnstore -Statement 'CREATE INDEX IX_Finding_Category ON sidata.Finding (CollectionId)' | Should -BeFalse
        $w = Get-SIIndexBuildWindowDecision -Rows @($row) -NowUtc $script:Now -NextRunUtc $script:Now.AddHours(2)
        $w.Start | Should -BeFalse -Because 'about 5 h does not fit a 2-hour window and it cannot pause'
        $row.EstMinutes = 60
        $w = Get-SIIndexBuildWindowDecision -Rows @($row) -NowUtc $script:Now -NextRunUtc $script:Now.AddHours(2)
        $w.Start | Should -BeTrue; $w.Resumable | Should -BeFalse
    }
    It 'COLUMNSTORE is created nowhere else in the product: not in a schema file, not in the data sync, not in the updater' {
        $hits = @(Get-ChildItem -Path $script:SIRoot -Recurse -File -Include *.ps1, *.sql, *.cs | Where-Object { $_.FullName -notmatch '[\\/](tests|docs|bin|obj)[\\/]' } |
                  Select-String -Pattern 'CREATE\s+(NONCLUSTERED\s+|CLUSTERED\s+)?COLUMNSTORE' -CaseSensitive | ForEach-Object { Split-Path -Leaf $_.Path } | Sort-Object -Unique)
        $hits | Should -Be @('SI-IndexBuild.ps1')
    }
    It 'the updater runs the step from its index build job check (every run), in its own try' {
        $src = Get-Content -Raw (Join-Path $script:SIRoot 'container\updater\_shared\SI-UpdaterDatabase.ps1')
        $fn = $src.Substring($src.IndexOf('function Invoke-SIUpdaterIndexBuildJob'))
        $fn | Should -Match 'try \{ \$null = Invoke-SIColumnstoreIndexStep -Invoke \$Store\.Invoke'
    }
}

Describe '#1316 (b) the index build job refuses a columnstore row while the setting is off' {
    BeforeAll {
        function script:New-JobW {
            param([bool]$On, [string]$Name = 'NCCI_Finding_Load', [bool]$Known = $true)
            $stmt = if ($Name -eq 'NCCI_Finding_Load') { Get-SIColumnstoreStatement -Index (Get-SIColumnstoreContract).Indexes[0] } else { "CREATE NONCLUSTERED COLUMNSTORE INDEX $Name ON sidata.Finding (CollectionId)" }
            $w = [pscustomobject]@{ Row = [pscustomobject]@{ Table = 'sidata.Finding'; Name = $Name; Statement = $stmt; State = 'waiting'; Pages = 1; EstMinutes = 30; Source = 'x'; Why = ''
                                                             SinceUtc = $script:Now.AddDays(-1); LastStartUtc = $null; LastEndUtc = $null; ForcedUtc = $null }
                                    Saves = (New-Object System.Collections.Generic.List[string]); Removed = 0; Built = $null; Log = (New-Object System.Collections.Generic.List[string]) }
            $s = @{
                Rows = { , @($w.Row) }.GetNewClosure()
                Save = { param($t, $i, $st, $why, $f) $w.Saves.Add($st); $true }.GetNewClosure()
                UpdateFirst = { '' }; OtherRunning = { '' }
                Gate = { param($h) [pscustomobject]@{ Go = $true; Reason = 'ok'; LockTaken = $true } }
                Beat = { param($h, $what) $true }; ExitGate = { param($h) }
                Exists = { param($t, $i) [bool]$w.Built }.GetNewClosure()
                ResumableOp = { param($t, $i) $null }
                Build = { param($sql, $interrupt, $onInterrupt) $w.Built = $sql; 600.0 }.GetNewClosure()
                Rate = { param($t, $secs) }
                ColumnstoreSetting = { [pscustomobject]@{ Known = $Known; On = $On } }.GetNewClosure()
                RemoveRow = { param($t, $i) $w.Removed++ }.GetNewClosure()
                # #1316 x #1317: a database without the collection partitions (the rule is tested in SIv3-ColumnstorePartitions)
                PartitionState = { [pscustomobject]@{ Live = $true; OnScheme = $false; Scheme = $false; MoveTable = $false; MoveState = '' } }
            }
            $w | Add-Member -NotePropertyName Seams -NotePropertyValue $s
            $w
        }
        function script:Invoke-JobW { param($W)
            $lg = $W.Log
            Invoke-SIIndexBuildJob -Store ([pscustomobject]@{ Invoke = { throw 'no database in this test' } }) -Holder 'caj-si-index-build:e1' -Request ([pscustomobject]@{ Table = ''; Index = ''; Minutes = 75; Force = $false }) -Seams $W.Seams -Log { param($m) $lg.Add($m) }.GetNewClosure() -NowUtc $script:Now }
    }
    It 'off: nothing built, its row removed, outcome nothing' {
        $w = New-JobW -On $false
        $r = Invoke-JobW $w
        $r.Outcome | Should -Be 'nothing'; $r.ExitCode | Should -Be 0
        $w.Built | Should -BeNullOrEmpty; $w.Removed | Should -Be 1
        ($w.Log -join ' ') | Should -Match 'the columnstore setting is off'
    }
    It 'the setting not readable: nothing built, nothing removed (not now)' {
        $w = New-JobW -On $false -Known $false
        $r = Invoke-JobW $w
        $r.Outcome | Should -Be 'not-now'; $w.Built | Should -BeNullOrEmpty; $w.Removed | Should -Be 0
    }
    It 'on: built ONLINE from its statement, recorded built' {
        $w = New-JobW -On $true
        $r = Invoke-JobW $w
        $r.Outcome | Should -Be 'built'
        $w.Built | Should -Match '^CREATE NONCLUSTERED COLUMNSTORE INDEX \[NCCI_Finding_Load\] ON \[sidata\]\.\[Finding\] \(.*\) WITH \(ONLINE = ON\)$'
        @($w.Saves) | Should -Be @('building', 'built')
    }
    It 'the gap before a scheduled run (a busy install): the runner''s late limit is the window -- a 2 h 30 min build fits the 3 h and is built online; a longer one is not started' {
        $w = New-JobW -On $true
        $w.Row.EstMinutes = 150
        $lg = $w.Log
        $gap = [int](Get-SIIndexBuildContract).GapLateMinutes
        $r = Invoke-SIIndexBuildJob -Store ([pscustomobject]@{ Invoke = { throw 'no database in this test' } }) -Holder 'caj-si-index-build:e2' -Request ([pscustomobject]@{ Table = 'sidata.Finding'; Index = 'NCCI_Finding_Load'; Minutes = $gap; Force = $false }) -Seams $w.Seams -Log { param($m) $lg.Add($m) }.GetNewClosure() -NowUtc $script:Now
        $r.Outcome | Should -Be 'built'
        $w.Built | Should -Match 'WITH \(ONLINE = ON\)$'
        $w2 = New-JobW -On $true
        $w2.Row.EstMinutes = $gap + 60
        $lg2 = $w2.Log
        $r2 = Invoke-SIIndexBuildJob -Store ([pscustomobject]@{ Invoke = { throw 'no database in this test' } }) -Holder 'caj-si-index-build:e3' -Request ([pscustomobject]@{ Table = 'sidata.Finding'; Index = 'NCCI_Finding_Load'; Minutes = $gap; Force = $false }) -Seams $w2.Seams -Log { param($m) $lg2.Add($m) }.GetNewClosure() -NowUtc $script:Now
        $r2.Outcome | Should -Be 'not-now'; $w2.Built | Should -BeNullOrEmpty
    }
    It 'a columnstore row that is not one of SI''s own is never built' {
        $w = New-JobW -On $true -Name 'NCCI_Other'
        $r = Invoke-JobW $w
        $r.Outcome | Should -Be 'failed'; $w.Built | Should -BeNullOrEmpty
    }
}

Describe 'REAL SQL: the load read and the columnstore path on a real database' -Skip:(-not $script:HasSql) {
    BeforeAll {
        $script:DbName = 'si_test_loadcs_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
        $m = New-Object System.Data.SqlClient.SqlConnection "Server=$($env:SI_TEST_LOCALSQL);Database=master;$($env:SI_TEST_SQL_AUTH);Connection Timeout=30"
        $m.Open(); try { $c = $m.CreateCommand(); $c.CommandText = "CREATE DATABASE [$script:DbName]"; $c.CommandTimeout = 300; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
        $cs = "Server=$($env:SI_TEST_LOCALSQL);Database=$script:DbName;$($env:SI_TEST_SQL_AUTH);Connection Timeout=30;Pooling=false"
        $script:Real = {
            param([string]$sql, $p, [string]$mode)
            $cn = New-Object System.Data.SqlClient.SqlConnection($cs)
            try {
                $cn.Open(); $cmd = $cn.CreateCommand(); $cmd.CommandText = $sql; $cmd.CommandTimeout = 300
                if ($p) { foreach ($k in @($p.Keys)) { $v = $p[$k]; [void]$cmd.Parameters.AddWithValue('@' + $k, $(if ($null -eq $v) { [DBNull]::Value } else { $v })) } }
                if ($mode -in @('reader', 'rows')) {
                    $rd = $cmd.ExecuteReader(); $out = New-Object System.Collections.Generic.List[object]
                    while ($rd.Read()) { $h = @{}; for ($i = 0; $i -lt $rd.FieldCount; $i++) { $h[$rd.GetName($i)] = $(if ($rd.IsDBNull($i)) { $null } else { $rd.GetValue($i) }) }; $out.Add($h) }
                    $rd.Close(); , $out.ToArray()
                } elseif ($mode -eq 'scalar') { $cmd.ExecuteScalar() } else { [void]$cmd.ExecuteNonQuery() }
            } finally { $cn.Dispose() }
        }.GetNewClosure()
        $real = $script:Real
        & $real 'CREATE SCHEMA sidata;' @{} 'nonquery'
        & $real 'CREATE SCHEMA cfg;' @{} 'nonquery'
        # the two tables with the columns the indexes take (types as sql\si-data-schema.sql has them)
        & $real @'
CREATE TABLE sidata.Finding (
    FindingId BIGINT IDENTITY(1, 1) NOT NULL, CollectionId INT NOT NULL, AssetKey NVARCHAR(400) NULL, AssetName NVARCHAR(400) NULL, ReportName NVARCHAR(256) NULL,
    SecurityDomain NVARCHAR(128) NULL, ConfigurationId NVARCHAR(256) NULL, Cve NVARCHAR(100) NULL, Title NVARCHAR(1000) NULL, Severity NVARCHAR(30) NULL, Tier TINYINT NULL,
    RiskScore FLOAT NULL, DetailJson NVARCHAR(MAX) NULL, RiskRating NVARCHAR(16) NULL, ExemptionId BIGINT NULL, HasExploit BIT NULL, DepartmentId INT NULL, Category NVARCHAR(256) NULL,
    Subcategory NVARCHAR(256) NULL, CiLifecycle NVARCHAR(16) NULL, EosStatus NVARCHAR(400) NULL, FixDueDate DATETIME2(3) NULL, SourceFirstDetected DATETIME2(3) NULL,
    CONSTRAINT PK_Finding PRIMARY KEY CLUSTERED (CollectionId, FindingId));
CREATE TABLE sidata.CiFindingState (
    OwnerKey NVARCHAR(450) NOT NULL, FindingKey NVARCHAR(256) NOT NULL, CiId NVARCHAR(64) NULL, State NVARCHAR(16) NOT NULL, FirstDetected DATETIME2(3) NOT NULL,
    LastSeen DATETIME2(3) NOT NULL, ClosedAt DATETIME2(3) NULL, CloseReason NVARCHAR(32) NULL, Severity NVARCHAR(16) NULL,
    CONSTRAINT PK_CiFindingState PRIMARY KEY (OwnerKey, FindingKey));
CREATE TABLE cfg.Setting (Name NVARCHAR(128) NOT NULL, Scope NVARCHAR(128) NOT NULL, ValueJson NVARCHAR(MAX) NULL, CONSTRAINT PK_Setting PRIMARY KEY (Name, Scope));
'@ @{} 'nonquery'
        # cfg.IndexBuild exactly as the settings schema creates it
        $pro = Get-Content -Raw (Join-Path $script:SIRoot 'sql\si-pro-settings.sql')
        $mx = [regex]::Match($pro, "(?s)IF OBJECT_ID\('cfg\.IndexBuild'\) IS NULL\s*CREATE TABLE cfg\.IndexBuild \(.*?\n\);")
        $mx.Success | Should -BeTrue
        & $real $mx.Value @{} 'nonquery'
        # a deterministic fixture: 3 collections x 400 findings over 37 assets, some exempted, mixed tiers / severities / scores
        & $real @'
SET NOCOUNT ON;
DECLARE @i int = 0;
WHILE @i < 1200
BEGIN
    INSERT sidata.Finding (CollectionId, AssetKey, AssetName, ReportName, SecurityDomain, ConfigurationId, Cve, Title, Severity, Tier, RiskScore, RiskRating, ExemptionId, HasExploit, CiLifecycle)
    VALUES (1 + @i / 400, N'ci-' + CONVERT(nvarchar(10), @i % 37), N'Asset ' + CONVERT(nvarchar(10), @i % 37), N'Report' + CONVERT(nvarchar(10), @i % 3), N'endpoint',
            N'CVE-2026-' + CONVERT(nvarchar(10), @i % 53), CASE WHEN @i % 5 = 0 THEN NULL ELSE N'CVE-2026-' + CONVERT(nvarchar(10), @i % 53) END, N'Title ' + CONVERT(nvarchar(10), @i % 53),
            CASE @i % 4 WHEN 0 THEN N'Critical' WHEN 1 THEN N'High' WHEN 2 THEN N'Medium' ELSE N'Low' END, @i % 3, (@i % 97) * 1.25, N'r' + CONVERT(nvarchar(4), @i % 6),
            CASE WHEN @i % 11 = 0 THEN 7 END, CASE WHEN @i % 2 = 0 THEN 1 ELSE 0 END, N'active');
    INSERT sidata.CiFindingState (OwnerKey, FindingKey, CiId, State, FirstDetected, LastSeen, ClosedAt, CloseReason, Severity)
    VALUES (N'ci-' + CONVERT(nvarchar(10), @i), N'CVE-2026-' + CONVERT(nvarchar(10), @i % 53), N'ci-' + CONVERT(nvarchar(10), @i % 37), CASE WHEN @i % 3 = 0 THEN N'closed' ELSE N'open' END,
            DATEADD(day, -(@i % 60), '2026-11-20'), '2026-11-20', CASE WHEN @i % 3 = 0 THEN DATEADD(day, -(@i % 20), '2026-11-20') END, CASE WHEN @i % 3 = 0 THEN N'remediated' END, N'High');
    SET @i += 1;
END
'@ @{} 'nonquery'
        # the changes phase's shape of read (per CI and collection: counts, sums, the lowest tier, distinct CVEs, exempted
        # counted apart) and the key figures' lifecycle counts -- run through the table's own index and through the columnstore
        $script:ChangesRead = @'
SELECT f.CollectionId, f.AssetKey, COUNT_BIG(*) AS N, SUM(f.RiskScore) AS Risk, MIN(f.Tier) AS Tier, COUNT(DISTINCT f.Cve) AS Cves,
       SUM(CASE WHEN f.ExemptionId IS NULL THEN 1 ELSE 0 END) AS Counted, MAX(f.Title) AS Title, MAX(f.RiskRating) AS Rating
FROM sidata.Finding AS f WITH (INDEX({0}))
GROUP BY f.CollectionId, f.AssetKey ORDER BY f.CollectionId, f.AssetKey
'@
        $script:StateRead = @'
SELECT COUNT_BIG(*) AS N, COUNT(DISTINCT s.CiId) AS Cis, AVG(CONVERT(float, DATEDIFF(hour, s.FirstDetected, s.ClosedAt)) / 24.0) AS Mttr
FROM sidata.CiFindingState AS s WITH (INDEX({0})) WHERE s.FindingKey LIKE N'CVE-%' AND s.ClosedAt > DATEADD(day, -30, '2026-11-20') AND s.CloseReason = N'remediated'
'@
        $script:Edition = [string](& $real "SELECT CONVERT(nvarchar(10), SERVERPROPERTY('EngineEdition'))" @{} 'scalar')
    }
    AfterAll {
        [System.Data.SqlClient.SqlConnection]::ClearAllPools()
        $m = New-Object System.Data.SqlClient.SqlConnection "Server=$($env:SI_TEST_LOCALSQL);Database=master;$($env:SI_TEST_SQL_AUTH);Connection Timeout=30"
        $m.Open(); try { $c = $m.CreateCommand(); $c.CommandTimeout = 300; $c.CommandText = "ALTER DATABASE [$script:DbName] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$script:DbName]"; [void]$c.ExecuteNonQuery() } catch { } finally { $m.Dispose() }
    }
    It '#1306 the load read runs and answers only K / Name / Hash / numbers; the largest tables first; it passes the agreed schema' {
        $null = & $script:Real "SELECT COUNT(*) FROM sidata.Finding WHERE Severity = N'High'" @{} 'scalar'
        $rows = @(& $script:Real (Get-SIHeartbeatDatabaseLoadSql) @{} 'rows' | ForEach-Object { $_ })
        $rows.Count | Should -BeGreaterThan 0
        foreach ($r in $rows) { @($r.Keys | Sort-Object) | Should -Be @('Hash', 'K', 'N1', 'N2', 'N3', 'Name') }
        @($rows | Where-Object { $_['K'] -eq 'denied' -and $_['Name'] -eq 'tables' }).Count | Should -Be 0 -Because 'the test login may read the partition stats'
        $l = ConvertFrom-SIHeartbeatDatabaseLoad -Rows $rows
        @($l.Tables | ForEach-Object { $_.name }) | Should -Contain 'sidata.Finding'
        $l.Tables[0].name | Should -BeIn @('sidata.Finding', 'sidata.CiFindingState')
        foreach ($q in @($l.Queries)) { $q.queryHash | Should -Match '^0x[0-9A-F]{16}$' }
        $base = Get-SIHeartbeatDatabase -Db $null -Space @{ sqlUsedMb = 10; sqlMaxMb = 100 }
        Test-SIHeartbeatField -Name 'Database' -Value (Add-SIHeartbeatDatabaseLoad -Database $base -Load $l) | Should -BeNullOrEmpty
    }
    It '#1306 a table someone else made (dbo / another schema), even the LARGEST one, never sends its name' {
        & $script:Real @'
SET NOCOUNT ON;
IF SCHEMA_ID('acme') IS NULL EXEC ('CREATE SCHEMA acme');
CREATE TABLE dbo.AcmeExport_2026 (Id int IDENTITY PRIMARY KEY, Pad char(4000) NOT NULL DEFAULT 'x');
CREATE TABLE acme.CustomerSecretList (Id int IDENTITY PRIMARY KEY, Pad char(4000) NOT NULL DEFAULT 'x');
DECLARE @i int = 0;
WHILE @i < 3000 BEGIN INSERT dbo.AcmeExport_2026 DEFAULT VALUES; INSERT acme.CustomerSecretList DEFAULT VALUES; SET @i += 1; END
'@ @{} 'nonquery'
        try {
            $rows = @(& $script:Real (Get-SIHeartbeatDatabaseLoadSql) @{} 'rows' | ForEach-Object { $_ })
            $names = @($rows | Where-Object { $_['K'] -eq 'table' } | ForEach-Object { [string]$_['Name'] })
            $names | Should -Contain 'sidata.Finding' -Because 'SI''s own tables still go'
            $names | Should -Not -Contain 'dbo.AcmeExport_2026'
            $names | Should -Not -Contain 'acme.CustomerSecretList'
            foreach ($n in $names) { ($n -split '\.')[0] | Should -BeIn @((Get-SIHeartbeatFieldsContract).DatabaseLoadSchemas) }
            (ConvertFrom-SIHeartbeatDatabaseLoad -Rows $rows | ConvertTo-Json -Depth 6 -Compress) | Should -Not -Match '(?i)Acme|CustomerSecret'
        } finally {
            & $script:Real 'DROP TABLE dbo.AcmeExport_2026; DROP TABLE acme.CustomerSecretList; DROP SCHEMA acme;' @{} 'nonquery'
        }
    }
    It '#1316 setting off: the updater''s step records nothing and builds nothing' {
        & $script:Real "INSERT cfg.Setting (Name, Scope, ValueJson) VALUES (N'SI_Data_ColumnstoreIndexes', N'solution', N'false')" @{} 'nonquery'
        $r = Invoke-SIColumnstoreIndexStep -Invoke $script:Real
        [int](& $script:Real 'SELECT COUNT(*) FROM cfg.IndexBuild' @{} 'scalar') | Should -Be 0
        [int](& $script:Real 'SELECT COUNT(*) FROM sys.indexes WHERE type = 6' @{} 'scalar') | Should -Be 0
    }
    It '#1316 setting not set (the default, on): two waiting rows with their statements and estimates; still no index until the index build job runs' {
        & $script:Real "DELETE FROM cfg.Setting WHERE Name = N'SI_Data_ColumnstoreIndexes'" @{} 'nonquery'
        $r = Invoke-SIColumnstoreIndexStep -Invoke $script:Real
        $rows = @(Read-SIIndexBuildRows -Invoke $script:Real)
        @($rows | ForEach-Object { $_.Name } | Sort-Object) | Should -Be @('NCCI_CiFindingState_Load', 'NCCI_Finding_Load')
        @($rows | ForEach-Object { $_.State } | Sort-Object -Unique) | Should -Be @('waiting')
        @($rows | Where-Object { $_.Statement -notmatch '^CREATE NONCLUSTERED COLUMNSTORE INDEX ' }).Count | Should -Be 0
        [int](& $script:Real 'SELECT COUNT(*) FROM sys.indexes WHERE type = 6' @{} 'scalar') | Should -Be 0 -Because 'only the index build job builds'
        # a second update records nothing new
        $r2 = Invoke-SIColumnstoreIndexStep -Invoke $script:Real
        @($r2.Plan | Where-Object { $_.Action -eq 'queue' }).Count | Should -Be 0
    }
    It '#1316 the index build job''s statement builds the index; a read through it answers row for row what the table''s own index answers' {
        $before = @(& $script:Real ($script:ChangesRead -f '1') @{} 'rows' | ForEach-Object { $_ })
        $beforeS = @(& $script:Real ($script:StateRead -f '1') @{} 'rows' | ForEach-Object { $_ })
        foreach ($row in @(Read-SIIndexBuildRows -Invoke $script:Real)) {
            $run = Get-SIIndexBuildRunSql -Row $row -Minutes 60
            $run.Resumable | Should -BeFalse
            # an Express / Standard engine refuses ONLINE index operations: the same statement without its WITH there
            $sql = if ($script:Edition -in @('3', '5', '8')) { $run.Sql } else { $row.Statement }
            & $script:Real $sql @{} 'nonquery'
            Save-SIIndexBuildRow -Invoke $script:Real -Table $row.Table -Index $row.Name -State 'built' -Why 'test' | Should -BeTrue
        }
        [int](& $script:Real 'SELECT COUNT(*) FROM sys.indexes WHERE type = 6' @{} 'scalar') | Should -Be 2
        $after = @(& $script:Real ($script:ChangesRead -f 'NCCI_Finding_Load') @{} 'rows' | ForEach-Object { $_ })
        $afterS = @(& $script:Real ($script:StateRead -f 'NCCI_CiFindingState_Load') @{} 'rows' | ForEach-Object { $_ })
        $before.Count | Should -Be 111
        $after.Count | Should -Be $before.Count
        for ($i = 0; $i -lt $before.Count; $i++) {
            foreach ($k in 'CollectionId', 'AssetKey', 'N', 'Risk', 'Tier', 'Cves', 'Counted', 'Title', 'Rating') { "$($after[$i][$k])" | Should -Be "$($before[$i][$k])" -Because "row $i column $k" }
        }
        foreach ($k in 'N', 'Cis') { "$($afterS[0][$k])" | Should -Be "$($beforeS[0][$k])" }
        # an average of fractions may be added up in another order by a batch-mode read: equal to the last 9 decimals
        [Math]::Round([double]$afterS[0]['Mttr'], 9) | Should -Be ([Math]::Round([double]$beforeS[0]['Mttr'], 9))
        [long]$beforeS[0]['N'] | Should -BeGreaterThan 0 -Because 'the fixture has fixed findings in the window'
        # the updater with the setting on and the index there: nothing to do
        @((Invoke-SIColumnstoreIndexStep -Invoke $script:Real).Plan | Where-Object { $_.Action -ne 'none' }).Count | Should -Be 0
    }
    It '#1316 the setting off again: the next update drops both indexes and removes their rows (the rollback)' {
        & $script:Real "INSERT cfg.Setting (Name, Scope, ValueJson) VALUES (N'SI_Data_ColumnstoreIndexes', N'solution', N'false')" @{} 'nonquery'
        $r = Invoke-SIColumnstoreIndexStep -Invoke $script:Real
        [int](& $script:Real 'SELECT COUNT(*) FROM sys.indexes WHERE type = 6' @{} 'scalar') | Should -Be 0
        [int](& $script:Real "SELECT COUNT(*) FROM cfg.IndexBuild WHERE IndexName LIKE N'NCCI[_]%'" @{} 'scalar') | Should -Be 0
        [int](& $script:Real 'SELECT COUNT(*) FROM sys.indexes WHERE name = N''PK_Finding''' @{} 'scalar') | Should -Be 1 -Because 'only its own indexes are dropped'
    }
}
