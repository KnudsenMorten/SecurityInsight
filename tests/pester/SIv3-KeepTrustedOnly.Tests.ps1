#Requires -Version 7.0
<#
    ONLY TRUSTED COLLECTIONS COUNT TOWARD THE KEPT ONES (REQUIREMENTS #1226; owner 2026-11-13: "we cannot loose a single row of
    data" / "quality and stability is focus"). A complete collection whose OWN verdict (sidata.CollectionTrust, written by Risk
    Analysis) says it was built on incomplete source data must never push a trusted collection out of the newest N.

    What these tests keep true (engine\_shared\data-sql\SI-DataSql.ps1: Get-SIDataRetentionStateSql,
    Get-SIDataCollectionRetentionPlan, Get-SIDataRetireMarkSql, Get-SIDataRetireTrustSql):
      * the newest N TRUSTED complete collections are kept, however many untrusted ones are newer;
      * an untrusted complete collection older than the newest trusted one is removed ('untrusted');
      * AT MOST ONE untrusted collection is kept: the newest, when it is newer than the newest trusted one (diagnosis, and what
        the next run carries from; never shown, never sent) -- plus one a kept collection carries rows from, by name;
      * NEGATIVE: never the published run (also when untrusted), never a collection a kept one carries rows from;
      * fall-back: a grain with NO trusted complete collection keeps the old rule (the newest N complete ones);
      * no verdict = trusted (a collection from before the verdict existed); no CollectionTrust table = the old rule;
      * the database's own guard refuses a trusted collection unless 2 newer TRUSTED complete ones exist, and an untrusted one
        unless a newer complete one exists; a mark 'untrusted' is removed like 'superseded' while a run goes.
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
    $script:Schema = Get-Content -Raw -LiteralPath (Join-Path $script:Root 'sql\si-data-schema.sql')
    $script:Quiet = { param($l, $m) }
    function script:T([int]$Day, [int]$Hour = 8) { [datetime]::SpecifyKind((Get-Date -Year 2026 -Month 11 -Day $Day -Hour $Hour -Minute 0 -Second 0 -Millisecond 0), 'Utc') }
    function script:Row([string]$Grain, $Id, [datetime]$Time, [string]$Status, [switch]$Published, [switch]$Untrusted) {
        @{ Grain = $Grain; CollectionId = $Id; CollectionTime = $Time; Status = $Status; RetiredAt = [System.DBNull]::Value; HasRows = 0
           Published = $(if ($Published) { 1 } else { 0 }); Untrusted = $(if ($Untrusted) { 1 } else { 0 }) }
    }
    function script:Plan($Rows, [int]$Keep = 3, $Links = @()) { Get-SIDataCollectionRetentionPlan -Collections $Rows -CarryLinks $Links -NowUtc (T 20) -StaleDays 0 -KeepCollections $Keep }
    function script:ActOf($Plan, $Id) { $m = @($Plan | Where-Object { $_.Grain -eq 'Detailed' -and $_.CollectionId -eq $Id }); if ($m.Count) { $m[0].Action } else { '(none)' } }
    function script:WhyOf($Plan, $Id) { @($Plan | Where-Object { $_.Grain -eq 'Detailed' -and $_.CollectionId -eq $Id })[0].Why }
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

Describe 'the plan: only trusted collections count' {
    It 'untrusted newer collections never push a trusted one out of the newest 3' {
        # 1..5 trusted, 6 and 7 untrusted (newer): the newest 3 trusted are 3, 4, 5 -- 1 and 2 go
        $rows = @(1..5 | ForEach-Object { Row Detailed $_ (T $_) Complete }) + @(6, 7 | ForEach-Object { Row Detailed $_ (T $_) Complete -Untrusted })
        $p = Plan $rows
        foreach ($id in 3, 4, 5) { ActOf $p $id | Should -Be 'Keep' -Because "collection $id is one of the newest 3 trusted" }
        foreach ($id in 1, 2) { ActOf $p $id | Should -Be 'Retire'; WhyOf $p $id | Should -Be 'superseded' }
        ActOf $p 7 | Should -Be 'Keep' -Because 'the newest untrusted one is kept for diagnosis and for what the next run carries from'
        ActOf $p 6 | Should -Be 'Retire' -Because 'at most ONE untrusted collection is kept'
        WhyOf $p 6 | Should -Be 'untrusted'
    }
    It 'three untrusted newer than the trusted one: ONE kept (Invardia 2026-11-13)' {
        $rows = @(1..3 | ForEach-Object { Row Detailed $_ (T $_) Complete }) + @(4..6 | ForEach-Object { Row Detailed $_ (T $_) Complete -Untrusted })
        $p = Plan $rows
        @($p | Where-Object { $_.Action -eq 'Keep' -and $_.CollectionId -ge 4 } | ForEach-Object { $_.CollectionId }) | Should -Be @(6)
        foreach ($id in 4, 5) { ActOf $p $id | Should -Be 'Retire'; WhyOf $p $id | Should -Be 'untrusted' }
        @($p | Where-Object { $_.CollectionId -eq 4 })[0].Reason | Should -Be 'built on incomplete source data, and a newer collection like it is the one kept'
        foreach ($id in 1, 2, 3) { ActOf $p $id | Should -Be 'Keep' }
    }
    It 'an untrusted collection older than the newest trusted one is removed as untrusted' {
        $rows = @((Row Detailed 1 (T 1) Complete), (Row Detailed 2 (T 2) Complete -Untrusted), (Row Detailed 3 (T 3) Complete), (Row Detailed 4 (T 4) Complete))
        $p = Plan $rows
        ActOf $p 2 | Should -Be 'Retire'; WhyOf $p 2 | Should -Be 'untrusted'
        @($p | Where-Object { $_.CollectionId -eq 2 })[0].Reason | Should -Match 'built on incomplete source data; the newer trusted collection of 2026-11-04 08:00 UTC replaces it'
        foreach ($id in 1, 3, 4) { ActOf $p $id | Should -Be 'Keep' -Because 'the untrusted one never counted: 1, 3, 4 are the newest 3 trusted' }
    }
    It 'six untrusted after one trusted: the trusted one and the newest untrusted one are kept, never more' {
        $rows = @((Row Detailed 1 (T 1) Complete)) + @(2..7 | ForEach-Object { Row Detailed $_ (T $_) Complete -Untrusted })
        $p = Plan $rows
        ActOf $p 1 | Should -Be 'Keep'
        ActOf $p 7 | Should -Be 'Keep'
        foreach ($id in 2..6) { ActOf $p $id | Should -Be 'Retire'; WhyOf $p $id | Should -Be 'untrusted' }
    }
    It 'an untrusted collection the kept one carries rows from is kept by name, not by a count' {
        $rows = @((Row Detailed 1 (T 1) Complete)) + @(2..4 | ForEach-Object { Row Detailed $_ (T $_) Complete -Untrusted })
        $p = Plan $rows 3 @(@{ CollectionId = 4; FromCollectionId = 2 })
        foreach ($id in 1, 2, 4) { ActOf $p $id | Should -Be 'Keep' }
        ActOf $p 3 | Should -Be 'Retire'
    }
    It 'the reason of an untrusted removal carries the run''s own verdict when it is known' {
        $rows = @((Row Detailed 1 (T 1) Complete -Untrusted)) + @(2..4 | ForEach-Object { Row Detailed $_ (T $_) Complete })
        $rows[0]['UntrustedWhy'] = 'the device collection failed'
        $p = Plan $rows
        @($p | Where-Object { $_.CollectionId -eq 1 })[0].Reason | Should -Be 'built on incomplete source data; the newer trusted collection of 2026-11-04 08:00 UTC replaces it; its run''s own verdict: the device collection failed'
    }
    It 'NEGATIVE: the published run is kept, also when it is untrusted' {
        $rows = @((Row Detailed 1 (T 1) Complete -Untrusted -Published)) + @(2..5 | ForEach-Object { Row Detailed $_ (T $_) Complete })
        $p = Plan $rows
        ActOf $p 1 | Should -Be 'Keep'
    }
    It 'NEGATIVE: an untrusted collection a kept one carries rows from is kept' {
        $rows = @((Row Detailed 1 (T 1) Complete -Untrusted)) + @(2..4 | ForEach-Object { Row Detailed $_ (T $_) Complete })
        $p = Plan $rows 3 @(@{ CollectionId = 4; FromCollectionId = 1 })
        ActOf $p 1 | Should -Be 'Keep'
    }
    It 'fall-back: no trusted complete collection at all -- the old rule over every complete one' {
        $rows = @(1..5 | ForEach-Object { Row Detailed $_ (T $_) Complete -Untrusted })
        $p = Plan $rows
        foreach ($id in 3, 4, 5) { ActOf $p $id | Should -Be 'Keep' }
        foreach ($id in 1, 2) { ActOf $p $id | Should -Be 'Retire'; WhyOf $p $id | Should -Be 'superseded' }
    }
    It 'no verdict = trusted: rows without the Untrusted field plan exactly as before' {
        $rows = @(1..5 | ForEach-Object { $r = Row Detailed $_ (T $_) Complete; $r.Remove('Untrusted'); $r })
        $p = Plan $rows
        foreach ($id in 3, 4, 5) { ActOf $p $id | Should -Be 'Keep' }
        foreach ($id in 1, 2) { ActOf $p $id | Should -Be 'Retire'; WhyOf $p $id | Should -Be 'superseded' }
    }
    It 'Summary follows the same rule' {
        $rows = @(1..4 | ForEach-Object { Row Summary $null (T $_) Complete }) + @(Row Summary $null (T 5) Complete -Untrusted)
        $p = Plan $rows
        @($p | Where-Object { $_.Grain -eq 'Summary' -and $_.CollectionTime -eq (T 1) })[0].Action | Should -Be 'Retire'
        foreach ($d in 2, 3, 4, 5) { @($p | Where-Object { $_.Grain -eq 'Summary' -and $_.CollectionTime -eq (T $d) })[0].Action | Should -Be 'Keep' }
    }
    It 'a mark ''untrusted'' is removed while a run goes, like ''superseded'' (the database checks the same reasons)' {
        $def = (Get-Command Invoke-SIDataCollectionRetention).Definition
        $def | Should -Match ([regex]::Escape("-notin 'superseded', 'abandoned', 'stopped run', 'untrusted'"))
        (Get-SIDataRetireMarkSql -Grain Detailed) | Should -Match 'sidata\.CollectionTrust'
        (Get-SIDataRetireMarkSql -Grain Summary) | Should -Match ([regex]::Escape("Grain = N''Summary'' AND Trusted = 0"))
        # every while-a-run-goes removal statement carries the same reasons (the batches, the ranges and the mark expression)
        $src = Get-Content -Raw -LiteralPath (Join-Path $script:Root 'engine\_shared\data-sql\SI-DataSql.ps1')
        [regex]::Matches($src, [regex]::Escape("N'superseded', N'abandoned', N'stopped run', N'untrusted'")).Count | Should -Be 3
        [regex]::Matches($src, [regex]::Escape("N'superseded', N'abandoned', N'stopped run')")).Count | Should -Be 0 -Because 'no statement is left on the old list'
    }
}

Describe 'on a real SQL Server: the state read, the plan and the database guard' {
    It 'reads each collection''s own verdict, keeps the newest 3 trusted, removes the older untrusted one; the guard refuses what the rule keeps' -Skip:(-not $script:LocalSql) {
        $db = 'sitrust_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
        $master = New-LocalInvoke 'master'
        [void](& $master "CREATE DATABASE [$db]" @{} 'nonquery')
        try {
            $inv = New-LocalInvoke $db
            [void](& $inv $script:Schema @{} 'nonquery')
            [void](& $inv (Get-SIDataRetiredColumnsSql) @{} 'scalar')
            # 1..6 complete; 2 and 6 untrusted; 1, 3, 4, 5 trusted (5 has an explicit trusted verdict, the rest none)
            foreach ($d in 1..6) {
                [void](& $inv ("SET IDENTITY_INSERT sidata.Collection ON; INSERT sidata.Collection (CollectionId, CollectionTime, Kind, Status, ViewsReadyAt, DerivedAt, ContextAt) VALUES ({0}, '2026-11-{0:00}T08:00:00', 'Detailed', 'Complete', SYSUTCDATETIME(), SYSUTCDATETIME(), SYSUTCDATETIME()); SET IDENTITY_INSERT sidata.Collection OFF;" -f $d) @{} 'nonquery')
                foreach ($i in 1..2) { [void](& $inv ("INSERT sidata.Finding (CollectionId, AssetKey, ReportName, Severity, Tier, RiskScore) VALUES ({0}, N'a{1}', N'R', N'High', 1, 5)" -f $d, $i) @{} 'nonquery') }
            }
            [void](& $inv "INSERT sidata.CollectionTrust (CollectionTime, Grain, Trusted, Why) VALUES ('2026-11-02T08:00:00', N'Detailed', 0, N'identity collection failed'), ('2026-11-06T08:00:00', N'Detailed', 0, N'device collection failed'), ('2026-11-05T08:00:00', N'Detailed', 1, NULL)" @{} 'nonquery')
            $cnt = { param($q) [int](& $inv $q @{} 'scalar') }

            $state = @(@(& $inv (Get-SIDataRetentionStateSql) @{} 'reader') | ForEach-Object { $_ })
            @($state | Where-Object { [int]$_['Untrusted'] -eq 1 } | ForEach-Object { [int]$_['CollectionId'] } | Sort-Object) | Should -Be @(2, 6)

            # NEGATIVE first, by the database itself: trusted 3 has only 2 newer complete TRUSTED ones (4, 5) -- accepted;
            # trusted 4 has only 1 newer trusted (5), though 2 newer complete (5, 6) -- refused
            (& $inv (Get-SIDataRetireMarkSql -Grain Detailed) @{ CollectionId = '4'; CollectionTime = ''; Why = 'test'; StaleBefore = '' } 'scalar') | Should -Be 0 -Because 'the untrusted 6 never counts toward the kept ones'
            # untrusted 6 has no newer collection at all -- refused
            (& $inv (Get-SIDataRetireMarkSql -Grain Detailed) @{ CollectionId = '6'; CollectionTime = ''; Why = 'test'; StaleBefore = '' } 'scalar') | Should -Be 0

            $r = Invoke-SIDataCollectionRetention -Invoke $inv -KeepCollections 3 -BatchSize 2 -Log $script:Quiet
            $r.Status | Should -Be 'ok'
            @($r.Removed | ForEach-Object { [int]$_.CollectionId } | Sort-Object) | Should -Be @(1, 2)
            & $cnt "SELECT COUNT(*) FROM sidata.Collection WHERE CollectionId = 2 AND RetiredWhy = N'untrusted'" | Should -Be 1
            & $cnt "SELECT COUNT(*) FROM sidata.Collection WHERE CollectionId = 1 AND RetiredWhy = N'superseded'" | Should -Be 1
            & $cnt 'SELECT COUNT(*) FROM sidata.Finding WHERE CollectionId IN (1, 2)' | Should -Be 0
            & $cnt 'SELECT COUNT(*) FROM sidata.Finding WHERE CollectionId IN (3, 4, 5, 6)' | Should -Be 8 -Because 'the newest 3 trusted and the newer untrusted one keep every row'
            # IDEMPOTENT
            @((Invoke-SIDataCollectionRetention -Invoke $inv -KeepCollections 3 -Log $script:Quiet).Removed).Count | Should -Be 0

            # a newer TRUSTED collection arrives: the untrusted 6 is now older than it -- removed; 3 goes as superseded
            [void](& $inv "SET IDENTITY_INSERT sidata.Collection ON; INSERT sidata.Collection (CollectionId, CollectionTime, Kind, Status, ViewsReadyAt, DerivedAt, ContextAt) VALUES (7, '2026-11-07T08:00:00', 'Detailed', 'Complete', SYSUTCDATETIME(), SYSUTCDATETIME(), SYSUTCDATETIME()); SET IDENTITY_INSERT sidata.Collection OFF;" @{} 'nonquery')
            $r2 = Invoke-SIDataCollectionRetention -Invoke $inv -KeepCollections 3 -Log $script:Quiet
            @($r2.Removed | ForEach-Object { [int]$_.CollectionId } | Sort-Object) | Should -Be @(3, 6)
            & $cnt "SELECT COUNT(*) FROM sidata.Collection WHERE CollectionId = 6 AND RetiredWhy = N'untrusted'" | Should -Be 1
            & $cnt 'SELECT COUNT(*) FROM sidata.Collection WHERE RetiredAt IS NULL' | Should -Be 3
        } finally {
            try { [void](& $master "ALTER DATABASE [$db] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$db]" @{} 'nonquery') } catch { }
        }
    }
    It 'an UNTRUSTED PUBLISHED run stays (the published guard wins); a removed untrusted one is said with its own verdict' -Skip:(-not $script:LocalSql) {
        $db = 'sitrust_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
        $master = New-LocalInvoke 'master'
        [void](& $master "CREATE DATABASE [$db]" @{} 'nonquery')
        try {
            $inv = New-LocalInvoke $db
            [void](& $inv $script:Schema @{} 'nonquery')
            [void](& $inv (Get-SIDataRetiredColumnsSql) @{} 'scalar')
            # 1 untrusted + PUBLISHED, 2 untrusted, 3..5 trusted (no verdict)
            foreach ($d in 1..5) {
                [void](& $inv ("SET IDENTITY_INSERT sidata.Collection ON; INSERT sidata.Collection (CollectionId, CollectionTime, Kind, Status, ViewsReadyAt, DerivedAt, ContextAt) VALUES ({0}, '2026-11-{0:00}T08:00:00', 'Detailed', 'Complete', SYSUTCDATETIME(), SYSUTCDATETIME(), SYSUTCDATETIME()); SET IDENTITY_INSERT sidata.Collection OFF;" -f $d) @{} 'nonquery')
                [void](& $inv ("INSERT sidata.Finding (CollectionId, AssetKey, ReportName, Severity, Tier, RiskScore) VALUES ({0}, N'a1', N'R', N'High', 1, 5)" -f $d) @{} 'nonquery')
            }
            [void](& $inv "INSERT sidata.CollectionTrust (CollectionTime, Grain, Trusted, Why) VALUES ('2026-11-01T08:00:00', N'Detailed', 0, N'the public IP collection failed'), ('2026-11-02T08:00:00', N'Detailed', 0, N'the identity collection failed'); INSERT sidata.PublishedRun (Name, DetailedCollectionId, DetailedCollectionTime, Source) VALUES (N'current', 1, '2026-11-01T08:00:00', N'run');" @{} 'nonquery')
            $cnt = { param($q) [int](& $inv $q @{} 'scalar') }
            # the database itself refuses the published one, whatever the caller asks
            (& $inv (Get-SIDataRetireMarkSql -Grain Detailed) @{ CollectionId = '1'; CollectionTime = ''; Why = 'untrusted'; StaleBefore = '' } 'scalar') | Should -Be 0
            $lines = New-Object System.Collections.Generic.List[string]
            $log = { param($l, $m) $lines.Add([string]$m) }.GetNewClosure()
            $r = Invoke-SIDataCollectionRetention -Invoke $inv -KeepCollections 3 -Log $log
            $r.Status | Should -Be 'ok'
            @($r.Removed | ForEach-Object { [int]$_.CollectionId }) | Should -Be @(2)
            & $cnt 'SELECT COUNT(*) FROM sidata.Collection WHERE CollectionId = 1 AND RetiredAt IS NULL' | Should -Be 1 -Because 'the published run stays, also when untrusted'
            & $cnt 'SELECT COUNT(*) FROM sidata.Finding WHERE CollectionId = 1' | Should -Be 1
            @($lines | Where-Object { $_ -match '^collections : collection 2 \(Detailed, 2026-11-02T08:00:00\.000\) marked removed as untrusted -- built on incomplete source data; the newer trusted collection of 2026-11-05 08:00 UTC replaces it; its run''s own verdict: the identity collection failed$' }).Count | Should -Be 1 -Because ($lines -join ' | ')
        } finally {
            try { [void](& $master "ALTER DATABASE [$db] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$db]" @{} 'nonquery') } catch { }
        }
    }
    It 'a database without CollectionTrust plans and marks exactly as before' -Skip:(-not $script:LocalSql) {
        $db = 'sitrust_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
        $master = New-LocalInvoke 'master'
        [void](& $master "CREATE DATABASE [$db]" @{} 'nonquery')
        try {
            $inv = New-LocalInvoke $db
            [void](& $inv $script:Schema @{} 'nonquery')
            [void](& $inv (Get-SIDataRetiredColumnsSql) @{} 'scalar')
            [void](& $inv 'DROP TABLE sidata.CollectionTrust' @{} 'nonquery')
            foreach ($d in 1..4) { [void](& $inv ("SET IDENTITY_INSERT sidata.Collection ON; INSERT sidata.Collection (CollectionId, CollectionTime, Kind, Status, ViewsReadyAt, DerivedAt, ContextAt) VALUES ({0}, '2026-11-{0:00}T08:00:00', 'Detailed', 'Complete', SYSUTCDATETIME(), SYSUTCDATETIME(), SYSUTCDATETIME()); SET IDENTITY_INSERT sidata.Collection OFF;" -f $d) @{} 'nonquery') }
            @(@(& $inv (Get-SIDataRetentionStateSql) @{} 'reader') | ForEach-Object { $_ } | Where-Object { [int]$_['Untrusted'] -eq 1 }).Count | Should -Be 0
            $r = Invoke-SIDataCollectionRetention -Invoke $inv -KeepCollections 3 -Log $script:Quiet
            @($r.Removed | ForEach-Object { [int]$_.CollectionId }) | Should -Be @(1)
        } finally {
            try { [void](& $master "ALTER DATABASE [$db] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$db]" @{} 'nonquery') } catch { }
        }
    }
}
