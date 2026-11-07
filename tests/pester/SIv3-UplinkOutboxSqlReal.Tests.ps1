#Requires -Version 5.1
<#
    framework 8.4 -- THE UPLINK OUTBOX ON REAL SQL (the test VM's SQL Server Express): the shipped cfg.UplinkOutbox blocks of
    sql\si-pro-settings.sql (twice: idempotent), the shipped engine grants (Get-SIEngineGrantSql), and every statement of
    engine\_shared\SI-UplinkOutbox.ps1 run AS an engine user that has ONLY the role si_engine:
      * the job-end insert keeps the record exactly, one attempt, the answer;
      * THE BOUND: rows older than 7 days go, the oldest rows beyond the row cap go, and the drops are COUNTED in
        cfg.InstallState 'UplinkOutbox';
      * the tick: the lease, oldest first, a taken record DELETED, the first refusal stops and keeps the record (its attempt
        and answer), the lease released, the drops said once; a lease held by another execution = busy;
      * the backlog read: pending + the oldest time; caught up = 0 / null.
#>

BeforeDiscovery {
    $script:HasSql = [bool]((Get-Command sqlcmd -ErrorAction SilentlyContinue) -and (Get-Service -Name 'MSSQL$SQLEXPRESS' -ErrorAction SilentlyContinue | Where-Object Status -eq 'Running'))
}

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\_shared\SI-UplinkOutbox.ps1')
    . (Join-Path $script:SIRoot 'engine\pro-settings\SI-EngineGrants.ps1')
    $script:Now = [datetime]::SpecifyKind([datetime]'2026-11-05T10:00:00', [DateTimeKind]::Utc)
    function script:Master([string]$Sql) {
        $m = New-Object System.Data.SqlClient.SqlConnection 'Server=.\SQLEXPRESS;Database=master;Integrated Security=SSPI;Connection Timeout=30'
        $m.Open(); try { $c = $m.CreateCommand(); $c.CommandText = $Sql; $c.CommandTimeout = 300; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
    }
    # the Pro store's own seam shape: (sql, params, mode) -> 'reader' = ONE array of hashtables; typed parameters
    function script:NewInvoke($Cn) {
        $global:SIPesterObCn = $Cn
        {
            param($Sql, $Params, $Mode)
            $c = $global:SIPesterObCn.CreateCommand(); $c.CommandText = $Sql; $c.CommandTimeout = 120
            if ($Params) { foreach ($k in $Params.Keys) { [void]$c.Parameters.AddWithValue('@' + $k, $(if ($null -eq $Params[$k]) { [System.DBNull]::Value } else { $Params[$k] })) } }
            switch ($Mode) {
                'reader' {
                    $rd = $c.ExecuteReader(); $out = New-Object System.Collections.Generic.List[object]
                    try { do { if ($rd.FieldCount -gt 0) { while ($rd.Read()) { $h = @{}; for ($i = 0; $i -lt $rd.FieldCount; $i++) { $h[$rd.GetName($i)] = $(if ($rd.IsDBNull($i)) { $null } else { $rd.GetValue($i) }) }; $out.Add($h) } } } while ($rd.NextResult()) } finally { $rd.Close() }
                    , $out.ToArray()
                }
                'scalar' { $c.ExecuteScalar() }
                default { [void]$c.ExecuteNonQuery() }
            }
        }
    }
    function script:Blocks {
        $sql = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'sql\si-pro-settings.sql'))
        $is = [regex]::Match($sql, "(?s)IF OBJECT_ID\('cfg\.InstallState'\) IS NULL\r?\nCREATE TABLE cfg\.InstallState \(.*?\r?\n\);").Value
        $tb = [regex]::Match($sql, "(?s)IF OBJECT_ID\('cfg\.UplinkOutbox'\) IS NULL\r?\nCREATE TABLE cfg\.UplinkOutbox \(.*?\r?\n\);").Value
        $ix = [regex]::Match($sql, "(?s)IF NOT EXISTS \(SELECT 1 FROM sys\.indexes WHERE name = 'IX_UplinkOutbox_Created'.*?;").Value
        @($is, $tb, $ix)
    }
}

Describe 'REAL SQL: the uplink outbox (framework 8.4)' -Skip:(-not $script:HasSql) {
    BeforeAll {
        $tag = [guid]::NewGuid().ToString('N').Substring(0, 8)
        $script:DbName = 'si_test_outbox_' + $tag
        Master "CREATE DATABASE [$($script:DbName)]"
        $script:Cn = New-Object System.Data.SqlClient.SqlConnection ("Server=.\SQLEXPRESS;Database=$($script:DbName);Integrated Security=SSPI;Connection Timeout=30;Pooling=false")
        $script:Cn.Open()
        $script:A = NewInvoke $script:Cn
        & $script:A 'CREATE SCHEMA cfg;' @{} 'nonquery'
        $script:B = Blocks
        foreach ($i in 1, 2) { foreach ($b in $script:B) { if (-not $b) { throw 'a shipped block was not found in sql\si-pro-settings.sql' }; & $script:A $b @{} 'nonquery' } }
        & $script:A 'CREATE USER si_t_engine WITHOUT LOGIN;' @{} 'nonquery'
        & $script:A (Get-SIEngineGrantSql -UserName 'si_t_engine') @{} 'nonquery'
        # every statement of the module as the engine user (only si_engine)
        $script:Eng = {
            param($Sql, $Params, $Mode)
            & $script:A "EXECUTE AS USER = N'si_t_engine';" @{} 'nonquery'
            try { & $script:A $Sql $Params $Mode } finally { & $script:A 'REVERT;' @{} 'nonquery' }
        }
        $script:Rows = { @(& $script:A 'SELECT OutboxId, Job, Kind, RecordJson, CreatedUtc, Attempts, LastAttemptUtc, LastAnswer FROM cfg.UplinkOutbox ORDER BY CreatedUtc, OutboxId;' @{} 'reader' | ForEach-Object { $_ }) }
        $script:State = { $v = & $script:A "SELECT Value FROM cfg.InstallState WHERE Name = N'UplinkOutbox';" @{} 'scalar'; if ($v -is [DBNull] -or $null -eq $v) { $null } else { $v | ConvertFrom-Json } }
        $script:Clear = { & $script:A "DELETE FROM cfg.UplinkOutbox; DELETE FROM cfg.InstallState WHERE Name = N'UplinkOutbox';" @{} 'nonquery' }
    }
    AfterAll {
        if ($script:Cn) { $script:Cn.Dispose() }
        try { Master "ALTER DATABASE [$($script:DbName)] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$($script:DbName)];" } catch { }
        $global:SIPesterObCn = $null
    }
    BeforeEach { & $script:Clear }

    It 'the shipped schema applies twice (idempotent) and the engine user holds exactly its four rights on the table' {
        [int](& $script:A "SELECT COUNT(*) FROM sys.indexes WHERE name = 'IX_UplinkOutbox_Created' AND object_id = OBJECT_ID('cfg.UplinkOutbox');" @{} 'scalar') | Should -Be 1
        $p = @(& $script:A "EXECUTE AS USER = N'si_t_engine'; SELECT permission_name FROM fn_my_permissions('cfg.UplinkOutbox', 'OBJECT') WHERE subentity_name = N'' ORDER BY permission_name; REVERT;" @{} 'reader' | ForEach-Object { $_ } | ForEach-Object { $_.permission_name })
        ($p -join ',') | Should -Be 'DELETE,INSERT,SELECT,UPDATE'
    }
    It 'JOB END: the record kept exactly, one attempt, the answer' {
        $json = '{"Schema":2,"Kind":"run","Job":"si-endpoint","Outcome":"failed","At":"2026-11-05T09:30:00Z"}'
        Add-SIUplinkOutboxRecord -Invoke $script:Eng -Job 'si-endpoint' -Json $json -Answer 'uplink POST failed: 429 (Too Many Requests)' -NowUtc $script:Now | Should -BeTrue
        $r = @(& $script:Rows)
        $r.Count | Should -Be 1
        $r[0].Job | Should -Be 'si-endpoint'; $r[0].Kind | Should -Be 'run'; $r[0].RecordJson | Should -Be $json; $r[0].Attempts | Should -Be 1
        $r[0].LastAnswer | Should -Match '429'
        ([datetime]$r[0].CreatedUtc) | Should -Be $script:Now
    }
    It 'THE BOUND: older than 7 days go, the oldest beyond the row cap go -- COUNTED in cfg.InstallState' {
        foreach ($d in 9, 8) { Add-SIUplinkOutboxRecord -Invoke $script:Eng -Job 'si-azure' -Json '{"Kind":"run"}' -Answer 'x' -NowUtc $script:Now.AddDays(-$d) | Should -BeTrue }
        @(& $script:Rows).Count | Should -Be 2 -Because 'the bound runs at each insert''s own time: a day apart, neither is older than 7 days then'
        Add-SIUplinkOutboxRecord -Invoke $script:Eng -Job 'si-endpoint' -Json '{"Kind":"run"}' -Answer 'x' -NowUtc $script:Now | Should -BeTrue
        $r = @(& $script:Rows)
        $r.Count | Should -Be 1; $r[0].Job | Should -Be 'si-endpoint'
        (& $script:State).dropped | Should -Be 2
        # the row cap (5,000 shipped -- 4 here, the same statement): the oldest go first
        $keep = $script:SIUplinkOutbox.MaxRows
        try {
            $script:SIUplinkOutbox.MaxRows = 4
            foreach ($i in 1..5) { $null = Add-SIUplinkOutboxRecord -Invoke $script:Eng -Job ('si-j' + $i) -Json '{"Kind":"run"}' -Answer 'x' -NowUtc $script:Now.AddMinutes($i) }
        } finally { $script:SIUplinkOutbox.MaxRows = $keep }
        $r = @(& $script:Rows)
        $r.Count | Should -Be 4
        @($r | ForEach-Object { $_.Job }) | Should -Be @('si-j2', 'si-j3', 'si-j4', 'si-j5')
        (& $script:State).dropped | Should -Be 4
    }
    It 'THE TICK: oldest first, a taken record deleted, the first refusal stops and keeps it, the lease released, the drops said once' {
        foreach ($i in 1..4) { $null = Add-SIUplinkOutboxRecord -Invoke $script:Eng -Job 'si-endpoint' -Json ('{{"Kind":"run","Seq":{0}}}' -f $i) -Answer 'x' -NowUtc $script:Now.AddMinutes(-60 + $i) }
        # one drop to say
        & $script:A "INSERT cfg.InstallState (Name, Value, UpdatedBy) VALUES (N'UplinkOutbox', N'{""dropped"":3,""said"":1}', N'pester');" @{} 'nonquery'
        $seen = New-Object System.Collections.Generic.List[long]
        $send = { param($Record) $seen.Add([long]$Record.Seq); if ($seen.Count -eq 3) { return [pscustomobject]@{ Status = 'failed'; Reason = 'uplink POST failed: 429 (Too Many Requests)' } }; [pscustomobject]@{ Status = 'ok' } }.GetNewClosure()
        $t = Invoke-SIUplinkOutboxTick -Invoke $script:Eng -HeartbeatStatus 'sent' -Send $send -Now $script:Now -Sleep { param($s) }
        $t.Status | Should -Be 'stopped'; $t.Sent | Should -Be 2; $t.Left | Should -Be 2; $t.Dropped | Should -Be 2
        @($seen) | Should -Be @(1, 2, 3)
        $r = @(& $script:Rows)
        $r.Count | Should -Be 2
        ($r[0].RecordJson | ConvertFrom-Json).Seq | Should -Be 3
        $r[0].Attempts | Should -Be 2; $r[0].LastAnswer | Should -Match '429'
        $r[1].Attempts | Should -Be 1
        $st = & $script:State
        $st.said | Should -Be 3
        $st.PSObject.Properties['drainUntilUtc'] | Should -BeNullOrEmpty -Because 'the lease is released at the end'
        $t2 = Invoke-SIUplinkOutboxTick -Invoke $script:Eng -HeartbeatStatus 'sent' -Send { param($Record) [pscustomobject]@{ Status = 'ok' } } -Now $script:Now -Sleep { param($s) }
        $t2.Status | Should -Be 'drained'; $t2.Sent | Should -Be 2; $t2.Left | Should -Be 0
        @($t2.Lines | Where-Object { $_ -match 'dropped' }).Count | Should -Be 0 -Because 'said once'
        @(& $script:Rows).Count | Should -Be 0
    }
    It 'ONE drain at a time: a lease held by another execution = busy and left as it is; a lease that ran out is taken' {
        $null = Add-SIUplinkOutboxRecord -Invoke $script:Eng -Job 'si-endpoint' -Json '{"Kind":"run"}' -Answer 'x' -NowUtc $script:Now
        & $script:A "INSERT cfg.InstallState (Name, Value, UpdatedBy) VALUES (N'UplinkOutbox', N'{""dropped"":0,""said"":0,""drainUntilUtc"":""2026-11-05T10:10:00Z""}', N'pester');" @{} 'nonquery'
        (Invoke-SIUplinkOutboxTick -Invoke $script:Eng -HeartbeatStatus 'sent' -Send { param($Record) throw 'must not send' } -Now $script:Now).Status | Should -Be 'busy'
        [string](& $script:A "SELECT Value FROM cfg.InstallState WHERE Name = N'UplinkOutbox';" @{} 'scalar') | Should -Match '"drainUntilUtc":"2026-11-05T10:10:00Z"'
        (Invoke-SIUplinkOutboxTick -Invoke $script:Eng -HeartbeatStatus 'sent' -Send { param($Record) [pscustomobject]@{ Status = 'ok' } } -Now $script:Now.AddMinutes(11) -Sleep { param($s) }).Status | Should -Be 'drained'
    }
    It 'the backlog: pending and the oldest time; caught up = 0 / null' {
        $z = Get-SIUplinkOutboxBacklog -Invoke $script:Eng -NowUtc $script:Now
        $z.pending | Should -Be 0; $z.oldestUtc | Should -BeNullOrEmpty; $z.checkedUtc | Should -Be '2026-11-05T10:00:00Z'
        $null = Add-SIUplinkOutboxRecord -Invoke $script:Eng -Job 'si-endpoint' -Json '{"Kind":"run"}' -Answer 'x' -NowUtc $script:Now.AddHours(-2)
        $null = Add-SIUplinkOutboxRecord -Invoke $script:Eng -Job 'si-azure' -Json '{"Kind":"run"}' -Answer 'x' -NowUtc $script:Now.AddHours(-1)
        $b = Get-SIUplinkOutboxBacklog -Invoke $script:Eng -NowUtc $script:Now
        $b.pending | Should -Be 2; $b.oldestUtc | Should -Be '2026-11-05T08:00:00Z'
    }
}
