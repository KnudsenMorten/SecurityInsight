#Requires -Version 5.1
<#
    #1210 SQL-STATS-PROOF (Invardia contract, framework §12.27 point 5; its check PERF-01 flags background statistics off, more
    than 10 % stale statistics, or no refresh after the last bulk write, per install).

    What must hold (offline: every database is a stub):
      (a) the heartbeat's Database field carries EXACTLY three more keys after its agreed six, in this order and with these
          types: statsAsync (bool), statsStalePct (a number 0-100), statsRefreshedUtc (ISO-8601 UTC, null = none recorded);
      (b) a read that fails (throws, or answers no whole row) leaves the three out -- Database keeps its six, NO other key is
          added -- and that is said once;
      (c) the stale rule: a statistic is stale when its changes exceed 20 % of its rows + 500 -- the PowerShell rule and the
          SQL say the same;
      (d) the refresh time: a pass of the pipeline's statistics refresh through every table is recorded in cfg.InstallState
          'StatisticsRefresh' (a setting-only call, a pass stopped part-way or a database without the procedure is not), and
          the heartbeat's settings read carries that row;
      (e) the update sets the background statistics setting (the database setup job's not-required batch) and READS IT BACK.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\_shared\SI-HeartbeatJob.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-HeartbeatFields.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\data-sql\SI-DataStatistics.ps1')
    . (Join-Path $script:SIRoot 'setup\_shared\SI-DbInitJob.ps1')
    $script:Now = [datetime]'2026-11-12T10:00:00Z'
    $script:OnlyDb = @{ Database = $true; Pipeline = $false; Jobs = $false; Sources = $false; Update = $false; Mail = $false; Warnings = $false; Security = $false
                        Published = $false; DataOut = $false; BuildPool = $false; UplinkBacklog = $false }
    $script:Six = @('tier', 'dtu', 'maxSizeMb', 'usedMb', 'peakLogWritePct1h', 'minutesAtLimit1h')
    $script:Nine = $script:Six + @('statsAsync', 'statsStalePct', 'statsRefreshedUtc')
    $script:Refreshed = [datetime]::SpecifyKind([datetime]'2026-11-12T03:41:07', 'Unspecified')
    $script:StateRow = [pscustomobject]@{ K = 'state'; Name = 'StatisticsRefresh'; T1 = $script:Refreshed; Txt = '{"tables":12,"refreshed":40,"failed":0,"seconds":95}' }
    function script:Get-Fields {
        param([object[]]$StatsRows, [object[]]$CfgRows, [scriptblock]$Log = { param($l) })
        $a = @{ Ring = 0; NowUtc = $script:Now; Switch = $script:OnlyDb; Counts = @{ sqlUsedMb = 2007; sqlMaxMb = 4096 }; Log = $Log }
        if ($PSBoundParameters.ContainsKey('StatsRows')) { $a['DatabaseStatsRows'] = $StatsRows }
        if ($PSBoundParameters.ContainsKey('CfgRows')) { $a['CfgRows'] = $CfgRows }
        New-SIHeartbeatFields @a
    }
}

Describe '#1210 (a) the three keys, present and typed, when the reads work' {
    It 'Database = the agreed six, then statsAsync / statsStalePct / statsRefreshedUtc, in that order, typed' {
        $f = Get-Fields -StatsRows @(@{ Async = $true; Total = 200; Stale = 7 }) -CfgRows @($script:StateRow)
        $d = $f['Database']
        @($d.PSObject.Properties.Name) | Should -Be $script:Nine
        $d.statsAsync | Should -BeOfType [bool]
        $d.statsAsync | Should -BeTrue
        $d.statsStalePct | Should -BeOfType [double]
        $d.statsStalePct | Should -Be 3.5
        $d.statsRefreshedUtc | Should -Be '2026-11-12T03:41:07Z'
        $d.usedMb | Should -Be 2007 -Because 'the six stay as they were'
        Test-SIHeartbeatField -Name 'Database' -Value $d | Should -BeNullOrEmpty
    }
    It 'async off, a database with no statistic computed (0 %), and no refresh recorded yet (null) -- still the three keys' {
        $d = (Get-Fields -StatsRows @(@{ Async = 0; Total = 0; Stale = 0 }) -CfgRows @())['Database']
        @($d.PSObject.Properties.Name) | Should -Be $script:Nine
        $d.statsAsync | Should -BeFalse
        $d.statsStalePct | Should -Be 0
        $d.statsRefreshedUtc | Should -BeNullOrEmpty
        ($d | ConvertTo-Json -Compress) | Should -Match '"statsAsync":false,"statsStalePct":0(\.0)?,"statsRefreshedUtc":null\}$'
    }
    It 'the contract lists exactly these three, behind one switch that is on' {
        $c = Get-SIHeartbeatFieldsContract
        @($c.DatabaseStatsFields) | Should -Be @('statsAsync', 'statsStalePct', 'statsRefreshedUtc')
        $c.DatabaseSendStats | Should -BeTrue
        @($c.Fields.Database) | Should -Be $script:Six -Because 'the agreed six are unchanged'
    }
    It 'the validator refuses a wrong type, a value over 100, a wrong order and any other key' {
        $ok = (Get-Fields -StatsRows @(@{ Async = $true; Total = 10; Stale = 1 }) -CfgRows @($script:StateRow))['Database']
        $x = $ok.PSObject.Copy(); $x.statsAsync = 'yes'; Test-SIHeartbeatField -Name 'Database' -Value $x | Should -Match 'statsAsync'
        $x = $ok.PSObject.Copy(); $x.statsStalePct = 100.5; Test-SIHeartbeatField -Name 'Database' -Value $x | Should -Match 'statsStalePct'
        $x = $ok.PSObject.Copy(); $x.statsRefreshedUtc = '2026-11-12 03:41'; Test-SIHeartbeatField -Name 'Database' -Value $x | Should -Match 'statsRefreshedUtc'
        $x = $ok.PSObject.Copy(); $x | Add-Member -NotePropertyName statsTotal -NotePropertyValue 10; Test-SIHeartbeatField -Name 'Database' -Value $x | Should -Match 'has the fields'
        $o = [ordered]@{}; foreach ($n in $script:Six) { $o[$n] = $ok.$n }; $o['statsStalePct'] = 1.0; $o['statsAsync'] = $true
        Test-SIHeartbeatField -Name 'Database' -Value ([pscustomobject]$o) | Should -Match 'has the fields' -Because 'the agreed order'
    }
}

Describe '#1210 (b) a read that fails leaves the three out, and adds no other key' {
    It 'no answer / a row that is not whole: Database keeps its six only, said once' {
        foreach ($rows in @(@(), @(@{ Async = $null; Total = 3; Stale = 1 }), @(@{ Async = $true; Total = 3; Stale = 9 }), @(@{ Async = $true; Total = 'x'; Stale = 1 }))) {
            $global:SI_HeartbeatFieldProblemsSaid = $false
            $said = New-Object System.Collections.Generic.List[string]
            $d = (Get-Fields -StatsRows $rows -CfgRows @($script:StateRow) -Log { param($l) $said.Add($l) }.GetNewClosure())['Database']
            @($d.PSObject.Properties.Name) | Should -Be $script:Six
            $said.Count | Should -Be 1
            $said[0] | Should -Match 'statistics'
        }
    }
    It 'a read that throws while it is taken apart: the six only, said once, never the heartbeat' {
        $global:SI_HeartbeatFieldProblemsSaid = $false
        $said = New-Object System.Collections.Generic.List[string]
        # a test session never reads a database on its own: the failure is handed in as an answer that throws on use
        $bad = @([pscustomobject]@{ Async = $true; Total = 5 } | Add-Member -MemberType ScriptProperty -Name Stale -Value { throw 'The SELECT permission was denied' } -PassThru)
        $d = (Get-Fields -StatsRows $bad -CfgRows @() -Log { param($l) $said.Add($l) }.GetNewClosure())['Database']
        @($d.PSObject.Properties.Name) | Should -Be $script:Six
        $said.Count | Should -Be 1
    }
    It 'nothing handed in (a test session reads no database): Database is the six, nothing said' {
        $global:SI_HeartbeatFieldProblemsSaid = $false
        $said = New-Object System.Collections.Generic.List[string]
        $d = (Get-Fields -CfgRows @($script:StateRow) -Log { param($l) $said.Add($l) }.GetNewClosure())['Database']
        @($d.PSObject.Properties.Name) | Should -Be $script:Six
        $said.Count | Should -Be 0
    }
    It 'the settings database not read: the refresh time is not known, so the three are left out (never a null that reads as "never refreshed")' {
        $global:SI_HeartbeatFieldProblemsSaid = $false
        $said = New-Object System.Collections.Generic.List[string]
        $d = (Get-Fields -StatsRows @(@{ Async = $true; Total = 4; Stale = 0 }) -Log { param($l) $said.Add($l) }.GetNewClosure())['Database']
        @($d.PSObject.Properties.Name) | Should -Be $script:Six
        $said.Count | Should -Be 1
    }
    It 'the switch off: the six only' {
        $c = Get-SIHeartbeatFieldsContract
        $was = $c.DatabaseSendStats
        try {
            $c.DatabaseSendStats = $false
            @((Get-Fields -StatsRows @(@{ Async = $true; Total = 1; Stale = 0 }) -CfgRows @())['Database'].PSObject.Properties.Name) | Should -Be $script:Six
        } finally { $c.DatabaseSendStats = $was }
    }
}

Describe '#1210 (c) the stale rule: changes over 20 % of the rows + 500' {
    It 'the boundary, in PowerShell' {
        Test-SIHeartbeatStatStale -Rows 1000 -Changes 700 | Should -BeFalse -Because '0.2 x 1000 + 500 = 700 is not over it'
        Test-SIHeartbeatStatStale -Rows 1000 -Changes 701 | Should -BeTrue
        Test-SIHeartbeatStatStale -Rows 0 -Changes 500 | Should -BeFalse
        Test-SIHeartbeatStatStale -Rows 0 -Changes 501 | Should -BeTrue
        Test-SIHeartbeatStatStale -Rows 10000000 -Changes 2000500 | Should -BeFalse
        Test-SIHeartbeatStatStale -Rows 10000000 -Changes 2000501 | Should -BeTrue
    }
    It 'the SQL says the same rule, over user tables, computed statistics only, read-only catalog views' {
        $q = Get-SIHeartbeatDatabaseStatsSql
        $q | Should -Match ([regex]::Escape('ISNULL(sp.modification_counter, 0) > 0.2 * ISNULL(sp.rows, 0) + 500'))
        $q | Should -Match 'is_auto_update_stats_async_on FROM sys\.databases'
        $q | Should -Match 't\.is_ms_shipped = 0'
        $q | Should -Match 'CROSS APPLY sys\.dm_db_stats_properties\(s\.object_id, s\.stats_id\)'
        $q | Should -Match 'sp\.last_updated IS NOT NULL'
        $q | Should -Match 'SET LOCK_TIMEOUT 5000'
        $q | Should -Not -Match '(?i)\b(INSERT|UPDATE|DELETE|MERGE|ALTER|EXEC)\b' -Because 'one read, never a change'
        $q | Should -Not -Match '(?i)\b(sidata|cfg|vuln)\.' -Because 'catalog views only, never a product table'
    }
    It 'the percentage: stale / counted, one decimal' {
        (ConvertFrom-SIHeartbeatDatabaseStats -Rows @(@{ Async = $true; Total = 3; Stale = 1 })).statsStalePct | Should -Be 33.3
        (ConvertFrom-SIHeartbeatDatabaseStats -Rows @(@{ Async = '1'; Total = 8; Stale = 8 })).statsStalePct | Should -Be 100
        (ConvertFrom-SIHeartbeatDatabaseStats -Rows @(@{ Async = 'False'; Total = 8; Stale = 0 })).statsAsync | Should -BeFalse
    }
}

Describe '#1210 (d) the refresh time is recorded by the pipeline''s refresh and read by the heartbeat' {
    It 'a pass through every table writes cfg.InstallState ''StatisticsRefresh'' once, through the settings seam' {
        $calls = New-Object System.Collections.Generic.List[object]
        $rec = { param($s, $p, $m) $calls.Add([pscustomobject]@{ Sql = $s; Params = $p; Mode = $m }) }.GetNewClosure()
        $answers = @(@{ Ready = $true; TableName = '[sidata].[Ci]'; Refreshed = 3; Failed = 0; Error = $null; Async = $true }, @{ Ready = $true; TableName = $null; Refreshed = 0; Failed = 0; Error = $null; Async = $true })
        $st = @{ I = 0 }
        $data = { param($s, $p, $m) $a = $answers[[Math]::Min($st.I, $answers.Count - 1)]; $st.I++; , @($a) }.GetNewClosure()
        $r = Invoke-SIDataStatisticsRefresh -Invoke $data -RecordInvoke $rec
        $r.Tables | Should -Be 1
        $calls.Count | Should -Be 1
        $calls[0].Mode | Should -Be 'nonquery'
        $calls[0].Sql | Should -Match "UPDATE cfg\.InstallState SET Value = LEFT\(@Value, 400\), UpdatedAt = SYSUTCDATETIME\(\)"
        $calls[0].Sql | Should -Match "N'StatisticsRefresh'"
        $calls[0].Params.Value | Should -Be '{"tables":1,"refreshed":3,"failed":0,"seconds":0}'
    }
    It 'nothing stale is still a finished pass (recorded); the setting-only call, a stopped pass and an old database are not' {
        Test-SIDataStatisticsPassDone ([pscustomobject]@{ Ready = $true; AsyncOnly = $false; Stopped = $false; Tables = 0 }) | Should -BeTrue
        Test-SIDataStatisticsPassDone ([pscustomobject]@{ Ready = $true; AsyncOnly = $true; Stopped = $false }) | Should -BeFalse
        Test-SIDataStatisticsPassDone ([pscustomobject]@{ Ready = $true; AsyncOnly = $false; Stopped = $true }) | Should -BeFalse
        Test-SIDataStatisticsPassDone ([pscustomobject]@{ Ready = $false; AsyncOnly = $false; Stopped = $false }) | Should -BeFalse
        $calls = New-Object System.Collections.Generic.List[object]
        $rec = { param($s, $p, $m) $calls.Add($s) }.GetNewClosure()
        $null = Invoke-SIDataStatisticsRefresh -Invoke { param($s, $p, $m) , @(@{ Ready = $true; TableName = $null; Async = $true }) } -AsyncOnly -RecordInvoke $rec
        $null = Invoke-SIDataStatisticsRefresh -Invoke { param($s, $p, $m) throw 'lost' } -RecordInvoke $rec
        $null = Invoke-SIDataStatisticsRefresh -Invoke { param($s, $p, $m) , @(@{ Ready = $false }) } -RecordInvoke $rec
        $calls.Count | Should -Be 0
    }
    It 'a record that cannot be written never fails the refresh' {
        $r = Invoke-SIDataStatisticsRefresh -Invoke { param($s, $p, $m) , @(@{ Ready = $true; TableName = $null; Async = $true }) } -RecordInvoke { param($s, $p, $m) throw 'denied' }
        $r.Ready | Should -BeTrue
        Save-SIDataStatisticsRefreshRecord -Invoke { param($s, $p, $m) throw 'denied' } -Result $r | Should -BeFalse
    }
    It 'the heartbeat''s settings read carries the row; the engine may write it (cfg.InstallState INSERT, UPDATE)' {
        Get-SIHeartbeatFieldsCfgSql | Should -Match "N'Housekeeping', N'StatisticsRefresh'\)"
        Get-SIHeartbeatStatsRefreshedUtc -Rows @($script:StateRow) | Should -Be '2026-11-12T03:41:07Z'
        Get-SIHeartbeatStatsRefreshedUtc -Rows @([pscustomobject]@{ K = 'state'; Name = 'Housekeeping'; T1 = $script:Refreshed }) | Should -BeNullOrEmpty
        . (Join-Path $script:SIRoot 'engine\pro-settings\SI-EngineGrants.ps1')
        $g = @($script:SIEngineObjectGrants | Where-Object { $_.Object -eq 'cfg.InstallState' })[0]
        $g.Verbs | Should -Match 'INSERT'; $g.Verbs | Should -Match 'UPDATE'
    }
}

Describe '#1210 (e) the update sets the background statistics setting and reads it back' {
    It 'the database setup job (started by every update) has the not-required batch for the Pro database, with a read back after the change' {
        $sql = Get-SIDbInitStatsAsyncSql
        $sql | Should -Match 'ALTER DATABASE CURRENT SET AUTO_UPDATE_STATISTICS_ASYNC ON'
        $at = $sql.IndexOf('ALTER DATABASE CURRENT SET AUTO_UPDATE_STATISTICS_ASYNC ON')
        $after = $sql.Substring($at)
        $after | Should -Match 'is_auto_update_stats_async_on FROM sys\.databases' -Because 'read back after the change'
        $after | Should -Match "THROW 51795, N'the background statistics setting did not change \(read back: still off\)'"
        $sql.Substring(0, $at) | Should -Match '= 0\s+BEGIN' -Because 'on already = a read only (idempotent)'
    }
}
