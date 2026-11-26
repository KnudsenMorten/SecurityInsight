#Requires -Version 7.0
<#
    THE KEY FIGURES FROM THE CHANGE SET, figure by figure (REQUIREMENTS #1334) -- engine\pro-data\_shared\SI-DataHistory.ps1
    Get-SIDataHistoryKeyFiguresCheckSql / Invoke-SIDataHistoryKeyFiguresCheck, on the lifecycle's own change marks
    (sidata.CiFindingState.ChangedAt / CiFindingStateGone, written by SI-DataCiLifecycle.ps1's statements) and the CI rows each
    key figures build read (sidata.KeyFigureInput).

    What these tests keep true (REAL SQL, the key figures' own full build -- Invoke-SIDataKeyFigures -- as the reference):
      * nothing moved since the previous collection's figures were built: the lifecycle and CI figures are CARRIED from it
        and the result equals the full build byte for byte;
      * a CI's read column moved and the figures built again: the CI figures come from the full build (and they differ from
        the previous one's), the lifecycle ones are still carried;
      * a lifecycle row whose first-detected time crossed the window's edge: that figure is not carried;
      * a real lifecycle change, the collection's figures built again: the figure is taken from the full build -- and it is
        NOT the previous one's (the signal mattered);
      * a carried figure that is wrong (the previous collection's stored row changed) is FOUND: a difference, never published.
    Runs on the Azure test runner (TEST_SQL_*: _SITestSql.ps1).
#>

BeforeDiscovery {
    $script:HasSql = [bool]($env:SI_TEST_LOCALSQL)
}

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    foreach ($f in 'engine\_shared\SI-KqlError.ps1', 'engine\pro-data\_shared\SI-DataKql.ps1', 'engine\_shared\SI-SchemaGate.ps1', 'engine\_shared\data-sql\SI-DataModel.ps1', 'engine\_shared\data-sql\SI-DataSql.ps1',
                   'engine\pro-data\_shared\SI-DataViewContext.ps1', 'engine\pro-data\_shared\SI-DataKeyFigures.ps1', 'engine\pro-data\_shared\SI-DataChangedSet.ps1', 'engine\pro-data\_shared\SI-DataHistory.ps1') {
        . (Join-Path $script:SIRoot $f)
    }
    $script:Quiet = { param($l, $m) }
}

Describe 'the statement' {
    It 'carries only the lifecycle and CI figures, each behind its own inputs, and compares every column' {
        $s = Get-SIDataHistoryKeyFiguresCheckSql
        foreach ($f in 'opened_30d', 'fixed_30d', 'mean_days_to_fix', 'not_onboarded', 'not_onboarded_status', 'not_seen_30d', 'azure_vm_no_agent', 'users_without_mfa') { $s | Should -Match ([regex]::Escape("N'$f'")) }
        foreach ($f in 'open_findings', 'missing_patches', 'tier0_very_high_high', 'high_recommendations', 'stale_admins') { $s | Should -Not -Match ([regex]::Escape("N'$f'")) }
        foreach ($x in 'ChangedAt > @tb', 'CiFindingStateGone', 'KeyFigureInput', 'LifecycleMarksSince') { $s | Should -Match ([regex]::Escape($x)) }
        $s | Should -Not -Match 'INSERT sidata\.KeyFigure|DELETE FROM sidata\.KeyFigure|UPDATE sidata\.KeyFigure'
    }
}

Describe 'the key figures from the change set equal the full build (real SQL)' -Skip:(-not $script:HasSql) {
    BeforeAll {
        $script:Db = 'si_test_kfchg_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
        $m = New-Object System.Data.SqlClient.SqlConnection "Server=$($env:SI_TEST_LOCALSQL);Database=master;$($env:SI_TEST_SQL_AUTH);Connection Timeout=30"
        $m.Open(); try { $c = $m.CreateCommand(); $c.CommandText = "CREATE DATABASE [$($script:Db)]"; $c.CommandTimeout = 300; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
        $script:Cn = New-Object System.Data.SqlClient.SqlConnection ("Server=$($env:SI_TEST_LOCALSQL);Database=$($script:Db);$($env:SI_TEST_SQL_AUTH);Connection Timeout=30;Pooling=false")
        $script:Cn.Open()
        $script:Seam = {
            param($Sql, $Params, $Mode)
            $c = $script:Cn.CreateCommand(); $c.CommandText = $Sql; $c.CommandTimeout = 600
            if ($Params) { foreach ($k in $Params.Keys) { $v = $Params[$k]; if ($null -eq $v) { $v = [System.DBNull]::Value }; [void]$c.Parameters.AddWithValue('@' + $k, $v) } }
            switch ($Mode) {
                { $_ -in 'reader', 'rows' } { $rd = $c.ExecuteReader(); $out = New-Object System.Collections.Generic.List[object]; try { while ($rd.Read()) { $h = @{}; for ($i = 0; $i -lt $rd.FieldCount; $i++) { $h[$rd.GetName($i)] = $rd.GetValue($i) }; $out.Add($h) } } finally { $rd.Close() }; , $out.ToArray() }
                'scalar' { $c.ExecuteScalar() }
                default { [void]$c.ExecuteNonQuery() }
            }
        }
        function script:X([string]$Sql) { & $script:Seam $Sql @{} 'nonquery' }
        function script:S([string]$Sql) { & $script:Seam $Sql @{} 'scalar' }
        X ([IO.File]::ReadAllText((Join-Path $script:SIRoot 'sql\si-data-schema.sql')))
        X @'
INSERT sidata.Collection (CollectionTime, Kind, Status, DerivedAt, ViewsReadyAt, ContextAt) VALUES ('2026-11-20T03:00:00', 'Detailed', 'Complete', SYSUTCDATETIME(), SYSUTCDATETIME(), SYSUTCDATETIME());
INSERT sidata.Collection (CollectionTime, Kind, Status, DerivedAt, ViewsReadyAt, ContextAt) VALUES ('2026-11-21T03:00:00', 'Detailed', 'Complete', SYSUTCDATETIME(), SYSUTCDATETIME(), SYSUTCDATETIME());
;WITH n AS (SELECT TOP (40) ROW_NUMBER() OVER (ORDER BY (SELECT 1)) AS i FROM sys.all_objects)
INSERT sidata.Ci (CiId, Class, Name, AssetType, OsPlatform, Lifecycle, Tier, InternetExposed, OnboardingStatus, MdeDeviceId, AccountEnabled, MfaRegistered, LastSignIn, PrivilegedAccessCount, CollectionTime)
SELECT CONCAT(N'ci-', i), CASE WHEN i <= 25 THEN N'device' ELSE N'identity' END, CONCAT(N'name', i),
       CASE WHEN i <= 25 THEN CASE WHEN i % 3 = 0 THEN N'Server' ELSE N'Workstation' END ELSE N'User' END,
       CASE WHEN i <= 25 THEN N'windows' END, N'active', i % 4, CASE WHEN i % 5 = 0 THEN 1 ELSE 0 END,
       CASE WHEN i <= 25 THEN CASE WHEN i % 4 = 0 THEN N'can_be_onboarded' ELSE N'onboarded' END END,
       CASE WHEN i <= 25 AND i % 4 <> 0 THEN CONCAT(N'mde-', i) END,
       CASE WHEN i > 25 THEN 1 END, CASE WHEN i > 25 THEN CASE WHEN i % 2 = 0 THEN 1 ELSE 0 END END,
       CASE WHEN i > 25 THEN CASE WHEN i % 3 = 0 THEN '2026-01-01' ELSE '2026-11-19' END END,
       CASE WHEN i > 35 THEN 2 ELSE 0 END, '2026-11-20T03:00:00'
FROM n;
-- the lifecycle: open and remediated CVE findings, none near a window's edge
;WITH n AS (SELECT TOP (60) ROW_NUMBER() OVER (ORDER BY (SELECT 1)) AS i FROM sys.all_objects)
INSERT sidata.CiFindingState (OwnerKey, FindingKey, CiId, State, FirstDetected, LastSeen, LastSnapshot, AbsentRuns, ClosedAt, CloseReason, Severity, DetectedBy)
SELECT CONCAT(N'ci-', 1 + i % 25), CONCAT(N'CVE-2026-', 100 + i), CONCAT(N'ci-', 1 + i % 25),
       CASE WHEN i % 4 = 0 THEN N'closed' ELSE N'open' END, CASE WHEN i % 2 = 0 THEN '2026-11-10' ELSE '2026-08-01' END, '2026-11-20', '2026-11-20', 0,
       CASE WHEN i % 4 = 0 THEN '2026-11-15' END, CASE WHEN i % 4 = 0 THEN N'remediated' END, N'high', N'R1'
FROM n;
'@
        foreach ($k in 0, 1) {
            X ("DECLARE @c INT = (SELECT CollectionId FROM sidata.Collection WHERE CollectionTime = '2026-11-2{0}T03:00:00'); ;WITH n AS (SELECT TOP (80) ROW_NUMBER() OVER (ORDER BY (SELECT 1)) AS i FROM sys.all_objects) INSERT sidata.Finding (CollectionId, AssetKey, AssetName, ReportName, SecurityDomain, ConfigurationId, Cve, Title, Severity, Tier, RiskScore) SELECT @c, CONCAT(N'ci-', 1 + i % 40), CONCAT(N'name', 1 + i % 40), N'Device_Missing_CVEs', N'Endpoint', CONCAT(N'CVE-2026-', 100 + i + {1}), CONCAT(N'CVE-2026-', 100 + i + {1}), N't', CASE WHEN i % 3 = 0 THEN N'Very High' ELSE N'High' END, i % 4, i FROM n;" -f $k, $k)
        }
        $script:P = [long](S "SELECT CollectionId FROM sidata.Collection WHERE CollectionTime = '2026-11-20T03:00:00'")
        $script:C = [long](S "SELECT CollectionId FROM sidata.Collection WHERE CollectionTime = '2026-11-21T03:00:00'")
        # the lifecycle's marks are written since before the figures are built (as Set-SIDataLifecycleMarks records it)
        X "INSERT sidata.CiBuildState (Name, Value) VALUES (N'LifecycleMarksSince', CONVERT(nvarchar(30), DATEADD(hour, -1, SYSUTCDATETIME()), 127));"
        Start-Sleep -Milliseconds 2200
        $script:KF1 = Invoke-SIDataKeyFigures -Invoke $script:Seam -Log $script:Quiet -Keep 5
        Start-Sleep -Milliseconds 1200
        function script:Check { Invoke-SIDataHistoryKeyFiguresCheck -Invoke $script:Seam -CollectionId $script:C -Prev ([string]$script:P) }
        # (both marks are stored to the second: the context mark is set clearly after the last build, so the collection is due again)
        function script:Rebuild-C { Start-Sleep -Milliseconds 2100; X "UPDATE sidata.Collection SET ContextAt = SYSUTCDATETIME() WHERE CollectionId = $($script:C)"; Start-Sleep -Milliseconds 1100; $r = Invoke-SIDataKeyFigures -Invoke $script:Seam -Log $script:Quiet -Keep 5; $r.Status | Should -Be 'ok' }
    }
    AfterAll {
        try { $script:Cn.Dispose() } catch { }
        [System.Data.SqlClient.SqlConnection]::ClearAllPools()
        try {
            $m = New-Object System.Data.SqlClient.SqlConnection "Server=$($env:SI_TEST_LOCALSQL);Database=master;$($env:SI_TEST_SQL_AUTH);Connection Timeout=30"
            $m.Open(); try { $c = $m.CreateCommand(); $c.CommandTimeout = 300; $c.CommandText = "ALTER DATABASE [$($script:Db)] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$($script:Db)]"; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
        } catch { }
    }
    It 'nothing moved: the eight lifecycle and CI figures are carried, the result equals the full build' {
        $script:KF1.Status | Should -Be 'ok' -Because ([string]$script:KF1.Error)
        [long](S "SELECT COUNT(*) FROM sidata.KeyFigure WHERE CollectionId = $($script:P)") | Should -BeGreaterThan 10
        $r = Check
        $r.Outcome | Should -Be 'same' -Because ([string]$r.Detail)
        $r.Carried | Should -Be 8
        [long](S "SELECT COUNT(*) FROM sidata.KeyFigureInput WHERE CollectionId IN ($($script:P), $($script:C))") | Should -Be 2
    }
    It 'a carried figure that is wrong is found -- a difference, nothing different published' {
        X "UPDATE sidata.KeyFigure SET Value = Value + 1 WHERE CollectionId = $($script:P) AND Block = N'patching' AND Figure = N'opened_30d'"
        $r = Check
        $r.Outcome | Should -Be 'differs'
        [string]$r.Detail | Should -Match 'opened_30d'
        X "UPDATE sidata.KeyFigure SET Value = Value - 1 WHERE CollectionId = $($script:P) AND Block = N'patching' AND Figure = N'opened_30d'"
        (Check).Outcome | Should -Be 'same'
    }
    It 'a column no CI figure reads moved: still carried; a CI''s read column moved and the figures built again: the CI figures from the full build' {
        X "UPDATE sidata.Ci SET LastSeen = SYSUTCDATETIME(), CollectionTime = SYSUTCDATETIME() WHERE CiId = N'ci-5'"
        Rebuild-C
        $r0 = Check
        $r0.Outcome | Should -Be 'same'; $r0.Carried | Should -Be 8 -Because 'the CI rows the build read are the same'
        X "UPDATE sidata.Ci SET MfaRegistered = 1 - MfaRegistered WHERE CiId = N'ci-31'"
        Rebuild-C
        $r = Check
        $r.Outcome | Should -Be 'same' -Because ([string]$r.Detail)
        $r.Carried | Should -Be 3
        $pv = S "SELECT Value FROM sidata.KeyFigure WHERE CollectionId = $($script:P) AND Block = N'identity' AND Figure = N'users_without_mfa'"
        $cv = S "SELECT Value FROM sidata.KeyFigure WHERE CollectionId = $($script:C) AND Block = N'identity' AND Figure = N'users_without_mfa'"
        $cv | Should -Not -Be $pv -Because 'a carry would have published the old value: the fingerprint mattered'
    }
    It 'a lifecycle row whose first-detected time crossed the window edge: that figure is not carried' {
        # in the previous collection's 30-day window, out of this one's -- an old row, unmarked (as one the lifecycle wrote long ago)
        X "INSERT sidata.CiFindingState (OwnerKey, FindingKey, CiId, State, FirstDetected, LastSeen, LastSnapshot, AbsentRuns, Severity, DetectedBy) VALUES (N'ci-2', N'CVE-2026-999', N'ci-2', N'open', '2026-10-21T15:00:00', '2026-11-20', '2026-11-20', 0, N'high', N'R1');"
        $r = Check
        $r.Outcome | Should -Be 'same'
        $r.Carried | Should -Be 2 -Because 'fixed and the mean time to fix stay carried; opened is not (and the CI figures are not, from the step before)'
    }
    It 'a real lifecycle change, the figures built again: taken from the full build -- and not the previous collection''s value' {
        # as the lifecycle's own close statement does: the read columns and the mark in one statement
        X "UPDATE sidata.CiFindingState SET State = N'closed', ClosedAt = '2026-11-20T12:00:00', CloseReason = N'remediated', ChangedAt = SYSUTCDATETIME() WHERE FindingKey IN (N'CVE-2026-101', N'CVE-2026-103')"
        Rebuild-C
        $r = Check
        $r.Outcome | Should -Be 'same' -Because ([string]$r.Detail)
        $r.Carried | Should -Be 0
        $pv = S "SELECT Value FROM sidata.KeyFigure WHERE CollectionId = $($script:P) AND Block = N'patching' AND Figure = N'fixed_30d'"
        $cv = S "SELECT Value FROM sidata.KeyFigure WHERE CollectionId = $($script:C) AND Block = N'patching' AND Figure = N'fixed_30d'"
        $cv | Should -Not -Be $pv -Because 'a carry would have published the old value: the signal mattered'
    }
}
