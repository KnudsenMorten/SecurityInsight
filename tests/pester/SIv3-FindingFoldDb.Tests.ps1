#Requires -Version 7.0
<#
    #1364 THE MEANING RULES IN THE DATABASE (owner 2026-11-25: "you cannot have 2 identical recommendations; only one" / "we cannot
    have 2 similar tasks"). Live on internal 3.1.46: Defender for Cloud's "Update openssl" was its own finding and its own task
    (configuration) next to the Defender for Endpoint openssl CVEs of the same server -- the fold rule mdc-update-software-on-mde-cve
    ran only where findings are published to SI_Finding_CL (off by default, #829), never for the findings per CI made from the
    database nor for the remediation tasks.

    What these tests keep true (a REAL SQL Server, the runner's):
      * an "Update openssl" recommendation on a CI that HAS openssl CVE findings is evidence on the first of them (by key): its row
        is MOVED out of sidata.Finding into sidata.FindingEvidence (the whole row, the canonical's key, the rule) -- sidata.Finding
        holds the CVE rows only, so every reader counts the CVEs alone; ONE task (the CVE / bundled one) with the CVE-only counts;
        its old task closes as "task changed" once and stays closed (no churn); the data quality counts a report's rows WITH its
        evidence rows (never fewer than the source);
      * the findings per CI made from the database: one finding, the recommendation's report in its detected-by, its own severity
        (never raised by the evidence), the evidence listed (si_finding_evidence); the lifecycle carries the recommendation's row
        onto the canonical key (an alias row);
      * on a CI WITHOUT a matching CVE the recommendation stays its own finding and its own task; another "Update <x>" too;
      * idempotent (a second fold moves nothing); a fold that no longer holds moves the row BACK as its own finding (same key, same row);
      * THE TWO PATHS AGREE: the published path (Merge-SIFindingFolds over the SI findings, SI_Finding_CL on) names the same
        canonical key and the same evidence keys as the database path.
    Needs SI_TEST_LOCALSQL. Loads Pro code (engine\pro-data): excluded from the free payload (solution.publish.json).
#>

BeforeAll {
    $script:Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:Root 'engine\_shared\SI-SchemaGate.ps1')
    . (Join-Path $script:Root 'engine\pro-data\_shared\SI-DataRemediationTask.ps1')
    . (Join-Path $script:Root 'engine\pro-data\_shared\SI-DataCi.ps1')
    . (Join-Path $script:Root 'engine\pro-data\_shared\SI-DataFindingFold.ps1')
    $script:DM = Join-Path $script:Root 'data-model'
    $script:Map = (Get-SIDataModelTemplate -Name 'finding-fields' -Root $script:DM).Document
    $script:VM = (Get-SIDataModelTemplate -Name 'value-maps' -Root $script:DM).Document.maps
    $script:EqDoc = (Get-SIDataModelTemplate -Name 'recommendation-equivalence' -Root $script:DM).Document
    $script:Eq = ConvertTo-SIRecommendationEquivalenceIndex -Document $script:EqDoc
    $script:NoEq = @{ ById = @{}; ByTitle = @{}; ByOwner = @{}; Folds = @() }
    $script:Schema = Get-Content -Raw -LiteralPath (Join-Path $script:Root 'sql\si-data-schema.sql')
    try { $script:LocalSql = [bool]$env:SI_TEST_LOCALSQL -and $null -ne ('System.Data.SqlClient.SqlConnection' -as [type]) } catch { $script:LocalSql = $false }
}

Describe 'the fold, pure: the rule''s own functions over distinct values' {
    It 'the shipped fold rule is live and reads fields the stored findings carry' {
        $r = @($script:Eq.Folds | Where-Object { $_.Group -eq 'mdc-update-software-on-mde-cve' })
        $r.Count | Should -Be 1
        $cols = Get-SIDataFoldColumns
        foreach ($s in 'Evidence', 'Canonical') { foreach ($f in (Get-SIDataFoldRuleFields -Rule $r[0] -Side $s)) { $cols.Contains($f) | Should -BeTrue -Because $f } }
        $ef = Get-SIDataFoldRuleFields -Rule $r[0] -Side Evidence; $cf = Get-SIDataFoldRuleFields -Rule $r[0] -Side Canonical
        ($ef -join ',') | Should -Be 'si_finding_type,si_title'
        ($cf -join ',') | Should -Be 'si_finding_type,si_affected_product'
    }
    It 'evidence values give the software they name; canonical values each product of a list; others nothing' {
        $r = @($script:Eq.Folds | Where-Object { $_.Group -eq 'mdc-update-software-on-mde-cve' })[0]
        $e = ConvertTo-SIDataFoldMatches -Rows @(@{ c0 = 'recommendation'; c1 = 'Update openssl' }, @{ c0 = 'recommendation'; c1 = 'Enable BitLocker' }, @{ c0 = 'cve'; c1 = 'Update openssl' }) -Fields @('si_finding_type', 'si_title') -Rule $r -Side Evidence
        @($e).Count | Should -Be 1; $e[0].M | Should -Be 'openssl'
        $c = ConvertTo-SIDataFoldMatches -Rows @(@{ c0 = 'cve'; c1 = 'openssl;Windows_Server_2022' }, @{ c0 = 'recommendation'; c1 = 'openssl' }) -Fields @('si_finding_type', 'si_affected_product') -Rule $r -Side Canonical
        @($c | ForEach-Object { $_.M } | Sort-Object) | Should -Be @('openssl', 'windows server 2022')
    }
}

Describe 'on a real SQL Server: Update openssl + the openssl CVEs of the same CI = one finding, one task' {
    BeforeAll {
        if (-not $script:LocalSql) { return }
        $script:Db = 'si_fold_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
        $m = [System.Data.SqlClient.SqlConnection]::new("Server=$($env:SI_TEST_LOCALSQL);Database=master;$($env:SI_TEST_SQL_AUTH);Connection Timeout=30")
        $m.Open(); try { $c = $m.CreateCommand(); $c.CommandText = "CREATE DATABASE [$script:Db]"; $c.CommandTimeout = 300; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
        $script:Cn = [System.Data.SqlClient.SqlConnection]::new("Server=$($env:SI_TEST_LOCALSQL);Database=$script:Db;$($env:SI_TEST_SQL_AUTH);Connection Timeout=30;Pooling=false")
        $script:Cn.Open()
        function script:Sql([string]$Text, [hashtable]$P = @{}, [string]$Mode = 'nonquery', [scriptblock]$OnRow) {
            if ($Mode -eq 'session') {
                $sc = [System.Data.SqlClient.SqlConnection]::new("Server=$($env:SI_TEST_LOCALSQL);Database=$script:Db;$($env:SI_TEST_SQL_AUTH);Connection Timeout=30;Pooling=false")
                $sc.Open()
                try {
                    $run = { param([string]$StepSql, [string]$StepMode) $k = $sc.CreateCommand(); $k.CommandText = $StepSql; $k.CommandTimeout = 0; if ($StepMode -eq 'scalar') { $k.ExecuteScalar() } else { [void]$k.ExecuteNonQuery() } }.GetNewClosure()
                    return (& $OnRow $run)
                } finally { $sc.Dispose() }
            }
            $c = $script:Cn.CreateCommand(); $c.CommandText = $Text; $c.CommandTimeout = 0
            foreach ($k in $P.Keys) { [void]$c.Parameters.AddWithValue('@' + $k, $(if ($null -eq $P[$k]) { [DBNull]::Value } else { $P[$k] })) }
            if ($Mode -eq 'scalar') { return $c.ExecuteScalar() }
            if ($Mode -in 'reader', 'rows') {
                $rd = $c.ExecuteReader(); $rows = New-Object System.Collections.Generic.List[object]
                try { while ($rd.Read()) { $h = @{}; for ($i = 0; $i -lt $rd.FieldCount; $i++) { $h[$rd.GetName($i)] = $rd.GetValue($i) }; $rows.Add($h) } } finally { $rd.Dispose() }
                return , $rows.ToArray()
            }
            [void]$c.ExecuteNonQuery()
        }
        $script:Seam = { param($s, $p, $m, $o) Sql $s $p $m $o }
        $script:Seam | Add-Member -NotePropertyName SISqlSession -NotePropertyValue $true
        function script:Rows([string]$Text, [hashtable]$P = @{}) { foreach ($r in (Sql $Text $P 'reader')) { $r } }
        function script:V($x) { if ($x -is [System.DBNull]) { $null } else { $x } }
        function script:NewCollection([string]$At) {
            $id = [int](Sql "INSERT sidata.Collection (CollectionTime, Kind, Status, ContextAt) VALUES (@t, 'Detailed', 'Complete', SYSUTCDATETIME()); SELECT CAST(SCOPE_IDENTITY() AS int)" @{ t = $At } 'scalar')
            foreach ($rep in 'R_cve', 'R_mdc') { Sql "INSERT sidata.RaReportStatus (CollectionTime, Grain, ReportName, State) VALUES (@t, 'Detailed', @n, 'Complete')" @{ t = $At; n = $rep } }
            $id
        }
        function script:Finding([int]$Cid, [string]$Owner, [string]$Key, [hashtable]$F) {
            $isCve = $Key -match '^CVE-'
            Sql @'
INSERT sidata.Finding (CollectionId, AssetKey, AssetName, ReportName, SecurityDomain, ConfigurationId, Cve, Title, Severity, Tier, RiskScore, RiskScoreWeighted, DepartmentId,
                       Component, AffectedProduct, AffectedVendor, AffectedVersion, RaFindingKey, RaSeq, DetailJson)
VALUES (@c, @o, @an, @rep, N'Endpoint', @k, @cve, @ttl, @sev, 1, @rs, @rs, 7, @comp, @prd, @ven, @ver, @rk, @seq, @dj)
'@ @{ c = $Cid; o = $Owner; an = ($Owner + '.contoso.test'); rep = $(if ($isCve) { 'R_cve' } else { 'R_mdc' }); k = $Key; cve = $(if ($isCve) { $Key } else { $null })
      ttl = $F.Title; sev = $F.Sev; rs = [double]$F.Risk; comp = $F.Comp; prd = $F.Prd; ven = $F.Ven; ver = $F.Ver; rk = ($Owner + '|' + $Key.ToLowerInvariant()); seq = [long]$F.Seq; dj = $(if ($F.Dj) { [string]$F.Dj } else { '{}' }) }
        }
        function script:State([string]$Owner, [string]$Key) {
            Sql "INSERT sidata.CiFindingState (OwnerKey, FindingKey, CiId, State, FirstDetected, LastSeen, LastSnapshot) VALUES (@o, @k, @o, N'open', '2026-11-01', SYSUTCDATETIME(), SYSUTCDATETIME())" @{ o = $Owner; k = $Key }
        }
        function script:Snapshot([string]$At) {
            Sql "MERGE sidata.CiBuildState AS b USING (SELECT N'FindingStateSnapshot' AS Name, CONVERT(NVARCHAR(400), CONVERT(datetime2(3), @t), 127) AS Value) AS v ON b.Name = v.Name WHEN MATCHED THEN UPDATE SET Value = v.Value WHEN NOT MATCHED THEN INSERT (Name, Value) VALUES (v.Name, v.Value);" @{ t = $At }
        }
        function script:Ci([string]$Id) {
            Sql "INSERT sidata.Ci (CiId, Class, Name, Tier, Lifecycle, CollectionTime, Owner, Department, CmdbId) VALUES (@i, 'device', @i, 1, 'active', '2026-11-01', N'it-ops@contoso.test', N'IT', N'sys-' + @i);" @{ i = $Id }
            Sql "INSERT sidata.Asset (AssetKey, AssetName, KeySource, FirstSeen, LastSeen, DepartmentId) VALUES (@a, @a, 'ledger', '2026-11-01', '2026-11-01', 3)" @{ a = $Id }
        }
        $script:Evidence = @([ordered]@{ DeviceId = 'mde-a'; Vendor = 'openssl'; Product = 'openssl'; Version = '3.0.10.0'; PathType = 'disk'; FullPath = 'C:\Program Files\Adobe\Acrobat DC\libcrypto-3.dll'
                                         InstallKind = 'bundled'; Application = 'Adobe Acrobat DC'; ApplicationVendor = $null; ApplicationVersion = $null; ApplicationSource = 'folder'; CollectionTime = [datetime]'2026-11-01T02:00:00' },
                             # #1373 ci-c: zlib in two places -- its own install and bundled in an application (two versions)
                             [ordered]@{ DeviceId = 'mde-c'; Vendor = 'zlib'; Product = 'zlib'; Version = '1.2.11'; PathType = 'disk'; FullPath = 'C:\Program Files\zlib\zlib1.dll'
                                         InstallKind = 'product'; Application = $null; ApplicationVendor = $null; ApplicationVersion = $null; ApplicationSource = $null; CollectionTime = [datetime]'2026-11-01T02:00:00' },
                             [ordered]@{ DeviceId = 'mde-c'; Vendor = 'zlib'; Product = 'zlib'; Version = '1.2.13'; PathType = 'disk'; FullPath = 'C:\Program Files\Foo App\zlib.dll'
                                         InstallKind = 'bundled'; Application = 'Foo App'; ApplicationVendor = $null; ApplicationVersion = $null; ApplicationSource = 'folder'; CollectionTime = [datetime]'2026-11-01T02:00:00' })
        function script:Build($Eq) {
            $lines = New-Object System.Collections.Generic.List[string]
            $r = Invoke-SIDataRemediationTasks -Invoke $script:Seam -Map $script:Map -ValueMaps $script:VM -DevicesPerPage 5 -Equivalence $Eq `
                -ReadEvidence { param($Inv, $Ids) @($script:Evidence | Where-Object { $Ids -contains $_.DeviceId }) } -Log { param($l, $m) $lines.Add("$l $m") }.GetNewClosure()
            $r | Add-Member -NotePropertyName Lines -NotePropertyValue $lines.ToArray() -Force
            $r
        }
        function script:Tasks([int]$Cid) { $o = @{}; foreach ($t in (Sql "SELECT * FROM sidata.RemediationTask WHERE CollectionId = @c" @{ c = $Cid } 'reader')) { $o[('{0}|{1}' -f $t['OwnerKey'], $t['TaskName'])] = $t }; $o }
        $script:Bundled = 'Update Adobe Acrobat DC (bundles openssl 3.0.10.0)'
        $script:SetupError = $null
        try {
            Sql ([IO.File]::ReadAllText((Join-Path $script:Root 'sql\si-pro-settings.sql')))
            Sql ([IO.File]::ReadAllText((Join-Path $script:Root 'sql\si-vulnerability-target.sql'))); Sql $script:Schema; Sql $script:Schema
            Ci 'ci-a'; Ci 'ci-b'; Ci 'ci-c'; Ci 'ci-d'
            Sql "INSERT sidata.CiLink (CiId, Provider, RecordType, NativeId, IsPrimary, State, LastSeen) VALUES ('ci-a', 'mde', 'device', 'mde-a', 1, 'active', '2026-11-01'), ('ci-c', 'mde', 'device', 'mde-c', 1, 'active', '2026-11-01')"
            $djUpd = { param($p) '{"si_recommendation_remediation_type":"Update","si_recommendation_product":"' + $p + '","si_recommendation_vendor":"' + $p + '"}' }
            $cveF = { param($s) @{ Comp = 'Application'; Prd = 'openssl'; Ven = 'openssl'; Ver = '3.0.10.0'; Title = 'OpenSSL'; Sev = 'High'; Risk = 30; Seq = $s } }
            $mdc = { param($t, $s) @{ Comp = 'Application'; Title = $t; Sev = 'Very High'; Risk = 60; Seq = $s } }
            $fill = {
                param([int]$Cid)
                # the recommendation's row FIRST (a lower RaSeq): the canonical's own row must still be the one the finding is made from
                Finding $Cid 'ci-a' 'mdc-ssl' (& $mdc 'Update openssl' 1)
                # #1373 ci-d: a typed "Update zstd" next to a zstd CVE of the same CI: folded onto the CVE -- no task of its own
                $m7 = & $mdc 'Update zstd' 7; $m7['Dj'] = (& $djUpd 'zstd'); Finding $Cid 'ci-d' 'mdc-zstd' $m7
                Finding $Cid 'ci-d' 'CVE-2026-0301' @{ Comp = 'Application'; Prd = 'zstd'; Ven = 'zstd'; Ver = '1.5.0'; Title = 'zstd flaw'; Sev = 'High'; Risk = 30; Seq = 8 }
                # #1373 ci-c: a Defender for Cloud "Update zlib" that Defender types Update, no CVE of zlib on the CI: its own task, a
                # software upgrade with the software's paths from the evidence (and one per application that bundles it)
                $m6 = & $mdc 'Update zlib' 6; $m6['Dj'] = (& $djUpd 'zlib'); Finding $Cid 'ci-c' 'mdc-zlib' $m6
                Finding $Cid 'ci-a' 'CVE-2026-0102' (& $cveF 3); Finding $Cid 'ci-a' 'CVE-2026-0101' (& $cveF 2)
                Finding $Cid 'ci-a' 'mdc-libc' (& $mdc 'Update libc6' 4)
                # (ci-b: no openssl CVE -- Defender's type Update makes it a software upgrade of its own; no evidence = no paths)
                $m5 = & $mdc 'Update openssl' 5; $m5['Dj'] = (& $djUpd 'openssl'); Finding $Cid 'ci-b' 'mdc-ssl' $m5
            }
            foreach ($k in 'mdc-ssl', 'CVE-2026-0101', 'CVE-2026-0102', 'mdc-libc') { State 'ci-a' $k }
            State 'ci-b' 'mdc-ssl'; State 'ci-c' 'mdc-zlib'; State 'ci-d' 'mdc-zstd'; State 'ci-d' 'CVE-2026-0301'
            # C0: as 3.1.46 built it (no fold in the database) -- the redundant task exists
            $at = { param($h) [datetime]::UtcNow.AddHours(-$h).ToString('yyyy-MM-ddTHH:mm:ss', [Globalization.CultureInfo]::InvariantCulture) }
            $script:C0 = NewCollection (& $at 3); & $fill $script:C0; Snapshot (& $at 3)
            $script:R0 = Build $script:NoEq; $script:T0 = Tasks $script:C0
            # C1: the fold
            $script:C1 = NewCollection (& $at 2); & $fill $script:C1; Snapshot (& $at 2)
            $script:R1 = Build $script:Eq; $script:T1 = Tasks $script:C1
            $script:Rows1 = @(Rows "SELECT AssetKey, ConfigurationId, RaFindingKey FROM sidata.Finding WHERE CollectionId = @c ORDER BY AssetKey, ConfigurationId" @{ c = $script:C1 })
            $script:Ev1 = @(Rows "SELECT OwnKey, CanonicalKey, RuleId, ReportName, ConfigurationId, Title, Severity, RowJson FROM sidata.FindingEvidence WHERE CollectionId = @c" @{ c = $script:C1 })
            $script:Rows0 = [int](Sql "SELECT COUNT(*) FROM sidata.Finding WHERE CollectionId = @c" @{ c = $script:C0 } 'scalar')
            $script:Again = Invoke-SIDataFindingFold -Invoke $script:Seam -CollectionId $script:C1 -Equivalence $script:Eq -Log { param($l, $m) }
            # C2: the next run (Risk Analysis gives the rows their own keys again) -- no churn
            $script:C2 = NewCollection (& $at 1); & $fill $script:C2; Snapshot (& $at 1)
            $script:R2 = Build $script:Eq; $script:T2 = Tasks $script:C2
            # the findings per CI from the database (C2) + the lifecycle's alias rows
            $p = Get-SIDataCiRatingBandParams; $p['CollectionId'] = [string]$script:C2
            $script:Staged = [long](Sql (Get-SIDataCiFindingFromDbSql) $p 'scalar')
            $script:Stage = @(Rows "SELECT CiId, FindingKey, Severity, DetectedBy, DocJson FROM sidata.CiFindingStage ORDER BY CiId, FindingKey")
            Sql 'DELETE FROM sidata.CiFindingLifecycleStage'
            $script:Aliases = [long](Sql (Get-SIDataFoldAliasStageSql) @{ CollectionId = [string]$script:C2 } 'scalar')
            $script:AliasRows = @(Rows "SELECT Kind, OwnerKey, FindingKey, Canonical FROM sidata.CiFindingLifecycleStage")
            # the data quality counts (the newest complete collection = C2): a report's rows WITH its evidence rows
            . (Join-Path $script:Root 'engine\pro-data\_shared\SI-DataQuality.ps1')
            $script:Quality = @(Rows (Get-SIDataQualityReportSql))
            # the CVEs gone on ci-a (C2 changed in place): the recommendation is its own finding again
            Sql "DELETE FROM sidata.Finding WHERE CollectionId = @c AND Cve IS NOT NULL" @{ c = $script:C2 }
            $script:Back = Invoke-SIDataFindingFold -Invoke $script:Seam -CollectionId $script:C2 -Equivalence $script:Eq -Log { param($l, $m) }
            $script:RowsBack = @(Rows "SELECT AssetKey, ConfigurationId, RaFindingKey, Title, Severity, ReportName, DetailJson FROM sidata.Finding WHERE CollectionId = @c AND ConfigurationId = N'mdc-ssl' ORDER BY AssetKey" @{ c = $script:C2 })
            $script:EvBack = [int](Sql "SELECT COUNT(*) FROM sidata.FindingEvidence WHERE CollectionId = @c" @{ c = $script:C2 } 'scalar')
        } catch { $script:SetupError = $_.Exception.Message + ' @ ' + $_.InvocationInfo.PositionMessage }
    }
    AfterAll {
        if (-not $script:LocalSql) { return }
        try { $script:Cn.Dispose() } catch { }
        $m = [System.Data.SqlClient.SqlConnection]::new("Server=$($env:SI_TEST_LOCALSQL);Database=master;$($env:SI_TEST_SQL_AUTH);Connection Timeout=30")
        $m.Open(); try { $c = $m.CreateCommand(); $c.CommandText = "ALTER DATABASE [$script:Db] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$script:Db]"; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
    }

    It 'before the fix (no fold): the redundant task exists -- Update openssl (configuration) next to the bundled CVE task' {
        if (-not $script:LocalSql) { Set-ItResult -Skipped -Because 'needs SI_TEST_LOCALSQL'; return }
        $script:SetupError | Should -BeNullOrEmpty
        foreach ($r in $script:R0, $script:R1, $script:R2) { Write-Host ("build: {0} {1} | {2}" -f $r.Status, $r.Error, (@($r.Lines) -join ' || ')) }
        $script:R0.Status | Should -Be 'ok' -Because $script:R0.Error
        $script:T0['ci-a|Update openssl'].Kind | Should -Be 'configuration'
        $script:T0["ci-a|$script:Bundled"].State | Should -Be 'open'
    }
    It 'the fold MOVES the row: sidata.Finding holds ONE finding for the weakness, the evidence table the other (on the FIRST CVE by key)' {
        if (-not $script:LocalSql) { Set-ItResult -Skipped -Because 'needs SI_TEST_LOCALSQL'; return }
        $script:Rows0 | Should -Be 8
        @($script:Rows1).Count | Should -Be 6
        @($script:Rows1 | Where-Object { $_.AssetKey -eq 'ci-a' -and $_.ConfigurationId -eq 'mdc-ssl' }).Count | Should -Be 0
        @($script:Rows1 | Where-Object { $_.AssetKey -eq 'ci-a' } | ForEach-Object { $_.ConfigurationId } | Sort-Object) | Should -Be @('CVE-2026-0101', 'CVE-2026-0102', 'mdc-libc')
        @($script:Rows1 | Where-Object { $_.AssetKey -eq 'ci-b' } | ForEach-Object { $_.ConfigurationId }) | Should -Be @('mdc-ssl')
        @($script:Ev1).Count | Should -Be 2
        $e = @($script:Ev1 | Where-Object { $_.OwnKey -eq 'ci-a|mdc-ssl' })[0]
        ($e.OwnKey, $e.CanonicalKey, $e.RuleId, $e.ReportName, $e.Title, $e.Severity) | Should -Be @('ci-a|mdc-ssl', 'ci-a|cve-2026-0101', 'mdc-update-software-on-mde-cve', 'R_mdc', 'Update openssl', 'critical')
        ([string]$e.RowJson | ConvertFrom-Json).RaSeq | Should -Be 1
        ($script:Again.Findings, $script:Again.Moved, $script:Again.Restored) | Should -Be @(2, 0, 0)
    }
    It 'ONE task: the bundled CVE task with the counts of the CVEs alone; the old task closes as task changed, once; no fix-less CI changes' {
        if (-not $script:LocalSql) { Set-ItResult -Skipped -Because 'needs SI_TEST_LOCALSQL'; return }
        $script:R1.Status | Should -Be 'ok' -Because $script:R1.Error
        $b0 = $script:T0["ci-a|$script:Bundled"]; $b1 = $script:T1["ci-a|$script:Bundled"]
        $b1.State | Should -Be 'open'
        ($b1.Findings, $b1.Cves, $b1.HighestSeverity) | Should -Be @($b0.Findings, $b0.Cves, $b0.HighestSeverity)
        ($b1.Findings, $b1.Cves) | Should -Be @(2, 2)
        $old = $script:T1['ci-a|Update openssl']
        ($old.State, $old.ClosedWhy) | Should -Be @('closed', 'task changed')
        $script:T1['ci-b|Update openssl'].State | Should -Be 'open'
        $script:T1['ci-b|Update openssl'].Kind | Should -Be 'software-upgrade' -Because 'Defender types it Update (#1373)'
        $script:T1['ci-a|Update libc6'].State | Should -Be 'open'
        @($script:T1.Values | Where-Object { $_.OwnerKey -eq 'ci-a' -and $_.State -eq 'open' } | ForEach-Object { $_.TaskName } | Sort-Object) | Should -Be @($script:Bundled, 'Update libc6')
        # the next run: no churn -- still closed, closed at the same moment, never reopened
        $o2 = $script:T2['ci-a|Update openssl']
        ($o2.State, $o2.ClosedWhy, $o2.ReopenCount) | Should -Be @('closed', 'task changed', 0)
        $o2.ClosedAt | Should -Be $old.ClosedAt
        $script:T2["ci-a|$script:Bundled"].Findings | Should -Be 2
    }
    It 'the findings per CI from the database: ONE finding, its own severity, the recommendation as evidence; the lifecycle carries the row' {
        if (-not $script:LocalSql) { Set-ItResult -Skipped -Because 'needs SI_TEST_LOCALSQL'; return }
        $a = @($script:Stage | Where-Object { $_.CiId -eq 'ci-a' })
        @($a | ForEach-Object { $_.FindingKey } | Sort-Object) | Should -Be @('CVE-2026-0101', 'CVE-2026-0102', 'mdc-libc')
        $c = @($a | Where-Object { $_.FindingKey -eq 'CVE-2026-0101' })[0]
        $c.Severity | Should -Be 'high'
        [string]$c.DetectedBy | Should -Match 'R_mdc'
        $doc = [string]$c.DocJson | ConvertFrom-Json
        $doc.si_finding_type | Should -Be 'cve'
        @($doc.si_finding_evidence | ForEach-Object { $_.key }) | Should -Be @('CVE-2026-0101', 'mdc-ssl')
        $doc.si_finding_rows | Should -Be 1
        @($script:Stage | Where-Object { $_.CiId -eq 'ci-b' } | ForEach-Object { $_.FindingKey }) | Should -Be @('mdc-ssl')
        $script:Aliases | Should -Be 2
        $al = @($script:AliasRows | Where-Object { $_.OwnerKey -eq 'ci-a' })[0]
        ($al.Kind, $al.OwnerKey, $al.FindingKey, $al.Canonical) | Should -Be @('a', 'ci-a', 'mdc-ssl', 'CVE-2026-0101')
    }
    It '#1373 Defender''s type: "Update zlib" (no CVE of zlib on its CI) is a software upgrade with the software''s paths; the folded "Update openssl" makes no task' {
        if (-not $script:LocalSql) { Set-ItResult -Skipped -Because 'needs SI_TEST_LOCALSQL'; return }
        $z = $script:T1['ci-c|Update zlib']
        $z | Should -Not -BeNullOrEmpty -Because (@($script:T1.Keys) -join ', ')
        ($z.Kind, $z.State, (V $z.Product)) | Should -Be @('software-upgrade', 'open', 'zlib')
        [string]$z.ApplicationPaths | Should -Be 'C:\Program Files\zlib\zlib1.dll'
        $fa = $script:T1['ci-c|Update Foo App (bundles zlib)']
        $fa | Should -Not -BeNullOrEmpty -Because (@($script:T1.Keys) -join ', ')
        ($fa.Kind, [string]$fa.ApplicationPaths, [string]$fa.Application) | Should -Be @('bundled-upgrade', 'C:\Program Files\Foo App\zlib.dll', 'Foo App')
        $script:T0['ci-c|Update zlib'].Kind | Should -Be 'software-upgrade'
        @($script:T1.Values | Where-Object { $_.OwnerKey -eq 'ci-a' -and $_.State -eq 'open' -and $_.TaskName -eq 'Update openssl' }).Count | Should -Be 0
        # the typed Update zstd folded onto its CVE: ONE task on ci-d, the CVE's -- no software upgrade of the recommendation
        @($script:T1.Values | Where-Object { $_.OwnerKey -eq 'ci-d' -and $_.State -eq 'open' } | ForEach-Object { $_.TaskName }) | Should -Be @('Update zstd 1.5.0 (zstd)')
    }
    It 'the data quality counts a report''s rows WITH its evidence rows (never fewer than the source)' {
        if (-not $script:LocalSql) { Set-ItResult -Skipped -Because 'needs SI_TEST_LOCALSQL'; return }
        $q = @{}; foreach ($r in $script:Quality) { $q[[string]$r.Report] = [long]$r.Rows }
        ($q['R_mdc'], $q['R_cve']) | Should -Be @(5, 3)
    }
    It 'a fold that no longer holds (the CVEs gone) moves the row BACK as its own finding: the same key, the same row' {
        if (-not $script:LocalSql) { Set-ItResult -Skipped -Because 'needs SI_TEST_LOCALSQL'; return }
        $script:Back.Restored | Should -Be 2
        $script:EvBack | Should -Be 0
        @($script:RowsBack).Count | Should -Be 2
        foreach ($r in $script:RowsBack) { $r.RaFindingKey | Should -Be ($r.AssetKey + '|mdc-ssl'); ($r.Title, $r.Severity, $r.ReportName) | Should -Be @('Update openssl', 'Very High', 'R_mdc'); if ($r.AssetKey -eq 'ci-a') { $r.DetailJson | Should -Be '{}' } }
    }
    It 'THE TWO PATHS AGREE: the published path (SI_Finding_CL on) names the same canonical and the same evidence' {
        if (-not $script:LocalSql) { Set-ItResult -Skipped -Because 'needs SI_TEST_LOCALSQL'; return }
        $f = { param($ci, $k, $t, $type, $prd, $rep, $sev) [pscustomobject][ordered]@{ si_ci_id = $ci; si_finding_key = $k; si_finding_type = $type; si_title = $t; si_affected_product = $prd; si_report_name = $rep; si_detected_by = @($rep); si_severity = $sev } }
        $items = @((& $f 'ci-a' 'mdc-ssl' 'Update openssl' 'recommendation' $null 'R_mdc' 'critical'), (& $f 'ci-a' 'CVE-2026-0102' 'OpenSSL' 'cve' @('openssl') 'R_cve' 'high'),
                   (& $f 'ci-a' 'CVE-2026-0101' 'OpenSSL' 'cve' @('openssl') 'R_cve' 'high'), (& $f 'ci-a' 'mdc-libc' 'Update libc6' 'recommendation' $null 'R_mdc' 'critical'),
                   (& $f 'ci-b' 'mdc-ssl' 'Update openssl' 'recommendation' $null 'R_mdc' 'critical'), (& $f 'ci-c' 'mdc-zlib' 'Update zlib' 'recommendation' $null 'R_mdc' 'critical'), (& $f 'ci-d' 'mdc-zstd' 'Update zstd' 'recommendation' $null 'R_mdc' 'critical'), (& $f 'ci-d' 'CVE-2026-0301' 'zstd flaw' 'cve' @('zstd') 'R_cve' 'high'))
        $left = @(Merge-SIFindingFolds -Findings $items -Folds @($script:Eq.Folds))
        $la = @($left | ForEach-Object { '{0}|{1}' -f $_.si_ci_id, $_.si_finding_key } | Sort-Object)
        $db = @($script:Stage | ForEach-Object { '{0}|{1}' -f $_.CiId, $_.FindingKey } | Sort-Object)
        $la | Should -Be $db
        $canonLa = @($left | Where-Object { $_.si_ci_id -eq 'ci-a' -and @($_.si_finding_aliases) -contains 'mdc-ssl' })
        $canonLa.Count | Should -Be 1
        $canonLa[0].si_finding_key | Should -Be @($script:AliasRows | Where-Object { $_.OwnerKey -eq 'ci-a' })[0].Canonical
        $dbDoc = [string](@($script:Stage | Where-Object { $_.FindingKey -eq 'CVE-2026-0101' -and $_.CiId -eq 'ci-a' })[0].DocJson) | ConvertFrom-Json
        @($canonLa[0].si_finding_evidence | ForEach-Object { [string]$_.key }) | Should -Be @($dbDoc.si_finding_evidence | ForEach-Object { [string]$_.key })
        @($canonLa[0].si_detected_by | Sort-Object) | Should -Be @(([string](@($script:Stage | Where-Object { $_.FindingKey -eq 'CVE-2026-0101' })[0].DetectedBy)).Split(';') | ForEach-Object { $_.Trim() } | Sort-Object)
    }
}
