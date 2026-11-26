#Requires -Version 7.0
<#
    #1365 THE DUPLICATE CHECK (#693 (6) / (9), #688; owner 2026-11-25: "you cannot have 2 identical recommendations; only one"
    / "we cannot have 2 similar tasks"). A weakness reported twice that is NOT merged into one finding / task is a DEFECT.

    What these tests keep true:
      * THE GATE (pure, the SHIPPED template): findings with the known duplicate shapes -- Defender for Cloud "Update openssl"
        next to the CVE findings of openssl, the same control from Defender for Endpoint and Defender for Cloud -- go through
        the publish path (ConvertTo-SIFindingRows with the shipped equivalence) and the detector finds NOTHING left. A fold or a
        key group that stops merging makes this suite red: the release gate fails on a broken merge.
      * the detector itself: without the merge it finds every shape (fold, key, link, same CVE); a finding that is already a
        canonical finding of a fold is never counted; a CI with "Update chrome" and no chrome CVE has no duplicate;
      * on a REAL SQL Server: the data sync's check over findings made from the database (no si_affected_product in their
        document -- the facts come from sidata.Finding), CIs read range by range, facts in FindingId ranges, the task rule
        ("Update openssl" next to "Update GitHub Desktop (bundles openssl ...)"; two versions of one product are NOT a
        duplicate); the counts and examples stored, the work rows removed; the read-only mode finds the same and writes
        nothing; once the duplicates are gone it finds 0;
      * the wiring: after the findings / tasks are written, before the data-quality step, a WARNING of the run, never a block.
    The SQL part needs SI_TEST_LOCALSQL (the Azure test runner's SQL Server). Loads Pro code (engine\pro-data).
#>

BeforeAll {
    $script:Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:Root 'engine\_shared\SI-SchemaGate.ps1')
    . (Join-Path $script:Root 'engine\data-model\SI-RecommendationEquivalence.ps1')
    . (Join-Path $script:Root 'engine\risk-analysis\_shared\RA-Findings.ps1')
    . (Join-Path $script:Root 'engine\pro-data\_shared\SI-DataDuplicateCheck.ps1')
    $script:Doc = [IO.File]::ReadAllText((Join-Path $script:Root 'data-model\recommendation-equivalence.locked.json')) | ConvertFrom-Json
    $script:Idx = ConvertTo-SIRecommendationEquivalenceIndex -Document $script:Doc
    $script:Schema = Get-Content -Raw -LiteralPath (Join-Path $script:Root 'sql\si-data-schema.sql')
    function script:Row([string]$Ci, [string]$Key, [string]$Title, [string]$Report, [string]$Product = '', [string]$Sev = 'High') {
        $o = [ordered]@{ si_ci_id = $Ci; AssetId = $Ci; ConfigurationId = $Key; ConfigurationName = $Title; ReportName = $Report; SecuritySeverity = $Sev; RiskScoreTotal = 20 }
        if ($Product) { $o['si_affected_product'] = $Product }
        [pscustomobject]$o
    }
    # the known duplicate shapes, as Risk Analysis publishes them (one row per report row)
    $script:Rows = @(
        (Row 'ci-1' 'CVE-2025-1001' 'OpenSSL flaw' 'Device_Missing_CVEs_Detailed' 'openssl'),
        (Row 'ci-1' 'CVE-2025-1002' 'OpenSSL flaw 2' 'Device_Missing_CVEs_Detailed' 'openssl'),
        (Row 'ci-1' '4b5d9550-3120-1f27-8fda-1764c1a66ac3' 'Update openssl' 'Azure_DefenderRecommendations_Detailed'),
        (Row 'ci-1' 'CVE-2025-2001' 'Windows flaw' 'Device_Missing_CVEs_Detailed' 'windows_server_2022'),
        (Row 'ci-1' 'mdc-xyz-windows' 'Update windows_server_2022' 'Azure_DefenderRecommendations_Detailed'),
        (Row 'ci-1' 'a5a0d2d3-909d-4954-a083-4fb40fcdc181' 'Require user authentication for remote connections by using Network Level Authentication' 'Azure_DefenderRecommendations_Detailed'),
        (Row 'ci-1' 'scid-45' 'Require Network Level Authentication' 'Device_Recommendations_Detailed'),
        (Row 'ci-2' 'mdc-xyz-chrome' 'Update chrome' 'Azure_DefenderRecommendations_Detailed'),
        (Row 'ci-2' 'CVE-2025-3001' 'Edge flaw' 'Device_Missing_CVEs_Detailed' 'edge')
    )
    try { $script:LocalSql = [bool]$env:SI_TEST_LOCALSQL -and $null -ne ('System.Data.SqlClient.SqlConnection' -as [type]) } catch { $script:LocalSql = $false }
}

Describe 'the gate: the shipped merge rules leave no duplicate' {
    It 'the shipped template has a live fold rule and the key groups -- the check has something to check' {
        @(Test-SIRecommendationEquivalence -Document $script:Doc).Count | Should -Be 0
        @($script:Idx.Folds | ForEach-Object { $_.Group }) | Should -Contain 'mdc-update-software-on-mde-cve'
        $script:Idx.ById.ContainsKey('scid-45') | Should -BeTrue
    }
    It 'the publish path (ConvertTo-SIFindingRows with the shipped equivalence) merges every known shape: the detector finds 0' {
        $pub = @(ConvertTo-SIFindingRows -Rows $script:Rows -Equivalence $script:Idx)
        $dup = @(Find-SIDuplicateFindings -Findings $pub -Index $script:Idx)
        ($dup | ForEach-Object { Format-SIDuplicateExample $_ }) -join ' || ' | Should -BeNullOrEmpty
        # and they ARE merged: one openssl / windows recommendation less, one NLA finding
        @($pub | Where-Object { $_.si_ci_id -eq 'ci-1' }).Count | Should -Be 4
        @($pub | Where-Object { $_.si_title -eq 'Update chrome' }).Count | Should -Be 1
    }
}

Describe 'the detector' {
    BeforeAll { $script:Raw = @(ConvertTo-SIFindingRows -Rows $script:Rows) }
    It 'without the merge it finds every shape: two folds, one key group; Update chrome without a chrome CVE is no duplicate' {
        $dup = @(Find-SIDuplicateFindings -Findings $script:Raw -Index $script:Idx)
        @($dup | Where-Object Rule -eq 'fold:mdc-update-software-on-mde-cve' | ForEach-Object Title | Sort-Object) | Should -Be @('Update openssl', 'Update windows_server_2022')
        ($dup | Where-Object { $_.Title -eq 'Update openssl' }).Onto | Should -Be 2
        @($dup | Where-Object Rule -eq 'key').Count | Should -Be 1
        @($dup | Where-Object Rule -eq 'key')[0].Value | Should -Be 'mdc-rdp-network-level-authentication'
        @($dup | Where-Object { $_.Owner -eq 'ci-2' }).Count | Should -Be 0
    }
    It 'the same CVE in two findings of one CI; one CVE on two CIs is not one' {
        $f = @(
            [pscustomobject]@{ si_ci_id = 'ci-1'; si_finding_key = 'CVE-2025-0003'; si_title = 'a'; si_finding_type = 'cve' },
            [pscustomobject]@{ si_ci_id = 'ci-1'; si_finding_key = 'tvm-0003'; si_title = 'b'; si_finding_type = 'recommendation'; si_cve = 'cve-2025-0003' },
            [pscustomobject]@{ si_ci_id = 'ci-2'; si_finding_key = 'CVE-2025-0003'; si_title = 'a'; si_finding_type = 'cve' })
        $dup = @(Find-SIDuplicateFindings -Findings $f -Index $script:Idx)
        $dup.Count | Should -Be 1
        $dup[0].Rule | Should -Be 'same-cve'; $dup[0].Key | Should -Be 'tvm-0003'; $dup[0].OntoKey | Should -Be 'CVE-2025-0003'
    }
    It 'a manual link that is still two findings' {
        $doc = [pscustomobject]@{ groups = @([pscustomobject]@{ id = 'link-1'; match = 'link'; owner = 'ci-9'; canonicalId = 'k1'; linkedBy = 'a@b'; reason = 'same'; members = @([pscustomobject]@{ id = 'k1' }, [pscustomobject]@{ id = 'k2' }) }) }
        $i = ConvertTo-SIRecommendationEquivalenceIndex -Document $doc
        $f = @([pscustomobject]@{ si_ci_id = 'ci-9'; si_finding_key = 'k1'; si_title = 'x' }, [pscustomobject]@{ si_ci_id = 'ci-9'; si_finding_key = 'k2'; si_title = 'y' })
        $dup = @(Find-SIDuplicateFindings -Findings $f -Index $i)
        $dup.Count | Should -Be 1; $dup[0].Rule | Should -Be 'link'; $dup[0].Key | Should -Be 'k2'
    }
    It 'a canonical finding of a fold already is never counted as a duplicate of another fold (no chain)' {
        $f = @(
            [pscustomobject]@{ si_ci_id = 'ci-1'; si_finding_key = 'CVE-2025-1001'; si_title = 't'; si_finding_type = 'cve'; si_affected_product = @('openssl') },
            [pscustomobject]@{ si_ci_id = 'ci-1'; si_finding_key = 'r1'; si_title = 'Update openssl'; si_finding_type = 'recommendation'; _si_fold_target = $true })
        @(Find-SIDuplicateFindings -Findings $f -Index $script:Idx).Count | Should -Be 0
    }
    It 'the summary: a line per rule with examples, the key numbers dup.*, a WARNING text; every checked rule has a number, 0 included' {
        $dup = @(Find-SIDuplicateFindings -Findings $script:Raw -Index $script:Idx)
        $s = Get-SIDuplicateCheckSummary -Items $dup -Checked @('fold:mdc-update-software-on-mde-cve', 'key', 'same-cve') -Tasks ([pscustomobject]@{ Duplicates = 0; Owners = 0; Examples = @() })
        $s.Total | Should -Be 3
        @($s.Metrics | ForEach-Object Key) | Should -Be @('dup.fold.mdc-update-software-on-mde-cve', 'dup.key', 'dup.same-cve', 'dup.task-update-restates-software')
        ($s.Metrics | Where-Object Key -eq 'dup.same-cve').Value | Should -Be 0
        @($s.Lines).Count | Should -Be 2
        $s.Lines[0] | Should -Match "^duplicates  : 2 duplicate\(s\) on 1 asset\(s\) were not merged -- rule fold:mdc-update-software-on-mde-cve: .*e\.g\. ci-1: 'Update openssl'"
        $s.Issue | Should -Match 'nothing was blocked'
    }
    It 'the fold prefilter narrows on the stored columns only (a superset of what the rule meets)' {
        $sql = Get-SIDupFoldPrefilterSql -Folds @($script:Idx.Folds)
        $sql | Should -Match "LOWER\(LTRIM\(c\.Title\)\) LIKE N'update %'"
        $sql | Should -Match "c\.FindingType"
        Get-SIDupPatternPrefix '^update (?<software>.+)$' | Should -Be 'update '
        Get-SIDupPatternPrefix '^updates? x' | Should -Be 'update'
        Get-SIDupPatternPrefix 'update' | Should -Be ''
        Get-SIDupFoldPrefilterSql -Folds @() | Should -Be '1 = 0'
    }
}

Describe 'the statements, the schema and the wiring' {
    It 'the schema adds the two tables guarded and additive' {
        (Test-SISchemaIsAdditive -Sql $script:Schema).IsAdditive | Should -BeTrue
        $script:Schema | Should -Match "IF OBJECT_ID\('sidata\.DuplicateCheck'\) IS NULL\s+CREATE TABLE sidata\.DuplicateCheck \("
        $script:Schema | Should -Match "IF OBJECT_ID\('sidata\.DuplicateCheckWork'\) IS NULL\s+CREATE TABLE sidata\.DuplicateCheckWork \("
    }
    It 'the data sync runs it after the findings and tasks, before the data-quality step, and it only warns' {
        $sync = Get-Content -Raw -LiteralPath (Join-Path $script:Root 'engine\pro-data\Invoke-SIDataSync.ps1')
        $sync | Should -Match '(?s)Invoke-SIDataSyncCore .*Invoke-SIDataDuplicateCheck -Invoke \$invoke .*Invoke-SIDataQuality .*-DuplicateCheck \$global:SI_DuplicateCheckResult'
        $sync | Should -Match "Add-SIRunIssue -Issues \`$runIssues -Level WARNING -Text \`$dupIssue"
        $dq = Get-Content -Raw -LiteralPath (Join-Path $script:Root 'engine\pro-data\_shared\SI-DataQuality.ps1')
        $dq | Should -Match "-Kind 'dup'"
    }
    It 'never fails the data sync: a database error is one WARN line' {
        $log = New-Object System.Collections.Generic.List[string]
        $r = Invoke-SIDataDuplicateCheck -Invoke { param($s, $p, $m) if ($m -eq 'scalar' -and $s -like '*DuplicateCheckWork*') { return 1 }; throw 'boom' } -Index $script:Idx -Log { param($l, $m) $log.Add("$l $m") }.GetNewClosure()
        $r.Status | Should -Be 'failed'
        ($log -join "`n") | Should -Match 'WARN duplicates  : the duplicate check was not completed this run -- .*boom.*Nothing was blocked'
    }
    It 'without the tables it says so and checks nothing' {
        $r = Invoke-SIDataDuplicateCheck -Invoke { param($s, $p, $m) 0 } -Index $script:Idx -Log { param($l, $m) }
        $r.Status | Should -Be 'no-schema'
    }
}

Describe 'the gate on the DEFAULT path (#1366 P2): the findings per CI made from the database merge as the publish path does' {
    # The known shapes as Risk Analysis stores them (sidata.Finding, keyed per row with the shipped equivalence -- RaFindingKey),
    # through the data sync's own database statement (Get-SIDataCiFindingFromDbSql, the #774 / #829 default path) into the
    # findings per CI; the detector must find NOTHING left -- exactly as on the publish path above. A merge rule that runs only
    # on one path makes this red (the fold of #693 ran only on the Log Analytics copy until #1364).
    BeforeAll {
        if (-not $script:LocalSql) { return }
        . (Join-Path $script:Root 'engine\pro-data\_shared\SI-DataCi.ps1')
        $script:Db2 = 'si_dupchk2_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
        $m = [System.Data.SqlClient.SqlConnection]::new("Server=$($env:SI_TEST_LOCALSQL);Database=master;$($env:SI_TEST_SQL_AUTH);Connection Timeout=30")
        $m.Open(); try { $c = $m.CreateCommand(); $c.CommandText = "CREATE DATABASE [$script:Db2]"; $c.CommandTimeout = 300; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
        $script:Cn2 = [System.Data.SqlClient.SqlConnection]::new("Server=$($env:SI_TEST_LOCALSQL);Database=$script:Db2;$($env:SI_TEST_SQL_AUTH);Connection Timeout=30;Pooling=false")
        $script:Cn2.Open()
        function script:Sql2([string]$Text, [hashtable]$P = @{}, [string]$Mode = 'nonquery') {
            $c = $script:Cn2.CreateCommand(); $c.CommandText = $Text; $c.CommandTimeout = 0
            foreach ($k in $P.Keys) { [void]$c.Parameters.AddWithValue('@' + $k, $(if ($null -eq $P[$k]) { [DBNull]::Value } else { $P[$k] })) }
            if ($Mode -eq 'scalar') { return $c.ExecuteScalar() }
            if ($Mode -eq 'reader') {
                $rd = $c.ExecuteReader(); $rows = New-Object System.Collections.Generic.List[object]
                try { while ($rd.Read()) { $h = @{}; for ($i = 0; $i -lt $rd.FieldCount; $i++) { $h[$rd.GetName($i)] = $rd.GetValue($i) }; $rows.Add($h) } } finally { $rd.Dispose() }
                return , $rows.ToArray()
            }
            [void]$c.ExecuteNonQuery()
        }
        $script:SetupError2 = $null
        try {
            Sql2 ([IO.File]::ReadAllText((Join-Path $script:Root 'sql\si-pro-settings.sql')))
            Sql2 ([IO.File]::ReadAllText((Join-Path $script:Root 'sql\si-vulnerability-target.sql'))); Sql2 $script:Schema
            $cid = [int](Sql2 "INSERT sidata.Collection (CollectionTime, Kind, Status, ContextAt) VALUES ('2026-11-24T21:27:18', 'Detailed', 'Complete', SYSUTCDATETIME()); SELECT CAST(SCOPE_IDENTITY() AS int)" @{} 'scalar')
            foreach ($ci in 'ci-1', 'ci-2') { Sql2 "INSERT sidata.Ci (CiId, Class, Name, Tier, Lifecycle, CollectionTime) VALUES (@i, 'device', @i, 1, 'active', '2026-11-24')" @{ i = $ci } }
            $seq = 0
            foreach ($r in $script:Rows) {
                $seq++
                $rk = Get-SIFindingGroupKey -Row $r -Equivalence $script:Idx
                $prod = [string]$r.PSObject.Properties['si_affected_product'].Value
                $det = '{"si_affected_product":"' + $prod + '"}'
                Sql2 @'
INSERT sidata.Finding (CollectionId, AssetKey, AssetName, ReportName, SecurityDomain, ConfigurationId, Cve, Title, Severity, Tier, RiskScore, AffectedProduct, RaFindingKey, RaSeq, DetailJson)
VALUES (@c, @a, @a, @rep, N'Endpoint', @k, @cve, @t, @s, 1, 20, @p, @rk, @q, @d)
'@ @{ c = $cid; a = [string]$r.si_ci_id; rep = [string]$r.ReportName; k = [string]$r.ConfigurationId; cve = $(if ($r.ConfigurationId -match '^CVE-') { $r.ConfigurationId } else { $null })
      t = [string]$r.ConfigurationName; s = [string]$r.SecuritySeverity; p = $(if ($prod) { $prod } else { $null }); rk = $rk; q = [long]$seq; d = $det }
            }
            # the data sync's own order (#1364): the meaning rules move an evidence finding out of sidata.Finding first, then
            # the findings per CI are made
            . (Join-Path $script:Root 'engine\pro-data\_shared\SI-DataFindingFold.ps1')
            $fold = Invoke-SIDataFindingFold -Invoke { param($s, $p, $m) Sql2 $s $p $m } -CollectionId $cid -Equivalence $script:Idx -Log { param($l, $m) }
            if ($fold.Status -ne 'ok') { throw ('the fold step: ' + $fold.Status + ' ' + $fold.Error) }
            $null = Sql2 (Get-SIDataCiFindingFromDbSql) @{ CollectionId = [string]$cid; B0 = '50'; B1 = '30'; B2 = '15' } 'scalar'
            Sql2 @'
INSERT sidata.CiFinding (CiId, AssetId, FindingKey, FindingType, Title, Severity, Tier, RiskScore, WeightedRiskScore, RiskRating, SecurityDomain, DetectedBy, RiskFactors, ExemptionId, CollectionTime, DocJson)
SELECT CiId, AssetId, FindingKey, FindingType, Title, Severity, Tier, RiskScore, WeightedRiskScore, RiskRating, SecurityDomain, DetectedBy, RiskFactors, ExemptionId, CollectionTime, DocJson FROM sidata.CiFindingStage
'@
        } catch { $script:SetupError2 = $_.Exception.Message }
    }
    AfterAll {
        if (-not $script:LocalSql) { return }
        try { $script:Cn2.Dispose() } catch { }
        $m = [System.Data.SqlClient.SqlConnection]::new("Server=$($env:SI_TEST_LOCALSQL);Database=master;$($env:SI_TEST_SQL_AUTH);Connection Timeout=30")
        $m.Open(); try { $c = $m.CreateCommand(); $c.CommandText = "ALTER DATABASE [$script:Db2] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$script:Db2]"; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
    }
    It 'no duplicate is left in the findings per CI made from the database (the same as the publish path)' {
        if (-not $script:LocalSql) { Set-ItResult -Skipped -Because 'needs SI_TEST_LOCALSQL'; return }
        $script:SetupError2 | Should -BeNullOrEmpty
        [int](Sql2 'SELECT COUNT(*) FROM sidata.CiFinding' @{} 'scalar') | Should -BeGreaterThan 0
        $r = Invoke-SIDataDuplicateCheck -Invoke { param($s, $p, $m) Sql2 $s $p $m } -Index $script:Idx -NoStore -Log { param($l, $m) }
        $r.Status | Should -Be 'ok'
        (@($r.Items) | ForEach-Object { Format-SIDuplicateExample $_ }) -join ' || ' | Should -BeNullOrEmpty
    }
}

Describe 'on a real SQL Server: findings made from the database, the tasks, ranges and facts' {
    BeforeAll {
        if (-not $script:LocalSql) { return }
        $script:Db = 'si_dupchk_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
        $m = [System.Data.SqlClient.SqlConnection]::new("Server=$($env:SI_TEST_LOCALSQL);Database=master;$($env:SI_TEST_SQL_AUTH);Connection Timeout=30")
        $m.Open(); try { $c = $m.CreateCommand(); $c.CommandText = "CREATE DATABASE [$script:Db]"; $c.CommandTimeout = 300; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
        $script:Cn = [System.Data.SqlClient.SqlConnection]::new("Server=$($env:SI_TEST_LOCALSQL);Database=$script:Db;$($env:SI_TEST_SQL_AUTH);Connection Timeout=30;Pooling=false")
        $script:Cn.Open()
        function script:Sql([string]$Text, [hashtable]$P = @{}, [string]$Mode = 'nonquery') {
            $c = $script:Cn.CreateCommand(); $c.CommandText = $Text; $c.CommandTimeout = 0
            foreach ($k in $P.Keys) { [void]$c.Parameters.AddWithValue('@' + $k, $(if ($null -eq $P[$k]) { [DBNull]::Value } else { $P[$k] })) }
            if ($Mode -eq 'scalar') { return $c.ExecuteScalar() }
            if ($Mode -eq 'reader') {
                $rd = $c.ExecuteReader(); $rows = New-Object System.Collections.Generic.List[object]
                try { while ($rd.Read()) { $h = @{}; for ($i = 0; $i -lt $rd.FieldCount; $i++) { $h[$rd.GetName($i)] = $rd.GetValue($i) }; $rows.Add($h) } } finally { $rd.Dispose() }
                return , $rows.ToArray()
            }
            [void]$c.ExecuteNonQuery()
        }
        $script:Seam = { param($s, $p, $m) Sql $s $p $m }
        $script:Writes = New-Object System.Collections.Generic.List[string]
        $script:ReadSeam = { param($s, $p, $m) if ($m -notin 'reader', 'scalar') { $script:Writes.Add($m) }; Sql $s $p $m }
        $script:Ct = '2026-11-24T21:27:18'
        $script:SetupError = $null
        try {
            Sql ([IO.File]::ReadAllText((Join-Path $script:Root 'sql\si-pro-settings.sql')))
            Sql ([IO.File]::ReadAllText((Join-Path $script:Root 'sql\si-vulnerability-target.sql'))); Sql $script:Schema; Sql $script:Schema
            $script:Cid = [int](Sql "INSERT sidata.Collection (CollectionTime, Kind, Status, ContextAt, RemediationTasksAt) VALUES (@t, 'Detailed', 'Complete', SYSUTCDATETIME(), SYSUTCDATETIME()); SELECT CAST(SCOPE_IDENTITY() AS int)" @{ t = $script:Ct } 'scalar')
            foreach ($ci in 'ci-a', 'ci-b', 'ci-c', 'ci-d') { Sql "INSERT sidata.Ci (CiId, Class, Name, Tier, Lifecycle, CollectionTime) VALUES (@i, 'device', @n, 1, 'active', '2026-11-24')" @{ i = $ci; n = ($ci + '.contoso.test') } }
            # findings per CI as the database path makes them: no si_affected_product in the document
            function script:CiF([string]$Ci, [string]$Key, [string]$Type, [string]$Title, [string]$Extra = '') {
                $doc = '{"si_ci_id":"' + $Ci + '","si_finding_key":"' + $Key + '","si_finding_type":"' + $Type + '","si_title":"' + $Title + '","si_finding_source":"database"' + $Extra + '}'
                Sql "INSERT sidata.CiFinding (CiId, AssetId, FindingKey, FindingType, Title, Severity, CollectionTime, DocJson) VALUES (@c, N'', @k, @ty, @ti, N'high', @t, @d)" @{ c = $Ci; k = $Key; ty = $Type; ti = $Title; t = $script:Ct; d = $doc }
            }
            function script:F([string]$Ci, [string]$Key, [string]$Prod) {
                Sql "INSERT sidata.Finding (CollectionId, AssetKey, ReportName, ConfigurationId, Cve, Title, Severity, AffectedProduct, RaFindingKey) VALUES (@cid, @c, N'R', @k, @cve, N't', N'High', @p, @rk)" @{
                    cid = $script:Cid; c = $Ci; k = $Key; cve = $(if ($Key -match '^CVE-') { $Key } else { $null }); p = $(if ($Prod) { $Prod } else { $null }); rk = ($Ci + '|' + $Key.ToLowerInvariant()) }
            }
            # ci-a: Defender for Cloud "Update openssl" next to two openssl CVEs (the fold missed it) + the NLA pair (the key group missed it)
            CiF 'ci-a' 'CVE-2025-1001' 'cve' 'OpenSSL flaw'; F 'ci-a' 'CVE-2025-1001' 'openssl'
            CiF 'ci-a' 'CVE-2025-1002' 'cve' 'OpenSSL flaw 2'; F 'ci-a' 'CVE-2025-1002' 'openssl;libssl'
            CiF 'ci-a' 'mdc-upd-openssl' 'recommendation' 'Update openssl'; F 'ci-a' 'mdc-upd-openssl' ''
            CiF 'ci-a' 'scid-45' 'recommendation' 'Require Network Level Authentication'; F 'ci-a' 'scid-45' ''
            CiF 'ci-a' 'a5a0d2d3-909d-4954-a083-4fb40fcdc181' 'recommendation' 'NLA'; F 'ci-a' 'a5a0d2d3-909d-4954-a083-4fb40fcdc181' ''
            # ci-b: the same CVE twice; ci-c: "Update chrome" without a chrome CVE (no duplicate)
            CiF 'ci-b' 'CVE-2025-5000' 'cve' 'x'; F 'ci-b' 'CVE-2025-5000' 'zlib'
            CiF 'ci-b' 'tvm-5000' 'recommendation' 'y' ',"si_cve":"CVE-2025-5000"'; F 'ci-b' 'tvm-5000' ''
            CiF 'ci-c' 'mdc-upd-chrome' 'recommendation' 'Update chrome'; F 'ci-c' 'mdc-upd-chrome' ''
            CiF 'ci-c' 'CVE-2025-6000' 'cve' 'z'; F 'ci-c' 'CVE-2025-6000' 'edge'
            CiF 'ci-d' 'CVE-2025-7000' 'cve' 'z'; F 'ci-d' 'CVE-2025-7000' 'nodejs'
            # the tasks of the collection
            function script:T([string]$Owner, [string]$Name, [string]$Kind, [string]$Prod, [string]$State = 'open') {
                Sql @'
INSERT sidata.RemediationTask (CollectionId, TaskId, OwnerKey, CiId, AssetKey, AssetName, TaskKey, TaskName, Kind, Product, Findings, Cves, Departments, FirstSeen, LastSeen, State, InThisCollection, RowHash, ChangedAt)
VALUES (@c, HASHBYTES('SHA2_256', @o + N'|' + @n), @o, @o, @o, @an, LOWER(@k + N'|' + @n), @n, @k, @p, 1, 0, 0, SYSUTCDATETIME(), SYSUTCDATETIME(), @s, 1, 0x00, SYSUTCDATETIME())
'@ @{ c = $script:Cid; o = $Owner; an = ($Owner + '.contoso.test'); n = $Name; k = $Kind; p = $(if ($Prod) { $Prod } else { $null }); s = $State }
            }
            T 'ci-a' 'Update openssl' 'configuration' ''
            T 'ci-a' 'Update GitHub Desktop (bundles openssl 3.5.5.0)' 'bundled-upgrade' 'openssl'
            T 'ci-a' 'Update .net' 'configuration' ''
            T 'ci-a' 'Update .net 10.0.9.0 (microsoft)' 'software-upgrade' '.net'
            T 'ci-a' 'Update .net 8.0.26.0 (microsoft)' 'software-upgrade' '.net'
            T 'ci-c' 'Update chrome' 'configuration' ''
            T 'ci-c' 'Update chrome 1.0 (google)' 'software-upgrade' 'chrome' 'closed'
            # a task whose software is known only from its finding's affected product (a security update)
            T 'ci-d' 'Update nodejs' 'configuration' ''
            T 'ci-d' 'Security update KB1' 'security-update' ''
            $fid = [long](Sql "SELECT FindingId FROM sidata.Finding WHERE CollectionId = @c AND RaFindingKey = N'ci-d|cve-2025-7000'" @{ c = $script:Cid } 'scalar')
            Sql "INSERT sidata.RemediationTaskFinding (CollectionId, TaskId, FindingKey, OwnerKey, FindingId, Cve, InThisCollection) VALUES (@c, HASHBYTES('SHA2_256', N'ci-d|Security update KB1'), N'CVE-2025-7000', N'ci-d', @f, N'CVE-2025-7000', 1)" @{ c = $script:Cid; f = $fid }
        } catch { $script:SetupError = $_.Exception.Message }
    }
    AfterAll {
        if (-not $script:LocalSql) { return }
        try { $script:Cn.Dispose() } catch { }
        $m = [System.Data.SqlClient.SqlConnection]::new("Server=$($env:SI_TEST_LOCALSQL);Database=master;$($env:SI_TEST_SQL_AUTH);Connection Timeout=30")
        $m.Open(); try { $c = $m.CreateCommand(); $c.CommandText = "ALTER DATABASE [$script:Db] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$script:Db]"; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
    }
    It 'finds every unmerged shape, a CI range and a FindingId range at a time; stores the counts and examples; leaves no work row' {
        if (-not $script:LocalSql) { Set-ItResult -Skipped -Because 'needs SI_TEST_LOCALSQL'; return }
        $script:SetupError | Should -BeNullOrEmpty
        $lines = New-Object System.Collections.Generic.List[string]
        $r = Invoke-SIDataDuplicateCheck -Invoke $script:Seam -Index $script:Idx -CisPerRange 1 -OwnersPerPage 1 -FindingIdsPerRange 2 -Log { param($l, $m) $lines.Add("$l $m") }.GetNewClosure()
        $r.Status | Should -Be 'ok'
        $by = @{}; foreach ($x in $r.Rules) { $by[$x.Id] = $x }
        $by['fold:mdc-update-software-on-mde-cve'].Duplicates | Should -Be 1
        $by['fold:mdc-update-software-on-mde-cve'].Examples[0].title | Should -Be 'Update openssl'
        $by['fold:mdc-update-software-on-mde-cve'].Examples[0].onto | Should -Be 2
        $by['key'].Duplicates | Should -Be 1
        $by['same-cve'].Duplicates | Should -Be 1
        $by['same-cve'].Examples[0].key | Should -Be 'tvm-5000'
        # openssl (product of the bundled task), .net (two versions = ONE duplicate of the "Update .net" task, not two), nodejs (a
        # security update known only by its finding); chrome's software task is closed: no duplicate
        $by['task-update-restates-software'].Duplicates | Should -Be 3
        $by['task-update-restates-software'].Owners | Should -Be 2
        @($by['task-update-restates-software'].Examples | ForEach-Object { $_.title } | Sort-Object) | Should -Be @('Update .net', 'Update nodejs', 'Update openssl')
        $r.Total | Should -Be 6
        ($lines -join "`n") | Should -Match "WARN duplicates  : 3 duplicate\(s\) on 2 asset\(s\) were not merged -- rule task-update-restates-software"
        # one row per checked rule, 0 included: two fold rules (#1369 eg-restates-mdc-recommendation), key, same-cve, the task rule
        [int](Sql 'SELECT COUNT(*) FROM sidata.DuplicateCheck WHERE CheckId = @i' @{ i = $r.CheckId } 'scalar') | Should -Be 5
        [int](Sql "SELECT Duplicates FROM sidata.DuplicateCheck WHERE CheckId = @i AND RuleId = N'task-update-restates-software'" @{ i = $r.CheckId } 'scalar') | Should -Be 3
        (Sql "SELECT ExamplesJson FROM sidata.DuplicateCheck WHERE CheckId = @i AND RuleId = N'fold:mdc-update-software-on-mde-cve'" @{ i = $r.CheckId } 'scalar') | Should -Match 'Update openssl'
        [int](Sql 'SELECT COUNT(*) FROM sidata.DuplicateCheckWork' @{} 'scalar') | Should -Be 0
        @($r.Metrics | ForEach-Object Key) | Should -Contain 'dup.task-update-restates-software'
    }
    It 'the read-only mode (the diagnostics) finds the same and writes nothing' {
        if (-not $script:LocalSql) { Set-ItResult -Skipped -Because 'needs SI_TEST_LOCALSQL'; return }
        $before = [int](Sql 'SELECT COUNT(*) FROM sidata.DuplicateCheck' @{} 'scalar')
        $script:Writes.Clear()
        $r = Invoke-SIDataDuplicateCheck -Invoke $script:ReadSeam -ReadOnly -Index $script:Idx -CisPerRange 2 -Log { param($l, $m) }
        $r.Status | Should -Be 'ok'
        $r.Total | Should -Be 6
        @($script:Writes).Count | Should -Be 0
        [int](Sql 'SELECT COUNT(*) FROM sidata.DuplicateCheck' @{} 'scalar') | Should -Be $before
    }
    It 'once the duplicates are merged it finds 0 (and says so as OK)' {
        if (-not $script:LocalSql) { Set-ItResult -Skipped -Because 'needs SI_TEST_LOCALSQL'; return }
        # as the merge leaves them: the folded / linked findings and the restating tasks are gone; the canonical keeps evidence
        Sql "DELETE FROM sidata.CiFinding WHERE FindingKey IN (N'mdc-upd-openssl', N'a5a0d2d3-909d-4954-a083-4fb40fcdc181', N'tvm-5000')"
        Sql "UPDATE sidata.CiFinding SET DocJson = JSON_MODIFY(DocJson, '$.si_finding_evidence', JSON_QUERY(N'[{""report"":""R"",""key"":""mdc-upd-openssl"",""rule"":""mdc-update-software-on-mde-cve""}]')) WHERE FindingKey = N'CVE-2025-1001'"
        Sql "DELETE FROM sidata.RemediationTask WHERE TaskName IN (N'Update openssl', N'Update .net', N'Update nodejs')"
        $lines = New-Object System.Collections.Generic.List[string]
        $r = Invoke-SIDataDuplicateCheck -Invoke $script:Seam -Index $script:Idx -Log { param($l, $m) $lines.Add("$l $m") }.GetNewClosure()
        $r.Total | Should -Be 0
        $r.Issue | Should -BeNullOrEmpty
        ($lines -join "`n") | Should -Match '^OK duplicates  : no duplicate finding or task'
    }
}
