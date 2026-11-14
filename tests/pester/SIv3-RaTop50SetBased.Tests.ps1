#Requires -Version 5.1
<#
    #1212 -- THE TOP 50 LISTS AND THE KEY FIGURES ARE WORKED OUT IN THE DATABASE, NOT ROW BY ROW (owner 2026-11-12).

    Live (a large ring-2 install, 3.1.8): after the last report the coordinator read every stored row back into PowerShell
    ("the AI summary and key figures read the rows"): ~5,400 rows a minute, ~4 h for 1.35 M rows. engine\risk-analysis\
    _shared\RA-TopListsSql.ps1 works the same lists and figures out set-based (a narrow work table, GROUP BY / ORDER BY / TOP).

    THE PROOF (real SQL Server): the SAME stored rows -- written through the engine's own stream path (New-RAStream,
    Write-RAStreamRows, Complete-RAStreamReport), a held report, rows outside the view -- through
      OLD  the row-by-row rollup exactly as it is in Invoke-RiskAnalysis.ps1 (its region between the '>>> / <<< THE ROW-BY-ROW
           ROLLUP' marks and its helper functions, run as they are) + the key figures' block (Invoke-RAKpiPass);
      NEW  Invoke-RATopListsInSql;
    compared field by field: the Top 50 assets and findings in the same order INCLUDING exact ties, every sum / count /
    first-seen value, the items, domains, hottest assets, links (AI on), the executive view's shape, and every key figure
    incl. the patch cycle. The fixture reaches every branch the lists read (asserted first).
    NEGATIVE: with the AI summary on the AI prompt's own inputs (links, cmdb id / data sensitivity, the asset count per
    finding) are there and equal; with it off they are not worked out at all -- and the executive view still gets every
    list. A row of a shape the database form does not mirror (an asset LIST) declines: nothing is used, the row loop runs.
    The timing of both on a larger fixture is printed ('[#1212 timing]'). NO EMOJI IN THIS FILE.
#>

BeforeDiscovery {
    $script:OnTestVm = ($PSScriptRoot -like 'C:\work\si\*') -or ($PSScriptRoot -like 'C:\work\si-*')
    $script:SqlUp = $false
    if ($env:SI_TEST_LOCALSQL -or $script:OnTestVm) {
        for ($try = 0; $try -lt 6 -and -not $script:SqlUp; $try++) {
            try { $p = New-Object System.Data.SqlClient.SqlConnection "Server=$($env:SI_TEST_LOCALSQL);Database=master;$($env:SI_TEST_SQL_AUTH);Connection Timeout=60"; $p.Open(); $p.Dispose(); $script:SqlUp = $true } catch { Start-Sleep -Seconds 5 }
        }
    }
    $root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:HasSql = ($script:SqlUp -or $script:OnTestVm) -and (Test-Path -LiteralPath ([IO.Path]::Combine($root, 'sql', 'si-data-schema.sql')))
}

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    # the stream path's functions, exactly as the scale-out equivalence suite loads them (its harness text, taken as it is)
    $eq = Join-Path $PSScriptRoot 'SIv3-RaScaleOutEquivalence.Tests.ps1'
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($eq, [ref]$null, [ref]$null)
    $script:LibText = ($ast.Find({ param($x) $x -is [System.Management.Automation.Language.AssignmentStatementAst] -and $x.Left.Extent.Text -eq '$script:LibText' }, $true)).Right.Expression.Value
    . ([scriptblock]::Create($script:LibText)) -SIRoot $script:SIRoot
    $ra = Join-Path $script:SIRoot 'engine\risk-analysis\_shared'
    foreach ($f in 'RA-RunProgress.ps1', 'RA-AISummaryMode.ps1', 'RA-KpiTally.ps1', 'RA-TopListsSql.ps1', 'RA-ExecView.ps1') { . (Join-Path $ra $f) }
    function script:Write-Info { param($m) }
    function script:Write-Warn2 { param($m) }

    $script:Engine = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'))
    $script:TopText = [IO.File]::ReadAllText((Join-Path $ra 'RA-TopListsSql.ps1'))
    # THE ROW-BY-ROW ROLLUP as the engine has it: its helpers (by the AST) and its region (between the marks)
    $eAst = [System.Management.Automation.Language.Parser]::ParseInput($script:Engine, [ref]$null, [ref]$null)
    $script:OldHelpers = (@('Test-LooksLikeHost', 'Split-ImpactedAssets', 'Get-RARowAssetKeys') | ForEach-Object {
        $n = $_; ($eAst.Find({ param($x) $x -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $x.Name -eq $n }, $true)).Extent.Text }) -join "`n"
    $a = $script:Engine.IndexOf('# >>> THE ROW-BY-ROW ROLLUP'); $b = $script:Engine.IndexOf('# <<< THE ROW-BY-ROW ROLLUP')
    $script:OldRegion = $(if ($a -gt 0 -and $b -gt $a) { $script:Engine.Substring($a, $b - $a) } else { '' })

    $script:SavedGlobals = @{}
    foreach ($g in 'ReportTemplate', 'SI_ProSettingsVersion', 'FinalRiskScoreColumnName', 'SI_RiskReport_TierMultiplier_T0') { $script:SavedGlobals[$g] = (Get-Variable -Name $g -Scope Global -ValueOnly -ErrorAction SilentlyContinue) }
    $global:ReportTemplate = 'RiskAnalysis_Detailed'; $global:SI_ProSettingsVersion = 'test'; $global:FinalRiskScoreColumnName = $null

    # one text for a result (keys sorted, numbers invariant round-trip) -- two results are identical when their texts are
    function script:ConvertTo-Canon {
        param($o)
        if ($null -eq $o) { return 'null' }
        if ($o -is [System.Collections.IDictionary]) { return '{' + ((@($o.Keys) | Sort-Object | ForEach-Object { "$_=" + (ConvertTo-Canon $o[$_]) }) -join ',') + '}' }
        if ($o -is [string]) { return '"' + $o + '"' }
        if ($o -is [System.Management.Automation.PSCustomObject]) { return '{' + ((@($o.PSObject.Properties) | Sort-Object Name | ForEach-Object { $_.Name + '=' + (ConvertTo-Canon $_.Value) }) -join ',') + '}' }
        if ($o -is [System.Collections.IEnumerable]) { return '[' + ((@($o) | ForEach-Object { ConvertTo-Canon $_ }) -join ',') + ']' }
        if ($o -is [double]) { return $o.ToString('R', [System.Globalization.CultureInfo]::InvariantCulture) }
        [string]$o
    }
    # where two canonical texts first differ (new vs old), with a little around it -- what a failure shows
    function script:Get-CanonDiff([string]$New, [string]$Old) {
        $n = [Math]::Min($New.Length, $Old.Length); $p = 0
        while ($p -lt $n -and $New[$p] -eq $Old[$p]) { $p++ }
        $s = [Math]::Max(0, $p - 120)
        'new ...{0}... | old ...{1}...' -f $New.Substring($s, [Math]::Min(260, $New.Length - $s)), $Old.Substring($s, [Math]::Min(260, $Old.Length - $s))
    }
    # what each consumer reads of an asset / a finding (-Ai: also what only the AI prompt reads)
    function script:Get-AssetFace($a, [bool]$Ai) {
        $h = [ordered]@{ Asset = [string]$a.Asset; AssetKey = [string]$a.AssetKey; TierLevel = [string]$a.TierLevel; Findings = [int]$a.Findings
                         TotalRiskScore = [double]$a.TotalRiskScore; TotalRiskScore_Weighted = [double]$a.TotalRiskScore_Weighted
                         CmdbName = [string]$a.CmdbName; CmdbCriticality = [string]$a.CmdbCriticality; Domains = @($a.Domains); TopItems = @($a.TopItems) }
        if ($Ai) { $h.CmdbId = [string]$a.CmdbId; $h.CmdbDataSensitivity = [string]$a.CmdbDataSensitivity; $h.Links = @($a.Links) }
        [pscustomobject]$h
    }
    function script:Get-FindingFace($f, [bool]$Ai) {
        $ev = ConvertTo-RAExecViewFinding -Finding $f -Rank 1
        $h = [ordered]@{ ConfId = [string]$f.ConfId; ConfName = [string]$f.ConfName; Category = [string]$f.Category; Subcategory = [string]$f.Subcategory
                         Severity = [string]$f.Severity; Domain = [string]$f.Domain; AffectedAssetCount = [int]$f.AffectedAssetCount
                         TotalRiskScore = [double]$f.TotalRiskScore; TotalRiskScore_Weighted = [double]$f.TotalRiskScore_Weighted; Hottest = @($ev.TopAffectedAssets) }
        if ($Ai) {
            $h.Links = @($f.Links)
            $h.AssetsInAll = $(if ($f.PSObject.Properties['AssetRiskScoreCount']) { [int]$f.AssetRiskScoreCount } else { [int]$f.AssetRiskScores.Count })
        }
        [pscustomobject]$h
    }
}

AfterAll {
    foreach ($g in $script:SavedGlobals.Keys) { Set-Variable -Name $g -Scope Global -Value $script:SavedGlobals[$g] }
}

Describe '#1212: what the database form reads, and when it declines (pure)' {
    It 'the AI-only values are read ONLY with the AI summary on: links, cmdb id, data sensitivity' {
        $off = Get-RATopReadNames -WithAi $false; $on = Get-RATopReadNames -WithAi $true
        foreach ($n in 'MoreDetails', 'cmdbId', 'CmdbId', 'cmdbDataSensitivity', 'CmdbDataSensitivity') {
            $off -ccontains $n | Should -BeFalse -Because "$n is read only by the AI prompt"
            $on -ccontains $n | Should -BeTrue
        }
        foreach ($n in 'RiskScoreTotal_Weighted', 'RiskScoreTotal', 'CriticalityTierLevel', 'ConfigurationId', 'AssetName', 'cmdbName', 'cmdbCriticality', 'SecuritySeverity', 'si_patch_cycle', 'ImpactedAssetCount') {
            $off -ccontains $n | Should -BeTrue -Because "$n is read by the executive view or the key figures"
        }
        $sqlOff = Get-RATopRangeSql -CollectionId 7 -Lo 0 -Hi 10 -WithAi $false
        $sqlOn = Get-RATopRangeSql -CollectionId 7 -Lo 0 -Hi 10 -WithAi $true
        # the view rows of the run, held reports left out (the pager's own filter) -- never a changed view condition
        $sqlOff | Should -Match 'AND f\.RaSeq IS NOT NULL AND f\.RaInView = 1;'
        (Get-RATopRangeSql -CollectionId 7 -Lo 0 -Hi 10 -Held @(4, 2) -WithAi $false) | Should -Match 'AND f\.RaInView = 1 AND f\.RaReport NOT IN \(2, 4\);'
        $sqlOff | Should -Not -Match 'MoreDetails'
        # a chain of two names that differ only in case reads BOTH keys (OPENJSON paths are case-sensitive)
        $names = Get-RATopReadNames -WithAi $false
        $iLow = @(for ($q = 0; $q -lt $names.Count; $q++) { if ($names[$q] -ceq 'Subcategory') { $q } })[0]; $iUp = @(for ($q = 0; $q -lt $names.Count; $q++) { if ($names[$q] -ceq 'SubCategory') { $q } })[0]
        $iLow | Should -Not -Be $iUp
        $sqlOff | Should -Match ([regex]::Escape(('COALESCE(b.n{0}, b.n{1}) AS Sub' -f $iLow, $iUp)))
        $sqlOn | Should -Match ([regex]::Escape("'$.""MoreDetails""'"))
        (Get-RATopAssetItemsSql -WithAi $false) | Should -Not -Match '''L'''
        (Get-RATopFindingItemsSql -WithAi $false) | Should -Not -Match '''L'''
        (Get-RATopAssetsSql -WithAi $false) | Should -Not -Match 'r\.CmId'
    }
    It 'a report whose column is a read column in another case is declined (OPENJSON reads exact names, PowerShell any case)' {
        $ok = [ordered]@{ R1 = @{ Columns = [System.Collections.Generic.List[string]]@('AssetName', 'SecuritySeverity', 'SubCategory', 'Other') } }
        Test-RATopListsColumns -Reports $ok -WithAi $false | Should -Be ''
        $bad = [ordered]@{ R1 = @{ Columns = [System.Collections.Generic.List[string]]@('AssetName', 'securityseverity') } }
        Test-RATopListsColumns -Reports $bad -WithAi $false | Should -Match "names its column 'securityseverity' in another case"
        # an AI-only column in another case matters only when the AI reads it
        $md = [ordered]@{ R1 = @{ Columns = [System.Collections.Generic.List[string]]@('moredetails') } }
        Test-RATopListsColumns -Reports $md -WithAi $false | Should -Be ''
        Test-RATopListsColumns -Reports $md -WithAi $true | Should -Not -Be ''
    }
    It 'NEVER THROWS and declines: no session seam, a Summary run, a Protection Score counted in the run' {
        $st = @{ Prot = $null; Patch = (New-SIPatchCycleTally) }
        $noSession = @{ Grain = 'Detailed'; CollectionId = 5; Reports = [ordered]@{}; Invoke = { param($Sql, $Params, $Mode, $OnRow) throw "SQL mode 'session' needs a step callback (OnRow)." } }
        $r = Invoke-RATopListsInSql -Stream $noSession -KpiState $st
        $r.Status | Should -Be 'declined'; $r.Why | Should -Match 'the database pass failed'
        (Invoke-RATopListsInSql -Stream @{ Grain = 'Summary'; CollectionId = 0; Invoke = { } } -KpiState $st).Status | Should -Be 'declined'
        (Invoke-RATopListsInSql -Stream $noSession -KpiState @{ Prot = 'counted'; Patch = $null }).Why | Should -Match 'Protection Score is counted'
        Format-RATopListsLine -Result $r | Should -Match '^Top 50 lists and key figures: read row by row as before \(the database pass failed'
    }
    It 'a tier text''s sort key is the row loop''s own (tier <n> -> n, else 99)' {
        foreach ($t in @('Critical - tier 0', 'High - Tier 1', 'tier12', 'Tier  3', '0', '', 'tiered', 'x tier 2 tier 1')) {
            $old = $(if ($t -match 'tier\s*(\d+)') { [int]$Matches[1] } else { 99 })
            Get-RATopTierSortKey -Text $t | Should -Be $old -Because "'$t'"
        }
    }
    It 'a group of rows with the same six values adds what the rows add one by one (Add-RAKpiRowFigures -Count)' {
        $rows = @(foreach ($i in 0..299) {
            [pscustomobject]@{ SecuritySeverity = @('Critical', 'High', 'medium', 'Low', '')[$i % 5]; SecurityDomain = @('Endpoint', 'PublicIp', '', 'Identity')[$i % 4]
                               Report = @('Device_X_Detailed', 'Identity_Y', 'Azure_Z')[$i % 3]; RiskScoreKPI = @(80, '55', $null)[$i % 3]; CriticalityTier = @(0, 1, '2', 3, 'x')[$i % 5]
                               ImpactedAssetCount = @(1, '5', $null, 12)[$i % 4] } })
        $one = New-RAKpiState; foreach ($r in $rows) { Add-RAKpiRowFigures -State $one -Row $r -Count 1 }
        $grp = New-RAKpiState
        foreach ($g in @($rows | Group-Object { '{0}|{1}|{2}|{3}|{4}|{5}' -f $_.SecuritySeverity, $_.SecurityDomain, $_.Report, $_.RiskScoreKPI, $_.CriticalityTier, $_.ImpactedAssetCount })) {
            Add-RAKpiRowFigures -State $grp -Row $g.Group[0] -Count $g.Count
        }
        $one.Rows = 300; $grp.Rows = 300
        (ConvertTo-Canon (Complete-RAKpiState -State $grp)) | Should -Be (ConvertTo-Canon (Complete-RAKpiState -State $one))
    }
    It 'a stored value comes back as the row decoder hands it over (a JSON number a number, a text a text)' {
        ConvertFrom-RATopStoredValue -Text '5' -AsJsonNumber $true | Should -BeOfType [long]
        ConvertFrom-RATopStoredValue -Text '5.0' -AsJsonNumber $true | Should -BeOfType [double]
        ConvertFrom-RATopStoredValue -Text '5.0' -AsJsonNumber $false | Should -Be '5.0'
        ConvertFrom-RATopStoredValue -Text 'n/a' -AsJsonNumber $true | Should -Be 'n/a'
        ConvertFrom-RATopStoredValue -Text $null -AsJsonNumber $true | Should -BeNullOrEmpty
    }
    It 'a mapping goes to the database as one JSON text; a score as its 64 bits (exact)' {
        foreach ($d in @(0.1, 12.5, 0.25, 7.0, -3.75, 1e-300, 123456789.123, 0.0, 9007199254740991.0)) {
            $me = ConvertTo-RATopExactDouble -Value $d
            ([double]$me.M * [Math]::Pow(2, $me.E)) | Should -Be $d -Because "$d is m x 2^e exactly"
            [Math]::Abs($me.M) | Should -BeLessThan 9007199254740992
        }
        { ConvertTo-RATopExactDouble -Value ([double]::NaN) } | Should -Throw
        $s = Get-RATopMapInsertSql -Table 'num' -SqlType 'float' -Pairs @(@{ H = 'AB'; V = 12.5 }) -Bits
        $s | Should -Match '"m":25,"e":-1'
        $s | Should -Match 'CONVERT\(float, m\.m\) \* POWER\(CONVERT\(float, 2\), m\.e\)'
        { Get-RATopMapInsertSql -Table 'x;drop' -SqlType 'int' -Pairs @() } | Should -Throw
        (Get-RATopMapInsertSql -Table 'cyc' -SqlType 'nvarchar(16)' -Pairs @(@{ H = 'AB'; V = "it's" })) | Should -Match "it''s"
    }
}

Describe '#1212: the engine wiring' {
    It 'a Detailed run with its result in SQL and the stored Protection Score works the lists out in the database first' {
        $script:Engine | Should -Match ([regex]::Escape(". (Join-Path `$PSScriptRoot '_shared/RA-TopListsSql.ps1')"))
        $script:Engine | Should -Match ([regex]::Escape("if (`$script:RAStreamOn -and `$null -ne `$script:RAStream -and [string]`$script:RAStream.Grain -eq 'Detailed' -and (Test-RAKpiProtectionFromStore)) {"))
        $script:Engine | Should -Match ([regex]::Escape('-Collapse $isDetailedTemplate -WithAi (-not $script:_RATopListsOnly)'))
        $script:Engine | Should -Match ([regex]::Escape('Write-Info (Format-RATopListsLine -Result $__sb)'))
        # the progress tick (#1180) while the rows are read in the database
        $script:Engine | Should -Match ([regex]::Escape("New-RAProgressTicker -Stream `$script:RAStream -What 'the Top 50 lists and key figures read the rows in the database'"))
        $script:TopText | Should -Match ([regex]::Escape('Step-SIStepProgressTicker -Ticker $Progress -Done $rows'))
        # paced by the database's own load
        $script:TopText | Should -Match ([regex]::Escape('Invoke-SISqlPacing -Invoke $inv -LastBatchMs $lastMs -Log $Log'))
    }
    It 'a declined pass leaves nothing behind: the row-by-row rollup runs as before (the else of the database pass)' {
        $script:OldRegion | Should -Not -BeNullOrEmpty
        $script:OldRegion | Should -Match ([regex]::Escape('$__aiPager = if ($script:RAStreamOn) { New-RARowPager -Stream $script:RAStream -Source View }'))
        $script:Engine | Should -Match '(?s)if \(\$null -ne \$__sb\) \{.{0,1800}\} else \{\s+# >>> THE ROW-BY-ROW ROLLUP'
        $script:Engine | Should -Match '(?s)# <<< THE ROW-BY-ROW ROLLUP\s+\}   # close #1212'
    }
    It 'equal assets / findings keep one order in the row loop too: where each first appears is the last sort key' {
        $script:OldRegion | Should -Match ([regex]::Escape('@{Expression="FirstSeen";Ascending=$true} |'))
        $script:OldRegion | Should -Match ([regex]::Escape('@{Expression="AffectedAssetCount";Descending=$true}, @{Expression="FirstSeen";Ascending=$true}'))
        $script:OldRegion | Should -Match 'FirstSeen\s+= \$assetAgg\.Count'
        $script:OldRegion | Should -Match 'FirstSeen\s+= \$findingAgg\.Count'
    }
    It 'the AI prompt reads the asset count of a finding from the database pass when it has one' {
        $script:Engine | Should -Match ([regex]::Escape("`$__arsN = if (`$f.PSObject.Properties['AssetRiskScoreCount']) { [int]`$f.AssetRiskScoreCount } else { [int]`$f.AssetRiskScores.Count }"))
        $script:Engine | Should -Match ([regex]::Escape('Asset rollup:   $($__assetsTotal) unique assets'))
    }
}

Describe '#1212: identical results -- the row-by-row rollup and the database form on the same stored rows (SQL Server)' -Skip:(-not $script:HasSql) {
    BeforeAll {
        $up = $false
        for ($try = 0; $try -lt 3 -and -not $up; $try++) {
            try { $p = New-Object System.Data.SqlClient.SqlConnection "Server=$($env:SI_TEST_LOCALSQL);Database=master;$($env:SI_TEST_SQL_AUTH);Connection Timeout=60"; $p.Open(); $p.Dispose(); $up = $true } catch { Start-Sleep -Seconds 5 }
        }
        if (-not $up) { throw 'SQL Server did not answer -- the proof did not run' }
        $script:Dbs = New-Object System.Collections.Generic.List[string]
        function script:New-Db([string]$Tag) {
            $name = 'si_test_top50_{0}_{1}' -f $Tag, [guid]::NewGuid().ToString('N').Substring(0, 6)
            $m = New-Object System.Data.SqlClient.SqlConnection "Server=$($env:SI_TEST_LOCALSQL);Database=master;$($env:SI_TEST_SQL_AUTH);Connection Timeout=30"
            $m.Open(); try { $c = $m.CreateCommand(); $c.CommandText = "CREATE DATABASE [$name]"; $c.CommandTimeout = 300; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
            $cn = New-Object System.Data.SqlClient.SqlConnection ("Server=$($env:SI_TEST_LOCALSQL);Database=$name;$($env:SI_TEST_SQL_AUTH);Connection Timeout=30;Pooling=false")
            $cn.Open(); try { foreach ($f in 'sql\si-data-schema.sql', 'sql\si-identity-schema.sql') { if (Test-Path -LiteralPath (Join-Path $script:SIRoot $f)) { $c = $cn.CreateCommand(); $c.CommandTimeout = 300; $c.CommandText = [IO.File]::ReadAllText((Join-Path $script:SIRoot $f)); [void]$c.ExecuteNonQuery() } } } finally { $cn.Dispose() }
            $script:Dbs.Add($name)
            $name
        }
        # the seam as the engine's (New-SIDataSqlInvoke): a connection per call; mode 'session' = ONE connection for the
        # caller's batches (#temp tables live from one to the next), its reader hands DBNull as $null
        function script:New-SessionSeam([string]$Db) {
            $cs = "Server=$($env:SI_TEST_LOCALSQL);Database=$Db;$($env:SI_TEST_SQL_AUTH);Connection Timeout=30;Pooling=false"
            { param($Sql, $Params, $Mode, $OnRow)
              $cn = New-Object System.Data.SqlClient.SqlConnection $cs; $cn.Open()
              try {
                  if ($Mode -eq 'session') {
                      $sc0 = $cn
                      $run = { param([string]$StepSql, [string]$StepMode)
                          $sc = $sc0.CreateCommand(); $sc.CommandText = $StepSql; $sc.CommandTimeout = 900
                          switch ($StepMode) {
                              'scalar' { $v = $sc.ExecuteScalar(); if ($v -is [System.DBNull]) { $null } else { $v } }
                              'reader' { $rd = $sc.ExecuteReader(); $out = New-Object System.Collections.Generic.List[object]
                                  try { while ($rd.Read()) { $h = @{}; for ($i = 0; $i -lt $rd.FieldCount; $i++) { $h[$rd.GetName($i)] = $(if ($rd.IsDBNull($i)) { $null } else { $rd.GetValue($i) }) }; $out.Add($h) } } finally { $rd.Close() }
                                  , $out.ToArray() }
                              default { [void]$sc.ExecuteNonQuery() }
                          } }.GetNewClosure()
                      return (& $OnRow $run)
                  }
                  $cmd = $cn.CreateCommand(); $cmd.CommandText = $Sql; $cmd.CommandTimeout = 900
                  if ($Params) { foreach ($k in $Params.Keys) { $v = $Params[$k]; [void]$cmd.Parameters.AddWithValue('@' + $k, $(if ($null -eq $v) { [System.DBNull]::Value } else { $v })) } }
                  switch ($Mode) {
                      { $_ -in 'reader', 'rows' } { $rd = $cmd.ExecuteReader(); $out = New-Object System.Collections.Generic.List[object]
                          try { while ($rd.Read()) { $h = @{}; for ($i = 0; $i -lt $rd.FieldCount; $i++) { $h[$rd.GetName($i)] = $rd.GetValue($i) }; $out.Add($h) } } finally { $rd.Close() }
                          , $out.ToArray() }
                      'scalar' { $cmd.ExecuteScalar() }
                      default { [void]$cmd.ExecuteNonQuery() }
                  }
              } finally { $cn.Dispose() } }.GetNewClosure()
        }

        # THE ROWS: every branch the lists and the figures read. Per asset: a name (a case twin with no id = the SAME asset;
        # a name with a comma; a trailing space; DeviceName only; none at all), an id or not (a blank one = by name), a tier
        # text (0..3, 'Tier2', blank, absent -> CriticalityTier as a number); per finding: CVE ids shared across assets (a
        # lower-case twin = the SAME finding, its CVE bucket collapsed per asset), non-CVE ids, 'CVE-2026-12a' (not a CVE),
        # scores with ties, a decimal comma and spaces in text, blank names (the first non-blank wins), cmdb values only on
        # later rows (first seen), reference texts with more than 6 links, an upper-case 'HTTP://' (no link), duplicates; the
        # key figures' severities / domains ('PublicIp', blank + report name) / tiers / ImpactedAssetCount (a number, a text,
        # 'n/a', absent) / RiskScoreKPI; the patch cycle's CVE rows with updates, a given cycle, an unknown month, no update.
        function script:New-Top50Rows([int]$Report, [int]$Assets, [int]$PerAsset, [int]$Seed) {
            $rng = [System.Random]::new($Seed)
            $tiers = @('Critical - tier 0', 'High - tier 1', 'Medium - tier 2', 'Low - tier 3', 'Tier2', '', $null)
            $sevs = @('Critical', 'Very High', 'High', 'Medium-High', 'Medium', 'Low', 'Informational', '')
            $doms = @('Endpoint', 'Identity', 'Azure', 'PublicIP', 'PublicIp', '', $null)
            $repNames = @('Device_Vulnerabilities_Detailed', 'Identity_Stale_Accounts', 'Attack_Paths_Public_IP_to_VM', 'Some_Other_Report')
            $updates = @(@('5127648', 'October 2026 Security Updates'), @('5124008', 'September 2026 Security Updates'), @('5040948', 'March 2025 Security Updates'), @('', ''), @('5099999', 'Cumulative update'))
            $ws = @(10, 20, 20, 30, 45, 45, 60, 90)
            $out = New-Object System.Collections.Generic.List[object]
            for ($a = 0; $a -lt $Assets; $a++) {
                $tier = $tiers[$a % $tiers.Count]
                for ($c = 0; $c -lt $PerAsset; $c++) {
                    $h = [ordered]@{}
                    # the asset
                    if ($a % 29 -eq 7) { }                                          # no asset at all
                    elseif ($a % 13 -eq 5) { $h['DeviceName'] = ('dev{0}.contoso.test' -f $a) }
                    elseif ($a % 17 -eq 3) { $h['AssetName'] = 'HOST-TWIN' }
                    elseif ($a % 17 -eq 4) { $h['AssetName'] = 'host-twin' }
                    elseif ($a % 19 -eq 6) { $h['AssetName'] = 'Doe, Jane (Admin)' }
                    elseif ($a % 23 -eq 8) { $h['AssetName'] = (' host{0} ' -f $a) }
                    else { $h['AssetName'] = ('host{0}' -f $a) }
                    if ($a % 3 -eq 0 -and $a % 17 -ne 3 -and $a % 17 -ne 4) { $h['AssetId'] = ('AID-{0:d4}' -f $a) } elseif ($a % 11 -eq 2) { $h['AssetId'] = '   ' }
                    $h['SI_AssetId'] = ('aid-{0}' -f $a); $h['si_ci_id'] = ('ci-{0}' -f ($a % 37))
                    if ($null -ne $tier) { $h['CriticalityTierLevel'] = $tier }
                    $h['CriticalityTier'] = @(0, 1, 2, 3, '2', 'x')[($a + $c) % 6]
                    # the finding
                    $k = $rng.Next(0, 90)
                    if ($k -lt 50) { $cid = ('CVE-2026-{0:d4}' -f ($k % 25)); if ($k % 7 -eq 0) { $cid = $cid.ToLowerInvariant() } }
                    elseif ($k -lt 80) { $cid = ('scid-{0}' -f ($k % 30)) }
                    elseif ($k -lt 85) { $cid = 'CVE-2026-12a' }
                    else { $cid = ('Rec-{0}' -f ($k % 4)) }
                    $h['ConfigurationId'] = $cid
                    $h['ConfigurationName'] = $(if ($rng.Next(0, 9) -eq 0) { '   ' } else { 'Fix ' + $cid.ToUpperInvariant() })
                    $h['Category'] = @('Vulnerabilities', 'Configuration', 'Identity')[$k % 3]
                    if ($k % 5 -ne 0) { $h['Subcategory'] = @('CVEs', 'Hardening')[$k % 2] } else { $h['SubCategory'] = 'Mixed' }
                    $h['SecuritySeverity'] = $sevs[$rng.Next(0, $sevs.Count)]
                    if ($h['SecuritySeverity'] -eq '') { $h['Severity'] = 'High' }
                    $d = $doms[$rng.Next(0, $doms.Count)]; if ($null -ne $d) { $h['SecurityDomain'] = $d }
                    $h['Report'] = $repNames[($Report + $c) % $repNames.Count]
                    $h['RiskScoreTotal_Weighted'] = $ws[$rng.Next(0, $ws.Count)]
                    $h['RiskScoreTotal'] = @(12, 12.5, '12,5', ' 7 ', 30, 0.25)[$rng.Next(0, 6)]
                    $h['RiskScoreKPI'] = @(80, 55, '40', 100)[$rng.Next(0, 4)]
                    $iac = $rng.Next(0, 5); if ($iac -eq 0) { $h['ImpactedAssetCount'] = 1 } elseif ($iac -eq 1) { $h['ImpactedAssetCount'] = '5' } elseif ($iac -eq 2) { $h['ImpactedAssetCount'] = 'n/a' } elseif ($iac -eq 3) { $h['ImpactedAssetCount'] = 12 }
                    if ($c -gt 0 -and $a % 4 -eq 1) { $h['cmdbName'] = ('Svc-{0}' -f ($a % 9)); $h['cmdbCriticality'] = @('High', 'Low')[$a % 2]; $h['cmdbId'] = ('CI{0}' -f $a); $h['cmdbDataSensitivity'] = 'Confidential' }
                    elseif ($a % 4 -eq 1) { $h['cmdbName'] = '  ' }
                    $links = @(for ($l = 0; $l -lt (1 + ($k % 9)); $l++) { 'https://kb.example.test/{0}/{1}' -f ($k % 13), $l })
                    if ($rng.Next(0, 4) -ne 0) { $h['MoreDetails'] = ('See {0}; HTTP://upper.example.test/x and https://nvd.nist.gov/vuln/detail/{1}.' -f ($links -join ', '), $cid) }
                    if ($cid -like 'CVE-*') {
                        $u = $updates[($a + $k) % $updates.Count]
                        if ($u[0]) { $h['si_fix_recommended_update_id'] = $u[0]; $h['si_fix_recommended_update'] = $u[1] }
                        if ($k % 11 -eq 0) { $h['si_patch_cycle'] = 'Catch-up (older than 1 month)' }
                    }
                    $h['RiskFactor_Probability_Detailed'] = ''; $h['RiskFactor_Consequence_Detailed'] = ''
                    $out.Add([pscustomobject]$h)
                }
            }
            # two assets that are equal on every sort key: their order is where each first appears
            foreach ($tw in 'tie-b', 'tie-a') {
                $out.Add([pscustomobject][ordered]@{ AssetName = $tw; CriticalityTierLevel = 'Critical - tier 0'; CriticalityTier = 0; ConfigurationId = ('TIE-{0}' -f $Report); ConfigurationName = 'Tie'
                    Category = 'Configuration'; Subcategory = 'Hardening'; SecuritySeverity = 'High'; SecurityDomain = 'Endpoint'; Report = 'Device_Vulnerabilities_Detailed'
                    RiskScoreTotal_Weighted = 500; RiskScoreTotal = 40; RiskScoreKPI = 50; ImpactedAssetCount = 1; si_ci_id = $tw; RiskFactor_Probability_Detailed = ''; RiskFactor_Consequence_Detailed = '' })
            }
            $out.ToArray()
        }
        # ONE run's stored result through the engine's own stream path: per report its rows written (every 23rd outside the
        # view), finished in SQL (the duplicates kept once, the shared trace names); -Held: that report is held back
        function script:New-StoredRun([string]$Db, [int]$Reports, [int]$Assets, [int]$PerAsset, [int]$Held = 0, [scriptblock]$Mutate) {
            $s = New-RAStream -Invoke (New-SessionSeam -Db $Db) -Grain Detailed -CollectionTime $script:CT -RunId 'top50' -Log { param($l, $t) }
            for ($r = 1; $r -le $Reports; $r++) {
                $name = 'Top50Gen{0}_Detailed' -f $r
                $null = Start-RAStreamReport -Stream $s -ReportName $name -Staged $false
                $rows = @(New-Top50Rows -Report $r -Assets $Assets -PerAsset $PerAsset -Seed (1212 + $r))
                if ($Mutate) { & $Mutate $rows }
                foreach ($x in $rows) { Add-Member -InputObject $x -NotePropertyName CollectionTime -NotePropertyValue $script:CT -Force }
                Set-RATraceIdentity -Rows $rows -IsDetailed $true
                $cols = New-Object 'System.Collections.Generic.List[string]'; $seen = @{}
                foreach ($x in $rows) { foreach ($pn in $x.PSObject.Properties.Name) { if (-not $seen.ContainsKey($pn)) { $seen[$pn] = 1; $cols.Add($pn) } } }
                Add-RAStreamColumns -Stream $s -Columns $cols.ToArray()
                $view = New-Object 'System.Collections.Generic.HashSet[object]'
                for ($i = 0; $i -lt $rows.Count; $i++) { if ($i % 23 -ne 22) { [void]$view.Add($rows[$i]) } }
                $half = [int][Math]::Floor($rows.Count / 2)
                $null = Write-RAStreamRows -Stream $s -Rows @($rows[0..($half - 1)]) -Bucket '1/2' -InView $view -IsDetailedShape $true
                $null = Write-RAStreamRows -Stream $s -Rows @($rows[$half..($rows.Count - 1)]) -Bucket '2/2' -InView $view -IsDetailedShape $true
                $null = Complete-RAStreamReport -Stream $s
                if ($r -eq $Held) { $null = Add-RAStreamHeldReport -Stream $s -ReportName $name -Ordinal ([int]$s.Reports[$name].Ordinal) -Cause 'test: held back' }
            }
            $s
        }
        # OLD: the engine's row-by-row rollup region, run as it is, then the key figures' block (Invoke-RAKpiPass)
        function script:Invoke-OldRollup($Stream) {
            $script:RAStreamOn = $true; $script:RAStream = $Stream
            $script:RAViewCount = [long](Get-RAStreamCount -Stream $Stream -Source View)
            $script:RAKpiFromAiPass = $null
            $TopN = $script:RAViewCount; $TopAssetsN = 50; $TopFindingsN = 50; $colRiskScore = 'RiskScoreTotal_Weighted'; $isDetailedTemplate = $true; $topRows = @()
            $sw = [Diagnostics.Stopwatch]::StartNew()
            . ([scriptblock]::Create($script:OldHelpers))
            . ([scriptblock]::Create($script:OldRegion))
            $kp = Invoke-RAKpiPass -FromAiPass $script:RAKpiFromAiPass -NewPager { New-RARowPager -Stream $Stream -Source View }
            $kpi = Complete-RAKpiState -State $kp.State
            $sec = $sw.Elapsed.TotalSeconds
            [pscustomobject]@{ Assets = @($assetRanked); Findings = @($findingRanked); Total = [long]$__assetsTotal; Kpi = $kpi; Rows = [long]$__aiRows; FromAi = [bool]$kp.FromAiPass; Seconds = $sec }
        }
        # NEW: the database form; its key figures through the same Invoke-RAKpiPass / Complete-RAKpiState
        function script:Invoke-NewRollup($Stream, [bool]$Ai) {
            $script:RAStreamOn = $true; $script:RAStream = $Stream
            $view = [long](Get-RAStreamCount -Stream $Stream -Source View)
            $r = Invoke-RATopListsInSql -Stream $Stream -ViewRows $view -Collapse $true -WithAi $Ai -KpiState (New-RAKpiState)
            $kpi = $null
            if ($r.Status -eq 'ok') { $kp = Invoke-RAKpiPass -FromAiPass $r.KpiState -NewPager { throw 'the key figures must not read the rows again' }; $kpi = Complete-RAKpiState -State $kp.State }
            [pscustomobject]@{ R = $r; Assets = @($r.TopAssets); Findings = @($r.TopFindings); Total = [long]$r.Assets; Kpi = $kpi; Rows = [long]$r.Rows; Seconds = [double]$r.Seconds }
        }

        $script:Db = New-Db -Tag 'same'
        $script:Run = New-StoredRun -Db $script:Db -Reports 4 -Assets 120 -PerAsset 4 -Held 4
        $script:Old = Invoke-OldRollup -Stream $script:Run
        $script:NewAi = Invoke-NewRollup -Stream $script:Run -Ai $true
        $script:NewOff = Invoke-NewRollup -Stream $script:Run -Ai $false
    }
    AfterAll {
        foreach ($d in @($script:Dbs)) {
            try {
                $m = New-Object System.Data.SqlClient.SqlConnection "Server=$($env:SI_TEST_LOCALSQL);Database=master;$($env:SI_TEST_SQL_AUTH);Connection Timeout=30"
                $m.Open(); try { $c = $m.CreateCommand(); $c.CommandText = "ALTER DATABASE [$d] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$d];"; $c.CommandTimeout = 120; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
            } catch { }
        }
    }

    It 'the fixture reaches every branch: more than 50 assets and findings, ties, the collapse, twins, first-seen cmdb, links over 6, the patch cycle' {
        $script:NewAi.R.Status | Should -Be 'ok' -Because $script:NewAi.R.Why
        $script:NewOff.R.Status | Should -Be 'ok' -Because $script:NewOff.R.Why
        $script:Old.Total | Should -BeGreaterThan 50
        $script:Old.Assets.Count | Should -Be 50
        $script:Old.Findings.Count | Should -Be 50
        $script:Old.Rows | Should -BeGreaterThan 1000
        $script:NewAi.R.Kept | Should -BeLessThan ($script:NewAi.Rows - $script:NewAi.R.NoAsset) -Because 'the *_Detailed collapse removed rows'
        $script:NewAi.R.NoAsset | Should -BeGreaterThan 0
        # an exact tie on every sort key of the asset list (the two 'tie-' assets)
        $ix = @(for ($i = 0; $i -lt $script:Old.Assets.Count; $i++) { if ([string]$script:Old.Assets[$i].Asset -like 'tie-*') { $i } })
        $ix.Count | Should -Be 2
        $t0 = $script:Old.Assets[$ix[0]]; $t1 = $script:Old.Assets[$ix[1]]
        ($t0.TotalRiskScore_Weighted -eq $t1.TotalRiskScore_Weighted -and $t0.TotalRiskScore -eq $t1.TotalRiskScore -and $t0.Findings -eq $t1.Findings -and $t0.TierLevel -eq $t1.TierLevel) | Should -BeTrue
        @($script:Old.Assets | Where-Object { $_.AssetKey -eq 'name:host-twin' }).Count | Should -BeLessOrEqual 1
        @($script:Old.Assets | Where-Object { [string]$_.CmdbName -like 'Svc-*' }).Count | Should -BeGreaterThan 0
        @($script:Old.Assets | Where-Object { @($_.Links).Count -eq 6 }).Count | Should -BeGreaterThan 0
        $script:Old.Kpi.PatchCycle.Findings | Should -BeGreaterThan 0
        @($script:Old.Kpi.PatchCycle.CatchUpFixes).Count | Should -BeGreaterThan 0
    }
    It 'THE SAME TOP 50 ASSETS in the same order (ties included), with every value the executive view reads' {
        $old = @($script:Old.Assets | ForEach-Object { Get-AssetFace $_ $false })
        $new = @($script:NewOff.Assets | ForEach-Object { Get-AssetFace $_ $false })
        $new.Count | Should -Be $old.Count
        for ($i = 0; $i -lt $old.Count; $i++) { $a1 = ConvertTo-Canon $new[$i]; $b1 = ConvertTo-Canon $old[$i]; $a1 | Should -Be $b1 -Because ("asset rank {0}: {1}" -f ($i + 1), (Get-CanonDiff $a1 $b1)) }
        $script:NewOff.Total | Should -Be $script:Old.Total
        # the executive view's own shape, as the web app reads it
        $ev = { param($l) @(for ($i = 0; $i -lt $l.Count; $i++) { ConvertTo-RAExecViewAsset -Asset $l[$i] -Rank ($i + 1) }) | ConvertTo-Json -Depth 6 -Compress }
        (& $ev $script:NewOff.Assets) | Should -Be (& $ev $script:Old.Assets)
    }
    It 'THE SAME TOP 50 FINDINGS in the same order, with their five hottest assets' {
        $old = @($script:Old.Findings | ForEach-Object { Get-FindingFace $_ $false })
        $new = @($script:NewOff.Findings | ForEach-Object { Get-FindingFace $_ $false })
        $new.Count | Should -Be $old.Count
        for ($i = 0; $i -lt $old.Count; $i++) { $a1 = ConvertTo-Canon $new[$i]; $b1 = ConvertTo-Canon $old[$i]; $a1 | Should -Be $b1 -Because ("finding rank {0}: {1}" -f ($i + 1), (Get-CanonDiff $a1 $b1)) }
        $ev = { param($l) @(for ($i = 0; $i -lt $l.Count; $i++) { ConvertTo-RAExecViewFinding -Finding $l[$i] -Rank ($i + 1) }) | ConvertTo-Json -Depth 6 -Compress }
        (& $ev $script:NewOff.Findings) | Should -Be (& $ev $script:Old.Findings)
    }
    It 'THE SAME KEY FIGURES: every domain score, severity count, total and the patch cycle -- and no row is read again' {
        $script:NewOff.Kpi | Should -Not -BeNullOrEmpty
        (ConvertTo-Canon $script:NewOff.Kpi) | Should -Be (ConvertTo-Canon $script:Old.Kpi)
        (ConvertTo-Canon $script:NewAi.Kpi) | Should -Be (ConvertTo-Canon $script:Old.Kpi)
        $script:Old.FromAi | Should -BeTrue -Because 'the row loop handed its tally to the key figures (one read of the rows)'
        $script:NewOff.Rows | Should -Be $script:Old.Rows
    }
    It 'NEGATIVE -- AI on: the AI prompt still gets its own inputs (links, cmdb id + data sensitivity, assets in all), equal to the row loop''s' {
        $old = @($script:Old.Assets | ForEach-Object { Get-AssetFace $_ $true })
        $new = @($script:NewAi.Assets | ForEach-Object { Get-AssetFace $_ $true })
        for ($i = 0; $i -lt $old.Count; $i++) { $a1 = ConvertTo-Canon $new[$i]; $b1 = ConvertTo-Canon $old[$i]; $a1 | Should -Be $b1 -Because ("asset rank {0}: {1}" -f ($i + 1), (Get-CanonDiff $a1 $b1)) }
        $oldF = @($script:Old.Findings | ForEach-Object { Get-FindingFace $_ $true })
        $newF = @($script:NewAi.Findings | ForEach-Object { Get-FindingFace $_ $true })
        for ($i = 0; $i -lt $oldF.Count; $i++) { $a1 = ConvertTo-Canon $newF[$i]; $b1 = ConvertTo-Canon $oldF[$i]; $a1 | Should -Be $b1 -Because ("finding rank {0}: {1}" -f ($i + 1), (Get-CanonDiff $a1 $b1)) }
        @($script:NewAi.Assets | Where-Object { @($_.Links).Count -gt 0 }).Count | Should -BeGreaterThan 0
        @($script:NewAi.Assets | Where-Object { $_.CmdbId }).Count | Should -BeGreaterThan 0
        @($script:NewAi.Findings | Where-Object { $_.AssetRiskScoreCount -gt 5 }).Count | Should -BeGreaterThan 0
    }
    It 'AI off: what only the AI prompt reads is not worked out at all -- and the executive view still gets every list' {
        @($script:NewOff.Assets | Where-Object { @($_.Links).Count -gt 0 -or $_.CmdbId -or $_.CmdbDataSensitivity }).Count | Should -Be 0
        @($script:NewOff.Findings | Where-Object { @($_.Links).Count -gt 0 }).Count | Should -Be 0
        $v = New-RAExecViewSnapshot -Grain Detailed -ReportTemplate 'RiskAnalysis_Detailed' -GeneratedAtUtc ([datetime]::UtcNow) -Mode PerReport -Leader Detailed -Kpi $script:NewOff.Kpi `
                -AISummaryEnabled $false -TopAssets $script:NewOff.Assets -TopFindings $script:NewOff.Findings
        @($v.TopAssets).Count | Should -Be 50
        @($v.TopFindings).Count | Should -Be 50
        $v.Kpi.TotalRows | Should -Be $script:Old.Kpi.TotalRows
    }
    It 'a stored row with an asset LIST (not mirrored) declines: nothing is used and the row loop reads the rows as before' {
        $db = New-Db -Tag 'list'
        $s = New-StoredRun -Db $db -Reports 1 -Assets 20 -PerAsset 2 -Mutate { param($rows) $rows[5] | Add-Member -NotePropertyName ImpactedAssetsList -NotePropertyValue @('a', 'b') -Force }
        $r = Invoke-NewRollup -Stream $s -Ai $false
        $r.R.Status | Should -Be 'declined'
        $r.R.Why | Should -Match 'asset list'
        @($r.R.TopAssets).Count | Should -Be 0
        $r.R.KpiState | Should -BeNullOrEmpty
        Format-RATopListsLine -Result $r.R | Should -Match 'read row by row as before'
        # a different row count than the run's own is declined too
        (Invoke-RATopListsInSql -Stream $s -ViewRows 1 -Collapse $true -WithAi $false -KpiState (New-RAKpiState)).Status | Should -Be 'declined'
    }
    It 'THE TIMING: the row loop and the database form on the same larger fixture (printed; the database form is not slower)' {
        $db = New-Db -Tag 'time'
        $s = New-StoredRun -Db $db -Reports 4 -Assets 1500 -PerAsset 4
        $o = Invoke-OldRollup -Stream $s
        $n = Invoke-NewRollup -Stream $s -Ai $false
        $n.R.Status | Should -Be 'ok' -Because $n.R.Why
        (ConvertTo-Canon $n.Kpi) | Should -Be (ConvertTo-Canon $o.Kpi)
        (ConvertTo-Canon @($n.Assets | ForEach-Object { Get-AssetFace $_ $false })) | Should -Be (ConvertTo-Canon @($o.Assets | ForEach-Object { Get-AssetFace $_ $false }))
        $inv = [Globalization.CultureInfo]::InvariantCulture
        $oRate = $o.Rows / [Math]::Max(0.001, $o.Seconds); $nRate = $n.Rows / [Math]::Max(0.001, $n.Seconds)
        $line = ([string]::Format($inv, '[#1212 timing] {0:N0} rows: row by row {1:N1} s ({2:N0} rows/s), in the database {3:N1} s ({4:N0} rows/s, {5} range(s)) -- {6:N1}x; at that rate 1.35 M rows in the database ~{7:N0} s',
            $o.Rows, $o.Seconds, $oRate, $n.Seconds, $nRate, $n.R.Ranges, ($o.Seconds / [Math]::Max(0.001, $n.Seconds)), (1350000 / [Math]::Max(1, $nRate))))
        Write-Host $line
        $n.Seconds | Should -BeLessThan $o.Seconds
    }
}
