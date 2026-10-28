#Requires -Version 5.1
<#
    RISK ANALYSIS KQL KEEPS ITS LISTS DYNAMIC, AND A REPORT THAT LOSES ITS ROWS SAYS SO. Ring 1, 2026-10-10: 12 Summary + 12
    Detailed reports lost every bucket ("set_has_element(): argument #1 must be a dynamic", "set_difference(): all arguments
    are expected to have the same type 'dynamic'", "strcat_array(): argument #1 was not of an expected data type: dynamic")
    and two more failed on "Failed to resolve table ... 'DeviceInfo'". What these tests keep true:
      * the scope preamble: every list it emits is dynamic([...]) -- with EMPTY settings and with ONE-ITEM settings;
      * the shipped YAML: every argument of set_has_element / set_difference / strcat_array is dynamic-typed or coerced;
      * the hybrid path: a dynamic column of the CI snapshot is inlined as a dynamic datatable column (declared type first,
        JSON-array values otherwise), never as a string;
      * routing: a CI + Defender-table query (DeviceTvm*, DeviceInfo) goes to advanced hunting; a Sentinel table or a
        column named Device* does not;
      * a report that returns 0 rows when its previous run had rows is a WARN line naming the report;
      * the CI side: a long identifier is stored hashed so its key fits the index (both readers hash alike); the SI_CI_CL
        column contract decides a full re-post.
    Offline: pure functions only. PS 5.1 and pwsh 7 (the datatable dynamic detection needs System.Text.Json: pwsh 7).
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\_shared\SI-Yaml.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-DataModelTemplates.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-DisabledAssets.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-CiKql.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-CiContext.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-FactorKeys.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-ScopePreamble.ps1')
    . (Join-Path $PSScriptRoot '_RaKqlDynamicLint.ps1')
    function script:Write-Info($m) { }
    function script:Write-Warn2($m) { $script:Warned.Add([string]$m) }
    function script:Write-Err2($m) { }
    function script:Write-Diag($m) { }
    $script:Warned = New-Object System.Collections.Generic.List[string]
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-ProfileAugment.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-RowCountGuard.ps1')
    # the routing predicate only (the file's other functions need the engine)
    $gh = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-GraphHunting.ps1'), [ref]$null, [ref]$null)
    $fn = $gh.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Test-RAQueryNeedsAdvancedHunting' }, $true) | Select-Object -First 1
    . ([scriptblock]::Create($fn.Extent.Text))
    function script:Get-SIItemValue($o, $n) { if ($null -eq $o) { return $null }; if ($o -is [System.Collections.IDictionary]) { return $o[$n] }; $p = $o.PSObject.Properties[$n]; if ($p) { $p.Value } }
    . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordSql.ps1')

    $script:YamlPath = Join-Path $script:SIRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'
    $script:Reports = @((ConvertFrom-SIYaml -Path $script:YamlPath).Reports)
    $script:Dm = Join-Path $script:SIRoot 'data-model'
    $script:Model = Get-SIDataModel -Root $script:Dm
    $script:Template = (Get-SIDataModelTemplate -Name 'report-scope' -Root $script:Dm).Document
    $script:Subjects = Get-RASubjectDefinitions -Template $script:Template
    $script:FieldClasses = @{}; foreach ($f in @($script:Model['field-catalog'].fields)) { $script:FieldClasses[[string]$f.name] = @($f.classes) }
    $script:Factors = @($script:Model['risk-factors'].factors)
    $script:FactorById = @{}; foreach ($f in $script:Factors) { $script:FactorById[[string]$f.id] = $f }
    $script:Lists = @{}; foreach ($l in @($script:Model['lists'].lists)) { $script:Lists[[string]$l.id] = $l }
    $script:ListLets = @('SI_ScopeTiers', 'SI_ExcludedAssets', 'SI_ExcludedAssetTags', 'SI_ExcludedConfigurationIds', 'SI_ExcludedCves', 'SI_ExcludedIpRanges', 'SI_ReportFactors')

    function script:ScopeBlock([string]$Name, [hashtable]$Change) {
        $r = @($script:Reports | Where-Object { $_.ReportName -eq $Name })[0]
        $spec = Get-RAReportScope -ReportName $Name -Template $script:Template
        $fs = @(Get-RAReportFactorSet -Spec $spec -Factors $script:Factors -Subjects $script:Subjects -FieldClasses $script:FieldClasses)
        $v = Get-RAScopeDefaults -Spec $spec -TierLabels @($r.CriticalityTierLevelScope) -FactorSet $fs
        $v.Lists = $script:Lists; $v.Factors = $script:FactorById; $v.FactorNames = Get-RAFactorNameMap -Factors $script:Factors -FactorSet $fs
        foreach ($k in $Change.Keys) { $v[$k] = $Change[$k] }
        New-RAScopeBlock -Active (Get-RAScopeActive -Spec $spec -Values $v) -Query (@($r.ReportQuery) -join "`n")
    }
}

Describe 'the scope preamble emits every list as dynamic([...])' {
    It 'with EMPTY settings and with ONE-ITEM settings, for every report' {
        $empty = @{ ExcludedAssets = @(); ExcludedAssetTags = @(); ExcludedConfigurationIds = @(); ExcludedCves = @(); ExcludedIpRanges = @(); FactorSet = @(); Tiers = @() }
        $one = @{ ExcludedAssets = @('host1'); ExcludedAssetTags = @('tag1'); ExcludedConfigurationIds = @('scid-1'); ExcludedCves = @('CVE-2024-0001'); ExcludedIpRanges = @('10.0.0.0/8'); FactorSet = @('internet_exposed'); Tiers = @(0) }
        $bad = New-Object System.Collections.Generic.List[string]
        foreach ($r in $script:Reports) {
            foreach ($case in @(@{ n = 'empty'; v = $empty }, @{ n = 'one'; v = $one })) {
                $b = script:ScopeBlock ([string]$r.ReportName) $case.v
                foreach ($let in $script:ListLets) {
                    $m = [regex]::Match($b, ('(?m)^let {0} = (.*);$' -f $let))
                    if (-not $m.Success -or $m.Groups[1].Value -notmatch '^dynamic\(\[.*\]\)$') { $bad.Add(('{0} [{1}] {2} = {3}' -f $r.ReportName, $case.n, $let, $m.Groups[1].Value)) }
                }
                if ($b -notmatch '(?m)^let SI_FactorNames = dynamic\(\{.*\}\);$') { $bad.Add(('{0} [{1}] SI_FactorNames' -f $r.ReportName, $case.n)) }
            }
        }
        $bad | Should -BeNullOrEmpty
    }
    It 'an empty list is dynamic([]) and a one-item list holds the item' {
        ConvertTo-RAKqlDynamic -Values @() | Should -Be 'dynamic([])'
        ConvertTo-RAKqlDynamic -Values $null | Should -Be 'dynamic([])'
        ConvertTo-RAKqlDynamic -Values @('a') | Should -Be 'dynamic(["a"])'
        ConvertTo-RAKqlDynamic -Values @(3) -Type int | Should -Be 'dynamic([3])'
    }
}

Describe 'the shipped YAML passes dynamic values to the set and array functions' {
    It 'every set_has_element / set_difference / strcat_array argument is dynamic-typed or coerced' {
        $bad = foreach ($r in $script:Reports) { foreach ($v in @(Get-RAKqlDynamicArgViolations -Query (@($r.ReportQuery) -join "`n"))) { '{0}: {1}' -f $r.ReportName, $v } }
        @($bad) | Should -BeNullOrEmpty
    }
    It 'the lint catches a text value, accepts a coerced one' {
        @(Get-RAKqlDynamicArgViolations -Query 'T | extend x = tostring(a) | extend y = strcat_array(x, ";")') | Should -Be @('strcat_array(x)')
        @(Get-RAKqlDynamicArgViolations -Query 'T | extend t = tolower(tostring(column_ifexists("si_tags", dynamic(null)))) | where set_has_element(t, "a")') | Should -Be @('set_has_element(t)')
        @(Get-RAKqlDynamicArgViolations -Query 'T | extend p = make_set(a) | extend y = strcat_array(coalesce(p, dynamic([])), ";"), z = set_difference(p, todynamic(q))') | Should -BeNullOrEmpty
    }
}

Describe 'the hybrid path inlines a dynamic column as dynamic' {
    BeforeAll {
        $script:Rows = @(
            [pscustomobject]@{ _ciKey = 'a'; si_rf_p = '["internet_exposed","overdue"]'; si_tier = '1'; si_tags_ = '' }
            [pscustomobject]@{ _ciKey = 'b'; si_rf_p = '[]'; si_tier = ''; si_tags_ = '["x"]' }
        )
    }
    It 'the declared type wins: dynamic stays dynamic, a text column stays text even when it holds JSON' {
        $kql = Convert-RowsToKqlDatatable -LetVarName _ciLink -Rows $script:Rows -ColumnTypes @{ _ciKey = 'string'; si_rf_p = 'dynamic'; si_tier = 'int'; si_tags_ = 'string' }
        $kql | Should -Match 'datatable\(_ciKey:string,si_rf_p:dynamic,si_tier:long,si_tags_:string\)'
        $kql | Should -Match 'dynamic\(\["internet_exposed","overdue"\]\)'
        $kql | Should -Match '"b",dynamic\(\[\]\),long\(null\),"\[\\"x\\"\]"'
    }
    It 'without declared types a column of JSON arrays is dynamic, an empty cell dynamic(null)' -Skip:($PSVersionTable.PSEdition -ne 'Core') {
        $kql = Convert-RowsToKqlDatatable -LetVarName _ciLink -Rows $script:Rows
        $kql | Should -Match 'si_rf_p:dynamic'
        $kql | Should -Match 'si_tags_:dynamic'
        $kql | Should -Match '"a",dynamic\(\["internet_exposed","overdue"\]\),1,dynamic\(null\)'
    }
    It 'an EMPTY bucket keeps the declared types (never all-string)' {
        $kql = Convert-RowsToKqlDatatable -LetVarName _ciLink -Rows @() -ColumnTypes @{ _ciKey = 'string'; si_rf_p = 'dynamic' } -BodyKqlForSchemaHint 'T | project _ciKey, si_rf_p'
        $kql | Should -Be 'let _ciLink = datatable(_ciKey:string,si_rf_p:dynamic) [];'
    }
    It 'a value that is not JSON never breaks the literal' {
        ConvertTo-SIKqlDynamicLiteral 'not json' | Should -Be 'dynamic("not json")'
        ConvertTo-SIKqlDynamicLiteral '' | Should -Be 'dynamic(null)'
    }
    It 'the hybrid fetch records the declared types for the inline (wiring)' {
        $src = Get-Content -LiteralPath (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-ProfileAugment.ps1') -Raw
        ([regex]::Matches($src, 'Convert-RowsToKqlDatatable -LetVarName[^\r\n]*-ColumnTypes')).Count | Should -BeGreaterOrEqual 4
        (Get-Content -LiteralPath (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-LogAnalyticsQuery.ps1') -Raw) | Should -Match 'RA_LastLaQueryColumnTypes\[\[string\]\$__c\.name\]'
    }
}

Describe 'a CI + Defender table query goes to advanced hunting' {
    It 'Device_Recommendations (DeviceTvm*, DeviceInfo, no graph) needs advanced hunting' {
        foreach ($n in 'Device_Recommendations_Summary', 'Device_Recommendations_Detailed') {
            Test-RAQueryNeedsAdvancedHunting -Query (@(@($script:Reports | Where-Object { $_.ReportName -eq $n })[0].ReportQuery) -join "`n") | Should -BeTrue -Because $n
        }
    }
    It 'a CI-only report, a Sentinel sign-in report and a Device* column do not' {
        Test-RAQueryNeedsAdvancedHunting -Query (@(@($script:Reports | Where-Object { $_.ReportName -eq 'Identity_NoMFA_Detailed' })[0].ReportQuery) -join "`n") | Should -BeFalse
        Test-RAQueryNeedsAdvancedHunting -Query "SI_CI_CL | join (SigninLogs | where x) on a | join (DeviceInfo | take 1) on b" | Should -BeFalse
        Test-RAQueryNeedsAdvancedHunting -Query "SI_CI_CL | project a,`n      DeviceKey,`n      DeviceInfoLatest = 1" | Should -BeFalse
        Test-RAQueryNeedsAdvancedHunting -Query "SI_CI_CL | join kind=leftouter (DeviceTvmSoftwareVulnerabilities | take 1) on DeviceId" | Should -BeTrue
    }
}

Describe 'a report that returns 0 rows after a run with rows is a WARN line naming it' {
    It 'WENT-TO-ZERO names the report and both counts; no history or a zero last time says nothing' {
        Get-RAZeroRowWarning -ReportName 'R1' -Previous @{ R1 = 606 } | Should -Match 'WENT-TO-ZERO R1: 0 rows this run, 606 in the previous run'
        Get-RAZeroRowWarning -ReportName 'R1' -Previous @{ R1 = 0 } | Should -BeNullOrEmpty
        Get-RAZeroRowWarning -ReportName 'R1' -Previous @{} | Should -BeNullOrEmpty
        Get-RAZeroRowWarning -ReportName 'Identity_TooManyGlobalAdmins_Summary' -Previous @{ Identity_TooManyGlobalAdmins_Summary = 1 } | Should -Match 'threshold'
    }
    It 'Write-RAZeroRowWarning reads the previous run and warns' {
        $dir = Join-Path ([IO.Path]::GetTempPath()) ('ra-zero-' + [guid]::NewGuid().ToString('N'))
        try {
            Write-RARowCountHistory -Path (Get-RARowCountHistoryPath -SettingsPath $dir) -TemplateName 'T1' -Counts @{ R9 = 12 }
            $script:Warned.Clear(); $script:_RAPrevRowCounts = $null
            Write-RAZeroRowWarning -ReportName 'R9' -SettingsPath $dir -TemplateName 'T1'
            @($script:Warned) | Should -HaveCount 1
            $script:Warned[0] | Should -Match 'R9'
        } finally { Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue }
    }
    It 'the engine calls it on both zero paths (wiring)' {
        $src = Get-Content -LiteralPath (Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1') -Raw
        ([regex]::Matches($src, 'Write-RAZeroRowWarning -ReportName')).Count | Should -BeGreaterOrEqual 2
    }
}

Describe 'the CI side' {
    It 'a long identifier is stored hashed (SHA-256 of UTF-16LE, as T-SQL HASHBYTES), a short one as it is' {
        ConvertTo-SIRecordIdValue 'ABC' | Should -Be 'abc'
        $long = '/subscriptions/' + ('a' * 200)
        ConvertTo-SIRecordIdValue $long | Should -Be 'sha256:1de608339a038c897dacb4743bb7f92f814d9b328c4c66c96be1979dfb7e15f2'
        ConvertTo-SIRecordIdValue $long.ToUpperInvariant() | Should -Be (ConvertTo-SIRecordIdValue $long)
    }
    It 'an Azure record''s identifier row fits the 900-byte key' {
        $id = '/subscriptions/00000000-0000-0000-0000-000000000000/resourcegroups/rg-a-very-long-resource-group-name/providers/microsoft.sql/servers/sql-server-name/databases/a-database-with-a-long-name'
        $rows = @([pscustomobject]@{ si_record_key = ('azure:' + $id); si_provider = 'azure'; si_record_type = 'azure_resource'; si_class = 'cloud_resource'; si_azure_resource_id = $id })
        $items = ConvertTo-SIRecordSqlItems -Rows $rows -TypeMap @{ si_azure_resource_id = 'AzureResourceId' }
        foreach ($i in @($items.Identifiers)) { (2 * (([string]$i.RecordKey).Length + ([string]$i.IdType).Length + ([string]$i.IdValue).Length)) | Should -BeLessOrEqual 900 }
        @($items.Identifiers).Count | Should -Be 1
    }
    It 'both SQL readers hash the plain value exactly as the writer does' {
        $graph = Get-Content -LiteralPath (Join-Path $script:SIRoot 'engine\data-model\SI-CiGraph.ps1') -Raw
        $build = Get-Content -LiteralPath (Join-Path $script:SIRoot 'engine\data-model\SI-CiBuildSql.ps1') -Raw
        $graph.Contains((Get-SIRecordIdValueSqlExpr -Expr 'r.ToValue')) | Should -BeTrue
        $build.Contains((Get-SIRecordIdValueSqlExpr -Expr 'k.v')) | Should -BeTrue
    }
}
