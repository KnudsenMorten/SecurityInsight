#Requires -Version 5.1
<#
    #690 (15) -- EVERY FINDING HAS ONE OF THE FIVE SI SEVERITIES, FROM ONE SEVERITY MODEL (owner 2026-10-15: "all security
    findings must have severity" / "it comes from different metrics, often impact score or directly from the source" /
    "unknown is not supported in any report" / "field must be normalized").

    What this file pins:
      * the model (data-model/severity-model.locked.json, kind severity-model): the scale is exactly Very High, High,
        Medium-High, Medium, Low; every kind maps only into it; every shipped report is listed once, its order ends with
        owner_defined and its own severity is one of the five -- loaded through the data model like every template, and
        valid in Test-SIDataModel;
      * Resolve-SISeverity: the owner's CVSS bands (>=9 Very High, >=7 High, >=4 Medium, >0 Low), the tier map (0 Very High
        ... 3 Low), the provider's severity words, the order (source first, then the score), owner_defined last -- a row
        with no metric still gets the report's own severity; never empty, never 'Unknown';
      * a Pro override of one report item is refused when it would leave a row without a severity;
      * THE CATALOG: every report's SecuritySeverity can only produce the five SI values, and never an empty one (each
        case() ends with one of the five, an alias column is followed to its own case()); no report says "Unknown";
      * the tier stays the tier rules' (no coalesce(si_tier, N) outside the attack paths, which are #690 (1)/(2)).
    The reports' queries do not read the model yet (the generated severity block is the next step). Offline.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\_shared\SI-Yaml.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-DataModelTemplates.ps1')
    # the Pro override check (Pro only: loaded when Test-Path finds it, the test is skipped without it)
    $script:ProRows = Join-Path $script:SIRoot 'engine\pro-settings\SI-DataModelTemplateRows.ps1'
    $script:HasPro = Test-Path -LiteralPath $script:ProRows
    if ($script:HasPro) { . $script:ProRows }
    $script:Five = @('Very High', 'High', 'Medium-High', 'Medium', 'Low')
    $script:Model = Get-SISeverityModel -Root (Join-Path $script:SIRoot 'data-model')
    $yaml = Join-Path $script:SIRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'
    $script:Reports = @((ConvertFrom-SIYaml -Yaml ([IO.File]::ReadAllText($yaml)) -SourceName $yaml).Reports)
    function script:CodeOf($r) { ((((@($r.ReportQuery) | ForEach-Object { [string]$_ }) -join "`n") -split "`r?`n") | Where-Object { $_.Trim() -notmatch '^//' }) -join "`n" }
    # the expression a column is assigned last in the query: a literal, a case(...) or a column / wrapper of a column
    $script:Rhs = '(?<rhs>"[^"]*"|case\((?:[^()]|\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\))*\)|[A-Za-z_][\w]*(?:\(\s*[A-Za-z_]\w*\s*\))?)'
    function script:Get-Outcomes([string]$Code, [string]$Column, [int]$Depth = 0, [string[]]$Seen = @()) {
        <# Every value the column can hold: @{ Values = string[]; Problems = string[] } #>
        $vals = New-Object System.Collections.Generic.List[string]; $probs = New-Object System.Collections.Generic.List[string]
        $ms = [regex]::Matches($Code, ('(?<![\w.])' + [regex]::Escape($Column) + '\s*=\s*' + $script:Rhs))
        if ($ms.Count -eq 0) { $probs.Add("$Column is never assigned"); return @{ Values = $vals.ToArray(); Problems = $probs.ToArray() } }
        foreach ($m in $ms) {
            $rhs = ($m.Groups['rhs'].Value -replace '\s+', ' ').Trim()
            if ($rhs -match '^"([^"]*)"$') { $vals.Add($Matches[1]); continue }
            if ($rhs -match '^case\(') {
                $body = $rhs.Substring(5, $rhs.Length - 6)
                # the comparisons' own literals are conditions, not results
                $res = $body -replace '(=~|==|!=|in~?|has_any|has|contains|startswith|endswith)\s*(\([^()]*\)|"[^"]*")', ' '
                foreach ($l in [regex]::Matches($res, '"([^"]*)"')) { $vals.Add($l.Groups[1].Value) }
                $last = [regex]::Match($rhs, ',\s*(?<d>"[^"]*"|[A-Za-z_]\w*)\s*\)$')
                if (-not $last.Success -or $last.Groups['d'].Value -notmatch '^"') { $probs.Add("$Column = case(...) does not end with a severity literal") }
                continue
            }
            $ref = [regex]::Match($rhs, '([A-Za-z_]\w*)\s*\)?$').Groups[1].Value
            if ($rhs -match '^[A-Za-z_]\w*\(\s*([A-Za-z_]\w*)\s*\)$') { $ref = $Matches[1] }
            # a column already being followed (SecuritySeverity -> X_Path = any(SecuritySeverity) -> ...): its other assignments are read there
            if ($ref -eq $Column -or $Seen -contains $ref) { continue }
            if ($Depth -ge 6 -or -not $ref) { $probs.Add("$Column = $rhs cannot be followed"); continue }
            $o = Get-Outcomes -Code $Code -Column $ref -Depth ($Depth + 1) -Seen (@($Seen) + @($Column))
            foreach ($v in $o.Values) { $vals.Add($v) }; foreach ($x in $o.Problems) { $probs.Add($x) }
        }
        @{ Values = $vals.ToArray(); Problems = $probs.ToArray() }
    }
}

Describe 'the severity model' {
    It 'is shipped, has the kind severity-model, and is valid' {
        $script:Model | Should -Not -BeNullOrEmpty
        [string]$script:Model.kind | Should -Be 'severity-model'
        @(Test-SISeverityModel -Model $script:Model) | Should -BeNullOrEmpty
        @(Get-SISeverityScale) | Should -Be $script:Five
    }
    It 'is loaded with the data model and valid in Test-SIDataModel' {
        $m = Get-SIDataModel -Root (Join-Path $script:SIRoot 'data-model')
        $m['severity-model'] | Should -Not -BeNullOrEmpty
        @(Test-SIDataModel -Model $m | Where-Object { $_ -like 'severity-model*' }) | Should -BeNullOrEmpty
    }
    It 'lists every shipped report exactly once, each ending with owner_defined and one of the five' {
        $ids = @(@($script:Model.reports) | ForEach-Object { [string]$_.id })
        @($ids | Group-Object | Where-Object Count -gt 1) | Should -BeNullOrEmpty
        $names = @($script:Reports | ForEach-Object { [string]$_.ReportName })
        @($names | Where-Object { $ids -notcontains $_ }) | Should -BeNullOrEmpty -Because 'a report without a model entry has no owner-defined severity'
        @($ids | Where-Object { $names -notcontains $_ }) | Should -BeNullOrEmpty -Because 'no entry for a report that does not exist'
        foreach ($r in @($script:Model.reports)) {
            @($r.order)[-1] | Should -Be 'owner_defined' -Because $r.id
            $script:Five | Should -Contain ([string]$r.ownerDefined) -Because $r.id
        }
    }
    It 'catches a broken model (the scale, a band outside the five, an order without owner_defined)' {
        $bad = '{"kind":"severity-model","scale":["Very High","High","Medium","Low","Unknown"],"models":[{"id":"cvss","type":"bands","bands":[{"min":9,"severity":"Critical"}]},{"id":"owner_defined","type":"fixed"}],"reports":[{"id":"R","order":["cvss"],"ownerDefined":"Unknown"}]}' | ConvertFrom-Json
        $p = @(Test-SISeverityModel -Model $bad)
        ($p -join "`n") | Should -Match 'the scale must be exactly'
        ($p -join "`n") | Should -Match "maps to 'Critical'"
        ($p -join "`n") | Should -Match 'ends with owner_defined'
        ($p -join "`n") | Should -Match "ownerDefined 'Unknown'"
    }
}

Describe 'Resolve-SISeverity: the first metric the row carries, the report''s own severity last' {
    It 'the owner''s CVSS bands' {
        $m = $script:Model
        foreach ($c in @(@(10, 'Very High'), @(9, 'Very High'), @(8.9, 'High'), @(7, 'High'), @(6.9, 'Medium'), @(4, 'Medium'), @(3.9, 'Low'), @(0.1, 'Low'))) {
            Resolve-SISeverity -Model $m -ReportName 'PublicIP_Vulnerabilities_Detailed' -Metrics @{ cvss = $c[0] } | Should -Be $c[1] -Because "CVSS $($c[0])"
        }
    }
    It 'the source''s own severity first, then the CVSS score, then the report''s own severity (the CVE report)' {
        $m = $script:Model
        Resolve-SISeverity -Model $m -ReportName 'Device_Missing_CVEs_Detailed' -Metrics @{ source_severity = 'Critical'; cvss = 2.0 } | Should -Be 'Very High'
        Resolve-SISeverity -Model $m -ReportName 'Device_Missing_CVEs_Detailed' -Metrics @{ source_severity = ''; cvss = 7.5 } | Should -Be 'High'
        Resolve-SISeverity -Model $m -ReportName 'Device_Missing_CVEs_Detailed' -Metrics @{ source_severity = 'Informational-ish'; cvss = $null } | Should -Be 'Low'
    }
    It 'the tier map' {
        foreach ($c in @(@(0, 'Very High'), @(1, 'High'), @(2, 'Medium'), @(3, 'Low'))) {
            Resolve-SISeverity -Model $script:Model -ReportName 'Endpoint_ExcludedAssets_Detailed' -Metrics @{ tier = $c[0] } | Should -Be $c[1]
        }
    }
    It 'every shipped report gives one of the five with no metric at all -- never empty, never Unknown' {
        foreach ($r in @($script:Model.reports)) {
            $s = Resolve-SISeverity -Model $script:Model -ReportName ([string]$r.id)
            $script:Five | Should -Contain $s -Because $r.id
        }
        Resolve-SISeverity -Model $script:Model -ReportName 'Not_A_Report' | Should -BeNullOrEmpty -Because 'an unlisted report is never guessed'
    }
    It 'a Pro override of one report is refused when a row could end without a severity' {
        if (-not $script:HasPro) { Set-ItResult -Skipped -Because 'the Pro settings are not in this copy'; return }
        $ok = '{"id":"Device_Missing_CVEs_Detailed","order":["source_severity","cvss","owner_defined"],"ownerDefined":"Medium"}' | ConvertFrom-Json
        @(Test-SIDataModelProItem -Key 'severity-model:Device_Missing_CVEs_Detailed' -Value $ok) | Should -BeNullOrEmpty
        $noOwner = '{"id":"Device_Missing_CVEs_Detailed","order":["cvss"],"ownerDefined":"Medium"}' | ConvertFrom-Json
        (@(Test-SIDataModelProItem -Key 'severity-model:Device_Missing_CVEs_Detailed' -Value $noOwner) -join ' ') | Should -Match 'owner_defined'
        $unknown = '{"id":"Device_Missing_CVEs_Detailed","order":["owner_defined"],"ownerDefined":"Unknown"}' | ConvertFrom-Json
        (@(Test-SIDataModelProItem -Key 'severity-model:Device_Missing_CVEs_Detailed' -Value $unknown) -join ' ') | Should -Match 'ownerDefined must be one of'
    }
}

Describe 'the catalog: every SecuritySeverity is one of the five, never empty' {
    It 'checks every report (not vacuous)' { $script:Reports.Count | Should -BeGreaterThan 100 }
    It 'SELF-CHECK: the reader finds a value outside the five through an alias column, and an empty default' {
        $q = "| extend Lvl = case(Score >= 9, `"Critical`", tolower(W) == `"high`", `"High`", `"Medium`")`n| extend SecuritySeverity = tostring(Lvl)"
        $o = Get-Outcomes -Code $q -Column 'SecuritySeverity'
        @($o.Values) | Should -Contain 'Critical'
        (@($o.Values) -ccontains 'high') | Should -BeFalse -Because 'a comparison''s literal is a condition, not a result'
        $e = Get-Outcomes -Code '| extend SecuritySeverity = case(X >= 1, "High", "")' -Column 'SecuritySeverity'
        @($e.Values) | Should -Contain ''
    }
    It 'every report''s SecuritySeverity can only produce Very High, High, Medium-High, Medium or Low' {
        $bad = New-Object System.Collections.Generic.List[string]
        foreach ($r in $script:Reports) {
            $o = Get-Outcomes -Code (CodeOf $r) -Column 'SecuritySeverity'
            foreach ($x in $o.Problems) { $bad.Add(('{0}: {1}' -f $r.ReportName, $x)) }
            foreach ($v in $o.Values) { if ($script:Five -cnotcontains $v) { $bad.Add(('{0}: produces "{1}"' -f $r.ReportName, $v)) } }
            if (@($o.Values).Count -eq 0) { $bad.Add(('{0}: no severity value found' -f $r.ReportName)) }
        }
        $bad | Should -BeNullOrEmpty -Because 'a value outside the five is dropped by the severity scope or breaks the normalised field; an empty one is a finding without severity'
    }
    It 'no report says "Unknown" as a severity' {
        foreach ($r in $script:Reports) {
            (CodeOf $r) | Should -Not -Match 'SecuritySeverity\s*=\s*"Unknown"' -Because $r.ReportName
            (CodeOf $r) | Should -Not -Match 'SecuritySeverity\s*=\s*case\(\s*isnull\(\w+\),\s*"Unknown"' -Because $r.ReportName
        }
    }
    It 'the tier stays the tier rules'': no report outside the attack paths turns a missing tier into a number' {
        @($script:Reports | Where-Object { [string]$_.ReportName -notlike 'Attack_Paths*' -and (CodeOf $_) -match 'coalesce\(si_tier,\s*\d+\)' } | ForEach-Object ReportName) | Should -BeNullOrEmpty
    }
}
