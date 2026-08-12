#Requires -Version 5.1
<#
    Summary and Detailed are a PAIR. A fix applied to one and not the other is the defect this pins.

    It is easy to make: the two queries are near-identical, they live hundreds of lines apart in one
    24,000-line YAML, and nothing reads them together. v2.2.429's partition fix had to be applied twice
    by hand; v2.2.430's exclusions report shipped as Detailed-only and the Summary had to follow in
    v2.2.431. Both were caught by an operator, not by a test. Now they are caught here.

    Comments are stripped before matching -- an earlier hand audit reported four false differences
    because one variant simply carried more explanatory text than its twin.
#>

BeforeAll {
    $yamlPath = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'
    Import-Module powershell-yaml -ErrorAction Stop
    $script:Doc = ConvertFrom-Yaml ([System.IO.File]::ReadAllText($yamlPath))

    function script:CodeOf {
        param([string]$Query)
        (($Query -split "`n" | Where-Object { $_.Trim() -notmatch '^//' }) -join "`n")
    }
    function script:QueryOf {
        param([string]$Name)
        ($script:Doc.Reports | Where-Object { $_.ReportName -eq $Name }).ReportQuery
    }
    # base name -> @{ S = <name>; D = <name> }
    $script:Pairs = @{}
    foreach ($r in $script:Doc.Reports) {
        $n = $r.ReportName
        if     ($n -match '^Attack_Paths_(Summary|Detailed)_(.+)$') { $base = 'Attack_Paths_' + $Matches[2]; $kind = $Matches[1] }
        elseif ($n -match '^(.+)_(Summary|Detailed)$')              { $base = $Matches[1];                  $kind = $Matches[2] }
        else { continue }
        if (-not $script:Pairs.ContainsKey($base)) { $script:Pairs[$base] = @{} }
        $script:Pairs[$base][$kind.Substring(0,1)] = $n
    }
}

Describe 'every report is paired' {
    It 'has both a Summary and a Detailed variant' {
        $unpaired = @()
        foreach ($k in $script:Pairs.Keys) {
            $p = $script:Pairs[$k]
            if (-not ($p.ContainsKey('S') -and $p.ContainsKey('D'))) { $unpaired += $k }
        }
        $unpaired -join ', ' | Should -BeExactly ''
    }
}

Describe 'paired reports receive the same structural treatment' {

    It 'both variants carry the same number of __BUCKET_FILTER__ blocks' {
        # v2.2.429 added an EARLY block to partition EG work in the CVE reports. Applying that to one
        # variant only would leave its twin doing the full graph scan per bucket -- the exact timeout
        # the change exists to fix, still present, in the report nobody re-tested.
        $diffs = @()
        foreach ($k in ($script:Pairs.Keys | Sort-Object)) {
            $p = $script:Pairs[$k]
            if (-not ($p.ContainsKey('S') -and $p.ContainsKey('D'))) { continue }
            $s = ([regex]::Matches((script:CodeOf (script:QueryOf $p.S)), '__BUCKET_FILTER_BEGIN__')).Count
            $d = ([regex]::Matches((script:CodeOf (script:QueryOf $p.D)), '__BUCKET_FILTER_BEGIN__')).Count
            if ($s -ne $d) { $diffs += ('{0} (S={1} D={2})' -f $k, $s, $d) }
        }
        $diffs -join '; ' | Should -BeExactly ''
    }

    It 'both variants apply the exclusion filter the same number of times' {
        # If one variant filters excluded assets and its twin does not, the same estate produces two
        # different asset populations depending on which report you read.
        $rx = 'where\s+tobool\(coalesce\(column_ifexists\("IsExcludedByTag"'
        $diffs = @()
        foreach ($k in ($script:Pairs.Keys | Sort-Object)) {
            $p = $script:Pairs[$k]
            if (-not ($p.ContainsKey('S') -and $p.ContainsKey('D'))) { continue }
            $s = ([regex]::Matches((script:CodeOf (script:QueryOf $p.S)), $rx)).Count
            $d = ([regex]::Matches((script:CodeOf (script:QueryOf $p.D)), $rx)).Count
            if ($s -ne $d) { $diffs += ('{0} (S={1} D={2})' -f $k, $s, $d) }
        }
        $diffs -join '; ' | Should -BeExactly ''
    }
}

Describe 'both shipped templates stay in step' {

    It 'RiskAnalysis_Summary and RiskAnalysis_Detailed include the same number of reports' {
        $s = ($script:Doc.ReportTemplates | Where-Object { $_.ReportName -eq 'RiskAnalysis_Summary'  }).ReportsIncluded.Count
        $d = ($script:Doc.ReportTemplates | Where-Object { $_.ReportName -eq 'RiskAnalysis_Detailed' }).ReportsIncluded.Count
        $s | Should -Be $d
    }

    It 'every templated report name resolves to a real report definition' {
        # An unresolvable name fails the run partway through, after the earlier reports have already
        # spent their query time.
        $defined = $script:Doc.Reports.ReportName
        foreach ($t in 'RiskAnalysis_Summary','RiskAnalysis_Detailed') {
            $tpl = $script:Doc.ReportTemplates | Where-Object { $_.ReportName -eq $t }
            $missing = @($tpl.ReportsIncluded.Name | Where-Object { $_ -notin $defined })
            $missing -join ', ' | Should -BeExactly '' -Because "template $t must not name a report that does not exist"
        }
    }

    It 'the exclusions report is present in BOTH templates' {
        foreach ($t in 'RiskAnalysis_Summary','RiskAnalysis_Detailed') {
            $tpl = $script:Doc.ReportTemplates | Where-Object { $_.ReportName -eq $t }
            @($tpl.ReportsIncluded.Name | Where-Object { $_ -like 'Endpoint_ExcludedAssets_*' }).Count |
                Should -Be 1 -Because "$t must surface suppressed assets"
        }
    }
}

Describe '🔴 the exclusions reports must NOT filter excluded assets out' {
    # They are the inverse of every other report: excluded assets are the subject. Adding the standard
    # filter here would make them permanently return zero rows -- and a governance report that silently
    # reports "nothing suppressed" is worse than not having one.

    It '<_> applies no exclusion filter' -ForEach @('Endpoint_ExcludedAssets_Summary','Endpoint_ExcludedAssets_Detailed') {
        $code = script:CodeOf (script:QueryOf $_)
        $code | Should -Not -Match 'where\s+tobool\(coalesce\(column_ifexists\("IsExcludedByTag"'
    }

    It '<_> selects excluded assets rather than all of them' -ForEach @('Endpoint_ExcludedAssets_Summary','Endpoint_ExcludedAssets_Detailed') {
        (script:CodeOf (script:QueryOf $_)) | Should -Match '_IsExcluded == true'
    }

    It '<_> reads only CL tables, so it can never hit the advanced-hunting 900s ceiling' -ForEach @('Endpoint_ExcludedAssets_Summary','Endpoint_ExcludedAssets_Detailed') {
        (script:CodeOf (script:QueryOf $_)) | Should -Not -Match 'ExposureGraph(Nodes|Edges)'
    }
}
