#Requires -Version 5.1
<#
    #278 -- THE AZURE RECOMMENDATIONS HAND-OFF: NOTHING HANDED TO A REPORT THAT DOES NOT RUN, AND A MOVE IS NOT A LOSS.

    Since #147 the Exposure Graph recommendation reports (Azure_Recommendations_*) leave every (resource,
    recommendation) pair Defender for Cloud carries to the Defender recommendation reports
    (Azure_DefenderRecommendations_*). Measured 2026-10-04:
      * 2.2 -> 3 upgrade test: Azure_Recommendations_Detailed 720 -> 19 and the guards said LARGE-DROP /
        COLUMN-EMPTIED. Every one of the 701 rows that left was in Azure_DefenderRecommendations_Detailed
        (1,667 rows). A move, reported as a loss.
      * ring 1: both Defender reports failed with a 400 on EVERY run. Their union stub declared
        AffectedEntityCount:int / SubFindingCount:int while that workspace's table has them as long, so union
        split each into _int and _long columns and the plain name no longer existed. The graph report still
        handed 170 rows to the failing report -- those findings, and all 750 Defender rows, were in no report.
    A Log Analytics type mismatch cannot be reproduced offline, so the query half is asserted on its shape.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $shared = Join-Path $script:SIRoot 'engine\risk-analysis\_shared'
    function script:Write-Info  { param($m) }
    function script:Write-Warn2 { param($m) }
    . (Join-Path $shared 'RA-ReportHandoff.ps1')
    . (Join-Path $shared 'RA-RowCountGuard.ps1')
    . (Join-Path $shared 'RA-ColumnFillGuard.ps1')
    $script:Y = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'))
    function script:Get-ReportBlock([string]$name) {
        [regex]::Match($script:Y, "(?s)- ReportName: $name\r?\n.*?(?=\r?\n    - ReportName: |\z)").Value
    }
}

Describe 'the Defender recommendation reports read the count columns whatever type the table has' {
    It 'the union stub declares neither count column (a typed stub that disagrees with the table fails the report)' {
        foreach ($g in 'Summary', 'Detailed') {
            $b = Get-ReportBlock "Azure_DefenderRecommendations_$g"
            $b | Should -Not -BeNullOrEmpty
            $stub = [regex]::Match($b, '(?s)let _recAll = union isfuzzy=true\s*\(datatable\((?<cols>[^)]*)\)\[\]\)').Groups['cols'].Value
            $stub | Should -Not -BeNullOrEmpty
            $stub | Should -Not -Match 'AffectedEntityCount'
            $stub | Should -Not -Match 'SubFindingCount'
            # the rest of the stub is unchanged: an install that has not collected yet still gets an empty report
            $stub | Should -Match 'CollectionTime:datetime'
            $stub | Should -Match 'ResourceIdLower:string'
        }
    }
    It 'the counts are read after the union with column_ifexists, so int, long and no table all work' {
        foreach ($g in 'Summary', 'Detailed') {
            $b = Get-ReportBlock "Azure_DefenderRecommendations_$g"
            $let = [regex]::Match($b, '(?s)let _recAll = .*?;').Value
            $let | Should -Match '\(SI_AzureRecommendation_CL \| where TimeGenerated > ago\(8d\)\)'
            $let | Should -Match 'extend AffectedEntityCount = toint\(column_ifexists\("AffectedEntityCount", int\(null\)\)\)'
            $let | Should -Match 'SubFindingCount = toint\(column_ifexists\("SubFindingCount", int\(null\)\)\)'
        }
    }
    It 'no report declares a typed count column for this table anywhere' {
        $script:Y | Should -Not -Match 'AffectedEntityCount:(int|long)'
        $script:Y | Should -Not -Match 'SubFindingCount:(int|long)'
    }
}

Describe 'the graph reports hand findings only to a Defender report that runs' {
    BeforeAll {
        $script:Graph = @{}
        foreach ($g in 'Summary', 'Detailed') { $script:Graph[$g] = Get-ReportBlock "Azure_Recommendations_$g" }
    }
    It 'both graph reports wrap the hand-off lookup in the markers the engine substitutes' {
        foreach ($g in 'Summary', 'Detailed') {
            $b = $script:Graph[$g]
            $blk = [regex]::Match($b, '(?s)//__DEFENDER_HANDOFF_BEGIN__(?<body>.*?)//__DEFENDER_HANDOFF_END__')
            $blk.Success | Should -BeTrue
            $blk.Groups['body'].Value | Should -Match 'let _dfcPairs = union isfuzzy=true'
            $blk.Groups['body'].Value | Should -Match '\| project _dfcKey;'
        }
    }
    It 'the hand-off lookup carries no column the slices are cut on, so it is never split per slice' {
        # Live 2026-10-14: a _ciKey column on _dfcPairs made the engine split the lookup on the resource id. Two of its
        # three pair keys (name + recommendation, resource + assessment key) do not follow that id, so their matches
        # fell into other slices and 147 recommendations Defender already reports stayed in the graph report (27 -> 174).
        # A lookup too large to travel whole is cut by the keys a slice needs (LookupNeededKeys), never by an id.
        foreach ($g in 'Summary', 'Detailed') {
            $body = [regex]::Match($script:Graph[$g], '(?s)//__DEFENDER_HANDOFF_BEGIN__(?<body>.*?)//__DEFENDER_HANDOFF_END__').Groups['body'].Value
            $body | Should -Match 'datatable\(_dfcKey:string\)\[\]'
            $body | Should -Not -Match '_ciKey|DeviceKey|si_ci_id'
            $script:Graph[$g] | Should -Match '(?m)^\s*- Lookup: _dfcPairs' -Because 'without the key cut the lookup would travel whole in every slice'
        }
    }
    It 'with the Defender report of the same grain in the run, the query is unchanged' {
        foreach ($g in 'Summary', 'Detailed') {
            $q = $script:Graph[$g]
            $out = Resolve-RADefenderHandoffBlock -Query $q -ReportName "Azure_Recommendations_$g" -IncludedReports @("Azure_Recommendations_$g", "Azure_DefenderRecommendations_$g")
            $out | Should -BeExactly $q
        }
    }
    It 'without it, the lookup becomes empty -- every recommendation stays in the graph report' {
        foreach ($g in 'Summary', 'Detailed') {
            $q = $script:Graph[$g]
            $out = Resolve-RADefenderHandoffBlock -Query $q -ReportName "Azure_Recommendations_$g" -IncludedReports @("Azure_Recommendations_$g", 'Device_Recommendations_Summary')
            $out | Should -Not -BeExactly $q
            $blk = [regex]::Match($out, '(?s)//__DEFENDER_HANDOFF_BEGIN__(?<body>.*?)//__DEFENDER_HANDOFF_END__').Groups['body'].Value
            $blk.Trim() | Should -BeExactly 'let _dfcPairs = datatable(_dfcKey:string)[];'
            # #349 the severity lookup by assessment key reads the same table on purpose and is not a hand-off -- it stays
            $rest = [regex]::Replace($out, '(?s)let _dfcRecByKey = .*?;', '')
            $rest | Should -Not -Match 'SI_AzureRecommendation_CL'
            # both drops still parse -- they now anti-join against nothing
            $out | Should -Match 'join kind=leftanti \(_dfcPairs\) on _dfcKey'
        }
    }
    It 'a Detailed graph report is not satisfied by the SUMMARY Defender report (same grain only)' {
        $q = $script:Graph['Detailed']
        $out = Resolve-RADefenderHandoffBlock -Query $q -ReportName 'Azure_Recommendations_Detailed' -IncludedReports @('Azure_Recommendations_Detailed', 'Azure_DefenderRecommendations_Summary')
        $out | Should -Not -BeExactly $q
    }
    It 'an unknown run (no report list) and a query without markers are left alone' {
        $q = $script:Graph['Detailed']
        Resolve-RADefenderHandoffBlock -Query $q -ReportName 'Azure_Recommendations_Detailed' -IncludedReports @() | Should -BeExactly $q
        Resolve-RADefenderHandoffBlock -Query 'T | take 1' -ReportName 'Azure_Recommendations_Detailed' -IncludedReports @('x') | Should -BeExactly 'T | take 1'
    }
    It 'the engine applies it to every report, with this run''s report list (wiring, asserted separately)' {
        $eng = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'))
        $eng | Should -Match "\. \(Join-Path \`$PSScriptRoot '_shared/RA-ReportHandoff\.ps1'\)"
        $eng | Should -Match '\$global:RA_TemplateReportNames = @\(\$incNamesForLog\)'
        $excl = $eng.IndexOf('$Query = Resolve-ExcludePlaceholders -Query $Query -ReportName $ReportName')
        $ho   = $eng.IndexOf('$Query = Resolve-RADefenderHandoffBlock -Query $Query -ReportName $ReportName -IncludedReports @($global:RA_TemplateReportNames)')
        $excl | Should -BeGreaterThan 0
        $ho   | Should -BeGreaterThan $excl
        # the report list is set BEFORE any report query is prepared
        $eng.IndexOf('$global:RA_TemplateReportNames = @($incNamesForLog)') | Should -BeLessThan $ho
    }
}

Describe 'the run-over-run row-count guard: a move is reported as a move, a lost hand-off is loud' {
    It 'the 2.2 -> 3 upgrade (720 -> 19, receiver new with 1,667) is HANDED-OFF, not LARGE-DROP' {
        $prev = @{ 'Azure_Recommendations_Detailed' = 720 }
        $curr = @{ 'Azure_Recommendations_Detailed' = 19; 'Azure_DefenderRecommendations_Detailed' = 1667 }
        $f = @(Get-RARowCountRegressions -Previous $prev -Current $curr)
        $f.Count | Should -Be 1
        $f[0].Kind | Should -Be 'HANDED-OFF'
        $f[0].Successor | Should -Be 'Azure_DefenderRecommendations_Detailed'
        $f[0].SuccessorCurrent | Should -Be 1667
        @($f | Where-Object { $_.Kind -eq 'LARGE-DROP' }).Count | Should -Be 0
    }
    It 'the same counts WITHOUT the hand-off map are a LARGE-DROP (the old behaviour this replaces)' {
        $prev = @{ 'Azure_Recommendations_Detailed' = 720 }
        $curr = @{ 'Azure_Recommendations_Detailed' = 19; 'Azure_DefenderRecommendations_Detailed' = 1667 }
        $f = @(Get-RARowCountRegressions -Previous $prev -Current $curr -Successors @{})
        $f[0].Kind | Should -Be 'LARGE-DROP'
    }
    It 'a receiver that came up short is still a loss' {
        $prev = @{ 'Azure_Recommendations_Detailed' = 720 }
        $curr = @{ 'Azure_Recommendations_Detailed' = 19; 'Azure_DefenderRecommendations_Detailed' = 40 }
        (@(Get-RARowCountRegressions -Previous $prev -Current $curr))[0].Kind | Should -Be 'LARGE-DROP'
    }
    It 'once the receiver has a history, the graph report is compared with itself again' {
        $prev = @{ 'Azure_Recommendations_Detailed' = 300; 'Azure_DefenderRecommendations_Detailed' = 1600 }
        $curr = @{ 'Azure_Recommendations_Detailed' = 0;   'Azure_DefenderRecommendations_Detailed' = 1650 }
        (@(Get-RARowCountRegressions -Previous $prev -Current $curr))[0].Kind | Should -Be 'WENT-TO-ZERO'
    }
    It 'a receiver that was attempted and produced nothing is HANDOFF-LOST -- even on the first run (ring 1)' {
        $f = @(Get-RARowCountRegressions -Previous @{} -Current @{ 'Azure_Recommendations_Summary' = 184 } `
                 -Attempted @('Azure_Recommendations_Summary', 'Azure_DefenderRecommendations_Summary'))
        $f.Count | Should -Be 1
        $f[0].Kind      | Should -Be 'HANDOFF-LOST'
        $f[0].Report    | Should -Be 'Azure_Recommendations_Summary'
        $f[0].Successor | Should -Be 'Azure_DefenderRecommendations_Summary'
    }
    It 'a receiver that ran (even with zero rows) is not HANDOFF-LOST; one not in the run is not either' {
        @(Get-RARowCountRegressions -Previous @{} -Current @{ 'Azure_Recommendations_Summary' = 184; 'Azure_DefenderRecommendations_Summary' = 0 } `
            -Attempted @('Azure_Recommendations_Summary', 'Azure_DefenderRecommendations_Summary')).Count | Should -Be 0
        @(Get-RARowCountRegressions -Previous @{} -Current @{ 'Azure_Recommendations_Summary' = 184 } -Attempted @('Azure_Recommendations_Summary')).Count | Should -Be 0
    }
    It 'Invoke reports HANDED-OFF as information, never as the FEWER-findings warning' {
        $script:warned = New-Object System.Collections.Generic.List[string]
        $script:infos  = New-Object System.Collections.Generic.List[string]
        function script:Write-Warn2 { param($m) $script:warned.Add([string]$m) }
        function script:Write-Info  { param($m) $script:infos.Add([string]$m) }
        $dir = Join-Path ([IO.Path]::GetTempPath()) ('si-276-' + [guid]::NewGuid().ToString('N'))
        try {
            $null = Invoke-RARowCountGuard -SettingsPath $dir -TemplateName 'RiskAnalysis_Detailed' -Counts @{ 'Azure_Recommendations_Detailed' = 720 }
            $null = Invoke-RARowCountGuard -SettingsPath $dir -TemplateName 'RiskAnalysis_Detailed' -Counts @{ 'Azure_Recommendations_Detailed' = 19; 'Azure_DefenderRecommendations_Detailed' = 1667 }
            @($script:warned).Count | Should -Be 0
            ($script:infos -join "`n") | Should -Match 'moved, not lost'
        } finally {
            Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
            function script:Write-Warn2 { param($m) }
            function script:Write-Info  { param($m) }
        }
    }
}

Describe 'the column-fill guard does not compare a report across a hand-off' {
    It 'the upgrade run: RiskFactor_Consequence_Detailed 623/720 -> 0/19 is not COLUMN-EMPTIED while the receiver is new' {
        $prev = @{ 'Azure_Recommendations_Detailed' = @{ '__rows' = 720; 'RiskFactor_Consequence_Detailed' = 623; 'AssetName' = 720 } }
        $curr = @{ 'Azure_Recommendations_Detailed' = @{ '__rows' = 19;  'RiskFactor_Consequence_Detailed' = 0;   'AssetName' = 19 }
                   'Azure_DefenderRecommendations_Detailed' = @{ '__rows' = 1667; 'AssetName' = 1667 } }
        @(Get-RAColumnFillRegressions -Previous $prev -Current $curr).Count | Should -Be 0
    }
    It 'without the hand-off map the same snapshots are COLUMN-EMPTIED (the old behaviour this replaces)' {
        $prev = @{ 'Azure_Recommendations_Detailed' = @{ '__rows' = 720; 'RiskFactor_Consequence_Detailed' = 623 } }
        $curr = @{ 'Azure_Recommendations_Detailed' = @{ '__rows' = 19;  'RiskFactor_Consequence_Detailed' = 0 }
                   'Azure_DefenderRecommendations_Detailed' = @{ '__rows' = 1667 } }
        (@(Get-RAColumnFillRegressions -Previous $prev -Current $curr -Successors @{}))[0].Kind | Should -Be 'COLUMN-EMPTIED'
    }
    It 'from the next run on, the report is compared with itself again' {
        $prev = @{ 'Azure_Recommendations_Detailed' = @{ '__rows' = 19; 'cmdbName' = 19 }; 'Azure_DefenderRecommendations_Detailed' = @{ '__rows' = 1667 } }
        $curr = @{ 'Azure_Recommendations_Detailed' = @{ '__rows' = 19; 'cmdbName' = 0 };  'Azure_DefenderRecommendations_Detailed' = @{ '__rows' = 1667 } }
        (@(Get-RAColumnFillRegressions -Previous $prev -Current $curr))[0].Kind | Should -Be 'COLUMN-EMPTIED'
    }
}
