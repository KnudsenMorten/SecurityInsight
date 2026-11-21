#Requires -Version 7.0
<#
    #1303 (Invardia 2026-11-21): the attack-path port (RA-GraphPathStage.ps1) must recognise the query text the ENGINE really
    sends for one slice -- not only a test rendering of it. Live, every queue worker said "the query is not the one this port
    was written for" and built the whole graph in every slice again (ek: 20 slices lost to 504 Gateway Timeout).

    This suite sends the locked query through the engine's own preparation steps, in the engine's order
    (Invoke-RiskAnalysis.ps1, the block before the bucket loop), then renders one slice with the engine's own bucket filter
    and asks Get-RAGpsQueryShape. After EVERY step the shape is asked again, so a failure names the step that broke it.
    The order of the steps is itself pinned against the engine file (a step added there must be added here). The FIRST step,
    Remove-RAOutBlock, was the live cause: the shape kept a mark for the data-out block the engine takes out.
#>

BeforeAll {
    . (Join-Path $PSScriptRoot '_RaGraphStageTest.ps1')
    $root = $script:RAGsRoot
    foreach ($f in 'engine\data-model\SI-DataModelTemplates.ps1', 'engine\_shared\SI-DisabledAssets.ps1', 'engine\_shared\SI-InstallRows.ps1',
                   'engine\risk-analysis\_shared\RA-CiKql.ps1', 'engine\risk-analysis\_shared\RA-CiContext.ps1', 'engine\risk-analysis\_shared\RA-FactorKeys.ps1',
                   'engine\risk-analysis\_shared\RA-ScopePreamble.ps1', 'engine\risk-analysis\_shared\RA-ExcludeLists.ps1', 'engine\risk-analysis\_shared\RA-ReportHandoff.ps1', 'engine\risk-analysis\_shared\RA-OutBlock.ps1') {
        . (Join-Path $root $f)
    }
    # the engine's own functions and marks that live in the entry script (it runs on load, so they are taken by the AST)
    $script:RaEngineFile = Join-Path $root 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'
    $tk = $null; $er = $null
    $script:RaAst = [System.Management.Automation.Language.Parser]::ParseFile($script:RaEngineFile, [ref]$tk, [ref]$er)
    $want = 'Resolve-ScalarPlaceholders', 'Resolve-CveFilterBlock', 'Resolve-StaleDeviceFilterBlock', 'Add-DeviceKeyBeforeBucketBlock', 'Replace-BucketFilterBlock', 'Test-QueryHasBucketFilterBlock', 'Get-WeightedFactorsConfig'
    foreach ($fn in @($script:RaAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $want -contains $n.Name }, $true))) {
        . ([scriptblock]::Create(($fn.Extent.Text -replace '^function\s+', 'function script:')))
    }
    $marks = '_BucketFilterBeginMark', '_BucketFilterEndMark', '_WeightedFactorsBeginMark', '_WeightedFactorsEndMark', '_CveFilterBeginMark', '_CveFilterEndMark',
             '_StaleDeviceFilterBeginMark', '_StaleDeviceFilterEndMark', '_ScalarTokenMap', '_GlobalExcludeTokens', '_GlobalExcludeFileName'
    foreach ($a in @($script:RaAst.EndBlock.Statements | Where-Object { $_ -is [System.Management.Automation.Language.AssignmentStatementAst] })) {
        $l = $a.Left.Extent.Text
        if ($l -match '^\$script:(?<n>\w+)$' -and $marks -contains $Matches['n']) { . ([scriptblock]::Create($a.Extent.Text)) }
    }
    $script:SkipEGBucketForCrossDomain = $false
    $global:RA_SolutionVersion = '3.1.41'

    function script:Get-RAGsEngineSteps {
        <# The engine's preparation, step by step, as Invoke-RiskAnalysis.ps1 runs it before the bucket loop. Each: @{ Name; Do }. #>
        param([Parameter(Mandatory)][string]$ReportName)
        @(
            @{ Name = 'Remove-RAOutBlock';               Do = { param($q, $ReportName) Remove-RAOutBlock -Query $q } }
            @{ Name = 'Ensure-QueryIsAssetNameSafe';     Do = { param($q, $ReportName) Ensure-QueryIsAssetNameSafe -Query $q } }
            @{ Name = 'Resolve-ExcludePlaceholders';     Do = { param($q, $ReportName) Resolve-ExcludePlaceholders -Query $q -ReportName $ReportName } }
            @{ Name = 'Resolve-RADefenderHandoffBlock';  Do = { param($q, $ReportName) Resolve-RADefenderHandoffBlock -Query $q -ReportName $ReportName -IncludedReports @($ReportName) } }
            @{ Name = 'Resolve-ScalarPlaceholders';      Do = { param($q, $ReportName) Resolve-ScalarPlaceholders -Query $q -ReportName $ReportName } }
            @{ Name = 'Resolve-RAScopePreamble';         Do = { param($q, $ReportName) (Resolve-RAScopePreamble -Query $q -ReportName $ReportName -TierLabels @() -Policy (Get-SIDisabledAssetPolicy)).Query } }
            @{ Name = 'Resolve-CveFilterBlock';          Do = { param($q, $ReportName) Resolve-CveFilterBlock -Query $q -ReportName $ReportName } }
            @{ Name = 'Resolve-StaleDeviceFilterBlock';  Do = { param($q, $ReportName) Resolve-StaleDeviceFilterBlock -Query $q -ReportName $ReportName } }
            @{ Name = 'Resolve-WeightedFactorsBlock';    Do = { param($q, $ReportName) Resolve-WeightedFactorsBlock -Query $q -ReportName $ReportName -Engine 'endpoint' } }
            @{ Name = 'Resolve-RACiFactorsBlock';        Do = { param($q, $ReportName) Resolve-RACiFactorsBlock -Query $q } }
            @{ Name = 'Add-SIInstallRowsFilter';         Do = { param($q, $ReportName) Add-SIInstallRowsFilter -Query $q -SolutionVersion $global:RA_SolutionVersion -LookbackDays 8 } }
            @{ Name = 'Add-DeviceKeyBeforeBucketBlock';  Do = { param($q, $ReportName) Add-DeviceKeyBeforeBucketBlock -Query $q } }
        )
    }
    function script:Get-RAGsSlice {
        <# One slice as the bucket loop renders it (Invoke-RiskAnalysis.ps1: Replace-BucketFilterBlock + New-BucketFilterKql). #>
        param([Parameter(Mandatory)][string]$Query, [Parameter(Mandatory)][string]$ReportName, [int]$Count = 16, [int]$Index = 5)
        Replace-BucketFilterBlock -Query $Query -BucketFilterKql (New-BucketFilterKql -BucketCount $Count -BucketIndex $Index -ReportName $ReportName)
    }
    function script:Get-RAGsFirstDifference {
        <# Where two shape texts first differ, with 160 characters of each from there. #>
        param([string]$A, [string]$B)
        $n = [Math]::Min($A.Length, $B.Length); $i = 0
        while ($i -lt $n -and $A[$i] -eq $B[$i]) { $i++ }
        if ($i -eq $n -and $A.Length -eq $B.Length) { return 'no difference' }
        $s = [Math]::Max(0, $i - 40)
        "at character $i`n  pinned: ...$($A.Substring($s, [Math]::Min(200, $A.Length - $s)))`n  engine: ...$($B.Substring($s, [Math]::Min(200, $B.Length - $s)))"
    }
}

Describe '#1303 the attack-path port recognises the text the engine sends' {
    It 'the engine runs these preparation steps, in this order, before the bucket loop' {
        $t = Get-Content -Raw -LiteralPath $script:RaEngineFile
        $at = -1
        foreach ($s in (Get-RAGsEngineSteps -ReportName 'x')) {
            $p = $t.IndexOf(('= {0} -Query $Query' -f $s.Name), [Math]::Max(0, $at))
            if ($p -lt 0 -and $s.Name -eq 'Resolve-RAScopePreamble') { $p = $t.IndexOf('$raScope = Resolve-RAScopePreamble -Query $Query', [Math]::Max(0, $at)) }
            $p | Should -BeGreaterThan $at -Because "$($s.Name) is a step of the engine, after the one before it"
            $at = $p
        }
    }

    It '<Grain>: every slice the engine builds is answered from the stored graph (shape Ok after each step)' -ForEach @(@{ Grain = 'Detailed' }, @{ Grain = 'Summary' }) {
        $name = "Attack_Paths_${Grain}_Device_with_high_severity_vulnerabilities_allows_lateral_movement_Azure"
        $q = Get-RAGsCatalogQuery -Grain $Grain
        $pinned = Get-RAGpsShapeText -Query $q
        $failed = New-Object System.Collections.Generic.List[string]
        # the text outside the per-run marks must stay the pinned one after every step (a change names its step)
        foreach ($s in (Get-RAGsEngineSteps -ReportName $name)) {
            $q = & $s.Do $q $name
            $now = Get-RAGpsShapeText -Query $q
            if ($now -ne $pinned) { $failed.Add(("after {0}: {1}" -f $s.Name, (Get-RAGsFirstDifference -A $pinned -B $now))); break }
        }
        ($failed -join "`n") | Should -BeNullOrEmpty
        $final = Get-RAGpsQueryShape -Query (Get-RAGsSlice -Query $q -ReportName $name)
        $final.Why | Should -BeNullOrEmpty
        $final.Grain | Should -Be $Grain
        $final.Count | Should -Be 16
        $final.Index | Should -Be 5
    }

    It 'a query that does not use a stored graph is a WARNING (said once), and without a stored graph an INFO line' {
        $q = (Get-RAGsCatalogQuery -Grain 'Detailed') -replace 'tolower\(TargetAzureAssetId\)', 'toupper(TargetAzureAssetId)'
        $q = Get-RAGsSlice -Query (Remove-RAOutBlock -Query $q) -ReportName 'x'
        $script:RAGpsShapeSaid = @{}; $script:RAGpsSet = @{ RunKey = 'r'; RunNo = 1 }; $script:RAGsLog.Clear()
        Get-RAGraphStagePlan -Query $q | Should -BeNullOrEmpty
        Get-RAGraphStagePlan -Query $q | Should -BeNullOrEmpty
        @($script:RAGsLog | Where-Object { $_ -like 'WARN the attack-path graph of this run is in the database, but this query does not use it*' }).Count | Should -Be 1
        $script:RAGpsShapeSaid = @{}; $script:RAGpsSet = $null; $script:RAGsLog.Clear()
        Get-RAGraphStagePlan -Query $q | Should -BeNullOrEmpty
        @($script:RAGsLog | Where-Object { $_ -like 'INFO the attack-path query is asked of advanced hunting as before*' }).Count | Should -Be 1
    }

    It 'the shipped query with its data-out block and the sent query without it have the same shape' {
        foreach ($g in 'Detailed', 'Summary') {
            $q = Get-RAGsCatalogQuery -Grain $g
            $q.IndexOf('//__SI_OUT_BEGIN__') | Should -BeGreaterThan 0
            Get-RAGpsShapeHash -Query (Remove-RAOutBlock -Query $q) | Should -Be (Get-RAGpsShapeHash -Query $q)
        }
    }
}
