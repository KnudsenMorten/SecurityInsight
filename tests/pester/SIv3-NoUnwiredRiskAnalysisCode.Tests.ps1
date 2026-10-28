#Requires -Version 5.1
<#
    TWO PIECES OF RISK ANALYSIS CODE THAT NOTHING COULD REACH ARE GONE, AND STAY GONE.

    * Apply-ScopeFilter (RA-RowShaping.ps1) -- called by nothing. It also omitted -IncludeBlank:$true, so reviving it
      would have dropped blank-severity rows, unlike the live scope filter.
    * The "skip the remaining buckets" branch keyed on $script:_AutoBucketSkipRemainingBuckets -- the flag was set to
      $false and never to $true, so the branch (and its bucket-loss accounting) could never run.
    Neither is dispatched by a constructed name (the engine's `& ('Invoke-SI{0}' -f ...)` dispatch covers only the
    profiling stages), so removing them changes nothing a run does.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:Files  = @(Get-ChildItem -LiteralPath (Join-Path $script:SIRoot 'engine') -Recurse -File -Include '*.ps1', '*.psm1')
}

Describe 'unreachable Risk Analysis code' {
    It 'the engine tree was actually read' { $script:Files.Count | Should -BeGreaterThan 50 }

    It '<_> appears nowhere in the engine' -ForEach @('Apply-ScopeFilter', '_AutoBucketSkipRemainingBuckets') {
        $name = $_
        $hits = @($script:Files | Where-Object { [System.IO.File]::ReadAllText($_.FullName).Contains($name) } | ForEach-Object { $_.FullName })
        $hits.Count | Should -Be 0 -Because ("it was unreachable and was removed:`n" + ($hits -join "`n"))
    }

    It 'the live scope filter it duplicated is still there' {
        $src = [System.IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'))
        $src | Should -Match 'function Filter-ObjectsByColumn'
        $src | Should -Match 'Filter-ObjectsByColumn -InputObject @\(\$ResultFiltered\)'
    }
}
