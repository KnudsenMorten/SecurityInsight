#Requires -Version 7.0
<#
    THE CI BUILD'S ENRICHMENT THREADS share the rules and the catalogs safely: the threads cases of SIv3-CiBuildSpeed.Tests.ps1,
    in their own file so the Linux runner runs them beside the rest (framework 12.1 rule 10). The set-up is the shared
    _SIv3CiBuildSpeedSetup.ps1. PowerShell 7.
#>

BeforeDiscovery {
    $script:IsPwsh = $PSVersionTable.PSVersion.Major -ge 7
    $script:HasSql = [bool]($env:SI_TEST_LOCALSQL)
}

BeforeAll {
    . (Join-Path $PSScriptRoot '_SIv3CiBuildSpeedSetup.ps1')
}

AfterAll { Restore-CiPerfSpeedGlobals }

Describe 'The enrichment''s threads share the rules and the catalogs safely' -Skip:(-not $script:IsPwsh) {
    It 'reads objects no thread has read before on 8 threads without a failure once they are prepared on one thread' {
        $fails = 0
        for ($r = 0; $r -lt 10; $r++) {
            $objs = @(1..2000 | ForEach-Object { '{"field":"f' + $_ + '","op":"eq","value":"x","any":null}' } | ConvertFrom-Json)
            $null = Initialize-SICiSharedObjects -Roots @(, $objs)
            $res = @(1..8 | ForEach-Object -ThrottleLimit 8 -Parallel {
                    try { foreach ($o in $using:objs) { foreach ($k in 'all', 'any', 'field', 'op', 'value') { $p = $o.PSObject.Properties[$k]; if ($p) { $null = $p.Value } } } } catch { 'ERR ' + $_.Exception.Message }
                })
            if (@($res | Where-Object { $_ -like 'ERR*' }).Count) { $fails++ }
        }
        $fails | Should -Be 0
    }

    It 'enriches on 4 threads exactly as on one' {
        # the CI documents before enrichment, twice over (the threads start from 500 CIs -- Get-SICiParallelism), in two copies
        $raw = New-Object System.Collections.Generic.List[object]
        $plan = @(Get-SICiFieldPlan -Catalog $script:Model['field-catalog'])
        foreach ($k in 1, 2) {
            $n = 0
            foreach ($g in (Groups)) {
                $n++
                $raw.Add((New-SICiDocument -CiId ('c{0}-{1}' -f $k, $n) -Records @($g.Members | ForEach-Object { $_.Record }) -Catalog $script:Model['field-catalog'] -FeedLatest $script:Feeds -Now $script:Now -FieldPlan $plan))
            }
        }
        $copy = { @(foreach ($x in $raw) { ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $x -Depth 20 -Compress) -AsHashtable }) }
        $a = & $copy; $b = & $copy
        $a.Count | Should -BeGreaterOrEqual 500
        $global:SI_CiParallel = 'off'
        $null = Invoke-SICiEnrichment -Cis $a -Model $script:Model -Rules $script:Rules -CmdbIndex (New-SICiCmdbIndex) -Now $script:Now
        $global:SI_CiParallel = '4'
        try { $null = Invoke-SICiEnrichment -Cis $b -Model $script:Model -Rules $script:Rules -CmdbIndex (New-SICiCmdbIndex) -Now $script:Now }
        finally { $global:SI_CiParallel = 'off' }
        for ($i = 0; $i -lt $a.Count; $i++) { (Canon $b[$i]) | Should -BeExactly (Canon $a[$i]) }
    }
}
