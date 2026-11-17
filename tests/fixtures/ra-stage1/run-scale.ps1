#Requires -Version 7.0
<#
    #1275 stage 1 -- the ON-DEMAND scale benches (Azure test runner only, never a gate): the tests tagged Scale of the named
    suites, with every line they print (the quick gate keeps a suite's own lines to itself, and ends a suite that prints
    nothing for 5 minutes -- a 1.5 M-row bench copies rows in SQL for longer than that). The SQL login from TEST_SQL_*.
      pwsh -NoProfile -File SOLUTIONS/SecurityInsight/tests/fixtures/ra-stage1/run-scale.ps1 -Suites SIv3-RaStage1,SIv3-RaTop50SetBased   (a comma, not ';')
#>
param([string]$Suites = 'SIv3-RaStage1,SIv3-RaTop50SetBased', [string]$Name = 'ra-stage1-scale')
$ErrorActionPreference = 'Stop'
$pester = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'pester'
. (Join-Path $pester '_SITestSql.ps1')
$s = Initialize-SITestSqlEnv
Write-Host ("SQL: {0} ({1})" -f $s.Server, $s.Source)
$c = New-PesterConfiguration
$c.Run.Path = @($Suites -split '[;,\s]+' | Where-Object { $_ } | ForEach-Object { Join-Path $pester "$_.Tests.ps1" })
$c.Run.PassThru = $true
$c.Output.Verbosity = 'Detailed'
$c.Filter.Tag = @('Scale')
$c.TestResult.Enabled = $true; $c.TestResult.OutputFormat = 'JUnitXml'; $c.TestResult.OutputPath = (Join-Path (Get-Location) "$Name-junit.xml")
$r = Invoke-Pester -Configuration $c
Write-Host ("PESTER: passed {0} failed {1} skipped {2} not run {3}" -f $r.PassedCount, $r.FailedCount, $r.SkippedCount, $r.NotRunCount)
if ($r.FailedCount -gt 0 -or $r.Result -ne 'Passed') { exit 1 }
exit 0
