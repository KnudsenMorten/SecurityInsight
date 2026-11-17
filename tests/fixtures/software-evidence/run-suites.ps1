#Requires -Version 7.0
<#
    the runner command of the software evidence lane (Azure test runner only): the named suites, the SQL login from TEST_SQL_*,
    JUnit results.
      pwsh -NoProfile -File SOLUTIONS/SecurityInsight/tests/fixtures/software-evidence/run-suites.ps1 -Suites 'SIv3-SoftwareEvidence;SIv3-DataModelEnrich'
#>
param([Parameter(Mandatory)][string]$Suites)
$ErrorActionPreference = 'Stop'
$pester = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'pester'
. (Join-Path $pester '_SITestSql.ps1')
$s = Initialize-SITestSqlEnv
Write-Host ("SQL: {0} ({1})" -f $s.Server, $s.Source)
$c = New-PesterConfiguration
$c.Run.Path = @($Suites -split ';' | Where-Object { $_ } | ForEach-Object { Join-Path $pester "$_.Tests.ps1" })
$c.Run.Exit = $true
$c.Output.Verbosity = 'Detailed'
$c.TestResult.Enabled = $true; $c.TestResult.OutputFormat = 'JUnitXml'; $c.TestResult.OutputPath = (Join-Path (Get-Location) 'software-evidence-junit.xml')
# the Windows-marked tests run on the Windows test VM only (framework 12.1 rule 6)
$c.Filter.ExcludeTag = @('Scale', 'Windows')
Invoke-Pester -Configuration $c