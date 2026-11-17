#Requires -Version 7.0
<#
    The Azure test runner's command for ONE on-demand SCALE suite (Pester tag Scale -- run only on the owner's words for a
    release): the SQL login from TEST_SQL_*, the bench sizes as NAME=VALUE pairs (-Env, separated by , or + -- use + when the runner's command holds several commands), the suite's wall time
    and this process's PEAK memory printed at the end. -At <commit>: the same suite from that commit's tree (a git worktree of
    the bundled history), for a before/after comparison.
      pwsh -NoProfile -File SOLUTIONS/SecurityInsight/tests/fixtures/review1/run-scale.ps1 -Suite SIv3-RemediationTaskScale -Env SI_BENCH_FINDINGS=2000000,SI_BENCH_CIS=50000
#>
param([Parameter(Mandatory)][string]$Suite, [string]$Env = '', [string]$At = '', [switch]$CurrentTest)
$ErrorActionPreference = 'Stop'
$si = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
$repo = Split-Path -Parent (Split-Path -Parent $si)
$tree = $si
if ($At) {
    $wt = Join-Path ([IO.Path]::GetTempPath()) ('si-scale-at-' + $At.Substring(0, [Math]::Min(9, $At.Length)))
    & git -C $repo worktree add --detach $wt $At 2>&1 | Out-Host
    if ($LASTEXITCODE -ne 0) { Write-Host "SCALE: the commit $At is not in this run's history -- not run there"; exit 3 }
    $tree = Join-Path $wt 'SOLUTIONS\SecurityInsight'
    # -CurrentTest: this branch's suite file run over that commit's code (a test fixed since runs against the code before)
    if ($CurrentTest) { Copy-Item -LiteralPath (Join-Path $si "tests\pester\$Suite.Tests.ps1") -Destination (Join-Path $tree "tests\pester\$Suite.Tests.ps1") -Force; Write-Host "SCALE: this branch's $Suite.Tests.ps1 over $At's code" }
}
. (Join-Path $si 'tests\pester\_SITestSql.ps1')
$s = Initialize-SITestSqlEnv
Write-Host ("SQL: {0} ({1})" -f $s.Server, $s.Source)
foreach ($pair in @($Env -split '[,+]' | Where-Object { $_ })) { $k, $v = $pair -split '=', 2; [Environment]::SetEnvironmentVariable($k.Trim(), $v.Trim()); Write-Host ("SCALE: {0}={1}" -f $k.Trim(), $v.Trim()) }
$c = New-PesterConfiguration
$c.Run.Path = @(Join-Path $tree "tests\pester\$Suite.Tests.ps1")
$c.Run.PassThru = $true
$c.Output.Verbosity = 'Detailed'
$c.TestResult.Enabled = $true; $c.TestResult.OutputFormat = 'JUnitXml'; $c.TestResult.OutputPath = (Join-Path (Get-Location) "scale-$Suite.xml")
$sw = [Diagnostics.Stopwatch]::StartNew()
$r = Invoke-Pester -Configuration $c
$p = [Diagnostics.Process]::GetCurrentProcess(); $p.Refresh()
Write-Host ("SCALE RESULT: {0}{1} -- passed {2} failed {3} skipped {4}; {5:N0} s; peak memory {6:N0} MB (working set), {7:N0} MB (private now)" -f $Suite, $(if ($At) { " at $At" } else { '' }), $r.PassedCount, $r.FailedCount, $r.SkippedCount, $sw.Elapsed.TotalSeconds, ($p.PeakWorkingSet64 / 1MB), ($p.PrivateMemorySize64 / 1MB))
if ($r.FailedCount -gt 0 -or $r.PassedCount -eq 0) { exit 1 }
exit 0
