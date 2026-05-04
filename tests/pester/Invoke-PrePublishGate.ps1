#Requires -Version 5.1
<#
.SYNOPSIS
    Run the SI v2.2 pre-publish Pester gate, print a category summary, and
    exit non-zero on any failure (suitable for CI gating).

.DESCRIPTION
    Wraps `Invoke-Pester` over `SI-v2.2.PrePublish.Tests.ps1` (sibling file in
    this folder). Aggregates results by Describe-block and prints a single
    pass/fail line per category, with a final BLOCKED/READY verdict. Designed
    so the developer can read one screen and know whether to ship.

    Exit codes:
       0 = all green, publish gate READY
       1 = one or more failures, publish gate BLOCKED
       2 = setup failure (Pester missing, test file missing, etc.)

.EXAMPLE
    pwsh -File ./Invoke-PrePublishGate.ps1
    powershell.exe -NoProfile -File ./Invoke-PrePublishGate.ps1
#>
[CmdletBinding()]
param(
    [string]$TestsFolder = $PSScriptRoot,   # all *.Tests.ps1 in this folder
    [switch]$Detailed
)

$ErrorActionPreference = 'Stop'

# --- prereqs ---
$testFiles = Get-ChildItem -Path $TestsFolder -Filter '*.Tests.ps1' -File -ErrorAction SilentlyContinue
if ($testFiles.Count -eq 0) {
    Write-Host "FATAL: no *.Tests.ps1 files in: $TestsFolder" -ForegroundColor Red
    exit 2
}
$pester = Get-Module -ListAvailable -Name Pester | Where-Object { $_.Version.Major -ge 5 } | Sort-Object Version -Descending | Select-Object -First 1
if (-not $pester) {
    Write-Host "FATAL: Pester >= 5.0 required. Install: Install-Module Pester -MinimumVersion 5.0 -Scope CurrentUser" -ForegroundColor Red
    exit 2
}
Import-Module Pester -MinimumVersion 5.0 -Force

# --- run ---
$cfg = New-PesterConfiguration
$cfg.Run.Path = $testFiles.FullName
$cfg.Run.PassThru = $true
$cfg.Output.Verbosity = if ($Detailed) { 'Detailed' } else { 'None' }
$cfg.TestResult.Enabled = $false   # don't write NUnit XML by default

$startedAt = Get-Date
$result = Invoke-Pester -Configuration $cfg
$elapsed = (Get-Date) - $startedAt

# --- aggregate by Describe block (top-level container) ---
function Get-DescribeName {
    param($test)
    # Walk up the block hierarchy to the top-level Describe
    $b = $test.Block
    while ($b -and $b.Parent -and $b.Parent.Name -ne 'Root') { $b = $b.Parent }
    if ($b) { $b.Name } else { '<unknown>' }
}

$byDescribe = [ordered]@{}
foreach ($t in $result.Tests) {
    $d = Get-DescribeName $t
    if (-not $byDescribe.Contains($d)) {
        $byDescribe[$d] = [pscustomobject]@{ Name=$d; Pass=0; Fail=0; Skip=0; Failures=@() }
    }
    switch ($t.Result) {
        'Passed'  { $byDescribe[$d].Pass++ }
        'Failed'  { $byDescribe[$d].Fail++; $byDescribe[$d].Failures += $t }
        'Skipped' { $byDescribe[$d].Skip++ }
    }
}

# --- print summary ---
$line = '-' * 72
Write-Host ''
Write-Host $line -ForegroundColor Cyan
Write-Host '  SecurityInsight v2.2  --  Pre-Publish Gate' -ForegroundColor Cyan
Write-Host $line -ForegroundColor Cyan
Write-Host ''

$catWidth = ($byDescribe.Keys | Measure-Object -Maximum -Property Length).Maximum
if (-not $catWidth -or $catWidth -lt 20) { $catWidth = 20 }

foreach ($k in $byDescribe.Keys) {
    $row = $byDescribe[$k]
    $total = $row.Pass + $row.Fail + $row.Skip
    $tag   = if ($row.Fail -gt 0) { 'FAIL' } elseif ($row.Skip -gt 0 -and $row.Pass -eq 0) { 'SKIP' } else { 'PASS' }
    $color = if ($row.Fail -gt 0) { 'Red' } elseif ($row.Skip -gt 0) { 'Yellow' } else { 'Green' }
    $line  = '  {0}  {1,4}/{2,-4}  {3}' -f ($k.PadRight($catWidth)), ($row.Pass), $total, $tag
    if ($row.Skip -gt 0) { $line += " (skip $($row.Skip))" }
    Write-Host $line -ForegroundColor $color
}

Write-Host ''
Write-Host ('  TOTAL    {0}/{1}    elapsed {2:N1}s' -f $result.PassedCount, $result.TotalCount, $elapsed.TotalSeconds)
Write-Host ''

# --- print failures (top 15) ---
$failed = $result.Tests | Where-Object Result -eq 'Failed'
if ($failed.Count -gt 0) {
    Write-Host ('FAILURES (' + $failed.Count + ')') -ForegroundColor Red
    $failed | Select-Object -First 15 | ForEach-Object {
        $describe = Get-DescribeName $_
        Write-Host ('  [' + $describe + '] ' + $_.Name) -ForegroundColor Red
        if ($_.ErrorRecord) {
            $msg = ($_.ErrorRecord[0].Exception.Message -split "`n")[0]
            Write-Host ('       -> ' + $msg) -ForegroundColor DarkGray
        }
    }
    if ($failed.Count -gt 15) { Write-Host ('  ... and ' + ($failed.Count - 15) + ' more (run with -Detailed for full output)') -ForegroundColor DarkGray }
    Write-Host ''
}

# --- verdict ---
if ($result.FailedCount -eq 0) {
    Write-Host '  PUBLISH GATE: READY  ' -BackgroundColor DarkGreen -ForegroundColor White
    Write-Host ''
    exit 0
} else {
    Write-Host ('  PUBLISH GATE: BLOCKED  (' + $result.FailedCount + ' failure(s))') -BackgroundColor DarkRed -ForegroundColor White
    Write-Host ''
    exit 1
}
