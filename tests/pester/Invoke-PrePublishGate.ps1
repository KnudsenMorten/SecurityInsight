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
       2 = setup failure (Pester missing, test file missing, pwsh missing, etc.)

    v3 GATES POWERSHELL 7 ONLY (operator 2026-10-09: "yes drop ps 5.1 for v3. i told that yesterday").
    Started from Windows PowerShell 5.1, the gate re-runs itself under pwsh and returns pwsh's exit code;
    -WindowsPowerShell keeps it on 5.1 -- an explicit opt-in. v2.2 on main keeps its own 5.1 gate.

    ONLY THE OWNER STARTS A FULL RUN (owner 2026-10-13: "full suite is not night either. it can only be triggered when i
    say so. no boddy can trigger full test, newer ! only me can start that"). This script runs EVERY *.Tests.ps1 in the
    folder in one process -- a full run -- so it REFUSES to start (exit 6, nothing run) unless -OwnerWords carries the
    owner's own sentence for THIS run. No default; never read from a file, an environment variable or a configuration;
    printed in the output when it runs. No session, builder, release command, workflow or schedule passes them on its
    own. To test a change, run the suites that cover it: tests\Invoke-FastGate.ps1 -Base <sha>, or
    -Suites 'A;B'.

.EXAMPLE
    pwsh -File ./Invoke-PrePublishGate.ps1 -OwnerWords '<the owner''s own sentence for this run>'   # ONLY on his words; refused without
#>
[CmdletBinding()]
param(
    [string]$TestsFolder,   # all *.Tests.ps1 in this folder; defaults to this script's folder
    # ONLY THE OWNER STARTS A FULL RUN (owner 2026-10-13): his own sentence for THIS run. No default -- and never read from
    # a file, an environment variable or a configuration. Without it nothing runs.
    [string]$OwnerWords,
    [switch]$Detailed,
    # v3 = PowerShell 7 only: on 5.1 the gate re-runs itself under pwsh unless this is given
    [switch]$WindowsPowerShell
)

$ErrorActionPreference = 'Stop'
# #918: a test run never reports to Invardia -- this process and every engine child process it starts (SI_TEST_GATE: the gate's marker; in a Pester session the suites test the sender with their own stub)
$env:SI_TELEMETRY_ENABLED = 'false'; $env:SI_TEST_GATE = '1'

# --- ONLY THE OWNER STARTS A FULL RUN (owner 2026-10-13) -- before anything else, on either PowerShell ------------------
$ownerWordsGiven = "$OwnerWords".Trim()
if (-not $ownerWordsGiven) {
    Write-Host 'REFUSED: only the owner starts a full run, and this script runs every suite. Nothing was run.' -ForegroundColor Red
    Write-Host '         Run the affected suites instead: tests\Invoke-FastGate.ps1 -Base <the commit released last>, or -Suites ''<name>;<name>''.' -ForegroundColor Red
    Write-Host '         A full run needs -OwnerWords with the owner''s own sentence for THIS run -- never a default, never from a file, an' -ForegroundColor Red
    Write-Host '         environment variable or a configuration, and never passed by a session, a release command, a workflow or a schedule on its own.' -ForegroundColor Red
    exit 6
}
Write-Host ('  a FULL run, started on the owner''s own words for this run: "{0}"' -f $ownerWordsGiven) -ForegroundColor Yellow

# --- v3: PowerShell 7 only ------------------------------------------------------
if ($PSVersionTable.PSEdition -ne 'Core' -and -not $WindowsPowerShell) {
    $pw = Get-Command pwsh.exe -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $pw) {
        Write-Host 'FATAL: v3 gates PowerShell 7 only and pwsh.exe is not on this machine (-WindowsPowerShell runs it on 5.1 instead)' -ForegroundColor Red
        exit 2
    }
    Write-Host '  v3 gates PowerShell 7 only -- re-running the gate under pwsh' -ForegroundColor DarkGray
    $relaunch = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath, '-OwnerWords', $ownerWordsGiven)
    if (-not [string]::IsNullOrWhiteSpace($TestsFolder)) { $relaunch += @('-TestsFolder', $TestsFolder) }
    if ($Detailed) { $relaunch += '-Detailed' }
    & $pw.Source @relaunch
    exit $LASTEXITCODE
}

# 🪤 THE DEFAULT IS RESOLVED HERE, NOT IN THE param() BLOCK, AND THAT IS NOT A STYLE CHOICE.
# On Windows PowerShell 5.1, a script that has [CmdletBinding()] AND runs via -File binds
# `$PSScriptRoot` as EMPTY in a parameter default -- while the SAME variable reads correctly in the
# body two lines later. PowerShell 7 resolves it in both places, so this is invisible unless the
# gate is actually run on 5.1.
# It used to read `[string]$TestsFolder = $PSScriptRoot`, so on 5.1 the folder came through blank,
# Get-ChildItem matched nothing, and the gate exited 2 with:
#     FATAL: no *.Tests.ps1 files in:
# i.e. the pre-publish gate could not run on 5.1 in exactly the way its own .EXAMPLE documents
# (`powershell.exe -NoProfile -File ./Invoke-PrePublishGate.ps1`). v3 now gates PowerShell 7 only,
# but the body default stays: the -WindowsPowerShell opt-in and v2.2 still run it on 5.1.
# 📌 This is the same shape as audit #70: a gate that is not running looks a lot like a gate that
# has nothing to complain about. Measured 2026-08-30 on 5.1.20348.3932 vs 7.6.3.
if ([string]::IsNullOrWhiteSpace($TestsFolder)) { $TestsFolder = $PSScriptRoot }

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

# --- scope: the private repository, or a public (Community) copy? -----------------------------
# See _SITestScope.ps1. In a public copy the checks OF the private repository (publish manifest,
# sync/, repo .gitignore, git, internal-vm launchers) have nothing to check and are left out, by name.
. (Join-Path $PSScriptRoot '_SITestScope.ps1')
$siRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$scope  = Get-SITestScope -SIRoot $siRoot
if ($scope -eq 'Ambiguous') {
    Write-Host "FATAL: cannot tell whether this is the private repository or a public copy: exactly one of" -ForegroundColor Red
    Write-Host "       solution.publish.json (in $siRoot) and <repo>\sync\Sync-AutomateIT.ps1 exists." -ForegroundColor Red
    Write-Host "       Refusing to guess -- guessing 'public' would switch private-repository checks off." -ForegroundColor Red
    exit 2
}
$scopeSkippedFiles = @()
if ($scope -eq 'PublicCopy') {
    $scopeSkippedFiles = @($testFiles | Where-Object { Test-SITestFilePrivateRepoOnly -Path $_.FullName })
    $testFiles = @($testFiles | Where-Object { -not (Test-SITestFilePrivateRepoOnly -Path $_.FullName) })
}

# --- run ---
$cfg = New-PesterConfiguration
$cfg.Run.Path = $testFiles.FullName
if ($scope -eq 'PublicCopy') { $cfg.Filter.ExcludeTag = @('PrivateRepo') }
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
if ($scope -eq 'PublicCopy') {
    Write-Host ''
    Write-Host ('  SCOPE    public copy -- {0} suite file(s) and every check tagged PrivateRepo were not run: they check' -f $scopeSkippedFiles.Count) -ForegroundColor Yellow
    Write-Host '           the private AutomateIT repository (publish manifest, sync/, .gitignore, git), which this copy does not contain.' -ForegroundColor Yellow
    foreach ($f in $scopeSkippedFiles) { Write-Host ('             - ' + $f.Name) -ForegroundColor DarkYellow }
} else {
    Write-Host '  SCOPE    private repository -- every suite and every check ran'
}
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

# --- suites that failed to LOAD ------------------------------------------------
# A container whose DISCOVERY throws contributes ZERO tests, so it adds zero to
# FailedCount -- and a verdict computed only from FailedCount calls that READY.
# Not hypothetical: under Pester 6 an empty `-ForEach` throws ("Value can not be
# null or empty array"), and SI-PublishPayloadSanitization's violation-driven
# -ForEach is empty in exactly the GOOD case. So a CLEAN payload made the whole
# publish-sanitization suite fail to load, and CI runs 31150698932 and 31150980938
# both printed PUBLISH GATE: READY having run 0 tests from it -- the one gate that
# stops secrets reaching the public mirror. A suite that did not run is not a pass.
$brokenContainers = @($result.Containers | Where-Object { $_.ErrorRecord -and @($_.ErrorRecord).Count -gt 0 })
if ($brokenContainers.Count -gt 0) {
    Write-Host ('SUITES THAT FAILED TO LOAD (' + $brokenContainers.Count + ')') -ForegroundColor Red
    foreach ($c in $brokenContainers) {
        $name = if ($c.Item -is [System.IO.FileInfo]) { $c.Item.Name } else { [string]$c.Item }
        Write-Host ('  [' + $name + '] discovery failed -- 0 tests ran from this file') -ForegroundColor Red
        $msg = ([string](@($c.ErrorRecord)[0].Exception.Message) -split "`n")[0]
        Write-Host ('       -> ' + $msg) -ForegroundColor DarkGray
    }
    Write-Host ''
}

# --- verdict ---
if ($result.FailedCount -eq 0 -and $brokenContainers.Count -eq 0) {
    Write-Host '  PUBLISH GATE: READY  ' -BackgroundColor DarkGreen -ForegroundColor White
    Write-Host ''
    exit 0
} else {
    $why = @()
    if ($result.FailedCount -gt 0)     { $why += ([string]$result.FailedCount + ' failure(s)') }
    if ($brokenContainers.Count -gt 0) { $why += ([string]$brokenContainers.Count + ' suite(s) failed to load') }
    Write-Host ('  PUBLISH GATE: BLOCKED  (' + ($why -join ', ') + ')') -BackgroundColor DarkRed -ForegroundColor White
    Write-Host ''
    exit 1
}
