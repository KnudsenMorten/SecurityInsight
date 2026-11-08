#Requires -Version 5.1
<#
.SYNOPSIS
    The web app's part of the QUICK GATE (tests\Invoke-FastGate.ps1): builds the test projects the change touches and runs
    only their selected test classes, in THIS process -- started by the gate as one more item beside the Pester suites, so
    the gate's hang rule ends it (its whole process tree: dotnet, MSBuild, the test host) like any suite. TEST-FAST (owner
    2026-11-02): no clock ends it; it is HUNG only when it prints nothing for 5 minutes -- so every build and test line
    is streamed to standard output as it comes (and a line per test: the console logger at normal verbosity).

.DESCRIPTION
    -PlanFile: JSON array of { Name; Path (the test .csproj); Filter (dotnet test --filter, '' = the whole project) }.
    Each project is BUILT (the project, never the whole solution: it builds what it references, nothing else), then tested
    with --no-build and its filter. -ResultFile is rewritten after EVERY step, so a run the gate stopped still says what
    finished: { Build = [ { Project; Ok; Summary; Seconds } ]; Projects = [ { Project; Ok; Summary; Seconds; Filtered } ] }.
    MSBuild nodes are never reused (-nodeReuse:false: the test VM is shared, a reused node another build ends takes this one
    down -- MSB4166, 2026-10-09; such a crash builds once more). A test run with NO result line (host crash, connection
    timeout) runs once more; a run that reported failed tests is a real result and is never re-run. Exit 0 always: the
    gate reads the result file.
#>
param(
    [Parameter(Mandatory)][string]$PlanFile,
    [Parameter(Mandatory)][string]$ResultFile,
    [string]$LogFile = ''
)
$ErrorActionPreference = 'Stop'
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'; $env:DOTNET_NOLOGO = '1'
# a loaded machine: the test host may take longer than vstest's default 90 s to connect
$env:VSTEST_CONNECTION_TIMEOUT = '600'
$plan = @([IO.File]::ReadAllText($PlanFile) | ConvertFrom-Json)
$out = [ordered]@{ Build = @(); Projects = @(); Error = '' }
$save = { [IO.File]::WriteAllText($ResultFile, (ConvertTo-Json -InputObject $out -Depth 6), (New-Object System.Text.UTF8Encoding($false))) }
$log = { param($lines) if ($LogFile) { Add-Content -LiteralPath $LogFile -Value ($lines | Out-String) } }
& $save
try {
    $built = $true
    # SPEED (framework 12.1 rule 10 (c)): this is the TEST build -- the .NET analyzers are off here only; the release build
    # (the image build) keeps them, so a rule an analyzer enforces is still enforced where the product is built
    $fastBuild = @('-p:RunAnalyzers=false', '-p:EnableNETAnalyzers=false', '-p:RunAnalyzersDuringBuild=false')
    foreach ($pj in $plan) {
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $b = @(& dotnet build ([string]$pj.Path) -c Release --nologo -v minimal -nodeReuse:false @fastBuild 2>&1 | ForEach-Object { $l = "$_"; [Console]::Out.WriteLine($l); $l }); $bc = $LASTEXITCODE
        if ($bc -and ($b -match 'MSB4166')) { & $log $b; $b = @(& dotnet build ([string]$pj.Path) -c Release --nologo -v minimal -nodeReuse:false @fastBuild 2>&1 | ForEach-Object { $l = "$_"; [Console]::Out.WriteLine($l); $l }); $bc = $LASTEXITCODE }
        & $log $b
        $errs = @($b | ForEach-Object { "$_".Trim() } | Where-Object { $_ -match ':\s*error\s+[A-Z]+\d+' } | Select-Object -Unique -First 8)
        $out.Build += [ordered]@{ Project = [string]$pj.Name; Ok = ($bc -eq 0); Summary = $(if ($bc) { 'dotnet build FAILED' + $(if ($errs.Count) { ': ' + ($errs -join ' | ') } else { '' }) } else { 'built' }); Seconds = [int]$sw.Elapsed.TotalSeconds }
        & $save
        if ($bc) { $built = $false }
    }
    if ($built) {
        foreach ($pj in $plan) {
            $sw = [Diagnostics.Stopwatch]::StartNew()
            $ta = @('test', [string]$pj.Path, '-c', 'Release', '--no-build', '--nologo', '--logger', 'console;verbosity=normal')
            if ("$($pj.Filter)") { $ta += @('--filter', [string]$pj.Filter) }
            $sum = ''; $tc = 0; $note = ''
            foreach ($attempt in 1, 2) {
                $o = @(& dotnet @ta 2>&1 | ForEach-Object { $l = "$_"; [Console]::Out.WriteLine($l); $l }); $tc = $LASTEXITCODE
                & $log $o
                $sum = @($o | Where-Object { $_ -match '(Passed|Failed|Skipped)!\s+-' } | ForEach-Object { $_.Trim() }) -join ' '
                if (-not $sum) { $sum = @($o | Where-Object { $_ -match '^\s*(Total tests|Passed|Failed|Skipped):\s*\d' } | ForEach-Object { $_.Trim() }) -join ' / ' }   # the 'Total tests: N' form
                $names = @(for ($k = 0; $k -lt $o.Count; $k++) {
                    if ($o[$k] -notmatch '^\s+Failed\s+\S') { continue }
                    $why = ''
                    for ($m = $k + 1; $m -lt [Math]::Min($o.Count, $k + 8); $m++) {
                        if ($o[$m] -match '^\s*Error Message:') { $why = @($o[($m + 1)..([Math]::Min($o.Count - 1, $m + 2))] | ForEach-Object { $_.Trim() } | Where-Object { $_ }) -join ' '; break }
                    }
                    $o[$k].Trim() + $(if ($why) { ' -- ' + $(if ($why.Length -gt 700) { $why.Substring(0, 700) } else { $why }) } else { '' })
                }) | Select-Object -First 15
                if ($names.Count) { $sum = ($(if ($sum) { $sum } else { '' }) + ' | ' + ($names -join ' | ')).Trim(' ', '|') }
                # a run that REPORTED its tests (either summary form: 'Failed!  - ...' or 'Total tests: N') is a result, not a
                # crash: a red result is not re-run (the re-run doubled a red web run's time and said nothing new)
                if ($tc -eq 0 -or ($o -match '(Passed|Failed|Skipped)!\s+-') -or ($o -match '^\s*Total tests:\s*\d')) { break }
                $note = "attempt $attempt produced no test result (exit $tc): " + (@($o | Where-Object { $_.Trim() } | Select-Object -Last 4) -join ' / ')
                # the failed tests' names stay in the summary (they were dropped here, so a red run never said which tests)
                $sum = $note + $(if ($names.Count) { ' | ' + ($names -join ' | ') } else { '' })
            }
            if ($note -and $tc -eq 0) { $sum = "$sum (passed on the re-run; first: $note)" }
            $out.Projects += [ordered]@{ Project = [string]$pj.Name; Ok = ($tc -eq 0); Summary = $(if ("$($pj.Filter)") { "[filtered] $sum" } else { $sum }); Seconds = [int]$sw.Elapsed.TotalSeconds; Filtered = [bool]"$($pj.Filter)" }
            & $save
        }
    }
} catch {
    $out.Error = $_.Exception.Message
}
& $save
exit 0
