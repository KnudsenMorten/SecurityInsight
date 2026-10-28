#Requires -Version 5.1
<#
.SYNOPSIS
    The web app's part of the QUICK GATE (tests\Invoke-FastGate.ps1): builds the test projects the change touches and runs
    only their selected test classes, in THIS process -- started by the gate as one more item beside the Pester suites, so
    the gate's hard 10-minute stop ends it (its whole process tree: dotnet, MSBuild, the test host) like any suite.

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
    foreach ($pj in $plan) {
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $b = @(& dotnet build ([string]$pj.Path) -c Release --nologo -v q -nodeReuse:false 2>&1 | ForEach-Object { "$_" }); $bc = $LASTEXITCODE
        if ($bc -and ($b -match 'MSB4166')) { & $log $b; $b = @(& dotnet build ([string]$pj.Path) -c Release --nologo -v q -nodeReuse:false 2>&1 | ForEach-Object { "$_" }); $bc = $LASTEXITCODE }
        & $log $b
        $errs = @($b | ForEach-Object { "$_".Trim() } | Where-Object { $_ -match ':\s*error\s+[A-Z]+\d+' } | Select-Object -Unique -First 8)
        $out.Build += [ordered]@{ Project = [string]$pj.Name; Ok = ($bc -eq 0); Summary = $(if ($bc) { 'dotnet build FAILED' + $(if ($errs.Count) { ': ' + ($errs -join ' | ') } else { '' }) } else { 'built' }); Seconds = [int]$sw.Elapsed.TotalSeconds }
        & $save
        if ($bc) { $built = $false }
    }
    if ($built) {
        foreach ($pj in $plan) {
            $sw = [Diagnostics.Stopwatch]::StartNew()
            $ta = @('test', [string]$pj.Path, '-c', 'Release', '--no-build', '--nologo')
            if ("$($pj.Filter)") { $ta += @('--filter', [string]$pj.Filter) }
            $sum = ''; $tc = 0; $note = ''
            foreach ($attempt in 1, 2) {
                $o = @(& dotnet @ta 2>&1 | ForEach-Object { "$_" }); $tc = $LASTEXITCODE
                & $log $o
                $sum = @($o | Where-Object { $_ -match '(Passed|Failed|Skipped)!\s+-' } | ForEach-Object { $_.Trim() }) -join ' '
                $names = @(for ($k = 0; $k -lt $o.Count; $k++) {
                    if ($o[$k] -notmatch '^\s+Failed\s+\S') { continue }
                    $why = ''
                    for ($m = $k + 1; $m -lt [Math]::Min($o.Count, $k + 8); $m++) {
                        if ($o[$m] -match '^\s*Error Message:') { $why = @($o[($m + 1)..([Math]::Min($o.Count - 1, $m + 2))] | ForEach-Object { $_.Trim() } | Where-Object { $_ }) -join ' '; break }
                    }
                    $o[$k].Trim() + $(if ($why) { ' -- ' + $(if ($why.Length -gt 700) { $why.Substring(0, 700) } else { $why }) } else { '' })
                }) | Select-Object -First 15
                if ($names.Count) { $sum = ($(if ($sum) { $sum } else { '' }) + ' | ' + ($names -join ' | ')).Trim(' ', '|') }
                if ($tc -eq 0 -or ($o -match '(Passed|Failed|Skipped)!\s+-')) { break }
                $note = "attempt $attempt produced no test result (exit $tc): " + (@($o | Where-Object { $_.Trim() } | Select-Object -Last 4) -join ' / ')
                $sum = $note
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
