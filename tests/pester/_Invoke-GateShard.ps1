#Requires -Version 5.1
<#
.SYNOPSIS
    ONE shard of the release gate (#416): runs the Pester suites listed in -ListFile in THIS process and writes the result
    as JSON to -ResultFile. Started by tests\Invoke-FastGate.ps1 -- one per worker process, PowerShell 5.1 and 7 alike.

.DESCRIPTION
    The list travels in a FILE, not as an array parameter: `pwsh -File x.ps1 -Names a,b` passes ONE string, and an array
    parameter silently takes only the first value (PIM hit this, 2026-10-06). A suite that fails to LOAD is reported as such
    (it ran 0 tests -- that is not a pass; see Invoke-PrePublishGate.ps1).
    Every SKIPPED or inconclusive test is written by name with its reason (Skips), the tests an excluded tag left out are
    counted per tag (NotRunByTag: Scale = on demand only), and a test that did not run for any other reason is named
    (NotRunUnexplained) -- the gate counts none of them as a pass (owner 2026-10-25).
#>
param(
    [Parameter(Mandatory)][string]$ListFile,
    [Parameter(Mandatory)][string]$ResultFile,
    # a public (Community) copy leaves the private-repository checks out (tests\pester\_SITestScope.ps1)
    [string]$ExcludeTag = ''
)
$ErrorActionPreference = 'Stop'
# #918: a test run never reports to Invardia -- this process and every engine child process it starts (SI_TEST_GATE: the gate's marker; in a Pester session the suites test the sender with their own stub)
$env:SI_TELEMETRY_ENABLED = 'false'; $env:SI_TEST_GATE = '1'
$files = @([IO.File]::ReadAllLines($ListFile) | Where-Object { $_.Trim() })
$out = [ordered]@{ Runtime = $PSVersionTable.PSVersion.ToString(); Edition = $PSVersionTable.PSEdition; Files = $files.Count
                   Passed = 0; Failed = 0; Skipped = 0; Total = 0; Seconds = 0; Containers = @(); Failures = @(); LoadFailures = @(); Error = ''
                   Skips = @(); NotRunByTag = [ordered]@{}; NotRunUnexplained = @() }
$sw = [Diagnostics.Stopwatch]::StartNew()
try {
    Import-Module Pester -MinimumVersion 5.0 -ErrorAction Stop
    $cfg = New-PesterConfiguration
    $cfg.Run.Path = [string[]]$files
    $cfg.Run.PassThru = $true
    $cfg.Output.Verbosity = 'None'
    $cfg.TestResult.Enabled = $false
    if ($ExcludeTag) { $cfg.Filter.ExcludeTag = @($ExcludeTag -split ',' | Where-Object { $_ }) }
    $r = Invoke-Pester -Configuration $cfg
    $out.Passed = [int]$r.PassedCount; $out.Failed = [int]$r.FailedCount; $out.Skipped = [int]$r.SkippedCount; $out.Total = [int]$r.TotalCount
    $cont = New-Object System.Collections.Generic.List[object]
    foreach ($c in @($r.Containers)) {
        $name = if ($c.Item -is [IO.FileInfo]) { $c.Item.Name } else { Split-Path -Leaf ([string]$c.Item) }
        $secs = 0.0
        foreach ($p in 'Duration', 'UserDuration') { if ($c.PSObject.Properties[$p] -and $c.$p) { $secs = [double]([timespan]$c.$p).TotalSeconds; break } }
        $cont.Add([ordered]@{ File = $name; Seconds = [Math]::Round($secs, 2); Result = [string]$c.Result; LoadError = [bool]($c.ErrorRecord -and @($c.ErrorRecord).Count) })
        if ($c.ErrorRecord -and @($c.ErrorRecord).Count) {
            $out.LoadFailures += [ordered]@{ File = $name; Message = ((@(([string](@($c.ErrorRecord)[0].Exception.Message)) -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ }) | Select-Object -First 4) -join " | ") }   # the cause, not only "Framework failed:"
        }
    }
    $out.Containers = $cont.ToArray()
    # the slowest tests of this batch (TEST-RUN-1: a slow batch names its slow tests, not only its suites)
    $out.SlowTests = @(@($r.Tests | Where-Object { $_.Duration }) | Sort-Object -Property @{ Expression = { [double]([timespan]$_.Duration).TotalSeconds } } -Descending | Select-Object -First 10 | ForEach-Object {
        $tf = ''; try { $tf = Split-Path -Leaf ([string]$_.ScriptBlock.File) } catch { }
        [ordered]@{ File = $tf; Test = [string]$_.ExpandedPath; Seconds = [Math]::Round(([timespan]$_.Duration).TotalSeconds, 2) } })
    foreach ($t in @($r.Tests | Where-Object { $_.Result -eq 'Failed' })) {
        $file = ''
        try { $file = Split-Path -Leaf ([string]$t.ScriptBlock.File) } catch { }
        $msg = ''; if ($t.ErrorRecord) { $msg = (([string]@($t.ErrorRecord)[0].Exception.Message) -split "`n")[0] }
        $out.Failures += [ordered]@{ File = $file; Test = [string]$t.ExpandedPath; Message = $msg }
    }
    # A SKIPPED test is NOT a pass (owner 2026-10-25): every skipped / inconclusive test by name with its reason. A test
    # LEFT OUT by an excluded tag (Scale: on demand only; PrivateRepo: a public copy) is counted per tag, never as a pass;
    # a test that did not run for any other reason is named too (Unexplained) and is not green either.
    $excluded = @($ExcludeTag -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $out.Skips = @(); $out.NotRunByTag = [ordered]@{}; $out.NotRunUnexplained = @()
    foreach ($t in @($r.Tests | Where-Object { $_.Result -in 'Skipped', 'Inconclusive', 'NotRun' })) {
        $file = ''; try { $file = Split-Path -Leaf ([string]$t.ScriptBlock.File) } catch { }
        if ($t.Result -eq 'NotRun') {
            # its own tags and every enclosing block's
            $tags = New-Object System.Collections.Generic.List[string]
            foreach ($x in @($t.Tag)) { if ($x) { $tags.Add([string]$x) } }
            $b = $t.Block; while ($b) { foreach ($x in @($b.Tag)) { if ($x) { $tags.Add([string]$x) } }; $b = $b.Parent }
            $hit = @($excluded | Where-Object { $tags -contains $_ }) | Select-Object -First 1
            if ($hit) { $out.NotRunByTag[$hit] = 1 + [int]$out.NotRunByTag[$hit] }
            else { $out.NotRunUnexplained += [ordered]@{ File = $file; Test = [string]$t.ExpandedPath } }
            continue
        }
        $why = ''
        if ($t.ErrorRecord -and @($t.ErrorRecord).Count) { $why = (([string]@($t.ErrorRecord)[0].Exception.Message) -split "`n")[0].Trim() }
        if (-not $why) { $why = '-Skip on the test or its block' }
        $out.Skips += [ordered]@{ File = $file; Test = [string]$t.ExpandedPath; Result = [string]$t.Result; Because = $why }
    }
    $out.Skipped = @($out.Skips).Count
} catch {
    $out.Error = $_.Exception.Message
}
$sw.Stop(); $out.Seconds = [Math]::Round($sw.Elapsed.TotalSeconds, 1)
[IO.File]::WriteAllText($ResultFile, (ConvertTo-Json -InputObject $out -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
exit 0
