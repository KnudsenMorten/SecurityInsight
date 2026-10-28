#Requires -Version 5.1
<#
.SYNOPSIS
    THE QUICK GATE of every release (owner 2026-10-13: "yes, build it the pim way"; "default release is quick"; "we even
    agreed on hard limit of max 10 min"). A fixed CORE SET + the few suites the change needs, each in its own PowerShell 7
    process, all in parallel; the web app's tests only when a web file changed, and then only the matching classes; at 10
    minutes STOP AND REPORT. -Full = every suite, ONLY on the owner's own words (below).
    v3 gates PowerShell 7 ONLY (operator 2026-10-09: "yes drop ps 5.1 for v3. i told that yesterday"). -Runtime ps51 or
    -Runtime both still runs Windows PowerShell 5.1, as an explicit opt-in; v2.2 on main keeps its own 5.1 gate.

.DESCRIPTION
    Before (measured 2026-10-13): naming 5 suites ran 88 of 466, because the selector added every suite covering a changed
    path, and every run built the web app (~9 min) and ran its whole test project (~22 min): 28-36 min a gate.
    Built as PIM's gate is (PIM docs\TESTS.md 1c-iia / 1c-iib, tests\Get-PimAffectedSuites.ps1, tests\_shared\Invoke-PimGate.ps1);
    SI's own rules and numbers in docs\TESTS.md "The quick gate".

      1. WHAT CHANGED: `git diff --name-only <Base>..HEAD` plus the working tree's own changes (SecurityInsight only), or
         -Paths. -Base: the commit released last (setup\Release-SI.ps1 passes it); default = where HEAD left origin/si-v3.
      2. WHICH SUITES (Get-SIQuickGateSelection; the data in tests\pester\fast-gate.map.json core / quick / hubs / explicit):
           - the CORE SET (12 suites) on every run with a code or test change;
           - a changed suite runs itself;
           - a NARROW file (seen by at most 3 suites: they name it, or -- when none does -- they name a script that loads
             it) -> those suites;
           - a BROAD file (seen by more than 3) -> at most 3 suites: named after the file first, then the ones that name
             it most often -- never "every suite covering the path";
           - a HUB (loads 20+ other SI files; the measured list is in the map) -> the core set + at most 3 suites named
             after it (owner 2026-10-13);
           - an UNMAPPED file (nothing sees it) -> the core set (never everything), named in the result;
           - a suite that READS a changed file's TEXT (Get-Content / ReadAllText / Select-String / the parser on it) ->
             that suite too, hub or not, when the change reaches what it reads: one of its 12+-character string literals
             is in a changed line, or the change is inside a function it names (owner 2026-10-25; no cap; -Paths without
             a diff = every reader);
           - documents (any .md) -> only their doc guards; release-bump files (VERSION, RELEASENOTES.md) -> only the
             suites that name them -- no core set when only those changed;
           - -Suites 'A;B' alone = exactly those + the core set, nothing added (what changed is not read).
         A selection that comes to EVERY suite is a full run: refused without the owner's words (below) -- a STOP and a
         question to him, never a start.
      3. THE WEB APP only when a web app file changed (the explicit map: pro-management\..., config\*.locked.json): the
         touched test project is BUILT (the project, not the solution) and only the test classes that match the changed
         pages / files run (dotnet test --filter; Get-SIFastGateDotnetFilter -NoWhole): at most 15 classes + the always-on
         ones, never the whole project in a quick gate -- a shared piece (Program.cs, the layout) runs the classes that
         name it.
      4. HOW IT RUNS (Invoke-SIQuickGateRun): every suite in its own pwsh 7 process (tests\pester\_Invoke-GateShard.ps1),
         the web app's build + tests in one more (tests\pester\_Invoke-GateDotnet.ps1), up to 12 at once, each with an empty
         standard input. A line the moment each finishes; every 60 s what still runs.
      5. AT 10 MINUTES: STOP AND REPORT. 600 s per suite AND 600 s for the whole gate (fast-gate.map.json quick; never
         above). A suite still running is ENDED -- its whole process tree, by process id (Stop-SIGateProcessTree), never
         by name -- and reported red BY NAME "TIMED OUT after N min"; a suite the limit left no time to start is "NOT RUN";
         the others' results stand. A stopped run is 'NOT TESTED' -- never green (exit 1).
         A suite MEASURED over 600 s is not stopped at 10 minutes for now (owner 2026-10-13: "accepted, skip 10 min for
         now"): it gets its measured time x1.5 (Get-SIQuickGateSlowLimit), said in the log; the gate reads OVER THE LIMIT.
      4b. SQL FIRST (owner 2026-10-25): when a selected suite has real-SQL tests, SQL Server Express is started if stopped
         and SELECT 1 is asked until it answers (up to 180 s); SI_TEST_LOCALSQL is then set for every suite. SQL that never
         answers = NOT TESTED at once.
      6. RESULT: PASS / FAIL / NOT TESTED, every suite by name with its seconds (SuiteResults), every failure, every suite
         that failed to LOAD (0 tests ran from it -- never a pass). A SKIPPED test is NOT a pass: a suite with one is NOT
         GREEN and the gate FAILS, naming each skipped test and its reason (owner 2026-10-25). The tests tagged Scale are
         left out (on demand only) and said as "not run (Scale, on demand)" -- never counted as passed. Exit 0 = pass, 1 = fail or not tested, 2 = could not
         run, 6 = REFUSED (a full run without the owner's words -- nothing ran). -ResultFile writes it as JSON.

    -Hotfix is kept for callers (setup\Release-SI.ps1 passes it): it is the same quick gate. -Precise -ListOnly prints the
    older COVERING selection (every suite that covers each path, one hop, the folder) as a diagnostic; it never runs.
    Tests tagged Scale (the 100,000-record benchmarks) never run in any gate; a selected suite runs whole otherwise.

    ONLY THE OWNER STARTS A FULL RUN (owner 2026-10-13: "full suite is not night either. it can only be triggered when i
    say so. no boddy can trigger full test, newer ! only me can start that"; "default release is quick"; "we even agreed
    on hard limit of max 10 min"). -Full runs EVERYTHING the same sharded way -- and REFUSES to start (exit 6, nothing
    run) unless -OwnerWords carries the owner's own sentence for THIS run. The words have no default and are never read
    from a file, an environment variable or a configuration: the caller types them, and they are printed in the log and
    written to the result file (OwnerWords). No session, builder, release command, schedule or night job passes them on
    its own; a full run is never a gate, never a diagnostic, never "to be safe" after a large merge, never part of a
    release. A selection that comes to EVERY suite by another road (-Suites / -Paths naming them all) is the same run
    and is refused the same way. Every release -- fix or feature, whatever its size -- runs the suites that cover the
    change + the core set (-Hotfix); setup\Release-SI.ps1 never passes -Full. There is no nightly or scheduled run.
    -ListOnly prints the selection with the reason for each suite and runs nothing.

.EXAMPLE
    .\tests\Invoke-FastGate.ps1                          # what this branch changed since it left origin/si-v3
    .\tests\Invoke-FastGate.ps1 -Base 0dc9062ef          # since the last release
    .\tests\Invoke-FastGate.ps1 -Full -OwnerWords '<the owner''s own sentence for this run>'   # ONLY on his words; refused without
    .\tests\Invoke-FastGate.ps1 -Suites 'SIv3-FastRoll;SIv3-Updater' -Runtime pwsh   # exactly those + the core set
#>
[CmdletBinding()]
param(
    [string]$Base,
    # what changed, given instead of read from git (';'-separated paths relative to SOLUTIONS\SecurityInsight): 'what would a
    # change to X run' -- the hotfix estimate
    [string]$Paths = '',
    [switch]$Full,
    # ONLY THE OWNER STARTS A FULL RUN (owner 2026-10-13): his own sentence for THIS run. No default -- and never read from
    # a file, an environment variable or a configuration. -Full (or any selection of every suite) refuses without it.
    [string]$OwnerWords,
    # #416 THE HOTFIX GATE (operator 2026-10-09: "a simple fix in si and pim must take max 15 min before it is released"):
    # only the suites that cover the changed files, ranked and measured against -HotfixBudgetSeconds (a warning, never a cut), plus the
    # fixed smoke set (fast-gate.map.json smoke) instead of the safety list; the dotnet build + the covering test classes
    [switch]$Hotfix,
    [double]$HotfixBudgetSeconds = 300,
    [double]$HotfixSuiteMaxSeconds = 120,
    # extra suites by file name, ';'-separated (a string, never an array: `-File` passes arrays as one value)
    [string]$Suites = '',
    # v3 = PowerShell 7 only (2026-10-09); ps51 / both add Windows PowerShell 5.1 -- an explicit opt-in, never the default
    [ValidateSet('both', 'pwsh', 'ps51')][string]$Runtime = 'pwsh',
    [int]$Workers = 0,
    [switch]$NoDotnet,
    [switch]$NoSafety,
    [switch]$ListOnly,
    # the selection as JSON (Full, Base, Changed, Suites, Dotnet, Unmapped, OverBudget, AllSuites, MeasuredSeconds,
    # LongestSeconds) -- setup\Release-SI.ps1 reads it (-ListOnly)
    [string]$SelectionFile,
    [switch]$UpdateDurations,
    [string]$ResultFile,
    # bounds a FULL run only (only the owner starts one); the quick gate has its own hard 10-minute stop (below)
    [int]$TimeoutMinutes = 40,
    # THE HARD 10-MINUTE STOP of the quick gate (owner 2026-10-13: "we even agreed on hard limit of max 10 min"): per suite and
    # for the whole gate; 0 = fast-gate.map.json quick (600). Never above 600 -- a shorter one is for the gate's own tests.
    [ValidateRange(0, 600)][int]$SuiteLimitSeconds = 0,
    [ValidateRange(0, 600)][int]$GateLimitSeconds = 0,
    [ValidateRange(1, 600)][int]$ProgressSeconds = 60,
    # the older COVERING selection (every suite that covers each changed path), as a diagnostic: -ListOnly only
    [switch]$Precise,
    # tests: define the functions only
    [Parameter(DontShow)][switch]$DefineOnly
)
$ErrorActionPreference = 'Stop'
# #918: a test run never reports to Invardia -- this process and every engine child process it starts (SI_TEST_GATE: the gate's marker; in a Pester session the suites test the sender with their own stub)
$env:SI_TELEMETRY_ENABLED = 'false'; $env:SI_TEST_GATE = '1'
$started = Get-Date
$siRoot = Split-Path -Parent $PSScriptRoot
. ([IO.Path]::Combine($siRoot, 'setup', '_shared', 'SI-GitText.ps1'))   # #917: git text as UTF-8 whatever the console
$pesterDir = Join-Path $PSScriptRoot 'pester'
$durationsFile = Join-Path $pesterDir 'suite-durations.json'
$mapFile = Join-Path $pesterDir 'fast-gate.map.json'

function Get-SIFastGateMap {
    <#
        The gate's data, tests\pester\fast-gate.map.json: the SAFETY suites (always on, never removed -- docs\TESTS.md), the
        EXPLICIT map (paths no suite names by file name) and where the dotnet solution and tests are. Data, not code, so a
        Community copy carries the same file and simply lacks some of the suites and projects it names.
    #>
    param([Parameter(Mandatory)][string]$Path)
    $j = [IO.File]::ReadAllText($Path) | ConvertFrom-Json
    [pscustomobject]@{
        Safety   = @($j.safety | ForEach-Object { [string]$_.suite })
        # the HOTFIX gate's fixed smoke set (#416, 2026-10-09) -- instead of the safety list
        Smoke    = @($j.smoke | Where-Object { $_ } | ForEach-Object { [string]$_.suite })
        Explicit = @($j.explicit | ForEach-Object { [pscustomobject]@{ Pattern = [string]$_.pattern; Suites = @($_.suites | ForEach-Object { [string]$_ }); Dotnet = @($_.dotnet | ForEach-Object { [string]$_ }); Exclusive = [bool]$_.exclusive; Kind = $(if ($_.PSObject.Properties['kind']) { [string]$_.kind } else { '' }) } })
        # THE QUICK GATE (owner 2026-10-13: "yes, build it the pim way"): the core set, its rules and the measured hubs
        Core     = @($j.core | Where-Object { $_ } | ForEach-Object { [string]$_.suite })
        Hubs     = @($j.hubs | Where-Object { $_ } | ForEach-Object { [string]$_.path })
        Quick    = [pscustomobject]@{
            BroadOver = $(if ($j.quick -and $j.quick.broadOver) { [int]$j.quick.broadOver } else { 3 })
            NamedMax  = $(if ($j.quick -and $j.quick.namedMax) { [int]$j.quick.namedMax } else { 3 })
            HubLoads  = $(if ($j.quick -and $j.quick.hubLoads) { [int]$j.quick.hubLoads } else { 20 })
            Throttle  = $(if ($j.quick -and $j.quick.throttle) { [int]$j.quick.throttle } else { 12 })
            # never above 600 s, whatever the file says: THE HARD 10-MINUTE STOP (owner: "we even agreed on hard limit of max 10 min")
            SuiteLimitSeconds = [Math]::Min(600, $(if ($j.quick -and $j.quick.suiteLimitSeconds) { [int]$j.quick.suiteLimitSeconds } else { 600 }))
            GateLimitSeconds  = [Math]::Min(600, $(if ($j.quick -and $j.quick.gateLimitSeconds) { [int]$j.quick.gateLimitSeconds } else { 600 }))
            DotnetMaxClasses  = $(if ($j.quick -and $j.quick.dotnetMaxClasses) { [int]$j.quick.dotnetMaxClasses } else { 15 })
        }
        Solution = [string]$j.dotnet.solution
        Tests    = [string]$j.dotnet.tests
        DotnetFilter = @($j.dotnetFilter | Where-Object { $_ } | ForEach-Object { [pscustomobject]@{ Project = [string]$_.project; Source = [string]$_.source; Tests = [string]$_.tests; Always = @($_.always | ForEach-Object { [string]$_ })
                                                                                                    Related = @($_.related | ForEach-Object { [string]$_ }); Shared = @($_.shared | ForEach-Object { [string]$_ }) } })
    }
}
function Remove-SIFastGateComments {
    # PURE. PowerShell text without its block comments and its whole-line comments.
    param([AllowEmptyString()][string]$Text)
    $t = [regex]::Replace([string]$Text, '(?s)<' + '#.*?#' + '>', '')
    (@($t -split "`r?`n" | Where-Object { -not $_.TrimStart().StartsWith('#') })) -join "`n"
}

function Get-SIFastGateKeys {
    <# PURE. What a suite would write to name a file: its file name, and its name without the extension (8+ characters). #>
    param([Parameter(Mandatory)][string]$RelativePath)
    $leaf = ($RelativePath -split '/')[-1]
    $keys = New-Object System.Collections.Generic.List[string]
    if ($leaf.Length -ge 6) { $keys.Add($leaf) }
    $stem = [IO.Path]::GetFileNameWithoutExtension($leaf)
    if ($stem.Length -ge 8 -and $stem -ne $leaf) { $keys.Add($stem) }
    $keys.ToArray()
}

function Get-SIFastGateSelection {
    <#
        PURE (given the texts). -Changed: relative paths ('/'). -SuiteText: suite name -> text. -CodeText: relative path ->
        text of every PowerShell file (the one-hop index). Returns @{ Suites (name -> reason); Dotnet (project -> reason);
        Unmapped (paths nothing covered); OverBudget (name -> reason: covering suites a -Hotfix runs although they pass
        its budget); Dropped (always empty: no covering suite is ever left out -- kept for older readers) }.

        -Hotfix (#416, operator 2026-10-09: "a simple fix in si and pim must take max 15 min before it is released"): only
        the suites that COVER the changed files -- a changed suite, the explicit map, a suite that names the file; one hop /
        the folder only for a path nothing names -- plus the fixed SMOKE set (map.smoke) instead of the safety list. A hub
        file is named by dozens of suites (Invoke-RiskAnalysis.ps1: 70), so the covering suites are RANKED -- a changed
        suite, a suite named after the file (SI-FastRoll.ps1 -> SIv3-FastRoll.Tests.ps1), the explicit map, then by how
        often the suite names the file -- and counted against -BudgetSeconds of measured seconds (-Seconds); a suite over
        -SuiteMaxSeconds counts as over the budget unless it is the file's own. EVERY covering suite runs (owner
        2026-10-09: no nightly run any more, so a suite left out would never run): what does not fit the budget is
        selected all the same and named in OverBudget, so the gate can say why it took longer.
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Changed, [Parameter(Mandatory)][hashtable]$SuiteText,
          [Parameter(Mandatory)]$Map, [hashtable]$CodeText = @{}, [switch]$NoSafety,
          [switch]$Hotfix, [hashtable]$Seconds = @{}, [double]$BudgetSeconds = 300, [double]$SuiteMaxSeconds = 120)
    if ($Hotfix) { return (Get-SIFastGateHotfixSelection -Changed $Changed -SuiteText $SuiteText -Map $Map -CodeText $CodeText -NoSafety:$NoSafety -Seconds $Seconds -BudgetSeconds $BudgetSeconds -SuiteMaxSeconds $SuiteMaxSeconds) }
    $suites = [ordered]@{}; $dotnet = [ordered]@{}; $unmapped = New-Object System.Collections.Generic.List[string]
    $add = { param($name, $why) if ($SuiteText.ContainsKey($name) -and -not $suites.Contains($name)) { $suites[$name] = $why } }
    $byKey = {
        param([string[]]$keys)
        $hit = New-Object System.Collections.Generic.List[string]
        foreach ($s in $SuiteText.Keys) { foreach ($k in $keys) { if ($SuiteText[$s].IndexOf($k, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $hit.Add($s); break } } }
        $hit.ToArray()
    }
    foreach ($p in $Changed) {
        $rel = ($p -replace '\\', '/').TrimStart('/')
        $leaf = ($rel -split '/')[-1]
        $covered = $false
        if ($rel -match '^tests/pester/[^/]+\.Tests\.ps1$') { & $add $leaf 'changed suite'; $covered = $true }
        foreach ($m in @($Map.Explicit)) {
            $mm = [regex]::Match($rel, $m.Pattern)
            if (-not $mm.Success) { continue }
            foreach ($s in $m.Suites) { & $add $s ("explicit map: $rel") }
            foreach ($d in $m.Dotnet) { $dn = $d; if ($dn -eq '${p}') { $dn = $mm.Groups['p'].Value }; if (-not $dotnet.Contains($dn)) { $dotnet[$dn] = "explicit map: $rel" } }
            $covered = $true
        }
        if ($rel -match '^tests/pester/[^/]+\.Tests\.ps1$') { continue }
        # an EXCLUSIVE explicit entry decides alone (a document is named by dozens of suites that test something else)
        if (@(@($Map.Explicit) | Where-Object { $_.PSObject.Properties['Exclusive'] -and $_.Exclusive -and $rel -match $_.Pattern }).Count) { continue }
        $keys = @(Get-SIFastGateKeys -RelativePath $rel)
        $direct = if ($keys.Count) { @(& $byKey $keys) } else { @() }
        foreach ($s in $direct) { & $add $s ("names {0}" -f $leaf) }
        if ($direct.Count) { $covered = $true }
        # one hop: a PowerShell file that loads the changed file -> the suites that name THAT file
        if ($keys.Count -and $rel -match '\.(ps1|psm1|psd1|yaml|yml|json|csv|sql)$') {
            foreach ($c in $CodeText.Keys) {
                if ($c -eq $rel) { continue }
                $t = $CodeText[$c]; $found = $false
                foreach ($k in $keys) { if ($t.IndexOf($k, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $found = $true; break } }
                if (-not $found) { continue }
                $hop = @(Get-SIFastGateKeys -RelativePath $c)
                if (-not $hop.Count) { continue }
                foreach ($s in @(& $byKey $hop)) { & $add $s ("names {0}, which loads {1}" -f ($c -split '/')[-1], $leaf); $covered = $true }
            }
        }
        if ($covered) { continue }
        # nothing names it: the suites of its folder (a suite naming a file next to it), then the parent folder
        $dir = if ($rel.Contains('/')) { $rel.Substring(0, $rel.LastIndexOf('/')) } else { '' }
        while (-not $covered) {
            $siblings = @($CodeText.Keys | Where-Object { $_ -ne $rel -and $_.StartsWith($(if ($dir) { $dir + '/' } else { '' })) -and $(if ($dir) { $true } else { -not $_.Contains('/') }) })
            foreach ($sib in $siblings) {
                $sk = @(Get-SIFastGateKeys -RelativePath $sib)
                if (-not $sk.Count) { continue }
                foreach ($s in @(& $byKey $sk)) { & $add $s ("folder of {0} (names {1})" -f $leaf, ($sib -split '/')[-1]); $covered = $true }
            }
            if ($covered -or -not $dir) { break }
            $dir = if ($dir.Contains('/')) { $dir.Substring(0, $dir.LastIndexOf('/')) } else { '' }
        }
        if (-not $covered) { $unmapped.Add($rel) }
    }
    if (-not $NoSafety) {
        foreach ($s in @($Map.Safety)) { & $add $s 'safety (always on)' }
        # the FULL cycle carries the hotfix smoke set too (it is a subset of the safety list today; kept explicit)
        foreach ($s in @(if ($Map.PSObject.Properties['Smoke']) { $Map.Smoke })) { & $add $s 'smoke (always on)' }
    }
    [pscustomobject]@{ Suites = $suites; Dotnet = $dotnet; Unmapped = $unmapped.ToArray(); OverBudget = [ordered]@{}; Dropped = [ordered]@{} }
}

function Get-SIFastGateOwnSuite {
    <# PURE. Is -Suite named after the changed file (SI-FastRoll.ps1 -> SIv3-FastRoll.Tests.ps1)? The SI-/SIv3-/verb prefixes are dropped; 6+ characters. #>
    param([Parameter(Mandatory)][string]$Suite, [Parameter(Mandatory)][string]$RelativePath)
    $norm = { param([string]$x) ($x -replace '\.Tests\.ps1$', '' -replace '\.[A-Za-z0-9]+$', '' -replace '^(SIv3-|SI-)', '' -replace '^(Invoke|Get|Set|New|Start|Test|Update|Publish|Build)-', '' -replace '[^A-Za-z0-9]', '').ToLowerInvariant() }
    $f = & $norm (($RelativePath -split '/')[-1]); $s = & $norm $Suite
    if ($f.Length -lt 6 -or $s.Length -lt 6) { return $false }
    $s.StartsWith($f) -or $f.StartsWith($s)
}

function Get-SIFastGateHotfixSelection {
    <# PURE. The -Hotfix selection (Get-SIFastGateSelection -Hotfix explains it). #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Changed, [Parameter(Mandatory)][hashtable]$SuiteText,
          [Parameter(Mandatory)]$Map, [hashtable]$CodeText = @{}, [switch]$NoSafety, [hashtable]$Seconds = @{}, [double]$BudgetSeconds = 300, [double]$SuiteMaxSeconds = 120)
    $dotnet = [ordered]@{}; $unmapped = New-Object System.Collections.Generic.List[string]
    # candidate -> rank (0 changed suite, 1 named after the file, 2 explicit map, 3 names the file, 4 one hop / folder), score, why, paths
    $cand = @{}
    $note = {
        param([string]$name, [int]$rank, [int]$score, [string]$why, [string]$path)
        if (-not $SuiteText.ContainsKey($name)) { return }
        if (-not $cand.ContainsKey($name)) { $cand[$name] = [pscustomobject]@{ Name = $name; Rank = $rank; Score = $score; Why = $why; Paths = (New-Object System.Collections.Generic.List[string]) } }
        $c = $cand[$name]
        if ($rank -lt $c.Rank -or ($rank -eq $c.Rank -and $score -gt $c.Score)) { $c.Rank = $rank; $c.Score = $score; $c.Why = $why }
        if (-not $c.Paths.Contains($path)) { $c.Paths.Add($path) }
    }
    $count = { param([string]$text, [string[]]$keys) $n = 0; foreach ($k in $keys) { $n += [regex]::Matches($text, [regex]::Escape($k), 'IgnoreCase').Count }; $n }
    $sec = { param($x) if ($Seconds.ContainsKey($x) -and $Seconds[$x] -gt 0) { [double]$Seconds[$x] } else { 20.0 } }
    foreach ($p in $Changed) {
        $rel = ($p -replace '\\', '/').TrimStart('/')
        $leaf = ($rel -split '/')[-1]
        $found = $false
        if ($rel -match '^tests/pester/[^/]+\.Tests\.ps1$') { & $note $leaf 0 0 'changed suite' $rel; $found = $true }
        foreach ($m in @($Map.Explicit)) {
            $mm = [regex]::Match($rel, $m.Pattern)
            if (-not $mm.Success) { continue }
            foreach ($s in $m.Suites) { & $note $s 2 0 ("explicit map: $rel") $rel }
            foreach ($d in $m.Dotnet) { $dn = $d; if ($dn -eq '${p}') { $dn = $mm.Groups['p'].Value }; if (-not $dotnet.Contains($dn)) { $dotnet[$dn] = "explicit map: $rel" } }
            $found = $true
        }
        if ($rel -match '^tests/pester/[^/]+\.Tests\.ps1$') { continue }
        if (@(@($Map.Explicit) | Where-Object { $_.PSObject.Properties['Exclusive'] -and $_.Exclusive -and $rel -match $_.Pattern }).Count) { continue }
        $keys = @(Get-SIFastGateKeys -RelativePath $rel)
        if ($keys.Count) {
            foreach ($s in $SuiteText.Keys) {
                $n = & $count $SuiteText[$s] $keys
                if (-not $n) { continue }
                $own = Get-SIFastGateOwnSuite -Suite $s -RelativePath $rel
                & $note $s $(if ($own) { 1 } else { 3 }) $n $(if ($own) { "named after $leaf" } else { "names $leaf ($n x)" }) $rel
                $found = $true
            }
        }
        if ($found) { continue }
        # nothing names it: one hop (a script that loads it), then the folder -- as the full cycle does
        $one = Get-SIFastGateSelection -Changed @($rel) -SuiteText $SuiteText -Map ([pscustomobject]@{ Safety = @(); Explicit = @() }) -CodeText $CodeText -NoSafety
        foreach ($k in $one.Suites.Keys) { & $note $k 4 0 $one.Suites[$k] $rel; $found = $true }
        if (-not $found) { $unmapped.Add($rel) }
    }
    # rank, then count against the budget: what fits first, then EVERY other covering suite too (no nightly run any more --
    # a suite left out here would never run), each named in OverBudget with its measured seconds
    $order = @($cand.Values | Sort-Object -Property @{ Expression = { $_.Rank } }, @{ Expression = { $_.Score }; Descending = $true }, @{ Expression = { & $sec $_.Name } }, @{ Expression = { $_.Name } })
    $suites = [ordered]@{}; $over = [ordered]@{}; $used = 0.0
    foreach ($c in $order) {
        $x = & $sec $c.Name
        $fits = ($c.Rank -eq 0) -or (($used + $x -le $BudgetSeconds) -and ($x -le $SuiteMaxSeconds -or $c.Rank -le 1))
        if ($fits) { $suites[$c.Name] = $c.Why; $used += $x }
    }
    foreach ($c in $order) {
        if ($suites.Contains($c.Name)) { continue }
        $x = & $sec $c.Name
        $suites[$c.Name] = $c.Why + ' (over the hotfix budget -- it covers the change, so it runs)'
        $over[$c.Name] = ("{0} s measured; {1}" -f [Math]::Round($x, 1), $c.Why)
        $used += $x
    }
    if (-not $NoSafety) { foreach ($s in @(if ($Map.PSObject.Properties['Smoke']) { $Map.Smoke })) { if ($SuiteText.ContainsKey($s) -and -not $suites.Contains($s)) { $suites[$s] = 'smoke (always on)' } } }
    [pscustomobject]@{ Suites = $suites; Dotnet = $dotnet; Unmapped = $unmapped.ToArray(); OverBudget = $over; Dropped = [ordered]@{} }
}

function Get-SIQuickGateLoads {
    <# PURE. How many OTHER SI code files does -RelativePath's own code name (by file name / stem)? A hub loads 20+. #>
    param([Parameter(Mandatory)][string]$RelativePath, [hashtable]$CodeText = @{})
    if (-not $CodeText.ContainsKey($RelativePath)) { return 0 }
    $t = [string]$CodeText[$RelativePath]; $n = 0
    foreach ($c in $CodeText.Keys) {
        if ($c -eq $RelativePath) { continue }
        foreach ($k in @(Get-SIFastGateKeys -RelativePath $c)) { if ($t.IndexOf($k, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $n++; break } }
    }
    $n
}

function Test-SIQuickGateTextReader {
    <#
        PURE. Does a suite READ -RelativePath's TEXT (owner 2026-10-25: three suites asserted on lines of the hub
        Invoke-RiskAnalysis.ps1 through IndexOf, the hub rule did not select them, and a reshaped line went unseen for a
        release)? Yes when a code line (not a comment) names the file (its path or file name) together with a read --
        Get-Content, [IO.File]::ReadAllText / ReadAllLines / ReadAllBytes, Select-String, the parser's ParseFile /
        ParseInput, Get-FileHash -- or assigns a variable that such a read takes later. Dot-sourcing it is a LOAD, not a read.
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text, [Parameter(Mandatory)][string]$RelativePath)
    $leaf = ($RelativePath -split '/')[-1]
    if ($Text.IndexOf($leaf, [StringComparison]::OrdinalIgnoreCase) -lt 0) { return $false }
    $read = '(Get-Content|ReadAllText|ReadAllLines|ReadAllBytes|Select-String|ParseFile|ParseInput|Get-FileHash)'
    $esc = [regex]::Escape($leaf); $vars = New-Object System.Collections.Generic.List[string]
    foreach ($l in ($Text -split "`r?`n")) {
        if ($l.TrimStart().StartsWith('#') -or $l -notmatch $esc) { continue }
        if ($l -match $read) { return $true }
        $m = [regex]::Match($l, '^\s*\$(?:script:|global:)?(\w+)\s*=')
        if ($m.Success) { $vars.Add($m.Groups[1].Value) }
    }
    foreach ($v in $vars) { if ([regex]::IsMatch($Text, $read + '[^\r\n]*\$(?:script:|global:)?' + [regex]::Escape($v) + '\b')) { return $true } }
    $false
}

function Get-SIQuickGateNeedles {
    <#
        PURE. The texts a suite LOOKS FOR: its string literals (the PowerShell tokenizer's own, so an apostrophe in a comment
        never shifts them), -MinLength characters or more, without $( ) inside, and never the file's own name or path.
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text, [string]$Leaf = '', [int]$MinLength = 12, [hashtable]$Ignore = @{})
    $n = New-Object System.Collections.Generic.List[string]; $seen = New-Object System.Collections.Generic.HashSet[string]
    $tok = $null; $err = $null
    [void][System.Management.Automation.Language.Parser]::ParseInput($Text, [ref]$tok, [ref]$err)
    foreach ($k in @($tok)) {
        if ($k -isnot [System.Management.Automation.Language.StringToken]) { continue }
        if ($k -is [System.Management.Automation.Language.StringExpandableToken] -and @($k.NestedTokens).Count) { continue }
        $s = [string]$k.Value
        if ($s.Length -lt $MinLength) { continue }
        if ($Leaf -and ($s -eq $Leaf -or $s.EndsWith($Leaf, [StringComparison]::OrdinalIgnoreCase) -or $s.EndsWith(($Leaf -replace '\.[^.]+$', ''), [StringComparison]::OrdinalIgnoreCase))) { continue }
        # a PowerShell word every script has (ForEach-Object, SilentlyContinue) says nothing about what the suite reads
        if ($Ignore.ContainsKey($s)) { continue }
        # and a bare .NET type name (System.Collections.Generic.List[string]) neither
        if ($s -match '^\[?System\.[\w.]+(\[[\w.,\s\[\]]*\])?\]?$') { continue }
        if ($seen.Add($s)) { $n.Add($s) }
    }
    $n.ToArray()
}

function Get-SIQuickGateCommonWords {
    <#
        The PowerShell words that say nothing about what a suite reads: every cmdlet name of this session (ForEach-Object,
        Where-Object, Select-Object ...) and the common enum values. A needle that is one of them is not used (measured:
        'ForEach-Object' / 'Where-Object' selected suites that read nothing the change touched). Case-insensitive keys.
    #>
    $h = @{}
    foreach ($c in @(Get-Command -CommandType Cmdlet -ErrorAction SilentlyContinue)) { $h[[string]$c.Name] = $true }
    foreach ($w in 'SilentlyContinue', 'OrdinalIgnoreCase', 'InvariantCulture', 'CurrentCulture', 'IgnoreCase', 'Multiline', 'Singleline', 'IgnorePatternWhitespace', 'ExplicitCapture', 'CultureInvariant', 'ExpandString', 'NoNewWindow') { $h[$w] = $true }
    $h
}

function Get-SIQuickGateTouchedFunctions {
    <# PURE. The functions (innermost) whose body holds a changed line: -OldLines in -OldText, -NewLines in -NewText. #>
    param([AllowEmptyString()][string]$OldText = '', [AllowEmptyString()][string]$NewText = '', [int[]]$OldLines = @(), [int[]]$NewLines = @())
    $names = New-Object System.Collections.Generic.List[string]
    foreach ($pair in @(@{ T = $OldText; L = $OldLines }, @{ T = $NewText; L = $NewLines })) {
        if (-not $pair.T -or -not @($pair.L).Count) { continue }
        $ast = [System.Management.Automation.Language.Parser]::ParseInput([string]$pair.T, [ref]$null, [ref]$null)
        $fs = @($ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true))
        foreach ($ln in @($pair.L)) {
            $best = $null
            foreach ($f in $fs) { if ($f.Extent.StartLineNumber -le $ln -and $f.Extent.EndLineNumber -ge $ln -and (-not $best -or ($f.Extent.EndLineNumber - $f.Extent.StartLineNumber) -lt ($best.Extent.EndLineNumber - $best.Extent.StartLineNumber))) { $best = $f } }
            if ($best -and -not $names.Contains($best.Name)) { $names.Add($best.Name) }
        }
    }
    $names.ToArray()
}

function Get-SIQuickGateTextReaders {
    <#
        PURE. THE TEXT-READER RULE (owner 2026-10-25, approved bound): a suite that READS a changed file's text
        (Test-SIQuickGateTextReader) is selected for that file -- hub, broad or narrow alike -- when the change can reach
        what it reads:
          * one of its own string literals (Get-SIQuickGateNeedles: 12+ characters, found at most -MaxInFile (10) times in
            the file, old or new; never a cmdlet name, a common enum word or a bare .NET type name) is in a CHANGED line,
            old or new side; or
          * it names a function whose body the change touches (Get-SIQuickGateTouchedFunctions).
        No cap: every such reader runs, each named with what matched. -Change $null = no diff is known (-Paths): EVERY reader
        is selected (the honest worst case). -Change: @{ Old (removed lines); New (added lines); OldLines; NewLines (their
        numbers); OldText; NewText (the file before / after) }. Returns an ordered name -> reason.
    #>
    param([Parameter(Mandatory)][string]$RelativePath, [Parameter(Mandatory)][hashtable]$SuiteText, $Change = $null,
          [int]$MinLength = 12, [int]$MaxInFile = 10, [hashtable]$NeedleCache = @{})
    $leaf = ($RelativePath -split '/')[-1]
    $out = [ordered]@{}
    $readers = @(@($SuiteText.Keys | Sort-Object) | Where-Object { Test-SIQuickGateTextReader -Text ([string]$SuiteText[$_]) -RelativePath $RelativePath })
    if (-not $readers.Count) { return $out }
    if ($null -eq $Change) {
        foreach ($s in $readers) { $out[$s] = ("reads {0}'s text (no diff known: every reader runs)" -f $leaf) }
        return $out
    }
    $changedText = (@(@($Change.Old) + @($Change.New) | ForEach-Object { [string]$_ })) -join "`n"
    $funcs = @(Get-SIQuickGateTouchedFunctions -OldText ([string]$Change.OldText) -NewText ([string]$Change.NewText) -OldLines @($Change.OldLines) -NewLines @($Change.NewLines))
    $short = { param([string]$x) $y = ($x -replace '\s+', ' ').Trim(); if ($y.Length -gt 70) { $y.Substring(0, 67) + '...' } else { $y } }
    foreach ($s in $readers) {
        $t = [string]$SuiteText[$s]
        if (-not $NeedleCache.ContainsKey('__common')) { $NeedleCache['__common'] = Get-SIQuickGateCommonWords }
        $ck = "$s|$leaf"
        if (-not $NeedleCache.ContainsKey($ck)) { $NeedleCache[$ck] = @(Get-SIQuickGateNeedles -Text $t -Leaf $leaf -MinLength $MinLength -Ignore $NeedleCache['__common']) }
        $why = ''
        if ($changedText) {
            foreach ($n in @($NeedleCache[$ck])) {
                if ($changedText.IndexOf($n, [StringComparison]::Ordinal) -lt 0) { continue }
                $inFile = [Math]::Max(([regex]::Matches([string]$Change.OldText, [regex]::Escape($n))).Count, ([regex]::Matches([string]$Change.NewText, [regex]::Escape($n))).Count)
                if ($inFile -gt $MaxInFile) { continue }
                $why = ("reads {0}'s text; the change touches '{1}'" -f $leaf, (& $short $n)); break
            }
        }
        if (-not $why) { foreach ($f in $funcs) { if ($t.IndexOf($f, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $why = ("reads {0}'s text; the change is inside {1}, which it names" -f $leaf, $f); break } } }
        if ($why) { $out[$s] = $why }
    }
    $out
}

function Get-SIFastGateChangedLines {
    <#
        What changed INSIDE -RelativePath (relative to SOLUTIONS\SecurityInsight, '/') between -Base and the working tree
        (`git diff -U0 <Base> -- <path>`: the commits since Base and the uncommitted edits together): @{ Old; New; OldLines;
        NewLines; OldText; NewText } for Get-SIQuickGateTextReaders. A file new since Base: every line is new.
    #>
    param([Parameter(Mandatory)][string]$RepoRoot, [Parameter(Mandatory)][string]$Base, [Parameter(Mandatory)][string]$RelativePath, [Parameter(Mandatory)][string]$SIRoot)
    $gp = 'SOLUTIONS/SecurityInsight/' + $RelativePath
    $disk = Join-Path $SIRoot ($RelativePath -replace '/', [IO.Path]::DirectorySeparatorChar)
    $newText = if (Test-Path -LiteralPath $disk -PathType Leaf) { [IO.File]::ReadAllText($disk) } else { '' }
    $oldText = (@(Invoke-SIGitText -RepoRoot $RepoRoot -Arguments @('show', ("{0}:{1}" -f $Base, $gp))) -join "`n"); if ($LASTEXITCODE) { $oldText = '' }
    $old = New-Object System.Collections.Generic.List[string]; $new = New-Object System.Collections.Generic.List[string]
    $oldLn = New-Object System.Collections.Generic.List[int]; $newLn = New-Object System.Collections.Generic.List[int]
    if (-not $oldText -and $newText) {
        $i = 0; foreach ($l in ($newText -split "`r?`n")) { $i++; $new.Add($l); $newLn.Add($i) }
    } else {
        foreach ($l in @(& git -C $RepoRoot -c core.quotepath=false diff -U0 --no-color --no-ext-diff $Base -- $gp 2>$null)) {
            $h = [regex]::Match($l, '^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@')
            if ($h.Success) {
                $o = [int]$h.Groups[1].Value; $oc = if ($h.Groups[2].Success) { [int]$h.Groups[2].Value } else { 1 }
                $nw = [int]$h.Groups[3].Value; $nc = if ($h.Groups[4].Success) { [int]$h.Groups[4].Value } else { 1 }
                for ($k = 0; $k -lt $oc; $k++) { $oldLn.Add($o + $k) }; for ($k = 0; $k -lt $nc; $k++) { $newLn.Add($nw + $k) }
                continue
            }
            if ($l.StartsWith('---') -or $l.StartsWith('+++') -or $l.StartsWith('diff ') -or $l.StartsWith('index ')) { continue }
            if ($l.StartsWith('-')) { $old.Add($l.Substring(1)) } elseif ($l.StartsWith('+')) { $new.Add($l.Substring(1)) }
        }
    }
    $global:LASTEXITCODE = 0
    [pscustomobject]@{ Old = $old.ToArray(); New = $new.ToArray(); OldLines = $oldLn.ToArray(); NewLines = $newLn.ToArray(); OldText = $oldText; NewText = $newText }
}

function Get-SIQuickGateSelection {
    <#
        PURE (given the texts). THE QUICK GATE's selection (owner 2026-10-13: "yes, build it the pim way"; PIM
        docs\TESTS.md 1c-iib; SI docs\TESTS.md "The quick gate"). Never "every suite that covers the path":

          - a CHANGED SUITE runs itself;
          - the EXPLICIT map (fast-gate.map.json): its suites / dotnet projects; an exclusive entry decides alone. kind doc
            (a document) -> its doc guards only; kind bump (VERSION, RELEASENOTES.md) -> only the suites that name it;
          - every other path: the suites that SEE it -- the suites that name it (file name / stem), or, when none does, the
            suites that name a script whose code names it (one hop):
              * a HUB (Map.Hubs, or its code names Map.Quick.HubLoads+ other SI code files) -> the core set + at most NamedMax
                suites NAMED AFTER it (owner 2026-10-13);
              * seen by at most Map.Quick.BroadOver (3) suites -> a NARROW file: those suites;
              * seen by more -> a BROAD file: at most Map.Quick.NamedMax (3) -- the suites NAMED AFTER the file first
                (Get-SIFastGateOwnSuite), then the ones that name it most often;
              * seen by none -> UNMAPPED: the core set (never everything) -- and named in Unmapped.
              * in EVERY case above: a suite that READS the file's text runs when the change reaches what it reads
                (Get-SIQuickGateTextReaders, owner 2026-10-25; -ChangedLines $null = every reader) -- TextReaders names them.
          - THE CORE SET (Map.Core) whenever a path is not a document / release-bump file (or nothing changed at all).
        -Suites given by name (-Named) = exactly those + the core set, and -Changed is ignored.
        Returns @{ Suites (name -> reason); Dotnet (project -> reason); Unmapped; Broad (path -> suites that see it);
        Hubs (paths); Narrow (paths); Notes; Core (bool: the core set was added) }.
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Changed, [Parameter(Mandatory)][hashtable]$SuiteText,
          [Parameter(Mandatory)]$Map, [hashtable]$CodeText = @{}, [AllowEmptyCollection()][string[]]$Named = @(),
          # what changed inside each path (Get-SIFastGateChangedLines), for the text-reader rule; $null = no diff known
          # (-Paths): every suite that reads a changed file's text is selected
          [hashtable]$ChangedLines = $null)
    $needleCache = @{}; $textReaders = [ordered]@{}
    $q = if ($Map.PSObject.Properties['Quick'] -and $Map.Quick) { $Map.Quick } else { [pscustomobject]@{ BroadOver = 3; NamedMax = 3; HubLoads = 20 } }
    $hubList = @(if ($Map.PSObject.Properties['Hubs']) { $Map.Hubs })
    $suites = [ordered]@{}; $dotnet = [ordered]@{}; $unmapped = New-Object System.Collections.Generic.List[string]
    $broad = [ordered]@{}; $hubs = New-Object System.Collections.Generic.List[string]; $narrow = New-Object System.Collections.Generic.List[string]
    $notes = New-Object System.Collections.Generic.List[string]
    $add = { param($name, $why) if ($SuiteText.ContainsKey($name) -and -not $suites.Contains($name)) { $suites[$name] = $why } }
    $named = @($Named | Where-Object { $_ } | ForEach-Object { $n = "$_".Trim(); if ($n -like '*.Tests.ps1') { $n } else { "$n.Tests.ps1" } })
    $needCore = $true
    if ($named.Count) {
        foreach ($n in $named) { if ($SuiteText.ContainsKey($n)) { & $add $n '-Suites (named)' } else { $notes.Add("no suite named $n here") } }
        $Changed = @()
    } elseif ($Changed.Count) { $needCore = $false }
    $count = { param([string]$text, [string[]]$keys) $n = 0; foreach ($k in $keys) { $n += [regex]::Matches($text, [regex]::Escape($k), 'IgnoreCase').Count }; $n }
    foreach ($p in $Changed) {
        $rel = ($p -replace '\\', '/').TrimStart('/')
        $leaf = ($rel -split '/')[-1]
        if ($rel -match '^tests/pester/[^/]+\.Tests\.ps1$') { & $add $leaf 'changed suite'; $needCore = $true; continue }
        $hits = @(@($Map.Explicit) | Where-Object { [regex]::IsMatch($rel, $_.Pattern) })
        foreach ($m in $hits) {
            $mm = [regex]::Match($rel, $m.Pattern)
            foreach ($s in $m.Suites) { & $add $s ("explicit map: $rel") }
            foreach ($d in $m.Dotnet) { $dn = $d; if ($dn -eq '${p}') { $dn = $mm.Groups['p'].Value }; if (-not $dotnet.Contains($dn)) { $dotnet[$dn] = "explicit map: $rel" } }
        }
        $kinds = @($hits | ForEach-Object { if ($_.PSObject.Properties['Kind']) { "$($_.Kind)" } else { '' } })
        $isDocOrBump = $hits.Count -and -not @($kinds | Where-Object { $_ -notin 'doc', 'bump' }).Count
        if (-not $isDocOrBump) { $needCore = $true }
        if (@($hits | Where-Object { $_.Exclusive }).Count) { continue }
        # the suites that SEE it: they name it; when none does, they name a script whose code names it (one hop)
        $keys = @(Get-SIFastGateKeys -RelativePath $rel)
        $direct = [ordered]@{}
        if ($keys.Count) { foreach ($s in @($SuiteText.Keys | Sort-Object)) { $n = & $count $SuiteText[$s] $keys; if ($n) { $direct[$s] = $n } } }
        $seen = [ordered]@{}; $via = 'names'
        foreach ($s in $direct.Keys) { $seen[$s] = ("names {0}" -f $leaf) }
        if (-not $seen.Count -and $keys.Count -and $rel -match '\.(ps1|psm1|psd1|yaml|yml|json|csv|sql)$') {
            $via = 'hop'
            foreach ($c in @($CodeText.Keys | Sort-Object)) {
                if ($c -eq $rel) { continue }
                $t = $CodeText[$c]; $found = $false
                foreach ($k in $keys) { if ($t.IndexOf($k, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $found = $true; break } }
                if (-not $found) { continue }
                $hop = @(Get-SIFastGateKeys -RelativePath $c)
                if (-not $hop.Count) { continue }
                foreach ($s in @($SuiteText.Keys | Sort-Object)) {
                    if ($seen.Contains($s)) { continue }
                    foreach ($k in $hop) { if ($SuiteText[$s].IndexOf($k, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $seen[$s] = ("names {0}, which loads {1}" -f ($c -split '/')[-1], $leaf); break } }
                }
            }
        }
        # THE TEXT-READER RULE (owner 2026-10-25): a suite that READS this file's text runs when the change reaches what it
        # reads -- hub, broad or narrow alike (Get-SIQuickGateTextReaders; no diff known = every reader)
        $chg = if ($null -ne $ChangedLines -and $ChangedLines.ContainsKey($rel)) { $ChangedLines[$rel] } else { $null }
        $readers = Get-SIQuickGateTextReaders -RelativePath $rel -SuiteText $SuiteText -Change $chg -NeedleCache $needleCache
        foreach ($s in $readers.Keys) { & $add $s $readers[$s] }
        if ($readers.Count) {
            if (-not $textReaders.Contains($rel)) { $textReaders[$rel] = @($readers.Keys) }
            $notes.Add(("{0}: {1} suite(s) read its text and the change reaches what they read ({2})" -f $rel, $readers.Count, $(if ($null -eq $chg) { 'no diff known: every reader' } else { 'a changed line holds their text, or a touched function is one they name' })))
        }
        $isHub = ($hubList -contains $rel) -or ($rel -notmatch '^tests/' -and $CodeText.ContainsKey($rel) -and (Get-SIQuickGateLoads -RelativePath $rel -CodeText $CodeText) -ge $q.HubLoads)
        if ($isHub) {
            $hubs.Add($rel)
            # owner 2026-10-13: a hub ALSO runs the suites NAMED AFTER it -- at most NamedMax (3)
            $own = @(@($SuiteText.Keys | Sort-Object) | Where-Object { Get-SIFastGateOwnSuite -Suite $_ -RelativePath $rel } | Select-Object -First $q.NamedMax)
            foreach ($s in $own) { & $add $s ("named after {0} (a hub: {1} suites see it)" -f $leaf, $seen.Count) }
            $notes.Add(("{0} is a HUB (it loads {1}+ SI files; seen by {2} suites) -- the core set + the {3} suite(s) named after it" -f $rel, $q.HubLoads, $seen.Count, $own.Count))
            continue
        }
        if (-not $seen.Count) {
            if (-not $hits.Count) { $unmapped.Add($rel); $notes.Add(("no suite sees {0} -- the core set checks it" -f $rel)) }
            continue
        }
        if ($seen.Count -le $q.BroadOver) {
            $narrow.Add($rel)
            foreach ($s in $seen.Keys) { & $add $s $seen[$s] }
            continue
        }
        # BROAD: at most NamedMax -- named after the file first, then the ones that name it most often
        $broad[$rel] = $seen.Count
        $pick = New-Object System.Collections.Generic.List[string]
        foreach ($s in @($SuiteText.Keys | Sort-Object)) { if ($pick.Count -lt $q.NamedMax -and (Get-SIFastGateOwnSuite -Suite $s -RelativePath $rel)) { $pick.Add($s) } }
        foreach ($s in @($direct.Keys | Sort-Object -Property @{ Expression = { $direct[$_] }; Descending = $true }, @{ Expression = { $_ } })) {
            if ($pick.Count -ge $q.NamedMax) { break }
            if (-not $pick.Contains($s)) { $pick.Add($s) }
        }
        foreach ($s in $pick) { & $add $s $(if (Get-SIFastGateOwnSuite -Suite $s -RelativePath $rel) { "named after $leaf (a broad file: $($seen.Count) suites see it)" } else { "names $leaf $($direct[$s]) x (a broad file: $($seen.Count) suites see it)" }) }
        $notes.Add(("{0} is BROAD: {1} suites see it ({2}) -- the core set + {3} of them" -f $rel, $seen.Count, $(if ($via -eq 'hop') { 'through a script that loads it' } else { 'they name it' }), $pick.Count))
    }
    if ($needCore) { foreach ($s in @(if ($Map.PSObject.Properties['Core']) { $Map.Core })) { & $add $s 'core set (every quick gate)' } }
    [pscustomobject]@{ Suites = $suites; Dotnet = $dotnet; Unmapped = $unmapped.ToArray(); Broad = $broad; Hubs = $hubs.ToArray(); Narrow = $narrow.ToArray(); Notes = $notes.ToArray(); Core = [bool]$needCore; TextReaders = $textReaders }
}

function New-SIFastGateBatches {
    <#
        PURE. The suites in BATCHES of about -TargetSeconds of measured time each (first-fit, heaviest first; a suite heavier
        than the target is a batch of its own), heaviest batch first. Each batch runs in a FRESH worker process: measured
        2026-10-06, a Windows PowerShell 5.1 process that runs suite after suite for half an hour slows down (a suite that
        takes 23 s on its own took 255 s at the end of a long shard) -- short-lived workers pulled from a queue keep every
        suite at its own speed and balance the runtimes by themselves. -TargetSeconds 0 = the total / (workers x 4), held
        between 45 and 180 s (TEST-RUN-1, 2026-10-07: a 5.1 batch of 240 measured seconds -- SIv3-ContainerUpdate,
        SIv3-VulnTargetLoop, SIv3-EngineRunConfigPath -- passed its 1,200 s timeout on the test VM while the dotnet build ran
        beside it; a shorter batch is a shorter re-run and balances better across 16 workers). Returns the batches as arrays
        of names.
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Names, [int]$Workers = 4, [hashtable]$Seconds = @{}, [double]$Default = 20, [double]$TargetSeconds = 0)
    $w = { param($x) if ($Seconds.ContainsKey($x) -and $Seconds[$x] -gt 0) { [double]$Seconds[$x] } else { $Default } }
    if (-not $Names.Count) { return }
    $total = 0.0; foreach ($n in $Names) { $total += (& $w $n) }
    if ($TargetSeconds -le 0) { $TargetSeconds = [Math]::Min(180, [Math]::Max(45, $total / ([Math]::Max(1, $Workers) * 4))) }
    $bins = New-Object System.Collections.Generic.List[object]
    foreach ($s in @($Names | Sort-Object -Property @{ Expression = { & $w $_ }; Descending = $true }, @{ Expression = { $_ } })) {
        $x = & $w $s; $placed = $false
        foreach ($b in $bins) { if ($b.Load + $x -le $TargetSeconds) { $b.Names.Add($s); $b.Load += $x; $placed = $true; break } }
        if (-not $placed) { $nb = [pscustomobject]@{ Names = (New-Object System.Collections.Generic.List[string]); Load = $x }; $nb.Names.Add($s); $bins.Add($nb) }
    }
    foreach ($b in @($bins | Sort-Object -Property Load -Descending)) { , $b.Names.ToArray() }
}
function Get-SIFastGateExcludeTags {
    <#
        PURE. The Pester tags a run leaves out, comma-separated ('' = none). A public copy: PrivateRepo. The dev FAST gate:
        Nightly (slow by nature). EVERY gate -- dev, -Hotfix and -Full -- leaves out the scale benchmarks (tag Scale: the
        100,000-record measurements of SIv3-CiBuildSql; owner 2026-10-11: "dont run that 100000 test" -- they took two hours of
        a full run). They run only when asked for by name: -Scale (a deliberate measurement, never part of a release gate).
    #>
    param([string]$Scope = '', [switch]$Full, [switch]$Hotfix, [switch]$Scale)
    $t = @()
    if ($Scope -eq 'PublicCopy') { $t += 'PrivateRepo' }
    if (-not $Full -and -not $Hotfix) { $t += 'Nightly' }
    if (-not $Scale) { $t += 'Scale' }
    $t -join ','
}
function Add-SIFastGatePs51Tag {
    <#
        PURE. The tag list (-Exclude, comma-separated) with 'Ps51' added when the gate runs PowerShell 7 only (-Runtime pwsh):
        the Windows PowerShell 5.1 parity probes (tag Ps51) run only on the 5.1 opt-in (-Runtime ps51 / both; operator
        2026-10-09: v3 gates PowerShell 7 only). Left out by tag they are said "not run (Ps51)", never a skip in a suite
        that then reads as not green (owner 2026-10-25: a skip is not a pass).
    #>
    param([AllowEmptyString()][string]$Exclude = '', [string]$Runtime = 'pwsh')
    if ($Runtime -ne 'pwsh') { return $Exclude }
    @(@($Exclude -split ',' | Where-Object { $_ }) + 'Ps51' | Select-Object -Unique) -join ','
}
function Get-SIFastGateBatchTimeout {
    <#
        PURE. How long ONE batch may run before it is stopped (its own process id) and re-run once in a fresh process: its
        measured seconds x -Factor, never under -MinSeconds. Nightly 2026-10-07 (a loaded mgmt1: other gates and an upgrade
        test at 01:00): suites ran 3x their measured time (SIv3-TemplateSplit 1,156 s -> 3,254 s on 5.1), so one fixed
        deadline for the whole run cut off two thirds of the queue. A hung suite is caught by its own batch timeout instead.
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Names, [hashtable]$Seconds = @{}, [double]$Default = 20, [double]$Factor = 5, [double]$MinSeconds = 900)
    $t = 0.0
    foreach ($n in $Names) { $t += $(if ($Seconds.ContainsKey($n) -and $Seconds[$n] -gt 0) { [double]$Seconds[$n] } else { $Default }) }
    [int][Math]::Ceiling([Math]::Max($MinSeconds, $t * $Factor))
}
function Get-SIFastGateDeadlineMinutes {
    <#
        PURE. The whole run's backstop: never shorter than -TimeoutMinutes; for a big run (the full suite, -Full) at least
        -Factor x the ideal wall time of the slowest runtime (its measured total / its workers) -- so a loaded machine makes
        the run slower, not red. Batches still queued when even this passes are reported 'never started' (never a pass).
        The ideal wall time is never shorter than the LONGEST single suite (-LongestSeconds): one suite runs in one process,
        so no number of workers ends the run before it does (2026-10-10: the hotfix gate runs the tests tagged Nightly, and
        SIv3-CiBuildSql's 100,000-record case alone outlasted a deadline computed from the total / the workers).
    #>
    param([int]$TimeoutMinutes = 40, [double[]]$RuntimeSeconds = @(), [int]$Workers = 1, [double]$Factor = 3, [double]$LongestSeconds = 0)
    $ideal = [Math]::Max(0.0, $LongestSeconds)
    foreach ($s in $RuntimeSeconds) { $ideal = [Math]::Max($ideal, [double]$s / [Math]::Max(1, $Workers)) }
    [int][Math]::Max($TimeoutMinutes, [Math]::Ceiling($ideal * $Factor / 60))
}
function Get-SIFastGateWorkers {
    <#
        PURE. Workers per runtime: the cores that are FREE now (-LoadPercent = the machine's CPU use before the gate starts),
        shared by the runtimes, at most cores / runtimes and never under half of that (a busy machine shares its CPU by
        process: one lone worker would get a sliver of it and take hours). Starting 4+4 PowerShell processes plus dotnet on
        a machine already at 90% only makes every one of them slower.
    #>
    param([Parameter(Mandatory)][int]$Cores, [int]$Runtimes = 2, [double]$LoadPercent = 0)
    $max = [Math]::Max(1, [int][Math]::Floor($Cores / [Math]::Max(1, $Runtimes)))
    $min = [Math]::Max(1, [int][Math]::Ceiling($max / 2))
    $free = [Math]::Max(0.0, [Math]::Min(100.0, 100.0 - $LoadPercent)) / 100.0
    [int][Math]::Min($max, [Math]::Max($min, [Math]::Ceiling($Cores * $free / [Math]::Max(1, $Runtimes))))
}
function Get-SIFastGateDotnetFilter {
    <#
        PURE. Which test classes of ONE test project cover the change (#416, 2026-10-09: the whole web suite -- ~4,000
        tests, 148 s on a loaded VM -- ran for every change, and one unrelated web test failed a release). Returns
        @{ Whole; Filter; Classes; Notes }: Whole = run the whole project (Filter ''); else Filter = the dotnet test
        --filter of Classes (the covering classes + -Always, the role matrix and the audit action list).

        For each changed path under -Related (other paths are not this project's):
          - a SHARED piece (-Shared regexes: Program.cs, the layout and shared partials, navigation, authorization, the
            project files) -> the WHOLE project;
          - a file of THIS test project: a *Tests class runs itself; a fake / fixture / anything else -> the WHOLE project;
            another test project's file -> nothing here;
          - a .cs / .cshtml source: the classes NAMED after it (its name without .cshtml / .cs and a trailing Service /
            Store / Model / Page / Repository / Controller, under -SourcePrefix), and the classes whose CODE names its class
            (-TestText) or, for a page, its route ("/Admin/Guards");
          - any other file (a config file, a stylesheet, a script): the classes whose code names the file.
        A change nothing names runs -Always only (the build still compiles it) and says so in Notes. More than
        -WholeOverShare of the classes picked -> the whole project (one run is as fast).
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Changed, [Parameter(Mandatory)][string]$SourcePrefix, [Parameter(Mandatory)][string]$TestPrefix,
          [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$TestClasses, [string[]]$Always = @(),
          [hashtable]$TestText = @{}, [string[]]$Related = @(), [string[]]$Shared = @(), [double]$WholeOverShare = 0.5,
          # a test FILE -> the test classes it declares (one file often holds several: GetStartedTests.cs holds GetStartedPageTests)
          [hashtable]$FileClasses = @{},
          # THE QUICK GATE (owner 2026-10-13: "never all 2,433 for a one-file change"): never the whole project -- a shared
          # piece or a fixture runs the classes that name it -- and at most -MaxClasses classes (+ -Always), in the order
          # found: a changed test class, a class named after the file, then a class whose code names it
          [switch]$NoWhole, [int]$MaxClasses = 0)
    $whole = { param($why) [pscustomobject]@{ Whole = $true; Filter = ''; Classes = @(); Notes = @($why) } }
    $pick = New-Object System.Collections.Generic.List[string]
    $pickAdd = { param([string]$c) if (-not @($pick | Where-Object { $_ -ieq $c }).Count) { $pick.Add($c) } }
    $notes = New-Object System.Collections.Generic.List[string]
    $named = {
        param([string[]]$keys, [switch]$Word)
        $hit = @()
        foreach ($cls in $TestClasses) {
            if ($cls -notmatch 'Tests$' -or -not $TestText.ContainsKey($cls)) { continue }
            foreach ($k in $keys) {
                if (-not $k) { continue }
                $rx = if ($Word) { '(?<![A-Za-z0-9_])' + [regex]::Escape($k) + '(?![A-Za-z0-9_])' } else { [regex]::Escape($k) }
                if ([regex]::IsMatch([string]$TestText[$cls], $rx, 'IgnoreCase')) { $hit += $cls; break }
            }
        }
        $hit
    }
    $mine = @($Changed | ForEach-Object { ($_ -replace '\\', '/').TrimStart('/') } | Where-Object { $c = $_; @($Related | Where-Object { $c -like "$_*" }).Count -or $c -like "$SourcePrefix*" -or $c -like "$TestPrefix*" })
    foreach ($c in $mine) {
        $isShared = $false
        foreach ($rx in $Shared) { if ($c -match $rx) { $isShared = $true; break } }
        if ($isShared -and -not $NoWhole) { return (& $whole "a shared piece changed ($c) -- the whole project runs") }
        if ($isShared) { $notes.Add("a shared piece changed ($c) -- the quick gate runs the classes that name it + the always-on classes (the whole project only in a full run, on the owner's words)") }
        $leaf = ($c -split '/')[-1]
        if ($c -like "$TestPrefix*") {
            $stem = $leaf -replace '\.cs$', ''
            if ($leaf -notmatch '\.cs$' -or $TestClasses -notcontains $stem -or $stem -notmatch 'Tests$') {
                if (-not $NoWhole) { return (& $whole "a shared test file changed ($leaf) -- the whole project runs") }
                $th = @(& $named @(Get-SIFastGateKeys -RelativePath $c) | Select-Object -Unique)
                if (-not $th.Count) { $th = @(& $named @($leaf -replace '\.cs$', '') -Word | Select-Object -Unique) }
                $notes.Add(("a shared test file changed ({0}) -- the quick gate runs the {1} class(es) that name it" -f $leaf, $th.Count))
                foreach ($h in $th) { & $pickAdd $h }
                continue
            }
            & $pickAdd $stem
            if ($FileClasses.ContainsKey($stem)) { foreach ($k in @($FileClasses[$stem])) { & $pickAdd $k } }
            continue
        }
        # another test project (a sibling of -TestPrefix): not this project's
        $testsRoot = ($TestPrefix.TrimEnd('/') -replace '/[^/]+$', '') + '/'
        if ($testsRoot.Length -gt 1 -and $c -like "$testsRoot*") { continue }
        $hits = @()
        if ($leaf -match '\.(cs|cshtml)$') {
            $full = $leaf -replace '\.cshtml\.cs$', '' -replace '\.(cs|cshtml)$', ''
            $stem = $full -replace '(Service|Store|Model|Page|Repository|Controller)$', ''
            if ($c -like "$SourcePrefix*" -and $stem.Length -ge 4) { $hits += @($TestClasses | Where-Object { $_.StartsWith($stem, [StringComparison]::OrdinalIgnoreCase) -and $_ -match 'Tests$' }) }
            # a page's class is <Name>Model; a generic page name (Index, Edit: every folder has one) is found by its route alone
            $generic = $full -in 'Index', 'Edit', 'Create', 'Delete', 'Details', 'Document', 'Documents', 'List' -or $full.Length -lt 5
            if (-not $generic) { $hits += @(& $named @($full, $(if ($leaf -like '*.cshtml*') { $full + 'Model' })) -Word) }
            if ($c -like "$($SourcePrefix)Pages/*") {
                $isIndex = $c -match '/Index\.cshtml(\.cs)?$'
                $route = '/' + ($c.Substring(($SourcePrefix + 'Pages/').Length) -replace '\.cshtml(\.cs)?$', '' -replace '/?Index$', '')
                if ($route.Length -gt 3) { $hits += @(& $named @(('"{0}"' -f $route), ('"{0}?' -f $route), $(if (-not $isIndex) { '"{0}/' -f $route }))) }
            }
        } else {
            $hits += @(& $named @(Get-SIFastGateKeys -RelativePath $c))
        }
        if (-not $hits.Count) { $notes.Add("no test class names $leaf -- the build and the always-on classes check it") }
        foreach ($h in $hits) { & $pickAdd $h }
    }
    if (-not $mine.Count -and -not $NoWhole) { return (& $whole 'no change of its own -- the whole project runs') }
    $total = @($TestClasses | Where-Object { $_ -match 'Tests$' }).Count
    if (-not $NoWhole -and $total -and ($pick.Count / $total) -gt $WholeOverShare) { return (& $whole ("{0} of {1} classes cover the change -- the whole project runs" -f $pick.Count, $total)) }
    if ($MaxClasses -gt 0 -and $pick.Count -gt $MaxClasses) {
        $notes.Add(("{0} classes cover the change -- the quick gate runs the first {1} (a changed test class, then the classes named after the file, then the ones whose code names it)" -f $pick.Count, $MaxClasses))
        $pick.RemoveRange($MaxClasses, $pick.Count - $MaxClasses)
    }
    foreach ($a in $Always) { if ($TestClasses -contains $a) { & $pickAdd $a } }
    $list = $pick.ToArray(); [Array]::Sort($list, [StringComparer]::Ordinal)
    [pscustomobject]@{ Whole = $false; Filter = (@($list | ForEach-Object { 'FullyQualifiedName~' + $_ }) -join '|'); Classes = $list; Notes = $notes.ToArray() }
}
function Get-SIFastGateBudget {
    <#
        PURE. THE 10-MINUTE LIMIT of every release gate (owner 2026-10-13: "we even agreed on hard limit of max 10 min"):
        600 s for the HOTFIX gate (the gate of every release, fix or feature) and for the FAST (dev) gate alike; a full
        run (only the owner starts one) has none. Over the limit is said PLAINLY -- "OVER THE 10-MINUTE LIMIT" -- and is
        never a reason to leave a suite out: -OverBudget names the covering suites that made the gate longer.
    #>
    param([Parameter(Mandatory)][string]$Mode, [Parameter(Mandatory)][double]$Seconds, [AllowEmptyCollection()][string[]]$OverBudget = @())
    $b = switch ($Mode) { 'quick' { 600 } 'hotfix' { 600 } 'fast' { 600 } default { 0 } }
    if (-not $b) { return $null }
    $met = $Seconds -le $b
    $why = @($OverBudget | Where-Object { $_ })
    $text = '{0} gate: {1:N0} s of the {2:N0} s limit (10 minutes) -- {3}' -f $Mode, $Seconds, $b, $(if ($met) { 'met' } else { 'OVER THE 10-MINUTE LIMIT' })
    if (-not $met -and $why.Count) { $text += (' (it took longer because {0} cover{1} the change)' -f ($why -join ', '), $(if ($why.Count -eq 1) { 's' } else { '' })) }
    [pscustomobject]@{ Target = $b; Seconds = [int]$Seconds; Met = $met; Text = $text }
}

function Get-SIGateProcessTree {
    <#
        The live descendants of ONE process the gate started (by its process id, through CIM Win32_Process
        ParentProcessId; a child counts only when it was created after its parent -- process ids are reused). Never by name:
        other lanes run on the same test VM. Returns @{ Id; ParentId; Name } (the root first); @() when CIM cannot be read.
    #>
    param([Parameter(Mandatory)][int]$RootId)
    try { $all = @(Get-CimInstance -ClassName Win32_Process -Property ProcessId, ParentProcessId, CreationDate, Name -ErrorAction Stop) } catch { return @() }
    $byId = @{}; $kids = @{}
    foreach ($p in $all) { $byId[[int]$p.ProcessId] = $p; $pp = [int]$p.ParentProcessId; if (-not $kids.ContainsKey($pp)) { $kids[$pp] = New-Object System.Collections.Generic.List[object] }; $kids[$pp].Add($p) }
    if (-not $byId.ContainsKey($RootId)) { return @() }
    $out = New-Object System.Collections.Generic.List[object]
    $out.Add([pscustomobject]@{ Id = $RootId; ParentId = 0; Name = [string]$byId[$RootId].Name })
    $queue = New-Object System.Collections.Generic.Queue[int]; $queue.Enqueue($RootId)
    while ($queue.Count) {
        $id = $queue.Dequeue()
        if (-not $kids.ContainsKey($id)) { continue }
        foreach ($c in $kids[$id]) {
            $cid = [int]$c.ProcessId
            if ($cid -eq $id -or $cid -eq $PID -or @($out | Where-Object Id -eq $cid).Count) { continue }
            if ($null -ne $c.CreationDate -and $null -ne $byId[$id].CreationDate -and $c.CreationDate -lt $byId[$id].CreationDate) { continue }
            $out.Add([pscustomobject]@{ Id = $cid; ParentId = $id; Name = [string]$c.Name }); $queue.Enqueue($cid)
        }
    }
    $out.ToArray()
}

function Stop-SIGateProcessTree {
    <#
        Ends a process the gate started AND every process it started (dotnet, MSBuild, a test host, a child pwsh) -- by the
        root's process id, never by name. PowerShell 7: the runtime's own tree kill (Process.Kill($true)); Windows
        PowerShell 5.1: taskkill /T /F /PID <root>. Then any descendant still alive (found by Get-SIGateProcessTree before
        the kill) by its own id. Returns the processes that were ended ("name (pid)"). Never throws.
    #>
    param([Parameter(Mandatory)][System.Diagnostics.Process]$Process)
    $tree = @()
    try { $tree = @(Get-SIGateProcessTree -RootId $Process.Id) } catch { }
    try {
        if (-not $Process.HasExited) {
            if ($Process.GetType().GetMethod('Kill', [type[]]@([bool]))) { $Process.Kill($true) }
            else { $null = & taskkill.exe /T /F /PID $Process.Id 2>&1 }
        }
    } catch { try { $null = & taskkill.exe /T /F /PID $Process.Id 2>&1 } catch { } }
    foreach ($m in @($tree | Where-Object { $_.Id -ne $Process.Id })) { try { Stop-Process -Id $m.Id -Force -ErrorAction SilentlyContinue } catch { } }
    try { [void]$Process.WaitForExit(10000) } catch { }
    $global:LASTEXITCODE = 0
    @($(if ($tree.Count) { $tree } else { @([pscustomobject]@{ Id = $Process.Id; ParentId = 0; Name = '' }) }) | ForEach-Object { '{0} ({1})' -f $(if ($_.Name) { $_.Name } else { 'process' }), $_.Id })
}

function Invoke-SIQuickGateRun {
    <#
        THE QUICK GATE's runner (owner 2026-10-13: "yes, build it the pim way"; PIM tests\_shared\Invoke-PimGate.ps1).
        -Items: @{ Name; Exe; Args (string[]); Kind } -- each runs in ITS OWN process (a Pester suite in its own pwsh, the
        web app's build + tests in one more), all at once up to -Throttle, every one with an EMPTY standard input (a
        prompt fails at once instead of waiting for a key over SSH).

        AT THE LIMIT: STOP AND REPORT. An item running longer than -SuiteLimitSeconds (600), or still running when the
        whole run has taken -GateLimitSeconds (600), is ENDED -- its whole process tree, by process id
        (Stop-SIGateProcessTree) -- and is State 'TimedOut' ("TIMED OUT after N min", by name); an item the limit left no
        time to start is State 'NotRun' ("NOT RUN"). The others' results stand. One line the moment an item finishes
        (-OnFinish turns the finished item into its status text and colour), and every -ProgressSeconds (60) the clock
        time and what still runs. Returns one result per item: @{ Name; Kind; State (Done | TimedOut | NotRun |
        StartFailed); Seconds; ExitCode; Note; Ended; Out; Err; Item }.
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Items, [Parameter(Mandatory)][string]$Work, [int]$Throttle = 12,
          [double]$SuiteLimitSeconds = 600, [double]$GateLimitSeconds = 600, [double]$ProgressSeconds = 60, [scriptblock]$OnFinish)
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $min = { param([double]$s) $m = [Math]::Max(0.1, [Math]::Round($s / 60, 1, [MidpointRounding]::AwayFromZero)); if ($m -eq [Math]::Floor($m)) { ([int]$m).ToString($inv) } else { $m.ToString('0.0', $inv) } }
    $clockText = { (Get-Date).ToString('HH:mm:ss', $inv) }
    $quote = { param([string]$v) if ($v -match '[\s"]') { '"' + ($v -replace '"', '\"') + '"' } else { $v } }
    New-Item -ItemType Directory -Force -Path $Work | Out-Null
    $noInput = Join-Path $Work 'no-input.txt'; [IO.File]::WriteAllText($noInput, '')
    $queue = New-Object System.Collections.Generic.Queue[object]; foreach ($i in $Items) { $queue.Enqueue($i) }
    $running = New-Object System.Collections.Generic.List[object]; $results = New-Object System.Collections.Generic.List[object]
    $clock = [Diagnostics.Stopwatch]::StartNew(); $nextProgress = $ProgressSeconds; $n = 0
    $finish = {
        param($r)
        $results.Add($r)
        $text = ''; $color = 'Gray'
        if ($OnFinish) { try { $f = & $OnFinish $r; if ($f) { $text = [string]$f.Text; if ($f.Color) { $color = [string]$f.Color } } } catch { $text = "(its result could not be read: $($_.Exception.Message))"; $color = 'Red' } }
        if ($r.State -ne 'Done') { $color = 'Red'; $text = $r.Note }
        Write-Host ("  [{0}] {1,7}s  {2}  {3}" -f (& $clockText), $r.Seconds.ToString('0.0', $inv), $r.Name, $text) -ForegroundColor $color
    }
    while ($queue.Count -or $running.Count) {
        $gateOver = $clock.Elapsed.TotalSeconds -ge $GateLimitSeconds
        while (-not $gateOver -and $queue.Count -and $running.Count -lt [Math]::Max(1, $Throttle)) {
            $it = $queue.Dequeue(); $n++
            $safe = ('{0:D3}-{1}' -f $n, ($it.Name -replace '[^A-Za-z0-9_.-]', '_'))
            $out = Join-Path $Work "$safe.out.log"; $err = Join-Path $Work "$safe.err.log"
            # an item's own environment (a Windows PowerShell 5.1 child must not inherit PowerShell 7's module path), restored at once
            $keepEnv = @{}
            if ($it.PSObject.Properties['Env'] -and $it.Env) { foreach ($k in @($it.Env.Keys)) { $keepEnv[$k] = [Environment]::GetEnvironmentVariable($k); [Environment]::SetEnvironmentVariable($k, [string]$it.Env[$k]) } }
            try {
                $p = Start-Process -FilePath $it.Exe -ArgumentList (@($it.Args | ForEach-Object { & $quote ([string]$_) }) -join ' ') -RedirectStandardInput $noInput -RedirectStandardOutput $out -RedirectStandardError $err -NoNewWindow -PassThru
                $null = $p.Handle   # keeps the exit code readable and the process id ours
                $running.Add([pscustomobject]@{ Item = $it; Process = $p; Watch = [Diagnostics.Stopwatch]::StartNew(); Out = $out; Err = $err })
            } catch {
                & $finish ([pscustomobject]@{ Name = $it.Name; Kind = $it.Kind; State = 'StartFailed'; Seconds = 0.0; ExitCode = 1; Note = "could not be started: $($_.Exception.Message)"; Ended = @(); Out = $out; Err = $err; Item = $it })
            } finally { foreach ($k in @($keepEnv.Keys)) { [Environment]::SetEnvironmentVariable($k, $keepEnv[$k]) } }
        }
        foreach ($r in $running.ToArray()) {   # .ToArray(): @( ) around a List[object] throws "Argument types do not match"
            $sec = $r.Watch.Elapsed.TotalSeconds
            if ($r.Process.HasExited) {
                $r.Process.WaitForExit()
                [void]$running.Remove($r)
                & $finish ([pscustomobject]@{ Name = $r.Item.Name; Kind = $r.Item.Kind; State = 'Done'; Seconds = [Math]::Round($sec, 1); ExitCode = [int]$r.Process.ExitCode; Note = ''; Ended = @(); Out = $r.Out; Err = $r.Err; Item = $r.Item })
                continue
            }
            # an item may carry its own limit (LimitSeconds): a suite measured over 10 minutes gets its measured time (owner 2026-10-13: "accepted, skip 10 min for now")
            $itemLimit = if ($r.Item.PSObject.Properties['LimitSeconds'] -and [double]$r.Item.LimitSeconds -gt 0) { [double]$r.Item.LimitSeconds } else { $SuiteLimitSeconds }
            $overSuite = $sec -ge $itemLimit
            if (-not $overSuite -and -not $gateOver) { continue }
            $note = if ($overSuite) { "TIMED OUT after $(& $min $itemLimit) min" } else { "TIMED OUT after $(& $min $sec) min (the whole gate's limit of $(& $min $GateLimitSeconds) min)" }
            $ended = @(Stop-SIGateProcessTree -Process $r.Process)
            [void]$running.Remove($r)
            & $finish ([pscustomobject]@{ Name = $r.Item.Name; Kind = $r.Item.Kind; State = 'TimedOut'; Seconds = [Math]::Round($sec, 1); ExitCode = 124; Note = "$note -- its process tree was ended ($($ended.Count) process(es))"; Ended = $ended; Out = $r.Out; Err = $r.Err; Item = $r.Item })
        }
        if ($gateOver) {
            while ($queue.Count) {
                $it = $queue.Dequeue()
                & $finish ([pscustomobject]@{ Name = $it.Name; Kind = $it.Kind; State = 'NotRun'; Seconds = 0.0; ExitCode = 125; Note = "NOT RUN -- the whole gate's limit of $(& $min $GateLimitSeconds) min passed before it could start"; Ended = @(); Out = ''; Err = ''; Item = $it })
            }
        }
        if ($running.Count -and $clock.Elapsed.TotalSeconds -ge $nextProgress) {
            $nextProgress = $clock.Elapsed.TotalSeconds + $ProgressSeconds
            $names = @($running | ForEach-Object { '{0} ({1}s)' -f $_.Item.Name, [int]$_.Watch.Elapsed.TotalSeconds })
            Write-Host ("  [{0}] still running ({1}): {2}{3}" -f (& $clockText), $running.Count, ($names -join ', '), $(if ($queue.Count) { "; waiting to start: $($queue.Count)" } else { '' })) -ForegroundColor DarkGray
        }
        if ($queue.Count -or $running.Count) { Start-Sleep -Milliseconds 200 }
    }
    $results.ToArray()
}

function Get-SIQuickGateSqlSuites {
    <#
        PURE. Which of the -Names suites run tests on a REAL local SQL Server (they read SI_TEST_LOCALSQL, probe the
        MSSQL$SQLEXPRESS service, or connect to .\SQLEXPRESS)? Their real-SQL tests SKIP without one -- and a skip is not a
        pass (owner 2026-10-25), so the gate waits for SQL before it starts them.
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Names, [Parameter(Mandatory)][hashtable]$SuiteText)
    @($Names | Where-Object { $SuiteText.ContainsKey($_) -and [regex]::IsMatch([string]$SuiteText[$_], 'SI_TEST_LOCALSQL|MSSQL\$SQLEXPRESS|\.\\SQLEXPRESS') })
}

function Wait-SIQuickGateSql {
    <#
        THE GATE WAITS FOR SQL (owner 2026-10-25: "the gate waits for SQL Express (start it, probe SELECT 1), sets
        SI_TEST_LOCALSQL for every suite"). The test VM carries SQL Server Express (.\SQLEXPRESS, Windows auth, the runner
        sysadmin -- Invardia's Initialize-InvardiaTestVm.ps1), but a suite that checks the service while Pester loads it
        skips its real-SQL tests when the service is not up yet. So: the service is started when it is stopped, and
        SELECT 1 is asked every -EverySeconds until it answers or -TimeoutSeconds pass. Never answered = Ready $false, and the
        gate is NOT TESTED at once (said plainly, nothing green). The service, start, probe and sleep are injectable
        (-GetStatus / -Start / -Probe / -Sleep) for the gate's own tests. Returns @{ Ready; Server; Tries; Started; Text }.
    #>
    param([string]$Server = '.\SQLEXPRESS', [string]$ServiceName = 'MSSQL$SQLEXPRESS', [int]$TimeoutSeconds = 180, [int]$EverySeconds = 5,
          [scriptblock]$GetStatus, [scriptblock]$Start, [scriptblock]$Probe, [scriptblock]$Sleep)
    if (-not $GetStatus) { $GetStatus = { $s = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue; if ($s) { [string]$s.Status } else { '' } } }
    if (-not $Start) { $Start = { Start-Service -Name $ServiceName -ErrorAction Stop } }
    if (-not $Probe) {
        $Probe = {
            $cn = New-Object System.Data.SqlClient.SqlConnection ("Server=$Server;Database=master;Integrated Security=SSPI;Connection Timeout=10;Pooling=false")
            try { $cn.Open(); $cmd = $cn.CreateCommand(); $cmd.CommandText = 'SELECT 1'; [int]$cmd.ExecuteScalar() -eq 1 } finally { $cn.Dispose() }
        }
    }
    if (-not $Sleep) { $Sleep = { Start-Sleep -Seconds $EverySeconds } }
    $local = $Server -match '^(\.|\(local\)|localhost|' + [regex]::Escape("$env:COMPUTERNAME") + ')\\SQLEXPRESS$'
    $started = $false; $startError = ''; $last = ''
    if ($local) {
        $st = "$(& $GetStatus)"
        if (-not $st) { return [pscustomobject]@{ Ready = $false; Server = $Server; Tries = 0; Started = $false; Text = ("SQL Server Express is not installed here (no service {0}) -- the real-SQL tests cannot run; the gate is NOT TESTED" -f $ServiceName) } }
        if ($st -ne 'Running') { try { & $Start; $started = $true } catch { $startError = $_.Exception.Message } }
    }
    $tries = [Math]::Max(1, [int][Math]::Ceiling($TimeoutSeconds / [double][Math]::Max(1, $EverySeconds)))
    for ($i = 1; $i -le $tries; $i++) {
        try { if (& $Probe) { return [pscustomobject]@{ Ready = $true; Server = $Server; Tries = $i; Started = $started; Text = ("SQL Server {0} answers SELECT 1 (try {1}{2})" -f $Server, $i, $(if ($started) { '; the service was started by the gate' } else { '' })) } } ; $last = 'SELECT 1 did not return 1' }
        catch { $last = (("$($_.Exception.Message)" -split "`r?`n")[0]).Trim() }
        if ($i -lt $tries) { & $Sleep }
    }
    [pscustomobject]@{ Ready = $false; Server = $Server; Tries = $tries; Started = $started
                       Text = ("SQL Server {0} did not answer SELECT 1 within {1} s ({2} tries; last: {3}{4}) -- the real-SQL tests cannot run; the gate is NOT TESTED" -f $Server, $TimeoutSeconds, $tries, $last, $(if ($startError) { "; starting $ServiceName failed: $startError" } else { '' })) }
}

function Get-SIQuickGateSlowLimit {
    <#
        PURE. A suite MEASURED over the 10-minute limit (-LimitSeconds, 600) is not stopped at 10 minutes in a release gate
        for now (owner 2026-10-13: "accepted, skip 10 min for now"): it gets its measured time x -Factor (1.5: a loaded VM;
        SIv3-CiBuildSql measured 1,800 s took 1,990 s on 2026-10-13). Returns that limit in seconds, or 0 = the normal
        10-minute limit. The gate says so in the log and its budget line reads "OVER THE 10-MINUTE LIMIT".
    #>
    param([double]$MeasuredSeconds = 0, [double]$LimitSeconds = 600, [double]$Factor = 1.5)
    if ($MeasuredSeconds -le $LimitSeconds) { return 0 }
    [int][Math]::Ceiling($MeasuredSeconds * $Factor)
}

function Get-SIQuickGateStatus {
    <#
        PURE. The quick gate's verdict from its items' outcomes (-Outcomes: @{ Name; State; Ok }): any item TIMED OUT or
        NOT RUN = 'NOT TESTED' (a stopped run is never green, whatever else passed) and Stopped names them; else any item
        not Ok = 'FAIL' -- a suite with a SKIPPED test included (Skipped names it: a skip is not a pass, owner 2026-10-25);
        else 'PASS'. The Scale tests left out are said (ScaleTests, ScaleOnly), never counted green. Text is the log line.
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Outcomes)
    $flag = { param($o, [string]$p) [bool]($o.PSObject.Properties[$p] -and $o.$p) }
    $timed = @($Outcomes | Where-Object { $_.State -eq 'TimedOut' } | ForEach-Object { $_.Name })
    $notRun = @($Outcomes | Where-Object { $_.State -eq 'NotRun' } | ForEach-Object { $_.Name })
    # a SKIPPED test is not a pass (owner 2026-10-25): a suite with skips is named apart from the failed ones, and is red
    $skipped = @($Outcomes | Where-Object { $_.State -notin 'TimedOut', 'NotRun' -and -not $_.Ok -and (& $flag $_ 'NotGreen') } | ForEach-Object { '{0} ({1} skipped)' -f $_.Name, $_.SkipCount })
    $red = @($Outcomes | Where-Object { $_.State -notin 'TimedOut', 'NotRun' -and -not $_.Ok -and -not (& $flag $_ 'NotGreen') } | ForEach-Object { $_.Name })
    # the Scale benchmarks run on demand only (owner rule): said, never counted as green
    $scale = @($Outcomes | Where-Object { & $flag $_ 'ScaleOnly' } | ForEach-Object { $_.Name })
    $scaleTests = 0; foreach ($o in $Outcomes) { if ($o.PSObject.Properties['ScaleNotRun']) { $scaleTests += [int]$o.ScaleNotRun } }
    $status = if ($timed.Count -or $notRun.Count) { 'NOT TESTED' } elseif ($red.Count -or $skipped.Count) { 'FAIL' } else { 'PASS' }
    $parts = @()
    if ($timed.Count) { $parts += ('TIMED OUT: ' + ($timed -join ', ')) }
    if ($notRun.Count) { $parts += ('NOT RUN: ' + ($notRun -join ', ')) }
    if ($red.Count) { $parts += ('RED: ' + ($red -join ', ')) }
    if ($skipped.Count) { $parts += ('SKIPPED (a skip is not a pass): ' + ($skipped -join ', ')) }
    $scaleText = if ($scaleTests) { '; {0} test(s) not run (Scale, on demand){1}' -f $scaleTests, $(if ($scale.Count) { ' -- ' + ($scale -join ', ') + ' not run at all' } else { '' }) } else { '' }
    $text = switch ($status) {
        'NOT TESTED' { 'NOT TESTED -- the gate was STOPPED at its 10-minute limit; a stopped run is never green (' + ($parts -join '; ') + ')' }
        'FAIL' { 'FAIL -- ' + ($parts -join '; ') + $scaleText }
        default { 'PASS -- {0} of {0} green{1}' -f (@($Outcomes).Count - $scale.Count), $scaleText }
    }
    [pscustomobject]@{ Status = $status; Stopped = @($timed + $notRun); TimedOut = $timed; NotRun = $notRun; Red = $red; Skipped = $skipped; ScaleOnly = $scale; ScaleTests = $scaleTests; Text = $text }
}

function Get-SIQuickGateItemOutcome {
    <#
        One finished item of Invoke-SIQuickGateRun, read from its result file: a Pester suite (tests\pester\_Invoke-GateShard.ps1
        JSON: Passed / Failed / LoadFailures / Error / Containers) or the web app's part (tests\pester\_Invoke-GateDotnet.ps1
        JSON: Build / Projects). Ok only when it ran to its end and every count is green: a suite that wrote no result, failed
        to LOAD (0 tests ran) or failed a test is red; a stopped item is red by its State. A suite with a SKIPPED test is
        NOT GREEN (NotGreen; owner 2026-10-25: a skip is not a pass); the tests an excluded tag left out are counted per tag
        (NotRunByTag, ScaleNotRun) and a suite of only Scale tests is ScaleOnly ("NOT RUN (Scale, on demand)"). Returns
        @{ Name; Kind; State; Ok; Seconds; Passed; Failed; Skipped; Total; Failures; LoadFailures; Broken; Containers; Dotnet;
        Skips; NotRunUnexplained; NotRunByTag; ScaleNotRun; SkipCount; NotGreen; ScaleOnly; Text; Color }.
    #>
    param([Parameter(Mandatory)]$Result)
    $o = [ordered]@{ Name = $Result.Name; Kind = $Result.Kind; State = $Result.State; Ok = $false; Seconds = [double]$Result.Seconds
                     Passed = 0; Failed = 0; Skipped = 0; Total = 0; Failures = @(); LoadFailures = @(); Broken = @(); Containers = @(); Dotnet = @(); Text = ''; Color = 'Red'
                     Skips = @(); NotRunUnexplained = @(); NotRunByTag = [ordered]@{}; ScaleNotRun = 0; SkipCount = 0; NotGreen = $false; ScaleOnly = $false }
    $rf = if ($Result.Item -and $Result.Item.PSObject.Properties['ResultFile']) { [string]$Result.Item.ResultFile } else { '' }
    $j = $null
    if ($rf -and (Test-Path -LiteralPath $rf)) { try { $j = [IO.File]::ReadAllText($rf) | ConvertFrom-Json } catch { $j = $null } }
    if ($Result.Kind -eq 'dotnet') {
        if ($j) {
            foreach ($b in @($j.Build)) { if ($b) { $o.Dotnet += [pscustomobject]@{ Project = 'build ' + $b.Project; Ok = [bool]$b.Ok; Summary = [string]$b.Summary; Seconds = [int]$b.Seconds } } }
            foreach ($p in @($j.Projects)) { if ($p) { $o.Dotnet += [pscustomobject]@{ Project = [string]$p.Project; Ok = [bool]$p.Ok; Summary = [string]$p.Summary; Seconds = [int]$p.Seconds } } }
            if ("$($j.Error)") { $o.Broken += ('dotnet: ' + $j.Error) }
        }
        $planned = @($Result.Item.Projects).Count
        $tested = @($o.Dotnet | Where-Object { $_.Project -notlike 'build *' }).Count
        $o.Ok = ($Result.State -eq 'Done') -and $j -and -not @($o.Dotnet | Where-Object { -not $_.Ok }).Count -and -not "$($j.Error)" -and $tested -ge $planned
        if ($Result.State -eq 'Done' -and -not $o.Ok -and -not @($o.Dotnet | Where-Object { -not $_.Ok }).Count) { $o.Broken += ('dotnet ended without every result ({0} of {1} project(s) tested)' -f $tested, $planned) }
        $o.Text = (@($o.Dotnet | ForEach-Object { '{0}: {1}' -f $_.Project, $(if ($_.Ok) { 'ok' } else { 'FAIL' }) }) -join '; ')
    } else {
        if ($j) {
            $o.Passed = [int]$j.Passed; $o.Failed = [int]$j.Failed; $o.Skipped = [int]$j.Skipped; $o.Total = [int]$j.Total
            $o.Failures = @($j.Failures | Where-Object { $_ }); $o.LoadFailures = @($j.LoadFailures | Where-Object { $_ }); $o.Containers = @($j.Containers | Where-Object { $_ })
            if ($j.PSObject.Properties['Skips']) { $o.Skips = @($j.Skips | Where-Object { $_ }) }
            if ($j.PSObject.Properties['NotRunUnexplained']) { $o.NotRunUnexplained = @($j.NotRunUnexplained | Where-Object { $_ }) }
            if ($j.PSObject.Properties['NotRunByTag'] -and $j.NotRunByTag) { foreach ($p in $j.NotRunByTag.PSObject.Properties) { $o.NotRunByTag[$p.Name] = [int]$p.Value } }
            if ($o.NotRunByTag.Contains('Scale')) { $o.ScaleNotRun = [int]$o.NotRunByTag['Scale'] }
            if ("$($j.Error)") { $o.Broken += ('{0}: {1}' -f $Result.Name, $j.Error) }
        } elseif ($Result.State -eq 'Done') {
            $e = if ($Result.Err -and (Test-Path -LiteralPath $Result.Err)) { ((Get-Content -Raw -LiteralPath $Result.Err -ErrorAction SilentlyContinue) -replace '\s+', ' ').Trim() } else { '' }
            $o.Broken += ('{0} wrote no result{1}' -f $Result.Name, $(if ($e) { ": $e" } else { '' }))
        }
        # A SKIPPED test is NOT a pass (owner 2026-10-25): a suite with a skipped / inconclusive test, or a test that did not
        # run for no excluded tag, is NOT GREEN. The tests an excluded tag left out (Scale: on demand only) are said, never
        # counted as passed; a suite whose every test is Scale is 'NOT RUN (Scale, on demand)', not a pass.
        $byTag = 0; foreach ($k in @($o.NotRunByTag.Keys)) { $byTag += [int]$o.NotRunByTag[$k] }
        $ran = [Math]::Max(0, $o.Total - $byTag)
        $o.SkipCount = @($o.Skips).Count + @($o.NotRunUnexplained).Count
        $clean = ($Result.State -eq 'Done') -and $j -and -not $o.Failed -and -not @($o.LoadFailures).Count -and -not "$($j.Error)"
        $o.Ok = $clean -and -not $o.SkipCount
        $o.NotGreen = $clean -and [bool]$o.SkipCount
        $o.ScaleOnly = $o.Ok -and $o.ScaleNotRun -gt 0 -and $ran -eq 0
        $tagText = (@($o.NotRunByTag.Keys | ForEach-Object { '{0} not run ({1}{2})' -f $o.NotRunByTag[$_], $_, $(if ($_ -eq 'Scale') { ', on demand' } elseif ($_ -eq 'Ps51') { ', the 5.1 opt-in' } else { '' }) })) -join '; '
        $skipText = if ($o.SkipCount) {
            $why = @(@($o.Skips | ForEach-Object { [string]$_.Because }) + @($o.NotRunUnexplained | ForEach-Object { 'did not run (no excluded tag)' }) | Group-Object | Sort-Object Count -Descending | ForEach-Object { if ($_.Count -gt 1) { '{0} x {1}' -f $_.Count, $_.Name } else { $_.Name } })
            ' ({0} skipped -- a skip is not a pass: {1})' -f $o.SkipCount, (($why | Select-Object -First 3) -join '; ')
        } else { '' }
        $o.Text = if (-not $j) { 'FAIL  no result' }
                  elseif ($o.ScaleOnly) { 'NOT RUN (Scale, on demand)  {0} test(s) left out' -f $o.ScaleNotRun }
                  else { '{0}  {1}/{2}{3}{4}' -f $(if ($o.Ok) { 'PASS' } elseif ($o.NotGreen) { 'NOT GREEN' } else { 'FAIL' }), $o.Passed, $ran, $(if (@($o.LoadFailures).Count) { ' (FAILED TO LOAD: 0 tests ran)' } elseif ($o.Failed) { " ($($o.Failed) failed)" } else { '' }), $skipText + $(if ($tagText) { " ($tagText)" } else { '' }) }
    }
    if ($Result.State -eq 'TimedOut') { $o.Broken += ('{0} {1}' -f $Result.Name, $Result.Note) }
    elseif ($Result.State -eq 'NotRun') { $o.Broken += ('{0} {1}' -f $Result.Name, $Result.Note) }
    elseif ($Result.State -eq 'StartFailed') { $o.Broken += ('{0} {1}' -f $Result.Name, $Result.Note) }
    if ($o.Ok) { $o.Color = $(if ($o.ScaleOnly) { 'DarkYellow' } else { 'Green' }) }
    [pscustomobject]$o
}

function Get-SIQuickGateItemLabel {
    <# PURE. One item's word in the gate's lists: PASS | FAIL | NOT GREEN (skipped) | NOT RUN (Scale, on demand) | TIMED OUT | NOT RUN. #>
    param([Parameter(Mandatory)]$Outcome)
    switch ($Outcome.State) {
        'TimedOut' { return 'TIMED OUT' }
        'NotRun' { return 'NOT RUN' }
    }
    if ($Outcome.PSObject.Properties['ScaleOnly'] -and $Outcome.ScaleOnly) { return 'NOT RUN (Scale, on demand)' }
    if ($Outcome.Ok) { return 'PASS' }
    if ($Outcome.PSObject.Properties['NotGreen'] -and $Outcome.NotGreen) { return 'NOT GREEN (skipped)' }
    'FAIL'
}
function Test-SIFastGateFullRun {
    <#
        PURE. ONLY THE OWNER STARTS A FULL RUN (owner 2026-10-13: "no boddy can trigger full test, newer ! only me can start
        that"). Is this run a FULL run, and may it start? A full run = -Full, or a selection that comes to every suite by
        another road (-Selected >= -Total, -Total > 0: -Suites / -Paths naming them all). It may start ONLY with the
        owner's own sentence for this run in -OwnerWords (not empty, not only white space). This function reads nothing:
        no file, no environment variable, no configuration -- the words come from the caller's command line or not at all.
        Returns @{ FullRun; Allowed; Words; Text }: Text is the line for the log -- the words when it may start, the plain
        refusal when it may not. A run that is not full is always allowed and carries no words.
    #>
    param([switch]$Full, [AllowNull()][AllowEmptyString()][string]$OwnerWords, [int]$Selected = 0, [int]$Total = 0)
    $everything = [bool]$Full -or ($Total -gt 0 -and $Selected -ge $Total)
    if (-not $everything) { return [pscustomobject]@{ FullRun = $false; Allowed = $true; Words = ''; Text = '' } }
    $words = "$OwnerWords".Trim()
    $what = if ($Full) { '-Full' } else { "a selection of every suite ($Selected of $Total)" }
    if ($words) { return [pscustomobject]@{ FullRun = $true; Allowed = $true; Words = $words; Text = ('a FULL run ({0}), started on the owner''s own words for this run: "{1}"' -f $what, $words) } }
    [pscustomobject]@{ FullRun = $true; Allowed = $false; Words = ''
                       Text = ('REFUSED: only the owner starts a full run ({0}). Nothing was run. Run the affected suites instead: -Base <the commit released last> -Hotfix (the suites that cover the change + the core set), or -Suites ''<name>;<name>''. A full run needs -OwnerWords with the owner''s own sentence for THIS run -- never a default, never from a file, an environment variable or a configuration, and never passed by a session, a release command or a schedule on its own.' -f $what) }
}
function Write-SIFastGateDurations {
    <# -UpdateDurations: the measured seconds per suite (this run's, else the ones kept) into suite-durations.json. #>
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][hashtable]$New, [Parameter(Mandatory)][hashtable]$Old)
    $doc = [ordered]@{ _comment = 'Measured seconds per Pester suite and runtime (tests\Invoke-FastGate.ps1 -UpdateDurations). The gate orders and balances its suites by these; an unknown suite counts 20 s. v3 gates PowerShell 7 only (2026-10-09): pwsh is the timing in use.'
                       measured = (Get-Date).ToString('yyyy-MM-dd'); pwsh = [ordered]@{} }
    # v3 keeps only the PowerShell 7 timings in use; a 5.1 section is written only when THIS run measured 5.1 (the opt-in)
    if ($New['ps51'].Count) { $doc['ps51'] = [ordered]@{} }
    foreach ($rt in @($doc.Keys | Where-Object { $_ -in 'pwsh', 'ps51' })) {
        # a quick gate measures only some suites: the rest keep their earlier seconds
        $src = @{}; foreach ($k in @($Old[$rt].Keys)) { $src[$k] = $Old[$rt][$k] }; foreach ($k in @($New[$rt].Keys)) { $src[$k] = $New[$rt][$k] }
        foreach ($k in @($src.Keys | Sort-Object)) { $doc[$rt][$k] = [Math]::Round([double]$src[$k], 1) }
    }
    [IO.File]::WriteAllText($Path, (ConvertTo-Json -InputObject $doc -Depth 4), (New-Object System.Text.UTF8Encoding($false)))
    Write-Host "  suite durations written: $Path"
}

function Get-SIFastGateChangedPaths {
    <# The SecurityInsight paths (relative, '/') changed between -Base and HEAD, plus the working tree's own changes. #>
    param([Parameter(Mandatory)][string]$RepoRoot, [Parameter(Mandatory)][string]$Base)
    $prefix = 'SOLUTIONS/SecurityInsight/'
    $all = @()
    $all += @(& git -C $RepoRoot diff --name-only ("{0}..HEAD" -f $Base) -- 'SOLUTIONS/SecurityInsight' 2>$null)
    if ($LASTEXITCODE) { throw "git diff $Base..HEAD failed -- is '$Base' a commit in this clone?" }
    $all += @(& git -C $RepoRoot diff --name-only HEAD -- 'SOLUTIONS/SecurityInsight' 2>$null)
    $all += @(& git -C $RepoRoot ls-files --others --exclude-standard -- 'SOLUTIONS/SecurityInsight' 2>$null)
    $global:LASTEXITCODE = 0
    @($all | Where-Object { $_ -and $_.StartsWith($prefix) } | ForEach-Object { $_.Substring($prefix.Length) } | Sort-Object -Unique)
}

if ($DefineOnly) { return }   # tests: the functions only

# ---- ONLY THE OWNER STARTS A FULL RUN (owner 2026-10-13) -- before anything else; -ListOnly runs nothing and may list ----
function Stop-SIFastGateRefused {
    # the refusal: said in the log, written to -ResultFile (Status REFUSED), exit 6 -- nothing ran
    param([Parameter(Mandatory)]$Decision)
    Write-Host ('  ' + $Decision.Text) -ForegroundColor Red
    if ($ResultFile) {
        $rd = Split-Path -Parent $ResultFile; if ($rd -and -not (Test-Path -LiteralPath $rd)) { New-Item -ItemType Directory -Force -Path $rd | Out-Null }
        $doc = [ordered]@{ Mode = 'full'; Status = 'REFUSED'; Refused = $Decision.Text; OwnerWords = ''; Started = $started.ToString('o'); Seconds = 0; Suites = 0 }
        [IO.File]::WriteAllText($ResultFile, (ConvertTo-Json -InputObject $doc -Depth 4), (New-Object System.Text.UTF8Encoding($false)))
    }
    exit 6
}
$fullRun = Test-SIFastGateFullRun -Full:$Full -OwnerWords $OwnerWords
if (-not $ListOnly -and -not $fullRun.Allowed) { Stop-SIFastGateRefused -Decision $fullRun }

# ---- 0. where we are --------------------------------------------------------------------------------------------------
. (Join-Path $pesterDir '_SITestScope.ps1')
$scope = Get-SITestScope -SIRoot $siRoot
if ($scope -eq 'Ambiguous') { Write-Host 'FATAL: cannot tell the private repository from a public copy (see tests\pester\_SITestScope.ps1)' -ForegroundColor Red; exit 2 }
$repoRoot = Split-Path -Parent (Split-Path -Parent $siRoot)
$allSuites = @(Get-ChildItem -LiteralPath $pesterDir -Filter '*.Tests.ps1' -File | Sort-Object Name)
if ($scope -eq 'PublicCopy') { $allSuites = @($allSuites | Where-Object { -not (Test-SITestFilePrivateRepoOnly -Path $_.FullName) }) }
$map = Get-SIFastGateMap -Path $mapFile
$dotnetAll = @()
$sln = Join-Path $siRoot $map.Solution
$dotnetTests = Join-Path $siRoot $map.Tests
if ($map.Solution -and (Test-Path -LiteralPath $sln) -and (Test-Path -LiteralPath $dotnetTests)) { $dotnetAll = @(Get-ChildItem -LiteralPath $dotnetTests -Filter '*.csproj' -Recurse -File | ForEach-Object { $_.BaseName }) }

# the measured seconds per suite: the shards are balanced by them, and the hotfix budget counts them
$durations = @{ pwsh = @{}; ps51 = @{} }
if (Test-Path -LiteralPath $durationsFile) {
    try {
        $dj = [IO.File]::ReadAllText($durationsFile) | ConvertFrom-Json
        foreach ($rt in 'pwsh', 'ps51') { if ($dj.$rt) { foreach ($p in $dj.$rt.PSObject.Properties) { $durations[$rt][$p.Name] = [double]$p.Value } } }
    } catch { Write-Host "  NOTE suite-durations.json is unreadable -- shards balanced by count" -ForegroundColor Yellow }
}# ---- 1-3. what to run -------------------------------------------------------------------------------------------------
$reasons = [ordered]@{}; $dotnetPick = [ordered]@{}; $unmapped = @(); $changed = @(); $overBudget = [ordered]@{}; $quickSel = $null
$phase = [ordered]@{}; $selectSw = [Diagnostics.Stopwatch]::StartNew()
if ($Precise -and -not $ListOnly) { Write-Host '  -Precise (the older covering selection) is a diagnostic: -ListOnly only -- the gate is the quick gate' -ForegroundColor Red; exit 2 }
if ($Full) {
    foreach ($s in $allSuites) { $reasons[$s.Name] = 'full' }
    foreach ($d in $dotnetAll) { $dotnetPick[$d] = 'full' }
} else {
    if (-not $Base) {
        $Base = "$(& git -C $repoRoot merge-base HEAD origin/si-v3 2>$null)".Trim()
        $head = "$(& git -C $repoRoot rev-parse HEAD 2>$null)".Trim()
        if (-not $Base -or $Base -eq $head) { $Base = "$(& git -C $repoRoot rev-parse HEAD~1 2>$null)".Trim() }
        $global:LASTEXITCODE = 0
    }
    # @( ) around the whole if: NO change must be an empty list, not $null (a gate at its own base failed to bind -Changed)
    # -Suites alone (the quick gate): exactly those + the core set -- what changed is not read at all
    $changed = @(if ($Paths) { @($Paths -split ';' | ForEach-Object { ($_.Trim() -replace '\\', '/').TrimStart('/') } | Where-Object { $_ }) } elseif ("$Suites".Trim() -and -not $Precise) { @() } else { @(Get-SIFastGateChangedPaths -RepoRoot $repoRoot -Base $Base) })
    $suiteText = @{}; foreach ($s in $allSuites) { $suiteText[$s.Name] = [IO.File]::ReadAllText($s.FullName) }
    $codeText = @{}
    foreach ($f in @(Get-ChildItem -LiteralPath $siRoot -Recurse -File -Include '*.ps1', '*.psm1', '*.psd1' -ErrorAction SilentlyContinue)) {
        $rel = $f.FullName.Substring($siRoot.Length).TrimStart('\', '/') -replace '\\', '/'
        if ($rel -match '^(tests/pester/[^/]+\.Tests\.ps1|logs/|output/|staging/)' -or $rel -match '/(bin|obj)/') { continue }
        # code only: a file that merely MENTIONS another in a comment does not load it (the one-hop index)
        $codeText[$rel] = Remove-SIFastGateComments -Text ([IO.File]::ReadAllText($f.FullName))
    }
    $namedList = @($Suites -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($Precise) {
        # the older COVERING selection (every suite that covers the path) -- a diagnostic, -ListOnly only
        $sel = Get-SIFastGateSelection -Changed $changed -SuiteText $suiteText -Map $map -CodeText $codeText -NoSafety:$NoSafety -Hotfix -Seconds $durations[$(if ($Runtime -eq 'ps51') { 'ps51' } else { 'pwsh' })] -BudgetSeconds $HotfixBudgetSeconds -SuiteMaxSeconds $HotfixSuiteMaxSeconds
        if ($sel.PSObject.Properties['OverBudget'] -and $sel.OverBudget) { $overBudget = $sel.OverBudget }
    } else {
        # THE QUICK GATE (owner 2026-10-13: "yes, build it the pim way"): -Suites alone = exactly those + the core set
        # the text-reader rule (owner 2026-10-25) needs WHAT changed inside each file: from git, since -Base (the working tree
        # included); -Paths names files without a diff -> $null = every suite that reads a changed file's text
        $changedLines = $null
        if (-not "$Paths".Trim() -and $changed.Count) {
            $changedLines = @{}
            foreach ($cp in $changed) { if ($cp -notmatch '^tests/pester/[^/]+\.Tests\.ps1$') { $changedLines[$cp] = Get-SIFastGateChangedLines -RepoRoot $repoRoot -Base $Base -RelativePath $cp -SIRoot $siRoot } }
        }
        $sel = if ($namedList.Count -and -not "$Paths".Trim()) { Get-SIQuickGateSelection -Changed @() -Named $namedList -SuiteText $suiteText -Map $map -CodeText $codeText }
               else { Get-SIQuickGateSelection -Changed $changed -SuiteText $suiteText -Map $map -CodeText $codeText -ChangedLines $changedLines }
        $quickSel = $sel
        if ($NoSafety) { foreach ($k in @($sel.Suites.Keys)) { if ("$($sel.Suites[$k])" -like 'core set*') { $sel.Suites.Remove($k) } } }
    }
    foreach ($k in $sel.Suites.Keys) { $reasons[$k] = $sel.Suites[$k] }
    foreach ($k in $sel.Dotnet.Keys) { if ($dotnetAll -contains $k) { $dotnetPick[$k] = $sel.Dotnet[$k] } }
    $unmapped = @($sel.Unmapped)
}
foreach ($s in @($Suites -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
    $n = if ($s -like '*.Tests.ps1') { $s } else { "$s.Tests.ps1" }
    if (@($allSuites | Where-Object Name -eq $n).Count -and -not $reasons.Contains($n)) { $reasons[$n] = '-Suites (named)' }
}
if ($NoDotnet) { $dotnetPick = [ordered]@{} }
# every suite by another road (-Suites / -Paths naming them all) is the same full run: refused without the owner's words
if (-not $Full) {
    $fullRun = Test-SIFastGateFullRun -OwnerWords $OwnerWords -Selected $reasons.Count -Total $allSuites.Count
    if (-not $ListOnly -and -not $fullRun.Allowed) { Stop-SIFastGateRefused -Decision $fullRun }
}
# the web app's test classes that cover the change (fast-gate.map.json dotnetFilter) -- decided here, so -ListOnly shows it
$dotnetPlan = @()
if ($dotnetPick.Count) {
    $dotnetPlan = @(foreach ($d in $dotnetPick.Keys) {
        $proj = Get-ChildItem -LiteralPath $dotnetTests -Filter "$d.csproj" -Recurse -File | Select-Object -First 1
        $df = [pscustomobject]@{ Whole = $true; Filter = ''; Classes = @(); Notes = @() }
        $nf = @($map.DotnetFilter | Where-Object { $_.Project -eq $d }) | Select-Object -First 1
        if (-not $Full -and $nf -and $changed.Count) {
            $tf = @(Get-ChildItem -LiteralPath $proj.DirectoryName -Filter '*.cs' -File)
            # every test CLASS, by its file name and by what the file declares (a file often holds several classes)
            $tt = @{}; $fc = @{}; $cls = New-Object System.Collections.Generic.List[string]
            foreach ($x in $tf) {
                $tx = [IO.File]::ReadAllText($x.FullName); $tt[$x.BaseName] = $tx; if (-not $cls.Contains($x.BaseName)) { $cls.Add($x.BaseName) }
                $decl = @([regex]::Matches($tx, '\bclass\s+([A-Za-z0-9_]+Tests)\b') | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique)
                $fc[$x.BaseName] = $decl
                foreach ($k in $decl) { if (-not $tt.ContainsKey($k)) { $tt[$k] = $tx }; if (-not $cls.Contains($k)) { $cls.Add($k) } }
            }
            # the quick gate: never the whole project, at most dotnetMaxClasses classes (+ the always-on ones)
            $df = Get-SIFastGateDotnetFilter -Changed $changed -SourcePrefix $nf.Source -TestPrefix $nf.Tests -TestClasses $cls.ToArray() -Always $nf.Always -TestText $tt -Related $nf.Related -Shared $nf.Shared -FileClasses $fc -NoWhole:(-not $Precise) -MaxClasses $(if ($Precise) { 0 } else { $map.Quick.DotnetMaxClasses })
        }
        [pscustomobject]@{ Name = $d; Path = $proj.FullName; Filter = $df.Filter; Whole = [bool]$df.Whole; Classes = @($df.Classes); Notes = @($df.Notes) }
    })
}
$selectSw.Stop(); $phase['select'] = [Math]::Round($selectSw.Elapsed.TotalSeconds, 1)

$line = '-' * 78
$modeName = if ($Full) { 'FULL (sharded)' } elseif ($Precise) { 'PRECISE (covering) selection' } else { 'QUICK' }
Write-Host $line -ForegroundColor Cyan
Write-Host ('  SecurityInsight -- {0} gate   ({1})' -f $modeName, $(if ($Full) { 'every suite' } else { "changes since $($Base.Substring(0, [Math]::Min(12, $Base.Length)))" })) -ForegroundColor Cyan
Write-Host $line -ForegroundColor Cyan
if ($fullRun.FullRun -and $fullRun.Allowed) { Write-Host ('  ' + $fullRun.Text) -ForegroundColor Yellow }
if (-not $Full) {
    Write-Host ('  {0} changed path(s); {1} of {2} suites; dotnet: {3}' -f $changed.Count, $reasons.Count, $allSuites.Count, $(if ($dotnetPlan.Count) { 'build + ' + (@($dotnetPlan | ForEach-Object { if ($_.Whole) { "$($_.Name) (whole)" } else { "$($_.Name) ($(@($_.Classes).Count) classes)" } }) -join ', ') } else { 'none (no web app file changed)' }))
    if ($quickSel) { foreach ($nq in @($quickSel.Notes)) { Write-Host ('  ' + $nq) -ForegroundColor DarkYellow } }
    elseif ($Precise) { foreach ($u in $unmapped) { Write-Host ("  NOTE no suite covers {0}" -f $u) -ForegroundColor Yellow } }
    # a covering suite over the hotfix budget RUNS (no nightly run any more); said plainly, one line each
    foreach ($k in $overBudget.Keys) { Write-Host ("  NOTE the hotfix gate takes longer: {0} covers the change ({1}) and runs although it is over the hotfix budget ({2:N0} s)" -f $k, $overBudget[$k], $HotfixBudgetSeconds) -ForegroundColor Yellow }
    foreach ($pj in $dotnetPlan) { foreach ($n in @($pj.Notes)) { Write-Host ("  dotnet {0}: {1}" -f $pj.Name, $n) -ForegroundColor DarkGray } }
    if ($ListOnly -or $VerbosePreference -ne 'SilentlyContinue') {
        foreach ($k in $reasons.Keys) { Write-Host ('    {0,-52} {1}' -f $k, $reasons[$k]) -ForegroundColor DarkGray }
    }
}
if ($SelectionFile) {
    $sd = Split-Path -Parent $SelectionFile; if ($sd -and -not (Test-Path -LiteralPath $sd)) { New-Item -ItemType Directory -Force -Path $sd | Out-Null }
    $selDoc = [ordered]@{ Full = [bool]$Full; Hotfix = [bool]$Hotfix; Base = "$Base"; Changed = @($changed); Suites = @($reasons.Keys); Dotnet = @($dotnetPick.Keys); Unmapped = @($unmapped)
                          OverBudget = @($overBudget.Keys); Dropped = @(); DotnetClasses = [ordered]@{} }
    foreach ($pj in $dotnetPlan) { $selDoc.DotnetClasses[$pj.Name] = $(if ($pj.Whole) { @('*') } else { @($pj.Classes) }) }
    # for the release command's STOP (setup\Release-SI.ps1: a selection of every suite, or one that cannot fit the
    # 10-minute limit, is a question to the owner): how many suites there are, and the selection's measured seconds
    $selSec = $durations[$(if ($Runtime -eq 'ps51') { 'ps51' } else { 'pwsh' })]; $selTotal = 0.0; $selLongest = 0.0; $selLongestName = ''
    foreach ($k in $reasons.Keys) { $x = if ($selSec.ContainsKey($k) -and $selSec[$k] -gt 0) { [double]$selSec[$k] } else { 20.0 }; $selTotal += $x; if ($x -gt $selLongest) { $selLongest = $x; $selLongestName = $k } }
    $selDoc.AllSuites = $allSuites.Count; $selDoc.MeasuredSeconds = [Math]::Round($selTotal, 1); $selDoc.LongestSeconds = [Math]::Round($selLongest, 1); $selDoc.LongestSuite = $selLongestName
    # the quick gate's own account: the core set, the broad files and hubs it met, its notes
    $selDoc.Mode = $(if ($Full) { 'full' } elseif ($Precise) { 'precise' } else { 'quick' })
    if ($quickSel) { $selDoc.CoreSet = [bool]$quickSel.Core; $selDoc.Broad = $quickSel.Broad; $selDoc.Hubs = @($quickSel.Hubs); $selDoc.Narrow = @($quickSel.Narrow); $selDoc.Notes = @($quickSel.Notes); $selDoc.TextReaders = $quickSel.TextReaders }
    [IO.File]::WriteAllText($SelectionFile, (ConvertTo-Json -InputObject $selDoc -Depth 4), (New-Object System.Text.UTF8Encoding($false)))
}
if ($ListOnly) { exit 0 }

# ---- 4q. THE QUICK GATE: every selected suite in its own process, in parallel; at 10 minutes STOP AND REPORT ------------
if (-not $Full) {
    $qRuntimes = @(switch ($Runtime) { 'both' { 'pwsh', 'ps51' } 'pwsh' { 'pwsh' } 'ps51' { 'ps51' } })
    $qExe = @{ pwsh = 'pwsh.exe'; ps51 = 'powershell.exe' }
    foreach ($rt in $qRuntimes) { if (-not (Get-Command $qExe[$rt] -ErrorAction SilentlyContinue)) { Write-Host "  FATAL: $($qExe[$rt]) not found" -ForegroundColor Red; exit 2 } }
    $qSuiteLimit = if ($SuiteLimitSeconds -gt 0) { $SuiteLimitSeconds } else { $map.Quick.SuiteLimitSeconds }
    $qGateLimit = if ($GateLimitSeconds -gt 0) { $GateLimitSeconds } else { $map.Quick.GateLimitSeconds }
    $qThrottle = if ($Workers -gt 0) { $Workers } else { [Math]::Max(1, [Math]::Min($map.Quick.Throttle, [Environment]::ProcessorCount)) }
    $work = Join-Path ([IO.Path]::GetTempPath()) ('si-gate-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    New-Item -ItemType Directory -Force -Path $work | Out-Null
    $shardScript = Join-Path $pesterDir '_Invoke-GateShard.ps1'
    # a public copy leaves the private-repository checks out; EVERY gate leaves out the scale benchmarks (tag Scale); a
    # suite the quick gate selects runs whole otherwise (its Nightly-tagged tests too: there is no nightly run)
    $exclude = Get-SIFastGateExcludeTags -Scope $scope -Hotfix
    $exclude = Add-SIFastGatePs51Tag -Exclude $exclude -Runtime $Runtime
    # THE GATE WAITS FOR SQL (owner 2026-10-25): a selected suite with real-SQL tests skips them without a local SQL
    # Server, and a skip is not a pass -- so SQL Express is started and probed first, and SI_TEST_LOCALSQL is set for
    # every suite. SQL that never answers = NOT TESTED, at once.
    $sqlEnv = $null
    $sqlSuites = @(Get-SIQuickGateSqlSuites -Names @($reasons.Keys) -SuiteText $suiteText)
    if ($sqlSuites.Count) {
        $sqlSw = [Diagnostics.Stopwatch]::StartNew()
        $sqlServer = if ("$env:SI_TEST_LOCALSQL".Trim()) { "$env:SI_TEST_LOCALSQL".Trim() } else { '.\SQLEXPRESS' }
        Write-Host ('  SQL: {0} selected suite(s) run tests on a real SQL Server -- waiting for {1} (SELECT 1, up to 180 s)' -f $sqlSuites.Count, $sqlServer) -ForegroundColor DarkGray
        $sqlWait = Wait-SIQuickGateSql -Server $sqlServer
        $phase['sql'] = [Math]::Round($sqlSw.Elapsed.TotalSeconds, 1)
        if (-not $sqlWait.Ready) {
            Write-Host ('  ' + $sqlWait.Text) -ForegroundColor Red
            Write-Host ('  GATE: NOT TESTED   (SQL)') -BackgroundColor DarkRed -ForegroundColor White
            if ($ResultFile) {
                $dir = Split-Path -Parent $ResultFile; if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
                $nt = [ordered]@{ Mode = 'quick'; Base = "$Base"; Commit = "$(& git -C $repoRoot rev-parse HEAD 2>$null)".Trim(); Started = $started.ToString('o'); Seconds = [int]((Get-Date) - $started).TotalSeconds
                                  Status = 'NOT TESTED'; StatusText = $sqlWait.Text; Sql = $sqlWait; SqlSuites = $sqlSuites; Suites = $reasons.Count; Changed = $changed.Count; Phases = $phase; SuiteResults = @(); OwnerWords = '' }
                [IO.File]::WriteAllText($ResultFile, (ConvertTo-Json -InputObject $nt -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
            }
            $global:LASTEXITCODE = 0
            exit 1
        }
        Write-Host ('  SQL: ' + $sqlWait.Text + ' -- SI_TEST_LOCALSQL=' + $sqlServer + ' for every suite') -ForegroundColor DarkGray
        if (-not (Get-Command sqlcmd -ErrorAction SilentlyContinue)) { Write-Host '  SQL NOTE: sqlcmd is not on this machine -- a suite that calls it skips, and a skip is not a pass' -ForegroundColor Yellow }
        $sqlEnv = @{ SI_TEST_LOCALSQL = $sqlServer }
    }
    $ps51Path = (@((Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'WindowsPowerShell\Modules'), (Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules'), (Join-Path $env:SystemRoot 'system32\WindowsPowerShell\v1.0\Modules')) -join ';')
    $items = New-Object System.Collections.Generic.List[object]
    # the web app first (its build is the longest item): only when a web app file changed (dotnetPlan), never the whole project
    if (-not $NoDotnet -and $dotnetPlan.Count -and (Get-Command dotnet -ErrorAction SilentlyContinue)) {
        $planFile = Join-Path $work 'dotnet-plan.json'
        [IO.File]::WriteAllText($planFile, (ConvertTo-Json -InputObject @($dotnetPlan | ForEach-Object { [ordered]@{ Name = $_.Name; Path = $_.Path; Filter = $_.Filter } }) -Depth 4), (New-Object System.Text.UTF8Encoding($false)))
        foreach ($pj in $dotnetPlan) { Write-Host ("  dotnet {0}: {1}" -f $pj.Name, $(if ($pj.Whole) { 'the whole project' } else { 'only ' + (@($pj.Classes) -join ', ') })) -ForegroundColor DarkGray }
        $dres = Join-Path $work 'dotnet.json'
        $items.Add([pscustomobject]@{ Name = 'dotnet (' + (@($dotnetPlan | ForEach-Object { $_.Name }) -join ', ') + ')'; Kind = 'dotnet'; Exe = $qExe['pwsh']; ResultFile = $dres; Projects = @($dotnetPlan | ForEach-Object { $_.Name })
                                      Args = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $pesterDir '_Invoke-GateDotnet.ps1'), '-PlanFile', $planFile, '-ResultFile', $dres, '-LogFile', (Join-Path $work 'dotnet.log')); Env = $null })
    }
    $slowSuites = [ordered]@{}
    foreach ($rt in $qRuntimes) {
        $sec = $durations[$rt]
        foreach ($s in @($reasons.Keys | Sort-Object -Property @{ Expression = { if ($sec.ContainsKey($_)) { [double]$sec[$_] } else { 20.0 } }; Descending = $true }, @{ Expression = { $_ } })) {
            $k = $items.Count + 1
            $list = Join-Path $work ('{0:D3}-{1}.txt' -f $k, $rt); $res = Join-Path $work ('{0:D3}-{1}.json' -f $k, $rt)
            [IO.File]::WriteAllLines($list, [string[]]@(Join-Path $pesterDir $s))
            $a = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $shardScript, '-ListFile', $list, '-ResultFile', $res)
            if ($exclude) { $a += @('-ExcludeTag', $exclude) }
            $envFor = if ($rt -eq 'ps51') { @{ PSModulePath = $ps51Path; SI_GATE_PS51 = '1' } } elseif ($qRuntimes -contains 'ps51') { @{ SI_GATE_PS51 = '1' } } else { $null }
            # SI_TEST_LOCALSQL for EVERY suite (owner 2026-10-25), in the item's own environment -- set and restored around its start
            if ($sqlEnv) { if (-not $envFor) { $envFor = @{} }; foreach ($ek in $sqlEnv.Keys) { $envFor[$ek] = $sqlEnv[$ek] } }
            # a suite MEASURED over 10 minutes is not stopped at 10 (owner 2026-10-13: "accepted, skip 10 min for now"): it gets
            # its measured time (x1.5 for a loaded VM) and the gate says plainly that it runs over the 10-minute limit
            $slow = Get-SIQuickGateSlowLimit -MeasuredSeconds $(if ($sec.ContainsKey($s)) { [double]$sec[$s] } else { 0 })
            if ($slow -gt 0) { $slowSuites[$s] = $slow; Write-Host ('  NOTE {0} is measured at {1:N0} s -- OVER THE 10-MINUTE LIMIT; it runs with its measured time (stopped only after {2:N0} s; owner 2026-10-13: "accepted, skip 10 min for now"), so this gate runs over 10 minutes' -f $s, [double]$sec[$s], $slow) -ForegroundColor Yellow }
            $items.Add([pscustomobject]@{ Name = $(if ($qRuntimes.Count -gt 1) { "$s [$rt]" } else { $s }); Suite = $s; Runtime = $rt; Kind = 'pester'; Exe = $qExe[$rt]; Args = $a; ResultFile = $res; Env = $envFor; LimitSeconds = $slow })
        }
    }
    # the whole gate never stops a named slow suite either: its limit grows to the longest slow suite's
    if ($slowSuites.Count) { $qGateLimit = [Math]::Max($qGateLimit, [int](@($slowSuites.Values) | Measure-Object -Maximum).Maximum) }
    Write-Host ('  QUICK GATE: {0} suite(s){1}, each in its own process, {2} at once; limit {3:N0} min per suite and {4:N0} min for the whole gate -- then STOP AND REPORT' -f @($items | Where-Object Kind -eq 'pester').Count, $(if (@($items | Where-Object Kind -eq 'dotnet').Count) { ' + the web app (build + its selected test classes)' } else { '' }), $qThrottle, ($qSuiteLimit / 60.0), ($qGateLimit / 60.0)) -ForegroundColor Cyan
    $describe = { param($r) $x = Get-SIQuickGateItemOutcome -Result $r; [pscustomobject]@{ Text = $x.Text; Color = $x.Color } }
    $runSw = [Diagnostics.Stopwatch]::StartNew()
    $runRes = @(Invoke-SIQuickGateRun -Items $items.ToArray() -Work $work -Throttle $qThrottle -SuiteLimitSeconds $qSuiteLimit -GateLimitSeconds $qGateLimit -ProgressSeconds $ProgressSeconds -OnFinish $describe)
    $runSw.Stop()
    $outs = @($runRes | ForEach-Object { Get-SIQuickGateItemOutcome -Result $_ })
    $verdict = Get-SIQuickGateStatus -Outcomes $outs
    $summary = [ordered]@{ Mode = 'quick'; Base = "$Base"; Commit = "$(& git -C $repoRoot rev-parse HEAD 2>$null)".Trim(); Started = $started.ToString('o'); Seconds = 0; Status = $verdict.Status
                           Changed = $changed.Count; Suites = $reasons.Count; Runtimes = [ordered]@{}; Dotnet = @(); Unmapped = $unmapped; OverBudget = @(); Phases = $phase; Budget = $null
                           Stopped = @($verdict.Stopped); TimedOut = @($verdict.TimedOut); NotRun = @($verdict.NotRun); StatusText = $verdict.Text
                           Limits = [ordered]@{ SuiteSeconds = $qSuiteLimit; GateSeconds = $qGateLimit; Throttle = $qThrottle; SlowSuites = $slowSuites }
                           CoreSet = $(if ($quickSel) { [bool]$quickSel.Core } else { $false }); Broad = $(if ($quickSel) { $quickSel.Broad } else { [ordered]@{} }); Hubs = $(if ($quickSel) { @($quickSel.Hubs) } else { @() })
                           SuiteResults = @(); OwnerWords = '' }
    $global:LASTEXITCODE = 0
    $newDurations = @{ pwsh = @{}; ps51 = @{} }
    foreach ($rt in $qRuntimes) {
        $agg = [ordered]@{ Passed = 0; Failed = 0; Skipped = 0; Total = 0; Shards = 0; Retried = 0; LongestShardSeconds = 0; WallSeconds = [int]$runSw.Elapsed.TotalSeconds; Failures = @(); LoadFailures = @(); Broken = @(); SlowTests = @() }
        foreach ($o in @($outs | Where-Object { $_.Kind -eq 'pester' })) {
            $it = @($runRes | Where-Object { $_.Name -eq $o.Name })[0].Item
            if ($it.Runtime -ne $rt) { continue }
            $agg.Shards++; $agg.Passed += $o.Passed; $agg.Failed += $o.Failed; $agg.Skipped += $o.Skipped; $agg.Total += $o.Total
            if ($o.Seconds -gt $agg.LongestShardSeconds) { $agg.LongestShardSeconds = $o.Seconds }
            foreach ($f in @($o.Failures)) { $agg.Failures += $f }
            foreach ($f in @($o.LoadFailures)) { $agg.LoadFailures += $f }
            foreach ($b in @($o.Broken)) { $agg.Broken += $b }
            foreach ($c in @($o.Containers)) { if ($c -and $c.File) { $newDurations[$rt][[string]$c.File] = [double]$c.Seconds } }
        }
        $summary.Runtimes[$rt] = $agg
    }
    foreach ($o in @($outs | Where-Object { $_.Kind -eq 'dotnet' })) {
        foreach ($d in @($o.Dotnet)) { $summary.Dotnet += $d }
        if ($o.State -ne 'Done' -or @($o.Broken).Count) { $summary.Dotnet += [pscustomobject]@{ Project = 'dotnet'; Ok = $false; Summary = (@($o.Broken) -join ' | '); Seconds = [int]$o.Seconds } }
    }
    # EVERY selected suite by name, with its seconds and its verdict -- the proof of what was counted
    $summary.SuiteResults = @(foreach ($o in $outs) {
        [ordered]@{ Suite = $o.Name; Kind = $o.Kind; Status = (Get-SIQuickGateItemLabel -Outcome $o)
                    Seconds = $o.Seconds; Passed = $o.Passed; Failed = $o.Failed; Skipped = $o.SkipCount; ScaleNotRun = $o.ScaleNotRun; Total = $o.Total
                    SkipReasons = @($o.Skips | ForEach-Object { '{0}: {1}' -f $_.Test, $_.Because } | Select-Object -First 20)
                    Reason = $(if ($reasons.Contains([string]$o.Name)) { [string]$reasons[[string]$o.Name] } else { '' }) }
    })
    $summary.Skipped = @($verdict.Skipped); $summary.ScaleNotRun = [ordered]@{ Tests = $verdict.ScaleTests; Suites = @($verdict.ScaleOnly); Text = 'not run (Scale, on demand)' }
    $summary.Seconds = [int]((Get-Date) - $started).TotalSeconds
    $phase['suites (wall)'] = [int]$runSw.Elapsed.TotalSeconds
    $dB = @($summary.Dotnet | Where-Object { "$($_.Project)" -like 'build *' }); $dT = @($summary.Dotnet | Where-Object { "$($_.Project)" -notlike 'build *' -and $_.Project -ne 'dotnet' })
    if ($dB.Count) { $phase['dotnet build'] = [int](($dB | Measure-Object -Property Seconds -Sum).Sum) }
    if ($dT.Count) { $phase['dotnet tests'] = [int](($dT | Measure-Object -Property Seconds -Sum).Sum) }
    $phase['total'] = $summary.Seconds
    $summary.Budget = Get-SIFastGateBudget -Mode 'quick' -Seconds $summary.Seconds -OverBudget @($slowSuites.Keys)
    $summary.OverBudget = @($slowSuites.Keys)

    Write-Host ''
    Write-Host ('  QUICK GATE TIMES (wall {0:N0} s; the slowest item sets it):' -f $runSw.Elapsed.TotalSeconds) -ForegroundColor Cyan
    foreach ($o in @($outs | Sort-Object -Property Seconds -Descending)) {
        Write-Host ('    {0,7:N1}s  {1,-10} {2}' -f $o.Seconds, (Get-SIQuickGateItemLabel -Outcome $o), $o.Name) -ForegroundColor $(if ($o.ScaleOnly) { 'DarkYellow' } elseif ($o.Ok) { 'Green' } else { 'Red' })
        foreach ($f in @($o.Failures | Select-Object -First 10)) { Write-Host ('        FAIL {0}' -f $f.Test) -ForegroundColor Red; if ($f.Message) { Write-Host ('             -> ' + $f.Message) -ForegroundColor DarkGray } }
        foreach ($f in @($o.Skips | Select-Object -First 10)) { Write-Host ('        SKIPPED (not a pass) {0} -- {1}' -f $f.Test, $f.Because) -ForegroundColor Red }
        foreach ($f in @($o.NotRunUnexplained | Select-Object -First 5)) { Write-Host ('        DID NOT RUN (no excluded tag) {0}' -f $f.Test) -ForegroundColor Red }
        if ($o.ScaleNotRun) { Write-Host ('        {0} test(s) not run (Scale, on demand)' -f $o.ScaleNotRun) -ForegroundColor DarkYellow }
        foreach ($f in @($o.LoadFailures)) { Write-Host ('        LOAD FAILED (0 tests ran): {0}' -f $f.Message) -ForegroundColor Red }
        foreach ($d in @($o.Dotnet)) { Write-Host ('        dotnet {0,-28} {1}  {2} ({3}s)' -f $d.Project, $(if ($d.Ok) { 'ok  ' } else { 'FAIL' }), $d.Summary, $d.Seconds) -ForegroundColor $(if ($d.Ok) { 'DarkGray' } else { 'Red' }) }
        foreach ($b in @($o.Broken)) { Write-Host ('        ' + $b) -ForegroundColor Red }
    }
    Write-Host ''
    Write-Host '  timing (seconds):' -ForegroundColor Cyan
    foreach ($k in $phase.Keys) { Write-Host ('    {0,-24} {1,6}' -f $k, $phase[$k]) }
    Write-Host ('    {0}' -f $summary.Budget.Text) -ForegroundColor $(if ($summary.Budget.Met) { 'Green' } else { 'Yellow' })
    foreach ($n in @($verdict.TimedOut)) { $tn = @($runRes | Where-Object { $_.Name -eq $n })[0]; Write-Host ('  QUICK GATE TIMED OUT: {0} after {1:N1} min' -f $n, ($tn.Seconds / 60.0)) -ForegroundColor Red }
    foreach ($n in @($verdict.NotRun)) { Write-Host ('  QUICK GATE NOT RUN: {0}' -f $n) -ForegroundColor Red }
    foreach ($n in @($verdict.Skipped)) { Write-Host ('  QUICK GATE NOT GREEN (skipped tests are not passes): {0}' -f $n) -ForegroundColor Red }
    Write-Host ('  QUICK GATE RESULT: {0} of {1} green -- {2}' -f @($outs | Where-Object { $_.Ok -and -not $_.ScaleOnly }).Count, ($outs.Count - @($verdict.ScaleOnly).Count), $verdict.Text)
    $bad = $verdict.Status -ne 'PASS'
    Write-Host ('  GATE: {0}   in {1} min' -f $summary.Status, [int][Math]::Ceiling(((Get-Date) - $started).TotalMinutes)) -BackgroundColor $(if ($bad) { 'DarkRed' } else { 'DarkGreen' }) -ForegroundColor White
    Write-Host ''
    if ($UpdateDurations) { Write-SIFastGateDurations -Path $durationsFile -New $newDurations -Old $durations }
    if ($ResultFile) {
        $dir = Split-Path -Parent $ResultFile; if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
        $summary.Durations = $newDurations
        [IO.File]::WriteAllText($ResultFile, (ConvertTo-Json -InputObject $summary -Depth 8), (New-Object System.Text.UTF8Encoding($false)))
    }
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
    if ($bad) { exit 1 }
    exit 0
}

# ---- 4. run: the runtime(s) asked for (default PowerShell 7 only), each sharded; dotnet alongside ----------------------

$runtimes = switch ($Runtime) { 'both' { @('ps51', 'pwsh') } 'pwsh' { @('pwsh') } 'ps51' { @('ps51') } }
$cores = [Environment]::ProcessorCount
$loadPct = 0.0
if ($Workers -le 0) {
    # bounded by the cores that are FREE now (other gates, upgrade tests and sessions share mgmt1)
    try { $loadPct = [double](@(1..3 | ForEach-Object { (Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop | Measure-Object -Property LoadPercentage -Average).Average; Start-Sleep -Milliseconds 300 }) | Measure-Object -Average).Average } catch { $loadPct = 0.0 }
    $Workers = Get-SIFastGateWorkers -Cores $cores -Runtimes $runtimes.Count -LoadPercent $loadPct
}
$work = Join-Path ([IO.Path]::GetTempPath()) ('si-gate-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Force -Path $work | Out-Null
$shardScript = Join-Path $pesterDir '_Invoke-GateShard.ps1'
# a public copy leaves the private-repository checks out; only the dev FAST gate leaves out the tests tagged Nightly (slow by
# nature, docs\TESTS.md 5b; the tag keeps its old name) -- a full run (only on the owner's words) runs them, and so does -Hotfix: a suite
# that covers the change runs WHOLE, there is no nightly run to catch what it would skip -- except the tests tagged Scale
# (the scale benchmarks, -Full only: a hotfix gate is fast, owner 2026-10-10)
$exclude = Get-SIFastGateExcludeTags -Scope $scope -Full:$Full -Hotfix:$Hotfix
$exclude = Add-SIFastGatePs51Tag -Exclude $exclude -Runtime $Runtime
$names = @($reasons.Keys)
$procs = New-Object System.Collections.Generic.List[object]
$ps51Path = (@((Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'WindowsPowerShell\Modules'), (Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules'), (Join-Path $env:SystemRoot 'system32\WindowsPowerShell\v1.0\Modules')) -join ';')
$keepPath = $env:PSModulePath
$queue = @{}; $exeOf = @{ pwsh = 'pwsh.exe'; ps51 = 'powershell.exe' }
foreach ($rt in $runtimes) {
    if (-not (Get-Command $exeOf[$rt] -ErrorAction SilentlyContinue)) { Write-Host "  FATAL: $($exeOf[$rt]) not found" -ForegroundColor Red; exit 2 }
    $queue[$rt] = New-Object System.Collections.Generic.Queue[object]
    foreach ($b in @(New-SIFastGateBatches -Names $names -Workers $Workers -Seconds $durations[$rt])) { if (@($b).Count) { $queue[$rt].Enqueue([pscustomobject]@{ Suites = @($b); Attempt = 1 }) } }
}
# the whole run's backstop, scaled to the work (a loaded machine makes the run slower, not red)
$rtSeconds = @(foreach ($rt in $runtimes) { $t = 0.0; foreach ($n in $names) { $t += $(if ($durations[$rt].ContainsKey($n) -and $durations[$rt][$n] -gt 0) { $durations[$rt][$n] } else { 20 }) }; $t })
$longestSuite = 0.0; foreach ($rt in $runtimes) { foreach ($n in $names) { if ($durations[$rt].ContainsKey($n) -and $durations[$rt][$n] -gt $longestSuite) { $longestSuite = [double]$durations[$rt][$n] } } }
$deadlineMinutes = Get-SIFastGateDeadlineMinutes -TimeoutMinutes $TimeoutMinutes -RuntimeSeconds $rtSeconds -Workers $Workers -LongestSeconds $longestSuite
if ($loadPct -gt 0 -or $deadlineMinutes -gt $TimeoutMinutes) { Write-Host ('  {0} worker(s) per runtime (CPU {1:N0}% busy before the start); deadline {2} min' -f $Workers, $loadPct, $deadlineMinutes) -ForegroundColor DarkGray }
$batchNo = 0
$startBatch = {
    param($rt, $item)
    $batch = @($item.Suites)
    $script:batchNo++
    $list = Join-Path $work ("{0}-{1}.txt" -f $rt, $script:batchNo); $res = Join-Path $work ("{0}-{1}.json" -f $rt, $script:batchNo)
    [IO.File]::WriteAllLines($list, [string[]]@($batch | ForEach-Object { Join-Path $pesterDir $_ }))
    # a 5.1 child started from PowerShell 7 must not inherit 7's module path (Get-FileHash, cert auth break)
    $env:PSModulePath = if ($rt -eq 'ps51') { $ps51Path } else { $keepPath }
    # the 5.1 opt-in also runs the 5.1-PARITY probes, which v3 skips otherwise (they read SI_GATE_PS51)
    $keepPs51Flag = $env:SI_GATE_PS51
    if ($runtimes -contains 'ps51') { $env:SI_GATE_PS51 = '1' }
    try {
        $a = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $shardScript, '-ListFile', $list, '-ResultFile', $res)
        if ($exclude) { $a += @('-ExcludeTag', $exclude) }
        $p = Start-Process -FilePath $exeOf[$rt] -ArgumentList $a -PassThru -WindowStyle Hidden -RedirectStandardOutput (Join-Path $work ("{0}-{1}.out" -f $rt, $script:batchNo)) -RedirectStandardError (Join-Path $work ("{0}-{1}.err" -f $rt, $script:batchNo))
    } finally { $env:PSModulePath = $keepPath; $env:SI_GATE_PS51 = $keepPs51Flag }
    $procs.Add([pscustomobject]@{ Kind = 'pester'; Runtime = $rt; Shard = $script:batchNo; Process = $p; Result = $res; Suites = @($batch); Err = (Join-Path $work ("{0}-{1}.err" -f $rt, $script:batchNo))
                                  Attempt = [int]$item.Attempt; StartedAt = (Get-Date); TimeoutSeconds = (Get-SIFastGateBatchTimeout -Names $batch -Seconds $durations[$rt]); Retried = $false; State = '' })
}
$dotnetResults = New-Object System.Collections.Generic.List[object]
$dotnetJob = $null
# #416: the dotnet BUILD runs in every gate (a change to any file can break the web app's compile), its tests only for the
# projects and classes that cover the change (decided above)
if (-not $NoDotnet -and $map.Solution -and (Test-Path -LiteralPath $sln) -and (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    $dlog = Join-Path $work 'dotnet.log'
    $projects = @($dotnetPlan | ForEach-Object { [pscustomobject]@{ Path = $_.Path; Filter = $_.Filter } })
    foreach ($pj in $dotnetPlan) { if (-not $pj.Whole) { Write-Host ("  dotnet {0}: only {1}" -f $pj.Name, (@($pj.Classes) -join ', ')) -ForegroundColor DarkGray } }
    $dotnetJob = Start-Job -ScriptBlock {
        param($sln, $projects, $log)
        $res = @()
        $sw = [Diagnostics.Stopwatch]::StartNew()
        # #416: never reuse MSBuild nodes -- the test VM is shared by many sessions under one account, and a reused node that
        # another build ends takes this one down (MSB4166 'Child node exited prematurely', 2026-10-09); such a crash builds once more
        $b = @(& dotnet build $sln -c Release --nologo -v q -nodeReuse:false 2>&1); $bc = $LASTEXITCODE
        if ($bc -and ($b -match 'MSB4166')) { Add-Content -LiteralPath $log -Value ($b | Out-String); $b = @(& dotnet build $sln -c Release --nologo -v q -nodeReuse:false 2>&1); $bc = $LASTEXITCODE }
        Add-Content -LiteralPath $log -Value ($b | Out-String)
        # a failed build names its first errors here: dotnet.log stays in the gate's work folder, which a test-VM run does not bring back
        $buildErrors = @($b | ForEach-Object { "$_".Trim() } | Where-Object { $_ -match ':\s*error\s+[A-Z]+\d+' } | Select-Object -Unique -First 8)
        $res += [pscustomobject]@{ Project = 'build'; Ok = ($bc -eq 0); Summary = $(if ($bc) { 'dotnet build FAILED' + $(if ($buildErrors.Count) { ': ' + ($buildErrors -join ' | ') } else { '' }) } else { 'built' }); Seconds = [int]$sw.Elapsed.TotalSeconds }
        if ($bc -eq 0) {
            # a loaded machine: the test host may take longer than vstest's default 90 s to connect -- the nightly of
            # 2026-10-07 lost all three projects that way (FAIL with no test result line, tests that pass in 1 s)
            $env:VSTEST_CONNECTION_TIMEOUT = '600'
            foreach ($pj in $projects) {
                $sw.Restart()
                $ta = @('test', $pj.Path, '-c', 'Release', '--no-build', '--nologo')
                if ($pj.Filter) { $ta += @('--filter', $pj.Filter) }
                $sum = ''; $tc = 0; $note = ''
                foreach ($attempt in 1, 2) {
                    $o = @(& dotnet @ta 2>&1 | ForEach-Object { "$_" }); $tc = $LASTEXITCODE
                    Add-Content -LiteralPath $log -Value ($o | Out-String)
                    $sum = @($o | Where-Object { $_ -match '(Passed|Failed|Skipped)!\s+-' } | ForEach-Object { $_.Trim() }) -join ' '
                    # each failed test with the first line of its error message (dotnet.log stays on the VM)
                    $names = @(for ($k = 0; $k -lt $o.Count; $k++) {
                        if ($o[$k] -notmatch '^\s+Failed\s+\S') { continue }
                        $why = ''
                        for ($m = $k + 1; $m -lt [Math]::Min($o.Count, $k + 8); $m++) {
                            if ($o[$m] -match '^\s*Error Message:') { $why = @($o[($m + 1)..([Math]::Min($o.Count - 1, $m + 2))] | ForEach-Object { $_.Trim() } | Where-Object { $_ }) -join ' '; break }
                        }
                        $line = $o[$k].Trim() + $(if ($why) { ' -- ' + $(if ($why.Length -gt 700) { $why.Substring(0, 700) } else { $why }) } else { '' })
                        $line
                    }) | Select-Object -First 15
                    if ($names.Count) { $sum = ($(if ($sum) { $sum } else { '' }) + ' | ' + ($names -join ' | ')).Trim(' ', '|') }
                    # NO result line = the test run itself never happened (host crash, connection timeout): run it once more;
                    # a run that reported failed tests is a real result and is never re-run
                    if ($tc -eq 0 -or ($o -match '(Passed|Failed|Skipped)!\s+-')) { break }
                    $tail = @($o | Where-Object { $_.Trim() } | Select-Object -Last 4) -join ' / '
                    $note = "attempt $attempt produced no test result (exit $tc): $tail"
                    $sum = $note
                }
                if ($note -and $tc -eq 0) { $sum = "$sum (passed on the re-run; first: $note)" }
                $res += [pscustomobject]@{ Project = [IO.Path]::GetFileNameWithoutExtension($pj.Path); Ok = ($tc -eq 0); Summary = $(if ($pj.Filter) { "[filtered] $sum" } else { $sum }); Seconds = [int]$sw.Elapsed.TotalSeconds }
            }
        }
        $res
    } -ArgumentList $sln, $projects, $dlog
}

# ---- run the queues; wait (only for the processes THIS gate started) ----------------------------------------------------
$deadline = (Get-Date).AddMinutes($deadlineMinutes)
while ($true) {
    # a batch past ITS OWN timeout (a hang, or a machine slowed far beyond the measured time) is stopped by its own id and
    # re-run ONCE in a fresh process; a batch whose process ended without a result (it never really started) likewise
    foreach ($p in @($procs | Where-Object { $_.Process -and -not $_.State })) {
        $over = (-not $p.Process.HasExited) -and (((Get-Date) - $p.StartedAt).TotalSeconds -gt $p.TimeoutSeconds)
        $noResult = $p.Process.HasExited -and -not (Test-Path -LiteralPath $p.Result)
        if (-not $over -and -not $noResult) { continue }
        if ($over) { try { Stop-Process -Id $p.Process.Id -Force -ErrorAction SilentlyContinue } catch { }; $p.State = 'TimedOut' } else { $p.State = 'NoResult' }
        if ($p.Attempt -lt 2) {
            $p.Retried = $true
            Write-Host ('  [{0}] batch {1} {2} -- re-run once ({3})' -f $p.Runtime, $p.Shard, $(if ($over) { "passed its $($p.TimeoutSeconds)s timeout" } else { 'ended without a result' }), ($p.Suites -join ', ')) -ForegroundColor Yellow
            $queue[$p.Runtime].Enqueue([pscustomobject]@{ Suites = @($p.Suites); Attempt = $p.Attempt + 1 })
        }
    }
    foreach ($rt in $runtimes) {
        while ($queue[$rt].Count -and @($procs | Where-Object { $_.Runtime -eq $rt -and $_.Process -and -not $_.Process.HasExited }).Count -lt $Workers) { & $startBatch $rt $queue[$rt].Dequeue() }
    }
    $running = @($procs | Where-Object { $_.Process -and -not $_.Process.HasExited })
    if (-not $running.Count -and -not @($runtimes | Where-Object { $queue[$_].Count }).Count) { break }
    if ((Get-Date) -gt $deadline) {
        foreach ($p in $running) { try { Stop-Process -Id $p.Process.Id -Force -ErrorAction SilentlyContinue } catch { }; $p.State = 'Deadline' }
        # what is still queued never ran: reported as such, never a pass
        foreach ($rt in $runtimes) { while ($queue[$rt].Count) { $b = $queue[$rt].Dequeue(); $procs.Add([pscustomobject]@{ Kind = 'pester'; Runtime = $rt; Shard = 0; Process = $null; Result = ''; Suites = @($b.Suites); Err = ''; Attempt = $b.Attempt; Retried = $false; State = 'NeverStarted' }) } }
        break
    }
    if ($running.Count) { $null = $running[0].Process.WaitForExit(1000) }
}
if ($dotnetJob) {
    $left = [int][Math]::Max(1, ($deadline - (Get-Date)).TotalSeconds)
    if (Wait-Job $dotnetJob -Timeout $left) { foreach ($r in @(Receive-Job $dotnetJob)) { $dotnetResults.Add($r) } }
    else { Stop-Job $dotnetJob; $dotnetResults.Add([pscustomobject]@{ Project = 'dotnet'; Ok = $false; Summary = 'timed out'; Seconds = 0 }) }
    Remove-Job $dotnetJob -Force
}

# ---- 5. result ----------------------------------------------------------------------------------------------------------
$summary = [ordered]@{ Mode = $(if ($Full) { 'full' } elseif ($Hotfix) { 'hotfix' } else { 'fast' }); Base = "$Base"; Commit = "$(& git -C $repoRoot rev-parse HEAD 2>$null)".Trim()
                       Started = $started.ToString('o'); Seconds = 0; Status = ''; Changed = $changed.Count; Suites = $names.Count; Runtimes = [ordered]@{}; Dotnet = @(); Unmapped = $unmapped; OverBudget = @($overBudget.Keys); Phases = $phase; Budget = $null }
$global:LASTEXITCODE = 0
# a full run carries the owner's own words for it (the refusal above let nothing else through); any other run carries none
$summary.OwnerWords = [string]$fullRun.Words
$bad = $false
$newDurations = @{ pwsh = @{}; ps51 = @{} }
foreach ($rt in $runtimes) {
    $agg = [ordered]@{ Passed = 0; Failed = 0; Skipped = 0; Total = 0; Shards = 0; Retried = 0; LongestShardSeconds = 0; WallSeconds = 0; Failures = @(); LoadFailures = @(); Broken = @(); SlowTests = @() }
    $mine = @($procs | Where-Object { $_.Runtime -eq $rt -and $_.Process })
    if ($mine.Count) { try { $agg.WallSeconds = [int](($mine | ForEach-Object { $_.Process.ExitTime } | Measure-Object -Maximum).Maximum - ($mine | ForEach-Object { $_.Process.StartTime } | Measure-Object -Minimum).Minimum).TotalSeconds } catch { } }
    foreach ($p in @($procs | Where-Object Runtime -eq $rt)) {
        # a batch that was re-run counts by its re-run alone
        if ($p.Retried) { $agg.Retried++; continue }
        $agg.Shards++
        $retry = if ($p.Attempt -gt 1) { ', already a re-run' } else { '' }
        switch ($p.State) {
            'TimedOut'     { $agg.Broken += ("batch {0} passed its own timeout of {1}s{2} -- stopped ({3})" -f $p.Shard, $p.TimeoutSeconds, $retry, ($p.Suites -join ', ')) }
            'NoResult'     { $agg.Broken += ("batch {0} ended without a result{1} ({2}): {3}" -f $p.Shard, $retry, ($p.Suites -join ', '), ((Get-Content -Raw -LiteralPath $p.Err -ErrorAction SilentlyContinue) -replace '\s+', ' ')) }
            'Deadline'     { $agg.Broken += ("batch {0} still running at the run's deadline ({1} min) -- stopped ({2})" -f $p.Shard, $deadlineMinutes, ($p.Suites -join ', ')) }
            'NeverStarted' { $agg.Broken += ("never started: the run's deadline ({0} min) passed with it still queued ({1})" -f $deadlineMinutes, ($p.Suites -join ', ')) }
        }
        if ($p.State) { continue }
        if (-not (Test-Path -LiteralPath $p.Result)) { $agg.Broken += ("batch {0} wrote no result ({1}): {2}" -f $p.Shard, ($p.Suites -join ', '), ((Get-Content -Raw -LiteralPath $p.Err -ErrorAction SilentlyContinue) -replace '\s+', ' ')); continue }
        $r = [IO.File]::ReadAllText($p.Result) | ConvertFrom-Json
        if ($r.Error) { $agg.Broken += ("batch {0}: {1}" -f $p.Shard, $r.Error) }
        $agg.Passed += [int]$r.Passed; $agg.Failed += [int]$r.Failed; $agg.Skipped += [int]$r.Skipped; $agg.Total += [int]$r.Total
        if ([double]$r.Seconds -gt $agg.LongestShardSeconds) { $agg.LongestShardSeconds = [double]$r.Seconds }
        foreach ($f in @($r.Failures)) { if ($f) { $agg.Failures += $f } }
        foreach ($f in @($r.LoadFailures)) { if ($f) { $agg.LoadFailures += $f } }
        foreach ($c in @($r.Containers)) { if ($c -and $c.File) { $newDurations[$rt][[string]$c.File] = [double]$c.Seconds } }
        if ($r.PSObject.Properties['SlowTests']) { foreach ($t in @($r.SlowTests)) { if ($t) { $agg.SlowTests += $t } } }
    }
    $agg.SlowTests = @($agg.SlowTests | Sort-Object -Property @{ Expression = { [double]$_.Seconds } } -Descending | Select-Object -First 15)
    if ($agg.Failed -or @($agg.LoadFailures).Count -or @($agg.Broken).Count) { $bad = $true }
    $summary.Runtimes[$rt] = $agg
}
foreach ($d in $dotnetResults) { $summary.Dotnet += $d; if (-not $d.Ok) { $bad = $true } }
if ($names.Count -eq 0 -and -not $dotnetPick.Count) { Write-Host '  nothing to run' -ForegroundColor Yellow }
$summary.Seconds = [int]((Get-Date) - $started).TotalSeconds
# #416: every phase's seconds, and the gate's own budget (the hotfix gate: 5 of the 15 minutes)
foreach ($rt in $runtimes) { $phase["pester $rt (wall)"] = [int]$summary.Runtimes[$rt].WallSeconds }
$dBuild = @($dotnetResults | Where-Object { $_.Project -eq 'build' }); $dTests = @($dotnetResults | Where-Object { $_.Project -ne 'build' })
if ($dBuild.Count) { $phase['dotnet build'] = [int]$dBuild[0].Seconds }
if ($dTests.Count) { $phase['dotnet tests'] = [int](($dTests | Measure-Object -Property Seconds -Sum).Sum) }
$phase['total'] = $summary.Seconds
$summary.Budget = Get-SIFastGateBudget -Mode $summary.Mode -Seconds $summary.Seconds -OverBudget @($overBudget.Keys)
$summary.Status = if ($bad) { 'FAIL' } else { 'PASS' }

Write-Host ''
foreach ($rt in $runtimes) {
    $a = $summary.Runtimes[$rt]
    $label = if ($rt -eq 'pwsh') { 'PowerShell 7  ' } else { 'PowerShell 5.1' }
    Write-Host ('  {0}  {1,5}/{2,-5}  {3} failed, {4} skipped/not run; {5} batch(es) on {6} worker(s){7}, {8}s wall, longest batch {9}s' -f $label, $a.Passed, $a.Total, $a.Failed, ($a.Total - $a.Passed - $a.Failed), $a.Shards, $Workers, $(if ($a.Retried) { " ($($a.Retried) re-run)" } else { '' }), [int]$a.WallSeconds, [int]$a.LongestShardSeconds) -ForegroundColor $(if ($a.Failed -or @($a.LoadFailures).Count -or @($a.Broken).Count) { 'Red' } else { 'Green' })
    foreach ($f in @($a.Failures | Select-Object -First 25)) { Write-Host ('    FAIL [{0}] {1}' -f $f.File, $f.Test) -ForegroundColor Red; if ($f.Message) { Write-Host ('         -> ' + $f.Message) -ForegroundColor DarkGray } }
    foreach ($f in @($a.LoadFailures)) { Write-Host ('    LOAD FAILED [{0}] 0 tests ran: {1}' -f $f.File, $f.Message) -ForegroundColor Red }
    foreach ($b in @($a.Broken)) { Write-Host ('    BROKEN {0}' -f $b) -ForegroundColor Red }
}
foreach ($d in $dotnetResults) { Write-Host ('  dotnet {0,-28} {1}  {2} ({3}s)' -f $d.Project, $(if ($d.Ok) { 'ok  ' } else { 'FAIL' }), $d.Summary, $d.Seconds) -ForegroundColor $(if ($d.Ok) { 'Green' } else { 'Red' }) }
Write-Host ''
Write-Host '  timing (seconds):' -ForegroundColor Cyan
foreach ($k in $phase.Keys) { Write-Host ('    {0,-24} {1,6}' -f $k, $phase[$k]) }
if ($summary.Budget) { Write-Host ('    {0}' -f $summary.Budget.Text) -ForegroundColor $(if ($summary.Budget.Met) { 'Green' } else { 'Yellow' }) }
Write-Host ('  GATE: {0}   in {1} min' -f $summary.Status, [int][Math]::Ceiling(((Get-Date) - $started).TotalMinutes)) -BackgroundColor $(if ($bad) { 'DarkRed' } else { 'DarkGreen' }) -ForegroundColor White
Write-Host ''

if ($UpdateDurations) { Write-SIFastGateDurations -Path $durationsFile -New $newDurations -Old $durations }
if ($ResultFile) {
    $dir = Split-Path -Parent $ResultFile; if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    $summary.Durations = $newDurations
    [IO.File]::WriteAllText($ResultFile, (ConvertTo-Json -InputObject $summary -Depth 8), (New-Object System.Text.UTF8Encoding($false)))
}
Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
if ($bad) { exit 1 }
exit 0
