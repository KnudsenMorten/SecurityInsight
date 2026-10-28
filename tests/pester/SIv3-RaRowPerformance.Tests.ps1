#Requires -Version 7.0
<#
    RISK ANALYSIS PER-ROW PERFORMANCE (REQUIREMENTS #666, owner 2026-10-14: "go ahead, fix the performance").

    Measured live on a mid-size customer (Detailed run, Device_Missing_CVEs_Detailed, one query slice of 42,894 rows): result
    conversion 175 s, filters 21 s, the context steps ~4 min, scoring 1,908 s (22 rows/s), column shaping 2.6 min, writing
    to SQL 16.5 min (43 rows/s). This file pins the fix:

      1. THE SAME OUTPUT. One synthetic slice shaped like the report's rows (tests\fixtures\ra-perf, the columns of the
         report's final project) goes through every step of Invoke-RAReportRows -- conversion, filters, the CI and Defender
         context, scoring, the trace identity and shaping, the SQL write with its seam stubbed -- once through the engine
         files AS THEY WERE (tests\fixtures\ra-perf\before, copied verbatim) and once through the current ones, in one
         process. Every scored row, every shaped row and every JSON item written to SQL is compared: every column, its
         type and value, the row order, the scores, TraceName / TraceID. Also on several cores and on one, in the 'ci'
         data model, and for Summary rows (the impacted-asset lists and pairs in every shape the engine handles).
      2. A TIME BUDGET PER STAGE. 10,000 rows (a quick-gate size: the live slice was 42,894) through the current code; each
         stage must keep a rows/second floor -- about three times what the code before this change managed on the test
         VM, so a return of the per-row cost fails here.
      3. NO ARRAY += IN A LOOP under engine\risk-analysis (owner 2026-10-14: "do we have other places in the code with +=
         instead of using hash tables or similar"): a static scan (tests\fixtures\ra-perf\ArrayAppendScan.ps1); the few
         that stay are bounded lists, each named below with its reason.
      4. The parts of the parallel step: the split, the setting, the plan key of the finding factors.
    Offline; PowerShell 7 (the v3 gate). Runs on the test VM only (never on mgmt1).
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:Fx = Join-Path $script:SIRoot 'tests\fixtures\ra-perf'
    function global:Write-Info { param($m) }
    function global:Write-Warn2 { param($m) $global:RaPerfWarned.Add([string]$m) }
    function global:Write-Ok { param($m) }
    function global:Write-Diag { param($m) }
    $global:RaPerfWarned = New-Object System.Collections.Generic.List[string]
    $ProgressPreference = 'SilentlyContinue'
    . (Join-Path $script:Fx 'RaPerfFixture.ps1')
    . (Join-Path $script:Fx 'ArrayAppendScan.ps1')
    foreach ($f in (Import-RaPerfEngine -SIRoot $script:SIRoot)) { . $f }
    $global:RA_FactorAliasMap = $null; $global:RA_FactorImpactMap = $null; $global:RA_FactorCatalogFactors = $null; $global:RA_FactorCatalog = $null
    $global:SI_SPN_TenantId = '00000000-0000-0000-0000-000000000001'
    $script:Index = New-RiskIndex -CsvRows @(Import-Csv -LiteralPath (Join-Path $script:SIRoot 'risk-analysis-detection\riskscore.index.locked.csv'))
    $script:Cis = New-RaPerfCis
    function script:Compare-RaPerfRows([object[]]$Old, [object[]]$New) {
        $d = New-Object System.Collections.Generic.List[string]
        if ($Old.Count -ne $New.Count) { $d.Add(('rows: {0} before, {1} now' -f $Old.Count, $New.Count)) }
        for ($i = 0; $i -lt [Math]::Min($Old.Count, $New.Count); $i++) {
            $a = Get-RaPerfRowText $Old[$i]; $b = Get-RaPerfRowText $New[$i]
            if ($a -cne $b) { $d.Add(("row {0}:`n  before {1}`n  now    {2}" -f $i, $a, $b)); if ($d.Count -ge 3) { break } }
        }
        , $d.ToArray()
    }
}

AfterAll {
    $global:SI_RA_ScoringThreads = $null; $global:SI_RA_ParallelMinRows = $null; $global:RaPerfWarned = $null
}

Describe '1. the same output as before the change -- every row, column, type, value and order' {
    BeforeAll {
        # the slice is small enough for the old code (~1 minute) and large enough to be split over the cores
        $global:SI_RA_ParallelMinRows = 500
        $script:N = 2400
        $sumRows = { New-RaPerfSummaryRows -Count 240 }
        $scoreSum = { param($rows) @(Calculate-RiskScore -Rows $rows -RiskIndex $script:Index -SecurityDomain 'Endpoint' -CategoryInputName Category -SubCategoryInputName Subcategory `
                -ConfigurationIdInputName ConfigurationId -SecuritySeverityInputName SecuritySeverity -CriticalityTierLevelInputName CriticalityTierLevel -SecurityDomainInputName SecurityDomain `
                -OutputPropertyOrder (Get-RaPerfOutputOrder) -SortBy @('RiskScoreTotal_Weighted') -Descending -ReportName 'Device_Missing_CVEs_Summary') }

        # BEFORE: the engine files as they were
        foreach ($sb in (Get-RaPerfBeforeScripts -SIRoot $script:SIRoot)) { . $sb }
        $script:Old = Invoke-RaPerfSlice -Raw (New-RaPerfRawRows -Count $script:N) -Cis $script:Cis -RiskIndex $script:Index
        $script:OldCi = Invoke-RaPerfSlice -Raw (New-RaPerfRawRows -Count 600 -Seed 7) -Cis $script:Cis -RiskIndex $script:Index -Mode ci
        $script:OldSum = & $scoreSum (New-RaPerfSummaryRows -Count 240)

        # NOW: the current engine files -- on several cores, then on one
        foreach ($f in (Import-RaPerfEngine -SIRoot $script:SIRoot)) { . $f }
        $global:RaPerfWarned.Clear()
        $global:SI_RA_ScoringThreads = 4
        $script:NewPar = Invoke-RaPerfSlice -Raw (New-RaPerfRawRows -Count $script:N) -Cis $script:Cis -RiskIndex $script:Index
        $script:WarnedPar = $global:RaPerfWarned.ToArray()
        $global:SI_RA_ScoringThreads = 1
        $script:NewSeq = Invoke-RaPerfSlice -Raw (New-RaPerfRawRows -Count $script:N) -Cis $script:Cis -RiskIndex $script:Index
        $global:SI_RA_ScoringThreads = 4
        $script:NewCi = Invoke-RaPerfSlice -Raw (New-RaPerfRawRows -Count 600 -Seed 7) -Cis $script:Cis -RiskIndex $script:Index -Mode ci
        $script:NewSum = & $scoreSum (New-RaPerfSummaryRows -Count 240)
        $global:SI_RA_ScoringThreads = $null
    }
    It 'the slice really is the report''s shape: rows scored, CVEs, duplicates removed, rows written' {
        $script:Old.Scored.Count | Should -BeGreaterThan 2300
        $script:Old.Rows['scoring'] | Should -BeLessThan $script:Old.Rows['conversion'] -Because 'the synthetic slice carries exact duplicates the scoring keeps once'
        [long]$script:Old.Rows['sql write'] | Should -Be $script:Old.Scored.Count
        @($script:Old.Scored | Where-Object { [string]$_.ConfigurationId -like 'CVE-*' }).Count | Should -Be $script:Old.Scored.Count
    }
    It 'on several cores the parallel steps really ran (no fall-back to one core was said)' {
        $script:WarnedPar | Should -BeNullOrEmpty
    }
    It 'scored rows: identical on several cores (every column, type, value and the order)' {
        Compare-RaPerfRows $script:Old.Scored $script:NewPar.Scored | Should -BeNullOrEmpty
    }
    It 'scored rows: identical on one core' {
        Compare-RaPerfRows $script:Old.Scored $script:NewSeq.Scored | Should -BeNullOrEmpty
    }
    It 'shaped rows (TraceName / TraceID, the column union, the order): identical' {
        Compare-RaPerfRows $script:Old.Shaped $script:NewPar.Shaped | Should -BeNullOrEmpty
        Compare-RaPerfRows $script:Old.Shaped $script:NewSeq.Shaped | Should -BeNullOrEmpty
    }
    It 'the rows written to SQL (every JSON item, the write order, dedup / trace / finding keys): identical' {
        $script:NewPar.Items.Count | Should -Be $script:Old.Items.Count
        ($script:NewPar.Items -join "`n") | Should -BeExactly ($script:Old.Items -join "`n")
        ($script:NewSeq.Items -join "`n") | Should -BeExactly ($script:Old.Items -join "`n")
    }
    It 'data model ci (the CI decides the asset factors): identical' {
        Compare-RaPerfRows $script:OldCi.Scored $script:NewCi.Scored | Should -BeNullOrEmpty
        ($script:NewCi.Items -join "`n") | Should -BeExactly ($script:OldCi.Items -join "`n")
    }
    It 'Summary rows (impacted-asset lists and pairs in every shape, MITRE from Categories): identical' {
        $script:OldSum.Count | Should -BeGreaterThan 0
        Compare-RaPerfRows $script:OldSum $script:NewSum | Should -BeNullOrEmpty
    }
}

Describe '2. a time budget per stage (10,000 rows; the live slice was 42,894)' {
    BeforeAll {
        foreach ($f in (Import-RaPerfEngine -SIRoot $script:SIRoot)) { . $f }
        # the job's size (4 CPU), not every core of the gate's host: since #716 the default is the cores, and 16 workers
        # here starved the one-core stages of this suite and of the suites running beside it in the gate
        $global:SI_RA_ScoringThreads = 4; $global:SI_RA_ParallelMinRows = $null
        # one small slice first: the worker runspaces are made once per process (the engine makes them once per run)
        $null = Invoke-RaPerfSlice -Raw (New-RaPerfRawRows -Count 2500 -Seed 11) -Cis $script:Cis -RiskIndex $script:Index
        $script:Run = Invoke-RaPerfSlice -Raw (New-RaPerfRawRows -Count 10000) -Cis $script:Cis -RiskIndex $script:Index
        $script:Rate = @{}
        foreach ($k in $script:Run.Times.Keys) { if ($k -notlike ' *') { $script:Rate[$k] = $script:Run.Rows[$k] / [Math]::Max(0.001, $script:Run.Times[$k]) } }
        foreach ($k in $script:Run.Times.Keys) { Write-Host ('  {0,-26} {1,8:N2} s {2,10:N0} rows/s' -f $k, $script:Run.Times[$k], ($script:Run.Rows[$k] / [Math]::Max(0.001, $script:Run.Times[$k]))) }
    }
    # floors: well above the code before this change on the test VM (measured 2026-10-14 at 20,000 rows: conversion ~1,400,
    # filters ~3,800, context ~930, scoring ~86, shaping ~850, SQL write ~220 rows/s; now ~11,000 / 5,200 / 4,400 / 1,000 /
    # 2,600 / 1,700) -- with room for a busy gate (suites run in parallel)
    It 'result conversion >= 4,000 rows/s' { $script:Rate['conversion'] | Should -BeGreaterThan 4000 }
    It 'filters >= 2,500 rows/s' { $script:Rate['filters'] | Should -BeGreaterThan 2500 }
    It 'CI + Defender context >= 1,500 rows/s' { $script:Rate['context'] | Should -BeGreaterThan 1500 }
    It 'scoring >= 300 rows/s' { $script:Rate['scoring'] | Should -BeGreaterThan 300 }
    It 'trace identity + shaping >= 1,200 rows/s' { $script:Rate['shaping'] | Should -BeGreaterThan 1200 }
    It 'the SQL write path (its seam stubbed) >= 700 rows/s' { $script:Rate['sql write'] | Should -BeGreaterThan 700 }
    It 'every row arrived: scored = written' { [long]$script:Run.Rows['sql write'] | Should -Be $script:Run.Rows['scoring'] }
}

Describe '3. no array += inside a loop under engine\risk-analysis' {
    It 'the static scan finds none outside the named bounded lists' {
        # file|variable -> why it may stay (each is a short list, never the rows of a slice)
        $allowed = @{
            'Invoke-RiskAnalysis.ps1|findinglines2' = 'the AI summary''s top findings (at most 50 lines); the append unrolls the formatter''s output collection'
            'Invoke-RiskAnalysis.ps1|assetlines'    = 'the AI summary''s top assets (at most 50 lines); same'
            'Build-QueriesDoc.ps1|domainssorted'    = 'a documentation tool: the four security domains'
            'RA-AutoBucketing.ps1|list'             = 'the bucket store''s own state document (a handful of entries)'
            'RA-CiContext.ps1|alias'                = 'one factor''s names (id, short name, legacy tokens)'
            'RA-ExcludeLists.ps1|maps'              = 'the exclude-list token maps (a handful)'
            'RA-FactorKeys.ps1|n'                   = 'the three risk rating bands'
            'RA-ProfileAugment.ps1|_rahybridlookups' = 'one entry per lookup of a query (a few)'
            'RA-RiskIndexOrder.ps1|maps'            = 'one map per key pattern of the risk index (a few)'
            'RA-RunProgress.ps1|parts'              = 'the parts of one progress value'
        }
        $found = New-Object System.Collections.Generic.List[string]
        foreach ($f in Get-ChildItem (Join-Path $script:SIRoot 'engine\risk-analysis') -Recurse -Filter *.ps1) {
            foreach ($h in (Find-SIArrayAppendInLoop -Path $f.FullName)) {
                $k = '{0}|{1}' -f $f.Name, $h.Variable
                if (-not $allowed.ContainsKey($k)) { $found.Add(('{0}:{1} {2}' -f $f.Name, $h.Line, $h.Text)) }
            }
        }
        $found | Should -BeNullOrEmpty -Because 'use a System.Collections.Generic.List and .ToArray() (never @() around a List[object])'
    }
    It 'the scan finds what it is for (a planted append in a loop, and not a number added to)' {
        $tmp = Join-Path ([IO.Path]::GetTempPath()) ('si-appendscan-{0}.ps1' -f [guid]::NewGuid().ToString('N'))
        try {
            [IO.File]::WriteAllText($tmp, 'function f { $a = @(); $n = 0; foreach ($x in 1..3) { $a += $x; $n += 1 }; $b = @(); while ($true) { $b += ,@(1); break } }')
            $h = Find-SIArrayAppendInLoop -Path $tmp   # (the function returns its list as one array)
            @($h | ForEach-Object Variable) | Should -Be @('a', 'b')
        } finally { Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue }
    }
}

Describe '4. the parts of the parallel step' {
    It 'Split-RAParallelParts: contiguous, in order, near-equal, never more parts than rows' {
        $p = Split-RAParallelParts -Count 10 -Parts 4
        @($p | ForEach-Object { $_[1] }) | Should -Be @(3, 3, 2, 2)
        @($p | ForEach-Object { $_[0] }) | Should -Be @(0, 3, 6, 8)
        (Split-RAParallelParts -Count 2 -Parts 4).Count | Should -Be 2
        (Split-RAParallelParts -Count 0 -Parts 4).Count | Should -Be 0
    }
    It 'SI_RA_ScoringThreads: 1 / off = one core; unset = ON, the cores the process has; below the minimum rows nothing is split' {
        Get-RAScoringThreads -Setting '1' -EnvValue '' | Should -Be 1
        # 2026-10-16 (SIv3-RaParallelScoring): ON by default again -- the 2026-10-14 "hang" was the Defender catalogue read
        Get-RAScoringThreads -Setting '' -Cores 16 -EnvValue '' | Should -Be 16
        Get-RAScoringThreads -Setting $null -Cores 4 -EnvValue '' | Should -Be 4
        Get-RAScoringThreads -Setting '4' -Cores 16 -EnvValue '' | Should -Be 4
        Get-RAScoringThreads -Setting '4' -Cores 2 -EnvValue '' | Should -Be 2 -Because 'a 2-core host never gets more workers than cores'
        Get-RAScoringThreads -Setting $null -Cores 16 -Default 4 -EnvValue '' | Should -Be 4
        Get-RAScoringThreads -Setting $null -Cores 2 -Default 4 -EnvValue '' | Should -Be 2
        Get-RAParallelMinRows -Setting $null | Should -Be 2000
        $global:SI_RA_ScoringThreads = 1
        try { Invoke-RAParallelScoring -Rows @(1..5000) -Bound @{} -RiskIndex ([pscustomobject]@{}) | Should -BeNullOrEmpty } finally { $global:SI_RA_ScoringThreads = $null }
    }
    It 'a worker part is never waited for without an end, and a part still running is never disposed (both would hang the run)' {
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-ParallelScore.ps1'))
        # no fixed time limit (owner 2026-10-22): the wait is in short steps and ends when the parts make no progress (no
        # CPU used) for the no-progress window -- then every part is stopped and the step is redone on one core
        $src | Should -Match 'while \(-not \$pw\[1\]\.AsyncWaitHandle\.WaitOne\(30000\)\)'
        $src | Should -Match '(?s)TotalProcessorTime.{0,400}\$quiet\).{0,200}BeginStop\(.{0,300}throw'
        $src | Should -Match 'if \(\$pw\[1\]\.IsCompleted\) \{ try \{ \$pw\[0\]\.Dispose\(\) \}'
        $src | Should -Match '\$script:RAScoringThreadsDefault = 0\b'
    }
    It 'the finding factors'' plan key: the same values give the same key, a list value gives none (that row is evaluated on its own)' {
        $plan = @{ Fields = @('si_published', 'si_epss', 'Other'); Items = @(); Ready = $true }
        $a = Get-RAFindingFactorPlanKey -Row ([pscustomobject]@{ si_published = '2025-01-01'; si_epss = 0.5; Other = 'x' }) -Plan $plan
        $b = Get-RAFindingFactorPlanKey -Row ([pscustomobject]@{ si_published = '2025-01-01'; si_epss = 0.5; Other = 'y'; si_ci_id = 'c' }) -Plan $plan
        $a | Should -Be $b -Because 'only the si_ fields the conditions read count'
        Get-RAFindingFactorPlanKey -Row ([pscustomobject]@{ si_published = '2025-01-01'; si_epss = '0.5' }) -Plan $plan | Should -Not -Be $a -Because 'a text and a number are different values'
        Get-RAFindingFactorPlanKey -Row ([pscustomobject]@{ si_published = @('a', 'b') }) -Plan $plan | Should -BeNullOrEmpty
    }
}


Describe '5. a Defender read never waits for ever, and a long stage is never silent (live 2026-10-14 on internal)' {
    # Live: the first CVE slice of every Detailed run sat 26 minutes without a line between "rows after filters" and
    # "calculating risk scores" -- the once-per-run read of Defender's vulnerability list (token line, then nothing) -- and
    # was stopped by hand as hung; the run before the per-row change did the same (00:19 -> 00:44Z), the slice after it in
    # each run took under a minute (the list read is kept for the run). A request without a time limit can wait for ever.
    BeforeAll {
        # a server that takes the connection and never answers (the TCP handshake is the operating system's)
        $script:Silent = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
        $script:Silent.Start()
        $script:SilentUrl = 'http://127.0.0.1:{0}/api/vulnerabilities' -f $script:Silent.LocalEndpoint.Port
        $script:Paged = Join-Path $script:SIRoot 'engine\asset-profiling\shared\Invoke-SIPagedRest.ps1'
        $script:ReadIn = {
            param([string]$CodeText, [string]$Paged, [string]$Url, [int]$Limit)
            $ps = [powershell]::Create()
            $null = $ps.AddScript({
                param($CodeText, $Paged, $Url, $Limit)
                $lines = [System.Collections.Generic.List[string]]::new()
                function Write-Info { param($m) $lines.Add([string]$m) }
                function Get-SIGraphToken { param($Resource) 'token' }
                . $Paged
                . ([scriptblock]::Create($CodeText))
                $script:RADefenderCveUrl = $Url
                $global:SI_RA_DefenderReadTimeoutSec = $Limit
                $sw = [System.Diagnostics.Stopwatch]::StartNew()
                $s = Get-RADefenderCveIndex -Refresh
                [pscustomobject]@{ Complete = $s.Complete; Error = [string]$s.Error; Seconds = $sw.Elapsed.TotalSeconds; Lines = $lines.ToArray() }
            }).AddArgument($CodeText).AddArgument($Paged).AddArgument($Url).AddArgument($Limit)
            , @($ps, $ps.BeginInvoke())
        }
    }
    AfterAll { try { $script:Silent.Stop() } catch { } }

    It 'REPRODUCED with the code as it was: the read of an answer that never comes is still waiting after 20 s' {
        $shared = (Join-Path $script:SIRoot 'engine\risk-analysis\_shared').Replace("'", "''")
        $old = [IO.File]::ReadAllText((Join-Path $script:Fx 'before\RA-DefenderCveContext.ps1.before.txt')).Replace('$PSScriptRoot', "'$shared'")
        $run = & $script:ReadIn $old $script:Paged $script:SilentUrl 2
        try {
            $run[1].AsyncWaitHandle.WaitOne(20000) | Should -BeFalse -Because 'the old read gives every request no time limit'
        } finally { $null = $run[0].BeginStop($null, $null) }
    }
    It 'now: every request has a time limit -- the read gives up, says it, and the rows go on unchanged' {
        $shared = (Join-Path $script:SIRoot 'engine\risk-analysis\_shared').Replace("'", "''")
        $new = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-DefenderCveContext.ps1')).Replace('$PSScriptRoot', "'$shared'")
        $run = & $script:ReadIn $new $script:Paged $script:SilentUrl 2
        $run[1].AsyncWaitHandle.WaitOne(90000) | Should -BeTrue -Because '4 attempts of 2 s each plus the pager''s waits between them'
        $r = @($run[0].EndInvoke($run[1]))[-1]
        $run[0].Dispose()
        $r.Complete | Should -BeFalse
        $r.Error | Should -Match 'page 1 failed'
        @($r.Lines) -join "`n" | Should -Match 'reading Defender''s vulnerability list once for this run'
        @($r.Lines) -join "`n" | Should -Match 'vulnerability list read once for this run: 0 read, 0 concern .* -- NOT complete'
        # the rows go on unchanged and the reason is said once
        $rows = @([pscustomobject]@{ ConfigurationId = 'CVE-2024-1' })
        $global:RA_DefenderCveSaid = $false
        $said = [System.Collections.Generic.List[string]]::new()
        $out = Add-RADefenderCveContext -Rows $rows -Index @{ Index = @{}; Complete = $false; Error = $r.Error } -Log { param($m) $said.Add($m) }
        @($out).Count | Should -Be 1
        @($out)[0].PSObject.Properties['si_exploit_verified'] | Should -BeNullOrEmpty
        $said.Count | Should -Be 1
    }
    It 'a long scoring and a long write say how far they are ("... 200 of 600 rows")' {
        $global:SI_RA_ProgressSeconds = 0; $global:SI_RA_ScoringThreads = 1   # (one core: the workers' lines are not shown)
        $global:RaPerfSaid = [System.Collections.Generic.List[string]]::new()
        function global:Write-Info { param($m) $global:RaPerfSaid.Add([string]$m) }
        try {
            $rows = ConvertTo-PSObjectDeep (New-RaPerfRawRows -Count 600 -Seed 21) -StripOData -CastPrimitiveArrays
            $rows = Add-RACiContext -Rows @($rows) -FactorSet @() -Index (New-RACiIndex -Cis $script:Cis)
            $scored = @(Calculate-RiskScore -Rows @($rows) -RiskIndex $script:Index -SecurityDomain 'Endpoint' -CategoryInputName Category -SubCategoryInputName Subcategory `
                -ConfigurationIdInputName ConfigurationId -SecuritySeverityInputName SecuritySeverity -CriticalityTierLevelInputName CriticalityTierLevel -SecurityDomainInputName SecurityDomain `
                -OutputPropertyOrder (Get-RaPerfOutputOrder) -ReportName 'Device_Missing_CVEs_Detailed')
            $null = ConvertTo-RAStreamRowItems -Rows $scored -FirstSeq 1 -InView ([bool[]]::new($scored.Count)) -DateCols ([System.Collections.Generic.HashSet[string]]::new()) `
                -Context @{ Grain = 'Detailed'; Ordinal = 1; Bucket = '1/2'; IsDetailedShape = $true; ConfigurationIdInputName = 'ConfigurationId'; SortColumn = 'RiskScoreTotal_Weighted'; FallbackSortColumn = 'RiskScoreTotal'; Dedup = $true; Equivalence = $null }
        } finally { function global:Write-Info { param($m) }; $global:SI_RA_ProgressSeconds = $null; $global:SI_RA_ScoringThreads = $null }
        $all = $global:RaPerfSaid -join "`n"
        $all | Should -Match 'the CI context added to 200 of \d{3} rows'
        $all | Should -Match 'risk scores worked out for 200 of \d{3} rows'
        $all | Should -Match 'prepared for the database: 200 of \d{3} rows'
    }
    It 'by default a stage says nothing extra unless it runs over 30 seconds' {
        $p = New-RAProgress -What 'x' -Total 10 -EverySeconds $null
        $p.Every | Should -Be 30
    }
}