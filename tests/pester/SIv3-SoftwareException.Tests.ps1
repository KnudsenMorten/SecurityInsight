#Requires -Version 7.0
<#
    A PER-SERVER EXCEPTION OF A SOFTWARE DETECTION (REQUIREMENTS #1219 (4); owner 2026-11-16: "we cannot make a generic rule
    where we look at paths ... we need a way to fine tune on a per server so i can exempt a wrong detection of wordpress so it
    doesnt use that on that specific server").

    THE PROOF, OLD AGAINST NEW (each tree in its own process, tests\fixtures\software-exceptions\Get-SITierProof.ps1): every
    shipped endpoint rule -- through the CI build's rule step (Invoke-SICiRules, the whole CI after the rules: tier, every tier
    claim, the explanation, every field) and through the profiler (Invoke-SIRuleEval, every match) -- over a CI per software
    name a shipped detection looks for plus named CIs, in
      before   the release before (tests\fixtures\software-exceptions\before\: rel-3123's SI-CiEnrich.ps1, SI-CiBuildSql.ps1,
               SI-RecordCapture.ps1, RuleEval.ps1, RuleIndexes.ps1 -- byte-identical, checked below by their git blob ids)
      now      this tree without an exception, and with exceptions on OTHER CIs only        -> BYTE-IDENTICAL to before
      except   this tree with WordpressWordpress / wordpress excepted on web01 (and the internal-wiki rule's wordpress on
               wiki1, a rule that also matches by its other evidence)                         -> exactly that rule's
               contribution on exactly that CI goes; every other CI, rule and tier source as before; the CI says so
    Undo = the exception removed: the read takes only the exceptions in force, so the build is the 'now' build again.
    Plus the pure parts (the index, the excepted item, the read SQL, the CI build's dirty check) and, on a real SQL Server,
    the table, the read of the exceptions in force and the profiler's read through sidata.CiLink.
    PowerShell 7 (the proof runs pwsh). Nothing is sent anywhere.
#>

BeforeDiscovery {
    $script:LocalSql = $false
    try { $script:LocalSql = [bool]$env:SI_TEST_LOCALSQL -and $null -ne ('System.Data.SqlClient.SqlConnection' -as [type]) } catch { $script:LocalSql = $false }
}

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\_shared\SI-SoftwareException.ps1')
    $script:Fix = Join-Path $script:SIRoot 'tests\fixtures\software-exceptions'
    $script:Before = Join-Path $script:Fix 'before'
    $script:Work = Join-Path ([IO.Path]::GetTempPath()) ('si-swexc-' + [guid]::NewGuid().ToString('n').Substring(0, 8))
    New-Item -ItemType Directory -Force -Path $script:Work | Out-Null

    # ---- two code trees: this one, and the release before (this one with rel-3123's files put back) ----
    $script:NewTree = Join-Path $script:Work 'new'; $script:OldTree = Join-Path $script:Work 'old'
    Write-Host 'tier proofs: copying the two code trees'
    foreach ($t in $script:NewTree, $script:OldTree) {
        foreach ($d in 'engine', 'data-model', 'asset-profiling-enrichment', 'config') { Copy-Item -LiteralPath (Join-Path $script:SIRoot $d) -Destination (Join-Path $t $d) -Recurse -Force }
    }
    $script:Put = [ordered]@{ 'SI-CiEnrich.ps1' = 'engine\data-model'; 'SI-CiBuildSql.ps1' = 'engine\data-model'; 'SI-RecordCapture.ps1' = 'engine\data-model'
                              'RuleEval.ps1' = 'engine\asset-profiling\shared'; 'RuleIndexes.ps1' = 'engine\asset-profiling\shared' }
    foreach ($k in $script:Put.Keys) { Copy-Item -LiteralPath (Join-Path $script:Before $k) -Destination (Join-Path (Join-Path $script:OldTree $script:Put[$k]) $k) -Force }

    $script:Ex = {
        param([string]$Name, [object[]]$Rows)
        $f = Join-Path $script:Work ($Name + '.json')
        [IO.File]::WriteAllText($f, (ConvertTo-Json -InputObject @($Rows) -Depth 4), (New-Object System.Text.UTF8Encoding($false)))
        $f
    }
    # THE FOUR PROOFS RUN SIDE BY SIDE, each in its own process (stdin closed: a child never waits on a prompt), with a line
    # every 20 s while they run and a hard limit -- a suite that only printed at the very end looked hung to a gate that ends
    # a suite silent for 5 minutes (each proof evaluates every shipped endpoint rule over ~500 CIs; on a busy runner one
    # took minutes, and the four ran one after the other).
    $script:RunAll = {
        param([object[]]$Jobs, [int]$LimitSeconds = 1500)
        $started = [datetime]::UtcNow
        $procs = @(foreach ($j in $Jobs) {
            $out = Join-Path $script:Work ($j.Name + '.txt')
            $a = @('-NoProfile', '-NonInteractive', '-File', (Join-Path $script:Fix 'Get-SITierProof.ps1'), '-Root', $j.Tree, '-Out', $out)
            if ($j.Exceptions) { $a += @('-Exceptions', $j.Exceptions) }
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = (Get-Process -Id $PID).Path
            foreach ($x in $a) { $psi.ArgumentList.Add([string]$x) }
            $psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true; $psi.RedirectStandardInput = $true
            $p = [System.Diagnostics.Process]::Start($psi)
            $p.StandardInput.Close()
            [pscustomobject]@{ Name = $j.Name; Out = $out; Proc = $p; StdOut = $p.StandardOutput.ReadToEndAsync(); StdErr = $p.StandardError.ReadToEndAsync() }
        })
        while (@($procs | Where-Object { -not $_.Proc.HasExited }).Count -gt 0) {
            $null = @($procs | Where-Object { -not $_.Proc.HasExited })[0].Proc.WaitForExit(20000)
            $secs = [int]([datetime]::UtcNow - $started).TotalSeconds
            $left = @($procs | Where-Object { -not $_.Proc.HasExited } | ForEach-Object { $_.Name })
            if ($left.Count) { Write-Host ("tier proofs: {0} of {1} done after {2} s (running: {3})" -f ($procs.Count - $left.Count), $procs.Count, $secs, ($left -join ', ')) }
            if ($secs -gt $LimitSeconds) {
                foreach ($x in $procs) { if (-not $x.Proc.HasExited) { try { $x.Proc.Kill($true) } catch { } } }
                throw ("the tier proofs did not finish in {0} s (still running: {1})" -f $LimitSeconds, ($left -join ', '))
            }
        }
        $res = @{}
        foreach ($x in $procs) {
            $x.Proc.WaitForExit()
            $log = ($x.StdOut.Result + ' ' + $x.StdErr.Result).Trim()
            if ($x.Proc.ExitCode -ne 0) { throw ("the tiers of {0} could not be built: {1}" -f $x.Name, $log) }
            Write-Host ('{0}: {1}' -f $x.Name, $log)
            $res[$x.Name] = [IO.File]::ReadAllLines($x.Out)
        }
        Write-Host ("tier proofs: all {0} done in {1} s" -f $procs.Count, [int]([datetime]::UtcNow - $started).TotalSeconds)
        $res
    }
    $row = { param($ci, $rule, $vendor, $product) [ordered]@{ CiId = $ci; RuleId = $rule; Vendor = $vendor; Product = $product; Reason = 'files on a data share, not a CMS'; SetBy = 'admin@example.test'; SetAt = '2026-11-16T08:00:00Z' } }
    $script:OtherRows = @((& $row 'ci-elsewhere' 'WordpressWordpress' 'wordpress' 'wordpress'), (& $row 'ci-elsewhere-2' 'InternalWikiIntranetServer' 'mediawiki' 'mediawiki'))
    $script:WpRows = @((& $row 'ci-wp' 'WordpressWordpress' 'wordpress' 'wordpress'), (& $row 'ci-wiki' 'InternalWikiIntranetServer' 'wordpress' 'wordpress'))

    $proofs = & $script:RunAll @(
        [pscustomobject]@{ Name = 'before'; Tree = $script:OldTree; Exceptions = '' }
        [pscustomobject]@{ Name = 'now'; Tree = $script:NewTree; Exceptions = '' }
        [pscustomobject]@{ Name = 'other'; Tree = $script:NewTree; Exceptions = (& $script:Ex 'other' $script:OtherRows) }
        [pscustomobject]@{ Name = 'except'; Tree = $script:NewTree; Exceptions = (& $script:Ex 'except' $script:WpRows) })
    $script:Old = $proofs['before']; $script:Now = $proofs['now']; $script:Other = $proofs['other']; $script:Exc = $proofs['except']

    $script:Ci = { param([string[]]$Lines, [string]$Id) $l = @($Lines | Where-Object { $_.StartsWith("C|$Id|", [StringComparison]::Ordinal) }); if ($l.Count -ne 1) { throw ("CI {0}: {1} line(s)" -f $Id, $l.Count) }; $l[0].Substring($Id.Length + 3) | ConvertFrom-Json -Depth 20 }
    $script:Claims = { param($ci) @($ci.si_tier_claims | ForEach-Object { ConvertTo-Json -InputObject $_ -Compress -Depth 10 }) }
}

AfterAll {
    if ($script:Work -and (Test-Path -LiteralPath $script:Work)) { Remove-Item -LiteralPath $script:Work -Recurse -Force -ErrorAction SilentlyContinue }
}

Describe 'the release before is rel-3123 (the reference is what ships today)' {
    It 'every before file is byte-identical to rel-3123 (git blob id over the LF text)' {
        $want = @{ 'SI-CiEnrich.ps1' = '5c13ee060b00344617532e6814a1eb750b5baff2'; 'SI-CiBuildSql.ps1' = '48308b0e9919ef8366aee100e64cee0ed2c5fb1c'
                   'SI-RecordCapture.ps1' = '1ec517c22dd25fc1c981044d65f0383bd5be0c09'; 'RuleEval.ps1' = '801c4e48d553a623d9d7966e454297ebd48e747f'
                   'RuleIndexes.ps1' = 'f45e011c069eccc5dcc135b7a70bd62cec872628' }
        foreach ($k in $want.Keys) {
            $txt = [IO.File]::ReadAllText((Join-Path $script:Before $k)).Replace("`r`n", "`n")
            $body = [Text.Encoding]::UTF8.GetBytes($txt)
            $head = [Text.Encoding]::ASCII.GetBytes(('blob {0}' -f $body.Length) + [char]0)
            $sha = [BitConverter]::ToString([Security.Cryptography.SHA1]::HashData([byte[]]($head + $body))).Replace('-', '').ToLowerInvariant()
            $sha | Should -Be $want[$k] -Because $k
        }
    }
}

Describe 'WITHOUT an exception every CI''s tier and tier sources are IDENTICAL to the release before' {
    It 'the proof covers the shipped software detections (control: it cannot pass by evaluating nothing)' {
        @($script:Old | Where-Object { $_.StartsWith('C|') }).Count | Should -BeGreaterThan 300
        @($script:Old | Where-Object { $_.StartsWith('P|') }).Count | Should -BeGreaterThan 300
        @($script:Old | Where-Object { $_ -match '"winner":true' }).Count | Should -BeGreaterThan 300
        @((& $script:Ci $script:Old 'ci-wp').si_tier_claims | Where-Object { $_.rule -like 'WordpressWordpress/*' -and [int]$_.tier -eq 2 }).Count | Should -Be 1 -Because 'WordPress is a CMS (Tier 2) today'
    }
    It 'no exception in force: every CI (tier, claims, explanation, every field) and every profiler match BYTE-IDENTICAL' {
        $script:Now.Count | Should -Be $script:Old.Count
        for ($i = 0; $i -lt $script:Old.Count; $i++) { $script:Now[$i] | Should -BeExactly $script:Old[$i] }
    }
    It 'exceptions in force on OTHER CIs only: still byte-identical (an exception never reaches another server)' {
        $script:Other.Count | Should -Be $script:Old.Count
        for ($i = 0; $i -lt $script:Old.Count; $i++) { $script:Other[$i] | Should -BeExactly $script:Old[$i] }
    }
}

Describe 'an exception drops exactly that rule''s software contribution on exactly that CI; the finding side stays; undo restores' {
    It 'every OTHER CI and every other device''s profiler match is byte-identical (web02 carries the same WordPress)' {
        $keep = { param($l) -not ($l.StartsWith('C|ci-wp|') -or $l.StartsWith('C|ci-wiki|') -or $l.StartsWith('P|dev-ci-wp|') -or $l.StartsWith('P|dev-ci-wiki|')) }
        $a = @($script:Old | Where-Object { & $keep $_ }); $b = @($script:Exc | Where-Object { & $keep $_ })
        $b.Count | Should -Be $a.Count
        for ($i = 0; $i -lt $a.Count; $i++) { $b[$i] | Should -BeExactly $a[$i] }
        (& $script:Ci $script:Exc 'ci-wp2').si_tier | Should -Be 2
    }
    It 'web01: the WordPress rule''s claim is gone, every other claim identical, the tier is the MIN of what is left; the CI says so' {
        $o = & $script:Ci $script:Old 'ci-wp'; $n = & $script:Ci $script:Exc 'ci-wp'
        @($o.si_tier_claims | Where-Object { $_.rule -like 'WordpressWordpress/*' }).Count | Should -Be 1
        @($n.si_tier_claims | Where-Object { $_.rule -like 'WordpressWordpress/*' }).Count | Should -Be 0
        $rest = @(& $script:Claims $o | Where-Object { $_ -notmatch '"rule":"WordpressWordpress/' })
        # the winner flag moves only when the removed claim had won: compare without it
        @(& $script:Claims $n | ForEach-Object { $_ -replace '"winner":(true|false)', '' }) | Should -Be @($rest | ForEach-Object { $_ -replace '"winner":(true|false)', '' })
        $left = @($n.si_tier_claims | Where-Object { $_.admissible -and $null -ne $_.tier -and $_.kind -eq 'rule' } | ForEach-Object { [int]$_.tier })
        if ($left.Count -gt 0) { [int]$n.si_tier | Should -Be ([int]($left | Measure-Object -Minimum).Minimum) }
        @($n.si_software_exceptions).Count | Should -Be 1
        $n.si_software_exceptions[0].rule | Should -Be 'WordpressWordpress'
        $n.si_software_exceptions[0].software | Should -Be 'wordpress/wordpress'
        $n.si_software_exceptions[0].effect | Should -Be 'removed'
        $n.si_software_exceptions[0].reason | Should -Be 'files on a data share, not a CMS'
        $n.si_tier_explanation | Should -Match 'Detection excepted on this server: rule WordpressWordpress for wordpress/wordpress \(the rule no longer claims a tier on this server; by admin@example\.test: files on a data share, not a CMS\)\.'
        # every field but the tier result and the exception's own is the CI as it was (the software list included: the finding side is untouched)
        foreach ($f in @($o.PSObject.Properties.Name | Where-Object { $_ -notin 'si_tier', 'si_tier_set_by', 'si_tier_reason', 'si_tier_claims', 'si_tier_explanation', 'si_purpose', 'si_category', 'si_tags', 'si_tags_all', 'si_rule_proposals' })) {
            (ConvertTo-Json -InputObject $n.$f -Compress -Depth 10) | Should -BeExactly (ConvertTo-Json -InputObject $o.$f -Compress -Depth 10) -Because $f
        }
        @($n.si_installed_software) | Should -Contain 'wordpress/wordpress' -Because 'the software stays on the CI -- only that rule does not look at it'
    }
    It 'web01: ANOTHER rule matching the same software (the internal-wiki rule, word*) is untouched -- scope is (CI, rule, software)' {
        $o = & $script:Ci $script:Old 'ci-wp'; $n = & $script:Ci $script:Exc 'ci-wp'
        $ow = @($o.si_tier_claims | Where-Object { $_.rule -like 'InternalWikiIntranetServer/*' }); $nw = @($n.si_tier_claims | Where-Object { $_.rule -like 'InternalWikiIntranetServer/*' })
        $ow.Count | Should -Be 1
        (ConvertTo-Json -InputObject $nw -Compress -Depth 10) -replace '"winner":(true|false)', '' | Should -BeExactly ((ConvertTo-Json -InputObject $ow -Compress -Depth 10) -replace '"winner":(true|false)', '')
    }
    It 'wiki1: an exception of a rule that also matches by its other evidence keeps its claim (said: other evidence), without the excepted software in what matched' {
        $o = & $script:Ci $script:Old 'ci-wiki'; $n = & $script:Ci $script:Exc 'ci-wiki'
        $nw = @($n.si_tier_claims | Where-Object { $_.rule -like 'InternalWikiIntranetServer/*' })
        $nw.Count | Should -Be 1
        @($nw[0].matched) -join ';' | Should -Not -Match 'wordpress/wordpress'
        @($n.si_software_exceptions)[0].effect | Should -Be 'other-evidence'
        [int]$n.si_tier | Should -Be ([int]$o.si_tier)
        # the WordPress rule on wiki1 is not named by the exception: unchanged
        (ConvertTo-Json -InputObject @($n.si_tier_claims | Where-Object { $_.rule -like 'WordpressWordpress/*' }) -Compress -Depth 10) -replace '"winner":(true|false)', '' |
            Should -BeExactly ((ConvertTo-Json -InputObject @($o.si_tier_claims | Where-Object { $_.rule -like 'WordpressWordpress/*' }) -Compress -Depth 10) -replace '"winner":(true|false)', '')
    }
    It 'the profiler: that rule no longer matches web01''s device; every other rule on it and every other device as before' {
        $o = @($script:Old | Where-Object { $_.StartsWith('P|dev-ci-wp|') }); $n = @($script:Exc | Where-Object { $_.StartsWith('P|dev-ci-wp|') })
        @($o | Where-Object { $_ -match '\|WordpressWordpress\|' }).Count | Should -Be 1
        @($n | Where-Object { $_ -match '\|WordpressWordpress\|' }).Count | Should -Be 0
        $n | Should -Be @($o | Where-Object { $_ -notmatch '\|WordpressWordpress\|' })
        # wiki1's internal-wiki rule still matches (mediawiki / its name): the excepted wordpress was not its only evidence
        @($script:Exc | Where-Object { $_.StartsWith('P|dev-ci-wiki|') }) | Should -Be @($script:Old | Where-Object { $_.StartsWith('P|dev-ci-wiki|') })
    }
    It 'UNDO: a removed exception is not read (only those in force), so the next build is the no-exception build -- identical to before' {
        Get-SICiSoftwareExceptionReadSql | Should -Match 'WHERE ISNULL\(Removed, 0\) = 0'
        Get-SIDeviceSoftwareExceptionReadSql | Should -Match 'WHERE ISNULL\(x\.Removed, 0\) = 0'
        # the build of the remaining rows (none) = the 'now' build, already proven identical to before
        (ConvertTo-SICiSoftwareExceptionIndex -Rows @()).Count | Should -Be 0
    }
}

Describe 'the pure parts' {
    It 'the index: CI (case-insensitive) -> exceptions; rows naming nothing are left out' {
        $ix = ConvertTo-SICiSoftwareExceptionIndex -Rows @(
            [pscustomobject]@{ CiId = 'CI-A'; RuleId = 'WordpressWordpress'; Vendor = 'WordPress'; Product = 'WordPress'; Reason = 'r'; SetBy = 'a'; SetAt = [datetime]'2026-11-16T08:00:00Z' }
            [pscustomobject]@{ CiId = ''; RuleId = 'X'; Vendor = 'v'; Product = 'p' }
            [pscustomobject]@{ CiId = 'ci-b'; RuleId = ''; Vendor = 'v'; Product = 'p' })
        $ix.Count | Should -Be 1
        $ix['ci-a'][0].software | Should -Be 'wordpress/wordpress'
        $ix['ci-a'][0].set_at | Should -Be '2026-11-16T08:00:00Z'
    }
    It 'the excepted item leaves out exactly the excepted software and never changes the CI; no software to leave out = the CI itself' {
        $ci = [ordered]@{ si_ci_id = 'ci-a'; si_installed_software = @('wordpress/wordpress', 'microsoft/edge'); si_tags = @('x') }
        $it = Get-SICiSoftwareExceptedItem -Ci $ci -Exceptions @(@{ rule = 'R'; software = 'WordPress/WordPress' })
        @($it['si_installed_software']) | Should -Be @('microsoft/edge')
        [object]::ReferenceEquals($it['si_tags'], $ci['si_tags']) | Should -BeTrue
        @($ci['si_installed_software']) | Should -Be @('wordpress/wordpress', 'microsoft/edge')
        [object]::ReferenceEquals((Get-SICiSoftwareExceptedItem -Ci $ci -Exceptions @(@{ rule = 'R'; software = 'drupal/drupal' })), $ci) | Should -BeTrue
        [object]::ReferenceEquals((Get-SICiSoftwareExceptedItem -Ci $ci -Exceptions @()), $ci) | Should -BeTrue
        Get-SICiRuleIdOf 'WordpressWordpress/WordpressWordpress' | Should -Be 'WordpressWordpress'
        Get-SICiRuleIdOf 'operator-tier-tag/tier3' | Should -Be 'operator-tier-tag'
    }
    It 'the profiler''s index: device -> rule -> software set; a failed read answers its error and no index' {
        $ix = ConvertTo-SIDeviceSoftwareExceptionIndex -Rows @([pscustomobject]@{ DeviceId = 'ABC'; RuleId = 'WordpressWordpress'; Vendor = 'wordpress'; Product = 'wordpress' })
        $ix['abc']['wordpresswordpress'].Contains('WORDPRESS/wordpress') | Should -BeTrue
        $r = Read-SIDeviceSoftwareExceptions -Invoke { param($s, $p, $m) throw 'timeout' }
        $r.Error | Should -Be 'timeout'
        $r.Index.Count | Should -Be 0
        (Read-SIDeviceSoftwareExceptions -Invoke { param($s, $p, $m) @() }).Index.Count | Should -Be 0
    }
    It 'a CI whose exception was set or removed since the last build is rebuilt (the incremental build''s dirty check)' {
        $s = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\data-model\SI-CiBuildSql.ps1'))
        $s | Should -Match ([regex]::Escape("IF @since IS NOT NULL AND OBJECT_ID('sidata.CiSoftwareException') IS NOT NULL"))
        $s | Should -Match ([regex]::Escape('SELECT DISTINCT CiId FROM sidata.CiSoftwareException WHERE SetAt >= @s OR RemovedAt >= @s'))
    }
    It 'the CI build reads the exceptions (SQL path) and hands them to the rule step; a failed read builds no CI (before the build marks itself running)' {
        $s = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\data-model\SI-CiBuildRun.ps1'))
        $s | Should -Match ([regex]::Escape('$SoftwareExceptionRows = @(& $sql (Get-SICiSoftwareExceptionReadSql) @{} ''rows'')'))
        $s | Should -Match ([regex]::Escape("Failed = `$true; Reason = 'the per-server software exceptions could not be read'"))
        $s | Should -Not -Match 'none is applied this run'
        # the stop comes before the build writes anything: its state 'running' / LastBuildStart, which moves the dirty check's start
        $s.IndexOf("Reason = 'the per-server software exceptions could not be read'") | Should -BeLessThan $s.IndexOf("n = 'LastBuildStart'")
        ([regex]::Matches($s, '-SoftwareExceptions \$swxIdx')).Count | Should -Be 2 -Because 'both the offline and the SQL build'
        $e = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\data-model\SI-CiEnrich.ps1'))
        ([regex]::Matches($e, '-SoftwareExceptions \$(using:)?SoftwareExceptions')).Count | Should -Be 2 -Because 'the parallel and the plain loop'
        ([regex]::Matches($s, 'Invoke-SICiEnrichment [^\r\n]*-SoftwareExceptions \$SoftwareExceptions')).Count | Should -Be 1 -Because 'the core hands them on'
        $p = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\stages\Invoke-Profile.ps1'))
        $p | Should -Match 'Read-SIDeviceSoftwareExceptions'
        $p | Should -Not -Match 'none is applied this run'
    }
}

Describe 'a FAILED read of the exceptions changes no tier: the endpoint profile keeps its last good state' {
    BeforeAll {
        $script:R = $script:SIRoot
        . (Join-Path $script:R 'engine\asset-profiling\_shared\Write-SIStyle.ps1')
        . (Join-Path $script:R 'engine\asset-profiling\storage\StorageContext.ps1')
        . (Join-Path $script:R 'engine\asset-profiling\storage\StagingBlob.ps1')
        if (-not (Get-Command Reset-SIProgress -ErrorAction SilentlyContinue)) { function script:Reset-SIProgress { param($Label) } }
        if (-not (Get-Command Write-SIProgress -ErrorAction SilentlyContinue)) { function script:Write-SIProgress { param($Label, $Index, $Total) } }
        # a scratch tree that runs the REAL Invoke-Profile.ps1 with one stand-in rule (Tier 0 on every device)
        $t = Join-Path $script:Work 'profile'
        $stages = Join-Path $t 'engine\asset-profiling\stages'; $shared = Join-Path $t 'engine\asset-profiling\shared'; $storage = Join-Path $t 'engine\asset-profiling\storage'
        foreach ($d in $stages, $shared, $storage) { New-Item -ItemType Directory -Force -Path $d | Out-Null }
        Copy-Item (Join-Path $script:R 'engine\asset-profiling\stages\Invoke-Profile.ps1') $stages
        $real = Join-Path $script:R 'engine\asset-profiling'
        Set-Content -Path (Join-Path $shared 'Get-SIRuleSet.ps1') -Value 'function Get-SIRuleSet { param($Engine) @([pscustomobject]@{ Id = ''WordpressWordpress''; Set = @{ Tier = 0 } }) }'
        Set-Content -Path (Join-Path $shared 'RuleIndexes.ps1') -Value 'function Build-SIRuleIndexes { param($Engine, $Rules, $Assets, $RunContext) @{} }'
        Set-Content -Path (Join-Path $shared 'RuleEval.ps1') -Value @'
function Get-SIAssetOsClass { param($Asset) 'WindowsServer' }
function Get-SIAssetField { param($Asset, $Name) '' }
function Invoke-SIRuleEval { param($Asset, $Rule) [pscustomobject]@{ RuleId = $Rule.Id; DetectionId = $Rule.Id; Set = $Rule.Set } }
'@
        Set-Content -Path (Join-Path $shared 'CmdbFieldPrecedence.ps1') -Value (". '{0}'" -f (Join-Path $real 'shared\CmdbFieldPrecedence.ps1'))
        Set-Content -Path (Join-Path $storage 'StagingBlob.ps1') -Value (". '{0}'" -f (Join-Path $real 'storage\StagingBlob.ps1'))
        . (Join-Path $stages 'Invoke-Profile.ps1')
        function script:New-ProfileRun {
            $ctx = New-SIStorageContext -Mock
            $ctx.MockState.Blobs['stg'] = @{}
            $recs = @('web01', 'web02') | ForEach-Object { [pscustomobject]@{ AssetName = $_; PrimaryEntityId = $_; Verdict = [pscustomobject]@{ SI_Tier = 3 }; Metadata = [pscustomobject]@{ MDE_DeviceName = $_ } } }
            $null = Write-SIStageShard -Context $ctx -ContainerName 'stg' -RunId 'run1' -Stage 'Classify' -ShardIndex 0 -Records @($recs)
            [pscustomobject]@{ Engine = 'endpoint'; StorageContext = $ctx; StagingContainer = 'stg'; RunId = 'run1'; ShardIndex = 0; CollectionTime = '2026-11-17T00:00:00Z' }
        }
        function script:Staged($rc) { ConvertTo-Json -InputObject @(Read-SIStageShards -Context $rc.StorageContext -ContainerName 'stg' -RunId 'run1' -Stage 'Classify' -ReplicaIndex 0) -Compress -Depth 10 }
    }
    It 'a failed read STOPS the endpoint profile before anything is written (said plainly); the staged devices are exactly as before' {
        $rc = New-ProfileRun
        $before = Staged $rc
        Mock Read-SIDeviceSoftwareExceptions { @{ Index = @{}; Rows = 0; Error = 'timeout' } }
        { Invoke-SIProfile -RunContext $rc 6>$null 3>$null } | Should -Throw '*per-server software exceptions could not be read (timeout)*'
        Staged $rc | Should -BeExactly $before -Because 'no un-excepted tier is written: the run publishes no profile and every device keeps its last good one'
        (Staged $rc) | Should -Match '"SI_Tier":3'
    }
    It 'a read that throws stops it the same way' {
        $rc = New-ProfileRun
        $before = Staged $rc
        Mock Read-SIDeviceSoftwareExceptions { throw 'login failed' }
        { Invoke-SIProfile -RunContext $rc 6>$null 3>$null } | Should -Throw '*could not be read (login failed)*'
        Staged $rc | Should -BeExactly $before
    }
    It 'CONTROL: a read that answers no exception (no table, or none in force) profiles exactly as before' {
        $rc = New-ProfileRun
        Mock Read-SIDeviceSoftwareExceptions { @{ Index = @{}; Rows = 0; Error = $null } }
        $res = Invoke-SIProfile -RunContext $rc 6>$null 3>$null
        $res.Matched | Should -Be 2
        @(Read-SIStageShards -Context $rc.StorageContext -ContainerName 'stg' -RunId 'run1' -Stage 'Classify' -ReplicaIndex 0 | ForEach-Object { [int]$_.Verdict.SI_Tier }) | Should -Be @(0, 0)
    }
    It 'the line says what happened and that the last good profile stays (no internal numbers)' {
        $l = Get-SIProfileExceptionStop -Reason 'x'
        $l | Should -Match '^The endpoint profile was NOT stored this run: the per-server software exceptions could not be read \(x\)\.'
        $l | Should -Match 'keeps its last good profile'
        $l | Should -Not -Match '#\d'
    }
}

Describe 'the table on a real SQL Server' {
    BeforeAll {
        function script:New-LocalInvoke([string]$Db) {
            $cs = "Server=$($env:SI_TEST_LOCALSQL);Database=$Db;$($env:SI_TEST_SQL_AUTH);TrustServerCertificate=True"
            {
                param([string]$sql, $p, [string]$mode)
                $cn = New-Object System.Data.SqlClient.SqlConnection($cs); $cn.Open()
                try {
                    $c = $cn.CreateCommand(); $c.CommandTimeout = 300; $c.CommandText = $sql
                    if ($p) { foreach ($k in $p.Keys) { [void]$c.Parameters.AddWithValue('@' + $k, $(if ($null -eq $p[$k]) { [DBNull]::Value } else { $p[$k] })) } }
                    if ($mode -eq 'scalar') { return $c.ExecuteScalar() }
                    if ($mode -eq 'nonquery') { return $c.ExecuteNonQuery() }
                    $r = $c.ExecuteReader(); $rows = New-Object System.Collections.Generic.List[object]
                    while ($r.Read()) { $h = [ordered]@{}; for ($i = 0; $i -lt $r.FieldCount; $i++) { $h[$r.GetName($i)] = $(if ($r.IsDBNull($i)) { $null } else { $r.GetValue($i) }) }; $rows.Add([pscustomobject]$h) }
                    $r.Close(); return , $rows.ToArray()
                } finally { $cn.Close() }
            }.GetNewClosure()
        }
    }
    It 'additive; the reads take the exceptions in force only; the profiler''s read finds the CI''s Defender devices' -Skip:(-not $script:LocalSql) {
        . (Join-Path $script:SIRoot 'engine\_shared\SI-SchemaGate.ps1')
        $schema = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'sql\si-data-schema.sql'))
        (Test-SISchemaIsAdditive -Sql $schema).IsAdditive | Should -BeTrue
        $db = 'siswx_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
        $master = New-LocalInvoke 'master'
        [void](& $master "CREATE DATABASE [$db]" @{} 'nonquery')
        try {
            $inv = New-LocalInvoke $db
            # before the table exists: no rows, no error
            @(& $inv (Get-SICiSoftwareExceptionReadSql) @{} 'rows' | ForEach-Object { $_ }).Count | Should -Be 0
            [void](& $inv $schema @{} 'nonquery'); [void](& $inv $schema @{} 'nonquery')
            [void](& $inv "INSERT sidata.CiSoftwareException (CiId, RuleId, Vendor, Product, Reason, SetBy) VALUES (N'CI-1', N'WordpressWordpress', N'wordpress', N'wordpress', N'data share', N'a@x'), (N'CI-2', N'DrupalDrupal', N'drupal', N'drupal', N'old copy', N'a@x')" @{} 'nonquery')
            [void](& $inv "UPDATE sidata.CiSoftwareException SET Removed = 1, RemovedBy = N'a@x', RemovedAt = SYSUTCDATETIME(), RemovedReason = N'wrong' WHERE CiId = N'CI-2'" @{} 'nonquery')
            [void](& $inv "INSERT sidata.CiLink (CiId, Provider, RecordType, NativeId, IsPrimary) VALUES (N'CI-1', N'mde', N'device', N'ABCDEF0123456789', 1), (N'CI-1', N'entra', N'device', N'x', 0), (N'CI-2', N'mde', N'device', N'ffff0000ffff0000', 1)" @{} 'nonquery')
            $rows = @(& $inv (Get-SICiSoftwareExceptionReadSql) @{} 'rows' | ForEach-Object { $_ })
            $rows.Count | Should -Be 1
            $rows[0].CiId | Should -Be 'CI-1'
            $ix = ConvertTo-SICiSoftwareExceptionIndex -Rows $rows
            $ix['ci-1'][0].software | Should -Be 'wordpress/wordpress'
            $r = Read-SIDeviceSoftwareExceptions -Invoke $inv
            $r.Error | Should -BeNullOrEmpty
            @($r.Index.Keys) | Should -Be @('abcdef0123456789')
            $r.Index['abcdef0123456789']['WordpressWordpress'].Contains('wordpress/wordpress') | Should -BeTrue
        } finally {
            try { [void](& $master "ALTER DATABASE [$db] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$db]" @{} 'nonquery') } catch { }
        }
    }
}
