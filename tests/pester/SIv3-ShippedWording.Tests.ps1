#Requires -Version 5.1
# SI-TestScope: PrivateRepo
#   reads the publish manifest, which a public copy does not carry (see _SITestScope.ps1)
<#
    WHAT SHIPS, READ AS AN OUTSIDER WOULD (framework audit SEC-05; owner rule: never publish anything a hacker can use).
    The model is EntraPolicySuite's Test-EpsShippedContent, narrowed to what SecurityInsight's text needs: SecurityInsight is
    a security product, so its finding texts, queries and tier reasons rightly talk about bypassed Conditional Access,
    unsigned drivers or an unverified publisher -- those describe the CUSTOMER's estate and are not scanned for. What is
    scanned for is wording about SecurityInsight's OWN controls, or engineering left-overs:
      * a work marker (TODO / FIXME / HACK);
      * another product's internal defect id (BUG-<n>);
      * a way around a control: bypassing / skipping / circumventing / getting around a gate, guard, check, signature,
        verification, approval, integrity check, checksum or digest -- or such a control described as bypassed;
      * a loophole, a backdoor, a security gap or hole, a known weakness, a gap in a check or guard;
      * an integrity value (checksum, digest, signature, SHA-256, hash) described as skipped or not checked.
    Operational status lines ("the job size was not checked (<reason>) -- the next update tries again") are what a run
    shows on purpose about a step that could not run; they name no weakness and are not scanned for.

    "Shipped" = every tracked file of SecurityInsight the public (Community) copy gets: solution.publish.json excludePaths
    and the shared publish stage's strips taken out (top-level logs, OUTPUT, staging, internal, demo,
    solution.publish.json, CLAUDE.md; the folders internal, logs, staging, demo, output at any depth; REQUIREMENTS.md,
    TESTS.md, CLAUDE.md at any depth; *.internal-vm.* / *.internal-azure.*). The shared, byte-equal copies (vendor/ =
    the framework's sign-in front, engine/_shared/InvardiaUpdate.verify.ps1 = Invardia's verifier) are not
    SecurityInsight's own text: they are changed at their source and are left out here. This file holds the rules
    themselves and is left out too.
    A new hit fails. There is no allow-list today; an entry would be file + exact text + the reason, one by one.
    FULLY OFFLINE: files only.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:SelfRel = 'tests/pester/' + (Split-Path -Leaf $PSCommandPath)

    # ---- the rules (each a name + a regex; case-insensitive unless the rule says so) ----
    $script:Rules = @(
        [pscustomobject]@{ Name = 'a work marker'; Rx = [regex]::new('\b(TODO|FIXME|HACK)\b') }
        [pscustomobject]@{ Name = 'another product''s internal defect id'; Rx = [regex]::new('\bBUG-\d+\b') }
        [pscustomobject]@{ Name = 'a way around a control'; Rx = [regex]::new('(?i)\b(bypass(es|ed|ing)?|circumvent(s|ed|ing)?|skip(s|ped|ping)|get(s|ting)? around|work(s|ed|ing)? around)\s+(the |a |an |this |that |any |our |its |their )?([\w-]+\s+)?(gate|guard|check|checks|signature|verification|approval|integrity|checksum|digest)\b') }
        [pscustomobject]@{ Name = 'a control described as gone around'; Rx = [regex]::new('(?i)\b(gate|guard|check|signature|verification|checksum|digest|safety rule)s?\s+(was |were |is |are |got |gets )?(bypassed|circumvented)\b|\bthat bypassed\b') }
        [pscustomobject]@{ Name = 'a named weakness'; Rx = [regex]::new('(?i)\b(loophole|backdoor|security (gap|hole)|known (hole|weakness)|gap in (the |our |its )?(check|guard|gate|validation|verification))\b') }
        [pscustomobject]@{ Name = 'an integrity value not checked'; Rx = [regex]::new('(?i)\b(checksum|digest|signature|sha-?256|hash)( check)?\s+(is |was |are |were )?(skipped|not (checked|verified))\b') }
    )
    function script:Get-SIWordingHits([string]$Line) {
        foreach ($r in $script:Rules) { foreach ($m in $r.Rx.Matches($Line)) { [pscustomobject]@{ Rule = $r.Name; Text = $m.Value } } }
    }

    # ---- the shipped set ----
    $pub = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'solution.publish.json')) | ConvertFrom-Json
    $script:Exclude = @($pub.excludePaths | ForEach-Object { ("$_" -replace '\\', '/').Trim('/') })
    $files = @()
    $git = Get-Command git -ErrorAction SilentlyContinue
    if ($git) {
        Push-Location $script:SIRoot
        try { $files = @(& git ls-files 2>$null | Where-Object { $_ }) } catch { $files = @() } finally { Pop-Location }
        $global:LASTEXITCODE = 0
    }
    $script:Source = 'git ls-files'
    if (-not $files.Count) {
        # not a git work tree: the files on disk, without build output
        $script:Source = 'the files on disk'
        $base = [IO.Path]::GetFullPath($script:SIRoot).TrimEnd('\', '/')
        $files = @(Get-ChildItem -LiteralPath $base -Recurse -File -Force | ForEach-Object { $_.FullName.Substring($base.Length + 1) -replace '\\', '/' } |
                   Where-Object { $_ -notmatch '(^|/)(bin|obj|node_modules|\.vs|TestResults|\.git)/' })
    }
    $topStrip = @('logs', 'output', 'staging', 'internal', 'demo', 'solution.publish.json', 'claude.md')
    $shared = '^(vendor/|engine/_shared/InvardiaUpdate\.verify\.ps1$)'
    $binary = '\.(png|jpg|jpeg|gif|ico|zip|dll|exe|pdb|woff2?|ttf|eot|pfx|cer|xlsx|docx|pptx|pdf|snk|nupkg|db|mdf|ldf|bak)$'
    $script:Shipped = @(foreach ($rel in $files) {
        $parts = $rel -split '/'
        if ($topStrip -contains $parts[0].ToLowerInvariant()) { continue }
        if (@($parts | Select-Object -SkipLast 1 | Where-Object { $_.ToLowerInvariant() -in @('internal', 'logs', 'staging', 'demo', 'output') }).Count) { continue }
        if ($parts[-1] -in @('REQUIREMENTS.md', 'TESTS.md', 'CLAUDE.md')) { continue }
        if ($parts[-1] -match '\.internal-(vm|azure)\.') { continue }
        if (@($script:Exclude | Where-Object { $rel -eq $_ -or $rel.StartsWith($_ + '/') }).Count) { continue }
        if ($rel -match $shared -or $rel -eq $script:SelfRel) { continue }
        if ($rel -match $binary) { continue }
        $rel
    })
}

Describe 'SEC-05: no shipped file describes a way around SecurityInsight''s own controls' {
    It 'the shipped set is found (README, release notes, the engine, setup, sql, the web app) and leaves out the internal docs and the Pro paths' {
        $script:Shipped.Count | Should -BeGreaterThan 500 -Because ('the Community payload from {0}' -f $script:Source)
        foreach ($must in 'README.md', 'RELEASENOTES.md', 'docs/DESIGN.md', 'setup/Install-SecurityInsight.Launcher.ps1', 'container/updater/Start-SIUpdater.ps1') { $script:Shipped | Should -Contain $must }
        foreach ($never in 'docs/REQUIREMENTS.md', 'docs/TESTS.md', 'CLAUDE.md', 'solution.publish.json') { $script:Shipped | Should -Not -Contain $never }
        @($script:Shipped | Where-Object { $_ -match '(?i)(^|/)internal/' }).Count | Should -Be 0
        # every Pro path of the manifest is left out
        $script:Exclude.Count | Should -BeGreaterThan 100
        @($script:Shipped | Where-Object { $s = $_; @($script:Exclude | Where-Object { $s -eq $_ -or $s.StartsWith($_ + '/') }).Count }).Count | Should -Be 0
    }
    It 'no shipped file has a work marker, another product''s defect id, or wording about a way around a control' {
        $hits = New-Object System.Collections.Generic.List[string]
        foreach ($rel in $script:Shipped) {
            $full = Join-Path $script:SIRoot ($rel -replace '/', [string][IO.Path]::DirectorySeparatorChar)
            if (-not [IO.File]::Exists($full)) { continue }
            $n = 0
            foreach ($line in [IO.File]::ReadAllLines($full)) {
                $n++
                foreach ($h in @(Get-SIWordingHits $line)) { $hits.Add(('{0}:{1} {2}: ''{3}''' -f $rel, $n, $h.Rule, $h.Text)) }
            }
        }
        ($hits | Select-Object -First 25) -join "`n" | Should -BeNullOrEmpty -Because ('{0} hit(s): describe the behaviour instead, without the hint' -f $hits.Count)
    }
    It 'the rules catch a planted marker, a defect id, a way around a gate, a skipped checksum, a bypassed guard and a backdoor' {
        foreach ($p in @('x # TODO the caller', 'see BUG-223', 'a path that bypassed the gate', 'it skips the checksum check', 'the guard was bypassed',
                         'one could bypass the signature verification', 'the digest is skipped', 'a backdoor', 'a gap in the check', 'getting around the approval')) {
            @(Get-SIWordingHits $p).Count | Should -BeGreaterThan 0 -Because $p
        }
    }
    It 'and lets SecurityInsight''s own product words pass (customer findings, status lines, Azure settings, the cadence skip gate)' {
        foreach ($p in @('Privileged users whose sign-ins bypass Conditional Access', 'Key Vault: bypass AzureServices', '-ExecutionPolicy Bypass',
                         'the job size was not checked (Login failed) -- the next update tries again', 'The application''s publisher is not verified',
                         'Tier-driven cadence (asset-profiling Stage Collect skip gate)', 'CVE-XXX => URL', 'a $todo list', 'unsigned drivers',
                         'a re-run checks the hash again', 'the download''s SHA-256 must match the release''s')) {
            @(Get-SIWordingHits $p).Count | Should -Be 0 -Because $p
        }
    }
}
