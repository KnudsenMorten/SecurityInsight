#Requires -Version 5.1
<#
.SYNOPSIS
    AUDIT #29 part 2 / #35 / #36 -- the rule-tree lint, and proof that it is wired
    to something.
.DESCRIPTION
    #29 part 2 was "nothing validates the one category of YAML a customer edits".
    Two mechanisms produced that:

      * The gate's YamlValidity globs *.locked.yaml + *.custom.sample.yaml. A
        customer's *.custom.yaml matches NEITHER pattern -- so it validated all
        550 shipped sample templates and none of the 8 real operator files.
      * engine/asset-profiling/lint/Test-SISchemaCompliance.ps1, the thing that
        exists to lint rules, iterated @('rules','rules-custom') -- two folders
        that have not existed since the rules moved to asset-profiling-enrichment/.
        Both Test-Path checks failed, it validated ZERO files and returned an
        empty violation list, i.e. it reported CLEAN. Nothing called it either.

    So the assertions here are deliberately about the DENOMINATOR as much as the
    verdict: an empty violation list means nothing unless you also know how many
    files produced it. That is #32's lesson (a check driven by a failure list
    disappears in the healthy case) applied to a linter instead of a Pester file.

    Blocking vs reporting -- the split is deliberate:
      * SHIPPED rules (*.locked.yaml) must be clean. They publish to the public
        mirror and to ~30 paying customers, so a violation there blocks.
      * LOCAL operator rules (*.custom.yaml) are gitignored and never ship. The
        operator recorded the decision explicitly while judging the 2.2.405 tag:
        the corrupted *.custom.yaml files are "operator data, not shipped code"
        and NOT a release blocker. So their CONTENT does not gate a publish --
        but their COVERAGE does, because being unseen is the #29 defect itself.
        Their content is surfaced where the operator actually looks: Get-SIRuleSet
        warns on every run (#29 parse failures, #36 zero-detection rules, #35
        unknown detect kinds), and `Test-SISchemaCompliance.ps1 -CustomOnly` is
        the on-demand check.
#>

BeforeAll {
    Import-Module powershell-yaml -Force
    # tests/pester/<file> -> tests/pester -> tests -> SecurityInsight
    $script:SiRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:LintPath = Join-Path $script:SiRoot 'engine\asset-profiling\lint\Test-SISchemaCompliance.ps1'
    . $script:LintPath
    $script:EnrichRoot = Join-Path $script:SiRoot 'asset-profiling-enrichment'

    $script:AllSummary    = Test-SISchemaCompliance -AsSummary
    $script:CustomSummary = Test-SISchemaCompliance -CustomOnly -AsSummary

    # The ground truth the lint is measured against -- globbed independently of
    # the lint, on purpose. If both used the same helper, a wrong glob would
    # agree with itself.
    $script:CustomOnDisk = @(Get-ChildItem -Path $script:EnrichRoot -Filter '*.custom.yaml' -Recurse -File -ErrorAction SilentlyContinue |
                             Where-Object { $_.FullName -notmatch '[\\/](OUTPUT|logs|staging)[\\/]' })

    # Spawn the lint with the SAME host that is running these tests, never a
    # hard-coded powershell.exe. CI installs Pester + powershell-yaml with
    # `-Scope CurrentUser` from `shell: pwsh`, which writes to
    # Documents\PowerShell\Modules -- a path Windows PowerShell 5.1 does not
    # look in. A hard-coded `powershell.exe` child therefore started without
    # powershell-yaml, the lint died on Import-Module, and its output contained
    # neither PASS nor FAIL. Green locally (gate runs under 5.1, module present
    # for 5.1), red on the runner. Locally this still resolves to 5.1 -- the
    # real engine runtime -- which is where the #37 defect actually lives.
    $script:HostExe = (Get-Process -Id $PID).Path
    if ([string]::IsNullOrWhiteSpace($script:HostExe)) { $script:HostExe = 'powershell.exe' }
    $script:LockedOnDisk = @(Get-ChildItem -Path $script:EnrichRoot -Filter '*.locked.yaml' -Recurse -File -ErrorAction SilentlyContinue |
                             Where-Object { $_.FullName -notmatch '[\\/](OUTPUT|logs|staging)[\\/]' })
}

Describe 'RuleSchemaCompliance' {

    Context 'the lint runs at all (#29 part 2 -- it did not)' {

        It 'scans a non-empty set of rule files (control -- a clean verdict over 0 files is not clean)' {
            $script:AllSummary.Scanned | Should -BeGreaterThan 0
        }

        It 'does not report the scanned-nothing violation' {
            @($script:AllSummary.Violations | Where-Object { $_.Rule -eq 'scanned-nothing' }) | Should -BeNullOrEmpty
        }

        It 'reports scanned-nothing when pointed at a tree with no rules (negative verification)' {
            $empty = Join-Path ([System.IO.Path]::GetTempPath()) ('si-lint-empty-' + [guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Path $empty -Force | Out-Null
            try {
                # RuleEval.ps1 is dot-sourced from the solution root, so the scratch
                # tree needs the engine folder; only the rule tree is absent.
                $engineDst = Join-Path $empty 'engine\asset-profiling\shared'
                New-Item -ItemType Directory -Path $engineDst -Force | Out-Null
                Copy-Item (Join-Path $script:SiRoot 'engine\asset-profiling\shared\RuleEval.ps1') $engineDst
                $v = Test-SISchemaCompliance -SolutionRoot $empty
                @($v | Where-Object { $_.Rule -eq 'scanned-nothing' }).Count | Should -Be 1
            } finally {
                Remove-Item $empty -Recurse -Force -ErrorAction SilentlyContinue
            }
        }

        It 'the lint file RUNS when invoked as a script, not just when dot-sourced' {
            # It used to only DEFINE a function: `.\Test-SISchemaCompliance.ps1`
            # printed nothing and returned nothing -- indistinguishable from clean.
            $out = & $script:HostExe -NoProfile -File $script:LintPath 2>&1 | Out-String
            $out | Should -Match 'PASS|FAIL'
        }
    }

    Context 'the printed VERDICT matches the violations found (#37)' {
        # `PASS|FAIL` above is satisfied by either word, so it passed all the
        # while the script printed PASS over a real violation. What made that
        # possible: `return $violations.ToArray()` holding ONE element is
        # unwrapped to a bare [pscustomobject], and .Count on one of those is
        # $null in PS 5.1 -- so `$result.Count -gt 0` was false. One violation
        # is the normal case for an operator repairing a rule, i.e. precisely
        # when this command is run. These cases assert the WORD, per count.

        BeforeAll {
            # A scratch solution root, so the assertions do not depend on how
            # many violations this machine's own rule tree happens to have.
            function script:New-LintScratchTree {
                param([int]$ViolatingRules, [int]$CleanRules)
                $root = Join-Path ([System.IO.Path]::GetTempPath()) ('si-lint-verdict-' + [guid]::NewGuid().ToString('N'))
                $shared = Join-Path $root 'engine\asset-profiling\shared'
                New-Item -ItemType Directory -Path $shared -Force | Out-Null
                Copy-Item (Join-Path $script:SiRoot 'engine\asset-profiling\shared\RuleEval.ps1') $shared
                $rules = Join-Path $root 'asset-profiling-enrichment\endpoint'
                New-Item -ItemType Directory -Path $rules -Force | Out-Null

                for ($i = 1; $i -le $CleanRules; $i++) {
                    $id = "ScratchClean$i"
                    @(
                        "id:        $id"
                        'appliesTo: endpoint'
                        'mode:      locked'
                        "purpose:   'Scratch fixture $i'"
                        "category:  'Scratch'"
                        'detections:'
                        '  - id: ScratchDetect'
                        '    detect:'
                        '      any:'
                        '        - kind: nameMatches'
                        '          namePatterns:'
                        "            - '(?i)^scratch\\d'"
                        '    set:'
                        '      Tier:     2'
                        "      Purpose:  'Scratch'"
                        "      Category: 'Scratch'"
                    ) | Set-Content -Path (Join-Path $rules "$id.locked.yaml") -Encoding UTF8
                }
                # The #36 shape exactly: parses, loads, ends at a bare
                # `detections:` -- one no-detections violation each.
                for ($i = 1; $i -le $ViolatingRules; $i++) {
                    $id = "ScratchBroken$i"
                    @(
                        "id:        $id"
                        'appliesTo: endpoint'
                        'mode:      locked'
                        "purpose:   'Scratch broken fixture $i'"
                        "category:  'Scratch'"
                        'detections:'
                    ) | Set-Content -Path (Join-Path $rules "$id.locked.yaml") -Encoding UTF8
                }
                return $root
            }
        }

        It 'prints FAIL for exactly ONE violation -- the count that used to print PASS' {
            $root = New-LintScratchTree -ViolatingRules 1 -CleanRules 2
            try {
                $out = & $script:HostExe -NoProfile -File $script:LintPath -SolutionRoot $root 2>&1 | Out-String
                $out | Should -Match 'FAIL: 1 violation'
                $out | Should -Not -Match 'PASS'
            } finally { Remove-Item $root -Recurse -Force -ErrorAction SilentlyContinue }
        }

        It 'prints FAIL for more than one violation' {
            $root = New-LintScratchTree -ViolatingRules 3 -CleanRules 1
            try {
                $out = & $script:HostExe -NoProfile -File $script:LintPath -SolutionRoot $root 2>&1 | Out-String
                $out | Should -Match 'FAIL: 3 violation'
            } finally { Remove-Item $root -Recurse -Force -ErrorAction SilentlyContinue }
        }

        It 'prints PASS only when there is genuinely nothing wrong' {
            $root = New-LintScratchTree -ViolatingRules 0 -CleanRules 2
            try {
                $out = & $script:HostExe -NoProfile -File $script:LintPath -SolutionRoot $root 2>&1 | Out-String
                $out | Should -Match 'PASS'
                $out | Should -Not -Match 'FAIL'
            } finally { Remove-Item $root -Recurse -Force -ErrorAction SilentlyContinue }
        }

        It 'states the DENOMINATOR on both verdicts, so clean-over-nothing cannot read as clean (#29 part 2)' {
            $root = New-LintScratchTree -ViolatingRules 0 -CleanRules 2
            try {
                $out = & $script:HostExe -NoProfile -File $script:LintPath -SolutionRoot $root 2>&1 | Out-String
                $out | Should -Match 'over 2 rule file\(s\)'
            } finally { Remove-Item $root -Recurse -Force -ErrorAction SilentlyContinue }

            $root2 = New-LintScratchTree -ViolatingRules 1 -CleanRules 1
            try {
                $out2 = & $script:HostExe -NoProfile -File $script:LintPath -SolutionRoot $root2 2>&1 | Out-String
                $out2 | Should -Match 'over 2 rule file\(s\)'
            } finally { Remove-Item $root2 -Recurse -Force -ErrorAction SilentlyContinue }
        }

        It 'negative verification -- the OLD expression is host-dependent, and the fix is not' {
            # Feeds the pre-fix comparison the exact shape it received, so the
            # defect cannot be reintroduced on the belief that .Count is safe.
            $single    = @([pscustomobject]@{ Rule = 'no-detections'; File = 'x'; Detail = 'y' })
            $unwrapped = & { return $single }          # what `return $arr.ToArray()` does to 1 element

            # The @() wrap holds on EVERY host -- that is the point of the fix.
            (@($unwrapped).Count -gt 0) | Should -BeTrue -Because 'the @() wrap is what makes the verdict correct on any host'

            if ($PSVersionTable.PSVersion.Major -le 5) {
                # Windows PowerShell 5.1 -- SI's real engine runtime, and the
                # local gate's host. .Count on a bare pscustomobject is $null,
                # so the old expression printed PASS over a real violation.
                ($unwrapped.Count -gt 0) | Should -BeFalse -Because '.Count is $null on a bare pscustomobject in PS 5.1 -- this IS the bug'
            } else {
                # PS 7+ (the CI runner's pwsh) added .Count on scalars, so the
                # old expression happens to be right here. That difference is
                # itself the finding: a verdict that depends on which host runs
                # it is not a verdict. Asserted rather than skipped, so the
                # divergence stays visible.
                ($unwrapped.Count -gt 0) | Should -BeTrue -Because 'PS 7+ masks the defect -- which is why offline-green under pwsh proved nothing about the 5.1 runtime'
            }
        }
    }

    Context 'shipped SAMPLES must be clean -- customers are instructed to copy them (#38)' {
        # The lint's allow-list used to be *.custom.yaml + *.locked.yaml, i.e.
        # what the ENGINE loads. Samples load nowhere, so nothing checked them --
        # while every one of them ships to the public mirror and to paying
        # customers as the file to copy. One shipped example set a field no schema
        # defines and no code reads, and set neither Tier nor any cmdb* field, so
        # following it produced a rule that matched assets and did nothing.
        # #29 skipped the files customers EDIT; this skipped the files they COPY.

        BeforeAll {
            $script:SamplesOnDisk = @(Get-ChildItem -Path $script:EnrichRoot -Filter '*.custom.sample.yaml' -Recurse -File -ErrorAction SilentlyContinue |
                                      Where-Object { $_.FullName -notmatch '[\\/](OUTPUT|logs|staging)[\\/]' })
        }

        It 'finds shipped *.custom.sample.yaml templates on disk' {
            $script:SamplesOnDisk.Count | Should -BeGreaterThan 0
        }

        It 'the lint SEES every shipped sample -- being unseen is the whole defect' {
            foreach ($f in $script:SamplesOnDisk) {
                $script:AllSummary.ScannedNames | Should -Contain $f.Name
            }
        }

        It 'no violations in any shipped *.custom.sample.yaml (BLOCKING -- these publish)' {
            $bad = @($script:AllSummary.Violations | Where-Object { $_.File -like '*.custom.sample.yaml' })
            $detail = ($bad | ForEach-Object { '{0}: {1}' -f $_.Rule, (Split-Path -Leaf $_.File) }) -join ' | '
            $bad | Should -BeNullOrEmpty -Because "a broken sample propagates by instruction: $detail"
        }

        It 'a broken sample IS caught (negative verification -- else this context proves nothing)' {
            # Reproduces #38 exactly: a detection setting neither Tier nor any
            # cmdb* field. Before samples were in the allow-list this returned 0.
            $root = Join-Path ([System.IO.Path]::GetTempPath()) ('si-lint-sample-' + [guid]::NewGuid().ToString('N'))
            $shared = Join-Path $root 'engine\asset-profiling\shared'
            New-Item -ItemType Directory -Path $shared -Force | Out-Null
            Copy-Item (Join-Path $script:SiRoot 'engine\asset-profiling\shared\RuleEval.ps1') $shared
            $rules = Join-Path $root 'asset-profiling-enrichment\endpoint'
            New-Item -ItemType Directory -Path $rules -Force | Out-Null
            try {
                @(
                    'id:        ScratchSample'
                    'appliesTo: endpoint'
                    'mode:      append'
                    "purpose:   'Scratch sample fixture'"
                    "category:  'Scratch'"
                    'detections:'
                    '  - id: NoTierNoCmdb'
                    '    detect:'
                    '      any:'
                    '        - kind: nameMatches'
                    '          namePatterns:'
                    "            - '(?i)^scratch\\d'"
                    '    set:'
                    '      someFieldNobodyReads: true'
                ) | Set-Content -Path (Join-Path $rules 'ScratchSample.custom.sample.yaml') -Encoding UTF8
                $v = @(Test-SISchemaCompliance -SolutionRoot $root)
                @($v | Where-Object { $_.Rule -eq 'no-tier-or-cmdb' }).Count | Should -Be 1
            } finally { Remove-Item $root -Recurse -Force -ErrorAction SilentlyContinue }
        }

        It 'the annotated _TEMPLATE is exempt from id==filename only, not from the other checks' {
            # Its id is a deliberate placeholder so the filename can never match,
            # but it is the most-copied file in the tree, so everything else applies.
            $tpl = @($script:SamplesOnDisk | Where-Object { $_.BaseName -like '_TEMPLATE*' })
            $tpl.Count | Should -BeGreaterThan 0 -Because 'the grammar-reference template must exist'
            @($script:AllSummary.Violations | Where-Object { $_.File -like '*_TEMPLATE*' }) | Should -BeNullOrEmpty
        }
    }

    Context 'shipped rules must be clean (they publish to the mirror and ~30 customers)' {

        It 'finds shipped *.locked.yaml rules on disk' {
            $script:LockedOnDisk.Count | Should -BeGreaterThan 0
        }

        It 'no violations in any shipped *.locked.yaml' {
            $shipped = @($script:AllSummary.Violations | Where-Object { $_.File -like '*.locked.yaml' })
            $detail  = ($shipped | ForEach-Object { '{0}: {1}' -f $_.Rule, (Split-Path -Leaf $_.File) }) -join ' | '
            $shipped | Should -BeNullOrEmpty -Because "shipped rules must lint clean: $detail"
        }
    }

    Context 'local operator rules are COVERED even though their content does not block (#29 part 2)' {

        It 'the lint sees every *.custom.yaml on disk -- the gap #29 was made of' {
            # The gate's YamlValidity glob (*.locked.yaml + *.custom.sample.yaml)
            # matches none of these. If this count ever drops below what is on
            # disk, the linter has gone blind the same way again.
            $script:CustomSummary.Scanned | Should -Be $script:CustomOnDisk.Count
        }

        It 'scans customer files by NAME, so a renamed or moved rule cannot slip out of coverage' {
            foreach ($f in $script:CustomOnDisk) {
                $script:CustomSummary.ScannedNames | Should -Contain $f.Name
            }
        }

        It 'reports local rule violations rather than swallowing them (content is the operator''s call, not a publish blocker)' {
            $local = @($script:CustomSummary.Violations)
            if ($local.Count -gt 0) {
                # Loud, named, and never silent -- but not a gate failure: these
                # files are gitignored and never reach a customer.
                Write-Warning ('LOCAL rule violations (do NOT block publish, DO block correct classification on this host): ' +
                    (($local | ForEach-Object { '{0} in {1}' -f $_.Rule, (Split-Path -Leaf $_.File) }) -join ', '))
            }
            # The assertion is that the lint produced an answer about these files
            # at all -- a summary object over a known denominator.
            $script:CustomSummary | Should -Not -BeNullOrEmpty
            $script:CustomSummary.Scanned | Should -BeGreaterOrEqual 0
        }
    }
}
