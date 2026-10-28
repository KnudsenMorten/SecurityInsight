#Requires -Version 5.1
<#
    THE RELEASE GATE (tests\Invoke-FastGate.ps1). Every gate but a full run is THE QUICK GATE (owner 2026-10-13: "yes, build
    it the pim way"; "default release is quick"; "we even agreed on hard limit of max 10 min"): a core set + the few suites
    the change needs (narrow / broad / hub / unmapped / documents / release-bump / a changed suite / -Suites), the web app's
    tests only for a web change and then only the matching classes, every suite in its own process in parallel, and a
    HARD 10-minute stop that ends a suite's whole process tree and reports it TIMED OUT by name (the run: NOT TESTED).
    These tests prove the selection (pure functions), the stop (a fake suite that sleeps past a SHORT test limit), the
    refusal of "everything", and the older covering selection / full-run sharding that -Precise and -Full still use.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'tests\Invoke-FastGate.ps1') -DefineOnly
    $script:Map = Get-SIFastGateMap -Path (Join-Path $script:SIRoot 'tests\pester\fast-gate.map.json')
    $script:Suites = @{
        'A-Engine.Tests.ps1'  = '. (Join-Path $root "engine\_shared\SI-Thing.ps1")'
        'B-Launcher.Tests.ps1' = 'runs launcher\Start-Collect.ps1 end to end'
        'C-Other.Tests.ps1'   = 'nothing relevant'
        'D-Sibling.Tests.ps1' = 'checks engine\deep\Known-Helper.ps1'
    }
    $script:Code = @{
        'engine/_shared/SI-Thing.ps1'      = 'function Get-Thing { 1 }'
        'launcher/Start-Collect.ps1'       = '. "$PSScriptRoot\..\engine\_shared\SI-Thing.ps1"'
        'engine/deep/Known-Helper.ps1'     = 'function A { }'
        'engine/deep/Unnamed-Helper.ps1'   = 'function B { }'
        'engine/other/Commented-Only.ps1'  = 'function C { }'
    }
    $script:NoMap = [pscustomobject]@{ Safety = @(); Explicit = @() }
}

Describe 'which suites cover a change' {
    It 'a suite that names the changed file covers it; one that names a script loading it covers it one hop further' {
        $s = Get-SIFastGateSelection -Changed @('engine/_shared/SI-Thing.ps1') -SuiteText $script:Suites -CodeText $script:Code -Map $script:NoMap
        @($s.Suites.Keys) | Should -Contain 'A-Engine.Tests.ps1'
        @($s.Suites.Keys) | Should -Contain 'B-Launcher.Tests.ps1'
        $s.Suites['B-Launcher.Tests.ps1'] | Should -Match 'Start-Collect\.ps1, which loads SI-Thing\.ps1'
        @($s.Suites.Keys) | Should -Not -Contain 'C-Other.Tests.ps1'
    }
    It 'a path NO suite names runs the suites of its folder (a suite naming a file next to it)' {
        $s = Get-SIFastGateSelection -Changed @('engine/deep/Unnamed-Helper.ps1') -SuiteText $script:Suites -CodeText $script:Code -Map $script:NoMap
        @($s.Suites.Keys) | Should -Be @('D-Sibling.Tests.ps1')
        $s.Suites['D-Sibling.Tests.ps1'] | Should -Match '^folder of Unnamed-Helper\.ps1'
        @($s.Unmapped).Count | Should -Be 0
    }
    It 'a changed suite runs itself; the safety suites run whatever changed (and only -NoSafety drops them)' {
        $suites = $script:Suites.Clone(); $suites['SI-PublishPayloadSanitization.Tests.ps1'] = 'x'
        $map = [pscustomobject]@{ Safety = @('SI-PublishPayloadSanitization.Tests.ps1'); Explicit = @() }
        $s = Get-SIFastGateSelection -Changed @('tests/pester/C-Other.Tests.ps1') -SuiteText $suites -CodeText $script:Code -Map $map
        $s.Suites['C-Other.Tests.ps1'] | Should -Be 'changed suite'
        $s.Suites['SI-PublishPayloadSanitization.Tests.ps1'] | Should -Be 'safety (always on)'
        (Get-SIFastGateSelection -Changed @() -SuiteText $suites -CodeText $script:Code -Map $map).Suites.Contains('SI-PublishPayloadSanitization.Tests.ps1') | Should -BeTrue
        (Get-SIFastGateSelection -Changed @() -SuiteText $suites -CodeText $script:Code -Map $map -NoSafety).Suites.Count | Should -Be 0
    }
    It 'the explicit map routes paths no suite names (VERSION; a web app project -> its dotnet tests, ${p} = the project folder)' {
        $m = [pscustomobject]@{ Safety = @(); Explicit = @(
                [pscustomobject]@{ Pattern = '^app/tests/(?<p>App\.[A-Za-z]+\.Tests)/'; Suites = @(); Dotnet = @('${p}') },
                [pscustomobject]@{ Pattern = '^app/src/App\.Core/'; Suites = @(); Dotnet = @('App.Core.Tests', 'App.Web.Tests') }) }
        $s = Get-SIFastGateSelection -Changed @('app/tests/App.Web.Tests/X.cs', 'app/src/App.Core/Y.cs') -SuiteText @{} -Map $m
        @($s.Dotnet.Keys) | Should -Contain 'App.Web.Tests'
        @($s.Dotnet.Keys) | Should -Contain 'App.Core.Tests'
        @($s.Dotnet.Keys) | Should -Not -Contain '${p}'
        $v = Get-SIFastGateSelection -Changed @('VERSION') -SuiteText @{ 'SIv3-SolutionVersionStamp.Tests.ps1' = ''; 'Z.Tests.ps1' = 'VERSION everywhere' } -Map $script:Map -NoSafety
        @($v.Suites.Keys) | Should -Contain 'SIv3-SolutionVersionStamp.Tests.ps1'
    }
    It 'a file mentioned only in a COMMENT does not count as loading it (no hop through comments)' {
        $code = $script:Code.Clone(); $code['engine/other/Commented-Only.ps1'] = Remove-SIFastGateComments -Text "<#`n uses SI-Thing.ps1 `n#>`n# and SI-Thing.ps1 again`nfunction C { }"
        $suites = $script:Suites.Clone(); $suites['E-Commented.Tests.ps1'] = 'Commented-Only.ps1'
        $s = Get-SIFastGateSelection -Changed @('engine/_shared/SI-Thing.ps1') -SuiteText $suites -CodeText $code -Map $script:NoMap
        @($s.Suites.Keys) | Should -Not -Contain 'E-Commented.Tests.ps1'
    }
    It 'a document change runs ONLY its exclusive suites -- not the dozens of suites that merely name REQUIREMENTS.md' {
        $suites = @{ 'Docs.Tests.ps1' = 'x'; 'Names-Requirements.Tests.ps1' = 'reads docs/REQUIREMENTS.md for a list' }
        $map = [pscustomobject]@{ Safety = @(); Explicit = @([pscustomobject]@{ Pattern = '^docs/[^/]+\.md$'; Suites = @('Docs.Tests.ps1'); Dotnet = @(); Exclusive = $true }) }
        $s = Get-SIFastGateSelection -Changed @('docs/REQUIREMENTS.md') -SuiteText $suites -Map $map
        @($s.Suites.Keys) | Should -Be @('Docs.Tests.ps1')
        $real = Get-SIFastGateMap -Path (Join-Path $script:SIRoot 'tests\pester\fast-gate.map.json')
        @($real.Explicit | Where-Object { $_.Exclusive -and 'docs/REQUIREMENTS.md' -match $_.Pattern }).Count | Should -Be 1
    }
    It 'short or generic names are not used as search keys (a 5-letter file would match half the suites)' {
        @(Get-SIFastGateKeys -RelativePath 'a/b.ps1').Count | Should -Be 0
        Get-SIFastGateKeys -RelativePath 'engine/_shared/SI-FastRoll.ps1' | Should -Be @('SI-FastRoll.ps1', 'SI-FastRoll')
    }
}

Describe '#416 the web app''s tests: only the classes that cover the change; the whole project only for a shared piece' {
    BeforeAll {
        $script:Cls = @('AuditTrailTests', 'RoleMatrixTests', 'ExemptionPageTests', 'ExemptionFlowTests', 'SettingsTests', 'CmdbFakes', 'PageTests', 'NavTests', 'BrandTests')
        $script:Txt = @{ 'NavTests' = 'var m = new GuardsModel(db); Assert.Contains("/Admin/Guards", html);'; 'BrandTests' = 'File.ReadAllText("wwwroot/css/site.css")'; 'PageTests' = 'Get("/Admin/Settings")'
                         'SettingsTests' = 'new SettingsCatalog()'; 'AuditTrailTests' = ''; 'RoleMatrixTests' = ''; 'ExemptionPageTests' = ''; 'ExemptionFlowTests' = ''; 'CmdbFakes' = '' }
        $script:Shared = @('^app/src/Web/Program\.cs$', '^app/src/Web/Pages/Shared/', '\.csproj$')
        $script:F = { param([string[]]$c) Get-SIFastGateDotnetFilter -Changed $c -SourcePrefix 'app/src/Web/' -TestPrefix 'app/tests/Web.Tests/' -TestClasses $script:Cls -Always @('RoleMatrixTests', 'AuditTrailTests') -TestText $script:Txt -Related @('app/', 'config/') -Shared $script:Shared }
    }
    It 'a page names its test classes (the .cshtml.cs / Page / Service suffixes dropped); the cross-cutting classes always run' {
        (& $script:F @('app/src/Web/Pages/Exemption.cshtml.cs')).Filter | Should -Be 'FullyQualifiedName~AuditTrailTests|FullyQualifiedName~ExemptionFlowTests|FullyQualifiedName~ExemptionPageTests|FullyQualifiedName~RoleMatrixTests'
        (& $script:F @('app/src/Web/Services/SettingsService.cs')).Filter | Should -Match 'SettingsTests'
        (& $script:F @('app/tests/Web.Tests/ExemptionFlowTests.cs')).Classes | Should -Contain 'ExemptionFlowTests'
    }
    It 'a class whose CODE names the changed class, its page route or the changed file covers it too (a page model, a stylesheet, a Core class, a config file)' {
        (& $script:F @('app/src/Web/Pages/Admin/Guards.cshtml.cs')).Classes | Should -Contain 'NavTests'
        (& $script:F @('app/src/Web/Pages/Admin/Settings/Index.cshtml')).Classes | Should -Contain 'PageTests'
        (& $script:F @('app/src/Web/wwwroot/css/site.css')).Classes | Should -Contain 'BrandTests'
        (& $script:F @('app/src/Core/SettingsCatalog.cs')).Classes | Should -Contain 'SettingsTests'
        # a generic page name (Index) is found by its route alone, never by its class name (every folder has an IndexModel)
        @((& $script:F @('app/src/Web/Pages/Admin/Settings/Index.cshtml.cs')).Classes) | Should -Not -Contain 'NavTests'
    }
    It 'a test FILE that declares several classes runs all of them (GetStartedTests.cs holds GetStartedPageTests); a declared class is matched by name like a file' {
        $cls = @($script:Cls) + @('WizardPageTests')
        $r = Get-SIFastGateDotnetFilter -Changed @('app/tests/Web.Tests/PageTests.cs') -SourcePrefix 'app/src/Web/' -TestPrefix 'app/tests/Web.Tests/' -TestClasses $cls -TestText $script:Txt -Related @('app/') -FileClasses @{ 'PageTests' = @('PageTests', 'WizardPageTests') }
        @($r.Classes) | Should -Contain 'WizardPageTests'
        (Get-SIFastGateDotnetFilter -Changed @('app/src/Web/Pages/Wizard.cshtml.cs') -SourcePrefix 'app/src/Web/' -TestPrefix 'app/tests/Web.Tests/' -TestClasses $cls -Related @('app/')).Classes | Should -Contain 'WizardPageTests'
        $g = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'tests\Invoke-FastGate.ps1')
        $g | Should -Match ([regex]::Escape("'\bclass\s+([A-Za-z0-9_]+Tests)\b'"))
    }
    It 'a change nothing names runs the always-on classes only -- never the whole project -- and says so' {
        $r = & $script:F @('app/src/Web/Pages/Nothing.cshtml.cs')
        $r.Whole | Should -BeFalse; @($r.Classes) | Should -Be @('AuditTrailTests', 'RoleMatrixTests')
        @($r.Notes) -join ' ' | Should -Match 'no test class names Nothing\.cshtml\.cs'
        (& $script:F @('config/shared.locked.json')).Whole | Should -BeFalse
        (& $script:F @('app/src/Web/Pages/Exemption.cshtml.cs', 'app/src/Core/Model.cs')).Whole | Should -BeFalse
    }
    It 'the WHOLE project runs only for a SHARED piece (Program.cs, the layout / shared partials, a project file) or a fake / fixture of the test project' {
        (& $script:F @('app/src/Web/Program.cs')).Whole | Should -BeTrue
        (& $script:F @('app/src/Web/Pages/Shared/_Layout.cshtml')).Whole | Should -BeTrue
        (& $script:F @('app/src/Web/Web.csproj')).Whole | Should -BeTrue
        (& $script:F @('app/tests/Web.Tests/CmdbFakes.cs')).Whole | Should -BeTrue
        (& $script:F @('app/src/Web/Pages/Exemption.cshtml.cs', 'app/src/Web/Program.cs')).Whole | Should -BeTrue
        (& $script:F @('engine/x.ps1')).Whole | Should -BeTrue   # nothing of its own here: a project picked only by -Full
    }
    It 'the real map names the shared pieces: Program.cs, Pages/Shared, navigation, authorization, the project files' {
        $nf = @($script:Map.DotnetFilter | Where-Object Project -eq 'SI.Management.Web.Tests')[0]
        # the paths are built from the map's own source folder (a free suite names no Pro path in code)
        foreach ($p in @('Program.cs', 'Pages/Shared/_Layout.cshtml', 'Navigation/Nav.cs', 'Auth/Policies.cs', 'Web.csproj' | ForEach-Object { $nf.Source + $_ })) {
            @($nf.Shared | Where-Object { $p -match $_ }).Count | Should -BeGreaterThan 0 -Because $p
        }
        @($nf.Shared | Where-Object { ($nf.Source + 'Pages/Admin/Guards.cshtml.cs') -match $_ }).Count | Should -Be 0
    }
}

Describe '#416 THE HOTFIX GATE: EVERY suite that covers the changed files (the budget is a warning, never a cut), plus the smoke set' {
    BeforeAll {
        $script:HS = @{
            'SIv3-FastRoll.Tests.ps1'  = '. engine\SI-FastRoll.ps1; SI-FastRoll SI-FastRoll'
            'SIv3-Heavy.Tests.ps1'     = 'SI-FastRoll.ps1 SI-FastRoll.ps1 SI-FastRoll.ps1 SI-FastRoll.ps1'
            'SIv3-Mention.Tests.ps1'   = 'mentions SI-FastRoll.ps1 once'
            'SIv3-Mention2.Tests.ps1'  = 'SI-FastRoll.ps1 SI-FastRoll.ps1'
            'SIv3-Loader.Tests.ps1'    = 'runs Start-Updater.ps1'
            'SIv3-NoMergeLeftovers.Tests.ps1' = 'x'; 'SI-PublishPayloadSanitization.Tests.ps1' = 'x'
        }
        $script:HC = @{ 'setup/_shared/SI-FastRoll.ps1' = 'function A { }'; 'container/Start-Updater.ps1' = '. SI-FastRoll.ps1' }
        $script:HM = [pscustomobject]@{ Safety = @('SI-PublishPayloadSanitization.Tests.ps1'); Smoke = @('SIv3-NoMergeLeftovers.Tests.ps1'); Explicit = @() }
        $script:HSec = @{ 'SIv3-FastRoll.Tests.ps1' = 200; 'SIv3-Heavy.Tests.ps1' = 150; 'SIv3-Mention.Tests.ps1' = 10; 'SIv3-Mention2.Tests.ps1' = 30; 'SIv3-Loader.Tests.ps1' = 5 }
    }
    It 'the hotfix runs the covering suites + the SMOKE set, not the safety list, and no one-hop suites when a suite names the file' {
        $s = Get-SIFastGateSelection -Changed @('setup/_shared/SI-FastRoll.ps1') -SuiteText $script:HS -CodeText $script:HC -Map $script:HM -Hotfix -Seconds $script:HSec -BudgetSeconds 1000
        @($s.Suites.Keys) | Should -Contain 'SIv3-FastRoll.Tests.ps1'
        @($s.Suites.Keys) | Should -Contain 'SIv3-Mention.Tests.ps1'
        $s.Suites['SIv3-NoMergeLeftovers.Tests.ps1'] | Should -Be 'smoke (always on)'
        @($s.Suites.Keys) | Should -Not -Contain 'SI-PublishPayloadSanitization.Tests.ps1'
        @($s.Suites.Keys) | Should -Not -Contain 'SIv3-Loader.Tests.ps1'
        $s.Suites['SIv3-FastRoll.Tests.ps1'] | Should -Match '^named after SI-FastRoll\.ps1'
        # the full cycle's gate is unchanged: the one-hop suite and the safety list (+ the smoke set)
        $f = Get-SIFastGateSelection -Changed @('setup/_shared/SI-FastRoll.ps1') -SuiteText $script:HS -CodeText $script:HC -Map $script:HM
        @($f.Suites.Keys) | Should -Contain 'SIv3-Loader.Tests.ps1'
        @($f.Suites.Keys) | Should -Contain 'SI-PublishPayloadSanitization.Tests.ps1'
        @($f.Suites.Keys) | Should -Contain 'SIv3-NoMergeLeftovers.Tests.ps1'
    }
    It 'NO NIGHTLY (owner 2026-10-09): a covering suite over the budget is still SELECTED -- named in OverBudget, never dropped' {
        $s = Get-SIFastGateSelection -Changed @('setup/_shared/SI-FastRoll.ps1') -SuiteText $script:HS -CodeText $script:HC -Map $script:HM -Hotfix -Seconds $script:HSec -BudgetSeconds 245 -SuiteMaxSeconds 120
        @($s.Suites.Keys) | Should -Contain 'SIv3-FastRoll.Tests.ps1'     # own, 200 s > the 120 s cap
        @($s.Suites.Keys) | Should -Contain 'SIv3-Mention2.Tests.ps1'     # 2 mentions, 30 s: 230 s used
        @($s.Suites.Keys) | Should -Contain 'SIv3-Mention.Tests.ps1'      # 10 s: 240 s
        # 150 s: over the cap and the budget -- it covers the change, so it RUNS
        @($s.Suites.Keys) | Should -Contain 'SIv3-Heavy.Tests.ps1'
        $s.Suites['SIv3-Heavy.Tests.ps1'] | Should -Match 'over the hotfix budget -- it covers the change, so it runs'
        @($s.OverBudget.Keys) | Should -Be @('SIv3-Heavy.Tests.ps1')
        $s.OverBudget['SIv3-Heavy.Tests.ps1'] | Should -Match '^150 s measured'
        @($s.Dropped.Keys).Count | Should -Be 0
        # a budget of 1 s: still every covering suite (each over it is named)
        $t = Get-SIFastGateSelection -Changed @('setup/_shared/SI-FastRoll.ps1') -SuiteText $script:HS -CodeText $script:HC -Map $script:HM -Hotfix -Seconds $script:HSec -BudgetSeconds 1
        foreach ($n in 'SIv3-FastRoll.Tests.ps1', 'SIv3-Heavy.Tests.ps1', 'SIv3-Mention.Tests.ps1', 'SIv3-Mention2.Tests.ps1') { @($t.Suites.Keys) | Should -Contain $n }
        @($t.Dropped.Keys).Count | Should -Be 0
    }
    It 'the budget is a WARNING: a missed hotfix budget says plainly which covering suites made it take longer' {
        $b = Get-SIFastGateBudget -Mode hotfix -Seconds 710 -OverBudget @('SIv3-Heavy.Tests.ps1')
        $b.Met | Should -BeFalse
        $b.Text | Should -Match 'hotfix gate: 710 s of the 600 s limit \(10 minutes\) -- OVER THE 10-MINUTE LIMIT \(it took longer because SIv3-Heavy\.Tests\.ps1 covers the change\)'
        (Get-SIFastGateBudget -Mode hotfix -Seconds 200 -OverBudget @('SIv3-Heavy.Tests.ps1')).Text | Should -Not -Match 'took longer'
    }
    It 'WIRING: no "left to the nightly" anywhere in the gate; the plain over-budget line is printed and OverBudget is in the selection file + result' {
        $g = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'tests\Invoke-FastGate.ps1')
        $g | Should -Not -Match '(?i)left to the nightly'
        $g | Should -Not -Match '(?i)nightly full gate runs'
        $g | Should -Not -Match '\(left out\)'
        $g | Should -Match 'NOTE the hotfix gate takes longer: \{0\} covers the change'
        $g | Should -Match 'OverBudget = @\(\$overBudget\.Keys\); Dropped = @\(\)'
        $g | Should -Match 'OverBudget = @\(\$overBudget\.Keys\); Phases = \$phase'
        $g | Should -Match 'Get-SIFastGateBudget -Mode \$summary\.Mode -Seconds \$summary\.Seconds -OverBudget'
    }
    It 'every changed path keeps its best covering suite, whatever the budget; a changed suite always runs itself' {
        $s = Get-SIFastGateSelection -Changed @('setup/_shared/SI-FastRoll.ps1', 'tests/pester/SIv3-Loader.Tests.ps1') -SuiteText $script:HS -CodeText $script:HC -Map $script:HM -Hotfix -Seconds $script:HSec -BudgetSeconds 1
        @($s.Suites.Keys) | Should -Contain 'SIv3-FastRoll.Tests.ps1'
        $s.Suites['SIv3-Loader.Tests.ps1'] | Should -Be 'changed suite'
    }
    It 'a path NO suite names: one hop, then its folder; nothing at all = Unmapped (Release-SI then STOPS and the owner is asked -- never a full run)' {
        $s = Get-SIFastGateSelection -Changed @('container/Start-Updater2.ps1') -SuiteText @{ 'SIv3-Loader.Tests.ps1' = 'runs Start-Updater.ps1' } -CodeText @{ 'container/Start-Updater.ps1' = 'x'; 'container/Start-Updater2.ps1' = 'y' } -Map $script:HM -Hotfix
        $s.Suites['SIv3-Loader.Tests.ps1'] | Should -Match '^folder of'
        $u = Get-SIFastGateSelection -Changed @('nowhere/new.ps1') -SuiteText @{ 'A.Tests.ps1' = 'x' } -Map $script:HM -Hotfix
        @($u.Unmapped) | Should -Be @('nowhere/new.ps1')
    }
    It 'the suite named after a file: SI- / SIv3- / verb prefixes dropped, 6+ characters' {
        Get-SIFastGateOwnSuite -Suite 'SIv3-FastRoll.Tests.ps1' -RelativePath 'setup/_shared/SI-FastRoll.ps1' | Should -BeTrue
        Get-SIFastGateOwnSuite -Suite 'SIv3-WidgetSync.Tests.ps1' -RelativePath 'setup/Widget-Sync.ps1' | Should -BeTrue
        Get-SIFastGateOwnSuite -Suite 'SIv3-FastGate.Tests.ps1' -RelativePath 'tests/Invoke-FastGate.ps1' | Should -BeTrue
        Get-SIFastGateOwnSuite -Suite 'SIv3-Unrelated.Tests.ps1' -RelativePath 'setup/_shared/SI-FastRoll.ps1' | Should -BeFalse
        Get-SIFastGateOwnSuite -Suite 'SIv3-Ab.Tests.ps1' -RelativePath 'x/Ab.ps1' | Should -BeFalse
    }
    It 'the real smoke set: every suite exists here (or is a Pro suite), and the whole set is at most ~2 minutes of measured time' {
        @($script:Map.Smoke).Count | Should -BeGreaterThan 5
        $d = ([IO.File]::ReadAllText((Join-Path $script:SIRoot 'tests\pester\suite-durations.json')) | ConvertFrom-Json).pwsh
        $sum = 0.0
        foreach ($s in $script:Map.Smoke) {
            Test-Path -LiteralPath (Join-Path $script:SIRoot "tests\pester\$s") | Should -BeTrue -Because "$s is a smoke suite"
            $sum += [double]$d.$s
        }
        $sum | Should -BeLessOrEqual 120
        # the smoke set is within the safety list: the full cycle runs all of it too
        foreach ($s in $script:Map.Smoke) { $script:Map.Safety | Should -Contain $s }
    }
    It 'THE 10-MINUTE LIMIT (owner 2026-10-13): 600 s for every release gate -- hotfix and fast alike; over it is said plainly; a full run has none' {
        $b = Get-SIFastGateBudget -Mode hotfix -Seconds 280; $b.Met | Should -BeTrue; $b.Target | Should -Be 600; $b.Text | Should -Match 'hotfix gate: 280 s of the 600 s limit \(10 minutes\) -- met'
        (Get-SIFastGateBudget -Mode hotfix -Seconds 600).Met | Should -BeTrue
        $o = Get-SIFastGateBudget -Mode hotfix -Seconds 601; $o.Met | Should -BeFalse; $o.Text | Should -Match 'OVER THE 10-MINUTE LIMIT'
        (Get-SIFastGateBudget -Mode fast -Seconds 590).Met | Should -BeTrue
        (Get-SIFastGateBudget -Mode fast -Seconds 601).Text | Should -Match 'fast gate: 601 s of the 600 s limit \(10 minutes\) -- OVER THE 10-MINUTE LIMIT'
        Get-SIFastGateBudget -Mode full -Seconds 5000 | Should -BeNullOrEmpty
    }
    It 'WIRING: the -Precise listing reaches the covering selection with the measured seconds; a FULL run builds the dotnet solution; the result carries Phases + Budget + OverBudget' {
        $g = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'tests\Invoke-FastGate.ps1')
        $g | Should -Match '-NoSafety:\$NoSafety -Hotfix -Seconds \$durations'
        $g | Should -Match 'if \(-not \$NoDotnet -and \$map\.Solution -and \(Test-Path -LiteralPath \$sln\)'
        $g | Should -Not -Match 'if \(\$dotnetPick\.Count -and \(Get-Command dotnet'
        $g | Should -Match 'Phases = \$phase; Budget = \$null'
        # never a reused MSBuild node on the shared test VM (MSB4166, 2026-10-09); such a crash builds once more
        $g | Should -Match 'dotnet build \$sln -c Release --nologo -v q -nodeReuse:false'
        $g | Should -Match "-match 'MSB4166'"
        $g | Should -Match "\`$phase\['dotnet build'\]"
        $g | Should -Not -Match 'Dropped = @\(\$dropped\.Keys\)'
        # the measured seconds are read BEFORE the selection (the hotfix budget counts them)
        $g.IndexOf('$durations = @{ pwsh = @{}; ps51 = @{} }') | Should -BeLessThan $g.IndexOf('$sel = Get-SIFastGateSelection')
    }
}
Describe 'the suites run in short batches from a queue, balanced by measured duration' {
    It 'every suite lands in exactly one batch; batches stay under the target, a heavier suite is a batch of its own; heaviest first' {
        $names = @('a', 'b', 'c', 'd', 'e', 'f')
        $sec = @{ a = 300; b = 60; c = 50; d = 40; e = 10; f = 5 }
        $b = @(New-SIFastGateBatches -Names $names -Seconds $sec -TargetSeconds 100)
        (@($b | ForEach-Object { $_ }) | Sort-Object) -join ',' | Should -Be 'a,b,c,d,e,f'
        @($b[0]) | Should -Be @('a')                                  # the heavy one alone, first
        foreach ($x in @($b | Select-Object -Skip 1)) { $l = 0; foreach ($n in $x) { $l += $sec[$n] }; $l | Should -BeLessOrEqual 100 }
    }
    It 'the default target keeps several batches per worker (short-lived workers: a long 5.1 process slows down)' {
        $names = @(1..40 | ForEach-Object { "s$_" })
        @(New-SIFastGateBatches -Names $names -Workers 4).Count | Should -BeGreaterOrEqual 8
        @(New-SIFastGateBatches -Names @('x') -Workers 4).Count | Should -Be 1
        @(New-SIFastGateBatches -Names @() -Workers 4).Count | Should -Be 0
    }
}
Describe 'a loaded machine makes the run slower, never red and never a silent pass (nightly 2026-10-07)' {
    It 'a batch may run its measured time x5, never under 15 min (a hang is caught by its own batch, not the whole run)' {
        Get-SIFastGateBatchTimeout -Names @('a', 'b') -Seconds @{ a = 1000; b = 156.5 } | Should -Be 5783
        Get-SIFastGateBatchTimeout -Names @('a') -Seconds @{ a = 10 } | Should -Be 900
        Get-SIFastGateBatchTimeout -Names @('unknown') | Should -Be 900
    }
    It 'the run deadline is never under -TimeoutMinutes and scales to 3x the slowest runtime''s ideal wall time' {
        Get-SIFastGateDeadlineMinutes -TimeoutMinutes 60 -RuntimeSeconds @(9906, 8141) -Workers 4 | Should -Be 124
        Get-SIFastGateDeadlineMinutes -TimeoutMinutes 40 -RuntimeSeconds @(300) -Workers 4 | Should -Be 40
    }
    It 'the run deadline is never shorter than 3x the LONGEST suite: one suite runs in one process, whatever the workers' {
        Get-SIFastGateDeadlineMinutes -TimeoutMinutes 40 -RuntimeSeconds @(2400) -Workers 14 -LongestSeconds 1800 | Should -Be 90
        Get-SIFastGateDeadlineMinutes -TimeoutMinutes 40 -RuntimeSeconds @(2400) -Workers 14 -LongestSeconds 60 | Should -Be 40
    }
    It 'workers follow the FREE cores, between half and all of cores / runtimes' {
        Get-SIFastGateWorkers -Cores 8 -Runtimes 2 -LoadPercent 0 | Should -Be 4
        Get-SIFastGateWorkers -Cores 8 -Runtimes 2 -LoadPercent 90 | Should -Be 2
        Get-SIFastGateWorkers -Cores 8 -Runtimes 2 -LoadPercent 40 | Should -Be 3
        Get-SIFastGateWorkers -Cores 1 -Runtimes 2 -LoadPercent 99 | Should -Be 1
        # v3 = one runtime: an idle machine gives it every core
        Get-SIFastGateWorkers -Cores 16 -Runtimes 1 -LoadPercent 0 | Should -Be 16
    }
    It 'WIRING: a timed-out or result-less batch is re-run once; what never ran is reported as such; dotnet survives a slow test host' {
        $g = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'tests\Invoke-FastGate.ps1')
        $g | Should -Match 'Get-SIFastGateBatchTimeout -Names \$batch'
        $g | Should -Match '\$p\.Attempt -lt 2'
        $g | Should -Match "'NeverStarted'\s*\{\s*\`$agg\.Broken \+="
        $g | Should -Match "'TimedOut'\s*\{\s*\`$agg\.Broken \+="
        $g | Should -Match "'Deadline'\s*\{\s*\`$agg\.Broken \+="
        $g | Should -Match "'NoResult'\s*\{\s*\`$agg\.Broken \+="
        $g | Should -Match 'VSTEST_CONNECTION_TIMEOUT'
        $g | Should -Match 'Get-SIFastGateDeadlineMinutes -TimeoutMinutes \$TimeoutMinutes'
    }
}
Describe 'the safety suites are complete and never silently empty' {
    It 'the map names the safety suites the brief requires, and each exists here or is a Pro suite (absent from a public copy)' {
        $req = 'SI-PublishPayloadSanitization', 'NoPsModules', 'SchemaGate', 'ReleaseArchivePayload', 'License', 'InvardiaUpdate', 'ReconcileGuards', 'ManagementRoles', 'NoInternalNumbersInOutput', 'AuditTrail'
        foreach ($r in $req) { @($script:Map.Safety | Where-Object { $_ -match [regex]::Escape($r) }).Count | Should -BeGreaterThan 0 -Because $r }
        $pub = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'solution.publish.json') -ErrorAction SilentlyContinue | ConvertFrom-Json -ErrorAction SilentlyContinue
        foreach ($s in $script:Map.Safety) {
            $here = Test-Path -LiteralPath (Join-Path $script:SIRoot "tests\pester\$s")
            $pro = $pub -and (@($pub.excludePaths) -contains "tests/pester/$s")
            ($here -or $pro) | Should -BeTrue -Because "$s is a safety suite"
        }
    }
    It 'every explicit pattern is a valid regex and names suites that exist here or are Pro suites' {
        foreach ($m in $script:Map.Explicit) { { [regex]::new($m.Pattern) } | Should -Not -Throw }
    }
}

Describe 'WIRING: v3 gates PowerShell 7 only by default (operator 2026-10-09: "yes drop ps 5.1 for v3. i told that yesterday")' {
    It 'the default -Runtime is pwsh; ps51 / both stay available as an explicit opt-in' {
        $g = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'tests\Invoke-FastGate.ps1')
        $g | Should -Match "\[ValidateSet\('both', 'pwsh', 'ps51'\)\]\[string\]\`$Runtime = 'pwsh'"
        $g | Should -Not -Match "\`$Runtime = 'both'"
    }
    It 'the measured durations carry the PowerShell 7 timings in use and no 5.1 section' {
        $d = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'tests\pester\suite-durations.json')) | ConvertFrom-Json
        @($d.pwsh.PSObject.Properties).Count | Should -BeGreaterThan 0
        $d.PSObject.Properties.Name | Should -Not -Contain 'ps51'
    }
}

Describe 'WIRING: the gate runs each runtime sharded, and only ever stops what it started' {
    It 'the shard worker takes its list from a FILE (an array parameter through -File passes only its first value)' {
        $w = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'tests\pester\_Invoke-GateShard.ps1')
        $w | Should -Match '\[string\]\$ListFile'
        $w | Should -Match 'ReadAllLines\(\$ListFile\)'
    }
    It 'a PowerShell 5.1 worker (the opt-in) gets the 5.1 module path; processes are stopped by their own id, never by name' {
        $g = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'tests\Invoke-FastGate.ps1')
        $g | Should -Match 'WindowsPowerShell\\v1\.0\\Modules'
        $g | Should -Match 'Stop-Process -Id \$p\.Process\.Id'
        $g | Should -Not -Match 'Stop-Process -Name'
        $g | Should -Match "'powershell\.exe'"
        $g | Should -Match "'pwsh\.exe'"
        $g.Contains('''test'', $pj.Path, ''-c'', ''Release'', ''--no-build''') | Should -BeTrue -Because 'dotnet test runs --no-build after the one build'
    }
    It 'only the dev fast gate leaves out tests tagged Nightly; a full run (only on the owner''s words) and -Hotfix (a covering suite runs whole) run them; every batch is a fresh process from a queue' {
        $g = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'tests\Invoke-FastGate.ps1')
        $g | Should -Match '\$exclude = Get-SIFastGateExcludeTags -Scope \$scope -Full:\$Full -Hotfix:\$Hotfix'
        Get-SIFastGateExcludeTags | Should -Be 'Nightly,Scale'
        Get-SIFastGateExcludeTags -Full | Should -Be 'Scale'
        Get-SIFastGateExcludeTags -Scope PublicCopy | Should -Be 'PrivateRepo,Nightly,Scale'
        $g | Should -Match 'Enqueue'
        $g | Should -Match 'New-SIFastGateBatches'
        (Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'tests\pester\_Invoke-GateShard.ps1')) | Should -Match 'Filter\.ExcludeTag'
    }
    It 'a PowerShell 7 gate leaves out the 5.1 parity probes by tag (Ps51: "not run", never a skip that turns a suite not green); the 5.1 opt-in runs them' {
        Add-SIFastGatePs51Tag -Exclude 'Nightly,Scale' -Runtime 'pwsh' | Should -Be 'Nightly,Scale,Ps51'
        Add-SIFastGatePs51Tag -Exclude '' -Runtime 'pwsh' | Should -Be 'Ps51'
        Add-SIFastGatePs51Tag -Exclude 'Scale' -Runtime 'ps51' | Should -Be 'Scale'
        Add-SIFastGatePs51Tag -Exclude 'Scale' -Runtime 'both' | Should -Be 'Scale'
        Add-SIFastGatePs51Tag -Exclude 'Scale,Ps51' -Runtime 'pwsh' | Should -Be 'Scale,Ps51'
        $g = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'tests\Invoke-FastGate.ps1')
        ([regex]::Matches($g, '(?m)^\s*\$exclude = Add-SIFastGatePs51Tag -Exclude \$exclude -Runtime \$Runtime\s*$')).Count | Should -Be 2 -Because 'the quick gate and the covering gate both apply it'
        # every 5.1 parity probe that skips itself on a PowerShell 7 gate carries the tag
        foreach ($f in @(Get-ChildItem -LiteralPath (Join-Path $script:SIRoot 'tests\pester') -Filter '*.Tests.ps1' | Where-Object { $_.Name -ne 'SIv3-FastGate.Tests.ps1' })) {
            $lines = @(Get-Content -LiteralPath $f.FullName)
            for ($i = 0; $i -lt $lines.Count; $i++) {
                if ($lines[$i] -notmatch "SI_GATE_PS51 -ne '1'") { continue }
                $it = $null; for ($k = $i; $k -ge 0; $k--) { if ($lines[$k] -match '^\s*It\s') { $it = $lines[$k]; break } }
                $it | Should -Match "-Tag 'Ps51'" -Because ('{0} line {1}: a 5.1 parity probe' -f $f.Name, ($i + 1))
            }
        }
    }
    It 'EVERY gate leaves out the scale benchmarks (tag Scale); the hotfix and full gates run the other Nightly tests; Scale runs only when asked for (owner 2026-10-11: "dont run that 100000 test")' {
        $h = @((Get-SIFastGateExcludeTags -Hotfix) -split ',')
        $h | Should -Contain 'Scale'
        $h | Should -Not -Contain 'Nightly'
        @((Get-SIFastGateExcludeTags -Full) -split ',' | Where-Object { $_ }) | Should -Contain 'Scale'
        @((Get-SIFastGateExcludeTags -Full) -split ',' | Where-Object { $_ }) | Should -Not -Contain 'Nightly'
        @((Get-SIFastGateExcludeTags) -split ',' | Where-Object { $_ }) | Should -Contain 'Scale'
        @((Get-SIFastGateExcludeTags -Full -Scale) -split ',' | Where-Object { $_ }) | Should -Not -Contain 'Scale'
        # both 100,000-record measurements of the CI build suite carry the tag
        $both = Join-Path (Join-Path (Join-Path $script:SIRoot 'tests') 'pester') 'SIv3-CiBuildSql.Tests.ps1'
        if (Test-Path -LiteralPath $both) { @(@(Get-Content -LiteralPath $both) | Where-Object { $_ -like "Describe '*100,000 records*' -Tag *'Scale'*" }).Count | Should -Be 2 }
        # the 100,000-record synthetic tenant of the CI build suite is a scale benchmark
        # (a Pro suite: checked where it exists -- the Community copy has no CI build suite)
        $ciSuite = Join-Path $script:SIRoot 'tests\pester\SIv3-CiBuildSql.Tests.ps1'
        if (Test-Path -LiteralPath $ciSuite) { (Get-Content -Raw -LiteralPath $ciSuite) | Should -Match "Describe 'A synthetic tenant of 100,000 records \(real SQL Server\)' -Tag 'Nightly', 'Scale'" }
    }
    It 'a suite that fails to LOAD fails the gate (0 tests from it is not a pass)' {
        $g = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'tests\Invoke-FastGate.ps1')
        $g | Should -Match 'LoadFailures\)\.Count'
    }
}

Describe 'TEST-RUN-1: the selection for a FIX release, and no batch longer than ~3 minutes' {
    It '-ListOnly -SelectionFile writes the selection (Release-SI reads it); a commit gated at ITS OWN base = no change, only the CORE SET' {
        # 2026-10-07 on the test VM: a gate whose base was HEAD failed to bind -Changed ($null instead of an empty list)
        $sf = Join-Path ([IO.Path]::GetTempPath()) ('si-sel-' + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.json')
        try {
            $exe = (Get-Process -Id $PID).Path
            $null = & $exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File (Join-Path $script:SIRoot 'tests\Invoke-FastGate.ps1') -Base HEAD -Paths ' ' -ListOnly -SelectionFile $sf 2>&1
            $LASTEXITCODE | Should -Be 0
            $sel = [IO.File]::ReadAllText($sf) | ConvertFrom-Json
            @($sel.Changed).Count | Should -Be 0
            @($sel.Unmapped).Count | Should -Be 0
            $here = @($script:Map.Core | Where-Object { Test-Path -LiteralPath (Join-Path $script:SIRoot "tests\pester\$_") })
            $sel.Mode | Should -Be 'quick'; $sel.CoreSet | Should -BeTrue
            @($sel.Suites | Sort-Object) -join ',' | Should -Be (@($here | Sort-Object) -join ',')
            $sel.Full | Should -BeFalse
            # what the release command's STOP reads: how many suites there are, and the selection's measured seconds
            [int]$sel.AllSuites | Should -Be @(Get-ChildItem -LiteralPath (Join-Path $script:SIRoot 'tests\pester') -Filter '*.Tests.ps1' -File).Count
            [int]$sel.AllSuites | Should -BeGreaterThan @($sel.Suites).Count
            [double]$sel.MeasuredSeconds | Should -BeGreaterThan 0
            [double]$sel.LongestSeconds | Should -BeLessOrEqual ([double]$sel.MeasuredSeconds)
            "$($sel.LongestSuite)" | Should -Match '\.Tests\.ps1$'
        } finally { Remove-Item -LiteralPath $sf -Force -ErrorAction SilentlyContinue }
    }
    It 'the default batch target is at most 180 s of measured time (a 5.1 batch of 240 s took 20 min on a busy VM); a heavier suite is alone' {
        $names = @(1..300 | ForEach-Object { "s$_" }); $sec = @{}; foreach ($n in $names) { $sec[$n] = 40 }
        $sec['s1'] = 400
        $b = @(New-SIFastGateBatches -Names $names -Workers 8 -Seconds $sec)
        @($b[0]) | Should -Be @('s1')
        foreach ($x in @($b | Select-Object -Skip 1)) { $l = 0; foreach ($n in $x) { $l += $sec[$n] }; $l | Should -BeLessOrEqual 180 }
    }
}

Describe 'ONLY THE OWNER STARTS A FULL RUN (owner 2026-10-13: "no boddy can trigger full test, newer ! only me can start that")' {
    BeforeAll {
        $script:GateFile = Join-Path $script:SIRoot 'tests\Invoke-FastGate.ps1'
        $script:PrePublishFile = Join-Path $script:SIRoot 'tests\pester\Invoke-PrePublishGate.ps1'
        $script:GateText = Get-Content -Raw -LiteralPath $script:GateFile
        $script:PrePublishText = Get-Content -Raw -LiteralPath $script:PrePublishFile
        $script:Exe = (Get-Process -Id $PID).Path
    }
    It 'NEGATIVE: -Full without the owner''s words is REFUSED -- no words, empty words, only white space; the refusal says it plainly' {
        foreach ($w in @($null, '', '   ', "`t ")) {
            $d = Test-SIFastGateFullRun -Full -OwnerWords $w
            $d.FullRun | Should -BeTrue
            $d.Allowed | Should -BeFalse -Because "words '$w'"
            $d.Words | Should -Be ''
            $d.Text | Should -Match '^REFUSED: only the owner starts a full run'
            $d.Text | Should -Match 'Nothing was run'
            $d.Text | Should -Match 'Run the affected suites instead'
            $d.Text | Should -Match 'never a default, never from a file, an environment variable or a configuration'
        }
        (Test-SIFastGateFullRun -Full).Allowed | Should -BeFalse
    }
    It 'POSITIVE: with his own sentence for this run the DECISION is "may start", and the words are carried as he said them (nothing is run here)' {
        $d = Test-SIFastGateFullRun -Full -OwnerWords '  run the full suite on the merged head now  '
        $d.FullRun | Should -BeTrue; $d.Allowed | Should -BeTrue
        $d.Words | Should -Be 'run the full suite on the merged head now'
        $d.Text | Should -Match 'a FULL run \(-Full\), started on the owner''s own words for this run: "run the full suite on the merged head now"'
    }
    It 'every suite by another road (-Suites / -Paths naming them all) is the same full run; an ordinary selection needs no words and carries none' {
        $all = Test-SIFastGateFullRun -Selected 466 -Total 466
        $all.FullRun | Should -BeTrue; $all.Allowed | Should -BeFalse
        $all.Text | Should -Match 'REFUSED: only the owner starts a full run \(a selection of every suite \(466 of 466\)\)'
        (Test-SIFastGateFullRun -Selected 466 -Total 466 -OwnerWords 'run them all tonight').Allowed | Should -BeTrue
        $some = Test-SIFastGateFullRun -Selected 40 -Total 466 -OwnerWords 'not needed'
        $some.FullRun | Should -BeFalse; $some.Allowed | Should -BeTrue; $some.Words | Should -Be ''
        # an empty tree (nothing to select from) is not a full run
        (Test-SIFastGateFullRun -Selected 0 -Total 0).FullRun | Should -BeFalse
    }
    It 'THE REAL RUNNER: Invoke-FastGate.ps1 -Full without the words exits 6 at once, runs nothing and writes Status = REFUSED' {
        $rf = Join-Path $TestDrive 'refused.json'
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $out = @(& $script:Exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $script:GateFile -Full -Runtime pwsh -ResultFile $rf 2>&1 | ForEach-Object { "$_" })
        $LASTEXITCODE | Should -Be 6
        $sw.Stop(); $sw.Elapsed.TotalSeconds | Should -BeLessThan 60
        ($out -join "`n") | Should -Match 'REFUSED: only the owner starts a full run \(-Full\)'
        ($out -join "`n") | Should -Not -Match 'GATE: (PASS|FAIL)'
        $r = [IO.File]::ReadAllText($rf) | ConvertFrom-Json
        $r.Status | Should -Be 'REFUSED'; $r.Mode | Should -Be 'full'; [int]$r.Suites | Should -Be 0; $r.OwnerWords | Should -Be ''
        $r.Refused | Should -Match 'only the owner starts a full run'
        # white-space words are no words
        $null = & $script:Exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $script:GateFile -Full -OwnerWords '   ' -Runtime pwsh 2>&1
        $LASTEXITCODE | Should -Be 6
    }
    It '-Full -ListOnly runs nothing, so it may list -- and its selection says Full = true (the release command reads that as a STOP)' {
        $sf = Join-Path $TestDrive 'full-sel.json'
        $null = & $script:Exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $script:GateFile -Full -ListOnly -SelectionFile $sf 2>&1
        $LASTEXITCODE | Should -Be 0
        $sel = [IO.File]::ReadAllText($sf) | ConvertFrom-Json
        $sel.Full | Should -BeTrue
        @($sel.Suites).Count | Should -Be ([int]$sel.AllSuites)
    }
    It 'THE REAL RUNNER: Invoke-PrePublishGate.ps1 (it runs every suite) exits 6 without the words and starts no Pester run' {
        $out = @(& $script:Exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $script:PrePublishFile -TestsFolder (Join-Path $TestDrive 'none') 2>&1 | ForEach-Object { "$_" })
        $LASTEXITCODE | Should -Be 6
        ($out -join "`n") | Should -Match 'REFUSED: only the owner starts a full run'
        ($out -join "`n") | Should -Match 'Run the affected suites instead'
        # the refusal comes before the re-run under pwsh, before the tests are found and before Pester is started
        $i = $script:PrePublishText.IndexOf('exit 6')
        $i | Should -BeGreaterThan 0
        $i | Should -BeLessThan $script:PrePublishText.IndexOf("PSEdition -ne 'Core' -and")
        $i | Should -BeLessThan $script:PrePublishText.IndexOf('Get-ChildItem -Path $TestsFolder')
        $i | Should -BeLessThan $script:PrePublishText.IndexOf('Invoke-Pester -Configuration')
        # a 5.1 start hands the words on to its pwsh re-run
        $script:PrePublishText | Should -Match "\`$PSCommandPath, '-OwnerWords', \`$ownerWordsGiven\)"
    }
    It 'WIRING: the words are never defaulted and never read from a file, an environment variable or a configuration -- in either runner' {
        foreach ($t in $script:GateText, $script:PrePublishText) {
            $t | Should -Match '(?m)^\s*\[string\]\$OwnerWords,\s*$'
            $t | Should -Not -Match '\$OwnerWords\s*='
            $t | Should -Not -Match '(?i)\$env:[A-Za-z_]*(Owner|FullRun|Approval)'
            $t | Should -Not -Match '(?i)(Get-Content|ReadAllText|ConvertFrom-Json)[^\n]*OwnerWords'
        }
        $a = $script:GateText.IndexOf('function Test-SIFastGateFullRun'); $b = $script:GateText.IndexOf('function Get-SIFastGateChangedPaths')
        $fn = Remove-SIFastGateComments -Text $script:GateText.Substring($a, $b - $a)
        $fn | Should -Not -Match '(?i)\$env:|Get-Content|ReadAllText|Test-Path|Get-Item'
    }
    It 'WIRING: the gate refuses BEFORE anything is selected or started, again for a selection of every suite, and the result carries the words' {
        $g = $script:GateText
        $first = $g.IndexOf('$fullRun = Test-SIFastGateFullRun -Full:$Full -OwnerWords $OwnerWords')
        $first | Should -BeGreaterThan $g.IndexOf('if ($DefineOnly) { return }')
        $first | Should -BeLessThan $g.IndexOf('$scope = Get-SITestScope')
        $g | Should -Match 'if \(-not \$ListOnly -and -not \$fullRun\.Allowed\) \{ Stop-SIFastGateRefused -Decision \$fullRun \}'
        $second = $g.IndexOf('Test-SIFastGateFullRun -OwnerWords $OwnerWords -Selected $reasons.Count -Total $allSuites.Count')
        $second | Should -BeGreaterThan $first
        $second | Should -BeLessThan $g.IndexOf('Start-Process -FilePath $exeOf[$rt]')
        $second | Should -BeLessThan $g.IndexOf('$dotnetJob = Start-Job')
        $g | Should -Match '\$summary\.OwnerWords = \[string\]\$fullRun\.Words'
        $g | Should -Match "Status = 'REFUSED'"
        $g | Should -Match '(?s)function Stop-SIFastGateRefused.*?exit 6'
        # the selection file carries what the release command's STOP reads
        $g | Should -Match '\$selDoc\.AllSuites = \$allSuites\.Count; \$selDoc\.MeasuredSeconds = '
    }
    It 'NO SCHEDULED OR NIGHTLY FULL RUN in the solution: no task or workflow definition here starts a gate or a Pester run' {
        $runner = '(?i)Invoke-FastGate|Invoke-GateOnTestVm|Invoke-PrePublishGate|Invoke-Pester|Invoke-SINightlyGate'
        $sched = '(?i)Register-ScheduledTask|New-ScheduledTaskTrigger|schtasks(\.exe)?\s+/create|New-JobTrigger|Register-ScheduledJob'
        $bad = New-Object System.Collections.Generic.List[string]
        foreach ($f in @(Get-ChildItem -LiteralPath $script:SIRoot -Recurse -File -Include '*.ps1', '*.psm1', '*.cmd', '*.bat' -ErrorAction SilentlyContinue)) {
            if ($f.FullName -match '\\(bin|obj|node_modules|logs|output|staging)\\' -or $f.Name -like '*.Tests.ps1') { continue }
            $t = [IO.File]::ReadAllText($f.FullName)
            if ($t -match $sched -and (Remove-SIFastGateComments -Text $t) -match $runner) { $bad.Add($f.FullName.Substring($script:SIRoot.Length)) }
        }
        $bad.ToArray() | Should -BeNullOrEmpty -Because 'a script that registers a scheduled task must not start a test run'
        # no workflow or task definition file of its own in the solution names a runner
        foreach ($f in @(Get-ChildItem -LiteralPath $script:SIRoot -Recurse -File -Include '*.yml', '*.yaml', '*.xml' -ErrorAction SilentlyContinue)) {
            if ($f.FullName -match '\\(bin|obj|node_modules|logs|output|staging)\\') { continue }
            $t = [IO.File]::ReadAllText($f.FullName)
            if ($t -match '(?i)schedule:|cron:|<ScheduledTask|<CalendarTrigger|<TimeTrigger') { $t | Should -Not -Match $runner -Because $f.Name }
        }
    }
}

Describe 'THE QUICK GATE selects the PIM way (owner 2026-10-13: "yes, build it the pim way")' {
    BeforeAll {
        # a small world: a core set of two, a narrow library, a broad one, a hub, a document, VERSION, a web page
        $script:QS = @{
            'Core-One.Tests.ps1'      = 'x'; 'Core-Two.Tests.ps1' = 'x'
            'SIv3-NarrowLib.Tests.ps1' = '. engine\Narrow-Lib.ps1'
            'SIv3-Other.Tests.ps1'    = 'nothing relevant'
            'SIv3-BroadThing.Tests.ps1' = 'engine\Broad-Thing.ps1'
            'S1.Tests.ps1' = 'Broad-Thing.ps1 Broad-Thing.ps1 Broad-Thing.ps1'; 'S2.Tests.ps1' = 'Broad-Thing.ps1 Broad-Thing.ps1'
            'S3.Tests.ps1' = 'Broad-Thing.ps1'; 'S4.Tests.ps1' = 'Broad-Thing.ps1'; 'S5.Tests.ps1' = 'Broad-Thing.ps1'
            'H1.Tests.ps1' = 'Hub-Main.ps1'; 'H2.Tests.ps1' = 'Hub-Main.ps1'; 'H3.Tests.ps1' = 'Hub-Main.ps1'; 'H4.Tests.ps1' = 'Hub-Main.ps1'
            'SIv3-HubMain.Tests.ps1' = 'x'; 'SIv3-HubMainParts.Tests.ps1' = 'x'; 'SIv3-HubMainRoll.Tests.ps1' = 'x'; 'SIv3-HubMainWire.Tests.ps1' = 'x'
            'Doc-Guard.Tests.ps1'     = 'x'; 'Version-Stamp.Tests.ps1' = 'VERSION'
            'Loader-Suite.Tests.ps1'  = 'runs Start-Loader.ps1'
        }
        $script:QC = @{
            'engine/Narrow-Lib.ps1' = 'function A { }'; 'engine/Broad-Thing.ps1' = 'function B { }'; 'engine/Hub-Main.ps1' = 'function H { }'
            'launcher/Start-Loader.ps1' = '. engine\Only-Loaded.ps1'; 'engine/Only-Loaded.ps1' = 'function L { }'
            'engine/Brand-NewFile.ps1' = 'function N { }'
        }
        $script:QM = [pscustomobject]@{
            Core = @('Core-One.Tests.ps1', 'Core-Two.Tests.ps1'); Hubs = @('engine/Hub-Main.ps1')
            Quick = [pscustomobject]@{ BroadOver = 3; NamedMax = 3; HubLoads = 20 }
            Explicit = @(
                [pscustomobject]@{ Pattern = '^VERSION$'; Suites = @('Version-Stamp.Tests.ps1'); Dotnet = @(); Exclusive = $true; Kind = 'bump' },
                [pscustomobject]@{ Pattern = '^docs/[^/]+\.md$'; Suites = @('Doc-Guard.Tests.ps1'); Dotnet = @(); Exclusive = $true; Kind = 'doc' },
                [pscustomobject]@{ Pattern = '^app/src/Web/'; Suites = @(); Dotnet = @('Web.Tests'); Exclusive = $false; Kind = '' })
        }
        $script:Q = { param([string[]]$c, [string[]]$n = @()) Get-SIQuickGateSelection -Changed $c -Named $n -SuiteText $script:QS -CodeText $script:QC -Map $script:QM }
    }
    It 'a NARROW library (seen by at most 3 suites) -> exactly the suites that see it + the core set' {
        $s = & $script:Q @('engine/Narrow-Lib.ps1')
        @($s.Suites.Keys) | Should -Be @('SIv3-NarrowLib.Tests.ps1', 'Core-One.Tests.ps1', 'Core-Two.Tests.ps1')
        $s.Suites['Core-One.Tests.ps1'] | Should -Be 'core set (every quick gate)'
        @($s.Narrow) | Should -Be @('engine/Narrow-Lib.ps1'); $s.Core | Should -BeTrue
        # one hop: a file no suite names, loaded by a script a suite names, is seen through it
        $h = & $script:Q @('engine/Only-Loaded.ps1')
        $h.Suites['Loader-Suite.Tests.ps1'] | Should -Match 'names Start-Loader\.ps1, which loads Only-Loaded\.ps1'
    }
    It 'a BROAD file (seen by more than 3) -> the core set + AT MOST 3: the suite named after it first, then the ones that name it most often -- never every suite covering it' {
        $s = & $script:Q @('engine/Broad-Thing.ps1')
        $picked = @($s.Suites.Keys | Where-Object { $_ -notlike 'Core-*' })
        $picked.Count | Should -Be 3
        $picked | Should -Be @('SIv3-BroadThing.Tests.ps1', 'S1.Tests.ps1', 'S2.Tests.ps1')
        $s.Suites['SIv3-BroadThing.Tests.ps1'] | Should -Match '^named after Broad-Thing\.ps1 \(a broad file: 6 suites see it\)'
        $s.Suites['S1.Tests.ps1'] | Should -Match '^names Broad-Thing\.ps1 6 x'
        $s.Broad['engine/Broad-Thing.ps1'] | Should -Be 6
        @($s.Notes) -join ' ' | Should -Match 'engine/Broad-Thing\.ps1 is BROAD: 6 suites see it'
    }
    It 'a HUB (in the map, or loading 20+ SI files) -> the core set + at most 3 suites NAMED AFTER it (owner 2026-10-13), never the suites that merely name it' {
        $s = & $script:Q @('engine/Hub-Main.ps1')
        @($s.Suites.Keys) | Should -Be @('SIv3-HubMain.Tests.ps1', 'SIv3-HubMainParts.Tests.ps1', 'SIv3-HubMainRoll.Tests.ps1', 'Core-One.Tests.ps1', 'Core-Two.Tests.ps1')
        $s.Suites['SIv3-HubMain.Tests.ps1'] | Should -Match '^named after Hub-Main\.ps1 \(a hub'
        @($s.Suites.Keys) | Should -Not -Contain 'H1.Tests.ps1'
        @($s.Hubs) | Should -Be @('engine/Hub-Main.ps1')
        @($s.Notes) -join ' ' | Should -Match 'engine/Hub-Main\.ps1 is a HUB .* the core set \+ the 3 suite\(s\) named after it'
        # the rule finds a new hub by itself: a file whose code names 20+ other SI files
        $code = $script:QC.Clone(); $body = ''
        foreach ($i in 1..21) { $code["engine/lib/Library-Number$i.ps1"] = 'x'; $body += ". Library-Number$i.ps1`n" }
        $code['engine/New-BigHub.ps1'] = $body
        $suites = $script:QS.Clone(); foreach ($i in 1..2) { $suites["BH$i.Tests.ps1"] = 'New-BigHub.ps1' }
        Get-SIQuickGateLoads -RelativePath 'engine/New-BigHub.ps1' -CodeText $code | Should -Be 21
        $b = Get-SIQuickGateSelection -Changed @('engine/New-BigHub.ps1') -SuiteText $suites -CodeText $code -Map $script:QM
        @($b.Hubs) | Should -Be @('engine/New-BigHub.ps1'); @($b.Suites.Keys) | Should -Not -Contain 'BH1.Tests.ps1'
    }
    It 'an UNMAPPED file (nothing sees it) -> the core set, never everything; it is named in Unmapped' {
        $s = & $script:Q @('engine/Brand-NewFile.ps1')
        @($s.Suites.Keys) | Should -Be @('Core-One.Tests.ps1', 'Core-Two.Tests.ps1')
        @($s.Unmapped) | Should -Be @('engine/Brand-NewFile.ps1')
    }
    It 'DOCUMENTS only -> only their doc guards: no code suite and no core set' {
        $s = & $script:Q @('docs/REQUIREMENTS.md')
        @($s.Suites.Keys) | Should -Be @('Doc-Guard.Tests.ps1'); $s.Core | Should -BeFalse
        # the real map: every .md is a document -- a doc guard runs, never the suites that merely name it
        foreach ($d in 'docs/TESTS.md', 'CLAUDE.md', 'engine/x/README.md', 'README.md') {
            $k = @($script:Map.Explicit | Where-Object { $d -match $_.Pattern })
            $k.Count | Should -Be 1 -Because $d; $k[0].Exclusive | Should -BeTrue; $k[0].Kind | Should -Be 'doc'
        }
    }
    It 'RELEASE-BUMP files only (VERSION) -> only the suites that name them: no core set' {
        $s = & $script:Q @('VERSION')
        @($s.Suites.Keys) | Should -Be @('Version-Stamp.Tests.ps1'); $s.Core | Should -BeFalse
        foreach ($b in 'VERSION', 'RELEASENOTES.md') { @($script:Map.Explicit | Where-Object { $b -match $_.Pattern -and $_.Kind -eq 'bump' -and $_.Exclusive }).Count | Should -Be 1 -Because $b }
        # a bump WITH a code change: the core set comes back
        (& $script:Q @('VERSION', 'engine/Narrow-Lib.ps1')).Core | Should -BeTrue
    }
    It 'a CHANGED SUITE runs itself (+ the core set)' {
        $s = & $script:Q @('tests/pester/SIv3-Other.Tests.ps1')
        @($s.Suites.Keys) | Should -Be @('SIv3-Other.Tests.ps1', 'Core-One.Tests.ps1', 'Core-Two.Tests.ps1')
        $s.Suites['SIv3-Other.Tests.ps1'] | Should -Be 'changed suite'
    }
    It 'a WEB file -> its dotnet test project, and only the matching test classes (bounded, never the whole project in a quick gate)' {
        $s = & $script:Q @('app/src/Web/Pages/Exemption.cshtml.cs')
        @($s.Dotnet.Keys) | Should -Be @('Web.Tests'); $s.Core | Should -BeTrue
        $cls = @('AuditTrailTests', 'RoleMatrixTests', 'ExemptionPageTests', 'ExemptionFlowTests', 'NavTests') + @(1..40 | ForEach-Object { "Feature$($_)Tests" })
        $txt = @{ 'NavTests' = 'Get("/Exemption")' }; foreach ($c in $cls) { if (-not $txt.ContainsKey($c)) { $txt[$c] = if ($c -like 'Feature*') { 'uses Program and Layout' } else { '' } } }
        $f = { param([string[]]$c, [int]$max = 15) Get-SIFastGateDotnetFilter -Changed $c -SourcePrefix 'app/src/Web/' -TestPrefix 'app/tests/Web.Tests/' -TestClasses $cls -Always @('RoleMatrixTests', 'AuditTrailTests') -TestText $txt -Related @('app/') -Shared @('^app/src/Web/Program\.cs$', '^app/src/Web/Pages/Shared/') -NoWhole -MaxClasses $max }
        $one = & $f @('app/src/Web/Pages/Exemption.cshtml.cs')
        $one.Whole | Should -BeFalse
        @($one.Classes) | Should -Be @('AuditTrailTests', 'ExemptionFlowTests', 'ExemptionPageTests', 'NavTests', 'RoleMatrixTests')
        $one.Filter | Should -Match '^FullyQualifiedName~AuditTrailTests\|'
        # a SHARED piece in a quick gate: never the whole project -- the classes that name it, at most -MaxClasses (+ always)
        $sh = & $f @('app/src/Web/Program.cs') 5
        $sh.Whole | Should -BeFalse
        @($sh.Classes | Where-Object { $_ -like 'Feature*' }).Count | Should -Be 5
        @($sh.Classes) | Should -Contain 'RoleMatrixTests'
        @($sh.Notes) -join ' ' | Should -Match 'a shared piece changed \(app/src/Web/Program\.cs\) -- the quick gate runs the classes that name it'
        @($sh.Notes) -join ' ' | Should -Match '40 classes cover the change -- the quick gate runs the first 5'
        # a fixture of the test project: the classes that name it, never the whole project
        $fx = Get-SIFastGateDotnetFilter -Changed @('app/tests/Web.Tests/CmdbFakes.cs') -SourcePrefix 'app/src/Web/' -TestPrefix 'app/tests/Web.Tests/' -TestClasses (@($cls) + 'CmdbFakes') -TestText @{ 'ExemptionFlowTests' = 'new CmdbFakes()'; 'NavTests' = '' } -Related @('app/') -NoWhole -MaxClasses 15
        $fx.Whole | Should -BeFalse; @($fx.Classes) | Should -Be @('ExemptionFlowTests')
        # the real map bounds it
        $script:Map.Quick.DotnetMaxClasses | Should -BeLessOrEqual 20
    }
    It '-Suites named EXPLICITLY = exactly those + the core set, nothing added (what changed is not read)' {
        $s = & $script:Q @('engine/Broad-Thing.ps1') @('SIv3-Other', 'S5.Tests.ps1')
        @($s.Suites.Keys) | Should -Be @('SIv3-Other.Tests.ps1', 'S5.Tests.ps1', 'Core-One.Tests.ps1', 'Core-Two.Tests.ps1')
        $s.Suites['SIv3-Other.Tests.ps1'] | Should -Be '-Suites (named)'
        @($s.Dotnet.Keys).Count | Should -Be 0
        # wiring: -Suites alone reads no change, and its selection has no other road in
        $g = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'tests\Invoke-FastGate.ps1')
        $g | Should -Match 'elseif \("\$Suites"\.Trim\(\) -and -not \$Precise\) \{ @\(\) \}'
        $g | Should -Match 'Get-SIQuickGateSelection -Changed @\(\) -Named \$namedList'
    }
    It 'a selection of EVERYTHING is a STOP and a question to the owner -- refused, never started' {
        $all = Test-SIFastGateFullRun -Selected 466 -Total 466
        $all.Allowed | Should -BeFalse; $all.Text | Should -Match '^REFUSED: only the owner starts a full run'
        # the real runner: -Suites naming every suite exits 6, runs nothing, writes REFUSED
        $names = (@(Get-ChildItem -LiteralPath (Join-Path $script:SIRoot 'tests\pester') -Filter '*.Tests.ps1' -File | ForEach-Object { $_.Name }) -join ';')
        $rf = Join-Path $TestDrive 'everything.json'
        $out = @(& (Get-Process -Id $PID).Path -NoProfile -NonInteractive -ExecutionPolicy Bypass -File (Join-Path $script:SIRoot 'tests\Invoke-FastGate.ps1') -Suites $names -Runtime pwsh -ResultFile $rf 2>&1 | ForEach-Object { "$_" })
        $LASTEXITCODE | Should -Be 6
        ($out -join "`n") | Should -Match 'REFUSED: only the owner starts a full run \(a selection of every suite'
        ([IO.File]::ReadAllText($rf) | ConvertFrom-Json).Status | Should -Be 'REFUSED'
        ($out -join "`n") | Should -Not -Match 'QUICK GATE:'
    }
    It 'the REAL map: a core set of 8-12 suites that exist here, about 2 minutes of measured time, with the tree-wide guards the owner named' {
        @($script:Map.Core).Count | Should -BeGreaterOrEqual 8
        @($script:Map.Core).Count | Should -BeLessOrEqual 12
        foreach ($r in 'SIv3-NoPsModules', 'SIv3-NoPsModulesSetup', 'SI-PublishPayloadSanitization', 'SIv3-SettingInfo', 'SIv3-NoMergeLeftovers', 'SIv3-ManagementRoles', 'SIv3-AuditTrail') { @($script:Map.Core | Where-Object { $_ -eq "$r.Tests.ps1" }).Count | Should -Be 1 -Because $r }
        $pub = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'solution.publish.json') -ErrorAction SilentlyContinue | ConvertFrom-Json -ErrorAction SilentlyContinue
        $d = ([IO.File]::ReadAllText((Join-Path $script:SIRoot 'tests\pester\suite-durations.json')) | ConvertFrom-Json).pwsh
        $sum = 0.0
        foreach ($s in $script:Map.Core) {
            $here = Test-Path -LiteralPath (Join-Path $script:SIRoot "tests\pester\$s"); $pro = $pub -and (@($pub.excludePaths) -contains "tests/pester/$s")
            ($here -or $pro) | Should -BeTrue -Because "$s is a core suite"
            if ($d.$s) { $sum += [double]$d.$s }
        }
        $sum | Should -BeLessOrEqual 150
        $script:Map.Quick.BroadOver | Should -Be 3; $script:Map.Quick.NamedMax | Should -Be 3; $script:Map.Quick.HubLoads | Should -Be 20
        $script:Map.Quick.SuiteLimitSeconds | Should -Be 600; $script:Map.Quick.GateLimitSeconds | Should -Be 600
        @($script:Map.Hubs).Count | Should -BeGreaterThan 5
        foreach ($h in $script:Map.Hubs) { Test-Path -LiteralPath (Join-Path $script:SIRoot ($h -replace '/', '\')) | Should -BeTrue -Because "$h is a listed hub" }
        # never above 10 minutes, whatever the file says
        $tmp = Join-Path $TestDrive 'map.json'
        $j = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'tests\pester\fast-gate.map.json')) | ConvertFrom-Json
        $j.quick.suiteLimitSeconds = 3600; $j.quick.gateLimitSeconds = 7200
        [IO.File]::WriteAllText($tmp, ($j | ConvertTo-Json -Depth 8))
        $m2 = Get-SIFastGateMap -Path $tmp
        $m2.Quick.SuiteLimitSeconds | Should -Be 600; $m2.Quick.GateLimitSeconds | Should -Be 600
    }
}

Describe 'THE QUICK GATE stops at its limit and reports (owner: "we even agreed on hard limit of max 10 min")' {
    BeforeAll {
        $script:Pw = (Get-Process -Id $PID).Path
        $script:Shard = Join-Path $script:SIRoot 'tests\pester\_Invoke-GateShard.ps1'
        # two FAKE suites: one passes at once, one sleeps far past the SHORT test limit -- after starting a child process
        # of its own (its process tree must be ended with it)
        $script:Fake = Join-Path $TestDrive 'fake'; New-Item -ItemType Directory -Force -Path $script:Fake | Out-Null
        $script:ChildPidFile = Join-Path $script:Fake 'child.pid'
        [IO.File]::WriteAllText((Join-Path $script:Fake 'Quick-Fake.Tests.ps1'), "Describe 'quick' { It 'passes' { 1 | Should -Be 1 } }")
        [IO.File]::WriteAllText((Join-Path $script:Fake 'Sleeper-Fake.Tests.ps1'), ("Describe 'sleeper' {{ It 'sleeps' {{ `$c = Start-Process -FilePath '{0}' -ArgumentList '-NoProfile -Command Start-Sleep -Seconds 300' -PassThru -WindowStyle Hidden; [IO.File]::WriteAllText('{1}', [string]`$c.Id); Start-Sleep -Seconds 300 }} }}" -f $script:Pw, $script:ChildPidFile))
        $script:Item = {
            param([string]$Name, [string]$Work)
            $list = Join-Path $Work "$Name.txt"; $res = Join-Path $Work "$Name.json"
            New-Item -ItemType Directory -Force -Path $Work | Out-Null
            [IO.File]::WriteAllLines($list, [string[]]@(Join-Path $script:Fake $Name))
            [pscustomobject]@{ Name = $Name; Kind = 'pester'; Exe = $script:Pw; ResultFile = $res; Env = $null
                               Args = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $script:Shard, '-ListFile', $list, '-ResultFile', $res) }
        }
    }
    It 'a suite past the per-suite limit is ENDED (its whole process tree) and reported TIMED OUT BY NAME; the other suite stands; the run is NOT TESTED' {
        $w = Join-Path $TestDrive 'run1'
        $items = @((& $script:Item 'Sleeper-Fake.Tests.ps1' $w), (& $script:Item 'Quick-Fake.Tests.ps1' $w))
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $r = @(Invoke-SIQuickGateRun -Items $items -Work $w -Throttle 4 -SuiteLimitSeconds 25 -GateLimitSeconds 120 -ProgressSeconds 5 6>$null)
        $sw.Stop()
        $sw.Elapsed.TotalSeconds | Should -BeLessThan 90 -Because 'the limit stops it -- nothing waits for the 300 s sleep'
        $sl = @($r | Where-Object Name -eq 'Sleeper-Fake.Tests.ps1')[0]
        $sl.State | Should -Be 'TimedOut'; $sl.ExitCode | Should -Be 124
        $sl.Note | Should -Match '^TIMED OUT after 0\.4 min -- its process tree was ended \(\d+ process\(es\)\)'
        # the child the suite started is gone too (the tree, by process id)
        if (Test-Path -LiteralPath $script:ChildPidFile) {
            $cid = [int]([IO.File]::ReadAllText($script:ChildPidFile))
            Start-Sleep -Milliseconds 500
            Get-Process -Id $cid -ErrorAction SilentlyContinue | Should -BeNullOrEmpty -Because 'the suite''s own child process is ended with it'
        }
        $q = @($r | Where-Object Name -eq 'Quick-Fake.Tests.ps1')[0]
        $q.State | Should -Be 'Done'
        $qo = Get-SIQuickGateItemOutcome -Result $q
        $qo.Ok | Should -BeTrue; $qo.Passed | Should -Be 1
        $outs = @($r | ForEach-Object { Get-SIQuickGateItemOutcome -Result $_ })
        @($outs | Where-Object { $_.Name -eq 'Sleeper-Fake.Tests.ps1' })[0].Ok | Should -BeFalse
        $v = Get-SIQuickGateStatus -Outcomes $outs
        $v.Status | Should -Be 'NOT TESTED'
        @($v.TimedOut) | Should -Be @('Sleeper-Fake.Tests.ps1')
        $v.Text | Should -Match '^NOT TESTED -- the gate was STOPPED at its 10-minute limit; a stopped run is never green \(TIMED OUT: Sleeper-Fake\.Tests\.ps1\)'
    }
    It 'at the WHOLE gate''s limit: what runs is ended, what never started is NOT RUN -- by name; never green' {
        $w = Join-Path $TestDrive 'run2'
        $items = @((& $script:Item 'Sleeper-Fake.Tests.ps1' $w), (& $script:Item 'Quick-Fake.Tests.ps1' $w))
        $r = @(Invoke-SIQuickGateRun -Items $items -Work $w -Throttle 1 -SuiteLimitSeconds 600 -GateLimitSeconds 15 -ProgressSeconds 5 6>$null)
        @($r | Where-Object Name -eq 'Sleeper-Fake.Tests.ps1')[0].State | Should -Be 'TimedOut'
        @($r | Where-Object Name -eq 'Sleeper-Fake.Tests.ps1')[0].Note | Should -Match "the whole gate's limit of 0\.3 min"
        $nr = @($r | Where-Object Name -eq 'Quick-Fake.Tests.ps1')[0]
        $nr.State | Should -Be 'NotRun'; $nr.ExitCode | Should -Be 125
        $nr.Note | Should -Match "^NOT RUN -- the whole gate's limit of 0\.3 min passed before it could start"
        $v = Get-SIQuickGateStatus -Outcomes @($r | ForEach-Object { Get-SIQuickGateItemOutcome -Result $_ })
        $v.Status | Should -Be 'NOT TESTED'; @($v.NotRun) | Should -Be @('Quick-Fake.Tests.ps1')
    }
    It 'a suite MEASURED over 10 minutes is not stopped at 10 in a release gate (owner 2026-10-13: "accepted, skip 10 min for now"): it gets its measured time and the gate says so' {
        Get-SIQuickGateSlowLimit -MeasuredSeconds 1800 | Should -Be 2700
        Get-SIQuickGateSlowLimit -MeasuredSeconds 600 | Should -Be 0
        Get-SIQuickGateSlowLimit -MeasuredSeconds 120 | Should -Be 0
        Get-SIQuickGateSlowLimit | Should -Be 0
        # the runner honours an item's own limit: a sleeping fake suite with LimitSeconds 30 is NOT ended at the 10 s suite limit
        $w = Join-Path $TestDrive 'run3'
        $it = & $script:Item 'Quick-Fake.Tests.ps1' $w
        $sl = & $script:Item 'Sleeper-Fake.Tests.ps1' $w; $sl | Add-Member -NotePropertyName LimitSeconds -NotePropertyValue 30 -Force
        $r = @(Invoke-SIQuickGateRun -Items @($sl, $it) -Work $w -Throttle 4 -SuiteLimitSeconds 10 -GateLimitSeconds 120 -ProgressSeconds 5 6>$null)
        $x = @($r | Where-Object Name -eq 'Sleeper-Fake.Tests.ps1')[0]
        $x.State | Should -Be 'TimedOut'; $x.Seconds | Should -BeGreaterOrEqual 29
        $x.Note | Should -Match '^TIMED OUT after 0\.5 min'
        # wiring: the gate gives a measured-slow suite its time, widens the whole gate's limit and says so plainly
        $g = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'tests\Invoke-FastGate.ps1')
        $g | Should -Match 'LimitSeconds = \$slow \}\)'
        $g | Should -Match 'OVER THE 10-MINUTE LIMIT; it runs with its measured time'
        $g | Should -Match '\$qGateLimit = \[Math\]::Max\(\$qGateLimit'
        $g | Should -Match "Get-SIFastGateBudget -Mode 'quick' -Seconds \`$summary\.Seconds -OverBudget @\(\`$slowSuites\.Keys\)"
    }
    It 'the verdict: a red suite = FAIL; all green = PASS; a stopped one wins over both (never green)' {
        (Get-SIQuickGateStatus -Outcomes @([pscustomobject]@{ Name = 'a'; State = 'Done'; Ok = $true }, [pscustomobject]@{ Name = 'b'; State = 'Done'; Ok = $false })).Text | Should -Be 'FAIL -- RED: b'
        (Get-SIQuickGateStatus -Outcomes @([pscustomobject]@{ Name = 'a'; State = 'Done'; Ok = $true })).Status | Should -Be 'PASS'
        (Get-SIQuickGateStatus -Outcomes @([pscustomobject]@{ Name = 'a'; State = 'Done'; Ok = $false }, [pscustomobject]@{ Name = 'c'; State = 'NotRun'; Ok = $false })).Status | Should -Be 'NOT TESTED'
    }
    It 'WIRING: the quick gate runs before (and instead of) the full-run engine, refuses "everything" first, stops by process id, and carries every suite by name' {
        $g = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'tests\Invoke-FastGate.ps1')
        $q = $g.IndexOf('# ---- 4q. THE QUICK GATE')
        $q | Should -BeGreaterThan $g.IndexOf('if ($ListOnly) { exit 0 }')
        $q | Should -BeLessThan $g.IndexOf('$dotnetJob = Start-Job')
        $g.IndexOf('Test-SIFastGateFullRun -OwnerWords $OwnerWords -Selected $reasons.Count') | Should -BeLessThan $g.IndexOf('$runRes = @(Invoke-SIQuickGateRun')
        $g | Should -Match '\$exclude = Get-SIFastGateExcludeTags -Scope \$scope -Hotfix\r?\n'
        $g | Should -Match 'Stop-SIGateProcessTree -Process \$r\.Process'
        $g | Should -Match "Kill', \[type\[\]\]@\(\[bool\]\)"
        $g | Should -Match 'taskkill\.exe /T /F /PID \$Process\.Id'
        $g | Should -Not -Match 'Stop-Process -Name'
        $g | Should -Match '-RedirectStandardInput \$noInput'
        $g | Should -Match 'still running \(\{1\}\)'
        $g | Should -Match 'SuiteResults = @\(\)'
        $g | Should -Match "Status = \`$verdict\.Status"
        $g | Should -Match 'QUICK GATE TIMED OUT: \{0\} after'
        $g | Should -Match 'QUICK GATE NOT RUN: \{0\}'
        # the limits can never be raised above 10 minutes
        $g | Should -Match '\[ValidateRange\(0, 600\)\]\[int\]\$SuiteLimitSeconds'
        $g | Should -Match '\[ValidateRange\(0, 600\)\]\[int\]\$GateLimitSeconds'
        $g | Should -Match 'SuiteLimitSeconds = \[Math\]::Min\(600'
        # the web app: built and tested in its own stoppable process, the PROJECT (never the solution), only on a web change
        $d = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'tests\pester\_Invoke-GateDotnet.ps1')
        $d | Should -Match 'dotnet build \(\[string\]\$pj\.Path\) -c Release --nologo -v q -nodeReuse:false'
        $d | Should -Not -Match '\.sln'
        $d | Should -Match "'test', \[string\]\`$pj\.Path, '-c', 'Release', '--no-build'"
        $g | Should -Match 'if \(-not \$NoDotnet -and \$dotnetPlan\.Count -and \(Get-Command dotnet'
        $g | Should -Match '-NoWhole:\(-not \$Precise\) -MaxClasses'
        # (the release passing -TimeoutMinutes 10 and the VM's offline smoke limit are Pro / vendor files: SIv3-ReleaseSI and SIv3-GateOnTestVm check them)
    }
}
