#Requires -Version 5.1
<#
    A DIRECT Invoke-SIEngineRun.ps1 LOADS THE CUSTOMER CONFIG; A LAUNCHED ONE DOES NOT RE-LOAD IT (#130).

    The auto-load path used THREE Split-Path calls -- a leftover of the old v2.2\ layer -- and resolved
    to SOLUTIONS\config\, which does not exist: a direct run silently never loaded custom.ps1.
    Simply correcting the path would have been worse: every launcher already applies the config layers
    and THEN the CLI flags that must win, so an engine that re-sourced custom.ps1 afterwards would
    silently invert that precedence on every scheduled run. The engine now reads its call stack.

    The tests run the SHIPPED resolution code (lifted by AST) inside a temp tree laid out like the
    solution, called directly and from a script named like a launcher -- a genuine call stack.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $engine = Join-Path $script:SIRoot 'engine\asset-profiling\Invoke-SIEngineRun.ps1'
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($engine, [ref]$null, [ref]$null)
    $assign = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                               $n.Parent -is [System.Management.Automation.Language.NamedBlockAst] -and
                               $n.Left.Extent.Text -in '$__calledByLauncher', '$customConfigPath' }, $false))
    $snippet = ($assign | Sort-Object { $_.Extent.StartOffset } | ForEach-Object { $_.Extent.Text }) -join "`r`n"

    # temp solution tree: <root>\SI\engine\asset-profiling\probe.ps1 and <root>\SI\launcher\x\launcher.test-vm.ps1
    $script:Tmp = Join-Path ([IO.Path]::GetTempPath()) ('si-cfg-' + [guid]::NewGuid().ToString('N'))
    $script:Si  = Join-Path $script:Tmp 'SI'
    $ap = Join-Path $script:Si 'engine\asset-profiling'
    $ln = Join-Path $script:Si 'launcher\x'
    New-Item -ItemType Directory -Force -Path $ap, $ln | Out-Null
    [IO.File]::WriteAllText((Join-Path $ap 'probe.ps1'), ($snippet + "`r`n" + '$customConfigPath'))
    $script:Probe = Join-Path $ap 'probe.ps1'
    [IO.File]::WriteAllText((Join-Path $ln 'launcher.test-vm.ps1'), ('& ''{0}''' -f $script:Probe))
    $script:Launcher = Join-Path $ln 'launcher.test-vm.ps1'
    [IO.File]::WriteAllText((Join-Path $ln 'some-other-script.ps1'), ('& ''{0}''' -f $script:Probe))
    $script:Other = Join-Path $ln 'some-other-script.ps1'
    $script:Snippet = $snippet
}

AfterAll {
    if ($script:Tmp -and $script:Tmp.StartsWith([IO.Path]::GetTempPath())) { Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue }
}

Describe 'the config path the engine resolves' {
    BeforeEach { $global:SI_CustomConfigPath = $null }
    AfterEach  { $global:SI_CustomConfigPath = $null }

    It 'the shipped resolution code was found (both assignments)' {
        $script:Snippet | Should -Match '\$__calledByLauncher = '
        $script:Snippet | Should -Match '\$customConfigPath = '
    }
    It 'a DIRECT run resolves the solution root config\SecurityInsight.custom.ps1 (it resolved one level too high)' {
        $p = & $script:Probe
        $expected = Join-Path $script:Si 'config/SecurityInsight.custom.ps1'
        [IO.Path]::GetFullPath($p) | Should -Be ([IO.Path]::GetFullPath($expected))
    }
    It 'a run STARTED BY A LAUNCHER does not re-load the config (the launcher already applied the layers + CLI flags)' {
        $p = & $script:Launcher
        $p | Should -BeNullOrEmpty
    }
    It 'a script that is not a launcher does not suppress the load' {
        $p = & $script:Other
        $p | Should -Not -BeNullOrEmpty
    }
    It 'an explicit SI_CustomConfigPath is always honoured, even under a launcher' {
        $global:SI_CustomConfigPath = 'C:\somewhere\my.custom.ps1'
        (& $script:Launcher) | Should -Be 'C:\somewhere\my.custom.ps1'
    }
}
