#Requires -Version 5.1
<#
    SHIPPED HELPERS MUST NOT CONTRADICT THE CONTRACTS THEY SHIP WITH (#143).

      * the config sample pulled a storage KEY (storage is OAuth-only);
      * tools\Run-AllEngines.ps1 killed EVERY launcher process on the host -- scheduled production runs too;
      * the GitHub-update preserve list said launchers\ (the folder is launcher\) and never covered the
        *.custom.* overlays, so riskscore.index.custom.csv was overwritten on update;
      * an internal AD domain and an internal company name sat in published files;
      * tools\Push-PreviewBundle.ps1 read a removed v2.2\ folder, and fixed naively would have zipped the
        customer's config (SPN secret) and internal docs "ready to ship to a customer".
    The scripts' OWN filter code is lifted by AST and evaluated.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    function script:ParseFile([string]$Rel) {
        [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:SIRoot $Rel), [ref]$null, [ref]$null)
    }
}

Describe 'the config sample does not fetch a storage key' {
    It 'no SI-StorageKey pull' {
        (Get-Content -LiteralPath (Join-Path $script:SIRoot 'config\SecurityInsight.custom.sample.ps1') -Raw) |
            Should -Not -Match "Get-PlatformSecret[^\r\n]*'SI-StorageKey'"
    }
}

Describe 'Run-AllEngines closes only its own windows' {
    BeforeAll {
        $ast = ParseFile 'tools\Run-AllEngines.ps1'
        $assign = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$stale' }, $true) | Select-Object -First 1
        $where  = $assign.Right.FindAll({ param($n) $n -is [System.Management.Automation.Language.ScriptBlockExpressionAst] }, $true) | Select-Object -First 1
        $script:StaleFilter = [scriptblock]::Create($where.ScriptBlock.EndBlock.Extent.Text)
    }
    It 'a scheduled production launcher is left alone; this tool''s own -NoExit window is closed' {
        $mePid = 1; $launcherPattern = 'launcher\.internal-vm\.ps1'
        $procs = @(
            [pscustomobject]@{ ProcessId = 10; CommandLine = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\SI\launcher\endpoint\launcher.internal-vm.ps1"' },
            [pscustomobject]@{ ProcessId = 11; CommandLine = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -NoExit -File "C:\SI\launcher\endpoint\launcher.internal-vm.ps1"' }
        )
        $hit = @($procs | Where-Object $script:StaleFilter)
        @($hit.ProcessId) | Should -Be @(11)
    }
}


Describe 'no internal names in published files' {
    It 'the diagnostics example and the wizard help text use placeholders' {
        # The CMDB diagnostic is a Pro file: absent from the Community edition, checked where it exists.
        $cmdbDiag = Join-Path $script:SIRoot 'diagnostics\Measure-SICmdbMatchRate.ps1'
        if (Test-Path -LiteralPath $cmdbDiag) { (Get-Content -LiteralPath $cmdbDiag -Raw) | Should -Not -Match '(?i)2linkit' }
        (Get-Content -LiteralPath (Join-Path $script:SIRoot 'setup\ConfigWizard\Setup-SecurityInsight.html') -Raw) | Should -Not -Match '(?i)2linkit'
    }
}

Describe 'the preview bundle carries tracked files only, minus internal documents' {
    BeforeAll {
        $ast = ParseFile 'tools\Push-PreviewBundle.ps1'
        $nb = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$script:NeverBundle' }, $true) | Select-Object -First 1
        $script:NeverBundle = & ([scriptblock]::Create($nb.Right.Extent.Text))
        $fn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-SIBundleFiles' }, $true) | Select-Object -First 1
        . ([scriptblock]::Create($fn.Extent.Text))
        $script:HaveGit = [bool](Get-Command git -ErrorAction SilentlyContinue)
    }
    It 'the source is the solution folder, not the removed v2.2 folder' {
        (Get-Content -LiteralPath (Join-Path $script:SIRoot 'tools\Push-PreviewBundle.ps1') -Raw) | Should -Not -Match "'SOLUTIONS\\SecurityInsight\\v2\.2'"
    }
    It 'engine code is in; internal docs and any customer overlay are out' -Tag 'PrivateRepo' -Skip:(-not (Get-Command git -ErrorAction SilentlyContinue)) {
        $files = @(Get-SIBundleFiles -SolutionRoot $script:SIRoot)
        $files | Should -Contain 'engine/risk-analysis/Invoke-RiskAnalysis.ps1'
        foreach ($x in 'CLAUDE.md','docs/REQUIREMENTS.md','docs/TESTS.md') { $files | Should -Not -Contain $x }
        @($files | Where-Object { $_ -like 'docs/V3-*' -or $_ -like 'internal/*' -or $_ -like 'config/*.custom.ps1' }).Count | Should -Be 0
    }
    It 'the Community layout drops every SecurityInsight Pro path; the paid layouts keep them' -Tag 'PrivateRepo' -Skip:(-not (Get-Command git -ErrorAction SilentlyContinue)) {
        $pro = @((Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'solution.publish.json') | ConvertFrom-Json).excludePaths |
                 Where-Object { $_ -notlike 'docs/*' })
        $isPro = { param($f) @($pro | Where-Object { $f -eq $_ -or $f.StartsWith("$_/") }).Count -gt 0 }
        $community = @(Get-SIBundleFiles -SolutionRoot $script:SIRoot -Community)
        $paid      = @(Get-SIBundleFiles -SolutionRoot $script:SIRoot)
        @($community | Where-Object { & $isPro $_ }).Count | Should -Be 0
        $community | Should -Contain 'engine/risk-analysis/Invoke-RiskAnalysis.ps1'
        @($paid | Where-Object { & $isPro $_ }).Count | Should -BeGreaterThan 0 -Because 'paying customers receive Pro'
    }
}
