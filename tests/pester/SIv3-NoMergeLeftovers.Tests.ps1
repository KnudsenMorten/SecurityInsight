#Requires -Modules Pester
<#
    No shipped PowerShell file may run a merge leftover as a command. Found live 2026-10-05: four lines of '======'
    left by a hand-resolved merge in engine\asset-cmdb\Invoke-SIVulnLoop.ps1 made the vulnerability connector die on
    its first line ("The term '======' is not recognized") on ring 1. The unit suites never caught it: they load the
    helper files, never that script's main body. This parses EVERY .ps1/.psm1 and fails on (a) a command whose name
    is only '=', '<' or '>' characters, (b) a git conflict marker at the start of a line, (c) a parse error.
#>
BeforeDiscovery {
    $script:siRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
    # -Include is ignored with -LiteralPath on PS 5.1: filter on the extension
    $script:files = @(Get-ChildItem -LiteralPath $script:siRoot -Recurse -File |
        Where-Object { ($_.Extension -eq '.ps1' -or $_.Extension -eq '.psm1') -and $_.FullName -notmatch '[\\/](node_modules|bin|obj|\.git)[\\/]' } |
        ForEach-Object { @{ Path = $_.FullName; Rel = $_.FullName.Substring($script:siRoot.Length + 1) } })
}
Describe 'Shipped PowerShell has no merge leftovers' {
    It '<Rel> parses and runs no merge leftover' -ForEach $script:files {
        $tokens = $null; $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
        @($errors | ForEach-Object { 'line {0}: {1}' -f $_.Extent.StartLineNumber, $_.Message }) | Should -BeNullOrEmpty -Because "$Rel must parse"
        @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and ([string]$n.GetCommandName()) -match '^[=<>]{3,}$' }, $true) |
            ForEach-Object { 'line {0}: {1}' -f $_.Extent.StartLineNumber, $_.GetCommandName() }) | Should -BeNullOrEmpty -Because "$Rel must not run a merge leftover as a command"
        @([IO.File]::ReadAllLines($Path) | Select-String -Pattern '^(<{7}|>{7}|={7})( |$)' | ForEach-Object { 'line {0}' -f $_.LineNumber }) |
            Should -BeNullOrEmpty -Because "$Rel must not hold a git conflict marker"
    }
}
