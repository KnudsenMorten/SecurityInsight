#Requires -Version 5.1
<#
    THE RETIRED POWER BI REFRESH IS SAID, NOT SILENT (#275 G5 / release blocker R5).

    2.2 refreshed a Power BI dataset after each Risk Analysis run when $global:SendToPowerBI was $true
    (PowerBI_WorkspaceName / _DatasetName / _AuthTenantId / _AuthClientId / _AuthClientSecret). 3.0 removed it.
    An upgraded config that still turns it on was ignored in silence -- the dataset just stopped refreshing.
    Initialize-LauncherConfig now prints ONE line when the refresh is still configured, and nothing otherwise.

    Each scenario runs the REAL loader in a CHILD process of the current shell (run the suite on powershell.exe
    AND pwsh), with the customer's settings in config\SecurityInsight.custom.ps1, and counts the lines.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:Exe    = [Diagnostics.Process]::GetCurrentProcess().Path

    # Runs Initialize-LauncherConfig (community mode, risk-analysis launcher) with the given solution-wide
    # settings and returns every line it wrote, from every stream.
    function script:Invoke-LoadOutput {
        param([string]$SolutionCustom)
        $root = Join-Path ([IO.Path]::GetTempPath()) ('si275pbi-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
        New-Item -ItemType Directory -Force (Join-Path $root 'config') | Out-Null
        try {
            [IO.File]::WriteAllText((Join-Path $root 'config\SecurityInsight.custom.ps1'), $SolutionCustom, [Text.UTF8Encoding]::new($true))
            # An explicit per-engine file, so a developer's own launcher\<engine>\LauncherConfig.custom.ps1 never leaks in.
            $engineCustomPath = Join-Path $root 'engine.custom.ps1'
            [IO.File]::WriteAllText($engineCustomPath, '# none', [Text.UTF8Encoding]::new($true))
            $out = Join-Path $root 'out.txt'
            $lib = Join-Path $script:SIRoot 'launcher\_lib\Initialize-LauncherConfig.ps1'
            $dir = Join-Path $script:SIRoot 'launcher\risk-analysis'
            $cmd = @"
`$ErrorActionPreference = 'Stop'
. '$lib'
Initialize-LauncherConfig -Solution 'SecurityInsight' -Engine 'RiskAnalysis' -LauncherDir '$dir' -RepoRoot '$root' -Mode 'community' -CustomConfigPath '$engineCustomPath' *>&1 | ForEach-Object { [string]`$_ } | Set-Content -LiteralPath '$out' -Encoding UTF8
"@
            & $script:Exe -NoProfile -NonInteractive -Command $cmd | Out-Null
            @(Get-Content -LiteralPath $out -Encoding UTF8)
        } finally { Remove-Item -Recurse -Force $root -ErrorAction SilentlyContinue }
    }

    function script:Get-NoticeLines([string[]]$Lines) {
        @($Lines | Where-Object { $_ -match 'Power BI refresh was retired' })
    }
}

Describe 'the retired Power BI refresh is reported once when it is still configured (#275 G5)' {

    It 'SendToPowerBI = $true -> exactly one line, in plain words, naming where to read instead' {
        $lines = Invoke-LoadOutput -SolutionCustom "`$global:SendToPowerBI = `$true`r`n"
        $n = @(Get-NoticeLines $lines)
        $n.Count | Should -Be 1
        $n[0] | Should -Match 'SecurityInsight 3\.0'
        $n[0] | Should -Match 'Log Analytics'
        $n[0] | Should -Match 'workbook'
        $n[0] | Should -Match 'Pro web app'
        # Customer language: no internal tracking numbers in the text.
        $n[0] | Should -Not -Match '#\d+|\bR5\b|\bG5\b'
    }

    It 'only PowerBI_* settings with a value (the refresh switch absent) -> exactly one line' {
        $lines = Invoke-LoadOutput -SolutionCustom "`$global:PowerBI_WorkspaceName = 'SecurityInsight-Reports'`r`n`$global:PowerBI_DatasetName = 'SecurityInsight - Risk Analysis'`r`n"
        @(Get-NoticeLines $lines).Count | Should -Be 1
    }

    It 'the switch AND every PowerBI_* setting -> still exactly one line' {
        $lines = Invoke-LoadOutput -SolutionCustom (
            "`$global:SendToPowerBI = `$true`r`n`$global:PowerBI_WorkspaceName = 'w'`r`n`$global:PowerBI_DatasetName = 'd'`r`n" +
            "`$global:PowerBI_AuthTenantId = 't'`r`n`$global:PowerBI_AuthClientId = 'c'`r`n`$global:PowerBI_AuthClientSecret = 's'`r`n")
        @(Get-NoticeLines $lines).Count | Should -Be 1
    }

    It 'the internal name SI_SendToPowerBI = $true -> exactly one line' {
        $lines = Invoke-LoadOutput -SolutionCustom "`$global:SI_SendToPowerBI = `$true`r`n"
        @(Get-NoticeLines $lines).Count | Should -Be 1
    }
}

Describe 'nothing is said when the Power BI refresh is not configured (#275 G5)' {

    It 'no Power BI setting at all -> no line' {
        $lines = Invoke-LoadOutput -SolutionCustom "# nothing set`r`n"
        @(Get-NoticeLines $lines).Count | Should -Be 0
        @($lines | Where-Object { $_ -match 'Power BI' }).Count | Should -Be 0
    }

    It 'SendToPowerBI = $false (the 2.2 default) and empty PowerBI_* values -> no line' {
        $lines = Invoke-LoadOutput -SolutionCustom "`$global:SendToPowerBI = `$false`r`n`$global:SI_SendToPowerBI = `$false`r`n`$global:PowerBI_WorkspaceName = ''`r`n`$global:PowerBI_AuthClientSecret = `$null`r`n"
        @(Get-NoticeLines $lines).Count | Should -Be 0
    }
}
