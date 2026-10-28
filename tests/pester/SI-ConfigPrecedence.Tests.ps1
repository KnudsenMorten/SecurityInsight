#Requires -Version 5.1
<#
    THE CUSTOMER'S SETTINGS WIN OVER THE SHIPPED ENGINE DEFAULTS (#183, operator decision 2026-09-30).

    Initialize-LauncherConfig loaded config\SecurityInsight.custom.ps1 BEFORE the shipped
    launcher\<engine>\LauncherConfig.defaults.ps1, so every value a defaults file set unguarded silently
    overwrote what the customer had set -- ExportDestination, AutoBucketMax, SI_Sinks_*, SI_ForceFullRun_*,
    SI_DefenderWorkspaceResourceId. The loader's own header, the sample and the defaults headers all said
    the opposite. Proven on PS 5.1 by the 2026-09-30 config review; on the internal tenant it discarded
    the configured Defender workspace and the chosen output sinks.

    Each scenario runs the REAL loader against the REAL shipped defaults in a CHILD process, so the
    dozens of globals it sets can never leak into a later suite.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:Exe    = [Diagnostics.Process]::GetCurrentProcess().Path

    # Runs Initialize-LauncherConfig (community mode) for one engine with the given customer files and
    # returns the named globals as a hashtable.
    function script:Invoke-Load {
        param([string]$Engine, [string]$SolutionCustom, [string]$EngineCustom, [string[]]$Names)
        $root = Join-Path ([IO.Path]::GetTempPath()) ('si183-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
        New-Item -ItemType Directory -Force (Join-Path $root 'config') | Out-Null
        try {
            if ($SolutionCustom) { [IO.File]::WriteAllText((Join-Path $root 'config\SecurityInsight.custom.ps1'), $SolutionCustom, [Text.UTF8Encoding]::new($true)) }
            $engineCustomPath = Join-Path $root 'engine.custom.ps1'
            # Always pass an explicit per-engine file, so a developer's own gitignored
            # launcher\<engine>\LauncherConfig.custom.ps1 can never leak into the result.
            [IO.File]::WriteAllText($engineCustomPath, $(if ($EngineCustom) { $EngineCustom } else { '# none' }), [Text.UTF8Encoding]::new($true))
            $out = Join-Path $root 'out.json'
            $lib = Join-Path $script:SIRoot 'launcher\_lib\Initialize-LauncherConfig.ps1'
            $dir = Join-Path $script:SIRoot "launcher\$Engine"
            $cmd = @"
`$ErrorActionPreference = 'Stop'
. '$lib'
Initialize-LauncherConfig -Solution 'SecurityInsight' -Engine 'X' -LauncherDir '$dir' -RepoRoot '$root' -Mode 'community' -CustomConfigPath '$engineCustomPath' *> `$null
`$h = @{}
foreach (`$n in @('$($Names -join "','")')) {
    `$v = Get-Variable -Name `$n -Scope Global -ValueOnly -ErrorAction SilentlyContinue
    # Arrays are flattened HERE: Windows PowerShell 5.1's ConvertTo-Json does not round-trip an array
    # held in a hashtable value the way pwsh 7 does.
    `$h[`$n] = if (`$v -is [array]) { (@(`$v) -join ',') } else { `$v }
}
`$h | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath '$out' -Encoding UTF8
"@
            & $script:Exe -NoProfile -NonInteractive -Command $cmd | Out-Null
            $json = Get-Content -Raw -LiteralPath $out | ConvertFrom-Json
            $h = @{}; foreach ($p in $json.PSObject.Properties) { $h[$p.Name] = $p.Value }
            $h
        } finally { Remove-Item -Recurse -Force $root -ErrorAction SilentlyContinue }
    }
}

Describe 'a value in config\SecurityInsight.custom.ps1 beats the shipped engine default (#183)' {

    It 'risk-analysis: ExportDestination, AutoBucketMax and OverwriteXlsx are the customer''s' {
        $r = Invoke-Load -Engine 'risk-analysis' -Names 'ExportDestination', 'AutoBucketMax', 'OverwriteXlsx' -SolutionCustom (
            "`$global:ExportDestination = 'https://acct.blob.core.windows.net/si/'`r`n`$global:AutoBucketMax = 1024`r`n`$global:OverwriteXlsx = `$false`r`n")
        $r.ExportDestination | Should -Be 'https://acct.blob.core.windows.net/si/'
        $r.AutoBucketMax | Should -Be 1024
        $r.OverwriteXlsx | Should -Be $false
    }

    It 'endpoint: SI_Sinks_Endpoint, SI_ForceFullRun_Endpoint and SI_DefenderWorkspaceResourceId are the customer''s' {
        $ws = '/subscriptions/0/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/def'
        $r = Invoke-Load -Engine 'endpoint' -Names 'SI_Sinks_Endpoint', 'SI_ForceFullRun_Endpoint', 'SI_DefenderWorkspaceResourceId' -SolutionCustom (
            "`$global:SI_Sinks_Endpoint = @('LA','Excel')`r`n`$global:SI_ForceFullRun_Endpoint = `$true`r`n`$global:SI_DefenderWorkspaceResourceId = '$ws'`r`n")
        (@($r.SI_Sinks_Endpoint) -join ',') | Should -Be 'LA,Excel'
        $r.SI_ForceFullRun_Endpoint | Should -Be $true
        $r.SI_DefenderWorkspaceResourceId | Should -Be $ws
    }

    It 'the engine default still applies where the customer set nothing' {
        $r = Invoke-Load -Engine 'risk-analysis' -Names 'AutoBucketMax', 'OverwriteXlsx' -SolutionCustom "# nothing set`r`n"
        $r.AutoBucketMax | Should -Be 131072
        $r.OverwriteXlsx | Should -Be $true
    }

    It 'the per-engine LauncherConfig.custom.ps1 still beats both (closest wins)' {
        $r = Invoke-Load -Engine 'risk-analysis' -Names 'AutoBucketMax' -SolutionCustom "`$global:AutoBucketMax = 1024`r`n" -EngineCustom "`$global:AutoBucketMax = 2048`r`n"
        $r.AutoBucketMax | Should -Be 2048
    }
}

Describe 'the shipped samples no longer carry values that would now take effect by surprise' {

    It '<_> sets no active placeholder ExportDestination, no forced full run, and the engine''s AutoBucketMax' -ForEach @(
        'config\SecurityInsight.custom.sample.ps1', 'config\SecurityInsight.custom.community.sample.ps1'
    ) {
        $lines = @(Get-Content -LiteralPath (Join-Path $script:SIRoot $_) | Where-Object { $_ -notmatch '^\s*#' })
        @($lines | Where-Object { $_ -match '^\s*\$global:ExportDestination\s*=' -and $_ -match '<' }).Count | Should -Be 0 -Because 'a placeholder URL would now be used as the export target'
        @($lines | Where-Object { $_ -match '^\s*\$global:SI_ForceFullRun_\w+\s*=\s*\$true' }).Count | Should -Be 0 -Because 'a forced full run on every schedule would now take effect'
        @($lines | Where-Object { $_ -match '^\s*\$global:AutoBucketMax\s*=\s*(\d+)' -and [int]$Matches[1] -lt 131072 }).Count | Should -Be 0 -Because 'a small AutoBucketMax would now cap large estates'
    }
}
