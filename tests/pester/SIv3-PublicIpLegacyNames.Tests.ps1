#Requires -Version 5.1
<#
    PUBLIC-IP HISTORY DOES NOT "STOP" SILENTLY (#186, operator decision 2026-09-30: "New table + warn").

    3.0.0 publishes public IPs to SI_PublicIP_Profile_CL through dcr-si-publicip-profile and no longer honours
    the legacy $global:SI_Shodan_DcrName / SI_Shodan_TableName. An install still carrying them (every
    internal install -- the internal config generator wrote one) would see its public-IP history move to a
    new, empty table with nothing in any log to explain it. The engine now says so, once per run.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $out = Join-Path $script:SIRoot 'engine\asset-profiling\stages\Invoke-Output.ps1'
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($out, [ref]$null, [ref]$null)
    # The real block, lifted from the engine -- never a copy pasted here.
    $script:Block = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.IfStatementAst] -and
        $n.Extent.Text -match 'SILegacyPublicIpNamesReported' -and $n.Extent.Text.StartsWith('if ($RunContext.Engine') }, $true) | Select-Object -First 1
    function script:Invoke-Block([string]$Engine, [hashtable]$Globals) {
        $script:SILegacyPublicIpNamesReported = $false
        foreach ($k in $Globals.Keys) { Set-Variable -Name $k -Scope Global -Value $Globals[$k] }
        try {
            $RunContext = [pscustomobject]@{ Engine = $Engine }
            $tableName = 'SI_PublicIP_Profile'; $dcrName = 'dcr-si-publicip-profile'
            $w = & ([scriptblock]::Create($script:Block.Extent.Text)) 3>&1
            @($w | Where-Object { $_ -is [System.Management.Automation.WarningRecord] } | ForEach-Object { $_.Message })
        } finally { foreach ($k in $Globals.Keys) { Remove-Variable -Name $k -Scope Global -ErrorAction SilentlyContinue } }
    }
}

Describe 'the legacy public-IP names are reported, not silently ignored (#186)' {
    It 'the engine carries the check (lifted from its AST)' { $script:Block | Should -Not -BeNullOrEmpty }

    It 'a legacy DCR name produces ONE clear line naming the new table and DCR and where the history is' {
        $m = @(Invoke-Block -Engine 'publicip' -Globals @{ SI_Shodan_DcrName = 'dcr-si-publicip' })
        @($m).Count | Should -Be 1
        $m[0] | Should -Match 'SI_Shodan_DcrName is no longer used'
        $m[0] | Should -Match "SI_PublicIP_Profile_CL through DCR 'dcr-si-publicip-profile'\."
        $m[0] | Should -Match 'the table the retired public-IP scanner wrote to'
        $m[0] | Should -Not -Match "dcr-si-publicip-profileRows"
    }
    It 'both legacy names are named together, and the old table is named from the customer''s own setting' {
        $m = @(Invoke-Block -Engine 'publicip' -Globals @{ SI_Shodan_DcrName = 'a'; SI_Shodan_TableName = 'SI_OldScanner' })[0]
        $m | Should -Match 'SI_Shodan_DcrName / SI_Shodan_TableName'
        $m | Should -Match 'the previous table \(SI_OldScanner_CL\)'
    }
    It 'nothing is said without a legacy name, or for another engine' {
        @(Invoke-Block -Engine 'publicip' -Globals @{}).Count | Should -Be 0
        @(Invoke-Block -Engine 'endpoint' -Globals @{ SI_Shodan_DcrName = 'x' }).Count | Should -Be 0
    }
    It 'no setup path writes a legacy name any more' {
        foreach ($f in 'setup\ConfigWizard\backend\Write-SICustomConfig.ps1', 'INTERNAL\New-SISolutionConfig.ps1') {
            $p = Join-Path $script:SIRoot $f
            if (-not (Test-Path -LiteralPath $p)) { continue }   # INTERNAL is not in every copy
            $code = ((Get-Content -LiteralPath $p) | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
            $code | Should -Not -Match 'global:SI_Shodan_(DcrName|TableName)\s*=' -Because $f
        }
    }
}
