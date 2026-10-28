#Requires -Version 5.1
<#
    THE TREND AND ASSET-TAGGING ENGINES RECORD THEIR RUN HEALTH LIKE EVERY OTHER ENGINE.

    Found by the live 2.2 -> 3.0 upgrade test: the trend engine wrote no SI_RunHealth_CL row at all -- no START, no END
    -- so a failed or crashed trend run could not be told from one that never ran, and no telemetry run report was sent
    for it (that report goes out at the run-health END). Asset tagging had none either.

    SI_TEST_ROOT (optional) points the wiring tests at another tree, e.g. an export of the code before the fix.
#>

BeforeAll {
    # #830: the trend job writes SI_Trend_CL only while the copy of the report rows to Log Analytics is on (off by default --
    # SIv3-SqlOnlyReaders.Tests.ps1); these tests drive that copy
    $script:SendToLaBefore = $global:SendToLogAnalytics; $global:SendToLogAnalytics = $true
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    if ($env:SI_TEST_ROOT) { $script:SIRoot = $env:SI_TEST_ROOT }
    $script:Scope = Join-Path $script:SIRoot 'engine\_shared\SI-RunHealthScope.ps1'

    function script:Get-TryFinallyCalls {
        # Every command named $Name that sits inside the FINALLY of a top-level try, in $Path.
        param([string]$Path, [string]$Name)
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$null)
        $tries = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.TryStatementAst] -and $n.Finally }, $true))
        @(foreach ($t in $tries) {
            $t.Finally.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq $Name }, $true)
        })
    }
    function script:Get-Calls {
        param([string]$Path, [string]$Name)
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$null)
        @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq $Name }, $true))
    }
}

Describe 'the run-health scope helper' {
    BeforeAll {
        $global:SITestSent = New-Object System.Collections.ArrayList
        # the stub FIRST, so the helper does not load the real record writer
        function global:Send-SIRunHealthRow {
            param($RunContext, $Phase, $AssetCount, $ExitReason, $ErrorMessage, [switch]$NoTelemetry)
            [void]$global:SITestSent.Add([pscustomobject]@{ Phase = $Phase; Engine = $RunContext.Engine; RunId = $RunContext.RunId; ExitReason = $ExitReason; WhatIf = $global:WhatIfMode; Msg = $ErrorMessage })
        }
        . $script:Scope
    }
    BeforeEach { $global:SITestSent.Clear(); $global:WhatIfMode = $null }
    AfterAll   { $global:WhatIfMode = $null; Remove-Item -Path 'Function:\Send-SIRunHealthRow' -ErrorAction SilentlyContinue }

    It 'START then END, same run id, the engine name and the exit reason' {
        $rh = Start-SIRunHealth -Engine 'asset-trend' -RunId 'run-1'
        Stop-SIRunHealth -Context $rh -ExitReason 'success-partial' -ErrorMessage 'weekly view unknown'
        @($global:SITestSent).Count | Should -Be 2
        $global:SITestSent[0].Phase | Should -Be 'Start'
        $global:SITestSent[1].Phase | Should -Be 'End'
        @($global:SITestSent | ForEach-Object { $_.RunId } | Select-Object -Unique) | Should -Be @('run-1')
        $global:SITestSent[1].Engine | Should -Be 'asset-trend'
        $global:SITestSent[1].ExitReason | Should -Be 'success-partial'
    }

    It 'END is sent once, even when called twice' {
        $rh = Start-SIRunHealth -Engine 'asset-trend'
        Stop-SIRunHealth -Context $rh -ExitReason 'success'
        Stop-SIRunHealth -Context $rh -ExitReason 'error'
        @($global:SITestSent | Where-Object Phase -eq 'End').Count | Should -Be 1
    }

    It 'an unknown exit reason is recorded as error, never passed through' {
        $rh = Start-SIRunHealth -Engine 'asset-trend'
        Stop-SIRunHealth -Context $rh -ExitReason 'banana'
        $global:SITestSent[1].ExitReason | Should -Be 'error'
    }

    It 'report-only asset tagging is still recorded, and the report-only switch is restored' {
        $global:WhatIfMode = $true
        $rh = Start-SIRunHealth -Engine 'asset-tagging' -RecordInReportMode
        Stop-SIRunHealth -Context $rh -ExitReason 'success'
        @($global:SITestSent | Where-Object { $_.WhatIf -eq $false }).Count | Should -Be 2 -Because 'the record is written while the run reports only'
        $global:WhatIfMode | Should -BeTrue -Because 'the engine must stay report-only'
    }

    It 'a failing record never fails the run' {
        function global:Send-SIRunHealthRow { throw 'workspace unreachable' }
        { $rh = Start-SIRunHealth -Engine 'asset-trend'; Stop-SIRunHealth -Context $rh -ExitReason 'success' } | Should -Not -Throw
    }
}

Describe 'the trend engine records its run (end to end, offline)' {
    BeforeAll {
        $global:SITestRows = New-Object System.Collections.ArrayList
        function global:Send-SIRunHealthRow {
            param($RunContext, $Phase, $AssetCount, $ExitReason, $ErrorMessage, [switch]$NoTelemetry)
            [void]$global:SITestRows.Add([pscustomobject]@{ Phase = $Phase; Engine = $RunContext.Engine; RunId = $RunContext.RunId; ExitReason = $ExitReason })
        }
        # Azure access stubs: no network, no Az modules.
        function global:Invoke-SIArm { throw 'not reached' }   # the Azure access layer counts as loaded: these stubs answer
        function global:Get-SIAzContext { $null }
        function global:Get-SIAzOperationalInsightsWorkspace { [pscustomobject]@{ CustomerId = [guid]'00000000-0000-0000-0000-000000000001' } }
        $script:Engine = Join-Path $script:SIRoot 'engine\asset-trend\Invoke-SITrend.ps1'
        $global:SI_WorkspaceResourceId = '/subscriptions/s/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/ws'
    }
    AfterAll {
        foreach ($f in 'Send-SIRunHealthRow', 'Invoke-SIArm', 'Get-SIAzContext', 'Get-SIAzOperationalInsightsWorkspace', 'Invoke-SIAzOperationalInsightsQuery') {
            Remove-Item -Path ("Function:\{0}" -f $f) -ErrorAction SilentlyContinue
        }
        $global:SI_WorkspaceResourceId = $null
    }
    BeforeEach { $global:SITestRows.Clear() }

    It 'a run that cannot read its source: START, then END as error, and the error still reaches the caller' {
        function global:Invoke-SIAzOperationalInsightsQuery { throw 'service unavailable' }
        { & $script:Engine 6>$null } | Should -Throw
        @($global:SITestRows | ForEach-Object Phase) | Should -Be @('Start', 'End')
        $global:SITestRows[1].ExitReason | Should -Be 'error'
        $global:SITestRows[1].Engine | Should -Be 'asset-trend'
    }

    # #636: the trend engine reads the Detailed grain by default (the Summary step is off by default)
    It 'a run with nothing to roll up yet: START, then END as success' {
        function global:Invoke-SIAzOperationalInsightsQuery { throw "Failed to resolve table or column expression named 'SI_RiskAnalysis_Detailed_CL'" }
        & $script:Engine 6>$null
        @($global:SITestRows | ForEach-Object Phase) | Should -Be @('Start', 'End')
        $global:SITestRows[1].ExitReason | Should -Be 'success'
    }

    It 'a dry run publishes nothing -- no health record either' {
        function global:Invoke-SIAzOperationalInsightsQuery { throw "Failed to resolve table or column expression named 'SI_RiskAnalysis_Detailed_CL'" }
        & $script:Engine -DryRun 6>$null
        @($global:SITestRows).Count | Should -Be 0
    }
}

Describe 'asset tagging is wired the same way' {
    It 'START before the run body, END in the finally of the try around it' {
        $p = Join-Path $script:SIRoot 'engine\asset-tagging\AssetTagging.ps1'
        $start = @(Get-Calls -Path $p -Name 'Start-SIRunHealth')
        $start.Count | Should -Be 1
        $start[0].Extent.Text | Should -Match "-Engine 'asset-tagging'"
        $start[0].Extent.Text | Should -Match '-RecordInReportMode' -Because 'report-only is the default and still writes its activity table'
        @(Get-TryFinallyCalls -Path $p -Name 'Stop-SIRunHealth').Count | Should -Be 1
    }
    It 'the trend engine too' {
        $p = Join-Path $script:SIRoot 'engine\asset-trend\Invoke-SITrend.ps1'
        @(Get-Calls -Path $p -Name 'Start-SIRunHealth').Count | Should -Be 1
        @(Get-TryFinallyCalls -Path $p -Name 'Stop-SIRunHealth').Count | Should -Be 1
    }
    It 'both names reach a telemetry job the receiver knows' {
        $src = Get-Content -Raw (Join-Path $script:SIRoot 'engine\_shared\SI-TelemetrySend.ps1')
        $src | Should -Match "'asset-trend'\s*=\s*'si-trend'"
        $src | Should -Match "'asset-tagging'\s*=\s*'si-asset-tagging'"
    }
}

AfterAll { $global:SendToLogAnalytics = $script:SendToLaBefore }
