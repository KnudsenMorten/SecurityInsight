#Requires -Version 5.1
<#
    THE RISK TREND IS WRITTEN -- by the job and at the end of Risk Analysis (#394).

    Found by the v3 release-readiness upgrade test: on every install and both PowerShell versions SI_Trend_CL was never
    created. The trend engine's `-Rows` parameter and its local `$rows` list were ONE variable (names are
    case-insensitive), so the list became a fixed array and `.Add` threw ("Collection was of a fixed size"); and at the
    end of Risk Analysis the same collision wiped the rows RA handed over ("the 0 row(s) this Risk Analysis run
    published"). The trend's END telemetry report then failed too ("You cannot call a method on a null-valued
    expression"): run with `&`, the trend got a script scope of its own, and the shared functions Risk Analysis had
    loaded read their settings from that EMPTY `$script:` scope.

    These tests run the REAL engine (engine/asset-trend/Invoke-SITrend.ps1) end to end, offline, on a realistic Risk
    Analysis Summary fixture. Only the edges are stubbed: the Log Analytics query, the workspace lookup, the run-health
    record, and the ingestion calls (global aliases -- an alias wins over the functions the engine dot-sources itself).
      1. the job (no -PublishedRows): reads the snapshot, writes the rollup rows (global / severity / tier / domain and
         their counted twins), END success;
      2. the end of Risk Analysis (Invoke-SIRaTrendAtEnd -> the real engine): the rows it is handed are rolled up --
         the snapshot query is never sent -- and written; the rollup equals the job's on the same rows;
      3. the trend run from Risk Analysis sees Risk Analysis's `$script:` state (the telemetry job map resolves), where a
         run with `&` saw none;
      4. wiring: Risk Analysis hands over the rows Log Analytics actually received, and only when the post succeeded.
    PS 5.1 + pwsh 7.
#>

BeforeAll {
    # #830: the trend job writes SI_Trend_CL only while the copy of the report rows to Log Analytics is on (off by default --
    # SIv3-SqlOnlyReaders.Tests.ps1); these tests drive that copy
    $script:SendToLaBefore = $global:SendToLogAnalytics; $global:SendToLogAnalytics = $true
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:Engine = Join-Path $script:SIRoot 'engine\asset-trend\Invoke-SITrend.ps1'
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-TrendAtEnd.ps1')

    # A realistic Summary snapshot: what Risk Analysis posts (types as the table stores them -- the tier a number on one
    # row, the asset list a JSON array, a one-element list as a bare string, a row with only the scalar id, an exempted row).
    function script:New-RaSummaryFixture {
        @(
            [pscustomobject]@{ ReportName = 'Endpoint - Critical CVE'; ConfigurationId = 'CVE'; SecuritySeverity = 'Critical'; CriticalityTier = '0'; SecurityDomain = 'Endpoint'
                               SI_ExemptionId = ''; RiskScoreTotal = 950; ImpactedAssetIds = '["dc01","dc02","srv03"]'; AssetId = 'dc01'; SI_AssetId = 'dc01'; SolutionVersion = '3.0.0+v3' }
            [pscustomobject]@{ ReportName = 'Endpoint - SMBv1 enabled'; ConfigurationId = 'scid-2001'; SecuritySeverity = 'High'; CriticalityTier = 0; SecurityDomain = 'Endpoint'
                               SI_ExemptionId = ''; RiskScoreTotal = 610.5; ImpactedAssetIds = 'dc01'; AssetId = 'dc01'; SI_AssetId = 'dc01'; SolutionVersion = '3.0.0+v3' }
            [pscustomobject]@{ ReportName = 'Identity - Global admin without MFA'; ConfigurationId = 'id-mfa'; SecuritySeverity = 'High'; CriticalityTier = '0'; SecurityDomain = 'Identity'
                               SI_ExemptionId = ''; RiskScoreTotal = 700; ImpactedAssetIds = '["admin1"]'; AssetId = 'admin1'; SI_AssetId = 'admin1'; SolutionVersion = '3.0.0+v3' }
            [pscustomobject]@{ ReportName = 'Azure - Storage public access'; ConfigurationId = 'az-st-public'; SecuritySeverity = 'Medium'; CriticalityTier = '1'; SecurityDomain = 'Azure'
                               SI_ExemptionId = ''; RiskScoreTotal = 300; ImpactedAssetIds = ''; AssetId = 'stdata01'; SI_AssetId = 'stdata01'; SolutionVersion = '3.0.0+v3' }
            [pscustomobject]@{ ReportName = 'Azure - VM missing backup'; ConfigurationId = 'az-vm-backup'; SecuritySeverity = 'Low'; CriticalityTier = '2'; SecurityDomain = 'Azure'
                               SI_ExemptionId = 'EX-12'; RiskScoreTotal = 40; ImpactedAssetIds = '["vm10"]'; AssetId = 'vm10'; SI_AssetId = 'vm10'; SolutionVersion = '3.0.0+v3' }
        )
    }

    function script:Get-Dim {
        param($Rows, [string]$Dimension, [string]$Value)
        @($Rows | Where-Object { $_.Dimension -eq $Dimension -and $_.DimensionValue -eq $Value })
    }

    # ---- the edges ----------------------------------------------------------------------------------------------------
    $script:Aliases = 'Send-SILogData', 'Update-SILogTableSchema', 'Select-SIIngestTarget', 'Set-SITrendTableRetention'
    function script:Set-TrendStubs {
        $global:SITrendTest = @{ Posted = New-Object System.Collections.ArrayList; Queries = New-Object System.Collections.ArrayList
                                 Health = New-Object System.Collections.ArrayList; Snapshot = @(New-RaSummaryFixture) }
        function global:Send-SIRunHealthRow {
            param($RunContext, $Phase, $AssetCount, $ExitReason, $ErrorMessage, [switch]$NoTelemetry)
            [void]$global:SITrendTest.Health.Add([pscustomobject]@{ Phase = $Phase; Engine = $RunContext.Engine; ExitReason = $ExitReason; Msg = $ErrorMessage })
        }
        function global:Invoke-SIArm { throw 'not reached' }   # the Azure access layer counts as loaded: the stubs below answer
        function global:Get-SIAzContext { $null }
        function global:Get-SIAzOperationalInsightsWorkspace { [pscustomobject]@{ CustomerId = [guid]'00000000-0000-0000-0000-000000000001' } }
        function global:Invoke-SIAzOperationalInsightsQuery {
            param($WorkspaceId, $Query)
            [void]$global:SITrendTest.Queries.Add([string]$Query)
            if ($Query -match 'startofweek|Snapshots|weekly') { return [pscustomobject]@{ Results = @() } }   # the weekly view: no history yet
            [pscustomobject]@{ Results = @($global:SITrendTest.Snapshot) }
        }
        function global:SITest-SendLogData { param($Data, $DcrName, $DceName, $TableName) foreach ($d in @($Data)) { [void]$global:SITrendTest.Posted.Add($d) }; $global:SITrendTest.Table = $TableName }
        function global:SITest-UpdateSchema { $null }
        function global:SITest-SelectTarget { $null }
        function global:SITest-Retention { @{ Outcome = 'kept'; TotalRetentionInDays = 365; RetentionInDays = 365 } }
        Set-Alias -Name Send-SILogData            -Value SITest-SendLogData  -Scope Global
        Set-Alias -Name Update-SILogTableSchema   -Value SITest-UpdateSchema -Scope Global
        Set-Alias -Name Select-SIIngestTarget     -Value SITest-SelectTarget -Scope Global
        Set-Alias -Name Set-SITrendTableRetention -Value SITest-Retention    -Scope Global
        $global:SI_WorkspaceResourceId = '/subscriptions/s/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/ws'
        $global:SI_SPN_AppId = '11111111-1111-1111-1111-111111111111'; $global:SI_SPN_TenantId = '22222222-2222-2222-2222-222222222222'
        $global:SI_SPN_CertThumbprint = 'ABCDEF'
    }
    function script:Remove-TrendStubs {
        foreach ($a in $script:Aliases) { Remove-Item -Path ("Alias:\{0}" -f $a) -Force -ErrorAction SilentlyContinue }
        foreach ($f in 'Send-SIRunHealthRow', 'Invoke-SIArm', 'Get-SIAzContext', 'Get-SIAzOperationalInsightsWorkspace', 'Invoke-SIAzOperationalInsightsQuery',
                       'SITest-SendLogData', 'SITest-UpdateSchema', 'SITest-SelectTarget', 'SITest-Retention') {
            Remove-Item -Path ("Function:\{0}" -f $f) -ErrorAction SilentlyContinue
        }
        foreach ($v in 'SI_WorkspaceResourceId', 'SI_SPN_AppId', 'SI_SPN_TenantId', 'SI_SPN_CertThumbprint', 'SITrendTest') {
            Remove-Variable -Name $v -Scope Global -ErrorAction SilentlyContinue
        }
    }
}

Describe 'SIv3-TrendWritesRows -- the risk trend is written (#394)' {
    BeforeEach { Set-TrendStubs }
    AfterEach  { Remove-TrendStubs }

    It 'the job (no -PublishedRows): reads the snapshot and writes the rollup rows; END success' {
        { & $script:Engine 6>$null } | Should -Not -Throw
        $posted = @($global:SITrendTest.Posted)
        $posted.Count | Should -BeGreaterThan 0 -Because 'the trend used to throw "Collection was of a fixed size" before writing anything'
        $global:SITrendTest.Table | Should -Be 'SI_Trend'
        @($global:SITrendTest.Queries | Where-Object { $_ -match 'SI_RiskAnalysis_Detailed_CL' }).Count | Should -BeGreaterThan 0 -Because '#636: the job rolls up the Detailed findings by default'
        $g = @(Get-Dim $posted 'global' 'all'); $g.Count | Should -Be 1
        [int]$g[0].Findings | Should -Be 5
        [int]$g[0].Assets | Should -Be 6 -Because 'dc01, dc02, srv03, admin1, stdata01, vm10 -- dc01 on two rows is one asset'
        [int](Get-Dim $posted 'global-counted' 'all')[0].Findings | Should -Be 4 -Because 'the exempted row is not counted'
        [int](Get-Dim $posted 'tier' '0')[0].Findings | Should -Be 3 -Because 'a tier stored as a number and one stored as text are the same tier'
        [int](Get-Dim $posted 'severity' 'High')[0].Assets | Should -Be 2
        [int](Get-Dim $posted 'domain' 'Endpoint')[0].Assets | Should -Be 3
        @($global:SITrendTest.Health | ForEach-Object Phase) | Should -Be @('Start', 'End')
        $global:SITrendTest.Health[1].ExitReason | Should -Be 'success'
    }

    It 'the end of Risk Analysis: the rows it hands over are rolled up and written -- the snapshot is never queried' {
        $published = @(New-RaSummaryFixture)
        $global:SITrendTest.Snapshot = @()   # Log Analytics still holds yesterday (nothing): it must not be read
        $log = New-Object System.Collections.Generic.List[string]
        $r = Invoke-SIRaTrendAtEnd -Rows $published -Detailed $true -Published $true -WhatIfRun $false -Engine $script:Engine `
                 -Log { param($l, $m) $log.Add("$l $m") }.GetNewClosure() 6>$null
        ($log -join ' | ') | Should -Not -Match 'WARN'
        $r.Ran | Should -BeTrue
        @($global:SITrendTest.Queries | Where-Object { $_ -match 'summarize max\(CollectionTime\)' }).Count | Should -Be 0 -Because 'the day is built from the rows this run published'
        $posted = @($global:SITrendTest.Posted)
        [int](Get-Dim $posted 'global' 'all')[0].Findings | Should -Be 5 -Because 'the run used to log "the 0 row(s) this Risk Analysis run published"'
        [int](Get-Dim $posted 'global' 'all')[0].Assets | Should -Be 6
        $global:SITrendTest.Health[-1].ExitReason | Should -Be 'success'
    }

    It 'the rollup from handed-over rows equals the job''s rollup over the same snapshot' {
        & $script:Engine 6>$null
        $job = @($global:SITrendTest.Posted | Where-Object { $_.Dimension -notlike 'weekly*' } | ForEach-Object { '{0}|{1}|{2}|{3}|{4}' -f $_.Dimension, $_.DimensionValue, $_.Findings, $_.Assets, $_.ScoreTotal } | Sort-Object)
        $global:SITrendTest.Posted.Clear()
        $null = Invoke-SIRaTrendAtEnd -Rows @(New-RaSummaryFixture) -Detailed $true -Published $true -WhatIfRun $false -Engine $script:Engine -Log { param($l, $m) } 6>$null
        $ra = @($global:SITrendTest.Posted | Where-Object { $_.Dimension -notlike 'weekly*' } | ForEach-Object { '{0}|{1}|{2}|{3}|{4}' -f $_.Dimension, $_.DimensionValue, $_.Findings, $_.Assets, $_.ScoreTotal } | Sort-Object)
        $job.Count | Should -BeGreaterThan 10
        ($ra -join "`n") | Should -Be ($job -join "`n")
    }

    It 'a trend failure at the end of Risk Analysis is said once and never fails Risk Analysis' {
        function global:SITest-SendLogData { throw 'ingestion refused (HTTP 403)' }
        $log = New-Object System.Collections.Generic.List[string]
        $r = Invoke-SIRaTrendAtEnd -Rows @(New-RaSummaryFixture) -Detailed $true -Published $true -WhatIfRun $false -Engine $script:Engine `
                 -Log { param($l, $m) $log.Add("$l $m") }.GetNewClosure() 6>$null
        $r.Ran | Should -BeFalse
        ($log -join ' | ') | Should -Match 'WARN .*403.*gap'
        $global:SITrendTest.Health[-1].ExitReason | Should -Be 'error'
    }
}

Describe 'SIv3-TrendWritesRows -- the trend run from Risk Analysis sees Risk Analysis''s script state (#394)' {
    It 'shared functions that keep their settings in $script: still resolve inside the trend run (the telemetry job map)' {
        $dir = Join-Path ([IO.Path]::GetTempPath()) ('si394-' + [guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path $dir
        try {
            $fakeEngine = Join-Path $dir 'fake-trend.ps1'
            Set-Content -LiteralPath $fakeEngine -Encoding ASCII -Value @'
param([string]$Grain, [AllowEmptyCollection()][object[]]$PublishedRows)
$global:SI394Probe = @{ Job = $(try { Resolve-SITelemetryJob -Engine 'asset-trend' } catch { 'threw: ' + $_.Exception.Message }); Rows = @($PublishedRows).Count }
'@
            # a stand-in for Risk Analysis: a SCRIPT that loads the telemetry sender at its own script scope, then runs the trend
            $outer = Join-Path $dir 'fake-ra.ps1'
            $tel = Join-Path $script:SIRoot 'engine\_shared\SI-TelemetrySend.ps1'
            $atEnd = Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-TrendAtEnd.ps1'
            Set-Content -LiteralPath $outer -Encoding ASCII -Value @"
param([string]`$Engine, [string]`$Mode)
. '$tel'
. '$atEnd'
if (`$Mode -eq 'ampersand') { `$null = & `$Engine -Grain Summary -PublishedRows @(1, 2) }
else { `$null = Invoke-SIRaTrendAtEnd -Rows @(1, 2) -Detailed `$true -Published `$true -WhatIfRun `$false -Engine `$Engine -Log { param(`$l, `$m) } }
"@
            # control: the old way (`& $Engine`) cannot see the sender's settings -- this is the failure the report showed
            & $outer -Engine $fakeEngine -Mode 'ampersand'
            [string]$global:SI394Probe.Job | Should -Match 'threw: .*null-valued'
            Remove-Variable -Name SI394Probe -Scope Global -ErrorAction SilentlyContinue
            # the fix
            & $outer -Engine $fakeEngine -Mode 'atend'
            $global:SI394Probe.Job | Should -Be 'si-trend'
            $global:SI394Probe.Rows | Should -Be 2
        } finally {
            Remove-Variable -Name SI394Probe -Scope Global -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'SIv3-TrendWritesRows -- wiring (#394)' {
    BeforeAll {
        $script:Ra = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'))
        $script:Tr = [IO.File]::ReadAllText($script:Engine)
        $script:AtEnd = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-TrendAtEnd.ps1'))
    }
    It 'Risk Analysis records the rows Log Analytics received, right after the post succeeded' {
        # posted in chunks (RA-Delivery.ps1): the result's own rows, recorded once every chunk is through -- no kept copy
        $send = $script:Ra.IndexOf('$__laDelivery = Invoke-RALaPagedPost -Pager $__pgL')
        $rec = $script:Ra.IndexOf('if ($script:RAStreamOn) { $script:_RAPublishedRows = @() } else { $script:_RAPublishedRows = $global:final }')
        $send | Should -BeGreaterThan 0
        $rec | Should -BeGreaterThan $send
        $script:Ra.Substring($send, $rec - $send) | Should -Not -Match '\bcatch\b' -Because 'only a post that did not throw counts as published'
        $script:Ra | Should -Match '(?m)^\$script:_RAPublishedRows = \$null'
    }
    It 'the trend at the end of Risk Analysis gets those rows, and "published" means they exist' {
        $script:Ra | Should -Match ([regex]::Escape('Invoke-SIRaTrendAtEnd -Rows @($script:_RAPublishedRows)'))
        $script:Ra | Should -Match ([regex]::Escape('-Published ($null -ne $script:_RAPublishedRows)'))
        $script:Ra | Should -Not -Match ([regex]::Escape('Invoke-SIRaTrendAtEnd -Rows @($global:final)'))
    }
    It 'the trend engine is dot-sourced in a child scope with -PublishedRows, never run with &' {
        $script:AtEnd | Should -Match ([regex]::Escape('. $__siTrendEngine -Grain Detailed -PublishedRows $__siTrendRows'))
        $script:AtEnd | Should -Not -Match '&\s*\$Engine\b'
        $script:Tr | Should -Match "\`$PSBoundParameters\.ContainsKey\('PublishedRows'\)"
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:Engine, [ref]$null, [ref]$null)
        @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.VariableExpressionAst] -and $n.VariablePath.UserPath -eq 'rows' }, $true)).Count |
            Should -Be 0 -Because 'the parameter used to be $Rows; the script-level code never uses that name again (any case)'
    }
}

AfterAll { $global:SendToLogAnalytics = $script:SendToLaBefore }
