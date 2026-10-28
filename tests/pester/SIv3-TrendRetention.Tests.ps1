#Requires -Version 5.1
<#
    THE TREND TABLE'S RETENTION IS SET BY THE ENGINE, NOT ASKED OF THE CUSTOMER.

    Found by the live 2.2 -> 3.0 upgrade test: every trend run printed three [WARN] lines asking the user to set the
    table's retention by hand (one of them read "the remaining 0 are long-term"). The table exists to outlive the
    profile tables and does not inherit that by itself. Now the run sets it when its identity may -- never lowering a
    longer retention the customer chose -- and only when it may not, says in ONE line what to run. Never fails the run.

    SI_TEST_ROOT (optional) points the tests at another tree, e.g. an export of the code before the fix.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    if ($env:SI_TEST_ROOT) { $script:SIRoot = $env:SI_TEST_ROOT }
    # offline: the Azure access layer is NOT loaded (its loader probe finds this stub), so each test's Invoke-SIAzRestMethod
    # stub is the one called
    function script:Invoke-SIArm { throw 'not reached' }
    . (Join-Path $script:SIRoot 'engine\asset-trend\_shared\SI-TrendRollup.ps1')
    $script:Ws = '/subscriptions/s/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/ws'
    $global:SITestCalls = New-Object System.Collections.ArrayList
    function script:New-TableResponse([int]$Ret, [int]$Total, [int]$Status = 200) {
        [pscustomobject]@{ StatusCode = $Status; Content = (@{ properties = @{ retentionInDays = $Ret; totalRetentionInDays = $Total } } | ConvertTo-Json -Depth 4) }
    }
}

Describe 'the retention plan never lowers what the customer chose' {
    It 'a table on the workspace default is raised to the intended year' {
        $p = Get-SITrendRetentionPlan -CurrentRetentionInDays 30 -CurrentTotalRetentionInDays 30
        $p.Action | Should -Be 'set'
        $p.RetentionInDays | Should -Be (Get-SITrendInteractiveRetentionDays)
        $p.TotalRetentionInDays | Should -Be (Get-SITrendRetentionDays)
    }
    It 'a table the customer keeps longer is kept as it is' {
        $p = Get-SITrendRetentionPlan -CurrentRetentionInDays 730 -CurrentTotalRetentionInDays 2556
        $p.Action | Should -Be 'keep'
    }
    It 'a long total with a short interactive part: only the interactive part is raised, the total stays' {
        $p = Get-SITrendRetentionPlan -CurrentRetentionInDays 30 -CurrentTotalRetentionInDays 2556
        $p.Action | Should -Be 'set'
        $p.RetentionInDays | Should -Be (Get-SITrendInteractiveRetentionDays)
        $p.TotalRetentionInDays | Should -Be 2556
    }
}

Describe 'setting the retention in the workspace' {
    BeforeEach { $global:SITestCalls.Clear() }
    AfterAll { Remove-Item -Path 'Function:\Invoke-SIAzRestMethod' -ErrorAction SilentlyContinue }

    It 'sets it when the identity may, on THIS table, with both values' {
        function global:Invoke-SIAzRestMethod { param($Path, $Method, $Payload)
            [void]$global:SITestCalls.Add([pscustomobject]@{ Path = $Path; Method = $Method; Payload = $Payload })
            if ($Method -eq 'GET') { return (New-TableResponse 30 30) }
            [pscustomobject]@{ StatusCode = 200; Content = '{}' } }
        $r = Set-SITrendTableRetention -WorkspaceResourceId $script:Ws -TableName 'SI_Trend'
        $r.Outcome | Should -Be 'set'
        $patch = @($global:SITestCalls | Where-Object Method -eq 'PATCH')
        $patch.Count | Should -Be 1
        $patch[0].Path | Should -Match '/workspaces/ws/tables/SI_Trend_CL\?api-version='
        $body = $patch[0].Payload | ConvertFrom-Json
        $body.properties.retentionInDays | Should -Be (Get-SITrendInteractiveRetentionDays)
        $body.properties.totalRetentionInDays | Should -Be (Get-SITrendRetentionDays)
    }

    It 'changes nothing when the table already keeps it at least as long' {
        function global:Invoke-SIAzRestMethod { param($Path, $Method, $Payload)
            [void]$global:SITestCalls.Add([pscustomobject]@{ Method = $Method })
            if ($Method -eq 'GET') { return (New-TableResponse 730 730) }
            [pscustomobject]@{ StatusCode = 200; Content = '{}' } }
        (Set-SITrendTableRetention -WorkspaceResourceId $script:Ws -TableName 'SI_Trend_CL').Outcome | Should -Be 'kept'
        @($global:SITestCalls | Where-Object Method -ne 'GET').Count | Should -Be 0
    }

    It 'no right to change it: reports failed with the reason -- never throws' {
        function global:Invoke-SIAzRestMethod { param($Path, $Method, $Payload)
            if ($Method -eq 'GET') { return (New-TableResponse 30 30) }
            [pscustomobject]@{ StatusCode = 403; Content = '{"error":{"code":"AuthorizationFailed"}}' } }
        $r = $null
        { $script:r = Set-SITrendTableRetention -WorkspaceResourceId $script:Ws -TableName 'SI_Trend' } | Should -Not -Throw
        $script:r.Outcome | Should -Be 'failed'
        $script:r.Reason | Should -Match '403'
    }

    It 'a sign-in or network failure: failed, never throws' {
        function global:Invoke-SIAzRestMethod { throw 'no Az context' }
        { $script:r = Set-SITrendTableRetention -WorkspaceResourceId $script:Ws -TableName 'SI_Trend' } | Should -Not -Throw
        $script:r.Outcome | Should -Be 'failed'
    }
}

Describe 'the engine sets it, and no longer asks with three warnings' {
    BeforeAll { $script:Src = Get-Content -Raw (Join-Path $script:SIRoot 'engine\asset-trend\Invoke-SITrend.ps1') }
    It 'calls the setter after publishing' {
        $script:Src | Should -Match 'Set-SITrendTableRetention'
    }
    It 'no [WARN] line asks the customer to set retention' {
        $script:Src | Should -Not -Match 'Write-TrWarn \("Set retention'
        $script:Src | Should -Not -Match 'Write-TrWarn \("\s+\{0\} days stay interactively queryable'
    }
}
