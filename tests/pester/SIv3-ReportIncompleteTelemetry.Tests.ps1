#Requires -Version 5.1
<#
    #641 -- A RISK ANALYSIS REPORT THAT IS NOT COMPLETE REACHES INVARDIA (owner 2026-10-13: an alert when a report fails;
    Invardia mails him on these records). The run record carries exactly what Invardia's receiver accepts today:
      Outcome warning (failed when the run failed), FailedStep ra-report, ErrorClass report-incomplete, Counts reportsExpected /
      reportsStored / reportsIncomplete (numbers only), Link (identified, <= 400 characters) = the web app page of the run's
      reports -- and NO report name (no free text). A record never carries more than 10 Counts keys (the receiver drops it).
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:SavedEndpointEnv = $env:SI_TELEMETRY_ENDPOINT
    $env:SI_TELEMETRY_ENDPOINT = 'https://127.0.0.1:9/api/uplink/v1/report'
    . (Join-Path $script:SIRoot 'engine\_shared\SI-TelemetrySend.ps1')
    $script:Posts = New-Object System.Collections.Generic.List[object]
    $script:StubOk = { param($Record, $Endpoint, $AccessCode, $TimeoutSec) $script:Posts.Add($Record); [pscustomobject]@{ Status = 'ok'; Reason = 'accepted' } }
    function script:New-Ctx([string]$Mode = 'identified', [string]$Dir) {
        [pscustomobject]@{ Mode = $Mode; Endpoint = 'https://stub.example.test/report'
                           AccessCode = $(if ($Mode -eq 'anonymous') { 'invardia-community-telemetry-v1' } else { 'inv-TESTKEYabcdefghijklmnopqrstuvwxyz' })
                           Edition = $(if ($Mode -eq 'anonymous') { 'community' } else { 'pro' }); LicenceState = $(if ($Mode -eq 'anonymous') { 'none' } else { 'valid' })
                           Version = '3.0.0'; Hosting = 'container'; RuntimeIdentity = 'mi-container'
                           InstallId = $(if ($Mode -eq 'anonymous') { '0f3c9a2e-5b7d-4c1a-9e8f-1a2b3c4d5e6f' } else { '' })
                           TenantId = $(if ($Mode -eq 'anonymous') { '' } else { '7f3e2a10-4b5c-4d6e-8f90-a1b2c3d4e5f6' }); StateDirectory = $Dir; Endpoints = @() }
    }
    function script:New-RaCtx([int]$Incomplete = 2) {
        [pscustomobject]@{ RunId = 'run-1'; Engine = 'risk-analysis'; ShardIndex = 0; ShardCount = 1; StartedAt = [datetime]'2026-10-13T06:00:00Z'
                           ReportsExpected = 60; ReportsStored = (60 - $Incomplete); ReportsIncomplete = $Incomplete
                           ReportsIncompleteLink = 'https://si.example.test/Admin/RunHealth/Reports/run-1' }
    }
    function script:Send([string]$Exit, [string]$Mode = 'identified') {
        $script:Posts.Clear(); $global:SI_TelemetryHalted = $null; $global:SI_Telemetry_Enabled = $null; $global:ReportTemplate = 'RiskAnalysis_Detailed'
        $null = Send-SITelemetryRunEnd -RunContext (New-RaCtx) -ExitReason $Exit -ErrorMessage "2 report(s) are not complete: Azure_Recommendations_Detailed, Identity_Secret_Detailed" -AssetCount 1234 `
            -Context (New-Ctx -Mode $Mode -Dir $TestDrive) -Transport $script:StubOk -Now ([datetime]'2026-10-13T07:00:00Z') -NoHeartbeat
        @($script:Posts | Where-Object { "$($_.Kind)" -eq 'run' })[0]
    }
}

AfterAll {
    $env:SI_TELEMETRY_ENDPOINT = $script:SavedEndpointEnv
    $global:SI_TelemetryHalted = $null; $global:SI_TelemetryContext = $null; $global:SI_Telemetry_Enabled = $null
}

Describe 'the values are ones the receiver accepts (the builder''s enum checks)' {
    It 'report-incomplete is an error class (lower-case a-z0-9-, at most 40) and ra-report a step name' {
        Get-SIErrorClasses | Should -Contain 'report-incomplete'
        'report-incomplete' | Should -MatchExactly '^[a-z0-9-]{1,40}$'
        (Get-SITelemetryContract).ReportIncompleteStep | Should -MatchExactly '^[a-z][a-z0-9\-]{0,31}$'
        (Get-SITelemetryContract).ReportIncompleteClass | Should -Be 'report-incomplete'
    }
    It 'the three report counts are count names the receiver accepts' {
        foreach ($n in 'reportsExpected', 'reportsStored', 'reportsIncomplete') {
            (Get-SITelemetryContract).CountNames | Should -Contain $n
            $n | Should -MatchExactly '^[a-z][A-Za-z0-9]{0,30}$'
        }
    }
    It 'a record with more than 40 Counts keys is refused by the builder (the receiver would drop it)' {
        $c = (Get-SITelemetryContract)
        $saved = $c.CountNames
        try {
            $c.CountNames = @($saved) + @(1..40 | ForEach-Object { "extra$_" })
            $counts = [ordered]@{}; foreach ($n in $c.CountNames) { $counts[$n] = 1 }
            { New-SITelemetryRunRecord -Job 'si-ra-detailed' -ExitReason 'success' -Edition 'pro' -Version '3.0.0' -Hosting 'container' -RuntimeIdentity 'mi-container' -LicenceState 'valid' -Counts $counts -TenantId 't' } |
                Should -Throw '*receiver drops*'
        } finally { $c.CountNames = $saved }
    }
    It 'every count name the product knows, all at once, stays within the receiver''s limit (40 keys)' {
        @((Get-SITelemetryContract).CountNames).Count | Should -BeLessOrEqual 40; (Get-SITelemetryContract).MaxCounts | Should -Be 40
    }
}

Describe 'a Risk Analysis run with a report that is not complete' {
    It 'identified: Outcome warning, FailedStep ra-report, ErrorClass report-incomplete, the three counts, the Link -- and no report name' {
        $r = Send 'success-partial'
        $r.Outcome | Should -Be 'warning'
        $r.FailedStep | Should -Be 'ra-report'
        $r.ErrorClass | Should -Be 'report-incomplete'
        [long]$r.Counts.reportsExpected | Should -Be 60
        [long]$r.Counts.reportsStored | Should -Be 58
        [long]$r.Counts.reportsIncomplete | Should -Be 2
        @($r.Counts.PSObject.Properties).Count | Should -BeLessOrEqual 40
        foreach ($p in $r.Counts.PSObject.Properties) { $p.Value | Should -BeOfType [ValueType] -Because 'numbers only' }
        $r.Link | Should -Be 'https://si.example.test/Admin/RunHealth/Reports/run-1'
        $r.Link.Length | Should -BeLessOrEqual 400
        ($r | ConvertTo-Json -Depth 6 -Compress) | Should -Not -Match 'Azure_Recommendations_Detailed|Identity_Secret_Detailed' -Because 'no report name leaves the install'
    }
    It 'a run that FAILED stays failed, still with the step, the class and the counts' {
        $r = Send 'error'
        $r.Outcome | Should -Be 'failed'
        $r.FailedStep | Should -Be 'ra-report'
        $r.ErrorClass | Should -Be 'report-incomplete'
        [long]$r.Counts.reportsIncomplete | Should -Be 2
    }
    It 'anonymous: the class and bucketed counts, no link, no text' {
        $r = Send 'success-partial' 'anonymous'
        $r.ErrorClass | Should -Be 'report-incomplete'
        $r.PSObject.Properties['Link'] | Should -BeNullOrEmpty
        $r.PSObject.Properties['ErrorText'] | Should -BeNullOrEmpty
    }
    It 'Risk Analysis sets the numbers and the link on its run context before the END record' {
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'))
        foreach ($n in 'ReportsExpected', 'ReportsStored', 'ReportsIncomplete', 'ReportsIncompleteLink') { $src | Should -Match ("@\('{0}'," -f $n) }
        $src.IndexOf("@('ReportsIncomplete',") | Should -BeLessThan $src.IndexOf("Send-RARunHealthEnd -ExitReason 'success'")
    }
}
