#Requires -Version 5.1
<#
    #709 -- REPORT-FAILURE TELEMETRY THAT EXPLAINS THE CAUSE IN PLAIN WORDS (engine\_shared\SI-UplinkCauses.ps1).

    A report failure reached the owner as a class ("kql-query-defect", "report-incomplete") and a session had to read logs
    to explain it. Each failed / not complete report now carries ONE sentence -- "<report>, <step>: <why>." -- built from
    what the engine already wrote: the reason Risk Analysis keeps in sidata.RaReportStatus, the error of a failed query, the
    retries it counted. It travels on fields Invardia already takes: the Reports[] item's Detail (identified; the sentence
    first, then the engine's own first error line) and the run record's ErrorMessage of a run with reports that are not
    complete (identified). An anonymous install sends no text, as before.

    OFFLINE: every transport is a stub, no database.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:SavedEndpointEnv = $env:SI_TELEMETRY_ENDPOINT
    $env:SI_TELEMETRY_ENDPOINT = 'https://127.0.0.1:9/api/uplink/v1/report'
    . (Join-Path $script:SIRoot 'engine\_shared\SI-TelemetrySend.ps1')
    $script:Posts = New-Object System.Collections.Generic.List[object]
    $script:StubOk = { param($Record, $Endpoint, $AccessCode, $TimeoutSec) $script:Posts.Add(($Record | ConvertTo-Json -Depth 8 -Compress | ConvertFrom-Json)); [pscustomobject]@{ Status = 'ok'; Reason = 'accepted' } }
    function script:Fact([string]$Report, [string]$State, [string]$Why, $Retries = $null) {
        [pscustomobject]@{ Report = $Report; State = $State; Why = $Why; StartedUtc = $null; RunMs = $null; Rows = $null; SourceCount = $null; Buckets = $null
                           QueryHash = ''; Retries = $Retries; LastGoodRows = $null; LastGoodRunMs = $null; LastGoodQueryHash = '' }
    }
    # the engine's own words (Invoke-RiskAnalysis Add-RAReportFailure, RA-ProfileAugment Assert-RAHybridQueryFits,
    # RA-SqlStream Get-RACompletenessVerdict) -- the sentence is built from them
    $script:LookupTooLarge = 'its query could not be sent: the lookup _dfcPairs (43,124 rows, 1.4 MB) is needed whole in every part of the query -- with the query text that is 1.5 MB in every part, more than a query to Microsoft Defender can carry (1.0 MB), so splitting the query into more parts cannot make it fit'
    $script:Timeout = 'it failed: The request was canceled due to the configured HttpClient.Timeout of 900 seconds elapsing. TaskCanceledException'
    $script:Syntax = "its query failed: BadRequest SYN0002 Query could not be parsed at 'of' on line [12,30]"
    $script:CountLess = 'not complete: the source holds 449 row(s) for this report, the run retrieved 0'
    $script:Slices = 'not complete: 3 query slice(s) of the report could not be read (504 Gateway Timeout) -- the rows of those slices are unknown, not resolved, so the source''s count is not taken from what the other slices returned'
    $script:Lost = 'not complete: the run retrieved 120 row(s) and stored 100: 20 row(s) are neither stored nor accounted for'
    $script:Tvm = "Failed to resolve table or column expression named 'DeviceTvmSoftwareVulnerabilities'"
}

AfterAll {
    $env:SI_TELEMETRY_ENDPOINT = $script:SavedEndpointEnv
    $global:SI_TelemetryHalted = $null; $global:SI_Telemetry_Enabled = $null
}

Describe 'the sentence: which report, which step, and why' {
    It 'a lookup too large for one Defender query names the lookup, its size and the limit' {
        $s = Get-SIReportCauseSentence -Fact (Fact 'Azure_Recommendations_Detailed' 'Failed' $script:LookupTooLarge)
        $s | Should -Be 'azure-recommendations-detailed, sending its query to Microsoft Defender: the lookup _dfcPairs is 1.4 MB (the query 1.5 MB in every part), over the 1.0 MB one Microsoft Defender query can carry -- more parts cannot make it fit.'
    }
    It 'Defender timing out says how many times (the retries the run counted)' {
        $s = Get-SIReportCauseSentence -Fact (Fact 'Device_Missing_CVEs_Detailed' 'Failed' $script:Timeout @{ '429' = 0; '502' = 0; '504' = 3 })
        $s | Should -Be 'device-missing-cves-detailed, running its query: Microsoft Defender timed out 3 times.'
        (Get-SIReportCauseSentence -Fact (Fact 'R' 'Failed' $script:Timeout @{ '429' = 2; '504' = 1 })) | Should -Match 'Microsoft Defender timed out once, it was throttled 2 times\.$'
        (Get-SIReportCauseSentence -Fact (Fact 'R' 'Failed' $script:Timeout)) | Should -Match 'the platform did not answer in time\.$'
    }
    It 'a syntax error says where' {
        Get-SIReportCauseSentence -Fact (Fact 'Identity_SPN_OwnerMismatch_Detailed' 'Failed' $script:Syntax) |
            Should -Be "identity-spn-ownermismatch-detailed, running its query: the query has a syntax error at 'of' (line 12, position 30)."
    }
    It 'the NotComplete reasons kept in sidata.RaReportStatus read as numbers a person can check' {
        Get-SIReportCauseSentence -Fact (Fact 'Device_Recommendations_Detailed' 'NotComplete' $script:CountLess) |
            Should -Be 'device-recommendations-detailed, checking its rows against the source: the source holds 449 rows, the run retrieved 0.'
        Get-SIReportCauseSentence -Fact (Fact 'R' 'NotComplete' $script:Slices) | Should -Be 'r, reading the parts of its query: 3 part(s) of its query could not be read -- their rows are unknown, not resolved.'
        Get-SIReportCauseSentence -Fact (Fact 'R' 'NotComplete' $script:Lost) | Should -Be 'r, storing its rows: 120 rows were retrieved and 100 stored -- 20 are neither stored nor accounted for.'
    }
    It 'a data source the tenant does not have, and the settings database' {
        Get-SIReportCauseSentence -Fact (Fact 'Device_Missing_CVEs_Summary' 'NotApplicable' $script:Tvm) |
            Should -Be 'device-missing-cves-summary, checking its data source: the tenant has no Defender vulnerability management (the table devicetvmsoftwarevulnerabilities is not there).'
        Get-SIReportCauseSentence -Fact (Fact 'R' 'Failed' 'it failed: SQL error 40 on the settings database') | Should -Be 'r, reading its settings: the settings database could not be reached.'
    }
    It 'a cause no rule reads says so -- never an empty sentence' {
        Get-SIReportCauseSentence -Fact (Fact 'R' 'Failed' 'it failed: something nobody has seen before') | Should -Match '^r, .+: the cause was not recognised -- the run''s log has the error\.$'
    }
    It 'the report is named by its uplink id (the one Reports[] carries), never its display name' {
        Get-SIReportCauseSentence -Fact (Fact 'Identity_PrivilegedSPN_NoLogin180Days_Detailed' 'NotComplete' $script:CountLess) | Should -Match '^identity-privilegedspn-nologin180days-detailed, '
    }
    It 'plain words: no ticket number, at most 300 characters, nothing that looks like a secret' {
        foreach ($w in @($script:LookupTooLarge, $script:Timeout, $script:Syntax, $script:CountLess, $script:Slices, $script:Lost, $script:Tvm)) {
            $s = Get-SIReportCauseSentence -Fact (Fact 'Report_X' 'Failed' $w)
            $s | Should -Not -Match '#\d'
            $s.Length | Should -BeLessOrEqual 300
            Test-SIUplinkLooksSecret $s | Should -BeFalse
        }
        Get-SIReportCauseSentence -Fact $null | Should -Be ''
        Get-SIReportCauseSentence -Fact (Fact '' 'Failed' 'x') | Should -Be ''
    }
}

Describe 'the stored NotComplete reasons are reused (sidata.RaReportStatus)' {
    It 'a fact without a reason takes the stored one; a report only a worker judged is added' {
        $facts = @((Fact 'A' 'NotComplete' ''), (Fact 'B' 'Failed' 'its query failed: SYN0002'))
        $stored = @([pscustomobject]@{ ReportName = 'A'; Reason = 'the source holds 9 row(s) for this report, the run retrieved 1' },
                    [pscustomobject]@{ ReportName = 'C'; Reason = 'the source holds 5 row(s) for this report, the run retrieved 2' })
        $out = @(Add-SIReportCauseStoredReasons -Facts $facts -Stored $stored)
        $out.Count | Should -Be 3
        ($out | Where-Object Report -eq 'A').Why | Should -Match 'holds 9 row'
        ($out | Where-Object Report -eq 'B').Why | Should -Be 'its query failed: SYN0002' -Because 'the run''s own reason is kept'
        ($out | Where-Object Report -eq 'C').State | Should -Be 'NotComplete'
        Get-SIReportCauseSentence -Fact ($out | Where-Object Report -eq 'C') | Should -Be 'c, checking its rows against the source: the source holds 5 rows, the run retrieved 2.'
    }
    It 'the SQL reads only NotComplete rows of the run''s collection and grain' {
        $q = Get-SIReportStatusReasonsSql
        $q | Should -Match "FROM sidata\.RaReportStatus WHERE CollectionTime = @t AND Grain = @Grain AND State = N'NotComplete'"
        $q | Should -Match "OBJECT_ID\('sidata\.RaReportStatus'\) IS NULL"
    }
    It 'Risk Analysis merges them before the run record is built (never on a queue worker)' {
        $ra = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'))
        $end = [regex]::Match($ra, '(?s)function Send-RARunHealthEnd \{.*?ReportCauses').Value
        $end | Should -Match 'Add-SIReportCauseStoredReasons -Facts \$__facts -Stored \$__stored'
        $end | Should -Match "\`$script:RAScaleRole -ne 'worker'"
    }
}

Describe 'where the sentence travels -- only fields Invardia already takes' {
    It 'identified: the Reports[] item Detail starts with the sentence, then the engine''s line, at most 500' {
        $i = @(ConvertTo-SIUplinkReports -Facts @(Fact 'Device_Missing_CVEs_Detailed' 'Failed' $script:Timeout @{ '504' = 3 }) -Identified -Version '3.0.0')[0]
        $i.Detail | Should -Match '^device-missing-cves-detailed, running its query: Microsoft Defender timed out 3 times\. \| it failed: '
        $i.Detail.Length | Should -BeLessOrEqual 500
        @($i.PSObject.Properties.Name) | Should -Not -Contain 'Cause' -Because 'no new item field -- Invardia would refuse the record'
    }
    It 'anonymous: no Detail, no sentence' {
        $i = @(ConvertTo-SIUplinkReports -Facts @(Fact 'R' 'Failed' $script:Timeout) -Version '3.0.0')[0]
        $i.PSObject.Properties['Detail'] | Should -BeNullOrEmpty
    }
    It 'Join-SIUplinkCauseDetail: sentence, line, both, neither' {
        Join-SIUplinkCauseDetail -Sentence 'S.' -Raw 'raw' | Should -Be 'S. | raw'
        Join-SIUplinkCauseDetail -Sentence 'S.' -Raw '' | Should -Be 'S.'
        Join-SIUplinkCauseDetail -Sentence '' -Raw 'raw' | Should -Be 'raw'
        Join-SIUplinkCauseDetail -Sentence '' -Raw '' | Should -BeNullOrEmpty
        (Join-SIUplinkCauseDetail -Sentence ('a' * 400) -Raw ('b' * 400)).Length | Should -Be 500
    }
    It 'the headline is the most severe report that failed or is not complete' {
        $f = @((Fact 'Late' 'NotApplicable' $script:Tvm), (Fact 'Slow' 'Failed' $script:Timeout @{ '504' = 2 }), (Fact 'Short' 'NotComplete' $script:CountLess))
        Get-SIReportCauseHeadline -Facts $f | Should -Be 'short, checking its rows against the source: the source holds 449 rows, the run retrieved 0.'
        Get-SIReportCauseHeadline -Facts @((Fact 'Late' 'NotApplicable' $script:Tvm)) | Should -Be ''
    }
    It 'identified: the run record of a run with reports not complete carries the first cause in its ErrorMessage' {
        $script:Posts.Clear(); $global:SI_TelemetryHalted = $null; $global:SI_Telemetry_Enabled = $null; $global:ReportTemplate = 'RiskAnalysis_Detailed'
        $rc = [pscustomobject]@{ RunId = 'run-1'; Engine = 'risk-analysis'; ShardIndex = 0; StartedAt = [datetime]'2026-10-15T06:00:00Z'
                                 ReportsExpected = 10; ReportsStored = 9; ReportsIncomplete = 1
                                 ReportCauses = @((Fact 'Device_Recommendations_Detailed' 'NotComplete' $script:CountLess)) }
        $ctx = [pscustomobject]@{ Mode = 'identified'; Endpoint = 'https://stub.example.test/report'; AccessCode = 'inv-TESTKEYabcdefghijklmnopqrstuvwxyz'; Edition = 'pro'; LicenceState = 'valid'
                                  Version = '3.0.0.202610151900'; Hosting = 'container'; RuntimeIdentity = 'mi-container'; InstallId = ''; TenantId = '7f3e2a10-4b5c-4d6e-8f90-a1b2c3d4e5f6'; StateDirectory = $TestDrive; Endpoints = @() }
        $null = Send-SITelemetryRunEnd -RunContext $rc -ExitReason 'success-partial' -ErrorMessage 'reports not complete' -AssetCount 10 -Context $ctx -Transport $script:StubOk -Now ([datetime]'2026-10-15T07:00:00Z') -NoHeartbeat
        $run = @($script:Posts | Where-Object { "$($_.Kind)" -eq 'run' })[0]
        $run | Should -Not -BeNullOrEmpty
        $txt = [string]$(if ($run.PSObject.Properties['ErrorText']) { $run.ErrorText } else { $run.ErrorMessage })
        $txt | Should -Match '^1 of 10 Risk Analysis report\(s\) are not complete in this run'
        $txt | Should -Match 'First cause: device-recommendations-detailed, checking its rows against the source: the source holds 449 rows, the run retrieved 0\.'
        $run.ErrorClass | Should -Be 'report-incomplete' -Because 'the class Invardia groups by is unchanged'
    }
    It 'anonymous: the run record carries no text at all' {
        $script:Posts.Clear(); $global:SI_TelemetryHalted = $null
        $rc = [pscustomobject]@{ RunId = 'run-2'; Engine = 'risk-analysis'; ShardIndex = 0; StartedAt = [datetime]'2026-10-15T06:00:00Z'
                                 ReportsExpected = 10; ReportsStored = 9; ReportsIncomplete = 1; ReportCauses = @((Fact 'R' 'NotComplete' $script:CountLess)) }
        $ctx = [pscustomobject]@{ Mode = 'anonymous'; Endpoint = 'https://stub.example.test/report'; AccessCode = 'invardia-community-telemetry-v1'; Edition = 'community'; LicenceState = 'none'
                                  Version = '3.0.0'; Hosting = 'container'; RuntimeIdentity = 'mi-container'; InstallId = '0f3c9a2e-5b7d-4c1a-9e8f-1a2b3c4d5e6f'; TenantId = ''; StateDirectory = $TestDrive; Endpoints = @() }
        $null = Send-SITelemetryRunEnd -RunContext $rc -ExitReason 'success-partial' -ErrorMessage 'x' -AssetCount 10 -Context $ctx -Transport $script:StubOk -Now ([datetime]'2026-10-15T07:00:00Z') -NoHeartbeat
        $j = @($script:Posts | Where-Object { "$($_.Kind)" -eq 'run' })[0] | ConvertTo-Json -Depth 8 -Compress
        $j | Should -Not -Match 'First cause|holds 449'
    }
}
