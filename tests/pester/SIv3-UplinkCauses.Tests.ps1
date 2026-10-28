#Requires -Version 5.1
<#
    #709 / framework 8.16 UPLINK-CAUSES -- engine/_shared/SI-UplinkCauses.ps1 and its use by SI-TelemetrySend.ps1.
    OFFLINE: no network, no database (every reader is a stub). The run record's Reports[] (the shape, Code + CauseClass
    always, at most 20 most severe first, Detail scrubbed and at most 500, never anonymous), the error codes against the
    catalogue (data-model/errors.locked.json), a broken mapping or a refused record that still sends the run record, the
    heartbeat's Capabilities / CiColumns / Licences, and the failure mail's reference codes.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:SavedEndpointEnv = $env:SI_TELEMETRY_ENDPOINT
    $env:SI_TELEMETRY_ENDPOINT = 'https://127.0.0.1:9/api/uplink/v1/report'
    . (Join-Path $script:SIRoot 'engine\_shared\SI-TelemetrySend.ps1')
    $script:Catalogue = @(Get-Content -LiteralPath (Join-Path $script:SIRoot 'data-model\errors.locked.json') -Raw | ConvertFrom-Json)
    $script:Posts = New-Object System.Collections.Generic.List[object]
    $script:StubOk = { param($Record, $Endpoint, $AccessCode, $TimeoutSec) $script:Posts.Add(($Record | ConvertTo-Json -Depth 8 -Compress | ConvertFrom-Json)); [pscustomobject]@{ Status = 'ok'; Reason = 'accepted' } }
    # Invardia 1.0.477 refuses (422) a record that carries Reports -- the sender must send it again without them
    $script:Stub422 = { param($Record, $Endpoint, $AccessCode, $TimeoutSec)
        $j = $Record | ConvertTo-Json -Depth 8 -Compress
        if ($Record.PSObject.Properties['Reports']) { return [pscustomobject]@{ Status = 'failed'; Reason = 'uplink POST failed: 422 (Unprocessable Entity)' } }
        $script:Posts.Add(($j | ConvertFrom-Json)); [pscustomobject]@{ Status = 'ok'; Reason = 'accepted' } }
    function script:New-Ctx([string]$Mode = 'identified', [string]$Dir) {
        [pscustomobject]@{ Mode = $Mode; Endpoint = 'https://stub.example.test/report'
                           AccessCode = $(if ($Mode -eq 'anonymous') { 'invardia-community-telemetry-v1' } else { 'inv-TESTKEYabcdefghijklmnopqrstuvwxyz' })
                           Edition = $(if ($Mode -eq 'anonymous') { 'community' } else { 'pro' }); LicenceState = $(if ($Mode -eq 'anonymous') { 'none' } else { 'valid' })
                           Version = '3.0.0.202610151900'; Hosting = 'container'; RuntimeIdentity = 'mi-container'
                           InstallId = $(if ($Mode -eq 'anonymous') { '0f3c9a2e-5b7d-4c1a-9e8f-1a2b3c4d5e6f' } else { '' })
                           TenantId = $(if ($Mode -eq 'anonymous') { '' } else { '7f3e2a10-4b5c-4d6e-8f90-a1b2c3d4e5f6' }); StateDirectory = $Dir; Endpoints = @() }
    }
    function script:New-Fact([string]$Report, [string]$State, [string]$Why) {
        [pscustomobject]@{ Report = $Report; State = $State; Why = $Why; StartedUtc = [datetime]'2026-10-15T06:00:00Z'; RunMs = 1234; Rows = 3; SourceCount = 4; Buckets = 2
                           QueryHash = ('ab' * 32); Retries = @{ '429' = 1; '504' = 2 }; LastGoodRows = 4; LastGoodRunMs = $null; LastGoodQueryHash = ('cd' * 32) }
    }
    function script:Send-Run($Causes, [string]$Mode = 'identified', [scriptblock]$Transport = $script:StubOk) {
        $script:Posts.Clear(); $global:SI_TelemetryHalted = $null; $global:SI_TelemetryWarned = $null; $global:SI_Telemetry_Enabled = $null; $global:ReportTemplate = 'RiskAnalysis_Detailed'
        $rc = [pscustomobject]@{ RunId = 'run-1'; Engine = 'risk-analysis'; ShardIndex = 0; StartedAt = [datetime]'2026-10-15T06:00:00Z'; ReportCauses = $Causes }
        $res = Send-SITelemetryRunEnd -RunContext $rc -ExitReason 'success-partial' -ErrorMessage 'reports not complete' -AssetCount 10 `
            -Context (New-Ctx -Mode $Mode -Dir $TestDrive) -Transport $Transport -Now ([datetime]'2026-10-15T07:00:00Z') -NoHeartbeat
        [pscustomobject]@{ Result = $res; Run = @($script:Posts | Where-Object { "$($_.Kind)" -eq 'run' })[0] }
    }
}

AfterAll {
    $env:SI_TELEMETRY_ENDPOINT = $script:SavedEndpointEnv
    $global:SI_TelemetryHalted = $null; $global:SI_TelemetryContext = $null; $global:SI_Telemetry_Enabled = $null; $global:SI_CapabilityProbe = $null
    $global:SI_UplinkRetryAnswers = $null; $global:SI_UplinkCurrentReport = $null; $global:SI_UplinkCausesWarned = $null
}

Describe 'the catalogue (data-model/errors.locked.json)' {
    It 'every entry has the same shape, a stable code and a CauseClass of the closed list' {
        $keys = @('code', 'title', 'causeClass', 'appliesTo', 'customerText', 'internalNote', 'whoActs', 'priority', 'opensTicket', 'action', 'fixedIn', 'waitForFix', 'steps', 'lesson', 'since')
        $c = Get-SIUplinkCausesContract
        foreach ($e in $script:Catalogue) {
            @($e.PSObject.Properties.Name) | Should -Be $keys -Because $e.code
            $e.code | Should -MatchExactly $c.CodePattern
            $c.CauseClasses | Should -Contain $e.causeClass
            $c.Actions | Should -Contain $e.action
        }
        @($script:Catalogue | ForEach-Object code | Select-Object -Unique).Count | Should -Be $script:Catalogue.Count -Because 'a code is never reused'
    }
    It 'has the known codes and a GENERIC code for every CauseClass, of that class' {
        $codes = @($script:Catalogue | ForEach-Object code)
        foreach ($k in 'si-ra-0101', 'si-ra-0102', 'si-ra-0103', 'si-ra-0201', 'si-ra-0302', 'si-set-0401', 'si-ra-0900') { $codes | Should -Contain $k }
        $c = Get-SIUplinkCausesContract
        foreach ($cls in $c.CauseClasses) {
            $g = $c.GenericCodes[$cls]
            $g | Should -Not -BeNullOrEmpty -Because $cls
            ($script:Catalogue | Where-Object code -eq $g).causeClass | Should -Be $cls
        }
    }
    It 'every code the mapper can return is in the catalogue' {
        $c = Get-SIUplinkCausesContract
        $all = @('si-ra-0101', 'si-ra-0102', 'si-ra-0103', 'si-ra-0201', 'si-ra-0302', 'si-set-0401', $c.UnknownCode) + @($c.GenericCodes.Values)
        foreach ($k in $all) { @($script:Catalogue | ForEach-Object code) | Should -Contain $k }
    }
}

Describe 'the cause and the code of one report' {
    It 'maps <Why> to <Code> (<Cls>)' -ForEach @(
        @{ State = 'NotApplicable'; Why = "Failed to resolve table or column expression named 'DeviceTvmSoftwareVulnerabilities'"; Code = 'si-ra-0101'; Cls = 'missing-licence'; Name = 'devicetvmsoftwarevulnerabilities' }
        @{ State = 'Failed'; Why = "its query failed: Failed to resolve scalar expression named 'si_cmdb_id'"; Code = 'si-ra-0102'; Cls = 'missing-column'; Name = 'si-cmdb-id' }
        @{ State = 'Failed'; Why = 'its query failed: BadRequest SYN0002 Query could not be parsed at ''of'''; Code = 'si-ra-0103'; Cls = 'query-defect'; Name = 'syn0002' }
        @{ State = 'Deviated'; Why = "the run retrieved 4 row(s), more than the source's count of 3 -- nothing is missing"; Code = 'si-ra-0201'; Cls = 'count-more'; Name = '' }
        @{ State = 'Failed'; Why = 'it failed: 413 Request Entity Too Large'; Code = 'si-ra-0302'; Cls = 'too-large'; Name = 'query-body' }
        @{ State = 'Failed'; Why = 'it failed: SQL error 40 on the settings database sql-si-x'; Code = 'si-set-0401'; Cls = 'settings-unreachable'; Name = '' }
        @{ State = 'NotComplete'; Why = 'not complete: the source holds 449 row(s) for this report, the run retrieved 0'; Code = 'si-ra-0907'; Cls = 'count-less'; Name = '' }
        @{ State = 'Failed'; Why = 'it failed: Response status code does not indicate success: 403 (Forbidden). graph.microsoft.com Authorization_RequestDenied'; Code = 'si-ra-0909'; Cls = 'permission'; Name = '' }
        @{ State = 'Failed'; Why = 'it failed: The request was canceled due to the configured HttpClient.Timeout of 900 seconds elapsing. TaskCanceledException'; Code = 'si-ra-0904'; Cls = 'platform-timeout'; Name = '' }
        @{ State = 'NotApplicable'; Why = 'SI-RA: advanced hunting is not provisioned in this tenant'; Code = 'si-ra-0901'; Cls = 'no-data-source'; Name = 'defender-xdr' }
        @{ State = 'Failed'; Why = 'it is not in this run'; Code = 'si-ra-0900'; Cls = 'query-defect'; Name = '' }
    ) {
        $cause = Get-SIReportCause -State $State -Text $Why
        $cause.CauseClass | Should -Be $Cls
        $cause.MissingName | Should -Be $Name
        Resolve-SIReportCauseCode -Cause $cause | Should -Be $Code
    }
    It 'Action / FixedIn: a fix this version already has is support, never a broken promise' {
        $e = $script:Catalogue | Where-Object code -eq 'si-ra-0102'
        (Get-SIUplinkCatalogueAction -Entry $e -Version '3.0.0.202610151000').Action | Should -Be 'fixed-in'
        (Get-SIUplinkCatalogueAction -Entry $e -Version '3.0.0.202610151000').FixedIn | Should -Be $e.fixedIn
        $now = Get-SIUplinkCatalogueAction -Entry $e -Version '3.0.0.202610152300+abc1234'
        $now.Action | Should -Be 'support'; $now.FixedIn | Should -BeNullOrEmpty
        (Get-SIUplinkCatalogueAction -Entry $null -Version '3.0.0').Action | Should -Be 'support'
    }
    It '#763: a count-more on a COMPLETE report is NOT a report item (no fix request); it is a note' {
        $fact = [pscustomobject]@{ Report = 'Attack_Paths_Summary_Credential_Based_Lateral_Movement'; State = 'Complete'; Rows = 3; SourceCount = 2; Why = "the run retrieved 3 row(s), more than the source's count of 2 -- nothing is missing" }
        @(ConvertTo-SIUplinkReports -Facts @($fact) -Version '3.0.0-rc.1267+08c23b1').Count | Should -Be 0
        @(Get-SIUplinkMailCodes -Facts @($fact)).Count | Should -Be 0
        $n = @(Get-SIUplinkReportNotes -Facts @($fact))
        $n.Count | Should -Be 1
        $n[0].Report | Should -Be 'Attack_Paths_Summary_Credential_Based_Lateral_Movement'
        $n[0].Rows | Should -Be 3; $n[0].SourceCount | Should -Be 2
        $n[0].Note | Should -Match 'no action'
        # a count-more on a report that is NOT complete stays as it was: a report item
        $dev = [pscustomobject]@{ Report = 'R2'; State = 'Deviated'; Why = "the run retrieved 4 row(s), more than the source's count of 3 -- nothing is missing" }
        @(ConvertTo-SIUplinkReports -Facts @($dev) -Version '3.0.0').Count | Should -Be 1
        @(Get-SIUplinkReportNotes -Facts @($dev)).Count | Should -Be 0
    }
    It 'the run record''s causes are compared with the RELEASE version (BUILD.json release), not the rc display' {
        [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\_shared\SI-TelemetrySend.ps1')) | Should -Match ([regex]::Escape('-Version (Get-SITelemetryReleaseVersion)'))
    }
}

Describe 'Reports[] -- the shape and the rules' {
    It 'every item has exactly the contract''s fields, ids only, Code + CauseClass always' {
        $items = @(ConvertTo-SIUplinkReports -Facts @(New-Fact 'Identity_SPN_OwnerMismatch' 'Failed' 'its query failed: SYN0002') -Identified -Version '3.0.0.202610151900' -Region 'West Europe')
        $items.Count | Should -Be 1
        $i = $items[0]
        @($i.PSObject.Properties.Name) | Should -Be @('Report', 'Code', 'CauseClass', 'MissingName', 'MissingLicence', 'Bucket', 'FixedIn', 'Action', 'RunMs', 'Rows', 'LastGoodRunMs', 'LastGoodRows',
                                                      'SourceCount', 'Buckets', 'Retries', 'QueryHash', 'QueryChanged', 'Region', 'StartedUtc', 'Detail')
        $i.Report | Should -MatchExactly '^[a-z0-9-]{1,60}$'
        $i.Report | Should -Be 'identity-spn-ownermismatch'
        $i.Code | Should -Be 'si-ra-0103'
        $i.CauseClass | Should -Be 'query-defect'
        $i.Region | Should -Be 'west-europe'
        $i.StartedUtc | Should -Be '2026-10-15T06:00:00Z'
        [long]$i.RunMs | Should -Be 1234; [long]$i.Rows | Should -Be 3; [long]$i.SourceCount | Should -Be 4; [long]$i.Buckets | Should -Be 2; [long]$i.LastGoodRows | Should -Be 4
        $i.Retries.'429' | Should -Be 1; $i.Retries.'502' | Should -Be 0; $i.Retries.'504' | Should -Be 2
        $i.QueryHash.Length | Should -BeLessOrEqual 16
        $i.QueryChanged | Should -BeTrue
        $i.LastGoodRunMs | Should -BeNullOrEmpty -Because 'not known is null, never guessed'
    }
    It 'never more than 20 items, failures first and the most severe first' {
        $f = @(1..20 | ForEach-Object { New-Fact ("NA_$_") 'NotApplicable' "Failed to resolve table or column expression named 'DeviceTvmSoftwareVulnerabilities'" }) +
             @(1..10 | ForEach-Object { New-Fact ("More_$_") 'Deviated' "the run retrieved 4 row(s), more than the source's count of 3" }) +
             @(New-Fact 'Lost' 'NotComplete' 'not complete: the source holds 9 row(s) for this report, the run retrieved 1') +
             @(New-Fact 'Settings' 'Failed' 'it failed: SQL error 40')
        $items = @(ConvertTo-SIUplinkReports -Facts $f -Identified -Version '3.0.0')
        $items.Count | Should -Be 20
        $items[0].CauseClass | Should -Be 'settings-unreachable'
        $items[1].CauseClass | Should -Be 'count-less'
        @($items | Where-Object CauseClass -eq 'count-more').Count | Should -Be 0 -Because 'the least severe are the ones left out'
    }
    It 'a secret in the engine''s error is scrubbed from Detail, which stays within 500 characters' {
        # the token is put together at run time, so the shipped test file itself carries no token shape (the publish scan)
        $jwt = ('e' + 'yJhbGciOiJIUzI1NiJ9') + '.' + ('e' + 'yJzdWIiOiIxMjM0NTY3ODkwIn0') + '.abcdefghijklmnop'
        $why = "it failed: Login failed; Server=tcp:sql-si.example.net;Password=Sup3rS3cret!; Bearer $jwt client_secret=abc123 key=Q2xpZW50U2VjcmV0VmFsdWUxMjM0NTY3ODkwYWJjZGVm sig=AbC%2Bdef " + ('x' * 900)
        $i = @(ConvertTo-SIUplinkReports -Facts @(New-Fact 'R1' 'Failed' $why) -Identified -Version '3.0.0')[0]
        $i.Detail | Should -Not -BeNullOrEmpty
        $i.Detail.Length | Should -BeLessOrEqual 500
        $i.Detail | Should -Not -Match 'Sup3rS3cret|eyJhbGci|abc123|Q2xpZW50U2VjcmV0|AbC%2Bdef'
        Test-SIUplinkLooksSecret $i.Detail | Should -BeFalse
    }
    It 'Detail is the FIRST line only, and a Detail that still looks like a secret is dropped' {
        ConvertTo-SIUplinkDetail "first line`nsecond line" | Should -Be 'first line'
        Mock -CommandName ConvertTo-SITelemetryErrorText -MockWith { param($Text) ('-----BEGIN ' + 'PRIVATE ' + 'KEY-----') + ' still here' }
        ConvertTo-SIUplinkDetail 'anything' | Should -BeNullOrEmpty
    }
    It 'anonymous: no Detail at all' {
        $i = @(ConvertTo-SIUplinkReports -Facts @(New-Fact 'R1' 'Failed' 'it failed: SYN0002') -Version '3.0.0')[0]
        $i.PSObject.Properties['Detail'] | Should -BeNullOrEmpty
    }
    It 'a broken catalogue still gives every item a code (the generic ones)' {
        $i = @(ConvertTo-SIUplinkReports -Facts @(New-Fact 'R1' 'NotComplete' 'not complete: the source holds 9 row(s) for this report, the run retrieved 1') -Version '3.0.0' -Catalogue @())[0]
        $i.Code | Should -Be 'si-ra-0907'
        $i.Action | Should -Be 'support'
    }
    It 'a cause mapping that throws still gives the item Code + CauseClass (si-ra-0900)' {
        Mock -CommandName Get-SIReportCause -MockWith { throw 'mapping broke' }
        $i = @(ConvertTo-SIUplinkReports -Facts @(New-Fact 'R1' 'Failed' 'x') -Version '3.0.0')[0]
        $i.Code | Should -Be 'si-ra-0900'
        $i.CauseClass | Should -Be 'query-defect'
    }
    It 'facts that cannot be read give no Reports -- never a throw' {
        { ConvertTo-SIUplinkReports -Facts @($null, 42, 'text', @{ }) } | Should -Not -Throw
        @(ConvertTo-SIUplinkReports -Facts $null).Count | Should -Be 0
    }
    It 'the record stays within the uplink''s 16 KB: Details shortened, then items left out' {
        $f = @(1..20 | ForEach-Object { New-Fact ("Report_With_A_Long_Name_$_") 'Failed' ("it failed: " + ('word ' * 200)) })
        $items = @(ConvertTo-SIUplinkReports -Facts $f -Identified -Version '3.0.0')
        $rec = [pscustomobject]@{ Kind = 'run'; Reports = $items }
        $null = Limit-SIUplinkRecordSize -Record $rec
        [System.Text.Encoding]::UTF8.GetByteCount(($rec | ConvertTo-Json -Depth 8 -Compress)) | Should -BeLessOrEqual 15000
        @($rec.Reports).Count | Should -BeGreaterThan 0
    }
}

Describe 'the run record carries Reports -- and a Reports problem never costs the record' {
    It 'identified: the run record carries Reports with Detail' {
        $s = Send-Run @(New-Fact 'Device_Missing_CVEs_Detailed' 'NotApplicable' "Failed to resolve table or column expression named 'DeviceTvmSoftwareVulnerabilities'")
        $s.Result.Status | Should -Be 'ok'
        @($s.Run.Reports).Count | Should -Be 1
        $s.Run.Reports[0].Code | Should -Be 'si-ra-0101'
        $s.Run.Reports[0].Report | Should -Be 'device-missing-cves-detailed'
        $s.Run.Reports[0].Detail | Should -Not -BeNullOrEmpty
    }
    It 'anonymous: Reports without Detail' {
        $s = Send-Run @(New-Fact 'R1' 'Failed' 'it failed: SYN0002') 'anonymous'
        $s.Run.Reports[0].Code | Should -Be 'si-ra-0103'
        $s.Run.Reports[0].PSObject.Properties['Detail'] | Should -BeNullOrEmpty
    }
    It 'a mapping that throws still sends the run record' {
        Mock -CommandName ConvertTo-SIUplinkReports -MockWith { throw 'boom' }
        $s = Send-Run @(New-Fact 'R1' 'Failed' 'x')
        $s.Result.Status | Should -Be 'ok'
        $s.Run | Should -Not -BeNullOrEmpty
        $s.Run.PSObject.Properties['Reports'] | Should -BeNullOrEmpty
    }
    It 'a record Invardia refuses WITH Reports is sent again without them' {
        $s = Send-Run @(New-Fact 'R1' 'Failed' 'it failed: SYN0002') 'identified' $script:Stub422
        $s.Result.Status | Should -Be 'ok'
        $s.Run | Should -Not -BeNullOrEmpty
        $s.Run.PSObject.Properties['Reports'] | Should -BeNullOrEmpty
        $global:SI_TelemetryHalted | Should -BeNullOrEmpty
    }
    It 'a run without report causes carries no Reports field' {
        $s = Send-Run $null
        $s.Run.PSObject.Properties['Reports'] | Should -BeNullOrEmpty
    }
}

Describe 'the run''s report facts (Risk Analysis)' {
    It 'failed, not complete, not applicable and deviated reports are in; a clean report is not' {
        $notes = @{
            'Clean' = @{ StartedUtc = [datetime]'2026-10-15T06:00:00Z'; EndedUtc = [datetime]'2026-10-15T06:00:05Z'; State = 'Complete'; Why = ''; Rows = 5 }
            'NA'    = @{ StartedUtc = [datetime]'2026-10-15T06:00:00Z'; EndedUtc = [datetime]'2026-10-15T06:00:01Z'; State = 'NotApplicable'; Why = 'Account is not provisioned'; Rows = 0 }
            'More'  = @{ State = 'Complete'; Why = "the run retrieved 4 row(s), more than the source's count of 3 -- nothing is missing"; Rows = 4; SourceCount = 3 }
            'Fail'  = @{ StartedUtc = [datetime]'2026-10-15T06:00:00Z'; EndedUtc = [datetime]'2026-10-15T06:00:02Z' }
        }
        $f = @(Get-SIReportCauseFacts -Notes $notes -Failures @(@{ Report = 'Fail'; Why = 'its query failed: SYN0002' }, @{ Report = 'Missing'; Why = 'it is not in this run' }) `
                -Done @{ Fail = 'NotComplete' } -Retries @{ Fail = @{ '429' = 3 } } -LastGood @{ Fail = @{ Rows = '7'; QueryHash = 'abc' } })
        @($f | ForEach-Object Report | Sort-Object) | Should -Be @('Fail', 'Missing', 'More', 'NA')
        ($f | Where-Object Report -eq 'Fail').State | Should -Be 'Failed'
        ($f | Where-Object Report -eq 'Fail').RunMs | Should -Be 2000
        ($f | Where-Object Report -eq 'Fail').LastGoodRows | Should -Be '7'
        ($f | Where-Object Report -eq 'Fail').Retries.'429' | Should -Be 3
        ($f | Where-Object Report -eq 'NA').State | Should -Be 'NotApplicable'
        ($f | Where-Object Report -eq 'More').State | Should -Be 'Complete' -Because '#814: a complete report with more rows than the source counted keeps its verdict'
    }
    It '#814: a COMPLETE report (Summary or Detailed) with more rows than the source counted is a note on the way to Invardia, never a report item' {
        $why = "the run retrieved 3 row(s), more than the source's count of 2 -- nothing is missing"
        foreach ($r in 'Attack_Paths_Summary_Credential_Based_Lateral_Movement', 'Attack_Paths_Detailed_Credential_Based_Lateral_Movement') {
            # the verdict as the run keeps it: on the report's note, or only in the run's verdicts
            foreach ($case in @(@{ Notes = @{ $r = @{ State = 'Complete'; Why = $why; Rows = 3; SourceCount = 2 } }; Done = @{} },
                                @{ Notes = @{ $r = @{ Why = $why; Rows = 3; SourceCount = 2 } }; Done = @{ $r = 'Complete' } })) {
                $f = @(Get-SIReportCauseFacts -Notes $case.Notes -Done $case.Done)
                $f.Count | Should -Be 1
                @(ConvertTo-SIUplinkReports -Facts $f -Identified -Version '3.0.0.202610221600').Count | Should -Be 0 -Because "$r is complete: nothing is missing"
                @(Get-SIUplinkMailCodes -Facts $f).Count | Should -Be 0
                $n = @(Get-SIUplinkReportNotes -Facts $f)
                $n.Count | Should -Be 1; $n[0].Rows | Should -Be 3; $n[0].SourceCount | Should -Be 2
            }
        }
        # a report that is NOT complete with that text stays a report item, as before
        $f2 = @(Get-SIReportCauseFacts -Notes @{ R2 = @{ State = 'Unverified'; Why = $why } } -Done @{ R2 = 'Unverified' })
        $f2[0].State | Should -Be 'Deviated'
        @(ConvertTo-SIUplinkReports -Facts $f2 -Version '3.0.0').Count | Should -Be 1
    }
    It 'counts 429 / 502 / 504 answers against the running report' {
        $global:SI_UplinkRetryAnswers = $null
        Add-SIReportRetryAnswer -Message '429 Too Many Requests' -Report 'R'
        Add-SIReportRetryAnswer -Message '502 Bad Gateway' -Report 'R'
        Add-SIReportRetryAnswer -Message 'TaskCanceledException' -Report 'R'
        Add-SIReportRetryAnswer -Message 'Fix syntax errors in your query' -Report 'R'
        $global:SI_UplinkRetryAnswers['R']['429'] | Should -Be 1
        $global:SI_UplinkRetryAnswers['R']['502'] | Should -Be 1
        $global:SI_UplinkRetryAnswers['R']['504'] | Should -Be 1
    }
    It 'Risk Analysis wires it: the notes, the hunting retries, the run context and the mail' {
        $ra = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'))
        $ra | Should -Match "_shared/SI-UplinkCauses\.ps1"
        $ra | Should -Match "NotePropertyName 'ReportCauses'"
        $ra | Should -Match 'Set-RAReportNote -ReportName \(\[string\]\$ReportName\) -Values @\{ StartedUtc'
        # the failure references come right BEFORE the AI section in the mail: the engine hands both to the report mail's
        # builder (RA-ReportMail.ps1), which appends the code section first and the AI section directly after it
        # (one splat, $__mailArgs, for every build of the body -- the Pro protection mail builds it sent-now or kept)
        $ra | Should -Match 'CodeSectionHtml = \$codeSection; AiSectionHtml = \$aiSection'
        foreach ($b in @([regex]::Matches($ra, 'ConvertTo-RAReportMailHtml -Kpi [^\r\n]*'))) { $b.Value | Should -Match '@__mailArgs' }
        $rm = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-ReportMail.ps1'))
        $rm | Should -Match '\.Append\(\$CodeSectionHtml\) \}\s*\r?\n\s*if \("\$AiSectionHtml"\.Trim\(\)\) \{ \[void\]\$c\.Append\(\$AiSectionHtml\)'
        $rm.IndexOf('Append($CodeSectionHtml)') | Should -BeLessThan $rm.IndexOf('Append($AiSectionHtml)')
        # ... and in the rendered mail: the references directly before the AI section, both after the report's figures
        . (Join-Path $script:SIRoot 'engine\_shared\SI-MailLayout.ps1')
        . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-ReportMail.ps1')
        $kpi = [pscustomobject]@{ GlobalScore = 72; Band = 'Moderate'; TotalRows = 10; DomainScore = @{ Endpoint = 70; Identity = 80; Azure = 95; PublicIP = 40 }
            SevCount = @{ Critical = 1; High = 2; Medium = 3; Low = 4 }
            SevByDomain = @{ Endpoint = @{ Critical = 1; High = 2; Medium = 3; Low = 4; Total = 10 }; Identity = @{ Critical = 0; High = 0; Medium = 0; Low = 0; Total = 0 }
                             Azure = @{ Critical = 0; High = 0; Medium = 0; Low = 0; Total = 0 }; PublicIP = @{ Critical = 0; High = 0; Medium = 0; Low = 0; Total = 0 } } }
        $mail = ConvertTo-RAReportMailHtml -Kpi $kpi -ReportLabel 'RiskAnalysis_Summary' -TenantTag 'contoso.example' -GeneratedAt '2026-10-17 06:00' -SolutionVersion '3.0.0' `
            -CodeSectionHtml '<p style="margin:0 0 10px 0;">CODE-SECTION-MARK</p>' -AiSectionHtml '<p style="margin:0 0 10px 0;">AI-SECTION-MARK</p>'
        $mail.IndexOf('CODE-SECTION-MARK') | Should -BeGreaterThan $mail.IndexOf('Findings by domain')
        $mail.IndexOf('CODE-SECTION-MARK') | Should -BeLessThan $mail.IndexOf('AI-SECTION-MARK')
        $mail | Should -Match 'CODE-SECTION-MARK</p><p style="margin:0 0 10px 0;">AI-SECTION-MARK' -Because 'nothing comes between the references and the AI section'
        $gh = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-GraphHunting.ps1'))
        $gh | Should -Match 'Add-SIReportRetryAnswer -Message \$msg'
        $ra.IndexOf("NotePropertyName 'ReportCauses'") | Should -BeLessThan $ra.IndexOf('Send-SIRunHealthRow -RunContext $script:_RunHealthCtx -Phase ''End''')
    }
}

Describe 'the heartbeat''s capability probe' {
    It 'Capabilities have the closed keys only; CiColumns are the optional CI columns as ids, at most 40' {
        $la = @([pscustomobject]@{ Kind = 'ok'; Name = '' }, [pscustomobject]@{ Kind = 'sentinel'; Name = '' }, [pscustomobject]@{ Kind = 'col'; Name = 'si_assetid' }) +
              @(1..50 | ForEach-Object { [pscustomobject]@{ Kind = 'col'; Name = ('si_cmdb_field{0:D2}' -f $_) } })
        $p = ConvertFrom-SICapabilityProbe -LaRows $la -HuntRows @([pscustomobject]@{ T = 'xdr' }, [pscustomobject]@{ T = 'mdi' }) `
                -Skus @([pscustomobject]@{ skuPartNumber = 'SPE_E5'; capabilityStatus = 'Enabled'; servicePlans = @([pscustomobject]@{ servicePlanName = 'INTUNE_A' }, [pscustomobject]@{ servicePlanName = 'AAD_PREMIUM_P2' }) },
                        [pscustomobject]@{ skuPartNumber = 'OLD_SKU'; capabilityStatus = 'Suspended'; servicePlans = @() }) -SkusRead
        $c = Get-SIUplinkCausesContract
        foreach ($k in @($p.Capabilities.Keys)) { $c.CapabilityKeys | Should -Contain $k }
        $p.Capabilities['defenderXdr'] | Should -BeTrue
        $p.Capabilities['defenderVulnMgmt'] | Should -BeFalse
        $p.Capabilities['mdi'] | Should -BeTrue
        $p.Capabilities['cmdb'] | Should -BeTrue
        $p.Capabilities['sentinel'] | Should -BeTrue
        $p.Capabilities['intune'] | Should -BeTrue
        $p.Capabilities['entraP2Pim'] | Should -BeTrue
        @($p.CiColumns).Count | Should -Be 40
        $p.CiColumns | Should -Not -Contain 'si-assetid' -Because 'a column every install has is not optional'
        $p.CiColumns[0] | Should -Be 'si-cmdb-field01'
        $p.Licences | Should -Be @('spe-e5')
    }
    It 'what was not read is LEFT OUT, never false by guess; no Defender XDR reads false' {
        $p = ConvertFrom-SICapabilityProbe -LaRows $null -HuntRows $null -Skus $null
        @($p.Capabilities.Keys).Count | Should -Be 0
        $p2 = ConvertFrom-SICapabilityProbe -LaRows $null -HuntRows $null -HuntNotProvisioned
        $p2.Capabilities['defenderXdr'] | Should -BeFalse
        $p2.Capabilities.Contains('dataLake') | Should -BeFalse
    }
    It 'licences that cannot be read (403) give no Licences and grant nothing' {
        $p = Get-SICapabilityProbe -RunQuery { param($k) @([pscustomobject]@{ Kind = 'ok'; Name = '' }) } -RunHunting { param($k) @() } -GraphGet { param($u) throw '403 Forbidden Authorization_RequestDenied' }
        @($p.Licences).Count | Should -Be 0
        $p.Capabilities.Contains('intune') | Should -BeFalse
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\_shared\SI-UplinkCauses.ps1'))
        $src | Should -Not -Match 'appRoleAssignments|New-SIAppRoleGrant|Grant-' -Because 'no permission is ever added for the licences'
    }
    It 'the heartbeat carries Capabilities and CiColumns; Licences only when identified' {
        $script:TestProbe = [pscustomobject]@{ Capabilities = [ordered]@{ defenderXdr = $true; cmdb = $false }; CiColumns = @('si-cmdb-id'); Licences = @('spe-e5') }
        foreach ($mode in 'identified', 'anonymous') {
            $script:Posts.Clear(); $global:SI_TelemetryHalted = $null; $global:SI_Telemetry_Enabled = $null
            $dir = Join-Path $TestDrive $mode; $null = New-Item -ItemType Directory -Force $dir
            $rc = [pscustomobject]@{ RunId = 'r'; Engine = 'endpoint'; ShardIndex = 0; StartedAt = [datetime]'2026-10-15T06:00:00Z' }
            $null = Send-SITelemetryRunEnd -RunContext $rc -ExitReason 'success' -AssetCount 1 -Context (New-Ctx -Mode $mode -Dir $dir) -Transport $script:StubOk `
                -Now ([datetime]'2026-10-15T07:00:00Z') -HeartbeatCounts { @{} } -CapabilityProbe { $script:TestProbe }
            $hb = @($script:Posts | Where-Object { "$($_.Kind)" -eq 'heartbeat' })[0]
            $hb | Should -Not -BeNullOrEmpty -Because $mode
            $hb.Capabilities.defenderXdr | Should -BeTrue
            $hb.CiColumns | Should -Be @('si-cmdb-id')
            if ($mode -eq 'identified') { $hb.Licences | Should -Be @('spe-e5') } else { $hb.PSObject.Properties['Licences'] | Should -BeNullOrEmpty }
        }
    }
}

Describe 'the failure mail links each code''s page' {
    It 'Reference: <code> linked to https://invardia.com/docs/si/errors/<code>/' {
        Get-SIErrorCodeUrl 'si-ra-0103' | Should -Be 'https://invardia.com/docs/si/errors/si-ra-0103/'
        Get-SIErrorCodeUrl 'not a code' | Should -Be ''
        $h = ConvertTo-SIErrorCodeMailHtml -Codes @('si-ra-0103', 'si-ra-0103', 'si-set-0401')
        $h | Should -Match ([regex]::Escape('href="https://invardia.com/docs/si/errors/si-ra-0103/"'))
        $h | Should -Match ([regex]::Escape('href="https://invardia.com/docs/si/errors/si-set-0401/"'))
        ([regex]::Matches($h, 'si-ra-0103/')).Count | Should -Be 1
        ConvertTo-SIErrorCodeMailHtml -Codes @() | Should -Be ''
    }
    It 'the mail''s codes never carry the internal Detail' {
        $codes = @(Get-SIUplinkMailCodes -Facts @(New-Fact 'R1' 'Failed' 'it failed: Password=hunter2 SYN0002'))
        $codes | Should -Be @('si-ra-0103')
        (ConvertTo-SIErrorCodeMailHtml -Codes $codes) | Should -Not -Match 'hunter2|SYN0002'
    }
}
