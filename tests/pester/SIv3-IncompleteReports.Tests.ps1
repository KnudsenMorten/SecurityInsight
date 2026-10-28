#Requires -Version 5.1
<#
    A REPORT THAT DID NOT DELIVER A WHOLE RESULT MAKES THE RUN PARTIAL -- its findings are UNKNOWN, never "no longer
    reported" and never closed as fixed.

    Ring 1, 2026-10-05: the Defender for Cloud recommendation report failed with a query error (400) on every run. The
    engine printed "query failed", skipped the report and ended the run 'success'; the row-count guard warned that the
    Azure recommendation report had left findings to it ("HANDOFF-LOST") -- and the run still ended 'success'. The data
    sync loaded the collection as complete, and the changes view showed those findings as gone. In the container the
    guard also had no history (the folder dies with the replica), so every run read as the first and a report that lost
    most of its findings could never be noticed.

    Now:
      * a failed query / an unreadable result is recorded per report (Add-RAReportFailure);
      * an empty result records its zero (a measurement, not a failure);
      * Get-RAIncompleteReports names every report that did not deliver: failed, attempted without a count, or flagged
        by the guard as HANDOFF-LOST (the giver), MISSING, WENT-TO-ZERO or LARGE-DROP -- never HANDED-OFF;
      * Send-RARunHealthEnd turns 'success' into 'success-partial' and names them, so the data sync HOLDS the collection
        and the close-loop closes nothing on it;
      * the container keeps the guard's history in the install's storage between runs.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    if ($env:SI_TEST_ROOT) { $script:SIRoot = $env:SI_TEST_ROOT }
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-RowCountGuard.ps1')
    function script:Write-Warn2 { param([string]$m) }
    function script:Write-Info  { param([string]$m) }
    $script:RaPath = Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'
    $script:RaSrc = Get-Content -LiteralPath $script:RaPath -Raw
    $script:RaAst = [System.Management.Automation.Language.Parser]::ParseFile($script:RaPath, [ref]$null, [ref]$null)
    function script:Get-RaFunctionText {
        param([string]$Name)
        $f = $script:RaAst.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $Name }, $true)
        if (-not $f) { throw "function $Name not found" }
        $f.Extent.Text
    }
}

Describe 'Get-RAIncompleteReports -- which reports did not deliver a whole result' {

    It 'names the report whose query failed, with the reason' {
        $r = @(Get-RAIncompleteReports -Failures @(@{ Report = 'Azure_DefenderRecommendations_Detailed'; Why = 'its query failed: BadRequest' }) -Attempted @('Azure_DefenderRecommendations_Detailed') -Counts @{})
        $r.Count | Should -Be 1
        $r[0].Report | Should -Be 'Azure_DefenderRecommendations_Detailed'
        $r[0].Why | Should -Be 'its query failed: BadRequest'
    }

    It 'HANDOFF-LOST makes the GIVER incomplete too (what it left to the failed report is in no report)' {
        $f = @(Get-RARowCountRegressions -Previous @{} -Current @{ Azure_Recommendations_Detailed = 500 } -Attempted @('Azure_Recommendations_Detailed', 'Azure_DefenderRecommendations_Detailed'))
        $r = @(Get-RAIncompleteReports -Findings $f -Attempted @('Azure_Recommendations_Detailed', 'Azure_DefenderRecommendations_Detailed') -Counts @{ Azure_Recommendations_Detailed = 500 })
        @($r | ForEach-Object { $_.Report } | Sort-Object) | Should -Be @('Azure_DefenderRecommendations_Detailed', 'Azure_Recommendations_Detailed')
        ($r | Where-Object { $_.Report -eq 'Azure_Recommendations_Detailed' }).Why | Should -Match 'in no report'
        ($r | Where-Object { $_.Report -eq 'Azure_DefenderRecommendations_Detailed' }).Why | Should -Be 'it produced no result'
    }

    It 'LARGE-DROP, WENT-TO-ZERO and MISSING each make the report incomplete' {
        $f = @(Get-RARowCountRegressions -Previous @{ A = 100; B = 40; C = 7 } -Current @{ A = 10; B = 0 } -Attempted @('A', 'B', 'C'))
        $r = @(Get-RAIncompleteReports -Findings $f -Attempted @('A', 'B', 'C') -Counts @{ A = 10; B = 0 })
        @($r | ForEach-Object { $_.Report } | Sort-Object) | Should -Be @('A', 'B', 'C')
        ($r | Where-Object { $_.Report -eq 'A' }).Why | Should -Be 'it went from 100 finding(s) last run to 10'
        ($r | Where-Object { $_.Report -eq 'B' }).Why | Should -Be 'it went from 40 finding(s) last run to none'
        ($r | Where-Object { $_.Report -eq 'C' }).Why | Should -Match 'produced no result'
    }

    It 'a report attempted without a count is incomplete even on its first run (no history to compare)' {
        $r = @(Get-RAIncompleteReports -Findings @() -Attempted @('New') -Counts @{})
        $r.Count | Should -Be 1
        $r[0].Why | Should -Be 'it produced no result'
    }

    It 'NEGATIVE -- a hand-off that arrived (HANDED-OFF), an empty result recorded as zero, a small drop: nothing incomplete' {
        $g = 'Azure_Recommendations_Detailed'; $rr = 'Azure_DefenderRecommendations_Detailed'
        $prev = @{ $g = 720; Z = 0; S = 100 }; $cur = @{ $g = 19; $rr = 701; Z = 0; S = 90 }
        $f = @(Get-RARowCountRegressions -Previous $prev -Current $cur -Attempted @($g, $rr, 'Z', 'S'))
        @($f | Where-Object { $_.Kind -eq 'HANDED-OFF' }).Count | Should -Be 1
        @(Get-RAIncompleteReports -Findings $f -Attempted @($g, $rr, 'Z', 'S') -Counts $cur).Count | Should -Be 0
        @(Get-RAIncompleteReports).Count | Should -Be 0
    }

    It 'one entry per report, reasons joined' {
        $f = @(@{ Report = 'A'; Kind = 'LARGE-DROP'; Previous = 10; Current = 1 })
        $r = @(Get-RAIncompleteReports -Findings $f -Failures @(@{ Report = 'A'; Why = 'its query failed: x' }) -Attempted @('A') -Counts @{ A = 1 })
        $r.Count | Should -Be 1
        $r[0].Why | Should -Be 'its query failed: x; it went from 10 finding(s) last run to 1'
    }

    It 'the run-health message names every incomplete report in plain words' {
        $m = Format-RAIncompleteReports -Incomplete @(@{ Report = 'A'; Why = 'x' }, @{ Report = 'B'; Why = 'y' })
        $m | Should -Be '2 report(s) incomplete -- their findings are unknown, not remediated: A (x); B (y)'
        Format-RAIncompleteReports -Incomplete @() | Should -Be ''
    }
}

Describe 'Send-RARunHealthEnd -- an incomplete report makes the run partial (run on the engine''s own function)' {
    BeforeAll {
        . ([scriptblock]::Create((Get-RaFunctionText 'Send-RARunHealthEnd')))
        . ([scriptblock]::Create((Get-RaFunctionText 'Add-RAReportFailure')))
        # Add-RAReportFailure also notes the report's end time for the run record's Reports[] (#709) -- the engine's own note function
        . ([scriptblock]::Create((Get-RaFunctionText 'Set-RAReportNote')))
        function script:Send-SIRunHealthRow { param($RunContext, $Phase, $AssetCount, $ExitReason, $ErrorMessage) $script:Sent = @{ Exit = $ExitReason; Msg = $ErrorMessage } }
    }
    BeforeEach {
        $script:_RunHealthEndSent = $false; $script:_RunHealthCtx = $null; $script:_RABucketLossRun = $null
        $script:_RAPublishFailures = $null; $script:_RAUpstreamOutcome = $null; $script:Sent = $null
        $script:_RAReportFailures = New-Object System.Collections.Generic.List[object]
        $script:_RAIncompleteReports = @()
    }

    It 'the guard named an incomplete report: success becomes success-partial, and the message names it' {
        $script:_RAIncompleteReports = @(@{ Report = 'Azure_Recommendations_Detailed'; Why = 'the findings it leaves to X are in no report, because X produced no result' })
        Send-RARunHealthEnd -ExitReason 'success'
        $script:Sent.Exit | Should -Be 'success-partial'
        $script:Sent.Msg | Should -Match 'Azure_Recommendations_Detailed'
        $script:Sent.Msg | Should -Match 'unknown, not remediated'
    }

    It 'a failed query alone (the guard did not run) still makes the run partial' {
        Add-RAReportFailure -ReportName 'Azure_DefenderRecommendations_Detailed' -Reason 'its query failed: BadRequest'
        Send-RARunHealthEnd -ExitReason 'success'
        $script:Sent.Exit | Should -Be 'success-partial'
        $script:Sent.Msg | Should -Match 'Azure_DefenderRecommendations_Detailed \(its query failed: BadRequest\)'
    }

    It 'NEGATIVE -- every report whole: the run stays success; an error stays an error' {
        Send-RARunHealthEnd -ExitReason 'success'
        $script:Sent.Exit | Should -Be 'success'
        $script:_RunHealthEndSent = $false
        $script:_RAIncompleteReports = @(@{ Report = 'A'; Why = 'x' })
        Send-RARunHealthEnd -ExitReason 'error' -ErrorMessage 'boom'
        $script:Sent.Exit | Should -Be 'error'
    }
}

Describe 'WIRING -- the engine records failures and empty results, and decides after the guard' {
    It 'the unbucketed query failure and the unreadable result are recorded per report' {
        $script:RaSrc | Should -Match 'Write-Err2 "query failed: \$\(\$_\.Exception\.Message\)"[\s\S]{0,400}?Add-RAReportFailure -ReportName \$ReportName'
        $script:RaSrc | Should -Match 'Write-Err2 "result conversion failed: \$\(\$_\.Exception\.Message\)"\s+Add-RAReportFailure -ReportName \$ReportName'
    }
    It 'an empty result records its zero before leaving the report (every "no results" exit)' {
        # (one exit books the empty answer in the stream first -- #673 -- so one line may sit between the two)
        ([regex]::Matches($script:RaSrc, 'Write-Info "Query returned no results"\s+(?:if \(\$script:RAStreamOn\) \{ Add-RAStreamBucket [^\r\n]*\s+)?if \(\$null -ne \$global:RA_RowCountsThisRun\) \{ \$global:RA_RowCountsThisRun\[\[string\]\$ReportName\] = 0 \}')).Count | Should -Be 2
        $script:RaSrc | Should -Match 'skipping filters \+ scoring for this report \(continuing with next report\)"\s+if \(\$null -ne \$global:RA_RowCountsThisRun\)'
    }
    It 'the incomplete reports are decided right after the row-count guard, from its findings' {
        $g = $script:RaSrc.IndexOf('$__rcFindings = Invoke-RARowCountGuard')
        $d = $script:RaSrc.IndexOf('$script:_RAIncompleteReports = @(Get-RAIncompleteReports -Findings @($__rcForInc)')
        $g | Should -BeGreaterThan 0
        $d | Should -BeGreaterThan $g
        $script:RaSrc.IndexOf("Send-RARunHealthEnd -ExitReason 'success'", $d) | Should -BeGreaterThan $d
    }
}

Describe 'the container keeps the completeness history between runs' {
    BeforeAll {
        . (Join-Path $script:SIRoot 'container\_shared\SI-ContainerRunState.ps1')
    }
    BeforeEach {
        Mock New-SIAzStorageContext { [pscustomobject]@{ StorageAccountName = $StorageAccountName } }
    }
    It 'one blob per template per file, at the engine''s own local paths' {
        $f = @(Get-SIRaGuardHistoryFiles -SettingsPath $TestDrive -Template 'RiskAnalysis_Detailed')
        @($f | ForEach-Object { $_.BlobName }) | Should -Be @('risk-analysis/RowCountHistory.RiskAnalysis_Detailed.json', 'risk-analysis/ColumnFillHistory.RiskAnalysis_Detailed.json')
        . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-ColumnFillGuard.ps1')
        $f[0].LocalPath | Should -Be (Get-RARowCountHistoryPath -SettingsPath $TestDrive)
        $f[1].LocalPath | Should -Be (Get-RAColumnFillHistoryPath -SettingsPath $TestDrive)
    }
    It 'saved after the run, loaded before the next' {
        $local = Join-Path $TestDrive 'OUTPUT\RowCountHistory.json'
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $local) | Out-Null
        '{"RiskAnalysis_Detailed":{"A":5}}' | Set-Content -LiteralPath $local
        $script:Saved = New-Object System.Collections.Generic.List[string]
        Mock Get-SIAzStorageContainer { $true }
        Mock Set-SIAzStorageBlobContent { [void]$script:Saved.Add($Blob) }
        Save-SIRaGuardHistory -AccountName 'acct' -SettingsPath $TestDrive -Template 'RiskAnalysis_Detailed' | Should -Be 1
        @($script:Saved) | Should -Be @('risk-analysis/RowCountHistory.RiskAnalysis_Detailed.json')
        Remove-Item -LiteralPath $local
        Mock Get-SIAzStorageBlob { if ($Blob -like '*RowCount*') { [pscustomobject]@{ Name = $Blob } } else { throw 'BlobNotFound' } }
        Mock Get-SIAzStorageBlobContent { '{"RiskAnalysis_Detailed":{"A":7}}' | Set-Content -LiteralPath $Destination }
        Restore-SIRaGuardHistory -AccountName 'acct' -SettingsPath $TestDrive -Template 'RiskAnalysis_Detailed' | Should -Be 1
        (Get-Content -LiteralPath $local -Raw | ConvertFrom-Json).RiskAnalysis_Detailed.A | Should -Be 7
    }
    It 'NEGATIVE -- nothing stored, storage failing, no account: never a failed run' {
        Mock Get-SIAzStorageBlob { throw 'BlobNotFound' }
        Restore-SIRaGuardHistory -AccountName 'acct' -SettingsPath (Join-Path $TestDrive 'none') -Template 'T' | Should -Be 0
        Mock New-SIAzStorageContext { throw 'no identity' }
        { Restore-SIRaGuardHistory -AccountName 'acct' -SettingsPath $TestDrive -Template 'T' -WarningAction SilentlyContinue } | Should -Not -Throw
        Restore-SIRaGuardHistory -AccountName '' -SettingsPath $TestDrive -Template 'T' | Should -Be 0
        Save-SIRaGuardHistory -AccountName '' -SettingsPath $TestDrive -Template 'T' | Should -Be 0
        Save-SIRaGuardHistory -AccountName 'acct' -SettingsPath (Join-Path $TestDrive 'empty') -Template 'T' | Should -Be 0
    }
    It 'WIRING -- loaded before the engine runs, saved after it' {
        $c = Get-Content -LiteralPath (Join-Path $script:SIRoot 'container\Start-RiskAnalysisInContainer.ps1') -Raw
        $run = $c.IndexOf('& $engineScript')
        $c.IndexOf('Restore-SIRaGuardHistory') | Should -BeLessThan $run
        $c.IndexOf('Restore-SIRaGuardHistory') | Should -BeGreaterThan 0
        $c.IndexOf('Save-SIRaGuardHistory') | Should -BeGreaterThan $run
    }
}
