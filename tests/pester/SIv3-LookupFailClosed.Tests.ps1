#Requires -Version 5.1
<#
    #674 -- A LOOKUP A REPORT NEEDS THAT CANNOT BE READ, OR A HAND-OFF LIST THAT READS EMPTY WHILE ITS TABLE SHOULD HOLD
    THE LATEST LIST, MAKES THAT REPORT NOT COMPLETE. NEVER COMPLETE WITH DUPLICATES OR MISSING ENRICHMENT.

    Before: when the read of a report's SecurityInsight lookup (SI_*_CL, from Log Analytics) failed, the engine wrote
    "[scope] failed; let-blocks left for table-shadow fallback", then "[shadow] failed; routing query as-is" -- and sent the
    query to Microsoft Defender, which does not have SI's tables, where `union isfuzzy` made the hand-off list EMPTY. The
    Azure recommendation report then listed every recommendation the Defender recommendation report also lists, and the
    run said Complete. The same for a 2-phase enrichment that could not be read (CI / CMDB values empty, Complete), and for
    a brand-new table in Log Analytics that reads empty for about 45 minutes (a new install's first run).

    The first Describe REPRODUCES the old behaviour's cause (the query reached Defender with the lookup unread) and now
    expects the report to stop instead. The engine is one large script that cannot be dot-sourced, so its half is asserted
    on the source -- the technique SIv3-LookupTooLargeForOneQuery uses.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-ProfileAugment.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-GraphHunting.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-AutoBucketing.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-ReportHandoff.ps1')

    function script:Write-Info  { param($m) $script:Info   += , [string]$m }
    function script:Write-Diag  { param($m) }
    function script:Write-Ok    { param($m) }
    function script:Write-Err2  { param($m) $script:Errs += , [string]$m }
    function script:Write-Warn2 { param($m) $script:Warned += , [string]$m }
    function script:Add-DynamicGroupKeyCasts { param($Query) $Query }
    function script:Reset-SupersededAttempts { }
    function script:Add-SupersededAttempt { param($Path, $Message) }
    function script:Resolve-SupersededOnSuccess { param($WinningPath) }
    function script:Flush-SupersededAttempts { }
    function script:Save-RARenderedQuery { param($Query, $Tag) }
    function script:Ensure-GraphAuth { param($MaxAgeMinutes) }
    function script:Start-Sleep { param($Seconds, $Milliseconds) }
    function script:Invoke-LogAnalyticsKqlQuery { param($WorkspaceResourceId, $Query) }
    function script:Invoke-SIHuntingQueryRest { param($Query, $Token, $TimeoutSec) }

    $script:Ws = '/subscriptions/x/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/w'

    # The shape of Azure_Recommendations_*: the CI lookup, the hand-off block (#147/#278) and the anti-join.
    $script:Q = @'
let _ciLink = SI_CI_CL
    | project _ciKey = tolower(tostring(si_link_azure)), si_tier = toint(si_tier)
    | where isnotempty(_ciKey);
//__DEFENDER_HANDOFF_BEGIN__
let _dfcPairs = union isfuzzy=true
    (datatable(_dfcKey:string)[]),
    (SI_AzureRecommendation_CL | where TimeGenerated > ago(8d) | project _dfcKey = strcat("h", tostring(hash(ResourceName))))
    | project _dfcKey;
//__DEFENDER_HANDOFF_END__
ExposureGraphNodes
| extend DeviceKey = tolower(NodeId)
| join kind=leftouter (_ciLink) on $left.DeviceKey == $right._ciKey
| join kind=leftanti (_dfcPairs) on _dfcKey
'@

    function script:Reset-State {
        $script:_HybridRowsCache = @{}; $script:_HybridSnapshotCache = @{}; $script:_HybridBucketGroupsCache = @{}; $script:_HybridBucketGroupsWhole = @{}
        $script:_HybridColumnTypesCache = @{}; $script:_CLSnapshotsKql = @{}; $script:_ProfileAugmentLookups = @{}
        $script:_CrossDomainBucketCoalesce = @(); $script:_SkipEGBucketForCrossDomain = $false; $script:_RACrossDomainReplicated = $false
        $script:_RAHybridLookups = $null; $script:_RAHybridLastRequest = $null
        $script:_SentinelLakeUnavailable = $true; $script:_RAHuntingNotProvisioned = $false; $script:_LakeTipShown = $true
        $script:_CurrentBucketCount = 0; $script:_CurrentBucketIndex = 0
        $script:_RAHandoffVerdicts = @{}; $script:_RAHandoffEmptyGivers = @{}
        $script:Warned = @(); $script:Info = @(); $script:Errs = @(); $script:Sent = New-Object System.Collections.Generic.List[string]; $script:LaAsked = New-Object System.Collections.Generic.List[string]
        $global:SI_WorkspaceResourceId = $script:Ws
        $global:SI_RA_DumpAugmentInput = $false
        $global:SI_HuntingRequestCapBytes = $null
        $global:SI_RA_HuntingRowCap = $null
    }
    $script:Ci    = @([pscustomobject]@{ _ciKey = '/subscriptions/s/resourcegroups/rg/providers/microsoft.compute/virtualmachines/vm1'; si_tier = 1 })
    $script:Pairs = @([pscustomobject]@{ _dfcKey = 'h123' }, [pscustomobject]@{ _dfcKey = 'h456' })
}

Describe 'REPRODUCED -- a lookup that cannot be read used to reach Defender unread; now the report stops' {
    BeforeEach {
        Reset-State
        Mock Resolve-ProfileAugmentPlan { @{ Query = $Query; Plans = @() } }
        Mock Invoke-SIHuntingQueryRest { [void]$script:Sent.Add([string]$Query); [pscustomobject]@{ Results = @() } }
    }

    It 'the hand-off list read fails (503): the "lookup unavailable" error, NOTHING sent to Defender, no fallback' {
        Mock Invoke-LogAnalyticsKqlQuery { [void]$script:LaAsked.Add([string]$Query); if ($Query -match 'SI_AzureRecommendation_CL') { throw 'Response status code does not indicate success: 503 (Service Unavailable).' } else { $script:Ci } }
        $err = $null
        try { $null = Invoke-GraphHuntingQuery -Query $script:Q -MaxRetries 1 } catch { $err = $_ }
        $err | Should -Not -BeNullOrEmpty
        Test-RALookupUnavailableError -Err $err | Should -BeTrue
        Test-RAReportCannotRunError -Err $err   | Should -BeTrue
        [string]$err.Exception.Message | Should -Match 'a lookup this report needs could not be read'
        [string]$err.Exception.Message | Should -Match '503'
        $script:Sent.Count | Should -Be 0
        @($script:Warned | Where-Object { $_ -match 'table-shadow fallback|routing query as-is' }).Count | Should -Be 0
    }

    It 'the CI lookup read fails: the same -- never Complete without the CI values' {
        Mock Invoke-LogAnalyticsKqlQuery { if ($Query -match 'SI_CI_CL') { throw 'Request timed out' } else { $script:Pairs } }
        $err = $null
        try { $null = Invoke-GraphHuntingQuery -Query $script:Q -MaxRetries 1 } catch { $err = $_ }
        Test-RALookupUnavailableError -Err $err | Should -BeTrue
        $script:Sent.Count | Should -Be 0
    }

    It 'a table that does NOT exist in Log Analytics keeps the existing "no data source" rule (control)' {
        Mock Invoke-LogAnalyticsKqlQuery { if ($Query -match 'SI_CI_CL') { throw "'project' operator: Failed to resolve table or column expression named 'SI_CI_CL'" } else { $script:Pairs } }
        $err = $null
        try { $null = Invoke-GraphHuntingQuery -Query $script:Q -MaxRetries 1 } catch { $err = $_ }
        $err | Should -Not -BeNullOrEmpty
        Test-RALookupUnavailableError -Err $err | Should -BeFalse
        Test-RANoDataSource -Message $err.Exception.Message | Should -BeTrue
        Get-RABucketFailureAction -Err $err | Should -Be 'Absent'
        $script:Sent.Count | Should -Be 0
    }

    It 'every lookup read: the query goes out as before (control)' {
        Mock Invoke-LogAnalyticsKqlQuery { if ($Query -match 'SI_AzureRecommendation_CL') { $script:Pairs } else { $script:Ci } }
        { $null = Invoke-GraphHuntingQuery -Query $script:Q -MaxRetries 1 } | Should -Not -Throw
        $script:Sent.Count | Should -Be 1
        $script:Sent[0] | Should -Match 'h456'
    }

    It 'a whole-table copy that cannot be read fails closed too' {
        { Invoke-RAResolveLookups -Query 'x' -WorkspaceResourceId $script:Ws -Resolve { param($q) $q } -Shadow { param($q) throw 'Bad gateway 502' } } | Should -Throw -ExpectedMessage '*a lookup this report needs could not be read*'
    }
}

Describe 'the bucket loop ends the report in one decision -- never retried, re-sized or split' {
    It 'the shared classifier says Fail (not Retry, not Split, not Absent)' {
        $e = New-RALookupUnavailableError -Message 'a lookup this report needs could not be read from Log Analytics (its lookups) -- 503'
        Get-RABucketFailureAction -Err $e | Should -Be 'Fail'
        Get-RABucketFailureAction -Err ([System.Management.Automation.ErrorRecord]::new($e, 'x', 'NotSpecified', $null)) | Should -Be 'Fail'
    }
    It 'the error is recognised by its mark and by its text' {
        Test-RALookupUnavailableError -Err (New-RALookupUnavailableError -Message 'zzz') | Should -BeTrue
        Test-RALookupUnavailableError -Err 'a lookup this report needs could not be read -- x' | Should -BeTrue
        Test-RALookupUnavailableError -Err 'something else' | Should -BeFalse
        Test-RAReportCannotRunError -Err (New-RALookupTooLargeError -Message 'zz') | Should -BeTrue
    }
    It 'the engine uses the combined test at every decision site and words the report failure plainly (source)' {
        $src = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1')
        ([regex]::Matches($src, 'Test-RAReportCannotRunError -Err \$_')).Count | Should -BeGreaterOrEqual 2
        $src | Should -Match "if \(Test-RALookupUnavailableError -Err \`$reportCannotFit\) \{ 'it was not run: \{0\}' \}"
        $ab = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-AutoBucketing.ps1')
        ([regex]::Matches($ab, 'Test-RAReportCannotRunError -Err')).Count | Should -Be 3
        $gh = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-GraphHunting.ps1')
        $gh | Should -Not -Match 'left for table-shadow fallback'
        $gh | Should -Not -Match 'routing query as-is'
    }
}

Describe 'the post-query enrichment (2-phase) that cannot be read fails closed' {
    BeforeEach { Reset-State }
    It 'a read failure throws the "lookup unavailable" error and is not cached as empty' {
        Mock Invoke-LogAnalyticsKqlQuery { throw 'Response status code does not indicate success: 429 (Too Many Requests).' }
        $plan = @{ Var = '_ep'; TableName = 'SI_Endpoint_Profile_CL'; LeftKey = 'DeviceKey'; RightKey = 'k'; ProjectionKql = 'SI_Endpoint_Profile_CL | project k'; ColumnAliases = @{ cmdbId = 'cmdbId' } }
        $err = $null
        try { $null = Invoke-ProfileAugment -Rows @([pscustomobject]@{ DeviceKey = 'a' }) -Plans @($plan) -WorkspaceResourceId $script:Ws } catch { $err = $_ }
        Test-RALookupUnavailableError -Err $err | Should -BeTrue
        $script:_ProfileAugmentLookups.Count | Should -Be 0
    }
    It 'a table that does not exist keeps its columns empty as before (control)' {
        Mock Invoke-LogAnalyticsKqlQuery { throw "Failed to resolve table or column expression named 'SI_Endpoint_Profile_CL'" }
        $plan = @{ Var = '_ep'; TableName = 'SI_Endpoint_Profile_CL'; LeftKey = 'DeviceKey'; RightKey = 'k'; ProjectionKql = 'SI_Endpoint_Profile_CL | project k'; ColumnAliases = @{ cmdbId = 'cmdbId' } }
        { $null = Invoke-ProfileAugment -Rows @([pscustomobject]@{ DeviceKey = 'a' }) -Plans @($plan) -WorkspaceResourceId $script:Ws } | Should -Not -Throw
    }
}

Describe 'a hand-off list that reads EMPTY -- told apart from an intentionally empty one' {
    BeforeEach {
        Reset-State
        Mock Resolve-ProfileAugmentPlan { @{ Query = $Query; Plans = @() } }
        Mock Invoke-SIHuntingQueryRest { [void]$script:Sent.Add([string]$Query); [pscustomobject]@{ Results = @() } }
        $script:CountAnswer = $null; $script:CountThrows = $null
        Mock Invoke-LogAnalyticsKqlQuery {
            [void]$script:LaAsked.Add([string]$Query)
            if ($Query -match 'summarize SIRows = count\(\)') { if ($script:CountThrows) { throw $script:CountThrows }; return @([pscustomobject]@{ SIRows = $script:CountAnswer }) }
            if ($Query -match 'SI_AzureRecommendation_CL') { return @() }
            $script:Ci
        }
    }

    It 'NEW TABLE, ROWS NOT READABLE YET (an install''s first ~45 minutes): NOT complete, nothing sent' {
        $script:CountAnswer = 0
        $err = $null
        try { $null = Invoke-GraphHuntingQuery -Query $script:Q -MaxRetries 1 } catch { $err = $_ }
        Test-RALookupUnavailableError -Err $err | Should -BeTrue
        [string]$err.Exception.Message | Should -Match 'none of its rows can be read yet'
        [string]$err.Exception.Message | Should -Match '45 minutes'
        $script:Sent.Count | Should -Be 0
    }

    It 'THE COUNT FAILS: not knowable, NOT complete' {
        $script:CountThrows = 'Request timed out'
        $err = $null
        try { $null = Invoke-GraphHuntingQuery -Query $script:Q -MaxRetries 1 } catch { $err = $_ }
        Test-RALookupUnavailableError -Err $err | Should -BeTrue
        [string]$err.Exception.Message | Should -Match 'could not say whether that is right'
    }

    It 'THE TABLE DOES NOT EXIST (no Defender list ever written): right, the report keeps every finding and runs' {
        $script:CountThrows = "Failed to resolve table or column expression named 'SI_AzureRecommendation_CL'"
        $ReportName = 'Azure_Recommendations_Summary'
        { $null = Invoke-GraphHuntingQuery -Query $script:Q -MaxRetries 1 } | Should -Not -Throw
        $script:Sent.Count | Should -Be 1
        $script:_RAHandoffEmptyGivers.ContainsKey('Azure_Recommendations_Summary') | Should -BeTrue
    }

    It 'ONLY OLDER LISTS (none in the last 8 days): right, kept as it is and said' {
        $script:CountAnswer = 812
        { $null = Invoke-GraphHuntingQuery -Query $script:Q -MaxRetries 1 } | Should -Not -Throw
        $script:Sent.Count | Should -Be 1
        @($script:Info | Where-Object { $_ -match 'is empty and that is right' }).Count | Should -Be 1
    }

    It 'the verdict is asked once per table and run -- the next slice and the next report reuse it' {
        $script:CountAnswer = 812
        $null = Invoke-GraphHuntingQuery -Query $script:Q -MaxRetries 1
        $null = Invoke-GraphHuntingQuery -Query $script:Q -MaxRetries 1
        @($script:LaAsked | Where-Object { $_ -match 'SIRows' }).Count | Should -Be 1
    }

    It 'a list WITH rows is never counted (control)' {
        Mock Invoke-LogAnalyticsKqlQuery { [void]$script:LaAsked.Add([string]$Query); if ($Query -match 'SI_AzureRecommendation_CL') { $script:Pairs } else { $script:Ci } }
        $null = Invoke-GraphHuntingQuery -Query $script:Q -MaxRetries 1
        @($script:LaAsked | Where-Object { $_ -match 'SIRows' }).Count | Should -Be 0
    }

    It 'the INTENTIONALLY empty hand-off (#278: the Defender report is not in the run) is not looked at' {
        $q2 = Resolve-RADefenderHandoffBlock -Query $script:Q -ReportName 'Azure_Recommendations_Summary' -IncludedReports @('Azure_Recommendations_Summary')
        $q2 | Should -Match 'let _dfcPairs = datatable\(_dfcKey:string\)\[\];'
        Get-RAHandoffLookupBinding -Query $q2 | Should -BeNullOrEmpty
        { $null = Invoke-GraphHuntingQuery -Query $q2 -MaxRetries 1 } | Should -Not -Throw
        @($script:LaAsked | Where-Object { $_ -match 'SIRows' }).Count | Should -Be 0
        $script:Sent.Count | Should -Be 1
    }

    It 'the check runs before the route is chosen, so the Sentinel data lake set-up decides the same way (source)' {
        $gh = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-GraphHunting.ps1')
        $gh.IndexOf('Assert-RAHandoffLookupReadable -Query $Query') | Should -BeGreaterThan 0
        $gh.IndexOf('Assert-RAHandoffLookupReadable -Query $Query') | Should -BeLessThan $gh.IndexOf('Invoke-SISentinelLakeQuery -Query $Query')
    }
}

Describe 'the receiving report finds rows the giver could not see: the giver is not complete' {
    It 'names the giver when its receiver found rows' {
        $g = @{ 'Azure_Recommendations_Summary' = 'SI_AzureRecommendation_CL does not exist in Log Analytics' }
        $r = @(Get-RAHandoffContradiction -ReportName 'Azure_DefenderRecommendations_Summary' -Retrieved 750 -EmptyGivers $g)
        $r.Count | Should -Be 1
        $r[0].Report | Should -Be 'Azure_Recommendations_Summary'
        $r[0].Why | Should -Match 'found 750 row'
    }
    It 'nothing when the receiver found nothing, or for another grain, or another report' {
        $g = @{ 'Azure_Recommendations_Summary' = 'x' }
        @(Get-RAHandoffContradiction -ReportName 'Azure_DefenderRecommendations_Summary' -Retrieved 0 -EmptyGivers $g).Count | Should -Be 0
        @(Get-RAHandoffContradiction -ReportName 'Azure_DefenderRecommendations_Detailed' -Retrieved 9 -EmptyGivers $g).Count | Should -Be 0
        @(Get-RAHandoffContradiction -ReportName 'Device_Missing_CVEs_Summary' -Retrieved 9 -EmptyGivers $g).Count | Should -Be 0
    }
    It 'the engine checks it where each report''s verdict is made and records the giver as not complete (source)' {
        $src = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1')
        $src | Should -Match 'Get-RAHandoffContradiction -ReportName \(\[string\]\$ReportName\) -Retrieved \$Retrieved'
        $src | Should -Match 'Add-RAReportFailure -ReportName \$__hc\.Report'
    }
}

Describe 'the verdict of an empty hand-off list (pure)' {
    It 'Absent / Stale / NotReady / Unknown' {
        (Get-RAHandoffSourceVerdict -Rows $null -CountError "Failed to resolve table or column expression named 'SI_AzureRecommendation_CL'" -Table 'SI_AzureRecommendation_CL').State | Should -Be 'Absent'
        (Get-RAHandoffSourceVerdict -Rows 4 -Table 'SI_AzureRecommendation_CL').State | Should -Be 'Stale'
        (Get-RAHandoffSourceVerdict -Rows 0 -Table 'SI_AzureRecommendation_CL').State | Should -Be 'NotReady'
        (Get-RAHandoffSourceVerdict -Rows $null -CountError 'timeout' -Table 'SI_AzureRecommendation_CL').State | Should -Be 'Unknown'
        # another table missing is not this table missing
        (Get-RAHandoffSourceVerdict -Rows $null -CountError "Failed to resolve table or column expression named 'SI_CI_CL'" -Table 'SI_AzureRecommendation_CL').State | Should -Be 'Unknown'
    }
    It 'the shipped Azure recommendation reports carry a hand-off block the check reads' {
        $y = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml')
        $b = Get-RAHandoffLookupBinding -Query $y
        $b | Should -Not -BeNullOrEmpty
        $b.Var   | Should -Be '_dfcPairs'
        $b.Table | Should -Be 'SI_AzureRecommendation_CL'
    }
}

Describe 'the count reads the Log Analytics reader''s real answer shape (one array, not rows)' {
    BeforeEach {
        Reset-State
        Mock Resolve-ProfileAugmentPlan { @{ Query = $Query; Plans = @() } }
        Mock Invoke-SIHuntingQueryRest { [void]$script:Sent.Add([string]$Query); [pscustomobject]@{ Results = @() } }
        # the real reader answers `return ,@($rows)` -- ONE array; @() around the call would make it one "row"
        function script:Invoke-LogAnalyticsKqlQuery { param($WorkspaceResourceId, $Query)
            if ($Query -match 'summarize SIRows = count\(\)') { return , @([pscustomobject]@{ SIRows = 812 }) }
            if ($Query -match 'SI_AzureRecommendation_CL') { return , @() }
            return , @($script:Ci)
        }
    }
    It 'older lists are read as older lists (812 rows), not as an unreadable new table' {
        { $null = Invoke-GraphHuntingQuery -Query $script:Q -MaxRetries 1 } | Should -Not -Throw
        $script:_RAHandoffVerdicts['SI_AzureRecommendation_CL'].State | Should -Be 'Stale'
        $script:Sent.Count | Should -Be 1
    }
}