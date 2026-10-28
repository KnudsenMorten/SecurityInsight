#Requires -Version 5.1
<#
    #690 (37) -- A LOG ANALYTICS PARTIAL ANSWER IS READ FOR WHAT IT SAYS; A RESULT TOO LARGE FOR ONE ANSWER IS READ IN PARTS.

    customer A 2026-10-15 19:22Z / 19:28Z (ring 2): Azure_Recommendations_Summary / _Detailed were "not run" (the hand-off
    list _dfcPairs "could not be read") and Azure_DefenderRecommendations_Summary / _Detailed "failed" -- every one with
    "Log Analytics returned a PARTIAL answer (PartialError: There were some errors when processing your query.) -- Query
    execution has exceeded the allowed limits", each within a second. The "exceeded the allowed limits" was the engine's OWN
    text (#641 refused EVERY partial answer with it). The service's real answer, proven on internal Log Analytics the same
    day: a `union isfuzzy=true` leg over an SI table the workspace does not have (SI_AzureRecommendation_CL did not exist
    there: "no recommendations stored") is answered HTTP 200 + PartialError, innererror severity Warning "Failed to resolve
    table or column expression named '<table>'" -- with the other legs' rows, i.e. the WHOLE result.

    What is held:
      * the verdict: that answer is the whole result (Unresolved), a limit is Limit, anything else is Other -- read from the
        LEAVES of the error, never from the generic outer text;
      * the reader: Unresolved rows are returned (said once per table); Limit is refused as too large (the bucket logic
        splits it); Other is refused in the service's words, never worded as too large;
      * too large for one answer: read again in 2, 4, ... parts until every part is whole -- the fake answers PartialError
        whole and at 2 parts and whole at 4 -- every row once, nothing of a short answer kept; a lookup (the CL snapshot)
        the same; MEASURED stop (two counts in a row refused with no row at all = the work itself is the limit): too large,
        si-ra-0302, the report ends as not complete;
      * plan B (#673, default on): the hand-off list _dfcPairs is NOT fetched at all for the Azure recommendation reports.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $ra = Join-Path $script:SIRoot 'engine\risk-analysis\_shared'
    function script:Write-Info  { param($m) $script:Info += , [string]$m }
    function script:Write-Warn2 { param($m) $script:Warned += , [string]$m }
    function script:Write-Err2  { param($m) }
    function script:Write-Ok    { param($m) }
    function script:Write-Diag  { param($m) }
    foreach ($f in 'RA-ProfileAugment.ps1', 'RA-LogAnalyticsQuery.ps1', 'RA-GraphHunting.ps1', 'RA-AutoBucketing.ps1', 'RA-ReportHandoff.ps1', 'RA-SummaryBucketMerge.ps1', 'RA-RowShaping.ps1', 'RA-SqlStream.ps1', 'RA-DefenderFilter.ps1') { . (Join-Path $ra $f) }
    foreach ($f in 'engine\_shared\data-sql\SI-DataModel.ps1', 'engine\_shared\data-sql\SI-DataSql.ps1') { . (Join-Path $script:SIRoot $f) }
    . (Join-Path $script:SIRoot 'engine\_shared\SI-Yaml.ps1')
    function script:Add-DynamicGroupKeyCasts { param($Query) $Query }
    function script:Reset-SupersededAttempts { }
    function script:Add-SupersededAttempt { param($Path, $Message) }
    function script:Resolve-SupersededOnSuccess { param($WinningPath) }
    function script:Flush-SupersededAttempts { }
    function script:Save-RARenderedQuery { param($Query, $Tag) }
    function script:Ensure-GraphAuth { param($MaxAgeMinutes) }
    function script:Invoke-SIHuntingQueryRest { param($Query, $Token, $TimeoutSec) }
    function script:Invoke-SISentinelLakeQuery { param($Query, $WorkspaceResourceId) }
    $script:Ws = '/subscriptions/x/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/w'

    # the answer internal Log Analytics gave 2026-10-15 to `union isfuzzy=true (datatable(a:string)["x"]), (SI_DoesNotExistProbe_CL | where TimeGenerated > ago(8d))`
    $script:FuzzyJson = '{"code":"PartialError","message":"There were some errors when processing your query.","details":[{"code":"EngineError","message":"Something went wrong processing your query on the server.","innererror":{"code":"-2133196790","message":"''where'' operator: Failed to resolve table or column expression named ''SI_AzureRecommendation_CL''","severity":3,"severityName":"Warning"}}]}'
    $script:LimitJson = '{"code":"PartialError","message":"There were some errors when processing your query.","details":[{"code":"EngineError","message":"Query result set has exceeded the internal data size limit 64000000 (E_QUERY_RESULT_SET_TOO_LARGE)"}]}'
    $script:OtherJson = '{"code":"PartialError","message":"There were some errors when processing your query.","details":[{"code":"EngineError","message":"Something went wrong processing your query on the server.","innererror":{"code":"-2133196790","message":"''extend'' operator: Failed to resolve scalar expression named ''Severity''"}}]}'
    function script:ErrObj([string]$j) { $j | ConvertFrom-Json }

    # 40 rows; the fake Log Analytics cuts a part by Id (the engine cuts by a hash of the whole row -- the same partition idea)
    $script:All = @(1..40 | ForEach-Object { [pscustomobject][ordered]@{ Id = $_; Name = "r$_" } })
    function script:PartOf([string]$Query) {
        if ($Query -match 'abs\(hash\(tostring\(pack_all\(\)\)\) % (\d+)\) == (\d+)\s*$') { return @{ N = [int]$Matches[1]; I = [int]$Matches[2] } }
        return @{ N = 1; I = 0 }
    }
    function script:RowsOf($p) { @($script:All | Where-Object { ($_.Id % $p.N) -eq $p.I }) }

    function script:Reset-State {
        $script:Info = @(); $script:Warned = @(); $script:Asked = New-Object System.Collections.Generic.List[string]
        $script:_RALaUnresolvedSaid = @{}
        $script:RADfcSet = $null; $script:RADfcLast = $null; $script:RADfcCompare = $null; $script:RADfcNoSqlSaid = $false
        $script:_RAHandoffVerdicts = @{}; $script:_RAHandoffEmptyGivers = @{}
        $script:_HybridRowsCache = @{}; $script:_HybridSnapshotCache = @{}; $script:_HybridBucketGroupsCache = @{}; $script:_HybridColumnTypesCache = @{}; $script:_CLSnapshotsKql = @{}
        $script:_SentinelLakeUnavailable = $true; $script:_RAHuntingNotProvisioned = $false; $script:_LakeTipShown = $true
        $script:_CurrentBucketCount = 0; $script:_CurrentBucketIndex = 0
        $global:SI_WorkspaceResourceId = $script:Ws
        $global:SI_RA_DefenderFilterInEngine = 'off'; $global:SI_RA_DefenderFilterCompare = $null
        $global:SI_RA_DumpAugmentInput = $false; $global:SI_HuntingRequestCapBytes = $null; $global:SI_RA_HuntingRowCap = $null
        $script:RAStreamOn = $false; $script:RAStream = $null
    }
}

AfterAll { $global:SI_RA_DefenderFilterInEngine = $null; $global:SI_RA_DefenderFilterCompare = $null }

Describe 'the verdict of a partial answer comes from its leaves' {
    It 'a fuzzy union over an SI table this workspace does not have: Unresolved -- the whole result' {
        $v = Get-RALaPartialVerdict -ErrorObject (ErrObj $script:FuzzyJson)
        $v.Kind | Should -Be 'Unresolved'
        @($v.Tables) | Should -Be @('SI_AzureRecommendation_CL')
    }
    It 'a union leaf words it "table expression" (no "or column"): still Unresolved' {
        $u = $script:FuzzyJson -replace "'where' operator: Failed to resolve table or column expression", "'union' operator: Failed to resolve table expression"
        $u | Should -Match "'union' operator: Failed to resolve table expression named"
        (Get-RALaPartialVerdict -ErrorObject (ErrObj $u)).Kind | Should -Be 'Unresolved'
    }
    It 'a result over the size limit: Limit' {
        (Get-RALaPartialVerdict -ErrorObject (ErrObj $script:LimitJson)).Kind | Should -Be 'Limit'
    }
    It 'anything else (a column that does not resolve, a missing table that is not SI''s, no detail): Other -- never Unresolved' {
        (Get-RALaPartialVerdict -ErrorObject (ErrObj $script:OtherJson)).Kind | Should -Be 'Other'
        (Get-RALaPartialVerdict -ErrorObject (ErrObj ($script:FuzzyJson -replace 'SI_AzureRecommendation_CL', 'DeviceInfo'))).Kind | Should -Be 'Other'
        (Get-RALaPartialVerdict -ErrorObject (ErrObj '{"code":"PartialError","message":"There were some errors when processing your query."}')).Kind | Should -Be 'Other'
    }
    It 'a missing SI table AND another cause in one answer: not Unresolved (the other leaf decides)' {
        $two = '{"code":"PartialError","message":"There were some errors when processing your query.","details":[{"code":"EngineError","message":"x","innererror":{"code":"1","message":"Failed to resolve table or column expression named ''SI_A_CL''"}},{"code":"EngineError","message":"Query result set has exceeded the internal data size limit 64000000 (E_QUERY_RESULT_SET_TOO_LARGE)"}]}'
        (Get-RALaPartialVerdict -ErrorObject (ErrObj $two)).Kind | Should -Be 'Limit'
    }
}

Describe 'the Log Analytics reader acts on the verdict' {
    BeforeEach {
        Reset-State
        Mock Resolve-WorkspaceCustomerId { '00000000-0000-0000-0000-000000000001' }
    }
    It 'Unresolved: the rows are the answer, said once per table and run (customer A 2026-10-15)' {
        Mock Invoke-SIAzOperationalInsightsQuery { [pscustomobject]@{ Results = @([pscustomobject]@{ a = 'x' }); Tables = $null; Error = (ErrObj $script:FuzzyJson) } }
        $rows = Invoke-LogAnalyticsKqlQuery -WorkspaceResourceId $script:Ws -Query 'q'
        @($rows).Count | Should -Be 1
        $null = Invoke-LogAnalyticsKqlQuery -WorkspaceResourceId $script:Ws -Query 'q'
        @($script:Info | Where-Object { $_ -match 'SI_AzureRecommendation_CL does not exist in Log Analytics yet' }).Count | Should -Be 1
        ($script:Info -join ' ') | Should -Not -Match 'exceeded'
    }
    It 'Limit: refused as too large -- the bucket logic splits it' {
        Mock Invoke-SIAzOperationalInsightsQuery { [pscustomobject]@{ Results = @([pscustomobject]@{ a = 'x' }); Tables = $null; Error = (ErrObj $script:LimitJson) } }
        $err = $null; try { $null = Invoke-LogAnalyticsKqlQuery -WorkspaceResourceId $script:Ws -Query 'q' } catch { $err = $_ }
        $err | Should -Not -BeNullOrEmpty
        $err.Exception.Message | Should -Match 'E_QUERY_RESULT_SET_TOO_LARGE'
        Test-RALaLimitPartialError -Err $err | Should -BeTrue
        Get-RALaPartialRowCount -Err $err | Should -Be 1
        Test-IsBucketOverflowError -Err $err | Should -BeTrue
        Get-RABucketFailureAction -Err $err | Should -Be 'Split'
    }
    It 'Other: refused in the service''s own words, never as too large (a smaller slice does not fix it)' {
        Mock Invoke-SIAzOperationalInsightsQuery { [pscustomobject]@{ Results = @(); Tables = $null; Error = (ErrObj $script:OtherJson) } }
        $err = $null; try { $null = Invoke-LogAnalyticsKqlQuery -WorkspaceResourceId $script:Ws -Query 'q' } catch { $err = $_ }
        $err | Should -Not -BeNullOrEmpty
        $err.Exception.Message | Should -Match "Failed to resolve scalar expression named 'Severity'"
        $err.Exception.Message | Should -Not -Match 'exceeded the allowed limits'
        Test-IsBucketOverflowError -Err $err | Should -BeFalse
        Test-RALaLimitPartialError -Err $err | Should -BeFalse
    }
}

Describe 'too large for one answer: read again in parts -- never fewer rows, never a short answer kept' {
    BeforeEach {
        Reset-State
        Mock Resolve-WorkspaceCustomerId { '00000000-0000-0000-0000-000000000001' }
        # the fake Log Analytics: PartialError (limit) for the whole result and at 2 parts, whole at 4
        Mock Invoke-SIAzOperationalInsightsQuery {
            [void]$script:Asked.Add([string]$Query)
            $p = PartOf $Query
            $rows = RowsOf $p
            if ($p.N -lt 4) { return [pscustomobject]@{ Results = @($rows | Select-Object -First 3); Tables = $null; Error = (ErrObj $script:LimitJson) } }
            [pscustomobject]@{ Results = $rows; Tables = $null; Error = $null }
        }
    }
    It 'PartialError whole and at 2 parts, whole at 4: every row once, in 4 parts' {
        $rows = Invoke-LogAnalyticsKqlQueryParted -WorkspaceResourceId $script:Ws -Query "SI_X_CL`n| where TimeGenerated > ago(8d);`n// a trailing comment`n" -What 'the test query'
        @($rows).Count | Should -Be 40
        @($rows | ForEach-Object { $_.Id } | Sort-Object -Unique).Count | Should -Be 40 -Because 'every row once: nothing of the short answers (3 rows each) is kept'
        $script:Asked.Count | Should -Be 6 -Because 'the whole query, the first part of 2 (refused), then the 4 parts'
        foreach ($i in 0..3) { @($script:Asked | Where-Object { $_ -match ('% 4\) == {0}\s*$' -f $i) }).Count | Should -Be 1 }
        @($script:Asked | Where-Object { $_ -match ';\s*\r?\n\| where abs' }).Count | Should -Be 0 -Because 'the trailing semicolon and comment are taken off before the part filter'
        ($script:Info -join ' ') | Should -Match 'reading it again in 4 parts'
        ($script:Info -join ' ') | Should -Match 'was read in 4 parts \(40 row\(s\)\)'
    }
    It 'a lookup snapshot (the CL rows a report inlines) is read the same way -- all of it' {
        Mock Invoke-LogAnalyticsKqlQuery {
            $p = PartOf $Query
            if ($p.N -lt 4) { throw (New-RALaPartialError -Verdict @{ Kind = 'Limit'; Code = 'PartialError'; Detail = 'Query result set has exceeded the internal data size limit' } -Rows 3) }
            , @(RowsOf $p)
        }
        $r = Get-SIHybridLetRows -VarName '_ciLink' -BodyKql "SI_CI_CL | where TimeGenerated > ago(30d)" -WorkspaceResourceId $script:Ws
        @($r.Rows).Count | Should -Be 40
        @($r.Rows | ForEach-Object { $_.Id } | Sort-Object -Unique).Count | Should -Be 40
    }
    It 'MEASURED stop: refused with no row at all at two counts in a row -- too large (si-ra-0302), the report ends as not complete' {
        Mock Invoke-SIAzOperationalInsightsQuery { [void]$script:Asked.Add([string]$Query); [pscustomobject]@{ Results = @(); Tables = $null; Error = (ErrObj $script:LimitJson) } }
        $err = $null; try { $null = Invoke-LogAnalyticsKqlQueryParted -WorkspaceResourceId $script:Ws -Query 'SI_X_CL' -What 'the lookup ''_x''' } catch { $err = $_ }
        $err | Should -Not -BeNullOrEmpty
        $script:Asked.Count | Should -Be 2 -Because 'the whole query and the first of 2 parts -- the work itself is the limit, more parts cannot help'
        $err.Exception.Data['SIRACode'] | Should -Be 'si-ra-0302'
        Test-RAReportCannotRunError -Err $err | Should -BeTrue
        Get-RABucketFailureAction -Err $err | Should -Be 'Fail'
        ConvertTo-RALookupUnavailableError -What 'the lookup' -Err $err | Should -BeNullOrEmpty -Because 'passed on as it is'
        $err.Exception.Message | Should -Match "the lookup '_x' is more than Log Analytics can answer"
    }
    It 'a short answer that held rows keeps the read going (a result over the size limit shrinks with more parts)' {
        Mock Invoke-SIAzOperationalInsightsQuery {
            [void]$script:Asked.Add([string]$Query); $p = PartOf $Query; $rows = RowsOf $p
            if ($p.N -lt 8) { return [pscustomobject]@{ Results = @($rows | Select-Object -First 2); Tables = $null; Error = (ErrObj $script:LimitJson) } }
            [pscustomobject]@{ Results = $rows; Tables = $null; Error = $null }
        }
        $rows = Invoke-LogAnalyticsKqlQueryParted -WorkspaceResourceId $script:Ws -Query 'SI_X_CL'
        @($rows).Count | Should -Be 40
    }
    It 'any other error is passed on as it is, after one read' {
        Mock Invoke-SIAzOperationalInsightsQuery { [void]$script:Asked.Add([string]$Query); throw "Operation returned an invalid status code 'BadRequest' -- SemanticError" }
        { Invoke-LogAnalyticsKqlQueryParted -WorkspaceResourceId $script:Ws -Query 'SI_X_CL' } | Should -Throw -ExpectedMessage '*SemanticError*'
        $script:Asked.Count | Should -Be 1
    }
    It 'the part filter is one hash of the whole result row, after the last statement' {
        $q = Get-RALaPartQuery -Query "let a = 1;`nT | where x == a;`n`n// end`n" -Parts 4 -Part 3
        $q | Should -Match '(?s)let a = 1;\s*T \| where x == a\s*\| where abs\(hash\(tostring\(pack_all\(\)\)\) % 4\) == 3$'
    }
}

Describe 'the engine reads Log Analytics through the parted reader' {
    It 'the report''s own query on the Log Analytics route, the lookups and the table copies' {
        $gh = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-GraphHunting.ps1'))
        $pa = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-ProfileAugment.ps1'))
        $gh | Should -Match ([regex]::Escape('$rows = Invoke-LogAnalyticsKqlQueryParted -WorkspaceResourceId $wsResId -Query $finalQuery'))
        $gh | Should -Not -Match ([regex]::Escape('$rows = Invoke-LogAnalyticsKqlQuery -WorkspaceResourceId $wsResId'))
        $pa | Should -Match ([regex]::Escape('$clRows = Invoke-LogAnalyticsKqlQueryParted -WorkspaceResourceId $WorkspaceResourceId -Query $bodyKql'))
        $pa | Should -Match ([regex]::Escape('$rows = Invoke-LogAnalyticsKqlQueryParted -WorkspaceResourceId $WorkspaceResourceId -Query $snapshotKql'))
        $pa | Should -Match ([regex]::Escape('$clRows = Invoke-LogAnalyticsKqlQueryParted -WorkspaceResourceId $WorkspaceResourceId -Query $plan.ProjectionKql'))
    }
}

Describe 'plan B (#673, on by default): the hand-off list _dfcPairs is not fetched at all' {
    BeforeAll {
        $script:Catalog = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml') | ConvertFrom-SIYaml
        function script:Get-Q([string]$Name) { [string]($script:Catalog.Reports | Where-Object ReportName -eq $Name).ReportQuery }
        $script:FakeSeam = {
            param($Sql, $Params, $Mode)
            if ($Sql -like "*OBJECT_ID('sidata.RaDefenderKey')*") { return 1 }
            if ($Sql -like 'DELETE FROM sidata.RaDefenderKey*') { return 0 }
            if ($Sql -like 'SELECT COUNT_BIG(*) FROM sidata.RaDefenderKey*') { return 0 }
            if ($Sql -like 'SELECT v.K FROM*') { return , @() }
            throw "unexpected SQL: $Sql"
        }
    }
    BeforeEach {
        Reset-State
        # plan B is OFF by default again (internal 2026-10-15: its de-duplication missed most Defender matches) -- this case
        # tests plan B itself, so it switches it on
        $global:SI_RA_DefenderFilterInEngine = 'on'
        $script:RAStreamOn = $true; $script:RAStream = @{ Invoke = $script:FakeSeam; RunKey = 'Detailed|2026-10-15T19:28:00.000'; Grain = 'Detailed'; Current = @{ Account = @{} } }
        # customer A: SI_AzureRecommendation_CL does not exist -- a direct (not fuzzy) read of it is refused as Log Analytics
        # refuses it; a fuzzy union over it (_dfcRecByKey) is the whole result (no rows), as the reader now takes it
        Mock Invoke-LogAnalyticsKqlQuery {
            [void]$script:Asked.Add([string]$Query)
            if ($Query -match 'SI_AzureRecommendation_CL' -and $Query -notmatch 'isfuzzy') { throw "Operation returned an invalid status code 'BadRequest' -- 'where' operator: Failed to resolve table or column expression named 'SI_AzureRecommendation_CL'" }
            , @()
        }
        Mock Resolve-ProfileAugmentPlan { @{ Query = $Query; Plans = @() } }
        Mock Invoke-SIHuntingQueryRest { $script:SentQ = $Query; [pscustomobject]@{ Results = @() } }
    }
    It '<_>: no Log Analytics read of the hand-off list -- only the Defender list''s own count, which says "never written"' -ForEach @('Azure_Recommendations_Detailed', 'Azure_Recommendations_Summary') {
        $q = Resolve-RADefenderHandoffBlock -Query (Get-Q $_) -ReportName $_ -IncludedReports @($_, ($_ -replace 'Azure_Recommendations', 'Azure_DefenderRecommendations'))
        Get-RAHandoffLookupBinding -Query $q | Should -Not -BeNullOrEmpty -Because 'the hand-off is active: the receiving report is in the run'
        $cut = ConvertTo-RADefenderFilterQuery -Query $q
        $cut.Applied | Should -BeTrue
        # the hand-off block is a typed empty datatable; the table is still read by _dfcRecByKey (Defender's severity per
        # assessment key, a lookup -- not the hand-off list)
        $cut.Query | Should -Match 'let _dfcPairs = datatable\(_dfcKey:string\)\[\];'
        $cut.Query | Should -Not -Match 'mv-expand _dfcKey = _keys' -Because 'nothing of the hand-off list''s body is in the query plan B sends'
        Get-RAHandoffLookupBinding -Query $cut.Query | Should -BeNullOrEmpty

        $null = Invoke-GraphHuntingQuery -Query $q -MaxRetries 1
        @($script:Asked | Where-Object { $_ -match 'mv-expand _dfcKey = _keys' }).Count | Should -Be 0 -Because 'the hand-off list is never fetched'
        @($script:Asked | Where-Object { $_ -match 'mv-expand _t = pack_array\(_t1, _t2, _t3\)' }).Count | Should -BeGreaterThan 0 -Because 'plan B reads its own key list instead (once per run)'
        @($script:Info | Where-Object { $_ -match "pre-fetching CL snapshot for let-binding '_dfcPairs'" }).Count | Should -Be 0
        $script:RADfcSet.Verdict.State | Should -Be 'Absent'
        $script:SentQ | Should -Not -Match 'leftanti \(_dfcPairs\)'
    }
}
