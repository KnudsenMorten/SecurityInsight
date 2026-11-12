#Requires -Version 5.1
<#
    WHEN EVERY DATA PATH OF A QUERY FAILS, THE ONE WARNING NAMES THE PATH THAT REALLY FAILED LAST, AND ITS CLASS COMES FROM
    THAT ANSWER (SUP-2026-00496, REQUIREMENTS #1206).

    Measured 2026-11-11 18:50Z, read-only, at the internal install (3.1.7, ring 0), worker of si-ra-detailed:
      [INFO] submitting query to advanced hunting (attempt 1/1; ...)            <- the completeness count (MaxRetries 1)
      [INFO] Tip (one-time): ...                                                <- advanced hunting answered 413 (too large)
      [WARN] all data paths failed for this query; attempts: lake: lake-query: HTTP 400 | api-body: {"error":{"code":
             "InvalidDatabaseInQuery","message":"Database '...' is not available for current user." ...}}
      [INFO] completeness: the source's count just before the read is not available (413 Request Entity Too Large ...)
    Cause: the consolidated WARN listed only the EARLIER failed paths -- advanced hunting's own failure (the last path) was
    never added -- so a lake that is simply not there for SecurityInsight's identity (a supported state) read as the whole
    failure, and the run's warning got the class 'unknown'. And the query was the completeness COUNT, a measurement whose
    caller already says "not available" as INFO: it should never have warned at all.

    Now: the last path's failure is listed LAST with its real words; a count (a measurement) never warns; the classifier
    reads the last non-lake attempt. The lake is asked only for a query that needs advanced hunting, so the path after a
    lake failure is advanced hunting (the hybrid path); Log Analytics direct gets the same last-attempt rule.
    OFFLINE; PS 5.1 and 7. Script-scope stubs only.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\_shared\SI-ErrorClass.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-LogAnalyticsQuery.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-GraphHunting.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-AutoBucketing.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-RunProgress.ps1')

    function script:Write-Info  { param($m) $script:Log.Add('[INFO] ' + [string]$m) }
    function script:Write-Diag  { param($m) $script:Log.Add('[DIAG] ' + [string]$m) }
    function script:Write-Ok    { param($m) $script:Log.Add('[OK] ' + [string]$m) }
    function script:Write-Err2  { param($m) $script:Log.Add('[ERR] ' + [string]$m) }
    function script:Write-Warn2 { param($m) $script:Log.Add('[WARN] ' + [string]$m) }
    function script:Add-DynamicGroupKeyCasts { param($Query) $Query }
    function script:Save-RARenderedQuery { param($Query, $Tag) }
    function script:Ensure-GraphAuth { param($MaxAgeMinutes) }
    function script:Start-Sleep { param($Seconds, $Milliseconds) }
    function script:Get-DefenderTableOwner { param($TableName) 'owner' }
    function script:Resolve-ProfileAugmentPlan { param($Query) @{ Plans = @(); Query = $Query } }
    # the lookups are read and put into the query by the real Invoke-RAResolveLookups -- its two readers answer the query as it is
    function script:Resolve-ProfileCLLetBlocks { param($Query, $WorkspaceResourceId, $BucketCount, $BucketIndex) $Query }
    function script:Add-CLSnapshotShadows { param($Query, $WorkspaceResourceId) $Query }

    # the measured lake answer (the install's workspace id replaced)
    $script:LakeRefusal = 'lake-query: HTTP 400 | api-body: {"error":{"code":"InvalidDatabaseInQuery","message":"Database ''log-ws-00000000-0000-0000-0000-000000000000'' is not available for current user.","target":null,"details":[]}} | db: log-ws-00000000-0000-0000-0000-000000000000'
    $script:Ah413 = '413 Request Entity Too Large -- {"error":{"code":"UnknownError","message":"<html><head><title>413 Request Entity Too Large</title></head><body><center><h1>413 Request Entity Too Large</h1></center><hr><center>nginx</center></body></html>"}}'
    $script:Ah504 = '504 Gateway Timeout -- {"error":{"code":"GatewayTimeout","message":"The gateway did not receive a response in time."}}'
    $script:Ah400 = '400 Bad Request -- {"error":{"code":"BadRequest","message":"''extend'' operator: Failed to resolve scalar expression named ''NoSuchColumn''. Fix semantic errors in your query."}}'

    # a query that reads an SI table AND the exposure graph: the lake is asked first, then the hybrid path to advanced hunting
    $script:EgQuery = "ExposureGraphNodes | join kind=inner (SI_CI_CL | project NodeId) on NodeId | take 10"

    function script:Invoke-SISentinelLakeQuery { param($Query, $WorkspaceResourceId) [pscustomobject]@{ _SILakeError = $script:LakeAnswer } }
    function script:Invoke-SIHuntingQueryRest {
        param($Query, $Token, $TimeoutSec)
        $script:AhCalls++
        if ($script:AhAnswer) { throw $script:AhAnswer }
        [pscustomobject]@{ Results = @() }
    }
    function script:Reset-Case {
        $script:Log = New-Object System.Collections.Generic.List[string]
        $script:_SentinelLakeUnavailable = $false
        $script:_RAHuntingNotProvisioned = $false
        $script:_RAHuntingMeasurement = $false
        $script:SIHuntingPrefetch = $null
        $script:LakeAnswer = $script:LakeRefusal
        $script:AhAnswer = $null
        $script:AhCalls = 0
        $global:SI_WorkspaceResourceId = '/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/ws'
    }
    function script:Warns { @($script:Log | Where-Object { $_ -like '[[]WARN]*' }) }
}

AfterAll { $global:SI_WorkspaceResourceId = $null }

Describe 'through the hunting call: the lake is not there for this identity (a supported state)' {
    BeforeEach { Reset-Case }
    It 'lake 400 InvalidDatabaseInQuery, then advanced hunting answers: no WARN, one INFO, the rows come back' {
        $r = Invoke-GraphHuntingQuery -Query $script:EgQuery -MaxRetries 1
        $r | Should -Not -BeNullOrEmpty
        @(Warns).Count | Should -Be 0
        $info = @($script:Log | Where-Object { $_ -match 'superseded fallback attempt' })
        $info.Count | Should -Be 1
        $info[0] | Should -Match 'advanced-hunting'
        $script:_SentinelLakeUnavailable | Should -BeTrue -Because 'the lake is not asked again in this run'
    }
    It 'the next query does not ask the lake again and says nothing about it' {
        [void](Invoke-GraphHuntingQuery -Query $script:EgQuery -MaxRetries 1)
        $script:Log.Clear()
        [void](Invoke-GraphHuntingQuery -Query $script:EgQuery -MaxRetries 1)
        @($script:Log | Where-Object { $_ -match 'superseded|all data paths' }).Count | Should -Be 0
    }
}

Describe 'through the hunting call: every path failed -- the WARN names the last real failure' {
    BeforeEach { Reset-Case }
    It 'lake refused + advanced hunting 504: ONE WARN listing both attempts, advanced hunting last with its words; class platform-timeout' {
        $script:AhAnswer = $script:Ah504
        { Invoke-GraphHuntingQuery -Query $script:EgQuery -MaxRetries 1 } | Should -Throw '*504*'
        $w = @(Warns | Where-Object { $_ -match 'all data paths failed' })
        $w.Count | Should -Be 1
        $w[0] | Should -Match 'attempts: lake: lake-query: HTTP 400'
        $w[0] | Should -Match ' \|\| advanced-hunting: 504 Gateway Timeout'
        $w[0].IndexOf('lake:') | Should -BeLessThan $w[0].IndexOf('advanced-hunting:')
        Get-SIErrorClass -Message $w[0] | Should -Be 'platform-timeout'
    }
    It 'lake refused + advanced hunting 400 semantic: the WARN names the semantic error; class kql-query-defect' {
        $script:AhAnswer = $script:Ah400
        { Invoke-GraphHuntingQuery -Query $script:EgQuery -MaxRetries 4 } | Should -Throw '*semantic*'
        $script:AhCalls | Should -Be 1 -Because 'a query defect fails on attempt 1 (working rule 4)'
        $w = @(Warns | Where-Object { $_ -match 'all data paths failed' })
        $w.Count | Should -Be 1
        $w[0] | Should -Match 'advanced-hunting: 400 Bad Request'
        Get-SIErrorClass -Message $w[0] | Should -Be 'kql-query-defect'
    }
    It 'lake refused + advanced hunting 413 on a report query: the WARN names the 413; class platform-5xx (never unknown)' {
        $script:AhAnswer = $script:Ah413
        { Invoke-GraphHuntingQuery -Query $script:EgQuery -MaxRetries 1 } | Should -Throw '*413*'
        $w = @(Warns | Where-Object { $_ -match 'all data paths failed' })
        $w.Count | Should -Be 1
        $w[0] | Should -Match 'advanced-hunting: 413 Request Entity Too Large'
        Get-SIErrorClass -Message $w[0] | Should -Be 'platform-5xx'
    }
    It 'no earlier path failed (the lake already known unavailable): no consolidated WARN -- advanced hunting says its own error as before' {
        $script:_SentinelLakeUnavailable = $true
        $script:AhAnswer = $script:Ah504
        { Invoke-GraphHuntingQuery -Query $script:EgQuery -MaxRetries 1 } | Should -Throw '*504*'
        @($script:Log | Where-Object { $_ -match 'all data paths failed' }).Count | Should -Be 0
        @($script:Log | Where-Object { $_ -match '^\[ERR\] Query failed after 1 attempts' }).Count | Should -Be 1
    }
}

Describe 'the completeness count is a measurement: it never raises a run warning (the measured case)' {
    BeforeEach { Reset-Case }
    It 'lake refused + advanced hunting 413 for the count: no WARN; the attempts are in the verbose log, both of them' {
        $script:AhAnswer = $script:Ah413
        $script:_RAHuntingMeasurement = $true
        try { { Invoke-GraphHuntingQuery -Query $script:EgQuery -MaxRetries 1 } | Should -Throw '*413*' } finally { $script:_RAHuntingMeasurement = $false }
        @(Warns).Count | Should -Be 0
        $d = @($script:Log | Where-Object { $_ -match '^\[DIAG\] every data path failed for this count' })
        $d.Count | Should -Be 1
        $d[0] | Should -Match 'lake: '
        $d[0] | Should -Match 'advanced-hunting: 413'
    }
    It 'the engine sets the measurement flag around the count query only, and clears it in a finally' {
        $ra = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'))
        $ra | Should -Match ([regex]::Escape('$script:_RAHuntingMeasurement = $true') + '\s+try \{ Get-RABucketRows -Resp \(Invoke-GraphHuntingQuery -Query \(Get-RAReportCountKql ')
        $ra | Should -Match ([regex]::Escape('finally { $script:_RAHuntingMeasurement = $false }'))
        @([regex]::Matches($ra, [regex]::Escape('$script:_RAHuntingMeasurement = $true'))).Count | Should -Be 1
    }
}

Describe 'the ledger (Flush-SupersededAttempts)' {
    BeforeEach { Reset-Case; Reset-SupersededAttempts }
    It 'the last path is listed last, first line of its words only; the buffer is cleared' {
        Add-SupersededAttempt -Path 'lake' -Message 'lake-query: HTTP 403 | Forbidden'
        Flush-SupersededAttempts -LastPath 'LA-direct' -LastMessage ("504 Gateway Timeout`nsecond line")
        $w = @(Warns)
        $w.Count | Should -Be 1
        $w[0] | Should -Match 'attempts: lake: lake-query: HTTP 403 \| Forbidden \|\| LA-direct: 504 Gateway Timeout$'
        $script:_SupersededAttempts.Count | Should -Be 0
        Get-SIErrorClass -Message $w[0] | Should -Be 'platform-timeout'
    }
    It 'nothing failed earlier: nothing is said (the last path says its own error)' {
        Flush-SupersededAttempts -LastPath 'advanced-hunting' -LastMessage $script:Ah504
        $script:Log.Count | Should -Be 0
    }
    It 'called without a last path it is the old consolidated WARN' {
        Add-SupersededAttempt -Path 'lake' -Message 'x'
        Flush-SupersededAttempts
        @(Warns).Count | Should -Be 1
    }
}

Describe 'Get-SIErrorClass: every known shape of the warning has a class, never unknown' {
    It 'the exact line measured at the internal install (3.1.7: the last path was not listed) -- platform-5xx, not unknown' {
        $line = '18:50:00  [WARN] all data paths failed for this query; attempts: ' + 'lake: ' + $script:LakeRefusal
        Get-SIErrorClass -Message $line | Should -Be 'platform-5xx'
        Get-SIErrorClass -Message (Get-SIErrorLines -Lines @('18:49:59  [INFO] bucket 1/8: running query', $line)) | Should -Be 'platform-5xx'
    }
    It 'the lake is dropped and the LAST other attempt decides (<Why>)' -TestCases @(
        @{ Why = 'advanced hunting 504'; Last = 'advanced-hunting: 504 Gateway Timeout'; Class = 'platform-timeout' }
        @{ Why = 'advanced hunting cancelled at 900 s'; Last = 'advanced-hunting: TaskCanceledException: The request was canceled due to the configured HttpClient.Timeout of 900 seconds elapsing.'; Class = 'platform-timeout' }
        @{ Why = 'advanced hunting 429'; Last = 'advanced-hunting: 429 Too Many Requests'; Class = 'throttled' }
        @{ Why = 'advanced hunting 502 too large'; Last = 'advanced-hunting: 502 Bad Gateway'; Class = 'platform-5xx' }
        @{ Why = 'advanced hunting 413 too large'; Last = 'advanced-hunting: 413 Request Entity Too Large -- nginx'; Class = 'platform-5xx' }
        @{ Why = 'advanced hunting 400 semantic'; Last = 'advanced-hunting: 400 Bad Request -- Failed to resolve scalar expression named ''X''. Fix semantic errors in your query.'; Class = 'kql-query-defect' }
        @{ Why = 'advanced hunting 400 syntax'; Last = 'advanced-hunting: 400 Bad Request -- Syntax error. Fix syntax errors in your query.'; Class = 'kql-query-defect' }
        @{ Why = 'advanced hunting 403'; Last = 'advanced-hunting: 403 Forbidden -- Missing role ThreatHunting.Read.All'; Class = 'defender-403' }
        @{ Why = 'Log Analytics 403'; Last = 'LA-direct: Response status code does not indicate success: 403 (Forbidden).'; Class = 'arm-403' }
        @{ Why = 'Log Analytics 504'; Last = 'LA-direct: 504 Gateway Timeout'; Class = 'platform-timeout' }
        @{ Why = 'Log Analytics 400 semantic'; Last = 'LA-direct: BadRequest SEM0100: Failed to resolve scalar expression named ''X'''; Class = 'kql-query-defect' }
    ) {
        param($Why, $Last, $Class)
        $t = 'all data paths failed for this query; attempts: lake: ' + $script:LakeRefusal + ' || ' + $Last
        Get-SIErrorClass -Message $t | Should -Be $Class
    }
    It 'a lake answer that is not a refusal and stands alone keeps its own class (a lake timeout is a platform timeout)' {
        Get-SIErrorClass -Message 'all data paths failed for this query; attempts: lake: lake-query: HTTP 504 Gateway Timeout' | Should -Be 'platform-timeout'
    }
    It 'every lake refusal shape alone is never unknown' -TestCases @(
        @{ W = 'lake-query: HTTP 403 | Forbidden' }
        @{ W = 'lake-query: HTTP 401 | Unauthorized' }
        @{ W = 'lake-query: HTTP 404 | TenantNotFound' }
        @{ W = $null }
    ) {
        param($W)
        if (-not $W) { $W = $script:LakeRefusal }
        Get-SIErrorClass -Message ('all data paths failed for this query; attempts: lake: ' + $W) | Should -Not -Be 'unknown'
    }
    It 'a bare 413 from advanced hunting is platform-5xx; an ingestion 413 is not moved into it' {
        Get-SIErrorClass -Message $script:Ah413 | Should -Be 'platform-5xx'
        Get-SIErrorClass -Message 'Logs Ingestion API (dataCollectionRules) answered 413 Request Entity Too Large' | Should -Not -Be 'platform-5xx'
    }
    It 'a text that is not this warning is not read as one' {
        Get-SIDataPathAttemptClass -Text 'Query failed after 4 attempts: 504 Gateway Timeout' | Should -Be ''
        Get-SIDataPathAttemptClass -Text '' | Should -Be ''
    }
    It 'every class it gives is on the closed list' {
        foreach ($t in @(
            ('all data paths failed for this query; attempts: lake: ' + $script:LakeRefusal),
            ('all data paths failed for this query; attempts: lake: x || advanced-hunting: ' + $script:Ah504))) {
            @(Get-SIErrorClasses) | Should -Contain (Get-SIErrorClass -Message $t)
        }
    }
}
