#Requires -Version 5.1
<#
    SI'S OWN STORAGE: A TRANSIENT ANSWER IS WAITED OUT, A LASTING ONE IS NAMED TRUTHFULLY, AN OPTIONAL LABEL FAILS ALONE.

    2026-10-22, one install (endpoint worker, version 220919): one Azure Table read of the app-group cache
    (Get-SIAppGroupRecord, a bare Invoke-RestMethod) hit "Connection timed out (<account>.table.core.windows.net:443)"; the
    whole endpoint run failed after 159 s and was reported as "Microsoft throttled this run".
      * every table call of TypeProfileCache.ps1 goes through the shared retrying REST call (Invoke-SIAzRestRequest): no answer /
        408 / 429 / 5xx are waited out (Retry-After honoured), a bounded number of times -- Microsoft's errors;
      * a run whose failures were only a service that did not answer is told so -- never "throttled";
      * the app group is an optional label: a read that still fails leaves that cluster without its label and is one run
        issue -- the rest of the run is kept.
    OFFLINE: the one HTTP seam (Invoke-SIAzRestHttp), the token and the pauses are Pester mocks (scoped to each It).
    NO EMOJI IN THIS FILE.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $st = Join-Path $script:SIRoot 'engine\asset-profiling\storage'
    . (Join-Path $st 'StorageContext.ps1')
    . (Join-Path $st 'TypeProfileCache.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-Throttle.ps1')
    # the app-group functions of the Enrich stage, taken out of the stage file (its top level is not run)
    $enrichFile = Join-Path $script:SIRoot 'engine\asset-profiling\stages\Invoke-Enrich.ps1'
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($enrichFile, [ref]$null, [ref]$null)
    $want = 'Add-SIAssetGroups', 'Get-SIAssetClusterKeys', 'Reset-SIEnrichIssues', 'Add-SIEnrichIssue', 'Get-SIEnrichIssues'
    foreach ($fn in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
        if ($want -contains $fn.Name) { . ([scriptblock]::Create($fn.Extent.Text)) }
    }
    $script:EnrichSrc = [IO.File]::ReadAllText($enrichFile)
    # the AI call of the app groups lives elsewhere: a script-scope stub, mocked per test
    function script:Invoke-SIAssetGroupAI { param($Engine, $ClusterPayload) $null }
    $script:Ctx = [pscustomobject]@{ Mode = 'OAuth'; AccountName = 'acct'; AzContext = $null; MockState = $null }
    $script:Timeout = 'Connection timed out (acct.table.core.windows.net:443)'
    function script:New-Answer([int]$Code, [string]$Content = '', [string]$RetryAfter = $null) {
        [pscustomobject]@{ StatusCode = $Code; Content = $Content; Bytes = $null; Headers = @{}; RetryAfter = $RetryAfter }
    }
}

Describe 'TypeProfileCache: every table call waits out Microsoft''s transient answers' {
    BeforeEach {
        $script:Calls = 0; $script:Pauses = New-Object System.Collections.Generic.List[int]
        Mock Get-SIAzureToken { 'tok' }
        Mock Start-Sleep { $script:Pauses.Add([int]$Seconds) }
    }
    It 'a read that times out twice, then answers: the record comes back, nothing fails' {
        Mock Invoke-SIAzRestHttp {
            $script:Calls++
            if ($script:Calls -le 2) { return (New-Answer 0 $script:Timeout) }
            New-Answer 200 '{"app_name":"Web farm","app_type":"Web","confidence":0.9}'
        }
        $r = Get-SIAppGroupRecord -Context $script:Ctx -TableName 'sitypeprofiles' -ClusterKey 'endpoint:prefix:web:abc'
        $r.app_name | Should -Be 'Web farm'
        $script:Calls | Should -Be 3
        $script:Pauses.Count | Should -Be 2 -Because 'each timeout is waited out before asking again'
    }
    It 'a 429 with Retry-After is waited for as Microsoft asks; a 503 too; a 404 is "not there" (no retry)' {
        Mock Invoke-SIAzRestHttp {
            $script:Calls++
            switch ($script:Calls) { 1 { New-Answer 429 'busy' '7' } 2 { New-Answer 503 'unavailable' } default { New-Answer 404 'ResourceNotFound' } }
        }
        Get-SISignalMapRecord -Context $script:Ctx -TableName 't' -Engine 'endpoint' -AssetType 'Device' -PromptVersion 'v1' | Should -BeNullOrEmpty
        $script:Calls | Should -Be 3
        $script:Pauses[0] | Should -Be 7
    }
    It 'a write and the table create retry too; a 409 on create is "already there"' {
        Mock Invoke-SIAzRestHttp { $script:Calls++; if ($script:Calls -eq 1) { New-Answer 0 'An existing connection was forcibly closed by the remote host.' } else { New-Answer 409 'TableAlreadyExists' } }
        Initialize-SITypeProfileTable -Context $script:Ctx | Should -Be 'sitypeprofiles'
        $script:Calls | Should -Be 2
        $script:Calls = 0
        Mock Invoke-SIAzRestHttp { $script:Calls++; if ($script:Calls -eq 1) { New-Answer 502 'Bad Gateway' } else { New-Answer 204 '' } }
        { Set-SIAppGroupRecord -Context $script:Ctx -TableName 't' -ClusterKey 'k' -ResourceGroup 'rg' -AppName 'a' -AppType 'Web' } | Should -Not -Throw
        $script:Calls | Should -Be 2
    }
    It 'a timeout that never ends: after a bounded number of attempts (Microsoft''s error) it is a cache MISS with a NAMED warning -- never a hang, never a run failure' {
        Mock Invoke-SIAzRestHttp { $script:Calls++; New-Answer 0 $script:Timeout }
        $w = $null
        $r = Get-SIAppGroupRecord -Context $script:Ctx -TableName 'sitypeprofiles' -ClusterKey 'endpoint:prefix:web:abc' -WarningVariable w -WarningAction SilentlyContinue
        $r | Should -BeNullOrEmpty -Because 'a cache that cannot be read is a miss'
        $script:Calls | Should -Be 6
        ($w -join "`n") | Should -Match "Read the app group 'endpoint:prefix:web:abc' from table 'sitypeprofiles' failed \(.*Connection timed out.*\) -- read as a cache miss this run"
        # a write that never gets through is skipped with a warning; the table create too
        { Set-SIAppGroupRecord -Context $script:Ctx -TableName 't' -ClusterKey 'k' -ResourceGroup 'rg' -AppName 'a' -AppType 'Web' -WarningAction SilentlyContinue } | Should -Not -Throw
        { Initialize-SITypeProfileTable -Context $script:Ctx -WarningAction SilentlyContinue } | Should -Not -Throw
    }
    It 'WIRING: every table call goes through the shared Invoke-SIStorageRequest; no bare call is left' {
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\storage\TypeProfileCache.ps1'))
        $src | Should -Not -Match 'Invoke-RestMethod -Method'
        $src | Should -Not -Match 'Invoke-SIAzRestRequest'
        ([regex]::Matches($src, 'Invoke-SIStorageRequest -Method')).Count | Should -Be 8
        ([regex]::Matches($src, 'catch \{ Write-SITableCacheMiss')).Count | Should -Be 8 -Because 'each call: a miss with a warning, never a throw'
    }
}

Describe 'ONE decision of what a failure really was (Get-SITransientKind)' {
    It 'throttled is ONLY a real throttling answer; a timeout, an unreachable service and an error are each their own' {
        Get-SITransientKind -StatusCode 429 | Should -Be 'throttled'
        Get-SITransientKind -Message 'Response status code does not indicate success: 429 (Too Many Requests).' | Should -Be 'throttled'
        Get-SITransientKind -SqlNumber 40501 | Should -Be 'throttled'
        Get-SITransientKind -StatusCode 0 -Message $script:Timeout | Should -Be 'timeout'
        Get-SITransientKind -StatusCode 504 | Should -Be 'timeout'
        Get-SITransientKind -SqlNumber -2 | Should -Be 'timeout'
        Get-SITransientKind -StatusCode 0 -Message 'An existing connection was forcibly closed by the remote host.' | Should -Be 'unavailable'
        Get-SITransientKind -Message 'No such host is known. (acct.table.core.windows.net:443)' | Should -Be 'unavailable'
        Get-SITransientKind -StatusCode 503 -Message 'Service Unavailable; Retry-After: 10' | Should -Be 'unavailable' -Because 'a Retry-After alone is not throttling'
        Get-SITransientKind -SqlNumber 40613 | Should -Be 'unavailable'
        Get-SITransientKind -StatusCode 400 -Message 'InvalidInput' | Should -Be 'error'
        Get-SITransientKind -Message 'Microsoft throttled this run; it runs again automatically at its next scheduled time.' | Should -Be 'error' -Because 'SI''s own sentence never classifies itself'
    }
    It 'tonight''s case: a storage timeout is a real failure with its own text -- never "Microsoft throttled this run"' {
        $msg = "Read the app group 'k' from table 't' failed. HTTP Status: 0 (NoResponse) Response: $script:Timeout"
        @(Get-SIRunFailureClasses -Message $msg) | Should -Be @('platform-timeout')
        Resolve-SIThrottledExitReason -ExitReason 'error' -ErrorMessage $msg | Should -Be 'error' -Because 'a failure: mailed, reported, the first collection restarted'
        Resolve-SIThrottledExitReason -ExitReason 'error' -ErrorMessage 'GET x failed. HTTP Status: 429 (TooManyRequests)' | Should -Be 'throttled'
        @(Get-SIThrottleClasses) | Should -Be @('throttled')
        Get-SIErrorClass -Message 'Exception calling "Open": A transport-level error has occurred' | Should -Be 'platform-5xx'
    }
    It 'WIRING: the flow keeps the step''s real error text; the classifier uses the one decision' {
        $jf = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\_shared\SI-JobFlow.ps1'))
        $jf | Should -Match ([regex]::Escape("if (`$endWhy -eq 'throttled') { `$st.ErrorClass = 'throttled'; if ([string]::IsNullOrWhiteSpace([string]`$st.Error)) { `$st.Error = Get-SIThrottleText } }"))
        $ec = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\_shared\SI-ErrorClass.ps1'))
        $ec | Should -Match ([regex]::Escape("if ((Get-SITransientKind -Message `$t) -eq 'throttled') { return 'throttled' }"))
        $ec | Should -Match ([regex]::Escape('switch (Get-SITransientKind -Message $t) {'))
    }
}

Describe 'the app groups fail alone: an optional label never throws the run away' {
    BeforeEach {
        Reset-SIEnrichIssues
        $script:AiCalls = 0
        Mock Invoke-SIAssetGroupAI { $script:AiCalls++; $null }
        function script:New-Rec([string]$Name) { @{ AssetId = $Name; Name = $Name; Metadata = @{ MDE_DeviceName = $Name }; Enrichment = @{} } }
    }
    It 'one cluster''s cache read fails for good: that cluster has no label, the others do, one run issue, no throw' {
        Mock Get-SIAppGroupRecord {
            if ($ClusterKey -like '*:prefix:web:*') { throw "Read the app group '$ClusterKey' from table 't' failed. HTTP Status: 0 (NoResponse) Response: Connection timed out" }
            [pscustomobject]@{ app_name = 'Domain controllers'; app_type = 'Directory'; confidence = 0.95 }
        }
        Mock Set-SIAppGroupRecord { }
        $recs = New-Object System.Collections.ArrayList
        foreach ($n in 'web-01', 'web-02', 'dc-01', 'dc-02', 'solo1') { [void]$recs.Add((New-Rec $n)) }
        $rc = [pscustomobject]@{ Engine = 'endpoint'; StorageContext = $script:Ctx }
        $stats = Add-SIAssetGroups -RunContext $rc -Enriched $recs -TypeProfileTable 't'
        $stats.Unread | Should -Be 1
        $stats.CacheHits | Should -Be 1
        foreach ($r in $recs | Where-Object { $_.Name -like 'dc-*' }) { $r.Enrichment['XENG_AppGroup'] | Should -Be 'Domain controllers' }
        foreach ($r in $recs | Where-Object { $_.Name -like 'web-*' }) { $r.Enrichment.ContainsKey('XENG_AppGroup') | Should -BeFalse -Because 'unknown for this run, never a guess' }
        $script:AiCalls | Should -Be 0 -Because 'a cache that could not be read is not taken for a cache miss'
        $iss = @(Get-SIEnrichIssues)
        $iss.Count | Should -Be 1
        $iss[0] | Should -Match 'The app groups of 1 of \d+ cluster\(s\) could not be read from the cache \(.*Connection timed out.*\) -- their app-group labels are unknown for this run'
    }
    It 'a cache write that fails keeps the label the AI gave (asked again next run), no run issue' {
        Mock Get-SIAppGroupRecord { $null }
        Mock Invoke-SIAssetGroupAI { [pscustomobject]@{ AppName = 'Web farm'; AppType = 'Web'; Confidence = 0.8; Reasoning = 'r' } }
        Mock Set-SIAppGroupRecord { throw 'HTTP Status: 0 (NoResponse) Response: Connection timed out' }
        $recs = New-Object System.Collections.ArrayList
        foreach ($n in 'web-01', 'web-02') { [void]$recs.Add((New-Rec $n)) }
        { Add-SIAssetGroups -RunContext ([pscustomobject]@{ Engine = 'endpoint'; StorageContext = $script:Ctx }) -Enriched $recs -TypeProfileTable 't' -WarningAction SilentlyContinue } | Should -Not -Throw
        $recs[0].Enrichment['XENG_AppGroup'] | Should -Be 'Web farm'
        @(Get-SIEnrichIssues).Count | Should -Be 0
    }
    It 'WIRING: the Enrich stage runs the app groups inside a fails-alone guard that records a run issue' {
        $script:EnrichSrc | Should -Match '(?s)try \{\s*\$tpTable = Initialize-SITypeProfileTable -Context \$RunContext\.StorageContext\s*\$appGroupStats = Add-SIAssetGroups .*?\} catch \{\s*Add-SIEnrichIssue \(''The app groups were not worked out'
    }
}

Describe 'the core helpers: a body that cannot be sent, and a token that is not issued, are retried where safe' {
    BeforeAll {
        . (Join-Path $script:SIRoot 'engine\_shared\SI-LogIngest.ps1')
        # a local port nothing listens on: the connection is refused while the body is sent (no network, no tenant)
        $l = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0); $l.Start(); $script:DeadPort = $l.LocalEndpoint.Port; $l.Stop()
    }
    It 'a PUT whose body cannot be sent is "no answer" (StatusCode 0) -- the shared loop retries it; a POST is thrown as before' {
        $u = "http://127.0.0.1:$script:DeadPort/t"
        $r = Invoke-SIAzRestHttp -Method PUT -Uri $u -Body '{"a":1}' -ContentType 'application/json' -TimeoutSec 5
        [int]$r.StatusCode | Should -Be 0
        [string]$r.Content | Should -Not -BeNullOrEmpty
        # a POST whose body could not be SENT is thrown from the send (not repeated blindly). On pwsh 7 the runtime may only
        # connect at the response, where "no answer" was already StatusCode 0 for every method (unchanged) -- so the rule is
        # checked in the source
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\_shared\SI-AzRest.ps1'))
        $src | Should -Match ([regex]::Escape("if (`$req.Method -eq 'POST') { throw }"))
    }
    It 'a token endpoint that times out twice, then answers: the token comes back' {
        $script:TokCalls = 0
        function script:Get-SIManagedIdentityToken { param($Resource, $ClientId, [switch]$ForceRefresh) $script:TokCalls++; if ($script:TokCalls -le 2) { throw 'Connection timed out (169.254.130.1:8081)' }; 'tok-ok' }
        Mock Start-Sleep { }
        Get-SILogIngestToken -Resource 'https://storage.azure.com/' -Auth @{ Mode = 'ManagedIdentity'; ClientId = 'c1' } -ForceRefresh | Should -Be 'tok-ok'
        $script:TokCalls | Should -Be 3
    }
    It 'a refused sign-in is not retried: it fails at once with its own answer' {
        $script:TokCalls = 0
        function script:Get-SIManagedIdentityToken { param($Resource, $ClientId, [switch]$ForceRefresh) $script:TokCalls++; throw 'AADSTS700016: Application with identifier x was not found in the directory. (400 Bad Request)' }
        Mock Start-Sleep { }
        { Get-SILogIngestToken -Resource 'https://storage.azure.com/' -Auth @{ Mode = 'ManagedIdentity'; ClientId = 'c2' } -ForceRefresh } | Should -Throw -ExpectedMessage '*AADSTS700016*'
        $script:TokCalls | Should -Be 1
    }
}