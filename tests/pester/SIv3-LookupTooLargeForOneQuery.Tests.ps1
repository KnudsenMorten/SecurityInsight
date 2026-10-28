#Requires -Version 5.1
<#
    A LOOKUP THAT IS NEEDED WHOLE IN EVERY SLICE AND IS LARGER THAN ONE REQUEST: THE REPORT FAILS IN ONE
    DECISION, SAYS SO, AND THE RUN GOES ON.

    Measured 2026-10-13 at a customer, report Azure_Recommendations_Summary: the lookup `_dfcPairs` (43,124 rows
    = 1,137,605 bytes) has no key the slices are cut on, so it was copied whole into every slice of the query --
    more than the about 1 MB one advanced-hunting request can carry. No slice count can change that. The engine
    escalated 2 -> 1,024 slices and then tried each of the 1,024 three times (about 34 hours of requests that
    could not be accepted); the job was stopped by its run limit, every later report never ran, and the
    customer had no findings.

    Now the part of the request that more slices can NOT shrink (the query text and every lookup copied whole)
    is measured before a request goes out:
      CERTAIN  -- that part alone is at or over what one request can carry: decided before anything is sent
      MEASURED -- a request was refused for its size and what more slices could still remove is a sliver of it
    Either way the report is failed as a whole (findings UNKNOWN, never "none") and the next report runs.

    The engine is one large script that cannot be dot-sourced, so its half is asserted on the source -- the
    same technique SIv3-BucketRecovery and SIv3-CrossDomainReplicate use. Everything else runs the real code.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-ProfileAugment.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-GraphHunting.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-AutoBucketing.ps1')

    # The engine's own helpers the hunting layer calls on the way to a request. None of them decides anything here.
    function script:Write-Info  { param($m) $script:Info   += , [string]$m }
    function script:Write-Diag  { param($m) }
    function script:Write-Ok    { param($m) }
    function script:Write-Err2  { param($m) }
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

    # The shape of Azure_Recommendations_*: a CI lookup keyed on the id the slices are cut on (`_ciKey`), and the
    # hand-off lookup, which is one column of hashes -- no key, so it is copied whole into every slice.
    $script:Q = @'
let _ciLink = SI_CI_CL
    | project _ciKey = tolower(tostring(si_link_azure)), si_tier = toint(si_tier)
    | where isnotempty(_ciKey);
let _dfcPairs = union isfuzzy=true
    (datatable(_dfcKey:string)[]),
    (SI_AzureRecommendation_CL | project _dfcKey = strcat("h", tostring(hash(ResourceName))))
    | project _dfcKey;
ExposureGraphNodes
| extend DeviceKey = tolower(NodeId)
//__BUCKET_FILTER_BEGIN__
| where 1 == 1
//__BUCKET_FILTER_END__
| join kind=leftouter (_ciLink) on $left.DeviceKey == $right._ciKey
| join kind=leftanti (_dfcPairs) on _dfcKey
'@

    function script:New-CiRows   { param([int]$Count) @(1..$Count | ForEach-Object { [pscustomobject]@{ _ciKey = ('/subscriptions/s/resourcegroups/rg/providers/microsoft.compute/virtualmachines/vm{0}' -f $_); si_tier = 1 } }) }
    function script:New-PairRows { param([int]$Count) @(1..$Count | ForEach-Object { [pscustomobject]@{ _dfcKey = ('h-{0:d18}' -f (7000000000 + $_)) } }) }

    function script:Reset-State {
        $script:_HybridRowsCache = @{}; $script:_HybridSnapshotCache = @{}; $script:_HybridBucketGroupsCache = @{}; $script:_HybridBucketGroupsWhole = @{}
        $script:_HybridColumnTypesCache = @{}; $script:_CLSnapshotsKql = @{}
        $script:_CrossDomainBucketCoalesce = @(); $script:_SkipEGBucketForCrossDomain = $false; $script:_RACrossDomainReplicated = $false
        $script:_LastHybridQueryBodyOverheadBytes = 0; $script:_LastHybridBytesPerRow = 0; $script:_LastHybridSnapshotRowCount = 0
        $script:_RAHybridLookups = $null; $script:_RAHybridLastRequest = $null
        $script:_SentinelLakeUnavailable = $true; $script:_RAHuntingNotProvisioned = $false; $script:_LakeTipShown = $true
        $script:_CurrentBucketCount = 0; $script:_CurrentBucketIndex = 0
        $script:AutoBucketMemo = @{}
        $script:Warned = @(); $script:Info = @(); $script:Sent = New-Object System.Collections.Generic.List[string]; $script:Probes = 0
        $global:SI_WorkspaceResourceId = $script:Ws
        $global:AutoBucketCache = $false
        $global:SI_RA_DumpAugmentInput = $false
        $global:SI_HuntingRequestCapBytes = $null
    }

    # The engine's AutoBucket probe (Invoke-RiskAnalysis.ps1, `$probe = {`), with the same two steps around the
    # request: publish the slice coordinates, and turn a size refusal that more slices cannot cure into the one
    # error that ends the ramp. The WIRING block below pins that the engine's probe has this shape.
    $script:Probe = {
        param([int]$BucketCount)
        $script:Probes++
        $script:_CurrentBucketCount = $BucketCount
        $script:_CurrentBucketIndex = 0
        try {
            try {
                $null = Invoke-GraphHuntingQuery -Query $script:Q -MaxRetries 1
            } catch {
                $__refused = Get-RARefusedRequestVerdict -Err $_
                if ($__refused) { throw (New-RALookupTooLargeError -Message $__refused) }
                throw
            }
        } finally {
            $script:_CurrentBucketCount = 0
            $script:_CurrentBucketIndex = 0
        }
    }
}

AfterAll {
    $global:SI_HuntingRequestCapBytes = $null
}

Describe 'the size helpers are exact and never over-estimate' {
    It 'a request counts UTF-8 bytes plus one byte per character JSON escapes' {
        Get-RARequestWireBytes -Text 'abc'          | Should -Be 3
        Get-RARequestWireBytes -Text '"h-1",'       | Should -Be 8      # 6 characters + 2 escaped quotes
        Get-RARequestWireBytes -Text "a`r`nb"       | Should -Be 6      # 4 characters + CR + LF escaped
        Get-RARequestWireBytes -Text ''             | Should -Be 0
        Get-RARequestWireBytes -Text $null          | Should -Be 0
    }
    It 'sizes read the same on every machine, whatever its regional settings' {
        Format-RAByteSize -Bytes 1137605 | Should -Be '1.1 MB'
        Format-RAByteSize -Bytes 81571   | Should -Be '80 KB'
        Format-RAByteSize -Bytes 512     | Should -Be '512 bytes'
    }
    It 'what one request can carry is 1 MB unless a test lowers it' {
        $global:SI_HuntingRequestCapBytes = $null
        Get-RAHuntingRequestCapBytes | Should -Be 1048576
        $global:SI_HuntingRequestCapBytes = 30000
        Get-RAHuntingRequestCapBytes | Should -Be 30000
        $global:SI_HuntingRequestCapBytes = $null
    }
    It 'names every lookup that is copied whole, largest first, with rows and size' {
        $t = Get-RAWholeLookupText -Lookups @(
            @{ Name = '_dfcRecByKey'; Rows = 1244;  WireBytes = 81571;   Whole = $true }
            @{ Name = '_ciLink';      Rows = 10;    WireBytes = 4298;    Whole = $false }
            @{ Name = '_dfcPairs';    Rows = 43124; WireBytes = 1137605; Whole = $true })
        $t | Should -Be 'the lookups _dfcPairs (43,124 rows, 1.1 MB) and _dfcRecByKey (1,244 rows, 80 KB) are needed whole in every part of the query'
        (Get-RAWholeLookupText -Lookups @(@{ Name = '_dfcPairs'; Rows = 43124; WireBytes = 1137605; Whole = $true })) |
            Should -Be 'the lookup _dfcPairs (43,124 rows, 1.1 MB) is needed whole in every part of the query'
    }
}

Describe 'CERTAIN -- a lookup copied whole that is larger than one request fails the report before anything is sent' {
    BeforeEach {
        Reset-State
        $script:Ci = New-CiRows -Count 40
        $script:Pairs = New-PairRows -Count 2000          # about 54 KB, whole in every slice
        $global:SI_HuntingRequestCapBytes = 30000         # one request carries 30 KB in this test
        Mock Invoke-LogAnalyticsKqlQuery { if ($Query -match 'SI_AzureRecommendation_CL') { $script:Pairs } else { $script:Ci } }
        Mock Resolve-ProfileAugmentPlan { @{ Query = $Query; Plans = @() } }
        Mock Invoke-SIHuntingQueryRest { [void]$script:Sent.Add([string]$Query); [pscustomobject]@{ Results = @() } }
    }

    It 'the lookup without a key is recorded as copied whole, the keyed one as split (control)' {
        $script:_CurrentBucketCount = 2
        $null = Resolve-ProfileCLLetBlocks -Query $script:Q -WorkspaceResourceId $script:Ws -BucketCount 2 -BucketIndex 0
        $l = @($script:_RAHybridLookups)
        $l.Count | Should -Be 2
        @($l | Where-Object { $_.Name -eq '_dfcPairs' })[0].Whole | Should -BeTrue
        @($l | Where-Object { $_.Name -eq '_dfcPairs' })[0].Rows  | Should -Be 2000
        @($l | Where-Object { $_.Name -eq '_ciLink' })[0].Whole   | Should -BeFalse
    }

    It 'the hunting layer throws the one recognised error and sends NOTHING' {
        $script:_CurrentBucketCount = 2; $script:_CurrentBucketIndex = 0
        $err = $null
        try { $null = Invoke-GraphHuntingQuery -Query $script:Q -MaxRetries 1 } catch { $err = $_ }
        $err | Should -Not -BeNullOrEmpty
        Test-RALookupTooLargeError -Err $err | Should -BeTrue
        $script:Sent.Count | Should -Be 0 -Because 'a request that cannot be accepted must not be sent'
    }

    It 'the message names the lookup, its rows and its size in plain words' {
        $script:_CurrentBucketCount = 2
        $msg = $null
        try { $null = Invoke-GraphHuntingQuery -Query $script:Q -MaxRetries 1 } catch { $msg = [string]$_.Exception.Message }
        $msg | Should -Match 'the lookup _dfcPairs \(2,000 rows, \d+ KB\) is needed whole in every part of the query'
        $msg | Should -Match 'more than a query to Microsoft Defender can carry \(29 KB\)'
        $msg | Should -Match 'splitting the query into more parts cannot make it fit'
        $msg | Should -Not -Match '#\d|\[hybrid\]|AutoBucket|nginx|413|bucket' -Because 'this text reaches the customer''s log'
    }

    It 'the escalation ramp stops after ONE probe: no second slice count is tried' {
        $err = $null
        try { $null = Get-OptimalBucketCount -QueryKey 'Azure_Recommendations_Summary|1' -MaxBucketCount 1024 -MinBucketCount 2 -ProbeScript $script:Probe } catch { $err = $_ }
        Test-RALookupTooLargeError -Err $err | Should -BeTrue -Because 'the error must leave the ramp as it is, so the caller can fail the report'
        $script:Probes     | Should -Be 1
        $script:Sent.Count | Should -Be 0
        $script:AutoBucketMemo.Count | Should -Be 0 -Because 'a slice count that never worked must not be remembered'
    }

    It 'it is the same decision at 1,024 slices -- more slices do not shrink a lookup that is copied whole' {
        $script:_CurrentBucketCount = 1024; $script:_CurrentBucketIndex = 19
        $err = $null
        try { $null = Invoke-GraphHuntingQuery -Query $script:Q -MaxRetries 1 } catch { $err = $_ }
        Test-RALookupTooLargeError -Err $err | Should -BeTrue
        @($script:_RAHybridLookups | Where-Object { $_.Name -eq '_dfcPairs' })[0].Rows | Should -Be 2000
        $script:Sent.Count | Should -Be 0
    }

    It 'the bucket classifier never splits or retries it -- even when a size in the text reads like a status code' {
        $e = New-RALookupTooLargeError -Message 'the lookup _x (9 rows, 429 KB) is needed whole in every part of the query -- with the query text that is 503 KB in every part, more than a query to Microsoft Defender can carry (1.0 MB), so splitting the query into more parts cannot make it fit'
        Get-RABucketFailureAction -Err $e | Should -Be 'Fail'
        Test-IsBucketOverflowError -Err ([string]$e.Message) | Should -BeFalse
    }

    It 'an UNSLICED query is not judged here -- it is sent and answered as before' {
        $script:_CurrentBucketCount = 0
        { $null = Invoke-GraphHuntingQuery -Query $script:Q -MaxRetries 1 } | Should -Not -Throw
        $script:Sent.Count | Should -Be 1
    }
}

Describe 'UNDER what one request can carry -- nothing changes' {
    BeforeEach {
        Reset-State
        $script:Ci = New-CiRows -Count 40
        $script:Pairs = New-PairRows -Count 200
        Mock Invoke-LogAnalyticsKqlQuery { if ($Query -match 'SI_AzureRecommendation_CL') { $script:Pairs } else { $script:Ci } }
        Mock Resolve-ProfileAugmentPlan { @{ Query = $Query; Plans = @() } }
        Mock Invoke-SIHuntingQueryRest { [void]$script:Sent.Add([string]$Query); [pscustomobject]@{ Results = @() } }
    }

    It 'every slice is sent, and the request is exactly what the inlining built' {
        foreach ($b in 0..3) {
            $script:_CurrentBucketCount = 4; $script:_CurrentBucketIndex = $b
            { $null = Invoke-GraphHuntingQuery -Query $script:Q -MaxRetries 1 } | Should -Not -Throw
        }
        $script:Sent.Count | Should -Be 4
        foreach ($b in 0..3) {
            $expected = Resolve-ProfileCLLetBlocks -Query $script:Q -WorkspaceResourceId $script:Ws -BucketCount 4 -BucketIndex $b
            $script:Sent[$b] | Should -BeExactly $expected
        }
    }

    It 'the keyed lookup is still split one row to one slice, the keyless one still whole in every slice' {
        $seenCi = 0
        foreach ($b in 0..3) {
            $r = Resolve-ProfileCLLetBlocks -Query $script:Q -WorkspaceResourceId $script:Ws -BucketCount 4 -BucketIndex $b
            $seenCi += @($script:Ci | Where-Object { $r -match ('"' + [regex]::Escape($_._ciKey) + '"') }).Count
            @($script:Pairs | Where-Object { $r -match ('"' + [regex]::Escape($_._dfcKey) + '"') }).Count | Should -Be 200
        }
        $seenCi | Should -Be 40
    }

    It 'the ramp finds its slice count as before and remembers it' {
        $n = Get-OptimalBucketCount -QueryKey 'Azure_Recommendations_Summary|2' -MaxBucketCount 1024 -MinBucketCount 2 -ProbeScript $script:Probe
        $n | Should -Be 2
        $script:AutoBucketMemo['Azure_Recommendations_Summary|2'] | Should -Be 2
        $script:Sent.Count | Should -Be 1
    }
}

Describe 'MEASURED -- a request refused for its size, where more slices can only remove a sliver' {
    BeforeEach {
        Reset-State
        Mock Resolve-ProfileAugmentPlan { @{ Query = $Query; Plans = @() } }
        # The service refuses every request for its size, whatever the slice count.
        Mock Invoke-SIHuntingQueryRest { [void]$script:Sent.Add([string]$Query); throw '413 Request Entity Too Large -- <html>nginx</html>' }
    }

    It 'the verdict is pure: a sliver left to shrink = cannot fit; a real share left = keep going' {
        $whole = @(@{ Name = '_dfcPairs'; Rows = 43124; WireBytes = 1100000; Whole = $true })
        $script:_RAHybridLastRequest = @{ BodyBytes = 1110000; FixedBytes = 1105000; BucketCount = 1024; Lookups = $whole }
        $v = Get-RARefusedRequestVerdict -Err '413 Request Entity Too Large'
        $v | Should -Match 'the lookup _dfcPairs \(43,124 rows, 1\.0 MB\) is needed whole in every part of the query'
        $v | Should -Match 'more than a query to Microsoft Defender can carry'
        $script:_RAHybridLastRequest = @{ BodyBytes = 2000000; FixedBytes = 1000000; BucketCount = 2; Lookups = $whole }
        Get-RARefusedRequestVerdict -Err '413 Request Entity Too Large' | Should -BeNullOrEmpty -Because 'half of this request still shrinks with more slices'
    }

    It 'only the request-size refusal is judged -- a result that is too large, a timeout or a throttle is not' {
        $script:_RAHybridLastRequest = @{ BodyBytes = 1010000; FixedBytes = 1005000; BucketCount = 8; Lookups = @() }
        Get-RARefusedRequestVerdict -Err 'Query execution has exceeded the allowed limits ... preempted' | Should -BeNullOrEmpty
        Get-RARefusedRequestVerdict -Err 'TaskCanceledException: the request was canceled'               | Should -BeNullOrEmpty
        Get-RARefusedRequestVerdict -Err '429 Too Many Requests'                                         | Should -BeNullOrEmpty
        Get-RARefusedRequestVerdict -Err $null                                                           | Should -BeNullOrEmpty
    }

    It 'without a measured request, or for an unsliced one, there is no verdict' {
        $script:_RAHybridLastRequest = $null
        Get-RARefusedRequestVerdict -Err '413 Request Entity Too Large' | Should -BeNullOrEmpty
        $script:_RAHybridLastRequest = @{ BodyBytes = 1010000; FixedBytes = 1005000; BucketCount = 0; Lookups = @() }
        Get-RARefusedRequestVerdict -Err '413 Request Entity Too Large' | Should -BeNullOrEmpty
    }

    It 'the measured shape belongs to ONE request: the next call starts without it' {
        $script:_RAHybridLastRequest = @{ BodyBytes = 1010000; FixedBytes = 1005000; BucketCount = 8; Lookups = @() }
        Mock Invoke-SIHuntingQueryRest { [pscustomobject]@{ Results = @() } }
        $null = Invoke-GraphHuntingQuery -Query 'ExposureGraphNodes | take 1' -MaxRetries 1
        $script:_RAHybridLastRequest | Should -BeNullOrEmpty
    }

    It 'the lookup copied whole is nearly all of the refused request: the ramp stops on the FIRST refusal' {
        $script:Ci = New-CiRows -Count 6                  # a few hundred bytes that more slices could remove
        $script:Pairs = New-PairRows -Count 4000          # about 108 KB that they cannot
        Mock Invoke-LogAnalyticsKqlQuery { if ($Query -match 'SI_AzureRecommendation_CL') { $script:Pairs } else { $script:Ci } }
        $err = $null
        try { $null = Get-OptimalBucketCount -QueryKey 'Azure_Recommendations_Summary|3' -MaxBucketCount 1024 -MinBucketCount 2 -ProbeScript $script:Probe } catch { $err = $_ }
        Test-RALookupTooLargeError -Err $err | Should -BeTrue
        $script:Probes     | Should -Be 1
        $script:Sent.Count | Should -Be 1 -Because 'one refusal is the measurement; the same request is not built again'
        [string]$err.Exception.Message | Should -Match 'the lookup _dfcPairs \(4,000 rows, \d+ KB\) is needed whole in every part of the query'
        [string]$err.Exception.Message | Should -Match 'Microsoft Defender refused the query at \d+ KB as too large'
    }

    It 'while more slices still shrink the request by a real share, the ramp keeps escalating as before' {
        $script:Ci = New-CiRows -Count 3000               # the split lookup is most of the request at 2 slices
        $script:Pairs = New-PairRows -Count 3000          # whole in every slice; a sliver is left once a slice holds about 20 of the split rows
        Mock Invoke-LogAnalyticsKqlQuery { if ($Query -match 'SI_AzureRecommendation_CL') { $script:Pairs } else { $script:Ci } }
        $err = $null
        try { $null = Get-OptimalBucketCount -QueryKey 'Azure_Recommendations_Summary|4' -MaxBucketCount 1024 -MinBucketCount 2 -ProbeScript $script:Probe } catch { $err = $_ }
        $script:Probes | Should -BeGreaterThan 3 -Because 'a request that more slices can still shrink must not be given up on its first refusal'
        Test-RALookupTooLargeError -Err $err | Should -BeTrue -Because 'once only a sliver is left to shrink, the same refusal ends it'
    }
}

Describe 'WIRING -- the engine fails the report once, says it, and goes on with the next report' {
    BeforeAll {
        $script:Eng  = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'))
        $script:Hunt = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-GraphHunting.ps1'))
        $i0 = $script:Eng.IndexOf('$reportCannotFit = $null')
        $i1 = $script:Eng.IndexOf('$script:AutoBucketMemo[$queryKey] = [int]$__abRemember', $i0)
        $script:Span = $script:Eng.Substring($i0, $i1 - $i0)
    }

    It 'the hunting layer checks the size after ALL inlining and outside the fallback try blocks, before the request' {
        $call    = 'Assert-RAHybridQueryFits -Query $Query -BucketCount $_bk'
        $iCall   = $script:Hunt.IndexOf($call)
        # #674: the inlining is one fail-closed step now (Invoke-RAResolveLookups) -- no fallback try blocks around it
        $iShadow = $script:Hunt.LastIndexOf('$Query = Invoke-RAResolveLookups -Query $Query -WorkspaceResourceId $wsForCL', $iCall)
        $iCall   | Should -BeGreaterThan 0
        $iShadow | Should -BeGreaterThan 0 -Because 'the check must come after the last inlining step'
        ([regex]::Matches($script:Hunt, [regex]::Escape($call))).Count | Should -Be 1
        $between = $script:Hunt.Substring($iShadow, $iCall - $iShadow)
        $between | Should -Not -Match '(?m)^\s*try \{' -Because 'inside a try block the error would be turned into a fallback and never reach the bucket loop'
        $iCall | Should -BeLessThan $script:Hunt.IndexOf('Invoke-SIHuntingQueryRest -Query $Query -Token')
    }
    It 'the flag is set per report, before the probe, and exists exactly once as a reset' {
        $script:Eng.IndexOf('$reportCannotFit = $null') | Should -BeGreaterThan 0
        ([regex]::Matches($script:Eng, [regex]::Escape('$reportCannotFit = $null'))).Count | Should -Be 1
        $script:Eng.IndexOf('$reportCannotFit = $null') | Should -BeLessThan $script:Eng.IndexOf('$probe = {')
    }
    It 'the engine''s probe turns a size refusal that more slices cannot cure into the one error (same shape as the test probe)' {
        $script:Span | Should -Match '(?s)\$null = Invoke-GraphHuntingQuery -Query \$probeQuery.{0,200}?-MaxRetries 1\s*\} catch \{.{0,400}?\$__refused = Get-RARefusedRequestVerdict -Err \$_\s*if \(\$__refused\) \{ throw \(New-RALookupTooLargeError -Message \$__refused\) \}\s*throw\s*\}'
    }
    It 'the probe''s caller recognises the error and does NOT fall back to the configured slice count for it' {
        $script:Span | Should -Match '(?s)\} catch \{\s*if \(Test-RAReportCannotRunError -Err \$_\) \{.{0,300}?\$reportCannotFit = \[string\]\$_\.Exception\.Message\s*\} else \{.{0,400}?AutoBucket failed for report'
    }
    It 'the bucket loop does not start, and does not restart, once the report cannot fit' {
        $script:Span | Should -Match 'while \(-not \$bucketRunSucceeded -and -not \$reportCannotFit\) \{'
    }
    It 'inside the loop the decision comes BEFORE the retry, the escalation and the sub-slice queue' {
        $a = $script:Span.IndexOf('$__cannotFit = if (Test-RAReportCannotRunError -Err $_) { [string]$_.Exception.Message } else { Get-RARefusedRequestVerdict -Err $_ }')
        $b = $script:Span.IndexOf('elseif ((Test-IsBucketOverflowError $_) -and -not (Test-RABucketBusyAnswer -Err $_)) {')   # #880
        $a | Should -BeGreaterThan 0
        $b | Should -BeGreaterThan $a
        $script:Span | Should -Not -Match '(?m)^\s*if \(Test-IsBucketOverflowError \$_\) \{' -Because 'the overflow branch must be the ELSE of the cannot-fit decision'
    }
    It 'the remaining slices are not tried, and neither the late retry nor the sub-slice pass runs' {
        $script:Span | Should -Match '(?s)if \(\$needEscalation\) \{ break \}\s*if \(\$reportCannotFit\) \{ break \}'
        $x = $script:Span.IndexOf('if ($reportCannotFit) { break }', $script:Span.IndexOf('if ($needEscalation) { break }') + 60)
        $x | Should -BeGreaterThan 0
        $x | Should -BeLessThan $script:Span.IndexOf('# LATE-RETRY PASS')
        $x | Should -BeLessThan $script:Span.IndexOf('ADAPTIVE SUB-BUCKETING PASS')
    }
    It 'the report is recorded as FAILED (findings unknown), nothing of it is kept, and the next report runs' {
        $script:Span | Should -Match '(?s)if \(\$reportCannotFit\) \{\s*\$script:_CurrentBucketCount = 0\s*\$script:_CurrentBucketIndex = 0\s*Reset-RABucketLoss\s*Write-Err2 \(.{0,400}?\)\s*(?:#[^\r\n]*\s*)?(?:\$__cannotWhy = [^\r\n]*\s*)?Add-RAReportFailure -ReportName \$ReportName -Reason \(.{0,200}?\)\s*continue\s*\}'
    }
    It 'the log line names the report and says the findings are unknown, not resolved -- in plain words' {
        $m = [regex]::Match($script:Span, 'Write-Err2 \("report ''\{0\}'' is NOT in this run: \{1\}\. ([^"]*)" -f \$ReportName, \$reportCannotFit\)')
        $m.Success | Should -BeTrue
        $m.Groups[1].Value | Should -Match 'Its findings are unknown for this run, not resolved'
        $m.Groups[1].Value | Should -Match 'The run continues with the next report'
        $m.Value | Should -Not -Match '#\d|\[hybrid\]|AutoBucket|nginx|bucket'
    }
    It 'a failed report is one the run reports as not whole (the existing end-of-run list)' {
        $script:Eng | Should -Match 'report\(s\) did not deliver a whole result this run\. Their findings are UNKNOWN, not remediated'
        $script:Eng | Should -Match '(?s)function Add-RAReportFailure \{.{0,400}?\$script:_RAReportFailures\.Add\(@\{ Report = \$ReportName; Why = \$Reason \}\)'
    }
}
