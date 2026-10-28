#Requires -Version 7.0
<#
    #880 -- A BUSY DEFENDER IS ASKED AGAIN, NEVER SPLIT; THE REMEMBERED SLICE COUNT NEVER GROWS FROM BUSY ANSWERS AND COMES
    BACK DOWN BY ITSELF.

    Live 2026-10-22 (internal): Device_Missing_CVEs_Detailed went from 12.6 min (3 hunting queries) to 133 min (263 queries,
    108 refused) and still ended NOT COMPLETE; its remembered count went 2 -> 18 -> 28. Advanced hunting answered "Query
    execution has exceeded the allowed limits. The query execution was preempted ... high CPU and/or memory" -- a busy
    backend: an 11 KB slice with 28 of 700 inlined rows was refused, about a third of the requests were refused at every
    slice size for two hours, and 3 of 8 refused slices went through when sent again at the same size 30 s later. The
    engine read the answer as "too large" and split, which multiplied the fixed reads every slice pays.

    What these tests keep true (offline, no tenant):
      * the busy answer is a RETRY (same size, backoff, late retry), in every pass, before every size test;
      * a slice whose only failures were busy answers is sized from its rows and bytes only (never its time, never "at
        least 2"), and the internal replay keeps 18 where the old rule went to 28;
      * a NOT COMPLETE report never raises its count (end of report and the early save), and is recorded 'incomplete';
        its partial measurement sizes nothing (shrink / down / start plan);
      * a split is stopped when it does not reduce the failure (the refused share must go down, measured per bucket);
      * a report that ran complete at fewer slices on the same query comes back towards that count;
      * the engine wiring, and the CVE reports reading Defender vulnerability management only for the slice's devices.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $shared = Join-Path $script:SIRoot 'engine\risk-analysis\_shared'
    . (Join-Path $shared 'RA-AutoBucketing.ps1')
    . (Join-Path $shared 'RA-BucketStore.ps1')
    $script:AutoBucketConfirmedKey = '__confirmed'
    function Write-Info { param($msg) }
    function Write-Warn2 { param($msg) }
    $script:Busy = '400 Bad Request -- {"error":{"code":"BadRequest","message":"Query execution has exceeded the allowed limits. The query execution was preempted. This could possibly be due to high CPU and/or memory resource consumption. Optimize your query by following best practices and try again."}}'
    function New-Slice { param([long]$Rows = 0, [double]$Seconds = 0, [int]$Busy = 0, [int]$SizeFails = 0, [switch]$TooLarge, [switch]$Lost, [switch]$LostBusy)
        [pscustomobject]@{ Rows = $Rows; Bytes = 0L; Seconds = $Seconds; TooLarge = [bool]$TooLarge; Lost = [bool]$Lost; OutOfMemory = $false; MaxPartRows = 0L
                           Busy = $Busy; SizeFails = $SizeFails; LostBusy = [bool]$LostBusy } }
    function New-Run { param([int]$Count, [int]$Start = -1, [string]$Decided = 'cache', [double]$Seconds = 20, [string]$Fp = '3665899830', [long]$Rows = 12000)
        if ($Start -lt 0) { $Start = $Count }
        [pscustomobject]@{ BucketCount = $Count; StartCount = $Start; Decided = $Decided; ResultRows = $Rows; MaxBucketRows = [long]($Rows / [Math]::Max(1, $Count))
                           MaxBucketBytes = 1000L; MaxRequestBytes = $null; RequestRows = $null; RequestBytesPerRow = $null; RequestOverheadBytes = $null
                           Fingerprint = $Fp; MaxBucketSeconds = $Seconds; RanCount = $Count } }
}

AfterAll { $global:SettingsPath = $null }

Describe 'a busy answer is retried at the same size, never split' {
    It 'the live answer of 2026-10-22 is a Retry -- before every size test, whatever the hunting layer flagged' {
        Test-IsBucketOverflowError -Err $script:Busy | Should -BeTrue -Because 'it carries the overflow wording (why it was split)'
        Get-RABucketFailureAction -Err $script:Busy | Should -Be 'Retry'
        Get-RABucketFailureAction -Err $script:Busy -AllTimedOut $true | Should -Be 'Retry'
        Test-RABucketExplicitTooLarge -Err $script:Busy | Should -BeFalse
    }
    It 'a real size answer is still split' {
        foreach ($m in 'Query execution has exceeded the allowed result size', 'Query execution has exceeded the allowed limits', '502 Bad Gateway <html>nginx</html>',
                       'TaskCanceledException: the request was canceled due to the configured timeout of 900 seconds elapsing.') {
            Get-RABucketFailureAction -Err $m | Should -Be 'Split' -Because $m
        }
    }
    It 'a defect, a missing data source and a worker out of memory keep their own answers' {
        Get-RABucketFailureAction -Err '400 Bad Request -- Fix syntax errors in your query' | Should -Be 'Defect'
        Get-RABucketFailureAction -Err "Failed to resolve table expression named 'DeviceTvmSoftwareVulnerabilities'" | Should -Be 'Absent'
        Get-RABucketFailureAction -Err ([System.OutOfMemoryException]::new('Exception of type ''System.OutOfMemoryException'' was thrown.')).Message | Should -Be 'Split'
    }
}

Describe 'busy answers never raise the remembered count' {
    It 'a slice whose only failures were busy answers is sized from its rows and bytes -- not its time, not "lost"' {
        $s = New-Slice -Rows 949 -Seconds 4000 -Busy 6 -LostBusy
        Get-RASliceNeed -Slice $s -Bound 4096 | Should -Be 1
        # the same slice with a smaller slice refused for its SIZE is sized as before (its time counts)
        $t = New-Slice -Rows 949 -Seconds 4000 -Busy 6 -SizeFails 1
        Get-RASliceNeed -Slice $t -Bound 4096 | Should -BeGreaterThan 1
        # a busy-only slice with genuinely many rows still needs the slices its rows need
        Get-RASliceNeed -Slice (New-Slice -Rows 60000 -Busy 2) -Bound 4096 | Should -Be 4
    }
    It 'replay of internal 2026-10-22: 5 of 18 buckets split by busy answers keep 18 (the old rule went to 28)' {
        $slices = @(1..5 | ForEach-Object { New-Slice -Rows 950 -Seconds 1500 -Busy 8 -LostBusy })
        Get-RACountAfterSplit -BucketCount 18 -Slices $slices -WorkingCount 73728 -FanOut 4 | Should -Be 18
        # what the old evidence (busy failures as Lost, their time summed) gave
        $old = @(1..5 | ForEach-Object { [pscustomobject]@{ Rows = 950L; Bytes = 0L; Seconds = 1500.0; TooLarge = $false; Lost = $true } })
        Get-RACountAfterSplit -BucketCount 18 -Slices $old -WorkingCount 73728 -FanOut 4 | Should -BeGreaterThan 18
    }
    It 'a NOT COMPLETE report never raises its count (-Incomplete)' {
        $big = @(New-Slice -Rows 90000 -TooLarge)
        Get-RACountAfterSplit -BucketCount 2 -Slices $big -WorkingCount 32 | Should -BeGreaterThan 2
        Get-RACountAfterSplit -BucketCount 2 -Slices $big -WorkingCount 32 -Incomplete | Should -Be 2
    }
    It 'the early save counts only slices whose size is proven (-ProvenOnly)' {
        $s = @((New-Slice -Rows 1000 -Seconds 2000 -SizeFails 2), (New-Slice -Rows 90000 -TooLarge))
        Get-RACountAfterSplit -BucketCount 2 -Slices @($s[0]) -WorkingCount 32 -ProvenOnly | Should -Be 2
        Get-RACountAfterSplit -BucketCount 2 -Slices $s -WorkingCount 32 -ProvenOnly | Should -BeGreaterThan 2
    }
    It 'the early save keeps nothing once a slice of the report is lost (-Incomplete)' {
        $global:AutoBucketCache = $true
        $global:SettingsPath = Join-Path ([IO.Path]::GetTempPath()) ('si-busy-' + [guid]::NewGuid().ToString('N'))
        $script:AutoBucketSql = $null
        Save-AutoBucketCountEarly -QueryKey 'R|1' -Count 28 -Incomplete | Should -BeFalse
        Save-AutoBucketCountEarly -QueryKey 'R|1' -Count 28 | Should -BeTrue
    }
}

Describe 'a NOT COMPLETE run is recorded as incomplete and sizes nothing' {
    BeforeEach {
        # the Pro database behind its ONE -Invoke seam: the history row's parameters are captured
        $rows = New-Object System.Collections.Generic.List[object]
        $script:Rows = $rows
        $script:AutoBucketSql = [pscustomobject]@{ Invoke = { param($s, $p, $m) $rows.Add($p) }.GetNewClosure(); Template = 'T'; RunId = 'r1'; State = @{}; Saved = @{}; History = @{}; Offline = $false }
        $script:AutoBucketMeasure = $null
        $script:AutoBucketJumps = $null
    }
    It 'the history row says incomplete, never raised' {
        $null = Complete-AutoBucketReport -ReportName 'Device_Missing_CVEs_Detailed' -QueryKey 'Device_Missing_CVEs_Detailed|3665899830' -StartCount 18 -FinalCount 18 -Source 'cache' -Incomplete
        $script:Rows[0].Decided | Should -Be 'incomplete'
        $null = Complete-AutoBucketReport -ReportName 'Device_Missing_CVEs_Detailed' -QueryKey 'Device_Missing_CVEs_Detailed|3665899830' -StartCount 18 -FinalCount 28 -Source 'cache'
        $script:Rows[1].Decided | Should -Be 'raised'
    }
    It 'shrink and the 3-run down step keep the count after an incomplete run' {
        $h = @((New-Run -Count 28 -Decided 'incomplete' -Rows 100), (New-Run -Count 28), (New-Run -Count 28))
        (Get-SIRaBucketShrinkCount -Count 28 -Floor 1 -History $h).Down | Should -BeFalse
        (Get-SIRaBucketDownCount -Count 28 -Floor 1 -History @((New-Run -Count 28 -Decided 'incomplete'), (New-Run -Count 28), (New-Run -Count 28))).Down | Should -BeFalse
    }
}

Describe 'a split must reduce the failure (measured, no fixed depth)' {
    It 'the first split is always tried; deeper only while the refused share goes down' {
        Test-RASplitReducesFailure -Tried @{} -Failed @{} -Depth 1 | Should -BeTrue
        Test-RASplitReducesFailure -Tried @{ 1 = 4 } -Failed @{ 1 = 3 } -Depth 2 | Should -BeTrue -Because '3 of 4 is below the bucket itself (1 of 1)'
        Test-RASplitReducesFailure -Tried @{ 1 = 4 } -Failed @{ 1 = 4 } -Depth 2 | Should -BeFalse -Because 'every smaller slice refused: the split did not help'
        Test-RASplitReducesFailure -Tried @{ 1 = 4; 2 = 12 } -Failed @{ 1 = 3; 2 = 9 } -Depth 3 | Should -BeFalse -Because '9 of 12 is as often as 3 of 4'
        Test-RASplitReducesFailure -Tried @{ 1 = 4; 2 = 12 } -Failed @{ 1 = 3; 2 = 2 } -Depth 3 | Should -BeTrue
    }
    It 'a depth with nothing measured yet does not stop the split' {
        Test-RASplitReducesFailure -Tried @{ 1 = 4 } -Failed @{ 1 = 1 } -Depth 3 | Should -BeTrue
    }
}

Describe 'the count comes back down from a complete run at fewer slices' {
    It 'internal: the query ran complete at 2 before the busy raises -> 2' {
        $h = @((New-Run -Count 28 -Start 18 -Decided 'raised' -Seconds 160), (New-Run -Count 18 -Start 2 -Decided 'raised' -Seconds 70), (New-Run -Count 2 -Seconds 17))
        Get-SIRaBucketCompleteLowerCount -Count 28 -History $h -Fingerprint '3665899830' | Should -Be 2
        Get-RACountAfterSmallRun -BucketCount 28 -Floor 2 | Should -Be 14
        Get-RACountAfterSmallRun -BucketCount 14 -Floor 2 | Should -Be 7
        Get-RACountAfterSmallRun -BucketCount 7 -Floor 2 | Should -Be 4
        Get-RACountAfterSmallRun -BucketCount 4 -Floor 2 | Should -Be 2
        Get-RACountAfterSmallRun -BucketCount 2 -Floor 2 | Should -Be 2
    }
    It 'only a complete, unsplit, timed run of the same query under half the ceiling counts' {
        Get-SIRaBucketCompleteLowerCount -Count 28 -History @((New-Run -Count 2 -Fp 'other')) -Fingerprint '3665899830' | Should -Be 0
        Get-SIRaBucketCompleteLowerCount -Count 28 -History @((New-Run -Count 2 -Decided 'incomplete')) -Fingerprint '3665899830' | Should -Be 0
        Get-SIRaBucketCompleteLowerCount -Count 28 -History @((New-Run -Count 8 -Start 2 -Decided 'raised')) -Fingerprint '3665899830' | Should -Be 0
        Get-SIRaBucketCompleteLowerCount -Count 28 -History @((New-Run -Count 2 -Seconds 500)) -Fingerprint '3665899830' | Should -Be 0
        Get-SIRaBucketCompleteLowerCount -Count 28 -History @((New-Run -Count 2 -Seconds 0)) -Fingerprint '3665899830' | Should -Be 0
        Get-SIRaBucketCompleteLowerCount -Count 2 -History @((New-Run -Count 2)) -Fingerprint '3665899830' | Should -Be 0 -Because 'not below the count'
    }
}

Describe 'the engine wiring (#880)' {
    BeforeAll { $script:Txt = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1')) }

    It 'the main pass sends a busy answer to the cause router (Retry), not to the overflow split' {
        $script:Txt | Should -Match ([regex]::Escape('elseif ((Test-IsBucketOverflowError $_) -and -not (Test-RABucketBusyAnswer -Err $_)) {'))
    }
    It 'the sub-slice pass retries a busy slice, then asks it again after its siblings (never split), and counts it as busy' {
        $script:Txt | Should -Match ([regex]::Escape("How = 'again'; RC = `$subRC; RI = `$subRI; M = `$false; A = (`$pRounds + 1)"))
        $script:Txt | Should -Match ([regex]::Escape('$__subBusy = ($subAction -eq ''Retry'') -and (Test-RABucketBusyAnswer -Err $_)'))
        $script:Txt | Should -Match ([regex]::Escape('$subFilter  = New-BucketFilterKql -BucketCount $pT -BucketIndex $pN -ReportName $ReportName'))
    }
    It 'a deeper split is asked only while it reduces the failure' {
        $script:Txt | Should -Match 'Test-RASplitReducesFailure -Tried '
        $script:Txt | Should -Match ([regex]::Escape('& $__subCount $__subFailed $root $depth'))
    }
    It 'the early save is proven-only and stops once a slice is lost; the end of the report is never raised when incomplete' {
        $script:Txt | Should -Match ([regex]::Escape('-FanOut $subFanOut -Cap ([int]$capBucket) -ProvenOnly'))
        $script:Txt | Should -Match ([regex]::Escape('Save-AutoBucketCountEarly -QueryKey $queryKey -Count $__abSplitNext -Incomplete:'))
        $script:Txt | Should -Match ([regex]::Escape('-Cap ([int]$capBucket) -Incomplete:$__abIncomplete'))
        $script:Txt | Should -Match ([regex]::Escape('-RanCount ([int]$bucketCountToUse) -Incomplete:$__abIncomplete'))
    }
    It 'a slice recovered by the late retry is measured' {
        $i = $script:Txt.IndexOf('late retry: bucket {0}/{1} recovered')
        $i | Should -BeGreaterThan 0
        $script:Txt.Substring($i, 900) | Should -Match 'Add-AutoBucketMeasure -Rows'
    }
}

Describe 'the CVE reports read Defender vulnerability management only for the slice''s devices' {
    BeforeAll {
        $yaml = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'))
        function script:Get-ReportBlock([string]$Name) {
            [regex]::Match($yaml, '(?s)- ReportName: ' + [regex]::Escape($Name) + '\r?\n(.*?)(?=\r?\n    - ReportName: |\z)').Groups[1].Value
        }
        # the engine's own block substitution
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'), [ref]$null, [ref]$null)
        $fn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Replace-BucketFilterBlock' }, $true) | Select-Object -First 1
        . ([scriptblock]::Create($fn.Extent.Text))
        $script:_BucketFilterBeginMark = '//__BUCKET_FILTER_BEGIN__'
        $script:_BucketFilterEndMark   = '//__BUCKET_FILTER_END__'
        $script:_SkipEGBucketForCrossDomain = $false
    }
    It '<_>: the slice''s device set carries the slice filter, and every vulnerability-management read before the joins uses it' -ForEach @('Device_Missing_CVEs_Summary', 'Device_Missing_CVEs_Detailed') {
        $b = Get-ReportBlock $_
        $b | Should -Match '(?s)let _sliceTvmDevices = DeviceTvmSoftwareVulnerabilities\s*\| summarize by DeviceKey = tolower\(tostring\(DeviceId\)\)\s*//__BUCKET_FILTER_BEGIN__\s*\| where 1 == 1\s*//__BUCKET_FILTER_END__\s*\| project DeviceKey;'
        $b | Should -Match '(?s)let _TvmOnly = DeviceTvmSoftwareVulnerabilities\s*\| where tolower\(tostring\(DeviceId\)\) in \(_sliceTvmDevices\)'
        $b | Should -Match '(?s)\| join kind=leftouter \(DeviceTvmSoftwareVulnerabilities\s*\| where tolower\(tostring\(DeviceId\)\) in \(_sliceTvmDevices\)'
        # the engine replaces EVERY slice block with the slice's filter -- none is left a no-op
        $q = Replace-BucketFilterBlock -Query $b -BucketFilterKql "| where __slice == 3"
        ([regex]::Matches($q, '__slice == 3')).Count | Should -Be 3
        $q | Should -Not -Match '(?s)//__BUCKET_FILTER_BEGIN__\s*\| where 1 == 1'
    }
}
