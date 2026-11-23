#Requires -Version 5.1
<#
    AZHANG-1 (2026-11-23): the Azure collect step's producer stopped for over an hour after the last Resource Graph page at
    a large install (twice), and at a second large install -- silent. The reads after that page (Defender for Cloud
    assessments from Resource Graph AND the ARM assessments API, other clouds, management groups, Azure context) each
    waited up to 6 x 300 s per call with the retries said only as Write-Verbose, and had no time-out of their own.

    What these tests keep true (OFFLINE -- every Azure call is a seam; one test uses a local socket that never answers):
      * a call that never answers times out (StatusCode 0) instead of waiting forever;
      * a call that times out is retried, and the retry is SAID (OnRetry); the default assessments-API getter waits at most
        120 s per page and tries 4 times;
      * a next link that changes but hands back the same page again stops the read with a clear error -- the subscription
        is then a failed read: UNKNOWN when Resource Graph has no rows for it, never "nothing there";
      * a subscription whose read runs past its time-out is a failed read the same way;
      * a Resource Graph next-page token handed back twice stops Invoke-SIArgPaged (INCOMPLETE) and the management-group
        read (no endless loop);
      * a progress line while a read runs ("Defender for Cloud assessments: subscription i of n ...");
      * a normal read gives exactly the rows it gave before.
    PS 7 (v3 gate).
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\_shared\SI-AzRest.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-LogIngest.ps1')
    . (Join-Path $script:SIRoot 'engine\asset-profiling\discovery\Invoke-SIArgPaged.ps1')
    . (Join-Path $script:SIRoot 'engine\asset-profiling\discovery\Get-SIMdcAssessmentSources.ps1')
    . (Join-Path $script:SIRoot 'engine\asset-profiling\discovery\Get-SIDerivedSources.ps1')
    $global:SIHangSaid = New-Object System.Collections.Generic.List[string]; $script:Said = $global:SIHangSaid
    function script:Write-SIInfo { param([string]$Message) if ($null -ne $global:SIHangSaid) { $global:SIHangSaid.Add([string]$Message) } }
    $script:Base = 'https://management.azure.com'
    function script:AssessUri([string]$Sub) { '{0}/subscriptions/{1}/providers/Microsoft.Security/assessments?api-version=2021-06-01' -f $script:Base, $Sub }
    function script:ApiA([string]$Res, [string]$Key) {
        [pscustomobject]@{ id = "$Res/providers/Microsoft.Security/assessments/$Key"; name = $Key
            properties = [pscustomobject]@{ resourceDetails = [pscustomobject]@{ Id = $Res }; displayName = 'a'; metadata = [pscustomobject]@{ severity = 'High' }
                status = [pscustomobject]@{ code = 'Unhealthy'; firstEvaluationDate = '2026-01-05T00:00:00Z'; statusChangeDate = '2026-10-22T08:00:00Z' } } }
    }
    $script:Vm1 = '/subscriptions/s1/resourcegroups/rg/providers/microsoft.compute/virtualmachines/vm1'
    $script:Vm2 = '/subscriptions/s1/resourcegroups/rg/providers/microsoft.compute/virtualmachines/vm2'
}

AfterAll {
    Remove-Item -Path Function:\Write-SIInfo -ErrorAction SilentlyContinue
    Remove-Variable -Scope Global -Name SI_MdcArmSubscriptionTimeoutMinutes, SI_AzureReadTimeoutSec, SIHangSaid -ErrorAction SilentlyContinue
}

Describe 'AZHANG-1: a call that hangs times out and is retried, and the retry is said' {
    It 'a server that accepts the connection and never answers: the request times out (no answer), it does not wait forever' {
        $l = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
        $l.Start()
        try {
            $port = ([System.Net.IPEndPoint]$l.LocalEndpoint).Port
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $r = Invoke-SIAzRestHttp -Method GET -Uri ("http://127.0.0.1:{0}/hang" -f $port) -TimeoutSec 2
            $sw.Stop()
            [int]$r.StatusCode | Should -Be 0 -Because 'no answer is "no response" -- the caller''s retry rule takes it'
            $sw.Elapsed.TotalSeconds | Should -BeLessThan 30
        } finally { $l.Stop() }
    }
    It 'a call that times out once is retried; OnRetry is told before the wait; the answer after it is returned' {
        $script:N = 0; $script:Told = @()
        Mock Get-SIAzureToken { 'tok' }
        Mock Test-SISupportRequestRoute { $false }
        Mock Start-Sleep { }
        Mock Invoke-SIAzRestHttp {
            $script:N++
            if ($script:N -eq 1) { return [pscustomobject]@{ StatusCode = 0; Content = 'The operation has timed out.'; Bytes = $null; Headers = @{}; RetryAfter = $null } }
            [pscustomobject]@{ StatusCode = 200; Content = '{"value":[]}'; Bytes = $null; Headers = @{}; RetryAfter = $null }
        }
        $r = Invoke-SIAzRestRequest -Method GET -Uri 'https://management.azure.com/x' -MaxAttempts 4 -OnRetry { param($Code, $Wait, $Attempt, $Max, $What) $script:Told += ('{0}/{1}/{2}' -f $Code, $Attempt, $Max) }
        [int]$r.StatusCode | Should -Be 200
        $script:N | Should -Be 2
        @($script:Told) | Should -Be @('0/1/4')
    }
    It 'a call that never answers stops after its attempts (bounded), every retry said' {
        $script:N = 0; $script:Told = @()
        Mock Get-SIAzureToken { 'tok' }
        Mock Test-SISupportRequestRoute { $false }
        Mock Start-Sleep { }
        Mock Invoke-SIAzRestHttp { $script:N++; [pscustomobject]@{ StatusCode = 0; Content = 'The operation has timed out.'; Bytes = $null; Headers = @{}; RetryAfter = $null } }
        { Invoke-SIAzRestRequest -Method GET -Uri 'https://management.azure.com/x' -MaxAttempts 3 -OnRetry { param($Code, $Wait, $Attempt) $script:Told += $Attempt } } | Should -Throw '*timed out*'
        $script:N | Should -Be 3
        @($script:Told) | Should -Be @(1, 2)
    }
    It 'the default assessments-API getter waits at most 120 s per page, tries 4 times, and SAYS each retry' {
        $script:N = 0; $script:Args = @(); $script:Said.Clear()
        Mock Get-SIAzureToken { 'tok' }
        Mock Test-SISupportRequestRoute { $false }
        Mock Start-Sleep { }
        Mock Invoke-SIAzRestHttp {
            $script:N++; $script:Args += $TimeoutSec
            if ($script:N -lt 3) { return [pscustomobject]@{ StatusCode = 0; Content = 'timed out'; Bytes = $null; Headers = @{}; RetryAfter = $null } }
            [pscustomobject]@{ StatusCode = 200; Content = '{"value":[{"id":"x"}]}'; Bytes = $null; Headers = @{}; RetryAfter = $null }
        }
        $get = Get-SIMdcArmGetDefault
        $p = & $get (AssessUri 's1')
        @($p.value).Count | Should -Be 1
        @($script:Args | Select-Object -Unique) | Should -Be @(120)
        @($script:Said | Where-Object { $_ -match 'Defender for Cloud assessments API: no answer \(HTTP 0\) on https://management.azure.com/subscriptions/s1/providers/Microsoft.Security/assessments -- retry 1/3' }).Count | Should -Be 1
        @($script:Said | Where-Object { $_ -match 'retry 2/3' }).Count | Should -Be 1
    }
}

Describe 'AZHANG-1: a read that would never end stops, and what it could not read is UNKNOWN' {
    BeforeEach { $script:Said.Clear(); Remove-Variable -Scope Global -Name SI_MdcArmSubscriptionTimeoutMinutes -ErrorAction SilentlyContinue }
    It 'a next link that CHANGES but hands back the same page again stops the read with a clear error' {
        $script:K = 0
        $get = { param([string]$Uri) $script:K++; [pscustomobject]@{ value = @((ApiA $script:Vm1 'p1')); nextLink = ((AssessUri 's1') + '&$skipToken=' + $script:K) } }
        { Read-SIMdcArmPages -Uri (AssessUri 's1') -Get $get } | Should -Throw '*handed back only items already read*'
        $script:K | Should -Be 2 -Because 'it stops at the first page that repeats -- no endless paging'
    }
    It 'that subscription is a failed read: Resource Graph has no rows for it -> INCOMPLETE and UNKNOWN, never "nothing there"' {
        $get = { param([string]$Uri) [pscustomobject]@{ value = @((ApiA $script:Vm1 'p1')); nextLink = ((AssessUri 's1') + '&$skipToken=' + [guid]::NewGuid()) } }
        $r = Get-SIMdcAssessmentRows -SubscriptionIds 's1' -GraphQuery { param($q) @() } -ArmGet $get
        $r.Complete | Should -BeFalse
        $r.Error | Should -Match 'unknown, not "nothing there".*handed back only items already read'
    }
    It 'a subscription whose read runs past its time-out is a failed read the same way (the next subscription is still read)' {
        $global:SI_MdcArmSubscriptionTimeoutMinutes = 0.0005   # 30 ms
        $get = {
            param([string]$Uri)
            if ($Uri -like '*subscriptions/s1/*') { Start-Sleep -Milliseconds 60; return [pscustomobject]@{ value = @((ApiA $script:Vm1 ('k' + [guid]::NewGuid()))); nextLink = ((AssessUri 's1') + '&$skipToken=' + [guid]::NewGuid()) } }
            [pscustomobject]@{ value = @((ApiA '/subscriptions/s2/resourcegroups/rg/providers/microsoft.keyvault/vaults/kv9' 'k9')) }
        }
        $r = Read-SIMdcArmAssessments -SubscriptionIds @('s1', 's2') -Get $get
        $r.Complete | Should -BeFalse
        [string]$r.Failed['s1'] | Should -Match 'did not finish within'
        $r.PerSubscription['s2'] | Should -Be 1
    }
    It 'a progress line names the subscription i of n while the read runs' {
        $get = { param([string]$Uri) [pscustomobject]@{ value = @((ApiA $script:Vm1 ('k' + [guid]::NewGuid()))) } }
        $null = Read-SIMdcArmAssessments -SubscriptionIds @('s1', 's2') -Get $get -ProgressSeconds 0.001
        @($script:Said | Where-Object { $_ -match 'Defender for Cloud assessments API: reading 2 subscription\(s\)' }).Count | Should -Be 1
        @($script:Said | Where-Object { $_ -match 'Defender for Cloud assessments: subscription 2 of 2, page 1' }).Count | Should -Be 1
    }
    It 'a normal read gives exactly the rows it gave before (every page, in order, nothing extra)' {
        $n1 = (AssessUri 's1') + '&$skipToken=p2'
        $pages = @{ (AssessUri 's1') = [pscustomobject]@{ value = @((ApiA $script:Vm1 'p1')); nextLink = $n1 }; $n1 = [pscustomobject]@{ value = @((ApiA $script:Vm2 'p2')) } }
        $get = { param([string]$Uri) $pages[$Uri] }.GetNewClosure()
        $r = Read-SIMdcArmAssessments -SubscriptionIds 's1' -Get $get
        $r.Complete | Should -BeTrue
        @($r.Rows | ForEach-Object { $_.ResourceId + '|' + $_.AssessmentKey }) | Should -Be @("$($script:Vm1)|p1", "$($script:Vm2)|p2")
    }
}

Describe 'AZHANG-1: Resource Graph paging stops on a repeated token and says its progress' {
    BeforeEach { $script:Said.Clear() }
    It 'Invoke-SIArgPaged: the same next-page token twice -> INCOMPLETE with a clear error, the rows read kept' {
        $script:P = 0
        $f = { param($p) $script:P++; [pscustomobject]@{ Data = @([pscustomobject]@{ n = $script:P }); SkipToken = 'same' } }
        $r = Invoke-SIArgPaged -Query 'x' -SourceLabel 'T' -PageFetcher $f -WarningAction SilentlyContinue
        $r.Complete | Should -BeFalse
        $r.Error | Should -Match 'same next-page token twice'
        $r.Rows.Count | Should -Be 2
    }
    It 'Invoke-SIArgPaged: a read past -TimeoutMinutes stops INCOMPLETE; a progress line while it runs' {
        $f = { param($p) Start-Sleep -Milliseconds 40; [pscustomobject]@{ Data = @([pscustomobject]@{ n = 1 }); SkipToken = [string][guid]::NewGuid() } }
        $r = Invoke-SIArgPaged -Query 'x' -SourceLabel 'Defender for Cloud assessments (Resource Graph)' -PageFetcher $f -TimeoutMinutes 0.003 -ProgressSeconds 0.001 -WarningAction SilentlyContinue
        $r.Complete | Should -BeFalse
        $r.Error | Should -Match 'did not finish within'
        @($script:Said | Where-Object { $_ -match 'Defender for Cloud assessments \(Resource Graph\): page \d+, \d+ row\(s\) so far' }).Count | Should -BeGreaterThan 0
    }
    It 'Invoke-SIArgPaged: a normal read gives exactly the rows it gave before' {
        $f = { param($p) $s = 0; if ($p.SkipToken) { $s = [int]$p.SkipToken }; [pscustomobject]@{ Data = @($s, ($s + 1)); SkipToken = $(if ($s -lt 4) { [string]($s + 2) } else { $null }) } }
        $r = Invoke-SIArgPaged -Query 'x' -SourceLabel 'T' -PageFetcher $f
        $r.Complete | Should -BeTrue
        @($r.Rows) | Should -Be @(0, 1, 2, 3, 4, 5)
    }
    It 'the default page call inside the pager waits at most 120 s and is tried twice by the REST client' {
        $script:Seen = @()
        Mock Invoke-SIAzRestRequest { $script:Seen += ('{0}/{1}/{2}' -f $TimeoutSec, $MaxAttempts, [bool]$OnRetry); [pscustomobject]@{ StatusCode = 200; Content = '{"data":[{"n":1}]}' } }
        $r = Invoke-SIArgPaged -Query 'x' -SourceLabel 'T'
        $r.Complete | Should -BeTrue
        @($script:Seen) | Should -Be @('120/2/True')
    }
    It 'outside the pager a Resource Graph page keeps its defaults (300 s, 6 attempts)' {
        $script:Seen = @()
        Mock Invoke-SIAzRestRequest { $script:Seen += ('{0}/{1}' -f $TimeoutSec, $MaxAttempts); [pscustomobject]@{ StatusCode = 200; Content = '{"data":[]}' } }
        $null = Invoke-SIResourceGraphPage -Query 'x'
        @($script:Seen) | Should -Be @('300/6')
    }
    It 'the management-group read stops on a repeated token (warned, no endless loop)' {
        $script:P = 0
        Mock Search-SIAzGraph { $script:P++; , (New-SIAzGraphPage -Rows @([pscustomobject]@{ SubscriptionId = 's1' }) -SkipToken 'same') }
        $w = @(Invoke-SIManagementGroupCapture -SubscriptionIds 's1' 3>&1)
        $script:P | Should -Be 2
        @($w | Where-Object { $_ -is [System.Management.Automation.WarningRecord] -and $_.Message -match 'same next-page token twice' }).Count | Should -Be 1
    }
}
