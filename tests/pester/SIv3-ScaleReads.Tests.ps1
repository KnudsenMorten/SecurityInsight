#Requires -Version 7.0
<#
    #882 -- READS THAT NEVER CUT DATA AT SCALE (owner 2026-10-22: "we cannot loose data (prio 1)" / "be smart think with scale
    out"). What these tests keep true (offline, every call through a seam):
      A1  a Graph read of many pages outlives one token: the token is asked before every page and renewed once after a 401,
          the SAME page is asked again, and no page already read is lost (Invoke-SIPagedRest);
      A2  Invoke-SIGraphRest waits the time Graph asks for (Retry-After), takes a 500 as temporary for a read, never for a
          POST, and tries 6 times;
      A3  a Defender hunting request is retried (throttling, 5xx, an expired token) and an answer of Microsoft's maximum of
          rows is CUT: it is read again in hash parts that add up EXACTLY to the whole answer, duplicates included;
      C6  the Exposure Graph identity buckets go out in parallel waves (one more after a clean wave, half after a throttled
          one, never more than the memory holds) and give the SAME index and records as the serial read, also when names
          are shared and when a bucket is cut and read again in halves;
      A4  every Log Analytics query asks to wait its maximum.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    function Write-SIInfo { param($m) }
    . (Join-Path $script:SIRoot 'engine\asset-profiling\shared\Invoke-SIPagedRest.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-GraphRest.ps1')
    . (Join-Path $script:SIRoot 'engine\asset-profiling\shared\HuntingQuery.ps1')
    . (Join-Path $script:SIRoot 'engine\asset-profiling\shared\IdentityRoleFetcher.ps1')
    function script:New-HttpError([int]$Status, [int]$RetryAfter = -1) {
        $resp = New-Object System.Net.Http.HttpResponseMessage ([System.Net.HttpStatusCode]$Status)
        if ($RetryAfter -ge 0) { $resp.Headers.RetryAfter = New-Object System.Net.Http.Headers.RetryConditionHeaderValue ([TimeSpan]::FromSeconds($RetryAfter)) }
        $ex = New-Object Microsoft.PowerShell.Commands.HttpResponseException ("Response status code does not indicate success: $Status"), $resp
        $ex
    }
}

Describe 'A1: a paged Graph read renews its token and loses no page' {
    It 'a 401 on page 3 renews the token ONCE and asks page 3 again -- every page is kept, the read is complete' {
        $script:Calls = New-Object System.Collections.Generic.List[string]
        $script:Expired = $true
        Mock Invoke-RestMethod {
            $tok = [string]$Headers['Authorization']
            $script:Calls.Add(('{0}|{1}' -f $Uri, $tok))
            if ($Uri -like '*page3*' -and $tok -eq 'Bearer old') { throw (New-HttpError 401) }
            switch -Wildcard ($Uri) {
                '*page1*' { [pscustomobject]@{ value = @(1, 2); '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/x?page2' } }
                '*page2*' { [pscustomobject]@{ value = @(3, 4); '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/x?page3' } }
                '*page3*' { [pscustomobject]@{ value = @(5) } }
            }
        }
        $script:Forced = 0
        $prov = { param([bool]$Force) if ($Force) { $script:Forced++; $script:Expired = $false }; if ($script:Expired) { 'old' } else { 'new' } }
        $r = Invoke-SIPagedRest -Url 'https://graph.microsoft.com/v1.0/x?page1' -Token 'old' -SourceLabel 't' -TokenProvider $prov
        $r.Complete | Should -BeTrue
        @($r.Rows) | Should -Be @(1, 2, 3, 4, 5)
        $script:Forced | Should -Be 1
        @($script:Calls | Where-Object { $_ -like '*page3*' }).Count | Should -Be 2
    }
    It 'a second 401 on the same page is a refusal: the pages read so far are KEPT and the read says it is not complete' {
        Mock Invoke-RestMethod { if ($Uri -like '*page2*') { throw (New-HttpError 401) }; [pscustomobject]@{ value = @('a'); '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/x?page2' } }
        $r = Invoke-SIPagedRest -Url 'https://graph.microsoft.com/v1.0/x?page1' -Token 't' -SourceLabel 't' -TokenProvider { param([bool]$Force) 't2' }
        $r.Complete | Should -BeFalse
        @($r.Rows) | Should -Be @('a')
        $r.Error | Should -Match '401'
    }
    It 'the default renewal works when the caller dot-sourced Get-SIGraphToken INSIDE one of its own functions (live 2026-10-23)' {
        # the token file defines Get-SIGraphToken + a helper it calls; a counting stub, renewed after a 401 mid-paging
        $tf = Join-Path ([IO.Path]::GetTempPath()) ('si-gt-{0}.ps1' -f [guid]::NewGuid().ToString('N'))
        Set-Content -LiteralPath $tf -Encoding utf8 -Value @'
function Get-SIGtStubHelper { param([bool]$Force) if ($Force) { $global:SIGtStubForced++; $global:SIGtStubExpired = $false }; $global:SIGtStubCalls++; if ($global:SIGtStubExpired) { 'old' } else { 'new' } }
function Get-SIGraphToken { param([string]$Resource, [switch]$ForceRefresh) $global:SIGtStubResource = $Resource; Get-SIGtStubHelper -Force ([bool]$ForceRefresh) }
'@
        $global:SIGtStubCalls = 0; $global:SIGtStubForced = 0; $global:SIGtStubExpired = $true; $global:SIGtStubResource = ''
        $script:Calls = New-Object System.Collections.Generic.List[string]
        Mock Invoke-RestMethod {
            $tok = [string]$Headers['Authorization']
            $script:Calls.Add(('{0}|{1}' -f $Uri, $tok))
            if ($Uri -like '*page2*' -and $tok -eq 'Bearer old') { throw (New-HttpError 401) }
            switch -Wildcard ($Uri) {
                '*page1*' { [pscustomobject]@{ value = @(1, 2); '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/x?page2' } }
                '*page2*' { [pscustomobject]@{ value = @(3, 4); '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/x?page3' } }
                '*page3*' { [pscustomobject]@{ value = @(5) } }
            }
        }
        function Invoke-CallerThatLoadsAuthInside { param($Path) . $Path; Invoke-SIPagedRest -Url 'https://graph.microsoft.com/v1.0/x?page1' -Token 'old' -SourceLabel 't' }
        try {
            # the suite may have a Get-SIGraphToken of its own loaded: the caller's (a counting stub) must be the one used --
            # the counters below only move when it is
            $r = Invoke-CallerThatLoadsAuthInside -Path $tf
        } finally { Remove-Item -LiteralPath $tf -Force -ErrorAction SilentlyContinue }
        $r.Complete | Should -BeTrue
        @($r.Rows) | Should -Be @(1, 2, 3, 4, 5)
        $global:SIGtStubForced | Should -Be 1 -Because 'the 401 renewed the token once through the captured function'
        $global:SIGtStubCalls | Should -BeGreaterThan 3 -Because 'the provider is asked before every page'
        $global:SIGtStubResource | Should -Be 'Graph'
        @($script:Calls | Where-Object { $_ -like '*page2*' }).Count | Should -Be 2
        @($script:Calls | Where-Object { $_ -like '*page3*' })[0] | Should -BeLike '*Bearer new'
        Remove-Variable -Scope Global -Name SIGtStubCalls, SIGtStubForced, SIGtStubExpired, SIGtStubResource -ErrorAction SilentlyContinue
    }
    It 'knows which token a Graph / Defender address takes; none for another address (the caller''s token as given)' {
        Get-SIPagedRestTokenResource -Url 'https://graph.microsoft.com/v1.0/users' | Should -Be 'Graph'
        Get-SIPagedRestTokenResource -Url 'https://api.securitycenter.microsoft.com/api/machines' | Should -Be 'Defender'
        Get-SIPagedRestTokenResource -Url 'https://management.azure.com/x' | Should -Be ''
    }
}

Describe 'A2: Invoke-SIGraphRest under throttling' {
    It 'waits the Retry-After Graph asks for, and succeeds on a later attempt' {
        $script:N = 0
        Mock Invoke-RestMethod { $script:N++; if ($script:N -lt 4) { throw (New-HttpError 429 37) }; [pscustomobject]@{ ok = 1 } }
        $script:Waits = New-Object System.Collections.Generic.List[int]
        (Invoke-SIGraphRest -Uri '/x' -Token 't' -Sleep { param($s) $script:Waits.Add([int]$s) }).ok | Should -Be 1
        @($script:Waits) | Should -Be @(37, 37, 37)
    }
    It 'a 500 is temporary for a read and a PATCH, never for a POST (it may not be safe to repeat)' {
        $script:N = 0
        Mock Invoke-RestMethod { $script:N++; if ($script:N -lt 2) { throw (New-HttpError 500) }; [pscustomobject]@{ ok = 1 } }
        (Invoke-SIGraphRest -Uri '/x' -Token 't' -Sleep { param($s) }).ok | Should -Be 1
        $script:N = 0
        { Invoke-SIGraphRest -Uri '/x' -Token 't' -Method Post -Body @{ a = 1 } -Sleep { param($s) } } | Should -Throw
        $script:N | Should -Be 1
    }
    It 'tries 6 times before it gives up (not 3 in ~3 s)' {
        $script:N = 0
        Mock Invoke-RestMethod { $script:N++; throw (New-HttpError 503) }
        { Invoke-SIGraphRest -Uri '/x' -Token 't' -Sleep { param($s) } } | Should -Throw
        $script:N | Should -Be 6
    }
}

Describe 'A3: Defender hunting -- retried, and a cut answer read whole in parts' {
    It 'retries a throttled request with the wait asked for, and renews an expired token once' {
        $script:N = 0; $script:Forced = 0
        $send = { param($tk, $q) $script:N++; if ($script:N -eq 1) { throw (New-HttpError 429 5) }; if ($script:N -eq 2) { throw (New-HttpError 401) }; [pscustomobject]@{ results = @(@{ a = 1 }) } }
        $tok = { param([bool]$Force) if ($Force) { $script:Forced++ }; 't' }
        $script:Waits = New-Object System.Collections.Generic.List[int]
        $r = Invoke-SIHuntingGraphRequest -Query 'X' -Send $send -Token $tok -Sleep { param($s) $script:Waits.Add([int]$s) }
        $r.Ok | Should -BeTrue
        @($r.Rows).Count | Should -Be 1
        @($script:Waits) | Should -Be @(5)
        $script:Forced | Should -Be 1
    }
    It 'a refused query (400) is not retried and answers its error' {
        $script:N = 0
        $r = Invoke-SIHuntingGraphRequest -Query 'X' -Send { param($tk, $q) $script:N++; throw (New-HttpError 400) } -Token { param([bool]$f) 't' } -Sleep { param($s) }
        $r.Ok | Should -BeFalse
        $script:N | Should -Be 1
    }
    It 'the parts add up EXACTLY to the whole answer (duplicates included), a part cut again is split in two' {
        # the "service": 23 rows (3 of them identical) and a cut at 5 rows; a part is selected by a hash of the whole row,
        # stood in for here by the row's value -- the same rule (row -> one part of n, part b of n = parts b and b+n of 2n)
        $all = @(1..20) + @(7, 7, 13)
        $cut = 5
        $ask = { param($q)
            if ($q -notmatch 'hash\(tostring\(pack_all\(\)\), (\d+)\)\s*\n\| where __siCutPart == (\d+)') { throw 'not a part query' }
            $n = [int]$Matches[1]; $b = [int]$Matches[2]
            $rows = @($all | Where-Object { ($_ % $n) -eq $b })
            [pscustomobject]@{ Ok = $true; Rows = @($rows | Select-Object -First $cut); Error = '' }
        }.GetNewClosure()
        $r = Invoke-SIHuntingCutSplit -Query 'T | project x' -Rows $cut -Ask $ask -Cut $cut
        $r.Ok | Should -BeTrue
        @($r.Rows | Sort-Object) | Should -Be @($all | Sort-Object)
    }
    It 'a part that fails makes the whole read fail -- never a partial answer read as whole' {
        $r = Invoke-SIHuntingCutSplit -Query 'T' -Rows 10 -Cut 5 -Ask { param($q) [pscustomobject]@{ Ok = $false; Rows = @(); Error = 'busy' } }
        $r.Ok | Should -BeFalse
        @($r.Rows).Count | Should -Be 0
    }
    It 'REVIEW M1: a cut part whose split does not reduce it (identical rows, one hash) stops -- a NAMED failure, never a partial answer, never endless' {
        $all = @(1, 2) + @(@(7) * 12)
        $cut = 5
        $calls = @{ n = 0 }
        $ask = { param($q)
            $calls.n++; if ($calls.n -gt 1000) { throw 'the split never ended' }
            if ($q -notmatch 'hash\(tostring\(pack_all\(\)\), (\d+)\)\s*\n\| where __siCutPart == (\d+)') { throw 'not a part query' }
            $n = [int]$Matches[1]; $b = [int]$Matches[2]
            [pscustomobject]@{ Ok = $true; Rows = @(@($all | Where-Object { ($_ % $n) -eq $b }) | Select-Object -First $cut); Error = '' }
        }.GetNewClosure()
        $r = Invoke-SIHuntingCutSplit -Query 'T | project x' -Rows $cut -Ask $ask -Cut $cut
        $r.Ok | Should -BeFalse
        @($r.Rows).Count | Should -Be 0 -Because 'never a partial answer'
        $r.Error | Should -Match 'is still cut at 5 rows after it was split in two and the other half is empty -- its rows are identical'
        $calls.n | Should -BeLessThan 20
    }
    It 'the part query takes its own hash column off again and keeps the caller''s query whole' {
        $q = Get-SIHuntingBucketQuery -Query "T | where a == 1;" -Buckets 4 -Bucket 3
        $q | Should -Match '^T \| where a == 1\n\| extend __siCutPart = hash\(tostring\(pack_all\(\)\), 4\)\n\| where __siCutPart == 3\n\| project-away __siCutPart$'
    }
    It 'WIRING: Invoke-SIHuntingQuery (DefenderGraph) retries and reads a cut answer in parts' {
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\shared\HuntingQuery.ps1'))
        $src | Should -Match '\$one = Invoke-SIHuntingGraphRequest -Query \$Query'
        $src | Should -Match 'Invoke-SIHuntingCutSplit -Query \$Query'
        $src | Should -Match '\$script:SIHuntingRowCut = 100000'
    }
}

Describe 'C6: the Exposure Graph identity buckets in parallel waves' {
    BeforeAll {
        # 7 buckets of canned rows; the answer of bucket i is "i"
        function script:New-Outcomes([object[]]$Qs, [hashtable]$Status = @{}) {
            , @(foreach ($q in $Qs) {
                $i = [int]([regex]::Match($q, '_bucket == (\d+)').Groups[1].Value)
                if ($Status.ContainsKey($i) -and $Status[$i].Count) { $s = $Status[$i][0]; $Status[$i] = @($Status[$i] | Select-Object -Skip 1); [pscustomobject]@{ Ok = $false; Rows = @(); Status = $s; RetryAfter = 3; Error = "HTTP $s"; Bytes = 0 } }
                else { [pscustomobject]@{ Ok = $true; Rows = @("r$i"); Status = 200; RetryAfter = $null; Error = ''; Bytes = 10 } }
            })
        }
        $script:Qs = @(0..6 | ForEach-Object { "ExposureGraphNodes | extend _bucket = hash(NodeId, 7) | where _bucket == $_" })
    }
    It 'every bucket answered once, in bucket order within each wave; the waves grow by one while nothing is throttled' {
        $script:Widths = New-Object System.Collections.Generic.List[int]
        $send = { param([string[]]$q) $script:Widths.Add(@($q).Count); New-Outcomes $q }
        $got = New-Object System.Collections.Generic.List[string]
        $r = @(Invoke-SIEgIdentityQueriesParallel -Queries $script:Qs -SendMany $send -Sleep { param($s) } -FreeBytes { -1L } | ForEach-Object { if ($_.Kind -eq 'answer') { $got.Add([string]$_.Rows[0]) } else { $_ } })
        @($got) | Should -Be @('r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6')
        @($script:Widths) | Should -Be @(1, 2, 3, 1)
        $r[0].Kind | Should -Be 'result'
        @($r[0].Failed).Count | Should -Be 0
    }
    It 'THE DEFAULT PATH (no seam): a wave of 2+ queries gives each query its own answer, a throttled one is read again' {
        # the real default sender, with only the HTTP sender and the token replaced IN THIS SCOPE (where its call resolves them);
        # the replacement answers like Invoke-SIEgHuntingRequests: ONE array of outcomes
        $script:Widths = New-Object System.Collections.Generic.List[int]; $script:St = @{ 1 = @(429) }   # wave 2's FIRST query
        function Get-SIGraphToken { param($Resource) 't' }
        function Invoke-SIEgHuntingRequests { param([string]$Token, [string[]]$Queries) $script:Widths.Add(@($Queries).Count); New-Outcomes $Queries $script:St }
        $got = New-Object System.Collections.Generic.List[string]
        $r = @(Invoke-SIEgIdentityQueriesParallel -Queries $script:Qs -Sleep { param($s) } -FreeBytes { -1L } | ForEach-Object { if ($_.Kind -eq 'answer') { $got.Add([string]$_.Rows[0]) } else { $_ } })
        @($got) | Should -Be @('r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6') -Because 'every bucket gets ITS OWN rows, the throttled one too'
        @($r | Where-Object { $_.Kind -eq 'result' })[0].Failed.Count | Should -Be 0
        @($script:Widths | Measure-Object -Sum).Sum | Should -Be 8 -Because 'only the throttled query is sent twice'
    }
    It 'a throttled wave halves the next and waits its Retry-After ONCE; the throttled bucket is read again, nothing is lost' {
        $script:Widths = New-Object System.Collections.Generic.List[int]; $script:St = @{ 2 = @(429) }
        $send = { param([string[]]$q) $script:Widths.Add(@($q).Count); New-Outcomes $q $script:St }
        $script:Waits = New-Object System.Collections.Generic.List[int]
        $got = New-Object System.Collections.Generic.List[string]
        $null = Invoke-SIEgIdentityQueriesParallel -Queries $script:Qs -SendMany $send -Sleep { param($s) $script:Waits.Add([int]$s) } -FreeBytes { -1L } | ForEach-Object { if ($_.Kind -eq 'answer') { $got.Add([string]$_.Rows[0]) } }
        @($got) | Should -Be @('r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6') -Because 'handed on in bucket order, the late one waited for'
        @($script:Waits) | Should -Be @(3)
        @($script:Widths)[2] | Should -Be 1 -Because 'the wave after a throttled one of 2 is halved to 1'
    }
    It 'never more answers at once than half the free memory holds (measured)' {
        Get-SIEgIdentityMemoryCap -FreeBytes 1000 -PerAnswerBytes 100 | Should -Be 5
        Get-SIEgIdentityMemoryCap -FreeBytes 10 -PerAnswerBytes 100 | Should -Be 1
        Get-SIEgIdentityMemoryCap -FreeBytes -1 -PerAnswerBytes 100 | Should -Be 0 -Because 'unknown memory = no cap'
        $s = [pscustomobject]@{ Concurrency = 5; ThrottledWaves = 0; Cap = 3 }
        Update-SIEgIdentityConcurrency -State $s -Throttled $false | Should -Be 3
    }
    It 'a bucket that fails three times is reported failed (the identities in it UNKNOWN), the others are read' {
        $script:St = @{ 4 = @(400, 400, 400) }
        $send = { param([string[]]$q) New-Outcomes $q $script:St }
        $res = @(Invoke-SIEgIdentityQueriesParallel -Queries $script:Qs -SendMany $send -Sleep { param($s) } -FreeBytes { -1L } | Where-Object { $_.Kind -eq 'result' })[0]
        @($res.Failed).Count | Should -Be 1
        $res.Failed[0].Index | Should -Be 4
    }
    It 'a CUT bucket is never handed on: it is read again through -Split, and the split queries'' answers are' {
        $send = { param($q)
            $l = New-Object System.Collections.Generic.List[object]
            foreach ($x in @($q)) { $rows = @([string]$x); if ([string]$x -eq 'BIG') { $rows = @(1..5) }; $l.Add([pscustomobject]@{ Ok = $true; Rows = $rows; Status = 200 }) }
            , $l.ToArray() }
        $got = New-Object System.Collections.Generic.List[object]
        $res = $null
        Invoke-SIEgIdentityQueriesParallel -Queries @('a', 'BIG') -SendMany $send -Sleep { param($s) } -FreeBytes { -1L } -CutRows 5 -Split { param($i) 'BIG-0'; 'BIG-1' } |
            ForEach-Object { if ($_.Kind -eq 'answer') { foreach ($x in $_.Rows) { $got.Add($x) } } else { $res = $_ } }
        (@($got | ForEach-Object { [string]$_ }) -join ',') | Should -Be 'a,BIG-0,BIG-1'
        [int]$res.Cuts | Should -Be 1
    }
    It 'the SAME index as one query after another -- also when a bucket is asked again and answers late, shared names included' {
        # 12 user nodes in 4 buckets (NodeId mod 4); two pairs share a display name: one after another, the FIRST node in bucket
        # order keeps the name (bucket 0 before 3, 1 before 2). Run once clean and once with bucket 0 throttled first (its
        # answer then arrives after the others): the index must be the same, the shared names too.
        $nodes = @(for ($i = 0; $i -lt 12; $i++) {
            $oid = '{0:d8}-0000-0000-0000-{1:d12}' -f $i, $i
            $name = if ($i -in 3, 8) { 'Shared One' } elseif ($i -in 5, 10) { 'Shared Two' } else { "user $i" }
            [pscustomobject]@{ NodeId = "n$i"; NodeLabel = 'user'; NodeName = $name; Categories = '[]'
                               EntityIds = (ConvertTo-Json -Compress @((ConvertTo-Json -Compress @{ type = 'AadObjectId'; id = $oid })))
                               NodeProperties = (ConvertTo-Json -Compress @{ rawData = @{ accountObjectId = $oid; isActive = $true } }) }
        })
        $answer = { param([string]$q)
            if ($q -match 'count$') { return @([pscustomobject]@{ Count = $(if ($q -match "'user'") { 12 } else { 0 }) }) }
            if ($q -notmatch "'user'") { return @() }
            if ($q -match 'hash\(NodeId, (\d+)\) \| where _bucket == (\d+)') { $n = [int]$Matches[1]; $b = [int]$Matches[2]; return @($nodes | Where-Object { ([int]($_.NodeId.Substring(1)) % $n) -eq $b }) }
            @($nodes)
        }.GetNewClosure()
        $global:SI_EgIdentityPageRows = 3   # 12 nodes -> 4 buckets
        Mock Invoke-SIHuntingQuery { & $answer $Query }
        $run = {
            param([bool]$ThrottleFirst)
            $script:_SICache = @{}
            $script:Thr = $ThrottleFirst
            $script:SIEgIdentitySleep = { param($s) }
            $script:SIEgIdentitySendMany = { param([string[]]$qs) , @(foreach ($q in $qs) {
                if ($script:Thr -and $q -match '_bucket == 0 ') { $script:Thr = $false; [pscustomobject]@{ Ok = $false; Rows = @(); Status = 429; RetryAfter = 1; Error = 'HTTP 429' } }
                else { [pscustomobject]@{ Ok = $true; Rows = @(& $answer $q); Status = 200 } } }) }
            $m = Get-SIExposureGraphIdentities
            $keys = @('shared one', 'shared two', 'user 0', 'n3', 'n8') + @(0..11 | ForEach-Object { '{0:d8}-0000-0000-0000-{1:d12}' -f $_, $_ })
            @(foreach ($k in $keys) { '{0}={1}' -f $k, $(if ($m.ContainsKey($k)) { [string]($m[$k]).NodeId } else { '-' }) })
        }
        try {
            $clean = & $run $false
            $late = & $run $true
            $late | Should -Be $clean
            $clean | Should -Contain 'shared one=n8' -Because 'bucket 0 (n8) comes before bucket 3 (n3), as one after another'
            $clean | Should -Contain 'shared two=n5'
            @($clean | Where-Object { $_ -match '=-$' }).Count | Should -Be 0
        } finally { $global:SI_EgIdentityPageRows = $null; $script:SIEgIdentitySendMany = $null; $script:SIEgIdentitySleep = $null }
    }
}
Describe 'A4: every Log Analytics query asks to wait its maximum' {
    It 'Invoke-SILaQuery and its paged read default to Prefer: wait=600' {
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\_shared\SI-AzRest.ps1'))
        ([regex]::Matches($src, [regex]::Escape("if (`$Wait -le 0) { `$Wait = 600 }"))).Count | Should -Be 2
    }
}
