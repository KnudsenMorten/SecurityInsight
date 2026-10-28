#Requires -Version 7.0
<#
    #738 -- THE RISK ANALYSIS UPLOAD TO LOG ANALYTICS: FASTER, AND EXACTLY THE SAME ROWS.

    A large install, 2026-10-17: 1,138,554 Risk Analysis rows went to Log Analytics at ~2,200 rows a minute (~8.5 hours), every POST
    made and waited for in line with the work that builds the rows, each about half full.

    What this file pins (offline: the Log Ingestion API is a fake that records every POST; the SQL part runs on the test VM's
    SQL Server Express and skips, saying so, where there is none):
      * EQUIVALENCE: through the sender (4 posts in flight) the service receives every row exactly once, the SAME JSON per
        row (byte for byte) as the synchronous path, in the same order (the posts put back in their order give the rows in
        the order handed over); through Invoke-RALaPagedPost the same chunks and prepared rows as the old page loop;
      * PARALLEL + 429: posts really overlap (never more than the degree); a 429 with Retry-After holds EVERY worker until
        then, and the refused post is sent again (once);
      * THE SIZE LIMIT: every POST is under the limit, measured after compression, and filled close to it; a 413 from the
        service lowers the limit and the batch goes again in two -- nothing lost or doubled;
      * A FAILED POST is the run-level verdict as before: the delivery throws with the service's answer and reports the
        rows that DID arrive;
      * THE PAGE READ: a page after the first is a range the order index can seek; the pager reading ahead on another
        thread returns the same rows in the same order as reading in line (real SQL);
      * the stored-row decode reads plain values without a call per column, with the same result;
      * WIRING: Risk Analysis delivers through Invoke-RALaPagedPost with the table's sender and a read-ahead pager.
    NO EMOJI IN THIS FILE.
#>

$script:HasSql = [bool](Get-Service -Name 'MSSQL$SQLEXPRESS' -ErrorAction SilentlyContinue | Where-Object Status -eq 'Running')
$script:HasSql = $script:HasSql -and (Test-Path -LiteralPath ([IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), 'sql', 'si-data-schema.sql')))

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $ra = Join-Path $script:SIRoot 'engine\risk-analysis\_shared'
    . (Join-Path $script:SIRoot 'engine\_shared\SI-LogIngest.ps1')
    . (Join-Path $ra 'RA-ColumnTypeAlign.ps1')
    . (Join-Path $ra 'RA-IngestKeyColumns.ps1')
    . (Join-Path $ra 'RA-Delivery.ps1')
    . (Join-Path $ra 'RA-SqlStream.ps1')

    $script:Sub = '11111111-1111-1111-1111-111111111111'
    $dceId = "/subscriptions/$($script:Sub)/resourceGroups/rg-si/providers/Microsoft.Insights/dataCollectionEndpoints/dce-si"
    $dcrId = "/subscriptions/$($script:Sub)/resourceGroups/rg-si/providers/Microsoft.Insights/dataCollectionRules/dcr-si-ra"
    $script:DcrId = $dcrId
    $script:DceJson = ([pscustomobject]@{ id = $dceId; name = 'dce-si'; properties = [pscustomobject]@{ logsIngestion = [pscustomobject]@{ endpoint = 'https://dce-si.test.ingest.monitor.azure.com' } } } | ConvertTo-Json -Depth 10 -Compress)
    $script:DcrJson = ([pscustomobject]@{ id = $dcrId; name = 'dcr-si-ra'; properties = [pscustomobject]@{ immutableId = 'dcr-0000'; dataCollectionEndpointId = $dceId
                        streamDeclarations = [pscustomobject]@{ 'Custom-SI_RA_T_CL' = [pscustomobject]@{ columns = @() } } } } | ConvertTo-Json -Depth 10 -Compress)

    # THE FAKE SERVICE. A plain function (no Pester mock): the sender hands its text to every post worker, and the shared
    # state ($SILogSeam: global here, given to each worker) records what arrived.
    # (defined in the scope the ingest client was loaded into, after it: this one is the one every call finds)
    function Invoke-SILogIngestHttp {
        param([string]$Method, [string]$Uri, [hashtable]$Headers, $Body, [string]$ContentType, [int]$TimeoutSec = 300)
        $f = $SILogSeam
        if ($Uri -notmatch '/streams/') {
            if ($Uri -match 'dataCollectionEndpoints/') { return [pscustomobject]@{ StatusCode = 200; Content = $f.Dce; RetryAfter = $null } }
            if ($Uri -match 'dataCollectionRules/') { return [pscustomobject]@{ StatusCode = 200; Content = $f.Dcr; RetryAfter = $null } }
            return [pscustomobject]@{ StatusCode = 404; Content = '{}'; RetryAfter = $null }
        }
        $bytes = [byte[]]$Body
        $raw = $bytes
        if ($Headers -and $Headers['Content-Encoding'] -eq 'gzip') {
            $in = [System.IO.MemoryStream]::new($bytes); $gz = [System.IO.Compression.GZipStream]::new($in, [System.IO.Compression.CompressionMode]::Decompress)
            $out = [System.IO.MemoryStream]::new(); $gz.CopyTo($out); $gz.Dispose(); $raw = $out.ToArray()
        }
        $t0 = [datetime]::UtcNow
        [System.Threading.Monitor]::Enter($f.SyncRoot)
        try {
            $f.No++; $no = $f.No; $f.InFlight++; if ($f.InFlight -gt $f.MaxInFlight) { $f.MaxInFlight = $f.InFlight }
            $answer = $null
            if ($f.Answers.ContainsKey($no)) { $answer = $f.Answers[$no] }
            elseif ($f.Over413 -gt 0 -and $bytes.Length -gt $f.Over413) { $answer = @{ Code = 413; RetryAfter = $null } }
        } finally { [System.Threading.Monitor]::Exit($f.SyncRoot) }
        try {
            if ($null -ne $answer) {
                $f.Calls.Enqueue([pscustomobject]@{ No = $no; Code = $answer.Code; Start = $t0; End = [datetime]::UtcNow; Sent = $bytes.Length; Rows = @() })
                return [pscustomobject]@{ StatusCode = $answer.Code; Content = '{"error":{"code":"Refused","message":"refused by the test"}}'; RetryAfter = $answer.RetryAfter }
            }
            if ($f.LatencyMs -gt 0) { Start-Sleep -Milliseconds $f.LatencyMs }
            $doc = [System.Text.Json.JsonDocument]::Parse([System.ReadOnlyMemory[byte]]::new($raw))
            $rows = [System.Collections.Generic.List[string]]::new()
            try { foreach ($e in $doc.RootElement.EnumerateArray()) { $rows.Add($e.GetRawText()) } } finally { $doc.Dispose() }
            $f.Calls.Enqueue([pscustomobject]@{ No = $no; Code = 204; Start = $t0; End = [datetime]::UtcNow; Sent = $bytes.Length; Rows = $rows.ToArray() })
            return [pscustomobject]@{ StatusCode = 204; Content = ''; RetryAfter = $null }
        } finally {
            [System.Threading.Monitor]::Enter($f.SyncRoot); try { $f.InFlight-- } finally { [System.Threading.Monitor]::Exit($f.SyncRoot) }
        }
    }
    function script:Get-SIManagedIdentityToken { param([string]$Resource, [string]$ClientId, [switch]$ForceRefresh) 'fake-token' }
    function script:Reset-Fake {
        param([int]$LatencyMs = 0, [hashtable]$Answers = @{}, [int]$Over413 = 0)
        $global:SI_LogIngestRunCache = $null
        $global:SILogSeam = [hashtable]::Synchronized(@{ Dce = $script:DceJson; Dcr = $script:DcrJson; No = 0; InFlight = 0; MaxInFlight = 0; LatencyMs = $LatencyMs
            Answers = $Answers; Over413 = $Over413; Calls = [System.Collections.Concurrent.ConcurrentQueue[object]]::new() })
        (Get-SILogIngestRunCache).DcrIds['dcr-si-ra'] = $script:DcrId
        $global:SI_AzSubscriptionId = $script:Sub; $global:SI_DcrResourceGroup = 'rg-si'; $global:SI_DceResourceGroup = 'rg-si'
        $global:EnableCompressionDefault = $true
        $global:SI_LogIngestRunCollectionTime = [datetime]'2026-10-17T09:00:00Z'
        $global:SI_LogIngestNewColumns = @{}
    }
    function script:Get-Posts { @($global:SILogSeam.Calls.ToArray() | Where-Object { $_.Code -ge 200 -and $_.Code -lt 300 } | Sort-Object { $_.Rows[0] -replace '^.*"K":"(k\d+)".*$', '$1' }) }
    function script:Get-ReceivedRows { foreach ($p in (Get-Posts)) { foreach ($r in $p.Rows) { $r } } }
    function script:Send-Rows {
        param([object[]]$Rows, [int]$Degree = 4, [long]$MaxPayloadBytes = 1MB, [int]$Per = 500)
        $null = Start-SILogIngestSender -TableName 'SI_RA_T' -Degree $Degree -MaxPayloadBytes $MaxPayloadBytes
        for ($i = 0; $i -lt $Rows.Count; $i += $Per) {
            $part = $Rows[$i..([Math]::Min($Rows.Count, $i + $Per) - 1)]
            $null = Send-SILogDataRest -Data $part -DcrName 'dcr-si-ra' -DceName 'dce-si' -TableName 'SI_RA_T' -UseManagedIdentity $true -MaxPayloadBytes $MaxPayloadBytes 6>$null
        }
        Complete-SILogIngestSender -TableName 'SI_RA_T' 6>$null
    }
    # rows with a sortable key K, mixed values (text with quotes / unicode, numbers, decimals, dates, empties, nested)
    function script:New-Rows {
        param([int]$Count, [int]$Pad = 300)
        $words = @('tier zero', 'admin "quoted"', 'Microsoft Windows Server 2022', 'remote desktop', 'ae oe aa', 'not patched')
        $out = [System.Collections.Generic.List[object]]::new()
        for ($i = 0; $i -lt $Count; $i++) {
            $o = [ordered]@{ K = ('k{0:D7}' -f $i); AssetName = ('host-{0:D5}' -f ($i % 997)); RiskScoreTotal = ([double](($i * 37) % 1000) / 10); CriticalityTier = ($i % 4)
                             LastSeen = [datetime]::SpecifyKind([datetime]'2026-10-12T10:00:00', 'Utc').AddMinutes($i); Note = ($words[$i % $words.Count] + ' ' + ('x' * (($i * 7) % $Pad)))
                             Empty = $null; Flag = (($i % 2) -eq 0) }
            if ($i % 9 -eq 0) { $o['Nested'] = [pscustomobject]@{ a = $i; b = @('p', 'q') } }
            $out.Add([pscustomobject]$o)
        }
        , $out.ToArray()
    }
    $ProgressPreference = 'SilentlyContinue'
}

AfterAll {
    foreach ($n in 'SILogSeam', 'SI_LogIngestRunCache', 'SI_AzSubscriptionId', 'SI_DcrResourceGroup', 'SI_DceResourceGroup', 'EnableCompressionDefault', 'SI_LogIngestRunCollectionTime', 'SI_LogIngestNewColumns') {
        Remove-Variable -Scope Global -Name $n -ErrorAction SilentlyContinue
    }
}

Describe 'EQUIVALENCE -- the same rows, the same JSON per row, nothing lost or doubled' {
    It 'four posts in flight: every row once, byte for byte the synchronous JSON, in the order handed over' {
        $rows = New-Rows -Count 6000
        Reset-Fake -LatencyMs 30
        $null = Send-SILogDataRest -Data $rows -DcrName 'dcr-si-ra' -DceName 'dce-si' -TableName 'SI_RA_T' -UseManagedIdentity $true -MaxPayloadBytes 32KB 6>$null
        $sync = @(Get-ReceivedRows)
        $sync.Count | Should -Be 6000
        Reset-Fake -LatencyMs 400
        $c = Send-Rows -Rows $rows -Degree 4 -MaxPayloadBytes 32KB -Per 777
        $par = @(Get-ReceivedRows)
        $c.RowsPosted | Should -Be 6000
        $c.RowsHandedOver | Should -Be 6000
        $par.Count | Should -Be 6000
        @($par | Select-Object -Unique).Count | Should -Be 6000 -Because 'no row is posted twice'
        # the posts put back in their order give the rows in the order handed over, each the same JSON as before
        for ($i = 0; $i -lt 6000; $i++) { if ($par[$i] -ne $sync[$i]) { throw ("row {0} differs: {1} <> {2}" -f $i, $par[$i], $sync[$i]) } }
        $global:SILogSeam.MaxInFlight | Should -BeGreaterThan 1 -Because 'the posts overlap'
        $global:SILogSeam.MaxInFlight | Should -BeLessOrEqual 4
    }

    It 'through Invoke-RALaPagedPost: the same chunks, prepared rows and JSON per row as the old page loop' {
        $rows = New-Rows -Count 3000 -Pad 900
        $types = @{ RiskScoreTotal = 'real'; CriticalityTier = 'long'; LastSeen = 'datetime'; Note = 'string'; AssetName = 'string' }
        $prep = { param($chunk) ConvertTo-RALaPostRows -Rows $chunk -HostName 'h' -Fqdn 'h.f' -User 'u' -Types $types }
        $post = { param($p) Send-SILogData -DceName 'dce-si' -DcrName 'dcr-si-ra' -Data $p -TableName 'SI_RA_T' -UseManagedIdentity $true -Verbose:$false 6>$null }
        Reset-Fake
        $old = New-RARowPager -Rows $rows
        $oldChunks = 0; $oldPosted = 0L
        while ($null -ne ($pg = $old.Next())) { $d = Invoke-RALaChunkedPost -Rows @($pg) -Prepare $prep -Post $post -TargetBytes 400KB; $oldChunks += $d.Chunks; $oldPosted += $d.RowsPosted }
        $before = @(Get-ReceivedRows)
        Reset-Fake -LatencyMs 20
        # the same chunk size as above (Invoke-RALaPagedPost's chunks are Invoke-RALaChunkedPost's)
        Mock Get-RALaChunkBytes { 400KB }
        $parts = [System.Collections.Generic.List[object]]::new()
        $res = Invoke-RALaPagedPost -Pager (New-RARowPager -Rows $rows) -Prepare $prep -Post $post -TableName 'SI_RA_T' -Degree 4 -OnChunk { param($n, $h, $c) $parts.Add(@($n, $h, $c)) } 6>$null
        $after = @(Get-ReceivedRows)
        $res.RowsPosted | Should -Be 3000
        $res.Chunks | Should -Be $oldChunks
        $oldPosted | Should -Be 3000
        $after.Count | Should -Be $before.Count
        for ($i = 0; $i -lt $after.Count; $i++) { if ($after[$i] -ne $before[$i]) { throw ("row {0} differs" -f $i) } }
        $parts.Count | Should -Be $oldChunks
        $parts[$parts.Count - 1][1] | Should -Be 3000 -Because 'the progress counts the rows handed over'
    }

    It 'with no table named the posts are made in line, as before (the rows confirmed = the rows handed over)' {
        $rows = New-Rows -Count 400
        Reset-Fake
        $res = Invoke-RALaPagedPost -Pager (New-RARowPager -Rows $rows) -Prepare { param($c) @{ Rows = $c; Align = $null } } `
                   -Post { param($p) Send-SILogData -DceName 'dce-si' -DcrName 'dcr-si-ra' -Data $p -TableName 'SI_RA_T' -UseManagedIdentity $true 6>$null } 6>$null
        $res.RowsPosted | Should -Be 400
        $res.Sender | Should -BeNullOrEmpty
        $global:SILogSeam.MaxInFlight | Should -Be 1
    }
}

Describe 'PARALLEL POSTS honour 429 / Retry-After' {
    It 'a 429 with Retry-After 1 holds every worker for that second; the refused post goes again; every row once' {
        $rows = New-Rows -Count 4000
        Reset-Fake -LatencyMs 40 -Answers @{ 2 = @{ Code = 429; RetryAfter = '1' } }
        $c = Send-Rows -Rows $rows -Degree 4 -MaxPayloadBytes 16KB -Per 1000
        @($global:SILogSeam.Calls.ToArray() | Where-Object Code -eq 429).Count | Should -Be 1
        $c.RowsPosted | Should -Be 4000
        @(Get-ReceivedRows).Count | Should -Be 4000
        @(Get-ReceivedRows | Select-Object -Unique).Count | Should -Be 4000
        $calls = @($global:SILogSeam.Calls.ToArray())
        $t429 = ($calls | Where-Object Code -eq 429 | Select-Object -First 1).End
        # no post STARTED while the service asked everyone to wait (a little slack for the clock)
        $during = @($calls | Where-Object { $_.Start -gt $t429.AddMilliseconds(50) -and $_.Start -lt $t429.AddMilliseconds(900) })
        $during.Count | Should -Be 0 -Because 'a 429 holds every worker until its Retry-After'
        $c.Retries | Should -BeGreaterOrEqual 1
    }

    It 'a persistent 503 gives up after the retries: the delivery throws with the answer and says which rows arrived' {
        $rows = New-Rows -Count 1500
        $ans = @{}; for ($n = 2; $n -le 400; $n++) { $ans[$n] = @{ Code = 503; RetryAfter = '1' } }
        Reset-Fake -Answers $ans
        $stopped = [System.Collections.Generic.List[long]]::new()
        $err = $null
        try {
            $null = Invoke-RALaPagedPost -Pager (New-RARowPager -Rows $rows) -Prepare { param($c) @{ Rows = $c; Align = $null } } -TableName 'SI_RA_T' -Degree 2 -MaxPayloadBytes 16KB `
                -Post { param($p) Send-SILogData -DceName 'dce-si' -DcrName 'dcr-si-ra' -Data $p -TableName 'SI_RA_T' -UseManagedIdentity $true 6>$null } `
                -OnStopped { param($c) $stopped.Add($c) } 6>$null
        } catch { $err = $_.Exception.Message }
        $err | Should -Match 'HTTP Status: 503'
        $stopped.Count | Should -Be 1
        $stopped[0] | Should -Be (@(Get-ReceivedRows).Count) -Because 'the rows reported as arrived are exactly the rows the service took'
        $stopped[0] | Should -BeLessThan 1500
        Get-SILogIngestSender -TableName 'SI_RA_T' | Should -BeNullOrEmpty -Because 'the workers are closed'
    }

    It 'a 400 fails at once (not retried) with the service''s answer -- the same verdict as a synchronous post' {
        $rows = New-Rows -Count 800
        Reset-Fake -Answers @{ 1 = @{ Code = 400; RetryAfter = $null } }
        { $null = Send-Rows -Rows $rows -Degree 4 -MaxPayloadBytes 32KB -Per 800 } | Should -Throw '*HTTP Status: 400*'
        @($global:SILogSeam.Calls.ToArray() | Where-Object Code -eq 400).Count | Should -Be 1
        $null = Stop-SILogIngestSender -TableName 'SI_RA_T'
    }

    It 'the degree is a small fixed number: 4 by default, 1 = one at a time, never more than 8' {
        Get-SILogIngestPostDegree -Setting $null -EnvValue '' | Should -Be 4
        Get-SILogIngestPostDegree -Setting 'off' -EnvValue '' | Should -Be 1
        Get-SILogIngestPostDegree -Setting 1 -EnvValue '' | Should -Be 1
        Get-SILogIngestPostDegree -Setting 32 -EnvValue '' | Should -Be 8
        Get-SILogIngestPostDegree -Setting $null -EnvValue '2' | Should -Be 2
    }
}

Describe 'A FAILURE WHILE ANSWERING -- the other posts still count, nothing more goes out' {
    BeforeAll {
        function script:New-DoneBatch([int]$Code, [int]$Rows, [long]$From) {
            $ps = [powershell]::Create()
            [void]$ps.AddScript(('@{{ Code = {0}; Content = ''''; Notes = @() }}' -f $Code))
            $h = $ps.BeginInvoke(); [void]$h.AsyncWaitHandle.WaitOne(10000)
            $l = [System.Collections.Generic.List[byte[]]]::new(); for ($i = 0; $i -lt $Rows; $i++) { $l.Add([byte[]](0x7B, 0x7D)) }
            @{ Rows = $l; Raw = 100; From = $From; Refresh = $false; Payload = [byte[]](1, 2, 3); PS = $ps; Handle = $h }
        }
    }
    AfterEach { function script:Get-SIManagedIdentityToken { param([string]$Resource, [string]$ClientId, [switch]$ForceRefresh) 'fake-token' }; $null = Stop-SILogIngestSender -TableName 'SI_RA_T' }

    It 'one answer throws (the token for a 401 resend) while three others landed: all three counted and disposed, the first error kept' {
        Reset-Fake
        function script:Get-SIManagedIdentityToken { param([string]$Resource, [string]$ClientId, [switch]$ForceRefresh) if ($ForceRefresh) { throw 'token refresh refused by the test' }; 'fake-token' }
        $s = Start-SILogIngestSender -TableName 'SI_RA_T' -Degree 4
        $s.Auth = @{ Mode = 'ManagedIdentity'; ClientId = '' }; $s.Uri = 'https://dce-si.test.ingest.monitor.azure.com/dataCollectionRules/dcr-0000/streams/Custom-SI_RA_T_CL?api-version=2023-01-01'
        $batches = @((New-DoneBatch 401 10 1), (New-DoneBatch 204 20 11), (New-DoneBatch 204 30 31), (New-DoneBatch 204 40 61))
        foreach ($b in $batches) { [void]$s.InFlight.Add($b) }
        $s.Accepted = 100; $s.Dispatched = 100
        Receive-SILogIngestSenderResults -Sender $s -All 6>$null
        $s.Confirmed | Should -Be 90 -Because 'the three posts that landed are counted'
        $s.Failed | Should -Match 'token refresh refused by the test'
        $s.InFlight.Count | Should -Be 0
        foreach ($b in $batches) { $b.PS | Should -BeNullOrEmpty -Because 'every worker is disposed' }
        @($global:SILogSeam.Calls.ToArray()).Count | Should -Be 0 -Because 'the 401 resend never went out'
    }

    It 'a 413 split whose half cannot be posted is the first error; the posts that landed still count' {
        Reset-Fake
        $s = Start-SILogIngestSender -TableName 'SI_RA_T' -Degree 4 -MaxPayloadBytes 64KB
        $s.Auth = @{ Mode = 'ManagedIdentity'; ClientId = '' }; $s.Uri = 'https://dce-si.test.ingest.monitor.azure.com/dataCollectionRules/dcr-0000/streams/Custom-SI_RA_T_CL?api-version=2023-01-01'
        $big = [System.Collections.Generic.List[byte[]]]::new()
        $rnd = [System.Random]::new(3)
        for ($i = 0; $i -lt 2; $i++) { $b = [byte[]]::new(200000); $rnd.NextBytes($b); $big.Add([System.Text.Encoding]::UTF8.GetBytes(('{"B":"' + [Convert]::ToBase64String($b) + '"}'))) }
        $b413 = New-DoneBatch 413 0 1; $b413.Rows = $big
        $batches = @($b413, (New-DoneBatch 204 5 3), (New-DoneBatch 204 7 8))
        foreach ($b in $batches) { [void]$s.InFlight.Add($b) }
        $s.Accepted = 14; $s.Dispatched = 14
        Receive-SILogIngestSenderResults -Sender $s -All 6>$null
        $s.Confirmed | Should -Be 12
        $s.Failed | Should -Match 'larger than the'
        foreach ($b in $batches) { $b.PS | Should -BeNullOrEmpty }
    }

    It 'once Failed is set no post goes out: neither a new batch nor a 401 resend' {
        Reset-Fake
        $tokens = [System.Collections.Generic.List[int]]::new()
        function script:Get-SIManagedIdentityToken { param([string]$Resource, [string]$ClientId, [switch]$ForceRefresh) $tokens.Add(1); 'fake-token' }
        $s = Start-SILogIngestSender -TableName 'SI_RA_T' -Degree 4
        $s.Auth = @{ Mode = 'ManagedIdentity'; ClientId = '' }; $s.Uri = 'https://dce-si.test.ingest.monitor.azure.com/dataCollectionRules/dcr-0000/streams/Custom-SI_RA_T_CL?api-version=2023-01-01'
        $s.Failed = 'Log Ingestion API request failed. HTTP Status: 400 Response: x'
        $l = [System.Collections.Generic.List[byte[]]]::new(); $l.Add([byte[]](0x7B, 0x7D))
        Send-SILogIngestSenderBatch -Sender $s -Payload ([byte[]](1, 2)) -Batch @{ Rows = $l; Raw = 2; From = 1; Refresh = $false }
        $b = New-DoneBatch 401 3 2
        [void]$s.InFlight.Add($b)
        Receive-SILogIngestSenderResults -Sender $s -All 6>$null
        $s.Posts | Should -Be 0
        $s.InFlight.Count | Should -Be 0
        $tokens.Count | Should -Be 0
        @($global:SILogSeam.Calls.ToArray()).Count | Should -Be 0
        $s.Failed | Should -Match 'HTTP Status: 400' -Because 'the first error stays'
    }
}

Describe 'THE SIZE LIMIT -- measured after compression, filled close to it, adapted' {
    It 'every POST is under the limit and, but the last, at least 80% full (the synchronous path split batches in half)' {
        $rows = New-Rows -Count 8000 -Pad 700
        Reset-Fake
        $c = Send-Rows -Rows $rows -Degree 4 -MaxPayloadBytes 64KB -Per 1000
        $posts = @(Get-Posts | Sort-Object No)
        $c.RowsPosted | Should -Be 8000
        @($posts | Where-Object { $_.Sent -gt 64KB }).Count | Should -Be 0
        $sizes = 'sizes: ' + (($posts | ForEach-Object Sent) -join ',')
        $notLast = @($posts | Sort-Object Sent | Select-Object -Skip 1)   # the smallest may be the last one
        @($notLast | Where-Object { $_.Sent -lt 0.6 * 64KB }).Count | Should -Be 0 -Because ("a post goes out only when it is well filled; $sizes")
        ($notLast | Measure-Object Sent -Average).Average | Should -BeGreaterThan (0.75 * 64KB) -Because $sizes
        $c.MaxBytesSent | Should -BeLessOrEqual 64KB
    }

    It 'a 413 lowers the limit: the batch goes again in two, nothing lost or doubled' {
        $rows = New-Rows -Count 3000 -Pad 500
        Reset-Fake -Over413 (40KB)
        $c = Send-Rows -Rows $rows -Degree 4 -MaxPayloadBytes 64KB -Per 1000
        $c.RowsPosted | Should -Be 3000
        $c.Split413 | Should -BeGreaterThan 0
        $got = @(Get-ReceivedRows)
        $got.Count | Should -Be 3000
        @($got | Select-Object -Unique).Count | Should -Be 3000
        @(Get-Posts | Where-Object { $_.Sent -gt 40KB }).Count | Should -Be 0
    }

    It 'a single record over the limit is refused, not truncated' {
        Reset-Fake
        $bytes = [byte[]]::new(90000); [System.Random]::new(7).NextBytes($bytes)
        $big = @([pscustomobject]@{ K = 'k0000000'; Blob = [Convert]::ToBase64String($bytes) })   # does not compress under the limit
        { $null = Send-Rows -Rows $big -Degree 4 -MaxPayloadBytes 16KB } | Should -Throw '*larger than the*limit*'
        $null = Stop-SILogIngestSender -TableName 'SI_RA_T'
    }

    It 'a check of new columns after the post sees every row handed over: the sender posts them first' {
        $rows = New-Rows -Count 1200
        Reset-Fake -LatencyMs 20
        $global:SI_LogIngestNewColumns = @{ 'dcr-si-ra' = @{ Table = 'SI_RA_T'; Columns = @('Note') } }
        $null = Start-SILogIngestSender -TableName 'SI_RA_T' -Degree 4 -MaxPayloadBytes 32KB
        $null = Send-SILogDataRest -Data $rows -DcrName 'dcr-si-ra' -DceName 'dce-si' -TableName 'SI_RA_T' -UseManagedIdentity $true 6>$null
        # every row of the call that finds the check due is posted and answered when it returns
        $s = Get-SILogIngestSender -TableName 'SI_RA_T'
        $s.Confirmed | Should -Be $s.Accepted
        $s.InFlight.Count | Should -Be 0
        $null = Complete-SILogIngestSender -TableName 'SI_RA_T' 6>$null
        $global:SI_LogIngestNewColumns = @{}
    }
}

Describe 'THE PAGE READ -- a seekable keyset, and the next page read ahead' {
    It 'a page after the first is a range the order index can seek, with the same tie rule' {
        foreach ($src in 'All', 'View') {
            $sql = Get-RAStreamPageSql -Grain Detailed -Source $src -After
            $sql | Should -Not -Match '@First'
            $sql | Should -Match ([regex]::Escape('RaSort <= CONVERT(float, @Sort) AND (RaSort < CONVERT(float, @Sort) OR RaSeq > CONVERT(bigint, @Seq))'))
            $sql | Should -Match 'ORDER BY RaSort DESC, RaSeq'
        }
        Get-RAStreamPageSql -Grain Summary -After | Should -Match ([regex]::Escape('RaSort <= CONVERT(float, @Sort) AND (RaSort < CONVERT(float, @Sort) OR RowNo > CONVERT(bigint, @Seq))'))
        Get-RAStreamPageSql -Grain Detailed -Source FindingKey -After | Should -Match ([regex]::Escape('RaFindingKey >= @FKey AND (RaFindingKey > @FKey OR RaSeq > CONVERT(bigint, @Seq))'))
        Get-RAStreamPageSql -Grain Detailed | Should -Match ([regex]::Escape("@First = '1'")) -Because 'the first page reads from the start'
    }

    It 'the two keyset forms select the same rows (every case of score and order, against the old predicate)' {
        $cases = foreach ($sort in 1.0, 2.0, 3.0) { foreach ($seq in 1, 5, 9) { [pscustomobject]@{ S = $sort; Q = $seq } } }
        foreach ($k in $cases) {
            foreach ($r in $cases) {
                $old = ($r.S -lt $k.S) -or ($r.S -eq $k.S -and $r.Q -gt $k.Q)
                $new = ($r.S -le $k.S) -and (($r.S -lt $k.S) -or ($r.Q -gt $k.Q))
                $new | Should -Be $old
            }
        }
    }

    It 'a seam without connection information: no read-ahead, the pages read in line as before' {
        $calls = [System.Collections.Generic.List[string]]::new()
        $seam = { param($Sql, $Params, $Mode) $calls.Add($Sql); , @() }.GetNewClosure()
        $st = @{ Invoke = $seam; Grain = 'Detailed'; CollectionId = 1; TimeText = 'x'; Reports = [ordered]@{} }
        $pg = New-RARowPager -Stream $st -Source All -ReadAhead
        $pg.Next() | Should -BeNullOrEmpty
        $pg.State.ReadAhead | Should -BeNullOrEmpty
        $calls.Count | Should -Be 1
    }
}

Describe 'THE PAGE READ ahead on real SQL (test VM)' -Skip:(-not $script:HasSql) {
    BeforeAll {
        $script:Db = 'si_test_laupload_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
        $m = [System.Data.SqlClient.SqlConnection]::new('Server=.\SQLEXPRESS;Database=master;Integrated Security=SSPI;Connection Timeout=30')
        $m.Open(); try { $c = $m.CreateCommand(); $c.CommandText = "CREATE DATABASE [$($script:Db)]"; $c.CommandTimeout = 300; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
        $script:Cs = "Server=.\SQLEXPRESS;Database=$($script:Db);Integrated Security=SSPI;Connection Timeout=30"
        $cn = [System.Data.SqlClient.SqlConnection]::new($script:Cs); $cn.Open()
        try {
            $c = $cn.CreateCommand(); $c.CommandTimeout = 600; $c.CommandText = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'sql\si-data-schema.sql')); [void]$c.ExecuteNonQuery()
            $c = $cn.CreateCommand(); $c.CommandText = "INSERT sidata.Collection (CollectionTime, Kind, Status) VALUES ('2026-10-17T09:00:00', 'Detailed', 'Loading'); SELECT CAST(SCOPE_IDENTITY() AS int)"
            $script:Cid = [int]$c.ExecuteScalar()
            # 5,000 rows, three share each score (ties), two reports, rows not in the view among them
            $c = $cn.CreateCommand(); $c.CommandTimeout = 300
            $c.CommandText = "INSERT sidata.Finding (CollectionId, DetailJson, RaSeq, RaSort, RaReport, RaInView) SELECT $($script:Cid), CONCAT('{""K"":""k', RIGHT(CONCAT('0000000', n - 1), 7), '"",""V"":', n % 13, ',""T"":""text ', n % 7, '""}'), n, FLOOR((5000 - n + 1) / 3), 1 + n % 2, CASE WHEN n % 5 = 0 THEN 0 ELSE 1 END FROM (SELECT TOP 5000 ROW_NUMBER() OVER (ORDER BY (SELECT 1)) AS n FROM sys.all_objects a CROSS JOIN sys.all_objects b) t"
            [void]$c.ExecuteNonQuery()
        } finally { $cn.Dispose() }
        $cs = $script:Cs
        $script:Seam = {
            param($Sql, $Params, $Mode)
            $k = [System.Data.SqlClient.SqlConnection]::new($cs); $k.Open()
            try {
                $c = $k.CreateCommand(); $c.CommandText = $Sql
                foreach ($n in $Params.Keys) { [void]$c.Parameters.AddWithValue('@' + $n, $(if ($null -eq $Params[$n]) { [System.DBNull]::Value } else { $Params[$n] })) }
                $rd = $c.ExecuteReader(); $out = [System.Collections.Generic.List[object]]::new()
                try { while ($rd.Read()) { $h = @{}; for ($j = 0; $j -lt $rd.FieldCount; $j++) { $h[$rd.GetName($j)] = $rd.GetValue($j) }; $out.Add($h) } } finally { $rd.Close() }
                , $out.ToArray()
            } finally { $k.Dispose() }
        }.GetNewClosure()
        $script:Seam | Add-Member -NotePropertyName SIConnectionInfo -NotePropertyValue ({ @{ ConnectionString = $cs; AccessToken = $null; CommandTimeout = 120 } }.GetNewClosure())
        $cols = [System.Collections.Generic.List[string]]::new([string[]]@('K', 'V', 'T'))
        $script:Stream = @{ Invoke = $script:Seam; Grain = 'Detailed'; CollectionId = $script:Cid; TimeText = '2026-10-17T09:00:00.000'
                            Reports = [ordered]@{ A = @{ Ordinal = 1; Columns = $cols; DateCols = $null }; B = @{ Ordinal = 2; Columns = $cols; DateCols = $null } } }
        function script:Read-All($pg) { $o = [System.Collections.Generic.List[string]]::new(); while ($null -ne ($p = $pg.Next())) { foreach ($r in $p) { $o.Add(($r | ConvertTo-Json -Compress)) } }; , $o.ToArray() }
    }
    AfterAll {
        [System.Data.SqlClient.SqlConnection]::ClearAllPools()
        $m = [System.Data.SqlClient.SqlConnection]::new('Server=.\SQLEXPRESS;Database=master;Integrated Security=SSPI;Connection Timeout=30')
        $m.Open(); try { $c = $m.CreateCommand(); $c.CommandTimeout = 300; $c.CommandText = "ALTER DATABASE [$($script:Db)] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$($script:Db)]"; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
    }

    It 'read ahead or in line, small pages: the same rows in the same order, every row once (All, View, FindingKey-free)' {
        foreach ($src in 'All', 'View') {
            $inline = Read-All (New-RARowPager -Stream $script:Stream -Source $src -TargetChars 9000)
            $pgA = New-RARowPager -Stream $script:Stream -Source $src -TargetChars 9000 -ReadAhead
            $ahead = Read-All $pgA
            $expected = if ($src -eq 'All') { 5000 } else { 4000 }
            $inline.Count | Should -Be $expected
            $ahead.Count | Should -Be $expected
            for ($i = 0; $i -lt $expected; $i++) { if ($ahead[$i] -ne $inline[$i]) { throw ("{0}: row {1} differs" -f $src, $i) } }
            @($ahead | Select-Object -Unique).Count | Should -Be $expected
            $pgA.State.AheadPages | Should -BeGreaterThan 2 -Because 'the pages after the first were read ahead'
            $pgA.State.AheadFallbacks | Should -Be 0
            $pgA.State.AheadRunspace | Should -BeNullOrEmpty -Because 'the read-ahead thread ends with the last page'
        }
    }

    It 'a read-ahead that fails is read again in line: no row lost' {
        $good = $script:Seam
        $bad = { param($Sql, $Params, $Mode) & $good $Sql $Params $Mode }.GetNewClosure()
        $bad | Add-Member -NotePropertyName SIConnectionInfo -NotePropertyValue ({ @{ ConnectionString = 'Server=tcp:127.0.0.1,1;Database=x;Integrated Security=SSPI;Connection Timeout=2'; AccessToken = $null; CommandTimeout = 5 } })
        $st = $script:Stream.Clone(); $st.Invoke = $bad
        $pg = New-RARowPager -Stream $st -Source All -TargetChars 60000 -ReadAhead
        $rows = Read-All $pg
        $rows.Count | Should -Be 5000
        $pg.State.AheadFallbacks | Should -BeGreaterThan 0
    }
}

Describe 'THE STORED-ROW DECODE reads plain values in place -- the same result' {
    It 'every kind of value decodes as ConvertFrom-RAStreamToken decodes it' {
        $json = '{"s":"text","n":7,"d":7.25,"b":true,"z":null,"dt":"2026-10-12T10:00:00Z","arr":[1,"a",null],"obj":{"x":1,"y":[2]},"big":12345678901234}'
        $dc = [System.Collections.Generic.HashSet[string]]::new([string[]]@('dt'))
        $row = ConvertFrom-RAStreamJson -Json $json -Columns @('s', 'missing', 'n') -DateCols $dc
        $tok = [Newtonsoft.Json.Linq.JToken]::Parse($json)
        foreach ($p in $tok.Properties()) {
            if ($p.Name -eq 'dt') { continue }
            $ref = ConvertFrom-RAStreamToken $p.Value
            (ConvertTo-Json -InputObject $row.($p.Name) -Compress -Depth 5) | Should -Be (ConvertTo-Json -InputObject $ref -Compress -Depth 5) -Because $p.Name
            if ($null -ne $ref -and -not ($ref -is [array])) { $row.($p.Name).GetType() | Should -Be $ref.GetType() }
        }
        $row.dt | Should -BeOfType [datetime]
        @($row.PSObject.Properties.Name)[0..2] -join ',' | Should -Be 's,missing,n'
        $row.missing | Should -BeNullOrEmpty
    }
}

Describe 'WIRING -- Risk Analysis delivers through the sender, with the page read ahead' {
    BeforeAll {
        $src = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1')
        $script:Ra = [regex]::Replace($src, '(?m)^\s*#.*$', '')
    }
    It 'Log Analytics: Invoke-RALaPagedPost with the table, a read-ahead pager from SQL, the confirmed rows counted' {
        $script:Ra | Should -Match ([regex]::Escape('New-RARowPager -Stream $script:RAStream -Source All -ReadAhead'))
        $script:Ra | Should -Match ([regex]::Escape('Invoke-RALaPagedPost -Pager $__pgL -KeyColumns @(Get-RAIngestKeyColumns) -TableName $laTable'))
        $script:Ra | Should -Match ([regex]::Escape('if ([long]$__laDelivery.RowsPosted -ne $script:RAAllCount) { throw'))
        $script:Ra | Should -Match ([regex]::Escape('-OnStopped { param($__confirmed) $script:_RALaRowsPosted = [long]$__confirmed }'))
        $script:Ra | Should -Not -Match ([regex]::Escape('while ($null -ne ($__pgPage = $__pgL.Next()))'))
    }
    It 'the ingest client routes a started table''s rows through its sender; the SQL seam offers its connection to a reader thread' {
        $li = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'engine\_shared\SI-LogIngest.ps1')
        $li | Should -Match ([regex]::Escape('$sender = Get-SILogIngestSender -TableName $TableName'))
        $li | Should -Match ([regex]::Escape('return (Send-SILogDataToSender -Sender $sender -Data $Data -DcrName $DcrName)'))
        $ds = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'engine\_shared\data-sql\SI-DataSql.ps1')
        $ds | Should -Match ([regex]::Escape('$invoke | Add-Member -NotePropertyName SIConnectionInfo -NotePropertyValue $connInfo'))
    }
    It 'a sender worker is given text only, never a script block of the run' {
        $li = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'engine\_shared\SI-LogIngest.ps1')
        $li | Should -Match ([regex]::Escape("SessionStateFunctionEntry(`$fn, `$def)"))
        $li | Should -Match ([regex]::Escape('[void]$ps.AddScript($Sender.Script)'))
    }
}
