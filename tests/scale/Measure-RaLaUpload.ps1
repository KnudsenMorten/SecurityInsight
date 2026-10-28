#Requires -Version 7.0
<#
.SYNOPSIS
    MEASUREMENT (offline, test VM only): the Risk Analysis upload to Log Analytics, through the real engine code, with only
    the Log Ingestion API faked -- where the time goes, and the rows the fake service received.

.DESCRIPTION
    Runs what Invoke-RiskAnalysis.ps1 runs after the reports are stored (#638 stream mode): the rows a PAGE at a time from
    their stored JSON (ConvertFrom-RAStreamJson, as New-RARowPager hands them over), each page prepared
    (ConvertTo-RALaPostRows) and posted (Send-SILogData) in chunks (Invoke-RALaChunkedPost), the progress line per chunk.
    The rows are GENERATED: -Rows rows of a Risk Analysis Detailed shape (four reports, ~320 columns between them, ~110 per
    row, strings / numbers / dates / empties), in report order, as SQL hands them back.

    The fake service (Invoke-SILogIngestHttp): ARM answers the rule and its endpoint; every POST to the ingestion endpoint
    is recorded (rows, raw and compressed bytes, start / end, which thread) and answered 204 after -LatencyMs plus
    -MsPerMB per compressed megabyte (the service's own time). -Throttle429Every N answers every Nth POST 429 with
    Retry-After 1 once.

    The output (-OutFile, JSON): the seconds per stage (page read, prepare, post), the posts (count, sizes, the largest,
    the most in flight at once), rows / minute, and -- with -Capture -- a SHA-256 over the rows the service received in
    the order they arrived per row key, so two trees can be compared (the same rows, the same JSON per row).

    -EngineRoot runs ANOTHER tree's engine with this harness (the base, for the before / after).
    Never on mgmt1. Not a gate: the gate runs SIv3-RaLaUploadSpeed.Tests.ps1, which is small.

.EXAMPLE
    pwsh -NoProfile -File tests\scale\Measure-RaLaUpload.ps1 -Rows 100000 -OutFile C:\work\si\laupload\after.json -Capture
#>
[CmdletBinding()]
param(
    [string]$EngineRoot = '',
    [ValidateRange(1, 5000000)][int]$Rows = 100000,
    [int]$LatencyMs = 400,
    [int]$MsPerMB = 300,
    [int]$Throttle429Every = 0,
    [string]$OutFile = '',
    [switch]$Capture,
    [ValidateSet('Sql', 'Memory')][string]$Source = 'Sql',
    [int]$Degree = 0,
    [switch]$NoReadAhead,
    # where sql\si-data-schema.sql is read from (default: this tree's)
    [string]$SchemaRoot = ''
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$siRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if ($EngineRoot) { $siRoot = (Resolve-Path -LiteralPath $EngineRoot).Path }
$raShared = Join-Path $siRoot 'engine\risk-analysis\_shared'
if (-not $SchemaRoot) { $SchemaRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot) }
. (Join-Path $siRoot 'engine\_shared\SI-LogIngest.ps1')
. (Join-Path $raShared 'RA-ColumnTypeAlign.ps1')
. (Join-Path $raShared 'RA-IngestKeyColumns.ps1')
. (Join-Path $raShared 'RA-Delivery.ps1')
. (Join-Path $raShared 'RA-SqlStream.ps1')
# #744: the engine's cores (the decode and the Log Analytics preparation run on them on a tree that has them; the base has none)
if (Test-Path -LiteralPath (Join-Path $raShared 'RA-ParallelScore.ps1')) { . (Join-Path $raShared 'RA-ParallelScore.ps1') }

# ---------------------------------------------------------------------------------------------------------------------
#  the fake Log Ingestion API + ARM
# ---------------------------------------------------------------------------------------------------------------------
$sub = '11111111-1111-1111-1111-111111111111'
$dceId = "/subscriptions/$sub/resourceGroups/rg-si/providers/Microsoft.Insights/dataCollectionEndpoints/dce-si"
$dcrId = "/subscriptions/$sub/resourceGroups/rg-si/providers/Microsoft.Insights/dataCollectionRules/dcr-si-ra"
$global:LaFake = [hashtable]::Synchronized(@{
    Dce = ([pscustomobject]@{ id = $dceId; name = 'dce-si'; properties = [pscustomobject]@{ logsIngestion = [pscustomobject]@{ endpoint = 'https://dce-si.westeurope-1.ingest.monitor.azure.com' } } } | ConvertTo-Json -Depth 10 -Compress)
    Dcr = ([pscustomobject]@{ id = $dcrId; name = 'dcr-si-ra'; properties = [pscustomobject]@{ immutableId = 'dcr-0000'; dataCollectionEndpointId = $dceId
            streamDeclarations = [pscustomobject]@{ 'Custom-SI_RiskAnalysis_Detailed_CL' = [pscustomobject]@{ columns = @() } } } } | ConvertTo-Json -Depth 10 -Compress)
    Posts = [System.Collections.Concurrent.ConcurrentQueue[object]]::new()
    PostNo = 0; InFlight = 0; MaxInFlight = 0; Arm = 0; Mx = [System.Threading.Mutex]::new()
    LatencyMs = $LatencyMs; MsPerMB = $MsPerMB; Throttle = $Throttle429Every; Capture = [bool]$Capture
    Clock = [System.Diagnostics.Stopwatch]::StartNew()
    Hashes = [System.Collections.Concurrent.ConcurrentDictionary[string, string]]::new()
    # #744: the row keys of every post, in the post's order (the rows of each post, in the same order, on both trees)
    PostKeys = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()
    Dups = 0
})
$fakeHttp = {
    param([string]$Method, [string]$Uri, [hashtable]$Headers, $Body, [string]$ContentType, [int]$TimeoutSec = 300)
    $f = $SILogSeam   # the shared state: global here, handed to every post worker by the sender (#738)
    if ($Uri -match '/dataCollectionRules/[^/]+/streams/') {
        $f.Mx.WaitOne() | Out-Null; try { $f.PostNo++; $no = $f.PostNo } finally { $f.Mx.ReleaseMutex() }
        if ($f.Throttle -gt 0 -and ($no % $f.Throttle) -eq 0) { return [pscustomobject]@{ StatusCode = 429; Content = '{"error":{"code":"TooManyRequests"}}'; RetryAfter = '1' } }
        $f.Mx.WaitOne() | Out-Null; try { $f.InFlight++; if ($f.InFlight -gt $f.MaxInFlight) { $f.MaxInFlight = $f.InFlight } } finally { $f.Mx.ReleaseMutex() }
        $t0 = $f.Clock.Elapsed.TotalMilliseconds
        $bytes = [byte[]]$Body
        $raw = $bytes
        if ($Headers -and $Headers['Content-Encoding'] -eq 'gzip') {
            $in = [System.IO.MemoryStream]::new($bytes); $gz = [System.IO.Compression.GZipStream]::new($in, [System.IO.Compression.CompressionMode]::Decompress)
            $out = [System.IO.MemoryStream]::new(); $gz.CopyTo($out); $gz.Dispose(); $raw = $out.ToArray()
        }
        $rowsIn = 0
        $keys = [System.Text.StringBuilder]::new()
        $doc = [System.Text.Json.JsonDocument]::Parse([System.ReadOnlyMemory[byte]]::new($raw))
        try {
            foreach ($e in $doc.RootElement.EnumerateArray()) {
                $rowsIn++
                if ($f.Capture) {
                    $txt = $e.GetRawText()
                    $k = $e.GetProperty('RowKey').GetString(); [void]$keys.Append($k).Append(',')
                    $sha = [System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::UTF8.GetBytes($txt))
                    if (-not $f.Hashes.TryAdd($k, [Convert]::ToHexString($sha))) { $f.Mx.WaitOne() | Out-Null; try { $f.Dups++ } finally { $f.Mx.ReleaseMutex() } }
                }
            }
        } finally { $doc.Dispose() }
        if ($f.Capture) { $f.PostKeys.Enqueue($keys.ToString()) }
        $wait = $f.LatencyMs + [int]($f.MsPerMB * $bytes.Length / 1MB)
        $left = $wait - ($f.Clock.Elapsed.TotalMilliseconds - $t0)
        if ($left -gt 0) { [System.Threading.Thread]::Sleep([int]$left) }
        $t1 = $f.Clock.Elapsed.TotalMilliseconds
        $f.Mx.WaitOne() | Out-Null; try { $f.InFlight-- } finally { $f.Mx.ReleaseMutex() }
        $f.Posts.Enqueue([pscustomobject]@{ No = $no; Rows = $rowsIn; Raw = $raw.Length; Sent = $bytes.Length; Start = $t0; End = $t1; Thread = [System.Threading.Thread]::CurrentThread.ManagedThreadId })
        return [pscustomobject]@{ StatusCode = 204; Content = ''; RetryAfter = $null }
    }
    $f.Mx.WaitOne() | Out-Null; try { $f.Arm++ } finally { $f.Mx.ReleaseMutex() }
    if ($Uri -match 'dataCollectionEndpoints/dce-si') { return [pscustomobject]@{ StatusCode = 200; Content = $f.Dce; RetryAfter = $null } }
    if ($Uri -match 'dataCollectionRules/dcr-si-ra') { return [pscustomobject]@{ StatusCode = 200; Content = $f.Dcr; RetryAfter = $null } }
    [pscustomobject]@{ StatusCode = 404; Content = '{}'; RetryAfter = $null }
}
# the fake is published globally (and as $global:SI_FakeLaHttp, for runspaces of the engine that rebuild it)
Set-Item -Path function:global:Invoke-SILogIngestHttp -Value $fakeHttp
Set-Item -Path function:script:Invoke-SILogIngestHttp -Value $fakeHttp
$global:SILogSeam = $global:LaFake
$global:LaFake.Tokens = 0
function global:Get-SIManagedIdentityToken { param([string]$Resource, [string]$ClientId, [switch]$ForceRefresh) $global:LaFake.Tokens++; 'fake-token' }
$global:SI_AzSubscriptionId = $sub; $global:SI_DcrResourceGroup = 'rg-si'; $global:SI_DceResourceGroup = 'rg-si'
(Get-SILogIngestRunCache).DcrIds['dcr-si-ra'] = $dcrId

# ---------------------------------------------------------------------------------------------------------------------
#  the generated result: stored JSON per row, four report shapes, interleaved (the final order is by score)
# ---------------------------------------------------------------------------------------------------------------------
$union = [System.Collections.Generic.List[string]]::new()
foreach ($c in 'RowKey', 'ReportName', 'CollectionTime', 'SolutionVersion', 'AssetName', 'AssetId', 'ConfigurationId', 'ConfigurationName', 'SecuritySeverity', 'CriticalityTier', 'RiskScoreTotal', 'Impact', 'LastSeen') { $union.Add($c) }
for ($i = 1; $union.Count -lt 320; $i++) { $union.Add(('Col{0:D3}{1}' -f $i, @('Name', 'Count', 'Score', 'Date', 'Text')[$i % 5])) }
$common = @($union[0..12])
$reports = @(
    @{ Name = 'Vulnerabilities by asset'; Cols = @($common + $union[13..112]) },
    @{ Name = 'Identity exposure'; Cols = @($common + $union[100..199]) },
    @{ Name = 'Azure misconfiguration'; Cols = @($common + $union[180..279]) },
    @{ Name = 'Endpoint hardening'; Cols = @($common + $union[220..319]) }
)
$dateCols = [System.Collections.Generic.HashSet[string]]::new()
foreach ($c in @('CollectionTime', 'LastSeen') + @($union | Where-Object { $_ -like '*Date' })) { [void]$dateCols.Add($c) }
$types = @{}
foreach ($c in $union) {
    $types[$c] = if ($c -like '*Count' -or $c -eq 'CriticalityTier') { 'long' } elseif ($c -like '*Score' -or $c -eq 'RiskScoreTotal') { 'real' } elseif ($dateCols.Contains($c)) { 'datetime' } elseif ($c -eq 'Impact') { 'long' } else { 'string' }
}
$words = @('high', 'exposure', 'tier zero', 'admin', 'Microsoft Windows Server 2022', 'contoso.local', 'remote desktop', 'CVE-2026-1234', 'not patched', 'internet facing', 'storage account', 'privileged role')
function New-RowJson([int]$i, $rep) {
    $sb = [System.Text.StringBuilder]::new(8192)
    [void]$sb.Append('{')
    $first = $true
    foreach ($c in $rep.Cols) {
        $v = switch -Wildcard ($c) {
            'RowKey'          { '"r{0:D7}"' -f $i }
            'ReportName'      { '"' + $rep.Name + '"' }
            'CollectionTime'  { '"2026-10-17T09:00:00Z"' }
            'SolutionVersion' { '"3.0.0.202610171139"' }
            'AssetName'       { '"host-{0:D5}.contoso.local"' -f ($i % 40000) }
            'AssetId'         { '"{0}"' -f ([guid]::new(('{0:D32}' -f ($i % 40000)))) }
            'ConfigurationId' { '"scid-{0}"' -f (1000 + $i % 731) }
            'ConfigurationName' { '"Ensure setting {0} is configured"' -f ($i % 731) }
            'SecuritySeverity' { '"' + @('Low', 'Medium', 'High', 'Critical')[$i % 4] + '"' }
            'CriticalityTier' { [string]($i % 4) }
            'RiskScoreTotal'  { ([double](($i * 37) % 1000) / 10).ToString('R', [cultureinfo]::InvariantCulture) }
            'Impact'          { if ($i % 13 -eq 0) { '7.9' } else { [string]($i % 10) } }
            'LastSeen'        { '"2026-10-{0:D2}T08:{1:D2}:00Z"' -f (1 + $i % 16), ($i % 60) }
            '*Count'          { if (($i + $c.Length) % 7 -eq 0) { 'null' } else { [string](($i * 7) % 5000) } }
            '*Score'          { (([double](($i * 13) % 1000)) / 7).ToString('R', [cultureinfo]::InvariantCulture) }
            '*Date'           { if (($i + $c.Length) % 5 -eq 0) { 'null' } else { '"2026-0{0}-1{1}T10:00:00Z"' -f (1 + $i % 9), ($i % 10) } }
            default           { if (($i + $c.Length) % 6 -eq 0) { 'null' } else { '"' + $words[($i + $c.Length) % $words.Count] + ' ' + ($i % 97) + '"' } }
        }
        if (-not $first) { [void]$sb.Append(',') }
        $first = $false
        [void]$sb.Append('"').Append($c).Append('":').Append($v)
    }
    [void]$sb.Append('}')
    $sb.ToString()
}
$genClock = [System.Diagnostics.Stopwatch]::StartNew()
$stored = [System.Collections.Generic.List[object]]::new($Rows)
for ($i = 0; $i -lt $Rows; $i++) {
    # the final order is by score, not by report: the reports' rows are interleaved (a part carries every report's columns)
    $ri = $i % $reports.Count
    $stored.Add(@{ Json = (New-RowJson $i $reports[$ri]); Rep = $ri })
}
$genSec = $genClock.Elapsed.TotalSeconds
$storedChars = 0L; foreach ($s in $stored) { $storedChars += $s.Json.Length }

# the pager: -Source Sql = the REAL New-RARowPager over a local SQL Server (the test VM's SQLEXPRESS), the rows stored in
# sidata.Finding by the real schema; -Source Memory = pages of 32 MB of stored JSON decoded per row, without a database
$db = $null; $sqlSec = 0.0
if ($Source -eq 'Sql') {
    $sqlClock = [System.Diagnostics.Stopwatch]::StartNew()
    $db = 'si_laupload_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
    $m = [System.Data.SqlClient.SqlConnection]::new('Server=.\SQLEXPRESS;Database=master;Integrated Security=SSPI;Connection Timeout=30')
    $m.Open(); try { $c = $m.CreateCommand(); $c.CommandText = "CREATE DATABASE [$db]"; $c.CommandTimeout = 300; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
    $cs = "Server=.\SQLEXPRESS;Database=$db;Integrated Security=SSPI;Connection Timeout=30"
    $cn = [System.Data.SqlClient.SqlConnection]::new($cs); $cn.Open()
    try {
        $c = $cn.CreateCommand(); $c.CommandTimeout = 600; $c.CommandText = [IO.File]::ReadAllText((Join-Path $SchemaRoot 'sql\si-data-schema.sql')); [void]$c.ExecuteNonQuery()
        $c = $cn.CreateCommand(); $c.CommandText = "INSERT sidata.Collection (CollectionTime, Kind, Status) VALUES ('2026-10-17T09:00:00', 'Detailed', 'Loading'); SELECT CAST(SCOPE_IDENTITY() AS int)"
        $collectionId = [int]$c.ExecuteScalar()
        $dt = [System.Data.DataTable]::new()
        foreach ($col in @(@('CollectionId', [int]), @('AssetKey', [string]), @('DetailJson', [string]), @('RaSeq', [long]), @('RaSort', [double]), @('RaReport', [int]), @('RaInView', [bool]))) { [void]$dt.Columns.Add($col[0], $col[1]) }
        for ($i = 0; $i -lt $stored.Count; $i++) {
            # the final order: score descending (ties: three rows share a score), then the write order
            [void]$dt.Rows.Add($collectionId, ('aid-{0}' -f ($i % 40000)), $stored[$i].Json, [long]($i + 1), [double][Math]::Floor(($stored.Count - $i) / 3), ($stored[$i].Rep + 1), $true)
        }
        $bc = [System.Data.SqlClient.SqlBulkCopy]::new($cn); $bc.DestinationTableName = 'sidata.Finding'; $bc.BulkCopyTimeout = 1200; $bc.BatchSize = 5000
        foreach ($col in $dt.Columns) { [void]$bc.ColumnMappings.Add($col.ColumnName, $col.ColumnName) }
        $bc.WriteToServer($dt); $dt.Dispose()
    } finally { $cn.Dispose() }
    $seam = {
        param($Sql, $Params, $Mode)
        $k = [System.Data.SqlClient.SqlConnection]::new($cs); $k.Open()
        try {
            $c = $k.CreateCommand(); $c.CommandText = $Sql; $c.CommandTimeout = 300
            if ($Params) { foreach ($n in $Params.Keys) { [void]$c.Parameters.AddWithValue('@' + $n, $(if ($null -eq $Params[$n]) { [System.DBNull]::Value } else { $Params[$n] })) } }
            if ($Mode -in 'reader', 'rows') {
                $rd = $c.ExecuteReader(); $out = [System.Collections.Generic.List[object]]::new()
                try { while ($rd.Read()) { $h = @{}; for ($j = 0; $j -lt $rd.FieldCount; $j++) { $h[$rd.GetName($j)] = $rd.GetValue($j) }; $out.Add($h) } } finally { $rd.Close() }
                , $out.ToArray()
            } elseif ($Mode -eq 'scalar') { $c.ExecuteScalar() } else { [void]$c.ExecuteNonQuery() }
        } finally { $k.Dispose() }
    }.GetNewClosure()
    # what New-SIDataSqlInvoke offers a reader on another thread (#738): the connection, as values
    $seam | Add-Member -NotePropertyName SIConnectionInfo -NotePropertyValue ({ @{ ConnectionString = $cs; AccessToken = $null; CommandTimeout = 300 } }.GetNewClosure())
    $repMap = [ordered]@{}
    for ($r = 0; $r -lt $reports.Count; $r++) { $repMap[$reports[$r].Name] = @{ Ordinal = ($r + 1); Columns = [System.Collections.Generic.List[string]]::new([string[]]$reports[$r].Cols); DateCols = $dateCols } }
    $stream = @{ Invoke = $seam; Grain = 'Detailed'; CollectionId = $collectionId; TimeText = '2026-10-17T09:00:00.000'; Reports = $repMap }
    $pagerArgs = @{ Stream = $stream; Source = 'All' }
    if ((Get-Command New-RARowPager).Parameters.ContainsKey('ReadAhead') -and -not $NoReadAhead) { $pagerArgs['ReadAhead'] = $true }
    $pager = New-RARowPager @pagerArgs
    $sqlSec = $sqlClock.Elapsed.TotalSeconds
} else {
    $pager = [pscustomobject]@{ At = 0 }
    $pager | Add-Member -MemberType ScriptMethod -Name Next -Value {
        if ($this.At -ge $stored.Count) { return $null }
        $out = [System.Collections.Generic.List[object]]::new()
        $chars = 0L
        while ($this.At -lt $stored.Count -and $chars -lt 32MB) {
            $s = $stored[$this.At]; $this.At++
            $chars += $s.Json.Length
            $out.Add((ConvertFrom-RAStreamJson -Json $s.Json -Columns $reports[$s.Rep].Cols -DateCols $dateCols))
        }
        , $out.ToArray()
    }
}

# ---------------------------------------------------------------------------------------------------------------------
#  the upload, as Invoke-RiskAnalysis.ps1 runs it
# ---------------------------------------------------------------------------------------------------------------------
$global:EnableCompressionDefault = $true
$global:SI_LogIngestRunCollectionTime = [datetime]'2026-10-17T09:00:00Z'
$prepare = { param($chunk) ConvertTo-RALaPostRows -Rows $chunk -HostName 'si-job' -Fqdn 'si-job' -User 'container' -Types $types -DecimalCompanions @('Impact') }
$post = { param($prepared) Send-SILogData -DceName 'dce-si' -DcrName 'dcr-si-ra' -Data $prepared -TableName 'SI_RiskAnalysis_Detailed' -UseManagedIdentity $true -Verbose:$false 4>$null }
$timing = [ordered]@{ PageInLine = 0.0; Upload = 0.0 }
$all = [System.Diagnostics.Stopwatch]::StartNew()
$posted = 0L; $chunks = 0; $senderInfo = $null
$useNew = [bool](Get-Command -Name Invoke-RALaPagedPost -ErrorAction Ignore)
if ($useNew) {
    $res = Invoke-RALaPagedPost -Pager $pager -Prepare $prepare -Post $post -KeyColumns @() -TableName 'SI_RiskAnalysis_Detailed' -Degree $Degree -OnChunk { param($n, $h, $c) } 6>$null
    $posted = [long]$res.RowsPosted; $chunks = [int]$res.Chunks; $senderInfo = $res.Sender
} else {
    while ($true) {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $page = $pager.Next()
        $timing.PageInLine += $sw.Elapsed.TotalSeconds
        if ($null -eq $page) { break }
        $sw.Restart()
        $d = Invoke-RALaChunkedPost -Rows @($page) -KeyColumns @() -Prepare $prepare -Post $post -OnChunk { param($n, $p, $t) } 6>$null
        $timing.Upload += $sw.Elapsed.TotalSeconds
        $posted += [long]$d.RowsPosted; $chunks += [int]$d.Chunks
    }
}
if ($pager.State -and $pager.State.ContainsKey('FetchSec')) { $timing['PagerFetchInLine'] = [Math]::Round($pager.State.FetchSec, 1); $timing['PagerDecode'] = [Math]::Round($pager.State.DecodeSec, 1); $timing['ReadAheadPages'] = $pager.State.AheadPages; $timing['ReadAheadFallbacks'] = $pager.State.AheadFallbacks }

$totalSec = $all.Elapsed.TotalSeconds
if ($db) {
    [System.Data.SqlClient.SqlConnection]::ClearAllPools()
    $m = [System.Data.SqlClient.SqlConnection]::new('Server=.\SQLEXPRESS;Database=master;Integrated Security=SSPI;Connection Timeout=30')
    $m.Open(); try { $c = $m.CreateCommand(); $c.CommandTimeout = 300; $c.CommandText = "ALTER DATABASE [$db] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$db]"; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
}

# a stage profile on a sample (the same functions, timed apart): decode, prepare, serialise, compress
$sample = @($stored[0..([Math]::Min(1999, $stored.Count - 1))])
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$dec = foreach ($s in $sample) { ConvertFrom-RAStreamJson -Json $s.Json -Columns $reports[$s.Rep].Cols -DateCols $dateCols }
$tDecode = $sw.Elapsed.TotalSeconds; $sw.Restart()
$prep = (& $prepare @($dec)).Rows
$tPrepare = $sw.Elapsed.TotalSeconds; $sw.Restart()
$ser = [System.Collections.Generic.List[byte[]]]::new(); foreach ($r in $prep) { $ser.Add([System.Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -Depth 100 -InputObject $r -Compress))) }
$tSerialise = $sw.Elapsed.TotalSeconds; $sw.Restart()
$ms = [System.IO.MemoryStream]::new(); foreach ($b in $ser) { $ms.Write($b, 0, $b.Length) }
$null = ConvertTo-SILogGzip -Bytes $ms.ToArray()
$tGzip = $sw.Elapsed.TotalSeconds; $sw.Restart()
$null = foreach ($r in $dec) { Get-RALaRowBytes $r }
$tMeasure = $sw.Elapsed.TotalSeconds

$posts = @($global:LaFake.Posts.ToArray() | Sort-Object Start)
$httpSec = (($posts | Measure-Object -Property { $_.End - $_.Start } -Sum).Sum) / 1000.0
$hashAll = ''; $postsHash = ''
if ($Capture) {
    $keys = @($global:LaFake.Hashes.Keys | Sort-Object)
    $acc = [System.Text.StringBuilder]::new()
    foreach ($k in $keys) { [void]$acc.Append($k).Append('=').Append($global:LaFake.Hashes[$k]).Append("`n") }
    $hashAll = [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::UTF8.GetBytes($acc.ToString())))
    $pk = @($global:LaFake.PostKeys.ToArray() | Sort-Object)
    $postsHash = [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::UTF8.GetBytes(($pk -join "`n"))))
}
$result = [ordered]@{
    Engine = $siRoot; Variant = $(if ($useNew) { 'paged-parallel' } else { 'base' }); Source = $Source; Rows = $Rows; StoredMB = [Math]::Round($storedChars / 1MB, 1)
    LatencyMs = $LatencyMs; MsPerMB = $MsPerMB; Throttle429Every = $Throttle429Every; SqlLoadSec = [Math]::Round($sqlSec, 1)
    GenerateSec = [Math]::Round($genSec, 1); TotalSec = [Math]::Round($totalSec, 1); RowsPerMinute = [int]($Rows / $totalSec * 60)
    RowsPosted = $posted; Chunks = $chunks; Posts = $posts.Count; HttpSecSum = [Math]::Round($httpSec, 1)
    MaxInFlight = $global:LaFake.MaxInFlight; ArmCalls = $global:LaFake.Arm; TokenCalls = $global:LaFake.Tokens
    RowsPerPostAvg = $(if ($posts.Count) { [int](($posts | Measure-Object Rows -Average).Average) } else { 0 })
    SentKBAvg = $(if ($posts.Count) { [int](($posts | Measure-Object Sent -Average).Average / 1KB) } else { 0 })
    SentKBMax = $(if ($posts.Count) { [int](($posts | Measure-Object Sent -Maximum).Maximum / 1KB) } else { 0 })
    Timing = $timing; Sender = $senderInfo
    SampleMsPerRow = [ordered]@{ Decode = [Math]::Round($tDecode * 1000 / $sample.Count, 3); Prepare = [Math]::Round($tPrepare * 1000 / $sample.Count, 3)
                                 Serialise = [Math]::Round($tSerialise * 1000 / $sample.Count, 3); Gzip = [Math]::Round($tGzip * 1000 / $sample.Count, 3); MeasureBytes = [Math]::Round($tMeasure * 1000 / $sample.Count, 3) }
    DistinctRowsReceived = $global:LaFake.Hashes.Count; Duplicates = $global:LaFake.Dups; RowsHash = $hashAll; PostsHash = $postsHash
    Threads = [string]$env:SI_RA_SCORINGTHREADS
    EveryRowOnce = ($posted -eq $Rows -and (-not $Capture -or ($global:LaFake.Hashes.Count -eq $Rows -and $global:LaFake.Dups -eq 0)))
}
$json = $result | ConvertTo-Json -Depth 5
if ($OutFile) { [IO.File]::WriteAllText($OutFile, $json) }
$json
