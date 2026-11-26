#Requires -Version 5.1
<#
    #1321 (SCALE-2 #1314; with #1250) -- RISK ANALYSIS ANSWERS READ WITHOUT HOLDING THEM IN MEMORY SEVERAL TIMES.

    What this file pins (prio 1 = the same rows):
      * THE STREAMING READ OF AN ADVANCED HUNTING ANSWER (SI_RA_HuntingStreamRead = on, engine\_shared\SI-HuntingStreamRead.ps1)
        gives exactly the rows of the older read (body as one string, ConvertFrom-Json, a bag per row): the same rows in the
        same order, the same columns in the same order, the same values AND types (dates, numbers, booleans, nulls, nested
        lists and objects, unicode, escapes, very long strings), the same schema -- and the same stored DetailJson
        (ConvertTo-PSObjectDeep -> ConvertTo-RAStreamJson). Also for an empty answer, an empty body, results null, one row,
        a byte-order mark, many parts ("paging": a few KB parsed at a time) and an answer that trickles in a few bytes at a
        time.
      * the slice's conversion a part at a time (ConvertFrom-RAHuntingResults) gives exactly the rows of
        ConvertTo-PSObjectDeep over the whole answer, and lets each part's bags go; only with the switch on.
      * MEMORY: the reader holds a buffer and one part -- measured: the live managed memory while a 40 MB (39.5 MiB) answer is read
        stays well under the answer's size (the older read held the body as one string: twice its size).
      * failures keep their meaning: an answer the reader cannot read is asked again the older way (the same rows, one
        line, the reader off for the process); rows ConvertFrom-Json refuses are "a body that is not JSON" as before; no
        memory is the out-of-memory text the slice split reads; the time limit is the TaskCanceledException text; a network
        drop is the transport's error and does not turn the reader off.
      * THE CI CONTEXT OF A SLICE IN PARTS (#1250): the same index as one read, the parts asked one after another, a part
        with no memory asked again in halves; real SQL where the runner has it.
    Offline: the HTTP seam is an in-process handler, the database a fake seam (or the runner's SQL). pwsh 7 (the container
    runtime); the streaming cases skip on Windows PowerShell.
#>

$script:IsCore = ($PSVersionTable.PSEdition -eq 'Core')
$script:HasSql = [bool]($env:SI_TEST_LOCALSQL) -and (Test-Path -LiteralPath ([IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), 'sql', 'si-data-schema.sql')))

BeforeAll {
    # (discovery's variables are not seen here: decided again)
    $script:IsCore = ($PSVersionTable.PSEdition -eq 'Core')
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $ra = Join-Path $script:SIRoot 'engine/risk-analysis/_shared'
    function script:Write-Info { param($m) }
    function script:Write-Warn2 { param($m) }
    function script:Write-Ok { param($m) }
    function script:Write-Diag { param($m) }
    . (Join-Path $script:SIRoot 'engine/_shared/SI-GraphRest.ps1')
    foreach ($f in 'RA-RowShaping.ps1', 'RA-CiContext.ps1', 'RA-SqlStream.ps1') { . (Join-Path $ra $f) }
    $ProgressPreference = 'SilentlyContinue'

    if ($script:IsCore -and -not ('SiHsFakeHandler' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

// an answer a few bytes at a time (Mode 1), stalled after FailAfter bytes until it is disposed (Mode 2), or a dropped
// connection after FailAfter bytes (Mode 3)
public class SiHsStream : Stream {
    private readonly byte[] data; private readonly int mode; private readonly int failAfter; private int pos;
    private readonly ManualResetEventSlim gone = new ManualResetEventSlim(false); private volatile bool disposed;
    public SiHsStream(byte[] d, int m, int f) { data = d; mode = m; failAfter = f; }
    public override bool CanRead { get { return true; } }
    public override bool CanSeek { get { return false; } }
    public override bool CanWrite { get { return false; } }
    public override long Length { get { throw new NotSupportedException(); } }
    public override long Position { get { return pos; } set { throw new NotSupportedException(); } }
    public override void Flush() { }
    public override long Seek(long o, SeekOrigin s) { throw new NotSupportedException(); }
    public override void SetLength(long v) { throw new NotSupportedException(); }
    public override void Write(byte[] b, int o, int c) { throw new NotSupportedException(); }
    public override int Read(byte[] b, int o, int c) {
        if (disposed) throw new ObjectDisposedException("SiHsStream");
        if ((mode == 2 || mode == 3) && pos >= failAfter) {
            if (mode == 3) throw new IOException("the connection was reset by the peer");
            // (never a hang: a reader that does not end the read itself fails the test after 20 s)
            if (!gone.Wait(TimeSpan.FromSeconds(20))) throw new IOException("the stalled test answer was never ended by the reader");
            throw new ObjectDisposedException("SiHsStream");
        }
        int max = c;
        if (mode == 1) max = Math.Min(c, 7);
        if (mode == 2 || mode == 3) max = Math.Min(max, failAfter - pos);
        int n = Math.Min(max, data.Length - pos);
        if (n <= 0) return 0;
        Buffer.BlockCopy(data, pos, b, o, n); pos += n; return n;
    }
    protected override void Dispose(bool d) { disposed = true; gone.Set(); base.Dispose(d); }
}

// a large synthetic answer made as it is read -- never held whole
public class SiHsGenStream : Stream {
    private readonly int rows; private int next = -1; private byte[] cur = new byte[0]; private int at; private bool done;
    private readonly string pad;
    public long Produced;
    public SiHsGenStream(int r, int padChars) { rows = r; pad = new string('x', padChars); }
    public override bool CanRead { get { return true; } }
    public override bool CanSeek { get { return false; } }
    public override bool CanWrite { get { return false; } }
    public override long Length { get { throw new NotSupportedException(); } }
    public override long Position { get { return Produced; } set { throw new NotSupportedException(); } }
    public override void Flush() { }
    public override long Seek(long o, SeekOrigin s) { throw new NotSupportedException(); }
    public override void SetLength(long v) { throw new NotSupportedException(); }
    public override void Write(byte[] b, int o, int c) { throw new NotSupportedException(); }
    private bool Advance() {
        if (done) return false;
        next++;
        string s;
        if (next == 0) s = "{\"schema\":[{\"name\":\"Id\",\"type\":\"Int64\"},{\"name\":\"Name\",\"type\":\"String\"}],\"results\":[";
        else if (next <= rows) s = (next > 1 ? "," : "") + "{\"Id\":" + next + ",\"Name\":\"host-" + next + "\",\"Text\":\"" + pad + "\",\"Arr\":[1,2,3],\"At\":\"2026-10-20T16:45:01Z\"}";
        else { s = "]}"; done = true; }
        cur = Encoding.UTF8.GetBytes(s); at = 0; return true;
    }
    public override int Read(byte[] b, int o, int c) {
        while (at >= cur.Length) { if (!Advance()) return 0; }
        int n = Math.Min(c, cur.Length - at);
        Buffer.BlockCopy(cur, at, b, o, n); at += n; Produced += n; return n;
    }
}

public class SiHsFakeHandler : HttpMessageHandler {
    public byte[] Body = new byte[0]; public int Status = 200; public int Mode; public int FailAfter; public int Calls;
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) {
        Interlocked.Increment(ref Calls);
        Stream s = Mode == 0 ? (Stream)new MemoryStream(Body, false) : new SiHsStream(Body, Mode, FailAfter);
        var r = new HttpResponseMessage((HttpStatusCode)Status) { Content = new StreamContent(s) };
        r.Content.Headers.TryAddWithoutValidation("Content-Type", "application/json; charset=utf-8");
        return Task.FromResult(r);
    }
}
'@
    }
    if ($script:IsCore) {
        $script:Fake = New-Object SiHsFakeHandler
        $script:SIGraphHttpHandler = $script:Fake
    }

    # a recorded-shape advanced hunting answer (synthetic -- no customer data): every kind of value the service sends
    function script:New-HsRow([int]$i, [int]$LongChars = 0) {
        $long = if ($LongChars -gt 0) { ('L' * $LongChars) } else { 'short' }
        '{"Timestamp":"2026-10-20T16:45:01.123Z","DeviceName":"srv-' + $i + '-' + [char]0xE6 + [char]0xF8 + [char]0xE5 + '","DeviceId":"d' + $i + '","Count":' + $i +
        ',"Big":9007199254740993,"Score":1.5e10,"Neg":-0.25,"Ok":true,"No":false,"Nothing":null,"Arr":[1,2,3],"Strs":["a","b"],' +
        '"Mixed":[1,"a",null,{"x":[]}],"Obj":{"a":{"b":[{"c":null}]}},"Empty":"","EmptyArr":[],"EmptyObj":{},' +
        '"Esc":"quote \" back \\ slash æ tab\t nl\n","Emoji":"' + [char]::ConvertFromUtf32(0x1F600) + ' 😀","Tags@odata.type":"#Collection(String)","Tags":["t1"],"Long":"' + $long + '"}'
    }
    function script:New-HsBody([int]$Rows = 3, [string]$Schema = '[{"name":"Timestamp","type":"DateTime"},{"name":"DeviceName","type":"String"}]', [int]$LongEvery = 0, [int]$LongChars = 0) {
        $sb = [System.Text.StringBuilder]::new()
        [void]$sb.Append('{"@odata.context":"https://graph.microsoft.com/beta/$metadata#microsoft.graph.security.huntingQueryResults","schema":').Append($Schema).Append(',"results":[')
        for ($i = 0; $i -lt $Rows; $i++) {
            if ($i) { [void]$sb.Append(',') }
            $lc = 0; if ($LongEvery -gt 0 -and ($i % $LongEvery) -eq 0) { $lc = $LongChars }
            [void]$sb.Append((New-HsRow -i $i -LongChars $lc))
        }
        [void]$sb.Append(']}')
        $sb.ToString()
    }
    # a value's full signature: its type and value, recursively (a date as its round-trip text and kind)
    function script:Get-HsSig($v) {
        if ($null -eq $v) { return 'null' }
        if ($v -is [string]) { return 's:' + $v }
        if ($v -is [datetime]) { return 'd:' + $v.ToString('o') + ':' + $v.Kind }
        if ($v -is [System.Management.Automation.PSCustomObject]) { return 'o{' + ((@($v.PSObject.Properties) | ForEach-Object { $_.Name + '=' + (Get-HsSig $_.Value) }) -join ',') + '}' }
        if ($v -is [System.Collections.IDictionary]) { return 'h{' + ((@($v.get_Keys()) | ForEach-Object { [string]$_ + '=' + (Get-HsSig $v[$_]) }) -join ',') + '}' }
        if ($v -is [System.Collections.IEnumerable]) { return 'a<' + $v.GetType().FullName + '>[' + ((@(foreach ($e in $v) { Get-HsSig $e })) -join ',') + ']' }
        $v.GetType().FullName + ':' + [System.Convert]::ToString($v, [System.Globalization.CultureInfo]::InvariantCulture)
    }
    function script:Get-HsAnswerSig($resp) {
        $rows = @(foreach ($r in @($resp.Results)) { Get-HsSig $r.AdditionalProperties })
        [pscustomobject]@{ Count = @($resp.Results).Count; Rows = $rows; Schema = (Get-HsSig $resp.Schema); ResultsType = $(if ($null -eq $resp.Results) { 'null' } else { $resp.Results.GetType().FullName }) }
    }
    # the stored form of each row (DetailJson): the slice's conversion, then the row's stored JSON
    function script:Get-HsDetailJson([object[]]$Rows) { @(foreach ($r in $Rows) { (ConvertTo-RAStreamJson -Row $r).Json }) }
    # one answer, read both ways (the handler answers the same bytes every call)
    function script:Invoke-HsBoth([byte[]]$Bytes, [int]$Mode = 0, [long]$ChunkBytes = 2048, [int]$Status = 200) {
        $script:Fake.Body = $Bytes; $script:Fake.Mode = $Mode; $script:Fake.Status = $Status
        $old = $null; $oldErr = $null; $new = $null; $newErr = $null
        $script:Fake.Mode = 0
        try { $old = Invoke-SIHuntingQueryRest -Query 'X' -Token 't' -TimeoutSec 30 } catch { $oldErr = [string]$_.Exception.Message }
        $script:Fake.Mode = $Mode
        try { $new = Invoke-SIHuntingQueryRest -Query 'X' -Token 't' -TimeoutSec 30 -StreamRows -StreamChunkBytes $ChunkBytes } catch { $newErr = [string]$_.Exception.Message }
        [pscustomobject]@{ Old = $old; New = $new; OldErr = $oldErr; NewErr = $newErr }
    }
    function script:Assert-HsSame($b, [switch]$ErrorAllowed) {
        if ($ErrorAllowed -and $b.OldErr) { $b.NewErr | Should -BeExactly $b.OldErr; return }
        $b.NewErr | Should -BeNullOrEmpty
        $b.OldErr | Should -BeNullOrEmpty
        $o = Get-HsAnswerSig $b.Old; $n = Get-HsAnswerSig $b.New
        $n.Count | Should -Be $o.Count
        $n.ResultsType | Should -Be $o.ResultsType
        $n.Schema | Should -BeExactly $o.Schema
        for ($i = 0; $i -lt $o.Count; $i++) { $n.Rows[$i] | Should -BeExactly $o.Rows[$i] -Because "row $i" }
        $b.New.Ok | Should -BeTrue
        $b.New.Error | Should -BeNullOrEmpty
    }
    $script:Utf8 = New-Object System.Text.UTF8Encoding($false)
}

AfterAll {
    $script:SIGraphHttpHandler = $null
    $global:SI_HuntingStreamOff = $null
    $global:SI_RA_HuntingStreamRead = $null
}

Describe 'the switch (default ON, owner 2026-11-23)' {
    It 'SI_RA_HuntingStreamRead is on unless it says off; the hunting call passes nothing when off' {
        Test-SIHuntingStreamOn -Setting $null | Should -BeTrue
        Test-SIHuntingStreamOn -Setting '' | Should -BeTrue
        Test-SIHuntingStreamOn -Setting 'On' | Should -BeTrue
        Test-SIHuntingStreamOn -Setting 'true' | Should -BeTrue
        # off stays reachable: the older read, exactly as before
        Test-SIHuntingStreamOn -Setting 'off' | Should -BeFalse
        Test-SIHuntingStreamOn -Setting ' OFF ' | Should -BeFalse
        Test-SIHuntingStreamOn -Setting 'false' | Should -BeFalse
        Test-SIHuntingStreamOn -Setting $false | Should -BeFalse
        $hunt = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine/risk-analysis/_shared/RA-GraphHunting.ps1'))
        $hunt | Should -Match "if \(\(Get-Command -Name Test-SIHuntingStreamOn[^\r\n]*\) \{ \`$__hsArgs\['StreamRows'\] = \`$true \}"
        $hunt | Should -Match "Test-SIHuntingStreamOn\)[^\r\n]*Parameters\.ContainsKey\('StreamRows'\)" -Because 'a hunting call without the streaming read is called as before'
        $hunt | Should -Match 'Invoke-SIHuntingQueryRest -Query \$Query -Token \$script:GraphAccessToken -TimeoutSec 900 @__hsArgs'
    }
    It 'it is in the settings catalog, ON by default, a normal setting (no REMOVE-ME) in the reference' {
        $cat = Get-Content -Raw (Join-Path $script:SIRoot 'config/settings.catalog.locked.json') | ConvertFrom-Json
        $s = @($cat.settings | Where-Object name -eq 'SI_RA_HuntingStreamRead')
        $s.Count | Should -Be 1
        [string]$s[0].type | Should -Be 'enum'
        (@($s[0].values) -join ',') | Should -Be 'off,on'
        [string]$s[0].defaultText | Should -Match '^on'
        "$($s[0].description) $($s[0].effect) $($s[0].whenToChange)" | Should -Not -Match 'REMOVE-ME'
        $ref = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'config/SecurityInsight.custom.reference.ps1'))
        $ref | Should -Match "on \(the default\)[^\r\n]*\r?\n(#[^\r\n]*\r?\n)*# \`$global:SI_RA_HuntingStreamRead = 'on'"
        $ref | Should -Not -Match "REMOVE-ME[^\r\n]*\r?\n(#[^\r\n]*\r?\n)*# \`$global:SI_RA_HuntingStreamRead"
    }
    It 'the slice converts a part at a time ONLY with the switch on, two or more rows, the advanced hunting shape' {
        $two = [pscustomobject]@{ Results = @([pscustomobject]@{ AdditionalProperties = [ordered]@{ a = 1 } }, [pscustomobject]@{ AdditionalProperties = [ordered]@{ a = 2 } }) }
        Test-RAHuntingResultsByPart -Resp $two -Setting 'off' | Should -BeFalse
        Test-RAHuntingResultsByPart -Resp $two -Setting 'on' | Should -BeTrue
        # not set = the default: on
        Test-RAHuntingResultsByPart -Resp $two -Setting $null | Should -BeTrue
        Test-RAHuntingResultsByPart -Resp $two -Setting 'false' | Should -BeFalse
        Test-RAHuntingResultsByPart -Resp ([pscustomobject]@{ Results = @([pscustomobject]@{ AdditionalProperties = [ordered]@{ a = 1 } }) }) -Setting 'on' | Should -BeFalse
        Test-RAHuntingResultsByPart -Resp ([pscustomobject]@{ Results = @() }) -Setting 'on' | Should -BeFalse
        Test-RAHuntingResultsByPart -Resp ([pscustomobject]@{ _SIDirectRows = @(1, 2) }) -Setting 'on' | Should -BeFalse
        Test-RAHuntingResultsByPart -Resp ([pscustomobject]@{ Results = @([pscustomobject]@{ x = 1 }, [pscustomobject]@{ x = 2 }) }) -Setting 'on' | Should -BeFalse
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine/risk-analysis/Invoke-RiskAnalysis.ps1'))
        # the main pass, the late retry / sub-slices (Get-RABucketRows) and the whole-report path
        ([regex]::Matches($src, 'Test-RAHuntingResultsByPart -Resp')).Count | Should -Be 3
        $src | Should -Match 'else \{ \$bucketResult = ConvertTo-PSObjectDeep \$rawResults -StripOData -CastPrimitiveArrays \}'
    }
}

Describe 'the streaming read gives the same rows as the older read' -Skip:(-not $script:IsCore) {
    BeforeEach { $global:SI_HuntingStreamOff = $null }

    It 'every kind of value: dates, numbers, booleans, nulls, nested lists and objects, unicode, escapes -- same rows, types, schema' {
        $b = Invoke-HsBoth -Bytes ($script:Utf8.GetBytes((New-HsBody -Rows 5)))
        Assert-HsSame $b
        @($b.New.Results).Count | Should -Be 5
        $b.New.Results[0].AdditionalProperties['Timestamp'] | Should -BeOfType [datetime]
        $b.New.Results[1].AdditionalProperties['DeviceName'] | Should -BeExactly ('srv-1-' + [char]0xE6 + [char]0xF8 + [char]0xE5)
    }
    It 'very long strings (larger than the read buffer) and many parts ("paging", a few KB parsed at a time)' {
        $body = New-HsBody -Rows 400 -LongEvery 97 -LongChars 300000
        $b = Invoke-HsBoth -Bytes ($script:Utf8.GetBytes($body)) -ChunkBytes 4096
        Assert-HsSame $b
        $global:SI_HuntingStreamLast.Chunks | Should -BeGreaterThan 20 -Because 'the answer was parsed in many parts'
        $global:SI_HuntingStreamLast.LargestBuffer | Should -BeGreaterThan 65536 -Because 'one row was larger than the first buffer'
    }
    It 'an answer that trickles in 7 bytes at a time, with a byte-order mark' {
        $bytes = [byte[]](@(0xEF, 0xBB, 0xBF) + $script:Utf8.GetBytes((New-HsBody -Rows 30)))
        Assert-HsSame (Invoke-HsBoth -Bytes $bytes -Mode 1 -ChunkBytes 1024)
    }
    It 'empty answer, empty body, results null, results missing, one row, a one-column and an empty schema, no schema' -ForEach @(
        @{ Body = '{"schema":[],"results":[]}' }
        @{ Body = '' }
        @{ Body = '   ' }
        @{ Body = '{"schema":[{"name":"a","type":"String"}],"results":null}' }
        @{ Body = '{"@odata.context":"x"}' }
        @{ Body = '{"schema":[{"name":"a","type":"String"}],"results":[{"a":"only"}]}' }
        @{ Body = '{"results":[{"a":1},{"a":2}]}' }
        @{ Body = '{"Results":[{"a":1},{"a":null}],"Schema":null}' }
        @{ Body = '{"results":{"a":1}}' }
        @{ Body = '{"results":[null,{"a":1},[1,2],"text",3]}' }
    ) {
        $global:SI_HuntingStreamOff = $null
        Assert-HsSame (Invoke-HsBoth -Bytes ($script:Utf8.GetBytes($Body)) -ChunkBytes 1024) -ErrorAllowed 6>$null
        $global:SI_HuntingStreamOff | Should -BeNullOrEmpty -Because 'none of these is a reader fault'
    }
    It 'the stored DetailJson of every row is byte-identical (the slice conversion, then the stored JSON)' {
        $b = Invoke-HsBoth -Bytes ($script:Utf8.GetBytes((New-HsBody -Rows 60 -LongEvery 13 -LongChars 5000))) -ChunkBytes 3000
        Assert-HsSame $b
        $oldRows = @(ConvertTo-PSObjectDeep $b.Old.Results.AdditionalProperties -StripOData -CastPrimitiveArrays)
        $global:SI_RA_HuntingStreamRead = 'on'
        try {
            Test-RAHuntingResultsByPart -Resp $b.New | Should -BeTrue
            $newRows = ConvertFrom-RAHuntingResults -Results $b.New.Results -PartRows 7
        } finally { $global:SI_RA_HuntingStreamRead = $null }
        $newRows.GetType().FullName | Should -Be 'System.Object[]'
        $newRows.Count | Should -Be $oldRows.Count
        $o = Get-HsDetailJson $oldRows; $n = Get-HsDetailJson $newRows
        for ($i = 0; $i -lt $o.Count; $i++) { $n[$i] | Should -BeExactly $o[$i] -Because "row $i" }
        for ($i = 0; $i -lt $oldRows.Count; $i++) { (Get-HsSig $newRows[$i]) | Should -BeExactly (Get-HsSig $oldRows[$i]) }
        @($b.New.Results | Where-Object { $null -ne $_ }).Count | Should -Be 0 -Because 'each converted row''s bag is let go'
        $n[0] | Should -Not -Match 'odata' -Because 'the @odata columns are left out as before'
    }
}

Describe 'failures keep their meaning' -Skip:(-not $script:IsCore) {
    BeforeEach { $global:SI_HuntingStreamOff = $null; $script:Fake.Status = 200; $script:Fake.Mode = 0 }
    AfterEach { $global:SI_HuntingStreamOff = $null }

    It 'an answer the reader cannot read (not one object) is asked again the older way: the same answer, one line, reader off' {
        $script:Fake.Body = $script:Utf8.GetBytes('[{"a":1}]'); $script:Fake.Calls = 0
        $old = Invoke-SIHuntingQueryRest -Query 'X' -Token 't' -TimeoutSec 30
        $script:Fake.Calls = 0
        $new = Invoke-SIHuntingQueryRest -Query 'X' -Token 't' -TimeoutSec 30 -StreamRows 6>$null
        $script:Fake.Calls | Should -Be 2 -Because 'asked once as it arrives, then again the older way'
        (Get-HsAnswerSig $new).Rows | Should -Be (Get-HsAnswerSig $old).Rows
        @($new.Results).Count | Should -Be @($old.Results).Count
        $global:SI_HuntingStreamOff | Should -Match 'failed on an answer'
        Get-SIHuntingStreamReaderType | Should -BeNullOrEmpty -Because 'off for the rest of the process'
    }
    It 'a field named twice is not read this way either (asked again the older way)' {
        $script:Fake.Body = $script:Utf8.GetBytes('{"results":[{"a":1}],"results":[{"a":2}]}'); $script:Fake.Calls = 0
        $err = $null; try { $null = Invoke-SIHuntingQueryRest -Query 'X' -Token 't' -TimeoutSec 30 -StreamRows 6>$null } catch { $err = $_ }
        $script:Fake.Calls | Should -Be 2
        $global:SI_HuntingStreamOff | Should -Match 'failed on an answer'
    }
    It 'rows ConvertFrom-Json refuses are "a body that is not JSON", as the older read says' {
        $script:Fake.Body = $script:Utf8.GetBytes('{"results":[{"a":1,"A":2}]}')
        $b = Invoke-HsBoth -Bytes $script:Fake.Body
        if ($b.OldErr) {
            $b.OldErr | Should -Match '^advanced hunting returned a body that is not JSON'
            $b.NewErr | Should -Match '^advanced hunting returned a body that is not JSON'
            $global:SI_HuntingStreamOff | Should -BeNullOrEmpty -Because 'the answer is the problem, not the reader'
        } else { Assert-HsSame $b }
    }
    It 'no memory to take the rows is the out-of-memory text the slice split reads (never a defect)' {
        $script:Fake.Body = $script:Utf8.GetBytes((New-HsBody -Rows 3))
        # (defined in this test's own scope: the reader's callback finds it, nothing after this test does)
        function ConvertFrom-Json { throw [System.OutOfMemoryException]::new() }
        $err = $null; try { $null = Invoke-SIHuntingQueryRest -Query 'X' -Token 't' -TimeoutSec 30 -StreamRows } catch { $err = [string]$_.Exception.Message }
        $err | Should -Match '(?i)OutOfMemoryException'
        $err | Should -Match '^advanced hunting returned a body that is not JSON'
        $global:SI_HuntingStreamOff | Should -BeNullOrEmpty
    }
    It 'a part whose rows do not add up is the READER''s fault: that answer is read again the older way, every row back, reader stays on' {
        $script:Fake.Body = $script:Utf8.GetBytes((New-HsBody -Rows 12))
        $old = Invoke-SIHuntingQueryRest -Query 'X' -Token 't' -TimeoutSec 30
        # (this test's own scope: the reader's callback finds it) -- one element of every part goes missing in the reader's
        # parse (-NoEnumerate); the older read's parse (the pipeline) is left as it is
        function ConvertFrom-Json {
            [CmdletBinding()] param([Parameter(ValueFromPipeline)]$InputObject, [switch]$NoEnumerate)
            process {
                if ($NoEnumerate) {
                    $all = Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $InputObject -NoEnumerate
                    , @($all | Select-Object -Skip 1)
                } else { Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $InputObject }
            }
        }
        $script:Fake.Calls = 0
        $r = $null; $err = $null
        try { $r = Invoke-SIHuntingQueryRest -Query 'X' -Token 't' -TimeoutSec 30 -StreamRows -StreamChunkBytes 2048 6>$null } catch { $err = [string]$_.Exception.Message }
        $err | Should -BeNullOrEmpty -Because 'a count mismatch is never "a body that is not JSON" (never a query defect)'
        $script:Fake.Calls | Should -Be 2 -Because 'asked once as it arrives, then that one answer again the older way'
        @($r.Results).Count | Should -Be 12 -Because 'never fewer rows than the answer holds'
        (Get-HsAnswerSig $r).Rows | Should -Be (Get-HsAnswerSig $old).Rows
        $global:SI_HuntingStreamOff | Should -BeNullOrEmpty -Because 'the reader stays on for other answers'
        Get-SIHuntingStreamReaderType | Should -Not -BeNullOrEmpty
        # and directly: the reader's own answer is Failed (the caller's fall-back), not a ParseError
        $a = Read-SIHuntingAnswerStream -Stream (New-Object System.IO.MemoryStream -ArgumentList @(, $script:Fake.Body)) -ChunkBytes 2048
        $a.Rows | Should -BeNullOrEmpty
        $a.ParseError | Should -BeNullOrEmpty
        $a.Failed | Should -Match 'do not add up: the reader cut out \d+ row\(s\), \d+ were taken'
    }
    It 'the whole-answer count check is kept, and a mismatch there is Failed (the older read), never a ParseError' {
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine/_shared/SI-HuntingStreamRead.ps1'))
        $src | Should -Match 'if \(\[long\]\$__hsRows\.Count -ne \[long\]\$a\.Rows\)'
        $src | Should -Match "Failed = \`$__hsWhy; ParseError = \`$null"
    }
    It 'a body the rows parse refuses (really not JSON) stays "a body that is not JSON", asked once' {
        $script:Fake.Body = $script:Utf8.GetBytes((New-HsBody -Rows 5))
        function ConvertFrom-Json {
            [CmdletBinding()] param([Parameter(ValueFromPipeline)]$InputObject, [switch]$NoEnumerate)
            process { throw [System.ArgumentException]::new('Conversion from JSON failed with error: Unexpected character encountered while parsing value') }
        }
        $script:Fake.Calls = 0
        $r = $null; $err = $null
        try { $r = Invoke-SIHuntingQueryRest -Query 'X' -Token 't' -TimeoutSec 30 -StreamRows -StreamChunkBytes 2048 } catch { $err = [string]$_.Exception.Message }
        $r | Should -BeNullOrEmpty
        $err | Should -Match '^advanced hunting returned a body that is not JSON: .*Conversion from JSON failed'
        $script:Fake.Calls | Should -Be 1 -Because 'a body that is not JSON is not asked again the older way'
        $global:SI_HuntingStreamOff | Should -BeNullOrEmpty
        $a = Read-SIHuntingAnswerStream -Stream (New-Object System.IO.MemoryStream -ArgumentList @(, $script:Fake.Body)) -ChunkBytes 2048
        $a.Failed | Should -BeNullOrEmpty
        $a.ParseError | Should -Match 'Conversion from JSON failed'
    }
    It 'an answer that stops arriving ends at the time limit with the TaskCanceledException text' {
        $script:Fake.Body = $script:Utf8.GetBytes((New-HsBody -Rows 50)); $script:Fake.Mode = 2; $script:Fake.FailAfter = 500
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $err = $null; try { $null = Invoke-SIHuntingQueryRest -Query 'X' -Token 't' -TimeoutSec 2 -StreamRows } catch { $err = [string]$_.Exception.Message }
        $sw.Stop()
        $err | Should -Match 'TaskCanceledException'
        $sw.Elapsed.TotalSeconds | Should -BeLessThan 30
        $global:SI_HuntingStreamOff | Should -BeNullOrEmpty
    }
    It 'a dropped connection is the transport''s error, and the reader stays on' {
        $script:Fake.Body = $script:Utf8.GetBytes((New-HsBody -Rows 50)); $script:Fake.Mode = 3; $script:Fake.FailAfter = 700
        $err = $null; try { $null = Invoke-SIHuntingQueryRest -Query 'X' -Token 't' -TimeoutSec 30 -StreamRows } catch { $err = [string]$_.Exception.Message }
        $err | Should -Match 'reset by the peer'
        $global:SI_HuntingStreamOff | Should -BeNullOrEmpty
    }
    It 'a refused answer (4xx / 5xx) is read as text and worded as before' {
        $b = Invoke-HsBoth -Bytes ($script:Utf8.GetBytes('{"error":{"code":"BadRequest","message":"Query execution has exceeded the allowed limits"}}')) -Status 502
        $script:Fake.Status = 200
        $b.OldErr | Should -Not -BeNullOrEmpty
        $b.NewErr | Should -BeExactly $b.OldErr
        $b.NewErr | Should -Match '^502 Bad Gateway -- '
    }
}

Describe 'memory stays bounded while a large answer is read' -Skip:(-not $script:IsCore) {
    It 'the live managed memory while a 40 MB (39.5 MiB) answer is read stays well under its size (measured)' {
        $global:SI_HuntingStreamOff = $null
        $t = Get-SIHuntingStreamReaderType
        $t | Should -Not -BeNullOrEmpty
        $gen = New-Object SiHsGenStream -ArgumentList 100000, 330
        [System.GC]::Collect(); [System.GC]::WaitForPendingFinalizers(); [System.GC]::Collect()
        $base = [System.GC]::GetTotalMemory($true)
        $script:HsPeak = 0L; $script:HsRows = 0L
        $cb = [System.Action[string, int]] {
            param([string]$Text, [int]$Count)
            $script:HsRows += $Count
            $live = [System.GC]::GetTotalMemory($true)
            if ($live -gt $script:HsPeak) { $script:HsPeak = $live }
        }
        $a = $t::Read($gen, [long]0, 65536, $cb, [long]512KB)
        $a.Rows | Should -Be 100000
        $script:HsRows | Should -Be 100000
        $gen.Produced | Should -BeGreaterThan 39MB
        $grow = $script:HsPeak - $base
        # the older read held the body as ONE string (twice the answer's bytes) before it parsed a row
        $grow | Should -BeLessThan ([long]($gen.Produced / 4)) -Because ('the reader holds one part, not the answer (grew {0:N0} bytes for a {1:N0}-byte answer)' -f $grow, $gen.Produced)
        $a.LargestBuffer | Should -BeLessOrEqual 65536 -Because 'no row was larger than the first buffer'
        $a.LargestChunkBytes | Should -BeLessThan (512KB + 4096)
        $a.Chunks | Should -BeGreaterThan 60
    }
}

Describe 'the CI context of a slice is read in parts, with the same context (#1250)' {
    BeforeAll {
        # an in-memory sidata.Ci + sidata.CiLink with the statement's rules: by the CI id or a link id (each listed id), or a
        # name exactly one current CI has; retired CIs are not current
        $script:Cis = @(
            @{ CiId = 'ci-1'; Name = 'srv01'; Life = ''; Links = @('mde:m1') }
            @{ CiId = 'ci-2'; Name = 'dup'; Life = ''; Links = @() }
            @{ CiId = 'ci-3'; Name = 'dup'; Life = ''; Links = @('az:/subs/x/vm3') }
            @{ CiId = 'ci-4'; Name = 'solo'; Life = ''; Links = @() }
            @{ CiId = 'ci-5'; Name = 'gone'; Life = 'retired'; Links = @('mde:m5') }
        )
        for ($k = 6; $k -le 60; $k++) { $script:Cis += @{ CiId = "ci-$k"; Name = "host$k"; Life = ''; Links = @("mde:dev$k") } }
        # the CI document as the CI build stores it: its linked objects carry the provider ids the index keys on
        function script:New-HsCiDoc($c) { '{{"si_ci_id":"{0}","si_asset_name":"{1}","si_tier":1,"si_linked_objects":[{2}]}}' -f $c.CiId, $c.Name, ((@($c.Links) | ForEach-Object { '{"id":"' + $_ + '"}' }) -join ',') }
        $script:Calls = 0
        $script:FakeCiSeam = {
            param($Sql, $Params, $Mode)
            $script:Calls++
            $ids = @($Params.Ids | ConvertFrom-Json); $names = @($Params.Names | ConvertFrom-Json)
            if ($null -ne $script:OomAbove -and $ids.Count -gt $script:OomAbove) { throw [System.OutOfMemoryException]::new() }
            $idSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase); foreach ($i in $ids) { if ($i) { [void]$idSet.Add([string]$i) } }
            $nmSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase); foreach ($n in $names) { if ($n) { [void]$nmSet.Add([string]$n) } }
            $out = [System.Collections.Generic.List[object]]::new()
            foreach ($c in $script:Cis) {
                if ($c.Life -eq 'retired') { continue }
                $hit = $idSet.Contains($c.CiId) -or @($c.Links | Where-Object { $idSet.Contains($_) }).Count -gt 0
                if (-not $hit -and $nmSet.Contains($c.Name)) { $hit = (@($script:Cis | Where-Object { $_.Name -eq $c.Name -and $_.Life -ne 'retired' }).Count -eq 1) }
                if ($hit) { $out.Add(@{ CiId = $c.CiId; DocJson = (New-HsCiDoc $c); Stale = 0 }) }
            }
            , $out.ToArray()
        }
        $rows = [System.Collections.Generic.List[object]]::new()
        $rows.Add([pscustomobject]@{ MdeDeviceId = 'm1'; AssetName = 'x' })
        $rows.Add([pscustomobject]@{ AssetName = 'dup' })
        $rows.Add([pscustomobject]@{ AssetName = 'solo' })
        $rows.Add([pscustomobject]@{ AzureResourceId = '/subs/x/vm3'; AssetName = 'srv01' })
        $rows.Add([pscustomobject]@{ MdeDeviceId = 'm5'; AssetName = 'gone' })
        for ($k = 6; $k -le 60; $k++) { $rows.Add([pscustomobject]@{ MdeDeviceId = "dev$k"; AssetName = "host$k" }) }
        $script:CiRows = $rows.ToArray()
        function script:Get-HsIndexSig($idx) {
            $a = @($idx.ById.Keys | Sort-Object | ForEach-Object { '{0}>{1}' -f $_, $idx.ById[$_].si_ci_id }) -join ';'
            $b = @($idx.ByName.Keys | Sort-Object | ForEach-Object { '{0}>{1}' -f $_, $idx.ByName[$_].si_ci_id }) -join ';'
            "$($idx.Count)|$a|$b"
        }
    }
    BeforeEach { $script:OomAbove = $null; $script:Calls = 0 }

    It 'in parts of 3 row ids: the same index as one read, the parts asked one after another' {
        $one = Get-RAStreamCiIndex -Invoke $script:FakeCiSeam -Rows $script:CiRows -PartKeys 100000
        $script:Calls | Should -Be 1
        $script:Calls = 0
        $parts = Get-RAStreamCiIndex -Invoke $script:FakeCiSeam -Rows $script:CiRows -PartKeys 3
        $script:Calls | Should -BeGreaterThan 10
        Get-HsIndexSig $parts | Should -BeExactly (Get-HsIndexSig $one)
        (Find-RACiForRow -Row $script:CiRows[0] -Index $parts).Ci.si_ci_id | Should -Be 'ci-1'
        (Find-RACiForRow -Row $script:CiRows[2] -Index $parts).Ci.si_ci_id | Should -Be 'ci-4'
        (Find-RACiForRow -Row $script:CiRows[3] -Index $parts).Ci.si_ci_id | Should -Be 'ci-3'
        Find-RACiForRow -Row $script:CiRows[4] -Index $parts | Should -BeNullOrEmpty -Because 'a retired CI is not current'
        $parts.Count | Should -Be $one.Count -Because 'a CI two parts both answer is kept once'
    }
    It 'a part the worker has no memory for is asked again in halves -- the same index, the smaller size kept for the run' {
        $one = Get-RAStreamCiIndex -Invoke $script:FakeCiSeam -Rows $script:CiRows -PartKeys 100000
        $script:OomAbove = 45
        $script:RAStreamCiPartKeys = $null
        $halved = Get-RAStreamCiIndex -Invoke $script:FakeCiSeam -Rows $script:CiRows -PartKeys 16
        Get-HsIndexSig $halved | Should -BeExactly (Get-HsIndexSig $one)
        $script:OomAbove = 1
        { Get-RAStreamCiIndex -Invoke $script:FakeCiSeam -Rows $script:CiRows -PartKeys 1 } | Should -Throw -Because 'at one id a part cannot be made smaller: the caller says the slice is scored without its CI context, as before'
        $script:RAStreamCiPartKeys = $null
    }
    It 'a slice within one part is ONE read with the same parameters as before (every id with every prefix)' {
        $script:Seen = $null
        $spy = { param($Sql, $Params, $Mode) $script:Seen = $Params; , @() }
        $null = Get-RAStreamCiIndex -Invoke $spy -Rows @([pscustomobject]@{ MdeDeviceId = 'M1'; SI_AssetId = 'mde:m1'; AssetName = ' srv01 ' }, [pscustomobject]@{ DeviceId = 'd2'; AssetName = 'SRV01' })
        @($script:Seen.Ids | ConvertFrom-Json) -join ',' | Should -Be 'm1,az:m1,eg:az:m1,eg:dev:m1,eg:m1,mde:m1,entra-user:m1,entra-sp:m1,entra-device:m1,aad:m1,d2,az:d2,eg:az:d2,eg:dev:d2,eg:d2,mde:d2,entra-user:d2,entra-sp:d2,entra-device:d2,aad:d2'
        @($script:Seen.Names | ConvertFrom-Json) -join ',' | Should -Be 'srv01'
    }

    It 'real SQL: the parts read the same CIs from sidata.Ci as one read' -Skip:(-not $script:HasSql) {
        $name = 'si_test_rslm_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
        $m = New-Object System.Data.SqlClient.SqlConnection "Server=$($env:SI_TEST_LOCALSQL);Database=master;$($env:SI_TEST_SQL_AUTH);Connection Timeout=30"
        $m.Open(); try { $c = $m.CreateCommand(); $c.CommandText = "CREATE DATABASE [$name]"; $c.CommandTimeout = 300; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
        $cn = New-Object System.Data.SqlClient.SqlConnection ("Server=$($env:SI_TEST_LOCALSQL);Database=$name;$($env:SI_TEST_SQL_AUTH);Connection Timeout=30;Pooling=false")
        $cn.Open()
        try {
            foreach ($f in 'sql/si-data-schema.sql', 'sql/si-identity-schema.sql') { $c = $cn.CreateCommand(); $c.CommandTimeout = 300; $c.CommandText = [IO.File]::ReadAllText((Join-Path $script:SIRoot $f)); [void]$c.ExecuteNonQuery() }
            $script:Conn = $cn
            $seam = {
                param($Sql, $Params, $Mode)
                $c = $script:Conn.CreateCommand(); $c.CommandText = $Sql; $c.CommandTimeout = 120
                if ($Params) { foreach ($k in $Params.Keys) { $v = $Params[$k]; [void]$c.Parameters.AddWithValue('@' + $k, $(if ($null -eq $v) { [System.DBNull]::Value } else { $v })) } }
                if ($Mode -eq 'nonquery') { [void]$c.ExecuteNonQuery(); return }
                $rd = $c.ExecuteReader(); $out = New-Object System.Collections.Generic.List[object]
                try { while ($rd.Read()) { $h = @{}; for ($i = 0; $i -lt $rd.FieldCount; $i++) { $h[$rd.GetName($i)] = $rd.GetValue($i) }; $out.Add($h) } } finally { $rd.Close() }
                , $out.ToArray()
            }
            $vals = [System.Collections.Generic.List[string]]::new(); $links = [System.Collections.Generic.List[string]]::new()
            foreach ($ci in $script:Cis) {
                $doc = New-HsCiDoc $ci
                $lc = if ($ci.Life) { "'" + $ci.Life + "'" } else { 'NULL' }
                $vals.Add(("('{0}','device','{1}','2026-11-23','{2}',{3})" -f $ci.CiId, $ci.Name, $doc, $lc))
                foreach ($l in $ci.Links) { $links.Add(("('{0}','mde','device','{1}',1)" -f $ci.CiId, $l)) }
            }
            & $seam ("INSERT sidata.Ci (CiId, Class, Name, CollectionTime, DocJson, Lifecycle) VALUES " + ($vals -join ',') + ';') @{} 'nonquery'
            & $seam ("INSERT sidata.CiLink (CiId, Provider, RecordType, NativeId, IsPrimary) VALUES " + ($links -join ',') + ';') @{} 'nonquery'
            $one = Get-RAStreamCiIndex -Invoke $seam -Rows $script:CiRows -PartKeys 100000
            $parts = Get-RAStreamCiIndex -Invoke $seam -Rows $script:CiRows -PartKeys 4
            Get-HsIndexSig $parts | Should -BeExactly (Get-HsIndexSig $one)
            (Find-RACiForRow -Row $script:CiRows[0] -Index $parts).Ci.si_ci_id | Should -Be 'ci-1'
            (Find-RACiForRow -Row $script:CiRows[3] -Index $parts).Ci.si_ci_id | Should -Be 'ci-3'
        } finally {
            $script:Conn = $null; try { $cn.Dispose() } catch { }
            [System.Data.SqlClient.SqlConnection]::ClearAllPools()
            $m = New-Object System.Data.SqlClient.SqlConnection "Server=$($env:SI_TEST_LOCALSQL);Database=master;$($env:SI_TEST_SQL_AUTH);Connection Timeout=30"
            $m.Open(); try { $c = $m.CreateCommand(); $c.CommandTimeout = 300; $c.CommandText = "ALTER DATABASE [$name] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$name]"; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
        }
    }
}
