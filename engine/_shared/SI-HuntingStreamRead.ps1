#Requires -Version 5.1
<#
    SecurityInsight -- AN ADVANCED HUNTING ANSWER READ AS IT ARRIVES, NEVER HELD WHOLE (#1321, SCALE-2 #1314; with #1250).

    The older read (Invoke-SIGraphHttp + Invoke-SIHuntingQueryRest) holds one answer several times at once: the response
    body as ONE string (twice its size in memory, and a single allocation -- a very large answer cannot be held at all), the
    whole parsed tree (ConvertFrom-Json), and a per-row copy of every value bag. At the largest install one Detailed report's
    slice kept splitting "too large for this worker's memory" to depth 9 for days on a 4 CPU / 8 GiB worker -- the largest
    size Container Apps consumption offers.

    Here the response stream is read through a small buffer (System.Text.Json's Utf8JsonReader, compiled once per process
    with Add-Type -- the same way as SI-LaStreamRead.ps1). Each row of the answer's "results" array is cut out as its own
    bytes, unchanged, and a few MB of rows at a time are handed on as ONE JSON array text; the caller parses that text with
    the same ConvertFrom-Json the older read used on the whole body, so every value comes out exactly as before (the same
    types, dates, numbers, nulls, nested lists and objects, the same column order). The rows are then built into the same
    Results[].AdditionalProperties shape. Only the rows are held, never the body or the whole tree.

    What the older read does with an odd answer is kept: an empty body or a "results" of null = no rows; a "results" that is
    not a list is one element (as @() made it); the schema is the "schema" value as ConvertFrom-Json reads it. An answer this
    reader cannot read (not one JSON object, a field named twice, a reader fault) is NOT an error of the query: the caller
    asks the same query again the older way and says so in one line, and the reader is off for the rest of the process.

    SI_RA_HuntingStreamRead = on (the default, owner 2026-11-23) | off (Risk Analysis only; every other engine keeps the
    older read). pwsh 7 only; Windows PowerShell or a process where the reader cannot be built keeps
    the older read. Nothing here lives in this file's script scope (#836): the C# source comes from a function, the compiled
    type is found by its name, the process-wide state is $global:.
    Windows PowerShell 5.1 must still PARSE this file (support scripts embed engine files): no generic type with array
    arguments in a type literal.
#>

function Test-SIHuntingStreamOn {
    <# PURE over the global. SI_RA_HuntingStreamRead = off | false | 0 | no: the older read, exactly as before. Not set /
       anything else: on (the default, owner 2026-11-23) -- Risk Analysis reads its advanced hunting answers as they arrive;
       an answer the reader cannot read is still asked again the older way. #>
    param($Setting = $global:SI_RA_HuntingStreamRead)
    return -not (([string]$Setting).Trim().ToLowerInvariant() -in @('off', 'false', '0', 'no'))
}

function Get-SIHuntingStreamReaderSource {
    <# The reader's C# source. A FUNCTION, never a $script: variable (#836). @@NS@@ is replaced by a hash of this text. #>
    @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Threading;

namespace SecurityInsight.HuntingStream.@@NS@@
{
    public sealed class HuntingAnswer
    {
        public string SchemaJson { get; set; }      // the "schema" value as its JSON text; null = the answer has none
        public bool HasResults { get; set; }
        public bool ResultsNull { get; set; }
        public bool Empty { get; set; }             // no JSON value at all (an empty or blank body)
        public long Rows { get; set; }              // the elements handed on
        public int Chunks { get; set; }
        public long BytesRead { get; set; }
        public int LargestBuffer { get; set; }
        public long LargestChunkBytes { get; set; }
    }

    // the answer is not in the shape this reader reads: the caller reads it again the older way
    public sealed class HuntingFormatException : Exception
    {
        public HuntingFormatException(string m) : base(m) { }
    }

    // the caller's chunk callback failed (its own failure, never the reader's)
    public sealed class HuntingChunkException : Exception
    {
        public HuntingChunkException(Exception inner) : base("the rows could not be taken: " + (inner == null ? "" : inner.Message), inner) { }
    }

    // the answer did not arrive within the time left (only time spent WAITING for the network counts, as before)
    public sealed class HuntingTimeoutException : TimeoutException
    {
        public HuntingTimeoutException(string m, Exception inner) : base(m, inner) { }
    }

    public static class HuntingReader
    {
        private sealed class Deadline : IDisposable
        {
            private readonly CancellationTokenSource cts = new CancellationTokenSource();
            private readonly CancellationTokenRegistration reg;
            private long leftMs;
            private int fired;
            public Deadline(Stream s, long ms)
            {
                leftMs = ms;
                reg = cts.Token.Register(() => { Interlocked.Exchange(ref fired, 1); try { s.Dispose(); } catch { } });
            }
            public bool Fired { get { return Volatile.Read(ref fired) == 1; } }
            public int Read(Stream s, byte[] b, int off, int len)
            {
                if (leftMs <= 0) { Interlocked.Exchange(ref fired, 1); throw new HuntingTimeoutException("the answer of advanced hunting timed out while it was read", null); }
                var sw = Stopwatch.StartNew();
                cts.CancelAfter(TimeSpan.FromMilliseconds(leftMs));
                try { return s.Read(b, off, len); }
                finally
                {
                    if (!cts.IsCancellationRequested) cts.CancelAfter(Timeout.Infinite);
                    leftMs -= sw.ElapsedMilliseconds;
                }
            }
            public void Dispose() { reg.Dispose(); cts.Dispose(); }
        }

        private sealed class Chunk
        {
            public MemoryStream Buf = new MemoryStream();
            public int Count;
            public long Limit;
            public Action<string, int> On;
            public HuntingAnswer Ans;
            public void Add(byte[] b, int off, int len)
            {
                Buf.WriteByte(Count == 0 ? (byte)'[' : (byte)',');
                Buf.Write(b, off, len);
                Count++;
                if (Buf.Length >= Limit) Flush();
            }
            public void Flush()
            {
                if (Count == 0) return;
                Buf.WriteByte((byte)']');
                long len = Buf.Length;
                string text = Encoding.UTF8.GetString(Buf.GetBuffer(), 0, (int)len);
                int n = Count;
                Count = 0;
                if (Buf.Capacity > Limit * 2 + 65536) Buf = new MemoryStream(); else Buf.SetLength(0);
                if (len > Ans.LargestChunkBytes) Ans.LargestChunkBytes = len;
                try { On(text, n); }
                catch (Exception e) { throw new HuntingChunkException(e); }
                Ans.Rows += n;
                Ans.Chunks++;
            }
        }

        // timeoutMs > 0: the time the reads of the answer may WAIT for the network, together; 0 = no limit
        public static HuntingAnswer Read(Stream stream, long timeoutMs, int bufferSize, Action<string, int> onChunk, long chunkBytes)
        {
            if (stream == null) throw new ArgumentNullException("stream");
            if (onChunk == null) throw new ArgumentNullException("onChunk");
            if (timeoutMs <= 0) return ReadCore(stream, bufferSize, onChunk, chunkBytes, null);
            using (var dl = new Deadline(stream, timeoutMs))
            {
                try { return ReadCore(stream, bufferSize, onChunk, chunkBytes, dl); }
                catch (HuntingChunkException) { throw; }
                catch (HuntingTimeoutException) { throw; }
                catch (Exception e)
                {
                    if (dl.Fired) throw new HuntingTimeoutException("the answer of advanced hunting timed out while it was read: " + e.Message, e);
                    throw;
                }
            }
        }

        private static HuntingAnswer ReadCore(Stream stream, int bufferSize, Action<string, int> onChunk, long chunkBytes, Deadline dl)
        {
            var ans = new HuntingAnswer();
            var chunk = new Chunk { Limit = Math.Max(1024, chunkBytes), On = onChunk, Ans = ans };
            byte[] buf = new byte[Math.Max(1024, bufferSize)];
            int filled = 0, start = 0;
            bool final = false;
            long total = 0;
            int largest = buf.Length;
            // the depth ConvertFrom-Json allows (1024), not the reader's default of 64
            JsonReaderState state = new JsonReaderState(new JsonReaderOptions { MaxDepth = 1024 });
            int phase = 0;     // 0 before the answer, 1 in the answer object, 2 in its results list, 3 after it
            string prop = null;
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            bool bomChecked = false;
            bool any = false;

            while (true)
            {
                // keep what is not consumed; grow only when one unit (one row, one value) does not fit
                if (start > 0) { Buffer.BlockCopy(buf, start, buf, 0, filled - start); filled -= start; start = 0; }
                if (!final)
                {
                    if (filled == buf.Length)
                    {
                        var bigger = new byte[checked(buf.Length * 2)];
                        Buffer.BlockCopy(buf, 0, bigger, 0, filled);
                        buf = bigger;
                        if (buf.Length > largest) largest = buf.Length;
                    }
                    int n = dl == null ? stream.Read(buf, filled, buf.Length - filled) : dl.Read(stream, buf, filled, buf.Length - filled);
                    if (n <= 0) final = true; else { filled += n; total += n; }
                    if (!bomChecked && (filled >= 3 || final))
                    {
                        bomChecked = true;
                        if (filled >= 3 && buf[0] == 0xEF && buf[1] == 0xBB && buf[2] == 0xBF) start = 3;
                    }
                    if (!final && filled < buf.Length && n > 0) continue;
                }

                // nothing but blanks in the whole body: no JSON value at all (the reader itself refuses an empty final block)
                if (final && !any)
                {
                    bool blank = true;
                    for (int q = start; q < filled; q++) { byte ch = buf[q]; if (ch != 0x20 && ch != 0x09 && ch != 0x0A && ch != 0x0D) { blank = false; break; } }
                    if (blank) { ans.Empty = true; break; }
                }
                var reader = new Utf8JsonReader(new ReadOnlySpan<byte>(buf, start, filled - start), final, state);
                bool more = false;
                while (true)
                {
                    JsonReaderState before = reader.CurrentState;
                    long beforeAt = reader.BytesConsumed;
                    if (!reader.Read()) { more = true; break; }
                    any = true;
                    JsonTokenType tt = reader.TokenType;
                    bool container = (tt == JsonTokenType.StartObject || tt == JsonTokenType.StartArray);
                    if (phase == 0)
                    {
                        if (tt == JsonTokenType.StartObject) { phase = 1; continue; }
                        throw new HuntingFormatException("the advanced hunting answer is not a JSON object");
                    }
                    if (phase == 1)
                    {
                        if (tt == JsonTokenType.EndObject) { phase = 3; continue; }
                        if (tt == JsonTokenType.PropertyName)
                        {
                            prop = reader.GetString();
                            if (!seen.Add(prop ?? "")) throw new HuntingFormatException("the advanced hunting answer names a field twice");
                            continue;
                        }
                        bool isResults = string.Equals(prop, "results", StringComparison.OrdinalIgnoreCase);
                        if (isResults && tt == JsonTokenType.StartArray) { ans.HasResults = true; phase = 2; prop = null; continue; }
                        int us = start + (int)reader.TokenStartIndex;
                        if (container && !reader.TrySkip()) { state = before; start += (int)beforeAt; more = true; goto Refill; }
                        int ue = start + (int)reader.BytesConsumed;
                        if (isResults)
                        {
                            ans.HasResults = true;
                            if (tt == JsonTokenType.Null) ans.ResultsNull = true;
                            else chunk.Add(buf, us, ue - us);     // not a list: one element (as @() made it)
                        }
                        else if (string.Equals(prop, "schema", StringComparison.OrdinalIgnoreCase))
                        {
                            ans.SchemaJson = Encoding.UTF8.GetString(buf, us, ue - us);
                        }
                        prop = null;
                        continue;
                    }
                    if (phase == 2)
                    {
                        if (tt == JsonTokenType.EndArray) { phase = 1; continue; }
                        int us = start + (int)reader.TokenStartIndex;
                        if (container && !reader.TrySkip()) { state = before; start += (int)beforeAt; more = true; goto Refill; }
                        int ue = start + (int)reader.BytesConsumed;
                        chunk.Add(buf, us, ue - us);
                        continue;
                    }
                    throw new HuntingFormatException("the advanced hunting answer goes on after its end");
                }
                state = reader.CurrentState;
                start += (int)reader.BytesConsumed;
            Refill:
                if (final)
                {
                    if (!any) { ans.Empty = true; break; }
                    if (phase != 3) throw new HuntingFormatException("the advanced hunting answer ended before it was complete");
                    break;
                }
                if (!more) continue;
            }
            chunk.Flush();
            ans.BytesRead = total;
            ans.LargestBuffer = largest;
            return ans;
        }
    }
}
'@
}

function Get-SIHuntingStreamReaderType {
    <# The compiled reader (SecurityInsight.HuntingStream.H<hash>.HuntingReader), built once per process; $null where it
       cannot be (Windows PowerShell, a compile that fails, or the reader was turned off for this process after it failed on
       an answer) -- the caller then keeps the older read. -Reason: why it is off. #>
    param([switch]$Reason)
    if ($Reason) { return [string]$global:SI_HuntingStreamOff }
    if ($PSVersionTable.PSEdition -ne 'Core') { return $null }
    if ($global:SI_HuntingStreamOff) { return $null }
    $src = Get-SIHuntingStreamReaderSource
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $h = ([System.BitConverter]::ToString($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes([string]$src))) -replace '-', '').Substring(0, 20) } finally { $sha.Dispose() }
    $name = 'SecurityInsight.HuntingStream.H' + $h + '.HuntingReader'
    $t = $name -as [type]
    if ($null -ne $t) { return $t }
    try {
        Add-Type -TypeDefinition ([string]$src).Replace('@@NS@@', 'H' + $h) -Language CSharp -ErrorAction Stop
        $t = $name -as [type]
        if ($null -eq $t) { throw 'the compiled type was not found' }
        return $t
    } catch {
        $global:SI_HuntingStreamOff = 'the reader could not be built in this process: ' + (Get-SIHuntingStreamShortReason $_.Exception.Message)
        return $null
    }
}

function Get-SIHuntingStreamShortReason {
    <# PURE. The first line of an error text, at most 300 characters. #>
    param([AllowNull()][AllowEmptyString()][string]$Text)
    $s = ([string]$Text -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 1)
    if (-not $s) { return 'no reason given' }
    $s = $s.Trim()
    if ($s.Length -gt 300) { $s = $s.Substring(0, 300) + ' ...' }
    return $s
}

function Write-SIHuntingStreamFallback {
    <# ONE plain line on the run log: the older read is used instead of the streaming one, and why. -Once: once per process
       for that reason (the reader cannot be built: every later read is the older one too). The rows are the same. #>
    param([AllowNull()][AllowEmptyString()][string]$Reason, [switch]$Once)
    if ([string]::IsNullOrWhiteSpace($Reason)) { $Reason = 'the streaming reader is not available in this process' }
    if ($Once) {
        if ($null -eq $global:SI_HuntingStreamFallbackSaid) { $global:SI_HuntingStreamFallbackSaid = @{} }
        if ($global:SI_HuntingStreamFallbackSaid.ContainsKey($Reason)) { return }
        $global:SI_HuntingStreamFallbackSaid[$Reason] = $true
    }
    Write-Host ('Advanced hunting answers are read the older way (whole, then parsed) instead of as they arrive -- {0}. The rows are the same; the read uses more memory.' -f $Reason) -ForegroundColor DarkYellow
}

function Test-SIHuntingStreamOutOfMemory {
    <# PURE. An OutOfMemoryException anywhere in the chain, by type or by its text. #>
    param($Exception)
    for ($e = $Exception; $null -ne $e; $e = $e.InnerException) {
        if ($e -is [System.OutOfMemoryException]) { return $true }
        if ([string]$e.Message -match '(?i)OutOfMemoryException|Insufficient memory') { return $true }
    }
    $false
}

function Read-SIHuntingAnswerStream {
    <#
        One advanced hunting answer READ FROM ITS STREAM -> @{ Failed; ParseError; Schema; Rows; BytesRead; Chunks;
        LargestBuffer; LargestChunkBytes } -- Rows: the rows in the shape Invoke-SIHuntingQueryRest returns them (each an
        object with an AdditionalProperties bag), built exactly as the older read builds them, from the same ConvertFrom-Json.
          * Failed (text): the answer could not be read this way (not one JSON object, a field named twice, a reader fault)
            -- the caller asks the same query again the older way. The reader is then off for this process. A ROW COUNT that
            does not add up (one part, or the whole answer) is Failed too: that one answer is read again the older way
            (never fewer rows, never a query defect) and the reader stays on for other answers.
          * ParseError (text): the rows could not be taken (ConvertFrom-Json refused them, or the process ran out of memory)
            -- what the older read says as "a body that is not JSON".
          * a network failure, or the time left running out while the answer arrives, is THROWN (the transport's own error).
        -TimeoutSec: the time the reads may wait for the network (0 = no limit). -ChunkBytes: about how many bytes of the
        answer are parsed at a time (default 4 MB). -BufferBytes: the first read buffer (it grows only for one larger row).
    #>
    param([Parameter(Mandatory)][System.IO.Stream]$Stream, [int]$TimeoutSec = 0, [long]$ChunkBytes = 0, [int]$BufferBytes = 65536)
    $t = Get-SIHuntingStreamReaderType
    if ($null -eq $t) { return [pscustomobject]@{ Failed = $(if (Get-SIHuntingStreamReaderType -Reason) { Get-SIHuntingStreamReaderType -Reason } else { 'the streaming reader is not available in this process' }); ParseError = $null; Schema = $null; Rows = $null } }
    if ($ChunkBytes -le 0) { $ChunkBytes = 4MB }
    $__hsRows = [System.Collections.Generic.List[object]]::new()
    # a row-count mismatch is the READER's fault, never the query's: noted here, the answer is then Failed (that one answer
    # is asked again the older way -- never fewer rows, never a query defect), and the reader stays on for other answers
    $__hsCount = @{ Mismatch = $null }
    # the rows of one chunk: the SAME conversion as the older read (Invoke-SIHuntingQueryRest) -- ConvertFrom-Json, then a bag
    # per row in the order of its fields
    $__hsOn = [System.Action[string, int]] {
        param([string]$Text, [int]$Count)
        # -ErrorAction Stop: a refused text is an ERROR of this chunk, never rows silently missing
        $parsed = ConvertFrom-Json -InputObject $Text -NoEnumerate -ErrorAction Stop
        $__hsBefore = $__hsRows.Count
        foreach ($r in $parsed) {
            $bag = [ordered]@{}
            foreach ($p in $r.PSObject.Properties) { $bag[$p.Name] = $p.Value }
            $__hsRows.Add([pscustomobject]@{ AdditionalProperties = $bag })
        }
        # NEVER FEWER ROWS: the rows taken from this chunk must be exactly the elements the reader cut out of the answer. Any
        # difference is an error of the chunk (the slice is then not kept and is asked again) -- never a short slice.
        $__hsAdded = $__hsRows.Count - $__hsBefore
        if ($__hsAdded -ne $Count) {
            $__hsCount.Mismatch = ('the rows of a part of the answer do not add up: the reader cut out {0} row(s), {1} were taken' -f $Count, $__hsAdded)
            throw $__hsCount.Mismatch
        }
    }
    $a = $null
    try {
        $a = $t::Read($Stream, [long]([long]$TimeoutSec * 1000L), [int]$BufferBytes, $__hsOn, [long]$ChunkBytes)
    } catch {
        $ex = $_.Exception
        $__hsRows = $null
        if (Test-SIHuntingStreamOutOfMemory -Exception $ex) {
            [System.GC]::Collect()
            return [pscustomobject]@{ Failed = $null; ParseError = "Exception of type 'System.OutOfMemoryException' was thrown."; Schema = $null; Rows = $null }
        }
        for ($e = $ex; $null -ne $e; $e = $e.InnerException) {
            $tn = $e.GetType().Name
            if ($tn -eq 'HuntingChunkException') {
                if ($__hsCount.Mismatch) { return [pscustomobject]@{ Failed = [string]$__hsCount.Mismatch; ParseError = $null; Schema = $null; Rows = $null } }
                $cause = $e.InnerException
                while ($null -ne $cause -and ($cause -is [System.Management.Automation.MethodInvocationException] -or $cause -is [System.Management.Automation.ActionPreferenceStopException]) -and $null -ne $cause.InnerException) { $cause = $cause.InnerException }
                $why = if ($null -ne $cause) { [string]$cause.Message } else { [string]$e.Message }
                return [pscustomobject]@{ Failed = $null; ParseError = $why; Schema = $null; Rows = $null }
            }
            if ($tn -eq 'HuntingTimeoutException') { throw $e }
        }
        for ($e = $ex; $null -ne $e; $e = $e.InnerException) {
            if ($e -is [System.IO.IOException] -or $e -is [System.Net.Http.HttpRequestException] -or $e -is [System.Net.Sockets.SocketException] -or $e -is [System.Net.WebException]) { throw $e }
        }
        $inner = $ex; while ($null -ne $inner.InnerException) { $inner = $inner.InnerException }
        $why = 'the streaming reader failed on an answer: ' + (Get-SIHuntingStreamShortReason $inner.Message)
        $global:SI_HuntingStreamOff = $why
        return [pscustomobject]@{ Failed = $why; ParseError = $null; Schema = $null; Rows = $null }
    }
    # a body of only blanks: what the older read makes of it is ITS answer -- asked again that way (never happens with the
    # service; the reader stays on). An empty body (no bytes) is no rows, as the older read has it.
    # and the whole answer: the rows taken equal every element the reader handed on (never a short answer)
    if ([long]$__hsRows.Count -ne [long]$a.Rows) {
        $__hsWhy = ('the rows of the answer do not add up: the reader cut out {0} row(s), {1} were taken' -f [long]$a.Rows, $__hsRows.Count)
        $__hsRows = $null
        return [pscustomobject]@{ Failed = $__hsWhy; ParseError = $null; Schema = $null; Rows = $null }
    }
    if ($a.Empty -and [long]$a.BytesRead -gt 0) {
        return [pscustomobject]@{ Failed = 'the answer is blank'; ParseError = $null; Schema = $null; Rows = $null }
    }
    # the schema as the older read has it ($resp.schema): the value as ConvertFrom-Json reads it, a list kept a list
    $schema = $null
    if ($null -ne $a.SchemaJson) {
        try { $schema = ConvertFrom-Json -InputObject ([string]$a.SchemaJson) -NoEnumerate -ErrorAction Stop }
        catch { return [pscustomobject]@{ Failed = $null; ParseError = [string]$_.Exception.Message; Schema = $null; Rows = $null } }
    }
    $global:SI_HuntingStreamLast = [pscustomobject]@{ BytesRead = [long]$a.BytesRead; Rows = [long]$a.Rows; Chunks = [int]$a.Chunks; LargestBuffer = [int]$a.LargestBuffer; LargestChunkBytes = [long]$a.LargestChunkBytes }
    [pscustomobject]@{ Failed = $null; ParseError = $null; Schema = $schema; Rows = $__hsRows; BytesRead = [long]$a.BytesRead; Chunks = [int]$a.Chunks
                       LargestBuffer = [int]$a.LargestBuffer; LargestChunkBytes = [long]$a.LargestChunkBytes; Empty = [bool]$a.Empty }
}
