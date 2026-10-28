#Requires -Version 5.1
<#
    SecurityInsight -- A LOG ANALYTICS ANSWER READ AS IT ARRIVES, NEVER HELD WHOLE (Risk Analysis' lookups and answers;
    owner rule "same method, all sizes; stream always").

    The lean read (#639, SI-AzRest.ps1 ConvertFrom-SILaQueryRows) reads the answer's BYTES into one array of their full
    length, parses them into a JsonDocument (an index of every token beside them), and only then builds the rows -- so
    while a lookup is read the process holds the whole answer about three times (bytes + index + rows). A Risk Analysis
    lookup at a large install is a tenant-sized answer (the identity CI lookup of a 153,000-user tenant: every key of every
    identity), read in parts of up to the service's own answer limit; the large install's Risk Analysis job ran out of
    memory on 2 CPU / 4 GiB (#730).

    Here the response stream is read through a small buffer: each ROW is parsed when its bytes are in, turned into the row
    object at once, and its bytes are let go. Only the rows are held -- the same rows the lean read builds: the same
    columns in the same order, the same TEXT values (strings as sent, numbers in the service's own spelling, true / false,
    null stays null, a nested value as its raw JSON text), the table named PrimaryResult else the first, the column list
    (name / type) and the partial-error object. Compact rows (SI_LaCompactRows, Get-SILaCompactRowType) when the caller
    asks for them, PSCustomObject rows otherwise.

    pwsh 7 only (System.Text.Json's Utf8JsonReader, compiled once per process with Add-Type). Windows PowerShell, or a
    process where the reader cannot be compiled: Get-SILaStreamReaderType answers $null and the caller keeps the lean read.

    #836 (found 2026-10-20): NOTHING HERE LIVES ONLY IN THIS FILE'S SCRIPT SCOPE. A function reads $script: of its CALLER's
    script, and in a container the entry point (container\Start-SIInContainer.ps1) dot-sources SI-AzRest.ps1 -> this file
    in ITS scope while every engine runs as its own script and skips reloading it -- so a $script: source was $null there,
    Add-Type failed, the failure was swallowed and no container engine ever streamed. The C# source comes from a FUNCTION
    (Get-SILaStreamReaderSource), the compiled type is found by its name, and the state a run must share (the reader is off
    and why, the last read's numbers) is $global:. The older read stays the fallback, but it is never silent: one plain line
    on the run log says the older read is used and why (Write-SILaStreamFallback).
#>

function Get-SILaStreamReaderSource {
    <# The reader's C# source. A FUNCTION, never a $script: variable (#836): callable from any script's scope. #>
    @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Management.Automation;
using System.Reflection;
using System.Text;
using System.Text.Json;

namespace SecurityInsight.LaStream
{
    public sealed class LaStreamAnswer
    {
        public object[] Rows { get; set; }
        public string[] ColumnNames { get; set; }
        public string[] ColumnTypes { get; set; }
        public string ErrorJson { get; set; }
        public long BytesRead { get; set; }
        public int LargestBuffer { get; set; }
        // with a page callback: the rows handed on and in how many pages (Rows is then empty)
        public long RowsDelivered { get; set; }
        public int Pages { get; set; }
    }

    // the caller's own page callback failed -- not a fault of the reader or of the answer
    public sealed class LaStreamPageException : Exception
    {
        public LaStreamPageException(Exception inner) : base("the page callback failed: " + (inner == null ? "" : inner.Message), inner) { }
    }

    public static class LaStreamReader
    {
        // the rows handed on a page at a time: the table being handed on, the answer bytes of the rows waiting, the totals
        private sealed class PageSink
        {
            public Action<object[]> On;
            public long Limit;
            public long Bytes;
            public object Table;
            public bool FromNonPrimary;
            public long Rows;
            public int Pages;
        }

        private static void Flush(PageSink sink, List<object> rows)
        {
            if (sink == null || rows == null || rows.Count == 0) { if (sink != null) sink.Bytes = 0; return; }
            object[] page = rows.ToArray();
            rows.Clear();
            sink.Bytes = 0;
            try { sink.On(page); }
            catch (Exception e) { throw new LaStreamPageException(e); }
            sink.Rows += page.Length;
            sink.Pages++;
        }

        public static LaStreamAnswer Read(Stream stream, bool compact, Func<string[], ConstructorInfo> compactCtorFor, int bufferSize, Func<string[], string[], object> plainRowFor)
        {
            return Read(stream, compact, compactCtorFor, bufferSize, plainRowFor, null, 0);
        }

        // onPage: the primary table's rows are handed on a page at a time (about pageBytes of the answer each) and never
        // collected; the answer's Rows is then empty, RowsDelivered / Pages say what was handed on
        public static LaStreamAnswer Read(Stream stream, bool compact, Func<string[], ConstructorInfo> compactCtorFor, int bufferSize, Func<string[], string[], object> plainRowFor, Action<object[]> onPage, long pageBytes)
        {
            PageSink sink = onPage == null ? null : new PageSink { On = onPage, Limit = Math.Max(1024, pageBytes) };
            return ReadCore(stream, compact, compactCtorFor, bufferSize, plainRowFor, sink);
        }

        private enum Ctx { Root, Tables, Table, Columns, Rows, Done }

        private sealed class TableAcc
        {
            public int Index;
            public string Name = "";
            public List<string> Names = new List<string>();
            public List<string> Types = new List<string>();
            public bool ColumnsDone;
            public bool Keep = true;
            public ConstructorInfo Ctor;
            public bool CtorAsked;
            public Dictionary<string, string> Pool;
            public List<object> Rows = new List<object>();
            public List<string[]> Early;   // rows met before the column list (kept as values, built at the end)
            public Func<string[], string[], object> Plain;   // names that differ only in case: the row is built as the lean read builds it
            public bool PlainChecked;
        }

        private static LaStreamAnswer ReadCore(Stream stream, bool compact, Func<string[], ConstructorInfo> compactCtorFor, int bufferSize, Func<string[], string[], object> plainRowFor, PageSink sink)
        {
            if (stream == null) throw new ArgumentNullException("stream");
            byte[] buf = new byte[Math.Max(1024, bufferSize)];
            int filled = 0, start = 0;
            bool final = false;
            long total = 0;
            int largest = buf.Length;
            JsonReaderState state = new JsonReaderState();
            var stack = new List<Ctx>();
            string prop = null;
            TableAcc cur = null, first = null, primary = null;
            int tableCount = 0;
            string errorJson = null;
            bool bomChecked = false;

            while (true)
            {
                // fill: keep what is not consumed, grow only when one unit does not fit
                if (start > 0) { Buffer.BlockCopy(buf, start, buf, 0, filled - start); filled -= start; start = 0; }
                if (!final)
                {
                    if (filled == buf.Length)
                    {
                        var bigger = new byte[buf.Length * 2]; Buffer.BlockCopy(buf, 0, bigger, 0, filled); buf = bigger;
                        if (buf.Length > largest) largest = buf.Length;
                    }
                    int n = stream.Read(buf, filled, buf.Length - filled);
                    if (n <= 0) final = true; else { filled += n; total += n; }
                    if (!bomChecked && (filled >= 3 || final))
                    {
                        bomChecked = true;
                        if (filled >= 3 && buf[0] == 0xEF && buf[1] == 0xBB && buf[2] == 0xBF) start = 3;
                    }
                    if (!final && filled < buf.Length && n > 0) continue;   // read until the buffer is full or the stream ends
                }

                var reader = new Utf8JsonReader(new ReadOnlySpan<byte>(buf, start, filled - start), final, state);
                bool more = false;
                while (true)
                {
                    JsonReaderState before = reader.CurrentState;
                    long beforeAt = reader.BytesConsumed;
                    if (!reader.Read()) { more = true; break; }
                    JsonTokenType tt = reader.TokenType;
                    Ctx ctx = stack.Count == 0 ? Ctx.Root : stack[stack.Count - 1];
                    if (stack.Count == 0)
                    {
                        if (tt == JsonTokenType.StartObject) { stack.Add(Ctx.Root); continue; }
                        throw new JsonException("the Log Analytics answer is not a JSON object");
                    }
                    if (tt == JsonTokenType.PropertyName) { prop = reader.GetString(); continue; }

                    // a UNIT: a value that is read whole (a row, a column, the error, anything skipped) -- its bytes must all be
                    // in the buffer; when they are not, everything goes back to before its first token and more is read
                    bool container = (tt == JsonTokenType.StartObject || tt == JsonTokenType.StartArray);
                    switch (ctx)
                    {
                        case Ctx.Root:
                            if (tt == JsonTokenType.EndObject) { stack[stack.Count - 1] = Ctx.Done; continue; }
                            if (prop == "tables" && tt == JsonTokenType.StartArray) { stack.Add(Ctx.Tables); prop = null; continue; }
                            {
                                int us = start + (int)reader.TokenStartIndex;
                                if (container && !reader.TrySkip()) { state = before; start += (int)beforeAt; more = true; goto Refill; }
                                int ue = start + (int)reader.BytesConsumed;
                                if (prop == "error")
                                {
                                    errorJson = (tt == JsonTokenType.Null) ? null : Encoding.UTF8.GetString(buf, us, ue - us);
                                }
                                prop = null;
                                continue;
                            }
                        case Ctx.Tables:
                            if (tt == JsonTokenType.EndArray) { stack.RemoveAt(stack.Count - 1); continue; }
                            if (tt == JsonTokenType.StartObject)
                            {
                                cur = new TableAcc { Index = tableCount++, Plain = plainRowFor };
                                // a later table's rows are kept only while no PrimaryResult was found before it
                                cur.Keep = (primary == null);
                                if (compact) cur.Pool = new Dictionary<string, string>(StringComparer.Ordinal);
                                stack.Add(Ctx.Table); prop = null; continue;
                            }
                            if (container && !reader.TrySkip()) { state = before; start += (int)beforeAt; more = true; goto Refill; }
                            continue;
                        case Ctx.Table:
                            if (tt == JsonTokenType.EndObject)
                            {
                                stack.RemoveAt(stack.Count - 1);
                                FinishTable(cur, compact, compactCtorFor);
                                if (sink != null && object.ReferenceEquals(sink.Table, cur)) Flush(sink, cur.Rows);
                                if (cur.Index == 0) first = cur;
                                if (primary == null && cur.Name == "PrimaryResult") { primary = cur; if (first != null && first != cur) first.Rows = null; }
                                else if (cur.Index != 0) cur.Rows = null;
                                cur = null; prop = null; continue;
                            }
                            if (prop == "name" && !container)
                            {
                                cur.Name = (tt == JsonTokenType.String) ? (reader.GetString() ?? "") : "";
                                prop = null; continue;
                            }
                            if (prop == "columns" && tt == JsonTokenType.StartArray) { stack.Add(Ctx.Columns); prop = null; continue; }
                            if (prop == "rows" && tt == JsonTokenType.StartArray) { stack.Add(Ctx.Rows); prop = null; continue; }
                            if (container && !reader.TrySkip()) { state = before; start += (int)beforeAt; more = true; goto Refill; }
                            prop = null; continue;
                        case Ctx.Columns:
                            if (tt == JsonTokenType.EndArray) { stack.RemoveAt(stack.Count - 1); cur.ColumnsDone = true; continue; }
                            {
                                int us = start + (int)reader.TokenStartIndex;
                                if (container && !reader.TrySkip()) { state = before; start += (int)beforeAt; more = true; goto Refill; }
                                int ue = start + (int)reader.BytesConsumed;
                                if (tt == JsonTokenType.StartObject) ReadColumn(buf, us, ue - us, cur);
                                continue;
                            }
                        case Ctx.Rows:
                            if (tt == JsonTokenType.EndArray) { stack.RemoveAt(stack.Count - 1); continue; }
                            {
                                int us = start + (int)reader.TokenStartIndex;
                                if (container && !reader.TrySkip()) { state = before; start += (int)beforeAt; more = true; goto Refill; }
                                int ue = start + (int)reader.BytesConsumed;
                                if (tt == JsonTokenType.StartArray && cur.Keep)
                                {
                                    if (sink == null) AddRow(buf, us, ue - us, cur, compact, compactCtorFor);
                                    else if (SinkTakes(sink, cur))
                                    {
                                        AddRow(buf, us, ue - us, cur, compact, compactCtorFor);
                                        sink.Bytes += (ue - us);
                                        if (sink.Bytes >= sink.Limit) Flush(sink, cur.Rows);
                                    }
                                }
                                continue;
                            }
                        default:
                            if (container && !reader.TrySkip()) { state = before; start += (int)beforeAt; more = true; goto Refill; }
                            continue;
                    }
                }
                state = reader.CurrentState;
                start += (int)reader.BytesConsumed;
            Refill:
                if (final)
                {
                    if (stack.Count == 0 || stack[0] != Ctx.Done) throw new JsonException("the Log Analytics answer ended before it was complete");
                    break;
                }
                if (!more) continue;
            }

            TableAcc pick = primary ?? first;
            var ans = new LaStreamAnswer { ErrorJson = errorJson, BytesRead = total, LargestBuffer = largest };
            if (sink != null) { ans.RowsDelivered = sink.Rows; ans.Pages = sink.Pages; }
            if (pick != null)
            {
                ans.Rows = (pick.Rows == null || sink != null) ? new object[0] : pick.Rows.ToArray();
                ans.ColumnNames = pick.Names.ToArray();
                ans.ColumnTypes = pick.Types.ToArray();
            }
            else { ans.Rows = new object[0]; ans.ColumnNames = new string[0]; ans.ColumnTypes = new string[0]; }
            return ans;
        }

        // with a page callback: does this table's row go to the pages? The table named PrimaryResult, else the first table --
        // as the whole read picks it. A PrimaryResult that comes after another table's rows were handed on cannot be read in
        // pages (those rows are gone): the read fails, never a wrong set handed on.
        private static bool SinkTakes(PageSink sink, TableAcc cur)
        {
            if (object.ReferenceEquals(sink.Table, cur)) return true;
            if (sink.Table == null)
            {
                if (cur.Name == "PrimaryResult" || cur.Index == 0) { sink.Table = cur; sink.FromNonPrimary = (cur.Name != "PrimaryResult"); return true; }
                return false;
            }
            if (cur.Name == "PrimaryResult" && sink.FromNonPrimary)
            {
                if (sink.Rows > 0) throw new InvalidOperationException("the Log Analytics answer names its primary table after another table whose rows were already handed on -- it cannot be read in pages");
                ((TableAcc)sink.Table).Rows.Clear();
                sink.Table = cur; sink.FromNonPrimary = false; sink.Bytes = 0;
                return true;
            }
            return false;
        }

        private static void ReadColumn(byte[] buf, int off, int len, TableAcc t)
        {
            var r = new Utf8JsonReader(new ReadOnlySpan<byte>(buf, off, len), true, new JsonReaderState());
            r.Read();   // StartObject
            string name = null, type = null; bool hasName = false;
            while (r.Read())
            {
                if (r.TokenType == JsonTokenType.EndObject && r.CurrentDepth == 0) break;
                if (r.TokenType != JsonTokenType.PropertyName) continue;
                string p = r.GetString();
                r.Read();
                if (r.TokenType == JsonTokenType.StartObject || r.TokenType == JsonTokenType.StartArray) { r.Skip(); continue; }
                if (p == "name") { name = (r.TokenType == JsonTokenType.String || r.TokenType == JsonTokenType.Null) ? r.GetString() : Encoding.UTF8.GetString(r.ValueSpan.ToArray()); hasName = true; }
                else if (p == "type") { type = (r.TokenType == JsonTokenType.String || r.TokenType == JsonTokenType.Null) ? r.GetString() : Encoding.UTF8.GetString(r.ValueSpan.ToArray()); }
            }
            if (!hasName) throw new KeyNotFoundException("a column of the Log Analytics answer has no name");
            t.Names.Add(name); t.Types.Add(type);
        }

        private static string[] ReadCells(byte[] buf, int off, int len, int nCols, Dictionary<string, string> pool)
        {
            var r = new Utf8JsonReader(new ReadOnlySpan<byte>(buf, off, len), true, new JsonReaderState());
            r.Read();   // StartArray
            var cells = nCols >= 0 ? new string[nCols] : null;
            var open = nCols < 0 ? new List<string>() : null;
            int i = 0;
            while (r.Read())
            {
                if (r.TokenType == JsonTokenType.EndArray && r.CurrentDepth == 0) break;
                string s;
                switch (r.TokenType)
                {
                    case JsonTokenType.String: s = r.GetString(); break;
                    case JsonTokenType.Null: s = null; break;
                    case JsonTokenType.True: s = "true"; break;
                    case JsonTokenType.False: s = "false"; break;
                    case JsonTokenType.StartObject:
                    case JsonTokenType.StartArray:
                        {
                            int ts = (int)r.TokenStartIndex;
                            r.Skip();
                            s = Encoding.UTF8.GetString(buf, off + ts, (int)r.BytesConsumed - ts);
                            break;
                        }
                    default: s = Encoding.UTF8.GetString(r.ValueSpan.ToArray()); break;
                }
                if (s != null && pool != null && s.Length <= 32)
                {
                    string p0;
                    if (pool.TryGetValue(s, out p0)) s = p0; else pool[s] = s;
                }
                if (open != null) open.Add(s);
                else if (i < nCols) cells[i] = s;
                i++;
            }
            return open != null ? open.ToArray() : cells;
        }

        private static object MakeRow(string[] cells, TableAcc t)
        {
            if (t.Ctor != null) return t.Ctor.Invoke(new object[] { cells });
            if (!t.PlainChecked)
            {
                t.PlainChecked = true;
                var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase); bool dup = false;
                foreach (var nm in t.Names) { if (nm != null && !seen.Add(nm)) { dup = true; break; } }
                if (!dup) t.Plain = null;
            }
            if (t.Plain != null) return t.Plain(t.Names.ToArray(), cells);
            var o = new PSObject();
            int n = t.Names.Count;
            for (int i = 0; i < n; i++)
            {
                string v = i < cells.Length ? cells[i] : null;
                var existing = o.Properties[t.Names[i]];
                if (existing != null) existing.Value = v; else o.Properties.Add(new PSNoteProperty(t.Names[i], v));
            }
            return o;
        }

        private static void AddRow(byte[] buf, int off, int len, TableAcc t, bool compact, Func<string[], ConstructorInfo> compactCtorFor)
        {
            if (!t.ColumnsDone && t.Names.Count == 0)
            {
                if (t.Early == null) t.Early = new List<string[]>();
                t.Early.Add(ReadCells(buf, off, len, -1, null));
                return;
            }
            if (compact && !t.CtorAsked) { MakeRowPrepare(t, compactCtorFor); }
            var cells = ReadCells(buf, off, len, t.Names.Count, t.Ctor != null ? t.Pool : null);
            t.Rows.Add(MakeRow(cells, t));
        }

        private static void MakeRowPrepare(TableAcc t, Func<string[], ConstructorInfo> compactCtorFor)
        {
            // the compact type for these columns, asked once; none -> PSCustomObject rows without pooling, as the lean read
            t.CtorAsked = true;
            if (compactCtorFor != null) t.Ctor = compactCtorFor(t.Names.ToArray());
            if (t.Ctor == null) t.Pool = null;
        }

        private static void FinishTable(TableAcc t, bool compact, Func<string[], ConstructorInfo> compactCtorFor)
        {
            if (t.Early == null) return;
            if (!t.Keep) { t.Early = null; return; }
            var built = new List<object>(t.Early.Count + t.Rows.Count);
            if (compact && !t.CtorAsked) MakeRowPrepare(t, compactCtorFor);
            int n = t.Names.Count;
            foreach (var raw in t.Early)
            {
                var cells = new string[n];
                for (int i = 0; i < n && i < raw.Length; i++) cells[i] = raw[i];
                built.Add(MakeRow(cells, t));
            }
            built.AddRange(t.Rows);
            t.Rows = built; t.Early = null;
        }
    }
}
'@
}

function Get-SILaStreamReaderType {
    <# The compiled reader ([SecurityInsight.LaStream.LaStreamReader]), built once per process; $null where it cannot be
       (Windows PowerShell, or a compile that fails -- the caller then keeps the lean read). Scope-independent (#836): the
       compiled type is found by its NAME (a type is per process), the source comes from a function, and a compile that
       failed is remembered for the whole process in $global:SI_LaStreamReaderOff (its reason) -- tried once, not per read. #>
    if ($PSVersionTable.PSEdition -ne 'Core') { return $null }
    # off for this process (it could not be built, or it failed on an answer -- Read-SILaQueryStreamSafe): the older read
    if ($global:SI_LaStreamReaderOff) { return $null }
    $t = 'SecurityInsight.LaStream.LaStreamReader' -as [type]
    if ($null -ne $t) { return $t }
    try {
        $src = Get-SILaStreamReaderSource
        if ([string]::IsNullOrWhiteSpace([string]$src)) { throw 'its source is empty' }
        Add-Type -TypeDefinition $src -Language CSharp -ErrorAction Stop
        $t = 'SecurityInsight.LaStream.LaStreamReader' -as [type]
        if ($null -eq $t) { throw 'the compiled type was not found' }
        return $t
    } catch {
        $global:SI_LaStreamReaderOff = 'the reader could not be built in this process: ' + (Get-SILaStreamShortReason $_.Exception.Message)
        return $null
    }
}

function Get-SILaStreamShortReason {
    <# PURE. The first line of an error text, at most 300 characters (a compiler error lists every line it refused). #>
    param([AllowNull()][AllowEmptyString()][string]$Text)
    $s = ([string]$Text -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 1)
    if (-not $s) { return 'no reason given' }
    $s = $s.Trim()
    if ($s.Length -gt 300) { $s = $s.Substring(0, 300) + ' ...' }
    return $s
}

function Write-SILaStreamFallback {
    <#
        #836: the older read is used instead of the streaming one -- ONE plain line on the run log (the transcript) saying
        so and why. -Once: said once per process for that reason (the reader cannot be built: every later read is the
        older one too, and saying it per read would flood the log). Without -Once (one read whose stream failed and was
        read again the older way) it is said every time it happens. The results are the same either way.
    #>
    param([AllowNull()][AllowEmptyString()][string]$Reason, [switch]$Once)
    if ([string]::IsNullOrWhiteSpace($Reason)) { $Reason = 'the streaming reader is not available in this process' }
    if ($Once) {
        if ($null -eq $global:SI_LaStreamFallbackSaid) { $global:SI_LaStreamFallbackSaid = @{} }
        if ($global:SI_LaStreamFallbackSaid.ContainsKey($Reason)) { return }
        $global:SI_LaStreamFallbackSaid[$Reason] = $true
    }
    Write-Host ('Log Analytics answers are read the older way (whole, then parsed) instead of as they arrive -- {0}. The rows are the same; the read uses more memory.' -f $Reason) -ForegroundColor DarkYellow
}

function Read-SILaQueryStreamSafe {
    <#
        #836: ConvertFrom-SILaQueryStream for Invoke-SILaQuery's -ReadStream -- DATA FIRST: a read that fails (the reader
        throws, the answer is not valid JSON, the connection drops mid-answer) is NOT an error of the query: it answers a
        marker (.SILaStreamFailed = why) and Invoke-SILaQuery reads the same query again the older way and says so in one
        line. A failure that is not the network's (IOException / a socket error) turns streaming off for the rest of the
        process ($global:SI_LaStreamReaderOff) so a reader fault never doubles every read.
    #>
    param([Parameter(Mandatory)][System.IO.Stream]$Stream, [switch]$Compact,
          # the rows a page at a time (ConvertFrom-SILaQueryStream -OnPage); -PageState counts the pages handed on so far
          [scriptblock]$OnPage, [long]$PageBytes = 4MB, [hashtable]$PageState)
    try {
        if ($OnPage) { return (ConvertFrom-SILaQueryStream -Stream $Stream -Compact:$Compact -OnPage $OnPage -PageBytes $PageBytes -PageState $PageState) }
        return (ConvertFrom-SILaQueryStream -Stream $Stream -Compact:$Compact)
    }
    catch {
        $ex = $_.Exception
        # the CALLER's page callback failed (a page could not be stored): its own failure, passed on as it is -- never a
        # reader fault, never read again
        for ($e = $ex; $null -ne $e; $e = $e.InnerException) {
            if ($e.GetType().FullName -eq 'SecurityInsight.LaStream.LaStreamPageException') {
                $cause = $e.InnerException
                while ($cause -is [System.Management.Automation.MethodInvocationException] -and $null -ne $cause.InnerException) { $cause = $cause.InnerException }
                if ($cause -is [System.Management.Automation.RuntimeException] -and $cause.ErrorRecord) { throw $cause.ErrorRecord }
                if ($null -ne $cause) { throw $cause }
                throw $e
            }
        }
        $net = $false
        for ($e = $ex; $null -ne $e; $e = $e.InnerException) {
            if ($e -is [System.IO.IOException] -or $e -is [System.Net.WebException] -or $e -is [System.Net.Sockets.SocketException]) { $net = $true; break }
        }
        $inner = $ex; while ($null -ne $inner.InnerException) { $inner = $inner.InnerException }
        $why = Get-SILaStreamShortReason $inner.Message
        if (-not $net) { $global:SI_LaStreamReaderOff = 'the streaming reader failed on an answer: ' + $why }
        return [pscustomobject]@{ SILaStreamFailed = $why; Network = $net }
    }
}

function ConvertFrom-SILaQueryStream {
    <#
        The Log Analytics query response READ FROM ITS STREAM -> @{ Rows; Columns; Error } -- the shape and the rows of
        ConvertFrom-SILaQueryRows (SI-AzRest.ps1), without the answer ever being held whole. -Compact: compact rows
        (Get-SILaCompactRowType) where a compact type can be built for the columns; PSCustomObject rows otherwise.
        -BufferBytes: the first buffer (it grows only when one row does not fit). Throws on an answer that is not valid
        JSON or ends early (as the lean read does).
        -OnPage { param($Rows) }: FOR EVERY READER, not only Risk Analysis -- the primary table's rows are handed on a page
        at a time, as soon as about -PageBytes of the answer's own bytes are in, and are never collected: memory is one
        page. .Rows is then empty; .RowCount / .Pages say what was handed on; -PageState (a hashtable) is kept up to date
        as pages go out (Pages, Rows). The error object (a cut answer) comes at the END of the answer, after the pages: a
        caller keeps its pages only once the whole read returned (Invoke-SILaQuery -OnPage refuses a cut answer there).
    #>
    param([Parameter(Mandatory)][System.IO.Stream]$Stream, [switch]$Compact, [int]$BufferBytes = 65536,
          [scriptblock]$OnPage, [long]$PageBytes = 4MB, [hashtable]$PageState)
    $t = Get-SILaStreamReaderType
    if ($null -eq $t) { throw 'the streaming Log Analytics reader is not available in this process' }
    $ctorFor = $null
    if ($Compact) {
        $ctorFor = [Func[string[], System.Reflection.ConstructorInfo]] {
            param([string[]]$names)
            $ct = $null
            if (Get-Command -Name Get-SILaCompactRowType -ErrorAction SilentlyContinue) { $ct = Get-SILaCompactRowType -Names $names }
            if ($null -eq $ct) { return $null }
            return $ct.GetConstructor([type[]]@([string[]]))
        }
    }
    # column names that differ only in case (never in a real answer): the row is built exactly as the lean read builds it
    # [[string[]]] -- the spelling Windows PowerShell 5.1 can parse too: setup scripts a customer runs there load this file
    # through SI-AzRest.ps1 (the same type as [Func[string[], string[], object]], which 5.1 refuses as a parse error)
    $plainFor = [Func[[string[]], [string[]], object]] {
        param([string[]]$names, [string[]]$cells)
        $o = [ordered]@{}
        for ($i = 0; $i -lt $names.Length; $i++) { $o[$names[$i]] = $(if ($i -lt $cells.Length) { $cells[$i] } else { $null }) }
        [pscustomobject]$o
    }
    if ($OnPage) {
        if ($null -eq $PageState) { $PageState = @{} }
        $PageState['Pages'] = 0; $PageState['Rows'] = 0L
        $__psOn = $OnPage; $__psState = $PageState
        $pageAction = [Action[object[]]] {
            param([object[]]$page)
            $null = & $__psOn $page
            $__psState['Pages'] = [int]$__psState['Pages'] + 1
            $__psState['Rows'] = [long]$__psState['Rows'] + $page.Length
        }
        $a = $t::Read($Stream, [bool]$Compact, $ctorFor, $BufferBytes, $plainFor, $pageAction, [long]$PageBytes)
    } else {
        $a = $t::Read($Stream, [bool]$Compact, $ctorFor, $BufferBytes, $plainFor)
    }
    $cols = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $a.ColumnNames.Length; $i++) { $cols.Add([pscustomobject]@{ name = $a.ColumnNames[$i]; type = $a.ColumnTypes[$i] }) }
    $err = $null
    if ($null -ne $a.ErrorJson) { $err = ($a.ErrorJson | ConvertFrom-Json) }
    $count = [long]$a.Rows.Length; if ($OnPage) { $count = [long]$a.RowsDelivered }
    # (#836: $global:, never $script: -- a function's $script: is its caller's)
    $global:SI_LaStreamLast = [pscustomobject]@{ BytesRead = $a.BytesRead; LargestBuffer = $a.LargestBuffer; Rows = $count; Pages = [int]$a.Pages }
    return [pscustomobject]@{ Rows = $a.Rows; Columns = $cols.ToArray(); Error = $err; RowCount = $count; Pages = [int]$a.Pages }
}
