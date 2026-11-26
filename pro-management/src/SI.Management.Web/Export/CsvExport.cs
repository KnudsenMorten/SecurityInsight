using System.Text;
using Microsoft.AspNetCore.Mvc;

namespace SI.Management.Web.Export;

/// <summary>
/// #1400 a CSV answer that knows how many records it holds (written as it was made): the audit trail records that count,
/// never reading the file again (owner 2026-11-26: "memory issues must not be a problem in any step").
/// </summary>
public sealed class CsvFileResult : FileStreamResult
{
    public CsvFileResult(Stream stream, string name, long rows) : base(stream, CsvExport.ContentType)
    {
        FileDownloadName = name;
        Rows = rows;
    }

    /// The records after the header row.
    public long Rows { get; }
}

/// <summary>
/// One CSV being written: a row at a time, straight to the file (UTF-8 with a BOM, formula-looking cells defused, RFC 4180
/// quoting). Nothing of the file is held in memory beyond the writer's buffer.
/// </summary>
public sealed class CsvSink
{
    private readonly TextWriter _w;
    internal CsvSink(TextWriter w) => _w = w;

    /// The records written so far (after the header).
    public long Rows { get; private set; }

    internal async Task HeaderAsync(IEnumerable<string?> cells) => await _w.WriteLineAsync(Line(cells));

    /// One record.
    public async Task RowAsync(IEnumerable<string?> cells)
    {
        await _w.WriteLineAsync(Line(cells));
        Rows++;
    }

    private static string Line(IEnumerable<string?> cells) => string.Join(",", cells.Select(Pages.Findings.IndexModel.Csv));
}

/// <summary>
/// #1400 (owner 2026-11-26: "memory issues must not be a problem in any step"; "SI never fewer rows than the source"): THE
/// web app's CSV export. The page's handler writes its rows (every matching row, read a chunk at a time) with a
/// <see cref="CsvSink"/>; this class writes them straight to a temporary file (deleted when the response is done -- the file
/// never sits in memory, as <see cref="ExcelExport"/> and the scope export already do) and answers it as a
/// <see cref="CsvFileResult"/>. The audit trail records the rows the sink counted. A failure while writing answers an
/// error, never half a file.
/// </summary>
public static class CsvExport
{
    public const string ContentType = "text/csv; charset=utf-8";

    public static async Task<IActionResult> FileAsync(string name, IReadOnlyList<string> headers, Func<CsvSink, Task> write, CancellationToken ct)
    {
        var path = Path.Combine(Path.GetTempPath(), "si-export-" + Guid.NewGuid().ToString("N") + ".csv");
        var file = new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None, 64 * 1024, FileOptions.DeleteOnClose);
        try
        {
            long rows;
            await using (var w = new StreamWriter(file, new UTF8Encoding(true), 64 * 1024, leaveOpen: true))
            {
                var sink = new CsvSink(w);
                await sink.HeaderAsync(headers);
                await write(sink);
                ct.ThrowIfCancellationRequested();
                rows = sink.Rows;
            }
            await file.FlushAsync(ct);
            file.Position = 0;
            // the audit trail (#260): an export records what left the app -- its row count, counted while it was written
            if (SI.Management.Web.Audit.AuditScope.Current is { } audit) audit.Rows ??= rows;
            return new CsvFileResult(file, name, rows);
        }
        catch
        {
            await file.DisposeAsync();
            throw;
        }
    }

    /// <summary>
    /// Every row of a chunked read: chunk 1, 2, ... until a chunk answers no rows (a short chunk is never taken as the end --
    /// a reader that answers fewer than asked still has every row read). <paramref name="read"/> gets the chunk number.
    /// </summary>
    public static async IAsyncEnumerable<IReadOnlyList<T>> ChunksAsync<T>(Func<int, CancellationToken, Task<IReadOnlyList<T>>> read,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        for (var chunk = 1; ; chunk++)
        {
            ct.ThrowIfCancellationRequested();
            var rows = await read(chunk, ct);
            if (rows.Count == 0) yield break;
            yield return rows;
        }
    }
}
