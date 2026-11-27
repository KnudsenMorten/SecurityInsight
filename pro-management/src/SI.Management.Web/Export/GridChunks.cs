using System.Globalization;
using SI.Management.Core.ProData;

namespace SI.Management.Web.Export;

/// <summary>
/// #1400 (owner 2026-11-26: "memory issues must not be a problem in any step"; "SI never fewer rows than the source"): the
/// rows of a grid export -- the first chunk the page read, then chunk 2, 3, ... (<paramref name="next"/>), each filled with
/// its extra columns (<paramref name="fill"/>) for its own rows and handed on before the next is read. No row cap.
/// The export ends when the SOURCE is exhausted: past the row count the first chunk carried (a REAL count of the request,
/// also on the index-ordered path -- never a stored total) AND at a chunk without rows.
/// TRUST (reviews of 70e9294fc and a2749b67d): a row whose key came already (a row that moved across the chunks) or rows
/// written that differ from that count ABORT the export (<see cref="Data.ExportIncompleteException"/>): nothing is
/// downloaded, the audit row and the log say why -- never a clean-looking short or doubled file.
/// "Export this page" (<paramref name="all"/> false): the page read, only.
/// </summary>
public static class GridChunks
{
    /// #1418 (a)(b): <paramref name="keyStart"/> -- the keys of the source read BEFORE the first chunk on the live path
    /// (<see cref="ExportConsistency.StartAsync"/>); with <paramref name="keyHash"/> they are read again after the last chunk and
    /// compared (<see cref="ExportConsistency.CheckAsync"/>).
    public static async IAsyncEnumerable<IReadOnlyDictionary<string, object?>> RowsAsync(GridPage first, bool all,
        Func<int, CancellationToken, Task<GridPage>> next,
        Func<IReadOnlyList<IReadOnlyDictionary<string, object?>>, CancellationToken, Task<IReadOnlyList<IReadOnlyDictionary<string, object?>>>> fill,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct, int size = ProDataFilters.ExportChunk, string? keyColumn = null,
        ExportKeyHash? keyStart = null, Func<CancellationToken, Task<ExportKeyHash?>>? keyHash = null)
    {
        var expected = first.Total;
        var seen = all && keyColumn is not null ? new KeySet() : null;
        long written = 0;
        var rows = first.Rows;
        for (var n = 1; ; n++)
        {
            if (seen is not null)
                foreach (var r in rows)
                {
                    // a row without a key value (null / empty) is never compared
                    var key = r.TryGetValue(keyColumn!, out var k) && k is not null ? Convert.ToString(k, CultureInfo.InvariantCulture) : null;
                    if (!seen.Add(string.IsNullOrEmpty(key) ? null : key)) throw new Data.ExportIncompleteException(Twice(key));
                }
            foreach (var row in await fill(rows, ct)) { written++; yield return row; }
            if (!all) yield break;
            // the source is exhausted: this chunk had no rows and the chunks read reach past the count the export began with
            if (rows.Count == 0 && (long)n * size >= expected) break;
            ct.ThrowIfCancellationRequested();
            rows = (await next(n + 1, ct)).Rows;
        }
        if (Note(expected, written) is { } note) throw new Data.ExportIncompleteException(note);
        await ExportConsistency.CheckAsync(keyStart, keyHash, ct);
    }

    /// The words when the rows written differ from the count the first chunk carried (null = they agree).
    public static string? Note(long expected, long written) => expected == written ? null
        : string.Format(CultureInfo.InvariantCulture,
            "the view counted {0:N0} rows when the export began; {1:N0} were read",
            expected, written);

    /// The words when a row came twice.
    public static string Twice(string? key) => "a row came twice (key " + (key ?? "(none)") + ") -- rows moved while the export read them";
}

/// <summary>
/// #1418 (a)(b) (the review of 6c9f60132: "the live-path +1/-1 blind spot on tables users edit"): ON THE LIVE PATH (the
/// database has snapshot isolation off -- the export's chunks read the live tables, <see cref="Data.ExportSession.Snapshot"/>
/// false) the keys of every row the export reads are hashed IN SQL before its first chunk and again after its last one
/// (<see cref="ExportKeyHash"/>: the row count and the sum of each key's hash -- no key is held in the web app). A row added
/// while another was removed leaves the count, the doubled-key check and the written rows as they were; it never leaves
/// the keys: the two reads differ and the export is REFUSED with the existing words
/// (<see cref="Data.ExportSessionPageFilter.Refusal"/>: "The data changed while it was exported -- nothing was downloaded.
/// Export again."), never delivered as if it were one view of the data. A snapshot export reads one view by itself: no
/// extra read.
/// </summary>
public static class ExportConsistency
{
    /// The keys at the start of the export -- only on the live path; null otherwise (snapshot, no export session, no reader).
    public static async Task<ExportKeyHash?> StartAsync(Func<CancellationToken, Task<ExportKeyHash?>>? read, CancellationToken ct)
    {
        if (read is null || Data.ExportSession.Current is not { } session) return null;
        // the snapshot state is settled FIRST, with one cheap statement: the keys (a full pass, a hash per row) are read only
        // when the export really reads the live tables -- never on the snapshot path
        await session.SettleAsync(ct);
        if (session.Snapshot == true) return null;
        try { return await read(ct); }
        catch (Exception ex) when (ex is not OperationCanceledException && ex is not Data.ExportIncompleteException)
        {
            // the export still goes on, with its row count and doubled-row checks -- said on the Export sheet, the audit row, the log
            session.Note(NotRead(ex));
            return null;
        }
    }

    /// The keys again at the end; different from <paramref name="start"/> = the export is refused.
    public static async Task CheckAsync(ExportKeyHash? start, Func<CancellationToken, Task<ExportKeyHash?>>? read, CancellationToken ct)
    {
        if (start is null || read is null) return;
        ExportKeyHash? end;
        try { end = await read(ct); }
        catch (Exception ex) when (ex is not OperationCanceledException && ex is not Data.ExportIncompleteException)
        {
            Data.ExportSession.Current?.Note(NotRead(ex));
            return;
        }
        if (end is null || end == start) return;
        throw new Data.ExportIncompleteException(Changed(start, end));
    }

    /// The words when the keys could not be read (the export keeps its other checks).
    public static string NotRead(Exception ex) =>
        "The rows' keys could not be compared at the start and the end of this export (" + ex.Message.Split('\n')[0].Trim() + "); its row count and doubled-row checks still applied.";

    /// The words of a refused export whose keys moved.
    public static string Changed(ExportKeyHash start, ExportKeyHash end) => string.Format(CultureInfo.InvariantCulture,
        "rows were added or removed while the export read them -- the view's keys differ between the export's start ({0:N0} rows) and its end ({1:N0} rows)",
        start.Rows, end.Rows);
}

/// <summary>
/// The keys an export has written, held as 64-bit hashes (8 bytes a row, never the rows): a key that comes again is a row
/// that moved across the chunks. A null key is never compared.
/// </summary>
public sealed class KeySet
{
    private readonly HashSet<ulong> _seen = new();

    /// False when the key came already.
    public bool Add(string? key) => key is null || _seen.Add(Hash(key));

    /// FNV-1a 64 over the key's UTF-16 code units (stable, no allocation).
    public static ulong Hash(string s)
    {
        var h = 14695981039346656037UL;
        foreach (var ch in s) { h ^= ch; h *= 1099511628211UL; }
        return h;
    }
}
