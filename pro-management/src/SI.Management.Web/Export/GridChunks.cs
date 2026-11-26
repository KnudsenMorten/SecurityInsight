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
    public static async IAsyncEnumerable<IReadOnlyDictionary<string, object?>> RowsAsync(GridPage first, bool all,
        Func<int, CancellationToken, Task<GridPage>> next,
        Func<IReadOnlyList<IReadOnlyDictionary<string, object?>>, CancellationToken, Task<IReadOnlyList<IReadOnlyDictionary<string, object?>>>> fill,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct, int size = ProDataFilters.ExportChunk, string? keyColumn = null)
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
