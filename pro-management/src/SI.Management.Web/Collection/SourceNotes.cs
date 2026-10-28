using System.Globalization;
using Microsoft.Extensions.Caching.Memory;
using SI.Management.Web.Data;

namespace SI.Management.Web.Collection;

/// A source (a collection step: endpoint, identity, azure, publicip) whose newest collection did not complete: the run
/// went on with its last good collection, and what is shown of that source is from then (sidata.SourceState, written by
/// the pipeline; sidata.CollectionSource, written by the data sync for each collection calculated meanwhile).
public sealed record SourceNote(string Source, DateTime? LastGoodUtc)
{
    /// The source as a person reads it (the mails say the same).
    public string Label => Source.Trim().ToLowerInvariant() switch
    {
        "endpoint" => "Endpoint",
        "identity" => "Identity",
        "azure" => "Azure",
        "publicip" => "Public IP scan",
        _ => Source,
    };

    /// "Endpoint data is from 10 Oct 2026 14:05 -- the last collection from that source did not complete."
    /// <paramref name="when"/> formats the time (a page: the viewer's regional format; an export: UTC).
    public string Text(Func<DateTime?, string> when) =>
        Label + " data is from " + (LastGoodUtc is null ? "its last good collection" : when(LastGoodUtc)) + " -- the last collection from that source did not complete.";

    /// The sentence with the time in UTC (an export's info sheet).
    public string TextUtc => Text(t => DateTime.SpecifyKind(t!.Value, DateTimeKind.Utc).ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture) + " UTC");
}

/// <summary>
/// The source notes, for the banner on every page and the note on a collection that was calculated while a source was on
/// its last good collection. Read-only; a database without the tables has no notes. NEVER throws: a failed read shows no
/// banner and is logged.
/// </summary>
public interface ISourceNotes
{
    /// The sources that are on their last good collection NOW.
    Task<IReadOnlyList<SourceNote>> CurrentAsync(CancellationToken ct);
    /// Per collection id: the sources that were on an older collection when that collection was calculated.
    Task<IReadOnlyDictionary<string, IReadOnlyList<SourceNote>>> ByCollectionAsync(CancellationToken ct);
}

public sealed class SqlSourceNotes : ISourceNotes
{
    /// ONE TRUSTED RUN (owner 2026-10-19): the pages show the published run, so the banner names the sources THAT run was
    /// calculated without (sidata.CollectionSource of its collection) -- never the state of a newer run that is not shown.
    /// With no published run yet, the sources' state now, as before.
    public const string CurrentSql = """
DECLARE @pub int = NULL;
IF OBJECT_ID(N'sidata.PublishedRun') IS NOT NULL AND OBJECT_ID(N'sidata.CollectionSource') IS NOT NULL
BEGIN
    SELECT @pub = p.DetailedCollectionId FROM sidata.PublishedRun AS p WHERE p.Name = N'current';
    IF @pub IS NOT NULL
    BEGIN
        SELECT c.Source, c.LastGoodAt FROM sidata.CollectionSource AS c WHERE c.CollectionId = @pub ORDER BY c.Source;
        RETURN;
    END
END
IF OBJECT_ID(N'sidata.SourceState') IS NULL
    SELECT TOP (0) CAST(NULL AS nvarchar(32)) AS Source, CAST(NULL AS datetime2(3)) AS LastGoodAt;
ELSE
    SELECT s.Source, s.LastGoodAt FROM sidata.SourceState AS s WHERE s.LastAttemptOk = 0 ORDER BY s.Source;
""";

    public const string ByCollectionSql = """
IF OBJECT_ID(N'sidata.CollectionSource') IS NULL
    SELECT TOP (0) CAST(NULL AS nvarchar(64)) AS CollectionId, CAST(NULL AS nvarchar(32)) AS Source, CAST(NULL AS datetime2(3)) AS LastGoodAt;
ELSE
    SELECT CONVERT(nvarchar(64), c.CollectionId) AS CollectionId, c.Source, c.LastGoodAt FROM sidata.CollectionSource AS c ORDER BY c.CollectionId, c.Source;
""";

    private readonly ISqlExecutor _sql;
    private readonly IMemoryCache? _cache;
    private readonly ILogger<SqlSourceNotes>? _log;
    public SqlSourceNotes(ISqlExecutor sql, IMemoryCache? cache = null, ILogger<SqlSourceNotes>? log = null) { _sql = sql; _cache = cache; _log = log; }

    private static SourceNote Note(SqlRow r) =>
        new(r.Str("Source") ?? "", r.TryGetValue("LastGoodAt", out var v) && v is DateTime d ? DateTime.SpecifyKind(d, DateTimeKind.Utc) : null);

    public async Task<IReadOnlyList<SourceNote>> CurrentAsync(CancellationToken ct)
    {
        if (_cache is not null && _cache.TryGetValue("source-notes-current", out IReadOnlyList<SourceNote>? hit) && hit is not null) return hit;
        IReadOnlyList<SourceNote> notes;
        try
        {
            var rows = await _sql.QueryAsync(CurrentSql, new Dictionary<string, object?>(), ct);
            notes = rows.Select(Note).Where(n => n.Source.Length > 0).ToList();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log?.LogWarning(ex, "the state of the sources could not be read -- no source banner is shown");
            notes = Array.Empty<SourceNote>();
        }
        _cache?.Set("source-notes-current", notes, TimeSpan.FromSeconds(60));
        return notes;
    }

    public async Task<IReadOnlyDictionary<string, IReadOnlyList<SourceNote>>> ByCollectionAsync(CancellationToken ct)
    {
        if (_cache is not null && _cache.TryGetValue("source-notes-collections", out IReadOnlyDictionary<string, IReadOnlyList<SourceNote>>? hit) && hit is not null) return hit;
        IReadOnlyDictionary<string, IReadOnlyList<SourceNote>> notes;
        try
        {
            var rows = await _sql.QueryAsync(ByCollectionSql, new Dictionary<string, object?>(), ct);
            notes = rows.Select(r => (Id: r.Str("CollectionId") ?? "", Note: Note(r)))
                .Where(x => x.Id.Length > 0 && x.Note.Source.Length > 0)
                .GroupBy(x => x.Id, StringComparer.Ordinal)
                .ToDictionary(g => g.Key, g => (IReadOnlyList<SourceNote>)g.Select(x => x.Note).ToList(), StringComparer.Ordinal);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log?.LogWarning(ex, "the sources of the collections could not be read -- no source note is shown on a collection");
            notes = new Dictionary<string, IReadOnlyList<SourceNote>>();
        }
        _cache?.Set("source-notes-collections", notes, TimeSpan.FromSeconds(60));
        return notes;
    }
}

/// What a page shows, and an export says, of the sources -- one rule for both.
public static class SourceNoteView
{
    /// The lines of an export's info sheet: the opened collection's notes when the export is of one that has them, else
    /// the current state of the sources. Times in UTC. Never throws.
    public static async Task<IReadOnlyList<string>> ExportLinesAsync(ISourceNotes notes, string? collectionId, CancellationToken ct)
    {
        try
        {
            if (!string.IsNullOrEmpty(collectionId) && (await notes.ByCollectionAsync(ct)).TryGetValue(collectionId, out var of))
                return of.Select(n => n.TextUtc).ToList();
            return (await notes.CurrentAsync(ct)).Select(n => n.TextUtc).ToList();
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { return Array.Empty<string>(); }
    }
}

/// The request's source notes, for code that has no services at hand (the Excel export): set per request in Program.cs.
public static class SourceNoteScope
{
    private static readonly AsyncLocal<ISourceNotes?> Ambient = new();
    public static ISourceNotes? Current { get => Ambient.Value; set => Ambient.Value = value; }
}
