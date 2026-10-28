using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace SI.Management.Core.ProData;

// =====================================================================================================================
// A VIEW'S PAGE IS READ ONCE PER DATA VERSION (owner 2026-10-11: "dont foget the caching in sql so performance works
// flawless", "again all views must be having the new requirement and performance fast").
//
// The collection views keep what they read per collection (a complete collection never changes). The views over the
// CURRENT data -- All CIs, the findings per CI, the findings per finding key, the records, the correlation figures and
// their trend, the findings browser's pivot -- had no such key, so every page load ran its whole statement again although
// nothing had changed since the last data sync. They are now kept per DATA VERSION:
//
//   * the data sync sets a mark when it has stored its data (sidata.ViewState 'data': a new value at the end of every run
//     that wrote -- engine/pro-data/_shared/SI-DataViewContext.ps1, Set-SIDataViewVersion);
//   * next to the mark, a few narrow figures of the tables the views read (the newest collection, the number of CIs and
//     how many have their prepared columns filled, the newest collection time of the findings per CI and of the records,
//     the CI build's own state) -- so data stored by anything else than the data sync is noticed too, and an install
//     whose data sync has not set a mark yet is still versioned.
//
// A result is kept until the version moves -- NEVER by time alone: while the data stands still a page is not read again,
// and the first page load after new data reads again. The version itself is asked at most every few seconds
// (<see cref="DataVersion.Ttl"/>): narrow index reads, never a document.
// =====================================================================================================================

// =====================================================================================================================
// THE PAGES STAY AS THEY ARE WHILE A DATA SYNC RUNS (owner 2026-10-12, after a demo given during a data sync: the
// database was at its limit and every page was read again and again, because each step of the run moved one of the
// figures above and the kept results were dropped each time -- about seven times in one run).
//
//   * The data sync says that it is running: one row, sidata.ViewState 'sync' (Value = its start time; UpdatedAt = the
//     same moment by the database's clock), written before its first write and taken away together with its end mark
//     (one transaction) -- or by itself when the run fails.
//   * While that row is there and younger than <see cref="DataSyncSignal.Limit"/>, the figures a data sync moves WHILE
//     it runs (<see cref="DataSyncSignal.MovedBySync"/>) are HELD at what they were when the run was first seen: the
//     version does not move, the kept results stay. It moves ONCE -- when the end mark is set (and the row is gone).
//   * A row older than the limit is a run that died: it is ignored, and the version follows the figures again.
//   * Everything a data sync does NOT write still moves the version at once, also while it runs: the CIs and the records
//     (the CI build, which also carries a person's tier decision), the CI build's state. What a person changes in the
//     web app itself (an exemption, a CMDB service, an early retirement) is never kept here at all -- it is read live.
// =====================================================================================================================

/// The data sync's "I am running" signal, as the web app reads it (the engine's twin: SI-DataViewContext.ps1).
public static class DataSyncSignal
{
    /// The row's name in sidata.ViewState.
    public const string Name = "sync";
    /// How long after its start a running data sync is believed: 60 minutes. Past it the row is a run that died (a run
    /// that really takes longer is then treated as before this rule existed: the pages follow every figure it moves).
    public static readonly TimeSpan Limit = TimeSpan.FromMinutes(60);
    public const string StartedColumn = "SyncStarted";
    public const string AgeColumn = "SyncAgeSeconds";

    /// The version's figures a data sync moves while it runs: the collections (loaded, counted, their views' data
    /// computed), the CIs' prepared columns, the findings per CI. NOT its end mark -- that is what moves the version.
    public static readonly IReadOnlySet<string> MovedBySync = new HashSet<string>(StringComparer.Ordinal)
    {
        "NewestCollection", "Collections", "Derived", "CiUnfilled", "CiContextUnfilled", "CiFindingNewest", "CiFindings",
    };

    /// A row with a start, not older than the limit (and not from the future by more than a clock's slack).
    public static bool Running(string? started, long? ageSeconds) =>
        !string.IsNullOrWhiteSpace(started) && ageSeconds is { } age && age >= -300 && age <= (long)Limit.TotalSeconds;
}

/// The version of the data the views show ("" = it cannot be told: nothing is kept then, every read is live).
public interface IDataVersion
{
    Task<string> CurrentAsync(CancellationToken ct);
}

/// Which of the tables the version is read from exist (a missing one is never named in a statement).
public sealed record DataVersionSchema(bool State, bool Collection, bool Derived, bool Ci, bool CiFields, bool CiContext, bool CiFinding, bool CiRecord, bool BuildState, bool Published = false);

/// <summary>The statements. Fixed text assembled from fixed parts by which tables exist; no parameters; read-only.</summary>
public static class DataVersionSql
{
    public static readonly string Schema = $"""
SELECT CASE WHEN OBJECT_ID(N'sidata.ViewState') IS NULL THEN 0 ELSE 1 END AS HasState,
       CASE WHEN OBJECT_ID(N'sidata.Collection') IS NULL THEN 0 ELSE 1 END AS HasCollection,
       CASE WHEN COL_LENGTH(N'sidata.Collection', N'DerivedAt') IS NULL THEN 0 ELSE 1 END AS HasDerived,
       CASE WHEN OBJECT_ID(N'sidata.Ci') IS NULL THEN 0 ELSE 1 END AS HasCi,
       CASE WHEN COL_LENGTH(N'sidata.Ci', N'DocFieldsHash') IS NULL THEN 0 ELSE 1 END AS HasCiFields,
       {ViewStoredColumns.CiSchemaProbe} AS HasCiContext,
       CASE WHEN OBJECT_ID(N'sidata.CiFinding') IS NULL THEN 0 ELSE 1 END AS HasCiFinding,
       CASE WHEN OBJECT_ID(N'sidata.CiRecord') IS NULL THEN 0 ELSE 1 END AS HasCiRecord,
       CASE WHEN OBJECT_ID(N'sidata.CiBuildState') IS NULL THEN 0 ELSE 1 END AS HasBuildState,
       CASE WHEN OBJECT_ID(N'sidata.PublishedRun') IS NULL THEN 0 ELSE 1 END AS HasPublished;
""";

    /// <summary>
    /// ONE row of what moves when data is stored: the data sync's mark, the newest collection (and when the newest views'
    /// data was computed), the CIs (newest collection time, how many, how many without their prepared columns), the newest
    /// collection time and the number of the findings per CI and of the records, the CI build's state. Every part reads an
    /// index end or counts a narrow index; "" when no table can answer.
    /// </summary>
    public static string Version(DataVersionSchema s)
    {
        var parts = new List<string>();
        if (s.State)
        {
            parts.Add("(SELECT TOP (1) v.Value FROM sidata.ViewState AS v WHERE v.Name = N'data') AS Mark");
            // "a data sync is running" (DataSyncSignal): its start, and its age by the database's own clock
            parts.Add($"(SELECT TOP (1) y.Value FROM sidata.ViewState AS y WHERE y.Name = N'{DataSyncSignal.Name}') AS {DataSyncSignal.StartedColumn}");
            parts.Add($"(SELECT TOP (1) DATEDIFF(SECOND, y2.UpdatedAt, SYSUTCDATETIME()) FROM sidata.ViewState AS y2 WHERE y2.Name = N'{DataSyncSignal.Name}') AS {DataSyncSignal.AgeColumn}");
        }
        if (s.Collection)
        {
            parts.Add("(SELECT MAX(k.CollectionId) FROM sidata.Collection AS k) AS NewestCollection");
            parts.Add("(SELECT COUNT_BIG(*) FROM sidata.Collection AS k2 WHERE k2.Status = N'Complete') AS Collections");
            if (s.Derived) parts.Add("(SELECT MAX(k3.DerivedAt) FROM sidata.Collection AS k3) AS Derived");
        }
        // ONE TRUSTED RUN: the published run (which collection, and when it was published) moves the version AT ONCE -- the
        // pages read the new trusted run on the next load, and nothing else of a run that is not trusted changes them.
        // #881 the CI and asset copies follow a publish range by range: CopiedAt (set only when every range is done) moves the
        // version again, so nothing a page cached while the copies were refreshed outlives the refresh
        if (s.Published)
            parts.Add("(SELECT TOP (1) CONCAT(p.DetailedCollectionId, N'|', CONVERT(nvarchar(30), p.PublishedAt, 126), N'|', CONVERT(nvarchar(30), p.CopiedAt, 126)) FROM sidata.PublishedRun AS p WHERE p.Name = N'current') AS Published");
        if (s.Ci)
        {
            parts.Add("(SELECT MAX(c.CollectionTime) FROM sidata.Ci AS c) AS CiNewest");
            parts.Add("(SELECT COUNT_BIG(*) FROM sidata.Ci AS c2) AS Cis");
            if (s.CiFields) parts.Add($"(SELECT COUNT_BIG(*) FROM sidata.Ci AS c WHERE NOT ({CiColumns.FilledSql}) OR c.DocFieldsHash IS NULL) AS CiUnfilled");
            if (s.CiFields && s.CiContext)
                parts.Add($"(SELECT COUNT_BIG(*) FROM sidata.Ci AS c WHERE NOT ({ViewStoredColumns.CiContextFilledSql(ViewStoredColumns.CiSetLiteral)}) OR c.CtxHash IS NULL OR c.CtxSet IS NULL) AS CiContextUnfilled");
        }
        if (s.CiFinding)
        {
            parts.Add("(SELECT MAX(f.CollectionTime) FROM sidata.CiFinding AS f) AS CiFindingNewest");
            parts.Add("(SELECT COUNT_BIG(*) FROM sidata.CiFinding AS f2) AS CiFindings");
        }
        if (s.CiRecord)
        {
            parts.Add("(SELECT MAX(r.CollectionTime) FROM sidata.CiRecord AS r) AS RecordNewest");
            parts.Add("(SELECT COUNT_BIG(*) FROM sidata.CiRecord AS r2) AS Records");
        }
        if (s.BuildState)
        {
            parts.Add("(SELECT MAX(b.UpdatedAt) FROM sidata.CiBuildState AS b) AS BuildAt");
            parts.Add("(SELECT CHECKSUM_AGG(CHECKSUM(b2.Name, b2.Value)) FROM sidata.CiBuildState AS b2) AS BuildState");
        }
        return parts.Count == 0 ? "" : "SELECT " + string.Join(",\n       ", parts) + ";";
    }
}

/// <summary>The SQL implementation over <see cref="IProSql"/>; every statement passes <see cref="SqlGuard"/> first.</summary>
public sealed class DataVersion : IDataVersion
{
    /// How long one answer is trusted: the version is asked at most this often, however many pages are opened.
    public static readonly TimeSpan Ttl = TimeSpan.FromSeconds(15);
    /// How long the list of tables is trusted (an update adds tables; it is noticed within this).
    public static readonly TimeSpan SchemaTtl = TimeSpan.FromMinutes(5);
    public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(30);

    private readonly IProSql _sql;
    private readonly TimeProvider _clock;
    private sealed record Cached<T>(DateTimeOffset At, T Value);
    private volatile Cached<DataVersionSchema>? _schema;
    private volatile Cached<string>? _version;

    public DataVersion(IProSql sql, TimeProvider? clock = null) { _sql = sql; _clock = clock ?? TimeProvider.System; }

    private async Task<IReadOnlyList<IReadOnlyDictionary<string, object?>>> Run(string text, CancellationToken ct)
    {
        SqlGuard.AssertReadOnly(text);
        return await ViewTimeout.Run(t => _sql.QueryAsync(new SqlQuery(text, new Dictionary<string, object?>()), t), Timeout, ct).ConfigureAwait(false);
    }

    private static bool Flag(IReadOnlyDictionary<string, object?> r, string c) => r.TryGetValue(c, out var v) && v is not null && Convert.ToInt64(v, CultureInfo.InvariantCulture) != 0;

    private async Task<DataVersionSchema> SchemaAsync(CancellationToken ct)
    {
        var now = _clock.GetUtcNow();
        if (_schema is { } s && now - s.At < SchemaTtl) return s.Value;
        var rows = await Run(DataVersionSql.Schema, ct).ConfigureAwait(false);
        var r = rows.Count > 0 ? rows[0] : new Dictionary<string, object?>();
        var schema = new DataVersionSchema(Flag(r, "HasState"), Flag(r, "HasCollection"), Flag(r, "HasDerived"), Flag(r, "HasCi"), Flag(r, "HasCiFields"),
            Flag(r, "HasCiContext"), Flag(r, "HasCiFinding"), Flag(r, "HasCiRecord"), Flag(r, "HasBuildState"), Flag(r, "HasPublished"));
        _schema = new Cached<DataVersionSchema>(now, schema);
        return schema;
    }

    /// The version as one text: every figure of <see cref="DataVersionSql.Version"/>, by name. "" when nothing answers.
    public async Task<string> CurrentAsync(CancellationToken ct)
    {
        var now = _clock.GetUtcNow();
        if (_version is { } v && now - v.At < Ttl) return v.Value;
        var text = DataVersionSql.Version(await SchemaAsync(ct).ConfigureAwait(false));
        var version = "";
        if (text.Length > 0)
        {
            var rows = await Run(text, ct).ConfigureAwait(false);
            if (rows.Count > 0) version = Compose(rows[0]);
        }
        _version = new Cached<string>(now, version);
        return version;
    }

    private readonly object _holdLock = new();
    private string? _heldFor;                       // the running data sync (its start) the figures below are held for
    private Dictionary<string, string>? _held;      // the figures a data sync moves, as they were when it was first seen
    private Dictionary<string, string>? _last;      // the figures of the last answer

    /// Whether the last answer was given while a data sync was seen running (for the tests).
    public bool Holding { get { lock (_holdLock) return _heldFor is not null; } }

    /// One answer's figures as the version text. While a data sync is running, the figures it moves are the ones held from
    /// before it (the last answer's, when a page was read recently -- else as they are now); the signal itself is never
    /// part of the version.
    private string Compose(IReadOnlyDictionary<string, object?> row)
    {
        var figures = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var kv in row)
            if (kv.Key != DataSyncSignal.StartedColumn && kv.Key != DataSyncSignal.AgeColumn) figures[kv.Key] = DataColumnKeys.Text(kv.Value);
        var started = row.TryGetValue(DataSyncSignal.StartedColumn, out var sv) && sv is not null ? DataColumnKeys.Text(sv) : "";
        long? age = null;
        if (row.TryGetValue(DataSyncSignal.AgeColumn, out var av) && av is not null)
        {
            try { age = Convert.ToInt64(av, CultureInfo.InvariantCulture); } catch (Exception ex) when (ex is FormatException or InvalidCastException or OverflowException) { age = null; }
        }
        lock (_holdLock)
        {
            if (!DataSyncSignal.Running(started, age)) { _heldFor = null; _held = null; }
            else
            {
                if (_heldFor != started || _held is null)
                {
                    var from = _last ?? figures;
                    _held = DataSyncSignal.MovedBySync.Where(from.ContainsKey).ToDictionary(k => k, k => from[k], StringComparer.Ordinal);
                    _heldFor = started;
                }
                foreach (var kv in _held) figures[kv.Key] = kv.Value;
            }
            _last = figures;
        }
        return string.Join("|", figures.OrderBy(kv => kv.Key, StringComparer.Ordinal).Select(kv => kv.Key + "=" + kv.Value));
    }
}

/// <summary>
/// What the views read, kept per data version (<see cref="IDataVersion"/>): an entry is served only while the version it was
/// read for is the current one; when the version moves every entry is dropped. A read whose version cannot be told is never
/// kept. Bounded (<see cref="Capacity"/> entries: reaching it drops them all -- a pace, never a limit on what a view shows).
/// An export is never kept (its callers read it live). The key carries the request's exempted-findings scope
/// (<see cref="Exempted.CacheKey"/>): a read with exempted findings left out and one with them included are two answers.
/// </summary>
public sealed class ViewResultCache
{
    public const int Capacity = 600;
    private readonly IDataVersion _version;
    private readonly object _lock = new();
    private string _for = "";
    private Dictionary<string, object> _entries = new(StringComparer.Ordinal);

    public ViewResultCache(IDataVersion version) => _version = version;

    /// How many results are kept now (for the tests).
    public int Count { get { lock (_lock) return _entries.Count; } }

    /// The key of one statement: the view, and a hash of the statement's text and every parameter value -- two reads with
    /// the same key ask the database the same thing.
    public static string Key(string view, SqlQuery q)
    {
        var sb = new StringBuilder(q.Text);
        foreach (var p in q.Parameters.OrderBy(p => p.Key, StringComparer.Ordinal))
            sb.Append('\u001f').Append(p.Key).Append('=').Append(p.Value is null ? "\u0000" : DataColumnKeys.Text(p.Value));
        return view + "|" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(sb.ToString())).AsSpan(0, 16));
    }

    /// The result kept under <paramref name="key"/> for the current data version, else <paramref name="read"/>'s (kept
    /// when the version is known and did not move meanwhile). A failure to tell the version reads live -- never an error.
    /// <paramref name="keep"/>: whether a result is worth keeping (an answer that stands for "could not be read" is not).
    public async Task<T> GetAsync<T>(string key, Func<Task<T>> read, CancellationToken ct, Func<T, bool>? keep = null) where T : class
    {
        string version;
        try { version = await _version.CurrentAsync(ct).ConfigureAwait(false); }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested) { version = ""; }
        if (version.Length == 0) return await read().ConfigureAwait(false);
        key = Exempted.CacheKey + "|" + key;
        lock (_lock)
        {
            if (_for != version) { _entries = new Dictionary<string, object>(StringComparer.Ordinal); _for = version; }
            else if (_entries.TryGetValue(key, out var hit) && hit is T t) return t;
        }
        var value = await read().ConfigureAwait(false);
        lock (_lock)
        {
            if (_for == version && (keep is null || keep(value)))
            {
                if (_entries.Count >= Capacity) _entries.Clear();
                _entries[key] = value;
            }
        }
        return value;
    }
}
