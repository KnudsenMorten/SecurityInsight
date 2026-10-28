using System.Text.RegularExpressions;

namespace SI.Management.Web.Data;

/// <summary>
/// ONE TRUSTED RUN FOR THE CIs (owner 2026-10-19: "and not show some parts from recent run and some from last known good
/// run"). The CI build and the data sync write sidata.Ci and its neighbours in place during every run, hours before the run
/// is trusted; the pages read the PUBLISHED COPY of each instead (sql/si-data-schema.sql "ONE TRUSTED RUN FOR THE CIs"),
/// refilled in the transaction that moves the published-run pointer. ONE place does it for every reader of the web app:
/// each statement's names of those tables and views are read as their published copies once a copy is published
/// (sidata.PublishedRun.CopiedAt) -- before that (a new install's first collection) the source tables, as before.
/// The web app never writes these tables (PublishedRunGuardTests keeps that true), so only reads are affected.
/// </summary>
public static partial class PublishedCopyNames
{
    /// The source -> what the pages read. Tables have a copy (<c>&lt;Table&gt;Pub</c>); the views have one over the copies;
    /// the daily CI rows and the full metadata keep their history, so a view cuts them at the published copy.
    public static readonly IReadOnlyDictionary<string, string> Map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        ["Ci"] = "CiPub", ["CiLink"] = "CiLinkPub", ["CiFinding"] = "CiFindingPub", ["CiService"] = "CiServicePub", ["CiRecord"] = "CiRecordPub",
        ["CiFindingState"] = "CiFindingStatePub", ["CiRelation"] = "CiRelationPub", ["Asset"] = "AssetPub", ["AssetIdentifier"] = "AssetIdentifierPub",
        ["AssetTag"] = "AssetTagPub",
        ["vCi"] = "vCiPub", ["vCiRelation"] = "vCiRelationPub", ["vCiUnowned"] = "vCiUnownedPub", ["vCiFindingModel"] = "vCiFindingModelPub",
        ["vServiceCi"] = "vServiceCiPub", ["vServiceFinding"] = "vServiceFindingPub",
        ["CiDaily"] = "vCiDailyPub", ["AssetMetadata"] = "vAssetMetadataPub",
    };

    // sidata.<name> as a whole name: not part of a longer name (sidata.CiOverride, sidata.AssetMetadataLoad stay), not
    // already a copy, with or without brackets
    [GeneratedRegex(@"(?<![\w.\]])sidata\.\[?(Ci|CiLink|CiFinding|CiService|CiRecord|CiFindingState|CiRelation|Asset|AssetIdentifier|AssetTag|vCi|vCiRelation|vCiUnowned|vCiFindingModel|vServiceCi|vServiceFinding|CiDaily|AssetMetadata)\]?(?![\w])", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex Names();

    /// PURE. The statement with every source name read as what the pages read.
    public static string Rewrite(string sql) => Names().Replace(sql, m => "sidata." + Map[m.Groups[1].Value]);

    /// Whether the published copies are filled (one small read; a database before the update answers 0).
    public const string LiveSql = """
IF OBJECT_ID(N'sidata.PublishedRun') IS NULL OR COL_LENGTH(N'sidata.PublishedRun', N'CopiedAt') IS NULL OR OBJECT_ID(N'sidata.CiPub') IS NULL
    SELECT 0 AS Live;
ELSE
    SELECT CASE WHEN EXISTS (SELECT 1 FROM sidata.PublishedRun WHERE Name = N'current' AND CopiedAt IS NOT NULL) THEN 1 ELSE 0 END AS Live;
""";
}

/// <summary>The executor every reader of the web app uses: <see cref="PublishedCopyNames.Rewrite"/> once the copies are live.</summary>
public sealed class PublishedCopyExecutor : ISqlExecutor
{
    /// How long "not live yet" is believed (a new install's first publish is seen within this). Once live, always live:
    /// a copy is never taken away.
    public static readonly TimeSpan Ttl = TimeSpan.FromSeconds(30);

    private readonly ISqlExecutor _inner;
    private readonly TimeProvider _clock;
    private volatile bool _live;
    private long _askedTicks = long.MinValue;

    public PublishedCopyExecutor(ISqlExecutor inner, TimeProvider? clock = null) { _inner = inner; _clock = clock ?? TimeProvider.System; }

    /// Whether the last answer said the copies are live (for the tests).
    public bool Live => _live;

    private async Task<bool> LiveAsync(CancellationToken ct)
    {
        if (_live) return true;
        var now = _clock.GetUtcNow().UtcTicks;
        var asked = Interlocked.Read(ref _askedTicks);
        if (asked != long.MinValue && now - asked < Ttl.Ticks) return false;
        Interlocked.Exchange(ref _askedTicks, now);
        try
        {
            var rows = await _inner.QueryAsync(PublishedCopyNames.LiveSql, new Dictionary<string, object?>(), ct).ConfigureAwait(false);
            if (rows.Count > 0 && rows[0].Long("Live") == 1) _live = true;
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { /* not known: the sources, as before */ }
        return _live;
    }

    public async Task<IReadOnlyList<SqlRow>> QueryAsync(string sql, IReadOnlyDictionary<string, object?> parameters, CancellationToken ct) =>
        await _inner.QueryAsync(await LiveAsync(ct).ConfigureAwait(false) ? PublishedCopyNames.Rewrite(sql) : sql, parameters, ct).ConfigureAwait(false);
}
