namespace SI.Management.Core.ProData;

/// <summary>
/// #1355 (owner 2026-11-24: "i would like a filter on the security recommendations views (summary, detailed) to select actual
/// risk vs. within accepted lifetime. default is actual risk (all)"): the reads of the "Within Accepted Lifecycle" choice of
/// Security recommendations > Summary and Detailed. The findings the wall board's lifecycle view counts are STORED per
/// collection by the key figures' own build (sidata.FindingLifecycleRisk, the same verdict as its findings_lifecycle figure,
/// with the marker KeyFigure meta 'lifecycle_rows'); the Summary's groupings of those findings are written after the key
/// figures (sidata.SummaryGroupLifecycle / SummaryGroupLifecycleState). Detailed narrows with
/// <see cref="CollectionViewSql.WithinAcceptedLifecycle"/>. Fixed text, every caller value a parameter, read-only.
/// (A file of its own: the Remediations pages' file, RecommendationViews.cs, stays the bytes the ServiceNow hand-off proof pins.)
/// </summary>
public static class AcceptedLifecycleSql
{
    /// The grid of one Summary grouping over the findings the "Within Accepted Lifecycle" view counts -- the same grid
    /// (<see cref="RecommendationSql.Grouped"/>) read from the lifecycle twin; those findings carry no exemption mark, so no
    /// counted twin applies. Same name: the person's column layout is the grouping's.
    public static GridSpec Grouped(string? id) => Specs[RecommendationSql.GroupingOf(id).Id];

    private const string GroupFrom = "FROM sidata.SummaryGroup AS s", GroupFromLifecycle = "FROM sidata.SummaryGroupLifecycle AS s";
    private const string GroupLate = "JOIN sidata.SummaryGroup AS sl", GroupLateLifecycle = "JOIN sidata.SummaryGroupLifecycle AS sl";

    private static readonly IReadOnlyDictionary<string, GridSpec> Specs =
        RecommendationSql.Groupings.ToDictionary(g => g.Id, g => GridSql.Check(OverLifecycle(RecommendationSql.Grouped(g.Id))), StringComparer.OrdinalIgnoreCase);

    private static GridSpec OverLifecycle(GridSpec s)
    {
        if (!s.Source.Contains(GroupFrom, StringComparison.Ordinal)) throw new InvalidOperationException($"grid {s.Name}: not read from sidata.SummaryGroup");
        static string From(string t) => t.Replace(GroupFrom, GroupFromLifecycle, StringComparison.Ordinal);
        return s with
        {
            Source = From(s.Source),
            Late = s.Late is { } l ? new GridLate(n => From(l.NarrowSource(n)), l.Join.Replace(GroupLate, GroupLateLifecycle, StringComparison.Ordinal)) : null,
        };
    }

    /// What the database holds for the choice (the tables; read before the per-collection reads).
    public const string Tables = """
SELECT CASE WHEN OBJECT_ID(N'sidata.FindingLifecycleRisk') IS NULL OR OBJECT_ID(N'sidata.KeyFigure') IS NULL THEN 0 ELSE 1 END AS HasRows,
       CASE WHEN OBJECT_ID(N'sidata.SummaryGroupLifecycle') IS NULL OR OBJECT_ID(N'sidata.SummaryGroupLifecycleState') IS NULL OR COL_LENGTH(N'sidata.Collection', N'KeyFiguresAt') IS NULL THEN 0 ELSE 1 END AS HasGroups;
""";

    /// The collection's findings the lifecycle view counts are stored: the key figures' marker, written in the same transaction
    /// as sidata.FindingLifecycleRisk (a collection figured before it has none: the choice is not offered).
    public const string RowsOf = """
SELECT TOP (1) 1 AS Ready FROM sidata.KeyFigure AS k
WHERE k.CollectionId = TRY_CONVERT(int, @CollectionId) AND k.Block = N'meta' AND k.Figure = N'lifecycle_rows';
""";

    /// The collection's lifecycle groupings are written for @Grouping, from its current key figures.
    public const string GroupsOf = """
SELECT TOP (1) 1 AS Ready FROM sidata.SummaryGroupLifecycleState AS s
JOIN sidata.Collection AS c ON c.CollectionId = s.CollectionId
WHERE s.CollectionId = TRY_CONVERT(int, @CollectionId) AND s.BuiltAt >= c.KeyFiguresAt AND s.Groupings LIKE N'%;' + @Grouping + N';%'
  AND EXISTS (SELECT 1 FROM sidata.KeyFigure AS k WHERE k.CollectionId = s.CollectionId AND k.Block = N'meta' AND k.Figure = N'lifecycle_rows');
""";
}

/// What one collection holds for the choice: its stored findings (Rows) and the asked grouping's lifecycle rows (Groups).
public sealed record AcceptedLifecycleRows(bool Rows, bool Groups)
{
    public static readonly AcceptedLifecycleRows None = new(false, false);
}

public interface IAcceptedLifecycleViews
{
    /// Whether the collection offers "Within Accepted Lifecycle": its stored findings (Rows), and -- <paramref name="grouping"/>
    /// given -- that grouping's lifecycle Summary rows (Groups).
    Task<QueryResult<AcceptedLifecycleRows>> AcceptedLifecycleAsync(string collectionId, string? grouping, CancellationToken ct);
}

/// The SQL reads of <see cref="IAcceptedLifecycleViews"/>; a database without the tables answers "not offered".
public sealed class SqlAcceptedLifecycleViews(IProSql sql, TimeProvider? clock = null) : IAcceptedLifecycleViews
{
    private readonly TimeProvider _clock = clock ?? TimeProvider.System;

    private async Task<IReadOnlyList<IReadOnlyDictionary<string, object?>>> Q(string text, Dictionary<string, object?> p, CancellationToken ct)
    {
        SqlGuard.AssertReadOnly(text);
        return await sql.QueryAsync(new SqlQuery(text, p), ct).ConfigureAwait(false);
    }

    public async Task<QueryResult<AcceptedLifecycleRows>> AcceptedLifecycleAsync(string collectionId, string? grouping, CancellationToken ct)
    {
        var id = CollectionViewSql.CollectionId(collectionId);
        var t = (await Q(AcceptedLifecycleSql.Tables, new(), ct)).FirstOrDefault();
        bool B(string k) => t is not null && ProDataQueries.L(t, k) == 1;
        var rows = B("HasRows") && (await Q(AcceptedLifecycleSql.RowsOf, new() { ["CollectionId"] = id }, ct)).Count > 0;
        var groups = rows && B("HasGroups") && !string.IsNullOrWhiteSpace(grouping)
            && (await Q(AcceptedLifecycleSql.GroupsOf, new() { ["CollectionId"] = id, ["Grouping"] = grouping }, ct)).Count > 0;
        return new(new AcceptedLifecycleRows(rows, groups), AcceptedLifecycleSql.RowsOf, sql.SourceName, _clock.GetUtcNow());
    }
}
