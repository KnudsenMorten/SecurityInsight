namespace SI.Management.Core.ProData;

// =====================================================================================================================
// ONE TRUSTED RUN (owner 2026-10-19: "it is a big problem that we have a mix of old and new data, so trust is broken to
// the solution. we need the views to use last know good run, where we can trust it apart all" / "and not show some parts
// from recent run and some from last known good run").
//
// Every view reads ONE run per install: the PUBLISHED run (sidata.PublishedRun 'current', sql/si-data-schema.sql "ONE
// TRUSTED RUN"). The pipeline runner moves it at the end of a run that is trusted -- every step succeeded, the data sync and
// the verification included, and the database found the run's own collection complete, its views and day totals written,
// its executive views of both grains, its summary and its merged assets (engine/_shared/data-sql/SI-DataPublishedRun.ps1).
// A run in progress, a failed run and (by default) a run in which a report fell back to an earlier result never move it.
//
// THE RULE FOR EVERY STATEMENT: "the newest" is never worked out by a reader. A reader that shows the current data takes
// the published collection from <see cref="DetailedId"/> / <see cref="DetailedTime"/> (sidata.vPublishedCollection), the
// executive views from sidata.vPublishedExecView, and a list or a trend never goes past the published collection
// (<see cref="NotAfter"/>). A collection a person CHOSE (the collection list, a link with its id) is still read as chosen.
// The guard test (PublishedRunGuardTests) fails on any statement that picks "the newest" collection on its own.
// =====================================================================================================================

/// <summary>The SQL parts every reader of "the current data" uses.</summary>
public static class PublishedRun
{
    /// The view of the published Detailed collection (one row; on an install where no run was published yet, the newest
    /// complete collection whose views are ready).
    public const string View = "sidata.vPublishedCollection";

    /// The published collection's id, as a scalar subquery (NULL = no collection yet).
    public const string DetailedId = "(SELECT TOP (1) pc.CollectionId FROM sidata.vPublishedCollection AS pc WHERE pc.Kind = N'Detailed')";

    /// The published collection's time, as a scalar subquery (NULL = no collection yet).
    public const string DetailedTime = "(SELECT TOP (1) pc.CollectionTime FROM sidata.vPublishedCollection AS pc WHERE pc.Kind = N'Detailed')";

    /// The published Summary collection time (sidata.SummaryLoad), as a scalar subquery: the published run's own summary;
    /// with no published run yet, the newest complete one (as before). NULL = none.
    public const string SummaryTime = """
(SELECT TOP (1) t.T FROM (
    SELECT p.SummaryCollectionTime AS T, 0 AS Pri FROM sidata.PublishedRun AS p WHERE p.Name = N'current' AND p.DetailedCollectionId IS NOT NULL
    UNION ALL
    SELECT MAX(l.CollectionTime), 1 FROM sidata.SummaryLoad AS l
    WHERE l.Status = N'Complete' AND NOT EXISTS (SELECT 1 FROM sidata.PublishedRun AS p2 WHERE p2.Name = N'current' AND p2.DetailedCollectionId IS NOT NULL)
) AS t ORDER BY t.Pri)
""";

    /// A list or a trend never reaches past the published collection: <paramref name="timeColumn"/> is at or before it
    /// (no published collection = no limit).
    public static string NotAfter(string timeColumn) => $"({timeColumn} <= ISNULL({DetailedTime}, {timeColumn}))";

    /// The banner's facts, ONE read: the published run (Name 'current') and the newest whole run that did not publish
    /// (Name 'refused'), each with the collection the views show (ShownTime) and whether a pipeline run is going now
    /// (Running, from the run records). A database the update has not given the pointer yet answers no row (no banner).
    public const string State = """
DECLARE @running bit = 0;
IF OBJECT_ID(N'cfg.FlowRun') IS NOT NULL
    SELECT TOP (1) @running = CASE WHEN r.State = N'Running' THEN 1 ELSE 0 END FROM cfg.FlowRun AS r WHERE r.FlowId = N'daily' ORDER BY r.StartedUtc DESC;
IF OBJECT_ID(N'sidata.PublishedRun') IS NULL OR OBJECT_ID(N'sidata.vPublishedCollection') IS NULL
    SELECT TOP (0) CAST(NULL AS nvarchar(16)) AS Name, CAST(NULL AS datetime2(3)) AS ShownTime, CAST(NULL AS datetime2(0)) AS At,
           CONVERT(bit, 0) AS [Partial], CAST(NULL AS nvarchar(400)) AS Note, CONVERT(bit, 0) AS Running, CAST(NULL AS datetime2(3)) AS CiFindingsTime;
ELSE
    SELECT x.Name, (SELECT TOP (1) pc.CollectionTime FROM sidata.vPublishedCollection AS pc WHERE pc.Kind = N'Detailed') AS ShownTime,
           x.PublishedAt AS At, x.[Partial], x.Note, @running AS Running, x.CiFindingsTime
    FROM (SELECT pr.Name, pr.PublishedAt, pr.[Partial], pr.Note, pr.CiFindingsTime
          -- review S2: as of when the findings per CI are, when they are NOT the published run's -- the STORED column
          -- sidata.PublishedRun.CiFindingTime. A database the update has not given the column yet answers NULL instead of
          -- failing: the unqualified CiFindingTime binds to the table's column when it exists, else to the outer NULL default.
          FROM (SELECT CAST(NULL AS datetime2(3)) AS CiFindingTime) AS dflt
          CROSS APPLY (SELECT p.Name, p.PublishedAt, p.[Partial], p.Note, CiFindingTime AS CiFindingsTime FROM sidata.PublishedRun AS p) AS pr
          UNION ALL
          SELECT N'none', NULL, CONVERT(bit, 0), NULL, NULL WHERE NOT EXISTS (SELECT 1 FROM sidata.PublishedRun AS p2 WHERE p2.Name = N'current')) AS x;
""";
}

/// <summary>What the banner says about the data shown (no internal names).</summary>
public sealed record PublishedRunState(
    DateTime? ShownTime,          // the collection every view shows (UTC)
    DateTime? PublishedAt,        // when it was published (null = no run published yet: the newest complete collection)
    bool Running,                 // a pipeline run is going now: what it brings is shown once it is trusted
    DateTime? RefusedAt,          // the newest run that ended and did NOT publish (null = none since the published one)
    string RefusedWhy,
    bool Partial,
    DateTime? CiFindingsTime = null)  // review S2: the findings per CI are NOT the shown run's -- they are as of this time (UTC)
{
    public static readonly PublishedRunState None = new(null, null, false, null, "", false);

    /// PURE. The rows of <see cref="PublishedRun.State"/> -> the state. No row = <see cref="None"/> (no banner).
    public static PublishedRunState From(IReadOnlyList<IReadOnlyDictionary<string, object?>> rows)
    {
        static DateTime? T(IReadOnlyDictionary<string, object?> r, string c) =>
            r.TryGetValue(c, out var v) && v is DateTime d ? DateTime.SpecifyKind(d, DateTimeKind.Utc) : null;
        static string S(IReadOnlyDictionary<string, object?> r, string c) =>
            r.TryGetValue(c, out var v) && v is not null && v is not DBNull ? Convert.ToString(v, System.Globalization.CultureInfo.InvariantCulture) ?? "" : "";
        static bool B(IReadOnlyDictionary<string, object?> r, string c) =>
            r.TryGetValue(c, out var v) && (v is bool b ? b : v is not null && v is not DBNull && Convert.ToInt64(v, System.Globalization.CultureInfo.InvariantCulture) != 0);
        if (rows.Count == 0) return None;
        var cur = rows.FirstOrDefault(r => S(r, "Name") == "current");
        var refused = rows.FirstOrDefault(r => S(r, "Name") == "refused");
        var published = cur is null ? null : T(cur, "At");
        DateTime? refusedAt = null; var why = "";
        // the newest whole run that did not publish counts only when it ended AFTER the run that is shown was published
        if (refused is not null && T(refused, "At") is { } ra && (published is null || ra > published)) { refusedAt = ra; why = S(refused, "Note"); }
        return new PublishedRunState(T(rows[0], "ShownTime"), published, B(rows[0], "Running"), refusedAt, why, cur is not null && B(cur, "Partial"),
                                     cur is null ? null : T(cur, "CiFindingsTime"));
    }
}