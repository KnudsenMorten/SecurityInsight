namespace SI.Management.Core.ProData;

// =====================================================================================================================
// THE CI GRAPH VIEWS (V3-DATA-MODEL 2.8.4 / 2.8.5): what the CI page and the service page show of a CI's place in the
// estate -- the business services that own it and what it inherits from them (sidata.CiService), its relations to other
// CIs both ways (sidata.vCiRelation), its findings with their whole lifecycle -- owner, SLA, due date, exemption, ticket
// (sidata.vCiFindingModel), and what changed on it (sidata.CiChange); and per service the CIs it owns with their open and
// overdue findings (sidata.vServiceCi). Written by the CI build and the data sync; read-only here. A database the updater
// has not updated yet has none of them: every read asks first and a missing part is an empty answer the page explains.
// =====================================================================================================================

/// Which graph parts exist in this database.
public sealed record CiGraphSchema(bool Services, bool Relations, bool FindingModel, bool Changes, bool ServiceCis)
{
    public static readonly CiGraphSchema None = new(false, false, false, false, false);
    public bool Any => Services || Relations || FindingModel || Changes;
}

/// One business service that owns the CI (sidata.CiService).
public sealed record CiServiceRow(string ServiceKey, string? ServiceName, string? Source, string? MatchedBy, string? Criticality, string? DataSensitivity,
    string? Environment, string? Owner, string? Department, bool Strictest, DateTime? FirstSeen);

/// One relation of the CI (sidata.vCiRelation): Direction "out" (the CI points at the other end) or "in".
public sealed record CiRelationRow(string Direction, string Kind, string? OtherCiId, string? OtherName, string? ToType, string? ToValue, string? Detail,
    string? Source, string? Confidence, string State, DateTime? FirstSeen, DateTime? LastSeen, DateTime? GoneAt);

/// One finding of the CI with its lifecycle (sidata.vCiFindingModel).
public sealed record CiFindingStateRow(string FindingKey, string? Title, string? FindingType, string? Severity, string State, string Status, DateTime? FirstDetected,
    DateTime? LastSeen, DateTime? ClosedAt, string? CloseReason, long ReopenCount, string? Owner, string? OwnerSource, long? SlaDays, DateTime? DueAt, bool Overdue,
    string? ExemptionReason, DateTime? ExemptedUntil, string? TicketState, bool Excluded);

/// One change of the CI (sidata.CiChange).
public sealed record CiChangeRow(DateTime? ChangedAt, string Field, string? OldValue, string? NewValue, string? Source, string? Reason);

/// Everything of the CI graph the CI page shows.
public sealed record CiGraph(CiGraphSchema Schema, IReadOnlyList<CiServiceRow> Services, IReadOnlyList<CiRelationRow> Relations,
    IReadOnlyList<CiFindingStateRow> Findings, IReadOnlyList<CiChangeRow> Changes)
{
    public static readonly CiGraph Empty = new(CiGraphSchema.None, [], [], [], []);
}

/// One CI a service owns (sidata.vServiceCi).
public sealed record ServiceCiRow(string CiId, string? Name, string? Class, int? Tier, string? Lifecycle, string? Source, string? MatchedBy, bool Strictest,
    double? WeightedRiskScore, long OpenFindings, long OverdueFindings, long OpenCritical, long OpenHigh);

public interface ICiGraphViews
{
    /// The services, relations, findings with their lifecycle and changes of one CI.
    Task<QueryResult<CiGraph>> CiGraphAsync(string ciId, CancellationToken ct);
    /// The CIs one service owns (by its key -- a CMDB service's number), with their open and overdue findings.
    Task<QueryResult<IReadOnlyList<ServiceCiRow>>> ServiceCisAsync(string serviceKey, CancellationToken ct);
    /// #855 M19: the CIs of one service of a lifecycle (null = the default, active; All = every CI the service owns).
    Task<QueryResult<IReadOnlyList<ServiceCiRow>>> ServiceCisAsync(string serviceKey, LifecycleFilter? lifecycle, CancellationToken ct) => ServiceCisAsync(serviceKey, ct);
}

/// <summary>The statements. Fixed text, parameters only, read-only.</summary>
public static class CiGraphSql
{
    public const int MaxRelations = 500;
    public const int MaxFindings = 500;
    public const int MaxChanges = 200;
    public const int MaxServiceCis = 500;
    public const int MaxServiceKey = 256;

    public const string Schema = """
SELECT CASE WHEN OBJECT_ID(N'sidata.CiService') IS NULL THEN 0 ELSE 1 END AS HasServices,
       CASE WHEN OBJECT_ID(N'sidata.vCiRelation') IS NULL THEN 0 ELSE 1 END AS HasRelations,
       CASE WHEN OBJECT_ID(N'sidata.vCiFindingModel') IS NULL THEN 0 ELSE 1 END AS HasFindingModel,
       CASE WHEN OBJECT_ID(N'sidata.CiChange') IS NULL THEN 0 ELSE 1 END AS HasChanges,
       CASE WHEN OBJECT_ID(N'sidata.vServiceCi') IS NULL THEN 0 ELSE 1 END AS HasServiceCis;
""";

    public const string Services = """
SELECT s.ServiceKey, s.ServiceName, s.Source, s.MatchedBy, s.Criticality, s.DataSensitivity, s.Environment, s.Owner, s.Department, s.Strictest, s.FirstSeen
FROM sidata.CiService AS s
WHERE s.CiId = @CiId
ORDER BY s.Strictest DESC, s.ServiceName, s.ServiceKey;
""";

    public const string Relations = """
SELECT TOP (@Take) v.Direction, v.Kind, v.OtherCiId, o.Name AS OtherName, v.ToType, v.ToValue, v.Detail, v.Source, v.Confidence, v.State, v.FirstSeen, v.LastSeen, v.GoneAt
FROM sidata.vCiRelation AS v
LEFT JOIN sidata.Ci AS o ON o.CiId = v.OtherCiId
WHERE v.CiId = @CiId
ORDER BY CASE WHEN v.State = N'active' THEN 0 ELSE 1 END, v.Direction DESC, v.Kind, COALESCE(o.Name, v.ToValue);
""";

    public const string Findings = """
SELECT TOP (@Take) m.FindingKey, m.Title, m.FindingType, m.Severity, m.State, m.Status, m.FirstDetected, m.LastSeen, m.ClosedAt, m.CloseReason, m.ReopenCount,
       m.Owner, m.OwnerSource, m.SlaDays, m.DueAt, m.Overdue, m.ExemptionReason, m.ExemptedUntil, m.TicketState, m.Excluded
FROM sidata.vCiFindingModel AS m
WHERE m.CiId = @CiId
ORDER BY CASE m.Status WHEN N'reopened' THEN 0 WHEN N'open' THEN 1 WHEN N'exempted' THEN 2 ELSE 3 END, m.Overdue DESC, m.DueAt, m.FindingKey;
""";

    public const string Changes = """
SELECT TOP (@Take) c.ChangedAt, c.Field, c.OldValue, c.NewValue, c.Source, c.Reason
FROM sidata.CiChange AS c
WHERE c.CiId = @CiId
ORDER BY c.ChangedAt DESC, c.ChangeId DESC;
""";

    public const string ServiceCis = """
SELECT TOP (@Take) v.CiId, v.Name, v.Class, v.Tier, v.Lifecycle, v.Source, v.MatchedBy, v.Strictest, v.WeightedRiskScore, v.OpenFindings, v.OverdueFindings,
       v.OpenCritical, v.OpenHigh
FROM sidata.vServiceCi AS v
WHERE v.ServiceKey = @ServiceKey
ORDER BY v.OverdueFindings DESC, v.OpenCritical DESC, CASE WHEN v.WeightedRiskScore IS NULL THEN 1 ELSE 0 END, v.WeightedRiskScore DESC, v.Name;
""";

    /// #855 M19: <see cref="ServiceCis"/> over the CIs of a lifecycle (the CI's own lifecycle; none = active). All = the
    /// statement as it is. The predicate comes from the fixed state names only.
    public static string ServiceCisFor(LifecycleFilter? lifecycle)
    {
        var life = lifecycle ?? LifecycleFilter.Active;
        return life.IsAll ? ServiceCis : ServiceCis.Replace("WHERE v.ServiceKey = @ServiceKey", "WHERE v.ServiceKey = @ServiceKey AND " + life.Sql("v.Lifecycle"), StringComparison.Ordinal);
    }

    /// A service key as it may reach a parameter (refused when it does not fit).
    public static string ServiceKey(string? v)
    {
        var t = v?.Trim();
        if (string.IsNullOrEmpty(t)) throw new ArgumentException("a service key is required");
        if (t.Length > MaxServiceKey || t.Any(char.IsControl)) throw new ArgumentException("the service key is not valid");
        return t;
    }
}

/// <summary>The SQL implementation over <see cref="IProSql"/>; every statement passes <see cref="SqlGuard"/> first.</summary>
public sealed class CiGraphViews : ICiGraphViews
{
    private readonly IProSql _sql;
    private readonly TimeProvider _clock;

    public CiGraphViews(IProSql sql, TimeProvider? clock = null) { _sql = sql; _clock = clock ?? TimeProvider.System; }

    private async Task<(IReadOnlyList<IReadOnlyDictionary<string, object?>> Rows, string Text)> Run(SqlQuery q, CancellationToken ct)
    {
        SqlGuard.AssertReadOnly(q.Text);
        var rows = await ViewTimeout.Run(t => _sql.QueryAsync(q, t), CiViews.Timeout, ct).ConfigureAwait(false);
        return (rows, EstateQueries.DescribeSql(q.Text, q.Parameters));
    }

    private QueryResult<T> R<T>(T data, string text) => new(data, text, _sql.SourceName, _clock.GetUtcNow());
    private static Dictionary<string, object?> P(params (string K, object? V)[] p) => p.ToDictionary(x => x.K, x => x.V);
    private static int? Int(IReadOnlyDictionary<string, object?> r, string c) => ProDataQueries.LN(r, c) is { } l ? (int)l : null;

    public async Task<CiGraphSchema> SchemaAsync(CancellationToken ct)
    {
        var (rows, _) = await Run(new SqlQuery(CiGraphSql.Schema, P()), ct).ConfigureAwait(false);
        var r = rows.Count > 0 ? rows[0] : new Dictionary<string, object?>();
        return new CiGraphSchema(CiViews.Flag(r, "HasServices"), CiViews.Flag(r, "HasRelations"), CiViews.Flag(r, "HasFindingModel"), CiViews.Flag(r, "HasChanges"),
            CiViews.Flag(r, "HasServiceCis"));
    }

    public async Task<QueryResult<CiGraph>> CiGraphAsync(string ciId, CancellationToken ct)
    {
        var id = CiSql.CiId(ciId);
        var schema = await SchemaAsync(ct).ConfigureAwait(false);
        if (!schema.Any) return R(CiGraph.Empty, "");
        var texts = new List<string>();
        IReadOnlyList<CiServiceRow> services = [];
        if (schema.Services)
        {
            var (rows, text) = await Run(new SqlQuery(CiGraphSql.Services, P(("CiId", id))), ct).ConfigureAwait(false);
            services = rows.Select(r => new CiServiceRow(ProDataQueries.S(r, "ServiceKey"), ProDataQueries.SN(r, "ServiceName"), ProDataQueries.SN(r, "Source"),
                ProDataQueries.SN(r, "MatchedBy"), ProDataQueries.SN(r, "Criticality"), ProDataQueries.SN(r, "DataSensitivity"), ProDataQueries.SN(r, "Environment"),
                ProDataQueries.SN(r, "Owner"), ProDataQueries.SN(r, "Department"), CiViews.Flag(r, "Strictest"), ProDataQueries.T(r, "FirstSeen"))).ToList();
            texts.Add(text);
        }
        IReadOnlyList<CiRelationRow> relations = [];
        if (schema.Relations)
        {
            var (rows, text) = await Run(new SqlQuery(CiGraphSql.Relations, P(("CiId", id), ("Take", CiGraphSql.MaxRelations))), ct).ConfigureAwait(false);
            relations = rows.Select(r => new CiRelationRow(ProDataQueries.S(r, "Direction"), ProDataQueries.S(r, "Kind"), ProDataQueries.SN(r, "OtherCiId"),
                ProDataQueries.SN(r, "OtherName"), ProDataQueries.SN(r, "ToType"), ProDataQueries.SN(r, "ToValue"), ProDataQueries.SN(r, "Detail"),
                ProDataQueries.SN(r, "Source"), ProDataQueries.SN(r, "Confidence"), ProDataQueries.S(r, "State"), ProDataQueries.T(r, "FirstSeen"),
                ProDataQueries.T(r, "LastSeen"), ProDataQueries.T(r, "GoneAt"))).ToList();
            texts.Add(text);
        }
        IReadOnlyList<CiFindingStateRow> findings = [];
        if (schema.FindingModel)
        {
            var (rows, text) = await Run(new SqlQuery(CiGraphSql.Findings, P(("CiId", id), ("Take", CiGraphSql.MaxFindings))), ct).ConfigureAwait(false);
            findings = rows.Select(r => new CiFindingStateRow(ProDataQueries.S(r, "FindingKey"), ProDataQueries.SN(r, "Title"), ProDataQueries.SN(r, "FindingType"),
                ProDataQueries.SN(r, "Severity"), ProDataQueries.S(r, "State"), ProDataQueries.S(r, "Status"), ProDataQueries.T(r, "FirstDetected"),
                ProDataQueries.T(r, "LastSeen"), ProDataQueries.T(r, "ClosedAt"), ProDataQueries.SN(r, "CloseReason"), ProDataQueries.L(r, "ReopenCount"),
                ProDataQueries.SN(r, "Owner"), ProDataQueries.SN(r, "OwnerSource"), ProDataQueries.LN(r, "SlaDays"), ProDataQueries.T(r, "DueAt"), CiViews.Flag(r, "Overdue"),
                ProDataQueries.SN(r, "ExemptionReason"), ProDataQueries.T(r, "ExemptedUntil"), ProDataQueries.SN(r, "TicketState"), CiViews.Flag(r, "Excluded"))).ToList();
            texts.Add(text);
        }
        IReadOnlyList<CiChangeRow> changes = [];
        if (schema.Changes)
        {
            var (rows, text) = await Run(new SqlQuery(CiGraphSql.Changes, P(("CiId", id), ("Take", CiGraphSql.MaxChanges))), ct).ConfigureAwait(false);
            changes = rows.Select(r => new CiChangeRow(ProDataQueries.T(r, "ChangedAt"), ProDataQueries.S(r, "Field"), ProDataQueries.SN(r, "OldValue"),
                ProDataQueries.SN(r, "NewValue"), ProDataQueries.SN(r, "Source"), ProDataQueries.SN(r, "Reason"))).ToList();
            texts.Add(text);
        }
        return R(new CiGraph(schema, services, relations, findings, changes), string.Join("\n\n", texts));
    }

    /// Every CI the service owns, whatever its lifecycle (a caller without a lifecycle choice, as before).
    public Task<QueryResult<IReadOnlyList<ServiceCiRow>>> ServiceCisAsync(string serviceKey, CancellationToken ct) => ServiceCisAsync(serviceKey, LifecycleFilter.All, ct);

    public async Task<QueryResult<IReadOnlyList<ServiceCiRow>>> ServiceCisAsync(string serviceKey, LifecycleFilter? lifecycle, CancellationToken ct)
    {
        var key = CiGraphSql.ServiceKey(serviceKey);
        var schema = await SchemaAsync(ct).ConfigureAwait(false);
        if (!schema.ServiceCis) return R<IReadOnlyList<ServiceCiRow>>([], "");
        var (rows, text) = await Run(new SqlQuery(CiGraphSql.ServiceCisFor(lifecycle), P(("ServiceKey", key), ("Take", CiGraphSql.MaxServiceCis))), ct).ConfigureAwait(false);
        return R<IReadOnlyList<ServiceCiRow>>(rows.Select(r => new ServiceCiRow(ProDataQueries.S(r, "CiId"), ProDataQueries.SN(r, "Name"), ProDataQueries.SN(r, "Class"),
            Int(r, "Tier"), ProDataQueries.SN(r, "Lifecycle"), ProDataQueries.SN(r, "Source"), ProDataQueries.SN(r, "MatchedBy"), CiViews.Flag(r, "Strictest"),
            ProDataQueries.DN(r, "WeightedRiskScore"), ProDataQueries.L(r, "OpenFindings"), ProDataQueries.L(r, "OverdueFindings"), ProDataQueries.L(r, "OpenCritical"),
            ProDataQueries.L(r, "OpenHigh"))).ToList(), text);
    }
}
