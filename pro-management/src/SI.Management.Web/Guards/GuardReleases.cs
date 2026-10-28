using System.Globalization;
using System.Text.Json;
using SI.Management.Web.Data;

namespace SI.Management.Web.Guards;

/// One line of a held close set's counts (an asset, or a CVE, and how many closes it holds).
public sealed record GuardReleaseCount(string Name, int Count);

/// <summary>
/// The close set a vulnerability connector run held when its close limit halted (operator decision 2026-10-04: "mass
/// closes from patching must never block -- we cannot block"). Stored by the engine (SI-VulnRelease.ps1) in
/// cfg.GuardRelease: held -> released (an Admin, ONCE) -> applied by the connector's next run | expired after 7 days.
/// </summary>
public sealed record GuardRelease(long Id, string GuardId, string Connector, string? Kind, string RunId, DateTime? HeldUtc, DateTime? ExpiresUtc,
    int HeldCount, string State, string? ReleasedBy, DateTime? ReleasedUtc, string? AppliedText, int Assets, int Cves,
    IReadOnlyList<GuardReleaseCount> ByAsset, IReadOnlyList<GuardReleaseCount> ByCve,
    DateTime? CollectionTime = null, long CollectionRows = 0, string? HoldReason = null, string? RunDetail = null,
    string? PlanHash = null, string? ReleasedPlanHash = null, DateTime? ReleaseUntilUtc = null, string? ReleaseReason = null, string? ReleaseApprovedBy = null,
    IReadOnlyDictionary<string, string>? Facts = null)
{
    /// The held set's own numbers from its summary (a CMDB hand-off: PreviousCis / CurrentCis / Disappeared / ChangePercent;
    /// asset metadata: Source / PreviousRows / CurrentRows / ChangePercent), as invariant text; empty when not stored.
    public string Fact(string name) => Facts is not null && Facts.TryGetValue(name, out var v) ? v : "";

    /// The data sync's held Risk Analysis collections (connector 'datasync/detailed', kind 'collection'): an Admin loads
    /// one ONCE, marked partial wherever it is shown (Operations > Guards, "Release: load this collection anyway").
    public const string CollectionKind = "collection";
    public bool IsCollection => string.Equals(Kind, CollectionKind, StringComparison.OrdinalIgnoreCase);

    /// Only a HELD set that has not expired can be released -- and only once.
    public bool CanRelease(DateTime nowUtc) => State == "held" && ExpiresUtc is { } e && e > nowUtc;

    /// GUARD-1.6: a release ends by itself -- after one run, or at the time the SuperAdmin chose (at most 24 hours).
    public const int MaxReleaseHours = 24;

    /// The latest a release may last: the chosen hours (1-24), never past the held set's own expiry.
    public DateTime ReleaseUntil(DateTime nowUtc, int hours)
    {
        var until = nowUtc.AddHours(Math.Clamp(hours, 1, MaxReleaseHours));
        return ExpiresUtc is { } e && e < until ? e : until;
    }

    /// The job that runs this connector: the ServiceNow connectors have their own job (#269); a held asset-properties
    /// collection (#301) is applied by the PROFILER that read the source (#412: 'asset-properties/&lt;profiler&gt;/&lt;source&gt;'
    /// -> caj-si-&lt;profiler&gt;; a hold stored before, 'asset-properties/&lt;source&gt;', by the profiler that reads that source).
    public string Job => string.Equals(Kind, "servicenow", StringComparison.OrdinalIgnoreCase) ? "caj-si-asset-vulns-servicenow"
        : string.Equals(Kind, "asset-properties", StringComparison.OrdinalIgnoreCase) ? AssetPropertiesJob(Connector)
        : string.Equals(Kind, "sql-cmdb", StringComparison.OrdinalIgnoreCase) ? "caj-si-asset-cmdb-sql"
        : IsCollection ? "caj-si-asset-datasync" : "caj-si-asset-vulnerabilities";

    /// The profiler job that applies a held asset-properties collection (#412): the profiler named in the connector, else
    /// the one that reads the source (endpoint: Defender, Entra devices, Intune, device Exposure Graph nodes; identity:
    /// Entra users / service principals, AD; azure: ARM and VM extensions).
    public static string AssetPropertiesJob(string? connector)
    {
        var parts = (connector ?? "").Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length >= 3 && parts[1] is "endpoint" or "identity" or "azure") return "caj-si-" + parts[1];
        var source = parts.Length >= 2 ? parts[^1] : "";
        return source switch
        {
            "entra-user" or "entra-serviceprincipal" or "ad-computer" => "caj-si-identity",
            "arm" or "arm-vm-extension" => "caj-si-azure",
            _ => "caj-si-endpoint",
        };
    }

    public static GuardRelease From(IReadOnlyDictionary<string, object?> r)
    {
        string? S(string k) => r.TryGetValue(k, out var v) && v is not null && v is not DBNull ? Convert.ToString(v, CultureInfo.InvariantCulture) : null;
        long L(string k) => r.TryGetValue(k, out var v) && v is not null && v is not DBNull ? Convert.ToInt64(v, CultureInfo.InvariantCulture) : 0;
        DateTime? D(string k) => r.TryGetValue(k, out var v) && v is DateTime d ? DateTime.SpecifyKind(d, DateTimeKind.Utc) : null;
        int assets = 0, cves = 0; DateTime? ct = null; long crows = 0; string? hold = null, runDetail = null;
        var byAsset = new List<GuardReleaseCount>(); var byCve = new List<GuardReleaseCount>();
        var facts = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var json = S("SummaryJson");
        if (!string.IsNullOrWhiteSpace(json))
        {
            try
            {
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;
                if (root.ValueKind == JsonValueKind.Object)
                    foreach (var p in root.EnumerateObject())
                        if (p.Value.ValueKind is JsonValueKind.Number or JsonValueKind.String) facts[p.Name] = p.Value.ValueKind == JsonValueKind.Number ? p.Value.GetRawText() : p.Value.GetString() ?? "";
                if (root.TryGetProperty("Assets", out var a) && a.TryGetInt32(out var ai)) assets = ai;
                if (root.TryGetProperty("Cves", out var c) && c.TryGetInt32(out var ci)) cves = ci;
                // a held collection: when, how many findings, why it was held and what its run said was incomplete
                if (root.TryGetProperty("CollectionTime", out var t) && t.ValueKind == JsonValueKind.String
                    && DateTime.TryParse(t.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var td)) ct = DateTime.SpecifyKind(td, DateTimeKind.Utc);
                if (root.TryGetProperty("Rows", out var rr) && rr.TryGetInt64(out var rl)) crows = rl;
                if (root.TryGetProperty("Reason", out var rs) && rs.ValueKind == JsonValueKind.String) hold = rs.GetString();
                if (root.TryGetProperty("RunDetail", out var rd) && rd.ValueKind == JsonValueKind.String) runDetail = rd.GetString();
                static void Read(JsonElement root, string name, List<GuardReleaseCount> into)
                {
                    if (!root.TryGetProperty(name, out var arr)) return;
                    var items = arr.ValueKind == JsonValueKind.Array ? arr.EnumerateArray().ToList() : arr.ValueKind == JsonValueKind.Object ? [arr] : [];
                    foreach (var x in items)
                        if (x.TryGetProperty("Name", out var n) && x.TryGetProperty("Count", out var k) && k.TryGetInt32(out var ki)) into.Add(new GuardReleaseCount(n.GetString() ?? "", ki));
                }
                Read(root, "ByAsset", byAsset); Read(root, "ByCve", byCve);
            }
            catch (JsonException) { }
        }
        return new GuardRelease(L("ReleaseId"), S("GuardId") ?? "", S("Connector") ?? "", S("ConnectorKind"), S("RunId") ?? "", D("HeldUtc"), D("ExpiresUtc"),
            (int)L("HeldCount"), S("State") ?? "", S("ReleasedBy"), D("ReleasedUtc"), S("AppliedText"), assets, cves, byAsset, byCve, ct, crows, hold, runDetail,
            S("CurrentPlanHash"), S("PlanHash"), D("ReleaseUntilUtc"), S("ReleaseReason"), S("ReleaseApprovedBy"), facts);
    }
}

public interface IGuardReleaseStore
{
    Task<bool> ExistsAsync(CancellationToken ct);
    /// The held close sets of the last 30 days (newest first).
    Task<IReadOnlyList<GuardRelease>> RecentAsync(CancellationToken ct);
    Task<GuardRelease?> FindAsync(long id, CancellationToken ct);
    /// held -> released, ONCE: false when the set is no longer held, has expired, or its plan is not the one the person saw.
    /// GUARD-1.6: with the reason, the plan hash, until when (at most 24 hours), the commit id and the second SuperAdmin.
    Task<bool> ReleaseAsync(long id, string by, string reason, string planHash, DateTime untilUtc, string scope, string? correlationId, string? approvedBy, CancellationToken ct);
}

public sealed class SqlGuardReleaseStore : IGuardReleaseStore
{
    public const string ExistsSql = "SELECT CASE WHEN OBJECT_ID(N'cfg.GuardRelease') IS NOT NULL THEN 1 ELSE 0 END AS HasTable;";
    private const string Columns = "ReleaseId, GuardId, Connector, ConnectorKind, RunId, HeldUtc, ExpiresUtc, HeldCount, SummaryJson, State, ReleasedBy, ReleasedUtc, AppliedText";
    /// GUARD-1.6 (#404): the plan hash as it is now, and what a release recorded -- read when the schema has them.
    private const string ReleaseColumns = ", CurrentPlanHash, PlanHash, ReleaseUntilUtc, ReleaseReason, ReleaseApprovedBy";
    private static string Either(string top, string where) =>
        "IF COL_LENGTH(N'cfg.GuardRelease', N'CurrentPlanHash') IS NULL SELECT " + top + Columns + " FROM cfg.GuardRelease " + where + ";\n" +
        "ELSE SELECT " + top + Columns + ReleaseColumns + " FROM cfg.GuardRelease " + where + ";";
    public static readonly string RecentSql = Either("TOP (200) ", "WHERE HeldUtc >= DATEADD(day, -30, SYSUTCDATETIME()) ORDER BY ReleaseId DESC");
    public static readonly string FindSql = Either("", "WHERE ReleaseId = @Id");
    /// The one write: a held, unexpired set becomes released -- once, and only for the plan the SuperAdmin saw (GUARD-1.6:
    /// a changed plan needs a new release), until a time of at most 24 hours. Every apply path checks both again
    /// (engine\asset-cmdb\_shared\SI-VulnRelease.ps1 'Expire' puts a release whose plan changed or whose time ran out back).
    public const string ReleaseSql =
        "UPDATE cfg.GuardRelease SET State = N'released', ReleasedBy = @By, ReleasedUtc = SYSUTCDATETIME(), ReleaseReason = @Reason, PlanHash = CurrentPlanHash,\n" +
        "       ReleaseUntilUtc = @Until, ReleaseScope = @Scope, ReleaseCorrelationId = @Cid, ReleaseApprovedBy = @ApprovedBy\n" +
        "WHERE ReleaseId = @Id AND State = N'held' AND ExpiresUtc > SYSUTCDATETIME() AND CurrentPlanHash = @PlanHash; SELECT @@ROWCOUNT AS Released;";

    private readonly ISqlExecutor _sql;
    public SqlGuardReleaseStore(ISqlExecutor sql) => _sql = sql;

    public async Task<bool> ExistsAsync(CancellationToken ct) =>
        (await _sql.QueryAsync(ExistsSql, new Dictionary<string, object?>(), ct)).FirstOrDefault()?.Long("HasTable") == 1;

    public async Task<IReadOnlyList<GuardRelease>> RecentAsync(CancellationToken ct)
    {
        if (!await ExistsAsync(ct)) return Array.Empty<GuardRelease>();
        return (await _sql.QueryAsync(RecentSql, new Dictionary<string, object?>(), ct)).Select(GuardRelease.From).ToList();
    }

    public async Task<GuardRelease?> FindAsync(long id, CancellationToken ct) =>
        (await _sql.QueryAsync(FindSql, new Dictionary<string, object?> { ["Id"] = id }, ct)).Select(GuardRelease.From).FirstOrDefault();

    public async Task<bool> ReleaseAsync(long id, string by, string reason, string planHash, DateTime untilUtc, string scope, string? correlationId, string? approvedBy, CancellationToken ct) =>
        (await _sql.QueryAsync(ReleaseSql, new Dictionary<string, object?>
        {
            ["Id"] = id, ["By"] = by, ["Reason"] = reason.Length > 1000 ? reason[..1000] : reason, ["PlanHash"] = planHash, ["Until"] = untilUtc,
            ["Scope"] = scope, ["Cid"] = correlationId, ["ApprovedBy"] = approvedBy,
        }, ct)).FirstOrDefault()?.Long("Released") == 1;
}
