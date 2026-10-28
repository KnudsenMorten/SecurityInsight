using System.Globalization;
using System.Text;
using Microsoft.Extensions.Options;

namespace SI.Management.Core;

/// The curated, read-only queries over the estate: Log Analytics (Risk Analysis, trend, run health) and the Pro
/// SQL database (vulnerability close-loop). Every method validates its input, fills a FIXED template from
/// <see cref="QueryTemplates"/>, runs it, and returns the data together with the exact text it ran.
public sealed class EstateQueries : IEstateQueries
{
    private readonly ILogAnalyticsReader _la;
    private readonly ISqlReader _sql;
    private readonly EstateOptions _o;
    private readonly TimeProvider _clock;

    public EstateQueries(ILogAnalyticsReader la, ISqlReader sql, IOptions<EstateOptions> options, TimeProvider? clock = null)
    {
        _la = la;
        _sql = sql;
        _o = options.Value;
        _clock = clock ?? TimeProvider.System;
    }

    // ---------------------------------------------------------------- query builders (pure, testable)

    internal string BuildTopRisks(int top) => BuildRanking(QueryParameters.Top(top));

    /// The ranking for every exposed asset (up to QueryParameters.MaxRanked): the same statement as top_risks.
    internal string BuildRankedAssets(int max) => BuildRanking(QueryParameters.Ranked(max));

    private string BuildRanking(int rows) => QueryTemplates.Fill(QueryTemplates.TopRisks, new Dictionary<string, string>
    {
        ["ID_DAYS"] = Int(QueryParameters.LookbackDays(_o.IdentityLookbackDays, nameof(_o.IdentityLookbackDays))),
        ["SNAP_DAYS"] = Int(QueryParameters.LookbackDays(_o.SnapshotLookbackDays, nameof(_o.SnapshotLookbackDays))),
        ["EDITION"] = QueryParameters.KqlString(QueryParameters.Edition(_o.RaEditionSuffix)),
        ["TOP"] = Int(rows),
        ["COUNTED"] = CountedFilter(),
    });

    /// #264: the KQL form of the shared predicate under the request's exempted scope ("true" = every row).
    internal static string CountedFilter() => SI.Management.Core.ProData.Exempted.Excluding ? SI.Management.Core.ProData.Exempted.KqlCounted : "true";

    /// The asset part of asset_lookup (the identity map over the profile tables, a prerequisite Risk Analysis reads in Log
    /// Analytics too). #830: its findings come from the database (<see cref="BuildAssetFindings"/>).
    internal string BuildAssetLookup(string nameOrId) => QueryTemplates.Fill(QueryTemplates.AssetLookup, new Dictionary<string, string>
    {
        ["ID_DAYS"] = Int(QueryParameters.LookbackDays(_o.IdentityLookbackDays, nameof(_o.IdentityLookbackDays))),
        ["NAME"] = QueryParameters.KqlString(QueryParameters.NameOrId(nameOrId)),
    });

    /// #830: the asset's top findings from the Detailed result in the database: the statement and its parameters (@i0..: the
    /// asset id and its related ids, each with and without "az:"), under the request's exempted scope.
    internal static (string Sql, IReadOnlyDictionary<string, object?> Params) BuildAssetFindings(string assetId, IEnumerable<string> relatedIds)
    {
        var ids = new List<string>();
        foreach (var raw in new[] { assetId }.Concat(relatedIds ?? Array.Empty<string>()))
        {
            var id = (raw ?? "").Trim();
            if (id.Length == 0) continue;
            var bare = id.StartsWith("az:", StringComparison.OrdinalIgnoreCase) ? id[3..] : id;
            foreach (var v in new[] { bare, "az:" + bare })
                if (v.Length <= 400 && !ids.Contains(v, StringComparer.OrdinalIgnoreCase)) ids.Add(v);
        }
        var p = new Dictionary<string, object?>();
        for (var i = 0; i < ids.Count; i++) p["i" + i.ToString(CultureInfo.InvariantCulture)] = ids[i];
        var counted = SI.Management.Core.ProData.Exempted.Excluding ? SI.Management.Core.ProData.Exempted.CountedSql("f") : "1 = 1";
        return (QueryTemplates.AssetTopFindings(Math.Max(1, ids.Count), counted), p);
    }

    internal static string BuildRunHealth(int days) => DaysOnly(QueryTemplates.RunHealth, days);

    private static string DaysOnly(string template, int days) =>
        QueryTemplates.Fill(template, new Dictionary<string, string> { ["DAYS"] = Int(QueryParameters.Days(days)) });

    private static string Int(int v) => v.ToString(CultureInfo.InvariantCulture);

    /// The Sunday (UTC) that starts the first of the last `weeks` weeks, this week included.
    internal DateTime FirstWeekStart(int weeks)
    {
        var today = _clock.GetUtcNow().UtcDateTime.Date;
        var thisWeek = today.AddDays(-(int)today.DayOfWeek);
        return thisWeek.AddDays(-7 * (weeks - 1));
    }

    /// The text a SQL result carries: the fixed statement plus the parameter values it ran with.
    internal static string DescribeSql(string sql, IReadOnlyDictionary<string, object?> p)
    {
        var sb = new StringBuilder(sql.TrimEnd());
        sb.Append('\n');
        foreach (var (k, v) in p)
            sb.Append("-- @").Append(k).Append(" = ").Append(v switch
            {
                null => "NULL",
                DateTime d => d.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture),
                IFormattable f => f.ToString(null, CultureInfo.InvariantCulture),
                _ => v.ToString(),
            }).Append('\n');
        return sb.ToString().TrimEnd();
    }

    // ---------------------------------------------------------------- IEstateQueries

    public async Task<QueryResult<IReadOnlyList<TopRisk>>> TopRisksAsync(int top, CancellationToken ct)
    {
        var q = BuildTopRisks(top);
        var rows = await _la.QueryAsync(q, ct).ConfigureAwait(false);
        var data = rows.Select(r => new TopRisk(
            Cell.Int(r, "Rank"), Cell.Str(r, "AssetName"), Cell.Str(r, "AssetId"), Cell.Str(r, "Tier"),
            Cell.Dbl(r, "WeightedRiskScore"), Cell.Int(r, "Findings"), Cell.List(r, "Domains"))).ToList();
        return new(MergeById(data, QueryParameters.Top(top)), q, _la.SourceName, _clock.GetUtcNow());
    }

    public async Task<QueryResult<IReadOnlyList<TopRisk>>> RankedAssetsAsync(int max, CancellationToken ct)
    {
        var q = BuildRankedAssets(max);
        var rows = await _la.QueryAsync(q, ct).ConfigureAwait(false);
        var data = rows.Select(r => new TopRisk(
            Cell.Int(r, "Rank"), Cell.Str(r, "AssetName"), Cell.Str(r, "AssetId"), Cell.Str(r, "Tier"),
            Cell.Dbl(r, "WeightedRiskScore"), Cell.Int(r, "Findings"), Cell.List(r, "Domains"))).ToList();
        return new(MergeById(data, QueryParameters.Ranked(max)), q, _la.SourceName, _clock.GetUtcNow());
    }

    /// ONE ASSET, ONE ROW -- enforced again after the query. The KQL already aggregates on the canonical id;
    /// this guards the contract in code (and is what the offline tests can exercise): rows that share an asset id
    /// (case-insensitive) are one asset whatever they are called, rows without an id are keyed by name. Scores and
    /// findings add up, the most critical tier wins, domains union, and a real name beats an id-shaped one.
    internal static IReadOnlyList<TopRisk> MergeById(IReadOnlyList<TopRisk> rows, int top)
    {
        var merged = rows
            .GroupBy(r => string.IsNullOrWhiteSpace(r.AssetId) ? "name:" + r.AssetName.Trim().ToLowerInvariant() : "id:" + r.AssetId.Trim().ToLowerInvariant())
            .Select(g =>
            {
                var name = g.Select(r => r.AssetName).FirstOrDefault(n => !LooksLikeId(n)) ?? g.First().AssetName;
                var tier = g.Select(r => r.Tier).Where(t => int.TryParse(t, NumberStyles.Integer, CultureInfo.InvariantCulture, out _))
                            .OrderBy(t => int.Parse(t, CultureInfo.InvariantCulture)).FirstOrDefault() ?? g.First().Tier;
                var domains = g.SelectMany(r => r.Domains).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(d => d, StringComparer.Ordinal).ToList();
                return new TopRisk(0, name, g.First().AssetId, tier, g.Sum(r => r.WeightedRiskScore), g.Sum(r => r.Findings), domains);
            })
            .OrderBy(r => int.TryParse(r.Tier, NumberStyles.Integer, CultureInfo.InvariantCulture, out var t) ? t : 99)
            .ThenByDescending(r => r.WeightedRiskScore)
            .ThenBy(r => r.AssetName, StringComparer.Ordinal)
            .Take(top)
            .Select((r, i) => r with { Rank = i + 1 })
            .ToList();
        return merged;
    }

    /// Test-SIAssetNameIsId: a 32/40-hex node or device id, a GUID, or an ARM path is not a name.
    internal static bool LooksLikeId(string? name)
    {
        var n = (name ?? "").Trim();
        return n.Length == 0
            || System.Text.RegularExpressions.Regex.IsMatch(n, "^([0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12})$")
            || System.Text.RegularExpressions.Regex.IsMatch(n, "^(az:)?/subscriptions/", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
    }

    public async Task<QueryResult<AssetDetail?>> AssetLookupAsync(string nameOrId, CancellationToken ct)
    {
        var q = BuildAssetLookup(nameOrId);
        var rows = await _la.QueryAsync(q, ct).ConfigureAwait(false);
        var a = rows.FirstOrDefault(r => Cell.Str(r, "Kind") == "asset");
        AssetDetail? detail = null;
        var text = q;
        if (a is not null)
        {
            // #830: the asset's findings from the Detailed result in the database (never SI_RiskAnalysis_Detailed_CL)
            var related = Cell.List(a, "RelatedIds");
            var (sql, p) = BuildAssetFindings(Cell.Str(a, "AssetId"), related);
            var frows = await _sql.QueryAsync(sql, p, ct).ConfigureAwait(false);
            var findings = frows
                .Select(r => new FindingSummary(Cell.Str(r, "Report"), Cell.Str(r, "Title"), Cell.Str(r, "Severity"), Cell.Dbl(r, "RiskScore")))
                .OrderByDescending(f => f.RiskScore)
                .ToList();
            detail = new AssetDetail(Cell.Str(a, "AssetId"), Cell.Str(a, "AssetName"), Cell.Str(a, "Tier"), Cell.Str(a, "AssetType"),
                related, findings);
            text = q + "\n;\n" + DescribeSql(sql, p);
        }
        return new(detail, text, _la.SourceName, _clock.GetUtcNow());
    }

    // #830 (owner 2026-10-20): the trend from the database -- the day totals the data sync writes (sidata.FindingDaily /
    // AssetDaily and their counted twins, ProDataSql.Trend: the newest collection of each day, never past the published run),
    // never SI_Trend_CL (part of the optional report-row copy, off by default). The request's exempted scope picks the twins.
    private SI.Management.Core.ProData.ProDataQueries Pro => _pro ??= new SI.Management.Core.ProData.ProDataQueries(new SI.Management.Core.ProData.SqlReaderProSql(_sql), clock: _clock);
    private SI.Management.Core.ProData.ProDataQueries? _pro;

    public async Task<QueryResult<IReadOnlyList<TrendPoint>>> RiskTrendAsync(int days, CancellationToken ct)
    {
        var d = QueryParameters.Days(days);
        var all = await Pro.TrendAsync(new SI.Management.Core.ProData.TrendRequest { Days = d, Dimension = SI.Management.Core.ProData.TrendDimensions.None }, ct).ConfigureAwait(false);
        var tiers = await Pro.TrendAsync(new SI.Management.Core.ProData.TrendRequest { Days = d, Dimension = SI.Management.Core.ProData.TrendDimensions.Tier }, ct).ConfigureAwait(false);
        var tier0 = tiers.Data.Where(c => c.Dimension == "0").GroupBy(c => c.Day).ToDictionary(g => g.Key, g => g.Max(c => c.Assets ?? 0));
        var data = all.Data.GroupBy(c => c.Day).OrderBy(g => g.Key).Select(g =>
        {
            var findings = g.Sum(c => c.Findings); var score = g.Sum(c => c.ScoreTotal);
            return new TrendPoint(g.Key, findings > 0 ? score / findings : null, (int)findings, (int)g.Sum(c => c.TopSeverityFindings),
                (int)(tier0.TryGetValue(g.Key, out var t0) ? t0 : 0));
        }).ToList();
        return new(data, all.Query + "\n;\n" + tiers.Query, all.Source, _clock.GetUtcNow());
    }

    public async Task<QueryResult<IReadOnlyList<DomainTrendPoint>>> DomainTrendAsync(int days, CancellationToken ct)
    {
        var r = await Pro.TrendAsync(new SI.Management.Core.ProData.TrendRequest { Days = QueryParameters.Days(days), Dimension = SI.Management.Core.ProData.TrendDimensions.Domain }, ct).ConfigureAwait(false);
        var data = r.Data.Where(c => !string.IsNullOrEmpty(c.Dimension)).OrderBy(c => c.Day).ThenBy(c => c.Dimension, StringComparer.Ordinal)
            .Select(c => new DomainTrendPoint(c.Day, c.Dimension, c.ScoreAverage, (int)c.Findings)).ToList();
        return new(data, r.Query, r.Source, _clock.GetUtcNow());
    }

    public async Task<QueryResult<VulnerabilityState>> VulnerabilityStateAsync(int weeks, CancellationToken ct)
    {
        var w = QueryParameters.Weeks(weeks);
        var p = new Dictionary<string, object?>
        {
            ["source"] = _o.VulnerabilitySource,
            ["firstWeek"] = FirstWeekStart(w),
            ["weeks"] = w,
        };
        var rows = await _sql.QueryAsync(QueryTemplates.VulnerabilityState, p, ct).ConfigureAwait(false);
        var data = rows.Select(r => new VulnerabilityWeek(Cell.Day(r, "WeekStart"), Cell.Int(r, "NewCount"), Cell.Int(r, "FixedCount"),
            Cell.Int(r, "ReopenedCount"), Cell.Int(r, "OpenCount"))).ToList();
        var median = rows.Select(r => Cell.DblOrNull(r, "MedianDaysToFix")).FirstOrDefault(x => x is not null);
        return new(new VulnerabilityState(data, median is null ? null : Math.Round(median.Value, 2)),
            DescribeSql(QueryTemplates.VulnerabilityState, p), _sql.SourceName, _clock.GetUtcNow());
    }

    public async Task<QueryResult<IReadOnlyList<RunHealthRow>>> RunHealthAsync(int days, CancellationToken ct)
    {
        var q = BuildRunHealth(days);
        var rows = await _la.QueryAsync(q, ct).ConfigureAwait(false);
        var data = rows.Select(r => new RunHealthRow(Cell.Time(r, "CollectionTime") ?? default, Cell.Str(r, "Engine"), Cell.Str(r, "Phase"),
            Cell.DblOrNull(r, "DurationSec"), Cell.Str(r, "ExitReason"), Cell.Str(r, "RunId"), Cell.Time(r, "TimeGenerated"), Cell.Str(r, "PermissionGaps"))).ToList();
        return new(data, q, _la.SourceName, _clock.GetUtcNow());
    }
}
