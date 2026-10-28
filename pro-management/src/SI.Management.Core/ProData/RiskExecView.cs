using System.Globalization;
using System.Text.Json;

namespace SI.Management.Core.ProData;

/// <summary>
/// THE RISK ANALYSIS EXECUTIVE VIEW (#288) -- the Risk Analysis mail, in the web app.
///
/// Every Risk Analysis run keeps what its mail showed (engine/risk-analysis/_shared/RA-ExecView.ps1): the Risk Score
/// KPI and band, the domain x severity table, the per-domain scores, the AI-written analysis and the Top-50 risky
/// assets, one view per report grain (Summary, Detailed). The data sync carries both into sidata.RiskExecView. This file
/// reads them and decides which one a viewer sees -- it NEVER recomputes a figure, so the page and the mail of the same
/// run cannot disagree.
///
/// THE AGREEMENT MODE (SI_AISummary_Mode, 2.2's "two modes"): in Consistent mode both reports show the leading report's
/// figures (SI_AISummary_Leader), so both selections on the page show the leader's view, exactly as both mails do; in
/// PerReport each report shows its own grain, and so does the page. The engine writes the mode it ran with into every
/// view; an unset setting is PerReport in SecurityInsight Pro and Consistent in Community (RA-AISummaryMode.ps1).
/// </summary>
public static class RiskExecGrain
{
    public const string Summary = "Summary";
    public const string Detailed = "Detailed";
    public static readonly IReadOnlyList<string> All = [Summary, Detailed];

    /// A request's grain in canonical spelling ("summary" -> "Summary"), else null.
    public static string? Parse(string? value) =>
        value?.Trim() is { Length: > 0 } v ? All.FirstOrDefault(g => g.Equals(v, StringComparison.OrdinalIgnoreCase)) : null;

    /// What each grain counts -- the mail's own explanation, in two words.
    public static string Counts(string grain) => grain == Detailed ? "asset findings" : "distinct assets";

    /// The notice in PerReport mode (the SecurityInsight Pro default since 2026-10-05): each selection shows its own report.
    public const string PerReportNotice = "Each report shows its own figures: Summary counts distinct assets, Detailed counts individual findings.";
}

public sealed record ExecKpi(
    int GlobalScore, string Band,
    IReadOnlyDictionary<string, int> DomainScore,
    IReadOnlyDictionary<string, IReadOnlyDictionary<string, int>> SevByDomain,
    IReadOnlyDictionary<string, int> SevCount, int TotalRows, ExecProtection? Protection = null)
{
    /// The four domains in the mail's order, with the label the mail prints.
    public static readonly IReadOnlyList<(string Key, string Label)> Domains = [("Endpoint", "Endpoint"), ("Identity", "Identity"), ("Azure", "Azure"), ("PublicIP", "Public IP")];
    public static readonly IReadOnlyList<string> Severities = ["Critical", "High", "Medium", "Low"];

    /// The word a severity key is SHOWN as: the stored key "Critical" is the top severity step, which SecurityInsight calls
    /// "Very High" (owner 2026-10-15: only the risk rating says Critical).
    public static string SeverityLabel(string key) => key == "Critical" ? "Very High" : key;

    public int Score(string domain) => DomainScore.TryGetValue(domain, out var s) ? s : 100;
    public int Count(string domain, string column) => SevByDomain.TryGetValue(domain, out var d) && d.TryGetValue(column, out var n) ? n : 0;
    /// The Total row exactly as the mail builds it: SevCount per severity, TotalRows in the Total column.
    public int TotalCount(string column) => column == "Total" ? TotalRows : SevCount.TryGetValue(column, out var n) ? n : 0;

    /// The mail's bands: 90+ Very Good, 75+ Good, 50+ Moderate, below 50 At Risk.
    public static string BandOf(int score) => score >= 90 ? "Very Good" : score >= 75 ? "Good" : score >= 50 ? "Moderate" : "At Risk";
    /// A CSS-safe band token (very-good, good, moderate, at-risk).
    public static string BandToken(string band) => band.Trim().ToLowerInvariant().Replace(' ', '-') is var t && t is "very-good" or "good" or "moderate" or "at-risk" ? t : "unknown";
}

/// <summary>
/// #636 (owner 2026-10-19): the PROTECTION SCORE the run's mail showed -- it replaced the old 0-100 KPI (GlobalScore / Band /
/// DomainScore stay in the parsed view only for views kept before; no page shows them). Both views, the assets in good
/// standing, and how many counted findings had no date; per asset type (Devices, Identities, Cloud resources, Public IPs).
/// </summary>
public sealed record ExecProtection(double Lifecycle, double Technical, int LifecycleGood, int TechnicalGood, int Assets, int NoDate, int Findings,
    IReadOnlyList<ExecProtectionType> ByType);

public sealed record ExecProtectionType(string Type, double? Lifecycle, double? Technical, int Assets);

public sealed record ExecTopAsset(int Rank, string Asset, string? AssetId, string Tier, double WeightedRiskScore, double TotalRiskScore,
    int Findings, IReadOnlyList<string> Domains, IReadOnlyList<string> TopItems);

public sealed record ExecAffected(string Asset, double WeightedRiskScore);

public sealed record ExecTopFinding(int Rank, string ConfigurationId, string Name, string Category, string Subcategory, string Severity,
    string Domain, int AffectedAssetCount, double WeightedRiskScore, double TotalRiskScore, IReadOnlyList<ExecAffected> TopAffectedAssets);

/// One kept view: what one report's mail showed.
public sealed record ExecSnapshot(
    string Grain, string ReportTemplate, string Tenant, DateTimeOffset GeneratedAt, DateTimeOffset? CollectionTime, string SolutionVersion,
    string Mode, string Leader, int MaxAgeHours, bool SharesFigures,
    string FiguresFromGrain, string FiguresFromTemplate, DateTimeOffset FiguresGeneratedAt,
    ExecKpi? Kpi, bool AISummaryEnabled, string AISummaryText,
    IReadOnlyList<ExecTopAsset> TopAssets, IReadOnlyList<ExecTopFinding> TopFindings)
{
    /// PURE. The engine's view file -> the snapshot. Throws FormatException on something that is not a view.
    public static ExecSnapshot Parse(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var r = doc.RootElement;
        if (r.ValueKind != JsonValueKind.Object || Int(r, "SchemaVersion") != 1) throw new FormatException("not an executive view (SchemaVersion 1)");
        var grain = RiskExecGrain.Parse(Str(r, "Grain")) ?? throw new FormatException("unknown grain");
        var mode = Str(r, "Mode") is "PerReport" ? "PerReport" : "Consistent";
        var leader = RiskExecGrain.Parse(Str(r, "Leader")) ?? RiskExecGrain.Summary;
        var gen = When(r, "GeneratedAt") ?? throw new FormatException("no GeneratedAt");
        string fromGrain = grain, fromTpl = Str(r, "ReportTemplate"); var fromAt = gen;
        if (r.TryGetProperty("FiguresFrom", out var ff) && ff.ValueKind == JsonValueKind.Object)
        {
            fromGrain = RiskExecGrain.Parse(Str(ff, "Grain")) ?? grain;
            if (Str(ff, "ReportTemplate") is { Length: > 0 } t) fromTpl = t;
            fromAt = When(ff, "GeneratedAt") ?? gen;
        }
        ExecKpi? kpi = null;
        if (r.TryGetProperty("Kpi", out var k) && k.ValueKind == JsonValueKind.Object)
        {
            var sbd = new Dictionary<string, IReadOnlyDictionary<string, int>>(StringComparer.OrdinalIgnoreCase);
            if (k.TryGetProperty("SevByDomain", out var s) && s.ValueKind == JsonValueKind.Object)
                foreach (var p in s.EnumerateObject()) sbd[p.Name] = Counts(p.Value);
            kpi = new ExecKpi(Int(k, "GlobalScore"), Str(k, "Band") is { Length: > 0 } b ? b : ExecKpi.BandOf(Int(k, "GlobalScore")),
                Counts(k.TryGetProperty("DomainScore", out var ds) ? ds : default), sbd,
                Counts(k.TryGetProperty("SevCount", out var sc) ? sc : default), Int(k, "TotalRows"), Protection(k));
        }
        var assets = Arr(r, "TopAssets").Select(a => new ExecTopAsset(Int(a, "Rank"), Str(a, "Asset"), Str(a, "AssetId") is { Length: > 0 } id ? id : null,
            Str(a, "Tier"), Dbl(a, "WeightedRiskScore"), Dbl(a, "TotalRiskScore"), Int(a, "Findings"), Strs(a, "Domains"), Strs(a, "TopItems")))
            .OrderBy(a => a.Rank).ToList();
        var findings = Arr(r, "TopFindings").Select(f => new ExecTopFinding(Int(f, "Rank"), Str(f, "ConfigurationId"), Str(f, "Name"), Str(f, "Category"),
            Str(f, "Subcategory"), Str(f, "Severity"), Str(f, "Domain"), Int(f, "AffectedAssetCount"), Dbl(f, "WeightedRiskScore"), Dbl(f, "TotalRiskScore"),
            Arr(f, "TopAffectedAssets").Select(x => new ExecAffected(Str(x, "Asset"), Dbl(x, "WeightedRiskScore"))).ToList()))
            .OrderBy(f => f.Rank).ToList();
        return new ExecSnapshot(grain, Str(r, "ReportTemplate"), Str(r, "Tenant"), gen, When(r, "CollectionTime"), Str(r, "SolutionVersion"),
            mode, leader, Int(r, "MaxAgeHours") is > 0 and var h ? h : 24, Bool(r, "SharesFigures"),
            fromGrain, fromTpl, fromAt, kpi, Bool(r, "AISummaryEnabled"), Str(r, "AISummaryText"), assets, findings);
    }

    private static ExecProtection? Protection(JsonElement k)
    {
        if (!k.TryGetProperty("Protection", out var p) || p.ValueKind != JsonValueKind.Object || !p.TryGetProperty("Lifecycle", out var l) || l.ValueKind != JsonValueKind.Number) return null;
        var types = new List<ExecProtectionType>();
        if (p.TryGetProperty("ByType", out var bt) && bt.ValueKind == JsonValueKind.Object)
            foreach (var t in bt.EnumerateObject())
                types.Add(new ExecProtectionType(t.Name, t.Value.TryGetProperty("Lifecycle", out var tl) && tl.ValueKind == JsonValueKind.Number ? tl.GetDouble() : null,
                    t.Value.TryGetProperty("Technical", out var tt) && tt.ValueKind == JsonValueKind.Number ? tt.GetDouble() : null, Int(t.Value, "Assets")));
        string[] order = ["Devices", "Identities", "Cloud resources", "Public IPs"];
        return new ExecProtection(l.GetDouble(), Dbl(p, "Technical"), Int(p, "LifecycleGood"), Int(p, "TechnicalGood"), Int(p, "Assets"), Int(p, "NoDate"), Int(p, "Findings"),
            types.OrderBy(x => Array.IndexOf(order, x.Type) is var i && i >= 0 ? i : 99).ToList());
    }

    private static string Str(JsonElement e, string n) => e.ValueKind == JsonValueKind.Object && e.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";
    private static bool Bool(JsonElement e, string n) => e.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.True;
    private static double Dbl(JsonElement e, string n) => e.TryGetProperty(n, out var v) ? v.ValueKind switch
    {
        JsonValueKind.Number => v.GetDouble(),
        JsonValueKind.String when double.TryParse(v.GetString(), NumberStyles.Float, CultureInfo.InvariantCulture, out var d) => d,
        _ => 0,
    } : 0;
    private static int Int(JsonElement e, string n) => (int)Math.Round(Dbl(e, n));
    private static DateTimeOffset? When(JsonElement e, string n) =>
        Str(e, n) is { Length: > 0 } s && DateTimeOffset.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var d) ? d : null;
    private static IEnumerable<JsonElement> Arr(JsonElement e, string n) =>
        e.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.Array ? v.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.Object).ToList() : [];
    private static IReadOnlyList<string> Strs(JsonElement e, string n) =>
        e.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.Array ? v.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString() ?? "").Where(x => x.Length > 0).ToList()
        : e.TryGetProperty(n, out var one) && one.ValueKind == JsonValueKind.String && one.GetString() is { Length: > 0 } s ? [s] : [];
    private static IReadOnlyDictionary<string, int> Counts(JsonElement e)
    {
        var d = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        if (e.ValueKind == JsonValueKind.Object) foreach (var p in e.EnumerateObject()) d[p.Name] = p.Value.ValueKind == JsonValueKind.Number ? (int)Math.Round(p.Value.GetDouble()) : 0;
        return d;
    }
}

/// What the page shows for one selection: the header of the selected report and the figures it carries.
public sealed record ExecPresentation(
    string Grain, string Mode, string Leader,
    // The selected report's own view (its header: report name, tenant, time). Null = that report has kept no view yet.
    ExecSnapshot? Own,
    // The figures shown: the leader's view in Consistent mode (as in the mails), else the report's own. Null = empty state.
    ExecSnapshot? Figures,
    // True when the figures are the leading report's because the agreement mode says so.
    bool FromLeader,
    // A plain sentence when what is shown differs from the simple case (a report without a view, the AI summary off).
    string? Note,
    // #636: false = the Risk Analysis Summary step is off -- the page offers the Detailed report only (RiskExecSelector.Choices).
    bool SummaryOn = true)
{
    /// The other grain's figures would be identical (Consistent, shared): the page says so.
    public bool BothIdentical => FromLeader;
}

public static class RiskExecSelector
{
    /// PURE. Which view the page shows for a grain, honouring the agreement mode the engine ran with (the NEWEST view's
    /// mode and leader -- what the most recent mail did).
    public static ExecPresentation Select(IReadOnlyList<ExecSnapshot> views, string grain)
    {
        grain = RiskExecGrain.Parse(grain) ?? RiskExecGrain.Detailed;
        var byGrain = views.GroupBy(v => v.Grain).ToDictionary(g => g.Key, g => g.OrderByDescending(v => v.GeneratedAt).First());
        var newest = views.OrderByDescending(v => v.GeneratedAt).FirstOrDefault();
        var mode = newest?.Mode ?? "Consistent";
        var leader = newest?.Leader ?? RiskExecGrain.Summary;
        byGrain.TryGetValue(grain, out var own);
        if (newest is null) return new(grain, mode, leader, null, null, false, null);
        if (mode == "Consistent")
        {
            if (!newest.SharesFigures)
                return new(grain, mode, leader, own, own, false, own is null ? null
                    : "The AI summary is off, so each report shows its own figures even though the reports are set to agree -- as the mails do.");
            if (byGrain.TryGetValue(leader, out var lead))
                return new(grain, mode, leader, own, lead, true, own is null && grain != leader
                    ? $"The {grain} report has not kept a view yet; its mail would carry these figures from the {leader} report." : null);
            return new(grain, mode, leader, own, own, false, own is null ? null
                : $"The leading report ({leader}) has not kept a view yet, so this is the {grain} report's own figures.");
        }
        return new(grain, mode, leader, own, own, false, null);
    }

    /// The grain a viewer sees when nothing is chosen (the cookie / ?grain= win): the leading report's in Consistent mode,
    /// else Detailed (owner 2026-10-19: "detailed must be the detailed view on wallboard + executive view").
    public static string DefaultGrain(IReadOnlyList<ExecSnapshot> views) =>
        views.OrderByDescending(v => v.GeneratedAt).FirstOrDefault() is { Mode: "Consistent" } n ? n.Leader : RiskExecGrain.Detailed;

    /// #636: the same with the Summary step OFF (Jobs/SummaryStep.cs) -- always Detailed: a kept Summary view, a Summary leader
    /// or a remembered Summary choice are ignored (the Summary report no longer runs; its last view would go stale).
    public static string DefaultGrain(IReadOnlyList<ExecSnapshot> views, bool summaryOn) => summaryOn ? DefaultGrain(views) : RiskExecGrain.Detailed;

    /// #636: Select with the Summary step OFF -- the Detailed report's own view and figures, whatever the agreement mode or the
    /// leader said (a Summary leader no longer runs, so nothing is carried from it), and no Summary selection. On: as Select.
    public static ExecPresentation Select(IReadOnlyList<ExecSnapshot> views, string grain, bool summaryOn)
    {
        if (summaryOn) return Select(views, grain);
        var own = views.Where(v => v.Grain == RiskExecGrain.Detailed).OrderByDescending(v => v.GeneratedAt).FirstOrDefault();
        return new(RiskExecGrain.Detailed, own?.Mode ?? "Consistent", RiskExecGrain.Detailed, own, own, false, null, SummaryOn: false);
    }

    /// #636: the report grains a viewer may choose -- without Summary while the Summary step is off.
    public static IReadOnlyList<string> Choices(bool summaryOn) => summaryOn ? RiskExecGrain.All : [RiskExecGrain.Detailed];
}

/// The read side: the kept views and the asset keys of the Top-50 assets.
public interface IRiskExecViews
{
    /// Every kept view (at most one per grain). Ready = false when the database does not carry the table yet.
    Task<QueryResult<RiskExecViewsResult>> ViewsAsync(CancellationToken ct);
    /// The CI key (sidata.Asset.AssetKey) for each engine asset id: the id itself when it is a CI key, else the CI that
    /// carries it as an identifier. Ids with no CI are left out.
    Task<IReadOnlyDictionary<string, string>> AssetKeysAsync(IEnumerable<string> assetIds, CancellationToken ct);
    /// #290: the findings of the given CIs in the published run's Detailed collection -- counted per domain / category /
    /// severity, and each CI's highest-risk findings (the drilldown). A reader without the statement answers with none.
    Task<QueryResult<ExecAssetFindings>> AssetFindingsAsync(IReadOnlyList<string> assetKeys, int topPerAsset, CancellationToken ct) =>
        Task.FromResult(new QueryResult<ExecAssetFindings>(new ExecAssetFindings([], []), "", "", DateTimeOffset.UtcNow));
    /// #863: the riskiest ACTIVE CIs from the database (<see cref="RiskExecSql.TopActiveCis"/>) -- what the Top 50 risky assets
    /// page shows when the run kept no list (a view written while Risk Analysis built the list only with the AI summary on).
    /// AssetId = the CI id (sidata.Ci.CiId). A reader without the statement answers with none.
    Task<QueryResult<IReadOnlyList<ExecTopAsset>>> TopActiveAssetsAsync(int top, CancellationToken ct) =>
        Task.FromResult(new QueryResult<IReadOnlyList<ExecTopAsset>>(Array.Empty<ExecTopAsset>(), "", "", DateTimeOffset.UtcNow));
}

/// #290: one CI's findings counted by domain, category and severity.
public sealed record ExecFindingGroup(string AssetKey, string Domain, string Category, string Severity, long Findings);
/// #290: one of a CI's highest-risk findings, with what opens it.
public sealed record ExecAssetFinding(string AssetKey, string CollectionId, string FindingId, string Title, string Issue, string Severity, double RiskScore, string Domain);
public sealed record ExecAssetFindings(IReadOnlyList<ExecFindingGroup> Groups, IReadOnlyList<ExecAssetFinding> Top);

public sealed record RiskExecViewsResult(bool Ready, IReadOnlyList<ExecSnapshot> Views, IReadOnlyList<string> Problems);

public static partial class RiskExecSql
{
    /// Whether the views are there, and (Published) whether the database has the published run's copies (the update adds them).
    public const string Ready = "SELECT CASE WHEN OBJECT_ID('sidata.RiskExecView') IS NOT NULL THEN 1 ELSE 0 END AS Ready, CASE WHEN OBJECT_ID('sidata.vPublishedExecView') IS NOT NULL THEN 1 ELSE 0 END AS Published";
    /// ONE TRUSTED RUN (owner 2026-10-19: the risk score panel showed an older run's mail view while the wall board showed
    /// another run): the executive views OF THE PUBLISHED RUN, as it wrote them -- never a newer run's, never an older one's.
    public const string Views = "SELECT Grain, GeneratedAt, PayloadJson FROM sidata.vPublishedExecView ORDER BY Grain";
    /// The same on a database the update has not given the published run yet: the views as each run last wrote them.
    public const string ViewsBeforePublished = "SELECT Grain, GeneratedAt, PayloadJson FROM sidata.RiskExecView ORDER BY Grain";
    /// Whether the database carries the findings' prepared category (sidata.Finding.Category) and the mark that says a
    /// collection's context is prepared (the schema update adds both).
    public const string HasFindingCategory =
        "SELECT CASE WHEN COL_LENGTH(N'sidata.Finding', N'Category') IS NOT NULL AND COL_LENGTH(N'sidata.Collection', N'ContextAt') IS NOT NULL THEN 1 ELSE 0 END AS Ready";

    /// <summary>
    /// #290: the drilldown's counts, in the published run's Detailed collection -- the category from its PREPARED column
    /// (sidata.Finding.Category, filled by the data sync), never worked out of each finding's row. Prepared = 0 on a row
    /// means the collection's context is not prepared yet: the caller then reads <see cref="AssetGroups"/> instead (the
    /// category would otherwise read as the report name). The findings of the 10 assets, by asset key (IX_Finding_Asset).
    /// </summary>
    public const string AssetGroupsStored = """
SELECT f.AssetKey, COALESCE(f.SecurityDomain, N'') AS Domain,
       COALESCE(NULLIF(f.Category, N''), f.ReportName, N'') AS Category,
       COALESCE(f.Severity, N'') AS Severity, COUNT_BIG(*) AS Findings,
       MIN(CASE WHEN k.ContextAt IS NULL THEN 0 ELSE 1 END) AS Prepared
FROM sidata.Finding AS f
JOIN sidata.vPublishedCollection AS l ON l.CollectionId = f.CollectionId AND l.Kind = N'Detailed'
JOIN sidata.Collection AS k ON k.CollectionId = f.CollectionId
WHERE f.AssetKey IN (SELECT k2.[value] FROM OPENJSON(@Keys) AS k2)
GROUP BY f.AssetKey, COALESCE(f.SecurityDomain, N''), COALESCE(NULLIF(f.Category, N''), f.ReportName, N''), COALESCE(f.Severity, N'')
""";

    /// #290: the same counts with the category read from each finding's row -- THE FALLBACK for a database without the
    /// prepared column, or a newest collection the data sync has not prepared yet.
    public const string AssetGroups = """
SELECT f.AssetKey, COALESCE(f.SecurityDomain, N'') AS Domain,
       COALESCE(NULLIF(JSON_VALUE(f.DetailJson, '$.Category'), N''), f.ReportName, N'') AS Category,
       COALESCE(f.Severity, N'') AS Severity, COUNT_BIG(*) AS Findings
FROM sidata.Finding AS f
JOIN sidata.vPublishedCollection AS l ON l.CollectionId = f.CollectionId AND l.Kind = N'Detailed'
WHERE f.AssetKey IN (SELECT k.[value] FROM OPENJSON(@Keys) AS k)
GROUP BY f.AssetKey, COALESCE(f.SecurityDomain, N''), COALESCE(NULLIF(JSON_VALUE(f.DetailJson, '$.Category'), N''), f.ReportName, N''), COALESCE(f.Severity, N'')
""";

    /// #290: each CI's highest-risk findings, in the published run's Detailed collection.
    public const string AssetTop = """
SELECT x.AssetKey, x.CollectionId, x.FindingId, x.Title, x.Issue, x.Severity, x.RiskScore, x.Domain
FROM (
    SELECT f.AssetKey, CONVERT(nvarchar(64), f.CollectionId) AS CollectionId, CONVERT(nvarchar(64), f.FindingId) AS FindingId,
           COALESCE(f.Title, N'') AS Title, COALESCE(f.Cve, f.ConfigurationId, N'') AS Issue, COALESCE(f.Severity, N'') AS Severity,
           COALESCE(f.RiskScore, 0) AS RiskScore, COALESCE(f.SecurityDomain, N'') AS Domain,
           ROW_NUMBER() OVER (PARTITION BY f.AssetKey ORDER BY f.RiskScore DESC, f.FindingId) AS rn
    FROM sidata.Finding AS f
    JOIN sidata.vPublishedCollection AS l ON l.CollectionId = f.CollectionId AND l.Kind = N'Detailed'
    WHERE f.AssetKey IN (SELECT k.[value] FROM OPENJSON(@Keys) AS k)
) AS x
WHERE x.rn <= @Top
ORDER BY x.AssetKey, x.rn
""";

    public const string AssetKeys = """
SELECT x.value AS Id, COALESCE(a.AssetKey, i.AssetKey) AS AssetKey
FROM STRING_SPLIT(@Ids, N'|') AS x
OUTER APPLY (SELECT TOP (1) s.AssetKey FROM sidata.Asset AS s WHERE s.AssetKey = x.value) AS a
OUTER APPLY (SELECT TOP (1) ai.AssetKey FROM sidata.AssetIdentifier AS ai WHERE ai.IdentifierValue = x.value ORDER BY ai.LastSeen DESC) AS i
WHERE x.value <> N''
""";
}

public sealed class SqlRiskExecViews(IProSql sql, TimeProvider? clock = null) : IRiskExecViews
{
    private readonly TimeProvider _clock = clock ?? TimeProvider.System;

    public async Task<QueryResult<RiskExecViewsResult>> ViewsAsync(CancellationToken ct)
    {
        SqlGuard.AssertReadOnly(RiskExecSql.Ready);
        var ready = await sql.QueryAsync(new SqlQuery(RiskExecSql.Ready, new Dictionary<string, object?>()), ct).ConfigureAwait(false);
        if (ready.Count == 0 || Convert.ToInt32(ready[0].TryGetValue("Ready", out var v) ? v ?? 0 : 0, CultureInfo.InvariantCulture) != 1)
            return new(new RiskExecViewsResult(false, [], []), RiskExecSql.Ready, sql.SourceName, _clock.GetUtcNow());
        var text = Convert.ToInt32(ready[0].TryGetValue("Published", out var pv) ? pv ?? 0 : 0, CultureInfo.InvariantCulture) == 1 ? RiskExecSql.Views : RiskExecSql.ViewsBeforePublished;
        SqlGuard.AssertReadOnly(text);
        var rows = await sql.QueryAsync(new SqlQuery(text, new Dictionary<string, object?>()), ct).ConfigureAwait(false);
        var views = new List<ExecSnapshot>(); var problems = new List<string>();
        foreach (var r in rows)
        {
            var grain = ProDataQueries.S(r, "Grain");
            try { views.Add(ExecSnapshot.Parse(ProDataQueries.S(r, "PayloadJson"))); }
            catch (Exception ex) when (ex is FormatException or JsonException) { problems.Add($"The {grain} view could not be read ({ex.Message})."); }
        }
        return new(new RiskExecViewsResult(true, views, problems), text, sql.SourceName, _clock.GetUtcNow());
    }

    public async Task<QueryResult<ExecAssetFindings>> AssetFindingsAsync(IReadOnlyList<string> assetKeys, int topPerAsset, CancellationToken ct)
    {
        var keys = JsonSerializer.Serialize(assetKeys.Where(k => !string.IsNullOrWhiteSpace(k)).Distinct().ToList());
        SqlGuard.AssertReadOnly(RiskExecSql.AssetGroups); SqlGuard.AssertReadOnly(RiskExecSql.AssetGroupsStored); SqlGuard.AssertReadOnly(RiskExecSql.AssetTop);
        // the category from its prepared column; from the finding rows only where the column is not there or not filled yet
        IReadOnlyList<IReadOnlyDictionary<string, object?>>? g = null;
        var groupsText = RiskExecSql.AssetGroups;
        if (await HasFindingCategoryAsync(ct).ConfigureAwait(false))
        {
            var stored = await sql.QueryAsync(new SqlQuery(RiskExecSql.AssetGroupsStored, new Dictionary<string, object?> { ["Keys"] = keys }), ct).ConfigureAwait(false);
            if (stored.All(r => ProDataQueries.L(r, "Prepared") == 1)) { g = stored; groupsText = RiskExecSql.AssetGroupsStored; }
        }
        g ??= await sql.QueryAsync(new SqlQuery(RiskExecSql.AssetGroups, new Dictionary<string, object?> { ["Keys"] = keys }), ct).ConfigureAwait(false);
        var t = await sql.QueryAsync(new SqlQuery(RiskExecSql.AssetTop, new Dictionary<string, object?> { ["Keys"] = keys, ["Top"] = Math.Clamp(topPerAsset, 1, 20) }), ct).ConfigureAwait(false);
        var groups = g.Select(r => new ExecFindingGroup(ProDataQueries.S(r, "AssetKey"), ProDataQueries.S(r, "Domain"), ProDataQueries.S(r, "Category"),
            ProDataQueries.S(r, "Severity"), ProDataQueries.L(r, "Findings"))).ToList();
        var top = t.Select(r => new ExecAssetFinding(ProDataQueries.S(r, "AssetKey"), ProDataQueries.S(r, "CollectionId"), ProDataQueries.S(r, "FindingId"),
            ProDataQueries.S(r, "Title"), ProDataQueries.S(r, "Issue"), ProDataQueries.S(r, "Severity"), ProDataQueries.D(r, "RiskScore"), ProDataQueries.S(r, "Domain"))).ToList();
        return new(new ExecAssetFindings(groups, top), groupsText + "\n" + RiskExecSql.AssetTop, sql.SourceName, _clock.GetUtcNow());
    }

    // once the database has the column it keeps it (the schema only adds): asked until the answer is yes
    private volatile bool _hasCategory;

    private async Task<bool> HasFindingCategoryAsync(CancellationToken ct)
    {
        if (_hasCategory) return true;
        SqlGuard.AssertReadOnly(RiskExecSql.HasFindingCategory);
        var rows = await sql.QueryAsync(new SqlQuery(RiskExecSql.HasFindingCategory, new Dictionary<string, object?>()), ct).ConfigureAwait(false);
        var ready = rows.Count > 0 && rows[0].TryGetValue("Ready", out var v) && v is not null && Convert.ToInt64(v, CultureInfo.InvariantCulture) == 1;
        if (ready) _hasCategory = true;
        return ready;
    }

    public async Task<QueryResult<IReadOnlyList<ExecTopAsset>>> TopActiveAssetsAsync(int top, CancellationToken ct)
    {
        SqlGuard.AssertReadOnly(RiskExecSql.TopActiveCis);
        var rows = await sql.QueryAsync(new SqlQuery(RiskExecSql.TopActiveCis, new Dictionary<string, object?> { ["Top"] = Math.Clamp(top, 1, 200) }), ct).ConfigureAwait(false);
        return new(RiskExecSql.ToTopAssets(rows), RiskExecSql.TopActiveCis, sql.SourceName, _clock.GetUtcNow());
    }

    public async Task<IReadOnlyDictionary<string, string>> AssetKeysAsync(IEnumerable<string> assetIds, CancellationToken ct)
    {
        var ids = assetIds.Where(i => !string.IsNullOrWhiteSpace(i) && !i.Contains('|')).Select(i => i.Trim().ToLowerInvariant()).Distinct().ToList();
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (ids.Count == 0) return map;
        SqlGuard.AssertReadOnly(RiskExecSql.AssetKeys);
        var rows = await sql.QueryAsync(new SqlQuery(RiskExecSql.AssetKeys, new Dictionary<string, object?> { ["Ids"] = string.Join("|", ids) }), ct).ConfigureAwait(false);
        foreach (var r in rows)
            if (ProDataQueries.SN(r, "AssetKey") is { } key) map[ProDataQueries.S(r, "Id")] = key;
        return map;
    }
}

/// #863: the Top list from the database (kept apart from the finding statements above: the lifecycle guard reads a window
/// around each statement, and this one's lifecycle filter must not count for them).
public static partial class RiskExecSql
{
    /// <summary>
    /// #863 (owner 2026-10-21: "Top 50 risky assets ... is empty" at an install with the AI summary off): the riskiest ACTIVE
    /// CIs (the CI lifecycle, #855: sidata.Ci.Lifecycle 'active') with risk on them, in the mail's order -- Criticality Tier
    /// first (Tier 0 highest, no tier last), then Weighted Risk Score, highest first. Read only when the kept view has no list.
    /// </summary>
    public const string TopActiveCis = """
SELECT TOP (@Top) c.CiId, COALESCE(NULLIF(c.Name, N''), c.CiId) AS Name, c.Tier, COALESCE(c.WeightedRiskScore, 0) AS WeightedRiskScore,
       COALESCE(c.RiskScore, 0) AS RiskScore, COALESCE(c.OpenFindings, 0) AS OpenFindings
FROM sidata.Ci AS c
WHERE c.Lifecycle = N'active' AND (COALESCE(c.OpenFindings, 0) > 0 OR COALESCE(c.WeightedRiskScore, 0) > 0)
ORDER BY CASE WHEN c.Tier BETWEEN 0 AND 3 THEN c.Tier ELSE 99 END, COALESCE(c.WeightedRiskScore, 0) DESC, c.CiId
""";

    /// PURE. The rows of <see cref="TopActiveCis"/> -> the Top list's shape (rank in the statement's order; the tier as the
    /// CI list says it: "Tier 0".."Tier 3", else "Unclassified").
    public static IReadOnlyList<ExecTopAsset> ToTopAssets(IReadOnlyList<IReadOnlyDictionary<string, object?>> rows) =>
        rows.Select((r, i) => new ExecTopAsset(i + 1, ProDataQueries.S(r, "Name") is { Length: > 0 } n ? n : ProDataQueries.S(r, "CiId"),
            ProDataQueries.SN(r, "CiId"), TierText(r.TryGetValue("Tier", out var t) ? t : null), ProDataQueries.D(r, "WeightedRiskScore"),
            ProDataQueries.D(r, "RiskScore"), (int)Math.Min(int.MaxValue, ProDataQueries.L(r, "OpenFindings")), [], [])).ToList();

    public static string TierText(object? tier) =>
        tier is null or DBNull ? "Unclassified"
        : int.TryParse(Convert.ToString(tier, CultureInfo.InvariantCulture), NumberStyles.Integer, CultureInfo.InvariantCulture, out var n) && n is >= 0 and <= 3 ? "Tier " + n.ToString(CultureInfo.InvariantCulture)
        : "Unclassified";
}
