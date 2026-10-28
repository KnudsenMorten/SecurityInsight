using Microsoft.AspNetCore.Http;
using SI.Management.Core;
using SI.Management.Core.ProData;

namespace SI.Management.Web.RiskExec;

/// <summary>
/// The kept Risk Analysis views (#288) as a page reads them: the grain the viewer asked for (?grain=, else the remembered
/// choice, else the leading report), remembered in the browser, and what the agreement mode says that grain shows. One
/// place, so the executive view and the three mail-section pages (#290) always pick the same figures.
/// </summary>
/// #636: while the Risk Analysis Summary step is off (Jobs/SummaryStep.cs) a Summary choice -- asked, remembered or the leader's --
/// is ignored and never remembered: every page shows the Detailed report, and the selector offers no Summary.
public sealed class ExecViewLoader(IRiskExecViews views, ILogger<ExecViewLoader> log, SI.Management.Web.Jobs.ISummaryStep? summaryStep = null)
{
    /// The browser's remembered choice (a display preference: no setting, no audit).
    public const string Cookie = "si-exec-grain";

    /// SummaryOn (#636): false = the Summary step is off -- the page offers only the Detailed report.
    public sealed record Loaded(ExecPresentation View, bool Ready, string? Error, IReadOnlyList<string> Problems, IReadOnlyList<ExecSnapshot> All,
        QueryResult<RiskExecViewsResult>? Query, bool SummaryOn = true);

    public IRiskExecViews Views => views;

    /// #636: is the Summary step on? (no step service = as before: on)
    public async Task<bool> SummaryOnAsync(CancellationToken ct) => summaryStep is null || await summaryStep.IsOnAsync(ct);

    public async Task<Loaded> LoadAsync(HttpContext http, string? askedGrain, CancellationToken ct)
    {
        var summaryOn = await SummaryOnAsync(ct);
        if (!summaryOn) return await LoadDetailedAsync(ct);
        var asked = RiskExecGrain.Parse(askedGrain);
        QueryResult<RiskExecViewsResult>? q = null; string? error = null;
        IReadOnlyList<ExecSnapshot> all = []; IReadOnlyList<string> problems = []; var ready = true;
        try { q = await views.ViewsAsync(ct); ready = q.Data.Ready; all = q.Data.Views; problems = q.Data.Problems; }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            log.LogWarning(ex, "risk analysis views");
            error = "The Risk Analysis view could not be read from the Pro database right now. The reason is in the application log.";
        }
        var grain = asked ?? RiskExecGrain.Parse(http.Request.Cookies[Cookie]) ?? RiskExecSelector.DefaultGrain(all);
        if (asked is not null)
            http.Response.Cookies.Append(Cookie, asked, new CookieOptions
            {
                HttpOnly = true, Secure = http.Request.IsHttps, SameSite = SameSiteMode.Lax, IsEssential = true, MaxAge = TimeSpan.FromDays(365), Path = "/",
            });
        return new Loaded(RiskExecSelector.Select(all, grain), ready, error, problems, all, q);
    }

    /// #636: the Summary step is off -- the Detailed report's own view, whatever was asked or remembered (nothing is remembered).
    private async Task<Loaded> LoadDetailedAsync(CancellationToken ct)
    {
        QueryResult<RiskExecViewsResult>? q = null; string? error = null;
        IReadOnlyList<ExecSnapshot> all = []; IReadOnlyList<string> problems = []; var ready = true;
        try { q = await views.ViewsAsync(ct); ready = q.Data.Ready; all = q.Data.Views; problems = q.Data.Problems; }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            log.LogWarning(ex, "risk analysis views");
            error = "The Risk Analysis view could not be read from the Pro database right now. The reason is in the application log.";
        }
        return new Loaded(RiskExecSelector.Select(all, RiskExecGrain.Detailed, summaryOn: false), ready, error, problems, all, q, SummaryOn: false);
    }

    /// Engine asset id -> CI key for the given assets (empty on failure: the links fall back to a search).
    public async Task<IReadOnlyDictionary<string, string>> AssetKeysAsync(IEnumerable<ExecTopAsset> assets, CancellationToken ct)
    {
        var ids = assets.Where(a => a.AssetId is not null).Select(a => a.AssetId!).ToList();
        if (ids.Count == 0) return new Dictionary<string, string>();
        try { return await views.AssetKeysAsync(ids, ct); }
        catch (Exception ex) when (ex is not OperationCanceledException) { log.LogWarning(ex, "risk analysis asset keys"); return new Dictionary<string, string>(); }
    }

    /// <summary>
    /// #863: the Top list a page shows. The run's own list when the kept view has one (the mail's); else -- a view written
    /// while Risk Analysis built the list only with the AI summary on -- the riskiest ACTIVE CIs from the database in the
    /// mail's order (<see cref="RiskExecSql.TopActiveCis"/>), said on the page (<see cref="AiSummaryNote"/>). Never "Top 0" as
    /// if the run had no risk. Keys: the CI of each asset (the database list: its own CI id).
    /// </summary>
    public sealed record TopList(IReadOnlyList<ExecTopAsset> Assets, bool FromDatabase, string? Note, IReadOnlyDictionary<string, string> Keys, QueryResult<IReadOnlyList<ExecTopAsset>>? Query);

    public async Task<TopList> TopAssetsAsync(ExecSnapshot f, int top, CancellationToken ct)
    {
        if (f.TopAssets.Count > 0)
        {
            var own = f.TopAssets.Take(top).ToList();
            return new TopList(own, false, null, await AssetKeysAsync(own, ct), null);
        }
        try
        {
            var q = await views.TopActiveAssetsAsync(top, ct);
            var list = q.Data.Take(top).ToList();
            var keys = list.Where(a => a.AssetId is not null).GroupBy(a => a.AssetId!.ToLowerInvariant()).ToDictionary(g => g.Key, g => g.First().AssetId!, StringComparer.OrdinalIgnoreCase);
            return new TopList(list, true, list.Count > 0 ? AiSummaryNote.TopAssetsFromDatabase : AiSummaryNote.TopAssetsNone, keys, q);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            log.LogWarning(ex, "risk analysis top assets from the database");
            return new TopList([], true, AiSummaryNote.TopAssetsNone, new Dictionary<string, string>(), null);
        }
    }

    /// The CI page of a CI from the database list (its CI id).
    public static string CiLink(ExecTopAsset a) =>
        a.AssetId is { } id ? "/Cis/Detail?id=" + Uri.EscapeDataString(id) : "/Cis?q=" + Uri.EscapeDataString(a.Asset);

    /// The CI page of an asset, else a search by its name.
    public static string AssetLink(ExecTopAsset a, IReadOnlyDictionary<string, string> keys) =>
        a.AssetId is { } id && keys.TryGetValue(id.ToLowerInvariant(), out var key)
            ? "/Collection/Asset?key=" + Uri.EscapeDataString(key)
            : "/Collection/Assets?q=" + Uri.EscapeDataString(a.Asset);
}
