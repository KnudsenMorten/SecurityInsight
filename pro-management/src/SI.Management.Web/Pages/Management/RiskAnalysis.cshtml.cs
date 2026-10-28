using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Core;
using SI.Management.Core.ProData;

namespace SI.Management.Web.Pages.Management;

/// <summary>
/// Overview > Risk Analysis (executive) (#288): the Risk Analysis mail management reads, in the web app -- the Risk
/// Score KPI and band, the domain x severity table, the per-domain scores, the AI-written analysis and the Top-50 risky
/// assets, from the view each run kept of its own mail (sidata.RiskExecView). Summary or Detailed: chosen here,
/// remembered in this browser, and deep-linkable (?grain=summary|detailed). The agreement mode decides what each
/// selection shows (<see cref="RiskExecSelector"/>): in Consistent mode both show the leading report's figures, as both
/// mails do; in PerReport each shows its own.
/// </summary>
/// #636: while the Risk Analysis Summary step is off (Jobs/SummaryStep.cs) the page shows the Detailed report only -- a Summary
/// choice (asked or remembered), a kept Summary view and a Summary leader are ignored, and nothing is remembered.
public sealed class RiskAnalysisModel(IRiskExecViews views, SI.Management.Web.Changes.RiskFactorStore factors, ILogger<RiskAnalysisModel> log,
    SI.Management.Web.Jobs.ISummaryStep? summaryStep = null) : SI.Management.Web.Columns.DataViewPageModel
{
    /// The browser's remembered choice (a display preference, like the number format: no setting, no audit).
    public const string Cookie = "si-exec-grain";

    [BindProperty(SupportsGet = true)] public string? Grain { get; set; }

    public ExecPresentation? View { get; private set; }
    public bool Ready { get; private set; } = true;
    public string? Error { get; private set; }
    public IReadOnlyList<string> Problems { get; private set; } = [];
    public QueryResult<RiskExecViewsResult>? Query { get; private set; }
    /// Engine asset id -> CI key, for the Top-50 links.
    public IReadOnlyDictionary<string, string> AssetKeys { get; private set; } = new Dictionary<string, string>();
    public IReadOnlyList<ExecSnapshot> All { get; private set; } = [];
    /// The "Risk factors" appendix: short name, description, asset / vulnerability, impact (empty when the catalog cannot be read).
    public IReadOnlyList<SI.Management.Web.Changes.RiskFactorLegend.Row> Legend { get; private set; } = [];

    public async Task OnGetAsync(CancellationToken ct)
    {
        var asked = RiskExecGrain.Parse(Grain);
        try
        {
            Query = await views.ViewsAsync(ct);
            Ready = Query.Data.Ready; Problems = Query.Data.Problems; All = Query.Data.Views;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            log.LogWarning(ex, "risk analysis executive view");
            Error = "The executive view could not be read from the Pro database right now. The reason is in the application log.";
            All = [];
        }
        // the "Risk factors" appendix of the printed report: the same rows Risk Analysis writes as <name>.riskfactors.json,
        // built from the factor catalog in force (the web app does not read the engine's output folder)
        try { if (await factors.ListAsync(ct) is { } rows) Legend = SI.Management.Web.Changes.RiskFactorLegend.FromFactors(SI.Management.Web.Changes.RiskFactorStore.Factors(rows)); }
        catch (Exception ex) when (ex is not OperationCanceledException) { log.LogWarning(ex, "risk factor legend"); }
        var summaryOn = summaryStep is null || await summaryStep.IsOnAsync(ct);
        var grain = summaryOn ? asked ?? RiskExecGrain.Parse(Request.Cookies[Cookie]) ?? RiskExecSelector.DefaultGrain(All) : RiskExecGrain.Detailed;
        if (asked is not null && summaryOn) Remember(asked);
        Grain = grain;
        View = RiskExecSelector.Select(All, grain, summaryOn);
        if (View.Figures is { } f && f.TopAssets.Any(a => a.AssetId is not null))
        {
            try { AssetKeys = await views.AssetKeysAsync(f.TopAssets.Where(a => a.AssetId is not null).Select(a => a.AssetId!), ct); }
            catch (Exception ex) when (ex is not OperationCanceledException) { log.LogWarning(ex, "executive view asset keys"); }
        }
    }

    // #589: the run's top risky assets as THE data table (the CI of each with its context, the chooser, the exports)
    protected override Task LoadForExportAsync(CancellationToken ct) => OnGetAsync(ct);

    protected override IReadOnlyList<SI.Management.Web.Columns.DataTable> BuildTables() =>
        View?.Figures is { } f
            ? new[] { ExecTables.TopAssets(f.TopAssets, AssetKeys, AssetLink, "topassets", "management-riskanalysis-topassets", "Top risky assets") }
            : Array.Empty<SI.Management.Web.Columns.DataTable>();

    private void Remember(string grain) =>
        Response.Cookies.Append(Cookie, grain, new CookieOptions
        {
            HttpOnly = true, Secure = Request.IsHttps, SameSite = SameSiteMode.Lax, IsEssential = true, MaxAge = TimeSpan.FromDays(365), Path = "/",
        });

    /// The link for one Top-50 asset: its CI page when the Pro database knows the CI, else a search by its name.
    public string AssetLink(ExecTopAsset a) =>
        a.AssetId is { } id && AssetKeys.TryGetValue(id.ToLowerInvariant(), out var key)
            ? "/Collection/Asset?key=" + Uri.EscapeDataString(key)
            : "/Collection/Assets?q=" + Uri.EscapeDataString(a.Asset);

    /// "3 h ago", "2 days ago": how old the shown figures are.
    public static string Age(DateTimeOffset when, DateTimeOffset now)
    {
        var d = now - when;
        if (d.TotalMinutes < 1) return "just now";
        if (d.TotalHours < 1) return $"{(int)d.TotalMinutes} min ago";
        if (d.TotalHours < 48) return $"{(int)d.TotalHours} h ago";
        return $"{(int)d.TotalDays} days ago";
    }
}
