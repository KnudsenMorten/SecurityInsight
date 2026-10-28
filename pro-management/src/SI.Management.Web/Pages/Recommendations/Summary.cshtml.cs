using Microsoft.AspNetCore.Mvc;
using SI.Management.Core.ProData;
using SI.Management.Web.Navigation;
using SI.Management.Web.Pages.Collection;
using SI.Management.Web.Summary;

namespace SI.Management.Web.Pages.Recommendations;

/// <summary>
/// Security recommendations > Summary (#636, owner 2026-10-13, approved; DECISIONS 2026-10-19 "summary could be build as
/// views with the detailed data instead"): THE ONE GROUPED VIEW of the Detailed findings -- the stored groupings the data
/// sync writes per collection (sidata.SummaryGroup / its counted twin, RecommendationSql.Grouped; one definition and one
/// engine function for Pro and Community), of the collection the page shows (the published run unless a person chose
/// one). The default is one row per security recommendation with the assets it affects; ?by= (or a named view) chooses
/// another grouping: per asset, tier, domain, domain > category (> subcategory), risk rating, department, severity, report.
/// The former /Summary grouped page opens here (Navigation/RetiredPages.cs). The named view "Vulnerabilities (CVE)" is one
/// row per CVE (the per-CVE rows of the vulnerabilities builder). A grouping not written for the collection says what is true
/// (#842, SummaryBuildStatus): being prepared only while the data sync runs, else that it comes with the run going, the data
/// sync waiting in the queue or the next data sync -- with links to the views that ARE written; a state that could not be
/// read is an error with its reason. Never computed at page load, never a second Risk Analysis.
/// </summary>
[SI.Management.Web.Exemptions.ExemptedSurface(SI.Management.Web.Exemptions.ExemptedSurface.Views)]
public sealed class SummaryModel(ICollectionViews views, ILogger<SummaryModel> log) : CollectionPageModel(views, log)
{
    [BindProperty(SupportsGet = true)] public string? View { get; set; }
    /// The grouping (RecommendationSql.Groupings id; empty = the view's, else per recommendation).
    [BindProperty(SupportsGet = true)] public string? By { get; set; }

    public override string PagePath => NamedViews.SummaryPage;
    public override string Heading => "Summary";
    /// #855: the grouped rows (sidata.SummaryGroup) and the per-CVE rows (sidata.CveSummary) are built over active CIs only --
    /// said on the page, no lifecycle choice.
    protected override string LifecycleWords(SI.Management.Core.ProData.CiLifecycleRules? rules) =>
        SI.Management.Core.ProData.LifecycleFilter.ActiveOnlyWords(rules ?? SI.Management.Core.ProData.CiLifecycleDefinitions.Defaults);
    public override string Lede => "The Detailed findings of the collection grouped, as the Summary report showed them: one row per security recommendation and tier -- the same vulnerability once for each tier it is on -- with its domain, category, the most severe severity and risk rating, the affected assets (how many, and their names), the risk score, a known exploit, first and last seen and the remediation; the most critical tier and the most risk first. Choose another grouping (per recommendation over every tier, asset, tier, Domain > Category > Subcategory, risk rating, department, severity, report); open a row for its findings in Detailed.";
    public override bool CompactFrame => true;
    public override string ExportName => "summary";

    public NamedView? CurrentView => NamedViews.Find(PagePath, View);
    public bool CveView => CurrentView?.Id == "cve";
    /// The grouping in use (the request's ?by=, else the named view's, else per recommendation).
    public RecommendationSql.SummaryGroupingDef Grouping => RecommendationSql.GroupingOf(!string.IsNullOrWhiteSpace(By) ? By : CurrentView?.Grouping);
    /// #842: the grouping is not written for the collection (null = it is, or the state could not be read): what the data sync
    /// is doing about it (the page's words, SummaryBuildStatus.Text).
    public DataSyncActivity? NotBuilt { get; private set; }
    /// The views that ARE written for the collection while the asked one is not (their names and links).
    public IReadOnlyList<(string Label, string Href)> BuiltViews { get; private set; } = [];
    /// #842: whether the grouping is written could not be read -- an error on the page, never "being prepared".
    public bool StateReadFailed { get; private set; }

    public override IEnumerable<(string Key, string Value)> ExtraState()
    {
        if (CurrentView is { } v) yield return ("view", v.Id);
        if (!CveView && !string.IsNullOrWhiteSpace(By) && Grouping.Id != RecommendationSql.DefaultGrouping) yield return ("by", Grouping.Id);
    }

    private IReadOnlyList<string> _hidden = [];
    public override ViewPicker? Picker => new(PagePath, Current?.CollectionId, NamedViews.Visible(PagePath, _hidden), CurrentView);

    protected override async Task<GridPlan?> PrepareAsync(bool forExport, CancellationToken ct)
    {
        if (!forExport) { await LoadFacetsAsync(ct); _hidden = await RowsModel.HiddenViewsAsync(HttpContext, ct); }
        // one row per CVE: the per-CVE rows of the collection (Security recommendations > Summary > Vulnerabilities (CVE))
        if (CveView)
            return new GridPlan(CollectionViewSql.Vulnerabilities, new Dictionary<string, object?> { ["CollectionId"] = Current!.CollectionId }, Current.Version + "|live",
                new Dictionary<string, IReadOnlyList<string>> { ["Severity"] = Options(Facets.Severity), ["Tier"] = TierValues, ["HasExploit"] = Flags }, CurrentView!.Sort, CurrentView.Desc);
        // #842: the page states what is true -- written, being written now, coming with a run that is going or waiting, coming
        // with the next data sync (and which views ARE here), or: the state could not be read (never "being prepared")
        var rec = HttpContext?.RequestServices.GetService(typeof(IRecommendationViews)) as IRecommendationViews;
        RecommendationState state;
        try
        {
            if (rec is null) throw new InvalidOperationException("the Pro database's views are not configured for this web app");
            var s = await rec.StateAsync(Current!.CollectionId, ct, Grouping.Id); state = s.Data; Queries.Add(QueryInfo.From(s, "What is built for this collection"));
        }
        catch (Exception ex) when (ex is not ArgumentException && !(ex is OperationCanceledException && ct.IsCancellationRequested))
        {
            Log.LogWarning(ex, "summary groupings state");
            StateReadFailed = true;
            Error = ReadFailedText + " " + ex.Message;
            return null;
        }
        if (!state.HasSummaryGroups)
        {
            NotBuilt = DataSyncActivity.Idle;
            Notice = Notice is null ? NoTablesText : NoTablesText + " " + Notice;
            return null;
        }
        if (!state.SummaryGroupsReady)
        {
            var sync = HttpContext?.RequestServices.GetService(typeof(SI.Management.Web.Jobs.IFlowStore)) is SI.Management.Web.Jobs.IFlowStore flows
                ? await SummaryBuildStatus.ReadAsync(flows, DateTimeOffset.UtcNow, ct)
                : new DataSyncState(DataSyncActivity.Unknown, null, "the pipeline's run record is not configured for this web app");
            NotBuilt = sync.Activity;
            BuiltViews = (state.BuiltGroupings ?? []).Where(id => !string.Equals(id, Grouping.Id, StringComparison.OrdinalIgnoreCase))
                .Select(id => NamedViews.Visible(PagePath, _hidden).FirstOrDefault(v => string.Equals(v.Grouping, id, StringComparison.OrdinalIgnoreCase)) is { } v
                    ? (v.Label, v.Href(PagePath, Current!.CollectionId))
                    : (RecommendationSql.GroupingOf(id).Label, ViewLink(PagePath, ("by", id))))
                .ToList();
            var why = SummaryBuildStatus.Text(sync, BuiltViews.Count > 0);
            Notice = Notice is null ? why : why + " " + Notice;   // the reason this view is missing first, any note about the collection after it
            return null;
        }
        var values = new Dictionary<string, IReadOnlyList<string>> { ["Tier"] = TierValues, ["HasExploit"] = Flags };
        if (Grouping.Id == "tier") values["K1"] = TierValues;
        if (Grouping.Id == RecommendationSql.ReportGrouping)
        {
            values["K2"] = TierValues;
            values["Severity"] = RecommendationSql.SeverityWords;
            values["RiskRating"] = RecommendationSql.RatingWords;
            values["Domain"] = Options(Facets.Domain);
        }
        return new GridPlan(RecommendationSql.Grouped(Grouping.Id), new Dictionary<string, object?> { ["CollectionId"] = Current!.CollectionId }, Current.Version + "|sum|" + Grouping.Id,
            values, CurrentView?.Sort, CurrentView?.Desc);
    }

    public const string ReadFailedText = "Whether the summary of this collection is built could not be read from the Pro database, so this view is not shown. Every finding is in Detailed. The reason:";
    public const string NoTablesText = "The Pro database does not have the grouped Summary tables yet -- the next update adds them, then the next data sync fills them. Until then every finding is in Detailed.";

    /// A grouped row opens its findings in Detailed, filtered by the row's keys.
    public override string? CellLink(string column, IReadOnlyDictionary<string, object?> row)
    {
        if (CveView) return column == "Cve" && Cell(row, "Cve") is { } cve ? ViewLink(NamedViews.DetailedPage, ("f.Cve", cve)) : null;
        if (column is not ("K1" or "K2" or "K3" or "Title" or "Findings" or "Assets" or "AssetNames")) return null;
        string? K(int i) => Cell(row, "K" + i.ToString(System.Globalization.CultureInfo.InvariantCulture));
        var k1 = K(1);
        (string Key, string? Value)[]? f = Grouping.Id switch
        {
            // the Summary report's row: that recommendation on the assets of that tier
            RecommendationSql.ReportGrouping when k1 is not null => [(k1.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase) ? "f.Cve" : "f.ConfigurationId", k1), ("f.Tier", K(2) == "Unclassified" ? null : K(2))],
            "recommendation" when k1 is not null => [(k1.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase) ? "f.Cve" : "f.ConfigurationId", k1)],
            "asset" when Cell(row, "Title") is { } n => [("f.AssetName", n)],
            "tier" when k1 is not null => [("f.Tier", k1)],
            "domain" when k1 is not null => [("f.SecurityDomain", k1)],
            "domain-category" when k1 is not null => [("f.SecurityDomain", k1), ("f.Category", K(2))],
            "domain-category-subcategory" when k1 is not null => [("f.SecurityDomain", k1), ("f.Category", K(2)), ("f.Subcategory", K(3))],
            "risk-rating" when k1 is not null => [("f.RiskRating", k1)],
            "severity" when k1 is not null => [("f.Severity", k1)],
            "report" when k1 is not null => [("f.ReportName", k1)],
            _ => null,
        };
        return f is null ? null : ViewLink(NamedViews.DetailedPage, f.Where(x => !string.IsNullOrEmpty(x.Value)).ToArray());
    }

    /// #589: a CVE row's title names its software.
    protected override IReadOnlyList<string> AlwaysFilled => CveView ? new[] { DataColumnKeys.Software } : Array.Empty<string>();
}
