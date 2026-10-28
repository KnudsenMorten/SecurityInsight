namespace SI.Management.Web.Columns;

/// What a page of the menu is to the column mechanism (#589).
public enum DataViewStatus
{
    /// A data view: the chooser (own + every extra column its rows carry), the all-rows exports with the chosen columns,
    /// the selected-row exports where it selects, and Export all columns.
    DataView,
    /// A page that keeps fixed columns, for the reason given (configuration, a dashboard, operations, a redirect).
    Fixed,
    /// A data view whose redesign is decided and follows on top of this mechanism (it is not retrofitted now).
    RedesignFollows,
}

/// One page and what it is; <see cref="Url"/> = a URL that renders it with data in the test app (a detail page needs its key).
public sealed record DataViewEntry(string Page, DataViewStatus Status, string Reason, string? Url = null);

/// <summary>
/// THE list of the pages of the menu (and the detail pages that list data) and what each is to the column mechanism
/// (owner 2026-10-11: "al views must support to add all available columns"; configuration pages keep fixed columns, each
/// with its reason). A guard test holds it to the menu: every page of <see cref="SI.Management.Web.Navigation.NavModel"/>
/// is here, and every data view renders the chooser, the all-rows exports ("all rows" in their words) and Export all columns.
/// </summary>
public static class DataViews
{
    private static DataViewEntry D(string page, string what, string? url = null) => new(page, DataViewStatus.DataView, what, url);
    private static DataViewEntry F(string page, string why) => new(page, DataViewStatus.Fixed, why);

    public const string Configuration = "configuration: the page edits settings, rules or templates -- its columns are the setting's own (owner 2026-10-11: configuration pages keep fixed columns)";
    public const string Dashboard = "a dashboard: tiles and charts over aggregates, no row list to choose columns of; its drill-downs are data views";
    public const string Operations = "operations: the product's own jobs, runs, guards and audit trail -- not asset, finding or CMDB data";

    /// Whether a page of the menu ("/Findings/Index" or "/Findings") is a data view (its menu link opens it with the
    /// person's remembered sort / filters, <see cref="ViewState.MenuHref"/>).
    public static bool IsDataView(string? page)
    {
        static string Plain(string p) => (p.EndsWith("/Index", StringComparison.OrdinalIgnoreCase) ? p[..^"/Index".Length] : p).TrimEnd('/');
        if (string.IsNullOrWhiteSpace(page)) return false;
        var asked = Plain(page.Trim());
        return All.Any(e => e.Status == DataViewStatus.DataView && Plain(e.Page).Equals(asked, StringComparison.OrdinalIgnoreCase));
    }

    public static readonly IReadOnlyList<DataViewEntry> All =
    [
        // ---- the collection views: THE shared grid (Pages/Collection/_Grid.cshtml, CollectionPageModel) ----
        D("/Collection/Rows", "the collection's findings"),
        D("/Collection/Assets", "the CIs at risk"),
        D("/Collection/RiskScore", "risk per CI"),
        D("/Collection/WeightedRisk", "weighted risk per CI / service"),
        D("/Collection/RiskRating", "findings by rating"),
        D("/Collection/Mitre", "findings by MITRE ATT&CK"),
        D("/Collection/Compliance", "findings by compliance tag"),
        D("/Collection/Cvss", "findings by CVSS"),
        D("/Collection/Vulnerabilities", "one row per CVE"),
        D("/Collection/TopFindings", "the mail's top critical findings"),
        D("/Collection/Correlation", "correlation quality per CI"),
        D("/Collection/Services", "the CMDB services and their assets"),
        D("/Collection/Changes", "what changed between two collections"),
        D("/Collection/Lifecycle", "the close-loop's events per collection"),
        D("/Collection/Exclusions", "exemptions at the collection"),
        D("/Collection/Connectors", "connector runs and items"),
        // #636: Security recommendations > Summary and the Remediations pages -- the same shared grid
        D("/Recommendations/Summary", "one row per security recommendation with its affected assets"),
        D("/Remediations/Index", "one row per fix"),
        D("/Remediations/TopFixes", "the 10 fixes with the most reach"),
        D("/Remediations/TopAssets", "the 10 most important assets and their fixes"),
        D("/Collection/Asset", "one CI's findings (a detail page)", "/Collection/Asset?key=ci-dc1"),
        D("/Departments/Detail", "a department's findings (a detail page)", "/Departments/Detail?id=1"),
        D("/Departments/Unassigned", "findings of no department"),
        // ---- the CI data model: the CI grid, the CI data grids, the records ----
        D("/Cis/Index", "every CI"),
        D("/Cis/Findings", "findings per CI"),
        D("/Cis/Summary", "findings per finding key"),
        D("/Records/Index", "records per source"),
        // ---- the page tables (THE data table, Pages/Shared/_DataTable.cshtml) ----
        D("/Findings/Index", "the findings browser"),
        D("/Summary/Index", "the Risk Analysis Summary rows"),
        D("/Cmdb/Index", "the CMDB services"),
        D("/Cmdb/NotSeen", "assets no longer seen"),
        D("/Cmdb/Service", "one service's assets and CIs (a detail page)", "/Cmdb/Service?id=1"),
        D("/Exemptions/Index", "exemptions and requests"),
        D("/Tasks/Index", "my tasks"),
        D("/Tasks/Delegated", "delegated tasks"),
        D("/Admin/Tasks", "all tasks"),
        D("/Management/TopAssets", "the run's top risky assets"),
        D("/Management/Drilldown", "the top 10 assets"),
        D("/Management/Tier0", "every tier-0 asset with findings"),
        D("/Management/RiskAnalysis", "the run's summary with its top assets"),
        D("/AssetTagging/Index", "the tag rules (listed by the owner among the data views)"),
        D("/Admin/DataQuality", "the data-quality warnings of a run, every key number it measured with its trend, and the history of runs -- lists a person exports and reorders"),
        // ---- the tier board (owner 2026-10-11): tier tiles with toggle chips on top, THE CI grid below (the tiles set its
        // tier / decided-by / class filters) and a row drawer (the grid's row-click hook) ----
        D("/Tiers/Index", "every CI by tier: the CI grid under the tier tiles"),
        // ---- fixed columns, each with its reason ----
        F("/Index", "the landing page: a redirect to each role's start page"),
        F("/Wallboard", "the wall board: tiles for a screen, no table"),
        F("/Chat", "the assistant: questions and answers, no table"),
        F("/Help", "help and glossary text"),
        F("/Docs/Index", "the documentation pages of this version: text, no data table"),   // #679
        F("/Management/Index", Dashboard),
        F("/Management/Overview", Dashboard),   // #636: the topics -- small tables over the stored key figures; every number opens a data view
        F("/Management/Report", "the executive report: the key figures blocks top to bottom, to read and print (#636)"),
        F("/Management/Domains", Dashboard),
        F("/Management/Summary", "the management summary mail: its sections and the send settings"),
        F("/Management/Trends", Dashboard),
        F("/Management/Closure", Dashboard),
        F("/Departments/Index", "the departments overview: counts per department; each department's findings are the data view Departments > Detail"),
        F("/Cis/NotOnboarded", "a triage page: the active devices not onboarded in Defender counted per status, and a fixed list of the chosen status to act on; the columns and the all-rows exports are the CI list's -- each status with an onboarding state opens there (Cis/Index, filtered by onboarding status); an Azure machine without the agent has no state the CI list filters on"),
        F("/Admin/Settings/Assumptions", "the assumptions behind the numbers: each rule and the value in force, with a link to where it is set -- settings text, not a list of data"),
        F("/Cis/Overrides","the manual override editor (set / change / remove one CI value) -- a change surface, not a list of data"),
        F("/Cmdb/Map", "the service map: drag-and-drop lanes that link assets to services -- an editor"),
        F("/Changes/Index", "review & commit: the staged changes with their before / after, not a table"),
        F("/Admin/Jobs", Operations), F("/Admin/RunHealth", Operations), F("/Admin/QuerySplitting", Operations), F("/Admin/Guards", Operations), F("/Admin/Verification", Operations), F("/Admin/DataHealth", Operations), F("/Admin/Performance", Operations),
        F("/Admin/Connectors", Operations), F("/Admin/CloseLoop", Operations), F("/Admin/Resend", Operations),
        F("/Admin/History", Operations), F("/Admin/Commits", Operations), F("/Admin/Deviations", Operations),
        F("/Admin/GetStarted", Configuration), F("/Admin/Settings/Index", Configuration), F("/Admin/Settings/RiskRating", Configuration), F("/Admin/Settings/Lifecycle", Configuration), F("/Admin/Settings/Email", Configuration),
        F("/Admin/Settings/Notifications", Configuration), F("/Admin/Settings/Reports", Configuration), F("/Admin/Settings/ExportImport", Configuration),
        F("/Admin/Backups", Configuration), F("/Admin/EnvironmentReport", Configuration), F("/Reports/Index", Configuration), F("/Connectors/Fields", Configuration), F("/Connectors/Scope", Configuration), F("/RiskIndex/Index", Configuration),
        F("/RiskFactors/Index", Configuration), F("/RiskFactors/Classification", Configuration), F("/RiskFactors/BreakGlass", Configuration),
        F("/Rules/Index", Configuration), F("/RulePacks/Index", Configuration), F("/SchemaOverlay/Index", Configuration), F("/Admin/Access", Configuration),
        F("/SchemaOverlay/NewContext", "what each source offers that was not there before: one row per source PROPERTY (not an asset, a finding or a CMDB item) with the two decisions an Admin takes on it -- its columns are the decision's own"),
        F("/Admin/Departments/Index", Configuration), F("/Admin/Departments/Rules", Configuration), F("/Admin/Departments/Flows", Configuration),
        F("/Admin/DomainRoles", Configuration), F("/Admin/ConnectorSetup/Index", Configuration), F("/Templates/Index", Configuration), F("/Templates/Releases", Configuration),
    ];

    public static DataViewEntry? Of(string page) => All.FirstOrDefault(e => string.Equals(e.Page, page, StringComparison.OrdinalIgnoreCase));
}
