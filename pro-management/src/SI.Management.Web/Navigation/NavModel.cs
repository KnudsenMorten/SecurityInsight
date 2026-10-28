using System.Security.Claims;
using SI.Management.Web.Auth;

namespace SI.Management.Web.Navigation;

/// One menu item: the top-level group it sits in, the Razor page it opens, the label the menu shows, and who sees it
/// ("reader", "admin", "superadmin", "change", "wallboard", "department", "readeronly"). An item that brings several pages
/// together has <see cref="Tabs"/>: the item opens the first tab, and every page of it shows the tab strip (the layout
/// renders it from here).
/// <see cref="Stage"/>: the heading the item sits under inside its menu group (owner 2026-10-19: "structure into menu groups
/// ... follow the namings used in pipeline" -- Configuration is grouped by the pipeline's stages, Collect -> Correlate ->
/// Deliver, plus Platform). <see cref="Lede"/>: the one line an area with tabs says about itself, under its tabs.
public sealed record NavItem(string Section, string Page, string Label, string Need, IReadOnlyList<NavTab>? Tabs = null, string? Stage = null, string? Lede = null)
{
    /// "Configuration > Departments (setup)" -- the path a person follows in the menu.
    public string Path => Section + NavModel.Separator + Label;

    /// The URL of the page: the Razor page name without a trailing /Index.
    public string Href => NavModel.HrefOf(Page);
}

/// One tab of a menu item that brings several pages together: its own page (its own URL, so an old link still opens
/// it, now under the item's tab strip), the tab's label, and who sees that tab.
/// <see cref="Query"/> ("view=explain"): a tab that is a VIEW of its page -- the same Razor page opened with this address
/// parameter (#910: Risk scores > Explained is the risk score page's per-finding view). The tab is the current one when the
/// address carries it; the page's plain tab is current when no such tab's parameter is in the address.
public sealed record NavTab(string Page, string Label, string Need = "reader", string? Query = null)
{
    public string Href => NavModel.HrefOf(Page) + (Query is { Length: > 0 } q ? "?" + q : "");
}

/// What the signed-in person may see; the layout fills it from the role and the department lookup it already does.
public readonly record struct NavAccess(bool IsReader, bool IsAdmin, bool IsSuperAdmin, bool MayChange, bool IsWallboard, bool IsDepartmentMember)
{
    public bool Shown(string need) => need switch
    {
        "admin" => IsAdmin,
        "superadmin" => IsSuperAdmin,
        "change" => MayChange,
        "wallboard" => IsReader || IsWallboard,
        // #415: Home ("/") -- every signed-in role with a start page: it lands on the wall board, or on its departments
        "home" => IsReader || IsWallboard || IsDepartmentMember,
        "department" => IsReader || IsDepartmentMember,
        "readeronly" => IsReader && !IsAdmin,
        _ => IsReader,
    };

    /// From the principal alone (no department lookup: a department-scoped sign-in counts as a department member).
    public static NavAccess Of(ClaimsPrincipal user) => new(user.IsReader(), user.IsAdmin(), user.IsSuperAdmin(), user.MayChange(),
        user.IsInRole(Roles.Wallboard), user.IsDepartmentScoped());
}

/// THE MENU of the Pro web app -- the one source of truth. The layout renders it, and every text that names a place in
/// the menu ("Configuration > Departments (setup)") renders it from here (the &lt;nav-ref&gt; tag helper in a page,
/// <see cref="PathOf"/> in a message), so a text can never name a menu path that no longer exists.
public static class NavModel
{
    public const string Separator = " > ";

    /// #415 (operator 2026-10-06: "make a home button in the menu also"): Home, the FIRST entry of the menu, a direct link
    /// (no drop-down) with a home icon. It opens "/" -- the landing page, which sends each role to its start: the wall
    /// board for every role that may see it, else the role's own start page (Pages/Index.cshtml.cs). Not one of
    /// <see cref="Items"/>: "/" is a redirect, not a page of its own, and the wall board already has its menu item.
    public static readonly NavItem Home = new("Home", "/Index", "Home", "home");

    /// Get Started (operator 2026-10-07, "similar to how i have made it in ELDK ... it should show the incompleted steps"):
    /// the second entry, right after Home, a direct link for Admins. It carries a red ! while a required step is open --
    /// asked shortly after a page loads (wwwroot/js/getstarted-badge.js), gone by itself when the step is done. Not one of
    /// <see cref="Items"/>: it guides through the pages of the menu, it is not a page of a group.
    public static readonly NavItem GetStarted = new("Get Started", "/Admin/GetStarted", "Get Started", "admin");

    /// Only pages that stand on their own: a DETAIL page (one CI, one finding, one department, one task) is reached by
    /// clicking it somewhere, never from the menu (operator 2026-10-05: the empty "Asset (CI)" page was "not relevant").
    /// Main categories (operator 2026-10-04; #636 2026-10-13: Risks retired, Remediations added): Overview, Assets &amp; services,
    /// Security recommendations, Remediations, Changes &amp; trends, Operations, Configuration -- and Help, last (operator 2026-10-05). Each page in exactly one place:
    /// a menu item, or one tab of one item; its role rule unchanged. The order here is the order of the menu.
    /// Pages that showed the same data under different names are ONE item with tabs (operator 2026-10-05: "i feel there is
    /// overlaps ... it must be easy to understand and communicate").
    public static readonly IReadOnlyList<NavItem> Items = new NavItem[]
    {
        // #636 (owner 2026-10-19: "one could be report and other could be click to see the stats with buttons of most
        // interesting topics so they can click around"): Executive overview to EXPLORE (topics, the Overview landing page)
        // and Executive report to READ (the key figures top to bottom, its PDF and the management mail) -- both from the same
        // stored figures. The risk-score tab is "Risk trend" (owner: "naming here is wrong"); today's Executive reports
        // (Risk Analysis view, Management summary) are tabs of the Executive report.
        Group("Overview", "Executive overview", "reader",
            new("/Management/Overview", "Topics"), new("/Management/Index", "Risk trend"), new("/Management/Domains", "Domains"), new("/Management/Tier0", "Tier-0 exposure")),
        Group("Overview", "Executive report", "reader",
            new("/Management/Report", "Key figures"), new("/Management/RiskAnalysis", "Risk Analysis"), new("/Management/Summary", "Management summary")),
        // one source for "the riskiest assets": the last Risk Analysis run, as the mail ranks them (the live "Riskiest
        // assets now" page answered the same question from another source; it redirects to Top 50 risky assets). The Top 50
        // critical findings are Security recommendations > Summary now (#636; the old address opens it).
        Group("Overview", "Top risks", "reader",
            new("/Management/TopAssets", "Top 50 risky assets"), new("/Management/Drilldown", "Top 10 asset drilldown")),
        new("Overview", "/Wallboard", "Wall board", "wallboard"),
        new("Overview", "/Chat", "Ask about your estate", "reader"),
        // owner 2026-10-11 ("why do we have these 2 - what is the difference"): ONE item for the CIs -- At risk (the CIs with
        // findings in a Risk Analysis collection, most risk first), All CIs (every CI the correlation built, the column
        // chooser), the findings on the CIs and what each source reported. Owner 2026-10-19 ("i thought the menu item showed
        // all cis - confused"): the item opens on ALL CIs; "At risk" says it is the CIs with findings; both tabs carry their
        // count (Navigation/TabCounts.cs)
        Group("Assets & services", "Assets (CIs)", "reader",
            new("/Cis/Index", "Active CIs"), new("/Collection/Assets", "At risk (with findings)"), new("/Cis/Findings", "Findings per CI"),
            // one row per finding key x tier x severity x CMDB group, with actions on its findings (#583 moved it here from Risks)
            new("/Cis/Summary", "Findings per finding key"),
            new("/Records/Index", "Records per source"),
            // #858 active devices Defender only discovered (can be onboarded / unsupported / insufficient info) and Azure
            // machines without the agent -- real, unprotected devices, counted while active
            new("/Cis/NotOnboarded", "Not onboarded in Defender"),
            // #462 the values an Admin set by hand on a CI (who, why, until)
            new("/Cis/Overrides", "Manual overrides")),
        new("Assets & services", "/Collection/Correlation", "Correlation quality", "reader"),
        new("Assets & services", "/Tiers/Index", "Tier board", "reader"),
        // #636: moved in from the retired Risks menu -- one row per asset, and one row per service (the weighted score)
        // named "Risk scores" (owner 2026-10-19: risk score and weighted risk score are the per-finding priority numbers, no limit,
        // higher = more risk; the 0-100 management number is the Protection score, never called "Risk score")
        Group("Assets & services", "Risk scores", "reader",
            new("/Collection/RiskScore", "Per asset"), new("/Collection/WeightedRisk", "Weighted, per service"),
            // #910 (owner 2026-10-27): each finding's score, explained -- a view of the risk score page
            new("/Collection/RiskScore", "Explained", Query: "view=explain")),
        Group("Assets & services", "CMDB", "reader",
            new("/Cmdb/Index", "CMDB"), new("/Collection/Services", "Services"), new("/Cmdb/Map", "Service map"),
            // #406: assets SecurityInsight no longer sees, in their grace period (an Admin may retire one early)
            new("/Cmdb/NotSeen", "Not seen anymore")),
        // #636 (owner 2026-10-13, approved): the menu "Risks" is gone -- risk is a dimension to filter and sort by, not a
        // place. Security recommendations: Summary (one row per recommendation with its affected assets), Detailed (one
        // recommendation on one asset) and Exemptions; Risk rating, MITRE, Compliance, CVSS, Vulnerabilities and Top 50
        // critical findings are named views of Summary / Detailed (Navigation/NamedViews.cs), their old addresses open them
        // (Navigation/RetiredPages.cs).
        new("Security recommendations", "/Recommendations/Summary", "Summary", "reader"),
        new("Security recommendations", "/Collection/Rows", "Detailed", "reader"),
        Group("Security recommendations", "Exemptions", "reader",
            new("/Exemptions/Index", "Exemptions"), new("/Collection/Exclusions", "Excluded / exempted")),
        // #636: one remediation = the same fix applied to many assets (built by the data sync). Reporting only today; the place
        // where actions (buttons, agents) come later.
        new("Remediations", "/Remediations/TopAssets", "Top 10 assets to fix", "reader"),
        new("Remediations", "/Remediations/TopFixes", "Top 10 fixes by reach", "reader"),
        new("Remediations", "/Remediations/Index", "All remediations", "reader"),
        new("Changes & trends", "/Management/Trends", "Trends", "reader"),
        new("Changes & trends", "/Collection/Changes", "What changed", "reader"),
        Group("Changes & trends", "Vulnerabilities over time", "reader",
            new("/Management/Closure", "Opened and closed"), new("/Collection/Lifecycle", "Per collection")),
        Group("Operations", "Tasks", "department",
            new("/Tasks/Index", "My tasks", "department"), new("/Tasks/Delegated", "Delegated tasks", "department"), new("/Admin/Tasks", "All tasks", "admin")),
        Group("Operations", "Departments", "department",
            new("/Departments/Index", "Departments", "department"), new("/Departments/Unassigned", "Unassigned")),
        new("Operations", "/Changes/Index", "Review & commit", "change"),
        Group("Operations", "Jobs", "admin",
            new("/Admin/Jobs", "Jobs", "admin"), new("/Admin/RunHealth", "Run health", "admin")),
        // #640: the Risk Analysis bucket counts per report, the jump flag and a one-time reset (readers see it; a reset is Admin)
        new("Operations", "/Admin/QuerySplitting", "Risk Analysis query splitting", "reader"),
        new("Operations", "/Admin/Guards", "Guards (safety checks)", "reader"),
        // V3-DATA-MODEL 2.11: the data-collection gaps the verification job found (readers see them; an Admin decides)
        new("Operations", "/Admin/Verification", "Verification (data gaps)", "reader"),
        // #757 (owner 2026-10-18: "add performance and stats in si gui so customer can see it. new page"): run times, collection
        // state, the databases' and the web app's load and size with a recommendation, the jobs' sizes and data health
        new("Operations", "/Admin/Performance", "Performance", "reader"),
        // #577: each run's key numbers against the median of the last 3 runs -- warnings only, never a block
        new("Operations", "/Admin/DataQuality", "Data quality", "reader"),
        // the connectors' state for an Admin; their runs moved to Configuration > Connectors > Runs (owner 2026-10-19)
        Group("Operations", "Connector state", "admin",
            new("/Admin/Connectors", "Status", "admin"), new("/Admin/CloseLoop", "Close-loop state", "admin"), new("/Admin/Resend", "Resend and undo", "admin")),
        new("Operations", "/Admin/History", "Audit trail", "change"),
        // #404 (CONFIG-1.2): the commit history from the change journal, and undo
        new("Operations", "/Admin/Commits", "Commits (undo)", "admin"),
        new("Operations", "/Admin/Deviations", "Deviations", "admin"),
        // owner 2026-10-19 ("can we structure into menu groups like Connectors, Data Enrichment, or let it follow the namings
        // used in pipeline"): Configuration under the pipeline's own stage titles (JobFlow.StageTitle, the same words the Jobs
        // page shows a step under), then Platform for the install itself.
        // Collect (data-in): what SecurityInsight reads -- the profile tables' columns and raw data, and what sources newly offer
        new NavItem("Configuration", "/SchemaOverlay/Index", "Schema overlays", "reader", Stage: Collect),
        // continuous discovery: what each source offers that was not there before; an Admin adds it to a default layout or maps it
        new NavItem("Configuration", "/SchemaOverlay/NewContext", "New context available", "reader", Stage: Collect),
        // Correlate (data structure): how SecurityInsight understands it -- the profiling rules, the CI rule packs (tier,
        // classification), the risk factors and the risk index that score it
        new NavItem("Configuration", "/Rules/Index", "Profiling rules", "reader", Stage: Correlate),
        // #462 the CI rule packs: live / testing, priority, what they set; staging an Invardia pack, promoting to live
        new NavItem("Configuration", "/RulePacks/Index", "Rule packs", "reader", Stage: Correlate),
        // #527 (4): the risk factor model: the factors (impact, state, the score preview), the ONE classification mapping
        // (dimensions such as component, asset type and subtype) and the break glass naming patterns -- one item, three tabs
        Group("Configuration", "Risk factors", "reader",
            new("/RiskFactors/Index", "Factors"), new("/RiskFactors/Classification", "Classification"), new("/RiskFactors/BreakGlass", "Break glass")) with { Stage = Correlate },
        new NavItem("Configuration", "/RiskIndex/Index", "Risk index", "readeronly", Stage: Correlate),
        new NavItem("Configuration", "/RiskIndex/Index", "Risk index", "admin", Stage: Correlate),
        // owner 2026-10-20 ("i need menuitem for risk rating and lifecycle in menu under configuration" -- "important things
        // will look for frequently and could chg"): the risk rating's thresholds and the lifecycles counted with (the accepted
        // lifecycle, the days to fix, the days before an unseen asset is retired) -- one item, two tabs, no longer inside Settings
        Group("Configuration", "Risk rating & lifecycle", "admin",
            new("/Admin/Settings/RiskRating", "Risk rating", "admin") /* #696: the customer's thresholds */,
            new("/Admin/Settings/Lifecycle", "Lifecycle and deadlines", "admin"),
            // #858 (owner 2026-10-21: "do we have a view or setting somewhere where we define these assumptions"): every
            // assumption with its value in force and a link to where it is set, from the readers the pages use
            new("/Admin/Settings/Assumptions", "Assumptions", "admin")) with { Stage = Correlate },
        // Deliver (data-out): what SecurityInsight sends out (owner 2026-10-19: "one for reports and one for connectors").
        // Reports has its own tab strip (Reports/_Tabs.cshtml); the stored documents (the former "Exclusions, weights, rules"
        // item) are its last, Admin-only tab -- exclusions and weights themselves are edited on its tabs
        new NavItem("Configuration", "/Reports/Index", "Reports", "reader", Stage: Deliver, Lede: ReportsLede),
        new NavItem("Configuration", ConnectorsPage, "Connectors", "reader", [
            // the readers' tabs first (the item opens its first tab); the setup, Admin only, last
            new("/Connectors/Fields", "Fields sent"), new("/Connectors/Scope", "Scope"), new("/Collection/Connectors", "Runs"),
            // CR2 (#656): the daily check of SecurityInsight's own data; Unhealthy holds data-out per channel (a SuperAdmin lets one through)
            new("/Admin/DataHealth", "Data-health hold"), new("/Admin/ConnectorSetup/Index", "Setup", "admin")], Stage: Deliver, Lede: ConnectorsLede),
        new NavItem("Configuration", "/AssetTagging/Index", "Asset tagging", "reader", Stage: Deliver),
        // Platform: the install itself
        Group("Configuration", "Settings", "admin",
            new("/Admin/Settings/Index", "Settings", "admin"), new("/Admin/Settings/Email", "E-mail + links", "admin"), new("/Admin/Settings/Notifications", "Notifications", "admin"), new("/Admin/Settings/Reports", "Reports and alerts", "admin"), new("/Admin/Settings/ExportImport", "Export / Import", "superadmin")) with { Stage = Platform },
        new NavItem("Configuration", "/Admin/Access", "Access (roles + scopes)", "superadmin", Stage: Platform),
        Group("Configuration", "Departments (setup)", "admin",
            new("/Admin/Departments/Index", "Departments", "admin"), new("/Admin/Departments/Rules", "Department rules", "admin"),
            new("/Admin/Departments/Flows", "Remediation flows", "admin")) with { Stage = Platform },
        new NavItem("Configuration", "/Admin/DomainRoles", "Security owners", "admin", Stage: Platform),
        // the shipped templates of every configuration item and their releases (what the vendor ships vs your changes)
        Group("Configuration", "Templates", "reader",
            new("/Templates/Index", "Template conformance"), new("/Templates/Releases", "Template releases")) with { Stage = Platform },
        // #404 (CONFIG-1.3 / 1.4): configuration backups and pick-what-you-restore
        new NavItem("Configuration", "/Admin/Backups", "Backups (restore)", "admin", Stage: Platform),
        new NavItem("Configuration", "/Admin/EnvironmentReport", "Environment report", "admin", Stage: Platform),   // ENV-REPORT-1 (#482)
        new("Help", "/Help", "Help + glossary", "reader"),
        // #679: the documentation of THIS version, shipped inside the release -- every signed-in role may read it
        new("Help", "/Docs/Index", "Documentation", "home"),
    };

    /// The Configuration headings: the pipeline's stage titles (the Jobs page's words), then the install itself.
    /// (constants: the menu is built before any other static of this class; a test holds them to JobFlow.StageTitle)
    public const string Collect = "Collect (data-in)";
    public const string Correlate = "Correlate (data structure)";
    public const string Deliver = "Deliver (data-out)";
    public const string Platform = "Platform";

    /// The Connectors area opens on what every reader may see (its first tab, the setup, is Admin only).
    public const string ConnectorsPage = "/Connectors/Fields";
    public const string ReportsLede = "What SecurityInsight reports and how: the reports, their templates, what they leave out and the workbooks people read.";
    public const string ConnectorsLede = "What SecurityInsight sends to other systems -- ServiceNow, SQL, tagging -- which fields, for which assets, and every run.";

    /// A menu item that brings several pages together as tabs; the menu opens the first.
    private static NavItem Group(string section, string label, string need, params NavTab[] tabs) => new(section, tabs[0].Page, label, need, tabs);

    /// Every page the menu reaches: each item's page, and each tab's page.
    public static IEnumerable<(NavItem Item, NavTab? Tab, string Page, string Need)> Pages() =>
        Items.SelectMany(i => i.Tabs is { } tabs
            ? tabs.Select(t => (i, (NavTab?)t, t.Page, t.Need))
            : new[] { (i, (NavTab?)null, i.Page, i.Need) });

    /// The menu item of a Razor page ("/Admin/Departments/Index"; "/Admin/Departments" finds it too) -- for a tab, the item
    /// it is a tab of -- or null.
    public static NavItem? Find(string page)
    {
        var p = Normalize(page);
        return Items.FirstOrDefault(i => Same(i.Page, p)) ?? TabGroupOf(page);
    }

    /// The tab a page is, or null when it is not a tab of any menu item.
    public static NavTab? TabOf(string page)
    {
        var p = Normalize(page);
        return Items.SelectMany(i => i.Tabs ?? []).FirstOrDefault(t => Same(t.Page, p));
    }

    /// The menu item with tabs that this page is one of (the layout draws its tab strip), or null.
    public static NavItem? TabGroupOf(string page)
    {
        var p = Normalize(page);
        return Items.FirstOrDefault(i => i.Tabs?.Any(t => Same(t.Page, p)) == true);
    }

    /// The menu path of a page in plain text, e.g. "Configuration > Departments (setup)"; a tab other than the first adds
    /// its label ("Changes &amp; trends > Vulnerabilities over time > Per collection"); <paramref name="then"/> adds a tab or
    /// section on that page ("Configuration > Reports > Management summary"). A page that is not in the menu
    /// throws -- the tests run every reference in the source through here, so this never reaches a person.
    public static string PathOf(string page, string? then = null)
    {
        var item = Find(page) ?? throw new InvalidOperationException("'" + page + "' is not in the menu (Navigation/NavModel.cs)");
        var path = item.Path;
        if (TabOf(page) is { } tab && !Same(item.Page, Normalize(tab.Page))) path += Separator + tab.Label;
        return string.IsNullOrEmpty(then) ? path : path + Separator + then;
    }

    /// "/Admin/Departments/Index" -> "/Admin/Departments"; "/Management/Index" -> "/Management".
    public static string HrefOf(string page)
    {
        var p = Normalize(page);
        return p.Length == 0 ? "/" : p;
    }

    private static string Normalize(string page)
    {
        var p = (page ?? "").Trim();
        if (p.EndsWith("/Index", StringComparison.OrdinalIgnoreCase)) p = p[..^"/Index".Length];
        return p.TrimEnd('/');
    }

    private static bool Same(string page, string normalized) => Normalize(page).Equals(normalized, StringComparison.OrdinalIgnoreCase);

    /// Is the Razor page <paramref name="current"/> (the route's page name, "/Management/Index") this tab?
    public static bool IsTab(NavTab tab, string current) => Same(tab.Page, Normalize(current));

    /// <summary>
    /// Is <paramref name="tab"/> the one being shown, given the address's parameters (<paramref name="query"/>: a parameter's
    /// value or null)? A tab with a <see cref="NavTab.Query"/> is current when its page is shown with that parameter; the
    /// page's plain tab when none of its page's view tabs is.
    /// </summary>
    public static bool IsTab(NavTab tab, string current, Func<string, string?> query)
    {
        if (!IsTab(tab, current)) return false;
        bool Carried(NavTab t) => t.Query is { } q && q.Split('=', 2) is [var k, var v] && string.Equals(query(k), v, StringComparison.OrdinalIgnoreCase);
        if (tab.Query is not null) return Carried(tab);
        return !(TabGroupOf(current)?.Tabs ?? []).Any(t => t.Query is not null && IsTab(t, current) && Carried(t));
    }

    /// Is <paramref name="page"/> (a menu item) the page being shown, or the menu item that page belongs under?
    public static bool IsCurrent(string page, string current) =>
        current.Equals(page, StringComparison.OrdinalIgnoreCase)
        || Items.Any(i => i.Page == page && i.Tabs?.Any(t => IsTab(t, current)) == true)   // any tab of the item
        || (page == "/Admin/Settings/Index" && current.StartsWith("/Admin/Settings", StringComparison.OrdinalIgnoreCase) && !current.StartsWith("/Admin/Settings/Document", StringComparison.OrdinalIgnoreCase) && !current.StartsWith("/Admin/Settings/Email", StringComparison.OrdinalIgnoreCase))
        // the stored documents (and one document) are the last tab of Reports
        || (page == "/Reports/Index" && current.StartsWith("/Admin/Settings/Document", StringComparison.OrdinalIgnoreCase))
        // a finding (and the old findings browser) sits under Detailed
        || (page == "/Collection/Rows" && current.StartsWith("/Findings", StringComparison.OrdinalIgnoreCase))
        || (page == "/Collection/Assets" && current.Equals("/Collection/Asset", StringComparison.OrdinalIgnoreCase))   // one CI sits under the list of CIs
        || (page == "/Cis/Index" && current.Equals("/Cis/Detail", StringComparison.OrdinalIgnoreCase))   // one CI sits under the CI inventory
        || (page == "/Cmdb/Index" && (current.StartsWith("/Cmdb/Service", StringComparison.OrdinalIgnoreCase) || current.StartsWith("/Cmdb/Source", StringComparison.OrdinalIgnoreCase)))
        || (page == "/Exemptions/Index" && current.StartsWith("/Exemptions", StringComparison.OrdinalIgnoreCase))
        || (page == "/Reports/Index" && current.StartsWith("/Reports", StringComparison.OrdinalIgnoreCase))
        || (page == ConnectorsPage && current.StartsWith("/Admin/ConnectorSetup", StringComparison.OrdinalIgnoreCase));
}
