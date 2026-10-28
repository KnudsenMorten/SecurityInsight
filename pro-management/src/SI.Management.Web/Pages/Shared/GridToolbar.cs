using Microsoft.AspNetCore.Html;
using SI.Management.Web.Actions;

namespace SI.Management.Web.Pages;

/// <summary>
/// THE toolbar of every grid (<c>Pages/Shared/_GridToolbar.cshtml</c>): one compact bar directly under the grid's search
/// box and filter chips and ABOVE the column headers -- the selection count and the actions on the left, "N row(s) · a-b"
/// and the pager on the right. It sticks to the top of the window while the page scrolls, so the actions and the paging
/// are never 50 rows away (operator 2026-10-05: "the buttons and pages below people dont see"). The actions are always
/// shown; with nothing ticked they are disabled with the hint "tick rows to act on them" (js/app/ui.js).
/// A page renders it once above the table and, for a long page, <see cref="Bottom"/> once more under it (pager only).
/// </summary>
public sealed record GridToolbar
{
    /// The element id of the toolbar.
    public required string Id { get; init; }
    /// Rows the view matches, the first row shown (0-based) and how many rows this page shows.
    public long Total { get; init; }
    public long Skip { get; init; }
    public int Count { get; init; }
    /// What a row is ("row(s)", "finding(s)", "task(s)", ...; <see cref="Plural"/> / <see cref="Singular"/> say it).
    public string Noun { get; init; } = "row(s)";
    public int Page { get; init; } = 1;
    public int Pages { get; init; } = 1;
    /// The link of a page number (1-based). Null = the grid is not paged (no pager at all).
    public Func<int, string>? PageLink { get; init; }
    /// "« First" and "Last »" beside Previous / Next.
    public bool FirstLast { get; init; }
    public string PreviousLabel { get; init; } = "← Previous";
    public string NextLabel { get; init; } = "Next →";
    /// Show "Page 1 of 1" too (the collection grids always say where you are); otherwise the pager shows from 2 pages.
    public bool AlwaysShowPage { get; init; }
    /// The shared action bar for selected findings (#272) -- rendered in the left slot.
    public FindingActionBar? Bar { get; init; }
    /// The page's own selection actions, when the grid does not list findings (a CI grid's "export selected", the
    /// exemption review's form, the report catalog's bulk change). Rendered in the left slot.
    public Func<object?, IHtmlContent>? Actions { get; init; }
    /// Rendered under the table (a second pager only): a long page keeps its paging at both ends.
    public bool Bottom { get; init; }
    /// <summary>
    /// #857 (owner 2026-10-21: "where is the ability to control number per page 50 is not enough"): the rows per page this
    /// page shows and the link of each choice (<see cref="SI.Management.Core.ProData.GridSql.PageChoices"/>: 50 / 100 / 250
    /// / 500), shown beside "Showing 1–50 of N". Plain links -- keyboard-reachable, no script: each keeps the view's sort,
    /// filters and search and starts at page 1, and "size" is part of the view's remembered state (Columns/ViewState), so
    /// the choice comes back with the view's other choices. Null = the grid offers no choice (a list that is not paged).
    /// </summary>
    public Func<int, string>? SizeLink { get; init; }
    public int Size { get; init; } = SI.Management.Core.ProData.GridSql.DefaultPageSize;

    /// The rows-per-page choices this toolbar shows (none when the grid offers no choice).
    public IReadOnlyList<int> SizeChoices => SizeLink is null ? [] : SI.Management.Core.ProData.GridSql.PageChoices;

    /// A rows-per-page value as a URL value (invariant -- never shown).
    public static string SizeParam(int size) => size.ToString(System.Globalization.CultureInfo.InvariantCulture);

    /// The rows a page must show before the pager is repeated under the table.
    public const int BottomPagerRows = 25;

    public bool Paged => PageLink is not null && (AlwaysShowPage || Pages > 1);
    /// A page long enough to carry a second pager under the table.
    public bool WantsBottom => PageLink is not null && Pages > 1 && Count >= BottomPagerRows;

    /// <summary>
    /// What the grid shows, in words (owner 2026-10-19: "1.117.524 row(s) · 1-50 [Page 1 of 22.351]" confused him):
    /// "Showing 1–50 of 1.117.524 findings" -- the view's own noun, in the viewer's number format; "No findings" when none.
    /// </summary>
    public string Range => Total <= 0 ? "No " + Plural(Noun)
        : Count > 0 ? "Showing " + Fmt.Int(Skip + 1) + "–" + Fmt.Int(Skip + Count) + " of " + Fmt.Int(Total) + " " + (Total == 1 ? Singular(Noun) : Plural(Noun))
        : Fmt.Int(Total) + " " + (Total == 1 ? Singular(Noun) : Plural(Noun));

    /// "finding(s)" / "findings" -> "findings"; "CI(s)" -> "CIs"; "vulnerability(ies)" -> "vulnerabilities".
    public static string Plural(string noun) => noun.Replace("y(ies)", "ies", StringComparison.Ordinal).Replace("(s)", "s", StringComparison.Ordinal);
    /// "finding(s)" -> "finding"; "vulnerability(ies)" -> "vulnerability"; a noun given as a plural ("events") keeps its form.
    public static string Singular(string noun) => noun.Replace("(ies)", "", StringComparison.Ordinal).Replace("(s)", "", StringComparison.Ordinal);

    /// The number the page box shows in place of the page a link goes to (the script puts the typed page there).
    public const int PageMarker = 987_654_321;

    /// The page link with a marker the page box replaces by the page typed (js/app/ui.js); null = not paged.
    public string? PageTemplate => PageLink?.Invoke(PageMarker);

    /// A page number as a URL value (invariant -- never shown).
    public static string PageParam(int page) => page.ToString(System.Globalization.CultureInfo.InvariantCulture);

    /// The same toolbar as a pager under the table.
    public GridToolbar AsBottom() => this with { Id = Id + "-bottom", Bottom = true, Bar = null, Actions = null, SizeLink = null };
}

/// What one row of a collection grid is, by the grid's name -- the noun the pager and the heading say (owner 2026-10-19:
/// "the right noun per view").
public static class GridNouns
{
    private static readonly IReadOnlyDictionary<string, string> ByGrid = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        ["rows"] = "finding(s)", ["department"] = "finding(s)", ["cifindings"] = "finding(s)", [SI.Management.Core.ProData.RiskExplainSql.Name] = "finding(s)",
        ["assets"] = "asset(s)", ["assetrisk"] = "asset(s)", ["assetsvc"] = "asset(s)", ["serviceassets"] = "asset(s)", ["svcassetw"] = "asset(s)",
        ["correlation"] = "asset(s)", ["assetchanges"] = "asset change(s)",
        ["vulns"] = "vulnerability(ies)", ["topissues"] = "issue(s)", ["issuekeys"] = "issue(s)", ["findingchanges"] = "change(s)",
        ["exemptions"] = "exemption(s)", ["events"] = "event(s)", ["connectorruns"] = "run(s)", ["connectoritems"] = "item(s)",
        ["services"] = "service(s)", ["svccrit"] = "service(s)", ["assetsvcs"] = "service(s)",
    };

    /// The noun of a grid (a department-restricted grid is named "rows@dept": its base name counts); "row(s)" when unknown.
    public static string Of(string? grid) =>
        grid is not null && ByGrid.TryGetValue(grid.Split('@')[0], out var n) ? n : "row(s)";
}
