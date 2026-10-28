using System.Globalization;

namespace SI.Management.Web.Navigation;

/// <summary>
/// One NAMED VIEW (#636, owner 2026-10-13, approved): a saved layout SI ships for Security recommendations > Summary and
/// Detailed -- a name in the picker at the top of the page and the filters / sort it opens with. Choosing one opens the page
/// with them in the URL (so the link shares the view exactly, and every filter can be changed from there).
/// <see cref="Facet"/>: the collection's counts per value of that facet are shown under the picker, each a link that
/// narrows the grid (what the retired MITRE, Compliance, CVSS and Risk rating pages showed above their rows).
/// </summary>
public sealed record NamedView(string Id, string Label, string Hint, IReadOnlyList<(string Column, string Value)> Filters,
    string? Sort = null, bool? Desc = null, string? Facet = null, string? FacetColumn = null, string? FacetTitle = null, string? Grouping = null)
{
    /// The page with this view: ?view=id plus its filters and sort; <paramref name="collection"/> keeps the collection.
    public string Href(string page, string? collection)
    {
        var parts = new List<string>();
        if (!string.IsNullOrEmpty(collection)) parts.Add("c=" + Uri.EscapeDataString(collection));
        if (Id != NamedViews.All) parts.Add("view=" + Uri.EscapeDataString(Id));
        // Summary: the stored grouping the view reads (RecommendationSql.Groupings)
        if (Grouping is not null) parts.Add("by=" + Uri.EscapeDataString(Grouping));
        foreach (var (col, val) in Filters) parts.Add("f." + Uri.EscapeDataString(col) + "=" + Uri.EscapeDataString(val));
        if (Sort is not null) parts.Add("sort=" + Uri.EscapeDataString(Sort));
        if (Desc is { } d) parts.Add("dir=" + (d ? "desc" : "asc"));
        return NavModel.HrefOf(page) + (parts.Count > 0 ? "?" + string.Join("&", parts) : "");
    }
}

/// <summary>
/// The shipped named views of the two Security recommendations pages, in picker order. An Admin hides one for everyone
/// with the setting SI_Pro_HiddenViews (the view ids); a person's own and the Admin-published layouts stay in the
/// toolbar's Layout list (cfg.ViewLayout), next to these.
/// </summary>
public static class NamedViews
{
    public const string All = "all";
    public const string SummaryPage = "/Recommendations/Summary";
    public const string DetailedPage = "/Collection/Rows";

    /// The views of Detailed (/Collection/Rows): its grid's column keys.
    public static readonly IReadOnlyList<NamedView> Detailed =
    [
        new(All, "All", "Every finding of the collection.", []),
        new("critical-high", "Critical and High", "The findings rated Critical or High -- where most teams start.", [("RiskRating", "Critical"), ("RiskRating", "High")],
            "RiskScoreWeighted", true, "rating", "RiskRating", "Findings per risk rating"),
        new("tier0", "On Tier 0", "The findings on Tier 0 assets: the most critical assets of the estate.", [("Tier", "0")], "RiskScoreWeighted", true),
        new("cve", "Vulnerabilities (CVE)", "The findings that are a CVE.", [("Cve", "CVE-")], "Cvss", true, "cvss", "Cvss", "Findings per CVSS band"),
        new("exploited", "Known exploited", "The findings with a known exploit.", [("HasExploit", "1")], "RiskScoreWeighted", true),
        new("mitre", "MITRE", "The findings by the MITRE ATT&CK tactics they enable.", [], "RiskScoreWeighted", true, "tactic", "MitreTactics", "Findings per MITRE ATT&CK tactic"),
        new("compliance", "Compliance", "The findings by the compliance tags and benchmarks they map to.", [], "RiskScoreWeighted", true, "tag", "ComplianceTags", "Findings per compliance tag"),
        new("cvss", "CVSS", "The findings with a CVSS score, the highest first.", [("Cvss", "0.1..10")], "Cvss", true, "cvss", "Cvss", "Findings per CVSS band"),
    ];

    /// The views of Summary (/Recommendations/Summary): the stored groupings of the Detailed findings (RecommendationSql.Grouped,
    /// its grid's column keys; Grouping = which grouping the view reads, none = per recommendation). "Vulnerabilities (CVE)"
    /// reads one row per CVE. MITRE, Compliance and CVSS are views of Detailed (the groupings do not carry them).
    public static readonly IReadOnlyList<NamedView> Summary =
    [
        // owner 2026-10-20: as the Summary report -- one row per recommendation and tier, the most critical tier and the most
        // risk first (Lead); "Per recommendation" is the same over every tier
        new(All, "All", "Every security recommendation of the collection once per tier it is on, with the assets it affects -- the most critical tier and the most risk first.", [], "Lead", true),
        new("critical-high", "Critical and High", "The recommendations with findings rated Critical or High.", [("RatedCriticalOrHigh", "1..")], "Lead", true),
        new("tier0", "On Tier 0", "The recommendations with findings on Tier 0 assets.", [("Tier0Findings", "1..")], "Lead", true),
        new("cve", "Vulnerabilities (CVE)", "One row per CVE: severity, CVSS, a known exploit, the affected assets and the open items of the close-loop.", [], "MaxRisk", true),
        new("exploited", "Known exploited", "The recommendations with a known exploit.", [("HasExploit", "1")], "Lead", true),
        new("by-recommendation", "Per recommendation", "One row per security recommendation over every tier, with the assets it affects.", [], "Lead", true, Grouping: "recommendation"),
        new("by-asset", "Per asset", "One row per asset with its findings, the most risk first.", [], "TotalRisk", true, Grouping: "asset"),
        new("by-tier", "Per tier", "One row per tier.", [], "K1", false, Grouping: "tier"),
        new("by-category", "Domain > Category > Subcategory", "One row per domain, category and subcategory.", [], "TotalRisk", true, Grouping: "domain-category-subcategory"),
        new("by-rating", "Per risk rating", "One row per risk rating.", [], "TotalRisk", true, Grouping: "risk-rating"),
        new("by-severity", "Per severity", "One row per severity.", [], "TotalRisk", true, Grouping: "severity"),
        new("by-department", "Per department", "One row per department (its id).", [], "TotalRisk", true, Grouping: "department"),
        new("by-report", "Per report", "One row per Risk Analysis report.", [], "TotalRisk", true, Grouping: "report"),
        new("by-mitre", "Per MITRE ATT&CK tactic", "One row per MITRE ATT&CK tactic the findings enable.", [], "TotalRisk", true, Grouping: "mitre-tactic"),
        new("by-compliance", "Per compliance control", "One row per compliance control the findings map to.", [], "TotalRisk", true, Grouping: "compliance-control"),
        new("by-cvss", "Per CVSS band", "One row per CVSS band.", [], "K1", true, Grouping: "cvss-band"),
    ];

    /// The views of a page (empty for a page without named views).
    public static IReadOnlyList<NamedView> Of(string page) =>
        string.Equals(NavModel.HrefOf(page), NavModel.HrefOf(SummaryPage), StringComparison.OrdinalIgnoreCase) ? Summary
        : string.Equals(NavModel.HrefOf(page), NavModel.HrefOf(DetailedPage), StringComparison.OrdinalIgnoreCase) ? Detailed : [];

    /// The view a request names (null = none: the page as it is; an unknown id is ignored).
    public static NamedView? Find(string page, string? id) =>
        string.IsNullOrWhiteSpace(id) ? null : Of(page).FirstOrDefault(v => string.Equals(v.Id, id.Trim(), StringComparison.OrdinalIgnoreCase));

    /// The views a person sees: every shipped one but those an Admin hid (SI_Pro_HiddenViews: "detailed:mitre", or "mitre"
    /// for both pages). "All" is never hidden.
    public static IReadOnlyList<NamedView> Visible(string page, IEnumerable<string>? hidden)
    {
        var h = (hidden ?? []).Select(x => x.Trim().ToLowerInvariant()).Where(x => x.Length > 0).ToHashSet();
        var prefix = Of(page) == Summary ? "summary:" : "detailed:";
        return Of(page).Where(v => v.Id == All || !(h.Contains(v.Id) || h.Contains(prefix + v.Id))).ToList();
    }

    /// The setting that hides shipped views (a list of view ids).
    public const string HiddenSetting = "SI_Pro_HiddenViews";

    /// The setting's value as the list of ids (a JSON array, or ';' / ',' separated text).
    public static IReadOnlyList<string> ParseHidden(string? valueJson)
    {
        if (string.IsNullOrWhiteSpace(valueJson)) return [];
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(valueJson);
            if (doc.RootElement.ValueKind == System.Text.Json.JsonValueKind.Array)
                return doc.RootElement.EnumerateArray().Where(e => e.ValueKind == System.Text.Json.JsonValueKind.String).Select(e => e.GetString()!).ToList();
            if (doc.RootElement.ValueKind == System.Text.Json.JsonValueKind.String) return Split(doc.RootElement.GetString());
        }
        catch (System.Text.Json.JsonException) { return Split(valueJson); }
        return [];
        static IReadOnlyList<string> Split(string? s) => (s ?? "").Split([';', ','], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }

    internal static string Inv(double d) => d.ToString(CultureInfo.InvariantCulture);
}

/// What the page frame shows above the table: the picker (the views a person sees, the one in use) and the facet links.
public sealed record ViewPicker(string Page, string? Collection, IReadOnlyList<NamedView> Views, NamedView? Current,
    IReadOnlyList<(string Label, long Findings, string Href)>? FacetLinks = null)
{
    public NamedView Selected => Current ?? Views.First(v => v.Id == NamedViews.All);
}
