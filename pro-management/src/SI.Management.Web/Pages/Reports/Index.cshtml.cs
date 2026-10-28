using System.Globalization;
using Microsoft.AspNetCore.Mvc;
using SI.Management.Core.ProData;
using SI.Management.Web.Audit;
using SI.Management.Web.Auth;
using SI.Management.Web.Changes;
using SI.Management.Web.Reports;
using ItemWrite = SI.Management.Core.ProData.ItemWrite; // the report designer's write (not the editors' Changes.ItemWrite)

namespace SI.Management.Web.Pages.Reports;

/// One row of the catalog grid.
public sealed record CatalogRow(ReportItem Item, string Name, string Purpose, string Domain, IReadOnlyList<string> Tables, IReadOnlyList<string> Severities, IReadOnlyList<string> Tiers, IReadOnlyList<string> InTemplates);

/// <summary>
/// The report catalog (#274 part 1): every report, vendor and yours, as ONE server-side grid (BRAND-2.7) -- search, the
/// filters, the sort and the page travel in the URL and are applied on the server. Bulk: untick Low, switch on / off, back
/// to the vendor's, on the selected reports -- staged as one change.
/// </summary>
public sealed class IndexModel : ReportsPage
{
    public IndexModel(IReportStore store, ChangeService changes, ILogger<IndexModel> log) : base(store, changes, log) { }

    public static readonly int[] Sizes = GridSql.PageChoices;
    [BindProperty(SupportsGet = true)] public string? Q { get; set; }
    [BindProperty(SupportsGet = true)] public string? Domain { get; set; }
    [BindProperty(SupportsGet = true)] public string? Origin { get; set; }
    [BindProperty(SupportsGet = true)] public string? Show { get; set; }
    [BindProperty(SupportsGet = true)] public string? Sort { get; set; }
    [BindProperty(SupportsGet = true)] public string? Dir { get; set; }
    [BindProperty(SupportsGet = true)] public int P { get; set; } = 1;
    [BindProperty(SupportsGet = true)] public int Size { get; set; } = 50;
    [BindProperty] public List<string> Selected { get; set; } = new();
    [BindProperty] public string? Op { get; set; }

    public IReadOnlyList<CatalogRow> Rows { get; private set; } = Array.Empty<CatalogRow>();
    public int Total { get; private set; }
    public int Pages => Math.Max(1, (Total + Size - 1) / Size);

    public async Task OnGetAsync(CancellationToken ct)
    {
        if (!await LoadAsync(ct)) return;
        Build();
    }

    public static IReadOnlyList<CatalogRow> All(ReportState s)
    {
        var inTpl = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        foreach (var t in s.Templates.Where(t => t.Enabled))
            foreach (var r in ReportBody.Included(t.Json)) { if (!inTpl.TryGetValue(r, out var l)) inTpl[r] = l = new(); l.Add(t.Name); }
        return s.Reports.Select(i =>
        {
            var o = i.Json;
            return new CatalogRow(i, i.Name, ReportBody.Text(o, "ReportPurpose"), ReportBody.Text(o, "SecurityDomain"), ReportBody.Tables(ReportBody.Query(o)),
                ReportBody.List(o, "SecuritySeverityScope"), ReportBody.List(o, "CriticalityTierLevelScope"), inTpl.TryGetValue(i.Name, out var l) ? l : new List<string>());
        }).ToList();
    }

    /// Filter, sort, page -- on the server.
    public static (IReadOnlyList<CatalogRow> Rows, int Total) Query(IReadOnlyList<CatalogRow> all, string? q, string? domain, string? origin, string? show, string? sort, bool desc, int page, int size)
    {
        IEnumerable<CatalogRow> r = all;
        if (!string.IsNullOrWhiteSpace(q)) r = r.Where(x => x.Name.Contains(q.Trim(), StringComparison.OrdinalIgnoreCase) || x.Purpose.Contains(q.Trim(), StringComparison.OrdinalIgnoreCase) || x.Tables.Any(t => t.Contains(q.Trim(), StringComparison.OrdinalIgnoreCase)));
        if (!string.IsNullOrWhiteSpace(domain)) r = r.Where(x => string.Equals(x.Domain, domain, StringComparison.OrdinalIgnoreCase));
        if (!string.IsNullOrWhiteSpace(origin)) r = r.Where(x => OriginLabel(x.Item.Origin) == origin);
        r = show switch
        {
            "off" => r.Where(x => !x.Item.Enabled),
            "on" => r.Where(x => x.Item.Enabled),
            "scoped" => r.Where(x => x.Severities.Count < ReportVocabulary.Severities.Count || x.Tiers.Count < ReportVocabulary.Tiers.Count),
            _ => r,
        };
        Func<CatalogRow, string> key = sort switch
        {
            "domain" => x => x.Domain + "|" + x.Name,
            "origin" => x => OriginLabel(x.Item.Origin) + "|" + x.Name,
            "enabled" => x => (x.Item.Enabled ? "1" : "0") + "|" + x.Name,
            _ => x => x.Name,
        };
        var list = (desc ? r.OrderByDescending(key, StringComparer.OrdinalIgnoreCase) : r.OrderBy(key, StringComparer.OrdinalIgnoreCase)).ToList();
        size = GridSql.PageSize(size);
        page = Math.Clamp(page, 1, Math.Max(1, (list.Count + size - 1) / size));
        return (list.Skip((page - 1) * size).Take(size).ToList(), list.Count);
    }

    /// #287: how many reports a filter choice gives under the OTHER filters (and the search).
    public int CountWith(string? domain, string? origin, string? show) =>
        State is null ? 0 : Query(All(State), Q, domain, origin, show, null, false, 1, 50).Total;

    /// The choices of one dropdown with their counts, the ones with reports first, the empty ones after.
    public IReadOnlyList<(string Value, string Label, int Count)> Choices(IEnumerable<(string Value, string Label)> choices, Func<string, int> count)
    {
        var l = choices.Select(c => (c.Value, c.Label, count(c.Value))).ToList();
        return l.Where(x => x.Item3 > 0).Concat(l.Where(x => x.Item3 == 0)).ToList();
    }

    private void Build()
    {
        if (State is null) return;
        Size = GridSql.PageSize(Size);
        var (rows, total) = Query(All(State), Q, Domain, Origin, Show, Sort, string.Equals(Dir, "desc", StringComparison.OrdinalIgnoreCase), P, Size);
        Rows = rows; Total = total;
        P = Math.Clamp(P, 1, Pages);
    }

    /// The writes a bulk operation makes on the selected reports.
    public static IReadOnlyList<ItemWrite> BulkWrites(ReportState s, IEnumerable<string> names, string op)
    {
        var writes = new List<ItemWrite>();
        foreach (var name in names.Distinct(StringComparer.Ordinal))
        {
            var it = s.Find("report/" + name);
            if (it is null) continue;
            ItemWrite? w = op switch
            {
                "untick-low" => ItemWrites.For("rareport", it.Key, it.TemplateBody, it.OverrideState, it.OverrideBody,
                    ReportBody.WithScope(it.Body, ReportBody.List(it.Json, "SecuritySeverityScope").Where(x => !string.Equals(x, "Low", StringComparison.OrdinalIgnoreCase)), ReportBody.List(it.Json, "CriticalityTierLevelScope")),
                    it.Enabled, "Low unticked: " + string.Join(", ", ReportBody.List(it.Json, "SecuritySeverityScope").Where(x => !string.Equals(x, "Low", StringComparison.OrdinalIgnoreCase)))),
                "disable" => it.Origin == ReportOrigin.Own ? null : ItemWrites.For("rareport", it.Key, it.TemplateBody, it.OverrideState, it.OverrideBody, it.Body, false, "switched off (left out of every template)"),
                "enable" => ItemWrites.For("rareport", it.Key, it.TemplateBody, it.OverrideState, it.OverrideBody, it.Origin == ReportOrigin.Vendor ? it.TemplateBody : it.Body, true, "switched on"),
                "reset" => it.TemplateBody is null ? null : ItemWrites.For("rareport", it.Key, it.TemplateBody, it.OverrideState, it.OverrideBody, it.TemplateBody, true, "back to the vendor's report"),
                _ => null,
            };
            if (w is not null) writes.Add(w);
        }
        return writes;
    }

    [Audited("report.scope.change")]
    public async Task<IActionResult> OnPostBulkAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        if (!await LoadAsync(ct)) return Page();
        if (Selected.Count == 0) { Messages.Add("Not staged: select one or more reports first"); Build(); return Page(); }
        var op = Op ?? "";
        if (op is not ("untick-low" or "enable" or "disable" or "reset")) { Messages.Add("Not staged: choose what to do with the selected reports"); Build(); return Page(); }
        var writes = BulkWrites(State!, Selected, op);
        var label = op switch { "untick-low" => "untick Low", "enable" => "switch on", "disable" => "switch off", _ => "back to the vendor's" };
        var staged = await StageAsync(ReportChanges.Catalog, $"Reports: {label} on {writes.Count} report(s)", writes, ct);
        if (staged is not null) return staged;
        Build();
        return Page();
    }

    public string Link(params (string Key, string? Value)[] overrides)
    {
        var d = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase)
        {
            ["q"] = Q, ["domain"] = Domain, ["origin"] = Origin, ["show"] = Show, ["sort"] = Sort, ["dir"] = Dir,
            ["size"] = Size == GridSql.DefaultPageSize ? null : Size.ToString(CultureInfo.InvariantCulture), ["p"] = P > 1 ? P.ToString(CultureInfo.InvariantCulture) : null,
        };
        foreach (var (k, v) in overrides) d[k] = v;
        if (overrides.All(o => o.Key != "p")) d["p"] = null;
        var qs = string.Join("&", d.Where(kv => !string.IsNullOrEmpty(kv.Value)).Select(kv => kv.Key + "=" + Uri.EscapeDataString(kv.Value!)));
        return "/Reports" + (qs.Length > 0 ? "?" + qs : "");
    }

    public string SortLink(string col) => Link(("sort", col == "name" ? null : col), ("dir", (Sort ?? "name") == col && !string.Equals(Dir, "desc", StringComparison.OrdinalIgnoreCase) ? "desc" : null));
    public string AriaSort(string col) => (Sort ?? "name") != col ? "none" : string.Equals(Dir, "desc", StringComparison.OrdinalIgnoreCase) ? "descending" : "ascending";
}
