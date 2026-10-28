using System.Globalization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Core.ProData;
using SI.Management.Web.Departments;

namespace SI.Management.Web.Pages;

/// One kind of result: what it is, how many matched (null = more than were read), the first few, and where to see them all.
public sealed record SearchSection(string Key, string Title, IReadOnlyList<SearchHit> Hits, long? Total, string? AllLink, string? Note = null);
public sealed record SearchHit(string Text, string? Detail, string Href);

/// <summary>
/// THE global search of the header (#285, framework BRAND-2: PIM's header search is the reference): one box that finds
/// CIs (assets), findings, CVEs, people and reports, and links to each. Every read goes through the same grids and stores
/// the pages use, under the reader's own visibility: an account limited to departments searches only the rows of its
/// departments, and a kind of result that cannot be limited that way is left out with a note, never shown unlimited.
/// Reads only.
/// </summary>
public sealed class SearchModel(ICollectionViews views, IDepartmentScopeResolver scope, DepartmentRepository departments,
    SI.Management.Web.Reports.IReportStore reports, ILogger<SearchModel> log) : PageModel
{
    public const int Shown = 10;
    public const int MinLength = 2;

    [BindProperty(SupportsGet = true)] public string? Q { get; set; }
    public string? Notice { get; private set; }
    public List<SearchSection> Sections { get; } = new();
    public long Found => Sections.Sum(s => s.Total ?? s.Hits.Count);

    public async Task OnGetAsync(CancellationToken ct)
    {
        Q = Q?.Trim();
        if (string.IsNullOrEmpty(Q)) { Notice = "Type at least " + MinLength + " characters: a CI or asset name, a finding, a CVE, a person or a report."; return; }
        if (Q.Length < MinLength) { Notice = "Type at least " + MinLength + " characters."; return; }
        if (Q.Length > 200) Q = Q[..200];
        var access = await scope.ResolveAsync(User, ct);
        ViewCollection? cur = null;
        try { cur = (await views.CollectionsAsync(ct)).Data.FirstOrDefault(); }
        catch (Exception ex) when (ex is not OperationCanceledException) { log.LogWarning(ex, "search: the collections could not be read"); }

        if (cur is not null)
        {
            await AssetSection(cur, access, ct);
            await GridSection("findings", "Findings", CollectionViewSql.Rows, new() { ["CollectionId"] = cur.CollectionId, ["AssetKey"] = null }, cur, access,
                r => new SearchHit(S(r, "Title") ?? S(r, "FindingId") ?? "", Detail(S(r, "AssetName"), S(r, "Severity")),
                    "/Findings/Detail?c=" + Uri.EscapeDataString(cur.CollectionId) + "&id=" + Uri.EscapeDataString(S(r, "FindingId") ?? "")),
                "/Collection/Rows?q=", ct);
            await CveSection(cur, access, ct);
        }
        else Notice = "No collection is loaded yet: CIs, findings and CVEs are searched once the first data sync has run.";

        await PeopleSection(access, ct);
        await ReportSection(access, ct);
    }

    private static string? S(IReadOnlyDictionary<string, object?> r, string k) =>
        r.TryGetValue(k, out var v) && v is not null && Convert.ToString(v, CultureInfo.InvariantCulture) is { Length: > 0 } s ? s : null;
    private static string? Tier(IReadOnlyDictionary<string, object?> r) => S(r, "Tier") is { } t ? (t.Length == 1 ? "Tier " + t : t) : null;
    private static string? Detail(params string?[] parts) => parts.Where(p => !string.IsNullOrWhiteSpace(p)).ToArray() is { Length: > 0 } a ? string.Join(" · ", a) : null;

    /// The CVEs: the collection's PRE-COMPUTED per-CVE rows (what Security recommendations > Vulnerabilities pages over).
    /// An account limited to departments searches its own findings grouped live -- the pre-computed rows span every
    /// department. Rows not written yet are said, never worked out here from every finding of the collection.
    private async Task CveSection(ViewCollection cur, DepartmentAccess access, CancellationToken ct)
    {
        static SearchHit Hit(IReadOnlyDictionary<string, object?> r) =>
            new(S(r, "Cve") ?? "", Detail(S(r, "Title"), S(r, "Severity")), "/Collection/Rows?f.Cve=" + Uri.EscapeDataString(S(r, "Cve") ?? ""));
        var spec = CollectionViewSql.Vulnerabilities;
        if (access.Rows is not null) spec = CollectionViewSql.VulnerabilitiesLive;
        else
        {
            CveSummaryState? state = null;
            try { state = (await views.CveSummaryStateAsync(cur, ct)).Data; }
            catch (Exception ex) when (ex is not OperationCanceledException) { log.LogWarning(ex, "search: the per-CVE rows' state could not be read"); }
            if (state is not { Built: true })
            {
                Sections.Add(new SearchSection("cves", "CVEs", Array.Empty<SearchHit>(), 0, null,
                    state is null ? "Could not be searched just now." : "Not searched yet: the data sync is preparing this collection's list of vulnerabilities."));
                return;
            }
        }
        await GridSection("cves", "CVEs", spec, new() { ["CollectionId"] = cur.CollectionId }, cur, access, Hit, "/Collection/Vulnerabilities?q=", ct);
    }

    /// The CIs: the collection's PRE-COMPUTED per-CI rows (what Assets (CIs) at risk pages over, 2026-10-19). An account
    /// limited to departments searches its own findings grouped live. Rows not written yet are said, never worked out here.
    private async Task AssetSection(ViewCollection cur, DepartmentAccess access, CancellationToken ct)
    {
        static SearchHit Hit(IReadOnlyDictionary<string, object?> r) =>
            new(S(r, "AssetName") ?? S(r, "AssetKey") ?? "", Detail(S(r, "AssetKind"), Tier(r)), "/Collection/Asset?key=" + Uri.EscapeDataString(S(r, "AssetKey") ?? ""));
        var spec = CollectionViewSql.Assets;
        if (access.Rows is not null) spec = CollectionViewSql.AssetsLive;
        else
        {
            AssetSummaryState? state = null;
            try { state = (await views.AssetSummaryStateAsync(cur, ct)).Data; }
            catch (Exception ex) when (ex is not OperationCanceledException) { log.LogWarning(ex, "search: the per-CI rows' state could not be read"); }
            if (state is not { Built: true })
            {
                Sections.Add(new SearchSection("assets", "CIs (assets)", Array.Empty<SearchHit>(), 0, null,
                    state is null ? "Could not be searched just now." : "Not searched yet: the data sync is preparing this collection's list of CIs."));
                return;
            }
        }
        await GridSection("assets", "CIs (assets)", spec, new() { ["CollectionId"] = cur.CollectionId }, cur, access, Hit, "/Collection/Assets?q=", ct);
    }

    private async Task GridSection(string key, string title, GridSpec spec, Dictionary<string, object?> p, ViewCollection cur, DepartmentAccess access,
        Func<IReadOnlyDictionary<string, object?>, SearchHit> hit, string allLink, CancellationToken ct)
    {
        var scopeKey = cur.Version;
        if (access.Rows is { } vis)
        {
            if (!DepartmentScope.CanRestrict(spec))
            {
                Sections.Add(new SearchSection(key, title, Array.Empty<SearchHit>(), 0, null, "Not searched: this list spans every department, and your account sees only its own."));
                return;
            }
            spec = DepartmentScope.Restrict(spec, vis);
            foreach (var kv in vis.Parameters) p[kv.Key] = kv.Value;
            scopeKey += "|" + vis.Key;
        }
        try
        {
            var g = (await views.GridAsync(new GridQuery(spec, p, scopeKey + "|search", new GridRequest { Search = Q, Size = 25 }), ct)).Data;
            Sections.Add(new SearchSection(key, title, g.Rows.Take(Shown).Select(hit).ToList(), g.Total, allLink + Uri.EscapeDataString(Q!)));
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            log.LogWarning(ex, "search: {Section} could not be read", key);
            Sections.Add(new SearchSection(key, title, Array.Empty<SearchHit>(), 0, null, "Could not be searched just now."));
        }
    }

    private async Task PeopleSection(DepartmentAccess access, CancellationToken ct)
    {
        try
        {
            var people = (await departments.MembersAsync(null, ct))
                .Where(m => access.Sees(m.DepartmentId))
                .Where(m => m.DisplayName.Contains(Q!, StringComparison.OrdinalIgnoreCase) || (m.Mail?.Contains(Q!, StringComparison.OrdinalIgnoreCase) ?? false))
                .GroupBy(m => (m.Mail ?? m.DisplayName).ToLowerInvariant()).Select(g => g.First()).ToList();
            Sections.Add(new SearchSection("people", "People", people.Take(Shown)
                .Select(m => new SearchHit(m.DisplayName, Detail(m.Mail, m.Role, m.IsExternal ? "external" : null), "/Departments/Detail?id=" + m.DepartmentId.ToString(CultureInfo.InvariantCulture)))
                .ToList(), people.Count, null));
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            log.LogDebug(ex, "search: people could not be read");
            Sections.Add(new SearchSection("people", "People", Array.Empty<SearchHit>(), 0, null, "Could not be searched just now."));
        }
    }

    private async Task ReportSection(DepartmentAccess access, CancellationToken ct)
    {
        if (!access.Unrestricted) return;   // the report catalog is a page of the whole install
        try
        {
            if (!await reports.SchemaAsync(ct)) return;
            var all = SI.Management.Web.Pages.Reports.IndexModel.All(await reports.LoadAsync(ct));
            var (rows, total) = SI.Management.Web.Pages.Reports.IndexModel.Query(all, Q, null, null, null, null, false, 1, 25);
            Sections.Add(new SearchSection("reports", "Reports", rows.Take(Shown)
                .Select(r => new SearchHit(r.Name, Detail(r.Domain, r.Item.Enabled ? null : "switched off"), "/Reports/Report?name=" + Uri.EscapeDataString(r.Name))).ToList(),
                total, "/Reports?q=" + Uri.EscapeDataString(Q!)));
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            log.LogDebug(ex, "search: reports could not be read");
            Sections.Add(new SearchSection("reports", "Reports", Array.Empty<SearchHit>(), 0, null, "Could not be searched just now."));
        }
    }
}
