using System.Globalization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Core.ProData;
using SI.Management.Web.Auth;
using SI.Management.Web.Exemptions;

namespace SI.Management.Web.Pages.Exemptions;

/// <summary>
/// "Request exemption" for 1..N findings -- the rows SELECTED in the findings browser or a collection view, or ALL the
/// rows matching its current filter. The page re-reads those findings itself from where they were selected (the
/// selection and the filter travel, never the findings' details), shows what will be requested -- one request per
/// security domain, or per category where the category has its own owners (#283) -- and exactly who each request is
/// asked of, and asks for the reason, the period and (optionally) the approver. Someone who may decide a request may
/// approve it in the same step. Nothing applies before it is approved.
/// </summary>
public sealed class RequestModel : PageModel
{
    public const string FromFindings = "findings";
    public const string FromRows = "rows";
    private static readonly string[] FindingKeys = ["c", "tier", "sev", "dom", "rep", "kind", "q"];

    private readonly ExemptionWorkflow _flow;
    private readonly IProDataQueries _findings;
    private readonly ICollectionViews _views;
    private readonly ILogger<RequestModel> _log;

    public RequestModel(ExemptionWorkflow flow, IProDataQueries findings, ICollectionViews views, ILogger<RequestModel> log)
    { _flow = flow; _findings = findings; _views = views; _log = log; }

    /// Where the selection came from and what it was: (name, value) pairs, carried as hidden "o.*" fields.
    public List<(string Key, string Value)> Origin { get; } = new();
    public string Source => Get("src") == FromRows ? FromRows : FromFindings;
    public bool All => Get("all") == "1";
    public IReadOnlyList<FindingRef> Items { get; private set; } = Array.Empty<FindingRef>();
    public long Matching { get; private set; }
    public string? Error { get; private set; }
    public IReadOnlyList<string> Problems { get; private set; } = Array.Empty<string>();
    public ExemptionSettings.Values Settings { get; private set; } = ExemptionSettings.Values.Defaults;
    public Roster Roster { get; private set; } = new(Array.Empty<DomainRoleRow>());
    public IReadOnlyList<(string Domain, int Findings)> Domains => Items.GroupBy(i => DomainRoles.Normalize(i.Domain)).Select(g => (g.Key, g.Count())).OrderBy(x => x.Key).ToList();
    /// #283: the requests this will make -- one per domain, or per category where the category has its own owners --
    /// each with exactly who will be asked (the most specific owners) and who else may decide.
    public IReadOnlyList<ExemptionWorkflow.RequestGroup> Groups => ExemptionWorkflow.Groups(Roster, Items);
    /// Everyone who may decide at least one of the requests -- the requester may name one of them.
    public IReadOnlyList<string> Approvers => Groups.SelectMany(g => g.Deciders).Distinct().OrderBy(x => x, StringComparer.Ordinal).ToList();
    public IReadOnlyList<ExemptionWorkflow.RequestGroup> MineToDecide => Groups.Where(g => ExemptionWorkflow.CanDecide(User, Roster, g.Domain, g.Category)).ToList();
    public bool MayApproveAny => MineToDecide.Count > 0;
    public string Back => Source == FromRows
        ? (Get("from") is { } p && p.StartsWith("/Collection/", StringComparison.Ordinal) ? p : "/Collection/Rows") + "?" + Query(k => k is not ("src" or "all" or "from"))
        : "/Findings?" + Query(k => FindingKeys.Contains(k));

    [BindProperty] public string Scope { get; set; } = "finding";
    [BindProperty] public string? Reason { get; set; }
    [BindProperty] public string? Period { get; set; }
    [BindProperty] public DateTime? CustomDate { get; set; }
    [BindProperty] public string? Approver { get; set; }
    [BindProperty] public bool ApproveNow { get; set; }

    private string? Get(string k) => Origin.FirstOrDefault(o => string.Equals(o.Key, k, StringComparison.OrdinalIgnoreCase)).Value;
    private IEnumerable<string> GetAll(string k) => Origin.Where(o => string.Equals(o.Key, k, StringComparison.OrdinalIgnoreCase)).Select(o => o.Value);
    private string Query(Func<string, bool> keep) => string.Join("&", Origin.Where(o => keep(o.Key)).Select(o => Uri.EscapeDataString(o.Key) + "=" + Uri.EscapeDataString(o.Value)));

    private static bool Carried(string k) =>
        k is "src" or "all" or "c" or "tier" or "sev" or "dom" or "rep" or "kind" or "q" or "key" or "sort" or "dir" or "from" or SI.Management.Core.ProData.Exempted.QueryKey
        || k.Equals("sel", StringComparison.OrdinalIgnoreCase) || k.StartsWith("f.", StringComparison.OrdinalIgnoreCase);

    private void ReadOrigin(IEnumerable<KeyValuePair<string, Microsoft.Extensions.Primitives.StringValues>> pairs, string prefix)
    {
        foreach (var kv in pairs)
        {
            if (!kv.Key.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) continue;
            var k = kv.Key[prefix.Length..];
            if (!Carried(k)) continue;
            foreach (var v in kv.Value) if (!string.IsNullOrWhiteSpace(v) && v.Length <= 400) Origin.Add((k.Equals("sel", StringComparison.OrdinalIgnoreCase) ? "sel" : k, v!));
        }
    }

    private async Task LoadAsync(CancellationToken ct)
    {
        Settings = await _flow.SettingsAsync(ct);
        Period ??= ExemptionPeriods.DefaultChoice(Settings.DefaultMonths);
        try
        {
            if (!await _flow.ReadyAsync(ct)) { Error = "This database does not have the exemption request tables yet: run the Pro settings setup (setup\\Import-SIProSettings.ps1 -- it only adds)."; return; }
            Roster = await _flow.RosterAsync(ct);
            (Items, Matching) = await ResolveAsync(ct);
            Items = await _flow.WithCategoriesAsync(Items, ct);
            await AuditBulkRefusalAsync();
            if (Items.Count == 0 && Error is null) Error = All ? "No finding matches this filter." : "Select at least one finding first.";
        }
        catch (ArgumentException ex) { Error = "The selection is not valid: " + ex.Message; }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "resolving the findings of an exemption request failed");
            Error = "The selected findings could not be read: " + ex.Message;
        }
    }

    /// #264: why a request for "all matching" was refused (null = it was not, or it was not one).
    public string? BulkRefused { get; private set; }

    /// The audit action of a request for "all matching" the bulk guard refused (#260 / #264).
    public const string BulkRefuseAction = "exemption.bulk.refuse";

    /// The refused bulk request outside an audited handler (GET, Prepare): exactly one 'refused' row of its own.
    private async Task AuditBulkRefusalAsync()
    {
        if (BulkRefused is null || SI.Management.Web.Audit.AuditScope.Current is not null) return;
        var writer = HttpContext?.RequestServices.GetService<SI.Management.Web.Audit.IAuditWriter>();
        if (writer is null) return;
        var scope = new SI.Management.Web.Audit.AuditScope(BulkRefuseAction, SI.Management.Web.Audit.AuditScope.ActorOf(User), SI.Management.Web.Audit.AuditScope.SourceOf(User))
        {
            Target = "exemption request (all matching, " + Source + ")",
            AfterJson = System.Text.Json.JsonSerializer.Serialize(new SortedDictionary<string, object?>(StringComparer.Ordinal)
            {
                ["matching"] = Matching,
                ["origin"] = Origin.Select(o => o.Key + "=" + o.Value).ToList(),
            }),
        };
        await writer.WriteAsync(scope.ToRecord(SI.Management.Web.Audit.AuditOutcomes.Refused, BulkRefused), CancellationToken.None);
    }

    /// The bulk guard, server-side: an "all matching" request needs a narrowing filter and at most SIWeb_Exemption_BulkMax
    /// findings. A crafted request (no filter, or over the maximum) is refused with the reason and logged.
    private (IReadOnlyList<FindingRef>, long) Refuse(string reason, long matching)
    {
        BulkRefused = reason;
        Error = reason;
        // #260 AUDIT-1: a refusal is audited. Inside an audited handler (Submit) the filter's ONE row carries it, under
        // the bulk guard's own action; outside one (the form opened by GET or by Prepare) LoadAsync writes the row.
        if (SI.Management.Web.Audit.AuditScope.Current is { } scope)
        {
            scope.Action = BulkRefuseAction;
            scope.Refused(reason);
        }
        _log.LogWarning("exemption request for all matching refused for {User}: {Reason} ({Matching} matching; origin {Origin})", User.Identity?.Name, reason, matching,
            string.Join("&", Origin.Select(o => o.Key + "=" + o.Value)));
        return (Array.Empty<FindingRef>(), matching);
    }

    /// The findings the selection or the filter names -- read again from the database, bounded. A finding already
    /// exempted (it carries the mark) is never requested again (#264).
    private async Task<(IReadOnlyList<FindingRef>, long)> ResolveAsync(CancellationToken ct)
    {
        var schema = HttpContext?.RequestServices.GetService<IExemptedSchema>();
        using var _ = SI.Management.Core.ProData.Exempted.Use(schema is not null && await schema.ReadyAsync(ct) ? SI.Management.Core.ProData.ExemptedScope.Exclude : null);
        var max = All ? Math.Min(ExemptionWorkflow.MaxItems, Settings.BulkMax) : ExemptionWorkflow.MaxItems;
        if (Source == FromRows)
        {
            var cols = (await _views.CollectionsAsync(ct)).Data;
            var c = Get("c");
            var cur = c is null ? cols.FirstOrDefault() : cols.FirstOrDefault(x => x.CollectionId == c);
            if (cur is null) { Error = "That collection is not in the Pro database."; return (Array.Empty<FindingRef>(), 0); }
            var filters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var g in Origin.Where(o => o.Key.StartsWith("f.", StringComparison.OrdinalIgnoreCase)).GroupBy(o => o.Key[2..], StringComparer.OrdinalIgnoreCase))
                filters[g.Key] = string.Join("|", g.Select(x => x.Value));
            var sel = All ? new List<string>() : GetAll("sel").ToList();
            if (!All && sel.Count == 0) return (Array.Empty<FindingRef>(), 0);
            var key = Get("key");
            if (All && filters.Count == 0 && string.IsNullOrWhiteSpace(Get("q")) && string.IsNullOrWhiteSpace(key))
                return Refuse(ExemptionBulkGuard.Check(false, 0, max).Reason!, 0);
            var q = new GridQuery(CollectionViewSql.Rows,
                new Dictionary<string, object?> { ["CollectionId"] = cur.CollectionId, ["AssetKey"] = key is null ? null : ProDataFilters.AssetKey(key) },
                cur.Version, new GridRequest { Search = Get("q"), Filters = filters, Selected = sel, Size = 50 });
            var page = (await _views.ExportAsync(q, ct)).Data;
            if (All && ExemptionBulkGuard.Check(true, page.Total, max) is { Allowed: false } v && page.Total > 0) return Refuse(v.Reason!, page.Total);
            if (page.Total > max) { Error = $"{Fmt.Int(page.Total)} findings match -- at most {Fmt.Int(max)} can be requested at once. Narrow the filter."; return (Array.Empty<FindingRef>(), page.Total); }
            string? S(IReadOnlyDictionary<string, object?> r, string k) => r.TryGetValue(k, out var v) && v is not null ? Convert.ToString(v, CultureInfo.InvariantCulture) : null;
            return (page.Rows.Select(r => new FindingRef(S(r, "FindingId") ?? "", S(r, "AssetKey") ?? "", S(r, "AssetName"), S(r, "ReportName"), S(r, "Cve"),
                S(r, "ConfigurationId"), S(r, "SecurityDomain"), S(r, "Title"))).ToList(), page.Total);
        }
        var c2 = Get("c");
        if (All)
        {
            if (!ExemptionBulkGuard.Narrows(Get("tier"), Get("sev"), Get("dom"), Get("rep"), Get("kind"), Get("q")))
                return Refuse(ExemptionBulkGuard.Check(false, 0, max).Reason!, 0);
            var f = ProDataFilters.Normalize(new FindingFilter
            {
                CollectionId = c2, Tier = Get("tier"), Severity = Get("sev"), Domain = Get("dom"), Report = Get("rep"), AssetKind = Get("kind"), Text = Get("q"),
                // #855 the lifecycle the findings browser listed (default active)
                Lifecycle = SI.Management.Core.ProData.LifecycleFilter.Parse(new[] { Get("lifecycle") }),
            });
            var rows = (await _findings.ExportAsync(f, max + 1, ct)).Data;
            if (rows.Count > max) return Refuse(ExemptionBulkGuard.Check(true, rows.Count, max).Reason!.Replace(Fmt.Int(rows.Count) + " findings match", "More than " + Fmt.Int(max) + " findings match"), rows.Count);
            return (rows.Select(Ref).ToList(), rows.Count);
        }
        var list = new List<FindingRef>();
        foreach (var id in GetAll("sel").Distinct().Take(GridSql.MaxSelected))
            if ((await _findings.FindingAsync(c2, id, ct)).Data is { } d) list.Add(Ref(d.Finding));
        return (list, list.Count);
    }

    private static FindingRef Ref(FindingRow r) => new(r.FindingId, r.AssetKey, r.AssetName, r.ReportName, r.Cve, r.ConfigurationId, r.SecurityDomain, r.Title, r.Category);

    /// From a link: the grid's "request for these / for all matching", a finding's page.
    public async Task OnGetAsync(CancellationToken ct)
    {
        ReadOrigin(Request.Query, "");
        await LoadAsync(ct);
    }

    /// From the findings browser's selection form (a POST: it carries the antiforgery token of that page).
    [SI.Management.Web.Audit.NotAudited("prepares the request form from a selection: nothing is written until Submit")]
    public async Task OnPostPrepareAsync(CancellationToken ct)
    {
        Origin.Add(("src", FromFindings));
        foreach (var k in FindingKeys) if (Request.Form[k].ToString() is { Length: > 0 } v) Origin.Add((k, v));
        foreach (var v in Request.Form["Sel"]) if (!string.IsNullOrWhiteSpace(v)) Origin.Add(("sel", v!));
        if (Request.Form["all"] == "1") Origin.Add(("all", "1"));
        await LoadAsync(ct);
    }

    [SI.Management.Web.Audit.Audited("exemption.request.submit")]
    public async Task<IActionResult> OnPostSubmitAsync(CancellationToken ct)
    {
        ReadOrigin(Request.Form, "o.");
        await LoadAsync(ct);
        if (Error is not null) return Page();
        var form = new RequestForm(Scope, Reason ?? "", Period, CustomDate, Approver, ApproveNow);
        var r = await _flow.RequestAsync(User, form, Items, Source == FromRows ? "collection" : "findings", ct);
        if (!r.Ok) { Problems = r.Problems.Concat(r.Notes).ToList(); return Page(); }
        var ids = string.Join(", ", r.Requests.Select(x => "#" + x.RequestId.ToString(CultureInfo.InvariantCulture)));
        TempData["toast"] = (r.Approved > 0
                ? $"{Fmt.Int(r.Approved)} exemption(s) approved by you and written ({ids}) -- they apply from the next run."
                : $"Requested: {Fmt.Int(r.Items)} finding(s) in {Fmt.Int(r.Requests.Count)} request(s) ({ids}). An approver decides; nothing applies before that.")
            + (r.Problems.Count > 0 ? $" {Fmt.Int(r.Problems.Count)} not requested: {r.Problems[0]}" : "")
            + (r.Notes.Count > 0 ? " " + r.Notes[0] : "");
        TempData["toastKind"] = r.Problems.Count > 0 ? "warn" : "ok";
        return Redirect("/Exemptions?view=mine");
    }
}
