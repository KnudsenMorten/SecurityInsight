using Microsoft.AspNetCore.Mvc;
using SI.Management.Core.ProData;
using SI.Management.Web.Audit;
using SI.Management.Web.Auth;
using SI.Management.Web.Changes;
using SI.Management.Web.Reports;
using ItemWrite = SI.Management.Core.ProData.ItemWrite; // the report designer's write (not the editors' Changes.ItemWrite)

namespace SI.Management.Web.Pages.Reports;

/// <summary>
/// Custom reports (#274 part 3): a report from your own KQL query. The editor shows the report contract (from the engine);
/// Test runs the query READ-ONLY against the workspace (capped, timed out) and checks its rows against the contract; Save
/// stages it as your own report/&lt;name&gt; and links it into the templates you tick -- one change. Only an Admin creates;
/// Readers see your reports read-only.
/// </summary>
public sealed class CustomModel : ReportsPage
{
    private readonly IReportQueryRunner _runner;
    public CustomModel(IReportStore store, ChangeService changes, IReportQueryRunner runner, ILogger<CustomModel> log) : base(store, changes, log) => _runner = runner;

    [BindProperty(SupportsGet = true)] public string? Name { get; set; }
    [BindProperty] public string? Purpose { get; set; }
    [BindProperty] public string? Domain { get; set; }
    [BindProperty] public string? Query { get; set; }
    [BindProperty] public List<string> Severities { get; set; } = new();
    [BindProperty] public List<string> Tiers { get; set; } = new();
    [BindProperty] public List<string> LinkTo { get; set; } = new();

    public ReportTestResult? Test { get; private set; }
    public ReportItem? Existing { get; private set; }
    public bool Runnable => _runner.Configured;
    public IEnumerable<ReportItem> Mine => State?.Reports.Where(r => r.Origin == ReportOrigin.Own) ?? Enumerable.Empty<ReportItem>();

    public async Task OnGetAsync(CancellationToken ct)
    {
        if (!await LoadAsync(ct)) return;
        Existing = Name is { Length: > 0 } ? State!.Find("report/" + Name) : null;
        if (Existing is { Origin: ReportOrigin.Own } e)
        {
            var o = e.Json;
            Purpose = ReportBody.Text(o, "ReportPurpose"); Domain = ReportBody.Text(o, "SecurityDomain"); Query = ReportBody.Query(o);
            Severities = ReportBody.List(o, "SecuritySeverityScope").ToList(); Tiers = ReportBody.List(o, "CriticalityTierLevelScope").ToList();
            LinkTo = State.Templates.Where(t => ReportBody.Included(t.Json).Contains(e.Name)).Select(t => t.Name).ToList();
        }
        else
        {
            Existing = null;
            Severities = ReportVocabulary.Severities.ToList(); Tiers = ReportVocabulary.Tiers.ToList();
        }
    }

    [Audited("report.custom.test")]
    public async Task<IActionResult> OnPostTestAsync(CancellationToken ct)
    {
        if (AuditScope.Current is { } audit) audit.WhatIf = true;   // read-only: never read as a change
        if (!User.IsAdmin()) return Forbid();
        if (!await LoadAsync(ct)) return Page();
        Existing = Name is { Length: > 0 } ? State!.Find("report/" + Name) : null;
        Test = await _runner.RunAsync(Query ?? "", ct);
        return Page();
    }

    /// The writes Save makes: the report (new or changed) and its link into every ticked template / out of every unticked one.
    public static (IReadOnlyList<ItemWrite> Writes, IReadOnlyList<string> Problems) SaveWrites(ReportState s, string? name, string? purpose, string? domain, string? query,
        IReadOnlyList<string> severities, IReadOnlyList<string> tiers, IReadOnlyList<string> linkTo)
    {
        var why = new List<string>();
        var n = name?.Trim() ?? "";
        if (!ReportVocabulary.Name.IsMatch(n)) why.Add("the name must be 1 to 100 letters, digits or _");
        var existing = s.Find("report/" + n);
        if (existing is not null && existing.Origin != ReportOrigin.Own) why.Add($"'{n}' is a vendor report -- give yours another name (a vendor report's scope is changed on the catalog)");
        if (s.Find("template/" + n) is not null) why.Add($"'{n}' is a template name");
        if (!ReportVocabulary.Domains.Contains(domain ?? "", StringComparer.Ordinal)) why.Add("choose the security domain the findings belong to");
        why.AddRange(KqlReadOnly.Problems(query));
        if (severities.Count == 0) why.Add("tick at least one severity");
        if (tiers.Count == 0) why.Add("tick at least one tier");
        foreach (var t in linkTo) if (s.Find("template/" + t) is null) why.Add($"the template '{t}' does not exist");
        if (why.Count > 0) return (Array.Empty<ItemWrite>(), why);
        var writes = new List<ItemWrite>();
        var body = ReportBody.NewReport(n, string.IsNullOrWhiteSpace(purpose) ? n : purpose.Trim(), domain!, query!, severities, tiers);
        var rw = ItemWrites.For("rareport", "report/" + n, null, existing?.OverrideState, existing?.OverrideBody, body, true, existing is null ? "your new report" : "your report changed");
        if (rw is not null) writes.Add(rw);
        foreach (var t in s.Templates)
        {
            var inc = ReportBody.Included(t.Json);
            var want = linkTo.Contains(t.Name, StringComparer.Ordinal);
            if (want == inc.Contains(n)) continue;
            var list = want ? TemplateBuilder.Add(inc, n) : TemplateBuilder.Remove(inc, n);
            if (list.Count == 0) { why.Add($"taking {n} out of {t.Name} would leave it empty -- retire the template instead"); continue; }
            var w = ItemWrites.For("rareport", t.Key, t.TemplateBody, t.OverrideState, t.OverrideBody, ReportBody.WithReports(t.Body, list), t.Enabled, want ? $"{n} added" : $"{n} taken out");
            if (w is not null) writes.Add(w);
        }
        return (writes, why);
    }

    [Audited("report.custom.create")]
    public async Task<IActionResult> OnPostSaveAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        if (!await LoadAsync(ct)) return Page();
        var (writes, why) = SaveWrites(State!, Name, Purpose, Domain, Query, Severities, Tiers, LinkTo);
        if (why.Count > 0) { Messages.AddRange(why.Select(w => "Not staged: " + w)); return Page(); }
        var staged = await StageAsync(ReportChanges.Custom, $"Custom report {Name!.Trim()}{(LinkTo.Count > 0 ? " in " + string.Join(", ", LinkTo) : "")}", writes, ct);
        return staged ?? Page();
    }

    /// Remove one of your own reports (and take it out of the templates that include it).
    [Audited("report.custom.remove")]
    public async Task<IActionResult> OnPostRemoveAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        if (!await LoadAsync(ct)) return Page();
        var it = State!.Find("report/" + (Name ?? ""));
        if (it is not { Origin: ReportOrigin.Own }) { Messages.Add("Not staged: only your own reports can be removed (a vendor report is switched off on the catalog)"); return Page(); }
        var writes = new List<ItemWrite> { new("rareport", it.Key, "inherit", null, it.ExpectedOld, "removed") };
        foreach (var t in State.Templates.Where(t => ReportBody.Included(t.Json).Contains(it.Name)))
        {
            var list = TemplateBuilder.Remove(ReportBody.Included(t.Json), it.Name);
            if (list.Count == 0) { Messages.Add($"Not staged: {t.Name} holds only this report -- retire the template first"); return Page(); }
            var w = ItemWrites.For("rareport", t.Key, t.TemplateBody, t.OverrideState, t.OverrideBody, ReportBody.WithReports(t.Body, list), t.Enabled, $"{it.Name} taken out");
            if (w is not null) writes.Add(w);
        }
        var staged = await StageAsync(ReportChanges.Custom, $"Remove custom report {it.Name}", writes, ct);
        return staged ?? Page();
    }
}
