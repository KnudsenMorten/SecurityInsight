using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using SI.Management.Core.ProData;
using SI.Management.Web.Audit;
using SI.Management.Web.Auth;
using SI.Management.Web.Changes;
using SI.Management.Web.Reports;
using SI.Management.Web.Settings;
using ItemWrite = SI.Management.Core.ProData.ItemWrite; // the report designer's write (not the editors' Changes.ItemWrite)

namespace SI.Management.Web.Pages.Reports;

/// <summary>
/// The report templates builder (#274 part 2): the catalog on the left, the template's reports on the right -- drag to add,
/// reorder and remove, with buttons and Alt+Up / Alt+Down / Delete as the keyboard equivalents (wwwroot/js/app/reports.js
/// keeps the draft; every list change ends in <see cref="TemplateBuilder"/>'s operations on the server). Create, copy,
/// rename (your own templates) and retire templates; shows which Risk Analysis job runs each one. All staged.
/// </summary>
public sealed class TemplatesModel : ReportsPage
{
    private readonly ISettingsStoreReader _settings;
    public TemplatesModel(IReportStore store, ChangeService changes, ISettingsStoreReader settings, ILogger<TemplatesModel> log) : base(store, changes, log) => _settings = settings;

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    [BindProperty(SupportsGet = true)] public string? Name { get; set; }
    [BindProperty] public string? Draft { get; set; }
    [BindProperty] public string? Purpose { get; set; }
    [BindProperty] public string? NewName { get; set; }

    public ReportItem? Selected { get; private set; }
    public IReadOnlyList<string> Included { get; private set; } = Array.Empty<string>();
    /// Template name -> the job(s) that run it.
    public IReadOnlyDictionary<string, string> Jobs { get; private set; } = new Dictionary<string, string>();

    /// The jobs in plain words (#312): the Container Apps job's resource name is never in the page's text, only in a tooltip.
    public const string SummaryJob = "the Summary report job";
    public const string DetailedJob = "the Detailed report job";
    private static readonly (string Job, string Resource)[] JobResource =
    {
        (SummaryJob, "caj-si-risk-analysis"), (DetailedJob, "caj-si-risk-analysis-detailed"),
    };

    /// "the Summary report job" -> "Summary report job" (a table cell, not a sentence); two jobs are listed with a comma.
    public static string JobCell(string jobs) => jobs.Replace("the ", "", StringComparison.Ordinal).Replace(" and ", ", ", StringComparison.Ordinal);
    /// The technical job name(s), for a tooltip only.
    public static string JobTooltip(string jobs) => "Container Apps job: " + string.Join(", ", JobResource.Where(j => jobs.Contains(j.Job, StringComparison.Ordinal)).Select(j => j.Resource));
    /// The template's kind in plain words: shipped with SecurityInsight, shipped and changed here, or made here.
    public static string KindLabel(ReportOrigin o) => o switch { ReportOrigin.Vendor => "Built-in", ReportOrigin.Changed => "Built-in, changed", _ => "Your own" };
    /// Is this report in the template being edited? (the catalog shows it as added)
    public bool IsIncluded(string report) => Included.Contains(report, StringComparer.Ordinal);

    public async Task OnGetAsync(CancellationToken ct)
    {
        if (!await LoadAsync(ct)) return;
        await PrepareAsync(ct);
    }

    private async Task PrepareAsync(CancellationToken ct)
    {
        Jobs = await JobsAsync(ct);
        Selected = (Name is { Length: > 0 } ? State!.Find("template/" + Name) : null) ?? State!.Templates.FirstOrDefault();
        Name = Selected?.Name;
        Included = Selected is null ? Array.Empty<string>() : ReportBody.Included(Selected.Json);
    }

    /// Which Risk Analysis job runs which template: the customer's defaults (RiskAnalysis_ReportTemplate_Default_Summary /
    /// _Detailed), else RiskAnalysis_Summary / RiskAnalysis_Detailed -- as Get-SIRiskAnalysisJobPlan decides.
    public async Task<IReadOnlyDictionary<string, string>> JobsAsync(CancellationToken ct)
    {
        string? Val(IReadOnlyList<SettingRow> rows, string n)
        {
            var r = rows.FirstOrDefault(x => x.Name == n && !string.IsNullOrWhiteSpace(x.ValueJson));
            if (r is null) return null;
            try { return JsonSerializer.Deserialize<string>(r.ValueJson!); } catch (JsonException) { return r.ValueJson!.Trim('"'); }
        }
        IReadOnlyList<SettingRow> rows = Array.Empty<SettingRow>();
        try { rows = (await _settings.ReadSettingsAsync(ct)).Rows; } catch (Exception ex) when (ex is not OperationCanceledException) { Log.LogWarning(ex, "settings could not be read"); }
        var sum = Val(rows, "RiskAnalysis_ReportTemplate_Default_Summary") ?? "RiskAnalysis_Summary";
        var det = Val(rows, "RiskAnalysis_ReportTemplate_Default_Detailed") ?? "RiskAnalysis_Detailed";
        var d = new Dictionary<string, string>(StringComparer.Ordinal) { [sum] = SummaryJob };
        d[det] = d.TryGetValue(det, out var x) ? x + " and " + DetailedJob : DetailedJob;
        return d;
    }

    private IReadOnlyList<string>? ReadDraft()
    {
        try
        {
            var l = JsonSerializer.Deserialize<List<string>>(Draft ?? "[]", Json) ?? new List<string>();
            return l.Where(n => !string.IsNullOrWhiteSpace(n)).Select(n => n.Trim()).Distinct(StringComparer.Ordinal).ToList();
        }
        catch (JsonException) { Messages.Add("Not staged: the template's reports could not be read -- reload the page"); return null; }
    }

    private IReadOnlyList<string> Unknown(IReadOnlyList<string> names)
    {
        var known = State!.Reports.Select(r => r.Name).ToHashSet(StringComparer.Ordinal);
        return names.Where(n => !known.Contains(n)).ToList();
    }

    private async Task<IActionResult> Done(IActionResult? staged, CancellationToken ct) { if (staged is not null) return staged; await PrepareAsync(ct); return Page(); }

    /// Save the selected template's reports (and purpose).
    [Audited("report.template.change")]
    public async Task<IActionResult> OnPostStageAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        if (!await LoadAsync(ct)) return Page();
        var t = State!.Find("template/" + (Name ?? ""));
        if (t is null) { Messages.Add("Not staged: choose a template"); return await Done(null, ct); }
        var draft = ReadDraft();
        if (draft is null) return await Done(null, ct);
        if (draft.Count == 0) { Messages.Add("Not staged: a template needs at least one report (retire it instead)"); return await Done(null, ct); }
        // a name the template already held stays allowed (Risk Analysis skips a report that is not in the catalog); a NEW one
        // must be a report of the catalog
        var held = ReportBody.Included(t.Json).ToHashSet(StringComparer.Ordinal);
        if (Unknown(draft).Where(n => !held.Contains(n)).ToList() is { Count: > 0 } bad) { Messages.Add("Not staged: not reports of this catalog: " + string.Join(", ", bad)); return await Done(null, ct); }
        var body = ReportBody.WithReports(t.Body, draft, Purpose is null ? null : Purpose.Trim());
        var w = ItemWrites.For("rareport", t.Key, t.TemplateBody, t.OverrideState, t.OverrideBody, body, true, $"{draft.Count} report(s): {string.Join(", ", draft.Take(8))}{(draft.Count > 8 ? ", ..." : "")}");
        return await Done(await StageAsync(ReportChanges.Template, $"Report template {t.Name}: {draft.Count} report(s)", w is null ? Array.Empty<ItemWrite>() : new[] { w }, ct), ct);
    }

    private string? NewNameProblem()
    {
        var n = NewName?.Trim() ?? "";
        if (!ReportVocabulary.Name.IsMatch(n)) return "the name must be 1 to 100 letters, digits or _";
        if (State!.Find("template/" + n) is not null || State.Find("report/" + n) is not null) return $"'{n}' is already a report or template name";
        return null;
    }

    [Audited("report.template.change")]
    public async Task<IActionResult> OnPostCreateAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        if (!await LoadAsync(ct)) return Page();
        if (NewNameProblem() is { } p) { Messages.Add("Not staged: " + p); return await Done(null, ct); }
        var draft = ReadDraft() ?? Array.Empty<string>();
        if (draft.Count == 0) { Messages.Add("Not staged: drag at least one report into the new template"); return await Done(null, ct); }
        if (Unknown(draft) is { Count: > 0 } bad) { Messages.Add("Not staged: not reports of this catalog: " + string.Join(", ", bad)); return await Done(null, ct); }
        var n = NewName!.Trim();
        var body = ReportBody.NewTemplate(n, string.IsNullOrWhiteSpace(Purpose) ? n : Purpose.Trim(), draft);
        var w = new ItemWrite("rareport", "template/" + n, "override", body, "", $"new template, {draft.Count} report(s)");
        return await Done(await StageAsync(ReportChanges.Template, $"New report template {n}", new[] { w }, ct), ct);
    }

    [Audited("report.template.change")]
    public async Task<IActionResult> OnPostCopyAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        if (!await LoadAsync(ct)) return Page();
        var t = State!.Find("template/" + (Name ?? ""));
        if (t is null) { Messages.Add("Not staged: choose the template to copy"); return await Done(null, ct); }
        if (NewNameProblem() is { } p) { Messages.Add("Not staged: " + p); return await Done(null, ct); }
        var n = NewName!.Trim();
        var w = new ItemWrite("rareport", "template/" + n, "override", ReportBody.Renamed(t.Body, n), "", $"a copy of {t.Name}");
        return await Done(await StageAsync(ReportChanges.Template, $"Copy report template {t.Name} as {n}", new[] { w }, ct), ct);
    }

    [Audited("report.template.change")]
    public async Task<IActionResult> OnPostRenameAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        if (!await LoadAsync(ct)) return Page();
        var t = State!.Find("template/" + (Name ?? ""));
        if (t is null) { Messages.Add("Not staged: choose the template to rename"); return await Done(null, ct); }
        if (t.Origin != ReportOrigin.Own) { Messages.Add("Not staged: a vendor template keeps its name (jobs and other installs refer to it) -- copy it under a new name instead"); return await Done(null, ct); }
        if (NewNameProblem() is { } p) { Messages.Add("Not staged: " + p); return await Done(null, ct); }
        var n = NewName!.Trim();
        var writes = new[]
        {
            new ItemWrite("rareport", "template/" + n, "override", ReportBody.Renamed(t.Body, n), "", $"renamed from {t.Name}"),
            new ItemWrite("rareport", t.Key, "inherit", null, t.ExpectedOld, $"renamed to {n}"),
        };
        if (Jobs.Count == 0) Jobs = await JobsAsync(ct);
        if (Jobs.ContainsKey(t.Name)) Messages.Add($"Note: {t.Name} is run by {Jobs[t.Name]} -- change the job's template setting to {n} too");
        return await Done(await StageAsync(ReportChanges.Template, $"Rename report template {t.Name} to {n}", writes, ct), ct);
    }

    [Audited("report.template.change")]
    public async Task<IActionResult> OnPostRetireAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        if (!await LoadAsync(ct)) return Page();
        var t = State!.Find("template/" + (Name ?? ""));
        if (t is null) { Messages.Add("Not staged: choose the template to retire"); return await Done(null, ct); }
        var jobs = await JobsAsync(ct);
        if (jobs.TryGetValue(t.Name, out var job)) { Messages.Add($"Not staged: {t.Name} is run by {job} -- point the job at another template first"); return await Done(null, ct); }
        var w = ItemWrites.For("rareport", t.Key, t.TemplateBody, t.OverrideState, t.OverrideBody, t.Body, false, "retired");
        return await Done(await StageAsync(ReportChanges.Template, $"Retire report template {t.Name}", w is null ? Array.Empty<ItemWrite>() : new[] { w }, ct), ct);
    }

    public string CatalogJson() => JsonSerializer.Serialize(State?.Reports.Select(r => new { name = r.Name, domain = ReportBody.Text(r.Json, "SecurityDomain"), on = r.Enabled }) ?? Enumerable.Empty<object>(), Json);
    public string DraftJson() => JsonSerializer.Serialize(Included, Json);
}
