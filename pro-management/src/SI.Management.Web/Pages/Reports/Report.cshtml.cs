using Microsoft.AspNetCore.Mvc;
using SI.Management.Core.ProData;
using SI.Management.Web.Audit;
using SI.Management.Web.Auth;
using SI.Management.Web.Changes;
using SI.Management.Web.Reports;
using ItemWrite = SI.Management.Core.ProData.ItemWrite; // the report designer's write (not the editors' Changes.ItemWrite)

namespace SI.Management.Web.Pages.Reports;

/// <summary>
/// One report (#274 part 1): purpose, domain, source tables, the query and the report contract; an Admin ticks its
/// severity and tier scope, switches it on / off, or puts it back to the vendor's -- staged for Review &amp; commit.
/// </summary>
public sealed class ReportModel : ReportsPage
{
    private readonly IReportQueryRunner _runner;
    public ReportModel(IReportStore store, ChangeService changes, IReportQueryRunner runner, ILogger<ReportModel> log) : base(store, changes, log) => _runner = runner;

    [BindProperty(SupportsGet = true)] public string? Name { get; set; }
    [BindProperty] public List<string> Severities { get; set; } = new();
    [BindProperty] public List<string> Tiers { get; set; } = new();
    [BindProperty] public bool Enabled { get; set; } = true;

    public ReportItem? Item { get; private set; }
    public ReportTestResult? Test { get; private set; }
    public bool Runnable => _runner.Configured;

    private bool Find()
    {
        Item = State?.Find("report/" + (Name ?? ""));
        return Item is not null;
    }

    public async Task<IActionResult> OnGetAsync(CancellationToken ct)
    {
        if (!await LoadAsync(ct)) return Page();
        if (!Find()) return NotFound();
        return Page();
    }

    /// The write the form's scope and switch make (null = nothing changes).
    public static ItemWrite? WriteFor(ReportItem it, IEnumerable<string> severities, IEnumerable<string> tiers, bool enabled)
    {
        var sev = severities.ToList(); var tl = tiers.ToList();
        var body = ReportBody.WithScope(it.Body, sev, tl);
        var describe = !enabled ? "switched off (left out of every template)"
            : $"severity {string.Join(", ", ReportVocabulary.Severities.Where(s => sev.Contains(s, StringComparer.OrdinalIgnoreCase)))}; tier {string.Join(", ", ReportVocabulary.Tiers.Where(t => tl.Contains(t, StringComparer.OrdinalIgnoreCase)))}";
        return ItemWrites.For("rareport", it.Key, it.TemplateBody, it.OverrideState, it.OverrideBody, body, enabled, describe);
    }

    [Audited("report.scope.change")]
    public async Task<IActionResult> OnPostStageAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        if (!await LoadAsync(ct)) return Page();
        if (!Find()) return NotFound();
        if (Enabled && Severities.Count == 0) { Messages.Add("Not staged: tick at least one severity -- a report with no severity reports nothing (switch it off instead)"); return Page(); }
        if (Enabled && Tiers.Count == 0) { Messages.Add("Not staged: tick at least one tier -- a report with no tier reports nothing (switch it off instead)"); return Page(); }
        var w = WriteFor(Item!, Severities, Tiers, Enabled);
        var staged = await StageAsync(ReportChanges.Catalog, $"Report {Item!.Name}: {(w?.Describe ?? "")}", w is null ? Array.Empty<ItemWrite>() : new[] { w }, ct);
        return staged ?? Page();
    }

    [Audited("report.scope.change")]
    public async Task<IActionResult> OnPostResetAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        if (!await LoadAsync(ct)) return Page();
        if (!Find()) return NotFound();
        if (Item!.TemplateBody is null) { Messages.Add("Not staged: this report is yours -- there is no vendor report to go back to (remove it on Custom reports)"); return Page(); }
        var w = ItemWrites.For("rareport", Item.Key, Item.TemplateBody, Item.OverrideState, Item.OverrideBody, Item.TemplateBody, true, "back to the vendor's report");
        var staged = await StageAsync(ReportChanges.Catalog, $"Report {Item.Name}: back to the vendor's", w is null ? Array.Empty<ItemWrite>() : new[] { w }, ct);
        return staged ?? Page();
    }

    /// Run the report's query read-only (capped, timed out) and check its rows against the contract.
    [Audited("report.custom.test")]
    public async Task<IActionResult> OnPostTestAsync(CancellationToken ct)
    {
        if (AuditScope.Current is { } audit) audit.WhatIf = true;   // read-only: never read as a change
        if (!User.IsAdmin()) return Forbid();
        if (!await LoadAsync(ct)) return Page();
        if (!Find()) return NotFound();
        Test = await _runner.RunAsync(ReportBody.Query(Item!.Json), ct);
        return Page();
    }
}
