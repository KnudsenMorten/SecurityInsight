using System.Globalization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Core.ProData;
using SI.Management.Web.Audit;
using SI.Management.Web.Auth;
using SI.Management.Web.MgmtReports;

namespace SI.Management.Web.Pages.Reports;

/// <summary>
/// Configuration > Reports > Management summary (#291): the management summary reports -- sections, data,
/// recipients and schedule; preview and send now. Readers see the list; an Admin adds, changes, removes and sends.
/// </summary>
public sealed class ManagementModel(MgmtReportSender sender, SI.Management.Web.Notify.AutoReader autoReader, ILogger<ManagementModel> log) : PageModel
{
    [BindProperty(SupportsGet = true)] public long? Id { get; set; }
    [BindProperty(SupportsGet = true)] public bool New { get; set; }

    [BindProperty] public string? Name { get; set; }
    [BindProperty] public string? Grain { get; set; }
    [BindProperty] public bool Kpi { get; set; }
    [BindProperty] public bool Domains { get; set; }
    [BindProperty] public bool Timeline { get; set; }
    /// #636: the key figures blocks the report carries (every block = the default).
    [BindProperty] public List<string> KeyBlocks { get; set; } = new();
    [BindProperty] public string? Recipients { get; set; }
    [BindProperty] public string? Cadence { get; set; }
    [BindProperty] public int Day { get; set; } = 1;
    [BindProperty] public string? TimeUtc { get; set; }
    [BindProperty] public bool Enabled { get; set; } = true;

    public bool Ready { get; private set; }
    public IReadOnlyList<MgmtReport> Reports { get; private set; } = [];
    public MgmtReport? Editing { get; private set; }
    public List<string> Problems { get; } = new();
    public string? Error { get; private set; }
    public bool CanEdit => User.IsAdmin() && Ready;
    public DateTime Now => sender.Now;
    /// #636: false = the Risk Analysis Summary step is off -- a new report is Detailed and the form offers no Summary.
    public bool SummaryOn { get; private set; } = true;

    private async Task LoadAsync(CancellationToken ct)
    {
        try
        {
            Ready = await sender.Store.ReadyAsync(ct);
            if (Ready) Reports = await sender.Store.ListAsync(ct);
            SummaryOn = await sender.SummaryOnAsync(ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            log.LogWarning(ex, "management summary reports");
            Error = "The management summary reports could not be read from the Pro database right now. The reason is in the application log.";
        }
    }

    public async Task OnGetAsync(CancellationToken ct)
    {
        await LoadAsync(ct);
        if (!CanEdit) return;
        Editing = New ? MgmtReport.New(Now) : Id is { } id ? Reports.FirstOrDefault(r => r.Id == id) : null;
        if (Editing is { } e) Fill(e);
    }

    private void Fill(MgmtReport e)
    {
        Name = e.Name; Grain = e.Grain; Kpi = e.Kpi; Domains = e.Domains; Timeline = e.Timeline; Recipients = string.Join("\n", e.Recipients);
        KeyBlocks = (e.KeyBlocks ?? SI.Management.Web.RiskExec.ExecutiveFigures.Blocks.Select(b => b.Key)).ToList();
        Cadence = e.Cadence; Day = e.Day; TimeUtc = e.TimeUtc; Enabled = e.Enabled;
    }

    private MgmtReport FromForm(MgmtReport? old) => new(Id ?? 0, (Name ?? "").Trim(), RiskExecGrain.Parse(Grain) ?? Grain ?? "", Kpi, Domains, Timeline,
        (Recipients ?? "").Split(new[] { '\n', '\r', ';', ',' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
        (Cadence ?? "").Trim().ToLowerInvariant(), Day, (TimeUtc ?? "").Trim(), Enabled, old?.LastPeriodKey, old?.LastSentAt, old?.CreatedAt ?? Now)
    {
        // every block chosen = the default (null), so a block added later reaches the report too
        KeyBlocks = SI.Management.Web.RiskExec.ExecutiveFigures.Blocks.All(b => KeyBlocks.Contains(b.Key)) ? null
            : SI.Management.Web.RiskExec.ExecutiveFigures.Blocks.Select(b => b.Key).Where(KeyBlocks.Contains).ToList(),
    };

    [Audited("report.summary.save")]
    public async Task<IActionResult> OnPostSaveAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        await LoadAsync(ct);
        if (!Ready) return Page();
        var old = Id is { } id and > 0 ? Reports.FirstOrDefault(r => r.Id == id) : null;
        if (Id is > 0 && old is null) return NotFound();
        var r = FromForm(old);
        Problems.AddRange(MgmtSchedule.Problems(r));
        if (Problems.Count > 0) { Editing = r; return Page(); }
        var saved = await sender.Store.SaveAsync(r, AuditScope.ActorOf(User), ct);
        // MAIL-2 item 5: a recipient who is not a user yet is added as Reader, so the mail's links open (never an escalation)
        var added = new List<string>();
        foreach (var to in r.Recipients) if ((await autoReader.EnsureAsync(to, AuditScope.ActorOf(User), ct)).State == "added") added.Add(to);
        TempData["toast"] = $"Saved: {r.Name} -- {MgmtSchedule.Describe(r)}" + (added.Count > 0 ? " Added as Reader: " + string.Join(", ", added) + "." : "");
        return RedirectToPage(new { Id = (long?)null, New = false, saved = saved });
    }

    [Audited("report.summary.remove")]
    public async Task<IActionResult> OnPostRemoveAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        await LoadAsync(ct);
        if (!Ready || Id is not { } id) return RedirectToPage();
        var ok = await sender.Store.RemoveAsync(id, AuditScope.ActorOf(User), ct);
        TempData["toast"] = ok ? "Removed." : "That report was already removed.";
        return RedirectToPage(new { Id = (long?)null });
    }

    [Audited("report.summary.send")]
    public async Task<IActionResult> OnPostSendAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        await LoadAsync(ct);
        if (!Ready || Id is not { } id || Reports.FirstOrDefault(r => r.Id == id) is not { } r) return NotFound();
        await sender.SendAsync(r, null, AuditScope.ActorOf(User), "web", ct);
        TempData["toast"] = $"Queued for {r.Recipients.Count} recipient(s): the mail job sends it within minutes.";
        return RedirectToPage(new { Id = (long?)null });
    }

    /// The report exactly as it would be mailed now (a stand-alone HTML page, shown in a frame on the page).
    public async Task<IActionResult> OnGetPreviewAsync(CancellationToken ct)
    {
        await LoadAsync(ct);
        if (!Ready) return NotFound();
        var r = Id is { } id ? Reports.FirstOrDefault(x => x.Id == id) : MgmtReport.New(Now) with { Grain = RiskExecGrain.Parse(Grain) ?? RiskExecGrain.Detailed };
        if (r is null) return NotFound();
        return await PreviewResult(HttpContext, sender, r, ct);
    }

    /// A mail's HTML carries inline styles (it is a mail); only this response allows them, and only inside a frame of the app.
    public static async Task<IActionResult> PreviewResult(HttpContext http, MgmtReportSender sender, MgmtReport r, CancellationToken ct)
    {
        var c = await sender.ComposeAsync(r, CultureInfo.CurrentCulture, ct);
        http.Response.Headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; frame-ancestors 'self'; base-uri 'none'; form-action 'none'";
        http.Response.Headers["X-Frame-Options"] = "SAMEORIGIN";
        return new ContentResult { Content = c.Html, ContentType = "text/html; charset=utf-8", StatusCode = 200 };
    }
}
