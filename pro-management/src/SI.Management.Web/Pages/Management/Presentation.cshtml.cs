using System.Globalization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.Audit;
using SI.Management.Web.Export;
using SI.Management.Web.Presentation;
using SI.Management.Web.RiskExec;

namespace SI.Management.Web.Pages.Management;

/// <summary>
/// Overview > Executive report > Presentation (owner 2026-10-29: "a wizard for mgmt. reporting, where i can select what i want
/// to export and then get a powerpoint with the exported data" / "customer must be able to do this themselves"): the run and
/// the run compared with, the sections, the title, the audience and the number format -- then a PowerPoint download, made by
/// <see cref="MgmtDeck"/> from the stored figures. The fixed Monthly management pack is one click (<see cref="OnGetPackAsync"/>),
/// also from the Executive report's Key figures.
/// WHO: everyone who may open the Management pages (the folder's policy, reader and up): a deck carries only what those
/// pages show. Pro only (<see cref="SI.Management.Web.Licensing.ProFeatures.Presentation"/>, refused server side on every
/// handler); the Community edition keeps the Executive report's PDF print. Every download is written to the audit trail.
/// </summary>
public sealed class PresentationModel(ILogger<PresentationModel> log) : PageModel
{
    [BindProperty(SupportsGet = true)] public string? C { get; set; }
    [BindProperty(SupportsGet = true)] public string? Vs { get; set; }
    [BindProperty] public List<string> Sections { get; set; } = new();
    [BindProperty] public string? Title { get; set; }
    [BindProperty] public string? Audience { get; set; }
    [BindProperty] public string? Format { get; set; }
    [BindProperty] public string? View { get; set; }
    [BindProperty] public bool AiNotes { get; set; } = true;

    public ExecutiveFigures Figures { get; private set; } = new() { Missing = ExecutiveFigures.NotBuilt };

    public RunPickerModel Picker() => new(Figures, "/Management/Presentation", Array.Empty<(string, string)>());

    /// The query of a link that keeps the shown run and the run compared with.
    public string RunQuery => (C is null ? "" : "&c=" + Uri.EscapeDataString(C)) + (Vs is null ? "" : "&vs=" + Uri.EscapeDataString(Vs));

    /// The title a new deck gets: "Security status – October 2026" (the month of the run shown, in English).
    public static string DefaultTitle(DateTime? run) => "Security status – " + (run ?? DateTime.UtcNow).ToString("MMMM yyyy", CultureInfo.InvariantCulture);

    public async Task OnGetAsync(CancellationToken ct)
    {
        Figures = await ExecutiveFigures.LoadAsync(HttpContext.RequestServices, C, ct, Vs);
        Sections = MgmtDeck.PackSections.ToList();
        Title = DefaultTitle(Figures.Current?.CollectionTime);
        Audience = MgmtDeck.Management;
        Format = DisplayCulture.Locale;
        View = "lifecycle";
    }

    /// The wizard's deck.
    [Audited("report.presentation.download")]
    public async Task<IActionResult> OnPostAsync(CancellationToken ct)
    {
        var sections = MgmtDeck.Normalize(Sections);
        var o = new MgmtDeck.Options(string.IsNullOrWhiteSpace(Title) ? DefaultTitle(null) : Title!, MgmtDeck.AudienceCode(Audience), sections, ExecutiveFigures.ProtectionView(View), AiNotes);
        return await GenerateAsync(C, Vs, o, Format, ct);
    }

    /// The Monthly management pack, one click: the fixed sections, for management, in the viewer's number format.
    [Audited("report.presentation.download")]
    public Task<IActionResult> OnGetPackAsync(CancellationToken ct) =>
        GenerateAsync(C, Vs, new MgmtDeck.Options(MgmtDeck.PackTitle, MgmtDeck.Management, MgmtDeck.PackSections), null, ct);

    private async Task<IActionResult> GenerateAsync(string? c, string? vs, MgmtDeck.Options o, string? culture, CancellationToken ct)
    {
        var inputs = await MgmtDeck.LoadAsync(HttpContext.RequestServices, c, vs, o.Sections, o.AiNotes, ct);
        var deck = MgmtDeck.WithCulture(culture, () => MgmtDeck.Build(o, inputs, MgmtDeck.Brand()));
        var f = inputs.Figures;
        // the audit trail: who (the filter), which run, the run compared with, the sections and the audience
        // (the row's target stays the page; a download made by a POST carries the same record as one made by a GET)
        if (AuditScope.Current is { } audit)
        {
            audit.Rows = deck.Slides;
            audit.Filter = "run: " + Run(f.Current) + "; compared with: " + Run(f.Previous) + "; sections: " + string.Join(", ", o.Sections)
                + "; audience: " + MgmtDeck.AudienceLabel(o.Audience) + (culture is null ? "" : "; number format: " + culture);
            audit.AfterJson = System.Text.Json.JsonSerializer.Serialize(new SortedDictionary<string, object?>(StringComparer.Ordinal)
            {
                ["page"] = "/Management/Presentation", ["file"] = deck.FileName, ["slides"] = deck.Slides, ["filter"] = audit.Filter,
            });
        }
        if (inputs.Errors.Count > 0) log.LogWarning("management presentation: {Sections} not available ({Reasons})", string.Join(", ", inputs.Errors.Keys), string.Join("; ", inputs.Errors.Values));
        return File(deck.Bytes, PptxWriter.ContentType, deck.FileName);
    }

    private static string Run(SI.Management.Core.ProData.ViewCollection? r) =>
        r is null ? "none" : r.CollectionTime.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture) + " UTC (" + r.CollectionId + ")";
}
