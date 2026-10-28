using System.Text;
using Microsoft.AspNetCore.Mvc;
using SI.Management.Core.ProData;
using SI.Management.Web.Audit;
using SI.Management.Web.Auth;
using SI.Management.Web.Changes;
using SI.Management.Web.Reports;

namespace SI.Management.Web.Pages.Reports;

/// <summary>
/// The Exclusions editor (#275 G7): the global excluded asset tags, and per report the excluded CVEs, configuration ids,
/// asset tags and the CVE minimum age -- as lists (add, remove, search) instead of raw JSON. The existing cfg.Document is
/// read into the lists; a v2.2 file (RiskAnalysisGlobalExclusions.custom.json, &lt;Report&gt;.exclude(.custom).json) can be
/// imported. Saved through THE existing document change (ChangeService.NewDocumentAsync -> Review &amp; commit), every
/// other property of the document (notes) kept; an unchanged document is never staged, so it stays byte for byte.
/// </summary>
public sealed class ExclusionsModel : ReportsPage
{
    private readonly DocumentRepository _documents;
    public ExclusionsModel(IReportStore store, ChangeService changes, DocumentRepository documents, ILogger<ExclusionsModel> log) : base(store, changes, log) => _documents = documents;

    [BindProperty(SupportsGet = true)] public string? Key { get; set; }
    [BindProperty] public string? Cves { get; set; }
    [BindProperty] public string? ConfigurationIds { get; set; }
    [BindProperty] public string? AssetTags { get; set; }
    [BindProperty] public int? CveMinAgeDays { get; set; }
    [BindProperty] public IFormFile? Upload { get; set; }

    public DocumentRow? Document { get; private set; }
    public IReadOnlyList<DocumentRow> All { get; private set; } = Array.Empty<DocumentRow>();
    public bool Global => (Key ?? "global") == "global";
    public bool Edited { get; private set; }
    /// The vendor reports an exclusions document may name (Risk Analysis reads exclusions of its shipped reports).
    public IEnumerable<string> ReportNames => State?.Reports.Where(r => r.Origin != ReportOrigin.Own).Select(r => r.Name) ?? Enumerable.Empty<string>();

    private async Task<bool> PrepareAsync(CancellationToken ct)
    {
        if (!await LoadAsync(ct)) return false;
        Key = string.IsNullOrWhiteSpace(Key) ? "global" : Key.Trim();
        if (!Global && !ReportNames.Contains(Key, StringComparer.Ordinal)) { Messages.Add($"Not found: '{Key}' is not a vendor report"); Key = "global"; }
        try
        {
            All = await _documents.ListAsync("exclusions", ct);
            Document = All.FirstOrDefault(d => d.Key == Key);
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { Log.LogError(ex, "exclusions documents"); Error = "The exclusion documents could not be read: " + ex.Message; return false; }
        return true;
    }

    private void Fill(ExclusionLists l)
    {
        Cves = string.Join("\n", l.Cves); ConfigurationIds = string.Join("\n", l.ConfigurationIds); AssetTags = string.Join("\n", l.AssetTags); CveMinAgeDays = l.CveMinAgeDays;
    }

    private static IReadOnlyList<string> Lines(string? s) => (s ?? "").Split('\n').Select(x => x.Trim()).Where(x => x.Length > 0).ToList();
    public ExclusionLists Draft => new(Lines(Cves), Lines(ConfigurationIds), Lines(AssetTags), CveMinAgeDays);

    public async Task OnGetAsync(CancellationToken ct)
    {
        if (!await PrepareAsync(ct)) return;
        Fill(ExclusionDocument.Read(Document?.Body));
    }

    /// The document change the lists make: Set (a new / changed document), Reset (every list emptied: the document is
    /// removed), or nothing when the document already says this.
    public static (string? Action, string? Body) Change(DocumentRow? current, ExclusionLists draft, bool global)
    {
        var body = ExclusionDocument.Write(current?.Body, draft, global);
        var empty = draft.AssetTags.Count == 0 && (global || (draft.Cves.Count == 0 && draft.ConfigurationIds.Count == 0 && (draft.CveMinAgeDays ?? 0) == 0));
        if (current is null) return empty ? (null, null) : ("Set", body);
        if (ProJson.Same(body, current.Body)) return (null, null);
        var hasNotes = (ProJson.Parse(body) as System.Text.Json.Nodes.JsonObject)?.Any(p => !p.Key.StartsWith('_')) == true;
        return !hasNotes ? ("Reset", null) : ("Set", body);
    }

    [Audited("exclusions.document.stage")]
    public async Task<IActionResult> OnPostStageAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        if (!await PrepareAsync(ct)) return Page();
        var (action, body) = Change(Document, Draft, Global);
        if (action is null) { Messages.Add("Not staged: nothing changed -- these are the exclusions in force"); return Page(); }
        if (string.IsNullOrWhiteSpace(Reason) || Reason.Trim().Length < 3) { Messages.Add("Not staged: give a reason (at least 3 characters)"); Edited = true; return Page(); }
        var (change, why) = await Changes.NewDocumentAsync("exclusions", Key!, action, body, Document?.Version, Reason, ct);
        if (change is null) { Messages.AddRange(why.Select(w => "Not staged: " + w)); Edited = true; return Page(); }
        var pending = await Changes.PendingAsync(User, ct);
        var old = pending.Where(p => p.Kind == ChangeKinds.Document && p.Get("docKind") == "exclusions" && p.Get("docKey") == Key).Select(p => p.Id).ToList();
        if (old.Count > 0) await Changes.DiscardAsync(User, old, ct);
        await Changes.StageAsync(User, change, ct);
        TempData["toast"] = "Staged: " + change.Title + ". Nothing is written until you review and commit.";
        TempData["toastKind"] = "ok";
        return RedirectToPage("/Changes/Index");
    }

    /// Read a v2.2 exclusions file into the lists (nothing stored until staged).
    [Audited("exclusions.draft.import")]
    public async Task<IActionResult> OnPostImportAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        if (!await PrepareAsync(ct)) return Page();
        if (Upload is null || Upload.Length == 0) { Messages.Add("Not imported: choose a JSON file"); Edited = true; return Page(); }
        if (Upload.Length > 1_000_000) { Messages.Add("Not imported: the file is larger than 1 MB"); Edited = true; return Page(); }
        string text;
        using (var r = new StreamReader(Upload.OpenReadStream(), Encoding.UTF8, detectEncodingFromByteOrderMarks: true)) text = await r.ReadToEndAsync(ct);
        if (ProJson.Parse(text) is not System.Text.Json.Nodes.JsonObject) { Messages.Add("Not imported: the file is not a JSON object"); Edited = true; return Page(); }
        var l = ExclusionDocument.Read(text);
        Fill(Global ? new ExclusionLists([], [], l.AssetTags, null) : l);
        Edited = true;
        Messages.Add($"Imported {Upload.FileName}: {l.Cves.Count} CVE(s), {l.ConfigurationIds.Count} configuration id(s), {l.AssetTags.Count} tag(s). Nothing is saved until you stage it and commit.");
        return Page();
    }
}
