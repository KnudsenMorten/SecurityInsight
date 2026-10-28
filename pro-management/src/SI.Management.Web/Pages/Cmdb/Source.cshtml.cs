using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.Auth;
using SI.Management.Web.Cmdb;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Pages.Cmdb;

/// <summary>
/// Switch the authoritative CMDB (SIWeb_CmdbSource) -- explicitly: choose (GET) -> Review, which says what happens to
/// each source's services and what becomes read-only (POST ?handler=Review) -> Save (POST ?handler=Save). The write is
/// the Settings writer's (validated by the catalog entry, one transaction with its cfg.ChangeLog row, refused when the
/// setting moved on since the page was opened). Nothing is copied or merged between sources.
/// </summary>
[Authorize(Policy = Policies.Admin)]
public sealed class SourceModel : PageModel
{
    private readonly ICmdbStore _store;
    private readonly SettingsWriter _writer;
    public SourceModel(ICmdbStore store, SettingsWriter writer) { _store = store; _writer = writer; }

    [BindProperty] public string? Target { get; set; }
    [BindProperty] public string? Reason { get; set; }
    [BindProperty] public long? ReadVersion { get; set; }

    public string Current { get; private set; } = CmdbSources.SI;
    public long? CurrentVersion { get; private set; }
    public Dictionary<string, (int Services, long Links)> Counts { get; } = new();
    public IReadOnlyList<string>? Consequences { get; private set; }
    public string? Error { get; private set; }
    public bool Stale { get; private set; }

    private async Task LoadAsync(CancellationToken ct)
    {
        (Current, CurrentVersion) = await _store.ActiveSourceAsync(ct);
        if (!(await _store.SchemaAsync(ct)).HasCmdb) { Error = SqlCmdbStore.MissingSchemaMessage; return; }
        foreach (var s in CmdbSources.All)
        {
            var list = await _store.ServicesAsync(s, false, ct);
            Counts[s] = (list.Count, list.Sum(x => x.Assets));
        }
    }

    public async Task OnGetAsync(CancellationToken ct) { await LoadAsync(ct); Target = Current; ReadVersion = CurrentVersion; }

    /// What switching from one source to another does, in the words the review shows.
    public static IReadOnlyList<string> Explain(string from, string to, IReadOnlyDictionary<string, (int Services, long Links)> counts)
    {
        (int Services, long Links) C(string s) => counts.TryGetValue(s, out var c) ? c : (0, 0);
        var lines = new List<string>
        {
            $"From the next data sync, every view that groups by service, risk weighting and departments read the services of {CmdbSources.Label(to)}: {Fmt.Int(C(to).Services)} service(s) with {Fmt.Int(C(to).Links)} linked asset(s) today.",
            $"The {Fmt.Int(C(from).Services)} service(s) of {CmdbSources.Label(from)} stay stored with their links and history, unused. Nothing is copied, merged or removed; switching back makes them authoritative again.",
        };
        lines.Add(to == CmdbSources.SI
            ? "The CMDB page and the service map become editable: add and retire services, link assets by dragging them."
            : "The CMDB page and the service map become read-only: services and links are changed in the source and arrive with its next import.");
        if (to != CmdbSources.SI && C(to).Services == 0)
            lines.Add(to == CmdbSources.ExternalCsv
                ? "This source holds no service yet: until a CMDB.csv is imported, no asset belongs to any service."
                : "This source holds no service yet: until the scheduled ServiceNow import has run, no asset belongs to any service.");
        lines.Add("The newest collection's services are worked out again by the next data sync; older collections keep the services they had.");
        return lines;
    }

    [SI.Management.Web.Audit.NotAudited("a review: shows the source change before it is saved and writes nothing")]
    public async Task<IActionResult> OnPostReviewAsync(CancellationToken ct)
    {
        await LoadAsync(ct);
        if (Error is not null) return Page();
        if (!CmdbSources.IsKnown(Target)) { Error = "Choose one of the CMDB sources."; return Page(); }
        if (Target == Current) { Error = "This is already the CMDB source -- nothing changes."; return Page(); }
        if (ReadVersion != CurrentVersion) { Stale = true; return Page(); }
        Consequences = Explain(Current, Target!, Counts);
        return Page();
    }

    [SI.Management.Web.Audit.Audited("cmdb.source.save")]
    public async Task<IActionResult> OnPostSaveAsync(CancellationToken ct)
    {
        await LoadAsync(ct);
        if (Error is not null) return Page();
        if (!CmdbSources.IsKnown(Target) || Target == Current) { Error = "Choose another CMDB source."; return Page(); }
        if (string.IsNullOrWhiteSpace(Reason) || Reason.Trim().Length < 3) { Error = "Give a reason (at least 3 characters)."; Consequences = Explain(Current, Target!, Counts); return Page(); }
        using var doc = JsonDocument.Parse(JsonSerializer.Serialize(Target));
        var r = await _writer.WriteAsync(new SettingWrite(CmdbSources.Setting, CatalogSetting.WebScope, "Set", doc.RootElement.Clone(), null, ReadVersion, Reason), User.ChangeName(), ct);
        switch (r.Status)
        {
            case WriteStatus.Saved:
                await _store.RecomputeAsync(ct);
                TempData["toast"] = $"The CMDB source is now {CmdbSources.Label(Target!)}.";
                TempData["toastKind"] = "ok";
                return RedirectToPage("Index");
            case WriteStatus.Stale:
                Stale = true; return Page();
            default:
                Error = r.Message; return Page();
        }
    }
}
