using System.Globalization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.Auth;
using SI.Management.Web.Changes;

namespace SI.Management.Web.Pages.SchemaOverlay;

/// <summary>
/// One engine's schema overlay: readers see it; an Admin edits the columns, contributors and raw-payload sources in the
/// form (re-shaped on the server), checks and stages it -- or removes the overlay. Nothing is written here.
/// </summary>
public sealed class EditModel : PageModel
{
    private readonly SchemaOverlayStore _store;
    private readonly SchemaOverlayChanges _changes;
    private readonly ChangeService _changeService;
    private readonly IStagingStore _staging;
    private readonly ILogger<EditModel> _log;

    public EditModel(SchemaOverlayStore store, SchemaOverlayChanges changes, ChangeService changeService, IStagingStore staging, ILogger<EditModel> log)
    { _store = store; _changes = changes; _changeService = changeService; _staging = staging; _log = log; }

    [BindProperty(SupportsGet = true)] public string? Engine { get; set; }
    [BindProperty] public OverlayFormModel Form { get; set; } = new();
    [BindProperty] public string? Op { get; set; }
    [BindProperty] public string? Reason { get; set; }
    [BindProperty] public string? Act { get; set; }

    public SchemaOverlayEntry? Entry { get; private set; }
    public bool Schema { get; private set; }
    public string? CannotShow { get; private set; }
    public IReadOnlyList<string> Problems { get; private set; } = Array.Empty<string>();
    public IReadOnlyList<string> Messages { get; private set; } = Array.Empty<string>();
    public string? Checked { get; private set; }
    public string? Error { get; private set; }

    private async Task<bool> LoadAsync(CancellationToken ct)
    {
        try
        {
            var (schema, list) = await _store.LoadAsync(ct);
            Schema = schema;
            Entry = list.FirstOrDefault(x => x.Engine == Engine);
            if (schema && Entry is null) { Error = $"'{Engine}' is not a profiling engine."; return false; }
            CannotShow = OverlayFormModel.CannotShow(Entry?.Body);
            return schema;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "the schema overlay could not be read");
            Error = "The schema overlay could not be read from the Pro database: " + ex.Message;
            return false;
        }
    }

    public async Task OnGetAsync(CancellationToken ct)
    {
        if (await LoadAsync(ct) && CannotShow is null) Form = OverlayFormModel.From(Entry!.Body);
    }

    [SI.Management.Web.Audit.Audited("schemaoverlay.draft.check")]
    public async Task<IActionResult> OnPostEditAsync(CancellationToken ct)
    {
        if (SI.Management.Web.Audit.AuditScope.Current is { } audit) audit.WhatIf = true;
        if (!User.IsAdmin()) return Forbid();
        if (!await LoadAsync(ct)) return Page();
        ModelState.Clear();
        var parts = (Op ?? "").Split(':');
        int I(int n) => parts.Length > n && int.TryParse(parts[n], NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) ? v : -1;
        switch (parts[0])
        {
            case "add-field": Form.Fields.Add(new OverlayField { Purpose = "context", WrittenBy = "enrich" }); break;
            case "remove-field": if (I(1) is var a && a >= 0 && a < Form.Fields.Count) Form.Fields.RemoveAt(a); break;
            case "add-contributor": Form.Contributors.Add(new OverlayContributor { Settings = { new OverlaySetting { Name = "source", Value = "\"cmdb\"" } } }); break;
            case "remove-contributor": if (I(1) is var b && b >= 0 && b < Form.Contributors.Count) Form.Contributors.RemoveAt(b); break;
            case "add-setting": if (I(1) is var c && c >= 0 && c < Form.Contributors.Count) Form.Contributors[c].Settings.Add(new OverlaySetting()); break;
            case "remove-setting": if (I(1) is var d && d >= 0 && d < Form.Contributors.Count && I(2) is var s && s >= 0 && s < Form.Contributors[d].Settings.Count) Form.Contributors[d].Settings.RemoveAt(s); break;
            case "add-source": Form.Sources.Add(new OverlaySource()); break;
            case "remove-source": if (I(1) is var e && e >= 0 && e < Form.Sources.Count) Form.Sources.RemoveAt(e); break;
            default:
            {
                var fp = Form.Problems();
                if (fp.Count > 0) { Problems = fp; break; }
                var body = Form.ToJson();
                Problems = ItemValidator.Validate(SchemaOverlayStore.Kind, Engine ?? "", body);
                Checked = body;
                if (Problems.Count == 0) Messages = new[] { "Checked: the overlay is valid -- it is stored exactly as shown below. Stage it to save it." };
                break;
            }
        }
        return Page();
    }

    [SI.Management.Web.Audit.Audited("schemaoverlay.overlay.stage")]
    public async Task<IActionResult> OnPostStageAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        if (!await LoadAsync(ct)) return Page();
        ModelState.Clear();
        var act = Act == "remove" ? "remove" : "save";
        string? body = null;
        if (act == "save")
        {
            if (CannotShow is not null) { Messages = new[] { "Not staged: this overlay holds parts the form cannot show -- " + CannotShow }; return Page(); }
            var fp = Form.Problems();
            if (fp.Count > 0) { Problems = fp; Messages = new[] { "Not staged: fix the problems below" }; return Page(); }
            body = Form.ToJson();
        }
        var (change, why) = await _changes.NewAsync(Engine ?? "", act, body, Reason, ct);
        if (change is null) { Problems = why; Messages = new[] { "Not staged: " + string.Join("; ", why) }; return Page(); }
        var old = (await _staging.ListAsync(User, ct)).Where(x => x.Kind == SchemaOverlayChanges.ChangeKind && x.Get("key") == change.Get("key")).Select(x => x.Id).ToList();
        if (old.Count > 0) await _changeService.DiscardAsync(User, old, ct);
        await _changeService.StageAsync(User, change, ct);
        TempData["toast"] = "Staged: " + change.Title + ". Nothing is written until you review and commit.";
        TempData["toastKind"] = "ok";
        return RedirectToPage("/Changes/Index");
    }
}
