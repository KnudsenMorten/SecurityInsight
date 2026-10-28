using System.Globalization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.Auth;
using SI.Management.Web.Changes;

namespace SI.Management.Web.Pages.AssetTagging;

/// <summary>
/// One asset tag rule: readers see it; an Admin changes it in the form (name and what it sets, mode, query engine, gate,
/// device-name scoping, description, queries), checks it and stages it -- or turns a vendor tag off, resets it, or
/// removes their own. Nothing is written here.
/// </summary>
public sealed class EditModel : PageModel
{
    private readonly TaggingStore _store;
    private readonly TaggingChanges _changes;
    private readonly ChangeService _changeService;
    private readonly IStagingStore _staging;
    private readonly ILogger<EditModel> _log;

    public EditModel(TaggingStore store, TaggingChanges changes, ChangeService changeService, IStagingStore staging, ILogger<EditModel> log)
    { _store = store; _changes = changes; _changeService = changeService; _staging = staging; _log = log; }

    [BindProperty(SupportsGet = true)] public string? Key { get; set; }
    [BindProperty] public TagFormModel Form { get; set; } = new();
    [BindProperty] public string? Op { get; set; }
    [BindProperty] public string? Reason { get; set; }
    [BindProperty] public string? Act { get; set; }

    public TaggingCatalog? Catalog { get; private set; }
    public TagEntry? Entry { get; private set; }
    public IReadOnlyList<string> Problems { get; private set; } = Array.Empty<string>();
    public IReadOnlyList<string> Messages { get; private set; } = Array.Empty<string>();
    public string? Checked { get; private set; }
    public string? Error { get; private set; }

    private async Task<bool> LoadAsync(CancellationToken ct)
    {
        try
        {
            Catalog = await _store.LoadAsync(ct);
            if (!string.IsNullOrWhiteSpace(Key)) Entry = Catalog.Find(Key);
            return Catalog.Schema;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "asset tagging could not be read");
            Error = "Asset tagging could not be read from the Pro database: " + ex.Message;
            return false;
        }
    }

    public async Task<IActionResult> OnGetAsync(CancellationToken ct)
    {
        if (!await LoadAsync(ct)) return Page();
        if (!string.IsNullOrWhiteSpace(Key) && Entry is null) { Error = $"There is no tag '{Key}'."; return Page(); }
        if (Entry is null)
        {
            if (!User.IsAdmin()) return RedirectToPage("/AssetTagging/Index");
            Form = new TagFormModel { Stem = "", Marker = "tier2", Queries = { "" } };
            return Page();
        }
        Form = TagFormModel.From(Entry.EditBody);
        return Page();
    }

    /// The key a staged change writes: an existing tag keeps its key (its name part is fixed); a new tag's key is its name's.
    private string TargetKey => Entry?.Key ?? Form.Key;

    [SI.Management.Web.Audit.Audited("tagging.draft.check")]
    public async Task<IActionResult> OnPostEditAsync(CancellationToken ct)
    {
        if (SI.Management.Web.Audit.AuditScope.Current is { } audit) audit.WhatIf = true;
        if (!User.IsAdmin()) return Forbid();
        if (!await LoadAsync(ct)) return Page();
        ModelState.Clear();
        var parts = (Op ?? "").Split(':');
        switch (parts[0])
        {
            case "add-query": Form.Queries.Add(""); break;
            case "remove-query":
                if (parts.Length > 1 && int.TryParse(parts[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out var i) && i >= 0 && i < Form.Queries.Count) Form.Queries.RemoveAt(i);
                break;
            default:
            {
                var fp = Form.Problems();
                if (fp.Count > 0) { Problems = fp; break; }
                var body = Form.ToJson();
                Problems = KeyProblem() is { } kp ? new[] { kp } : TaggingStore.Problems(TargetKey, body);
                Checked = body;
                if (Problems.Count == 0) Messages = new[] { "Checked: the tag is valid -- it is stored exactly as shown below. Stage it to save it." };
                break;
            }
        }
        return Page();
    }

    /// An existing tag keeps its name part (it is the tag's identity: the vendor's tag of that name is what it replaces).
    private string? KeyProblem() => Entry is not null && !string.Equals("tag/" + ItemValidator.StemKey(Form.Name), Entry.Key, StringComparison.Ordinal)
        ? $"the name part '{Entry.Key[4..^4]}' identifies this tag -- change the tier or excluded marker, or add a new tag for another name"
        : Entry is null && Catalog?.Find(Form.Key) is not null ? $"a tag {Form.Key[4..]} exists already -- open it to change it" : null;

    [SI.Management.Web.Audit.Audited("tagging.tag.stage")]
    public async Task<IActionResult> OnPostStageAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        if (!await LoadAsync(ct)) return Page();
        ModelState.Clear();
        var act = Act ?? "save";
        string? body = null;
        if (act == "save")
        {
            var fp = Form.Problems();
            if (fp.Count == 0 && KeyProblem() is { } kp) fp = new[] { kp };
            if (fp.Count > 0) { Problems = fp; Messages = new[] { "Not staged: fix the problems below" }; return Page(); }
            body = Form.ToJson();
        }
        var key = act == "save" ? TargetKey : Entry?.Key ?? "";
        var (change, why) = await _changes.NewAsync(key, act, body, Reason, ct);
        if (change is null) { Problems = why; Messages = new[] { "Not staged: " + string.Join("; ", why) }; return Page(); }
        var old = (await _staging.ListAsync(User, ct)).Where(x => x.Kind == TaggingChanges.ChangeKind && string.Equals(x.Get("key"), change.Get("key"), StringComparison.OrdinalIgnoreCase)).Select(x => x.Id).ToList();
        if (old.Count > 0) await _changeService.DiscardAsync(User, old, ct);
        await _changeService.StageAsync(User, change, ct);
        TempData["toast"] = "Staged: " + change.Title + ". Nothing is written until you review and commit.";
        TempData["toastKind"] = "ok";
        return RedirectToPage("/Changes/Index");
    }
}
