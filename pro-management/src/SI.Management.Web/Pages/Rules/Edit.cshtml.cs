using System.Globalization;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.Auth;
using SI.Management.Web.Changes;

namespace SI.Management.Web.Pages.Rules;

/// <summary>
/// One profiling rule: its text in force and the vendor's, and -- for an Admin -- the editor: a form (rule fields,
/// detections, their conditions, what each sets) or the YAML itself, with Check (the same validation the run applies)
/// and Stage (Review &amp; commit). The form is re-shaped on the server (add / remove a detection, a condition, a value),
/// so the page works without script. Nothing is written here.
/// </summary>
public sealed partial class EditModel : PageModel
{
    private readonly RuleItemStore _store;
    private readonly RuleItemChanges _changes;
    private readonly ChangeService _changeService;
    private readonly IStagingStore _staging;
    private readonly ILogger<EditModel> _log;

    public EditModel(RuleItemStore store, RuleItemChanges changes, ChangeService changeService, IStagingStore staging, ILogger<EditModel> log)
    { _store = store; _changes = changes; _changeService = changeService; _staging = staging; _log = log; }

    [BindProperty(SupportsGet = true)] public string? Key { get; set; }
    /// A new rule: its engine and id (the key is engine/id).
    [BindProperty(SupportsGet = true)] public string? Engine { get; set; }
    [BindProperty] public string? NewId { get; set; }
    /// form | yaml
    [BindProperty] public string View { get; set; } = "form";
    [BindProperty] public RuleFormModel Form { get; set; } = new();
    [BindProperty] public string? Yaml { get; set; }
    [BindProperty] public string? Op { get; set; }
    [BindProperty] public string? Reason { get; set; }
    /// save | off | reset | remove
    [BindProperty] public string? Act { get; set; }

    public RuleCatalog? Catalog { get; private set; }
    public RuleEntry? Entry { get; private set; }
    public string? FormWhy { get; private set; }
    public IReadOnlyList<string> Problems { get; private set; } = Array.Empty<string>();
    public IReadOnlyList<string> Messages { get; private set; } = Array.Empty<string>();
    public string? Checked { get; private set; }
    public string? Error { get; private set; }
    public bool IsNew => Entry is null;
    public static readonly string[] Engines = ["endpoint", "identity", "azure", "shared"];

    [GeneratedRegex(@"^[A-Za-z0-9][A-Za-z0-9_\-]{0,99}$", RegexOptions.CultureInvariant)] private static partial Regex IdRx();

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
            _log.LogError(ex, "the profiling rules could not be read");
            Error = "The profiling rules could not be read from the Pro database: " + ex.Message;
            return false;
        }
    }

    public async Task<IActionResult> OnGetAsync(CancellationToken ct)
    {
        if (!await LoadAsync(ct)) return Page();
        if (!string.IsNullOrWhiteSpace(Key) && Entry is null) { Error = $"There is no rule '{Key}'."; return Page(); }
        if (Entry is null)
        {
            if (!User.IsAdmin()) return RedirectToPage("/Rules/Index");   // only an Admin adds a rule; a reader is shown the list
            Engine = Engines.Contains(Engine) ? Engine : "endpoint";
            NewId = "";
            Form = RuleFormModel.New("MyRule", Engine!);
            Yaml = Form.ToYaml();
            return Page();
        }
        Yaml = Entry.EditBody ?? "";
        var (f, why) = RuleFormModel.Parse(Yaml);
        if (f is null) { View = "yaml"; FormWhy = why; }
        else Form = f;
        return Page();
    }

    /// The key this page edits (an existing rule's, or engine/id of a new one).
    public string TargetKey => Entry?.Key ?? $"{(Engines.Contains(Engine) ? Engine : "endpoint")}/{(NewId ?? "").Trim()}";

    private string Body() => View == "yaml" ? (Yaml ?? "").Replace("\r\n", "\n") : Form.ToYaml();

    /// Re-shape the form, switch between form and YAML, or check the text -- never stored.
    [SI.Management.Web.Audit.Audited("rules.draft.check")]
    public async Task<IActionResult> OnPostEditAsync(CancellationToken ct)
    {
        if (SI.Management.Web.Audit.AuditScope.Current is { } audit) audit.WhatIf = true;
        if (!User.IsAdmin()) return Forbid();
        if (!await LoadAsync(ct)) return Page();
        ModelState.Clear();
        var op = Op ?? "";
        var parts = op.Split(':');
        int I(int n) => parts.Length > n && int.TryParse(parts[n], NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) ? v : -1;
        var d = I(1) is var di && di >= 0 && di < Form.Detections.Count ? Form.Detections[di] : null;
        var c = d is not null && I(2) is var ci && ci >= 0 && ci < d.Conditions.Count ? d.Conditions[ci] : null;
        switch (parts[0])
        {
            case "to-yaml":
                var p = Form.Problems();
                if (p.Count > 0) { Problems = p; break; }
                Yaml = Form.ToYaml(); View = "yaml";
                break;
            case "to-form":
            {
                var (f, why) = RuleFormModel.Parse(Yaml ?? "");
                if (f is null) { FormWhy = why; View = "yaml"; Messages = new[] { "Not shown as a form: " + why }; }
                else { Form = f; View = "form"; }
                break;
            }
            case "add-field": Form.Fields.Add(new RuleParam()); break;
            case "remove-field": if (I(1) is var fi && fi >= 0 && fi < Form.Fields.Count) Form.Fields.RemoveAt(fi); break;
            case "add-detection":
                Form.Detections.Add(new RuleDetection { Id = $"{Form.Id}-{Form.Detections.Count + 1}", Conditions = { new RuleCondition { Kind = "nameMatches", Params = { new RuleParam { Name = "namePatterns", List = true } } } } });
                break;
            case "remove-detection": if (d is not null) Form.Detections.Remove(d); break;
            case "add-condition": d?.Conditions.Add(new RuleCondition()); break;
            case "remove-condition": if (c is not null) d!.Conditions.Remove(c); break;
            case "kind":
                // the kind's own parameters, offered when the condition has none yet
                if (c is not null && c.Params.Count == 0 && RuleFormModel.KindParams.TryGetValue(c.Kind ?? "", out var names))
                    foreach (var n in names) c.Params.Add(new RuleParam { Name = n, List = n.EndsWith('s') });
                break;
            case "add-param": c?.Params.Add(new RuleParam()); break;
            case "remove-param": if (c is not null && I(3) is var pi && pi >= 0 && pi < c.Params.Count) c.Params.RemoveAt(pi); break;
            case "add-set": d?.Set.Add(new RuleParam()); break;
            case "remove-set": if (d is not null && I(2) is var si && si >= 0 && si < d.Set.Count) d.Set.RemoveAt(si); break;
            case "add-dfield": d?.Fields.Add(new RuleParam { Name = "excludeAssets", List = true }); break;
            case "remove-dfield": if (d is not null && I(2) is var dfi && dfi >= 0 && dfi < d.Fields.Count) d.Fields.RemoveAt(dfi); break;
            default:
            {
                // Check: the same rules the run applies, on the text that would be stored
                var key = TargetKey;
                var fp = View == "form" ? Form.Problems() : Array.Empty<string>();
                if (fp.Count > 0) { Problems = fp; break; }
                var body = Body();
                Problems = RuleItemStore.Problems(Catalog!, key, body);
                Checked = body;
                if (Problems.Count == 0) Messages = new[] { "Checked: the rule is valid -- it is read exactly as shown below. Stage it to save it." };
                break;
            }
        }
        if (View == "form" && Entry is null && !string.IsNullOrWhiteSpace(NewId)) Form.Id = NewId.Trim();
        return Page();
    }

    /// Stage the change for Review & commit (replaces a change to the same rule already pending).
    [SI.Management.Web.Audit.Audited("rules.rule.stage")]
    public async Task<IActionResult> OnPostStageAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        if (!await LoadAsync(ct)) return Page();
        ModelState.Clear();
        var act = Act ?? "save";
        if (Entry is null && act == "save")
        {
            var id = (NewId ?? "").Trim();
            if (!IdRx().IsMatch(id)) { Messages = new[] { "Not staged: the rule id must be letters, digits, _ and - (starting with a letter or a digit)" }; return Page(); }
            if (View == "form") Form.Id = id;
            if (Catalog!.Find(TargetKey) is not null) { Messages = new[] { $"Not staged: a rule {TargetKey} exists already -- open it to change it" }; return Page(); }
        }
        string? body = null;
        if (act == "save")
        {
            if (View == "form")
            {
                var fp = Form.Problems();
                if (fp.Count > 0) { Problems = fp; Messages = new[] { "Not staged: fix the problems below" }; return Page(); }
            }
            body = Body();
        }
        var (change, why) = await _changes.NewAsync(TargetKey, act, body, Reason, ct);
        if (change is null) { Problems = why; Messages = new[] { "Not staged: " + string.Join("; ", why) }; return Page(); }
        var pending = await _staging.ListAsync(User, ct);
        var old = pending.Where(x => x.Kind == RuleItemChanges.ChangeKind && string.Equals(x.Get("key"), change.Get("key"), StringComparison.OrdinalIgnoreCase)).Select(x => x.Id).ToList();
        if (old.Count > 0) await _changeService.DiscardAsync(User, old, ct);
        await _changeService.StageAsync(User, change, ct);
        TempData["toast"] = "Staged: " + change.Title + ". Nothing is written until you review and commit.";
        TempData["toastKind"] = "ok";
        return RedirectToPage("/Changes/Index");
    }

    public static string ParamLabel(string name) => RuleFormModel.Label(name);
}
