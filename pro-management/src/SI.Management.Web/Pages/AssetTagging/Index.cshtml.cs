using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.Auth;
using SI.Management.Web.Changes;

namespace SI.Management.Web.Pages.AssetTagging;

/// <summary>
/// Configuration > Asset tagging (#275 G9): the tag rules the tagging run writes to Defender (v2.2's AssetTagging.locked
/// / .custom.yaml) and the gates that switch the automatic exclusion tags on (v2.2's config\asset-tagging.config.json).
/// Readers see both; an Admin opens a tag to change it, turns a vendor tag off, adds a tag, or changes the gates here.
/// Nothing is written on these pages: every change goes through Review &amp; commit.
/// </summary>
public sealed class IndexModel : SI.Management.Web.Columns.DataViewPageModel
{
    private readonly TaggingStore _store;
    private readonly TaggingChanges _changes;
    private readonly ChangeService _changeService;
    private readonly IStagingStore _staging;
    private readonly ILogger<IndexModel> _log;

    public IndexModel(TaggingStore store, TaggingChanges changes, ChangeService changeService, IStagingStore staging, ILogger<IndexModel> log)
    { _store = store; _changes = changes; _changeService = changeService; _staging = staging; _log = log; }

    public TaggingCatalog? Catalog { get; private set; }
    [BindProperty] public GatesFormModel Gates { get; set; } = new();
    [BindProperty] public string? Reason { get; set; }
    [BindProperty] public string? Act { get; set; }
    public IReadOnlyList<string> Messages { get; private set; } = Array.Empty<string>();
    public string? Error { get; private set; }

    private async Task<bool> LoadAsync(CancellationToken ct)
    {
        try { Catalog = await _store.LoadAsync(ct); return Catalog.Schema; }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "asset tagging could not be read");
            Error = "Asset tagging could not be read from the Pro database: " + ex.Message;
            return false;
        }
    }

    // #589: the tag rules as THE data table -- every field of a rule (its query too), the chooser, the all-rows exports
    protected override Task LoadForExportAsync(CancellationToken ct) => LoadAsync(ct);

    protected override IReadOnlyList<SI.Management.Web.Columns.DataTable> BuildTables()
    {
        if (Catalog is not { Schema: true } cat) return Array.Empty<SI.Management.Web.Columns.DataTable>();
        static TagEntry T(object o) => (TagEntry)o;
        var config = TaggingStore.Parse(cat.ConfigBody);
        string GateIs(TagEntry t) => t.Gate is null ? "always runs" : GatesFormModel.Flag(config, t.Gate) ? "on" : "off";
        var rows = cat.Tags.Cast<object>().ToList();
        SI.Management.Web.Columns.DataColumn[] own =
        [
            new("Name", "Tag", o => T(o).Name, Link: o => "/AssetTagging/Edit?key=" + Uri.EscapeDataString(T(o).Key)),
            new("Key", "Key", o => T(o).Key),
            new("Origin", "Source", o => OriginLabel(T(o).Origin)),
            new("Sets", "Sets", o => T(o).Excluded ? "excluded" : T(o).Tier is { } tr ? "Tier " + tr : ""),
            new("Mode", "Mode", o => T(o).Mode),
            new("QueryEngine", "Query engine", o => T(o).QueryEngine),
            new("Gate", "Gate", o => T(o).Gate),
            new("GateIs", "Gate is", o => GateIs(T(o))),
            new("UpdatedBy", "Changed by", o => T(o).UpdatedBy),
            new("UpdatedAt", "Changed", o => T(o).UpdatedAt),
            new("Version", "Version", o => T(o).Version, Number: true),
        ];
        var table = new SI.Management.Web.Columns.DataTable
        {
            Id = "tags", View = "assettagging", Title = "Tag rules", Rows = rows, Marker = "data-tags-table",
            RowAttributes = o => new Dictionary<string, string?> { ["data-tag"] = T(o).Key },
            // then every field of the rule as it is stored; one named like a column above ("Mode") says it is the rule's field
            Columns = [.. own, .. SI.Management.Web.Columns.DataTable.Bag(rows, o => Fields(T(o).EditBody), "Rule", shown: false, taken: own.Select(c => c.Label), what: "rule field")],
        };
        table.Html["Origin"] = o => new Microsoft.AspNetCore.Html.HtmlString("<span class=\"badge " + System.Net.WebUtility.HtmlEncode(OriginClass(T(o).Origin)) + "\" data-origin=\""
            + System.Net.WebUtility.HtmlEncode(OriginLabel(T(o).Origin)) + "\">" + System.Net.WebUtility.HtmlEncode(OriginLabel(T(o).Origin)) + "</span>");
        return new[] { table };
    }

    /// Every top-level field of a rule's body (its query, its gate...) as text -- a list or an object as compact JSON.
    public static IReadOnlyList<KeyValuePair<string, string>> Fields(string? body) =>
        TaggingStore.Parse(body) is { } o
            ? o.Select(kv => new KeyValuePair<string, string>(kv.Key, kv.Value is System.Text.Json.Nodes.JsonValue v ? v.ToString() : kv.Value?.ToJsonString() ?? "")).ToList()
            : Array.Empty<KeyValuePair<string, string>>();

    public async Task OnGetAsync(CancellationToken ct)
    {
        if (await LoadAsync(ct)) Gates = GatesFormModel.From(Catalog!.ConfigBody, Catalog.Tags.Where(t => t.Origin != RuleOrigin.Off).Select(t => t.Gate));
    }

    /// Stage the gates (save, or reset = no gates stored) for Review & commit.
    [SI.Management.Web.Audit.Audited("tagging.gates.stage")]
    public async Task<IActionResult> OnPostGatesAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        if (!await LoadAsync(ct)) return Page();
        var act = Act == "reset" ? "reset" : "save";
        var fp = act == "save" ? Gates.Problems() : Array.Empty<string>();
        if (fp.Count > 0) { Messages = fp.Select(p => "Not staged: " + p).ToList(); return Page(); }
        var (change, why) = await _changes.NewAsync(TaggingStore.ConfigKey, act, act == "save" ? Gates.ToJson() : null, Reason, ct);
        if (change is null) { Messages = why.Select(w => "Not staged: " + w).ToList(); return Page(); }
        var old = (await _staging.ListAsync(User, ct)).Where(x => x.Kind == TaggingChanges.ChangeKind && x.Get("key") == TaggingStore.ConfigKey).Select(x => x.Id).ToList();
        if (old.Count > 0) await _changeService.DiscardAsync(User, old, ct);
        await _changeService.StageAsync(User, change, ct);
        TempData["toast"] = "Staged: " + change.Title + ". Nothing is written until you review and commit.";
        TempData["toastKind"] = "ok";
        return RedirectToPage("/Changes/Index");
    }

    public static string OriginLabel(RuleOrigin o) => SI.Management.Web.Pages.Rules.IndexModel.OriginLabel(o);
    public static string OriginClass(RuleOrigin o) => SI.Management.Web.Pages.Rules.IndexModel.OriginClass(o);
}
