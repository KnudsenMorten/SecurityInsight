using System.Globalization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Core.ProData;
using SI.Management.Web.Audit;
using SI.Management.Web.Auth;
using SI.Management.Web.Changes;

namespace SI.Management.Web.Pages.Admin.Settings;

/// <summary>
/// #772: Admin &gt; Settings &gt; ServiceNow &gt; Sub-CI mapping (/Admin/Settings/Mapping/servicenow-subci) and Admin &gt; Settings &gt;
/// OS family mapping (/Admin/Settings/Mapping/os-family) -- ONE page over the ONE classification mechanism
/// (<see cref="DimensionMapping"/>): (a) the buckets -- add, rename, remove, one marked the fallback; (b) per base value (the
/// sub-CI: per component) which bucket; (c) ordered rules on other fields, first match wins, before the base; (d) "Preview"
/// counts per bucket over the newest complete collection (the OS family: over the CIs) with the mapping in force and the one
/// entered, before anything is staged; (e) "Stage" turns the difference into data-model changes (cfg.ItemOverride) staged on
/// Review &amp; commit in the signed-in name with the reason -- the change log; the next run classifies with them, nothing
/// already stored is rewritten. Readers see the page; every change checks Admin itself.
/// </summary>
public sealed class MappingModel : PageModel
{
    private readonly RiskFactorStore _store;
    private readonly ChangeService _changes;
    private readonly ICollectionViews _views;
    private readonly DimensionMappingPreview _preview;
    private readonly ILogger<MappingModel> _log;

    public MappingModel(RiskFactorStore store, ChangeService changes, ICollectionViews views, DimensionMappingPreview preview, ILogger<MappingModel> log)
    { _store = store; _changes = changes; _views = views; _preview = preview; _log = log; }

    /// The mapping shown (route): servicenow-subci | os-family.
    [BindProperty(SupportsGet = true)] public string? M { get; set; }

    [BindProperty] public List<string?> Bucket { get; set; } = new();
    [BindProperty] public string? Fallback { get; set; }
    [BindProperty] public Dictionary<string, string?> Base { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    [BindProperty] public List<string?> RuleField { get; set; } = new();
    [BindProperty] public List<string?> RuleMatch { get; set; } = new();
    [BindProperty] public List<string?> RuleValues { get; set; } = new();
    [BindProperty] public List<string?> RuleBucket { get; set; } = new();
    [BindProperty] public List<string?> RuleOrder { get; set; } = new();
    [BindProperty] public string? Reason { get; set; }

    public DimensionMapping.Spec Spec { get; private set; } = DimensionMapping.ServiceNowSubCi;
    public DimensionMapping.Mapping InForce { get; private set; } = new(Array.Empty<string>(), "", new Dictionary<string, string>(), Array.Empty<DimensionMapping.Rule>());
    public IReadOnlyList<string> BaseValues { get; private set; } = Array.Empty<string>();
    public bool SchemaMissing { get; private set; }
    public string? Error { get; private set; }
    public IReadOnlyList<string> Problems { get; private set; } = Array.Empty<string>();
    public IReadOnlyList<DimensionMapping.Change>? Planned { get; private set; }

    /// The preview: what the last run stored, the mapping in force and the one entered, counted per bucket.
    public bool Previewing { get; private set; }
    public ViewCollection? Collection { get; private set; }
    public IReadOnlyDictionary<string, long>? StoredCounts { get; private set; }
    public IReadOnlyDictionary<string, long>? InForceCounts { get; private set; }
    public IReadOnlyDictionary<string, long>? EnteredCounts { get; private set; }
    public string? PreviewNotice { get; private set; }

    public bool CanEdit => User.IsAdmin();
    public string Route => "/Admin/Settings/Mapping/" + Spec.Id;

    /// The extra empty slots the form offers (a new bucket, a new rule).
    public const int SpareBuckets = 2;
    public const int SpareRules = 3;

    public async Task<IActionResult> OnGetAsync(CancellationToken ct)
    {
        if (DimensionMapping.Find(M ?? DimensionMapping.ServiceNowSubCi.Id) is not { } spec) return NotFound();
        Spec = spec;
        await LoadAsync(ct);
        FillForm(InForce);
        return Page();
    }

    private async Task<IReadOnlyList<DataModelRow>> LoadAsync(CancellationToken ct)
    {
        try
        {
            var rows = await _store.ListAsync(ct);
            if (rows is null) { SchemaMissing = true; rows = Array.Empty<DataModelRow>(); }
            BaseValues = DimensionMapping.BaseValues(Spec, rows);
            InForce = DimensionMapping.Read(Spec, rows);
            return rows;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "the {Mapping} could not be read", Spec.Id);
            Error = $"The {Spec.Title.ToLowerInvariant()} could not be read from the Pro database: " + ex.Message;
            InForce = new(Spec.BucketDefault, Spec.FallbackDefault, new Dictionary<string, string>(), Array.Empty<DimensionMapping.Rule>());
            return Array.Empty<DataModelRow>();
        }
    }

    /// The form from a mapping: the buckets by slot, the fallback slot, the base and rule buckets by slot.
    private void FillForm(DimensionMapping.Mapping m)
    {
        Bucket = m.Buckets.Select(b => (string?)b).ToList();
        string Slot(string b) => m.Buckets.ToList().FindIndex(x => string.Equals(x, b, StringComparison.Ordinal)) is var i and >= 0 ? i.ToString(CultureInfo.InvariantCulture) : "";
        Fallback = Slot(m.Fallback);
        Base = BaseValues.ToDictionary(v => v, v => (string?)(m.Base.TryGetValue(v, out var b) ? Slot(b) : ""), StringComparer.OrdinalIgnoreCase);
        RuleField = m.Rules.Select(r => (string?)r.Field).ToList();
        RuleMatch = m.Rules.Select(r => (string?)r.Match).ToList();
        RuleValues = m.Rules.Select(r => (string?)string.Join("; ", r.Values)).ToList();
        RuleBucket = m.Rules.Select(r => (string?)Slot(r.Bucket)).ToList();
        RuleOrder = m.Rules.Select((_, i) => (string?)((i + 1) * 10).ToString(CultureInfo.InvariantCulture)).ToList();
    }

    /// The posted form, its rules in the order typed (the order column; equal numbers keep the page order).
    private DimensionMapping.Posted Posted()
    {
        var n = new[] { RuleField.Count, RuleMatch.Count, RuleValues.Count, RuleBucket.Count }.Max();
        string? At(List<string?> l, int i) => i < l.Count ? l[i] : null;
        var rules = Enumerable.Range(0, n)
            .Select(i => (i, Order: double.TryParse(At(RuleOrder, i), NumberStyles.Float, CultureInfo.InvariantCulture, out var o) ? o : 1e9 + i))
            .OrderBy(x => x.Order).ThenBy(x => x.i)
            .Select(x => (At(RuleField, x.i), At(RuleMatch, x.i), At(RuleValues, x.i), At(RuleBucket, x.i))).ToList();
        return new DimensionMapping.Posted(Bucket, Fallback, Base, rules);
    }

    /// "Preview" (Admin): the entered mapping counted against the stored values -- reads only, stages nothing.
    [NotAudited("a preview: counts the findings / assets per bucket with the entered mapping; stages and writes nothing")]
    public async Task<IActionResult> OnPostPreviewAsync(CancellationToken ct)
    {
        if (DimensionMapping.Find(M ?? DimensionMapping.ServiceNowSubCi.Id) is not { } spec) return NotFound();
        Spec = spec;
        if (!User.IsAdmin()) return Forbid();
        var rows = await LoadAsync(ct);
        var (entered, why) = DimensionMapping.Parse(Spec, Posted(), BaseValues);
        Problems = why;
        Previewing = true;
        if (entered is not null) Planned = DimensionMapping.Plan(Spec, rows, entered, BaseValues);
        await PreviewAsync(entered, ct);
        return Page();
    }

    private async Task PreviewAsync(DimensionMapping.Mapping? entered, CancellationToken ct)
    {
        try
        {
            int? collectionId = null;
            if (!Spec.Assets)
            {
                Collection = (await _views.CollectionsAsync(ct)).Data.FirstOrDefault();
                if (Collection is null) { PreviewNotice = "No complete collection has been loaded into the Pro database yet, so there are no findings to count."; return; }
                if (!int.TryParse(Collection.CollectionId, NumberStyles.Integer, CultureInfo.InvariantCulture, out var cid)) { PreviewNotice = "The newest collection could not be read."; return; }
                collectionId = cid;
            }
            var groups = await _preview.ReadAsync(Spec, collectionId, ct);
            if (groups is null || groups.Count == 0) { PreviewNotice = Spec.Assets ? "No CI is in the Pro database yet, so there is nothing to count." : "The newest collection holds no findings to count."; return; }
            var stored = new Dictionary<string, long>(StringComparer.Ordinal);
            foreach (var g in groups) { var k = string.IsNullOrWhiteSpace(g.Stored) ? NotSet : g.Stored!; stored[k] = (stored.TryGetValue(k, out var c) ? c : 0) + g.N; }
            StoredCounts = stored;
            InForceCounts = DimensionMapping.Count(InForce, groups.Select(g => (g.Facts, g.N)), Spec.BaseField);
            if (entered is not null) EnteredCounts = DimensionMapping.Count(entered, groups.Select(g => (g.Facts, g.N)), Spec.BaseField);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogWarning(ex, "the {Mapping} preview could not be read", Spec.Id);
            PreviewNotice = "The preview could not be counted: " + ex.Message;
        }
    }

    /// The row heading of a stored value that is empty (a run before this field).
    public const string NotSet = "(not set yet)";

    /// Admin only: the difference between the mapping in force and the one entered, staged as data-model changes.
    [Audited("datamodel.item.stage")]
    public async Task<IActionResult> OnPostStageAsync(CancellationToken ct)
    {
        if (DimensionMapping.Find(M ?? DimensionMapping.ServiceNowSubCi.Id) is not { } spec) return NotFound();
        Spec = spec;
        if (!User.IsAdmin()) return Forbid();
        var rows = await LoadAsync(ct);
        var (want, why) = DimensionMapping.Parse(Spec, Posted(), BaseValues);
        if (want is null) return Refused(string.Join("; ", why));
        var plan = DimensionMapping.Plan(Spec, rows, want, BaseValues);
        if (plan.Count == 0) return Refused("this is the mapping in force already -- nothing to change");
        // every change is checked before any is staged: all of them or none
        var staged = new List<StagedChange>();
        foreach (var c in plan)
        {
            var reason = string.IsNullOrWhiteSpace(Reason) ? $"{Spec.Title}: {c.What}" : $"{Reason!.Trim()} ({c.What})";
            var (change, refused) = await _changes.NewDataModelItemAsync(c.Key, c.State, c.Body, reason, ct);
            if (change is null) return Refused($"{c.What}: {string.Join("; ", refused)}");
            staged.Add(change);
        }
        foreach (var s in staged) await _changes.StageAsync(User, s, ct);
        return Back(true, $"Staged {staged.Count} change(s) of the {Spec.Title.ToLowerInvariant()}. Nothing is written until you review and commit; the next run classifies with them.");
    }

    private IActionResult Refused(string message)
    {
        AuditScope.Current?.Refused(message);
        return Back(false, "Not staged: " + message);
    }

    private IActionResult Back(bool ok, string message)
    {
        TempData["toast"] = message;
        TempData["toastKind"] = ok ? "ok" : "error";
        return Redirect(Route);
    }
}
