using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.Auth;
using SI.Management.Web.Changes;

namespace SI.Management.Web.Pages.RiskFactors;

/// <summary>
/// Classification -- THE ONE editor of the generic classification mapping (readers see it; every change checks Admin
/// itself). One page for every classification target: the dimensions (component first, with its values) and asset type /
/// subtype. Each row: source + SI field + match -> target = value, priority. The row wizard follows the risk factor
/// criteria pattern: closed dropdowns, values SecurityInsight collected, a plain glob for prefix / pattern -- nothing
/// typed reaches a query. A change is a 'classification:&lt;id&gt;' cfg.ItemOverride row (a shipped row is turned off or
/// changed, a customer row added or removed), staged on Review &amp; commit in the signed-in name.
/// </summary>
public sealed class ClassificationModel : PageModel
{
    private readonly RiskFactorStore _store;
    private readonly ChangeService _changes;
    private readonly ILogger<ClassificationModel> _log;

    public ClassificationModel(RiskFactorStore store, ChangeService changes, ILogger<ClassificationModel> log) { _store = store; _changes = changes; _log = log; }

    /// The target shown (si_component, si_asset_type, si_asset_subtype, si_&lt;dimension&gt;).
    [BindProperty(SupportsGet = true)] public string? Target { get; set; }
    /// The row being edited ('classification:&lt;id&gt;'), or null for a new row.
    [BindProperty(SupportsGet = true)] public string? Edit { get; set; }
    /// Step 1 of the wizard (GET): what the row reads.
    [BindProperty(SupportsGet = true)] public string? Source { get; set; }
    [BindProperty(SupportsGet = true)] public string? Field { get; set; }
    [BindProperty(SupportsGet = true)] public string? Match { get; set; }
    /// Step 2 (POST): the picked collected values / the pattern, the value to set, the priority.
    [BindProperty] public string[]? Pick { get; set; }
    [BindProperty] public string? Pattern { get; set; }
    [BindProperty] public string? Set { get; set; }
    [BindProperty] public string? Priority { get; set; }
    [BindProperty] public string? Key { get; set; }
    [BindProperty] public string? Reason { get; set; }

    public IReadOnlyList<Dimensions.DimensionView> DimensionList { get; private set; } = Array.Empty<Dimensions.DimensionView>();
    public IReadOnlyList<ClassificationMapping.Row> Rows { get; private set; } = Array.Empty<ClassificationMapping.Row>();
    public IReadOnlyList<string> Targets { get; private set; } = Array.Empty<string>();
    /// The targets of the template header (field, dimension, assets / findings, multi, fallback).
    public IReadOnlyList<ClassificationMapping.Target> TargetList { get; private set; } = ClassificationMapping.DefaultTargets;
    public ClassificationMapping.Target? CurrentTargetInfo => TargetList.FirstOrDefault(t => t.Field == CurrentTarget);
    public IReadOnlyList<string> TargetValues { get; private set; } = Array.Empty<string>();
    public Dimensions.DimensionView? Dimension { get; private set; }
    public ClassificationMapping.Row? Editing { get; private set; }
    public IReadOnlyList<FactorCriteria.Collected> Collected { get; private set; } = Array.Empty<FactorCriteria.Collected>();
    public string? CollectedError { get; private set; }
    public bool SchemaMissing { get; private set; }
    public string? Error { get; private set; }

    public string CurrentTarget => Target is { Length: > 0 } t && Targets.Contains(t) ? t : Targets.FirstOrDefault(x => x == "si_asset_type") ?? Targets.FirstOrDefault() ?? "si_component";
    public IEnumerable<ClassificationMapping.Row> TargetRows => Rows.Where(r => r.Target == CurrentTarget);

    public async Task OnGetAsync(CancellationToken ct)
    {
        try
        {
            var rows = await _store.ListAsync(ct);
            Load(rows ?? Array.Empty<DataModelRow>());
            if (rows is null) { SchemaMissing = true; return; }
            if (!string.IsNullOrEmpty(Edit))
            {
                Editing = Rows.FirstOrDefault(r => r.Data.ItemKey == Edit);
                if (Editing is not null)
                {
                    Source ??= Editing.Source; Field ??= Editing.Field; Match ??= Editing.Match;
                    if (string.IsNullOrEmpty(Target)) Target = Editing.Target;
                    TargetValues = ClassificationMapping.TargetValues(CurrentTarget, TargetList, DimensionList, Rows);
                }
            }
            if (ClassificationMapping.Fields.Any(f => f.Field == Field) && Match is "equals" or "in")
            {
                try { Collected = await _store.CollectedForAsync(Field!, ClassificationMapping.SubjectOf(Field), ct); }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _log.LogWarning(ex, "the collected values for {Field} could not be read", Field);
                    CollectedError = "The values SecurityInsight collected could not be read: " + ex.Message;
                }
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "the classification mapping could not be read");
            Error = "The classification mapping could not be read from the Pro database: " + ex.Message;
        }
    }

    private void Load(IReadOnlyList<DataModelRow> rows)
    {
        DimensionList = Dimensions.Of(rows);
        Rows = ClassificationMapping.Of(rows);
        TargetList = ClassificationMapping.Targets(rows);
        Targets = TargetList.Select(t => t.Field).ToList();
        Dimension = DimensionList.FirstOrDefault(d => d.Id == CurrentTargetInfo?.Dimension);
        TargetValues = ClassificationMapping.TargetValues(CurrentTarget, TargetList, DimensionList, Rows);
    }

    /// Admin only: a new or changed row built by the wizard from closed sets and collected values.
    [SI.Management.Web.Audit.Audited("datamodel.item.stage")]
    public async Task<IActionResult> OnPostStageRowAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        var rows = await _store.ListAsync(ct) ?? Array.Empty<DataModelRow>();
        Load(rows);
        var existing = string.IsNullOrEmpty(Edit) ? null : Rows.FirstOrDefault(r => r.Data.ItemKey == Edit);
        if (!string.IsNullOrEmpty(Edit) && existing is null) return Toast(false, "the row is not in the classification mapping any more -- reload the page");
        var collected = ClassificationMapping.Fields.Any(f => f.Field == Field) && Match is "equals" or "in"
            ? await _store.CollectedForAsync(Field!, ClassificationMapping.SubjectOf(Field), ct)
            : Array.Empty<FactorCriteria.Collected>();
        var targetValues = ClassificationMapping.TargetValues(CurrentTarget, TargetList, DimensionList, Rows);
        var (key, body, why) = ClassificationMapping.Build(existing, Rows.Select(r => r.Id), new ClassificationMapping.Posted(Source, Field, Match, Pick, Pattern, Target, Set, Priority),
            collected, Targets.ToList(), targetValues.ToList());
        if (key is null || body is null) return Toast(false, string.Join("; ", why));
        return await StageAsync(key, ItemOverrideRepository.StateOverride, body, ct);
    }

    /// Admin only: remove a row -- a customer row is removed, a shipped row is turned off.
    [SI.Management.Web.Audit.Audited("datamodel.item.stage")]
    public async Task<IActionResult> OnPostRemoveRowAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        var rows = await _store.ListAsync(ct) ?? Array.Empty<DataModelRow>();
        var r = rows.FirstOrDefault(x => x.ItemKey == Key && x.Template == ClassificationMapping.Template);
        if (r is null) return Toast(false, "the row is not in the classification mapping any more -- reload the page");
        return await StageAsync(r.ItemKey, r.Own ? ItemOverrideRepository.StateInherit : ItemOverrideRepository.StateDisable, null, ct);
    }

    /// Admin only: put a changed or turned-off shipped row back as SecurityInsight ships it.
    [SI.Management.Web.Audit.Audited("datamodel.item.stage")]
    public async Task<IActionResult> OnPostRestoreRowAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        var rows = await _store.ListAsync(ct) ?? Array.Empty<DataModelRow>();
        var r = rows.FirstOrDefault(x => x.ItemKey == Key && x.Template == ClassificationMapping.Template);
        if (r is null || r.Own) return Toast(false, "only a shipped row can be put back");
        return await StageAsync(r.ItemKey, ItemOverrideRepository.StateInherit, null, ct);
    }

    private async Task<IActionResult> StageAsync(string key, string state, string? body, CancellationToken ct)
    {
        var (change, why) = await _changes.NewDataModelItemAsync(key, state, body, Reason ?? "", ct);
        if (change is null) return Toast(false, string.Join("; ", why));
        await _changes.StageAsync(User, change, ct);
        return Toast(true, change.Title);
    }

    private IActionResult Toast(bool ok, string text)
    {
        TempData["toast"] = ok ? "Staged: " + text + ". Nothing is written until you review and commit." : "Not staged: " + text;
        TempData["toastKind"] = ok ? "ok" : "error";
        return RedirectToPage(new { target = Target });
    }
}
