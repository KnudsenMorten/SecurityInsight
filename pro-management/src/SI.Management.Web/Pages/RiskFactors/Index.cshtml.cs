using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.Auth;
using SI.Management.Web.Changes;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Pages.RiskFactors;

/// <summary>
/// #527 (4) Risk factors (readers see it; every change checks Admin itself). The factor list with each factor's provider
/// links, the provider mappings (where every raw source field lives), and the network ranges -- all from the Pro data
/// model IN SQL: the 'datamodel' cfg.Template rows plus the customer's cfg.ItemOverride rows; the ranges are the setting
/// SI_InternetExposedRanges. An Admin changes a factor or a mapping (its JSON), turns one off or puts the shipped one
/// back: staged on Review &amp; commit, written as a cfg.ItemOverride row in the signed-in name. UpgradeAvailable (the
/// shipped item changed under an override) comes from the template conformance view and is decided there.
/// A renamed or new SOURCE field is a mapping change -- a factor reads SI fields only (owner 2026-10-10).
/// </summary>
public sealed class IndexModel : PageModel
{
    public const string RangesSetting = "SI_InternetExposedRanges";

    private readonly RiskFactorStore _store;
    private readonly TemplateConformance _conformance;
    private readonly ISettingsStoreReader _settings;
    private readonly ChangeService _changes;
    private readonly ILogger<IndexModel> _log;

    private readonly SI.Management.Web.RiskIndex.IRiskIndexStore _riskIndex;

    public IndexModel(RiskFactorStore store, TemplateConformance conformance, ISettingsStoreReader settings, ChangeService changes, SI.Management.Web.RiskIndex.IRiskIndexStore riskIndex, ILogger<IndexModel> log)
    { _store = store; _conformance = conformance; _settings = settings; _changes = changes; _riskIndex = riskIndex; _log = log; }

    /// The score preview's sample finding (GET): the risk index matchers, each a dropdown of the values the index names.
    /// Bases = "index" (the risk index in force gives both bases, first match) or "manual" (Ab / Vb).
    [BindProperty(SupportsGet = true)] public string? Bases { get; set; }
    [BindProperty(SupportsGet = true)] public Dictionary<string, string>? Sample { get; set; }
    /// The risk index in force, in first-match order (empty when it cannot be read).
    public IReadOnlyList<SI.Management.Core.ProData.RiskIndexRow> IndexRows { get; private set; } = Array.Empty<SI.Management.Core.ProData.RiskIndexRow>();
    public bool UseIndex => IndexRows.Count > 0 && Bases != "manual";
    public string SampleValue(string column) => Sample is not null && Sample.TryGetValue(column, out var v) ? v ?? "" : "";

    /// The sample finding from the picked values -- only values the index names are taken (a closed set).
    public SI.Management.Core.ProData.RiskIndexFinding SampleFinding()
    {
        string P(string c) { var v = SampleValue(c); return RiskFactorModel.IndexValues(IndexRows, c).Contains(v, StringComparer.OrdinalIgnoreCase) ? v : ""; }
        string Pick(string c, IReadOnlyList<string> allowed) { var v = SampleValue(c); return allowed.Contains(v, StringComparer.OrdinalIgnoreCase) ? v : ""; }
        var cols = SI.Management.Core.ProData.RiskIndexColumns.SharedMatchers;
        return new SI.Management.Core.ProData.RiskIndexFinding(P(cols[0]), P(cols[1]), P(cols[2]), P(cols[3]), P(cols[4]),
            Pick(SI.Management.Core.ProData.RiskIndexColumns.AssetClass, SI.Management.Core.ProData.RiskIndexVocabulary.AssetClasses),
            Pick(SI.Management.Core.ProData.RiskIndexColumns.Severity, SI.Management.Core.ProData.RiskIndexVocabulary.Severities),
            Pick(SI.Management.Core.ProData.RiskIndexColumns.Tier, SI.Management.Core.ProData.RiskIndexVocabulary.Tiers));
    }

    [BindProperty(SupportsGet = true)] public string? Key { get; set; }
    [BindProperty] public string? Body { get; set; }
    [BindProperty] public string? Reason { get; set; }

    /// The factor list as shown: filtered by About / Group and sorted (AllFactors = every factor).
    public IReadOnlyList<RiskFactorView> Factors { get; private set; } = Array.Empty<RiskFactorView>();
    public IReadOnlyList<RiskFactorView> AllFactors { get; private set; } = Array.Empty<RiskFactorView>();
    public IReadOnlyList<string> Groups { get; private set; } = Array.Empty<string>();
    /// Filter + sort of the factor list (GET): About = Asset | Vulnerability, Group, Sort = a column key, Desc.
    [BindProperty(SupportsGet = true)] public string? About { get; set; }
    [BindProperty(SupportsGet = true)] public string? Group { get; set; }
    [BindProperty(SupportsGet = true)] public string? Sort { get; set; }
    [BindProperty(SupportsGet = true)] public bool Desc { get; set; }
    /// The score preview (GET, read-only): the asset-side base, the vulnerability-side base and the picked factors.
    [BindProperty(SupportsGet = true)] public int? Ab { get; set; }
    [BindProperty(SupportsGet = true)] public int? Vb { get; set; }
    [BindProperty(SupportsGet = true)] public string[]? Pf { get; set; }
    public RiskFactorModel.ScorePreview? Preview { get; private set; }
    /// The posted impact (1-5) or state (enabled / disabled) of one factor.
    [BindProperty] public string? Impact { get; set; }
    [BindProperty] public string? FactorState { get; set; }
    public IReadOnlyList<(string Provider, string Field, string Sources, DataModelRow Row)> Mappings { get; private set; } = Array.Empty<(string, string, string, DataModelRow)>();
    public IReadOnlyList<string> Ranges { get; private set; } = Array.Empty<string>();
    /// #541 (6): the report x factor matrix (read view) -- which factors reach which Risk Analysis report, derived as the engine does
    public IReadOnlyList<ReportFactorRow> Matrix { get; private set; } = Array.Empty<ReportFactorRow>();
    /// #464 the same recommendation across providers (data-model template recommendation-equivalence).
    public IReadOnlyList<(string Title, string CanonicalId, IReadOnlyList<string> Members, string Stage, DataModelRow Row)> Equivalences { get; private set; } = Array.Empty<(string, string, IReadOnlyList<string>, string, DataModelRow)>();
    /// item key -> its conformance state (UpToDate / Overridden / Disabled / UpgradeAvailable / Own / Retired)
    public IReadOnlyDictionary<string, string> States { get; private set; } = new Dictionary<string, string>();
    public DataModelRow? Selected { get; private set; }
    /// #541 (7): the criteria wizard of the selected factor (null = it has no criteria -- the JSON editor only)
    public FactorCriteria? Criteria { get; private set; }
    public DataModelRow? CriteriaList { get; private set; }
    public IReadOnlyList<FactorCriteria.ListEntry> ListEntries { get; private set; } = Array.Empty<FactorCriteria.ListEntry>();
    public IReadOnlyList<FactorCriteria.Collected> Collected { get; private set; } = Array.Empty<FactorCriteria.Collected>();
    public int? Threshold { get; private set; }
    public string? CollectedError { get; private set; }
    public bool SchemaMissing { get; private set; }
    public string? Error { get; private set; }

    private string? Joined(string key) =>
        MultiFilter.ValuesOf(Request.Query, key) is { Count: > 0 } v ? string.Join(SI.Management.Core.ProData.ProDataFilters.ValueSeparator, v) : null;

    /// The chosen values of the About / Group filter.
    public IReadOnlyList<string> Chosen(string? joined) => SI.Management.Core.ProData.ProDataFilters.Values(joined);

    public string StateOf(DataModelRow r) => States.TryGetValue(r.ItemKey, out var s) ? s : r.Own ? TemplateConformance.Own : r.Disabled ? TemplateConformance.Disabled : r.Overridden ? TemplateConformance.Overridden : TemplateConformance.UpToDate;

    public async Task OnGetAsync(CancellationToken ct)
    {
        try
        {
            var rows = await _store.ListAsync(ct);
            if (rows is null) { SchemaMissing = true; return; }
            AllFactors = RiskFactorStore.Factors(rows);
            Groups = RiskFactorModel.Groups(AllFactors);
            // the filters take several values (one parameter per value): '|'-joined for the list
            (About, Group) = (Joined("about") ?? About, Joined("group") ?? Group);
            Factors = RiskFactorModel.Arrange(AllFactors, About, Group, Sort, Desc);
            try { if (await _riskIndex.SchemaAsync(ct)) IndexRows = (await _riskIndex.LoadAsync(ct)).Ordered; }
            catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "the risk index could not be read for the score preview"); }
            Preview = (UseIndex ? RiskFactorModel.PreviewFromIndex(AllFactors, IndexRows, SampleFinding(), Pf) : RiskFactorModel.Preview(AllFactors, Ab, Vb, Pf))
                with { Bands = RiskFactorStore.Bands(rows) };
            Mappings = RiskFactorStore.Mappings(rows);
            try { Matrix = ReportFactorMatrix.Build(rows, SI.Management.Core.ProData.CiColumns.FieldClasses); }
            catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "the report x factor matrix could not be built"); }
            Equivalences = RiskFactorStore.Equivalences(rows);
            try { States = (await _conformance.ListAsync(DataModelItemValidator.Kind, ct)).ToDictionary(r => r.ItemKey, r => r.Conformance, StringComparer.Ordinal); }
            catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "the data-model conformance could not be read"); }
            try
            {
                var (settings, _) = await _settings.ReadSettingsAsync(ct);
                Ranges = ParseRanges(settings.FirstOrDefault(s => string.Equals(s.Name, RangesSetting, StringComparison.OrdinalIgnoreCase))?.ValueJson);
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "the network ranges setting could not be read"); }
            if (!string.IsNullOrWhiteSpace(Key)) Selected = rows.FirstOrDefault(r => r.ItemKey == Key);
            if (Selected is not null && Selected.Template == "risk-factors") await LoadCriteriaAsync(rows, Selected, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "the risk factors could not be read");
            Error = "The risk factors could not be read from the Pro database: " + ex.Message;
        }
    }

    private async Task LoadCriteriaAsync(IReadOnlyList<DataModelRow> rows, DataModelRow factor, CancellationToken ct)
    {
        var body = factor.Effective ?? factor.TemplateBody;
        Criteria = FactorCriteria.Of(body);
        if (Criteria is null || body is null) return;
        if (Criteria.Kind == "threshold") { Threshold = Criteria.CurrentThreshold(body); return; }
        if (Criteria.Kind != "list" || Criteria.List is null) return;
        CriteriaList = rows.FirstOrDefault(r => r.ItemKey == "lists:" + Criteria.List);
        ListEntries = FactorCriteria.Entries(CriteriaList?.Effective ?? CriteriaList?.TemplateBody);
        if (Criteria.Source != "collected") return;
        try { Collected = await _store.CollectedAsync(Criteria.Field, Criteria.DetailField, ct); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogWarning(ex, "the collected values for {Field} could not be read", Criteria.Field);
            CollectedError = "The values SecurityInsight collected could not be read: " + ex.Message;
        }
    }

    [BindProperty] public string? Value { get; set; }
    [BindProperty] public int[]? Keep { get; set; }
    [BindProperty] public string[]? Pick { get; set; }

    /// Admin only: the threshold wizard -- a whole number inside the criteria's range becomes the factor's override.
    [SI.Management.Web.Audit.Audited("datamodel.item.stage")]
    public async Task<IActionResult> OnPostStageThresholdAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        var rows = await _store.ListAsync(ct) ?? Array.Empty<DataModelRow>();
        var f = rows.FirstOrDefault(r => r.ItemKey == Key && r.Template == "risk-factors");
        var body = f?.Effective ?? f?.TemplateBody;
        var crit = FactorCriteria.Of(body);
        if (f is null || body is null || crit is null) return Toast(false, "this factor has no threshold to set");
        var (nb, why) = crit.WithThreshold(body, Value);
        if (nb is null) return Toast(false, string.Join("; ", why));
        return await StageAsync(f.ItemKey, nb, ct);
    }

    /// Admin only: the list wizard -- the kept entries plus the picked COLLECTED values become the list's override.
    [SI.Management.Web.Audit.Audited("datamodel.item.stage")]
    public async Task<IActionResult> OnPostStageListAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        var rows = await _store.ListAsync(ct) ?? Array.Empty<DataModelRow>();
        var f = rows.FirstOrDefault(r => r.ItemKey == Key && r.Template == "risk-factors");
        var crit = FactorCriteria.Of(f?.Effective ?? f?.TemplateBody);
        if (crit is null || crit.Kind != "list" || crit.List is null) return Toast(false, "this factor has no list to change");
        var list = rows.FirstOrDefault(r => r.ItemKey == "lists:" + crit.List);
        var lb = list?.Effective ?? list?.TemplateBody;
        if (lb is null) return Toast(false, $"the list '{crit.List}' is not in the data model");
        var collected = crit.Source == "collected" ? await _store.CollectedAsync(crit.Field, crit.DetailField, ct) : Array.Empty<FactorCriteria.Collected>();
        var (nb, why) = crit.WithList(lb, Keep ?? Array.Empty<int>(), Pick ?? Array.Empty<string>(), collected);
        if (nb is null) return Toast(false, string.Join("; ", why));
        return await StageAsync("lists:" + crit.List, nb, ct);
    }

    /// Admin only: a factor's impact (1 very low .. 5 very high) becomes the factor's override.
    [SI.Management.Web.Audit.Audited("datamodel.item.stage")]
    public async Task<IActionResult> OnPostStageImpactAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        var rows = await _store.ListAsync(ct) ?? Array.Empty<DataModelRow>();
        var f = rows.FirstOrDefault(r => r.ItemKey == Key && r.Template == "risk-factors");
        if (f is null) return Toast(false, "the factor is not in the data model");
        var (nb, why) = RiskFactorModel.WithImpact(f.Effective ?? f.TemplateBody ?? f.OverrideBody, Impact);
        if (nb is null) return Toast(false, string.Join("; ", why));
        return await StageAsync(f.ItemKey, nb, ct, f);
    }

    /// Admin only: an OPTIONAL factor switched on or off (its state); a built-in factor is always on and is refused.
    [SI.Management.Web.Audit.Audited("datamodel.item.stage")]
    public async Task<IActionResult> OnPostStageStateAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        var rows = await _store.ListAsync(ct) ?? Array.Empty<DataModelRow>();
        var f = rows.FirstOrDefault(r => r.ItemKey == Key && r.Template == "risk-factors");
        if (f is null) return Toast(false, "the factor is not in the data model");
        var (nb, why) = RiskFactorModel.WithState(f, f.Effective ?? f.TemplateBody ?? f.OverrideBody, FactorState);
        if (nb is null) return Toast(false, string.Join("; ", why));
        return await StageAsync(f.ItemKey, nb, ct, f);
    }

    /// Admin only: #693 the promotion switch -- a meaning rule at stage testing made live (its stage set to production; one
    /// data-model override, staged on Review &amp; commit). Folds from the next Risk Analysis run.
    [SI.Management.Web.Audit.Audited("datamodel.item.stage")]
    public async Task<IActionResult> OnPostStagePromoteAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        var rows = await _store.ListAsync(ct) ?? Array.Empty<DataModelRow>();
        var g = rows.FirstOrDefault(r => r.ItemKey == Key && r.Template == "recommendation-equivalence");
        if (g is null) return Toast(false, "the rule is not in the data model");
        var (nb, why) = RiskFactorStore.PromoteFold(g.Effective ?? g.TemplateBody ?? g.OverrideBody);
        if (nb is null) return Toast(false, why ?? "the rule cannot be promoted");
        if (string.IsNullOrWhiteSpace(Reason)) Reason = "promoted from testing to live";
        return await StageAsync(g.ItemKey, nb, ct, g);
    }

    private async Task<IActionResult> StageAsync(string itemKey, string body, CancellationToken ct, DataModelRow? shipped = null)
    {
        var refused = RiskFactorModel.ShippedProblems(shipped, ItemOverrideRepository.StateOverride, body);
        if (refused.Count > 0) return Toast(false, string.Join("; ", refused));
        var (change, why) = await _changes.NewDataModelItemAsync(itemKey, ItemOverrideRepository.StateOverride, body, Reason ?? "", ct);
        if (change is null) return Toast(false, string.Join("; ", why));
        await _changes.StageAsync(User, change, ct);
        return Toast(true, change.Title);
    }

    private IActionResult Toast(bool ok, string text)
    {
        TempData["toast"] = ok ? "Staged: " + text + ". Nothing is written until you review and commit." : "Not staged: " + text;
        TempData["toastKind"] = ok ? "ok" : "error";
        return RedirectToPage(new { key = Key });
    }
    /// PURE. The setting's value (a JSON list or one string, ';' / ',' / space separated) as ranges.
    public static IReadOnlyList<string> ParseRanges(string? valueJson)
    {
        if (string.IsNullOrWhiteSpace(valueJson)) return Array.Empty<string>();
        var parts = new List<string>();
        try
        {
            using var d = JsonDocument.Parse(valueJson);
            if (d.RootElement.ValueKind == JsonValueKind.Array) parts.AddRange(d.RootElement.EnumerateArray().Select(x => x.ToString()));
            else parts.Add(d.RootElement.ToString());
        }
        catch (JsonException) { parts.Add(valueJson); }
        return parts.SelectMany(p => p.Split(new[] { ';', ',', ' ', '\t', '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries)).Distinct(StringComparer.Ordinal).ToList();
    }

    /// Admin only: stage a changed factor / mapping (Body = its JSON), or turning it off, or the shipped one back.
    [SI.Management.Web.Audit.Audited("datamodel.item.stage")]
    public async Task<IActionResult> OnPostStageAsync(string decision, CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        var state = decision switch { "override" => ItemOverrideRepository.StateOverride, "disable" => ItemOverrideRepository.StateDisable, "inherit" => ItemOverrideRepository.StateInherit, _ => "" };
        // a built-in factor is always on: refused against the SHIPPED item before the generic checks
        var shipped = (Key ?? "").StartsWith("risk-factors:", StringComparison.Ordinal) ? (await _store.ListAsync(ct) ?? Array.Empty<DataModelRow>()).FirstOrDefault(r => r.ItemKey == Key) : null;
        var refused = RiskFactorModel.ShippedProblems(shipped, state, Body);
        StagedChange? change = null;
        IReadOnlyList<string> why = refused;
        if (refused.Count == 0) (change, why) = await _changes.NewDataModelItemAsync(Key ?? "", state, Body, Reason ?? "", ct);
        if (change is not null)
        {
            await _changes.StageAsync(User, change, ct);
            TempData["toast"] = "Staged: " + change.Title + ". Nothing is written until you review and commit.";
            TempData["toastKind"] = "ok";
        }
        else
        {
            TempData["toast"] = "Not staged: " + string.Join("; ", why);
            TempData["toastKind"] = "error";
        }
        return RedirectToPage(new { key = Key });
    }

    public static string Badge(string state) => state switch
    {
        TemplateConformance.UpToDate => "good",
        TemplateConformance.UpgradeAvailable => "warn",
        TemplateConformance.Disabled or TemplateConformance.Retired => "bad",
        _ => "",
    };

    /// The body to edit: pretty-printed JSON of the body in force (the template's when the item is switched off).
    public static string Pretty(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return "";
        try { using var d = JsonDocument.Parse(json); return JsonSerializer.Serialize(d.RootElement, new JsonSerializerOptions { WriteIndented = true }); }
        catch (JsonException) { return json; }
    }
}
