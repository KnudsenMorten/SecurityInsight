using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Core.ProData;
using SI.Management.Web.Audit;
using SI.Management.Web.Auth;
using SI.Management.Web.Changes;

namespace SI.Management.Web.Pages.Admin.Settings;

/// <summary>
/// #696: Admin &gt; Settings &gt; Risk rating -- the customer sets the thresholds of the risk rating. The rating keeps its
/// four words (Critical / High / Moderate / Low, si_risk_rating; it is for management); the three thresholds are the
/// customer's: the data-model list 'lists:risk_rating_bands' (shipped 50 / 30 / 15). The page shows the values in force,
/// the shipped default and the item's template conformance; an Admin stages new values as the list's override, or puts the
/// shipped list back, through the one data-model change path (<see cref="ChangeService.NewDataModelItemAsync"/>, Review
/// &amp; commit, cfg.ItemOverride; audited as datamodel.item.stage). The values are validated with
/// <see cref="RiskRatingBands.Problems"/> before anything is staged. "Preview" (GET, read-only) counts the findings of the
/// newest loaded collection per rating with the entered values, from its precomputed score distribution in SQL -- no
/// engine run. The next Risk Analysis run scores with the committed values.
/// </summary>
public sealed class RiskRatingModel : PageModel
{
    public const string Anchor = "risk-rating";

    private readonly RiskFactorStore _store;
    private readonly ChangeService _changes;
    private readonly TemplateConformance _conformance;
    private readonly ICollectionViews _views;
    private readonly ILogger<RiskRatingModel> _log;

    public RiskRatingModel(RiskFactorStore store, ChangeService changes, TemplateConformance conformance, ICollectionViews views, ILogger<RiskRatingModel> log)
    { _store = store; _changes = changes; _conformance = conformance; _views = views; _log = log; }

    /// The entered thresholds (the form; a GET with them is the preview).
    [BindProperty(SupportsGet = true)] public string? Critical { get; set; }
    [BindProperty(SupportsGet = true)] public string? High { get; set; }
    [BindProperty(SupportsGet = true)] public string? Moderate { get; set; }
    [BindProperty] public string? Reason { get; set; }

    public DataModelRow? Row { get; private set; }
    public RiskRatingBands InForce { get; private set; } = RiskRatingBands.Default;
    public RiskRatingBands Shipped { get; private set; } = RiskRatingBands.Default;
    /// The customer's override is in force (a valid one): "Reset to default" is offered.
    public bool Overridden => Row is { Overridden: true } || Row is { Disabled: true };
    /// The stored override is not a valid list: the engine scores with the built-in values until it is fixed.
    public bool OverrideInvalid => Row is { Overridden: true } && RiskRatingBands.FromList(Row.OverrideBody) is null;
    /// The item's template conformance (UpToDate / Overridden / UpgradeAvailable / ...); null = not read.
    public string? Conformance { get; private set; }
    public bool SchemaMissing { get; private set; }
    public string? Error { get; private set; }

    /// The preview: the entered values (null when not valid -- see <see cref="Problems"/>) and the counts.
    public RiskRatingBands? Entered { get; private set; }
    public IReadOnlyList<string> Problems { get; private set; } = Array.Empty<string>();
    public bool Previewing { get; private set; }
    public ViewCollection? Collection { get; private set; }
    public IReadOnlyDictionary<string, long>? NowCounts { get; private set; }
    public IReadOnlyDictionary<string, long>? InForceCounts { get; private set; }
    public IReadOnlyDictionary<string, long>? EnteredCounts { get; private set; }
    public string? PreviewNotice { get; private set; }

    public bool CanEdit => User.IsAdmin();

    public async Task OnGetAsync(CancellationToken ct)
    {
        await LoadAsync(ct);
        Previewing = !string.IsNullOrWhiteSpace(Critical) || !string.IsNullOrWhiteSpace(High) || !string.IsNullOrWhiteSpace(Moderate);
        if (Previewing)
        {
            var (bands, why) = RiskRatingThresholds.Parse(Critical, High, Moderate);
            Entered = bands; Problems = why;
        }
        else
        {
            Critical = Whole(InForce.Critical); High = Whole(InForce.High); Moderate = Whole(InForce.Moderate);
        }
        await PreviewAsync(ct);
    }

    /// "Preview": the entered values counted over the newest collection. Reads only -- nothing is staged or written.
    [NotAudited("a preview: counts the findings per rating with the entered values; stages and writes nothing")]
    public async Task<IActionResult> OnPostPreviewAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        await LoadAsync(ct);
        Previewing = true;
        var (bands, why) = RiskRatingThresholds.Parse(Critical, High, Moderate);
        Entered = bands; Problems = why;
        await PreviewAsync(ct);
        return Page();
    }

    private static string Whole(double v) => ((long)v).ToString(System.Globalization.CultureInfo.InvariantCulture);

    private async Task LoadAsync(CancellationToken ct)
    {
        try
        {
            var rows = await _store.ListAsync(ct);
            if (rows is null) SchemaMissing = true;
            else
            {
                Row = rows.FirstOrDefault(r => r.ItemKey == RiskRatingBands.ItemKey);
                InForce = RiskRatingThresholds.InForce(Row);
                Shipped = RiskRatingThresholds.Shipped(Row);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "the risk rating thresholds could not be read");
            Error = "The risk rating thresholds could not be read from the Pro database: " + ex.Message;
        }
        try
        {
            Conformance = (await _conformance.ListAsync(DataModelItemValidator.Kind, ct)).FirstOrDefault(r => r.ItemKey == RiskRatingBands.ItemKey)?.ConformanceText;
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "the risk rating conformance could not be read"); }
        Conformance ??= Row is null ? null : Row.Own ? TemplateConformance.Own : Row.Disabled ? TemplateConformance.Disabled : Row.Overridden ? TemplateConformance.Overridden : TemplateConformance.UpToDate;
    }

    /// The counts per rating of the newest loaded collection: now (the stored rating), with the values in force, and with
    /// the entered values -- all from its precomputed score distribution (sidata.FindingFacet).
    private async Task PreviewAsync(CancellationToken ct)
    {
        try
        {
            var cols = (await _views.CollectionsAsync(ct)).Data;
            Collection = cols.FirstOrDefault();
            if (Collection is null) { PreviewNotice = "No complete collection has been loaded into the Pro database yet, so there are no findings to count."; return; }
            if (Collection.DerivedAt is null) { PreviewNotice = "The newest collection's score counts are computed by the data sync after each load, and are not computed yet."; return; }
            var facets = (await _views.FacetsAsync(Collection, ct)).Data;
            NowCounts = RiskRatingThresholds.Now(facets);
            InForceCounts = RiskRatingThresholds.Preview(facets, InForce);
            if (Entered is not null) EnteredCounts = RiskRatingThresholds.Preview(facets, Entered);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogWarning(ex, "the risk rating preview could not be read");
            PreviewNotice = "The findings could not be counted: " + ex.Message;
        }
    }

    /// Admin only: the three numbers become the override of lists:risk_rating_bands, staged on Review &amp; commit.
    [Audited("datamodel.item.stage")]
    public async Task<IActionResult> OnPostStageAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        var (bands, why) = RiskRatingThresholds.Parse(Critical, High, Moderate);
        if (bands is null) return Refused(string.Join("; ", why));
        var rows = await _store.ListAsync(ct) ?? Array.Empty<DataModelRow>();
        var row = rows.FirstOrDefault(r => r.ItemKey == RiskRatingBands.ItemKey);
        if (RiskRatingBands.FromList(row?.Effective) == bands)
            return Refused("these are the thresholds in force already -- nothing to change");
        var (body, problems) = RiskRatingThresholds.WithBands(row?.Effective ?? row?.TemplateBody, bands);
        if (body is null) return Refused(string.Join("; ", problems));
        var reason = string.IsNullOrWhiteSpace(Reason) ? "Risk rating thresholds " + RiskRatingThresholds.Text(bands) : Reason!;
        var (change, refused) = await _changes.NewDataModelItemAsync(RiskRatingBands.ItemKey, ItemOverrideRepository.StateOverride, body, reason, ct);
        if (change is null) return Refused(string.Join("; ", refused));
        await _changes.StageAsync(User, change, ct);
        return Back(true, "Staged: the risk rating thresholds " + RiskRatingThresholds.Text(bands) + " (Critical / High / Moderate). Nothing is written until you review and commit; the next Risk Analysis run scores with them.");
    }

    /// Admin only: "Reset to default" -- the override is removed (state inherit), so the shipped list applies again.
    [Audited("datamodel.item.stage")]
    public async Task<IActionResult> OnPostResetAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        var rows = await _store.ListAsync(ct) ?? Array.Empty<DataModelRow>();
        var row = rows.FirstOrDefault(r => r.ItemKey == RiskRatingBands.ItemKey);
        if (row is null || (!row.Overridden && !row.Disabled)) return Refused("the shipped thresholds are in force already -- there is no change of yours to remove");
        var reason = string.IsNullOrWhiteSpace(Reason) ? "Risk rating thresholds back to the shipped default" : Reason!;
        var (change, refused) = await _changes.NewDataModelItemAsync(RiskRatingBands.ItemKey, ItemOverrideRepository.StateInherit, null, reason, ct);
        if (change is null) return Refused(string.Join("; ", refused));
        await _changes.StageAsync(User, change, ct);
        return Back(true, "Staged: the risk rating thresholds back to the shipped default " + RiskRatingThresholds.Text(RiskRatingThresholds.Shipped(row)) + ". Nothing is written until you review and commit.");
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
        return Redirect("/Admin/Settings/RiskRating#" + Anchor);
    }
}
