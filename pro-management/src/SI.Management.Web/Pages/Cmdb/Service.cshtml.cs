using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.Auth;
using SI.Management.Web.Cmdb;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Pages.Cmdb;

/// <summary>
/// One CMDB service: its fields (every CMDB.csv column, the extra ones too), the assets linked to it, and its change
/// history (cfg.ChangeLog). An SI-homed service is edited or retired here (Admin); the edit is refused when the service
/// changed since the page was opened. A retired service keeps its history and cannot be changed.
/// </summary>
[SI.Management.Web.Exemptions.ExemptedSurface(SI.Management.Web.Exemptions.ExemptedSurface.Views)]
public sealed class ServiceModel : SI.Management.Web.Columns.DataViewPageModel
{
    public const int AssetPage = 200;
    private readonly ICmdbStore _store;
    private readonly ISettingsStoreReader _history;
    private readonly ILogger<ServiceModel> _log;
    private readonly SI.Management.Core.ProData.ICiGraphViews? _graph;
    public ServiceModel(ICmdbStore store, ISettingsStoreReader history, ILogger<ServiceModel> log, SI.Management.Core.ProData.ICiGraphViews? graph = null)
    { _store = store; _history = history; _log = log; _graph = graph; }

    /// #496 the reverse view: the CIs this service owns (by the CI build -- a link, a service model rule or the CI's own CMDB
    /// record) with their open and overdue findings. Empty until the CI build has run with this release.
    public IReadOnlyList<SI.Management.Core.ProData.ServiceCiRow> OwnedCis { get; private set; } = Array.Empty<SI.Management.Core.ProData.ServiceCiRow>();
    public bool OwnedCisRead { get; private set; }
    /// #855 M19: the lifecycle of the owned CIs listed (default: active) and the rules its words come from.
    public SI.Management.Core.ProData.LifecycleFilter Lifecycle { get; private set; } = SI.Management.Core.ProData.LifecycleFilter.Active;
    public SI.Management.Core.ProData.CiLifecycleRules LifecycleRules { get; private set; } = SI.Management.Core.ProData.CiLifecycleDefinitions.Defaults;

    [BindProperty(SupportsGet = true)] public int Id { get; set; }

    public CmdbService? Service { get; private set; }
    public string Source { get; private set; } = CmdbSources.SI;
    public IReadOnlyList<MapAsset> Assets { get; private set; } = Array.Empty<MapAsset>();
    public long AssetTotal { get; private set; }
    public IReadOnlyList<ChangeLogRow> History { get; private set; } = Array.Empty<ChangeLogRow>();
    public string? Error { get; private set; }
    public bool Editable => Service is { Retired: false } s && s.Source == CmdbSources.SI && Source == CmdbSources.SI;

    public async Task<IActionResult> OnGetAsync(CancellationToken ct)
    {
        await LoadAsync(ct);
        return Service is null && Error is null ? NotFound() : Page();
    }

    private async Task LoadAsync(CancellationToken ct)
    {
        try
        {
            Source = (await _store.ActiveSourceAsync(ct)).Source;
            Service = await _store.ServiceAsync(Id, ct);
            if (Service is null) return;
            // #855 M18 / M19: the linked assets and the owned CIs of the lifecycle chosen (default: active)
            Lifecycle = SI.Management.Web.Pages.LifecycleChoice.Read(Request);
            try
            {
                (Assets, AssetTotal) = await _store.ServiceAssetsAsync(Id, new MapFilter { Lifecycle = Lifecycle.Key }, 0, AssetPage, ct);
                // #589: an export takes EVERY linked asset, page by page
                if (Exporting)
                {
                    var all = Assets.ToList();
                    while (all.Count < AssetTotal && all.Count < SI.Management.Core.ProData.ProDataFilters.MaxExport)
                    {
                        var (more, _) = await _store.ServiceAssetsAsync(Id, new MapFilter { Lifecycle = Lifecycle.Key }, all.Count, SI.Management.Core.ProData.ProDataFilters.MaxTake, ct);
                        if (more.Count == 0) break;
                        all.AddRange(more);
                    }
                    Assets = all;
                }

            }
            catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "the service's assets could not be read"); }
            if (_graph is not null)
            {
                // #855 M19: the CIs of the lifecycle chosen (default: active), said above the list
                try { if (HttpContext?.RequestServices.GetService<SI.Management.Core.ProData.ICiLifecycleRulesReader>() is { } lr) LifecycleRules = await lr.ReadAsync(ct); }
                catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "the lifecycle settings could not be read; the defaults are shown"); }
                try { OwnedCis = (await _graph.ServiceCisAsync(Service.Number, Lifecycle, ct)).Data; OwnedCisRead = true; }
                catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "the service's CIs could not be read"); }
            }
            History = (await _history.ReadChangeLogAsync("cmdb/" + Service.Number, 100, ct)).Rows
                .Where(r => r.Name.Equals("cmdb/" + Service.Number, StringComparison.OrdinalIgnoreCase)).ToList();
            if (!Exporting) await LoadTablesAsync(ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "the CMDB service could not be read");
            Error = "The service could not be read from the Pro database: " + ex.Message;
        }
    }

    // ---- #589 the linked assets and the owned CIs as the shared data table ----------------------------------------------

    protected override Task LoadForExportAsync(CancellationToken ct) => LoadAsync(ct);

    protected override IReadOnlyList<SI.Management.Web.Columns.DataTable> BuildTables()
    {
        static MapAsset A(object o) => (MapAsset)o;
        static SI.Management.Core.ProData.ServiceCiRow C(object o) => (SI.Management.Core.ProData.ServiceCiRow)o;
        var svc = Service?.Number ?? "";
        var assets = new SI.Management.Web.Columns.DataTable
        {
            Id = "assets", View = "cmdb-service-assets", Title = "Linked assets " + svc, Rows = Assets.Cast<object>().ToList(), Marker = "data-service-assets",
            Ci = SI.Management.Core.ProData.RowCiKey.AssetKey, RefOf = o => new SI.Management.Web.Columns.RowRef(A(o).AssetKey),
            Columns =
            [
                new("AssetName", "Asset", o => A(o).AssetName, Link: o => "/Findings?q=" + Uri.EscapeDataString(A(o).AssetName)),
                new("AssetKey", "Asset (CI) key", o => A(o).AssetKey, Link: o => "/Collection/Asset?key=" + Uri.EscapeDataString(A(o).AssetKey)),
                new("AssetKind", "Kind", o => A(o).AssetKind),
                new("Tier", "Tier", o => A(o).Tier),
                new("WeightedRisk", "Weighted risk", o => A(o).WeightedRisk, Number: true),
                new("Services", "Services it is in", o => A(o).Services, Number: true),
                new("ServiceNumbers", "Services", o => A(o).ServiceNumbers),
            ],
        };
        var cis = new SI.Management.Web.Columns.DataTable
        {
            Id = "cis", View = "cmdb-service-cis", Title = "CIs of " + svc, Rows = OwnedCis.Cast<object>().ToList(),
            Ci = SI.Management.Core.ProData.RowCiKey.CiId, RefOf = o => new SI.Management.Web.Columns.RowRef(C(o).CiId),
            RowAttributes = o => new Dictionary<string, string?> { ["data-ci"] = C(o).CiId },
            Columns =
            [
                new("Name", "CI", o => C(o).Name ?? C(o).CiId, Link: o => "/Cis/Detail?id=" + Uri.EscapeDataString(C(o).CiId)),
                // "CI key": the extra column "CI id" (the CI found in the CI list by this key) is offered next to it
                new("CiId", "CI key", o => C(o).CiId),
                new("Class", "Class", o => C(o).Class),
                new("Tier", "Tier", o => C(o).Tier is >= 0 and <= 3 ? "Tier " + C(o).Tier : "Unclassified"),
                new("Lifecycle", "Lifecycle", o => C(o).Lifecycle),
                new("MatchedBy", "Placed by", o => C(o).MatchedBy),
                new("Strictest", "Decides its criticality", o => C(o).Strictest),
                new("CiSource", "Source", o => C(o).Source),
                new("OpenFindings", "Open findings", o => C(o).OpenFindings, Number: true),
                new("OverdueFindings", "Overdue", o => C(o).OverdueFindings, Number: true),
                new("OpenCritical", "Very High", o => C(o).OpenCritical, Number: true),
                new("OpenHigh", "High", o => C(o).OpenHigh, Number: true),
                new("WeightedRiskScore", "Weighted risk", o => C(o).WeightedRiskScore, Number: true, Text: o => Fmt.Score(C(o).WeightedRiskScore)),
            ],
        };
        cis.Html["Name"] = o => new Microsoft.AspNetCore.Html.HtmlString("<a href=\"/Cis/Detail?id=" + System.Net.WebUtility.HtmlEncode(Uri.EscapeDataString(C(o).CiId)) + "\">"
            + System.Net.WebUtility.HtmlEncode(C(o).Name ?? C(o).CiId) + "</a>" + (C(o).Strictest ? " <span class=\"badge info\">decides its criticality</span>" : ""));
        // overdue findings stand out (a warning badge), as before the table became the shared one
        cis.Html["OverdueFindings"] = o => C(o).OverdueFindings > 0
            ? SI.Management.Web.Columns.DataCellHtml.Badges(("warn", Fmt.Int(C(o).OverdueFindings)))
            : new Microsoft.AspNetCore.Html.HtmlString(System.Net.WebUtility.HtmlEncode(Fmt.Int(C(o).OverdueFindings)));
        return [assets, cis];
    }

    [BindProperty] public string? Name { get; set; }
    [BindProperty] public string? Description { get; set; }
    [BindProperty] public string? Owner { get; set; }
    [BindProperty] public string? OwnerMail { get; set; }
    [BindProperty] public string? Criticality { get; set; }
    [BindProperty] public string? DataSensitivity { get; set; }
    [BindProperty] public string? Environment { get; set; }
    [BindProperty] public string? Department { get; set; }
    [BindProperty] public string? Reason { get; set; }
    [BindProperty] public long Version { get; set; }

    [SI.Management.Web.Audit.Audited("cmdb.service.save")]
    public async Task<IActionResult> OnPostSaveAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        var r = await _store.UpdateAsync(Id, new CmdbServiceInput(Name ?? "", Description, Owner, OwnerMail, Criticality, DataSensitivity, Environment, Department), Version, User.ChangeName(), Reason, ct);
        return Done(r, "Saved", "Not saved: ");
    }

    [SI.Management.Web.Audit.Audited("cmdb.service.retire")]
    public async Task<IActionResult> OnPostRetireAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        var r = await _store.RetireAsync(Id, Version, User.ChangeName(), Reason ?? "", ct);
        return Done(r, "Retired -- the service and its history are kept", "Not retired: ");
    }

    private IActionResult Done(WriteResult r, string ok, string not)
    {
        TempData["toast"] = r.Status == WriteStatus.Saved ? ok : not + r.Message;
        TempData["toastKind"] = r.Status == WriteStatus.Saved ? "ok" : "error";
        return RedirectToPage(new { id = Id });
    }
}
