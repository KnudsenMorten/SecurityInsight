using System.Globalization;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.Auth;
using SI.Management.Web.Changes;
using SI.Management.Web.Cmdb;

namespace SI.Management.Web.Pages.Cmdb;

/// <summary>
/// THE SERVICE MAP (#256), the tier board's way: services are lanes, assets are cards (name, kind, tier, weighted risk of
/// the newest collection), loaded page by page from the server. The first lane is the ASSET POOL, filtered on the
/// server (kind, tier, department, unlinked only, text). Select cards (their checkbox, or Ctrl/Cmd-click) or tick "all
/// matching the filter", then DRAG them onto a service to link them; drag cards out of a service lane back onto the pool
/// to unlink them from that service; drag from one service onto another to add them there too.
/// AN ASSET IN SEVERAL SERVICES appears as a card in EACH of their lanes, with a badge "in N services" (the numbers on
/// hover); linking it to one more service never removes it from another -- only an unlink does.
/// A drop NEVER writes: it stages ONE change through the existing staging (Review &amp; commit), like the tier board.
/// With an external CMDB the map shows the links read-only; changes are made in the source.
/// </summary>
[SI.Management.Web.Exemptions.ExemptedSurface(SI.Management.Web.Exemptions.ExemptedSurface.Views)]
public sealed class MapModel : PageModel
{
    public const int PageSize = 30;
    public const string Pool = "pool";
    private readonly ICmdbStore _store;
    private readonly ChangeService _changes;
    private readonly CmdbChanges _cmdb;
    private readonly ILogger<MapModel> _log;
    public MapModel(ICmdbStore store, ChangeService changes, CmdbChanges cmdb, ILogger<MapModel> log) { _store = store; _changes = changes; _cmdb = cmdb; _log = log; }

    [BindProperty(SupportsGet = true)] public string? Kind { get; set; }
    [BindProperty(SupportsGet = true)] public string? Tier { get; set; }
    [BindProperty(SupportsGet = true)] public string? Q { get; set; }
    [BindProperty(SupportsGet = true)] public string? Dept { get; set; }
    [BindProperty(SupportsGet = true)] public bool Unlinked { get; set; }

    public string Source { get; private set; } = CmdbSources.SI;
    public bool ReadOnly => CmdbSources.IsReadOnly(Source);
    public IReadOnlyList<CmdbService> Services { get; private set; } = Array.Empty<CmdbService>();
    public IReadOnlyList<string> Departments { get; private set; } = Array.Empty<string>();
    public IReadOnlyList<MapAsset> PoolAssets { get; private set; } = Array.Empty<MapAsset>();
    public long PoolTotal { get; private set; }
    public Dictionary<int, (IReadOnlyList<MapAsset> Assets, long Total)> Lanes { get; } = new();
    public IReadOnlyList<StagedChange> Pending { get; private set; } = Array.Empty<StagedChange>();
    public string? Error { get; private set; }

    public MapFilter Filter => new() { Kind = Many("kind", Kind), Tier = Many("tier", Tier), Text = N(Q), Department = Many("dept", Dept), UnlinkedOnly = Unlinked, Lifecycle = LifecycleInForce.Key };

    /// #855 M18: the CI lifecycle of the assets on the map (default: active), from the address; said and chosen on the page.
    public SI.Management.Core.ProData.LifecycleFilter LifecycleInForce => SI.Management.Web.Pages.LifecycleChoice.Read(HttpContext?.Request);
    public SI.Management.Core.ProData.CiLifecycleRules LifecycleRules { get; private set; } = SI.Management.Core.ProData.CiLifecycleDefinitions.Defaults;
    private static string? N(string? s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();

    /// A filter of several values (owner 2026-10-19: every filter multi-select): one parameter per value, or '|'-joined;
    /// the model binds the first value only, so the values are read here.
    private string? Many(string key, string? bound)
    {
        var values = HttpContext?.Request is { } r ? MultiFilter.ValuesOf(r.Query, key) : Array.Empty<string>();
        return values.Count == 0 ? N(bound) : string.Join(SI.Management.Core.ProData.ProDataFilters.ValueSeparator, values);
    }

    /// The chosen values of one filter (kind, tier, dept).
    public IReadOnlyList<string> Chosen(string key) => SI.Management.Core.ProData.ProDataFilters.Values(key switch { "kind" => Filter.Kind, "tier" => Filter.Tier, "dept" => Filter.Department, _ => null });

    /// The query string the cards and the stage call carry (the same filter on every request).
    public string QueryString => string.Concat(
        Filter.Kind is { Length: > 0 } k ? "&kind=" + Uri.EscapeDataString(k) : "", Filter.Tier is { Length: > 0 } t ? "&tier=" + Uri.EscapeDataString(t) : "",
        Q is { Length: > 0 } ? "&q=" + Uri.EscapeDataString(Q) : "", Filter.Department is { Length: > 0 } d ? "&dept=" + Uri.EscapeDataString(d) : "", Unlinked ? "&unlinked=true" : "",
        LifecycleInForce.QueryValue is { } lv ? "&" + SI.Management.Core.ProData.LifecycleFilter.Parameter + "=" + Uri.EscapeDataString(lv) : "");

    public sealed record Card(string Key, string Name, string? Kind, string Tier, string? Risk, int Services, string? Numbers);
    public static Card ToCard(MapAsset a) => new(a.AssetKey, a.AssetName, a.AssetKind, a.Tier,
        // shown on the card (and by cmdbmap.js) in the viewer's number format
        a.WeightedRisk is { } w ? SI.Management.Core.ProData.ScoreFormat.Whole(w) : null, a.Services, a.ServiceNumbers);

    public async Task OnGetAsync(CancellationToken ct)
    {
        try
        {
            if (!(await _store.SchemaAsync(ct)).HasCmdb) { Error = "This database has no CMDB tables yet. Run the Pro settings schema (setup) once."; return; }
            Source = (await _store.ActiveSourceAsync(ct)).Source;
            try { if (HttpContext?.RequestServices.GetService<SI.Management.Core.ProData.ICiLifecycleRulesReader>() is { } lr) LifecycleRules = await lr.ReadAsync(ct); }
            catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "the lifecycle settings could not be read; the defaults are shown"); }
            var all = await _store.ServicesAsync(Source, false, ct);
            Departments = all.Select(s => s.Department).Where(d => !string.IsNullOrWhiteSpace(d)).Select(d => d!).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(d => d).ToList();
            var depts = Chosen("dept");
            Services = depts.Count > 0 ? all.Where(s => depts.Contains(s.Department ?? "", StringComparer.OrdinalIgnoreCase)).ToList() : all;
            (PoolAssets, PoolTotal) = await _store.AssetsAsync(Filter, 0, PageSize, ct);
            foreach (var s in Services) Lanes[s.ServiceId] = await _store.ServiceAssetsAsync(s.ServiceId, Filter, 0, PageSize, ct);
            if (User.IsAdmin()) Pending = (await _changes.PendingAsync(User, ct)).Where(p => p.Kind == ChangeKinds.CmdbLink).ToList();
        }
        catch (ArgumentException ex) { Error = "The filter is not valid: " + ex.Message; }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "the service map could not be read");
            Error = "The service map could not be read from the Pro database: " + ex.Message;
        }
    }

    /// The staged links the map draws dashed: asset key -> target lane (service id), or the pool for an unlink.
    public object StagedForMap() => Pending.SelectMany(p => CmdbChanges.AssetsOf(p).Select(a => new
    {
        assetKey = a.Key, lane = p.Get("action") == "unlink" ? Pool : p.Get("serviceId"),
    })).ToList();

    /// The next page of one lane as JSON (server-side filter + paging).
    public async Task<IActionResult> OnGetCardsAsync(string? lane, int skip, CancellationToken ct)
    {
        try
        {
            var (items, total) = lane is null or Pool
                ? await _store.AssetsAsync(Filter, skip, PageSize, ct)
                : int.TryParse(lane, NumberStyles.Integer, CultureInfo.InvariantCulture, out var id) ? await _store.ServiceAssetsAsync(id, Filter, skip, PageSize, ct)
                : throw new ArgumentException("unknown lane");
            return new JsonResult(new { items = items.Select(ToCard), more = skip + items.Count < total, total });
        }
        catch (ArgumentException ex) { return BadRequest(new { error = ex.Message }); }
    }

    // ---- staging (Admin): the drop handler posts here ----
    [BindProperty] public string? Action { get; set; }
    [BindProperty] public int ServiceId { get; set; }
    /// The selected cards: [{"key":"...","name":"..."}].
    [BindProperty] public string? Assets { get; set; }
    /// "all matching the filter": the server expands the filter (the same one the pool shows) into the asset list.
    [BindProperty] public bool AllMatching { get; set; }
    [BindProperty] public string? Reason { get; set; }

    [SI.Management.Web.Audit.Audited("cmdb.link.stage")]
    public async Task<IActionResult> OnPostStageAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        (StagedChange? change, IReadOnlyList<string> why) r;
        try
        {
            IReadOnlyList<CmdbChanges.Asset> list;
            if (AllMatching) list = (await _store.AssetKeysAsync(Filter, CmdbChanges.MaxPerChange + 1, ct)).Select(k => new CmdbChanges.Asset(k.Key, k.Name)).ToList();
            else
            {
                try { list = JsonSerializer.Deserialize<List<CmdbChanges.Asset>>(Assets ?? "[]", new JsonSerializerOptions(JsonSerializerDefaults.Web)) ?? new List<CmdbChanges.Asset>(); }
                catch (JsonException) { list = Array.Empty<CmdbChanges.Asset>(); }
            }
            r = Action is "link" or "unlink" ? await _cmdb.NewLinkAsync(ServiceId, list, Action == "link", Reason, ct) : (null, new[] { $"unknown action '{Action}'" });
        }
        catch (ArgumentException ex) { r = (null, new[] { ex.Message }); }
        string message;
        if (r.change is not null)
        {
            await _changes.StageAsync(User, r.change, ct);
            message = "Staged: " + r.change.Title + ". Nothing is written until you review and commit.";
        }
        else message = "Not staged: " + string.Join("; ", r.why);
        var pending = (await _changes.PendingAsync(User, ct)).Count;
        if (Request.Headers.Accept.ToString().Contains("application/json", StringComparison.OrdinalIgnoreCase))
            return new JsonResult(new { ok = r.change is not null, message, pending, staged = r.change is null ? null : new { r.change.Id, r.change.Title, count = CmdbChanges.AssetsOf(r.change).Count } });
        TempData["toast"] = message;
        TempData["toastKind"] = r.change is null ? "error" : "ok";
        return Redirect("/Cmdb/Map?" + QueryString.TrimStart('&'));
    }
}
