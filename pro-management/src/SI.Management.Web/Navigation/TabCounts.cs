using System.Security.Claims;
using Microsoft.Extensions.Caching.Memory;
using SI.Management.Core.ProData;
using SI.Management.Web.Pages;

namespace SI.Management.Web.Navigation;

/// <summary>
/// The counts the "Assets (CIs)" tabs carry (owner 2026-10-19: "i see a difference in CIs, here 19847 ... here 9903 ...
/// confused"): "All CIs · 19.847" and "At risk (with findings) · 9.903", so every count says what it includes. Both come
/// from what is already stored and cached -- never a scan per page load: every CI = the CI filter choices' per-class
/// counts (read from the class column's index, cached per data version); at risk = the newest collection's
/// pre-computed per-tier aggregates (sidata.FindingFacet: an asset is in one tier, so the tiers' assets add up to the
/// distinct CIs with findings). Kept 5 minutes. None for an account limited to departments (both span every
/// department), and none while a number is not there yet (the tab then shows its label alone).
/// </summary>
public sealed class TabCounts(ICiViews cis, ICollectionViews views, IMemoryCache cache, ILogger<TabCounts> log)
{
    public const string AllCisPage = "/Cis/Index";
    public const string AtRiskPage = "/Collection/Assets";

    /// Every CI the correlation built, and the CIs with at least one finding in the newest complete collection (null =
    /// not known).
    public sealed record CiCounts(long? All, long? AtRisk);

    public async Task<CiCounts> CiAsync(ClaimsPrincipal user, IServiceProvider services, CancellationToken ct)
    {
        var resolver = services.GetService<SI.Management.Web.Departments.IDepartmentScopeResolver>();
        if (resolver is not null && (await resolver.ResolveAsync(user, ct)).Rows is not null) return new(null, null);
        return await cache.GetOrCreateAsync("tabcounts:ci", async e =>
        {
            e.AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(5);
            return new CiCounts(await AllAsync(ct), await AtRiskAsync(ct));
        }) ?? new(null, null);
    }

    private async Task<long?> AllAsync(CancellationToken ct)
    {
        try
        {
            var schema = (await cis.SchemaAsync(ct)).Data;
            if (!schema.Ci) return null;
            var state = (await cis.DataStateAsync(schema, ct)).Data;
            var facets = (await cis.CiFacetsAsync(state, ct)).Data;
            // owner 2026-10-19: the tab counts the CI list's active default (the stored lifecycle) -- the same set the CI list
            // and the tier board open on; a database whose CIs carry no lifecycle yet counts every CI, as before
            var life = facets.Where(f => f.Facet == "Lifecycle").ToList();
            if (life.Count > 0) return life.Where(f => string.Equals(f.Value, CiLifecycleDefinitions.DefaultFilter, StringComparison.OrdinalIgnoreCase)).Sum(f => f.N);
            var classes = facets.Where(f => f.Facet == "Class").ToList();
            return classes.Count == 0 ? null : classes.Sum(f => f.N);
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { log.LogWarning(ex, "the count of every CI could not be read"); return null; }
    }

    private async Task<long?> AtRiskAsync(CancellationToken ct)
    {
        try
        {
            // owner 2026-10-19: the active CIs with at least one open finding (sidata.Ci.OpenFindings, the published run's
            // findings per CI), counted by the lifecycle under that filter -- the same set as the active CI count beside it
            var schema = (await cis.SchemaAsync(ct)).Data;
            if (schema.Ci)
            {
                var state = (await cis.DataStateAsync(schema, ct)).Data;
                var spec = CiColumns.Default.Spec(CiColumns.Always.Append("OpenFindings").ToList(), state.Mode, state.CtxMode);
                var byLife = (await cis.ValueCountsAsync(spec, new GridRequest { Filters = new Dictionary<string, string> { ["OpenFindings"] = "1" } }, "Lifecycle", ct)).Data;
                if (byLife.Count > 0) return byLife.Where(f => string.Equals(f.Value, CiLifecycleDefinitions.DefaultFilter, StringComparison.OrdinalIgnoreCase)).Sum(f => f.N);
            }
            // a database before the CI lifecycle: the newest collection's CIs with findings, as before
            var newest = (await views.CollectionsAsync(ct)).Data.FirstOrDefault();
            if (newest is null || newest.DerivedAt is null) return null;
            var tiers = (await views.FacetsAsync(newest, ct)).Data.Where(f => f.Facet == Facets.Tier).ToList();
            return tiers.Count == 0 ? null : tiers.Sum(f => f.Assets);
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { log.LogWarning(ex, "the count of the CIs at risk could not be read"); return null; }
    }

    /// The count a tab carries (null = none).
    public static long? Of(CiCounts c, string page) =>
        NavModel.HrefOf(page) == NavModel.HrefOf(AllCisPage) ? c.All : NavModel.HrefOf(page) == NavModel.HrefOf(AtRiskPage) ? c.AtRisk : null;

    /// "9.903 of 19.847 active CIs have at least one finding" (the viewer's number format); null when either count is unknown.
    public static string? AtRiskSentence(CiCounts c) =>
        c is { All: { } all, AtRisk: { } risk } ? Fmt.Int(risk) + " of " + Fmt.Int(all) + " active CIs have at least one finding" : null;
}
