using Microsoft.Extensions.Caching.Memory;
using SI.Management.Core;
using SI.Management.Core.ProData;
using SI.Management.Web.Auth;
using SI.Management.Web.Changes;
using SI.Management.Web.Cmdb;
using SI.Management.Web.Guards;
using SI.Management.Web.Pages.Admin;
using SI.Management.Web.Settings;

namespace SI.Management.Web.GetStarted;

/// Where Get Started's facts come from (tests replace it with fixture data).
public interface IGetStartedFactsSource
{
    Task<GetStartedFacts> ReadAsync(CancellationToken ct);
}

/// <summary>
/// Reads Get Started's facts from the stores the web app already has -- the same reads the pages behind each step make.
/// Every read stands alone: one that fails (a table not there yet, the workspace unreachable) puts its key in
/// <see cref="GetStartedFacts.Unread"/> and the others still count. Nothing is written.
/// </summary>
public sealed class GetStartedFactsReader : IGetStartedFactsSource
{
    private readonly IServiceProvider _sp;
    private readonly TimeProvider _clock;
    private readonly ILogger<GetStartedFactsReader> _log;

    public GetStartedFactsReader(IServiceProvider sp, TimeProvider clock, ILogger<GetStartedFactsReader> log) { _sp = sp; _clock = clock; _log = log; }

    /// The Log Analytics read (run records) gets at most this long; Get Started never waits on a slow workspace.
    public static readonly TimeSpan RunsTimeout = TimeSpan.FromSeconds(20);

    /// When the Pro database was created (UTC on Azure SQL) -- the install's age. Read-only, one row.
    public const string InstalledSql = "SELECT create_date AS CreatedUtc FROM sys.databases WHERE database_id = DB_ID();";

    public async Task<GetStartedFacts> ReadAsync(CancellationToken ct)
    {
        var unread = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var now = _clock.GetUtcNow().UtcDateTime;
        async Task<T?> Try<T>(string key, Func<Task<T?>> read)
        {
            try { return await read(); }
            catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
            {
                _log.LogInformation(ex, "Get Started: {Key} could not be read", key);
                unread.Add(key);
                return default;
            }
        }
        T Need<T>() where T : notnull => _sp.GetRequiredService<T>();

        var licence = await Try("licence", () => Need<InstalledLicenceReader>().ReadAsync(ct));
        var access = await Try("access", () => Need<IAccessStore>().ListAsync(ct));
        var mail = await Try("mail", async () =>
        {
            var o = await Need<MailOverviewLoader>().LoadAsync(ct);
            if (o.Error is not null) throw new InvalidOperationException(o.Error);
            return o;
        });
        var runs = await Try("runs", async () =>
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(RunsTimeout);
            var r = await Need<IEstateQueries>().RunHealthAsync(GetStartedGuide.RunDays, cts.Token);
            // the resilient wrapper answers a failed query with no rows and "(the ... query failed ...)" as its text
            if (r.Data.Count == 0 && r.Query.StartsWith("(", StringComparison.Ordinal)) throw new InvalidOperationException(r.Query);
            return r.Data;
        });
        var collections = await Try("collections", async () => (await Need<ICollectionViews>().CollectionsAsync(ct)).Data);
        // #855 M16: the ACTIVE CIs per tier (sidata.Ci, the tier board's own count -- its "Class" facet counts each CI once),
        // never every row of sidata.Asset: a retired or not seen CI does not make tier 0 "done"
        var tiers = await Try("tiers", async () => (IReadOnlyList<TierCount>)(await Need<ICiViews>().TierCountsAsync(LifecycleFilter.Active.States, ct)).Data
            .Where(t => t.Facet == CiTierCount.ClassFacet).Select(t => new TierCount(t.Tier, t.N)).ToList());
        var ring = await Try("ring", () => Need<InstallRingReader>().ReadAsync(ct));
        var settings = await Try("settings", async () => (await Need<ISettingsStoreReader>().ReadSettingsAsync(ct)).Rows);
        var services = await Try("cmdb", async () =>
        {
            var store = Need<ICmdbStore>();
            var (source, _) = await store.ActiveSourceAsync(ct);
            return await store.ServicesAsync(source, false, ct);
        });
        var connectors = await Try("connectors", () => Need<ConnectorRepository>().ListAsync(ct));
        var connectorRuns = await Try("connectors", () => Need<ConnectorRepository>().RunsAsync(null, 200, ct));
        var holds = await Try("guards", () => Need<IGuardReleaseStore>().RecentAsync(ct));
        // #446: the Entra role holders -- fail-soft (null when the lookup is off): never makes a step "could not be read"
        IReadOnlyList<SI.Management.Web.Auth.AppRoleHolder>? entra = null;
        try { entra = await Need<SI.Management.Web.Auth.IDirectoryNames>().AppRoleHoldersAsync(Need<Microsoft.Extensions.Configuration.IConfiguration>()["AzureAd:ClientId"] ?? "", ct); }
        catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogInformation(ex, "Get Started: the Entra role holders could not be read"); }
        // the install's age and the run in progress only choose the WORDS of a step that waits ("not run yet", "it
        // started ...") -- fail-soft as well: not known = the plain "Waiting for the first run"
        DateTime? installed = null, runStarted = null;
        try { installed = (await Need<SI.Management.Web.Data.ISqlExecutor>().QueryAsync(InstalledSql, new Dictionary<string, object?>(), ct)).FirstOrDefault()?.Date("CreatedUtc"); }
        catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogInformation(ex, "Get Started: the install's age could not be read"); }
        try { runStarted = GetStartedGuide.RunningSince(await Need<SI.Management.Web.Jobs.IFlowStore>().LastRunAsync(ct), now); }
        catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogInformation(ex, "Get Started: the pipeline's last run could not be read"); }

        return new GetStartedFacts
        {
            NowUtc = now,
            Licence = licence,
            Access = access ?? Array.Empty<AccessAssignment>(),
            Mail = mail,
            LatestRuns = runs is null ? Array.Empty<LatestRun>() : RunHealthModel.LatestRuns(runs),
            Permissions = runs is null ? Array.Empty<EnginePermissions>() : GetStartedPermissions.Latest(runs),
            CompleteCollections = collections?.Count ?? 0,
            NewestCollectionUtc = collections is { Count: > 0 } c ? c.Max(x => x.CollectionTime) : null,
            AssetsPerTier = (tiers ?? Array.Empty<TierCount>()).GroupBy(t => t.Tier).ToDictionary(g => g.Key, g => g.Sum(t => t.Assets)),
            Ring = ring,
            RingSetting = settings is null ? null : InstallRingReader.RingOf(MailMode.Plain(MailMode.RowOf(settings, InstallRingReader.SettingName)?.ValueJson)),
            Services = services?.Count(s => !s.Retired) ?? 0,
            ServicesWithMembers = services?.Count(s => !s.Retired && s.Assets > 0) ?? 0,
            Connectors = connectors ?? Array.Empty<ConnectorRow>(),
            ConnectorRuns = connectorRuns ?? Array.Empty<ConnectorRunRow>(),
            OpenHolds = holds?.Count(h => h.CanRelease(now)) ?? 0,
            Settings = settings ?? Array.Empty<SettingRow>(),
            EntraRoles = entra,
            InstalledUtc = installed,
            RunStartedUtc = runStarted,
            Unread = unread,
        };
    }
}

/// <summary>
/// Get Started as it stands: the page evaluates it FRESH on every visit (and refreshes the cached copy); the menu's red !
/// asks the cached copy (at most <see cref="CacheFor"/> old), so the badge never costs a page its load time and is gone by
/// itself within a minute of the last required step being done. Nothing is stored anywhere but this in-memory cache.
/// </summary>
public sealed class GetStartedService
{
    public const string CacheKey = "si-getstarted";
    public static readonly TimeSpan CacheFor = TimeSpan.FromSeconds(60);

    private readonly IGetStartedFactsSource _facts;
    private readonly IMemoryCache _cache;

    private readonly SI.Management.Web.Licensing.IProLicence? _licence;

    public GetStartedService(IGetStartedFactsSource facts, IMemoryCache cache, SI.Management.Web.Licensing.IProLicence? licence = null) { _facts = facts; _cache = cache; _licence = licence; }

    public async Task<GetStartedResult> EvaluateAsync(bool fresh, CancellationToken ct)
    {
        if (!fresh && _cache.TryGetValue(CacheKey, out GetStartedResult? cached) && cached is not null) return cached;
        // the free version (no Pro licence): the paid steps are not steps of this install (GetStartedGuide.IsProStep)
        var pro = _licence is null || await _licence.IsProAsync(ct);
        var result = GetStartedGuide.Evaluate(await _facts.ReadAsync(ct), pro);
        _cache.Set(CacheKey, result, CacheFor);
        return result;
    }

    /// After a save: the next badge question checks again instead of answering from the cache.
    public void Forget() => _cache.Remove(CacheKey);
}
