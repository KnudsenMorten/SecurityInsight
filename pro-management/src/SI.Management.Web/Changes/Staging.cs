using System.Security.Claims;
using System.Text.Json;
using Microsoft.Extensions.Caching.Distributed;

namespace SI.Management.Web.Changes;

/// The kinds of change the GUI can stage. Each is committed by exactly one <see cref="IChangeHandler"/>.
public static class ChangeKinds
{
    /// A new cfg.Exemption (a finding, an issue on every asset, or a whole asset).
    public const string Exemption = "exemption";
    /// Revoke an existing cfg.Exemption.
    public const string ExemptionRevoke = "exemption-revoke";
    /// Pin an asset to a tier: a cfg.Document of kind 'rule' (a nameMatches rule setting the tier).
    public const string TierPin = "tier-pin";
    /// Turn a shipped/custom tier rule off: a cfg.Document of kind 'rule' with mode: disable.
    public const string RuleDisable = "rule-disable";
    /// Move a whole rule to another tier: a cfg.ItemOverride row of kind 'ruletier' (State 'override').
    public const string RuleTier = "rule-tier";
    /// Put a moved rule back in its own tiers: the cfg.ItemOverride 'ruletier' row goes back to 'inherit' (removed).
    public const string RuleTierReset = "rule-tier-reset";
    /// #527 (4): one data-model item of the Pro data model in SQL (a risk factor or a provider mapping): a cfg.ItemOverride
    /// row of kind 'datamodel' -- override (a changed body), disable, or inherit (back to the shipped template: removed).
    public const string DataModelItem = "datamodel-item";
    /// Any cfg.Document edited in the Settings documents editor (exclusions, weights, rule, ...).
    public const string Document = "document";
    /// Template conformance: take the new template -- the item's cfg.ItemOverride goes back to inherit (removed).
    public const string TemplateTake = "template-take";
    /// Template conformance: keep mine and acknowledge -- the override's BaseHash moves to the current template content.
    public const string TemplateKeep = "template-keep";
    /// A cfg.Connector row: created, changed (incl. enable / disable / mode / arming) or removed on the Connectors page.
    public const string Connector = "connector";
    /// Template releases: release a staged template pack -- every detection method or the selected ones. The commit starts
    /// the caj-si-templates job with the accepted selection fingerprint; the job writes, verifies and records it.
    public const string TemplateRelease = "template-release";
    /// Template releases: roll the selected detection methods back to a previous version (cfg.TemplateRevision), same job.
    public const string TemplateRollback = "template-rollback";
    /// The service map: link (or unlink) a set of assets to one SI-homed CMDB service -- cfg.CmdbServiceAsset (#256).
    public const string CmdbLink = "cmdb-link";
    /// #404 (CONFIG-1.2 / 1.4): one configuration record written back by an undo or a restore (Config\ConfigRevertHandler).
    public const string ConfigRevert = "config-revert";
}

/// <summary>
/// One staged change: NOTHING is written when it is staged (by a drop, a button or a picker). It is reviewed (diff)
/// and committed on the Review &amp; commit page, where each one is written in its own transaction with its
/// cfg.ChangeLog row.
/// </summary>
public sealed record StagedChange
{
    public string Id { get; init; } = Guid.NewGuid().ToString("N")[..12];
    public required string Kind { get; init; }
    /// One line for the list ("Exempt CVE-2024-1 on srv-01").
    public required string Title { get; init; }
    public Dictionary<string, string?> Data { get; init; } = new(StringComparer.Ordinal);
    public DateTime StagedAt { get; init; } = DateTime.UtcNow;

    public string? Get(string key) => Data.TryGetValue(key, out var v) ? v : null;
}

/// The pending changes of ONE signed-in user.
public interface IStagingStore
{
    Task<IReadOnlyList<StagedChange>> ListAsync(ClaimsPrincipal user, CancellationToken ct);
    Task AddAsync(ClaimsPrincipal user, StagedChange change, CancellationToken ct);
    Task RemoveAsync(ClaimsPrincipal user, IEnumerable<string> ids, CancellationToken ct);
}

/// <summary>
/// Pending changes kept server-side per user in the distributed cache (in-memory by default: the deploy pins the web
/// app to session affinity so one user stays on one replica). 8 hours sliding; at most 200 per user. Losing the cache
/// loses only UNCOMMITTED staging -- nothing was written yet.
/// </summary>
public sealed class CacheStagingStore : IStagingStore
{
    public const int MaxPerUser = 200;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private readonly IDistributedCache _cache;
    private static readonly SemaphoreSlim Lock = new(1, 1);

    public CacheStagingStore(IDistributedCache cache) => _cache = cache;

    public static string KeyFor(ClaimsPrincipal user)
    {
        var id = user.FindFirst("http://schemas.microsoft.com/identity/claims/objectidentifier")?.Value
                 ?? user.FindFirst("oid")?.Value
                 ?? user.FindFirst("preferred_username")?.Value
                 ?? user.Identity?.Name
                 ?? throw new InvalidOperationException("the signed-in user has no id to keep pending changes under");
        return "si-staging:" + id.ToLowerInvariant();
    }

    public async Task<IReadOnlyList<StagedChange>> ListAsync(ClaimsPrincipal user, CancellationToken ct)
    {
        var bytes = await _cache.GetAsync(KeyFor(user), ct);
        if (bytes is null || bytes.Length == 0) return Array.Empty<StagedChange>();
        try { return JsonSerializer.Deserialize<List<StagedChange>>(bytes, Json) ?? new List<StagedChange>(); }
        catch (JsonException) { return Array.Empty<StagedChange>(); }
    }

    private Task SaveAsync(ClaimsPrincipal user, IReadOnlyList<StagedChange> list, CancellationToken ct) =>
        _cache.SetAsync(KeyFor(user), JsonSerializer.SerializeToUtf8Bytes(list, Json),
            new DistributedCacheEntryOptions { SlidingExpiration = TimeSpan.FromHours(8) }, ct);

    public async Task AddAsync(ClaimsPrincipal user, StagedChange change, CancellationToken ct)
    {
        await Lock.WaitAsync(ct);
        try
        {
            var list = (await ListAsync(user, ct)).ToList();
            if (list.Count >= MaxPerUser) throw new InvalidOperationException($"at most {MaxPerUser} changes can be pending -- review and commit first");
            // the same target staged twice keeps the newest (dragging an asset twice = one pending pin)
            var target = TargetOf(change);
            if (target is not null) list.RemoveAll(c => TargetOf(c) == target);
            list.Add(change);
            await SaveAsync(user, list, ct);
        }
        finally { Lock.Release(); }
    }

    public async Task RemoveAsync(ClaimsPrincipal user, IEnumerable<string> ids, CancellationToken ct)
    {
        await Lock.WaitAsync(ct);
        try
        {
            var drop = ids.ToHashSet(StringComparer.Ordinal);
            var list = (await ListAsync(user, ct)).Where(c => !drop.Contains(c.Id)).ToList();
            await SaveAsync(user, list, ct);
        }
        finally { Lock.Release(); }
    }

    /// What a change writes to: two staged changes with the same target replace each other.
    public static string? TargetOf(StagedChange c) => c.Kind switch
    {
        ChangeKinds.TierPin => "pin:" + c.Get("assetKey"),
        ChangeKinds.RuleDisable or ChangeKinds.RuleTier or ChangeKinds.RuleTierReset => "rule:" + c.Get("ruleKey"),
        ChangeKinds.Document => "doc:" + c.Get("docKind") + "/" + c.Get("docKey"),
        ChangeKinds.ExemptionRevoke => "revoke:" + c.Get("exemptionId"),
        ChangeKinds.TemplateTake or ChangeKinds.TemplateKeep => "item:" + c.Get("itemKind") + "/" + c.Get("itemKey"),
        // one pending change per output column (it writes the same cfg.ItemOverride row as a template decision would)
        SI.Management.Web.Outputs.OutputMapChanges.ChangeKind => "item:datamodel/" + c.Get("key"),
        ChangeKinds.Connector => "connector:" + c.Get("name"),
        // #640: one pending bucket reset per report (or one for all): staging it again replaces the earlier one
        SI.Management.Web.QuerySplitting.QuerySplittingChanges.ChangeKind => "bucketreset:" + c.Get("templates") + "/" + c.Get("report"),
        ChangeKinds.DataModelItem => "item:datamodel/" + c.Get("itemKey"),
        // one template release (or roll back) pending at a time: the newest staged replaces the previous one
        ChangeKinds.TemplateRelease or ChangeKinds.TemplateRollback => "templates:release",
        // one pending undo / restore per record: staging it again replaces the earlier one
        ChangeKinds.ConfigRevert => "config:" + c.Get("entity") + "|" + c.Get("key"),
        _ => null,
    };
}
