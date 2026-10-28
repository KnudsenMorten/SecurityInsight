namespace SI.Management.Web.Auth;

/// <summary>
/// #765 (owner 2026-10-19, "SI decides"): when the web app starts after the update, every Entra app role holder of its
/// enterprise application (users AND groups -- not applications, which never sign in to the web app) is carried over into
/// SecurityInsight's access table ONCE, with a change-history row "carried over from Entra": the people who never sign in
/// soon and the groups are in the Access table at once, and nobody gains or loses access. The same idempotent statement the
/// sign-in uses (<see cref="IAccessStore.CarryOverAsync"/>): a holder already carried over is not touched again, so a person
/// removed on the Access page stays removed. Needs the directory lookup (Access:GraphLookup, Application.Read.All); without
/// it, each holder is carried over at their next sign-in instead. Never stops the app.
/// </summary>
public sealed class AccessCarryOverAtStart(IServiceProvider services, IConfiguration config, ILogger<AccessCarryOverAtStart> log) : BackgroundService
{
    /// The first pass waits for the app to be up; later passes pick up an app role an administrator gave in Entra since.
    public static readonly TimeSpan FirstDelay = TimeSpan.FromSeconds(45);
    public static readonly TimeSpan Every = TimeSpan.FromHours(6);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try { await Task.Delay(FirstDelay, stoppingToken); } catch (OperationCanceledException) { return; }
        while (!stoppingToken.IsCancellationRequested)
        {
            try { await RunOnceAsync(services.GetRequiredService<IAccessStore>(), services.GetRequiredService<IDirectoryNames>(), config["AzureAd:ClientId"] ?? "", log, stoppingToken); }
            catch (Exception ex) when (ex is not OperationCanceledException) { log.LogWarning(ex, "the Entra app roles could not be carried over into SecurityInsight's access table this time"); }
            try { await Task.Delay(Every, stoppingToken); } catch (OperationCanceledException) { return; }
        }
    }

    /// One pass. Returns how many identities were added or raised (the marks alone are not counted).
    public static async Task<int> RunOnceAsync(IAccessStore store, IDirectoryNames directory, string clientId, ILogger log, CancellationToken ct)
    {
        if (!directory.Enabled) return 0;
        var holders = await directory.AppRoleHoldersAsync(clientId, ct);
        if (holders is null || holders.Count == 0) return 0;
        if (!await store.TableExistsAsync(ct)) return 0;
        var carried = await store.CarriedAsync(ct);
        var rows = await store.ListAsync(ct);
        var changed = 0;
        // the highest app role per identity (a holder can have several assignments)
        foreach (var g in holders.Where(h => h.Type is "User" or "Group")
                     .Select(h => (h, role: AccessClaims.ParseRole(h.Role)))
                     .Where(x => x.role is { } r && RoleDefinitions.RankOf(r) > 0)
                     .GroupBy(x => x.h.ObjectId, StringComparer.OrdinalIgnoreCase))
        {
            var best = g.OrderByDescending(x => RoleDefinitions.RankOf(x.role!.Value)).First();
            var role = best.role!.Value;
            if (carried.Contains(SqlAccessStore.CarriedKey(best.h.ObjectId, role))) continue;
            var row = rows.FirstOrDefault(r => string.Equals(r.PrincipalId, best.h.ObjectId, StringComparison.OrdinalIgnoreCase));
            var markOnly = row is not null && RoleDefinitions.RankOf(row.Role) >= RoleDefinitions.RankOf(role);
            var type = best.h.Type == "Group" ? AccessAssignment.Group : AccessAssignment.User;
            var w = await store.CarryOverAsync(new CarryOver(best.h.ObjectId, type, best.h.Name, null, role, markOnly), ct);
            if (w.Status != SI.Management.Web.Settings.WriteStatus.Saved) { log.LogInformation("carry-over from Entra: {Why}", w.Message); return changed; }
            if (!markOnly) changed++;
        }
        if (changed > 0) log.LogInformation("carried {Count} Entra app role holder(s) over into SecurityInsight's access table", changed);
        return changed;
    }
}
