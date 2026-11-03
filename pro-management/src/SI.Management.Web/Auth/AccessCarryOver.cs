namespace SI.Management.Web.Auth;

/// <summary>
/// #765 (owner 2026-10-19, "SI decides"): when the web app starts after the update, every Entra app role holder of its
/// enterprise application (users AND groups -- not applications, which never sign in to the web app) is carried over into
/// SecurityInsight's access table ONCE, with a change-history row "carried over from Entra": the people who never sign in
/// soon and the groups are in the Access table at once, and nobody gains or loses access. The same idempotent statement the
/// sign-in uses (<see cref="IAccessStore.CarryOverAsync"/>): a holder already carried over is not touched again, so a person
/// removed on the Access page stays removed. Needs the directory lookup (Access:GraphLookup, Application.Read.All); without
/// it, each holder is carried over at their next sign-in instead. Never stops the app.
/// <para>
/// #999: the app role holders of the ONE sign-in application belong to THIS install only when no other install shares the
/// application -- every install in a tenant uses the same application, so a role given in Entra for one install is not a role
/// in another. The pass therefore runs ONCE per install (it is the move of the access people already had, nothing more):
/// only while this install has carried nothing over yet, and only when the application sends people back to exactly one
/// web address (this install's). A role given in Entra after that is carried over when that person signs in to THIS
/// install (the sign-in path; not while the application is shared -- <see cref="SignInAppSharing"/>) -- or is given on the Access page.
/// </para>
/// </summary>
public sealed class AccessCarryOverAtStart(IServiceProvider services, IConfiguration config, ILogger<AccessCarryOverAtStart> log) : BackgroundService
{
    /// The pass waits for the app to be up.
    public static readonly TimeSpan FirstDelay = TimeSpan.FromSeconds(45);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try { await Task.Delay(FirstDelay, stoppingToken); } catch (OperationCanceledException) { return; }
        try { await RunOnceAsync(services.GetRequiredService<IAccessStore>(), services.GetRequiredService<IDirectoryNames>(), config["AzureAd:ClientId"] ?? "", log, stoppingToken); }
        catch (Exception ex) when (ex is not OperationCanceledException) { log.LogWarning(ex, "the Entra app roles could not be carried over into SecurityInsight's access table this time"); }
    }

    /// One pass. Returns how many identities were added or raised (the marks alone are not counted).
    public static async Task<int> RunOnceAsync(IAccessStore store, IDirectoryNames directory, string clientId, ILogger log, CancellationToken ct)
    {
        if (!directory.Enabled) return 0;
        if (!await store.TableExistsAsync(ct)) return 0;
        var carried = await store.CarriedAsync(ct);
        // #999: this install already carried its people over -- a later Entra role is not bound to this install
        if (carried.Count > 0) return 0;
        var hosts = await directory.SignInHostsAsync(clientId, ct);
        if (hosts is null || hosts.Count != 1)
        {
            log.LogInformation("carry-over from Entra skipped: the sign-in application {Why} -- its app role holders cannot be told apart per install; each person is carried over at their own sign-in here",
                hosts is null ? "could not be read" : $"is shared by {hosts.Count} web addresses");
            return 0;
        }
        var holders = await directory.AppRoleHoldersAsync(clientId, ct);
        if (holders is null || holders.Count == 0) return 0;
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

/// <summary>
/// #999: whether the sign-in application is SHARED by several installs (the directory lists more than one web address it
/// sends people back to) -- then the sign-in no longer copies an Entra app role into this install's access table. Asked on
/// every sign-in of a person not carried over yet, so the answer is kept for <see cref="Keep"/>. UNKNOWN (the directory
/// lookup is off or failed) is NOT shared: today's single-install behaviour stays as it was.
/// </summary>
public sealed class SignInAppSharing(IDirectoryNames directory, string clientId, ILogger<SignInAppSharing> log, TimeProvider? clock = null)
{
    public static readonly TimeSpan Keep = TimeSpan.FromMinutes(10);
    private readonly TimeProvider _clock = clock ?? TimeProvider.System;
    private (bool Shared, DateTimeOffset At)? _known;
    private readonly object _lock = new();

    public async Task<bool> SharedAsync(CancellationToken ct)
    {
        var now = _clock.GetUtcNow();
        lock (_lock) { if (_known is { } k && now - k.At < Keep) return k.Shared; }
        var shared = false;
        if (directory.Enabled && clientId.Length > 0)
        {
            try
            {
                var hosts = await directory.SignInHostsAsync(clientId, ct);
                shared = hosts is { Count: > 1 };
                if (shared) log.LogInformation("the sign-in application is shared by {Count} web addresses: an Entra app role is not carried over into this install's access table at sign-in", hosts!.Count);
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { log.LogInformation(ex, "the sign-in application's web addresses could not be read"); }
        }
        lock (_lock) { _known = (shared, now); }
        return shared;
    }
}
