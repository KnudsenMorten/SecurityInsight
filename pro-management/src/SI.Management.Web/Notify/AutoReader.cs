using SI.Management.Web.Auth;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Notify;

/// What a mail recipient is in the web app: "reader+" (has a role already), "added" (just added as Reader), "not-found"
/// (not in the directory), "unknown" (the directory lookup is off or failed), "group" (a group address -- never added),
/// "refused" (the write was refused).
public sealed record RecipientAccess(string Address, string State, string Words, string? Role = null);

/// <summary>
/// Framework MAIL-2 item 5 -- a mail recipient who is not yet a user of the web app is added as a READER (the lowest role),
/// so the deep links in their mails open. Found in Entra by their address (the directory lookup the Access page uses); an
/// existing user keeps their role -- never escalated, never lowered; a group is never added; removing a recipient never
/// removes a role. Every add goes through the Access store (cfg.AccessAssignment + its change log) with its reason.
/// </summary>
public sealed class AutoReader(IAccessStore access, IDirectoryNames directory, IConfiguration config, ILogger<AutoReader> log)
{
    public const string Reason = "added as a Reader because they receive SecurityInsight mails";

    /// What the recipient is now, without changing anything.
    public async Task<RecipientAccess> CheckAsync(string address, CancellationToken ct) => (await ResolveAsync(address, ct)).Access;

    /// Adds the recipient as Reader when they have no role; returns what they are afterwards.
    public async Task<RecipientAccess> EnsureAsync(string address, string by, CancellationToken ct)
    {
        var (a, person) = await ResolveAsync(address, ct);
        if (a.State != "none" || person is null) return a;
        var w = await access.WriteAsync(new AccessAssignment(person.ObjectId, AccessAssignment.User, string.IsNullOrWhiteSpace(person.Name) ? address : person.Name, SiRole.Reader, new AccessScope(),
            AccountMail: person.Mail ?? address), null, by, Reason, ct);
        return w.Status == WriteStatus.Saved
            ? new RecipientAccess(address, "added", "added as Reader", "Reader")
            : new RecipientAccess(address, "refused", "could not be added as Reader: " + w.Message);
    }

    private async Task<(RecipientAccess Access, DirectoryPerson? Person)> ResolveAsync(string address, CancellationToken ct)
    {
        address = (address ?? "").Trim();
        if (!directory.Enabled) return (new RecipientAccess(address, "unknown", "not checked -- the directory lookup is off (Access:GraphLookup)"), null);
        DirectoryPerson? p;
        try { p = await directory.FindAsync(address, ct); }
        catch (Exception ex) when (ex is not OperationCanceledException) { log.LogInformation(ex, "auto-Reader: lookup of a recipient failed"); return (new RecipientAccess(address, "unknown", "not checked -- the directory could not be read"), null); }
        if (p is null) return (new RecipientAccess(address, "not-found", "not found in Entra ID (an outside address cannot sign in)"), null);
        if (p.Type.Equals("group", StringComparison.OrdinalIgnoreCase)) return (new RecipientAccess(address, "group", "a group -- its members need their own role"), null);
        var mapped = (await access.ListAsync(ct)).FirstOrDefault(x => x.PrincipalType == AccessAssignment.User && x.PrincipalId.Equals(p.ObjectId, StringComparison.OrdinalIgnoreCase));
        if (mapped is not null && mapped.Role != SiRole.None) return (new RecipientAccess(address, "reader+", "a user (" + AccessClaims.Label(mapped.Role) + ")", AccessClaims.Label(mapped.Role)), p);
        IReadOnlyList<AppRoleHolder>? holders = null;
        try { holders = await directory.AppRoleHoldersAsync(config["AzureAd:ClientId"] ?? "", ct); }
        catch (Exception ex) when (ex is not OperationCanceledException) { log.LogInformation(ex, "auto-Reader: app role holders"); }
        if (holders?.FirstOrDefault(h => h.ObjectId.Equals(p.ObjectId, StringComparison.OrdinalIgnoreCase)) is { } h)
            return (new RecipientAccess(address, "reader+", "a user (" + h.Role + " in Entra)", h.Role), p);
        return (new RecipientAccess(address, "none", "not a user yet"), p);
    }
}
