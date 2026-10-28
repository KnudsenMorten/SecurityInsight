using System.Globalization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Core.ProData;
using SI.Management.Web.Auth;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Pages.Admin;

/// <summary>
/// Admin &gt; Access (#253, SuperAdmin only). #765 (owner 2026-10-19: "where in the gui can i add more people to have
/// access and their role. i dont see any add peoples anywhere" / "this view is also confusing. it should have a single
/// table" / "SI decides"): ONE table, "People with access" -- every person and group once, with the role SecurityInsight
/// gives them, its scope, where their SecurityInsight mail goes, where the role came from, and Change / Remove -- and
/// "Add a person or group" at the TOP. SecurityInsight decides the role: an Entra app role only counts until it was carried
/// over into this table once (AccessClaims.AppRoleCounts); a holder not carried over yet is shown in the same table, marked
/// so. Every change is written at once, in its own transaction with its cfg.ChangeLog row and a reason.
/// </summary>
public sealed class AccessModel : PageModel
{
    private readonly IAccessStore _store;
    private readonly IDirectoryNames _names;
    private readonly IProDataQueries _data;
    private readonly ILogger<AccessModel> _log;
    private readonly IConfiguration _config;

    public AccessModel(IAccessStore store, IDirectoryNames names, IProDataQueries data, IConfiguration config, ILogger<AccessModel> log)
    { _store = store; _names = names; _data = data; _config = config; _log = log; }

    /// One line of the table: an assignment of SecurityInsight, or an Entra app role holder not carried over yet.
    public sealed record PersonRow(AccessAssignment Assignment, bool FromEntraOnly)
    {
        public string Source => FromEntraOnly ? "Entra app role -- moves into SecurityInsight at their next sign-in"
            : Assignment.CarriedOver ? "carried over from Entra" : "SecurityInsight";
    }

    public IReadOnlyList<AccessAssignment> Assignments { get; private set; } = Array.Empty<AccessAssignment>();
    public IReadOnlyList<PersonRow> People { get; private set; } = Array.Empty<PersonRow>();
    public IReadOnlyList<string> Domains { get; private set; } = SecurityDomains.Known;
    public bool TableExists { get; private set; } = true;
    public bool NameLookup => _names.Enabled;
    public string? Error { get; private set; }
    public AccessAssignment? Editing { get; private set; }
    /// The row the last save wrote (highlighted, scrolled to): the redirect after a save names it.
    [BindProperty(SupportsGet = true, Name = "saved")] public string? Saved { get; set; }

    [BindProperty(SupportsGet = true)] public string? Edit { get; set; }

    // ---- the form
    [BindProperty] public string? PrincipalId { get; set; }
    [BindProperty] public string PrincipalType { get; set; } = AccessAssignment.User;
    [BindProperty] public string? DisplayName { get; set; }
    [BindProperty] public string? AccountMail { get; set; }
    [BindProperty] public string? Role { get; set; }
    [BindProperty] public List<string> ScopeDomains { get; set; } = new();
    [BindProperty] public List<string> ScopeKinds { get; set; } = new();
    [BindProperty] public List<string> ScopeTiers { get; set; } = new();
    /// #765: "Send SecurityInsight mail to" (a person only; empty = their own mail).
    [BindProperty] public string? ForwardTo { get; set; }
    [BindProperty] public string? Reason { get; set; }
    /// The row version the form was opened with; empty = a new assignment.
    [BindProperty] public string? Version { get; set; }

    public static IReadOnlyList<SiRole> AssignableRoles => [SiRole.Reader, SiRole.Delegated, SiRole.Admin, SiRole.SuperAdmin];

    public async Task OnGetAsync(CancellationToken ct)
    {
        if (Saved is not null && !SqlAccessStore.ObjectId().IsMatch(Saved)) Saved = null;
        await LoadAsync(ct);
    }

    /// #446 / #765: the people picker -- users (members AND guests) and groups whose name, mail or sign-in name starts with
    /// what was typed (JSON: id, type, name, mail, guest). SuperAdmin, like the page. Empty when the lookup is off or fails.
    public async Task<IActionResult> OnGetSearchAsync(string? q, CancellationToken ct)
    {
        if (!User.IsSuperAdmin()) return Forbid();
        var found = _names.Enabled ? await _names.SearchAsync(q ?? "", ct) : Array.Empty<DirectoryPerson>();
        return new JsonResult(found.Select(p => new
        {
            id = p.ObjectId,
            type = p.Type.Equals("group", StringComparison.OrdinalIgnoreCase) ? AccessAssignment.Group : AccessAssignment.User,
            name = p.Name,
            mail = p.Mail,
            guest = p.Guest,
        }));
    }

    private async Task LoadAsync(CancellationToken ct)
    {
        try
        {
            TableExists = await _store.TableExistsAsync(ct);
            Assignments = TableExists ? await _store.ListAsync(ct) : Array.Empty<AccessAssignment>();
            Editing = Edit is null ? null : Assignments.FirstOrDefault(a => string.Equals(a.PrincipalId, Edit, StringComparison.OrdinalIgnoreCase));
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "the access assignments could not be read");
            Error = "The people with access could not be read from the Pro database: " + ex.Message;
        }
        // the domains to offer: the known ones, plus every domain present in the data, plus any already assigned
        var set = new SortedSet<string>(SecurityDomains.Known, StringComparer.OrdinalIgnoreCase);
        try
        {
            if ((await _data.FacetsAsync(ct)).Data.TryGetValue("domain", out var fromData))
                foreach (var d in fromData) if (!string.IsNullOrWhiteSpace(d) && SecurityDomains.IsWellFormed(d)) set.Add(d);
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "the security domains in the data could not be read"); }
        foreach (var a in Assignments) foreach (var d in a.Scope.Domains) if (d != AccessScope.AnyDomain) set.Add(d);
        Domains = set.ToList();
        // the Entra app role holders not in the table yet (being carried over): in the SAME table, marked so
        var rows = Assignments.Select(a => new PersonRow(a, false)).ToList();
        try
        {
            if (await _names.AppRoleHoldersAsync(_config["AzureAd:ClientId"] ?? "", ct) is { } holders)
            {
                var carried = TableExists ? await _store.CarriedAsync(ct) : new HashSet<string>();
                foreach (var g in holders.Where(h => h.Type is "User" or "Group").GroupBy(h => h.ObjectId, StringComparer.OrdinalIgnoreCase))
                {
                    if (Assignments.Any(a => string.Equals(a.PrincipalId, g.Key, StringComparison.OrdinalIgnoreCase))) continue;
                    var best = g.Select(h => (h, r: AccessClaims.ParseRole(h.Role))).Where(x => x.r is { } r && RoleDefinitions.RankOf(r) > 0)
                        .OrderByDescending(x => RoleDefinitions.RankOf(x.r!.Value)).FirstOrDefault();
                    // carried over already and then removed here: no access -- not shown as having it
                    if (best.r is not { } role || carried.Contains(SqlAccessStore.CarriedKey(g.Key, role))) continue;
                    rows.Add(new PersonRow(new AccessAssignment(g.Key, best.h.Type == "Group" ? AccessAssignment.Group : AccessAssignment.User, best.h.Name, role, new AccessScope()), true));
                }
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "the Entra role holders could not be read"); }
        People = rows.OrderByDescending(r => RoleDefinitions.RankOf(r.Assignment.Role)).ThenBy(r => r.Assignment.DisplayName, StringComparer.OrdinalIgnoreCase).ToList();
        // "Change" on a holder not carried over yet opens the form filled in, as a NEW assignment of SecurityInsight
        if (Editing is null && Edit is not null && People.FirstOrDefault(p => p.FromEntraOnly && string.Equals(p.Assignment.PrincipalId, Edit, StringComparison.OrdinalIgnoreCase)) is { } e)
        { Editing = e.Assignment; EditingIsNew = true; }
    }

    /// The form edits a row that is not in SecurityInsight's table yet (an Entra holder): saved as a new assignment.
    public bool EditingIsNew { get; private set; }

    private bool IsSelf(string? principalId) =>
        AccessClaims.ObjectId(User) is { } me && string.Equals(me, principalId?.Trim(), StringComparison.OrdinalIgnoreCase);

    /// Lock-out guard: a SuperAdmin cannot lower or remove their own access here -- another SuperAdmin can.
    private string? SelfGuard(string? principalId, SiRole? newRole) =>
        IsSelf(principalId) && (newRole is null || newRole < SiRole.SuperAdmin)
            ? "you cannot lower or remove your own access here -- another SuperAdmin can"
            : null;

    /// Never the last SuperAdmin: a change or removal that would leave nobody SuperAdmin is refused (the statement checks
    /// it again in its transaction).
    private string? LastSuperAdminGuard(string? principalId, SiRole? newRole)
    {
        var id = (principalId ?? "").Trim();
        var cur = Assignments.FirstOrDefault(a => string.Equals(a.PrincipalId, id, StringComparison.OrdinalIgnoreCase));
        if (cur?.Role != SiRole.SuperAdmin || newRole == SiRole.SuperAdmin) return null;
        return Assignments.Count(a => a.Role == SiRole.SuperAdmin) <= 1 ? SqlAccessStore.LastSuperAdminMessage : null;
    }

    [SI.Management.Web.Audit.Audited("access.assignment.save")]
    public async Task<IActionResult> OnPostSaveAsync(CancellationToken ct)
    {
        if (!User.IsSuperAdmin()) return Forbid();
        await LoadAsync(ct);
        var role = AccessClaims.ParseRole(Role);
        var id = (PrincipalId ?? "").Trim().ToLowerInvariant();
        var type = string.Equals(PrincipalType, AccessAssignment.Group, StringComparison.OrdinalIgnoreCase) ? AccessAssignment.Group : AccessAssignment.User;
        var name = (DisplayName ?? "").Trim();
        if (name.Length == 0 && _names.Enabled && SqlAccessStore.ObjectId().IsMatch(id) && await _names.NameOfAsync(id, ct) is { } found)
        {
            name = found.Name; type = found.Type;
        }
        var scope = role is { } rr && AccessClaims.IsScopeBound(rr) ? AccessScope.Of(ScopeDomains, ScopeKinds, ScopeTiers) : new AccessScope();
        long? expected = long.TryParse(Version, NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) ? v : null;
        var (forward, forwardError) = type == AccessAssignment.Group ? (null, null) : MailForward.Clean(ForwardTo);
        var mail = MailForward.IsAddress(AccountMail) || (AccountMail ?? "").Contains('@') ? AccountMail!.Trim() : null;
        WriteResult r;
        if (role is null) r = new WriteResult(WriteStatus.Refused, "choose a role: Reader, Delegated, Admin or SuperAdmin");
        else if (forwardError is not null) r = new WriteResult(WriteStatus.Refused, forwardError);
        else if (SelfGuard(id, role) is { } self) r = new WriteResult(WriteStatus.Refused, self);
        else if (LastSuperAdminGuard(id, role) is { } last) r = new WriteResult(WriteStatus.Refused, last);
        else r = await _store.WriteAsync(new AccessAssignment(id, type, name, role.Value, scope, AccountMail: mail, ForwardTo: forward), expected, User.ChangeName(), Reason ?? "", ct);
        Toast(r);
        if (r.Status == WriteStatus.Refused) { await LoadAsync(ct); Error = r.Message; return Page(); }
        return Redirect("/Admin/Access" + (r.Status == WriteStatus.Saved ? "?saved=" + Uri.EscapeDataString(id) + "#p-" + id : ""));
    }

    [SI.Management.Web.Audit.Audited("access.assignment.remove")]
    public async Task<IActionResult> OnPostRemoveAsync(CancellationToken ct)
    {
        if (!User.IsSuperAdmin()) return Forbid();
        await LoadAsync(ct);
        var r = SelfGuard(PrincipalId, null) is { } self ? new WriteResult(WriteStatus.Refused, self)
            : LastSuperAdminGuard(PrincipalId, null) is { } last ? new WriteResult(WriteStatus.Refused, last)
            : !long.TryParse(Version, NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) ? new WriteResult(WriteStatus.Refused, "the assignment's version is missing -- open the page again")
            : await _store.RemoveAsync(PrincipalId ?? "", v, User.ChangeName(), Reason ?? "", ct);
        Toast(r);
        return RedirectToPage();
    }

    private void Toast(WriteResult r)
    {
        TempData["toast"] = r.Status switch
        {
            WriteStatus.Saved => "Saved: " + r.Message + ". It applies within a few seconds.",
            _ => "Not saved: " + r.Message,
        };
        TempData["toastKind"] = r.Status == WriteStatus.Saved ? "ok" : r.Status == WriteStatus.Stale ? "warn" : "error";
    }
}
