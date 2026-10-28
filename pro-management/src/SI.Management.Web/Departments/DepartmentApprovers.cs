using System.Security.Claims;
using SI.Management.Web.Auth;
using SI.Management.Web.Exemptions;

namespace SI.Management.Web.Departments;

/// One row of a department's PEOPLE TABLE as posted (#335): the person kept from before (MemberId) or picked / typed
/// (Person: a mail address or an object id), the role, and -- for an outside person only -- name and company.
public sealed class PeopleRow
{
    public int? MemberId { get; set; }
    public string? Person { get; set; }
    public string? Role { get; set; }
    public string? Name { get; set; }
    public string? Company { get; set; }
    public bool Remove { get; set; }
}

/// A suggestion of the people picker: the value a row stores, what the list shows, user | group | mail.
public sealed record PersonSuggestion(string Value, string Label, string Type);

/// <summary>
/// The people table of a department (#335) turned into department members: each person picked or typed (a mail address or an Entra
/// object id) is looked up in the directory when Access:GraphLookup is on -- a user found by mail or sign-in name, or a
/// user / group by object id, is stored with its object id, name and mail -- else a mail address is kept as a mail-only
/// person and an object id as a user with that id. Nothing is invented: a lookup that fails keeps what was typed.
/// </summary>
public sealed class DepartmentPeopleResolver(IDirectoryNames directory, DepartmentRepository repo)
{
    public bool DirectoryOn => directory.Enabled;

    /// <summary>
    /// The PEOPLE TABLE's rows (#335) turned into the department's wanted list: a row kept from before keeps its person
    /// (only its role can change); a new row's person -- picked from the list (a mail address or an object id) or typed as
    /// a mail address -- is looked up; someone the directory does not know is an outside person by mail, with the name
    /// and company of the row. Blank rows and rows marked Remove are left out. Problems name the row.
    /// </summary>
    public async Task<(IReadOnlyList<MemberInput> People, IReadOnlyList<string> Problems)> ResolveRowsAsync(int departmentId, IReadOnlyList<PeopleRow> rows,
        IReadOnlyList<DepartmentMemberRow> existing, CancellationToken ct)
    {
        var people = new List<MemberInput>();
        var problems = new List<string>();
        for (var i = 0; i < rows.Count; i++)
        {
            var r = rows[i];
            if (r.Remove) continue;
            var role = DepartmentRoles.Normalize(r.Role);
            var person = (r.Person ?? "").Trim();
            var kept = r.MemberId is { } mid ? existing.FirstOrDefault(m => m.MemberId == mid) : null;
            if (kept is null && person.Length == 0) continue;
            var who = kept?.DisplayName ?? person;
            if (!DepartmentRoles.All.Contains(role)) { problems.Add($"row {i + 1} ({who}): pick a role"); continue; }
            if (kept is not null)
            {
                people.Add(new MemberInput(departmentId, role, kept.ObjectId, kept.PrincipalType, kept.DisplayName, kept.Mail, kept.Company, kept.IsExternal));
                continue;
            }
            person = person.Trim('<', '>', '"', '\'');
            if (!DepartmentPeople.IsMail(person) && !DepartmentPeople.IsObjectId(person))
            {
                problems.Add($"row {i + 1}: '{(person.Length > 80 ? person[..80] + "..." : person)}' -- pick the person from the list, or type their e-mail address");
                continue;
            }
            var m = await ResolveOneAsync(departmentId, role, person, ct);
            if (m.PrincipalType == "mail")
            {
                var name = (r.Name ?? "").Trim();
                m = m with { DisplayName = name.Length > 0 ? name : m.DisplayName, Company = string.IsNullOrWhiteSpace(r.Company) ? null : r.Company.Trim(), IsExternal = directory.Enabled };
            }
            people.Add(m);
        }
        return (people, problems);
    }

    /// <summary>
    /// The people picker's suggestions for what was typed: the directory's users and groups (Access:GraphLookup on), then
    /// people already on any department. Value = what a row stores (a mail address, else an object id); Label = name + mail.
    /// </summary>
    public async Task<IReadOnlyList<PersonSuggestion>> SearchAsync(string? text, CancellationToken ct)
    {
        var t = (text ?? "").Trim();
        if (t.Length < 2) return Array.Empty<PersonSuggestion>();
        var list = new List<PersonSuggestion>();
        if (directory.Enabled)
        {
            try
            {
                foreach (var p in await directory.SearchAsync(t, ct))
                    list.Add(new PersonSuggestion(p.Mail ?? p.ObjectId, p.Mail is null ? $"{p.Name} ({p.Type})" : $"{p.Name} <{p.Mail}>", p.Type));
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { /* the known people below still answer */ }
        }
        try
        {
            foreach (var m in await repo.MembersAsync(null, ct))
            {
                var value = m.Mail ?? m.ObjectId;
                if (value is null) continue;
                if (!(m.DisplayName.Contains(t, StringComparison.OrdinalIgnoreCase) || value.Contains(t, StringComparison.OrdinalIgnoreCase))) continue;
                list.Add(new PersonSuggestion(value, m.Mail is null ? $"{m.DisplayName} ({m.PrincipalType})" : $"{m.DisplayName} <{m.Mail}>", m.PrincipalType));
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { /* the directory's answer stands */ }
        return list.GroupBy(s => s.Value, StringComparer.OrdinalIgnoreCase).Select(g => g.First()).Take(15).ToList();
    }

    public async Task<MemberInput> ResolveOneAsync(int departmentId, string role, string entry, CancellationToken ct)
    {
        DirectoryPerson? p = null;
        if (directory.Enabled)
        {
            try { p = await directory.FindAsync(entry, ct); }
            catch (Exception ex) when (ex is not OperationCanceledException) { p = null; }
        }
        if (p is not null) return new MemberInput(departmentId, role, p.ObjectId, p.Type, p.Name, p.Mail ?? (DepartmentPeople.IsMail(entry) ? entry : null), null, false);
        if (DepartmentPeople.IsObjectId(entry)) return new MemberInput(departmentId, role, entry.ToLowerInvariant(), "user", entry.ToLowerInvariant(), null, null, false);
        return new MemberInput(departmentId, role, null, "mail", entry, entry, null, false);
    }
}

/// <summary>
/// WHO APPROVES WHAT for a department (#335). Business approvers decide the exemption requests ("accept the risk") raised
/// from the department's own findings (its governance log names the request); technical approvers approve planning a fix
/// into the department's maintenance window. A person matches by object id (their own, or a group in their token) or --
/// for a person stored by mail address only -- by the address an Entra sign-in carries (never a magic-link session). Every
/// read fails CLOSED: a department or a membership that cannot be read approves nothing.
/// </summary>
public sealed class DepartmentApprovers(DepartmentRepository repo, ILogger<DepartmentApprovers> log) : IDepartmentDeciders
{
    /// Whether a department person is the signed-in user.
    public static bool Matches(DepartmentMemberRow m, ClaimsPrincipal user)
    {
        if (user.Identity?.IsAuthenticated != true) return false;
        if (m.ObjectId is { Length: > 0 } oid) return MembershipDepartmentScope.ObjectIds(user).Contains(oid.ToLowerInvariant());
        var name = user.ChangeName();
        return m.Mail is { Length: > 0 } && name.Length > 0 && AuthMethods.Detect(user) == AuthMethods.OAuth
               && string.Equals(m.Mail.Trim(), name.Trim(), StringComparison.OrdinalIgnoreCase);
    }

    public async Task<IReadOnlyList<DepartmentMemberRow>> PeopleAsync(int departmentId, string role, CancellationToken ct) =>
        (await repo.MembersAsync(departmentId, ct)).Where(m => m.Role == DepartmentRoles.Normalize(role)).ToList();

    public async Task<bool> IsAsync(ClaimsPrincipal user, int departmentId, string role, CancellationToken ct)
    {
        try { return (await PeopleAsync(departmentId, role, ct)).Any(m => Matches(m, user)); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            log.LogWarning(ex, "the department's approvers could not be read");
            return false;
        }
    }

    public async Task<(int DepartmentId, string Name)?> DepartmentOfRequestAsync(long requestId, CancellationToken ct)
    {
        try { return await repo.RequestDepartmentAsync(requestId, ct); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            log.LogWarning(ex, "the department of an exemption request could not be read");
            return null;
        }
    }

    public Task<bool> IsBusinessApproverAsync(ClaimsPrincipal user, int departmentId, CancellationToken ct) => IsAsync(user, departmentId, DepartmentRoles.BusinessApprover, ct);

    /// <summary>
    /// #391: the department's business approvers as the exemption flow routes to them -- the names shown (mail address,
    /// else display name: a group or a person known only by object id is still a business approver) and the addresses
    /// mailed. Null = the department does not exist (or is retired) or cannot be read: the flow routes to the owners.
    /// </summary>
    public async Task<DepartmentApproverSet?> BusinessApproversAsync(int departmentId, CancellationToken ct)
    {
        try
        {
            var dept = await repo.GetAsync(departmentId, ct);
            if (dept is null || dept.Retired) return null;
            var people = await PeopleAsync(departmentId, DepartmentRoles.BusinessApprover, ct);
            var names = people.Select(m => m.Mail is { Length: > 0 } mail ? mail.Trim().ToLowerInvariant() : m.DisplayName.Trim()).Where(n => n.Length > 0)
                .Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(n => n, StringComparer.Ordinal).ToList();
            var mails = people.Select(m => m.Mail?.Trim().ToLowerInvariant()).Where(m => m is { Length: > 0 } && DepartmentPeople.IsMail(m)).Select(m => m!)
                .Distinct().OrderBy(m => m, StringComparer.Ordinal).ToList();
            return new DepartmentApproverSet(departmentId, dept.Name, names, mails);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            log.LogWarning(ex, "the department's business approvers could not be read");
            return null;
        }
    }

    public async Task<IReadOnlyList<string>> BusinessApproverMailsAsync(int departmentId, CancellationToken ct)
    {
        try
        {
            return (await PeopleAsync(departmentId, DepartmentRoles.BusinessApprover, ct)).Select(m => m.Mail?.Trim().ToLowerInvariant())
                .Where(m => m is { Length: > 0 } && DepartmentPeople.IsMail(m)).Select(m => m!).Distinct().ToList();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            log.LogWarning(ex, "the department's business approvers could not be read");
            return Array.Empty<string>();
        }
    }
}
