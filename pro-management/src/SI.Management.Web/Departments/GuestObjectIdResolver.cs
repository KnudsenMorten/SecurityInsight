using System.Globalization;
using SI.Management.Web.Auth;
using SI.Management.Web.Data;

namespace SI.Management.Web.Departments;

/// One department person or advisor kept by mail address only (no object id). Kind 'member' -> cfg.DepartmentMember.MemberId,
/// 'advisor' -> cfg.DepartmentAdvisor.AdvisorId. #1370: 'domainrole' / 'categoryrole' = a Security domain / category owner or
/// approver (cfg.DomainRole / cfg.CategoryRole; Id and DepartmentId 0, the row is Domain + Category + Role + the Principal
/// address in Mail).
public sealed record MailOnlyEntry(string Kind, int Id, int DepartmentId, string Role, string DisplayName, string Mail, string? Domain = null, string? Category = null)
{
    public const string Member = "member";
    public const string Advisor = "advisor";
    public const string DomainRole = "domainrole";
    public const string CategoryRole = "categoryrole";
    public bool IsRoster => Kind is DomainRole or CategoryRole;
}

/// What one lookup did with one entry. Outcome: resolved | not-found | ambiguous | duplicate | unavailable | gone.
public sealed record MailOnlyOutcome(MailOnlyEntry Entry, string Outcome, string? ObjectId = null)
{
    public const string Resolved = "resolved";
    public const string NotFound = "not-found";
    public const string Ambiguous = "ambiguous";
    public const string Duplicate = "duplicate";
    public const string Unavailable = "unavailable";
    public const string Gone = "gone";
}

/// One pass over the mail-only entries: when, and what happened to each.
public sealed record MailOnlyPass(DateTime At, IReadOnlyList<MailOnlyOutcome> Entries)
{
    public int Count(string outcome) => Entries.Count(e => e.Outcome == outcome);

    /// The pass in words, for the log and for the Admin's toast after a save. Empty = nothing was kept by mail only.
    public string Words()
    {
        if (Entries.Count == 0) return "";
        var parts = new List<string>();
        void Add(string outcome, string one, string many) { var n = Count(outcome); if (n > 0) parts.Add(n == 1 ? one : string.Format(CultureInfo.InvariantCulture, many, n)); }
        Add(MailOnlyOutcome.Resolved, "1 person kept by e-mail address now has their object id from the directory", "{0} people kept by e-mail address now have their object id from the directory");
        Add(MailOnlyOutcome.NotFound, "1 address matched no account in the directory", "{0} addresses matched no account in the directory");
        Add(MailOnlyOutcome.Ambiguous, "1 address matched more than one account (left as it is -- record the object id)", "{0} addresses matched more than one account (left as they are -- record the object ids)");
        Add(MailOnlyOutcome.Duplicate, "1 person is already listed by object id in the same role", "{0} people are already listed by object id in the same role");
        Add(MailOnlyOutcome.Unavailable, "the directory could not be read for 1 address (tried again later)", "the directory could not be read for {0} addresses (tried again later)");
        return string.Join("; ", parts);
    }
}

/// <summary>
/// #995b (owner 2026-11-25, SEC-CHANGE-1: a security change never breaks the customer's work). Since #995 a guest (Entra B2B)
/// is matched by OBJECT ID only -- its sign-in name is chosen by its home tenant, so an address-only entry could be claimed by
/// another account. A department person or advisor kept by e-mail address only therefore stopped matching when they signed in
/// as a guest. This resolves such an entry ONCE: the directory's ONE user whose mail or sign-in name is EXACTLY the address
/// (<see cref="IDirectoryNames.MatchMailAsync"/> -- SecurityInsight's own names from the engine's Graph read, or the web
/// app's Graph lookup when that is on; no new right) gets its object id stored on the row, in place (the row keeps its id,
/// so tasks and sign-in links keep pointing at it), with a change-history row. From then on the row matches by object id
/// only. None, or more than one, = the row stays as it is and the outcome is logged and shown on the Admin's lists -- never a
/// guess. The sign-in itself never matches by address: this runs at the Admin's save and in the background (after start
/// and every few hours), never at sign-in.
/// </summary>
public sealed class GuestObjectIdResolver(ISqlExecutor sql, IDirectoryNames directory, ILogger<GuestObjectIdResolver> log, TimeProvider? clock = null)
{
    /// The name the change history records.
    public const string By = "SecurityInsight (directory lookup)";

    /// What a pass covers (@Part): the department people and advisors, the Security owners' roster, or both.
    public const string PartAll = "all";
    public const string PartDepartment = "department";
    public const string PartRoster = "roster";

    /// Every live entry kept by address only (a group is never one). @DepartmentId NULL = every department. #1370: the roster
    /// rows (live, no object id, the Principal an address) only where the database has the ObjectId columns -- named inside
    /// EXEC, so the statement compiles on a database one schema behind.
    public const string PendingSql = """
SET NOCOUNT ON;
DECLARE @p TABLE (Kind nvarchar(16), Id int, DepartmentId int, Role nvarchar(24), DisplayName nvarchar(256), Mail nvarchar(256), Domain nvarchar(64), Category nvarchar(128));
IF @Part <> N'roster' AND OBJECT_ID(N'cfg.DepartmentMember') IS NOT NULL AND OBJECT_ID(N'cfg.Department') IS NOT NULL
    INSERT @p SELECT N'member', m.MemberId, m.DepartmentId, m.Role, m.DisplayName, m.Mail, NULL, NULL
    FROM cfg.DepartmentMember AS m JOIN cfg.Department AS d ON d.DepartmentId = m.DepartmentId AND d.RetiredAt IS NULL
    WHERE m.ObjectId IS NULL AND m.Mail IS NOT NULL AND m.PrincipalType <> N'group' AND (@DepartmentId IS NULL OR m.DepartmentId = @DepartmentId);
IF @Part <> N'roster' AND OBJECT_ID(N'cfg.DepartmentAdvisor') IS NOT NULL AND OBJECT_ID(N'cfg.Department') IS NOT NULL
    INSERT @p SELECT N'advisor', a.AdvisorId, a.DepartmentId, N'advisor', a.DisplayName, a.Mail, NULL, NULL
    FROM cfg.DepartmentAdvisor AS a JOIN cfg.Department AS d ON d.DepartmentId = a.DepartmentId AND d.RetiredAt IS NULL
    WHERE a.ObjectId IS NULL AND a.Mail IS NOT NULL AND a.RevokedAt IS NULL AND (@DepartmentId IS NULL OR a.DepartmentId = @DepartmentId);
IF @Part <> N'department' AND COL_LENGTH(N'cfg.DomainRole', N'ObjectId') IS NOT NULL
    INSERT @p EXEC (N'SELECT N''domainrole'', 0, 0, r.Role, r.Principal, r.Principal, r.Domain, NULL FROM cfg.DomainRole AS r
                     WHERE r.RemovedAt IS NULL AND r.ObjectId IS NULL AND r.Principal LIKE N''%_@_%''');
IF @Part <> N'department' AND COL_LENGTH(N'cfg.CategoryRole', N'ObjectId') IS NOT NULL
    INSERT @p EXEC (N'SELECT N''categoryrole'', 0, 0, r.Role, r.Principal, r.Principal, r.Domain, r.Category FROM cfg.CategoryRole AS r
                     WHERE r.RemovedAt IS NULL AND r.ObjectId IS NULL AND r.Principal LIKE N''%_@_%''');
SELECT Kind, Id, DepartmentId, Role, DisplayName, Mail, Domain, Category FROM @p ORDER BY DepartmentId, Kind, Id, Domain, Category, Mail;
""";

    /// #1370: the object id stored on ONE live Security domain owner / approver row -- only while it is still the same
    /// address-only row; never when another live row of the same domain and role already has that object id. The change
    /// history names the same principal before and after (the row's key does not change), the object id in the reason.
    public const string ResolveDomainRoleSql = """
SET XACT_ABORT ON;
BEGIN TRAN;
IF NOT EXISTS (SELECT 1 FROM cfg.DomainRole WITH (UPDLOCK, HOLDLOCK) WHERE Domain = @Domain AND Role = @Role AND Principal = @Mail AND RemovedAt IS NULL AND ObjectId IS NULL)
BEGIN COMMIT; SELECT N'Gone' AS Outcome; RETURN; END;
IF EXISTS (SELECT 1 FROM cfg.DomainRole WITH (UPDLOCK, HOLDLOCK) WHERE Domain = @Domain AND Role = @Role AND RemovedAt IS NULL AND ObjectId = @ObjectId)
BEGIN COMMIT; SELECT N'Duplicate' AS Outcome; RETURN; END;
UPDATE cfg.DomainRole SET ObjectId = @ObjectId WHERE Domain = @Domain AND Role = @Role AND Principal = @Mail AND RemovedAt IS NULL AND ObjectId IS NULL;
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (LEFT(N'domain-role/' + @Domain + N'/' + @Role, 128), N'domain-role', N'domain-role', N'Set', @Mail, @Mail, @By,
        LEFT(CONCAT(N'object id ', @ObjectId, N' found in the directory for ', @Mail, N' (matched by object id from now on)'), 400));
COMMIT;
SELECT N'Saved' AS Outcome;
""";

    /// #1370: the same for ONE live Security category owner row.
    public const string ResolveCategoryRoleSql = """
SET XACT_ABORT ON;
BEGIN TRAN;
IF NOT EXISTS (SELECT 1 FROM cfg.CategoryRole WITH (UPDLOCK, HOLDLOCK) WHERE Domain = @Domain AND Category = @Category AND Role = @Role AND Principal = @Mail AND RemovedAt IS NULL AND ObjectId IS NULL)
BEGIN COMMIT; SELECT N'Gone' AS Outcome; RETURN; END;
IF EXISTS (SELECT 1 FROM cfg.CategoryRole WITH (UPDLOCK, HOLDLOCK) WHERE Domain = @Domain AND Category = @Category AND Role = @Role AND RemovedAt IS NULL AND ObjectId = @ObjectId)
BEGIN COMMIT; SELECT N'Duplicate' AS Outcome; RETURN; END;
UPDATE cfg.CategoryRole SET ObjectId = @ObjectId WHERE Domain = @Domain AND Category = @Category AND Role = @Role AND Principal = @Mail AND RemovedAt IS NULL AND ObjectId IS NULL;
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (LEFT(N'domain-role/' + @Domain + N'/' + @Category + N'/' + @Role, 128), N'domain-role', N'domain-role', N'Set', @Mail, @Mail, @By,
        LEFT(CONCAT(N'object id ', @ObjectId, N' found in the directory for ', @Mail, N' (matched by object id from now on)'), 400));
COMMIT;
SELECT N'Saved' AS Outcome;
""";

    /// The object id stored on ONE department person -- only while it is still the same address-only row; never a second
    /// row for the same person in the same role (the unique index would refuse it anyway). Type 'user' (the directory's).
    public const string ResolveMemberSql = """
SET XACT_ABORT ON;
BEGIN TRAN;
DECLARE @role nvarchar(24), @old nvarchar(max);
SELECT TOP (1) @role = m.Role,
       @old = (SELECT m.Role, m.ObjectId, m.PrincipalType, m.DisplayName, m.Mail, m.Company, m.IsExternal FOR JSON PATH, WITHOUT_ARRAY_WRAPPER)
FROM cfg.DepartmentMember AS m WITH (UPDLOCK, HOLDLOCK)
WHERE m.MemberId = @Id AND m.DepartmentId = @DepartmentId AND m.ObjectId IS NULL AND m.Mail = @Mail AND m.PrincipalType <> N'group';
IF @old IS NULL BEGIN COMMIT; SELECT N'Gone' AS Outcome; RETURN; END;
IF EXISTS (SELECT 1 FROM cfg.DepartmentMember WITH (UPDLOCK, HOLDLOCK) WHERE DepartmentId = @DepartmentId AND Role = @role AND ObjectId = @ObjectId)
BEGIN COMMIT; SELECT N'Duplicate' AS Outcome; RETURN; END;
UPDATE cfg.DepartmentMember SET ObjectId = @ObjectId, PrincipalType = N'user' WHERE MemberId = @Id AND ObjectId IS NULL;
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
SELECT LEFT(CONCAT(N'department/', @DepartmentId), 128), N'department', N'department', N'Set', @old,
       (SELECT m.Role, m.ObjectId, m.PrincipalType, m.DisplayName, m.Mail, m.Company, m.IsExternal FOR JSON PATH, WITHOUT_ARRAY_WRAPPER), @By,
       LEFT(CONCAT(N'object id found in the directory for ', @Mail, N' (matched by object id from now on)'), 400)
FROM cfg.DepartmentMember AS m WHERE m.MemberId = @Id;
COMMIT;
SELECT N'Saved' AS Outcome;
""";

    /// The object id stored on ONE active advisor -- only while it is still the same address-only row; never when another
    /// active advisor of the department already has that object id.
    public const string ResolveAdvisorSql = """
SET XACT_ABORT ON;
BEGIN TRAN;
DECLARE @old nvarchar(max) = (SELECT TOP (1) (SELECT a.Kind, a.DisplayName, a.Company, a.Mail, a.ObjectId FOR JSON PATH, WITHOUT_ARRAY_WRAPPER)
                              FROM cfg.DepartmentAdvisor AS a WITH (UPDLOCK, HOLDLOCK)
                              WHERE a.AdvisorId = @Id AND a.DepartmentId = @DepartmentId AND a.ObjectId IS NULL AND a.Mail = @Mail AND a.RevokedAt IS NULL);
IF @old IS NULL BEGIN COMMIT; SELECT N'Gone' AS Outcome; RETURN; END;
IF EXISTS (SELECT 1 FROM cfg.DepartmentAdvisor WITH (UPDLOCK, HOLDLOCK) WHERE DepartmentId = @DepartmentId AND RevokedAt IS NULL AND ObjectId = @ObjectId)
BEGIN COMMIT; SELECT N'Duplicate' AS Outcome; RETURN; END;
UPDATE cfg.DepartmentAdvisor SET ObjectId = @ObjectId WHERE AdvisorId = @Id AND ObjectId IS NULL AND RevokedAt IS NULL;
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
SELECT LEFT(CONCAT(N'department/', @DepartmentId), 128), N'department', N'department', N'Set', @old,
       (SELECT a.Kind, a.DisplayName, a.Company, a.Mail, a.ObjectId FOR JSON PATH, WITHOUT_ARRAY_WRAPPER), @By,
       LEFT(CONCAT(N'advisor''s object id found in the directory for ', @Mail, N' (matched by object id from now on)'), 400)
FROM cfg.DepartmentAdvisor AS a WHERE a.AdvisorId = @Id;
COMMIT;
SELECT N'Saved' AS Outcome;
""";

    private readonly object _gate = new();
    private readonly Dictionary<string, MailOnlyOutcome> _last = new(StringComparer.Ordinal);
    private readonly TimeProvider _clock = clock ?? TimeProvider.System;

    /// When the last pass ran (null = not yet).
    public DateTime? LastAt { get; private set; }

    private static string Key(string kind, int id) => kind + ":" + id.ToString(CultureInfo.InvariantCulture);
    private static string RosterKey(string? domain, string? category, string role, string principal) =>
        (string.IsNullOrEmpty(category) ? MailOnlyEntry.DomainRole : MailOnlyEntry.CategoryRole) + ":" + (domain ?? "").ToLowerInvariant() + "|" + (category ?? "").ToLowerInvariant()
        + "|" + role.ToLowerInvariant() + "|" + principal.Trim().ToLowerInvariant();
    private static string KeyOf(MailOnlyEntry e) => e.IsRoster ? RosterKey(e.Domain, e.Category, e.Role, e.Mail) : Key(e.Kind, e.Id);

    /// <summary>
    /// The words next to an address-only entry on the Admin's lists: what the last lookup found for it, else the rule.
    /// </summary>
    public string NoteFor(string kind, int id) => Note(Key(kind, id), MailOnlyMatch.AdminNote);

    /// #1370: the same for a Security domain / category owner or approver kept by address only (the Security owners page).
    public string NoteForRole(string domain, string? category, string role, string principal) => Note(RosterKey(domain, category, role, principal), MailOnlyMatch.RosterNote);

    private string Note(string key, string rule)
    {
        MailOnlyOutcome? o;
        lock (_gate) _last.TryGetValue(key, out o);
        var why = o?.Outcome switch
        {
            MailOnlyOutcome.NotFound => "SecurityInsight found no account with exactly this address in the directory",
            MailOnlyOutcome.Ambiguous => "more than one account in the directory has this address, so SecurityInsight did not pick one",
            MailOnlyOutcome.Duplicate => "this person is already listed by object id in the same role -- this row can be removed",
            MailOnlyOutcome.Unavailable => "the directory could not be read for this address yet",
            _ => null,
        };
        return why is null ? rule : why + " -- " + rule;
    }

    /// #1370: a pass over the Security owners' roster only (after a change on the Security owners page).
    public Task<MailOnlyPass> RunRosterAsync(CancellationToken ct) => RunCoreAsync(null, PartRoster, ct);

    /// One pass: <paramref name="departmentId"/> null = everything (department people, advisors AND the roster); a
    /// department id = that department's people and advisors only.
    public Task<MailOnlyPass> RunAsync(int? departmentId, CancellationToken ct) => RunCoreAsync(departmentId, departmentId is null ? PartAll : PartDepartment, ct);

    /// <summary>
    /// One pass: every address-only entry (of one department, or of all) looked up once per address and, when exactly one
    /// account has it, given its object id. Never throws for a lookup or a row: the outcome says what happened. A database
    /// without the tables answers no entries.
    /// </summary>
    private async Task<MailOnlyPass> RunCoreAsync(int? departmentId, string part, CancellationToken ct)
    {
        var at = _clock.GetUtcNow().UtcDateTime;
        if (!directory.CanSearch) return new MailOnlyPass(at, Array.Empty<MailOnlyOutcome>());
        var pending = (await sql.QueryAsync(PendingSql, new Dictionary<string, object?> { ["DepartmentId"] = departmentId, ["Part"] = part }, ct))
            .Select(r => new MailOnlyEntry(r.Str("Kind") ?? "", (int)(r.Long("Id") ?? 0), (int)(r.Long("DepartmentId") ?? 0), r.Str("Role") ?? "", r.Str("DisplayName") ?? "", r.Str("Mail") ?? "",
                r.Str("Domain"), r.Str("Category")))
            .Where(e => e.Mail.Trim().Length > 0 && (e.Kind is MailOnlyEntry.Member or MailOnlyEntry.Advisor
                ? e.Id > 0 && e.DepartmentId > 0
                : (e.Kind == MailOnlyEntry.DomainRole || (e.Kind == MailOnlyEntry.CategoryRole && !string.IsNullOrEmpty(e.Category))) && !string.IsNullOrEmpty(e.Domain)))
            .ToList();
        var looked = new Dictionary<string, MailMatch>(StringComparer.OrdinalIgnoreCase);
        var outcomes = new List<MailOnlyOutcome>();
        foreach (var e in pending)
        {
            var address = e.Mail.Trim();
            if (!looked.TryGetValue(address, out var match))
            {
                try { match = await directory.MatchMailAsync(address, ct); }
                catch (Exception ex) when (ex is not OperationCanceledException) { log.LogWarning(ex, "an address could not be looked up"); match = MailMatch.Unavailable; }
                looked[address] = match;
            }
            outcomes.Add(match.Outcome switch
            {
                MailMatchOutcome.Resolved when match.Person is { } p && DepartmentPeople.IsObjectId(p.ObjectId) => await StoreAsync(e, p.ObjectId.ToLowerInvariant(), ct),
                MailMatchOutcome.NotFound => new MailOnlyOutcome(e, MailOnlyOutcome.NotFound),
                MailMatchOutcome.Ambiguous => new MailOnlyOutcome(e, MailOnlyOutcome.Ambiguous),
                _ => new MailOnlyOutcome(e, MailOnlyOutcome.Unavailable),
            });
        }
        var pass = new MailOnlyPass(at, outcomes);
        lock (_gate)
        {
            if (part == PartAll) _last.Clear();
            foreach (var o in outcomes) _last[KeyOf(o.Entry)] = o;
            LastAt = at;
        }
        Report(pass);
        return pass;
    }

    private async Task<MailOnlyOutcome> StoreAsync(MailOnlyEntry e, string objectId, CancellationToken ct)
    {
        try
        {
            var statement = e.Kind switch
            {
                MailOnlyEntry.Member => ResolveMemberSql,
                MailOnlyEntry.Advisor => ResolveAdvisorSql,
                MailOnlyEntry.DomainRole => ResolveDomainRoleSql,
                _ => ResolveCategoryRoleSql,
            };
            var args = e.IsRoster
                ? new Dictionary<string, object?> { ["Domain"] = e.Domain, ["Category"] = e.Category, ["Role"] = e.Role, ["Mail"] = e.Mail, ["ObjectId"] = objectId, ["By"] = By }
                : new Dictionary<string, object?> { ["Id"] = e.Id, ["DepartmentId"] = e.DepartmentId, ["Mail"] = e.Mail, ["ObjectId"] = objectId, ["By"] = By };
            var rows = await sql.QueryAsync(statement, args, ct);
            return (rows.Count > 0 ? rows[0].Str("Outcome") : null) switch
            {
                "Saved" => new MailOnlyOutcome(e, MailOnlyOutcome.Resolved, objectId),
                "Duplicate" => new MailOnlyOutcome(e, MailOnlyOutcome.Duplicate, objectId),
                _ => new MailOnlyOutcome(e, MailOnlyOutcome.Gone),
            };
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            log.LogWarning(ex, "the object id of {Kind} {Id} could not be stored", e.Kind, e.Id);
            return new MailOnlyOutcome(e, MailOnlyOutcome.Unavailable);
        }
    }

    private void Report(MailOnlyPass pass)
    {
        foreach (var o in pass.Entries)
        {
            // no address in the log: the department + row id, or (#1370) the security domain / category + role
            var where = o.Entry.IsRoster
                ? $"{o.Entry.Role} of security {(o.Entry.Category is { Length: > 0 } c ? $"category {o.Entry.Domain} / {c}" : $"domain {o.Entry.Domain}")}"
                : $"{o.Entry.Kind} {o.Entry.Id} of department {o.Entry.DepartmentId}";
            if (o.Outcome == MailOnlyOutcome.Resolved)
                log.LogInformation("#995b: {Where} now has its object id from the directory (a change-history row says so) -- matched by object id from now on", where);
            else if (o.Outcome is MailOnlyOutcome.NotFound or MailOnlyOutcome.Ambiguous or MailOnlyOutcome.Duplicate)
                log.LogWarning("#995b: {Where} was NOT resolved: {Outcome} -- it stays matched by address for this directory's own accounts only (a guest needs its object id)",
                    where, o.Outcome);
        }
        if (pass.Entries.Count > 0)
            log.LogInformation("#995b/#1370: address-only department people, advisors and security owners: {Resolved} resolved, {NotFound} not found, {Ambiguous} more than one match, {Duplicate} already listed, {Unavailable} not looked up (directory not readable)",
                pass.Count(MailOnlyOutcome.Resolved), pass.Count(MailOnlyOutcome.NotFound), pass.Count(MailOnlyOutcome.Ambiguous), pass.Count(MailOnlyOutcome.Duplicate), pass.Count(MailOnlyOutcome.Unavailable));
    }

    /// The pass after a save of one department (the Admin's toast); never fails the save.
    public async Task<string> AfterSaveAsync(int departmentId, CancellationToken ct)
    {
        try { return (await RunAsync(departmentId, ct)).Words(); }
        catch (Exception ex) when (ex is not OperationCanceledException) { log.LogWarning(ex, "the address-only people of department {Id} could not be looked up", departmentId); return ""; }
    }

    /// #1370: the pass after a change on the Security owners page (the toast); never fails the change.
    public async Task<string> AfterRosterSaveAsync(CancellationToken ct)
    {
        try { return (await RunRosterAsync(ct)).Words(); }
        catch (Exception ex) when (ex is not OperationCanceledException) { log.LogWarning(ex, "the address-only security owners could not be looked up"); return ""; }
    }
}

/// <summary>
/// #995b: the existing installs -- every address-only department person and advisor is looked up after the web app starts
/// (the first start after the update does it for everything already there; nobody enters anything by hand) and again every
/// <see cref="Every"/> (a guest invited later, the engine's names read again). Never stops the app.
/// </summary>
public sealed class GuestObjectIdsInBackground(GuestObjectIdResolver resolver, ILogger<GuestObjectIdsInBackground> log) : BackgroundService
{
    public static readonly TimeSpan FirstDelay = TimeSpan.FromSeconds(60);
    public static readonly TimeSpan Every = TimeSpan.FromHours(6);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try { await Task.Delay(FirstDelay, stoppingToken); } catch (OperationCanceledException) { return; }
        while (!stoppingToken.IsCancellationRequested)
        {
            try { await resolver.RunAsync(null, stoppingToken); }
            catch (OperationCanceledException) { return; }
            catch (Exception ex) { log.LogWarning(ex, "#995b: the address-only department people and advisors could not be looked up this time"); }
            try { await Task.Delay(Every, stoppingToken); } catch (OperationCanceledException) { return; }
        }
    }
}
