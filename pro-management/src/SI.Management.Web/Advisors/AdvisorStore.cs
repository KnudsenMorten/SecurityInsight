using System.Text.Json;
using System.Text.RegularExpressions;
using SI.Management.Web.Data;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Advisors;

/// The kinds of advisor (#258): one consultant, or a consultancy (its advisory mailbox).
public static class AdvisorKinds
{
    public const string Person = "person";
    public const string Company = "company";
    public static readonly IReadOnlyList<string> All = [Person, Company];
    public static string Label(string kind) => kind == Company ? "Company" : "Person";
}

/// One advisor of a department (cfg.DepartmentAdvisor). Revoked, never deleted.
public sealed record AdvisorRow(int AdvisorId, int DepartmentId, string Kind, string DisplayName, string? Company, string? Mail, string? ObjectId,
    bool IsExternal, string? Note, DateTime? AddedAt, string? AddedBy, DateTime? RevokedAt, string? RevokedBy, string? RevokeReason)
{
    public bool Active => RevokedAt is null;
}

public sealed record AdvisorInput(int DepartmentId, string Kind, string DisplayName, string? Company, string? Mail, string? ObjectId, bool IsExternal, string? Note);

/// A department person a signed-in user (or a sign-in link) stands for: an advisor, or a person of cfg.DepartmentMember.
/// Kind 'advisor' -> PersonId is cfg.DepartmentAdvisor.AdvisorId; 'member' -> cfg.DepartmentMember.MemberId.
public sealed record DepartmentPerson(int DepartmentId, string Kind, int PersonId, string Role, string DisplayName, string? Mail)
{
    public const string AdvisorKind = "advisor";
    public const string MemberKind = "member";
    public bool IsAdvisor => Kind == AdvisorKind;
}

/// <summary>The advisors of the departments, and who a signed-in Entra user is in the departments.</summary>
public interface IAdvisorStore
{
    Task<bool> ReadyAsync(CancellationToken ct);
    Task<IReadOnlyList<AdvisorRow>> ListAsync(int? departmentId, bool includeRevoked, CancellationToken ct);
    Task<WriteResult> AddAsync(AdvisorInput a, string by, CancellationToken ct);
    Task<WriteResult> RevokeAsync(int departmentId, int advisorId, string reason, string by, CancellationToken ct);
    /// The department people an Entra user is: active advisors by object id or by the UPN Entra issued, and persons of a
    /// department by object id (their own or a group in the token) or by a mail-only entry. Retired departments never.
    Task<IReadOnlyList<DepartmentPerson>> PeopleAsync(IReadOnlyCollection<string> objectIds, string? upn, CancellationToken ct);
    /// The active department people with a mail address, of one department (who a sign-in link can be sent to).
    Task<IReadOnlyList<DepartmentPerson>> MailablePeopleAsync(int departmentId, CancellationToken ct);
}

/// <summary>
/// THE one class that knows cfg.DepartmentAdvisor (si-pro-settings.sql, #258). Every write is ONE transaction with its
/// cfg.ChangeLog row -- Name 'department/&lt;id&gt;', Scope 'department', Kind 'department', like the department's other
/// people. Revoking stamps RevokedAt (a revoked advisor's sessions stop on their next request).
/// </summary>
public sealed partial class SqlAdvisorStore : IAdvisorStore
{
    [GeneratedRegex(@"^[^@\s;,<>""]{1,64}@[^@\s;,<>""]{1,190}\.[A-Za-z]{2,}$", RegexOptions.CultureInvariant)] private static partial Regex MailPattern();
    [GeneratedRegex(@"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", RegexOptions.CultureInvariant)] private static partial Regex GuidPattern();

    public const string ReadySql = "SELECT CASE WHEN OBJECT_ID(N'cfg.DepartmentAdvisor') IS NULL OR OBJECT_ID(N'cfg.DepartmentSignIn') IS NULL OR OBJECT_ID(N'cfg.FindingComment') IS NULL THEN 0 ELSE 1 END AS Ready;";

    public const string ListSql = """
SELECT a.AdvisorId, a.DepartmentId, a.Kind, a.DisplayName, a.Company, a.Mail, a.ObjectId, a.IsExternal, a.Note, a.AddedAt, a.AddedBy, a.RevokedAt, a.RevokedBy, a.RevokeReason
FROM cfg.DepartmentAdvisor AS a
WHERE (@DepartmentId IS NULL OR a.DepartmentId = @DepartmentId) AND (@IncludeRevoked = 1 OR a.RevokedAt IS NULL)
ORDER BY CASE WHEN a.RevokedAt IS NULL THEN 0 ELSE 1 END, a.DisplayName;
""";

    public const string AddSql = """
SET XACT_ABORT ON;
BEGIN TRAN;
IF NOT EXISTS (SELECT 1 FROM cfg.Department WHERE DepartmentId = @DepartmentId AND RetiredAt IS NULL) BEGIN COMMIT; SELECT N'Gone' AS Outcome; RETURN; END;
IF EXISTS (SELECT 1 FROM cfg.DepartmentAdvisor WITH (UPDLOCK, HOLDLOCK)
           WHERE DepartmentId = @DepartmentId AND RevokedAt IS NULL
             AND ((@Mail IS NOT NULL AND Mail = @Mail) OR (@ObjectId IS NOT NULL AND ObjectId = @ObjectId)))
BEGIN COMMIT; SELECT N'Exists' AS Outcome; RETURN; END;
INSERT cfg.DepartmentAdvisor (DepartmentId, Kind, DisplayName, Company, Mail, ObjectId, IsExternal, Note, AddedBy)
VALUES (@DepartmentId, @Kind, @DisplayName, @Company, @Mail, @ObjectId, @IsExternal, @Note, @By);
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (LEFT(CONCAT(N'department/', @DepartmentId), 128), N'department', N'department', N'Set', NULL, @Body, @By, N'advisor added');
COMMIT;
SELECT N'Saved' AS Outcome;
""";

    public const string RevokeSql = """
SET XACT_ABORT ON;
BEGIN TRAN;
DECLARE @old nvarchar(max) = (SELECT TOP (1) (SELECT a.Kind, a.DisplayName, a.Company, a.Mail, a.ObjectId FOR JSON PATH, WITHOUT_ARRAY_WRAPPER)
                              FROM cfg.DepartmentAdvisor AS a WITH (UPDLOCK, HOLDLOCK)
                              WHERE a.AdvisorId = @AdvisorId AND a.DepartmentId = @DepartmentId AND a.RevokedAt IS NULL);
IF @old IS NULL BEGIN COMMIT; SELECT N'Gone' AS Outcome; RETURN; END;
UPDATE cfg.DepartmentAdvisor SET RevokedAt = SYSUTCDATETIME(), RevokedBy = @By, RevokeReason = @Reason
WHERE AdvisorId = @AdvisorId AND RevokedAt IS NULL;
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (LEFT(CONCAT(N'department/', @DepartmentId), 128), N'department', N'department', N'Reset', @old, NULL, @By, LEFT(CONCAT(N'advisor revoked: ', @Reason), 400));
COMMIT;
SELECT N'Saved' AS Outcome;
""";

    /// The department people an Entra user is (see <see cref="IAdvisorStore.PeopleAsync"/>). Tables that do not exist yet
    /// answer nothing (deferred name resolution inside IF).
    public const string PeopleSql = """
DECLARE @p TABLE (DepartmentId int, Kind nvarchar(8), PersonId int, Role nvarchar(24), DisplayName nvarchar(256), Mail nvarchar(256));
IF OBJECT_ID(N'cfg.DepartmentMember') IS NOT NULL
    INSERT @p SELECT m.DepartmentId, N'member', m.MemberId, m.Role, m.DisplayName, m.Mail
    FROM cfg.DepartmentMember AS m JOIN cfg.Department AS d ON d.DepartmentId = m.DepartmentId AND d.RetiredAt IS NULL
    WHERE m.ObjectId IN (SELECT j.[value] FROM OPENJSON(@ObjectIds) AS j)
       OR (m.ObjectId IS NULL AND @Upn IS NOT NULL AND m.Mail = @Upn);
IF OBJECT_ID(N'cfg.DepartmentAdvisor') IS NOT NULL
    INSERT @p SELECT a.DepartmentId, N'advisor', a.AdvisorId, N'advisor', a.DisplayName, a.Mail
    FROM cfg.DepartmentAdvisor AS a JOIN cfg.Department AS d ON d.DepartmentId = a.DepartmentId AND d.RetiredAt IS NULL
    WHERE a.RevokedAt IS NULL
      AND (a.ObjectId IN (SELECT j.[value] FROM OPENJSON(@ObjectIds) AS j) OR (@Upn IS NOT NULL AND a.Mail = @Upn));
SELECT DepartmentId, Kind, PersonId, Role, DisplayName, Mail FROM @p;
""";

    /// Everyone of one department a sign-in link can be mailed to: active advisors and persons (users / mail-only) with a
    /// mail address. A group is never mailed a personal link.
    public const string MailableSql = """
DECLARE @p TABLE (DepartmentId int, Kind nvarchar(8), PersonId int, Role nvarchar(24), DisplayName nvarchar(256), Mail nvarchar(256));
IF OBJECT_ID(N'cfg.DepartmentMember') IS NOT NULL
    INSERT @p SELECT m.DepartmentId, N'member', m.MemberId, m.Role, m.DisplayName, m.Mail
    FROM cfg.DepartmentMember AS m JOIN cfg.Department AS d ON d.DepartmentId = m.DepartmentId AND d.RetiredAt IS NULL
    WHERE m.DepartmentId = @DepartmentId AND m.PrincipalType <> N'group' AND m.Mail IS NOT NULL AND LTRIM(RTRIM(m.Mail)) <> N'';
IF OBJECT_ID(N'cfg.DepartmentAdvisor') IS NOT NULL
    INSERT @p SELECT a.DepartmentId, N'advisor', a.AdvisorId, N'advisor', a.DisplayName, a.Mail
    FROM cfg.DepartmentAdvisor AS a JOIN cfg.Department AS d ON d.DepartmentId = a.DepartmentId AND d.RetiredAt IS NULL
    WHERE a.DepartmentId = @DepartmentId AND a.RevokedAt IS NULL AND a.Mail IS NOT NULL;
SELECT DepartmentId, Kind, PersonId, Role, DisplayName, Mail FROM @p ORDER BY Kind, DisplayName;
""";

    private readonly ISqlExecutor _sql;
    public SqlAdvisorStore(ISqlExecutor sql) => _sql = sql;

    private static string? Blank(string? s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();
    private static string Cut(string s, int n) => s.Length > n ? s[..n] : s;

    public static IReadOnlyList<string> Validate(AdvisorInput a)
    {
        var why = new List<string>();
        if (!AdvisorKinds.All.Contains(a.Kind)) why.Add("an advisor is a person or a company");
        if (string.IsNullOrWhiteSpace(a.DisplayName) || a.DisplayName.Trim().Length > 256 || a.DisplayName.Any(char.IsControl)) why.Add("give the advisor's name (up to 256 characters)");
        var mail = Blank(a.Mail); var oid = Blank(a.ObjectId);
        if (mail is null && oid is null) why.Add("give the mail address the sign-in links go to (or, for a B2B guest, their object id)");
        if (mail is not null && !MailPattern().IsMatch(mail)) why.Add($"'{mail}' is not a mail address");
        if (oid is not null && !GuidPattern().IsMatch(oid)) why.Add($"'{oid}' is not an Entra object id");
        if ((a.Company?.Length ?? 0) > 256) why.Add("the company is longer than 256 characters");
        if ((a.Note?.Length ?? 0) > 400) why.Add("the note is longer than 400 characters");
        if (a.Kind == AdvisorKinds.Company && mail is null) why.Add("a company advisor needs its advisory mailbox");
        return why;
    }

    private static WriteResult Outcome(IReadOnlyList<SqlRow> rows, string saved, string exists, string gone) => (rows.Count > 0 ? rows[0].Str("Outcome") : null) switch
    {
        "Saved" => new WriteResult(WriteStatus.Saved, saved),
        "Exists" => new WriteResult(WriteStatus.Stale, exists),
        "Gone" => new WriteResult(WriteStatus.Stale, gone),
        _ => throw new InvalidOperationException("the write returned no outcome"),
    };

    public async Task<bool> ReadyAsync(CancellationToken ct)
    {
        var rows = await _sql.QueryAsync(ReadySql, new Dictionary<string, object?>(), ct);
        return rows.Count > 0 && rows[0].Long("Ready") == 1;
    }

    public async Task<IReadOnlyList<AdvisorRow>> ListAsync(int? departmentId, bool includeRevoked, CancellationToken ct) =>
        (await _sql.QueryAsync(ListSql, new Dictionary<string, object?> { ["DepartmentId"] = departmentId, ["IncludeRevoked"] = includeRevoked ? 1 : 0 }, ct))
        .Select(r => new AdvisorRow((int)(r.Long("AdvisorId") ?? 0), (int)(r.Long("DepartmentId") ?? 0), r.Str("Kind") ?? AdvisorKinds.Person, r.Str("DisplayName") ?? "",
            r.Str("Company"), r.Str("Mail"), r.Str("ObjectId"), r.TryGetValue("IsExternal", out var x) && x is true or 1 or (long)1, r.Str("Note"),
            r.Date("AddedAt"), r.Str("AddedBy"), r.Date("RevokedAt"), r.Str("RevokedBy"), r.Str("RevokeReason"))).ToList();

    public async Task<WriteResult> AddAsync(AdvisorInput a, string by, CancellationToken ct)
    {
        var why = Validate(a);
        if (why.Count > 0) return new WriteResult(WriteStatus.Refused, string.Join("; ", why));
        if (string.IsNullOrWhiteSpace(by)) return new WriteResult(WriteStatus.Refused, "the signed-in user has no name to record");
        var mail = Blank(a.Mail)?.ToLowerInvariant(); var oid = Blank(a.ObjectId)?.ToLowerInvariant();
        var rows = await _sql.QueryAsync(AddSql, new Dictionary<string, object?>
        {
            ["DepartmentId"] = a.DepartmentId, ["Kind"] = a.Kind, ["DisplayName"] = a.DisplayName.Trim(), ["Company"] = Blank(a.Company), ["Mail"] = mail, ["ObjectId"] = oid,
            ["IsExternal"] = a.IsExternal, ["Note"] = Blank(a.Note), ["By"] = Cut(by, 256),
            ["Body"] = JsonSerializer.Serialize(new { Role = "advisor", a.Kind, DisplayName = a.DisplayName.Trim(), Company = Blank(a.Company), Mail = mail, ObjectId = oid, a.IsExternal, Note = Blank(a.Note) }),
        }, ct);
        return Outcome(rows, $"{a.DisplayName.Trim()} added as an advisor", $"{a.DisplayName.Trim()} is already an advisor of this department", "that department is retired or gone");
    }

    public async Task<WriteResult> RevokeAsync(int departmentId, int advisorId, string reason, string by, CancellationToken ct)
    {
        var r = (reason ?? "").Trim();
        if (r.Length is < 3 or > 400) return new WriteResult(WriteStatus.Refused, "give a reason (3 to 400 characters) -- it is what the audit shows");
        var rows = await _sql.QueryAsync(RevokeSql, new Dictionary<string, object?> { ["DepartmentId"] = departmentId, ["AdvisorId"] = advisorId, ["Reason"] = r, ["By"] = Cut(by, 256) }, ct);
        return Outcome(rows, "advisor revoked: their sign-in links and sessions stop working at once (the row is kept for the audit)", "", "that advisor is already revoked");
    }

    private static IReadOnlyList<DepartmentPerson> People(IReadOnlyList<SqlRow> rows) => rows
        .Select(r => new DepartmentPerson((int)(r.Long("DepartmentId") ?? 0), r.Str("Kind") ?? "", (int)(r.Long("PersonId") ?? 0), r.Str("Role") ?? "", r.Str("DisplayName") ?? "", r.Str("Mail")))
        .Where(p => p.DepartmentId > 0 && p.PersonId > 0 && p.Kind is DepartmentPerson.AdvisorKind or DepartmentPerson.MemberKind).ToList();

    public async Task<IReadOnlyList<DepartmentPerson>> PeopleAsync(IReadOnlyCollection<string> objectIds, string? upn, CancellationToken ct)
    {
        var ids = objectIds.Where(o => GuidPattern().IsMatch(o ?? "")).Select(o => o.ToLowerInvariant()).Distinct().Take(500).ToList();
        var mail = Blank(upn)?.ToLowerInvariant();
        if (mail is not null && !MailPattern().IsMatch(mail)) mail = null;
        if (ids.Count == 0 && mail is null) return Array.Empty<DepartmentPerson>();
        return People(await _sql.QueryAsync(PeopleSql, new Dictionary<string, object?> { ["ObjectIds"] = JsonSerializer.Serialize(ids), ["Upn"] = mail }, ct));
    }

    public async Task<IReadOnlyList<DepartmentPerson>> MailablePeopleAsync(int departmentId, CancellationToken ct) =>
        People(await _sql.QueryAsync(MailableSql, new Dictionary<string, object?> { ["DepartmentId"] = departmentId }, ct));
}
