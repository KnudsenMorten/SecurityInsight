using SI.Management.Web.Data;

namespace SI.Management.Web.Auth;

/// When the people picker's names were read: the newest read of the users and of the groups by SecurityInsight's engine
/// (sidata.DirectoryNameLoad), and whether each read was complete. Null times = no run has saved names yet.
public sealed record DirectoryFreshness(DateTime? UsersAt, bool UsersComplete, DateTime? GroupsAt, bool GroupsComplete)
{
    /// The newer of the two reads.
    public DateTime? At => UsersAt is { } u && GroupsAt is { } g ? (u > g ? u : g) : UsersAt ?? GroupsAt;
    public bool Any => At is not null;
    public bool Complete => UsersComplete && (GroupsAt is null || GroupsComplete);
}

/// <summary>
/// THE PEOPLE PICKER FROM SECURITYINSIGHT'S OWN DATA (owner 2026-11-16: "can engine provide the data"; framework GRAPH-PICKER
/// under SECURE-WEB-1: the internet-facing web identity never holds or uses a directory-read Graph permission). Used when
/// Access:GraphLookup is OFF: users and groups are searched in sidata.DirectoryName -- filled by the ENGINE (the identity
/// collection's user pages and one light group read; an Admin's "Search the tenant", engine\asset-profiling\shared\
/// SI-DirectoryNames.ps1) -- with the web app's database reader right. NO Microsoft Graph call; the web identity holds no
/// directory right. A database without the tables (one schema behind), or any failure: nothing found / unknown, never an
/// error page. Who holds a role on the sign-in application (AppRoleHoldersAsync) needs Graph and stays unknown here: the
/// Access page then shows SecurityInsight's own table only, Get started shows the people added here.
/// </summary>
public sealed class SqlDirectoryNames(ISqlExecutor sql, ILogger<SqlDirectoryNames> log) : IDirectoryNames
{
    /// The picker shows at most this many people and groups (enabled ones first).
    public const int Top = 10;

    /// The size of the search's LIKE patterns (nvarchar) in <see cref="SearchSql"/>: the longest escaped text fits.
    public const int PatternMax = 400;
    /// The longest text the search takes (<see cref="Clean"/>).
    public const int TextMax = 100;

    /// Prefix search: the name, the sign-in name or the mail starting with the text (each its own index seek); a mail address
    /// also finds a guest by the sign-in name Entra made of it (anna@contoso.com -> anna_contoso.com#EXT#...). Enabled
    /// people and groups first, then by name. Only the picker's columns.
    /// The LIKE patterns hold the ESCAPED text: every character may become three ('[' -> '[[]', '%' -> '[%]', '_' -> '[_]'),
    /// plus the trailing '%'. <see cref="PatternMax"/> fits the longest text the search takes (<see cref="Clean"/>: 100, a
    /// guest's sign-in name start: 105) escaped in full -- a pattern is never cut short.
    public const string SearchSql = """
SET NOCOUNT ON;
IF OBJECT_ID(N'sidata.DirectoryName') IS NULL BEGIN SELECT CAST(NULL AS nvarchar(64)) AS ObjectId WHERE 1 = 0; RETURN; END
DECLARE @p nvarchar(400) = REPLACE(REPLACE(REPLACE(@q, N'[', N'[[]'), N'%', N'[%]'), N'_', N'[_]') + N'%';
DECLARE @g nvarchar(400) = CASE WHEN @guest IS NULL THEN NULL ELSE REPLACE(REPLACE(REPLACE(@guest, N'[', N'[[]'), N'%', N'[%]'), N'_', N'[_]') + N'%' END;
SELECT TOP (@n) ObjectId, Kind, DisplayName, Upn, Mail, AccountEnabled, Guest
FROM (
    SELECT ObjectId, Kind, DisplayName, Upn, Mail, AccountEnabled, Guest FROM sidata.DirectoryName WHERE DisplayName LIKE @p
    UNION SELECT ObjectId, Kind, DisplayName, Upn, Mail, AccountEnabled, Guest FROM sidata.DirectoryName WHERE Upn LIKE @p
    UNION SELECT ObjectId, Kind, DisplayName, Upn, Mail, AccountEnabled, Guest FROM sidata.DirectoryName WHERE Mail LIKE @p
    UNION SELECT ObjectId, Kind, DisplayName, Upn, Mail, AccountEnabled, Guest FROM sidata.DirectoryName WHERE @g IS NOT NULL AND Upn LIKE @g
) AS x
ORDER BY CASE WHEN x.AccountEnabled = 0 THEN 1 ELSE 0 END, x.DisplayName, x.ObjectId;
""";

    public const string NameSql = """
SET NOCOUNT ON;
IF OBJECT_ID(N'sidata.DirectoryName') IS NULL BEGIN SELECT CAST(NULL AS nvarchar(64)) AS ObjectId WHERE 1 = 0; RETURN; END
SELECT ObjectId, Kind, DisplayName, Upn, Mail, AccountEnabled, Guest FROM sidata.DirectoryName WHERE ObjectId = @id;
""";

    /// A person by mail or sign-in name: only an exact match of exactly one user counts.
    public const string FindByMailSql = """
SET NOCOUNT ON;
IF OBJECT_ID(N'sidata.DirectoryName') IS NULL BEGIN SELECT CAST(NULL AS nvarchar(64)) AS ObjectId WHERE 1 = 0; RETURN; END
SELECT TOP (2) ObjectId, Kind, DisplayName, Upn, Mail, AccountEnabled, Guest FROM (
    SELECT ObjectId, Kind, DisplayName, Upn, Mail, AccountEnabled, Guest FROM sidata.DirectoryName WHERE Kind = N'user' AND Mail = @m
    UNION SELECT ObjectId, Kind, DisplayName, Upn, Mail, AccountEnabled, Guest FROM sidata.DirectoryName WHERE Kind = N'user' AND Upn = @m) AS x;
""";

    public const string FreshnessSql = """
SET NOCOUNT ON;
IF OBJECT_ID(N'sidata.DirectoryNameLoad') IS NULL BEGIN SELECT CAST(NULL AS nvarchar(8)) AS Kind WHERE 1 = 0; RETURN; END
SELECT Kind, ReadAt, CAST(Complete AS int) AS Complete FROM sidata.DirectoryNameLoad;
""";

    /// Graph lookup: off (this is the web app WITHOUT it). The picker searches SecurityInsight's own names.
    public bool Enabled => false;
    public bool CanSearch => true;
    public bool CanAskTenant => true;

    /// PURE. The text as the search takes it (2..100 characters, no control character), else null.
    public static string? Clean(string? text)
    {
        var t = (text ?? "").Trim();
        return t.Length < 2 || t.Length > TextMax || t.Any(char.IsControl) ? null : t;
    }

    /// PURE. A guest's sign-in name Entra made of a home address (anna@contoso.com -> anna_contoso.com#EXT#), else null.
    public static string? GuestUpnStart(string t)
    {
        var at = t.LastIndexOf('@');
        return at > 0 && at < t.Length - 1 && !t.Contains("#EXT#", StringComparison.OrdinalIgnoreCase) ? $"{t[..at]}_{t[(at + 1)..]}#EXT#" : null;
    }

    private static DirectoryPerson? Person(SqlRow r)
    {
        var id = r.Str("ObjectId");
        if (string.IsNullOrEmpty(id)) return null;
        var group = string.Equals(r.Str("Kind"), "group", StringComparison.OrdinalIgnoreCase);
        var name = r.Str("DisplayName") is { Length: > 0 } n ? n : r.Str("Mail") ?? r.Str("Upn") ?? id;
        var mail = r.Str("Mail") ?? (group ? null : r.Str("Upn"));
        var enabled = r.TryGetValue("AccountEnabled", out var e) && e is not null ? Convert.ToBoolean(e, System.Globalization.CultureInfo.InvariantCulture) : (bool?)null;
        var guest = r.TryGetValue("Guest", out var g) && g is not null && Convert.ToBoolean(g, System.Globalization.CultureInfo.InvariantCulture);
        return new DirectoryPerson(group ? "group" : "user", id.ToLowerInvariant(), name, mail, guest) { Disabled = enabled == false };
    }

    public async Task<IReadOnlyList<DirectoryPerson>> SearchAsync(string text, CancellationToken ct)
    {
        if (Clean(text) is not { } t) return Array.Empty<DirectoryPerson>();
        try
        {
            var rows = await sql.QueryAsync(SearchSql, new Dictionary<string, object?> { ["q"] = t, ["guest"] = GuestUpnStart(t), ["n"] = Top }, ct);
            return rows.Select(Person).Where(p => p is not null).Select(p => p!).ToList();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            log.LogWarning(ex, "the people picker could not read SecurityInsight's names");
            return Array.Empty<DirectoryPerson>();
        }
    }

    public async Task<(string Type, string Name)?> NameOfAsync(string objectId, CancellationToken ct)
    {
        if (!SqlAccessStore.ObjectId().IsMatch(objectId ?? "")) return null;
        try
        {
            var rows = await sql.QueryAsync(NameSql, new Dictionary<string, object?> { ["id"] = objectId!.Trim().ToLowerInvariant() }, ct);
            if (rows.Count != 1 || Person(rows[0]) is not { } p) return null;
            return (p.Type == "group" ? AccessAssignment.Group : AccessAssignment.User, p.Name);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            log.LogWarning(ex, "a name could not be read from SecurityInsight's names");
            return null;
        }
    }

    public async Task<DirectoryPerson?> FindAsync(string mailOrObjectId, CancellationToken ct)
    {
        var q = (mailOrObjectId ?? "").Trim();
        string query; Dictionary<string, object?> args;
        if (SqlAccessStore.ObjectId().IsMatch(q)) { query = NameSql; args = new() { ["id"] = q.ToLowerInvariant() }; }
        else if (SI.Management.Web.Departments.DepartmentPeople.IsMail(q)) { query = FindByMailSql; args = new() { ["m"] = q }; }
        else return null;
        try
        {
            var rows = await sql.QueryAsync(query, args, ct);
            return rows.Count == 1 ? Person(rows[0]) : null;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            log.LogWarning(ex, "a person could not be looked up in SecurityInsight's names");
            return null;
        }
    }

    public async Task<DirectoryFreshness?> FreshnessAsync(CancellationToken ct)
    {
        try
        {
            DateTime? users = null, groups = null; bool uOk = false, gOk = false;
            foreach (var r in await sql.QueryAsync(FreshnessSql, new Dictionary<string, object?>(), ct))
            {
                var at = r.Date("ReadAt") is { } d ? DateTime.SpecifyKind(d, DateTimeKind.Utc) : (DateTime?)null;
                var ok = r.Long("Complete") == 1;
                if (string.Equals(r.Str("Kind"), "user", StringComparison.OrdinalIgnoreCase)) { users = at; uOk = ok; }
                else if (string.Equals(r.Str("Kind"), "group", StringComparison.OrdinalIgnoreCase)) { groups = at; gOk = ok; }
            }
            return new DirectoryFreshness(users, uOk, groups, gOk);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            log.LogWarning(ex, "the time of SecurityInsight's names could not be read");
            return null;
        }
    }
}

/// One "Search the tenant" request as the person who asked sees it.
public sealed record DirectorySearchStatus(long RequestId, string State, int? Found, string? Detail);

/// <summary>
/// "SEARCH THE TENANT" (framework GRAPH-PICKER): a name the picker did not find is looked up by SecurityInsight's ENGINE, not
/// by the web app. An Admin's request (the text, a reason) becomes ONE row through sidata.DirectorySearchAsk (the procedure
/// checks it: 2..100 characters, a reason; no limit on how many, owner 2026-11-17); the engine's background job
/// (caj-si-signin-methods, every 15 minutes, and between its batches while it runs) reads Microsoft Graph as the engine
/// identity -- names starting with the text, reads only -- and stores what it finds as names the picker then finds in SQL.
/// The web app holds no Graph right and starts no job.
/// </summary>
public sealed class DirectorySearchRequests(ISqlExecutor sql, ILogger<DirectorySearchRequests> log)
{
    /// No limit on how many (owner 2026-11-17): the procedure checks the text and the reason and writes the request.
    public const string AskSql = "EXEC sidata.DirectorySearchAsk @Text = @Text, @Reason = @Reason, @By = @By;";

    /// Only the asker's own request is answered.
    public const string StatusSql = """
SET NOCOUNT ON;
IF OBJECT_ID(N'sidata.DirectorySearchRequest') IS NULL BEGIN SELECT CAST(NULL AS bigint) AS RequestId WHERE 1 = 0; RETURN; END
SELECT RequestId, Outcome, Found, Detail FROM sidata.DirectorySearchRequest WHERE RequestId = @id AND RequestedBy = @by;
""";

    /// The words the picker shows after asking.
    public const string AskedWords = "Asked. SecurityInsight's engine looks this up in Microsoft Entra within about 15 minutes (reads only); the people and groups it finds then show in the list -- type the name again.";

    /// (RequestId, null) when written; (null, the reason) when refused or not possible.
    public async Task<(long? RequestId, string? Refused)> AskAsync(string? text, string? reason, string by, CancellationToken ct)
    {
        if (SqlDirectoryNames.Clean(text) is not { } t) return (null, "type 2 to 100 characters of the name, sign-in name or mail");
        var r = (reason ?? "").Trim();
        if (r.Length < 3) return (null, "give a reason");
        if (string.IsNullOrWhiteSpace(by)) return (null, "the person asking is not known");
        try
        {
            var rows = await sql.QueryAsync(AskSql, new Dictionary<string, object?> { ["Text"] = t, ["Reason"] = r.Length > 400 ? r[..400] : r, ["By"] = by.Length > 256 ? by[..256] : by }, ct);
            if (rows.Count == 0) return (null, "the request was not written");
            if (rows[0].Long("RequestId") is { } id) return (id, null);
            return (null, rows[0].Str("Refused") ?? "the request was refused");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            log.LogWarning(ex, "a tenant search could not be asked for");
            return (null, "the request could not be written (the database may be one update behind): " + ViewerError.Text(ex));
        }
    }

    /// waiting | done | failed | refused | expired; null = not this person's request (or not readable).
    public async Task<DirectorySearchStatus?> StatusAsync(long id, string by, CancellationToken ct)
    {
        try
        {
            var rows = await sql.QueryAsync(StatusSql, new Dictionary<string, object?> { ["id"] = id, ["by"] = by }, ct);
            if (rows.Count != 1) return null;
            return new DirectorySearchStatus(id, rows[0].Str("Outcome") ?? "waiting", rows[0].Long("Found") is { } f ? (int?)f : null, rows[0].Str("Detail"));
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            log.LogWarning(ex, "a tenant search's state could not be read");
            return null;
        }
    }
}
