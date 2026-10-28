using System.Text.RegularExpressions;
using Microsoft.Extensions.Caching.Memory;
using SI.Management.Web.Data;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Auth;

/// <summary>
/// One person or group with access to SecurityInsight (cfg.AccessAssignment): an Entra user or group (by object id) -> a
/// role, and for Delegated its scope. #765: SI DECIDES -- this row is the person's role; an Entra app role only counts until
/// it was carried over here once (<see cref="IAccessStore.CarryOverAsync"/>). AccountMail = the person's own mail as Entra
/// gives it; ForwardTo = where SecurityInsight mail to them goes instead (null = their own, <see cref="MailForward"/>).
/// </summary>
public sealed record AccessAssignment(string PrincipalId, string PrincipalType, string DisplayName, SiRole Role, AccessScope Scope,
    DateTime? UpdatedAt = null, string? UpdatedBy = null, long Version = 0, string? AccountMail = null, string? ForwardTo = null)
{
    public const string User = "User";
    public const string Group = "Group";

    public bool Matches(string? oid, IReadOnlyCollection<string> groups) => PrincipalType == Group
        ? groups.Contains(PrincipalId, StringComparer.OrdinalIgnoreCase)
        : oid is not null && string.Equals(PrincipalId, oid, StringComparison.OrdinalIgnoreCase);

    /// A B2B guest: Entra gives a guest a sign-in name with #EXT# in it.
    public bool IsGuest => PrincipalType == User && ((AccountMail ?? "").Contains("#EXT#", StringComparison.OrdinalIgnoreCase) || DisplayName.Contains("#EXT#", StringComparison.OrdinalIgnoreCase));

    /// "Person", "Guest" or "Group" -- how the Access table names the kind of identity.
    public string Kind => PrincipalType == Group ? "Group" : IsGuest ? "Guest" : "Person";

    /// The row was written by the carry-over from Entra (its "changed by").
    public bool CarriedOver => string.Equals(UpdatedBy, SqlAccessStore.CarryOverBy, StringComparison.Ordinal);
}

/// One app role to carry over (#765): who, the ladder role their Entra app role gives, and whether a row already gives at
/// least that much (then only the "carried over" mark is written -- nothing changes for the person).
public sealed record CarryOver(string PrincipalId, string PrincipalType, string DisplayName, string? AccountMail, SiRole Role, bool MarkOnly);

/// The portal role mapping (cfg.AccessAssignment in the Pro database). Every write has its cfg.ChangeLog row.
public interface IAccessStore
{
    /// Every assignment (cached for seconds; a write clears the cache). Throws when the store cannot be read.
    Task<IReadOnlyList<AccessAssignment>> ListAsync(CancellationToken ct);
    /// Whether the table exists yet (the Pro settings schema adds it).
    Task<bool> TableExistsAsync(CancellationToken ct);
    /// Create or change one assignment. ExpectedVersion = the version read (null = must not exist yet).
    Task<WriteResult> WriteAsync(AccessAssignment a, long? expectedVersion, string by, string reason, CancellationToken ct);
    /// Remove one assignment (the user / group then has no access, #765).
    Task<WriteResult> RemoveAsync(string principalId, long expectedVersion, string by, string reason, CancellationToken ct);
    /// #765: the (object id, role) pairs already carried over from Entra, as "objectid|Role" (lower-case id). Empty = none
    /// known -- every app role still counts (the safe reading for a store that cannot say).
    Task<IReadOnlySet<string>> CarriedAsync(CancellationToken ct) => Task.FromResult<IReadOnlySet<string>>(new HashSet<string>());
    /// #765: carries one Entra app role over into this table, once (idempotent). Refused = nothing written (the schema has no
    /// carry-over table yet): the app role keeps counting.
    Task<WriteResult> CarryOverAsync(CarryOver c, CancellationToken ct) => Task.FromResult(new WriteResult(WriteStatus.Refused, "not supported"));
}

/// <summary>
/// THE one class that knows the shape of cfg.AccessAssignment (sql\si-pro-settings.sql): PrincipalId, PrincipalType,
/// DisplayName, Role, ScopeJson, AccountMail, ForwardTo, UpdatedAt, UpdatedBy, RowVersion -- and of cfg.AccessCarriedOver
/// (#765). Each write is one transaction with its cfg.ChangeLog row (Name 'access/&lt;object id&gt;', Scope 'access', Kind
/// 'access'; Set = assigned or changed, Reset = removed). A write that would leave no SuperAdmin is refused by the
/// statement itself. A database one schema version behind (no AccountMail / ForwardTo, no carry-over table) keeps working.
/// </summary>
public sealed partial class SqlAccessStore : IAccessStore
{
    public const string CacheKey = "si-access-assignments";
    public const string CarriedCacheKey = "si-access-carried";
    private const string CarryMissingKey = "si-access-carry-missing";
    public static readonly TimeSpan CacheFor = TimeSpan.FromSeconds(15);
    /// The "changed by" of a row the carry-over wrote, and the reason of its change-history row.
    public const string CarryOverBy = "SecurityInsight (carried over from Entra)";
    public const string CarryOverReason = "carried over from Entra: the Entra app role this person or group held, now kept in SecurityInsight -- nobody gains or loses access";

    [GeneratedRegex(@"^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$", RegexOptions.CultureInvariant)] public static partial Regex ObjectId();

    public const string ExistsSql = "SELECT CASE WHEN OBJECT_ID(N'cfg.AccessAssignment') IS NULL THEN 0 ELSE 1 END AS HasTable;";

    /// No table yet = no assignments (not an error): until the schema is updated, everyone has exactly the app role.
    public const string ListSql = """
IF OBJECT_ID(N'cfg.AccessAssignment') IS NOT NULL
BEGIN
    IF COL_LENGTH(N'cfg.AccessAssignment', N'ForwardTo') IS NOT NULL
        EXEC (N'SELECT PrincipalId, PrincipalType, DisplayName, Role, ScopeJson, UpdatedAt, UpdatedBy, CONVERT(bigint, RowVersion) AS Version, AccountMail, ForwardTo
FROM cfg.AccessAssignment ORDER BY Role DESC, DisplayName;');
    ELSE
        SELECT PrincipalId, PrincipalType, DisplayName, Role, ScopeJson, UpdatedAt, UpdatedBy, CONVERT(bigint, RowVersion) AS Version,
               CAST(NULL AS nvarchar(320)) AS AccountMail, CAST(NULL AS nvarchar(320)) AS ForwardTo
        FROM cfg.AccessAssignment ORDER BY Role DESC, DisplayName;
END;
""";

    public const string WriteSql = """
SET XACT_ABORT ON;
IF OBJECT_ID(N'cfg.AccessAssignment') IS NULL
BEGIN
    SELECT N'Missing' AS Outcome;
    RETURN;
END;
DECLARE @hasMail bit = CASE WHEN COL_LENGTH(N'cfg.AccessAssignment', N'ForwardTo') IS NULL THEN 0 ELSE 1 END;
BEGIN TRAN;
DECLARE @cur bigint = (SELECT CONVERT(bigint, RowVersion) FROM cfg.AccessAssignment WITH (UPDLOCK, HOLDLOCK) WHERE PrincipalId = @PrincipalId);
DECLARE @old nvarchar(max) = (SELECT Role + COALESCE(N' ' + ScopeJson, N'') FROM cfg.AccessAssignment WHERE PrincipalId = @PrincipalId);
DECLARE @oldFwd nvarchar(320) = NULL;
IF @hasMail = 1 AND @cur IS NOT NULL
    EXEC sp_executesql N'SELECT @o = ForwardTo FROM cfg.AccessAssignment WHERE PrincipalId = @p;', N'@o nvarchar(320) OUTPUT, @p nvarchar(64)', @o = @oldFwd OUTPUT, @p = @PrincipalId;
IF @oldFwd IS NOT NULL SET @old = @old + N' -- mail to ' + @oldFwd;
IF (@Expected IS NULL AND @cur IS NOT NULL) OR (@Expected IS NOT NULL AND (@cur IS NULL OR @cur <> @Expected))
BEGIN
    COMMIT;
    SELECT N'Stale' AS Outcome;
    RETURN;
END;
DECLARE @supersBefore int = (SELECT COUNT(*) FROM cfg.AccessAssignment WHERE Role = N'SuperAdmin');
IF @cur IS NULL
BEGIN
    IF @hasMail = 1
        EXEC sp_executesql N'INSERT cfg.AccessAssignment (PrincipalId, PrincipalType, DisplayName, Role, ScopeJson, UpdatedBy, AccountMail, ForwardTo)
VALUES (@PrincipalId, @PrincipalType, @DisplayName, @Role, @ScopeJson, @By, @AccountMail, @ForwardTo);',
            N'@PrincipalId nvarchar(64), @PrincipalType nvarchar(8), @DisplayName nvarchar(256), @Role nvarchar(16), @ScopeJson nvarchar(max), @By nvarchar(256), @AccountMail nvarchar(320), @ForwardTo nvarchar(320)',
            @PrincipalId = @PrincipalId, @PrincipalType = @PrincipalType, @DisplayName = @DisplayName, @Role = @Role, @ScopeJson = @ScopeJson, @By = @By, @AccountMail = @AccountMail, @ForwardTo = @ForwardTo;
    ELSE
        INSERT cfg.AccessAssignment (PrincipalId, PrincipalType, DisplayName, Role, ScopeJson, UpdatedBy)
        VALUES (@PrincipalId, @PrincipalType, @DisplayName, @Role, @ScopeJson, @By);
END
ELSE
BEGIN
    IF @hasMail = 1
        EXEC sp_executesql N'UPDATE cfg.AccessAssignment SET PrincipalType = @PrincipalType, DisplayName = @DisplayName, Role = @Role, ScopeJson = @ScopeJson,
       AccountMail = COALESCE(@AccountMail, AccountMail), ForwardTo = @ForwardTo, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By
WHERE PrincipalId = @PrincipalId;',
            N'@PrincipalId nvarchar(64), @PrincipalType nvarchar(8), @DisplayName nvarchar(256), @Role nvarchar(16), @ScopeJson nvarchar(max), @By nvarchar(256), @AccountMail nvarchar(320), @ForwardTo nvarchar(320)',
            @PrincipalId = @PrincipalId, @PrincipalType = @PrincipalType, @DisplayName = @DisplayName, @Role = @Role, @ScopeJson = @ScopeJson, @By = @By, @AccountMail = @AccountMail, @ForwardTo = @ForwardTo;
    ELSE
        UPDATE cfg.AccessAssignment SET PrincipalType = @PrincipalType, DisplayName = @DisplayName, Role = @Role, ScopeJson = @ScopeJson,
               UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By
        WHERE PrincipalId = @PrincipalId;
END;
IF @supersBefore > 0 AND NOT EXISTS (SELECT 1 FROM cfg.AccessAssignment WHERE Role = N'SuperAdmin')
BEGIN
    ROLLBACK;
    SELECT N'LastSuperAdmin' AS Outcome;
    RETURN;
END;
-- #765: SecurityInsight decided for this identity -- no Entra app role of theirs is carried over on top of it later
IF OBJECT_ID(N'cfg.AccessCarriedOver') IS NOT NULL
    INSERT cfg.AccessCarriedOver (PrincipalId, Role)
    SELECT @PrincipalId, r.Role FROM (VALUES (N'Reader'), (N'Admin'), (N'SuperAdmin')) AS r(Role)
    WHERE NOT EXISTS (SELECT 1 FROM cfg.AccessCarriedOver AS c WHERE c.PrincipalId = @PrincipalId AND c.Role = r.Role);
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (LEFT(N'access/' + @PrincipalId, 128), N'access', N'access', N'Set', @old,
        @Role + COALESCE(N' ' + @ScopeJson, N'') + N' -- ' + @DisplayName + CASE WHEN @hasMail = 1 AND @ForwardTo IS NOT NULL THEN N' -- mail to ' + @ForwardTo ELSE N'' END,
        @By, LEFT(@Reason, 400));
COMMIT;
SELECT N'Saved' AS Outcome;
""";

    public const string RemoveSql = """
SET XACT_ABORT ON;
IF OBJECT_ID(N'cfg.AccessAssignment') IS NULL
BEGIN
    SELECT N'Missing' AS Outcome;
    RETURN;
END;
BEGIN TRAN;
DECLARE @cur bigint = (SELECT CONVERT(bigint, RowVersion) FROM cfg.AccessAssignment WITH (UPDLOCK, HOLDLOCK) WHERE PrincipalId = @PrincipalId);
DECLARE @old nvarchar(max) = (SELECT Role + COALESCE(N' ' + ScopeJson, N'') + N' -- ' + DisplayName FROM cfg.AccessAssignment WHERE PrincipalId = @PrincipalId);
IF @cur IS NULL OR @cur <> @Expected
BEGIN
    COMMIT;
    SELECT N'Stale' AS Outcome;
    RETURN;
END;
DECLARE @supersBefore int = (SELECT COUNT(*) FROM cfg.AccessAssignment WHERE Role = N'SuperAdmin');
DELETE FROM cfg.AccessAssignment WHERE PrincipalId = @PrincipalId;
IF @supersBefore > 0 AND NOT EXISTS (SELECT 1 FROM cfg.AccessAssignment WHERE Role = N'SuperAdmin')
BEGIN
    ROLLBACK;
    SELECT N'LastSuperAdmin' AS Outcome;
    RETURN;
END;
-- #765: SecurityInsight decided for this identity -- no Entra app role of theirs is carried over on top of it later
IF OBJECT_ID(N'cfg.AccessCarriedOver') IS NOT NULL
    INSERT cfg.AccessCarriedOver (PrincipalId, Role)
    SELECT @PrincipalId, r.Role FROM (VALUES (N'Reader'), (N'Admin'), (N'SuperAdmin')) AS r(Role)
    WHERE NOT EXISTS (SELECT 1 FROM cfg.AccessCarriedOver AS c WHERE c.PrincipalId = @PrincipalId AND c.Role = r.Role);
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (LEFT(N'access/' + @PrincipalId, 128), N'access', N'access', N'Reset', @old, NULL, @By, LEFT(@Reason, 400));
COMMIT;
SELECT N'Saved' AS Outcome;
""";

    /// #765: the app roles already carried over. No table yet = none (every app role still counts).
    public const string CarriedSql = """
IF OBJECT_ID(N'cfg.AccessCarriedOver') IS NOT NULL
    SELECT PrincipalId, Role FROM cfg.AccessCarriedOver;
ELSE
    SELECT CAST(NULL AS nvarchar(64)) AS PrincipalId, CAST(NULL AS nvarchar(16)) AS Role WHERE 1 = 0;
""";

    /// <summary>
    /// #765: carries one Entra app role over, ONCE: the (identity, role) mark first -- a second call answers 'Already' and
    /// writes nothing; then, unless a row already gives at least that role (or MarkOnly), the row is created or RAISED to it
    /// (never lowered; a Delegated row raised to Admin loses its scope, which Admin does not need) with its change-history
    /// row "carried over from Entra". Nobody gains or loses access: the person had exactly this role through Entra.
    /// </summary>
    public const string CarryOverSql = """
SET XACT_ABORT ON;
IF OBJECT_ID(N'cfg.AccessAssignment') IS NULL OR OBJECT_ID(N'cfg.AccessCarriedOver') IS NULL
BEGIN
    SELECT N'Missing' AS Outcome;
    RETURN;
END;
BEGIN TRAN;
IF EXISTS (SELECT 1 FROM cfg.AccessCarriedOver WITH (UPDLOCK, HOLDLOCK) WHERE PrincipalId = @PrincipalId AND Role = @Role)
BEGIN
    COMMIT;
    SELECT N'Already' AS Outcome;
    RETURN;
END;
INSERT cfg.AccessCarriedOver (PrincipalId, Role) VALUES (@PrincipalId, @Role);
DECLARE @curRole nvarchar(16), @curScope nvarchar(max), @curName nvarchar(256);
SELECT @curRole = Role, @curScope = ScopeJson, @curName = DisplayName FROM cfg.AccessAssignment WITH (UPDLOCK, HOLDLOCK) WHERE PrincipalId = @PrincipalId;
DECLARE @want int = CASE @Role WHEN N'Reader' THEN 1 WHEN N'Delegated' THEN 2 WHEN N'Admin' THEN 3 WHEN N'SuperAdmin' THEN 4 ELSE 0 END;
DECLARE @have int = CASE @curRole WHEN N'Reader' THEN 1 WHEN N'Delegated' THEN 2 WHEN N'Admin' THEN 3 WHEN N'SuperAdmin' THEN 4 ELSE 0 END;
IF @MarkOnly = 1 OR @have >= @want OR @want = 0
BEGIN
    COMMIT;
    SELECT N'Marked' AS Outcome;
    RETURN;
END;
DECLARE @hasMail bit = CASE WHEN COL_LENGTH(N'cfg.AccessAssignment', N'AccountMail') IS NULL THEN 0 ELSE 1 END;
IF @curRole IS NULL
BEGIN
    IF @hasMail = 1
        EXEC sp_executesql N'INSERT cfg.AccessAssignment (PrincipalId, PrincipalType, DisplayName, Role, ScopeJson, UpdatedBy, AccountMail) VALUES (@PrincipalId, @PrincipalType, @DisplayName, @Role, NULL, @By, @AccountMail);',
            N'@PrincipalId nvarchar(64), @PrincipalType nvarchar(8), @DisplayName nvarchar(256), @Role nvarchar(16), @By nvarchar(256), @AccountMail nvarchar(320)',
            @PrincipalId = @PrincipalId, @PrincipalType = @PrincipalType, @DisplayName = @DisplayName, @Role = @Role, @By = @By, @AccountMail = @AccountMail;
    ELSE
        INSERT cfg.AccessAssignment (PrincipalId, PrincipalType, DisplayName, Role, ScopeJson, UpdatedBy) VALUES (@PrincipalId, @PrincipalType, @DisplayName, @Role, NULL, @By);
END
ELSE
    UPDATE cfg.AccessAssignment SET Role = @Role, ScopeJson = NULL, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By WHERE PrincipalId = @PrincipalId;
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (LEFT(N'access/' + @PrincipalId, 128), N'access', N'access', N'Set',
        CASE WHEN @curRole IS NULL THEN NULL ELSE @curRole + COALESCE(N' ' + @curScope, N'') END,
        @Role + N' -- ' + COALESCE(@curName, @DisplayName), @By, LEFT(@Reason, 400));
COMMIT;
SELECT N'Saved' AS Outcome;
""";

    public const string MissingTableMessage = "this database has no cfg.AccessAssignment table yet -- roles can be assigned here after the Pro settings schema is updated (until then everyone has exactly their Entra app role)";
    public const string LastSuperAdminMessage = "SecurityInsight always keeps at least one SuperAdmin -- make someone else SuperAdmin first";

    private readonly ISqlExecutor _sql;
    private readonly IMemoryCache _cache;
    public SqlAccessStore(ISqlExecutor sql, IMemoryCache cache) { _sql = sql; _cache = cache; }

    public static AccessAssignment? Map(SqlRow r)
    {
        var id = r.Str("PrincipalId"); var role = AccessClaims.ParseRole(r.Str("Role"));
        if (id is null || role is null) return null;
        var type = string.Equals(r.Str("PrincipalType"), AccessAssignment.Group, StringComparison.OrdinalIgnoreCase) ? AccessAssignment.Group : AccessAssignment.User;
        return new AccessAssignment(id, type, r.Str("DisplayName") ?? id, role.Value, AccessScope.Parse(r.Str("ScopeJson")), r.Date("UpdatedAt"), r.Str("UpdatedBy"), r.Long("Version") ?? 0,
            r.Str("AccountMail"), r.Str("ForwardTo"));
    }

    public async Task<IReadOnlyList<AccessAssignment>> ListAsync(CancellationToken ct)
    {
        if (_cache.TryGetValue(CacheKey, out IReadOnlyList<AccessAssignment>? hit) && hit is not null) return hit;
        var rows = await _sql.QueryAsync(ListSql, new Dictionary<string, object?>(), ct);
        IReadOnlyList<AccessAssignment> list = rows.Select(Map).Where(a => a is not null).Select(a => a!).ToList();
        _cache.Set(CacheKey, list, CacheFor);
        return list;
    }

    public async Task<IReadOnlySet<string>> CarriedAsync(CancellationToken ct)
    {
        if (_cache.TryGetValue(CarriedCacheKey, out IReadOnlySet<string>? hit) && hit is not null) return hit;
        var rows = await _sql.QueryAsync(CarriedSql, new Dictionary<string, object?>(), ct);
        IReadOnlySet<string> set = rows.Select(r => (r.Str("PrincipalId") ?? "").Trim().ToLowerInvariant() + "|" + (r.Str("Role") ?? "").Trim())
            .Where(k => !k.StartsWith('|')).ToHashSet(StringComparer.OrdinalIgnoreCase);
        _cache.Set(CarriedCacheKey, set, CacheFor);
        return set;
    }

    public static string CarriedKey(string principalId, SiRole role) => principalId.Trim().ToLowerInvariant() + "|" + AccessClaims.Label(role);

    public async Task<WriteResult> CarryOverAsync(CarryOver c, CancellationToken ct)
    {
        if (!ObjectId().IsMatch(c.PrincipalId ?? "")) return new WriteResult(WriteStatus.Refused, "no object id");
        if (RoleDefinitions.RankOf(c.Role) == 0) return new WriteResult(WriteStatus.Refused, "only a role on the ladder is carried over");
        // a database without the carry-over table yet: asked again only every few minutes, not on every request
        if (_cache.TryGetValue(CarryMissingKey, out bool _)) return new WriteResult(WriteStatus.Refused, MissingTableMessage);
        var name = (c.DisplayName ?? "").Trim();
        var rows = await _sql.QueryAsync(CarryOverSql, new Dictionary<string, object?>
        {
            ["PrincipalId"] = c.PrincipalId.Trim().ToLowerInvariant(), ["PrincipalType"] = c.PrincipalType == AccessAssignment.Group ? AccessAssignment.Group : AccessAssignment.User,
            ["DisplayName"] = name.Length is > 0 and <= 256 ? name : c.PrincipalId, ["AccountMail"] = MailForward.IsAddress(c.AccountMail) || (c.AccountMail ?? "").Contains('@') ? Trim320(c.AccountMail!.Trim()) : null,
            ["Role"] = AccessClaims.Label(c.Role), ["MarkOnly"] = c.MarkOnly, ["By"] = CarryOverBy, ["Reason"] = CarryOverReason,
        }, ct);
        var outcome = rows.Count > 0 ? rows[0].Str("Outcome") : null;
        if (outcome == "Missing") { _cache.Set(CarryMissingKey, true, TimeSpan.FromMinutes(5)); return new WriteResult(WriteStatus.Refused, MissingTableMessage); }
        _cache.Remove(CacheKey); _cache.Remove(CarriedCacheKey);
        return outcome switch
        {
            "Saved" => new WriteResult(WriteStatus.Saved, $"{name} carried over from Entra as {AccessClaims.Label(c.Role)}"),
            "Marked" or "Already" => new WriteResult(WriteStatus.Saved, "already in SecurityInsight"),
            _ => throw new InvalidOperationException("the carry-over returned no outcome"),
        };
    }

    public async Task<bool> TableExistsAsync(CancellationToken ct)
    {
        var rows = await _sql.QueryAsync(ExistsSql, new Dictionary<string, object?>(), ct);
        return rows.Count > 0 && rows[0].Long("HasTable") == 1;
    }

    /// Why an assignment cannot be stored (empty = it can). Sends nothing.
    public static IReadOnlyList<string> Validate(AccessAssignment a, string reason)
    {
        var why = new List<string>();
        if (!ObjectId().IsMatch(a.PrincipalId ?? "")) why.Add("the object id must be the Entra object id of the user or group (a GUID)");
        if (a.PrincipalType is not (AccessAssignment.User or AccessAssignment.Group)) why.Add("the identity is a User or a Group");
        var name = a.DisplayName?.Trim() ?? "";
        if (name.Length is < 1 or > 256 || name.Any(char.IsControl)) why.Add("give the name the identity is shown with (1 to 256 characters)");
        if (RoleDefinitions.Find(a.Role) is not { Rank: > 0 }) why.Add($"the role is {string.Join(", ", RoleDefinitions.Ladder.Select(d => d.Name))} (an advisor is added on the department's page)");
        if (AccessClaims.IsScopeBound(a.Role)) why.AddRange(a.Scope.Validate());
        else if (!a.Scope.IsEmpty) why.Add("only a Delegated assignment has a scope (the other roles apply everywhere)");
        if (a.ForwardTo is not null)
        {
            if (a.PrincipalType == AccessAssignment.Group) why.Add("a group has no mail forward -- set it on the person");
            else if (!MailForward.IsAddress(a.ForwardTo)) why.Add("the mail forward is not a mail address");
        }
        if ((reason?.Trim().Length ?? 0) < 3) why.Add("give a reason (at least 3 characters) -- it is what the audit shows");
        return why;
    }

    public async Task<WriteResult> WriteAsync(AccessAssignment a, long? expectedVersion, string by, string reason, CancellationToken ct)
    {
        var why = Validate(a, reason);
        if (why.Count > 0) return new WriteResult(WriteStatus.Refused, string.Join("; ", why));
        if (string.IsNullOrWhiteSpace(by)) return new WriteResult(WriteStatus.Refused, "the signed-in user has no name to record");
        var rows = await _sql.QueryAsync(WriteSql, new Dictionary<string, object?>
        {
            ["PrincipalId"] = a.PrincipalId.Trim().ToLowerInvariant(), ["PrincipalType"] = a.PrincipalType, ["DisplayName"] = a.DisplayName.Trim(),
            ["Role"] = AccessClaims.Label(a.Role), ["ScopeJson"] = AccessClaims.IsScopeBound(a.Role) ? a.Scope.ToJson() : null,
            ["AccountMail"] = string.IsNullOrWhiteSpace(a.AccountMail) ? null : Trim320(a.AccountMail.Trim()),
            ["ForwardTo"] = a.ForwardTo is null ? null : a.ForwardTo.Trim().ToLowerInvariant(),
            ["Expected"] = expectedVersion, ["By"] = Trim256(by), ["Reason"] = reason.Trim(),
        }, ct);
        _cache.Remove(CacheKey); _cache.Remove(CarriedCacheKey);
        return Outcome(rows, $"{a.DisplayName} is {AccessClaims.Label(a.Role)}" + (AccessClaims.IsScopeBound(a.Role) ? $" for {a.Scope.Describe()}" : "")
            + (a.ForwardTo is null ? "" : $"; SecurityInsight mail to them goes to {a.ForwardTo.Trim().ToLowerInvariant()}"));
    }

    public async Task<WriteResult> RemoveAsync(string principalId, long expectedVersion, string by, string reason, CancellationToken ct)
    {
        if (!ObjectId().IsMatch(principalId ?? "")) return new WriteResult(WriteStatus.Refused, "no object id");
        if ((reason?.Trim().Length ?? 0) < 3) return new WriteResult(WriteStatus.Refused, "give a reason (at least 3 characters)");
        var rows = await _sql.QueryAsync(RemoveSql, new Dictionary<string, object?>
        {
            ["PrincipalId"] = principalId!.Trim().ToLowerInvariant(), ["Expected"] = expectedVersion, ["By"] = Trim256(by), ["Reason"] = reason!.Trim(),
        }, ct);
        _cache.Remove(CacheKey); _cache.Remove(CarriedCacheKey);
        return Outcome(rows, "removed -- they have no access to SecurityInsight any more");
    }

    private static WriteResult Outcome(IReadOnlyList<SqlRow> rows, string saved) => (rows.Count > 0 ? rows[0].Str("Outcome") : null) switch
    {
        "Saved" => new WriteResult(WriteStatus.Saved, saved),
        "Stale" => new WriteResult(WriteStatus.Stale, "the assignment changed since you opened the page -- nothing was written; open it again"),
        "Missing" => new WriteResult(WriteStatus.Refused, MissingTableMessage),
        "LastSuperAdmin" => new WriteResult(WriteStatus.Refused, LastSuperAdminMessage),
        _ => throw new InvalidOperationException("the access write returned no outcome"),
    };

    private static string Trim256(string s) => s.Length > 256 ? s[..256] : s;
    private static string Trim320(string s) => s.Length > 320 ? s[..320] : s;
}
