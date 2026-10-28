using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using SI.Management.Web.Data;

namespace SI.Management.Web.Advisors;

/// <summary>
/// The secrets of a department sign-in (#258), pure. A LINK token is "d1." + 32 random bytes (base64url); only its
/// SHA-256 is stored. A one-time CODE is six random digits; only SHA-256(salt || sign-in id ":" code) is stored, with its
/// own 16-byte salt -- and a code lives ten minutes and takes five tries, so the hash is not worth brute-forcing.
/// </summary>
public static partial class SignInSecrets
{
    public const string Prefix = "d1.";
    [GeneratedRegex(@"^d1\.[A-Za-z0-9_\-]{43}$", RegexOptions.CultureInvariant)] private static partial Regex TokenPattern();
    [GeneratedRegex(@"^[0-9]{6}$", RegexOptions.CultureInvariant)] private static partial Regex CodePattern();

    private static string B64(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static string NewToken() => Prefix + B64(RandomNumberGenerator.GetBytes(32));
    /// A department sign-in token (as opposed to the signed one-page magic link token).
    public static bool IsToken(string? t) => t is not null && TokenPattern().IsMatch(t);
    public static byte[] TokenHash(string token) => SHA256.HashData(Encoding.ASCII.GetBytes(token));

    public static string NewCode() => RandomNumberGenerator.GetInt32(0, 1_000_000).ToString("D6", System.Globalization.CultureInfo.InvariantCulture);
    public static bool IsCode(string? c) => c is not null && CodePattern().IsMatch(c);
    public static byte[] NewSalt() => RandomNumberGenerator.GetBytes(16);
    public static byte[] CodeHash(byte[] salt, long signInId, string code) =>
        SHA256.HashData([.. salt, .. Encoding.UTF8.GetBytes(signInId.ToString(System.Globalization.CultureInfo.InvariantCulture) + ":" + code)]);
    public static bool CodeMatches(byte[] salt, byte[] hash, long signInId, string code) =>
        IsCode(code) && CryptographicOperations.FixedTimeEquals(CodeHash(salt, signInId, code), hash);
}

/// One issued sign-in link -- and, once redeemed, the session it became.
public sealed record SignInRow(long SignInId, int DepartmentId, string PersonKind, int PersonId, string Mail, string Origin, string? TargetPath,
    DateTime IssuedAt, string IssuedBy, DateTime ExpiresAt, DateTime? RedeemedAt, DateTime? SessionExpiresAt, DateTime? OtpConfirmedAt,
    DateTime? RevokedAt, string? RevokedBy, string? PersonName = null)
{
    public string State(DateTime now) =>
        RevokedAt is not null ? "revoked"
        : RedeemedAt is null ? (ExpiresAt <= now ? "expired" : "waiting")
        : SessionExpiresAt is { } s && s > now ? (OtpConfirmedAt is null ? "signed in" : "signed in + code") : "ended";
}

/// A session's row plus what it stands on: is the department active, is the person still listed, and as what.
public sealed record SessionState(SignInRow Row, bool DepartmentActive, bool PersonActive, string PersonRole, string PersonName)
{
    public bool ValidAt(DateTime now) => Row.RedeemedAt is not null && Row.RevokedAt is null && Row.SessionExpiresAt is { } e && e > now && DepartmentActive && PersonActive;
}

public sealed record NewSignIn(int DepartmentId, string PersonKind, int PersonId, string Mail, byte[] TokenHash, string Origin, string? TargetPath,
    DateTime IssuedAt, DateTime ExpiresAt, string IssuedBy, int MaxPerHour);

public sealed record CodeRow(long CodeId, long SignInId, byte[] Salt, byte[] CodeHash, DateTime ExpiresAt, int Attempts);

/// <summary>cfg.DepartmentSignIn + cfg.DepartmentSignInCode (#258). Every statement takes the app's clock (@Now).</summary>
public interface IDepartmentSignInStore
{
    /// Saved (with the id) | Limited (too many links for that person this hour) | Gone (department retired).
    Task<(string Outcome, long? SignInId)> IssueAsync(NewSignIn s, CancellationToken ct);
    /// Fresh (with the row) | Used | Expired | Revoked | PersonGone | Unknown. Atomic: a link is redeemed once.
    Task<(string Outcome, SignInRow? Row)> RedeemAsync(byte[] tokenHash, DateTime now, DateTime sessionExpires, CancellationToken ct);
    Task<SessionState?> SessionAsync(long signInId, CancellationToken ct);
    /// Saved | Gone.
    Task<string> RevokeAsync(long signInId, int departmentId, DateTime now, string by, CancellationToken ct);
    Task<IReadOnlyList<SignInRow>> ListAsync(int departmentId, DateTime now, CancellationToken ct);
    /// Saved | Limited | Gone (the session is not valid). An earlier unused code of the session stops working.
    Task<string> AddCodeAsync(long signInId, byte[] salt, byte[] hash, DateTime now, DateTime expires, int maxPerHour, string by, CancellationToken ct);
    Task<CodeRow?> LatestCodeAsync(long signInId, DateTime now, int maxAttempts, CancellationToken ct);
    /// Confirmed | Wrong (with the tries left) | Spent.
    Task<(string Outcome, int Left)> UseCodeAsync(long codeId, long signInId, bool match, DateTime now, int maxAttempts, string by, CancellationToken ct);
}

/// <summary>
/// THE one class that knows cfg.DepartmentSignIn and cfg.DepartmentSignInCode. Every write is ONE transaction with its
/// cfg.ChangeLog row -- Name 'department-signin/&lt;id&gt;', Scope 'department', Kind 'signin': issued, redeemed, refused
/// (used / expired / revoked / person gone), revoked, code sent, code confirmed, wrong code. No token or code is logged.
/// </summary>
public sealed class SqlDepartmentSignInStore : IDepartmentSignInStore
{

    public const string IssueSql = """
SET XACT_ABORT ON;
BEGIN TRAN;
IF NOT EXISTS (SELECT 1 FROM cfg.Department WHERE DepartmentId = @DepartmentId AND RetiredAt IS NULL) BEGIN COMMIT; SELECT N'Gone' AS Outcome, CAST(NULL AS bigint) AS SignInId; RETURN; END;
IF (SELECT COUNT(*) FROM cfg.DepartmentSignIn WITH (UPDLOCK, HOLDLOCK)
    WHERE PersonKind = @PersonKind AND PersonId = @PersonId AND IssuedAt > DATEADD(hour, -1, @Now)) >= @MaxPerHour
BEGIN COMMIT; SELECT N'Limited' AS Outcome, CAST(NULL AS bigint) AS SignInId; RETURN; END;
DECLARE @ids TABLE (SignInId bigint);
INSERT cfg.DepartmentSignIn (DepartmentId, PersonKind, PersonId, Mail, TokenHash, Origin, TargetPath, IssuedAt, IssuedBy, ExpiresAt)
OUTPUT inserted.SignInId INTO @ids
VALUES (@DepartmentId, @PersonKind, @PersonId, @Mail, @TokenHash, @Origin, @TargetPath, @Now, @By, @ExpiresAt);
DECLARE @id bigint = (SELECT TOP (1) SignInId FROM @ids);
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (LEFT(CONCAT(N'department-signin/', @id), 128), N'department', N'signin', N'Set', NULL, @Body, @By, LEFT(CONCAT(N'sign-in link issued (', @Origin, N')'), 400));
COMMIT;
SELECT N'Saved' AS Outcome, @id AS SignInId;
""";


    public const string RedeemSql = """
SET XACT_ABORT ON;
BEGIN TRAN;
DECLARE @id bigint, @dept int, @kind nvarchar(8), @pid int, @exp datetime2(0), @red datetime2(0), @rev datetime2(0), @mail nvarchar(256);
SELECT @id = SignInId, @dept = DepartmentId, @kind = PersonKind, @pid = PersonId, @exp = ExpiresAt, @red = RedeemedAt, @rev = RevokedAt, @mail = Mail
FROM cfg.DepartmentSignIn WITH (UPDLOCK, HOLDLOCK) WHERE TokenHash = @TokenHash;
IF @id IS NULL BEGIN COMMIT; SELECT N'Unknown' AS Outcome; RETURN; END;
DECLARE @why nvarchar(16) = CASE WHEN @rev IS NOT NULL THEN N'Revoked' WHEN @red IS NOT NULL THEN N'Used' WHEN @exp <= @Now THEN N'Expired' END;
IF @why IS NULL AND NOT EXISTS (SELECT 1 FROM cfg.Department WHERE DepartmentId = @dept AND RetiredAt IS NULL) SET @why = N'PersonGone';
IF @why IS NULL AND @kind = N'advisor' AND NOT EXISTS (SELECT 1 FROM cfg.DepartmentAdvisor WHERE AdvisorId = @pid AND DepartmentId = @dept AND RevokedAt IS NULL) SET @why = N'PersonGone';
IF @why IS NULL AND @kind = N'member' AND NOT EXISTS (SELECT 1 FROM cfg.DepartmentMember WHERE MemberId = @pid AND DepartmentId = @dept) SET @why = N'PersonGone';
IF @why IS NOT NULL
BEGIN
    INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
    VALUES (LEFT(CONCAT(N'department-signin/', @id), 128), N'department', N'signin', N'Set', NULL, NULL, @mail, LEFT(CONCAT(N'sign-in link refused: ', @why), 400));
    COMMIT;
    SELECT @why AS Outcome;
    RETURN;
END;
UPDATE cfg.DepartmentSignIn SET RedeemedAt = @Now, SessionExpiresAt = @SessionExpires WHERE SignInId = @id;
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (LEFT(CONCAT(N'department-signin/', @id), 128), N'department', N'signin', N'Set', NULL, CONCAT(N'session until ', CONVERT(nvarchar(19), @SessionExpires, 126)), @mail, N'sign-in link redeemed');
COMMIT;
SELECT N'Fresh' AS Outcome, s.SignInId, s.DepartmentId, s.PersonKind, s.PersonId, s.Mail, s.Origin, s.TargetPath, s.IssuedAt, s.IssuedBy, s.ExpiresAt, s.RedeemedAt, s.SessionExpiresAt, s.OtpConfirmedAt, s.RevokedAt, s.RevokedBy
FROM cfg.DepartmentSignIn AS s WHERE s.SignInId = @id;
""";

    public const string SessionSql = """
SELECT s.SignInId, s.DepartmentId, s.PersonKind, s.PersonId, s.Mail, s.Origin, s.TargetPath, s.IssuedAt, s.IssuedBy, s.ExpiresAt, s.RedeemedAt, s.SessionExpiresAt, s.OtpConfirmedAt, s.RevokedAt, s.RevokedBy,
       CASE WHEN d.RetiredAt IS NULL THEN 1 ELSE 0 END AS DepartmentActive,
       CASE WHEN s.PersonKind = N'advisor'
            THEN (SELECT COUNT(*) FROM cfg.DepartmentAdvisor AS a WHERE a.AdvisorId = s.PersonId AND a.DepartmentId = s.DepartmentId AND a.RevokedAt IS NULL)
            ELSE (SELECT COUNT(*) FROM cfg.DepartmentMember AS m WHERE m.MemberId = s.PersonId AND m.DepartmentId = s.DepartmentId) END AS PersonActive,
       COALESCE((SELECT TOP (1) m.Role FROM cfg.DepartmentMember AS m WHERE s.PersonKind = N'member' AND m.MemberId = s.PersonId), N'advisor') AS PersonRole,
       COALESCE((SELECT TOP (1) a.DisplayName FROM cfg.DepartmentAdvisor AS a WHERE s.PersonKind = N'advisor' AND a.AdvisorId = s.PersonId),
                (SELECT TOP (1) m.DisplayName FROM cfg.DepartmentMember AS m WHERE s.PersonKind = N'member' AND m.MemberId = s.PersonId), s.Mail) AS PersonName
FROM cfg.DepartmentSignIn AS s JOIN cfg.Department AS d ON d.DepartmentId = s.DepartmentId
WHERE s.SignInId = @SignInId;
""";

    public const string RevokeSql = """
SET XACT_ABORT ON;
BEGIN TRAN;
DECLARE @id bigint = @SignInId;
UPDATE cfg.DepartmentSignIn SET RevokedAt = @Now, RevokedBy = @By WHERE SignInId = @id AND DepartmentId = @DepartmentId AND RevokedAt IS NULL;
IF @@ROWCOUNT = 0 BEGIN COMMIT; SELECT N'Gone' AS Outcome; RETURN; END;
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (LEFT(CONCAT(N'department-signin/', @id), 128), N'department', N'signin', N'Reset', NULL, NULL, @By, N'sign-in link revoked');
COMMIT;
SELECT N'Saved' AS Outcome;
""";

    public const string ListSql = """
SELECT TOP (50) s.SignInId, s.DepartmentId, s.PersonKind, s.PersonId, s.Mail, s.Origin, s.TargetPath, s.IssuedAt, s.IssuedBy, s.ExpiresAt, s.RedeemedAt, s.SessionExpiresAt, s.OtpConfirmedAt, s.RevokedAt, s.RevokedBy,
       COALESCE((SELECT TOP (1) a.DisplayName FROM cfg.DepartmentAdvisor AS a WHERE s.PersonKind = N'advisor' AND a.AdvisorId = s.PersonId),
                (SELECT TOP (1) m.DisplayName FROM cfg.DepartmentMember AS m WHERE s.PersonKind = N'member' AND m.MemberId = s.PersonId), s.Mail) AS PersonName
FROM cfg.DepartmentSignIn AS s
WHERE s.DepartmentId = @DepartmentId AND s.IssuedAt > DATEADD(day, -30, @Now)
ORDER BY s.IssuedAt DESC, s.SignInId DESC;
""";

    public const string AddCodeSql = """
SET XACT_ABORT ON;
BEGIN TRAN;
DECLARE @id bigint = @SignInId;
IF NOT EXISTS (SELECT 1 FROM cfg.DepartmentSignIn WITH (UPDLOCK, HOLDLOCK)
               WHERE SignInId = @id AND RedeemedAt IS NOT NULL AND RevokedAt IS NULL AND SessionExpiresAt > @Now)
BEGIN COMMIT; SELECT N'Gone' AS Outcome; RETURN; END;
IF (SELECT COUNT(*) FROM cfg.DepartmentSignInCode WHERE SignInId = @id AND IssuedAt > DATEADD(hour, -1, @Now)) >= @MaxPerHour
BEGIN COMMIT; SELECT N'Limited' AS Outcome; RETURN; END;
UPDATE cfg.DepartmentSignInCode SET UsedAt = @Now WHERE SignInId = @id AND UsedAt IS NULL;
INSERT cfg.DepartmentSignInCode (SignInId, Salt, CodeHash, IssuedAt, ExpiresAt) VALUES (@id, @Salt, @CodeHash, @Now, @ExpiresAt);
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (LEFT(CONCAT(N'department-signin/', @id), 128), N'department', N'signin', N'Set', NULL, NULL, @By, N'one-time code sent (second check)');
COMMIT;
SELECT N'Saved' AS Outcome;
""";

    public const string LatestCodeSql = """
SELECT TOP (1) c.CodeId, c.SignInId, c.Salt, c.CodeHash, c.ExpiresAt, c.Attempts
FROM cfg.DepartmentSignInCode AS c
WHERE c.SignInId = @SignInId AND c.UsedAt IS NULL AND c.ExpiresAt > @Now AND c.Attempts < @MaxAttempts
ORDER BY c.CodeId DESC;
""";

    public const string UseCodeSql = """
SET XACT_ABORT ON;
BEGIN TRAN;
DECLARE @id bigint = @SignInId;
IF NOT EXISTS (SELECT 1 FROM cfg.DepartmentSignInCode WITH (UPDLOCK, HOLDLOCK)
               WHERE CodeId = @CodeId AND SignInId = @id AND UsedAt IS NULL AND Attempts < @MaxAttempts AND ExpiresAt > @Now)
BEGIN COMMIT; SELECT N'Spent' AS Outcome, 0 AS [Left]; RETURN; END;
IF @Match = 1
BEGIN
    UPDATE cfg.DepartmentSignInCode SET UsedAt = @Now, Attempts = Attempts + 1 WHERE CodeId = @CodeId;
    UPDATE cfg.DepartmentSignIn SET OtpConfirmedAt = @Now WHERE SignInId = @id AND RevokedAt IS NULL;
    INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
    VALUES (LEFT(CONCAT(N'department-signin/', @id), 128), N'department', N'signin', N'Set', NULL, N'second check passed', @By, N'one-time code confirmed');
    COMMIT;
    SELECT N'Confirmed' AS Outcome, 0 AS [Left];
    RETURN;
END;
UPDATE cfg.DepartmentSignInCode SET Attempts = Attempts + 1 WHERE CodeId = @CodeId;
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (LEFT(CONCAT(N'department-signin/', @id), 128), N'department', N'signin', N'Set', NULL, NULL, @By, N'wrong one-time code');
COMMIT;
SELECT N'Wrong' AS Outcome, (SELECT @MaxAttempts - c.Attempts FROM cfg.DepartmentSignInCode AS c WHERE c.CodeId = @CodeId) AS [Left];
""";

    private readonly ISqlExecutor _sql;
    public SqlDepartmentSignInStore(ISqlExecutor sql) => _sql = sql;

    private static string Cut(string s, int n) => s.Length > n ? s[..n] : s;

    public static SignInRow Row(SqlRow r) => new(r.Long("SignInId") ?? 0, (int)(r.Long("DepartmentId") ?? 0), r.Str("PersonKind") ?? "", (int)(r.Long("PersonId") ?? 0),
        r.Str("Mail") ?? "", r.Str("Origin") ?? "", r.Str("TargetPath"), r.Date("IssuedAt") ?? DateTime.MinValue, r.Str("IssuedBy") ?? "", r.Date("ExpiresAt") ?? DateTime.MinValue,
        r.Date("RedeemedAt"), r.Date("SessionExpiresAt"), r.Date("OtpConfirmedAt"), r.Date("RevokedAt"), r.Str("RevokedBy"), r.Str("PersonName"));

    public async Task<(string Outcome, long? SignInId)> IssueAsync(NewSignIn s, CancellationToken ct)
    {
        var rows = await _sql.QueryAsync(IssueSql, new Dictionary<string, object?>
        {
            ["DepartmentId"] = s.DepartmentId, ["PersonKind"] = s.PersonKind, ["PersonId"] = s.PersonId, ["Mail"] = Cut(s.Mail, 256), ["TokenHash"] = s.TokenHash,
            ["Origin"] = s.Origin, ["TargetPath"] = s.TargetPath, ["Now"] = s.IssuedAt, ["ExpiresAt"] = s.ExpiresAt, ["By"] = Cut(s.IssuedBy, 256), ["MaxPerHour"] = s.MaxPerHour,
            ["Body"] = JsonSerializer.Serialize(new { s.DepartmentId, s.PersonKind, s.PersonId, s.Mail, s.Origin, s.TargetPath, ExpiresAt = s.ExpiresAt.ToString("o", System.Globalization.CultureInfo.InvariantCulture) }),
        }, ct);
        return rows.Count == 0 ? ("Gone", null) : (rows[0].Str("Outcome") ?? "Gone", rows[0].Long("SignInId"));
    }

    public async Task<(string Outcome, SignInRow? Row)> RedeemAsync(byte[] tokenHash, DateTime now, DateTime sessionExpires, CancellationToken ct)
    {
        var rows = await _sql.QueryAsync(RedeemSql, new Dictionary<string, object?> { ["TokenHash"] = tokenHash, ["Now"] = now, ["SessionExpires"] = sessionExpires }, ct);
        if (rows.Count == 0) return ("Unknown", null);
        var o = rows[0].Str("Outcome") ?? "Unknown";
        return o == "Fresh" ? (o, Row(rows[0])) : (o, null);
    }

    public async Task<SessionState?> SessionAsync(long signInId, CancellationToken ct)
    {
        var rows = await _sql.QueryAsync(SessionSql, new Dictionary<string, object?> { ["SignInId"] = signInId }, ct);
        if (rows.Count == 0 || rows[0].Long("SignInId") is not { } id || id != signInId) return null;
        var r = rows[0];
        return new SessionState(Row(r), r.Long("DepartmentActive") == 1, (r.Long("PersonActive") ?? 0) > 0, r.Str("PersonRole") ?? "advisor", r.Str("PersonName") ?? r.Str("Mail") ?? "");
    }

    public async Task<string> RevokeAsync(long signInId, int departmentId, DateTime now, string by, CancellationToken ct)
    {
        var rows = await _sql.QueryAsync(RevokeSql, new Dictionary<string, object?> { ["SignInId"] = signInId, ["DepartmentId"] = departmentId, ["Now"] = now, ["By"] = Cut(by, 256) }, ct);
        return rows.Count > 0 ? rows[0].Str("Outcome") ?? "Gone" : "Gone";
    }

    public async Task<IReadOnlyList<SignInRow>> ListAsync(int departmentId, DateTime now, CancellationToken ct) =>
        (await _sql.QueryAsync(ListSql, new Dictionary<string, object?> { ["DepartmentId"] = departmentId, ["Now"] = now }, ct))
        .Where(r => r.Long("SignInId") is > 0).Select(Row).ToList();

    public async Task<string> AddCodeAsync(long signInId, byte[] salt, byte[] hash, DateTime now, DateTime expires, int maxPerHour, string by, CancellationToken ct)
    {
        var rows = await _sql.QueryAsync(AddCodeSql, new Dictionary<string, object?>
        {
            ["SignInId"] = signInId, ["Salt"] = salt, ["CodeHash"] = hash, ["Now"] = now, ["ExpiresAt"] = expires, ["MaxPerHour"] = maxPerHour, ["By"] = Cut(by, 256),
        }, ct);
        return rows.Count > 0 ? rows[0].Str("Outcome") ?? "Gone" : "Gone";
    }

    public async Task<CodeRow?> LatestCodeAsync(long signInId, DateTime now, int maxAttempts, CancellationToken ct)
    {
        var rows = await _sql.QueryAsync(LatestCodeSql, new Dictionary<string, object?> { ["SignInId"] = signInId, ["Now"] = now, ["MaxAttempts"] = maxAttempts }, ct);
        if (rows.Count == 0 || rows[0].Long("CodeId") is not { } id || !rows[0].TryGetValue("Salt", out var salt) || salt is not byte[] s || !rows[0].TryGetValue("CodeHash", out var h) || h is not byte[] hash) return null;
        return new CodeRow(id, signInId, s, hash, rows[0].Date("ExpiresAt") ?? DateTime.MinValue, (int)(rows[0].Long("Attempts") ?? 0));
    }

    public async Task<(string Outcome, int Left)> UseCodeAsync(long codeId, long signInId, bool match, DateTime now, int maxAttempts, string by, CancellationToken ct)
    {
        var rows = await _sql.QueryAsync(UseCodeSql, new Dictionary<string, object?>
        {
            ["CodeId"] = codeId, ["SignInId"] = signInId, ["Match"] = match, ["Now"] = now, ["MaxAttempts"] = maxAttempts, ["By"] = Cut(by, 256),
        }, ct);
        return rows.Count == 0 ? ("Spent", 0) : (rows[0].Str("Outcome") ?? "Spent", (int)(rows[0].Long("Left") ?? 0));
    }
}
