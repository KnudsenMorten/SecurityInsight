using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;
using SI.Management.Web.Data;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Departments;

/// The people roles of a department (#254, #335). Technical owners fix things; business owners are accountable and receive
/// the monthly report; TECHNICAL approvers approve technical changes (a fix planned into the maintenance window); BUSINESS
/// approvers approve accepting a risk (an exemption request raised from the department's findings); delegates work the
/// findings; advisors are trusted outside consultants (#258).
public static class DepartmentRoles
{
    public const string TechnicalOwner = "technical-owner";
    public const string BusinessOwner = "business-owner";
    public const string TechnicalApprover = "technical-approver";
    public const string BusinessApprover = "business-approver";
    public const string Delegate = "delegate";
    public const string Advisor = "advisor";
    /// The single approver role before #335. sql\si-pro-settings.sql moves every such row to <see cref="BusinessApprover"/>;
    /// until it has run, a row still carrying it is READ as a business approver (<see cref="Normalize"/>), never refused.
    public const string LegacyApprover = "approver";
    public static readonly IReadOnlyList<string> All = [TechnicalOwner, BusinessOwner, TechnicalApprover, BusinessApprover, Delegate, Advisor];

    public static string Normalize(string? role) => string.Equals(role, LegacyApprover, StringComparison.OrdinalIgnoreCase) ? BusinessApprover : role ?? "";

    public static string Label(string role) => Normalize(role) switch
    {
        TechnicalOwner => "Technical owner",
        BusinessOwner => "Business owner",
        TechnicalApprover => "Technical approver",
        BusinessApprover => "Business approver",
        Delegate => "Delegate",
        Advisor => "Advisor",
        _ => role,
    };

    public static string Purpose(string role) => Normalize(role) switch
    {
        TechnicalOwner => "fixes things; receives the operational reviews",
        BusinessOwner => "accountable; receives the monthly status report",
        TechnicalApprover => "approves planning a fix into the maintenance window",
        BusinessApprover => "approves accepting a risk raised from the department",
        Delegate => "works on the department's findings",
        Advisor => "a trusted outside consultant or company advising the owners",
        _ => "",
    };
}

/// What a people-table row may name: an e-mail address or an Entra object id (#335).
public static partial class DepartmentPeople
{
    [GeneratedRegex(@"^[^@\s;,<>""]{1,64}@[^@\s;,<>""]{1,190}\.[A-Za-z]{2,}$", RegexOptions.CultureInvariant)] private static partial Regex MailPattern();
    [GeneratedRegex(@"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", RegexOptions.CultureInvariant)] private static partial Regex GuidPattern();

    public static bool IsMail(string s) => MailPattern().IsMatch(s);
    public static bool IsObjectId(string s) => GuidPattern().IsMatch(s);
}

public sealed record DepartmentRow(int DepartmentId, string Name, string? Mail, string? Description, string? MatchValues, string? MaintenanceWindowsJson,
    DateTime? UpdatedAt, string? UpdatedBy, DateTime? RetiredAt)
{
    public bool Retired => RetiredAt is not null;
    public IReadOnlyList<string> MatchList => (MatchValues ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
}

public sealed record DepartmentMemberRow(int MemberId, int DepartmentId, string Role, string? ObjectId, string PrincipalType, string DisplayName, string? Mail,
    string? Company, bool IsExternal, DateTime? AddedAt, string? AddedBy);

public sealed record DepartmentInput(int? DepartmentId, string Name, string? Mail, string? Description, string? MatchValues, string? MaintenanceWindowsJson);

public sealed record MemberInput(int DepartmentId, string Role, string? ObjectId, string PrincipalType, string DisplayName, string? Mail, string? Company, bool IsExternal);

public sealed record RuleRow(int RuleId, string Kind, string Pattern, int DepartmentId, string DepartmentName, int SortOrder, bool Enabled, string? Note, DateTime? UpdatedAt, string? UpdatedBy);

public sealed record RuleInput(string Kind, string Pattern, int DepartmentId, int SortOrder, string? Note);

public sealed record OverrideRow(long OverrideId, string Scope, string? AssetKey, string? RecommendationKey, int DepartmentId, string DepartmentName,
    string Reason, DateTime? CreatedAt, string CreatedBy);

/// <summary>
/// THE one class that knows the shape of cfg.Department, cfg.DepartmentMember, cfg.ResponsibilityRule and
/// cfg.ResponsibilityOverride (si-pro-settings.sql, #254). Every write is ONE transaction with its cfg.ChangeLog row:
/// Name 'department/&lt;id&gt;' (Scope 'department', Kind 'department') for a department and its people;
/// 'responsibility-rule/&lt;id&gt;' and 'responsibility-override/&lt;id&gt;' (Scope 'responsibility', Kind 'responsibility')
/// for the policy. Action 'Set' = created or changed, 'Reset' = retired, removed or revoked. A department is never
/// removed (findings already point at it); an override is never removed (revoking stamps RevokedAt). The data sync picks
/// every change up on its next run.
/// </summary>
public sealed partial class DepartmentRepository
{
    public const int MaxBulk = 5_000;

    [GeneratedRegex(@"^[\p{L}\p{N}][\p{L}\p{N} &._()/+'\-]{0,127}$", RegexOptions.CultureInvariant)] private static partial Regex NamePattern();
    [GeneratedRegex(@"^[^@\s;,<>""]{1,64}@[^@\s;,<>""]{1,190}\.[A-Za-z]{2,}$", RegexOptions.CultureInvariant)] private static partial Regex MailPattern();
    [GeneratedRegex(@"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", RegexOptions.CultureInvariant)] private static partial Regex GuidPattern();
    [GeneratedRegex(@"^[A-Za-z0-9._:\-]{1,256}$", RegexOptions.CultureInvariant)] private static partial Regex RecommendationPattern();

    public const string ExistsSql = "SELECT CASE WHEN OBJECT_ID(N'cfg.Department') IS NULL OR OBJECT_ID(N'cfg.ResponsibilityOverride') IS NULL THEN 0 ELSE 1 END AS HasTable;";

    public const string ListSql = """
SELECT d.DepartmentId, d.Name, d.Mail, d.Description, d.MatchValues, d.MaintenanceWindowsJson, d.UpdatedAt, d.UpdatedBy, d.RetiredAt
FROM cfg.Department AS d
WHERE (@IncludeRetired = 1 OR d.RetiredAt IS NULL)
ORDER BY CASE WHEN d.RetiredAt IS NULL THEN 0 ELSE 1 END, d.Name;
""";

    public const string MembersSql = """
SELECT m.MemberId, m.DepartmentId, m.Role, m.ObjectId, m.PrincipalType, m.DisplayName, m.Mail, m.Company, m.IsExternal, m.AddedAt, m.AddedBy
FROM cfg.DepartmentMember AS m
WHERE (@DepartmentId IS NULL OR m.DepartmentId = @DepartmentId)
ORDER BY m.DepartmentId, m.Role, m.DisplayName;
""";

    public const string CreateSql = """
SET XACT_ABORT ON;
BEGIN TRAN;
IF EXISTS (SELECT 1 FROM cfg.Department WITH (UPDLOCK, HOLDLOCK) WHERE Name = @Name)
BEGIN
    COMMIT;
    SELECT N'Exists' AS Outcome, CAST(NULL AS int) AS DepartmentId;
    RETURN;
END;
DECLARE @ids TABLE (DepartmentId int);
INSERT cfg.Department (Name, Mail, Description, MatchValues, MaintenanceWindowsJson, CreatedBy, UpdatedBy)
OUTPUT inserted.DepartmentId INTO @ids
VALUES (@Name, @Mail, @Description, @MatchValues, @Windows, @By, @By);
DECLARE @id int = (SELECT TOP (1) DepartmentId FROM @ids);
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (LEFT(CONCAT(N'department/', @id), 128), N'department', N'department', N'Set', NULL, @Body, @By, N'department created');
-- #335: the people typed on the New department form, in the SAME transaction (a JSON array; '[]' = none) -- one
-- change-log row per person, as adding them one by one would write
DECLARE @p TABLE (Role nvarchar(24) NOT NULL, ObjectId nvarchar(64) NULL, PrincipalType nvarchar(8) NOT NULL, DisplayName nvarchar(256) NOT NULL,
                  Mail nvarchar(256) NULL, Company nvarchar(256) NULL, IsExternal bit NOT NULL);
INSERT @p (Role, ObjectId, PrincipalType, DisplayName, Mail, Company, IsExternal)
SELECT j.Role, j.ObjectId, j.PrincipalType, j.DisplayName, j.Mail, j.Company, ISNULL(j.IsExternal, 0)
FROM OPENJSON(@People) WITH (Role nvarchar(24) '$.Role', ObjectId nvarchar(64) '$.ObjectId', PrincipalType nvarchar(8) '$.PrincipalType',
                             DisplayName nvarchar(256) '$.DisplayName', Mail nvarchar(256) '$.Mail', Company nvarchar(256) '$.Company', IsExternal bit '$.IsExternal') AS j;
INSERT cfg.DepartmentMember (DepartmentId, Role, ObjectId, PrincipalType, DisplayName, Mail, Company, IsExternal, AddedBy)
SELECT @id, p.Role, p.ObjectId, p.PrincipalType, p.DisplayName, p.Mail, p.Company, p.IsExternal, @By FROM @p AS p;
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
SELECT LEFT(CONCAT(N'department/', @id), 128), N'department', N'department', N'Set', NULL,
       (SELECT p.Role, p.ObjectId, p.PrincipalType, p.DisplayName, p.Mail, p.Company, p.IsExternal FOR JSON PATH, WITHOUT_ARRAY_WRAPPER), @By, LEFT(CONCAT(N'person added: ', p.Role), 400)
FROM @p AS p;
DECLARE @n int = (SELECT COUNT(*) FROM @p);
COMMIT;
SELECT N'Saved' AS Outcome, @id AS DepartmentId, @n AS People;
""";

    public const string UpdateSql = """
SET XACT_ABORT ON;
BEGIN TRAN;
DECLARE @old nvarchar(max) = (SELECT TOP (1) (SELECT d.Name, d.Mail, d.Description, d.MatchValues, d.MaintenanceWindowsJson FOR JSON PATH, WITHOUT_ARRAY_WRAPPER)
                              FROM cfg.Department AS d WITH (UPDLOCK, HOLDLOCK) WHERE d.DepartmentId = @DepartmentId AND d.RetiredAt IS NULL);
IF @old IS NULL BEGIN COMMIT; SELECT N'Gone' AS Outcome, @DepartmentId AS DepartmentId; RETURN; END;
IF EXISTS (SELECT 1 FROM cfg.Department WHERE Name = @Name AND DepartmentId <> @DepartmentId) BEGIN COMMIT; SELECT N'Exists' AS Outcome, @DepartmentId AS DepartmentId; RETURN; END;
UPDATE cfg.Department SET Name = @Name, Mail = @Mail, Description = @Description, MatchValues = @MatchValues, MaintenanceWindowsJson = @Windows,
       UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By
WHERE DepartmentId = @DepartmentId;
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (LEFT(CONCAT(N'department/', @DepartmentId), 128), N'department', N'department', N'Set', @old, @Body, @By, N'department changed');
COMMIT;
SELECT N'Saved' AS Outcome, @DepartmentId AS DepartmentId;
""";

    public const string RetireSql = """
SET XACT_ABORT ON;
BEGIN TRAN;
DECLARE @name nvarchar(128) = (SELECT TOP (1) Name FROM cfg.Department WITH (UPDLOCK, HOLDLOCK) WHERE DepartmentId = @DepartmentId AND RetiredAt IS NULL);
IF @name IS NULL BEGIN COMMIT; SELECT N'Gone' AS Outcome; RETURN; END;
UPDATE cfg.Department SET RetiredAt = SYSUTCDATETIME(), RetiredBy = @By, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By WHERE DepartmentId = @DepartmentId;
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (LEFT(CONCAT(N'department/', @DepartmentId), 128), N'department', N'department', N'Reset', @name, NULL, @By, LEFT(@Reason, 400));
COMMIT;
SELECT N'Saved' AS Outcome;
""";

    public const string AddMemberSql = """
SET XACT_ABORT ON;
BEGIN TRAN;
IF NOT EXISTS (SELECT 1 FROM cfg.Department WHERE DepartmentId = @DepartmentId AND RetiredAt IS NULL) BEGIN COMMIT; SELECT N'Gone' AS Outcome; RETURN; END;
IF EXISTS (SELECT 1 FROM cfg.DepartmentMember WITH (UPDLOCK, HOLDLOCK)
           WHERE DepartmentId = @DepartmentId AND Role = @Role
             AND ((@ObjectId IS NOT NULL AND ObjectId = @ObjectId) OR (@ObjectId IS NULL AND ObjectId IS NULL AND Mail = @Mail)))
BEGIN COMMIT; SELECT N'Exists' AS Outcome; RETURN; END;
INSERT cfg.DepartmentMember (DepartmentId, Role, ObjectId, PrincipalType, DisplayName, Mail, Company, IsExternal, AddedBy)
VALUES (@DepartmentId, @Role, @ObjectId, @PrincipalType, @DisplayName, @Mail, @Company, @IsExternal, @By);
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (LEFT(CONCAT(N'department/', @DepartmentId), 128), N'department', N'department', N'Set', NULL, @Body, @By, LEFT(CONCAT(N'person added: ', @Role), 400));
COMMIT;
SELECT N'Saved' AS Outcome;
""";

    /// <summary>
    /// #335: the department's PEOPLE TABLE saved in one go -- @People (a JSON array) is the whole wanted list. A person
    /// (role + object id, or role + mail for someone without one) no longer on it is removed; one not yet there is added;
    /// a role change is the old row removed and the new one added. One transaction, one change-log row PER CHANGE.
    /// Advisors kept on their own panel (cfg.DepartmentAdvisor) are not touched.
    /// </summary>
    public const string SetPeopleSql = """
SET XACT_ABORT ON;
BEGIN TRAN;
IF NOT EXISTS (SELECT 1 FROM cfg.Department WITH (UPDLOCK, HOLDLOCK) WHERE DepartmentId = @DepartmentId AND RetiredAt IS NULL)
BEGIN COMMIT; SELECT N'Gone' AS Outcome, 0 AS Added, 0 AS Removed; RETURN; END;
DECLARE @p TABLE (Role nvarchar(24) NOT NULL, ObjectId nvarchar(64) NULL, PrincipalType nvarchar(8) NOT NULL, DisplayName nvarchar(256) NOT NULL,
                  Mail nvarchar(256) NULL, Company nvarchar(256) NULL, IsExternal bit NOT NULL);
INSERT @p (Role, ObjectId, PrincipalType, DisplayName, Mail, Company, IsExternal)
SELECT j.Role, j.ObjectId, j.PrincipalType, j.DisplayName, j.Mail, j.Company, ISNULL(j.IsExternal, 0)
FROM OPENJSON(@People) WITH (Role nvarchar(24) '$.Role', ObjectId nvarchar(64) '$.ObjectId', PrincipalType nvarchar(8) '$.PrincipalType',
                             DisplayName nvarchar(256) '$.DisplayName', Mail nvarchar(256) '$.Mail', Company nvarchar(256) '$.Company', IsExternal bit '$.IsExternal') AS j;
DECLARE @gone TABLE (Role nvarchar(24) NOT NULL, ObjectId nvarchar(64) NULL, PrincipalType nvarchar(8) NOT NULL, DisplayName nvarchar(256) NOT NULL,
                     Mail nvarchar(256) NULL, Company nvarchar(256) NULL, IsExternal bit NOT NULL);
DELETE m
OUTPUT deleted.Role, deleted.ObjectId, deleted.PrincipalType, deleted.DisplayName, deleted.Mail, deleted.Company, deleted.IsExternal INTO @gone
FROM cfg.DepartmentMember AS m WITH (UPDLOCK, HOLDLOCK)
WHERE m.DepartmentId = @DepartmentId
  AND NOT EXISTS (SELECT 1 FROM @p AS p WHERE p.Role = m.Role AND ((p.ObjectId IS NOT NULL AND p.ObjectId = m.ObjectId) OR (p.ObjectId IS NULL AND m.ObjectId IS NULL AND p.Mail = m.Mail)));
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
SELECT LEFT(CONCAT(N'department/', @DepartmentId), 128), N'department', N'department', N'Reset',
       (SELECT g.Role, g.ObjectId, g.PrincipalType, g.DisplayName, g.Mail, g.Company, g.IsExternal FOR JSON PATH, WITHOUT_ARRAY_WRAPPER), NULL, @By, LEFT(CONCAT(N'person removed: ', g.Role), 400)
FROM @gone AS g;
DECLARE @new TABLE (Role nvarchar(24) NOT NULL, ObjectId nvarchar(64) NULL, PrincipalType nvarchar(8) NOT NULL, DisplayName nvarchar(256) NOT NULL,
                    Mail nvarchar(256) NULL, Company nvarchar(256) NULL, IsExternal bit NOT NULL);
INSERT @new SELECT p.* FROM @p AS p
WHERE NOT EXISTS (SELECT 1 FROM cfg.DepartmentMember AS m WHERE m.DepartmentId = @DepartmentId AND m.Role = p.Role
                  AND ((p.ObjectId IS NOT NULL AND p.ObjectId = m.ObjectId) OR (p.ObjectId IS NULL AND m.ObjectId IS NULL AND p.Mail = m.Mail)));
INSERT cfg.DepartmentMember (DepartmentId, Role, ObjectId, PrincipalType, DisplayName, Mail, Company, IsExternal, AddedBy)
SELECT @DepartmentId, n.Role, n.ObjectId, n.PrincipalType, n.DisplayName, n.Mail, n.Company, n.IsExternal, @By FROM @new AS n;
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
SELECT LEFT(CONCAT(N'department/', @DepartmentId), 128), N'department', N'department', N'Set', NULL,
       (SELECT n.Role, n.ObjectId, n.PrincipalType, n.DisplayName, n.Mail, n.Company, n.IsExternal FOR JSON PATH, WITHOUT_ARRAY_WRAPPER), @By, LEFT(CONCAT(N'person added: ', n.Role), 400)
FROM @new AS n;
DECLARE @added int = (SELECT COUNT(*) FROM @new), @removed int = (SELECT COUNT(*) FROM @gone);
COMMIT;
SELECT N'Saved' AS Outcome, @added AS Added, @removed AS Removed;
""";

    public const string RemoveMemberSql = """
SET XACT_ABORT ON;
BEGIN TRAN;
DECLARE @old nvarchar(max) = (SELECT TOP (1) (SELECT m.Role, m.ObjectId, m.PrincipalType, m.DisplayName, m.Mail, m.Company, m.IsExternal FOR JSON PATH, WITHOUT_ARRAY_WRAPPER)
                              FROM cfg.DepartmentMember AS m WITH (UPDLOCK, HOLDLOCK) WHERE m.MemberId = @MemberId AND m.DepartmentId = @DepartmentId);
IF @old IS NULL BEGIN COMMIT; SELECT N'Gone' AS Outcome; RETURN; END;
DELETE FROM cfg.DepartmentMember WHERE MemberId = @MemberId AND DepartmentId = @DepartmentId;
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (LEFT(CONCAT(N'department/', @DepartmentId), 128), N'department', N'department', N'Reset', @old, NULL, @By, N'person removed');
COMMIT;
SELECT N'Saved' AS Outcome;
""";

    public const string RulesSql = """
SELECT r.RuleId, r.Kind, r.Pattern, r.DepartmentId, d.Name AS DepartmentName, r.SortOrder, r.Enabled, r.Note, r.UpdatedAt, r.UpdatedBy
FROM cfg.ResponsibilityRule AS r JOIN cfg.Department AS d ON d.DepartmentId = r.DepartmentId
ORDER BY r.SortOrder, r.RuleId;
""";

    public const string AddRuleSql = """
SET XACT_ABORT ON;
BEGIN TRAN;
IF NOT EXISTS (SELECT 1 FROM cfg.Department WHERE DepartmentId = @DepartmentId AND RetiredAt IS NULL) BEGIN COMMIT; SELECT N'Gone' AS Outcome; RETURN; END;
DECLARE @ids TABLE (RuleId int);
INSERT cfg.ResponsibilityRule (Kind, Pattern, DepartmentId, SortOrder, Note, CreatedBy, UpdatedBy)
OUTPUT inserted.RuleId INTO @ids
VALUES (@Kind, @Pattern, @DepartmentId, @SortOrder, @Note, @By, @By);
DECLARE @id int = (SELECT TOP (1) RuleId FROM @ids);
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (LEFT(CONCAT(N'responsibility-rule/', @id), 128), N'responsibility', N'responsibility', N'Set', NULL, @Body, @By, N'rule added');
COMMIT;
SELECT N'Saved' AS Outcome;
""";

    public const string RemoveRuleSql = """
SET XACT_ABORT ON;
BEGIN TRAN;
DECLARE @old nvarchar(max) = (SELECT TOP (1) (SELECT r.Kind, r.Pattern, r.DepartmentId, r.SortOrder, r.Note FOR JSON PATH, WITHOUT_ARRAY_WRAPPER)
                              FROM cfg.ResponsibilityRule AS r WITH (UPDLOCK, HOLDLOCK) WHERE r.RuleId = @RuleId);
IF @old IS NULL BEGIN COMMIT; SELECT N'Gone' AS Outcome; RETURN; END;
DELETE FROM cfg.ResponsibilityRule WHERE RuleId = @RuleId;
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (LEFT(CONCAT(N'responsibility-rule/', @RuleId), 128), N'responsibility', N'responsibility', N'Reset', @old, NULL, @By, N'rule removed');
COMMIT;
SELECT N'Saved' AS Outcome;
""";

    public const string OverridesSql = """
SELECT TOP (@Top) o.OverrideId, o.Scope, o.AssetKey, o.RecommendationKey, o.DepartmentId, d.Name AS DepartmentName, o.Reason, o.CreatedAt, o.CreatedBy
FROM cfg.ResponsibilityOverride AS o JOIN cfg.Department AS d ON d.DepartmentId = o.DepartmentId
WHERE o.RevokedAt IS NULL AND (@Scope IS NULL OR o.Scope = @Scope)
ORDER BY o.CreatedAt DESC, o.OverrideId DESC;
""";

    /// <summary>
    /// Bulk override: for every key in @Keys (a JSON array), the active override of that scope is REPLACED (revoked, then a
    /// new one) by one for @DepartmentId -- all in one transaction, one change-log row per override. A key already
    /// assigned to the same department is left as it is. Returns the counts.
    /// </summary>
    public const string BulkOverrideSql = """
SET XACT_ABORT ON;
BEGIN TRAN;
IF NOT EXISTS (SELECT 1 FROM cfg.Department WHERE DepartmentId = @DepartmentId AND RetiredAt IS NULL) BEGIN COMMIT; SELECT N'Gone' AS Outcome, 0 AS Created, 0 AS Replaced, 0 AS Unchanged; RETURN; END;
DECLARE @k TABLE (K nvarchar(400) NOT NULL PRIMARY KEY);
INSERT @k SELECT DISTINCT LEFT(j.[value], 400) FROM OPENJSON(@Keys) AS j WHERE j.[value] IS NOT NULL AND j.[value] <> N'';
DECLARE @old TABLE (OverrideId bigint, K nvarchar(400), DepartmentId int);
INSERT @old SELECT o.OverrideId, k.K, o.DepartmentId
FROM cfg.ResponsibilityOverride AS o WITH (UPDLOCK, HOLDLOCK)
JOIN @k AS k ON k.K = CASE WHEN @Scope = N'asset' THEN o.AssetKey ELSE o.RecommendationKey END
WHERE o.Scope = @Scope AND o.RevokedAt IS NULL;
DECLARE @unchanged int = (SELECT COUNT(*) FROM @old WHERE DepartmentId = @DepartmentId);
DELETE k FROM @k AS k WHERE EXISTS (SELECT 1 FROM @old AS o WHERE o.K = k.K AND o.DepartmentId = @DepartmentId);
UPDATE o SET RevokedAt = SYSUTCDATETIME(), RevokedBy = @By
FROM cfg.ResponsibilityOverride AS o JOIN @old AS x ON x.OverrideId = o.OverrideId
WHERE x.DepartmentId <> @DepartmentId;
DECLARE @replaced int = @@ROWCOUNT;
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
SELECT LEFT(CONCAT(N'responsibility-override/', x.OverrideId), 128), N'responsibility', N'responsibility', N'Reset',
       CONCAT(@Scope, N' ', x.K, N' -> department ', x.DepartmentId), NULL, @By, LEFT(CONCAT(N'replaced: ', @Reason), 400)
FROM @old AS x WHERE x.DepartmentId <> @DepartmentId;
DECLARE @new TABLE (OverrideId bigint, K nvarchar(400));
INSERT cfg.ResponsibilityOverride (Scope, AssetKey, RecommendationKey, DepartmentId, Reason, CreatedBy)
OUTPUT inserted.OverrideId, COALESCE(inserted.AssetKey, inserted.RecommendationKey) INTO @new
SELECT @Scope, CASE WHEN @Scope = N'asset' THEN k.K END, CASE WHEN @Scope = N'recommendation' THEN LEFT(k.K, 256) END, @DepartmentId, @Reason, @By
FROM @k AS k;
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
SELECT LEFT(CONCAT(N'responsibility-override/', n.OverrideId), 128), N'responsibility', N'responsibility', N'Set', NULL,
       CONCAT(@Scope, N' ', n.K, N' -> department ', @DepartmentId), @By, LEFT(@Reason, 400)
FROM @new AS n;
DECLARE @created int = (SELECT COUNT(*) FROM @new);
COMMIT;
SELECT N'Saved' AS Outcome, @created AS Created, @replaced AS Replaced, @unchanged AS Unchanged;
""";

    public const string RevokeOverrideSql = """
SET XACT_ABORT ON;
BEGIN TRAN;
DECLARE @old nvarchar(max) = (SELECT TOP (1) CONCAT(Scope, N' ', COALESCE(AssetKey, RecommendationKey), N' -> department ', DepartmentId)
                              FROM cfg.ResponsibilityOverride WITH (UPDLOCK, HOLDLOCK) WHERE OverrideId = @OverrideId AND RevokedAt IS NULL);
IF @old IS NULL BEGIN COMMIT; SELECT N'Gone' AS Outcome; RETURN; END;
UPDATE cfg.ResponsibilityOverride SET RevokedAt = SYSUTCDATETIME(), RevokedBy = @By WHERE OverrideId = @OverrideId AND RevokedAt IS NULL;
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (LEFT(CONCAT(N'responsibility-override/', @OverrideId), 128), N'responsibility', N'responsibility', N'Reset', @old, NULL, @By, LEFT(@Reason, 400));
COMMIT;
SELECT N'Saved' AS Outcome;
""";

    /// The departments an object (the signed-in user, or any group in their token) is a person of, with the role.
    public const string MembershipSql = """
IF OBJECT_ID(N'cfg.DepartmentMember') IS NOT NULL
SELECT DISTINCT m.DepartmentId, m.Role
FROM cfg.DepartmentMember AS m JOIN cfg.Department AS d ON d.DepartmentId = m.DepartmentId AND d.RetiredAt IS NULL
WHERE m.ObjectId IN (SELECT j.[value] FROM OPENJSON(@ObjectIds) AS j);
""";

    /// #335: the department an exemption request was raised from -- the governance log's "accept the risk" entry names it.
    /// Only a request whose entries name exactly ONE active department has one.
    public const string RequestDepartmentSql = """
IF OBJECT_ID(N'cfg.GovernanceEntry') IS NOT NULL
SELECT DISTINCT e.DepartmentId, d.Name
FROM cfg.GovernanceEntry AS e JOIN cfg.Department AS d ON d.DepartmentId = e.DepartmentId AND d.RetiredAt IS NULL
WHERE e.ExemptionRequestId = @RequestId;
""";

    /// What the "check an asset" preview needs of one CI: its name, kind and platform tags (sidata.Asset / sidata.AssetTag).
    public const string AssetFactsSql = $"""
SELECT N'asset' AS Row, a.AssetName AS A, a.AssetKind AS B, a.ResponsibilitySource AS C, d.Name AS D
FROM sidata.Asset AS a LEFT JOIN cfg.Department AS d ON d.DepartmentId = a.DepartmentId
WHERE a.AssetKey = @AssetKey
UNION ALL
SELECT N'tag', t.Source, t.TagName, t.TagValue, NULL FROM sidata.AssetTag AS t WHERE t.AssetKey = @AssetKey
UNION ALL
SELECT DISTINCT N'tag', N'service', N'Service', COALESCE(sm.ServiceName, sm.ServiceKey), NULL
FROM sidata.ServiceMember AS sm
WHERE sm.AssetKey = @AssetKey AND sm.CollectionId = {SI.Management.Core.ProData.PublishedRun.DetailedId};
""";

    private readonly ISqlExecutor _sql;
    public DepartmentRepository(ISqlExecutor sql) => _sql = sql;

    /// The CI's name, kind, platform tags, and the department the data sync last gave it (null when the CI is unknown).
    public async Task<(string? Name, string? Kind, IReadOnlyList<SI.Management.Core.ProData.AssetTagValue> Tags, string? StoredSource, string? StoredDepartment)?> AssetFactsAsync(string assetKey, CancellationToken ct)
    {
        var rows = await _sql.QueryAsync(AssetFactsSql, new Dictionary<string, object?> { ["AssetKey"] = assetKey }, ct);
        var a = rows.FirstOrDefault(r => r.Str("Row") == "asset");
        if (a is null) return null;
        var tags = rows.Where(r => r.Str("Row") == "tag").Select(r => new SI.Management.Core.ProData.AssetTagValue(r.Str("A") ?? "", r.Str("B") ?? "", r.Str("C") ?? "")).ToList();
        return (a.Str("A"), a.Str("B"), tags, a.Str("C"), a.Str("D"));
    }

    // ---- validation (pure) --------------------------------------------------------------------------------------

    public static IReadOnlyList<string> Validate(DepartmentInput d)
    {
        var why = new List<string>();
        if (string.IsNullOrWhiteSpace(d.Name) || !NamePattern().IsMatch(d.Name.Trim())) why.Add("give the department a name (letters, digits, spaces and & . _ ( ) / + ' -, up to 128)");
        if (!string.IsNullOrWhiteSpace(d.Mail) && !MailPattern().IsMatch(d.Mail.Trim())) why.Add($"'{d.Mail}' is not a mail address");
        if ((d.Description?.Length ?? 0) > 400) why.Add("the description is longer than 400 characters");
        var match = (d.MatchValues ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if ((d.MatchValues?.Length ?? 0) > 1000) why.Add("the 'also matches' values are longer than 1000 characters");
        if (match.Any(v => v.Length > 256 || v.Any(char.IsControl))) why.Add("an 'also matches' value is longer than 256 characters or has a control character");
        if (!string.IsNullOrWhiteSpace(d.MaintenanceWindowsJson))
        {
            try { using var _ = JsonDocument.Parse(d.MaintenanceWindowsJson); why.AddRange(SI.Management.Core.ProData.MaintenanceWindows.Parse(d.MaintenanceWindowsJson).Problems); }
            catch (JsonException) { why.Add("the maintenance windows are not valid JSON"); }
        }
        return why;
    }

    public static IReadOnlyList<string> Validate(MemberInput m)
    {
        var why = new List<string>();
        if (!DepartmentRoles.All.Contains(DepartmentRoles.Normalize(m.Role))) why.Add($"'{m.Role}' is not a role ({string.Join(", ", DepartmentRoles.All)})");
        if (m.PrincipalType is not ("user" or "group" or "mail")) why.Add("a person is a user, a group, or a mail address only");
        var oid = string.IsNullOrWhiteSpace(m.ObjectId) ? null : m.ObjectId.Trim();
        var mail = string.IsNullOrWhiteSpace(m.Mail) ? null : m.Mail.Trim();
        if (oid is not null && !GuidPattern().IsMatch(oid)) why.Add($"'{oid}' is not an Entra object id");
        if (m.PrincipalType is "user" or "group" && oid is null) why.Add($"a {m.PrincipalType} needs its Entra object id");
        if (m.PrincipalType == "mail" && oid is not null) why.Add("a person by mail address has no object id");
        if (oid is null && mail is null) why.Add("give the Entra object id or, for someone without one, a mail address");
        if (mail is not null && !MailPattern().IsMatch(mail)) why.Add($"'{mail}' is not a mail address");
        if (string.IsNullOrWhiteSpace(m.DisplayName) || m.DisplayName.Trim().Length > 256 || m.DisplayName.Any(char.IsControl)) why.Add("give a display name (up to 256 characters)");
        if ((m.Company?.Length ?? 0) > 256) why.Add("the company is longer than 256 characters");
        if (m.Role == DepartmentRoles.BusinessOwner && mail is null) why.Add("a business owner needs a mail address -- the monthly report goes there");
        return why;
    }

    public static IReadOnlyList<string> Validate(RuleInput r)
    {
        var why = new List<string>();
        if (!SI.Management.Core.ProData.ResponsibilityResolver.RuleKinds.Contains(r.Kind)) why.Add($"'{r.Kind}' is not a rule kind ({string.Join(", ", SI.Management.Core.ProData.ResponsibilityResolver.RuleKinds)})");
        if (string.IsNullOrWhiteSpace(r.Pattern) || r.Pattern.Trim().Length > 400 || r.Pattern.Any(char.IsControl)) why.Add("give the pattern (up to 400 characters; * and ? are the wildcards)");
        if (r.Kind == "kind" && !SI.Management.Core.ProData.ProDataFilters.AssetKinds.Contains(r.Pattern?.Trim() ?? "")) why.Add($"a kind rule names an asset kind ({string.Join(", ", SI.Management.Core.ProData.ProDataFilters.AssetKinds)})");
        if (r.SortOrder is < 0 or > 100_000) why.Add("the order is a number from 0 to 100000");
        if ((r.Note?.Length ?? 0) > 400) why.Add("the note is longer than 400 characters");
        return why;
    }

    /// The scopes an override is set at: one recommendation on every asset, or one asset.
    public static readonly IReadOnlyList<string> OverrideScopes = ["recommendation", "asset"];

    public static IReadOnlyList<string> ValidateOverride(string scope, IReadOnlyCollection<string> keys, string reason)
    {
        var why = new List<string>();
        if (!OverrideScopes.Contains(scope)) why.Add("an override is set on a recommendation or on an asset");
        if (keys.Count == 0) why.Add("nothing is selected -- pick rows, or apply to every row the filter matches");
        if (keys.Count > MaxBulk) why.Add($"at most {SI.Management.Core.ProData.ScoreFormat.Count(MaxBulk)} overrides at a time -- narrow the filter");
        if (scope == "recommendation" && keys.Any(k => !RecommendationPattern().IsMatch(k))) why.Add("a recommendation key is a configuration id or CVE id (letters, digits, . _ : -)");
        if (scope == "asset" && keys.Any(k => SI.Management.Core.ProData.ProDataFilters.AssetKey(k) is null)) why.Add("an asset key is not valid");
        var t = reason?.Trim() ?? "";
        if (t.Length < 3 || t.Length > 400) why.Add("give a reason (3 to 400 characters) -- it is what the audit shows");
        return why;
    }

    private static string Trim256(string s) => s.Length > 256 ? s[..256] : s;
    private static string? Blank(string? s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();

    private static WriteResult Outcome(IReadOnlyList<SqlRow> rows, string saved, string exists, string gone) => (rows.Count > 0 ? rows[0].Str("Outcome") : null) switch
    {
        "Saved" => new WriteResult(WriteStatus.Saved, saved),
        "Exists" => new WriteResult(WriteStatus.Stale, exists),
        "Gone" => new WriteResult(WriteStatus.Stale, gone),
        _ => throw new InvalidOperationException("the write returned no outcome"),
    };

    // ---- reads ----------------------------------------------------------------------------------------------------

    public async Task<bool> TablesExistAsync(CancellationToken ct)
    {
        var rows = await _sql.QueryAsync(ExistsSql, new Dictionary<string, object?>(), ct);
        return rows.Count > 0 && rows[0].Long("HasTable") == 1;
    }

    public async Task<IReadOnlyList<DepartmentRow>> ListAsync(bool includeRetired, CancellationToken ct) =>
        (await _sql.QueryAsync(ListSql, new Dictionary<string, object?> { ["IncludeRetired"] = includeRetired ? 1 : 0 }, ct)).Select(Department).ToList();

    public async Task<DepartmentRow?> GetAsync(int id, CancellationToken ct) =>
        (await ListAsync(true, ct)).FirstOrDefault(d => d.DepartmentId == id);

    private static DepartmentRow Department(SqlRow r) => new((int)(r.Long("DepartmentId") ?? 0), r.Str("Name") ?? "", r.Str("Mail"), r.Str("Description"), r.Str("MatchValues"),
        r.Str("MaintenanceWindowsJson"), r.Date("UpdatedAt"), r.Str("UpdatedBy"), r.Date("RetiredAt"));

    /// The people, the old 'approver' role read as business approver (#335) -- and such an old row dropped where the same
    /// person already is a business approver of that department (the role split left it, additive; shown once).
    public async Task<IReadOnlyList<DepartmentMemberRow>> MembersAsync(int? departmentId, CancellationToken ct)
    {
        var raw = (await _sql.QueryAsync(MembersSql, new Dictionary<string, object?> { ["DepartmentId"] = departmentId }, ct)).Select(r => (Legacy: string.Equals(r.Str("Role"), DepartmentRoles.LegacyApprover, StringComparison.OrdinalIgnoreCase), Row: new DepartmentMemberRow(
            (int)(r.Long("MemberId") ?? 0), (int)(r.Long("DepartmentId") ?? 0), DepartmentRoles.Normalize(r.Str("Role")), r.Str("ObjectId"), r.Str("PrincipalType") ?? "", r.Str("DisplayName") ?? "",
            r.Str("Mail"), r.Str("Company"), r.TryGetValue("IsExternal", out var x) && x is true or 1 or (long)1, r.Date("AddedAt"), r.Str("AddedBy")))).ToList();
        static bool Same(DepartmentMemberRow a, DepartmentMemberRow b) => a.DepartmentId == b.DepartmentId && a.Role == b.Role
            && (a.ObjectId is not null ? string.Equals(a.ObjectId, b.ObjectId, StringComparison.OrdinalIgnoreCase) : b.ObjectId is null && string.Equals(a.Mail, b.Mail, StringComparison.OrdinalIgnoreCase));
        return raw.Where(m => !m.Legacy || !raw.Any(o => !o.Legacy && Same(o.Row, m.Row))).Select(m => m.Row).ToList();
    }

    public async Task<IReadOnlyList<RuleRow>> RulesAsync(CancellationToken ct) =>
        (await _sql.QueryAsync(RulesSql, new Dictionary<string, object?>(), ct)).Select(r => new RuleRow((int)(r.Long("RuleId") ?? 0), r.Str("Kind") ?? "", r.Str("Pattern") ?? "",
            (int)(r.Long("DepartmentId") ?? 0), r.Str("DepartmentName") ?? "", (int)(r.Long("SortOrder") ?? 0), r.TryGetValue("Enabled", out var e) && e is true or 1 or (long)1,
            r.Str("Note"), r.Date("UpdatedAt"), r.Str("UpdatedBy"))).ToList();

    public async Task<IReadOnlyList<OverrideRow>> OverridesAsync(string? scope, int top, CancellationToken ct) =>
        (await _sql.QueryAsync(OverridesSql, new Dictionary<string, object?> { ["Scope"] = scope, ["Top"] = Math.Clamp(top, 1, 5000) }, ct)).Select(r => new OverrideRow(
            r.Long("OverrideId") ?? 0, r.Str("Scope") ?? "", r.Str("AssetKey"), r.Str("RecommendationKey"), (int)(r.Long("DepartmentId") ?? 0), r.Str("DepartmentName") ?? "",
            r.Str("Reason") ?? "", r.Date("CreatedAt"), r.Str("CreatedBy") ?? "")).ToList();

    /// The departments the given object ids (a user's oid and the groups in their token) are people of.
    public async Task<IReadOnlyList<(int DepartmentId, string Role)>> MembershipAsync(IReadOnlyCollection<string> objectIds, CancellationToken ct)
    {
        var ids = objectIds.Where(o => GuidPattern().IsMatch(o ?? "")).Select(o => o.ToLowerInvariant()).Distinct().Take(500).ToList();
        if (ids.Count == 0) return Array.Empty<(int, string)>();
        var rows = await _sql.QueryAsync(MembershipSql, new Dictionary<string, object?> { ["ObjectIds"] = JsonSerializer.Serialize(ids) }, ct);
        return rows.Select(r => ((int)(r.Long("DepartmentId") ?? 0), DepartmentRoles.Normalize(r.Str("Role")))).Where(x => x.Item1 > 0).ToList();
    }

    public async Task<(int DepartmentId, string Name)?> RequestDepartmentAsync(long requestId, CancellationToken ct)
    {
        var rows = await _sql.QueryAsync(RequestDepartmentSql, new Dictionary<string, object?> { ["RequestId"] = requestId }, ct);
        return rows.Count == 1 && rows[0].Long("DepartmentId") is { } id and > 0 ? ((int)id, rows[0].Str("Name") ?? "") : null;
    }

    // ---- writes ---------------------------------------------------------------------------------------------------

    public Task<(WriteResult Result, int? DepartmentId)> SaveAsync(DepartmentInput d, string by, CancellationToken ct) => SaveAsync(d, Array.Empty<MemberInput>(), by, ct);

    /// Every person normalised and validated (what does not fit is added to <paramref name="why"/>, naming the person and
    /// role), the same person in the same role once -- the table's two unique keys: (role, object id) and, for a person
    /// without one, (role, mail).
    public static List<MemberInput> CleanPeople(IEnumerable<MemberInput> people, List<string> why)
    {
        var clean = new List<MemberInput>();
        foreach (var m in people)
        {
            var n = m with { Role = DepartmentRoles.Normalize(m.Role), ObjectId = Blank(m.ObjectId)?.ToLowerInvariant(), Mail = Blank(m.Mail), DisplayName = (m.DisplayName ?? "").Trim(), Company = Blank(m.Company) };
            var w = Validate(n);
            if (w.Count > 0) { why.Add($"{(n.DisplayName.Length > 0 ? n.DisplayName : n.Mail ?? n.ObjectId)} as {DepartmentRoles.Label(n.Role).ToLowerInvariant()}: {string.Join("; ", w)}"); continue; }
            if (clean.Any(c => c.Role == n.Role && (n.ObjectId is not null ? c.ObjectId == n.ObjectId : c.ObjectId is null && string.Equals(c.Mail, n.Mail, StringComparison.OrdinalIgnoreCase)))) continue;
            clean.Add(n);
        }
        return clean;
    }

    private static string PeopleJson(IEnumerable<MemberInput> people) =>
        JsonSerializer.Serialize(people.Select(m => new { m.Role, m.ObjectId, m.PrincipalType, DisplayName = Trim256(m.DisplayName), m.Mail, m.Company, m.IsExternal }));

    /// <summary>
    /// #335: the people table of a department saved in ONE transaction (<see cref="SetPeopleSql"/>): the list given is
    /// the whole wanted list -- missing people are removed, new ones added, each change with its change-log row. A
    /// person that does not fit refuses the whole save and nothing is written.
    /// </summary>
    public async Task<WriteResult> SetPeopleAsync(int departmentId, IReadOnlyList<MemberInput> people, string by, CancellationToken ct)
    {
        var why = new List<string>();
        var clean = CleanPeople(people, why);
        if (why.Count > 0) return new WriteResult(WriteStatus.Refused, string.Join("; ", why) + " -- nothing was saved");
        if (string.IsNullOrWhiteSpace(by)) return new WriteResult(WriteStatus.Refused, "the signed-in user has no name to record");
        var rows = await _sql.QueryAsync(SetPeopleSql, new Dictionary<string, object?> { ["DepartmentId"] = departmentId, ["People"] = PeopleJson(clean), ["By"] = Trim256(by) }, ct);
        if (rows.Count > 0 && rows[0].Str("Outcome") == "Saved")
        {
            long added = rows[0].Long("Added") ?? 0, removed = rows[0].Long("Removed") ?? 0;
            return new WriteResult(WriteStatus.Saved, added + removed == 0 ? "people saved -- nothing changed"
                : string.Create(CultureInfo.InvariantCulture, $"people saved: {added} added, {removed} removed"));
        }
        return Outcome(rows, "", "", "that department is retired or gone -- nothing was saved");
    }

    /// <summary>
    /// Creates (DepartmentId null) or changes a department. A NEW department is written together with its people (#335:
    /// the New department form's technical owners, business owners, technical and business approvers) in ONE
    /// transaction -- the department and every person, or nothing; people are refused on a change (they have their own
    /// handlers). Every person is validated first; one that does not fit refuses the whole create.
    /// </summary>
    public async Task<(WriteResult Result, int? DepartmentId)> SaveAsync(DepartmentInput d, IReadOnlyList<MemberInput> people, string by, CancellationToken ct)
    {
        var why = Validate(d).ToList();
        if (d.DepartmentId is not null && people.Count > 0) why.Add("people are added on the department's page");
        var clean = CleanPeople(people, why);
        if (why.Count > 0) return (new WriteResult(WriteStatus.Refused, string.Join("; ", why)), null);
        if (string.IsNullOrWhiteSpace(by)) return (new WriteResult(WriteStatus.Refused, "the signed-in user has no name to record"), null);
        var match = string.Join(";", (d.MatchValues ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Distinct(StringComparer.OrdinalIgnoreCase));
        var p = new Dictionary<string, object?>
        {
            ["Name"] = d.Name.Trim(), ["Mail"] = Blank(d.Mail), ["Description"] = Blank(d.Description), ["MatchValues"] = match.Length == 0 ? null : match,
            ["Windows"] = Blank(d.MaintenanceWindowsJson), ["By"] = Trim256(by),
            ["Body"] = JsonSerializer.Serialize(new { Name = d.Name.Trim(), Mail = Blank(d.Mail), Description = Blank(d.Description), MatchValues = match, MaintenanceWindows = Blank(d.MaintenanceWindowsJson) }),
        };
        if (d.DepartmentId is { } id) p["DepartmentId"] = id;
        else p["People"] = PeopleJson(clean);
        var rows = await _sql.QueryAsync(d.DepartmentId is null ? CreateSql : UpdateSql, p, ct);
        var saved = $"department '{d.Name.Trim()}' saved" + (clean.Count > 0 ? string.Create(CultureInfo.InvariantCulture, $" with {clean.Count} {(clean.Count == 1 ? "person" : "people")}") : "");
        var r = Outcome(rows, saved, $"a department named '{d.Name.Trim()}' already exists -- nothing was written", "that department is retired or gone -- nothing was written");
        return (r, rows.Count > 0 ? (int?)rows[0].Long("DepartmentId") : null);
    }

    public async Task<WriteResult> RetireAsync(int id, string reason, string by, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(reason) || reason.Trim().Length < 3) return new WriteResult(WriteStatus.Refused, "give a reason (at least 3 characters)");
        var rows = await _sql.QueryAsync(RetireSql, new Dictionary<string, object?> { ["DepartmentId"] = id, ["By"] = Trim256(by), ["Reason"] = reason.Trim() }, ct);
        return Outcome(rows, "department retired: it takes part in no resolution from the next data sync on; findings already stamped keep their history", "", "that department is already retired");
    }

    public async Task<WriteResult> AddMemberAsync(MemberInput m, string by, CancellationToken ct)
    {
        m = m with { Role = DepartmentRoles.Normalize(m.Role) };
        var why = Validate(m);
        if (why.Count > 0) return new WriteResult(WriteStatus.Refused, string.Join("; ", why));
        var oid = Blank(m.ObjectId)?.ToLowerInvariant();
        var rows = await _sql.QueryAsync(AddMemberSql, new Dictionary<string, object?>
        {
            ["DepartmentId"] = m.DepartmentId, ["Role"] = m.Role, ["ObjectId"] = oid, ["PrincipalType"] = m.PrincipalType, ["DisplayName"] = m.DisplayName.Trim(),
            ["Mail"] = Blank(m.Mail), ["Company"] = Blank(m.Company), ["IsExternal"] = m.IsExternal, ["By"] = Trim256(by),
            ["Body"] = JsonSerializer.Serialize(new { m.Role, ObjectId = oid, m.PrincipalType, DisplayName = m.DisplayName.Trim(), Mail = Blank(m.Mail), Company = Blank(m.Company), m.IsExternal }),
        }, ct);
        return Outcome(rows, $"{m.DisplayName.Trim()} added as {DepartmentRoles.Label(m.Role).ToLowerInvariant()}", $"{m.DisplayName.Trim()} already has that role here", "that department is retired or gone");
    }

    public async Task<WriteResult> RemoveMemberAsync(int departmentId, int memberId, string by, CancellationToken ct)
    {
        var rows = await _sql.QueryAsync(RemoveMemberSql, new Dictionary<string, object?> { ["DepartmentId"] = departmentId, ["MemberId"] = memberId, ["By"] = Trim256(by) }, ct);
        return Outcome(rows, "person removed", "", "that person is not in the department any more");
    }

    public async Task<WriteResult> AddRuleAsync(RuleInput r, string by, CancellationToken ct)
    {
        var why = Validate(r);
        if (why.Count > 0) return new WriteResult(WriteStatus.Refused, string.Join("; ", why));
        var rows = await _sql.QueryAsync(AddRuleSql, new Dictionary<string, object?>
        {
            ["Kind"] = r.Kind, ["Pattern"] = r.Pattern.Trim(), ["DepartmentId"] = r.DepartmentId, ["SortOrder"] = r.SortOrder, ["Note"] = Blank(r.Note), ["By"] = Trim256(by),
            ["Body"] = JsonSerializer.Serialize(new { r.Kind, Pattern = r.Pattern.Trim(), r.DepartmentId, r.SortOrder, Note = Blank(r.Note) }),
        }, ct);
        return Outcome(rows, $"rule added: {r.Kind} {r.Pattern.Trim()} -- applied on the next data sync", "", "that department is retired or gone");
    }

    public async Task<WriteResult> RemoveRuleAsync(int ruleId, string by, CancellationToken ct)
    {
        var rows = await _sql.QueryAsync(RemoveRuleSql, new Dictionary<string, object?> { ["RuleId"] = ruleId, ["By"] = Trim256(by) }, ct);
        return Outcome(rows, "rule removed -- applied on the next data sync", "", "that rule is gone");
    }

    /// Assigns many assets or recommendations to one department at once (the Unassigned triage's bulk assign).
    public async Task<WriteResult> OverrideAsync(string scope, IReadOnlyCollection<string> keys, int departmentId, string reason, string by, CancellationToken ct)
    {
        var clean = keys.Where(k => !string.IsNullOrWhiteSpace(k)).Select(k => k.Trim()).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var why = ValidateOverride(scope, clean, reason);
        if (why.Count > 0) return new WriteResult(WriteStatus.Refused, string.Join("; ", why));
        var rows = await _sql.QueryAsync(BulkOverrideSql, new Dictionary<string, object?>
        {
            ["Scope"] = scope, ["Keys"] = JsonSerializer.Serialize(clean), ["DepartmentId"] = departmentId, ["Reason"] = reason.Trim(), ["By"] = Trim256(by),
        }, ct);
        if (rows.Count > 0 && rows[0].Str("Outcome") == "Saved")
        {
            var created = rows[0].Long("Created") ?? 0; var replaced = rows[0].Long("Replaced") ?? 0; var same = rows[0].Long("Unchanged") ?? 0;
            var what = scope == "asset" ? "asset" : "recommendation";
            return new WriteResult(WriteStatus.Saved, string.Create(CultureInfo.InvariantCulture,
                $"{created} {what} override(s) set ({replaced} replaced an earlier one, {same} already pointed there) -- the findings move on the next data sync"));
        }
        return Outcome(rows, "", "", "that department is retired or gone -- nothing was written");
    }

    public async Task<WriteResult> RevokeOverrideAsync(long overrideId, string reason, string by, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(reason) || reason.Trim().Length < 3) return new WriteResult(WriteStatus.Refused, "give a reason (at least 3 characters)");
        var rows = await _sql.QueryAsync(RevokeOverrideSql, new Dictionary<string, object?> { ["OverrideId"] = overrideId, ["By"] = Trim256(by), ["Reason"] = reason.Trim() }, ct);
        return Outcome(rows, "override revoked -- applied on the next data sync", "", "that override is not active any more");
    }
}
