using System.Globalization;
using System.Text.Json;
using SI.Management.Web.Data;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Exemptions;

/// <summary>
/// Everything the governed exemption flow reads and writes (#252). <see cref="SqlExemptionStore"/> is the ONE class that
/// knows the shape of cfg.DomainRole + cfg.CategoryRole (#283), cfg.ExemptionRequest(+Item), the #252 / #283 columns of
/// cfg.Exemption and cfg.ExemptionMail. Every write is one transaction with its cfg.ChangeLog row(s). Nothing is ever
/// deleted: a role is removed by stamping RemovedAt, an exemption is ended by stamping RevokedAt.
/// </summary>
public interface IExemptionStore
{
    /// Whether the database has the #252 and #283 tables and columns (setup adds them; until then the flow says so).
    Task<bool> ReadyAsync(CancellationToken ct);
    /// Every person in every role: domain level (cfg.DomainRole, Category null) and category level (cfg.CategoryRole).
    Task<IReadOnlyList<DomainRoleRow>> RolesAsync(CancellationToken ct);
    /// Adds a person to a node: the domain (category null) or a category inside it (#283, owners only).
    Task<WriteResult> AddRoleAsync(string domain, string? category, string role, string principal, string by, CancellationToken ct);
    Task<WriteResult> RemoveRoleAsync(string domain, string? category, string role, string principal, string by, CancellationToken ct);
    /// #283: each finding's Category (FindingId -> category) from the Pro data, for findings that came without one.
    Task<IReadOnlyDictionary<string, string>> CategoriesAsync(IReadOnlyCollection<string> findingIds, CancellationToken ct);
    /// #283: the Domain -> Category pairs the latest collection carries (what the Security owners page offers) -- 2026-10-19:
    /// as the data sync wrote them for that collection (sidata.DomainCategory), never read from every finding per request.
    Task<IReadOnlyList<(string Domain, string Category)>> CategoryPairsAsync(CancellationToken ct);
    /// Whether the latest collection's pairs are written: true = written (or no collection yet), false = being prepared,
    /// null = the database does not have the tables yet. A store that does not keep them (a fake) answers true.
    Task<bool?> CategoryPairsWrittenAsync(CancellationToken ct) => Task.FromResult<bool?>(true);

    Task<long> CreateRequestAsync(NewRequest request, string by, CancellationToken ct);
    Task<RequestRow?> RequestAsync(long requestId, CancellationToken ct);
    Task<IReadOnlyList<RequestItem>> ItemsAsync(long requestId, CancellationToken ct);
    Task<IReadOnlyList<RequestRow>> RequestsAsync(string? state, int top, CancellationToken ct);
    /// Approves a REQUESTED request: its items become cfg.Exemption rows (approved by <paramref name="by"/>). Stale = it
    /// was not waiting any more. Returns how many exemptions were written (an item an active one covers is linked to it).
    Task<(WriteStatus Status, int Created)> ApproveAsync(long requestId, string by, string? comment, CancellationToken ct);
    Task<WriteStatus> RejectAsync(long requestId, string by, string comment, CancellationToken ct);

    Task<IReadOnlyList<ExemptionInfo>> ExemptionsAsync(int top, CancellationToken ct);
    Task<WriteStatus> ExtendAsync(long exemptionId, DateTime? expiresAt, string by, string reason, CancellationToken ct);
    Task<WriteStatus> KeepAsync(long exemptionId, string by, string reason, CancellationToken ct);
    Task<WriteStatus> EndAsync(long exemptionId, string by, string reason, CancellationToken ct);

    Task QueueMailAsync(QueuedMail mail, string by, CancellationToken ct);
}

public sealed class SqlExemptionStore : IExemptionStore
{
    public const string ReadySql = """
SELECT CASE WHEN OBJECT_ID(N'cfg.DomainRole') IS NOT NULL AND OBJECT_ID(N'cfg.ExemptionRequest') IS NOT NULL
             AND OBJECT_ID(N'cfg.ExemptionRequestItem') IS NOT NULL AND OBJECT_ID(N'cfg.ExemptionMail') IS NOT NULL
             AND COL_LENGTH(N'cfg.Exemption', N'ReviewedAt') IS NOT NULL
             AND OBJECT_ID(N'cfg.CategoryRole') IS NOT NULL AND COL_LENGTH(N'cfg.Exemption', N'Category') IS NOT NULL
             AND COL_LENGTH(N'cfg.ExemptionRequest', N'Category') IS NOT NULL AND COL_LENGTH(N'cfg.ExemptionRequestItem', N'Category') IS NOT NULL
             THEN 1 ELSE 0 END AS Ready;
""";

    /// Both levels in one list: a domain-level row carries Category NULL.
    public const string RolesSql = """
IF OBJECT_ID(N'cfg.DomainRole') IS NOT NULL AND OBJECT_ID(N'cfg.CategoryRole') IS NOT NULL
SELECT Domain, CAST(NULL AS nvarchar(128)) AS Category, Role, Principal, AddedAt, AddedBy FROM cfg.DomainRole WHERE RemovedAt IS NULL
UNION ALL
SELECT Domain, Category, Role, Principal, AddedAt, AddedBy FROM cfg.CategoryRole WHERE RemovedAt IS NULL
ORDER BY Domain, Category, Role, Principal;
ELSE IF OBJECT_ID(N'cfg.DomainRole') IS NOT NULL
SELECT Domain, CAST(NULL AS nvarchar(128)) AS Category, Role, Principal, AddedAt, AddedBy FROM cfg.DomainRole WHERE RemovedAt IS NULL ORDER BY Domain, Role, Principal;
""";

    /// A category-level owner (#283): the same shape as <see cref="AddRoleSql"/> over cfg.CategoryRole.
    public const string AddCategoryRoleSql = """
SET XACT_ABORT ON;
BEGIN TRAN;
IF EXISTS (SELECT 1 FROM cfg.CategoryRole WITH (UPDLOCK, HOLDLOCK) WHERE Domain = @Domain AND Category = @Category AND Role = @Role AND Principal = @Principal AND RemovedAt IS NULL)
BEGIN
    COMMIT;
    SELECT N'Exists' AS Outcome;
    RETURN;
END;
IF EXISTS (SELECT 1 FROM cfg.CategoryRole WHERE Domain = @Domain AND Category = @Category AND Role = @Role AND Principal = @Principal)
    UPDATE cfg.CategoryRole SET RemovedAt = NULL, RemovedBy = NULL, AddedAt = SYSUTCDATETIME(), AddedBy = @By
    WHERE Domain = @Domain AND Category = @Category AND Role = @Role AND Principal = @Principal;
ELSE
    INSERT cfg.CategoryRole (Domain, Category, Role, Principal, AddedBy) VALUES (@Domain, @Category, @Role, @Principal, @By);
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (LEFT(N'domain-role/' + @Domain + N'/' + @Category + N'/' + @Role, 128), N'domain-role', N'domain-role', N'Set', NULL, @Principal, @By, N'added');
COMMIT;
SELECT N'Saved' AS Outcome;
""";

    public const string RemoveCategoryRoleSql = """
SET XACT_ABORT ON;
BEGIN TRAN;
IF NOT EXISTS (SELECT 1 FROM cfg.CategoryRole WITH (UPDLOCK, HOLDLOCK) WHERE Domain = @Domain AND Category = @Category AND Role = @Role AND Principal = @Principal AND RemovedAt IS NULL)
BEGIN
    COMMIT;
    SELECT N'Gone' AS Outcome;
    RETURN;
END;
UPDATE cfg.CategoryRole SET RemovedAt = SYSUTCDATETIME(), RemovedBy = @By WHERE Domain = @Domain AND Category = @Category AND Role = @Role AND Principal = @Principal;
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (LEFT(N'domain-role/' + @Domain + N'/' + @Category + N'/' + @Role, 128), N'domain-role', N'domain-role', N'Reset', @Principal, NULL, @By, N'removed');
COMMIT;
SELECT N'Saved' AS Outcome;
""";

    /// #283: the Category of each named finding, from its Risk Analysis row (DetailJson). Bounded by the request (2,000).
    public const string CategoriesSql = """
IF OBJECT_ID(N'sidata.Finding') IS NOT NULL
SELECT CONVERT(nvarchar(64), f.FindingId) AS FindingId,
       LEFT(CASE WHEN ISJSON(f.DetailJson) = 1 THEN JSON_VALUE(f.DetailJson, '$.Category') END, 128) AS Category
FROM sidata.Finding AS f
WHERE f.FindingId IN (SELECT TRY_CONVERT(bigint, j.[value]) FROM OPENJSON(@Ids) AS j);
""";

    /// <summary>
    /// #283: the Domain -> Category pairs of the published run's collection (the Security owners page offers them) -- as the
    /// data sync wrote them once per collection (sidata.DomainCategory, SI-DataViewContext.ps1 Invoke-SIDataDomainCategory;
    /// 2026-10-19: the per-request form below read the Category of EVERY finding's DetailJson -- 1.1 million JSON documents at
    /// a large customer). The first 500 in name order, as before. A collection without its pairs answers none (the page says
    /// they are being prepared, <see cref="CategoryPairsStateSql"/>).
    /// </summary>
    public const string CategoryPairsSql = $"""
IF OBJECT_ID(N'sidata.DomainCategory') IS NOT NULL AND OBJECT_ID(N'sidata.Collection') IS NOT NULL
BEGIN
    DECLARE @c int = {SI.Management.Core.ProData.PublishedRun.DetailedId};
    SELECT TOP (500) p.Domain, p.Category
    FROM sidata.DomainCategory AS p
    WHERE p.CollectionId = @c
    ORDER BY p.Domain, p.Category;
END;
""";

    /// Whether the published run's collection's pairs are written (Written = 1 also when there is no collection yet); HasSchema
    /// = 0 on a database the update has not reached.
    public const string CategoryPairsStateSql = $"""
IF OBJECT_ID(N'sidata.DomainCategoryState') IS NULL OR OBJECT_ID(N'sidata.Collection') IS NULL
    SELECT CONVERT(bit, 0) AS HasSchema, CONVERT(bit, 0) AS Written;
ELSE
BEGIN
    DECLARE @c int = {SI.Management.Core.ProData.PublishedRun.DetailedId};
    SELECT CONVERT(bit, 1) AS HasSchema,
           CONVERT(bit, CASE WHEN @c IS NULL OR EXISTS (SELECT 1 FROM sidata.DomainCategoryState AS s WHERE s.CollectionId = @c) THEN 1 ELSE 0 END) AS Written;
END;
""";

    /// The same pairs read from every finding per request -- what the page read before 2026-10-19. Kept ONLY as the reference
    /// the equality check and the measurement compare the stored pairs with; nothing reads it.
    public const string CategoryPairsLiveSql = $"""
IF OBJECT_ID(N'sidata.Finding') IS NOT NULL AND OBJECT_ID(N'sidata.Collection') IS NOT NULL
BEGIN
    DECLARE @c int = {SI.Management.Core.ProData.PublishedRun.DetailedId};
    SELECT DISTINCT TOP (500) x.Domain, x.Category
    FROM (SELECT f.SecurityDomain AS Domain, LEFT(CASE WHEN ISJSON(f.DetailJson) = 1 THEN JSON_VALUE(f.DetailJson, '$.Category') END, 128) AS Category
          FROM sidata.Finding AS f WHERE f.CollectionId = @c AND f.SecurityDomain IS NOT NULL) AS x
    WHERE x.Category IS NOT NULL
    ORDER BY x.Domain, x.Category;
END;
""";

    public const string AddRoleSql = """
SET XACT_ABORT ON;
BEGIN TRAN;
IF EXISTS (SELECT 1 FROM cfg.DomainRole WITH (UPDLOCK, HOLDLOCK) WHERE Domain = @Domain AND Role = @Role AND Principal = @Principal AND RemovedAt IS NULL)
BEGIN
    COMMIT;
    SELECT N'Exists' AS Outcome;
    RETURN;
END;
IF EXISTS (SELECT 1 FROM cfg.DomainRole WHERE Domain = @Domain AND Role = @Role AND Principal = @Principal)
    UPDATE cfg.DomainRole SET RemovedAt = NULL, RemovedBy = NULL, AddedAt = SYSUTCDATETIME(), AddedBy = @By
    WHERE Domain = @Domain AND Role = @Role AND Principal = @Principal;
ELSE
    INSERT cfg.DomainRole (Domain, Role, Principal, AddedBy) VALUES (@Domain, @Role, @Principal, @By);
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (LEFT(N'domain-role/' + @Domain + N'/' + @Role, 128), N'domain-role', N'domain-role', N'Set', NULL, @Principal, @By, N'added');
COMMIT;
SELECT N'Saved' AS Outcome;
""";

    public const string RemoveRoleSql = """
SET XACT_ABORT ON;
BEGIN TRAN;
IF NOT EXISTS (SELECT 1 FROM cfg.DomainRole WITH (UPDLOCK, HOLDLOCK) WHERE Domain = @Domain AND Role = @Role AND Principal = @Principal AND RemovedAt IS NULL)
BEGIN
    COMMIT;
    SELECT N'Gone' AS Outcome;
    RETURN;
END;
UPDATE cfg.DomainRole SET RemovedAt = SYSUTCDATETIME(), RemovedBy = @By WHERE Domain = @Domain AND Role = @Role AND Principal = @Principal;
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (LEFT(N'domain-role/' + @Domain + N'/' + @Role, 128), N'domain-role', N'domain-role', N'Reset', @Principal, NULL, @By, N'removed');
COMMIT;
SELECT N'Saved' AS Outcome;
""";

    /// One request and its items (passed as one JSON parameter), with its "requested" ChangeLog row.
    public const string CreateRequestSql = """
SET XACT_ABORT ON;
BEGIN TRAN;
DECLARE @ids TABLE (RequestId bigint);
INSERT cfg.ExemptionRequest (Domain, Category, Reason, ExpiresAt, Approver, State, RequestedBy, ItemCount, Source)
OUTPUT inserted.RequestId INTO @ids
VALUES (@Domain, @Category, @Reason, @ExpiresAt, @Approver, N'requested', @By, @ItemCount, @Source);
DECLARE @id bigint = (SELECT TOP (1) RequestId FROM @ids);
INSERT cfg.ExemptionRequestItem (RequestId, ItemNo, Scope, ReportName, ConfigurationId, Cve, AssetKey, AssetName, Title, Category)
SELECT @id, j.ItemNo, j.Scope, j.ReportName, j.ConfigurationId, j.Cve, j.AssetKey, j.AssetName, j.Title, j.Category
FROM OPENJSON(@Items) WITH (ItemNo int '$.n', Scope nvarchar(16) '$.scope', ReportName nvarchar(128) '$.report', ConfigurationId nvarchar(128) '$.cfg',
                            Cve nvarchar(32) '$.cve', AssetKey nvarchar(256) '$.asset', AssetName nvarchar(400) '$.name', Title nvarchar(400) '$.title',
                            Category nvarchar(128) '$.category') AS j;
-- #391: the department page it was requested on and who it was routed to -- written only where the columns exist (a
-- database whose setup has not added them yet keeps the request without them; the flow then routes to the owners)
IF @DepartmentId IS NOT NULL AND COL_LENGTH(N'cfg.ExemptionRequest', N'Routing') IS NOT NULL
    EXEC sp_executesql N'UPDATE cfg.ExemptionRequest SET DepartmentId = @d, Routing = @r WHERE RequestId = @i;',
        N'@d int, @r nvarchar(32), @i bigint', @d = @DepartmentId, @r = @Routing, @i = @id;
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (LEFT(N'exemption-request/' + CONVERT(nvarchar(30), @id), 128), N'exemption', N'exemption', N'Set', NULL,
        CONCAT(N'requested: ', @ItemCount, N' finding(s) in ', @Domain, CASE WHEN @Category IS NULL THEN N'' ELSE N' / ' + @Category END, N', ', @Until,
               CASE WHEN @RoutingNote IS NULL OR COL_LENGTH(N'cfg.ExemptionRequest', N'Routing') IS NULL THEN N'' ELSE N'; asked of ' + @RoutingNote END), @By, LEFT(@Reason, 400));
COMMIT;
SELECT @id AS RequestId;
""";

    private const string RequestColumns = "RequestId, Domain, Category, Reason, ExpiresAt, Approver, State, RequestedBy, RequestedAt, DecidedBy, DecidedAt, DecisionComment, ItemCount, Source";

    /// #391: with the department routing where the columns exist (dynamic, so a database without them still reads), else NULL.
    public const string RequestsSql = $"""
IF OBJECT_ID(N'cfg.ExemptionRequest') IS NOT NULL AND COL_LENGTH(N'cfg.ExemptionRequest', N'Routing') IS NOT NULL
EXEC sp_executesql N'SELECT TOP (@Top) {RequestColumns}, DepartmentId, Routing
FROM cfg.ExemptionRequest WHERE (@State IS NULL OR State = @State) ORDER BY RequestedAt DESC, RequestId DESC;', N'@Top int, @State nvarchar(16)', @Top = @Top, @State = @State;
ELSE IF OBJECT_ID(N'cfg.ExemptionRequest') IS NOT NULL
SELECT TOP (@Top) {RequestColumns}, CAST(NULL AS int) AS DepartmentId, CAST(NULL AS nvarchar(32)) AS Routing
FROM cfg.ExemptionRequest WHERE (@State IS NULL OR State = @State) ORDER BY RequestedAt DESC, RequestId DESC;
""";

    public const string RequestSql = $"""
IF OBJECT_ID(N'cfg.ExemptionRequest') IS NOT NULL AND COL_LENGTH(N'cfg.ExemptionRequest', N'Routing') IS NOT NULL
EXEC sp_executesql N'SELECT {RequestColumns}, DepartmentId, Routing FROM cfg.ExemptionRequest WHERE RequestId = @RequestId;', N'@RequestId bigint', @RequestId = @RequestId;
ELSE IF OBJECT_ID(N'cfg.ExemptionRequest') IS NOT NULL
SELECT {RequestColumns}, CAST(NULL AS int) AS DepartmentId, CAST(NULL AS nvarchar(32)) AS Routing FROM cfg.ExemptionRequest WHERE RequestId = @RequestId;
""";

    public const string ItemsSql = """
IF OBJECT_ID(N'cfg.ExemptionRequestItem') IS NOT NULL
SELECT ItemNo, Scope, ReportName, ConfigurationId, Cve, AssetKey, AssetName, Title, ExemptionId, Category
FROM cfg.ExemptionRequestItem WHERE RequestId = @RequestId ORDER BY ItemNo;
""";

    /// <summary>
    /// Approval, in ONE transaction: the request must still be 'requested' (locked), it becomes 'approved'; an item an
    /// ACTIVE exemption already covers is linked to that one; every other item becomes a cfg.Exemption row created by
    /// the requester and approved by the approver, each with its ChangeLog row; plus the request's own ChangeLog row.
    /// </summary>
    public const string ApproveSql = """
SET XACT_ABORT ON;
BEGIN TRAN;
DECLARE @r TABLE (Domain nvarchar(64), Reason nvarchar(400), ExpiresAt datetime2(0), RequestedBy nvarchar(256));
INSERT @r SELECT Domain, Reason, ExpiresAt, RequestedBy FROM cfg.ExemptionRequest WITH (UPDLOCK, HOLDLOCK)
WHERE RequestId = @RequestId AND State = N'requested';
IF NOT EXISTS (SELECT 1 FROM @r)
BEGIN
    COMMIT;
    SELECT N'Gone' AS Outcome, 0 AS Created;
    RETURN;
END;
UPDATE cfg.ExemptionRequest SET State = N'approved', DecidedBy = @By, DecidedAt = SYSUTCDATETIME(), DecisionComment = @Comment
WHERE RequestId = @RequestId;
UPDATE i SET ExemptionId = (
    SELECT TOP (1) e.ExemptionId FROM cfg.Exemption AS e WITH (UPDLOCK, HOLDLOCK)
    WHERE e.Scope = i.Scope AND e.RevokedAt IS NULL AND (e.ExpiresAt IS NULL OR e.ExpiresAt > SYSUTCDATETIME())
      AND ISNULL(e.ReportName, N'') = ISNULL(i.ReportName, N'') AND ISNULL(e.ConfigurationId, N'') = ISNULL(i.ConfigurationId, N'')
      AND ISNULL(e.Cve, N'') = ISNULL(i.Cve, N'') AND ISNULL(e.AssetKey, N'') = ISNULL(i.AssetKey, N'')
    ORDER BY e.ExemptionId)
FROM cfg.ExemptionRequestItem AS i
WHERE i.RequestId = @RequestId;
DECLARE @new TABLE (ExemptionId bigint, ItemNo int);
MERGE cfg.Exemption AS t
USING (SELECT i.ItemNo, i.Scope, i.ReportName, i.ConfigurationId, i.Cve, i.AssetKey, i.Category, r.Reason, r.ExpiresAt, r.RequestedBy, r.Domain
       FROM cfg.ExemptionRequestItem AS i CROSS JOIN @r AS r
       WHERE i.RequestId = @RequestId AND i.ExemptionId IS NULL) AS s
ON 1 = 0
WHEN NOT MATCHED THEN
    INSERT (Scope, ReportName, ConfigurationId, Cve, AssetKey, Reason, ExpiresAt, CreatedBy, CreatedAt, RequestId, Domain, Category, ApprovedBy, ApprovedAt)
    VALUES (s.Scope, s.ReportName, s.ConfigurationId, s.Cve, s.AssetKey, s.Reason, s.ExpiresAt, s.RequestedBy, SYSUTCDATETIME(), @RequestId, s.Domain, s.Category, @By, SYSUTCDATETIME())
OUTPUT inserted.ExemptionId, s.ItemNo INTO @new (ExemptionId, ItemNo);
UPDATE i SET ExemptionId = n.ExemptionId
FROM cfg.ExemptionRequestItem AS i JOIN @new AS n ON n.ItemNo = i.ItemNo
WHERE i.RequestId = @RequestId;
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
SELECT LEFT(N'exemption/' + CONVERT(nvarchar(30), n.ExemptionId), 128), N'exemption', N'exemption', N'Set', NULL,
       CONCAT(N'approved from request ', @RequestId), @By, LEFT(r.Reason, 400)
FROM @new AS n CROSS JOIN @r AS r;
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (LEFT(N'exemption-request/' + CONVERT(nvarchar(30), @RequestId), 128), N'exemption', N'exemption', N'Set', N'requested', N'approved', @By, LEFT(@Comment, 400));
COMMIT;
SELECT N'Saved' AS Outcome, (SELECT COUNT(*) FROM @new) AS Created;
""";

    public const string RejectSql = """
SET XACT_ABORT ON;
BEGIN TRAN;
IF NOT EXISTS (SELECT 1 FROM cfg.ExemptionRequest WITH (UPDLOCK, HOLDLOCK) WHERE RequestId = @RequestId AND State = N'requested')
BEGIN
    COMMIT;
    SELECT N'Gone' AS Outcome;
    RETURN;
END;
UPDATE cfg.ExemptionRequest SET State = N'rejected', DecidedBy = @By, DecidedAt = SYSUTCDATETIME(), DecisionComment = @Comment
WHERE RequestId = @RequestId;
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (LEFT(N'exemption-request/' + CONVERT(nvarchar(30), @RequestId), 128), N'exemption', N'exemption', N'Reset', N'requested', N'rejected', @By, LEFT(@Comment, 400));
COMMIT;
SELECT N'Saved' AS Outcome;
""";

    /// Every exemption (newest first, bounded), with the #252 columns and -- for one that came from a request -- the asset's name.
    public const string ExemptionsSql = """
IF OBJECT_ID(N'cfg.Exemption') IS NOT NULL AND COL_LENGTH(N'cfg.Exemption', N'ReviewedAt') IS NOT NULL AND OBJECT_ID(N'cfg.ExemptionRequestItem') IS NOT NULL
   AND COL_LENGTH(N'cfg.Exemption', N'Category') IS NOT NULL
EXEC sp_executesql N'
WITH names AS (SELECT ExemptionId, MAX(AssetName) AS AssetName FROM cfg.ExemptionRequestItem WHERE ExemptionId IS NOT NULL GROUP BY ExemptionId)
SELECT TOP (@Top) e.ExemptionId, e.Scope, e.ReportName, e.ConfigurationId, e.Cve, e.AssetKey, e.Reason, e.ExpiresAt, e.CreatedBy, e.CreatedAt,
       e.RevokedAt, e.RevokedBy, e.RequestId, e.Domain, e.ApprovedBy, e.ApprovedAt, e.ReviewedBy, e.ReviewedAt, n.AssetName, e.Category
FROM cfg.Exemption AS e LEFT JOIN names AS n ON n.ExemptionId = e.ExemptionId
ORDER BY e.CreatedAt DESC, e.ExemptionId DESC;', N'@Top int', @Top = @Top;
""";

    public const string ExtendSql = """
SET XACT_ABORT ON;
BEGIN TRAN;
DECLARE @old nvarchar(64) = (SELECT TOP (1) ISNULL(CONVERT(nvarchar(30), ExpiresAt, 126), N'no end date') FROM cfg.Exemption WITH (UPDLOCK, HOLDLOCK)
                             WHERE ExemptionId = @ExemptionId AND RevokedAt IS NULL);
IF @old IS NULL
BEGIN
    COMMIT;
    SELECT N'Gone' AS Outcome;
    RETURN;
END;
UPDATE cfg.Exemption SET ExpiresAt = @ExpiresAt, ReviewedBy = @By, ReviewedAt = SYSUTCDATETIME() WHERE ExemptionId = @ExemptionId;
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (LEFT(N'exemption/' + CONVERT(nvarchar(30), @ExemptionId), 128), N'exemption', N'exemption', N'Set', @old,
        CONCAT(N'extended: ', ISNULL(CONVERT(nvarchar(30), @ExpiresAt, 126), N'no end date')), @By, LEFT(@Reason, 400));
COMMIT;
SELECT N'Saved' AS Outcome;
""";

    public const string KeepSql = """
SET XACT_ABORT ON;
BEGIN TRAN;
IF NOT EXISTS (SELECT 1 FROM cfg.Exemption WITH (UPDLOCK, HOLDLOCK) WHERE ExemptionId = @ExemptionId AND RevokedAt IS NULL)
BEGIN
    COMMIT;
    SELECT N'Gone' AS Outcome;
    RETURN;
END;
UPDATE cfg.Exemption SET ReviewedBy = @By, ReviewedAt = SYSUTCDATETIME() WHERE ExemptionId = @ExemptionId;
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (LEFT(N'exemption/' + CONVERT(nvarchar(30), @ExemptionId), 128), N'exemption', N'exemption', N'Set', NULL, N'reviewed: kept', @By, LEFT(@Reason, 400));
COMMIT;
SELECT N'Saved' AS Outcome;
""";

    public const string EndSql = """
SET XACT_ABORT ON;
BEGIN TRAN;
IF NOT EXISTS (SELECT 1 FROM cfg.Exemption WITH (UPDLOCK, HOLDLOCK) WHERE ExemptionId = @ExemptionId AND RevokedAt IS NULL)
BEGIN
    COMMIT;
    SELECT N'Gone' AS Outcome;
    RETURN;
END;
UPDATE cfg.Exemption SET RevokedAt = SYSUTCDATETIME(), RevokedBy = @By, ReviewedBy = @By, ReviewedAt = SYSUTCDATETIME() WHERE ExemptionId = @ExemptionId;
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (LEFT(N'exemption/' + CONVERT(nvarchar(30), @ExemptionId), 128), N'exemption', N'exemption', N'Reset', N'active', N'ended', @By, LEFT(@Reason, 400));
COMMIT;
SELECT N'Saved' AS Outcome;
""";

    public const string QueueMailSql = """
INSERT cfg.ExemptionMail (Kind, RequestId, Domain, ToList, Subject, BodyHtml, QueuedBy)
VALUES (@Kind, @RequestId, @Domain, @ToList, @Subject, @BodyHtml, @By);
SELECT N'Saved' AS Outcome;
""";

    private readonly ISqlExecutor _sql;
    public SqlExemptionStore(ISqlExecutor sql) => _sql = sql;

    private static Dictionary<string, object?> P(params (string K, object? V)[] p) => p.ToDictionary(x => x.K, x => x.V, StringComparer.Ordinal);
    private static string? Outcome(IReadOnlyList<SqlRow> rows) => rows.Count > 0 ? rows[0].Str("Outcome") : null;
    private static WriteStatus Status(IReadOnlyList<SqlRow> rows) => Outcome(rows) switch
    {
        "Saved" => WriteStatus.Saved,
        "Gone" or "Exists" => WriteStatus.Stale,
        _ => throw new InvalidOperationException("the exemption write returned no outcome"),
    };

    public async Task<bool> ReadyAsync(CancellationToken ct)
    {
        var rows = await _sql.QueryAsync(ReadySql, P(), ct);
        return rows.Count > 0 && rows[0].Long("Ready") == 1;
    }

    public async Task<IReadOnlyList<DomainRoleRow>> RolesAsync(CancellationToken ct) =>
        (await _sql.QueryAsync(RolesSql, P(), ct)).Select(r => new DomainRoleRow(r.Str("Domain") ?? "", r.Str("Role") ?? "", r.Str("Principal") ?? "", r.Date("AddedAt"), r.Str("AddedBy"),
            DomainRoles.NormalizeCategory(r.Str("Category")))).ToList();

    private static string Who(string role, string domain, string? category) => $"{DomainRoles.RoleLabel(role, category)} of {DomainRoles.Label(domain, category)}";

    public async Task<WriteResult> AddRoleAsync(string domain, string? category, string role, string principal, string by, CancellationToken ct)
    {
        var s = category is null
            ? Status(await _sql.QueryAsync(AddRoleSql, P(("Domain", domain), ("Role", role), ("Principal", principal), ("By", by)), ct))
            : Status(await _sql.QueryAsync(AddCategoryRoleSql, P(("Domain", domain), ("Category", category), ("Role", role), ("Principal", principal), ("By", by)), ct));
        return s == WriteStatus.Saved ? new(s, $"{principal} is now {Who(role, domain, category)}") : new(s, $"{principal} already is {Who(role, domain, category)}");
    }

    public async Task<WriteResult> RemoveRoleAsync(string domain, string? category, string role, string principal, string by, CancellationToken ct)
    {
        var s = category is null
            ? Status(await _sql.QueryAsync(RemoveRoleSql, P(("Domain", domain), ("Role", role), ("Principal", principal), ("By", by)), ct))
            : Status(await _sql.QueryAsync(RemoveCategoryRoleSql, P(("Domain", domain), ("Category", category), ("Role", role), ("Principal", principal), ("By", by)), ct));
        return s == WriteStatus.Saved ? new(s, $"{principal} is no longer {Who(role, domain, category)}") : new(s, $"{principal} was not {Who(role, domain, category)}");
    }

    public async Task<IReadOnlyDictionary<string, string>> CategoriesAsync(IReadOnlyCollection<string> findingIds, CancellationToken ct)
    {
        var ids = findingIds.Where(i => long.TryParse(i, NumberStyles.None, CultureInfo.InvariantCulture, out _)).Distinct().Take(ExemptionWorkflow.MaxItems).ToList();
        var map = new Dictionary<string, string>(StringComparer.Ordinal);
        if (ids.Count == 0) return map;
        foreach (var r in await _sql.QueryAsync(CategoriesSql, P(("Ids", JsonSerializer.Serialize(ids))), ct))
            if (r.Str("FindingId") is { } id && DomainRoles.NormalizeCategory(r.Str("Category")) is { } c) map[id] = c;
        return map;
    }

    public async Task<IReadOnlyList<(string Domain, string Category)>> CategoryPairsAsync(CancellationToken ct) =>
        (await _sql.QueryAsync(CategoryPairsSql, P(), ct))
            .Select(r => (Domain: (r.Str("Domain") ?? "").Trim(), Category: DomainRoles.NormalizeCategory(r.Str("Category"))))
            .Where(x => x.Domain.Length > 0 && x.Category is not null).Select(x => (x.Domain, x.Category!)).ToList();

    public async Task<bool?> CategoryPairsWrittenAsync(CancellationToken ct)
    {
        var r = (await _sql.QueryAsync(CategoryPairsStateSql, P(), ct)).FirstOrDefault();
        if (r is null || !Flag(r.Str("HasSchema"))) return null;
        return Flag(r.Str("Written"));
    }

    private static bool Flag(string? v) => v is "1" or "True" or "true";

    public static string ItemsJson(IReadOnlyList<RequestItem> items) => JsonSerializer.Serialize(items.Select((i, n) => new Dictionary<string, object?>
    {
        ["n"] = n + 1, ["scope"] = i.Scope, ["report"] = i.ReportName, ["cfg"] = i.ConfigurationId, ["cve"] = i.Cve, ["asset"] = i.AssetKey,
        ["name"] = Cut(i.AssetName, 400), ["title"] = Cut(i.Title, 400), ["category"] = Cut(i.Category, 128),
    }));

    private static string? Cut(string? s, int n) => s is null ? null : s.Length > n ? s[..n] : s;

    public async Task<long> CreateRequestAsync(NewRequest r, string by, CancellationToken ct)
    {
        var rows = await _sql.QueryAsync(CreateRequestSql, P(("Domain", r.Domain), ("Category", r.Category), ("Reason", r.Reason), ("ExpiresAt", r.ExpiresAt), ("Approver", r.Approver),
            ("By", by), ("ItemCount", r.Items.Count), ("Source", r.Source), ("Items", ItemsJson(r.Items)), ("Until", ExemptionPeriods.Describe(r.ExpiresAt)),
            ("DepartmentId", r.DepartmentId), ("Routing", Cut(r.Routing, 32)), ("RoutingNote", Cut(r.RoutingNote, 400))), ct);
        return rows.Count > 0 && rows[0].Long("RequestId") is { } id ? id : throw new InvalidOperationException("the request write returned no id");
    }

    private static RequestRow Row(SqlRow r) => new(r.Long("RequestId") ?? 0, r.Str("Domain") ?? "", r.Str("Reason") ?? "", r.Date("ExpiresAt"), r.Str("Approver"),
        r.Str("State") ?? "", r.Str("RequestedBy") ?? "", r.Date("RequestedAt") ?? default, r.Str("DecidedBy"), r.Date("DecidedAt"), r.Str("DecisionComment"),
        (int)(r.Long("ItemCount") ?? 0), r.Str("Source"), DomainRoles.NormalizeCategory(r.Str("Category")),
        r.Long("DepartmentId") is { } d and > 0 ? (int)d : null, string.IsNullOrWhiteSpace(r.Str("Routing")) ? null : r.Str("Routing")!.Trim());

    public async Task<RequestRow?> RequestAsync(long requestId, CancellationToken ct) =>
        (await _sql.QueryAsync(RequestSql, P(("RequestId", requestId)), ct)).Select(Row).FirstOrDefault();

    public async Task<IReadOnlyList<RequestItem>> ItemsAsync(long requestId, CancellationToken ct) =>
        (await _sql.QueryAsync(ItemsSql, P(("RequestId", requestId)), ct)).Select(r => new RequestItem(r.Str("Scope") ?? "", r.Str("ReportName"), r.Str("ConfigurationId"),
            r.Str("Cve"), r.Str("AssetKey"), r.Str("AssetName"), r.Str("Title"), r.Long("ExemptionId"), DomainRoles.NormalizeCategory(r.Str("Category")))).ToList();

    public async Task<IReadOnlyList<RequestRow>> RequestsAsync(string? state, int top, CancellationToken ct) =>
        (await _sql.QueryAsync(RequestsSql, P(("State", state), ("Top", Math.Clamp(top, 1, 2000))), ct)).Select(Row).ToList();

    public async Task<(WriteStatus Status, int Created)> ApproveAsync(long requestId, string by, string? comment, CancellationToken ct)
    {
        var rows = await _sql.QueryAsync(ApproveSql, P(("RequestId", requestId), ("By", by), ("Comment", comment)), ct);
        return (Status(rows), (int)(rows.Count > 0 ? rows[0].Long("Created") ?? 0 : 0));
    }

    public async Task<WriteStatus> RejectAsync(long requestId, string by, string comment, CancellationToken ct) =>
        Status(await _sql.QueryAsync(RejectSql, P(("RequestId", requestId), ("By", by), ("Comment", comment)), ct));

    public async Task<IReadOnlyList<ExemptionInfo>> ExemptionsAsync(int top, CancellationToken ct) =>
        (await _sql.QueryAsync(ExemptionsSql, P(("Top", Math.Clamp(top, 1, 5000))), ct)).Select(r => new ExemptionInfo(
            r.Long("ExemptionId") ?? 0, r.Str("Scope") ?? "", r.Str("ReportName"), r.Str("ConfigurationId"), r.Str("Cve"), r.Str("AssetKey"), r.Str("Reason") ?? "",
            r.Date("ExpiresAt"), r.Str("CreatedBy") ?? "", r.Date("CreatedAt") ?? default, r.Date("RevokedAt"), r.Str("RevokedBy"), r.Long("RequestId"), r.Str("Domain"),
            r.Str("ApprovedBy"), r.Date("ApprovedAt"), r.Str("ReviewedBy"), r.Date("ReviewedAt"), r.Str("AssetName"), DomainRoles.NormalizeCategory(r.Str("Category")))).ToList();

    public async Task<WriteStatus> ExtendAsync(long exemptionId, DateTime? expiresAt, string by, string reason, CancellationToken ct) =>
        Status(await _sql.QueryAsync(ExtendSql, P(("ExemptionId", exemptionId), ("ExpiresAt", expiresAt), ("By", by), ("Reason", reason)), ct));

    public async Task<WriteStatus> KeepAsync(long exemptionId, string by, string reason, CancellationToken ct) =>
        Status(await _sql.QueryAsync(KeepSql, P(("ExemptionId", exemptionId), ("By", by), ("Reason", reason)), ct));

    public async Task<WriteStatus> EndAsync(long exemptionId, string by, string reason, CancellationToken ct) =>
        Status(await _sql.QueryAsync(EndSql, P(("ExemptionId", exemptionId), ("By", by), ("Reason", reason)), ct));

    public async Task QueueMailAsync(QueuedMail m, string by, CancellationToken ct) =>
        await _sql.QueryAsync(QueueMailSql, P(("Kind", m.Kind), ("RequestId", m.RequestId), ("Domain", m.Domain), ("ToList", Cut(string.Join(";", m.To), 2000)),
            ("Subject", Cut(m.Subject, 400)), ("BodyHtml", SI.Management.Core.Mail.MailLayout.Normalize(m.BodyHtml)), ("By", by)), ct);

    public static string Invariant(DateTime d) => d.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
}
