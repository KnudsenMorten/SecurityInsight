using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;
using SI.Management.Core.ProData;
using SI.Management.Web.Data;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Departments;

public sealed record GovernanceEntryRow(long EntryId, string AssetKey, string RecommendationKey, int? DepartmentId, string? DepartmentName, string? Status,
    string Comment, string Source, int? FlowId, DateTime? ScheduledFor, long? ExemptionRequestId, DateTime? CreatedAt, string CreatedBy);

public sealed record GovernanceStateRow(string AssetKey, string RecommendationKey, int? DepartmentId, string Status, DateTime? ScheduledFor, int? FlowId,
    long? ExemptionRequestId, DateTime? UpdatedAt, string? UpdatedBy);

public sealed record RemediationFlowRow(int FlowId, int? DepartmentId, string? DepartmentName, string Category, string Subcategory, string Action,
    string? VendorName, string? VendorMail, string? Note, int SortOrder, DateTime? UpdatedAt, string? UpdatedBy, DateTime? RetiredAt)
{
    public bool Retired => RetiredAt is not null;
    public RemediationFlowDef Def => new(FlowId, DepartmentId, Category, Subcategory, Action, VendorName, VendorMail, Note, SortOrder, Retired);
}

public sealed record RemediationFlowInput(int? DepartmentId, string Category, string Subcategory, string Action, string? VendorName, string? VendorMail, string? Note, int SortOrder);

/// What one governance write records: the finding (asset + recommendation), its department now, the status (null = a
/// comment only), the comment, where it came from, and -- for the remediation flows -- the flow, the window it was
/// scheduled for, the exemption request it raised, the vendor mail it queued.
public sealed record GovernanceWrite(string AssetKey, string RecommendationKey, int? DepartmentId, string? Status, string Comment, string Source,
    int? FlowId = null, DateTime? ScheduledFor = null, long? ExemptionRequestId = null, string? CollectionId = null, GovernanceMailItem? Mail = null);

/// A mail queued with an entry (a vendor escalation): sent by the close-loop mail job through the Risk Analysis relay.
public sealed record GovernanceMailItem(string Kind, IReadOnlyList<string> To, string Subject, string BodyHtml);

/// <summary>
/// THE one class that knows the shape of cfg.GovernanceEntry, cfg.GovernanceState, cfg.RemediationFlow and cfg.GovernanceMail
/// (si-pro-settings.sql, #254 phase 2 + 3). Every write is ONE transaction with its cfg.ChangeLog row: Name
/// 'governance/&lt;entry id&gt;' (Scope + Kind 'governance') for a log entry -- with the current-status row and a queued mail in the
/// same transaction -- and 'remediation-flow/&lt;id&gt;' (Scope + Kind 'remediation') for a flow. Nothing is removed: an entry is
/// appended, a flow retired. It never decides who may write: <see cref="GovernanceService"/> does.
/// </summary>
public sealed partial class GovernanceRepository
{
    public const int MaxComment = 2000;
    public const string ScopeGovernance = "governance";
    public const string ScopeRemediation = "remediation";
    public static readonly IReadOnlyList<string> Sources = ["web", "flow", "sync"];

    [GeneratedRegex(@"^[^@\s;,<>""]{1,64}@[^@\s;,<>""]{1,190}\.[A-Za-z]{2,}$", RegexOptions.CultureInvariant)] private static partial Regex MailPattern();
    [GeneratedRegex(@"^[\p{L}\p{N} &._()/+'\-]{1,128}$", RegexOptions.CultureInvariant)] private static partial Regex CategoryPattern();

    public const string ExistsSql = "SELECT CASE WHEN OBJECT_ID(N'cfg.GovernanceEntry') IS NULL OR OBJECT_ID(N'cfg.GovernanceState') IS NULL OR OBJECT_ID(N'cfg.RemediationFlow') IS NULL OR OBJECT_ID(N'cfg.GovernanceMail') IS NULL THEN 0 ELSE 1 END AS HasTable;";

    /// The department a finding of one collection was stamped with by the data sync (phase 1), with its collection.
    public const string FindingDepartmentSql = """
SELECT TOP (1) f.DepartmentId, d.Name AS DepartmentName, CONVERT(nvarchar(32), f.CollectionId) AS CollectionId
FROM sidata.Finding AS f LEFT JOIN cfg.Department AS d ON d.DepartmentId = f.DepartmentId
WHERE f.CollectionId = TRY_CONVERT(int, @CollectionId) AND f.FindingId = TRY_CONVERT(bigint, @FindingId);
""";

    private const string EntryColumns = """
e.EntryId, e.AssetKey, e.RecommendationKey, e.DepartmentId, d.Name AS DepartmentName, e.Status, e.Comment, e.Source, e.FlowId, e.ScheduledFor,
e.ExemptionRequestId, e.CreatedAt, e.CreatedBy
""";

    public const string FindingLogSql = $"""
SELECT TOP (200) {EntryColumns}
FROM cfg.GovernanceEntry AS e LEFT JOIN cfg.Department AS d ON d.DepartmentId = e.DepartmentId
WHERE e.AssetKey = @AssetKey AND e.RecommendationKey = @RecommendationKey
ORDER BY e.CreatedAt DESC, e.EntryId DESC;
""";

    public const string DepartmentLogSql = $"""
SELECT TOP (@Top) {EntryColumns}
FROM cfg.GovernanceEntry AS e LEFT JOIN cfg.Department AS d ON d.DepartmentId = e.DepartmentId
WHERE e.DepartmentId = @DepartmentId
ORDER BY e.CreatedAt DESC, e.EntryId DESC;
""";

    public const string StateSql = """
SELECT s.AssetKey, s.RecommendationKey, s.DepartmentId, s.Status, s.ScheduledFor, s.FlowId, s.ExemptionRequestId, s.UpdatedAt, s.UpdatedBy
FROM cfg.GovernanceState AS s
WHERE s.AssetKey = @AssetKey AND s.RecommendationKey = @RecommendationKey;
""";

    public const string DepartmentStatesSql = """
SELECT TOP (@Top) s.AssetKey, s.RecommendationKey, s.DepartmentId, s.Status, s.ScheduledFor, s.FlowId, s.ExemptionRequestId, s.UpdatedAt, s.UpdatedBy
FROM cfg.GovernanceState AS s
WHERE s.DepartmentId = @DepartmentId
ORDER BY CASE WHEN s.ScheduledFor IS NULL THEN 1 ELSE 0 END, s.ScheduledFor, s.UpdatedAt DESC;
""";

    public const string DepartmentStatusCountsSql = """
SELECT s.Status, COUNT_BIG(*) AS N FROM cfg.GovernanceState AS s WHERE s.DepartmentId = @DepartmentId GROUP BY s.Status;
""";

    /// <summary>
    /// ONE governance write: the entry, the current status (when the entry sets one), the change-log row, and a queued mail
    /// (a vendor escalation) -- all or nothing.
    /// </summary>
    public const string AddEntrySql = """
SET XACT_ABORT ON;
BEGIN TRAN;
DECLARE @ids TABLE (EntryId bigint);
INSERT cfg.GovernanceEntry (AssetKey, RecommendationKey, DepartmentId, Status, Comment, Source, FlowId, ScheduledFor, ExemptionRequestId, CollectionId, CreatedBy)
OUTPUT inserted.EntryId INTO @ids
VALUES (@AssetKey, @RecommendationKey, @DepartmentId, @Status, @Comment, @Source, @FlowId, CONVERT(datetime2(0), @ScheduledFor, 126), @ExemptionRequestId, TRY_CONVERT(int, @CollectionId), @By);
DECLARE @id bigint = (SELECT TOP (1) EntryId FROM @ids);
IF @Status IS NOT NULL
BEGIN
    UPDATE cfg.GovernanceState WITH (UPDLOCK, HOLDLOCK)
       SET DepartmentId = @DepartmentId, Status = @Status, ScheduledFor = CONVERT(datetime2(0), @ScheduledFor, 126), FlowId = @FlowId,
           ExemptionRequestId = @ExemptionRequestId, LastEntryId = @id, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By
     WHERE AssetKey = @AssetKey AND RecommendationKey = @RecommendationKey;
    IF @@ROWCOUNT = 0
        INSERT cfg.GovernanceState (AssetKey, RecommendationKey, DepartmentId, Status, ScheduledFor, FlowId, ExemptionRequestId, LastEntryId, UpdatedBy)
        VALUES (@AssetKey, @RecommendationKey, @DepartmentId, @Status, CONVERT(datetime2(0), @ScheduledFor, 126), @FlowId, @ExemptionRequestId, @id, @By);
END;
IF @MailTo IS NOT NULL
    INSERT cfg.GovernanceMail (Kind, EntryId, ToList, Subject, BodyHtml, QueuedBy) VALUES (@MailKind, @id, @MailTo, @MailSubject, @MailBody, @By);
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (LEFT(CONCAT(N'governance/', @id), 128), N'governance', N'governance', N'Set', NULL, @Body, @By, LEFT(@Comment, 400));
COMMIT;
SELECT N'Saved' AS Outcome, @id AS EntryId;
""";

    public const string FlowsSql = """
SELECT r.FlowId, r.DepartmentId, d.Name AS DepartmentName, r.Category, r.Subcategory, r.Action, r.VendorName, r.VendorMail, r.Note, r.SortOrder,
       r.UpdatedAt, r.UpdatedBy, r.RetiredAt
FROM cfg.RemediationFlow AS r LEFT JOIN cfg.Department AS d ON d.DepartmentId = r.DepartmentId
WHERE (@IncludeRetired = 1 OR r.RetiredAt IS NULL)
ORDER BY CASE WHEN r.RetiredAt IS NULL THEN 0 ELSE 1 END, d.Name, r.SortOrder, r.FlowId;
""";

    public const string AddFlowSql = """
SET XACT_ABORT ON;
BEGIN TRAN;
IF @DepartmentId IS NOT NULL AND NOT EXISTS (SELECT 1 FROM cfg.Department WHERE DepartmentId = @DepartmentId AND RetiredAt IS NULL) BEGIN COMMIT; SELECT N'Gone' AS Outcome; RETURN; END;
DECLARE @ids TABLE (FlowId int);
INSERT cfg.RemediationFlow (DepartmentId, Category, Subcategory, Action, VendorName, VendorMail, Note, SortOrder, CreatedBy, UpdatedBy)
OUTPUT inserted.FlowId INTO @ids
VALUES (@DepartmentId, @Category, @Subcategory, @Action, @VendorName, @VendorMail, @Note, @SortOrder, @By, @By);
DECLARE @id int = (SELECT TOP (1) FlowId FROM @ids);
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (LEFT(CONCAT(N'remediation-flow/', @id), 128), N'remediation', N'remediation', N'Set', NULL, @Body, @By, N'remediation flow added');
COMMIT;
SELECT N'Saved' AS Outcome, @id AS FlowId;
""";

    public const string RetireFlowSql = """
SET XACT_ABORT ON;
BEGIN TRAN;
DECLARE @old nvarchar(max) = (SELECT TOP (1) (SELECT r.DepartmentId, r.Category, r.Subcategory, r.Action, r.VendorName, r.VendorMail, r.Note, r.SortOrder FOR JSON PATH, WITHOUT_ARRAY_WRAPPER)
                              FROM cfg.RemediationFlow AS r WITH (UPDLOCK, HOLDLOCK) WHERE r.FlowId = @FlowId AND r.RetiredAt IS NULL);
IF @old IS NULL BEGIN COMMIT; SELECT N'Gone' AS Outcome; RETURN; END;
UPDATE cfg.RemediationFlow SET RetiredAt = SYSUTCDATETIME(), RetiredBy = @By, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By WHERE FlowId = @FlowId;
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (LEFT(CONCAT(N'remediation-flow/', @FlowId), 128), N'remediation', N'remediation', N'Reset', @old, NULL, @By, LEFT(@Reason, 400));
COMMIT;
SELECT N'Saved' AS Outcome;
""";

    private readonly ISqlExecutor _sql;
    public GovernanceRepository(ISqlExecutor sql) => _sql = sql;

    private static string Trim256(string s) => s.Length > 256 ? s[..256] : s;
    private static string? Blank(string? s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();
    private static string Iso(DateTime d) => DateTime.SpecifyKind(d, DateTimeKind.Utc).ToString("yyyy-MM-ddTHH:mm:ss", CultureInfo.InvariantCulture);
    private static int? Int(SqlRow r, string c) => r.Long(c) is { } v ? (int)v : null;

    // ---- validation (pure) --------------------------------------------------------------------------------------

    private static bool ValidAssetKey(string? k)
    {
        try { return ProDataFilters.AssetKey(k) is not null; }
        catch (ArgumentException) { return false; }
    }

    public static IReadOnlyList<string> Validate(GovernanceWrite w)
    {
        var why = new List<string>();
        if (!ValidAssetKey(w.AssetKey)) why.Add("the finding has no valid asset key");
        if (string.IsNullOrWhiteSpace(w.RecommendationKey) || w.RecommendationKey.Length > 256) why.Add("the finding has no recommendation (configuration id or CVE)");
        if (w.Status is not null && !GovernanceStatuses.All.Contains(w.Status)) why.Add($"'{w.Status}' is not a status ({string.Join(", ", GovernanceStatuses.All)})");
        var c = w.Comment?.Trim() ?? "";
        if (c.Length < 3) why.Add("write a comment (at least 3 characters) -- it is what the log and the audit show");
        if (c.Length > MaxComment) why.Add($"the comment is longer than {MaxComment} characters");
        if (c.Any(ch => char.IsControl(ch) && ch is not ('\r' or '\n' or '\t'))) why.Add("the comment has a control character");
        if (!Sources.Contains(w.Source)) why.Add($"'{w.Source}' is not a source");
        if (w.Mail is { } m && (m.To.Count == 0 || m.To.Any(t => !MailPattern().IsMatch(t)))) why.Add("the mail has no valid recipient");
        return why;
    }

    public static IReadOnlyList<string> Validate(RemediationFlowInput f)
    {
        var why = new List<string>();
        if (!RemediationActions.All.Contains(f.Action)) why.Add($"'{f.Action}' is not a flow ({string.Join(", ", RemediationActions.All)})");
        var cat = (f.Category ?? "").Trim();
        var sub = (f.Subcategory ?? "").Trim();
        if (cat != RemediationFlowResolver.Any && !CategoryPattern().IsMatch(cat)) why.Add("the category is a security domain (Endpoint, Identity, Azure, PublicIP, ...) or *");
        if (sub != RemediationFlowResolver.Any && (sub.Length is 0 or > 256 || sub.Any(char.IsControl))) why.Add("the subcategory is a report name (up to 256 characters) or *");
        var mail = Blank(f.VendorMail);
        if (mail is not null && !MailPattern().IsMatch(mail)) why.Add($"'{mail}' is not a mail address");
        if (f.Action == RemediationActions.EscalateVendor && mail is null) why.Add("an escalation to the vendor needs the vendor contact's mail address");
        if ((f.VendorName?.Length ?? 0) > 256) why.Add("the vendor name is longer than 256 characters");
        if ((f.Note?.Length ?? 0) > 400) why.Add("the note is longer than 400 characters");
        if (f.SortOrder is < 0 or > 100_000) why.Add("the order is a number from 0 to 100000");
        return why;
    }

    private static WriteResult Outcome(IReadOnlyList<SqlRow> rows, string saved, string gone) => (rows.Count > 0 ? rows[0].Str("Outcome") : null) switch
    {
        "Saved" => new WriteResult(WriteStatus.Saved, saved),
        "Gone" => new WriteResult(WriteStatus.Stale, gone),
        _ => throw new InvalidOperationException("the write returned no outcome"),
    };

    // ---- reads ----------------------------------------------------------------------------------------------------

    public async Task<bool> TablesExistAsync(CancellationToken ct)
    {
        var rows = await _sql.QueryAsync(ExistsSql, new Dictionary<string, object?>(), ct);
        return rows.Count > 0 && rows[0].Long("HasTable") == 1;
    }

    /// The department the data sync stamped on one finding (null department = Unassigned); null = no such finding row.
    public async Task<(int? DepartmentId, string? DepartmentName, string CollectionId)?> FindingDepartmentAsync(string collectionId, string findingId, CancellationToken ct)
    {
        var rows = await _sql.QueryAsync(FindingDepartmentSql, new Dictionary<string, object?> { ["CollectionId"] = collectionId, ["FindingId"] = findingId }, ct);
        if (rows.Count == 0) return null;
        return (Int(rows[0], "DepartmentId"), rows[0].Str("DepartmentName"), rows[0].Str("CollectionId") ?? collectionId);
    }

    private static GovernanceEntryRow Entry(SqlRow r) => new(r.Long("EntryId") ?? 0, r.Str("AssetKey") ?? "", r.Str("RecommendationKey") ?? "", Int(r, "DepartmentId"),
        r.Str("DepartmentName"), r.Str("Status"), r.Str("Comment") ?? "", r.Str("Source") ?? "", Int(r, "FlowId"), r.Date("ScheduledFor"), r.Long("ExemptionRequestId"),
        r.Date("CreatedAt"), r.Str("CreatedBy") ?? "");

    private static GovernanceStateRow State(SqlRow r) => new(r.Str("AssetKey") ?? "", r.Str("RecommendationKey") ?? "", Int(r, "DepartmentId"), r.Str("Status") ?? "",
        r.Date("ScheduledFor"), Int(r, "FlowId"), r.Long("ExemptionRequestId"), r.Date("UpdatedAt"), r.Str("UpdatedBy"));

    public async Task<IReadOnlyList<GovernanceEntryRow>> FindingLogAsync(string assetKey, string recommendationKey, CancellationToken ct) =>
        (await _sql.QueryAsync(FindingLogSql, new Dictionary<string, object?> { ["AssetKey"] = assetKey, ["RecommendationKey"] = recommendationKey }, ct)).Select(Entry).ToList();

    public async Task<IReadOnlyList<GovernanceEntryRow>> DepartmentLogAsync(int departmentId, int top, CancellationToken ct) =>
        (await _sql.QueryAsync(DepartmentLogSql, new Dictionary<string, object?> { ["DepartmentId"] = departmentId, ["Top"] = Math.Clamp(top, 1, 1000) }, ct)).Select(Entry).ToList();

    public async Task<GovernanceStateRow?> StateAsync(string assetKey, string recommendationKey, CancellationToken ct) =>
        (await _sql.QueryAsync(StateSql, new Dictionary<string, object?> { ["AssetKey"] = assetKey, ["RecommendationKey"] = recommendationKey }, ct)).Select(State).FirstOrDefault();

    public async Task<IReadOnlyList<GovernanceStateRow>> DepartmentStatesAsync(int departmentId, int top, CancellationToken ct) =>
        (await _sql.QueryAsync(DepartmentStatesSql, new Dictionary<string, object?> { ["DepartmentId"] = departmentId, ["Top"] = Math.Clamp(top, 1, 1000) }, ct)).Select(State).ToList();

    public async Task<IReadOnlyDictionary<string, long>> DepartmentStatusCountsAsync(int departmentId, CancellationToken ct) =>
        (await _sql.QueryAsync(DepartmentStatusCountsSql, new Dictionary<string, object?> { ["DepartmentId"] = departmentId }, ct))
            .Where(r => r.Str("Status") is not null).ToDictionary(r => r.Str("Status")!, r => r.Long("N") ?? 0);

    public async Task<IReadOnlyList<RemediationFlowRow>> FlowsAsync(bool includeRetired, CancellationToken ct) =>
        (await _sql.QueryAsync(FlowsSql, new Dictionary<string, object?> { ["IncludeRetired"] = includeRetired ? 1 : 0 }, ct)).Select(r => new RemediationFlowRow(
            (int)(r.Long("FlowId") ?? 0), Int(r, "DepartmentId"), r.Str("DepartmentName"), r.Str("Category") ?? RemediationFlowResolver.Any, r.Str("Subcategory") ?? RemediationFlowResolver.Any,
            r.Str("Action") ?? "", r.Str("VendorName"), r.Str("VendorMail"), r.Str("Note"), (int)(r.Long("SortOrder") ?? 0), r.Date("UpdatedAt"), r.Str("UpdatedBy"), r.Date("RetiredAt"))).ToList();

    // ---- writes ---------------------------------------------------------------------------------------------------

    /// Appends one entry (and its status, change-log row and queued mail) in one transaction. Validated first: a refused
    /// write sends nothing to the database.
    public async Task<(WriteResult Result, long? EntryId)> AddAsync(GovernanceWrite w, string by, CancellationToken ct)
    {
        var why = Validate(w);
        if (string.IsNullOrWhiteSpace(by)) why = why.Append("the signed-in user has no name to record").ToList();
        if (why.Count > 0) return (new WriteResult(WriteStatus.Refused, string.Join("; ", why)), null);
        var comment = w.Comment.Trim();
        var p = new Dictionary<string, object?>
        {
            ["AssetKey"] = w.AssetKey.Trim(), ["RecommendationKey"] = w.RecommendationKey.Trim(), ["DepartmentId"] = w.DepartmentId, ["Status"] = w.Status,
            ["Comment"] = comment, ["Source"] = w.Source, ["FlowId"] = w.FlowId, ["ScheduledFor"] = w.ScheduledFor is { } s ? Iso(s) : null,
            ["ExemptionRequestId"] = w.ExemptionRequestId, ["CollectionId"] = Blank(w.CollectionId), ["By"] = Trim256(by),
            ["MailKind"] = w.Mail?.Kind, ["MailTo"] = w.Mail is { } m ? string.Join(";", m.To) : null, ["MailSubject"] = w.Mail?.Subject, ["MailBody"] = w.Mail is { } mb ? SI.Management.Core.Mail.MailLayout.Normalize(mb.BodyHtml) : null,
            ["Body"] = JsonSerializer.Serialize(new
            {
                AssetKey = w.AssetKey.Trim(), RecommendationKey = w.RecommendationKey.Trim(), w.DepartmentId, w.Status, w.Source, w.FlowId,
                ScheduledFor = w.ScheduledFor is { } x ? Iso(x) : null, w.ExemptionRequestId, Mail = w.Mail is { } mm ? string.Join(";", mm.To) : null,
            }),
        };
        var rows = await _sql.QueryAsync(AddEntrySql, p, ct);
        var r = Outcome(rows, w.Status is null ? "comment added to the governance log" : $"status set to {GovernanceStatuses.Label(w.Status).ToLowerInvariant()} and logged", "");
        return (r, rows.Count > 0 ? rows[0].Long("EntryId") : null);
    }

    public async Task<WriteResult> AddFlowAsync(RemediationFlowInput f, string by, CancellationToken ct)
    {
        var why = Validate(f);
        if (why.Count > 0) return new WriteResult(WriteStatus.Refused, string.Join("; ", why));
        var cat = f.Category.Trim(); var sub = f.Subcategory.Trim();
        var rows = await _sql.QueryAsync(AddFlowSql, new Dictionary<string, object?>
        {
            ["DepartmentId"] = f.DepartmentId, ["Category"] = cat, ["Subcategory"] = sub, ["Action"] = f.Action, ["VendorName"] = Blank(f.VendorName),
            ["VendorMail"] = Blank(f.VendorMail), ["Note"] = Blank(f.Note), ["SortOrder"] = f.SortOrder, ["By"] = Trim256(by),
            ["Body"] = JsonSerializer.Serialize(new { f.DepartmentId, Category = cat, Subcategory = sub, f.Action, VendorName = Blank(f.VendorName), VendorMail = Blank(f.VendorMail), Note = Blank(f.Note), f.SortOrder }),
        }, ct);
        return Outcome(rows, $"flow added: {RemediationActions.Label(f.Action)} for {cat} / {sub}", "that department is retired or gone -- nothing was written");
    }

    public async Task<WriteResult> RetireFlowAsync(int flowId, string reason, string by, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(reason) || reason.Trim().Length < 3) return new WriteResult(WriteStatus.Refused, "give a reason (at least 3 characters)");
        var rows = await _sql.QueryAsync(RetireFlowSql, new Dictionary<string, object?> { ["FlowId"] = flowId, ["By"] = Trim256(by), ["Reason"] = reason.Trim() }, ct);
        return Outcome(rows, "flow retired -- findings already handled by it keep their log", "that flow is already retired");
    }
}
