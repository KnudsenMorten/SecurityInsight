using System.Globalization;
using System.Security.Claims;
using System.Text.Json;
using SI.Management.Core.ProData;
using SI.Management.Web.Auth;
using SI.Management.Web.Data;
using SI.Management.Web.Settings;

namespace SI.Management.Web.FindingComments;

/// <summary>
/// COMMENTS ON ONE FINDING (#258): what advisors, department people and the security team say about a finding -- a
/// comment, a recommendation, or an approval of the recommended change. Kept apart on purpose: the governance log of
/// #254 phase 2 is built in parallel and may absorb this table (cfg.FindingComment) and this writer.
/// </summary>
public static class FindingCommentKinds
{
    public const string Comment = "comment";
    public const string Recommend = "recommend";
    public const string Approve = "approve";
    public static readonly IReadOnlyList<string> All = [Comment, Recommend, Approve];

    public static AccessAction ActionOf(string kind) => kind switch
    {
        Recommend => AccessAction.Recommend,
        Approve => AccessAction.Approve,
        _ => AccessAction.Comment,
    };

    public static string Label(string kind) => kind switch { Recommend => "Recommendation", Approve => "Approval", _ => "Comment" };
}

/// A finding's stable key: its asset and its recommendation (ConfigurationId, or the CVE id) -- the same across
/// collections, so the thread follows the finding from run to run.
public static class FindingKey
{
    public static string Of(string assetKey, string recommendationKey) => assetKey.Trim() + "|" + recommendationKey.Trim();
}

public sealed record FindingCommentRow(long CommentId, string FindingKey, string AssetKey, string RecommendationKey, int? DepartmentId, string Kind, string Body,
    string Author, string AuthorRole, string AuthMethod, long? SignInId, DateTime? CreatedAt);

/// What the newest complete collection knows of a finding: its department and the facts the scope check needs.
public sealed record FindingFacts(string AssetKey, string RecommendationKey, string? AssetName, string? Title, string? Severity, string? SecurityDomain,
    string? AssetKind, string? Tier, int? DepartmentId, string? CollectionId);

public interface IFindingCommentStore
{
    Task<bool> ReadyAsync(CancellationToken ct);
    Task<IReadOnlyList<FindingCommentRow>> ListAsync(string findingKey, CancellationToken ct);
    Task<WriteResult> AddAsync(FindingCommentRow row, CancellationToken ct);
    /// The finding as the newest complete detailed collection has it, or null when it is not there.
    Task<FindingFacts?> FactsAsync(string assetKey, string recommendationKey, CancellationToken ct);
}

/// <summary>
/// THE one class that knows cfg.FindingComment. A comment is written in ONE transaction with its cfg.ChangeLog row
/// (Name 'finding-comment/&lt;id&gt;', Scope 'finding', Kind 'finding-comment'). Never updated, never deleted.
/// </summary>
public sealed class SqlFindingCommentStore : IFindingCommentStore
{
    public const string ReadySql = "SELECT CASE WHEN OBJECT_ID(N'cfg.FindingComment') IS NULL THEN 0 ELSE 1 END AS Ready;";

    public const string ListSql = """
SELECT TOP (500) c.CommentId, c.FindingKey, c.AssetKey, c.RecommendationKey, c.DepartmentId, c.Kind, c.Body, c.Author, c.AuthorRole, c.AuthMethod, c.SignInId, c.CreatedAt
FROM cfg.FindingComment AS c
WHERE c.FindingKey = @FindingKey
ORDER BY c.CreatedAt, c.CommentId;
""";

    public const string AddSql = """
SET XACT_ABORT ON;
BEGIN TRAN;
DECLARE @ids TABLE (CommentId bigint);
INSERT cfg.FindingComment (FindingKey, AssetKey, RecommendationKey, DepartmentId, Kind, Body, Author, AuthorRole, AuthMethod, SignInId)
OUTPUT inserted.CommentId INTO @ids
VALUES (@FindingKey, @AssetKey, @RecommendationKey, @DepartmentId, @Kind, @Body, @Author, @AuthorRole, @AuthMethod, @SignInId);
DECLARE @id bigint = (SELECT TOP (1) CommentId FROM @ids);
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (LEFT(CONCAT(N'finding-comment/', @id), 128), N'finding', N'finding-comment', N'Set', NULL,
        (SELECT @FindingKey AS finding, @DepartmentId AS department, @Kind AS kind, @AuthorRole AS role, @AuthMethod AS signedInBy, @Body AS text FOR JSON PATH, WITHOUT_ARRAY_WRAPPER),
        @Author, LEFT(CONCAT(@Kind, N' on ', @FindingKey), 400));
COMMIT;
SELECT N'Saved' AS Outcome, @id AS CommentId;
""";

    /// The finding in the published run's collection (its department as the data sync stamped it).
    public const string FactsSql = $"""
DECLARE @c int = {SI.Management.Core.ProData.PublishedRun.DetailedId};
SELECT TOP (1) f.AssetKey, COALESCE(f.ConfigurationId, f.Cve) AS RecommendationKey, f.AssetName, f.Title, f.Severity, f.SecurityDomain,
       a.AssetKind, CONVERT(nvarchar(8), f.Tier) AS Tier, f.DepartmentId, CONVERT(nvarchar(64), f.CollectionId) AS CollectionId
FROM sidata.Finding AS f
LEFT JOIN sidata.Asset AS a ON a.AssetKey = f.AssetKey
WHERE f.CollectionId = @c AND f.AssetKey = @AssetKey AND COALESCE(f.ConfigurationId, f.Cve) = @RecommendationKey;
""";

    private readonly ISqlExecutor _sql;
    public SqlFindingCommentStore(ISqlExecutor sql) => _sql = sql;

    public async Task<bool> ReadyAsync(CancellationToken ct)
    {
        var rows = await _sql.QueryAsync(ReadySql, new Dictionary<string, object?>(), ct);
        return rows.Count > 0 && rows[0].Long("Ready") == 1;
    }

    public async Task<IReadOnlyList<FindingCommentRow>> ListAsync(string findingKey, CancellationToken ct) =>
        (await _sql.QueryAsync(ListSql, new Dictionary<string, object?> { ["FindingKey"] = findingKey }, ct))
        .Where(r => r.Long("CommentId") is > 0)
        .Select(r => new FindingCommentRow(r.Long("CommentId") ?? 0, r.Str("FindingKey") ?? "", r.Str("AssetKey") ?? "", r.Str("RecommendationKey") ?? "", (int?)r.Long("DepartmentId"),
            r.Str("Kind") ?? FindingCommentKinds.Comment, r.Str("Body") ?? "", r.Str("Author") ?? "", r.Str("AuthorRole") ?? "", r.Str("AuthMethod") ?? "", r.Long("SignInId"), r.Date("CreatedAt"))).ToList();

    public async Task<WriteResult> AddAsync(FindingCommentRow c, CancellationToken ct)
    {
        var rows = await _sql.QueryAsync(AddSql, new Dictionary<string, object?>
        {
            ["FindingKey"] = c.FindingKey, ["AssetKey"] = c.AssetKey, ["RecommendationKey"] = c.RecommendationKey, ["DepartmentId"] = c.DepartmentId, ["Kind"] = c.Kind,
            ["Body"] = c.Body, ["Author"] = c.Author, ["AuthorRole"] = c.AuthorRole, ["AuthMethod"] = c.AuthMethod, ["SignInId"] = c.SignInId,
        }, ct);
        return rows.Count > 0 && rows[0].Str("Outcome") == "Saved"
            ? new WriteResult(WriteStatus.Saved, FindingCommentKinds.Label(c.Kind) + " added")
            : throw new InvalidOperationException("the comment write returned no outcome");
    }

    public async Task<FindingFacts?> FactsAsync(string assetKey, string recommendationKey, CancellationToken ct)
    {
        var rows = await _sql.QueryAsync(FactsSql, new Dictionary<string, object?> { ["AssetKey"] = assetKey, ["RecommendationKey"] = recommendationKey }, ct);
        var r = rows.FirstOrDefault(x => x.Str("AssetKey") is not null && x.Str("RecommendationKey") is not null);
        return r is null ? null : new FindingFacts(r.Str("AssetKey")!, r.Str("RecommendationKey")!, r.Str("AssetName"), r.Str("Title"), r.Str("Severity"), r.Str("SecurityDomain"),
            r.Str("AssetKind"), r.Str("Tier"), (int?)r.Long("DepartmentId"), r.Str("CollectionId"));
    }
}

/// <summary>
/// Comment / recommend / approve on a finding -- every permission through the role framework (<see cref="IAccessScope"/>):
/// the target is the finding's security domain, asset kind, tier AND department, so a Delegated user decides inside
/// their domain scope, an advisor or a department person inside their department, and Approve demands the strong
/// sign-in their role asks for (an Entra sign-in, or a magic link confirmed with the one-time code).
/// </summary>
public sealed class FindingCommentService
{
    public const int MaxBody = 2000;
    private readonly IFindingCommentStore _store;
    private readonly IAccessScope _access;
    public FindingCommentService(IFindingCommentStore store, IAccessScope access) { _store = store; _access = access; }

    public Task<bool> ReadyAsync(CancellationToken ct) => _store.ReadyAsync(ct);
    public Task<FindingFacts?> FactsAsync(string assetKey, string recommendationKey, CancellationToken ct) => _store.FactsAsync(assetKey, recommendationKey, ct);
    public Task<IReadOnlyList<FindingCommentRow>> ListAsync(string assetKey, string recommendationKey, CancellationToken ct) => _store.ListAsync(FindingKey.Of(assetKey, recommendationKey), ct);

    /// The scope target of a finding: its domain, asset kind, tier and department.
    public static ScopeTarget Target(FindingFacts f) => new ScopeTarget(f.SecurityDomain, f.AssetKind, f.Tier)
        .With(ScopeTypes.Department, f.DepartmentId?.ToString(CultureInfo.InvariantCulture));

    public AccessDecision Can(ClaimsPrincipal user, string kind, FindingFacts f) => _access.Can(user, FindingCommentKinds.ActionOf(kind), Target(f));

    public async Task<WriteResult> AddAsync(ClaimsPrincipal user, string kind, FindingFacts f, string? text, CancellationToken ct)
    {
        if (!FindingCommentKinds.All.Contains(kind)) return new WriteResult(WriteStatus.Refused, $"'{kind}' is not comment, recommend or approve");
        var gate = Can(user, kind, f);
        if (!gate.Allowed) return new WriteResult(WriteStatus.Refused, gate.Reason);
        var body = (text ?? "").Trim();
        if (body.Length < (kind == FindingCommentKinds.Approve ? 0 : 3)) return new WriteResult(WriteStatus.Refused, "write at least 3 characters");
        if (body.Length > MaxBody) return new WriteResult(WriteStatus.Refused, $"at most {MaxBody} characters");
        if (body.Any(ch => char.IsControl(ch) && ch is not ('\n' or '\r' or '\t'))) return new WriteResult(WriteStatus.Refused, "the text has a control character");
        if (body.Length == 0) body = "approved";
        var by = user.ChangeName();
        if (string.IsNullOrWhiteSpace(by)) return new WriteResult(WriteStatus.Refused, "the signed-in user has no name to record");
        if (!await _store.ReadyAsync(ct)) return new WriteResult(WriteStatus.Refused, "the Pro database does not have the finding comment table yet -- apply sql\\si-pro-settings.sql again (it only adds)");
        return await _store.AddAsync(new FindingCommentRow(0, FindingKey.Of(f.AssetKey, f.RecommendationKey), f.AssetKey, f.RecommendationKey, f.DepartmentId, kind, body,
            by.Length > 256 ? by[..256] : by, AccessClaims.Label(user.EffectiveRole()), AuthMethods.Of(user), DepartmentSessions.SignInId(user), null), ct);
    }
}
