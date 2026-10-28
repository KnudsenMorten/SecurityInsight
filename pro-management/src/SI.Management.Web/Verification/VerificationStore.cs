using System.Text.Json;
using SI.Management.Web.Data;

namespace SI.Management.Web.Verification;

/// One check of the verification service's catalog (config\verification-checks.locked.json): a stable id, what it finds,
/// why it matters for SecurityInsight's results, the fix, the severity and the scope it applies to.
public sealed record VerificationCheck(string Id, string Title, string Why, string Fix, string Severity, string Scope, string Source, string State);

/// The check catalog, read from the same file the engine reads (linked by the csproj as catalog\verification-checks.locked.json).
public sealed class VerificationCatalog
{
    public IReadOnlyList<VerificationCheck> Checks { get; }
    public int ReviewDays { get; }
    public string Version { get; }

    public VerificationCatalog(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var r = doc.RootElement;
        static string S(JsonElement e, string n) => e.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";
        Checks = r.GetProperty("checks").EnumerateArray()
            .Select(c => new VerificationCheck(S(c, "id"), S(c, "title"), S(c, "why"), S(c, "fix"), S(c, "severity"), S(c, "scope"), S(c, "source"), S(c, "state")))
            .Where(c => c.State != "not_used").ToList();
        ReviewDays = r.TryGetProperty("defaults", out var d) && d.TryGetProperty("decisionReviewDays", out var rd) && rd.TryGetInt32(out var n) && n > 0 ? n : 180;
        Version = S(r, "version");
    }

    public VerificationCheck? Find(string? id) => Checks.FirstOrDefault(c => string.Equals(c.Id, id, StringComparison.Ordinal));

    public const string FileName = "verification-checks.locked.json";
    public static string DefaultPath => Path.Combine(AppContext.BaseDirectory, "catalog", FileName);
    private static readonly Lazy<VerificationCatalog> Shipped = new(() => new VerificationCatalog(File.ReadAllText(Locate())));
    public static VerificationCatalog Default => Shipped.Value;

    /// The linked copy next to the app; else (a source-tree run) config\ of the SecurityInsight folder above it.
    public static string Locate()
    {
        if (File.Exists(DefaultPath)) return DefaultPath;
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            var p = Path.Combine(dir.FullName, "config", FileName);
            if (File.Exists(p)) return p;
        }
        throw new FileNotFoundException("the verification check catalog is missing", DefaultPath);
    }
}

/// The active decision on a gap: ignored or accepted, by whom, when, why, the reviewer and when it is due for review.
public sealed record VerificationDecisionInfo(long DecisionId, string Decision, string Reason, string? Owner, string DecidedBy, DateTime DecidedAt, DateTime ReviewDueAt)
{
    public bool ReviewDue(DateTime nowUtc) => ReviewDueAt <= nowUtc;
}

/// One data-collection gap (cfg.VerificationFinding) with its active decision, if any. Times are UTC.
public sealed record VerificationFindingRow(
    string FindingKey, string CheckId, string ScopeKind, string ScopeKey, string? ScopeName, string Severity, string? Detail,
    string Status, DateTime FirstSeenAt, DateTime LastSeenAt, DateTime? ResolvedAt, VerificationDecisionInfo? Decision);

/// One check's result in the last run: ok | gaps | not-checked (with the reason).
public sealed record VerificationCheckResult(string CheckId, string State, string? Reason, long Findings);

/// The last run of the verification service.
public sealed record VerificationRunInfo(long RunId, DateTime StartedAt, DateTime? FinishedAt, string? Outcome);

/// One event of a gap's history (opened, reopened, resolved), or a decision on it.
public sealed record VerificationHistoryRow(DateTime At, string Kind, string Text, string? By);

public sealed record VerificationView(bool HasTables, VerificationRunInfo? LastRun, IReadOnlyList<VerificationCheckResult> Checks, IReadOnlyList<VerificationFindingRow> Findings)
{
    public static readonly VerificationView Missing = new(false, null, Array.Empty<VerificationCheckResult>(), Array.Empty<VerificationFindingRow>());
}

/// The outcome of a decision: saved, or why not.
public sealed record VerificationDecideResult(bool Saved, string Message);

/// <summary>
/// THE VERIFICATION SERVICE'S DATA (docs\V3-DATA-MODEL.md 2.11). The engine (engine\verification\) writes the runs, the
/// check results and the gaps; the web app READS them and writes only the DECISIONS: an Admin ignores a gap (not a gap for
/// this organisation) or accepts it (a known gap whose risk is accepted for now) with a reason and a reviewer; every
/// decision is due for review after the catalog's decisionReviewDays (180). A decision is never changed in place: a review
/// or a new decision is a NEW row and the one it replaces gets RevokedAt, so the history of every decision stays.
/// </summary>
public interface IVerificationStore
{
    Task<VerificationView> ReadAsync(int resolvedDays, CancellationToken ct);
    Task<IReadOnlyList<VerificationHistoryRow>> HistoryAsync(string findingKey, CancellationToken ct);
    Task<VerificationDecideResult> DecideAsync(string findingKey, string decision, string? reason, string? owner, string by, int reviewDays, CancellationToken ct);
    Task<VerificationDecideResult> RevokeAsync(string findingKey, string by, CancellationToken ct);
}

public sealed class SqlVerificationStore : IVerificationStore
{
    private readonly ISqlExecutor _sql;
    public SqlVerificationStore(ISqlExecutor sql) => _sql = sql;

    public const string ProbeSql = """
SELECT CASE WHEN OBJECT_ID(N'cfg.VerificationRun') IS NOT NULL AND OBJECT_ID(N'cfg.VerificationCheckRun') IS NOT NULL AND OBJECT_ID(N'cfg.VerificationFinding') IS NOT NULL
             AND OBJECT_ID(N'cfg.VerificationFindingEvent') IS NOT NULL AND OBJECT_ID(N'cfg.VerificationDecision') IS NOT NULL THEN 1 ELSE 0 END AS HasTables
""";

    /// The newest FINISHED run and its check results.
    public const string LastRunSql = """
SET NOCOUNT ON;
DECLARE @run bigint = (SELECT TOP (1) RunId FROM cfg.VerificationRun WHERE FinishedAt IS NOT NULL ORDER BY RunId DESC);
SELECT r.RunId, r.StartedAt, r.FinishedAt, r.Outcome, c.CheckId, c.State, c.Reason, CAST(c.Findings AS bigint) AS Findings
FROM cfg.VerificationRun AS r LEFT JOIN cfg.VerificationCheckRun AS c ON c.RunId = r.RunId
WHERE r.RunId = @run ORDER BY c.CheckId;
""";

    /// Every open gap and the ones resolved in the last @Days days, each with its active decision.
    public const string FindingsSql = """
SELECT f.FindingKey, f.CheckId, f.ScopeKind, f.ScopeKey, f.ScopeName, f.Severity, f.Detail, f.[Status], f.FirstSeenAt, f.LastSeenAt, f.ResolvedAt,
       d.DecisionId, d.Decision, d.Reason, d.[Owner], d.DecidedBy, d.DecidedAt, d.ReviewDueAt
FROM cfg.VerificationFinding AS f
OUTER APPLY (SELECT TOP (1) x.DecisionId, x.Decision, x.Reason, x.[Owner], x.DecidedBy, x.DecidedAt, x.ReviewDueAt
             FROM cfg.VerificationDecision AS x WHERE x.FindingKey = f.FindingKey AND x.RevokedAt IS NULL ORDER BY x.DecisionId DESC) AS d
WHERE f.[Status] = N'open' OR f.ResolvedAt >= DATEADD(day, -@Days, SYSUTCDATETIME())
ORDER BY CASE f.Severity WHEN N'high' THEN 0 WHEN N'medium' THEN 1 WHEN N'low' THEN 2 ELSE 3 END, f.CheckId, f.ScopeName, f.FindingKey;
""";

    /// A gap's history: its events and every decision on it (also the replaced and revoked ones).
    public const string HistorySql = """
SELECT e.At, e.[Event] AS Kind, COALESCE(e.Detail, N'') AS [Text], CAST(NULL AS nvarchar(256)) AS [By] FROM cfg.VerificationFindingEvent AS e WHERE e.FindingKey = @Key
UNION ALL
SELECT d.DecidedAt, d.Decision, CONCAT(d.Reason, N' (reviewer: ', COALESCE(d.[Owner], d.DecidedBy), N'; review by ', CONVERT(nvarchar(10), d.ReviewDueAt, 23), N')'), d.DecidedBy FROM cfg.VerificationDecision AS d WHERE d.FindingKey = @Key
UNION ALL
SELECT d.RevokedAt, N'withdrawn', N'decision withdrawn or replaced', d.RevokedBy FROM cfg.VerificationDecision AS d WHERE d.FindingKey = @Key AND d.RevokedAt IS NOT NULL
ORDER BY 1 DESC;
""";

    /// Ignore / accept a gap, or review its decision: in ONE transaction, the active decision (if any) is replaced
    /// (RevokedAt) by a NEW row due for review in @ReviewDays days. Outcome saved | missing | unknown.
    public const string DecideSql = """
SET NOCOUNT ON;
SET XACT_ABORT ON;
IF OBJECT_ID(N'cfg.VerificationDecision') IS NULL OR OBJECT_ID(N'cfg.VerificationFinding') IS NULL
BEGIN
    SELECT N'missing' AS Outcome;
    RETURN;
END
BEGIN TRAN;
DECLARE @check nvarchar(64) = (SELECT CheckId FROM cfg.VerificationFinding WITH (UPDLOCK, ROWLOCK) WHERE FindingKey = @Key);
IF @check IS NULL BEGIN ROLLBACK; SELECT N'unknown' AS Outcome; RETURN; END
DECLARE @prev bigint = (SELECT TOP (1) DecisionId FROM cfg.VerificationDecision WITH (UPDLOCK) WHERE FindingKey = @Key AND RevokedAt IS NULL ORDER BY DecisionId DESC);
UPDATE cfg.VerificationDecision SET RevokedAt = SYSUTCDATETIME(), RevokedBy = @By WHERE FindingKey = @Key AND RevokedAt IS NULL;
INSERT cfg.VerificationDecision (FindingKey, CheckId, Decision, Reason, [Owner], DecidedBy, ReviewDueAt, ReplacesDecisionId)
VALUES (@Key, @check, @Decision, @Reason, @Owner, @By, DATEADD(day, @ReviewDays, SYSUTCDATETIME()), @prev);
COMMIT;
SELECT N'saved' AS Outcome;
""";

    /// Withdraw the active decision: the gap is open again. Outcome revoked | none | missing.
    public const string RevokeSql = """
SET NOCOUNT ON;
IF OBJECT_ID(N'cfg.VerificationDecision') IS NULL BEGIN SELECT N'missing' AS Outcome; RETURN; END
UPDATE cfg.VerificationDecision SET RevokedAt = SYSUTCDATETIME(), RevokedBy = @By WHERE FindingKey = @Key AND RevokedAt IS NULL;
SELECT CASE WHEN @@ROWCOUNT > 0 THEN N'revoked' ELSE N'none' END AS Outcome;
""";

    public static readonly string[] Decisions = ["ignored", "accepted"];

    public async Task<VerificationView> ReadAsync(int resolvedDays, CancellationToken ct)
    {
        var probe = await _sql.QueryAsync(ProbeSql, new Dictionary<string, object?>(), ct);
        if ((probe.FirstOrDefault()?.Long("HasTables") ?? 0) != 1) return VerificationView.Missing;
        var runRows = await _sql.QueryAsync(LastRunSql, new Dictionary<string, object?>(), ct);
        VerificationRunInfo? run = null;
        var checks = new List<VerificationCheckResult>();
        foreach (var r in runRows)
        {
            run ??= new VerificationRunInfo(r.Long("RunId") ?? 0, r.Date("StartedAt") ?? DateTime.MinValue, r.Date("FinishedAt"), r.Str("Outcome"));
            if (r.Str("CheckId") is { } id) checks.Add(new VerificationCheckResult(id, r.Str("State") ?? "", r.Str("Reason"), r.Long("Findings") ?? 0));
        }
        var rows = await _sql.QueryAsync(FindingsSql, new Dictionary<string, object?> { ["Days"] = Math.Clamp(resolvedDays, 1, 365) }, ct);
        var findings = rows.Select(r => new VerificationFindingRow(
            r.Str("FindingKey") ?? "", r.Str("CheckId") ?? "", r.Str("ScopeKind") ?? "", r.Str("ScopeKey") ?? "", r.Str("ScopeName"), r.Str("Severity") ?? "",
            r.Str("Detail"), r.Str("Status") ?? "", r.Date("FirstSeenAt") ?? DateTime.MinValue, r.Date("LastSeenAt") ?? DateTime.MinValue, r.Date("ResolvedAt"),
            r.Long("DecisionId") is { } did
                ? new VerificationDecisionInfo(did, r.Str("Decision") ?? "", r.Str("Reason") ?? "", r.Str("Owner"), r.Str("DecidedBy") ?? "", r.Date("DecidedAt") ?? DateTime.MinValue, r.Date("ReviewDueAt") ?? DateTime.MinValue)
                : null)).ToList();
        return new VerificationView(true, run, checks, findings);
    }

    public async Task<IReadOnlyList<VerificationHistoryRow>> HistoryAsync(string findingKey, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(findingKey)) return Array.Empty<VerificationHistoryRow>();
        var probe = await _sql.QueryAsync(ProbeSql, new Dictionary<string, object?>(), ct);
        if ((probe.FirstOrDefault()?.Long("HasTables") ?? 0) != 1) return Array.Empty<VerificationHistoryRow>();
        var rows = await _sql.QueryAsync(HistorySql, new Dictionary<string, object?> { ["Key"] = findingKey }, ct);
        return rows.Select(r => new VerificationHistoryRow(r.Date("At") ?? DateTime.MinValue, r.Str("Kind") ?? "", r.Str("Text") ?? "", r.Str("By"))).ToList();
    }

    /// PURE. Why a decision cannot be saved, or null: a known decision, a reason of at least 3 characters.
    public static string? Validate(string? decision, string? reason)
    {
        if (decision is null || !Decisions.Contains(decision)) return "Not saved: choose Ignore or Accept.";
        if (string.IsNullOrWhiteSpace(reason) || reason.Trim().Length < 3) return "Not saved: say why (the reason is on the audit trail and in the gap's history).";
        return null;
    }

    public async Task<VerificationDecideResult> DecideAsync(string findingKey, string decision, string? reason, string? owner, string by, int reviewDays, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(findingKey)) return new VerificationDecideResult(false, "No gap was chosen.");
        if (Validate(decision, reason) is { } bad) return new VerificationDecideResult(false, bad);
        var why = reason!.Trim(); if (why.Length > 2000) why = why[..2000];
        var reviewer = string.IsNullOrWhiteSpace(owner) ? null : owner.Trim()[..Math.Min(owner.Trim().Length, 256)];
        var days = Math.Clamp(reviewDays, 1, 3650);
        var rows = await _sql.QueryAsync(DecideSql, new Dictionary<string, object?>
        {
            ["Key"] = findingKey, ["Decision"] = decision, ["Reason"] = why, ["Owner"] = reviewer, ["By"] = by, ["ReviewDays"] = days,
        }, ct);
        return (rows.FirstOrDefault()?.Str("Outcome") ?? "") switch
        {
            "saved" => new VerificationDecideResult(true, $"Saved: {(decision == "ignored" ? "ignored" : "accepted")}, due for review in {days} days."),
            "unknown" => new VerificationDecideResult(false, "This gap is not known (any more)."),
            "missing" => new VerificationDecideResult(false, "This database has no verification tables yet. Run the Pro schema (setup) once."),
            _ => new VerificationDecideResult(false, "Not saved: the database gave no answer."),
        };
    }

    public async Task<VerificationDecideResult> RevokeAsync(string findingKey, string by, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(findingKey)) return new VerificationDecideResult(false, "No gap was chosen.");
        var rows = await _sql.QueryAsync(RevokeSql, new Dictionary<string, object?> { ["Key"] = findingKey, ["By"] = by }, ct);
        return (rows.FirstOrDefault()?.Str("Outcome") ?? "") switch
        {
            "revoked" => new VerificationDecideResult(true, "The decision is withdrawn: the gap is open again."),
            "none" => new VerificationDecideResult(false, "This gap has no decision to withdraw."),
            "missing" => new VerificationDecideResult(false, "This database has no verification tables yet. Run the Pro schema (setup) once."),
            _ => new VerificationDecideResult(false, "Not withdrawn: the database gave no answer."),
        };
    }
}

/// PURE helpers of the page: the filter and the review queue.
public static class VerificationFilter
{
    /// The review queue: every active decision of an OPEN gap due within @withinDays days (overdue first).
    public static IReadOnlyList<VerificationFindingRow> ReviewQueue(IEnumerable<VerificationFindingRow> rows, DateTime nowUtc, int withinDays = 30) =>
        rows.Where(r => r.Status == "open" && r.Decision is not null && r.Decision.ReviewDueAt <= nowUtc.AddDays(withinDays))
            .OrderBy(r => r.Decision!.ReviewDueAt).ThenBy(r => r.FindingKey, StringComparer.Ordinal).ToList();

    /// The list as filtered: check id, status (open | resolved | all), decision (none | ignored | accepted | due | any),
    /// severity. Check, decision and severity may each hold several values, '|'-joined (owner 2026-10-19: every filter
    /// multi-select): a row matches when ANY value of the filter fits it.
    public static IReadOnlyList<VerificationFindingRow> Apply(IEnumerable<VerificationFindingRow> rows, string? check, string? status, string? decision, string? severity, DateTime nowUtc)
    {
        var q = rows;
        var checks = SI.Management.Core.ProData.ProDataFilters.Values(check);
        if (checks.Count > 0) q = q.Where(r => checks.Contains(r.CheckId, StringComparer.Ordinal));
        var st = string.IsNullOrWhiteSpace(status) ? "open" : status;
        if (st != "all") q = q.Where(r => r.Status == st);
        var decisions = SI.Management.Core.ProData.ProDataFilters.Values(decision).Where(d => d is "none" or "ignored" or "accepted" or "due").ToList();
        if (decisions.Count > 0)
            q = q.Where(r => decisions.Any(d => d switch
            {
                "none" => r.Decision is null,
                "due" => r.Decision is not null && r.Decision.ReviewDue(nowUtc),
                _ => r.Decision?.Decision == d,
            }));
        var severities = SI.Management.Core.ProData.ProDataFilters.Values(severity);
        if (severities.Count > 0) q = q.Where(r => severities.Contains(r.Severity, StringComparer.Ordinal));
        return q.ToList();
    }
}
