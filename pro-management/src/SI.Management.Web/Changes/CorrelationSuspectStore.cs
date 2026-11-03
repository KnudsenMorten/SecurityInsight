using System.Globalization;
using System.Text.Json;
using SI.Management.Web.Data;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Changes;

/// One CI of a suspect group (sidata.CiSuspect): the correlation gatekeeper's current finding, written by the data sync
/// (engine\pro-data\_shared\SI-CorrelationSuspects.ps1).
public sealed record CorrelationSuspectRow(string GroupKey, string Rule, string Severity, string? GroupLabel, string? Evidence, string CiId, string? Name,
    string? Class, string? AssetType, int? Tier, string? TierSetBy, int? OpenFindings, double? WeightedRiskScore, bool Anchored, int ActiveLinks,
    string? Role, bool Dismissed, long? DecisionId, DateTime? ComputedAt);

/// One suspect group: its CIs (most critical tier first) and what a person decided about it.
public sealed record CorrelationSuspectGroup(string GroupKey, string Rule, string Severity, string? Label, string? Evidence, bool Dismissed, long? DecisionId,
    IReadOnlyList<CorrelationSuspectRow> Members)
{
    /// The CIs carry different tiers -- the highest-impact signal (the most critical tier may sit on the wrong CI).
    public bool TierConflict => Members.Select(m => m.Tier).Distinct().Count() > 1;
    /// A person can decide about it (a placeholder name is fixed at its source, never merged).
    public bool Decidable => Rule is CorrelationSuspectStore.RuleHardId or CorrelationSuspectStore.RuleName;
    public IReadOnlyList<string> CiIds => Members.Select(m => m.CiId).ToList();
    public string Names => string.Join(" + ", Members.Select(m => string.IsNullOrWhiteSpace(m.Name) ? m.CiId : m.Name));
}

/// One decision a person made about a group (sidata.CiSuspectDecision).
public sealed record CorrelationDecisionRow(long Id, string Verdict, string? GroupKey, string CiIds, string? Names, string Reason, string SetBy, DateTime? SetAt,
    bool Removed, string? RemovedBy, DateTime? RemovedAt, string? RemovedReason, string? SplitFromCiId)
{
    public IReadOnlyList<string> CiIdList => CiIds.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    /// "in force" | "split again" | "removed".
    public string StateText => !Removed ? "in force" : Verdict == CorrelationSuspectStore.VerdictSame ? "split again" : "removed";
}

/// <summary>
/// #1053 the C# twin of what a decision may be (the engine applies it: a "same" decision is an edge of the CI build's
/// grouping, Get-SICiGroupingStepSql; a removed one is split again, Get-SICiSplitDecisionSql). Sends nothing.
/// </summary>
public static class CorrelationDecisionValidator
{
    public const int MaxCiId = 64, MaxReason = 1000;

    public static IReadOnlyList<string> Validate(string? verdict, IReadOnlyList<string> ciIds, string? reason)
    {
        var why = new List<string>();
        if (verdict is not (CorrelationSuspectStore.VerdictSame or CorrelationSuspectStore.VerdictNotSame))
            why.Add("say whether the CIs are the same machine or not");
        var ids = ciIds.Where(s => !string.IsNullOrWhiteSpace(s)).Select(s => s.Trim()).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (ids.Count < 2) why.Add("a decision names two or more CIs");
        if (ids.Any(s => s.Length > MaxCiId)) why.Add("a CI id is at most 64 characters");
        var r = (reason ?? "").Trim();
        if (r.Length < 3) why.Add("give a reason (at least 3 characters) -- it is kept with the decision and on the audit trail");
        else if (r.Length > MaxReason) why.Add($"the reason is longer than {MaxReason} characters");
        return why;
    }
}

/// <summary>
/// #1053 the correlation gatekeeper in the Pro database: reads the current suspects (sidata.CiSuspect) and the decisions,
/// and writes a decision (sidata.CiSuspectDecision + the CIs and their current records, sidata.CiSuspectDecisionRecord) or
/// removes one (soft) -- each in ONE transaction with its cfg.ChangeLog row (Scope 'ci', Kind 'cisuspect'). A "same" decision
/// makes the next CI build merge the records; removing it splits them again (SplitFromCiId = the CI they are merged into
/// now, when the merge was built). Nothing here is called except through Review &amp; commit (CorrelationDecisionChanges).
/// </summary>
public sealed class CorrelationSuspectStore
{
    public const string Kind = "cisuspect";
    public const string RuleHardId = "hardid", RuleName = "name", RulePlaceholder = "placeholder";
    public const string VerdictSame = "same", VerdictNotSame = "not_same";
    public const string MissingTableMessage = "This database has no correlation suspects tables yet (sidata.CiSuspect, sidata.CiSuspectDecision) -- they arrive with the next update of the database schema.";
    /// Removed decisions stay listed this long (the history beyond it is in the audit trail and the change log).
    public const int RemovedListDays = 90;

    public const string ExistsSql = "SELECT CASE WHEN OBJECT_ID(N'sidata.CiSuspect') IS NULL OR OBJECT_ID(N'sidata.CiSuspectDecision') IS NULL OR OBJECT_ID(N'sidata.CiSuspectDecisionRecord') IS NULL THEN 0 ELSE 1 END AS HasTable;";

    /// Every suspect of the current set: the gatekeeper's result of the latest data sync, high severity first.
    public const string ListSql = """
IF OBJECT_ID(N'sidata.CiSuspect') IS NOT NULL
SELECT s.GroupKey, s.[Rule], s.Severity, s.GroupLabel, s.Evidence, s.CiId, s.Name, s.Class, s.AssetType, CONVERT(int, s.Tier) AS Tier, s.TierSetBy, s.OpenFindings,
       s.WeightedRiskScore, CONVERT(int, s.Anchored) AS Anchored, s.ActiveLinks, s.[Role], CONVERT(int, s.Dismissed) AS Dismissed, s.DecisionId, s.ComputedAt
FROM sidata.CiSuspect AS s
ORDER BY CASE s.Severity WHEN N'high' THEN 0 WHEN N'medium' THEN 1 ELSE 2 END, s.[Rule], s.GroupKey, s.Tier, s.CiId;
""";

    /// The suspects one CI is part of (its badge on the CI page).
    public const string ForCiSql = """
IF OBJECT_ID(N'sidata.CiSuspect') IS NOT NULL
SELECT s.GroupKey, s.[Rule], s.Severity, s.GroupLabel, s.Evidence, s.CiId, s.Name, s.Class, s.AssetType, CONVERT(int, s.Tier) AS Tier, s.TierSetBy, s.OpenFindings,
       s.WeightedRiskScore, CONVERT(int, s.Anchored) AS Anchored, s.ActiveLinks, s.[Role], CONVERT(int, s.Dismissed) AS Dismissed, s.DecisionId, s.ComputedAt
FROM sidata.CiSuspect AS s
WHERE s.GroupKey IN (SELECT GroupKey FROM sidata.CiSuspect WHERE CiId = @CiId)
ORDER BY s.GroupKey, s.Tier, s.CiId;
""";

    public const string DecisionsSql = """
IF OBJECT_ID(N'sidata.CiSuspectDecision') IS NOT NULL
SELECT d.DecisionId, d.Verdict, d.GroupKey, d.CiIds, d.Names, d.Reason, d.SetBy, d.SetAt, CONVERT(int, d.Removed) AS Removed, d.RemovedBy, d.RemovedAt, d.RemovedReason, d.SplitFromCiId
FROM sidata.CiSuspectDecision AS d
WHERE d.Removed = 0 OR d.RemovedAt >= DATEADD(day, -@RemovedDays, SYSUTCDATETIME())
ORDER BY d.Removed, d.SetAt DESC, d.DecisionId DESC;
""";

    public const string ReadSql = """
IF OBJECT_ID(N'sidata.CiSuspectDecision') IS NOT NULL
SELECT d.DecisionId, d.Verdict, d.GroupKey, d.CiIds, d.Names, d.Reason, d.SetBy, d.SetAt, CONVERT(int, d.Removed) AS Removed, d.RemovedBy, d.RemovedAt, d.RemovedReason, d.SplitFromCiId
FROM sidata.CiSuspectDecision AS d WHERE d.DecisionId = @Id;
""";

    /// <summary>
    /// A decision: refused (Stale) when one in force already names every one of these CIs; else the decision, a row per CI
    /// (RecordKey '') and per CURRENT record of each CI (sidata.CiRecord) -- the decision sticks to the records -- and its
    /// cfg.ChangeLog row, in one transaction. @CiIds: a JSON array of CI ids.
    /// </summary>
    public const string DecideSql = """
SET XACT_ABORT ON;
IF OBJECT_ID(N'sidata.CiSuspectDecision') IS NULL OR OBJECT_ID(N'sidata.CiSuspectDecisionRecord') IS NULL OR OBJECT_ID(N'cfg.ChangeLog') IS NULL
BEGIN
    SELECT N'Missing' AS Outcome;
    RETURN;
END;
DECLARE @ci TABLE (CiId NVARCHAR(64) NOT NULL PRIMARY KEY);
INSERT @ci (CiId) SELECT DISTINCT LEFT(LTRIM(RTRIM(j.[value])), 64) FROM OPENJSON(@CiIds) AS j WHERE LTRIM(RTRIM(j.[value])) <> N'';
DECLARE @n INT = (SELECT COUNT(*) FROM @ci);
BEGIN TRAN;
IF EXISTS (SELECT 1 FROM sidata.CiSuspectDecision d WITH (UPDLOCK, HOLDLOCK)
           WHERE d.Removed = 0 AND (SELECT COUNT(*) FROM sidata.CiSuspectDecisionRecord x JOIN @ci c ON c.CiId = x.CiId
                                    WHERE x.DecisionId = d.DecisionId AND x.RecordKey = N'') >= @n)
BEGIN
    COMMIT;
    SELECT N'Stale' AS Outcome;
    RETURN;
END;
DECLARE @names NVARCHAR(2000) = (SELECT LEFT(STRING_AGG(CONVERT(NVARCHAR(MAX), COALESCE(k.Name, c.CiId)), N' + ') WITHIN GROUP (ORDER BY c.CiId), 2000)
                                 FROM @ci c LEFT JOIN sidata.Ci k ON k.CiId = c.CiId);
DECLARE @ids NVARCHAR(1000) = (SELECT LEFT(STRING_AGG(CONVERT(NVARCHAR(MAX), c.CiId), N',') WITHIN GROUP (ORDER BY c.CiId), 1000) FROM @ci c);
INSERT sidata.CiSuspectDecision (Verdict, GroupKey, CiIds, Names, Reason, SetBy) VALUES (@Verdict, @GroupKey, @ids, @names, @Reason, @By);
DECLARE @id BIGINT = SCOPE_IDENTITY();
INSERT sidata.CiSuspectDecisionRecord (DecisionId, CiId, RecordKey) SELECT @id, c.CiId, N'' FROM @ci c;
INSERT sidata.CiSuspectDecisionRecord (DecisionId, CiId, RecordKey)
SELECT DISTINCT @id, c.CiId, r.RecordKey FROM @ci c JOIN sidata.CiRecord r ON r.CiId = c.CiId;
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (LEFT(N'suspect|' + CONVERT(NVARCHAR(20), @id), 128), N'ci', N'cisuspect', N'Set', NULL,
        LEFT(CASE WHEN @Verdict = N'same' THEN N'the same machine (the next CI build merges them): ' ELSE N'not the same machine: ' END + @names, 4000), @By, LEFT(@Reason, 400));
COMMIT;
SELECT N'Saved' AS Outcome, @id AS DecisionId;
""";

    /// <summary>
    /// Remove (soft) one decision. A "same" decision is SPLIT AGAIN: SplitFromCiId = the CI that holds most of its records
    /// now (the merged CI, once the CI build merged them; none before -- then removing the edge is all there is to undo).
    /// </summary>
    public const string RemoveSql = """
SET XACT_ABORT ON;
IF OBJECT_ID(N'sidata.CiSuspectDecision') IS NULL OR OBJECT_ID(N'cfg.ChangeLog') IS NULL
BEGIN
    SELECT N'Missing' AS Outcome;
    RETURN;
END;
BEGIN TRAN;
DECLARE @verdict NVARCHAR(16) = NULL, @names NVARCHAR(2000) = NULL;
SELECT @verdict = Verdict, @names = Names FROM sidata.CiSuspectDecision WITH (UPDLOCK, HOLDLOCK) WHERE DecisionId = @Id AND Removed = 0;
IF @verdict IS NULL
BEGIN
    COMMIT;
    SELECT N'Stale' AS Outcome;
    RETURN;
END;
DECLARE @into NVARCHAR(64) = NULL;
IF @verdict = N'same'
    SELECT TOP (1) @into = r.CiId
    FROM sidata.CiSuspectDecisionRecord x JOIN sidata.CiRecord r ON r.RecordKey = x.RecordKey
    WHERE x.DecisionId = @Id AND x.RecordKey <> N'' AND r.CiId IS NOT NULL
    GROUP BY r.CiId
    HAVING COUNT(DISTINCT x.CiId) > 1
    ORDER BY COUNT(*) DESC, r.CiId;
UPDATE sidata.CiSuspectDecision SET Removed = 1, RemovedBy = @By, RemovedAt = SYSUTCDATETIME(), RemovedReason = @Reason, SplitFromCiId = @into WHERE DecisionId = @Id;
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (LEFT(N'suspect|' + CONVERT(NVARCHAR(20), @Id), 128), N'ci', N'cisuspect', N'Reset',
        LEFT(CASE WHEN @verdict = N'same' THEN N'the same machine: ' ELSE N'not the same machine: ' END + ISNULL(@names, N''), 4000),
        CASE WHEN @verdict = N'same' THEN N'(split again -- the next CI build builds them as separate CIs)' ELSE N'(removed -- the gatekeeper warns about them again)' END, @By, LEFT(@Reason, 400));
COMMIT;
SELECT N'Saved' AS Outcome, @into AS SplitFromCiId;
""";

    private readonly ISqlExecutor _sql;
    public CorrelationSuspectStore(ISqlExecutor sql) => _sql = sql;

    private static bool Flag(SqlRow r, string k) => (r.Long(k) ?? 0) != 0;
    private static int? Int(SqlRow r, string k) => r.Long(k) is { } v ? (int)v : null;
    private static double? Dbl(SqlRow r, string k) => (r.TryGetValue(k, out var raw) ? raw : null) switch
    {
        null => null,
        double d => d,
        float f => f,
        decimal m => (double)m,
        var o => double.TryParse(Convert.ToString(o, CultureInfo.InvariantCulture), NumberStyles.Float, CultureInfo.InvariantCulture, out var x) ? x : null,
    };

    public static CorrelationSuspectRow MapSuspect(SqlRow r) => new(r.Str("GroupKey") ?? "", r.Str("Rule") ?? "", r.Str("Severity") ?? "", r.Str("GroupLabel"), r.Str("Evidence"),
        r.Str("CiId") ?? "", r.Str("Name"), r.Str("Class"), r.Str("AssetType"), Int(r, "Tier"), r.Str("TierSetBy"), Int(r, "OpenFindings"), Dbl(r, "WeightedRiskScore"),
        Flag(r, "Anchored"), Int(r, "ActiveLinks") ?? 0, r.Str("Role"), Flag(r, "Dismissed"), r.Long("DecisionId"), r.Date("ComputedAt"));

    public static CorrelationDecisionRow MapDecision(SqlRow r) => new(r.Long("DecisionId") ?? 0, r.Str("Verdict") ?? "", r.Str("GroupKey"), r.Str("CiIds") ?? "", r.Str("Names"),
        r.Str("Reason") ?? "", r.Str("SetBy") ?? "", r.Date("SetAt"), Flag(r, "Removed"), r.Str("RemovedBy"), r.Date("RemovedAt"), r.Str("RemovedReason"), r.Str("SplitFromCiId"));

    /// PURE. The rows as groups, in the order they came (high severity first), each group's CIs by tier then name.
    public static IReadOnlyList<CorrelationSuspectGroup> Groups(IEnumerable<CorrelationSuspectRow> rows) => rows
        .GroupBy(r => r.GroupKey, StringComparer.Ordinal)
        .Select(g =>
        {
            var f = g.First();
            return new CorrelationSuspectGroup(g.Key, f.Rule, f.Severity, f.GroupLabel, f.Evidence, f.Dismissed, f.DecisionId,
                g.OrderBy(m => m.Tier ?? 9).ThenBy(m => m.Name, StringComparer.OrdinalIgnoreCase).ThenBy(m => m.CiId, StringComparer.Ordinal).ToList());
        })
        .ToList();

    public async Task<bool> TableExistsAsync(CancellationToken ct)
    {
        var rows = await _sql.QueryAsync(ExistsSql, new Dictionary<string, object?>(), ct);
        return rows.Count > 0 && rows[0].Long("HasTable") == 1;
    }

    public async Task<IReadOnlyList<CorrelationSuspectGroup>> ListAsync(CancellationToken ct) =>
        Groups((await _sql.QueryAsync(ListSql, new Dictionary<string, object?>(), ct)).Select(MapSuspect));

    public async Task<IReadOnlyList<CorrelationSuspectGroup>> ForCiAsync(string ciId, CancellationToken ct) =>
        Groups((await _sql.QueryAsync(ForCiSql, new Dictionary<string, object?> { ["CiId"] = ciId }, ct)).Select(MapSuspect));

    public async Task<IReadOnlyList<CorrelationDecisionRow>> DecisionsAsync(CancellationToken ct) =>
        (await _sql.QueryAsync(DecisionsSql, new Dictionary<string, object?> { ["RemovedDays"] = RemovedListDays }, ct)).Select(MapDecision).ToList();

    public async Task<CorrelationDecisionRow?> ReadAsync(long id, CancellationToken ct) =>
        (await _sql.QueryAsync(ReadSql, new Dictionary<string, object?> { ["Id"] = id }, ct)).Select(MapDecision).FirstOrDefault();

    private static string Clip(string s, int n) => s.Length > n ? s[..n] : s;

    /// Record a decision about these CIs (verdict same | not_same).
    public async Task<WriteResult> DecideAsync(string verdict, IReadOnlyList<string> ciIds, string? groupKey, string reason, string by, CancellationToken ct)
    {
        var why = CorrelationDecisionValidator.Validate(verdict, ciIds, reason);
        if (why.Count > 0) return new WriteResult(WriteStatus.Refused, string.Join("; ", why));
        if (string.IsNullOrWhiteSpace(by)) return new WriteResult(WriteStatus.Refused, "the signed-in user has no name to record");
        var rows = await _sql.QueryAsync(DecideSql, new Dictionary<string, object?>
        {
            ["Verdict"] = verdict, ["CiIds"] = JsonSerializer.Serialize(ciIds.Select(s => s.Trim()).Distinct(StringComparer.OrdinalIgnoreCase).ToArray()),
            ["GroupKey"] = string.IsNullOrWhiteSpace(groupKey) ? null : Clip(groupKey.Trim(), 80), ["Reason"] = Clip(reason.Trim(), 1000), ["By"] = Clip(by, 256),
        }, ct);
        return Outcome(rows, verdict == VerdictSame ? "the decision (the same machine) saved -- the next CI build merges them" : "the decision (not the same machine) saved -- they are no longer warned about");
    }

    /// Remove (soft) one decision: a "same" one is split again by the next CI build.
    public async Task<WriteResult> RemoveAsync(long id, string reason, string by, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(reason) || reason.Trim().Length < 3) return new WriteResult(WriteStatus.Refused, "give a reason (at least 3 characters)");
        if (string.IsNullOrWhiteSpace(by)) return new WriteResult(WriteStatus.Refused, "the signed-in user has no name to record");
        var rows = await _sql.QueryAsync(RemoveSql, new Dictionary<string, object?> { ["Id"] = id, ["Reason"] = Clip(reason.Trim(), 1000), ["By"] = Clip(by, 256) }, ct);
        return Outcome(rows, "the decision removed -- the next CI build and data sync take it into account");
    }

    private static WriteResult Outcome(IReadOnlyList<SqlRow> rows, string what) => (rows.Count > 0 ? rows[0].Str("Outcome") : null) switch
    {
        "Saved" => new WriteResult(WriteStatus.Saved, what),
        "Stale" => new WriteResult(WriteStatus.Stale, "a decision in force already names these CIs, or the decision was removed meanwhile -- nothing was written; open the page again"),
        "Missing" => new WriteResult(WriteStatus.Refused, MissingTableMessage + " Nothing was written."),
        _ => throw new InvalidOperationException("the correlation decision write returned no outcome"),
    };
}

/// <summary>
/// #1053 the correlation decisions through THE staging (Review &amp; commit): "the same machine" (the next CI build merges
/// them), "not the same machine" (no longer warned about), or remove a decision (a "same" one is split again). Validated
/// when staged, previewed before -> after, written by <see cref="CorrelationSuspectStore"/> in one transaction with its
/// cfg.ChangeLog row, in the signed-in name. Admin only (ChangeAccess: Administer).
/// </summary>
public sealed class CorrelationDecisionChanges : IStagedChangeHandler
{
    public const string ChangeKind = "ci-suspect-decision";
    private readonly CorrelationSuspectStore _store;
    public CorrelationDecisionChanges(CorrelationSuspectStore store) => _store = store;

    public bool Handles(string kind) => kind == ChangeKind;

    public static string VerdictText(string verdict) => verdict == CorrelationSuspectStore.VerdictSame ? "the same machine" : "not the same machine";

    /// Stage a decision about the CIs of one group.
    public async Task<(StagedChange? Change, IReadOnlyList<string> Problems)> NewDecisionAsync(string? verdict, IReadOnlyList<string> ciIds, string? groupKey, string? names, string? reason, CancellationToken ct)
    {
        var why = CorrelationDecisionValidator.Validate(verdict, ciIds, reason);
        if (why.Count > 0) return (null, why);
        if (!await _store.TableExistsAsync(ct)) return (null, new[] { CorrelationSuspectStore.MissingTableMessage });
        var ids = ciIds.Select(s => s.Trim()).Where(s => s.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(s => s, StringComparer.Ordinal).ToList();
        var who = string.IsNullOrWhiteSpace(names) ? string.Join(" + ", ids) : names.Trim();
        return (new StagedChange
        {
            Kind = ChangeKind,
            Title = (verdict == CorrelationSuspectStore.VerdictSame ? "The same machine (merge): " : "Not the same machine: ") + who,
            Data = new(StringComparer.Ordinal)
            {
                ["action"] = "decide", ["key"] = "suspect:" + string.Join(",", ids), ["verdict"] = verdict, ["ciIds"] = string.Join(",", ids),
                ["groupKey"] = groupKey, ["names"] = who, ["reason"] = reason!.Trim(),
            },
        }, Array.Empty<string>());
    }

    /// Stage the removal (soft) of one decision -- for a "same" one, the split.
    public async Task<(StagedChange? Change, IReadOnlyList<string> Problems)> NewRemoveAsync(long id, string? reason, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(reason) || reason.Trim().Length < 3) return (null, new[] { "give a reason (at least 3 characters)" });
        if (!await _store.TableExistsAsync(ct)) return (null, new[] { CorrelationSuspectStore.MissingTableMessage });
        var cur = await _store.ReadAsync(id, ct);
        if (cur is null || cur.Removed) return (null, new[] { "that decision does not exist or is already removed" });
        return (new StagedChange
        {
            Kind = ChangeKind,
            Title = (cur.Verdict == CorrelationSuspectStore.VerdictSame ? "Split again: " : "Remove the decision \"not the same machine\": ") + (cur.Names ?? cur.CiIds),
            Data = new(StringComparer.Ordinal)
            {
                ["action"] = "remove", ["key"] = "suspect-decision:" + id.ToString(CultureInfo.InvariantCulture), ["id"] = id.ToString(CultureInfo.InvariantCulture),
                ["verdict"] = cur.Verdict, ["names"] = cur.Names, ["reason"] = reason.Trim(),
            },
        }, Array.Empty<string>());
    }

    public async Task<ChangePreview> PreviewAsync(StagedChange c, CancellationToken ct)
    {
        var why = new List<string>(); var warnings = new List<string>();
        if (!await _store.TableExistsAsync(ct)) return new ChangePreview(c, "", "", new[] { CorrelationSuspectStore.MissingTableMessage }, warnings);
        if (c.Get("action") == "remove")
        {
            var cur = long.TryParse(c.Get("id"), NumberStyles.Integer, CultureInfo.InvariantCulture, out var id) ? await _store.ReadAsync(id, ct) : null;
            if (cur is null || cur.Removed) why.Add("the decision is already removed -- discard this change");
            if (cur?.Verdict == CorrelationSuspectStore.VerdictSame)
                warnings.Add("Split again: the next CI build builds these as separate CIs again; the side that was not the merged CI gets its own id back. The gatekeeper may list them as suspects again.");
            return new ChangePreview(c, cur is null ? "(none)" : $"{VerdictText(cur.Verdict)}: {cur.Names ?? cur.CiIds} -- decided by {cur.SetBy}\nReason: {cur.Reason}",
                cur?.Verdict == CorrelationSuspectStore.VerdictSame ? "(split again -- separate CIs from the next CI build)" : "(removed -- the gatekeeper warns about them again)", why, warnings);
        }
        var ids = (c.Get("ciIds") ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        why.AddRange(CorrelationDecisionValidator.Validate(c.Get("verdict"), ids, c.Get("reason")));
        if (c.Get("verdict") == CorrelationSuspectStore.VerdictSame)
            warnings.Add("The next CI build MERGES these CIs into one: the oldest CI id is kept, the others are retired; their findings, links and tier follow the merged CI. It can be undone (Split again).");
        return new ChangePreview(c, "(no decision -- the gatekeeper warns about them)", $"{VerdictText(c.Get("verdict") ?? "")}: {c.Get("names")}\nReason: {c.Get("reason")}", why, warnings);
    }

    public async Task<WriteResult> CommitAsync(StagedChange c, string by, CancellationToken ct)
    {
        if (c.Get("action") == "remove")
            return long.TryParse(c.Get("id"), NumberStyles.Integer, CultureInfo.InvariantCulture, out var id)
                ? await _store.RemoveAsync(id, c.Get("reason") ?? "", by, ct)
                : new WriteResult(WriteStatus.Refused, "the change names no decision");
        var ids = (c.Get("ciIds") ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return await _store.DecideAsync(c.Get("verdict") ?? "", ids, c.Get("groupKey"), c.Get("reason") ?? "", by, ct);
    }
}
