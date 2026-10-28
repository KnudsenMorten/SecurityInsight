using System.Globalization;
using System.Text.RegularExpressions;
using SI.Management.Web.Data;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Changes;

/// One manual CI override (sidata.CiOverride): a field of one CI an Admin set by hand, with who, why and until when.
public sealed record CiOverrideRow(long Id, string CiId, string Field, string? Value, string Reason, string SetBy, DateTime? SetAt, DateTime? ExpiresAt,
    bool Removed, string? RemovedBy, DateTime? RemovedAt)
{
    /// Past its expiry: shown as expired, and no longer wins (the CI build reads only overrides in force -- Get-SICiOverrideReadSql).
    public bool Expired(DateTime nowUtc) => ExpiresAt is { } e && e <= nowUtc;
    /// In force: not removed and not expired -- the value the next CI build applies over the rules.
    public bool Active(DateTime nowUtc) => !Removed && !Expired(nowUtc);
    /// "active" | "expired" | "removed".
    public string StateText(DateTime nowUtc) => Removed ? "removed" : Expired(nowUtc) ? "expired" : "active";
}

/// <summary>
/// #462 the C# twin of the override rules of engine\data-model\SI-CiRules.ps1 (ConvertTo-SICiOverrideIndex): which fields
/// an Admin may override on a CI, and what a valid value is. Sends nothing.
/// </summary>
public static partial class CiOverrideValidator
{
    public const int MaxCiId = 64, MaxField = 64, MaxValue = 400, MaxReason = 1000;

    /// The overridable fields -- exactly the pattern the CI build accepts (si_lifecycle is evidence, never a decision).
    [GeneratedRegex(@"^(si_tier|si_purpose|si_category|si_department|si_cmdb_[a-z_]+)$", RegexOptions.CultureInvariant)]
    public static partial Regex FieldPattern();

    /// The fields the page offers in its picker (any si_cmdb_* field may also be typed).
    public static readonly string[] Offered = ["si_tier", "si_purpose", "si_category", "si_department", "si_cmdb_criticality", "si_cmdb_data_sensitivity", "si_cmdb_name", "si_cmdb_id"];

    /// The reasons an override is refused (empty = accepted).
    public static IReadOnlyList<string> Validate(string? ciId, string? field, string? value, string? reason, DateTime? expiresAtUtc, DateTime nowUtc)
    {
        var why = new List<string>();
        if (string.IsNullOrWhiteSpace(ciId) || ciId.Trim().Length > MaxCiId) why.Add("name the CI (its id, at most 64 characters)");
        var f = (field ?? "").Trim().ToLowerInvariant();
        if (!FieldPattern().IsMatch(f)) why.Add($"'{field}' cannot be overridden -- tier, purpose, category, department or a CMDB field (si_cmdb_...)");
        var v = (value ?? "").Trim();
        if (v.Length == 0) why.Add("give the value the CI should have");
        else if (v.Length > MaxValue) why.Add($"the value is longer than {MaxValue} characters");
        if (f == "si_tier" && !(int.TryParse(v, NumberStyles.Integer, CultureInfo.InvariantCulture, out var t) && t is >= 0 and <= 3 && t.ToString(CultureInfo.InvariantCulture) == v))
            why.Add("a tier is 0, 1, 2 or 3");
        var r = (reason ?? "").Trim();
        if (r.Length < 3) why.Add("give a reason (at least 3 characters) -- it is shown on the CI");
        else if (r.Length > MaxReason) why.Add($"the reason is longer than {MaxReason} characters");
        if (expiresAtUtc is { } e && e <= nowUtc) why.Add("the expiry is in the past -- leave it empty for an override without an end, or pick a later date");
        return why;
    }
}

/// <summary>
/// #462 manual CI overrides: reads and writes sidata.CiOverride (the install database; the CI build applies the overrides in
/// force over the rules, precedence 1). Every write is ONE transaction with its cfg.ChangeLog row (Name = '&lt;ci&gt;|&lt;field&gt;',
/// Scope 'ci', Kind 'cioverride'). A new override for a field REPLACES the one in force (that one is removed, soft, in the
/// same transaction -- one override per CI and field); a removal is SOFT (Removed = 1, RemovedBy, RemovedAt), as the schema
/// defines, so the history stays. Optimistic: a write carries the id of the override in force when it was staged (null =
/// none) and is Stale when that changed. Nothing here is called except through Review &amp; commit (CiOverrideChanges).
/// </summary>
public sealed class CiOverrideStore
{
    public const string Kind = "cioverride";
    public const string MissingTableMessage = "This database has no manual CI overrides table yet (sidata.CiOverride) -- it arrives with the next update of the database schema.";
    /// Removed overrides stay listed this long (the history beyond it is in the audit trail and the change log).
    public const int RemovedListDays = 90;

    public const string ExistsSql = "SELECT CASE WHEN OBJECT_ID(N'sidata.CiOverride') IS NULL THEN 0 ELSE 1 END AS HasTable;";

    public const string ListSql = """
IF OBJECT_ID(N'sidata.CiOverride') IS NOT NULL
SELECT TOP (2000) OverrideId, CiId, Field, Value, Reason, SetBy, SetAt, ExpiresAt, CONVERT(int, Removed) AS Removed, RemovedBy, RemovedAt
FROM sidata.CiOverride
WHERE (@CiId IS NULL OR CiId = @CiId)
  AND (Removed = 0 OR RemovedAt >= DATEADD(day, -@RemovedDays, SYSUTCDATETIME()))
ORDER BY Removed, CiId, Field, SetAt DESC;
""";

    public const string ReadSql = """
IF OBJECT_ID(N'sidata.CiOverride') IS NOT NULL
SELECT OverrideId, CiId, Field, Value, Reason, SetBy, SetAt, ExpiresAt, CONVERT(int, Removed) AS Removed, RemovedBy, RemovedAt
FROM sidata.CiOverride WHERE OverrideId = @Id;
""";

    /// The override in force for one CI and field (not removed; an expired one counts too -- a new one replaces it).
    public const string CurrentSql = """
IF OBJECT_ID(N'sidata.CiOverride') IS NOT NULL
SELECT TOP (1) OverrideId, CiId, Field, Value, Reason, SetBy, SetAt, ExpiresAt, CONVERT(int, Removed) AS Removed, RemovedBy, RemovedAt
FROM sidata.CiOverride WHERE CiId = @CiId AND Field = @Field AND Removed = 0 ORDER BY SetAt DESC, OverrideId DESC;
""";

    public const string SetSql = """
SET XACT_ABORT ON;
IF OBJECT_ID(N'sidata.CiOverride') IS NULL OR OBJECT_ID(N'cfg.ChangeLog') IS NULL
BEGIN
    SELECT N'Missing' AS Outcome;
    RETURN;
END;
BEGIN TRAN;
DECLARE @cur bigint = NULL, @old nvarchar(max) = NULL;
SELECT TOP (1) @cur = OverrideId, @old = COALESCE(Value, N'') + N' (' + Reason + COALESCE(N'; until ' + CONVERT(nvarchar(30), ExpiresAt, 126), N'') + N')'
FROM sidata.CiOverride WITH (UPDLOCK, HOLDLOCK) WHERE CiId = @CiId AND Field = @Field AND Removed = 0 ORDER BY SetAt DESC, OverrideId DESC;
IF (@Expected IS NULL AND @cur IS NOT NULL) OR (@Expected IS NOT NULL AND (@cur IS NULL OR @cur <> @Expected))
BEGIN
    COMMIT;
    SELECT N'Stale' AS Outcome;
    RETURN;
END;
UPDATE sidata.CiOverride SET Removed = 1, RemovedBy = @By, RemovedAt = SYSUTCDATETIME() WHERE CiId = @CiId AND Field = @Field AND Removed = 0;
INSERT sidata.CiOverride (CiId, Field, Value, Reason, SetBy, ExpiresAt) VALUES (@CiId, @Field, @Value, @Reason, @By, @ExpiresAt);
DECLARE @new bigint = SCOPE_IDENTITY();
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (LEFT(@CiId + N'|' + @Field, 128), N'ci', N'cioverride', N'Set', @old,
        @Value + COALESCE(N' (until ' + CONVERT(nvarchar(30), @ExpiresAt, 126) + N')', N''), @By, LEFT(@Reason, 400));
COMMIT;
SELECT N'Saved' AS Outcome, @new AS OverrideId;
""";

    public const string RemoveSql = """
SET XACT_ABORT ON;
IF OBJECT_ID(N'sidata.CiOverride') IS NULL OR OBJECT_ID(N'cfg.ChangeLog') IS NULL
BEGIN
    SELECT N'Missing' AS Outcome;
    RETURN;
END;
BEGIN TRAN;
DECLARE @ci nvarchar(64) = NULL, @field nvarchar(64) = NULL, @old nvarchar(max) = NULL;
SELECT @ci = CiId, @field = Field, @old = COALESCE(Value, N'') + N' (' + Reason + N')'
FROM sidata.CiOverride WITH (UPDLOCK, HOLDLOCK) WHERE OverrideId = @Id AND Removed = 0;
IF @ci IS NULL
BEGIN
    COMMIT;
    SELECT N'Stale' AS Outcome;
    RETURN;
END;
UPDATE sidata.CiOverride SET Removed = 1, RemovedBy = @By, RemovedAt = SYSUTCDATETIME() WHERE OverrideId = @Id;
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (LEFT(@ci + N'|' + @field, 128), N'ci', N'cioverride', N'Reset', @old, N'(removed -- the rules decide again)', @By, LEFT(@Reason, 400));
COMMIT;
SELECT N'Saved' AS Outcome;
""";

    private readonly ISqlExecutor _sql;
    public CiOverrideStore(ISqlExecutor sql) => _sql = sql;

    public static CiOverrideRow Map(SqlRow r) => new(r.Long("OverrideId") ?? 0, r.Str("CiId") ?? "", r.Str("Field") ?? "", r.Str("Value"), r.Str("Reason") ?? "",
        r.Str("SetBy") ?? "", r.Date("SetAt"), r.Date("ExpiresAt"), (r.Long("Removed") ?? 0) != 0, r.Str("RemovedBy"), r.Date("RemovedAt"));

    public async Task<bool> TableExistsAsync(CancellationToken ct)
    {
        var rows = await _sql.QueryAsync(ExistsSql, new Dictionary<string, object?>(), ct);
        return rows.Count > 0 && rows[0].Long("HasTable") == 1;
    }

    /// Every override (of one CI when ciId is given): those in force and expired ones, plus those removed in the last 90 days.
    public async Task<IReadOnlyList<CiOverrideRow>> ListAsync(string? ciId, CancellationToken ct) =>
        (await _sql.QueryAsync(ListSql, new Dictionary<string, object?> { ["CiId"] = string.IsNullOrWhiteSpace(ciId) ? null : ciId.Trim(), ["RemovedDays"] = RemovedListDays }, ct)).Select(Map).ToList();

    public async Task<CiOverrideRow?> ReadAsync(long id, CancellationToken ct) =>
        (await _sql.QueryAsync(ReadSql, new Dictionary<string, object?> { ["Id"] = id }, ct)).Select(Map).FirstOrDefault();

    public async Task<CiOverrideRow?> CurrentAsync(string ciId, string field, CancellationToken ct) =>
        (await _sql.QueryAsync(CurrentSql, new Dictionary<string, object?> { ["CiId"] = ciId, ["Field"] = field }, ct)).Select(Map).FirstOrDefault();

    private static string Clip(string s, int n) => s.Length > n ? s[..n] : s;

    /// Set (or replace) the override of one CI field. expectedId = the override in force when it was staged (null = none).
    public async Task<WriteResult> SetAsync(string ciId, string field, string value, string reason, DateTime? expiresAtUtc, long? expectedId, string by, CancellationToken ct)
    {
        var why = CiOverrideValidator.Validate(ciId, field, value, reason, expiresAtUtc, DateTime.UtcNow);
        if (why.Count > 0) return new WriteResult(WriteStatus.Refused, string.Join("; ", why));
        if (string.IsNullOrWhiteSpace(by)) return new WriteResult(WriteStatus.Refused, "the signed-in user has no name to record");
        var rows = await _sql.QueryAsync(SetSql, new Dictionary<string, object?>
        {
            ["CiId"] = ciId.Trim(), ["Field"] = field.Trim().ToLowerInvariant(), ["Value"] = value.Trim(), ["Reason"] = reason.Trim(),
            ["ExpiresAt"] = expiresAtUtc, ["Expected"] = expectedId, ["By"] = Clip(by, 256),
        }, ct);
        return Outcome(rows, $"the override of {field} on {ciId}");
    }

    /// Remove (soft) one override: the rules decide the field again on the next CI build.
    public async Task<WriteResult> RemoveAsync(long id, string reason, string by, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(reason) || reason.Trim().Length < 3) return new WriteResult(WriteStatus.Refused, "give a reason (at least 3 characters)");
        if (string.IsNullOrWhiteSpace(by)) return new WriteResult(WriteStatus.Refused, "the signed-in user has no name to record");
        var rows = await _sql.QueryAsync(RemoveSql, new Dictionary<string, object?> { ["Id"] = id, ["Reason"] = Clip(reason.Trim(), 1000), ["By"] = Clip(by, 256) }, ct);
        return Outcome(rows, "the override");
    }

    private static WriteResult Outcome(IReadOnlyList<SqlRow> rows, string what) => (rows.Count > 0 ? rows[0].Str("Outcome") : null) switch
    {
        "Saved" => new WriteResult(WriteStatus.Saved, what + " saved -- the next CI build applies it"),
        "Stale" => new WriteResult(WriteStatus.Stale, what + " changed since this was staged -- nothing was written; open it again and stage it again"),
        "Missing" => new WriteResult(WriteStatus.Refused, MissingTableMessage + " Nothing was written."),
        _ => throw new InvalidOperationException("the CI override write returned no outcome"),
    };
}

/// <summary>
/// #462 the manual CI overrides through THE staging (Review &amp; commit): set / replace one override, or remove one. Validated
/// when staged (a refused one is never staged), previewed before -> after, written by <see cref="CiOverrideStore"/> in one
/// transaction with its cfg.ChangeLog row, in the signed-in name. Admin only (ChangeAccess: Administer).
/// </summary>
public sealed class CiOverrideChanges : IStagedChangeHandler
{
    public const string ChangeKind = "ci-override";
    private readonly CiOverrideStore _store;
    public CiOverrideChanges(CiOverrideStore store) => _store = store;

    public bool Handles(string kind) => kind == ChangeKind;

    private static string Iso(DateTime? d) => d?.ToString("o", CultureInfo.InvariantCulture) ?? "";
    private static DateTime? ParseIso(string? s) =>
        DateTime.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var d) ? d : null;
    private static string Until(DateTime? d) => d is { } e ? "until " + e.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture) + " UTC" : "no end date";

    public static string Describe(CiOverrideRow r) => $"{r.Field} = {r.Value} -- set by {r.SetBy}, {Until(r.ExpiresAt)}\nReason: {r.Reason}";

    /// Stage a new or changed override of one CI field (it replaces the one in force).
    public async Task<(StagedChange? Change, IReadOnlyList<string> Problems)> NewSetAsync(string? ciId, string? field, string? value, string? reason, DateTime? expiresAtUtc, CancellationToken ct)
    {
        var why = CiOverrideValidator.Validate(ciId, field, value, reason, expiresAtUtc, DateTime.UtcNow);
        if (why.Count > 0) return (null, why);
        if (!await _store.TableExistsAsync(ct)) return (null, new[] { CiOverrideStore.MissingTableMessage });
        var ci = ciId!.Trim(); var f = field!.Trim().ToLowerInvariant(); var v = value!.Trim();
        var cur = await _store.CurrentAsync(ci, f, ct);
        if (cur is not null && cur.Active(DateTime.UtcNow) && cur.Value == v && cur.ExpiresAt == expiresAtUtc && cur.Reason == reason!.Trim())
            return (null, new[] { "nothing changed -- this is the override in force" });
        return (new StagedChange
        {
            Kind = ChangeKind,
            Title = (cur is null ? "Override " : "Change the override of ") + $"{f} on {ci} to {v}" + (expiresAtUtc is null ? "" : $" ({Until(expiresAtUtc)})"),
            Data = new(StringComparer.Ordinal)
            {
                ["action"] = "set", ["key"] = ci + "|" + f, ["ciId"] = ci, ["field"] = f, ["value"] = v, ["reason"] = reason!.Trim(), ["expiresAt"] = Iso(expiresAtUtc),
                ["expectedId"] = cur?.Id.ToString(CultureInfo.InvariantCulture),
            },
        }, Array.Empty<string>());
    }

    /// Stage the removal (soft) of one override.
    public async Task<(StagedChange? Change, IReadOnlyList<string> Problems)> NewRemoveAsync(long id, string? reason, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(reason) || reason.Trim().Length < 3) return (null, new[] { "give a reason (at least 3 characters)" });
        if (!await _store.TableExistsAsync(ct)) return (null, new[] { CiOverrideStore.MissingTableMessage });
        var cur = await _store.ReadAsync(id, ct);
        if (cur is null || cur.Removed) return (null, new[] { "that override does not exist or is already removed" });
        return (new StagedChange
        {
            Kind = ChangeKind, Title = $"Remove the override of {cur.Field} on {cur.CiId} ({cur.Value})",
            Data = new(StringComparer.Ordinal)
            {
                ["action"] = "remove", ["key"] = cur.CiId + "|" + cur.Field, ["id"] = id.ToString(CultureInfo.InvariantCulture), ["ciId"] = cur.CiId, ["field"] = cur.Field, ["reason"] = reason.Trim(),
            },
        }, Array.Empty<string>());
    }

    public async Task<ChangePreview> PreviewAsync(StagedChange c, CancellationToken ct)
    {
        var why = new List<string>(); var warnings = new List<string>();
        if (!await _store.TableExistsAsync(ct)) return new ChangePreview(c, "", "", new[] { CiOverrideStore.MissingTableMessage }, warnings);
        var ci = c.Get("ciId") ?? ""; var f = c.Get("field") ?? "";
        if (c.Get("action") == "remove")
        {
            var cur = long.TryParse(c.Get("id"), NumberStyles.Integer, CultureInfo.InvariantCulture, out var id) ? await _store.ReadAsync(id, ct) : null;
            if (cur is null || cur.Removed) why.Add("the override is already removed -- discard this change");
            return new ChangePreview(c, cur is null ? "(none)" : Describe(cur), "(removed -- the rules decide this field again on the next CI build)", why, warnings);
        }
        var exp = ParseIso(c.Get("expiresAt"));
        why.AddRange(CiOverrideValidator.Validate(ci, f, c.Get("value"), c.Get("reason"), exp, DateTime.UtcNow));
        var now = await _store.CurrentAsync(ci, f, ct);
        var expected = long.TryParse(c.Get("expectedId"), NumberStyles.Integer, CultureInfo.InvariantCulture, out var e) ? e : (long?)null;
        if (now?.Id != expected) why.Add("the override of this field changed since this was staged -- discard this change and stage it again");
        if (f == "si_tier") warnings.Add("A tier override wins over every tier rule until it is removed or expires; the CI shows it as set by an override, with your reason.");
        return new ChangePreview(c, now is null ? "(no override -- the rules decide)" : Describe(now),
            $"{f} = {c.Get("value")} -- {Until(exp)}\nReason: {c.Get("reason")}", why, warnings);
    }

    public async Task<WriteResult> CommitAsync(StagedChange c, string by, CancellationToken ct)
    {
        if (c.Get("action") == "remove")
            return long.TryParse(c.Get("id"), NumberStyles.Integer, CultureInfo.InvariantCulture, out var id)
                ? await _store.RemoveAsync(id, c.Get("reason") ?? "", by, ct)
                : new WriteResult(WriteStatus.Refused, "the change names no override");
        var expected = long.TryParse(c.Get("expectedId"), NumberStyles.Integer, CultureInfo.InvariantCulture, out var e) ? e : (long?)null;
        return await _store.SetAsync(c.Get("ciId") ?? "", c.Get("field") ?? "", c.Get("value") ?? "", c.Get("reason") ?? "", ParseIso(c.Get("expiresAt")), expected, by, ct);
    }
}
