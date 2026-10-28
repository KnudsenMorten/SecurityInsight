using System.Globalization;
using SI.Management.Web.Data;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Changes;

/// One vendor template row (cfg.Template) of a kind.
public sealed record ItemTemplateRow(string Key, string Body, string Format, int SortOrder, bool Retired, string? Source, string? Version);

/// The customer's state of one item (cfg.ItemOverride): override (their body) | disable | inherit. Version = RowVersion.
public sealed record ItemOverrideRow2(string Key, string State, string? Body, string Format, long Version, DateTime? UpdatedAt, string? UpdatedBy);

/// One cfg.Document of the kind (only 'rule' has documents -- the Pro-1b home of a customer rule).
public sealed record ItemDocumentRow(string Key, string Body, long Version, DateTime? UpdatedAt, string? UpdatedBy);

/// Everything stored for one kind.
public sealed record ItemSet(string Kind, bool Schema, IReadOnlyList<ItemTemplateRow> Templates, IReadOnlyList<ItemOverrideRow2> Overrides, IReadOnlyList<ItemDocumentRow> Documents)
{
    public ItemTemplateRow? Template(string key) => Templates.FirstOrDefault(t => string.Equals(t.Key, key, StringComparison.OrdinalIgnoreCase));
    public ItemOverrideRow2? Override(string key) => Overrides.FirstOrDefault(o => string.Equals(o.Key, key, StringComparison.OrdinalIgnoreCase));
    public ItemDocumentRow? Document(string key) => Documents.FirstOrDefault(d => string.Equals(d.Key, key, StringComparison.OrdinalIgnoreCase));
}

/// One item write. Home 'override' = cfg.ItemOverride (State override | disable | inherit = the row removed);
/// Home 'document' = cfg.Document (State override = Set, inherit = Reset). ExpectedVersion = the row's version when
/// the editor read it (null = no row then): a write over a row that moved on is refused as Stale.
public sealed record ItemWrite(string Kind, string Key, string Home, string State, string? Body, long? ExpectedVersion);

/// <summary>
/// The ONE storage seam of the profiling and tagging editors (rules, asset tagging, schema overlays): read a kind's
/// templates, overrides and documents; write ONE item in ONE transaction with its cfg.ChangeLog row and an optimistic
/// version check. The SQL lives in <see cref="SqlItemSource"/>; the tests and the E2E fixture server use an in-memory one.
/// </summary>
public interface IItemSource
{
    Task<ItemSet> LoadAsync(string kind, CancellationToken ct);
    Task<WriteResult> WriteAsync(ItemWrite w, string by, string reason, CancellationToken ct);
}

/// <summary>
/// cfg.Template / cfg.ItemOverride / cfg.Document through <see cref="ISqlExecutor"/>. The item write is the twin of
/// Set-SIProItem (engine\pro-settings\SI-ProConfig.ps1): State override | disable | inherit (= the row removed), Format of
/// the kind, BaseVersion / BaseHash = the live template of the same item (what Merge-SIProItems compares to say "the
/// template changed since you overrode it"), and the cfg.ChangeLog row (Name = the key, Scope 'item', Kind, Action
/// Set | Reset, Old / New = State[:Body]) -- plus a version check Set-SIProItem has not: two Admins editing the same rule
/// cannot overwrite each other. One item, one home: an override of a rule that has a cfg.Document is refused in the same
/// transaction (the run would refuse the pair). A document write is <see cref="DocumentRepository"/>'s own.
/// </summary>
public sealed class SqlItemSource : IItemSource
{
    public const string MissingSchemaMessage = "this database has no template tables yet (cfg.Template, cfg.ItemOverride) -- this configuration is still read from the installation; setup or the next update creates them";

    public const string LoadSql = """
SELECT CASE WHEN OBJECT_ID(N'cfg.Template') IS NULL OR OBJECT_ID(N'cfg.ItemOverride') IS NULL THEN 0 ELSE 1 END AS HasTables;
""";

    public const string TemplatesSql = """
IF OBJECT_ID(N'cfg.Template') IS NOT NULL
SELECT ItemKey, BodyJson, Format, SortOrder, Source, [Version] AS TemplateVersion, RetiredAt
FROM cfg.Template
WHERE Kind = @Kind
ORDER BY SortOrder, ItemKey;
""";

    public const string OverridesSql = """
IF OBJECT_ID(N'cfg.ItemOverride') IS NOT NULL
SELECT ItemKey, State, BodyJson, Format, UpdatedAt, UpdatedBy, CONVERT(bigint, RowVersion) AS Version
FROM cfg.ItemOverride
WHERE Kind = @Kind
ORDER BY ItemKey;
""";

    public const string DocumentsSql = """
IF OBJECT_ID(N'cfg.Document') IS NOT NULL
SELECT [Key] AS DocKey, Body, UpdatedAt, UpdatedBy, CONVERT(bigint, [Version]) AS Version
FROM cfg.Document
WHERE Kind = @Kind
ORDER BY [Key];
""";

    public const string WriteSql = """
SET XACT_ABORT ON;
IF OBJECT_ID(N'cfg.ItemOverride') IS NULL
BEGIN
    SELECT N'Missing' AS Outcome;
    RETURN;
END;
BEGIN TRAN;
DECLARE @cur bigint = NULL, @old nvarchar(max) = NULL, @bv nvarchar(32) = NULL, @bh char(64) = NULL;
SELECT @cur = CONVERT(bigint, RowVersion), @old = State + COALESCE(N':' + BodyJson, N'') FROM cfg.ItemOverride WITH (UPDLOCK, HOLDLOCK) WHERE Kind = @Kind AND ItemKey = @Key;
IF (@Expected IS NULL AND @cur IS NOT NULL) OR (@Expected IS NOT NULL AND (@cur IS NULL OR @cur <> @Expected))
BEGIN
    COMMIT;
    SELECT N'Stale' AS Outcome;
    RETURN;
END;
IF @Kind = N'rule' AND @State <> N'inherit' AND OBJECT_ID(N'cfg.Document') IS NOT NULL
   AND EXISTS (SELECT 1 FROM cfg.Document WITH (UPDLOCK, HOLDLOCK) WHERE Kind = N'rule' AND [Key] = @Key)
BEGIN
    COMMIT;
    SELECT N'Conflict' AS Outcome;
    RETURN;
END;
IF OBJECT_ID(N'cfg.Template') IS NOT NULL
    SELECT @bv = [Version], @bh = COALESCE(ContentHash, BodyHash) FROM cfg.Template WHERE Kind = @Kind AND ItemKey = @Key AND RetiredAt IS NULL;
IF @State = N'inherit'
    DELETE FROM cfg.ItemOverride WHERE Kind = @Kind AND ItemKey = @Key;
ELSE IF @cur IS NOT NULL
    UPDATE cfg.ItemOverride SET State = @State, BodyJson = @Body, Format = @Format, BaseVersion = @bv, BaseHash = @bh, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By WHERE Kind = @Kind AND ItemKey = @Key;
ELSE
    INSERT cfg.ItemOverride (Kind, ItemKey, State, BodyJson, Format, BaseVersion, BaseHash, UpdatedBy) VALUES (@Kind, @Key, @State, @Body, @Format, @bv, @bh, @By);
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (@Key, N'item', @Kind, CASE WHEN @State = N'inherit' THEN N'Reset' ELSE N'Set' END, @old, @State + COALESCE(N':' + @Body, N''), @By, @Reason);
COMMIT;
SELECT N'Saved' AS Outcome;
""";

    private readonly ISqlExecutor _sql;
    public SqlItemSource(ISqlExecutor sql) => _sql = sql;

    public async Task<ItemSet> LoadAsync(string kind, CancellationToken ct)
    {
        var s = await _sql.QueryAsync(LoadSql, new Dictionary<string, object?>(), ct);
        if (s.Count == 0 || s[0].Long("HasTables") != 1) return new ItemSet(kind, false, Array.Empty<ItemTemplateRow>(), Array.Empty<ItemOverrideRow2>(), Array.Empty<ItemDocumentRow>());
        var p = new Dictionary<string, object?> { ["Kind"] = kind };
        var t = await _sql.QueryAsync(TemplatesSql, p, ct);
        var o = await _sql.QueryAsync(OverridesSql, p, ct);
        var d = kind == ItemValidator.Rule ? await _sql.QueryAsync(DocumentsSql, p, ct) : Array.Empty<SqlRow>();
        return new ItemSet(kind, true,
            t.Select(r => new ItemTemplateRow(r.Str("ItemKey") ?? "", r.Str("BodyJson") ?? "", r.Str("Format") ?? "json", (int)(r.Long("SortOrder") ?? 0), r.Date("RetiredAt") is not null, r.Str("Source"), r.Str("TemplateVersion"))).ToList(),
            o.Select(r => new ItemOverrideRow2(r.Str("ItemKey") ?? "", r.Str("State") ?? "", r.Str("BodyJson"), r.Str("Format") ?? "json", r.Long("Version") ?? 0, r.Date("UpdatedAt"), r.Str("UpdatedBy"))).ToList(),
            d.Select(r => new ItemDocumentRow(r.Str("DocKey") ?? "", r.Str("Body") ?? "", r.Long("Version") ?? 0, r.Date("UpdatedAt"), r.Str("UpdatedBy"))).ToList());
    }

    public async Task<WriteResult> WriteAsync(ItemWrite w, string by, string reason, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(by)) return new WriteResult(WriteStatus.Refused, "the signed-in user has no name to record");
        if (w.Home == "document")
        {
            var action = w.State == "inherit" ? "Reset" : "Set";
            return await new DocumentRepository(_sql).WriteAsync(new DocumentWrite(w.Kind, w.Key, action, w.Body, w.ExpectedVersion, reason), Array.Empty<string>(), by, ct);
        }
        if (!ItemValidator.Kinds.TryGetValue(w.Kind, out var spec)) return new WriteResult(WriteStatus.Refused, $"'{w.Kind}' is not a kind this editor writes");
        if (w.State is not ("override" or "disable" or "inherit")) return new WriteResult(WriteStatus.Refused, $"'{w.State}' is not a state (override, disable, inherit)");
        // mandatory controls: never switch off or weaken what SecurityInsight requires
        var required = MandatoryControls.Shipped.Check(w.Kind, w.Key, w.State, w.Body);
        if (required.Count > 0) return new WriteResult(WriteStatus.Refused, string.Join("; ", required));
        if (w.State == "override")
        {
            var why = ItemValidator.Validate(w.Kind, w.Key, w.Body);
            if (why.Count > 0) return new WriteResult(WriteStatus.Refused, $"{w.Kind}/{w.Key}: " + string.Join("; ", why));
        }
        var r = reason.Trim();
        var rows = await _sql.QueryAsync(WriteSql, new Dictionary<string, object?>
        {
            ["Kind"] = w.Kind, ["Key"] = w.Key, ["State"] = w.State, ["Body"] = w.State == "override" ? w.Body : null, ["Format"] = spec.Format,
            ["Expected"] = w.ExpectedVersion, ["By"] = by.Length > 256 ? by[..256] : by, ["Reason"] = r.Length > 400 ? r[..400] : r,
        }, ct);
        return (rows.Count > 0 ? rows[0].Str("Outcome") : null) switch
        {
            "Saved" => new WriteResult(WriteStatus.Saved, $"{w.Kind}/{w.Key} saved"),
            "Stale" => new WriteResult(WriteStatus.Stale, $"{w.Kind}/{w.Key} changed since this was staged -- nothing was written; open it again and stage it again"),
            "Conflict" => new WriteResult(WriteStatus.Refused, $"{w.Kind}/{w.Key} is also kept as a settings document -- nothing was written; edit it again (the editor then changes the document)"),
            "Missing" => new WriteResult(WriteStatus.Refused, MissingSchemaMessage + " -- nothing was written"),
            _ => throw new InvalidOperationException("the item write returned no outcome"),
        };
    }

    public static string Num(long? v) => v?.ToString(CultureInfo.InvariantCulture) ?? "";
}
