using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;
using SI.Management.Web.Data;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Changes;

public sealed record ItemOverrideRow(string Kind, string ItemKey, string State, string? BodyJson, string Format, string? BaseVersion, string? BaseHash,
    DateTime? UpdatedAt, string? UpdatedBy, long Version)
{
    /// The tier of a 'ruletier' override (null when the body says none).
    public int? Tier => ItemOverrideRepository.TierOf(BodyJson);
}

/// One item-override change: State 'override' (with Body) or 'inherit' (= back to the rule's own tiers: the row is removed).
public sealed record ItemOverrideWrite(string Kind, string ItemKey, string State, string? Body, string? Reason);

/// <summary>
/// THE one class that writes cfg.ItemOverride from the GUI -- the C# twin of Set-SIProItem (engine\pro-settings\
/// SI-ProConfig.ps1), for the one kind the tier board writes: 'ruletier' (move a whole rule to another tier). The row is
/// Kind 'ruletier', ItemKey = the rule key, State 'override', Format 'json', BodyJson {"ruleKey":"&lt;key&gt;","tier":0-3};
/// BaseVersion / BaseHash = the live cfg.Template of the same (Kind, ItemKey) when there is one, else NULL. Validated
/// FIRST by the same rules as Test-SIProItem (nothing is sent for a refused write), then ONE batch, ONE transaction with
/// its cfg.ChangeLog row (Name = the key, Scope 'item', Kind = the kind, Action Set | Reset, Old/New = State[:BodyJson]).
/// Like Set-SIProItem there is no version check: the row is locked (UPDLOCK, HOLDLOCK) and the last write wins.
/// 'inherit' REMOVES the row, as Set-SIProItem does.
/// </summary>
public sealed partial class ItemOverrideRepository
{
    public const string RuleTierKind = "ruletier";
    public const string StateOverride = "override";
    public const string StateInherit = "inherit";
    public const string StateDisable = "disable";
    public const string Format = "json";

    /// The 'ruletier' key pattern of SI-ProConfig.ps1 ($script:SIProItemKinds). PowerShell's -match ignores case.
    [GeneratedRegex(@"^(endpoint|identity|azure|shared)/[A-Za-z0-9][A-Za-z0-9_\-]{0,99}$", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    public static partial Regex RuleTierKey();

    public const string ExistsSql = "SELECT CASE WHEN OBJECT_ID(N'cfg.ItemOverride') IS NULL THEN 0 ELSE 1 END AS HasTable;";

    public const string ListSql = """
IF OBJECT_ID(N'cfg.ItemOverride') IS NOT NULL
SELECT Kind, ItemKey, State, BodyJson, Format, BaseVersion, BaseHash, UpdatedAt, UpdatedBy, CONVERT(bigint, RowVersion) AS Version
FROM cfg.ItemOverride
WHERE Kind = @Kind
ORDER BY ItemKey;
""";

    public const string ReadSql = """
IF OBJECT_ID(N'cfg.ItemOverride') IS NOT NULL
SELECT Kind, ItemKey, State, BodyJson, Format, BaseVersion, BaseHash, UpdatedAt, UpdatedBy, CONVERT(bigint, RowVersion) AS Version
FROM cfg.ItemOverride
WHERE Kind = @Kind AND ItemKey = @Key;
""";

    public const string WriteSql = """
SET XACT_ABORT ON;
IF OBJECT_ID(N'cfg.ItemOverride') IS NULL
BEGIN
    SELECT N'Missing' AS Outcome;
    RETURN;
END;
BEGIN TRAN;
DECLARE @old nvarchar(max) = (SELECT State + COALESCE(N':' + BodyJson, N'') FROM cfg.ItemOverride WITH (UPDLOCK, HOLDLOCK) WHERE Kind = @Kind AND ItemKey = @Key);
DECLARE @BaseVersion nvarchar(32) = NULL, @BaseHash char(64) = NULL;
IF OBJECT_ID(N'cfg.Template') IS NOT NULL
    SELECT @BaseVersion = [Version], @BaseHash = COALESCE(ContentHash, BodyHash) FROM cfg.Template WHERE Kind = @Kind AND ItemKey = @Key AND RetiredAt IS NULL;
IF @State = N'inherit'
    DELETE FROM cfg.ItemOverride WHERE Kind = @Kind AND ItemKey = @Key;
ELSE IF @old IS NOT NULL
    UPDATE cfg.ItemOverride SET State = @State, BodyJson = @Body, Format = @Format, BaseVersion = @BaseVersion, BaseHash = @BaseHash, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By WHERE Kind = @Kind AND ItemKey = @Key;
ELSE
    INSERT cfg.ItemOverride (Kind, ItemKey, State, BodyJson, Format, BaseVersion, BaseHash, UpdatedBy) VALUES (@Kind, @Key, @State, @Body, @Format, @BaseVersion, @BaseHash, @By);
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (@Key, N'item', @Kind, CASE WHEN @State = N'inherit' THEN N'Reset' ELSE N'Set' END, @old, @State + COALESCE(N':' + @Body, N''), @By, @Reason);
COMMIT;
SELECT N'Saved' AS Outcome;
""";

    /// #251: a CONFIGURATION DOCUMENT kept as a customer-only cfg.ItemOverride row (no template, no base): today the CMDB
    /// ownership map (Kind 'cmdbownership', ItemKey 'map'). Written from the Settings documents flow with an OPTIMISTIC
    /// version check (@Expected = the RowVersion read when the page opened; NULL = it did not exist then), one transaction
    /// with its cfg.ChangeLog row. Reset removes the row (back to the shipped default).
    public const string ConfigDocumentWriteSql = """
SET XACT_ABORT ON;
IF OBJECT_ID(N'cfg.ItemOverride') IS NULL
BEGIN
    SELECT N'Missing' AS Outcome;
    RETURN;
END;
BEGIN TRAN;
DECLARE @cur bigint = NULL, @old nvarchar(max) = NULL;
SELECT @cur = CONVERT(bigint, RowVersion), @old = State + COALESCE(N':' + BodyJson, N'') FROM cfg.ItemOverride WITH (UPDLOCK, HOLDLOCK) WHERE Kind = @Kind AND ItemKey = @Key;
IF (@Expected IS NULL AND @cur IS NOT NULL) OR (@Expected IS NOT NULL AND (@cur IS NULL OR @cur <> @Expected))
BEGIN
    COMMIT;
    SELECT N'Stale' AS Outcome;
    RETURN;
END;
IF @Action = N'Reset'
    DELETE FROM cfg.ItemOverride WHERE Kind = @Kind AND ItemKey = @Key;
ELSE IF @cur IS NOT NULL
    UPDATE cfg.ItemOverride SET State = N'override', BodyJson = @Body, Format = N'json', BaseVersion = NULL, BaseHash = NULL, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By WHERE Kind = @Kind AND ItemKey = @Key;
ELSE
    INSERT cfg.ItemOverride (Kind, ItemKey, State, BodyJson, Format, BaseVersion, BaseHash, UpdatedBy) VALUES (@Kind, @Key, N'override', @Body, N'json', NULL, NULL, @By);
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (@Key, N'item', @Kind, @Action, @old, CASE WHEN @Action = N'Reset' THEN N'inherit' ELSE N'override:' + @Body END, @By, @Reason);
COMMIT;
SELECT N'Saved' AS Outcome;
""";

    /// Write a configuration document (cmdbownership/map): validated first (nothing is sent for a refused one), then
    /// ConfigDocumentWriteSql. Action Set | Reset; expectedVersion = the row's RowVersion when it was read (null = none).
    public async Task<WriteResult> WriteConfigDocumentAsync(string kind, string key, string action, string? body, long? expectedVersion, string by, string? reason, CancellationToken ct)
    {
        if (!OwnershipMapValidator.Is(kind, key)) return new WriteResult(WriteStatus.Refused, $"{kind}/{key} is not a configuration document");
        if (action is not ("Set" or "Reset")) return new WriteResult(WriteStatus.Refused, $"unknown action '{action}'");
        if (action == "Set")
        {
            var why = OwnershipMapValidator.Validate(body);
            if (why.Count > 0) return new WriteResult(WriteStatus.Refused, $"{kind}/{key} is not valid: " + string.Join("; ", why));
        }
        else if (expectedVersion is null) return new WriteResult(WriteStatus.Refused, $"{kind}/{key} does not exist -- nothing to remove");
        if (string.IsNullOrWhiteSpace(by)) return new WriteResult(WriteStatus.Refused, "the signed-in user has no name to record");
        var r = string.IsNullOrWhiteSpace(reason) ? "" : reason.Trim();
        if (r.Length > 400) r = r[..400];
        var rows = await _sql.QueryAsync(ConfigDocumentWriteSql, new Dictionary<string, object?>
        {
            ["Kind"] = kind, ["Key"] = key, ["Action"] = action, ["Body"] = action == "Set" ? (body ?? "").TrimStart((char)0xFEFF) : null,
            ["Expected"] = expectedVersion, ["By"] = by.Length > 256 ? by[..256] : by, ["Reason"] = r,
        }, ct);
        return (rows.Count > 0 ? rows[0].Str("Outcome") : null) switch
        {
            "Saved" => new WriteResult(WriteStatus.Saved, $"{kind}/{key} saved"),
            "Stale" => new WriteResult(WriteStatus.Stale, $"{kind}/{key} changed since it was staged -- nothing was written; stage it again"),
            "Missing" => new WriteResult(WriteStatus.Refused, "this database has no cfg.ItemOverride table yet -- nothing was written"),
            _ => throw new InvalidOperationException("the configuration document write returned no outcome"),
        };
    }

    public const string MissingTableMessage = "this database has no cfg.ItemOverride table yet -- a rule cannot be moved to another tier until the Pro settings schema is updated";

    private readonly ISqlExecutor _sql;
    public ItemOverrideRepository(ISqlExecutor sql) => _sql = sql;

    private static ItemOverrideRow Map(SqlRow r) => new(r.Str("Kind") ?? "", r.Str("ItemKey") ?? "", r.Str("State") ?? "", r.Str("BodyJson"), r.Str("Format") ?? Format,
        r.Str("BaseVersion"), r.Str("BaseHash"), r.Date("UpdatedAt"), r.Str("UpdatedBy"), r.Long("Version") ?? 0);

    public async Task<bool> TableExistsAsync(CancellationToken ct)
    {
        var rows = await _sql.QueryAsync(ExistsSql, new Dictionary<string, object?>(), ct);
        return rows.Count > 0 && rows[0].Long("HasTable") == 1;
    }

    /// Every override of a kind (empty when the table does not exist yet).
    public async Task<IReadOnlyList<ItemOverrideRow>> ListAsync(string kind, CancellationToken ct) =>
        (await _sql.QueryAsync(ListSql, new Dictionary<string, object?> { ["Kind"] = kind }, ct)).Select(Map).ToList();

    public async Task<ItemOverrideRow?> ReadAsync(string kind, string key, CancellationToken ct) =>
        (await _sql.QueryAsync(ReadSql, new Dictionary<string, object?> { ["Kind"] = kind, ["Key"] = key }, ct)).Select(Map).FirstOrDefault();

    /// The 'ruletier' body the engine reads: exactly { "ruleKey": "&lt;key&gt;", "tier": n }.
    public static string RuleTierBody(string ruleKey, int tier) => JsonSerializer.Serialize(new { ruleKey, tier });

    /// The tier a 'ruletier' body names, or null.
    public static int? TierOf(string? body)
    {
        if (string.IsNullOrWhiteSpace(body)) return null;
        try
        {
            using var d = JsonDocument.Parse(body);
            return d.RootElement.ValueKind == JsonValueKind.Object && d.RootElement.TryGetProperty("tier", out var t) && TierValue(t) is { } n ? n : null;
        }
        catch (JsonException) { return null; }
    }

    /// Test-SIProItem's tier rule: [int]::TryParse([string]$tier), the text must be the number itself, and 0..3.
    private static int? TierValue(JsonElement t)
    {
        string? s = t.ValueKind switch
        {
            JsonValueKind.Number => t.TryGetDouble(out var d) ? d.ToString(CultureInfo.InvariantCulture) : null,
            JsonValueKind.String => t.GetString(),
            _ => null,
        };
        if (s is null || !int.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out var n)) return null;
        if (n.ToString(CultureInfo.InvariantCulture) != s.Trim() || n is < 0 or > 3) return null;
        return n;
    }

    /// The reasons a write is refused (empty = accepted) -- Set-SIProItem's checks and Test-SIProItem's 'ruletier'
    /// rules, in the same order. Sends nothing.
    public static IReadOnlyList<string> Validate(ItemOverrideWrite w) => Validate(w, MandatoryControls.Shipped);

    /// The same, with the mandatory controls given (tests). A write that switches off or weakens what SecurityInsight
    /// requires (config\template-mandatory.locked.json) is refused with the plain reason, before any other rule.
    public static IReadOnlyList<string> Validate(ItemOverrideWrite w, MandatoryControls mandatory)
    {
        var required = mandatory.Check(w.Kind, w.ItemKey, w.State, w.Body);
        if (required.Count > 0) return required;
        return ValidateItem(w);
    }

    private static IReadOnlyList<string> ValidateItem(ItemOverrideWrite w)
    {
        if (w.Kind == OwnershipMapValidator.Kind)
        {
            // the CMDB ownership map: one configuration document, written by WriteConfigDocumentAsync (with a version check)
            if (OwnershipMapValidator.KeyProblem(w.ItemKey) is { } kp) return new[] { kp };
            if (w.State == StateInherit) return Array.Empty<string>();
            if (w.State != StateOverride) return new[] { "the CMDB ownership map is set or removed, never switched off" };
            return OwnershipMapValidator.Validate(w.Body);
        }
        if (w.Kind == SI.Management.Core.ProData.OutputMapRules.Kind && w.ItemKey.StartsWith("outputs/", StringComparison.Ordinal))
        {
            // an output column (V3-DATA-MODEL 2.12): 'datamodel' rows of the output maps only -- 'outputs/<id>:<target>'.
            // The full check (the shipped column's value translation, unique names) is OutputMapChanges'; here the row itself.
            var k = SI.Management.Core.ProData.OutputMapRules.SplitKey(w.ItemKey);
            if (k is null) return new[] { $"'{w.ItemKey}' is not an output column the GUI writes (outputs/<output>:<column>)" };
            if (SI.Management.Core.ProData.OutputMapRules.Locked(k.Value.OutputId) is { } locked) return new[] { locked };
            if (w.State is not (StateOverride or StateInherit or StateDisable)) return new[] { $"'{w.State}' is not a state (override, disable, inherit)" };
            if (w.State != StateOverride) return Array.Empty<string>();
            var own = SI.Management.Core.ProData.OutputMapRules.ParseColumn(w.Body);
            return SI.Management.Core.ProData.OutputMapRules.Validate(w.ItemKey, w.Body, own);
        }
        // #527 (4): the Risk factors page -- a data-model item (a factor or a provider mapping) of the Pro data model in SQL
        // (the same kind as the output columns: a key that is neither is refused as both)
        if (w.Kind == DataModelItemValidator.Kind && !DataModelItemValidator.GuiWrites(w.ItemKey))
            return new[] { $"'{w.ItemKey}' is not an output column the GUI writes (outputs/<output>:<column>), nor an item of a data-model template it writes ({DataModelItemValidator.GuiTemplatesText})" };
        if (w.Kind == DataModelItemValidator.Kind) return DataModelItemValidator.Validate(w.ItemKey, w.State, w.Body);
        if (w.Kind != RuleTierKind) return new[] { $"'{w.Kind}' is not a configuration kind the GUI writes ({RuleTierKind}, {OwnershipMapValidator.Kind}, {DataModelItemValidator.Kind} items and output columns)" };
        if (string.IsNullOrEmpty(w.ItemKey) || !RuleTierKey().IsMatch(w.ItemKey)) return new[] { $"'{w.ItemKey}' is not a valid {w.Kind} key" };
        if (w.State is not (StateOverride or StateInherit or StateDisable)) return new[] { $"'{w.State}' is not a state (override, disable, inherit)" };
        if (w.State != StateOverride) return Array.Empty<string>();
        var text = (w.Body ?? "").TrimStart((char)0xFEFF);
        if (string.IsNullOrWhiteSpace(text)) return new[] { "the body is empty" };
        JsonDocument doc;
        try { doc = JsonDocument.Parse(text); }
        catch (JsonException ex) { return new[] { "the body is not valid JSON: " + ex.Message }; }
        using (doc)
        {
            var o = doc.RootElement;
            if (o.ValueKind != JsonValueKind.Object) return new[] { "a rule tier decision must be a JSON object" };
            var why = new List<string>();
            var rk = o.TryGetProperty("ruleKey", out var k) ? (k.ValueKind == JsonValueKind.String ? k.GetString() : k.ValueKind == JsonValueKind.Null ? "" : k.GetRawText()) : "";
            if (!string.Equals(rk, w.ItemKey, StringComparison.Ordinal)) why.Add($"ruleKey must be '{w.ItemKey}' -- the key names the rule");
            if (!o.TryGetProperty("tier", out var t) || TierValue(t) is null) why.Add("tier must be 0, 1, 2 or 3");
            return why;
        }
    }

    public async Task<WriteResult> WriteAsync(ItemOverrideWrite w, string by, CancellationToken ct)
    {
        var why = Validate(w);
        if (why.Count > 0) return new WriteResult(WriteStatus.Refused, $"{w.Kind}/{w.ItemKey} is not valid: " + string.Join("; ", why));
        if (string.IsNullOrWhiteSpace(by)) return new WriteResult(WriteStatus.Refused, "the signed-in user has no name to record");
        var reason = string.IsNullOrWhiteSpace(w.Reason) ? "" : w.Reason.Trim();
        if (reason.Length > 400) reason = reason[..400];
        var rows = await _sql.QueryAsync(WriteSql, new Dictionary<string, object?>
        {
            ["Kind"] = w.Kind, ["Key"] = w.ItemKey, ["State"] = w.State, ["Body"] = w.State == StateOverride ? (w.Body ?? "").TrimStart((char)0xFEFF) : null,
            ["Format"] = Format, ["By"] = by.Length > 256 ? by[..256] : by, ["Reason"] = reason,
        }, ct);
        return (rows.Count > 0 ? rows[0].Str("Outcome") : null) switch
        {
            "Saved" => new WriteResult(WriteStatus.Saved, $"{w.Kind}/{w.ItemKey} saved"),
            "Missing" => new WriteResult(WriteStatus.Refused, MissingTableMessage + " -- nothing was written"),
            _ => throw new InvalidOperationException("the item override write returned no outcome"),
        };
    }
}
