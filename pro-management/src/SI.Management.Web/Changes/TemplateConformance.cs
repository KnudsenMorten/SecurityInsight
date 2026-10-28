using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using SI.Management.Web.Data;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Changes;

/// One item of the conformance view (a template, the customer's override of it, or the customer's own item).
/// AdditionsApplied (adopted from PIM4EntraPS): the override is behind the shipped content, but the new shipped version only
/// ADDS -- the run puts the additions into the customer's effective item and never touches their values, so the item reads
/// Overridden ("new shipped additions applied"), not UpgradeAvailable.
public sealed record ConformanceRow(string Kind, string ItemKey, bool HasTemplate, string? TemplateVersion, string? ContentHash, string? BodyHash,
    DateTime? RetiredAt, string? State, string? BaseVersion, string? BaseHash, DateTime? UpdatedAt, string? UpdatedBy, bool AdditionsApplied = false)
{
    public string Conformance => AdditionsApplied ? TemplateConformance.Overridden : RawConformance;
    /// The state by the hashes alone (before the additive check).
    public string RawConformance => TemplateConformance.StateOf(HasTemplate, RetiredAt is not null, State, BaseHash, ContentHash, BodyHash);
    /// What the page shows.
    public string ConformanceText => AdditionsApplied ? TemplateConformance.AdditionsAppliedText : Conformance;
    public string Name => Kind + "/" + ItemKey;
}

/// The outcome of the additive check (Get-SIProAdditiveMerge): Body = the merged JSON (or the override as it was).
public sealed record AdditiveResult(bool Additive, bool Changed, string? Body, IReadOnlyList<string> Added, IReadOnlyList<string> Kept, string Reason);

/// One item with its bodies: the current template, the customer's override and the template body the override was made
/// against (cfg.TemplateRevision by BaseHash -- null for an override older than revisions).
public sealed record ConformanceItem(ConformanceRow Row, string Format, string? TemplateBody, string? OverrideBody, string? BaseBody);

/// The per-install summary: counts per state (every state, 0 when none), the recorded fingerprint and when.
public sealed record ConformanceSummary(IReadOnlyDictionary<string, int> Counts, int Total, string? Fingerprint, string? FingerprintVersion, DateTime? FingerprintAt, string? FingerprintBy)
{
    public int UpgradeAvailable => Counts.TryGetValue(TemplateConformance.UpgradeAvailable, out var n) ? n : 0;
    public bool Conformant => UpgradeAvailable == 0;
}

/// One difference between two normalised bodies.
public sealed record ContentChange(string Path, string Change, string? Old, string? New);

/// <summary>
/// THE TEMPLATE CONFORMANCE VIEW -- the C# twin of Get-SIProConformance (engine\pro-settings\SI-TemplateVersioning.ps1),
/// adopted from PIM4EntraPS. Per item: UpToDate / Overridden / Disabled / UpgradeAvailable / Own / Retired, and per install
/// the counts and the recorded template fingerprint. An Admin resolves "upgrade available" through Review &amp; commit:
/// "take the new template" (the override goes back to inherit -- the row is removed, as Set-SIProItem does) or "keep mine
/// and acknowledge" (the override's BaseHash / BaseVersion move to the current template content; its body is not touched).
/// Fixed, parameterised SQL only. The content hashes themselves are computed by PowerShell at publish (cfg.Template.
/// ContentHash); this class only compares them, and diffs bodies for display.
/// </summary>
public sealed class TemplateConformance
{
    public const string UpToDate = "UpToDate";
    public const string Overridden = "Overridden";
    public const string Disabled = "Disabled";
    public const string UpgradeAvailable = "UpgradeAvailable";
    public const string Own = "Own";
    public const string Retired = "Retired";
    /// The states, in the order the PowerShell view lists them (a test compares the two lists).
    public static readonly string[] States = { "UpToDate", "Overridden", "Disabled", "UpgradeAvailable", "Own", "Retired" };
    /// How the page names an Overridden item whose new shipped additions reach it (the PowerShell view's StateText).
    public const string AdditionsAppliedText = "Overridden -- new shipped additions applied";
    /// The kinds the vendor publishes templates for ($script:SIProItemKinds, Templated = $true): vendor-developed content only.
    public static readonly string[] TemplatedKinds = { "rareport", "riskindex", "rule", "assettagging", "servicemodel", "datamodel" };
    /// #251: kinds that WERE templates and are configuration now (names are settings; the CMDB ownership map is the
    /// customer's own document). Their retired cfg.Template rows stay as history but are never listed, counted or released.
    public static readonly string[] FormerTemplateKinds = { "naming", "cmdbownership" };
    public static bool IsFormerTemplateKind(string? kind) => kind is not null && FormerTemplateKinds.Contains(kind, StringComparer.Ordinal);

    /// Get-SIProConformanceState, rule for rule.
    public static string StateOf(bool hasTemplate, bool retired, string? state, string? baseHash, string? contentHash, string? bodyHash)
    {
        if (!hasTemplate) return Own;
        if (retired) return state == "override" ? Own : Retired;
        if (state == "disable") return Disabled;
        if (state != "override") return UpToDate;
        var b = (baseHash ?? "").Trim();
        if (b.Length > 0 && (b == (contentHash ?? "").Trim() || b == (bodyHash ?? "").Trim())) return Overridden;
        return UpgradeAvailable;
    }

    public const string SchemaSql = """
SELECT CASE WHEN OBJECT_ID(N'cfg.Template') IS NULL OR OBJECT_ID(N'cfg.ItemOverride') IS NULL THEN 0 ELSE 1 END AS HasTables,
       CASE WHEN COL_LENGTH(N'cfg.Template', N'ContentHash') IS NULL OR OBJECT_ID(N'cfg.TemplateRevision') IS NULL OR OBJECT_ID(N'cfg.InstallState') IS NULL THEN 0 ELSE 1 END AS HasVersioning;
""";

    /// Every template and every override (FULL JOIN: an override without a template is the customer's own item). Sent only
    /// when SchemaSql says the versioning schema is there -- ContentHash would not compile otherwise.
    public const string ListSql = """
SELECT COALESCE(t.Kind, o.Kind) AS Kind, COALESCE(t.ItemKey, o.ItemKey) AS ItemKey,
       CASE WHEN t.TemplateId IS NULL THEN 0 ELSE 1 END AS HasTemplate,
       t.[Version] AS TemplateVersion, t.ContentHash, t.BodyHash, t.RetiredAt,
       o.State, o.BaseVersion, o.BaseHash, o.UpdatedAt, o.UpdatedBy,
       CASE WHEN b.Behind = 1 THEN 1 ELSE 0 END AS Behind, t.Format AS TemplateFormat,
       CASE WHEN b.Behind = 1 THEN t.BodyJson END AS TemplateBody, CASE WHEN b.Behind = 1 THEN o.BodyJson END AS OverrideBody,
       r.BodyJson AS BaseBody
FROM cfg.Template t
FULL OUTER JOIN cfg.ItemOverride o ON o.Kind = t.Kind AND o.ItemKey = t.ItemKey
CROSS APPLY (SELECT CASE WHEN o.State = N'override' AND t.TemplateId IS NOT NULL AND t.RetiredAt IS NULL AND o.BaseHash IS NOT NULL
                          AND o.BaseHash <> COALESCE(t.ContentHash, N'') AND o.BaseHash <> COALESCE(t.BodyHash, N'') THEN 1 ELSE 0 END AS Behind) b
LEFT JOIN cfg.TemplateRevision r ON b.Behind = 1 AND r.Kind = t.Kind AND r.ItemKey = t.ItemKey AND r.ContentHash = o.BaseHash
WHERE (@Kind IS NULL OR COALESCE(t.Kind, o.Kind) = @Kind)
  AND COALESCE(t.Kind, o.Kind) NOT IN (N'naming', N'cmdbownership')
ORDER BY COALESCE(t.Kind, o.Kind), COALESCE(t.ItemKey, o.ItemKey);
""";

    public const string ItemSql = """
SELECT k.Kind, k.ItemKey,
       CASE WHEN t.TemplateId IS NULL THEN 0 ELSE 1 END AS HasTemplate,
       t.[Version] AS TemplateVersion, t.ContentHash, t.BodyHash, t.RetiredAt, t.Format AS TemplateFormat, t.BodyJson AS TemplateBody,
       o.State, o.BaseVersion, o.BaseHash, o.UpdatedAt, o.UpdatedBy, o.Format AS OverrideFormat, o.BodyJson AS OverrideBody,
       r.BodyJson AS BaseBody
FROM (SELECT @Kind AS Kind, @Key AS ItemKey) k
LEFT JOIN cfg.Template t ON t.Kind = k.Kind AND t.ItemKey = k.ItemKey
LEFT JOIN cfg.ItemOverride o ON o.Kind = k.Kind AND o.ItemKey = k.ItemKey
LEFT JOIN cfg.TemplateRevision r ON r.Kind = k.Kind AND r.ItemKey = k.ItemKey AND r.ContentHash = o.BaseHash;
""";

    /// Every shipped body of one item -- for an override whose base is a RAW body hash (made before content hashes): the
    /// base is the revision whose UTF-8 SHA-256 is that hash (SQL cannot hash UTF-8, so C# does).
    public const string RevisionsSql = """
SELECT BodyJson FROM cfg.TemplateRevision WHERE Kind = @Kind AND ItemKey = @Key;
""";

    public const string FingerprintSql = """
SELECT Value, [Version], UpdatedAt, UpdatedBy FROM cfg.InstallState WHERE Name = N'TemplateFingerprint';
""";

    /// "Keep mine and acknowledge": the override's base moves to the CURRENT template content, only when the override is
    /// still an override and the template content is still the one the Admin reviewed (@Expected). One transaction with
    /// its cfg.ChangeLog row; the actor (@By) is the signed-in identity.
    public const string KeepSql = """
SET XACT_ABORT ON;
IF OBJECT_ID(N'cfg.ItemOverride') IS NULL OR COL_LENGTH(N'cfg.Template', N'ContentHash') IS NULL
BEGIN
    SELECT N'Missing' AS Outcome;
    RETURN;
END;
BEGIN TRAN;
DECLARE @state nvarchar(16), @oldHash char(64), @newHash char(64), @newVersion nvarchar(32);
SELECT @state = State, @oldHash = BaseHash FROM cfg.ItemOverride WITH (UPDLOCK, HOLDLOCK) WHERE Kind = @Kind AND ItemKey = @Key;
EXEC sp_executesql N'SELECT @h = ContentHash, @v = [Version] FROM cfg.Template WHERE Kind = @k AND ItemKey = @i AND RetiredAt IS NULL',
    N'@h char(64) OUTPUT, @v nvarchar(32) OUTPUT, @k nvarchar(32), @i nvarchar(128)', @h = @newHash OUTPUT, @v = @newVersion OUTPUT, @k = @Kind, @i = @Key;
IF @state IS NULL OR @state <> N'override' BEGIN ROLLBACK; SELECT N'NotOverridden' AS Outcome; RETURN; END;
IF @newHash IS NULL BEGIN ROLLBACK; SELECT N'NoTemplate' AS Outcome; RETURN; END;
IF @newHash <> @Expected BEGIN ROLLBACK; SELECT N'Stale' AS Outcome; RETURN; END;
UPDATE cfg.ItemOverride SET BaseHash = @newHash, BaseVersion = @newVersion, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By WHERE Kind = @Kind AND ItemKey = @Key;
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (@Key, N'item', @Kind, N'Set', CONCAT(N'base:', COALESCE(@oldHash, N'(none)')), CONCAT(N'base:', @newHash, N' (', @newVersion, N')'), @By, @Reason);
COMMIT;
SELECT N'Saved' AS Outcome;
""";

    /// "Take the new template": the override is removed (= inherit), only when it still has the BaseHash the Admin
    /// reviewed (@ExpectedBase; NULL = the override had none). One transaction with its cfg.ChangeLog row.
    public const string TakeSql = """
SET XACT_ABORT ON;
IF OBJECT_ID(N'cfg.ItemOverride') IS NULL
BEGIN
    SELECT N'Missing' AS Outcome;
    RETURN;
END;
BEGIN TRAN;
DECLARE @old nvarchar(max), @base char(64), @found bit = 0;
SELECT @found = 1, @old = State + COALESCE(N':' + BodyJson, N''), @base = BaseHash FROM cfg.ItemOverride WITH (UPDLOCK, HOLDLOCK) WHERE Kind = @Kind AND ItemKey = @Key;
IF @found = 0 BEGIN ROLLBACK; SELECT N'NotOverridden' AS Outcome; RETURN; END;
IF COALESCE(@base, N'') <> COALESCE(@ExpectedBase, N'') BEGIN ROLLBACK; SELECT N'Stale' AS Outcome; RETURN; END;
DELETE FROM cfg.ItemOverride WHERE Kind = @Kind AND ItemKey = @Key;
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (@Key, N'item', @Kind, N'Reset', @old, N'inherit', @By, @Reason);
COMMIT;
SELECT N'Saved' AS Outcome;
""";

    /// Plain status: setup and every update create the schema themselves (#250), so the page never hands out a command.
    public const string MissingSchemaMessage = "Templates are being prepared -- the next update or setup run installs them.";

    private readonly ISqlExecutor _sql;
    public TemplateConformance(ISqlExecutor sql) => _sql = sql;

    /// (tables exist, versioning schema exists)
    public async Task<(bool Tables, bool Versioning)> SchemaAsync(CancellationToken ct)
    {
        var r = (await _sql.QueryAsync(SchemaSql, new Dictionary<string, object?>(), ct)).FirstOrDefault();
        return (r?.Long("HasTables") == 1, r?.Long("HasVersioning") == 1);
    }

    private static ConformanceRow MapRow(SqlRow r) => new(r.Str("Kind") ?? "", r.Str("ItemKey") ?? "", r.Long("HasTemplate") == 1, r.Str("TemplateVersion"),
        r.Str("ContentHash")?.Trim(), r.Str("BodyHash")?.Trim(), r.Date("RetiredAt"), r.Str("State"), r.Str("BaseVersion"), r.Str("BaseHash")?.Trim(), r.Date("UpdatedAt"), r.Str("UpdatedBy"));

    public async Task<IReadOnlyList<ConformanceRow>> ListAsync(string? kind, CancellationToken ct)
    {
        var list = new List<ConformanceRow>();
        foreach (var r in await _sql.QueryAsync(ListSql, new Dictionary<string, object?> { ["Kind"] = string.IsNullOrWhiteSpace(kind) ? null : kind }, ct))
        {
            var row = MapRow(r);
            if (IsFormerTemplateKind(row.Kind)) continue;
            if (row.RawConformance == UpgradeAvailable && r.Long("Behind") == 1)
                row = await WithAdditiveAsync(row, r.Str("TemplateFormat") ?? "json", r.Str("TemplateBody"), r.Str("OverrideBody"), r.Str("BaseBody"), ct);
            list.Add(row);
        }
        return list;
    }

    public async Task<ConformanceItem?> ItemAsync(string kind, string key, CancellationToken ct)
    {
        if (IsFormerTemplateKind(kind)) return null;
        var r = (await _sql.QueryAsync(ItemSql, new Dictionary<string, object?> { ["Kind"] = kind, ["Key"] = key }, ct)).FirstOrDefault();
        if (r is null) return null;
        var row = MapRow(r);
        if (!row.HasTemplate && row.State is null) return null;
        var format = r.Str("TemplateFormat") ?? r.Str("OverrideFormat") ?? "json";
        var baseBody = r.Str("BaseBody");
        if (row.RawConformance == UpgradeAvailable)
        {
            baseBody ??= await BaseByRawHashAsync(row, ct);
            row = await WithAdditiveAsync(row, format, r.Str("TemplateBody"), r.Str("OverrideBody"), baseBody, ct);
        }
        return new ConformanceItem(row, format, r.Str("TemplateBody"), r.Str("OverrideBody"), baseBody);
    }

    /// #529 (1): the row with AdditionsApplied when the new shipped version only adds to what the override was made on.
    private async Task<ConformanceRow> WithAdditiveAsync(ConformanceRow row, string format, string? templateBody, string? overrideBody, string? baseBody, CancellationToken ct)
    {
        if (templateBody is null || overrideBody is null) return row;
        baseBody ??= await BaseByRawHashAsync(row, ct);
        if (baseBody is null) return row;
        return Additive(baseBody, templateBody, overrideBody, format).Additive ? row with { AdditionsApplied = true } : row;
    }

    /// The revision whose raw body hash is the override's base (an override made before content hashes), or null.
    private async Task<string?> BaseByRawHashAsync(ConformanceRow row, CancellationToken ct)
    {
        var b = (row.BaseHash ?? "").Trim();
        if (b.Length != 64) return null;
        foreach (var r in await _sql.QueryAsync(RevisionsSql, new Dictionary<string, object?> { ["Kind"] = row.Kind, ["Key"] = row.ItemKey }, ct))
        {
            var body = r.Str("BodyJson");
            if (body is not null && string.Equals(Sha256Hex(body), b, StringComparison.OrdinalIgnoreCase)) return body;
        }
        return null;
    }

    /// Get-SIProTextHash: SHA-256 (hex, lower case) of a text as UTF-8.
    public static string Sha256Hex(string text) => Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(text))).ToLowerInvariant();

    public async Task<ConformanceSummary> SummaryAsync(IReadOnlyList<ConformanceRow> rows, CancellationToken ct)
    {
        var counts = States.ToDictionary(s => s, _ => 0, StringComparer.Ordinal);
        rows = rows.Where(r => !IsFormerTemplateKind(r.Kind)).ToList();
        foreach (var r in rows) counts[r.Conformance]++;
        var f = (await _sql.QueryAsync(FingerprintSql, new Dictionary<string, object?>(), ct)).FirstOrDefault();
        return new ConformanceSummary(counts, rows.Count, f?.Str("Value"), f?.Str("Version"), f?.Date("UpdatedAt"), f?.Str("UpdatedBy"));
    }

    /// The reasons a take / keep is refused before anything is sent (empty = accepted).
    public static IReadOnlyList<string> Validate(string kind, string key)
    {
        if (IsFormerTemplateKind(kind)) return new[] { $"'{kind}' is configuration now, not a template -- change it on the Settings pages" };
        if (!TemplatedKinds.Contains(kind, StringComparer.Ordinal)) return new[] { $"'{kind}' is not a templated configuration kind" };
        if (string.IsNullOrWhiteSpace(key) || key.Length > 128 || key.Any(char.IsControl)) return new[] { $"'{key}' is not a valid {kind} key" };
        return Array.Empty<string>();
    }

    private static string By(string by) => by.Length > 256 ? by[..256] : by;
    private static string Reason(string? reason, string fallback) { var r = string.IsNullOrWhiteSpace(reason) ? fallback : reason.Trim(); return r.Length > 400 ? r[..400] : r; }

    private static WriteResult Outcome(IReadOnlyList<SqlRow> rows, string what) => (rows.Count > 0 ? rows[0].Str("Outcome") : null) switch
    {
        "Saved" => new WriteResult(WriteStatus.Saved, what + " saved"),
        "Missing" => new WriteResult(WriteStatus.Refused, MissingSchemaMessage + " -- nothing was written"),
        "NotOverridden" => new WriteResult(WriteStatus.Stale, what + ": the item is no longer overridden -- nothing was written"),
        "NoTemplate" => new WriteResult(WriteStatus.Stale, what + ": the template is not published any more -- nothing was written"),
        "Stale" => new WriteResult(WriteStatus.Stale, what + ": the item changed since this was staged -- discard it and stage it again"),
        _ => throw new InvalidOperationException("the template conformance write returned no outcome"),
    };

    public async Task<WriteResult> KeepAsync(string kind, string key, string expectedContentHash, string? reason, string by, CancellationToken ct)
    {
        var why = Validate(kind, key);
        if (why.Count > 0) return new WriteResult(WriteStatus.Refused, string.Join("; ", why));
        if (string.IsNullOrWhiteSpace(by)) return new WriteResult(WriteStatus.Refused, "the signed-in user has no name to record");
        if (!Regex.IsMatch(expectedContentHash ?? "", "^[0-9a-f]{64}$")) return new WriteResult(WriteStatus.Refused, "the reviewed template content is not known -- stage it again");
        var rows = await _sql.QueryAsync(KeepSql, new Dictionary<string, object?>
        {
            ["Kind"] = kind, ["Key"] = key, ["Expected"] = expectedContentHash, ["By"] = By(by), ["Reason"] = Reason(reason, "kept my version; acknowledged the new template"),
        }, ct);
        return Outcome(rows, $"{kind}/{key}");
    }

    public async Task<WriteResult> TakeAsync(string kind, string key, string? expectedBaseHash, string? reason, string by, CancellationToken ct)
    {
        var why = Validate(kind, key);
        if (why.Count > 0) return new WriteResult(WriteStatus.Refused, string.Join("; ", why));
        if (string.IsNullOrWhiteSpace(by)) return new WriteResult(WriteStatus.Refused, "the signed-in user has no name to record");
        var rows = await _sql.QueryAsync(TakeSql, new Dictionary<string, object?>
        {
            ["Kind"] = kind, ["Key"] = key, ["ExpectedBase"] = string.IsNullOrWhiteSpace(expectedBaseHash) ? null : expectedBaseHash.Trim(),
            ["By"] = By(by), ["Reason"] = Reason(reason, "took the new template"),
        }, ct);
        return Outcome(rows, $"{kind}/{key}");
    }

    // ------------------------------------------------------------------------------------------------- the diff

    private static readonly HashSet<string> DocOnly = new(StringComparer.OrdinalIgnoreCase) { "description", "comment", "comments", "notes", "$schema" };

    private static bool IsDocOnly(string key) => key.StartsWith('_') || DocOnly.Contains(key);

    /// A JSON body with documentation-only keys dropped (at any depth) and keys in ordinal order -- Get-SIProContentText's
    /// normalisation for JSON. Null when the body is not JSON.
    public static JsonNode? Normalise(string? body)
    {
        if (string.IsNullOrWhiteSpace(body)) return null;
        try { return Clean(JsonNode.Parse(body.TrimStart('﻿'))); }
        catch (JsonException) { return null; }
    }

    private static JsonNode? Clean(JsonNode? n) => n switch
    {
        JsonObject o => new JsonObject(o.Where(p => !IsDocOnly(p.Key)).OrderBy(p => p.Key, StringComparer.Ordinal).Select(p => KeyValuePair.Create(p.Key, Clean(p.Value)))),
        JsonArray a => new JsonArray(a.Select(Clean).ToArray()),
        null => null,
        // a number is written the way ConvertTo-SIProJson writes it: 1.50 and 1.5 are the same value
        JsonValue v when v.TryGetValue<JsonElement>(out var e) && e.ValueKind == JsonValueKind.Number && e.TryGetDouble(out var d) =>
            d == Math.Floor(d) && Math.Abs(d) < 1e15 ? JsonValue.Create((long)d) : JsonValue.Create(d),
        _ => JsonNode.Parse(n.ToJsonString()),
    };

    private static string Text(JsonNode? n) => n is null ? "null" : n.ToJsonString();

    // ------------------------------------------------------------------------------------------------- the additive upgrade

    /// <summary>
    /// Get-SIProAdditiveMerge, rule for rule (adopted from PIM4EntraPS: "missing blocks are added, existing values never
    /// touched"). The vendor's change base -> current (normalised) must only ADD: a new key in an object, new entries in a
    /// list (the base's entries all still there, in order). Each addition goes into the customer's body: a key they do not
    /// have is added, one they have keeps their value (Kept); a list entry they do not hold is appended. An addition whose
    /// place the customer removed, or anything the vendor changed or removed, makes it not additive (UpgradeAvailable).
    /// Only JSON items; a YAML tier rule is never merged.
    /// </summary>
    public static AdditiveResult Additive(string? baseBody, string? currentBody, string? overrideBody, string format)
    {
        AdditiveResult No(string why) => new(false, false, overrideBody, Array.Empty<string>(), Array.Empty<string>(), why);
        if (format != "json") return No("a YAML item is never merged automatically -- review the new version");
        if (string.IsNullOrWhiteSpace(baseBody)) return No("the shipped version your change was made on is not known");
        JsonNode? b, c, cm, o;
        try
        {
            b = Normalise(baseBody); c = Normalise(currentBody);
            cm = JsonNode.Parse((currentBody ?? "").TrimStart('﻿')); o = JsonNode.Parse((overrideBody ?? "").TrimStart('﻿'));
        }
        catch (JsonException ex) { return No("a body is not valid JSON: " + ex.Message); }
        if (b is null || c is null) return No("a body is not valid JSON");
        var added = new List<string>(); var kept = new List<string>();
        string? fail = null;
        static string Canon(JsonNode? n) => Text(Clean(n));

        void Walk(string path, JsonNode? x, JsonNode? y, JsonNode? ym, JsonNode? t, bool hasT)
        {
            if (fail is not null) return;
            var show = path.Length == 0 ? "(item)" : path;
            if (x is JsonObject ox && y is JsonObject oy)
            {
                foreach (var k in ox.Select(p => p.Key))
                    if (!oy.ContainsKey(k)) { fail = $"'{(path.Length == 0 ? k : path + "." + k)}' was removed from the shipped version"; return; }
                var tObj = hasT ? t as JsonObject : null;
                foreach (var k in oy.Select(p => p.Key).ToList())
                {
                    var p = path.Length == 0 ? k : path + "." + k;
                    var ymk = ym is JsonObject ymo && ymo.TryGetPropertyValue(k, out var v) ? v : oy[k];
                    if (ox.ContainsKey(k))
                    {
                        var has = tObj is not null && tObj.ContainsKey(k);
                        Walk(p, ox[k], oy[k], ymk, has ? tObj![k] : null, has);
                        if (fail is not null) return;
                        continue;
                    }
                    if (tObj is null) { fail = $"the shipped version adds '{p}', but your version has no '{show}' to add it to"; return; }
                    if (tObj.ContainsKey(k)) kept.Add(p); else { tObj[k] = ymk?.DeepClone(); added.Add(p); }
                }
                return;
            }
            if (x is JsonArray ax && y is JsonArray ay)
            {
                var xc = ax.Select(Canon).ToList(); var yc = ay.Select(Canon).ToList();
                var yma = ym as JsonArray;
                int j = 0; var fresh = new List<int>();
                for (var i = 0; i < ay.Count; i++) { if (j < ax.Count && yc[i] == xc[j]) j++; else fresh.Add(i); }
                if (j == ax.Count)
                {
                    if (fresh.Count == 0) return;
                    if (!(hasT && t is JsonArray ta)) { fail = $"the shipped version adds entries to '{show}', but your version has no list there"; return; }
                    var tc = ta.Select(Canon).ToList();
                    foreach (var i in fresh)
                    {
                        var p = path + "[" + i.ToString(CultureInfo.InvariantCulture) + "]";
                        if (tc.Contains(yc[i])) kept.Add(p);
                        else { ta.Add((yma is not null && i < yma.Count ? yma[i] : ay[i])?.DeepClone()); tc.Add(yc[i]); added.Add(p); }
                    }
                    return;
                }
                if (ax.Count != ay.Count) { fail = $"entries of '{show}' were changed or removed in the shipped version"; return; }
                var tl = hasT && t is JsonArray tla && tla.Count == ax.Count ? tla : null;
                for (var i = 0; i < ax.Count; i++)
                {
                    if (xc[i] == yc[i]) continue;
                    if (tl is null) { fail = $"an entry of '{show}' changed in the shipped version and your list does not line up with it"; return; }
                    Walk(path + "[" + i.ToString(CultureInfo.InvariantCulture) + "]", ax[i], ay[i], yma is not null && i < yma.Count ? yma[i] : ay[i], tl[i], true);
                    if (fail is not null) return;
                }
                return;
            }
            if (Text(x) != Text(y)) fail = $"'{show}' changed in the shipped version";
        }

        Walk("", b, c, cm, o, true);
        if (fail is not null) return No(fail);
        var body = added.Count > 0 ? o!.ToJsonString(new JsonSerializerOptions { WriteIndented = true }) : overrideBody;
        return new AdditiveResult(true, added.Count > 0, body, added, kept, "");
    }

    /// What changed between two bodies of one item. JSON: a structured diff of the normalised bodies (Path like
    /// "services[0].components[0].role"), the same paths Get-SIProContentDiff reports. YAML (a tier rule): the lines
    /// that differ once comment and blank lines are left out (Path "line N").
    public static IReadOnlyList<ContentChange> Diff(string? oldBody, string? newBody, string format)
    {
        var list = new List<ContentChange>();
        if (format == "yaml") { YamlLines(oldBody, newBody, list); return list; }
        var a = Normalise(oldBody); var b = Normalise(newBody);
        if ((a is null && !string.IsNullOrWhiteSpace(oldBody)) || (b is null && !string.IsNullOrWhiteSpace(newBody)))
        {
            if (!string.Equals(oldBody, newBody, StringComparison.Ordinal)) list.Add(new ContentChange("(body)", "changed", oldBody, newBody));
            return list;
        }
        Walk("", a, b, list);
        return list;
    }

    private static void Walk(string path, JsonNode? x, JsonNode? y, List<ContentChange> list)
    {
        if (x is JsonObject ox && y is JsonObject oy)
        {
            foreach (var k in ox.Select(p => p.Key).Union(oy.Select(p => p.Key)).OrderBy(k => k, StringComparer.Ordinal))
            {
                var p = path.Length == 0 ? k : path + "." + k;
                if (!ox.ContainsKey(k)) list.Add(new ContentChange(p, "added", null, Text(oy[k])));
                else if (!oy.ContainsKey(k)) list.Add(new ContentChange(p, "removed", Text(ox[k]), null));
                else Walk(p, ox[k], oy[k], list);
            }
            return;
        }
        if (x is JsonArray ax && y is JsonArray ay)
        {
            for (var i = 0; i < Math.Max(ax.Count, ay.Count); i++)
            {
                var p = path + "[" + i.ToString(CultureInfo.InvariantCulture) + "]";
                if (i >= ax.Count) list.Add(new ContentChange(p, "added", null, Text(ay[i])));
                else if (i >= ay.Count) list.Add(new ContentChange(p, "removed", Text(ax[i]), null));
                else Walk(p, ax[i], ay[i], list);
            }
            return;
        }
        var tx = Text(x); var ty = Text(y);
        if (!string.Equals(tx, ty, StringComparison.Ordinal)) list.Add(new ContentChange(path.Length == 0 ? "(value)" : path, "changed", tx, ty));
    }

    /// YAML lines without comment-only and blank lines, a trailing " # comment" removed outside quotes.
    public static IReadOnlyList<string> YamlContentLines(string? body)
    {
        var lines = new List<string>();
        foreach (var raw in (body ?? "").TrimStart('﻿').Replace("\r\n", "\n").Split('\n'))
        {
            var t = raw.TrimEnd();
            if (t.TrimStart().StartsWith('#') || t.Trim().Length == 0) continue;
            lines.Add(StripTrailingComment(t));
        }
        return lines;
    }

    private static string StripTrailingComment(string line)
    {
        var sb = new StringBuilder(); char? q = null;
        for (var i = 0; i < line.Length; i++)
        {
            var c = line[i];
            if (q is null && (c == '\'' || c == '"')) q = c;
            else if (q == c) q = null;
            else if (q is null && c == '#' && i > 0 && char.IsWhiteSpace(line[i - 1])) break;
            sb.Append(c);
        }
        return sb.ToString().TrimEnd();
    }

    private static void YamlLines(string? oldBody, string? newBody, List<ContentChange> list)
    {
        var a = YamlContentLines(oldBody); var b = YamlContentLines(newBody);
        // longest common subsequence -- template bodies are small (a rule is tens of lines)
        var n = a.Count; var m = b.Count;
        var l = new int[n + 1, m + 1];
        for (var i = n - 1; i >= 0; i--) for (var j = m - 1; j >= 0; j--) l[i, j] = a[i] == b[j] ? l[i + 1, j + 1] + 1 : Math.Max(l[i + 1, j], l[i, j + 1]);
        int x = 0, y = 0;
        while (x < n || y < m)
        {
            if (x < n && y < m && a[x] == b[y]) { x++; y++; }
            else if (y < m && (x == n || l[x, y + 1] >= l[x + 1, y])) { list.Add(new ContentChange("line " + (y + 1).ToString(CultureInfo.InvariantCulture), "added", null, b[y].Trim())); y++; }
            else { list.Add(new ContentChange("line " + (x + 1).ToString(CultureInfo.InvariantCulture), "removed", a[x].Trim(), null)); x++; }
        }
    }
}
