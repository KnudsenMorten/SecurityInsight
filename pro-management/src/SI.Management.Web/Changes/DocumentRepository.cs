using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using SI.Management.Web.Data;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Changes;

public sealed record DocumentRow(string Kind, string Key, string Body, DateTime? UpdatedAt, string? UpdatedBy, long Version);

/// One document change: Set (create / replace) or Reset (remove). ExpectedVersion = the row's Version when it was
/// read (null = it did not exist then); a write is refused when the row moved on since.
public sealed record DocumentWrite(string Kind, string Key, string Action, string? Body, long? ExpectedVersion, string? Reason);

/// <summary>
/// THE one class that writes cfg.Document -- the C# twin of Set-SIProDocument (engine\pro-settings\SI-ProSettings.ps1):
/// validated FIRST by <see cref="DocumentValidator"/> (nothing is sent for a refused document), then ONE batch, ONE
/// transaction with its cfg.ChangeLog row (Name = the key, Scope 'document', Kind = the kind), and an optimistic
/// Version check. Tier changes from the tier board (asset pins, rule disables) are rule documents written here; a
/// whole-rule re-tier is a cfg.ItemOverride row of kind 'ruletier' (<see cref="ItemOverrideRepository"/>).
/// </summary>
public sealed class DocumentRepository
{
    public const string ListSql = """
IF OBJECT_ID(N'cfg.Document') IS NOT NULL
SELECT Kind, [Key] AS DocKey, Body, UpdatedAt, UpdatedBy, CONVERT(bigint, [Version]) AS Version
FROM cfg.Document
WHERE (@Kind IS NULL OR Kind = @Kind)
ORDER BY Kind, [Key];
""";

    public const string ReadSql = """
SELECT Kind, [Key] AS DocKey, Body, UpdatedAt, UpdatedBy, CONVERT(bigint, [Version]) AS Version
FROM cfg.Document
WHERE Kind = @Kind AND [Key] = @Key;
""";

    public const string WriteSql = """
SET XACT_ABORT ON;
BEGIN TRAN;
DECLARE @cur bigint = NULL, @old nvarchar(max) = NULL;
SELECT @cur = CONVERT(bigint, [Version]), @old = Body FROM cfg.Document WITH (UPDLOCK, HOLDLOCK) WHERE Kind = @Kind AND [Key] = @Key;
IF (@Expected IS NULL AND @cur IS NOT NULL) OR (@Expected IS NOT NULL AND (@cur IS NULL OR @cur <> @Expected))
BEGIN
    COMMIT;
    SELECT N'Stale' AS Outcome;
    RETURN;
END;
IF @Action = N'Reset'
    DELETE FROM cfg.Document WHERE Kind = @Kind AND [Key] = @Key;
ELSE IF @cur IS NOT NULL
    UPDATE cfg.Document SET Body = @Body, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By WHERE Kind = @Kind AND [Key] = @Key;
ELSE
    INSERT cfg.Document (Kind, [Key], Body, UpdatedBy) VALUES (@Kind, @Key, @Body, @By);
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (@Key, N'document', @Kind, @Action, @old, @Body, @By, @Reason);
COMMIT;
SELECT N'Saved' AS Outcome;
""";

    private readonly ISqlExecutor _sql;
    public DocumentRepository(ISqlExecutor sql) => _sql = sql;

    private static DocumentRow Map(SqlRow r) => new(r.Str("Kind") ?? "", r.Str("DocKey") ?? "", r.Str("Body") ?? "", r.Date("UpdatedAt"), r.Str("UpdatedBy"), r.Long("Version") ?? 0);

    /// Every cfg.Document of a kind (null = all). #251: the CMDB ownership map is a document of the Settings flow too, but
    /// it lives in cfg.ItemOverride (cfg.Document's CHECK allows only exclusions / weights / rule) -- listed with the rest
    /// when every kind or that kind is asked for.
    public async Task<IReadOnlyList<DocumentRow>> ListAsync(string? kind, CancellationToken ct)
    {
        var list = kind == OwnershipMapValidator.Kind ? new List<DocumentRow>()
            : (await _sql.QueryAsync(ListSql, new Dictionary<string, object?> { ["Kind"] = kind }, ct)).Select(Map).ToList();
        if (kind is null || kind == OwnershipMapValidator.Kind)
        {
            var map = await ReadConfigDocumentAsync(OwnershipMapValidator.Kind, OwnershipMapValidator.Key, ct);
            if (map is not null) list.Add(map);
        }
        return list;
    }

    public async Task<DocumentRow?> ReadAsync(string kind, string key, CancellationToken ct)
    {
        if (OwnershipMapValidator.Is(kind, key)) return await ReadConfigDocumentAsync(kind, key, ct);
        return (await _sql.QueryAsync(ReadSql, new Dictionary<string, object?> { ["Kind"] = kind, ["Key"] = key }, ct)).Select(Map).FirstOrDefault();
    }

    /// A configuration document (cmdbownership/map) as a document row: its body, who changed it, and its RowVersion as the
    /// version the optimistic check compares. Only a State 'override' row is a document.
    private async Task<DocumentRow?> ReadConfigDocumentAsync(string kind, string key, CancellationToken ct)
    {
        var r = (await _sql.QueryAsync(ItemOverrideRepository.ReadSql, new Dictionary<string, object?> { ["Kind"] = kind, ["Key"] = key }, ct)).FirstOrDefault();
        if (r is null || r.Str("State") != ItemOverrideRepository.StateOverride) return null;
        return new DocumentRow(kind, key, r.Str("BodyJson") ?? "", r.Date("UpdatedAt"), r.Str("UpdatedBy"), r.Long("Version") ?? 0);
    }

    /// The reasons a write is refused (empty = accepted). Sends nothing.
    public static IReadOnlyList<string> Validate(DocumentWrite w, IReadOnlyCollection<string> knownReports)
    {
        if (w.Action is not ("Set" or "Reset")) return new[] { $"unknown action '{w.Action}'" };
        if (w.Action == "Reset")
        {
            var k = DocumentValidator.KeyProblem(w.Kind, w.Key);
            if (k is not null) return new[] { k };
            return w.ExpectedVersion is null ? new[] { $"{w.Kind}/{w.Key} does not exist -- nothing to remove" } : Array.Empty<string>();
        }
        return DocumentValidator.Validate(w.Kind, w.Key, w.Body, knownReports);
    }

    public async Task<WriteResult> WriteAsync(DocumentWrite w, IReadOnlyCollection<string> knownReports, string by, CancellationToken ct)
    {
        var why = Validate(w, knownReports);
        if (why.Count > 0) return new WriteResult(WriteStatus.Refused, $"{w.Kind}/{w.Key}: " + string.Join("; ", why));
        if (string.IsNullOrWhiteSpace(by)) return new WriteResult(WriteStatus.Refused, "the signed-in user has no name to record");
        // #251: the ownership map is written to cfg.ItemOverride, never cfg.Document -- same version check, same ChangeLog row
        if (OwnershipMapValidator.Is(w.Kind, w.Key))
            return await new ItemOverrideRepository(_sql).WriteConfigDocumentAsync(w.Kind, w.Key, w.Action, w.Body, w.ExpectedVersion, by, w.Reason, ct);
        var reason = string.IsNullOrWhiteSpace(w.Reason) ? null : w.Reason.Trim();
        if (reason is { Length: > 400 }) reason = reason[..400];
        var rows = await _sql.QueryAsync(WriteSql, new Dictionary<string, object?>
        {
            ["Kind"] = w.Kind, ["Key"] = w.Key, ["Action"] = w.Action, ["Body"] = w.Action == "Reset" ? null : w.Body,
            ["Expected"] = w.ExpectedVersion, ["By"] = by.Length > 256 ? by[..256] : by, ["Reason"] = reason,
        }, ct);
        return (rows.Count > 0 ? rows[0].Str("Outcome") : null) switch
        {
            "Saved" => new WriteResult(WriteStatus.Saved, $"{w.Kind}/{w.Key} saved"),
            "Stale" => new WriteResult(WriteStatus.Stale, $"{w.Kind}/{w.Key} changed since it was staged -- nothing was written; stage it again"),
            _ => throw new InvalidOperationException("the document write returned no outcome"),
        };
    }
}

/// <summary>
/// The rule texts the tier board writes. Each carries the Settings page's marker (so the Community/Pro rule views treat
/// it as page-created) and passes <see cref="DocumentValidator.RuleProblems"/> by construction (a test proves it).
/// </summary>
public static class RuleTemplates
{
    public const string Marker = "# Created by the SecurityInsight Settings page";

    public static string EngineFor(string assetKind) => assetKind.ToLowerInvariant() switch
    {
        "endpoint" => "endpoint",
        "identity" => "identity",
        "azure" => "azure",
        _ => "shared",
    };

    /// What the id of a pin's rule starts with (the tier board tells a pin's claim from a rule's claim by it).
    public const string PinPrefix = "gui-pin-";

    /// A stable id per asset: re-pinning the same asset replaces its pin instead of adding a second rule.
    public static string PinId(string assetKey) =>
        PinPrefix + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(assetKey.ToLowerInvariant())))[..16].ToLowerInvariant();

    private static string Y(string s) => "'" + s.Replace("'", "''").Replace("\r", " ").Replace("\n", " ") + "'";

    /// A rule that sets the tier of ONE asset, matched by its exact name. Tiers combine as the lowest (most critical)
    /// of all matching rules, so a pin can make an asset MORE critical; a less critical tier also needs the rule that
    /// set the current tier changed.
    public static (string Key, string Body) Pin(string assetKey, string assetName, string assetKind, int tier, string reason)
    {
        var id = PinId(assetKey);
        var engine = EngineFor(assetKind);
        var applies = engine == "shared" ? (assetKind.Equals("publicip", StringComparison.OrdinalIgnoreCase) ? "publicip" : "any") : engine;
        var pattern = "(?i)^" + Regex.Escape(assetName) + "$";
        var purpose = $"Pinned to Tier {tier} in the management GUI";
        var body = string.Join("\r\n", new[]
        {
            $"{Marker} -- pins {assetName.Replace("\r", " ").Replace("\n", " ")} to Tier {tier} (management GUI).",
            $"id: {id}", $"appliesTo: {applies}", "mode: append", $"purpose: {Y(purpose)}", "category: 'Custom'", $"description: {Y(reason)}",
            "", "detections:", $"  - id: {id}", "    detect:", "      any:", "        - kind: nameMatches", "          namePatterns:",
            $"            - {Y(pattern)}", "    set:", $"      Tier: {tier}", $"      Purpose: {Y(purpose)}", "      Category: 'Custom'", "",
        });
        return ($"{engine}/{id}", body);
    }

    /// Turns a rule off (the Settings page's own 'disable' text).
    public static string Disable(string ruleKey)
    {
        var id = ruleKey[(ruleKey.IndexOf('/') + 1)..];
        return $"{Marker} -- turns off the shipped rule {id}.\r\nid: {id}\r\nmode: disable\r\n";
    }
}
