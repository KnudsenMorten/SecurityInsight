using System.Text.Json;
using System.Text.RegularExpressions;
using SI.Management.Web.Data;

namespace SI.Management.Web.Settings;

public sealed record SettingRow(string Name, string Scope, string? ValueJson, string? KeyVaultSecretName, DateTime? UpdatedAt, string? UpdatedBy, long Version);
public sealed record ChangeLogRow(long ChangeId, string Name, string Scope, string Action, string? OldValue, string? NewValue, DateTime? ChangedAt, string ChangedBy, string? Reason);

/// Read side of cfg (sql\si-pro-settings.sql). Each read returns the SQL it ran, for the page's "query behind this".
public interface ISettingsStoreReader
{
    Task<(IReadOnlyList<SettingRow> Rows, string Query)> ReadSettingsAsync(CancellationToken ct);
    Task<(IReadOnlyList<ChangeLogRow> Rows, string Query)> ReadChangeLogAsync(string? nameContains, int top, CancellationToken ct);
}

public sealed class SqlSettingsReader : ISettingsStoreReader
{
    public const string SettingsSql =
        "SELECT Name, Scope, ValueJson, KeyVaultSecretName, UpdatedAt, UpdatedBy, CONVERT(bigint, RowVersion) AS Version\n" +
        "FROM cfg.Setting\nORDER BY Name, Scope;";

    public const string ChangeLogSql =
        "SELECT TOP (@Top) ChangeId, Name, Scope, Action, OldValue, NewValue, ChangedAt, ChangedBy, Reason\n" +
        "FROM cfg.ChangeLog\nWHERE (@Name IS NULL OR Name LIKE @Name)\nORDER BY ChangeId DESC;";

    private readonly ISqlExecutor _sql;
    public SqlSettingsReader(ISqlExecutor sql) => _sql = sql;

    public async Task<(IReadOnlyList<SettingRow> Rows, string Query)> ReadSettingsAsync(CancellationToken ct)
    {
        var rows = await _sql.QueryAsync(SettingsSql, new Dictionary<string, object?>(), ct);
        return (rows.Select(r => new SettingRow(r.Str("Name")!, r.Str("Scope")!, r.Str("ValueJson"), r.Str("KeyVaultSecretName"),
            r.Date("UpdatedAt"), r.Str("UpdatedBy"), r.Long("Version") ?? 0)).ToList(), SettingsSql);
    }

    public async Task<(IReadOnlyList<ChangeLogRow> Rows, string Query)> ReadChangeLogAsync(string? nameContains, int top, CancellationToken ct)
    {
        var p = new Dictionary<string, object?>
        {
            ["Top"] = Math.Clamp(top, 1, 2000),
            ["Name"] = string.IsNullOrWhiteSpace(nameContains) ? null : "%" + EscapeLike(nameContains.Trim()) + "%",
        };
        var rows = await _sql.QueryAsync(ChangeLogSql, p, ct);
        return (rows.Select(r => new ChangeLogRow(r.Long("ChangeId") ?? 0, r.Str("Name")!, r.Str("Scope")!, r.Str("Action")!, r.Str("OldValue"),
            r.Str("NewValue"), r.Date("ChangedAt"), r.Str("ChangedBy") ?? "", r.Str("Reason"))).ToList(), ChangeLogSql);
    }

    /// A user's filter text is matched literally: LIKE's own wildcards are escaped.
    internal static string EscapeLike(string s) => s.Replace("[", "[[]").Replace("%", "[%]").Replace("_", "[_]");
}

/// One change as the edit form posts it. ExpectedVersion is the row's RowVersion when the operator READ it (null = the
/// row did not exist then); a write is refused when the row has moved on since.
public sealed record SettingWrite(string Name, string Scope, string Action, JsonElement? Value, string? KeyVaultSecretName, long? ExpectedVersion, string? Reason);

/// A change that passed validation: exactly what the SQL will store.
public sealed record PreparedChange(SettingWrite Change, CatalogSetting Setting, string? ValueJson, string? KeyVaultSecretName);

public enum WriteStatus { Saved, Refused, Stale }
public sealed record WriteResult(WriteStatus Status, string Message, long? NewVersion = null);

/// <summary>
/// The C# twin of Set-SIProSetting (engine\pro-settings\SI-ProSettings.ps1), plus the optimistic-concurrency check the
/// page needs: validation FIRST (no SQL is sent for a refused change); then ONE batch, ONE transaction carrying the
/// upsert (or the Reset's removal) and its cfg.ChangeLog row; a secret only ever as a Key Vault secret NAME; and a
/// write whose RowVersion no longer matches what the operator reviewed is refused, writing nothing.
/// </summary>
public sealed class SettingsWriter
{
    public const string WriteSql = """
SET XACT_ABORT ON;
BEGIN TRAN;
DECLARE @cur bigint = NULL, @old nvarchar(max) = NULL;
SELECT @cur = CONVERT(bigint, RowVersion), @old = COALESCE(ValueJson, N'keyvault:' + KeyVaultSecretName)
  FROM cfg.Setting WITH (UPDLOCK, HOLDLOCK) WHERE Name = @Name AND Scope = @Scope;
IF (@Expected IS NULL AND @cur IS NOT NULL) OR (@Expected IS NOT NULL AND (@cur IS NULL OR @cur <> @Expected))
BEGIN
    COMMIT;
    SELECT N'Stale' AS Outcome, @cur AS Version;
    RETURN;
END;
IF @Action = N'Reset'
    DELETE FROM cfg.Setting WHERE Name = @Name AND Scope = @Scope;
ELSE IF @cur IS NOT NULL
    UPDATE cfg.Setting SET ValueJson = @ValueJson, KeyVaultSecretName = @Kv, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By
     WHERE Name = @Name AND Scope = @Scope;
ELSE
    INSERT cfg.Setting (Name, Scope, ValueJson, KeyVaultSecretName, UpdatedBy) VALUES (@Name, @Scope, @ValueJson, @Kv, @By);
INSERT cfg.ChangeLog (Name, Scope, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (@Name, @Scope, @Action, @old, COALESCE(@ValueJson, N'keyvault:' + @Kv), @By, @Reason);
DECLARE @new bigint = (SELECT CONVERT(bigint, RowVersion) FROM cfg.Setting WHERE Name = @Name AND Scope = @Scope);
COMMIT;
SELECT N'Saved' AS Outcome, @new AS Version;
""";

    /// Key Vault secret names: 1-127 of letters, digits and dashes.
    private static readonly Regex KvName = new("^[0-9A-Za-z-]{1,127}$", RegexOptions.CultureInvariant);
    private static readonly Regex ScopePattern = new("^engine:[a-z0-9\\-]+$", RegexOptions.CultureInvariant);

    /// The words for a secret value typed where its Key Vault secret NAME belongs (operator 2026-10-09: the Azure OpenAI
    /// key typed into the name field).
    public const string NotTheKey = "This field takes the name of the secret in your Key Vault, not the key itself";
    private static readonly Regex HexRun = new("^[0-9A-Fa-f]{32,}$", RegexOptions.CultureInvariant);
    private static readonly Regex KeyChars = new("[+/=]", RegexOptions.CultureInvariant);

    /// Does a "secret name" look like the secret itself? A key: 32+ hex characters (an Azure OpenAI / Cognitive Services
    /// key), base64 characters (+ / =), or a long run of letters AND digits without a dash -- a Key Vault secret name is
    /// letters, digits and dashes, and the names people give are words with dashes ("SI-OpenAI-Key").
    public static bool LooksLikeKey(string? text)
    {
        var t = (text ?? "").Trim();
        if (t.Length == 0) return false;
        if (HexRun.IsMatch(t)) return true;
        if (t.Length >= 20 && KeyChars.IsMatch(t)) return true;
        return t.Length >= 40 && !t.Contains('-') && t.Any(char.IsDigit) && t.Any(char.IsLetter);
    }

    private readonly ISqlExecutor _sql;
    private readonly SettingsCatalog _catalog;

    /// #302 (AUDIT-1.1): a saved setting is put in force by the jobs at their next run -- who saved it is recorded at the save.
    private readonly SI.Management.Web.Audit.IChangeAttributionWriter? _attribution;

    /// The web app's memory cache: the header's context (environment name, tenant name, update ring) is kept there for a
    /// minute, and a saved setting drops it so the next page shows the new value (null in tests that build a writer by hand).
    private readonly Microsoft.Extensions.Caching.Memory.IMemoryCache? _cache;

    public SettingsWriter(ISqlExecutor sql, SettingsCatalog catalog, SI.Management.Web.Audit.IChangeAttributionWriter? attribution = null,
        Microsoft.Extensions.Caching.Memory.IMemoryCache? cache = null) { _sql = sql; _catalog = catalog; _attribution = attribution; _cache = cache; }

    /// <summary>Validate a change. Returns the prepared change, or the reason it is refused. Sends nothing.</summary>
    public (PreparedChange? Prepared, string? Refusal) Prepare(SettingWrite c)
    {
        var s = _catalog.Find(c.Name);
        if (s is null) return (null, $"'{c.Name}' is not a known setting");
        if (c.Scope != "solution" && !ScopePattern.IsMatch(c.Scope)) return (null, $"'{c.Scope}' is not a valid scope");
        // a web-app setting at any engine-visible scope would be refused at run start and stop the run
        if (s.WebOnly && c.Scope != CatalogSetting.WebScope) return (null, $"{s.Name} is a setting of the management web app: it is stored only at {CatalogSetting.WebScope}");
        if (!s.WebOnly && c.Scope == CatalogSetting.WebScope) return (null, $"{CatalogSetting.WebScope} holds only the web app's own settings");
        if (c.Action is not ("Set" or "Reset")) return (null, $"unknown action '{c.Action}'");
        // read only by setup: a stored value would change nothing until setup runs again (a Reset of an old row is allowed)
        if (s.SetupOnly && c.Action == "Set") return (null, $"{s.Name}: {CatalogSetting.SetupOnlyNote} -- it cannot be changed here");
        if (c.Action == "Reset")
        {
            if (c.ExpectedVersion is null) return (null, $"{s.Name} has no row at {c.Scope} -- nothing to reset");
            return (new PreparedChange(c with { Name = s.Name }, s, null, null), null);
        }
        if (s.Secret)
        {
            if (c.Value is { ValueKind: not (JsonValueKind.Null or JsonValueKind.Undefined) })
                return (null, $"{s.Name} is a secret: give its Key Vault secret name, never the value");
            var kv = c.KeyVaultSecretName?.Trim();
            if (string.IsNullOrEmpty(kv)) return (null, $"{s.Name} is a secret: give its Key Vault secret name, never the value");
            // a key typed into the name field would be stored as plain text in cfg.Setting: refused, and never echoed back
            if (LooksLikeKey(kv)) return (null, NotTheKey);
            if (!KvName.IsMatch(kv)) return (null, $"'{kv}' is not a Key Vault secret name (letters, digits and dashes, at most 127)");
            return (new PreparedChange(c with { Name = s.Name }, s, null, kv), null);
        }
        if (!string.IsNullOrEmpty(c.KeyVaultSecretName)) return (null, $"only a secret setting may point at Key Vault -- {s.Name} is not a secret");
        var why = SettingValidator.Validate(s, c.Value);
        if (why is not null) return (null, $"{s.Name} {why}");
        var json = c.Value is { } v ? SettingJson.ToStoredText(v) : "null";
        return (new PreparedChange(c with { Name = s.Name }, s, json, null), null);
    }

    public async Task<WriteResult> WriteAsync(SettingWrite change, string changedBy, CancellationToken ct)
    {
        var (p, refusal) = Prepare(change);
        if (p is null) return new WriteResult(WriteStatus.Refused, refusal!);
        if (string.IsNullOrWhiteSpace(changedBy)) return new WriteResult(WriteStatus.Refused, "the signed-in user has no name to record");
        var reason = string.IsNullOrWhiteSpace(change.Reason) ? null : change.Reason.Trim();
        if (reason is { Length: > 400 }) return new WriteResult(WriteStatus.Refused, "the reason is longer than 400 characters");
        var parameters = new Dictionary<string, object?>
        {
            ["Name"] = p.Change.Name, ["Scope"] = p.Change.Scope, ["Action"] = p.Change.Action,
            ["ValueJson"] = p.ValueJson, ["Kv"] = p.KeyVaultSecretName,
            ["Expected"] = p.Change.ExpectedVersion, ["By"] = changedBy.Length > 256 ? changedBy[..256] : changedBy, ["Reason"] = reason,
        };
        var rows = await _sql.QueryAsync(WriteSql, parameters, ct);
        var outcome = rows.Count > 0 ? rows[0].Str("Outcome") : null;
        return outcome switch
        {
            "Saved" => await SavedAsync(p, changedBy, rows[0].Long("Version"), ct),
            "Stale" => new WriteResult(WriteStatus.Stale, $"{p.Change.Name} ({p.Change.Scope}) changed since you read it -- nothing was written; reload and review again"),
            _ => throw new InvalidOperationException("the settings write returned no outcome"),
        };
    }

    private async Task<WriteResult> SavedAsync(PreparedChange p, string changedBy, long? version, CancellationToken ct)
    {
        // the header read its values up to a minute ago: after a save the next page reads them again (owner 2026-10-12:
        // a new environment name was saved, the header kept the old one, and a second Save answered "Nothing changed.")
        if (_cache is not null) SI.Management.Web.Pages.HeaderContext.Forget(_cache);
        if (_attribution is not null && !p.Setting.WebOnly)
            await _attribution.RecordAsync(SI.Management.Web.Audit.ChangeAttribution.CorrelationId(),
                [new SI.Management.Web.Audit.AttributionEntry($"setting:{p.Change.Name}@{p.Change.Scope}", changedBy, SI.Management.Web.Audit.AttributionKinds.Change,
                    p.Change.Action == "Reset" ? SI.Management.Web.Audit.AttributionOps.Remove : SI.Management.Web.Audit.AttributionOps.Set) { Title = $"{p.Change.Name} ({p.Change.Scope}) {(p.Change.Action == "Reset" ? "reset" : "saved")}" }], ct);
        return new WriteResult(WriteStatus.Saved, $"{p.Change.Name} ({p.Change.Scope}) saved", version);
    }
}

public enum DiffKind { Added, Changed, Removed, Unchanged }
public sealed record DiffEntry(string Name, string Scope, DiffKind Kind, string Old, string New);

/// The review step: what the row is now, and what it becomes.
public static class SettingsDiff
{
    public const string NotSet = "(not set here -- the files / shipped default apply)";

    public static string Display(string? valueJson, string? kv) =>
        kv is not null ? $"Key Vault secret: {kv}" : valueJson ?? NotSet;

    public static DiffEntry Build(SettingRow? current, PreparedChange p)
    {
        var old = current is null ? NotSet : Display(current.ValueJson, current.KeyVaultSecretName);
        if (p.Change.Action == "Reset")
            return new DiffEntry(p.Change.Name, p.Change.Scope, current is null ? DiffKind.Unchanged : DiffKind.Removed, old, NotSet);
        var @new = Display(p.ValueJson, p.KeyVaultSecretName);
        if (current is null) return new DiffEntry(p.Change.Name, p.Change.Scope, DiffKind.Added, old, @new);
        var same = p.KeyVaultSecretName is not null
            ? string.Equals(current.KeyVaultSecretName, p.KeyVaultSecretName, StringComparison.Ordinal) && current.ValueJson is null
            : current.KeyVaultSecretName is null && JsonEquals(current.ValueJson, p.ValueJson);
        return new DiffEntry(p.Change.Name, p.Change.Scope, same ? DiffKind.Unchanged : DiffKind.Changed, old, @new);
    }

    /// Two stored values are the same when they are the same JSON (formatting aside).
    internal static bool JsonEquals(string? a, string? b)
    {
        if (a is null || b is null) return a == b;
        try
        {
            using var da = JsonDocument.Parse(a);
            using var db = JsonDocument.Parse(b);
            return SettingJson.ToStoredText(da.RootElement) == SettingJson.ToStoredText(db.RootElement);
        }
        catch (JsonException) { return a == b; }
    }
}
