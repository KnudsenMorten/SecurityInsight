using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.DataProtection;
using SI.Management.Web.Data;

namespace SI.Management.Web.ChangeJournal;

/// One configuration backup. NoChange = it records that nothing changed since the backup it points at (SameAsBackupId).
public sealed record ConfigBackup(long Id, DateTime TakenUtc, string TakenBy, string Trigger, string ContentHash, long? SameAsBackupId, string? Counts,
    string? ProductVersion, string? Note, bool Pinned, string? PinnedBy, DateTime? PinnedUtc, string? PinNote)
{
    public bool NoChange => SameAsBackupId is not null;
    /// "setting 12 · department 4 ..." from the counts JSON.
    public IReadOnlyList<(string Entity, long N)> CountList
    {
        get
        {
            if (string.IsNullOrWhiteSpace(Counts)) return Array.Empty<(string, long)>();
            try { return (JsonNode.Parse(Counts) as JsonArray ?? new JsonArray()).OfType<JsonObject>().Select(o => (ConfigEntities.Text(o["e"]), o["n"]?.GetValue<long>() ?? 0)).ToList(); }
            catch (Exception ex) when (ex is JsonException or InvalidOperationException or FormatException) { return Array.Empty<(string, long)>(); }
        }
    }
    public long Records => CountList.Sum(c => c.N);
}

/// One record of a backup's content: entity, key and the full record.
public sealed record ConfigRecord(string Entity, string Key, JsonObject Record);

public interface IConfigBackupStore
{
    Task<bool> ExistsAsync(CancellationToken ct);
    Task<IReadOnlyList<ConfigBackup>> ListAsync(int top, CancellationToken ct);
    Task<ConfigBackup?> FindAsync(long id, CancellationToken ct);
    /// The backup's content (a "no change" backup's is the content it points at).
    Task<IReadOnlyList<ConfigRecord>> ContentAsync(long id, CancellationToken ct);
    /// The configuration in force now, in the backup's shape.
    Task<IReadOnlyList<ConfigRecord>> NowAsync(CancellationToken ct);
    Task<(long Id, bool NoChange)> TakeAsync(string by, string trigger, string? note, string? commitId, string? version, CancellationToken ct);
    Task<long> ImportAsync(string contentJson, string by, string? note, string? commitId, string? version, CancellationToken ct);
    Task<bool> PinAsync(long id, bool pinned, string by, string? note, CancellationToken ct);
}

/// <summary>
/// #404 (framework CONFIG-1.3) -- the configuration backups. Taken, imported and pinned ONLY through the owner-chained
/// procedures (cfg.ConfigBackupTake / Import / Pin: every identity is DENIED direct writes on cfg.ConfigBackup); read with
/// the same least-privilege reads as the configuration. Pruning is the backup job's (cfg.ConfigBackupPrune, audited).
/// </summary>
public sealed class SqlConfigBackupStore : IConfigBackupStore
{
    public const string ExistsSql = "SELECT CASE WHEN OBJECT_ID(N'cfg.ConfigBackup') IS NOT NULL AND OBJECT_ID(N'cfg.vConfigSnapshot') IS NOT NULL THEN 1 ELSE 0 END AS HasTable;";
    private const string Cols = "BackupId, TakenUtc, TakenBy, TriggerKind, ContentHash, SameAsBackupId, EntityCountsJson, ProductVersion, Note, Pinned, PinnedBy, PinnedUtc, PinNote";
    public const string ListSql = "SELECT TOP (@Top) " + Cols + " FROM cfg.ConfigBackup ORDER BY BackupId DESC;";
    public const string FindSql = "SELECT " + Cols + " FROM cfg.ConfigBackup WHERE BackupId = @Id;";
    public const string ContentSql =
        "SELECT CAST(DECOMPRESS(c.Content) AS NVARCHAR(MAX)) AS ContentJson FROM cfg.ConfigBackup AS b\n" +
        "JOIN cfg.ConfigBackup AS c ON c.BackupId = COALESCE(b.SameAsBackupId, b.BackupId) WHERE b.BackupId = @Id;";
    public const string NowSql = "SELECT Entity, EntityKey, RecordJson FROM cfg.vConfigSnapshot ORDER BY Entity, EntityKey;";
    public const string TakeSql = "EXEC cfg.ConfigBackupTake @TakenBy = @By, @Trigger = @Trigger, @Note = @Note, @CommitId = @CommitId, @ProductVersion = @Version;";
    public const string ImportSql = "EXEC cfg.ConfigBackupImport @ContentJson = @Json, @TakenBy = @By, @Note = @Note, @CommitId = @CommitId, @ProductVersion = @Version;";
    public const string PinSql = "EXEC cfg.ConfigBackupPin @BackupId = @Id, @Pinned = @Pinned, @By = @By, @Note = @Note;";

    private readonly ISqlExecutor _sql;
    public SqlConfigBackupStore(ISqlExecutor sql) => _sql = sql;
    private static Dictionary<string, object?> P(params (string K, object? V)[] kv) => kv.ToDictionary(x => x.K, x => x.V);

    public async Task<bool> ExistsAsync(CancellationToken ct) => (await _sql.QueryAsync(ExistsSql, P(), ct)).FirstOrDefault()?.Long("HasTable") == 1;

    private static DateTime? Utc(DateTime? d) => d is { } x ? DateTime.SpecifyKind(x, DateTimeKind.Utc) : null;
    private static ConfigBackup From(SqlRow r) => new(r.Long("BackupId") ?? 0, Utc(r.Date("TakenUtc")) ?? DateTime.MinValue, r.Str("TakenBy") ?? "", r.Str("TriggerKind") ?? "",
        r.Str("ContentHash") ?? "", r.Long("SameAsBackupId"), r.Str("EntityCountsJson"), r.Str("ProductVersion"), r.Str("Note"),
        r.TryGetValue("Pinned", out var pv) && pv is bool b && b, r.Str("PinnedBy"), Utc(r.Date("PinnedUtc")), r.Str("PinNote"));

    public async Task<IReadOnlyList<ConfigBackup>> ListAsync(int top, CancellationToken ct) =>
        (await _sql.QueryAsync(ListSql, P(("Top", Math.Clamp(top, 1, 2000))), ct)).Select(From).ToList();

    public async Task<ConfigBackup?> FindAsync(long id, CancellationToken ct) =>
        (await _sql.QueryAsync(FindSql, P(("Id", id)), ct)).Select(From).FirstOrDefault();

    public async Task<IReadOnlyList<ConfigRecord>> ContentAsync(long id, CancellationToken ct)
    {
        var json = (await _sql.QueryAsync(ContentSql, P(("Id", id)), ct)).FirstOrDefault()?.Str("ContentJson");
        return ConfigBackupFile.ParseContent(json);
    }

    public async Task<IReadOnlyList<ConfigRecord>> NowAsync(CancellationToken ct) =>
        (await _sql.QueryAsync(NowSql, P(), ct)).Select(r => ConfigEntities.Parse(r.Str("RecordJson")) is { } o ? new ConfigRecord(r.Str("Entity") ?? "", r.Str("EntityKey") ?? "", o) : null)
            .Where(x => x is not null).Select(x => x!).ToList();

    public async Task<(long Id, bool NoChange)> TakeAsync(string by, string trigger, string? note, string? commitId, string? version, CancellationToken ct)
    {
        var r = (await _sql.QueryAsync(TakeSql, P(("By", by), ("Trigger", trigger), ("Note", note), ("CommitId", commitId), ("Version", version)), ct)).FirstOrDefault();
        return (r?.Long("BackupId") ?? 0, (r?.Long("NoChange") ?? 0) == 1);
    }

    public async Task<long> ImportAsync(string contentJson, string by, string? note, string? commitId, string? version, CancellationToken ct) =>
        (await _sql.QueryAsync(ImportSql, P(("Json", contentJson), ("By", by), ("Note", note), ("CommitId", commitId), ("Version", version)), ct)).FirstOrDefault()?.Long("BackupId") ?? 0;

    public async Task<bool> PinAsync(long id, bool pinned, string by, string? note, CancellationToken ct) =>
        (await _sql.QueryAsync(PinSql, P(("Id", id), ("Pinned", pinned), ("By", by), ("Note", note)), ct)).FirstOrDefault()?.Long("Changed") == 1;
}

/// <summary>
/// PURE. CONFIG-1.4 -- a backup against now, per entity, record and field: added since (in force now, not in the backup),
/// removed since (in the backup, not in force now) and changed since (both, the content differs -- the fields that differ,
/// old -> new). The stamps (who saved it, when) never make a difference.
/// </summary>
public static class ConfigDiff
{
    public enum Kind { AddedSince, RemovedSince, ChangedSince }

    public sealed record Item(ConfigEntities.Entity Entity, string Key, Kind Kind, JsonObject? Backup, JsonObject? Now, IReadOnlyList<(string Field, string? Backup, string? Now)> Fields)
    {
        /// What restoring it does: put the backup's record back (Add), take the new one out (Remove), set it back (Modify).
        public string RestoreOp => Kind switch { Kind.AddedSince => "Remove", Kind.RemovedSince => "Add", _ => "Modify" };
        public string Id => Entity.Name + "|" + Key;
        public string Words => Kind switch { Kind.AddedSince => "added since", Kind.RemovedSince => "removed since", _ => "changed since" };
    }

    public static IReadOnlyList<Item> Compare(IReadOnlyList<ConfigRecord> backup, IReadOnlyList<ConfigRecord> now, ConfigEntities entities)
    {
        var b = backup.GroupBy(r => (r.Entity, r.Key)).ToDictionary(g => g.Key, g => g.First().Record);
        var n = now.GroupBy(r => (r.Entity, r.Key)).ToDictionary(g => g.Key, g => g.First().Record);
        var list = new List<Item>();
        foreach (var key in b.Keys.Union(n.Keys))
        {
            var e = entities.Find(key.Entity);
            if (e is null || !e.Backup) continue;
            b.TryGetValue(key, out var bo); n.TryGetValue(key, out var no);
            if (bo is not null && no is not null)
            {
                if (ConfigEntities.SameContent(e, bo, no)) continue;
                list.Add(new Item(e, key.Key, Kind.ChangedSince, bo, no, ConfigEntities.Fields(e, no, bo).Select(f => (f.Field, f.After, f.Before)).ToList()));
            }
            else if (bo is not null) list.Add(new Item(e, key.Key, Kind.RemovedSince, bo, null, ConfigEntities.Fields(e, null, bo).Select(f => (f.Field, f.After, f.Before)).ToList()));
            else list.Add(new Item(e, key.Key, Kind.AddedSince, null, no, ConfigEntities.Fields(e, no, null).Select(f => (f.Field, f.After, f.Before)).ToList()));
        }
        return list.OrderBy(i => i.Entity.Order).ThenBy(i => i.Key, StringComparer.Ordinal).ToList();
    }
}

/// <summary>
/// CONFIG-1.3 -- THE BACKUP FILE: one format, signed. JSON with the product, the backup's time and who took it, the
/// content (the configuration set's records) and its SHA-256. The signature is the content hash protected by the web
/// app's own data-protection key ring (cfg.WebKeyRing -- shared by every revision and replica; no new private key exists
/// anywhere): this installation verifies its own files; a file from another installation reads "signed elsewhere -- cannot
/// be verified here", and importing it needs an explicit tick (audited). A file whose content does not match its hash is
/// refused outright.
/// </summary>
public static class ConfigBackupFile
{
    public const string Format = "securityinsight-config-backup";
    public const int Version = 1;
    public const string Purpose = "SecurityInsight.ConfigBackup.v1";

    public enum Verdict { Verified, SignedElsewhere, Unsigned, Corrupt }

    /// PURE. Lower-case hex SHA-256 of the content's UTF-8 bytes.
    public static string Sha256(string content) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(content))).ToLowerInvariant();

    public static string Build(ConfigBackup b, string contentJson, string exportedBy, DateTime exportedUtc, IDataProtector protector, string? productVersion)
    {
        // the hash is over the content in its compact form (what Read recomputes from the parsed file, whatever its indent)
        var compact = JsonNode.Parse(contentJson)!.ToJsonString();
        var hash = Sha256(compact);
        var o = new JsonObject
        {
            ["format"] = Format, ["version"] = Version, ["productVersion"] = productVersion, ["backupId"] = b.Id,
            ["takenUtc"] = b.TakenUtc.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture), ["takenBy"] = b.TakenBy,
            ["exportedUtc"] = exportedUtc.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture), ["exportedBy"] = exportedBy,
            ["contentSha256"] = hash, ["signature"] = protector.Protect(hash), ["content"] = JsonNode.Parse(compact),
        };
        return o.ToJsonString(new JsonSerializerOptions { WriteIndented = true });
    }

    /// Reads a file: its content (as the JSON text it carries) and how far it can be trusted.
    public static (Verdict Verdict, string? Content, JsonObject? Header, string Message) Read(string fileText, IDataProtector protector)
    {
        JsonObject? o;
        try { o = JsonNode.Parse(fileText) as JsonObject; } catch (JsonException) { o = null; }
        if (o is null || ConfigEntities.Text(o["format"]) != Format) return (Verdict.Corrupt, null, null, "this is not a SecurityInsight configuration backup file");
        if (o["content"] is not JsonArray content) return (Verdict.Corrupt, null, o, "the file holds no configuration");
        var text = content.ToJsonString();
        var claimed = ConfigEntities.Text(o["contentSha256"]);
        if (!string.Equals(Sha256(text), claimed, StringComparison.Ordinal)) return (Verdict.Corrupt, null, o, "the content does not match its checksum -- the file was changed or damaged; nothing can be imported from it");
        var sig = ConfigEntities.Text(o["signature"]);
        if (string.IsNullOrEmpty(sig)) return (Verdict.Unsigned, text, o, "the file carries no signature");
        try { return protector.Unprotect(sig) == claimed ? (Verdict.Verified, text, o, "signed by this installation") : (Verdict.Corrupt, null, o, "the signature does not match the content"); }
        catch (CryptographicException) { return (Verdict.SignedElsewhere, text, o, "signed by another installation -- it cannot be verified here"); }
    }

    /// PURE. The content array ([{e, k, r}, ...]) as records; anything unreadable is left out.
    public static IReadOnlyList<ConfigRecord> ParseContent(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return Array.Empty<ConfigRecord>();
        try
        {
            return (JsonNode.Parse(json) as JsonArray ?? new JsonArray()).OfType<JsonObject>()
                .Where(o => o["r"] is JsonObject).Select(o => new ConfigRecord(ConfigEntities.Text(o["e"]), ConfigEntities.Text(o["k"]), (JsonObject)o["r"]!.DeepClone())).ToList();
        }
        catch (JsonException) { return Array.Empty<ConfigRecord>(); }
    }
}
