using System.Text.Json;
using System.Text.Json.Nodes;

namespace SI.Management.Web.ChangeJournal;

/// <summary>
/// #404 (framework CONFIG-1) -- THE CONFIGURATION SET: config\config-entities.locked.json, linked next to the app (the SAME
/// file the schema generator and PowerShell read). Every customer-made configuration record of the Pro database: what the
/// change journal records (one trigger per table), what a backup holds (cfg.vConfigSnapshot) and what an undo or a
/// restore may write back -- through <see cref="ConfigApplier"/>, the one generic writer, with the entity's own rules
/// (its key, its soft removal, its stamps, the role that may change it).
/// </summary>
public sealed class ConfigEntities
{
    public sealed record Soft(string At, string? By);

    public sealed record Entity(string Name, string Label, string Table, IReadOnlyList<string> Pk, string? Identity, IReadOnlyList<string> Key,
        IReadOnlyList<string> Columns, IReadOnlyList<string> Meta, Soft? SoftRemove, bool Backup, bool Undo, string? NoUndoWhy, string MinRole,
        string ChangeLogScope, string? FixedSource, int Order)
    {
        /// The columns that say what the record IS (compared, diffed and restored): every column but the stamps.
        public IReadOnlyList<string> Content => Columns.Where(c => !Meta.Contains(c, StringComparer.Ordinal)).ToList();
        public bool Has(string column) => Columns.Contains(column, StringComparer.Ordinal);
        /// The stamp a write sets to now / to the person (never restored from a record).
        public string? UpdatedAt => Has("UpdatedAt") ? "UpdatedAt" : null;
        public string? UpdatedBy => Has("UpdatedBy") ? "UpdatedBy" : null;
    }

    public IReadOnlyList<Entity> All { get; }
    public IReadOnlyList<string> Sources { get; }
    private readonly Dictionary<string, Entity> _by;

    public ConfigEntities(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var r = doc.RootElement;
        static List<string> L(JsonElement e, string n) => e.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.Array ? v.EnumerateArray().Select(x => x.GetString()!).ToList() : new();
        static string? S(JsonElement e, string n) => e.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
        static bool B(JsonElement e, string n) => e.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.True;
        Sources = L(r, "sources");
        var i = 0;
        All = r.GetProperty("entities").EnumerateArray().Select(e => new Entity(
            S(e, "entity")!, S(e, "label")!, S(e, "table")!, L(e, "pk"), S(e, "identity"), L(e, "key"), L(e, "columns"), L(e, "meta"),
            e.TryGetProperty("soft", out var s) && s.ValueKind == JsonValueKind.Object ? new Soft(S(s, "at")!, S(s, "by")) : null,
            B(e, "backup"), B(e, "undo"), S(e, "noUndoWhy"), S(e, "minRole") ?? "Admin", S(e, "changeLogScope") ?? "other", S(e, "source"), i++)).ToList();
        foreach (var e in All)
        {
            if (!System.Text.RegularExpressions.Regex.IsMatch(e.Table, "^cfg\\.[A-Za-z]+$")) throw new InvalidOperationException($"configuration entity '{e.Name}': table '{e.Table}' is not cfg.<Name>");
            foreach (var c in e.Columns.Concat(e.Key).Concat(e.Pk))
                if (!System.Text.RegularExpressions.Regex.IsMatch(c, "^[A-Za-z][A-Za-z0-9]*$")) throw new InvalidOperationException($"configuration entity '{e.Name}': column '{c}' is not a plain name");
        }
        _by = All.ToDictionary(e => e.Name, StringComparer.Ordinal);
    }

    public Entity? Find(string? name) => name is not null && _by.TryGetValue(name, out var e) ? e : null;
    public IEnumerable<Entity> Backed => All.Where(e => e.Backup);

    /// PURE. The record's key text as the triggers write it (key columns joined with '|', a missing value empty).
    public static string KeyOf(Entity e, JsonObject record) => string.Join("|", e.Key.Select(k => Text(record[k])));

    /// PURE. A JSON value as SQL's CONCAT writes it in the key (a string as is, a number as written, true/false as 1/0).
    public static string Text(JsonNode? n) => n switch
    {
        null => "",
        JsonValue v when v.TryGetValue<string>(out var s) => s,
        JsonValue v when v.TryGetValue<bool>(out var b) => b ? "1" : "0",
        _ => n.ToJsonString(),
    };

    /// PURE. The content of a record (the stamps left out), in catalog order -- what a diff and a change-since check compare.
    public static JsonObject ContentOf(Entity e, JsonObject record)
    {
        var o = new JsonObject();
        foreach (var c in e.Content) o[c] = record[c]?.DeepClone();
        return o;
    }

    /// PURE. Two records say the same thing (content only, byte for byte as JSON).
    public static bool SameContent(Entity e, JsonObject? a, JsonObject? b) =>
        a is null || b is null ? a is null && b is null : ContentOf(e, a).ToJsonString() == ContentOf(e, b).ToJsonString();

    /// PURE. The fields whose content differs: (field, before, after) as display text.
    public static IReadOnlyList<(string Field, string? Before, string? After)> Fields(Entity e, JsonObject? before, JsonObject? after)
    {
        var list = new List<(string, string?, string?)>();
        foreach (var c in e.Content)
        {
            var b = before?[c]; var a = after?[c];
            var bs = b?.ToJsonString(); var @as = a?.ToJsonString();
            if (bs == @as) continue;
            list.Add((c, Show(b), Show(a)));
        }
        return list;
    }

    /// A value the way a person reads it: text as text, null as "(empty)".
    public static string? Show(JsonNode? n) => n is null ? "(empty)" : n is JsonValue v && v.TryGetValue<string>(out var s) ? s : n.ToJsonString();

    /// PURE. A record from its JSON text, or null.
    public static JsonObject? Parse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try { return JsonNode.Parse(json) as JsonObject; } catch (JsonException) { return null; }
    }

    public const string FileName = "config-entities.locked.json";
    public static string DefaultPath => Path.Combine(AppContext.BaseDirectory, "catalog", FileName);
    private static readonly Lazy<ConfigEntities> Shipped = new(() => new ConfigEntities(File.ReadAllText(Locate())));

    /// The linked copy next to the app; else (a source-tree run) config\ of the SecurityInsight folder above it.
    public static string Locate()
    {
        if (File.Exists(DefaultPath)) return DefaultPath;
        for (var d = new DirectoryInfo(AppContext.BaseDirectory); d is not null; d = d.Parent)
        {
            var p = Path.Combine(d.FullName, "config", FileName);
            if (File.Exists(p)) return p;
        }
        throw new FileNotFoundException("the configuration set is missing", DefaultPath);
    }
    public static ConfigEntities Default => Shipped.Value;
}
