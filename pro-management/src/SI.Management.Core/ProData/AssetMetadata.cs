using System.Globalization;
using System.Text.Json;

namespace SI.Management.Core.ProData;

// =====================================================================================================================
// FULL ASSET METADATA (REQUIREMENTS #301 / #408): every property each source system reports about a CI, read from the
// GENERIC store the data sync fills when SI_AssetProperties = 'full' (sidata.AssetMetadata: one row per CI, source
// system, source record and item; the source object as JSON, arrays kept as arrays -- see sql\si-data-schema.sql).
// Read-only statements, every caller value a parameter. The level itself is read from cfg.Setting.
// =====================================================================================================================

/// One source object of a CI (sidata.AssetMetadata). PropertiesJson is the object exactly as the source reported it.
public sealed record AssetMetadataObject(string SourceSystem, string ItemName, string MemberAssetId, DateTime CollectionTime, string? SerialNumber,
    string? MacAddress, string? ParentResourceId, long? PropertyCount, long? PropertiesBytes, bool Dropped, bool HandoffHeld, string PropertiesJson);

/// The level the install runs and what the data sync last stored. ModeSetting = the cfg.Setting value ("full" /
/// "security"; null = not set in the Pro database). RetentionDays = SI_AssetProperties_RetentionDays (3 when not set).
public sealed record AssetMetadataState(string? ModeSetting, int RetentionDays, DateTime? LastSnapshot, DateTime? LastLoadedAt, long LastRows, long LastAssets, string? LastSources);

public interface IAssetMetadataViews
{
    Task<QueryResult<AssetMetadataState>> StateAsync(CancellationToken ct);
    /// EVERY kept snapshot of each (source system, record, item) of one CI (#412 history), Entra first (see
    /// <see cref="AssetMetadataText.Order"/>), newest first within a record. <see cref="AssetMetadataText.Newest"/> gives
    /// the current objects, <see cref="AssetMetadataText.History"/> the snapshots with what changed between them.
    Task<QueryResult<IReadOnlyList<AssetMetadataObject>>> ForAssetAsync(string assetKey, CancellationToken ct);
}

/// One change between two consecutive snapshots of a source object: a property path that was added, removed or changed,
/// with its value before and after as plain text (an array: the items added and removed, compared as a set -- the order
/// a source lists them in is not a change).
public sealed record MetadataChange(string Path, string Kind, string? Before, string? After);

/// One kept snapshot of a source object and what changed against the snapshot before it (null: the oldest kept -- there
/// is nothing older to compare with).
public sealed record AssetMetadataSnapshot(AssetMetadataObject Object, IReadOnlyList<MetadataChange>? Changes);

/// Every kept snapshot of one (source system, record, item), newest first.
public sealed record AssetMetadataHistory(string SourceSystem, string MemberAssetId, string ItemName, IReadOnlyList<AssetMetadataSnapshot> Snapshots);

/// <summary>The statements. Fixed text, parameters only, read-only.</summary>
public static class AssetMetadataSql
{
    public const string State = """
SELECT m.ModeJson, r.RetentionJson, l.CollectionTime AS LastSnapshot, l.LoadedAt AS LastLoadedAt, l.[Rows] AS LastRows, l.Assets AS LastAssets, l.Sources AS LastSources
FROM (SELECT 1 AS One) AS x
OUTER APPLY (SELECT TOP (1) s.ValueJson AS ModeJson FROM cfg.Setting AS s WHERE s.Name = N'SI_AssetProperties'
             ORDER BY CASE WHEN s.Scope = N'solution' THEN 0 ELSE 1 END, s.Scope) AS m
OUTER APPLY (SELECT TOP (1) s.ValueJson AS RetentionJson FROM cfg.Setting AS s WHERE s.Name = N'SI_AssetProperties_RetentionDays'
             ORDER BY CASE WHEN s.Scope = N'solution' THEN 0 ELSE 1 END, s.Scope) AS r
OUTER APPLY (SELECT TOP (1) a.CollectionTime, a.LoadedAt, a.[Rows], a.Assets, a.Sources FROM sidata.AssetMetadataLoad AS a ORDER BY a.CollectionTime DESC) AS l;
""";

    public const string ForAsset = """
SELECT m.SourceSystem, m.ItemName, m.MemberAssetId, m.CollectionTime, m.SerialNumber, m.MacAddress, m.ParentResourceId, m.PropertyCount, m.PropertiesBytes,
       m.Dropped, m.HandoffHeld, m.PropertiesJson
FROM sidata.AssetMetadata AS m
WHERE m.AssetKey = @AssetKey
ORDER BY m.SourceSystem, m.MemberAssetId, m.ItemName, m.CollectionTime DESC;
""";
}

/// <summary>The SQL implementation over <see cref="IProSql"/>; every statement passes <see cref="SqlGuard"/> first.</summary>
public sealed class AssetMetadataViews : IAssetMetadataViews
{
    public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(60);
    private readonly IProSql _sql;
    private readonly TimeProvider _clock;

    public AssetMetadataViews(IProSql sql, TimeProvider? clock = null) { _sql = sql; _clock = clock ?? TimeProvider.System; }

    private async Task<(IReadOnlyList<IReadOnlyDictionary<string, object?>> Rows, string Text)> Run(SqlQuery q, CancellationToken ct)
    {
        SqlGuard.AssertReadOnly(q.Text);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(Timeout);
        return (await _sql.QueryAsync(q, cts.Token).ConfigureAwait(false), EstateQueries.DescribeSql(q.Text, q.Parameters));
    }

    private QueryResult<T> R<T>(T data, string text) => new(data, text, _sql.SourceName, _clock.GetUtcNow());
    private static bool B(IReadOnlyDictionary<string, object?> r, string c) => r.TryGetValue(c, out var v) && v switch
    {
        bool b => b, null => false, string s => s is "1" or "True" or "true", _ => Convert.ToInt64(v, CultureInfo.InvariantCulture) != 0,
    };

    public async Task<QueryResult<AssetMetadataState>> StateAsync(CancellationToken ct)
    {
        var (rows, text) = await Run(new SqlQuery(AssetMetadataSql.State, new Dictionary<string, object?>()), ct).ConfigureAwait(false);
        var r = rows.Count > 0 ? rows[0] : new Dictionary<string, object?>();
        return R(new AssetMetadataState(AssetMetadataText.SettingText(ProDataQueries.SN(r, "ModeJson")), AssetMetadataText.RetentionDays(ProDataQueries.SN(r, "RetentionJson")),
            ProDataQueries.T(r, "LastSnapshot"), ProDataQueries.T(r, "LastLoadedAt"), ProDataQueries.L(r, "LastRows"), ProDataQueries.L(r, "LastAssets"),
            ProDataQueries.SN(r, "LastSources")), text);
    }

    public async Task<QueryResult<IReadOnlyList<AssetMetadataObject>>> ForAssetAsync(string assetKey, CancellationToken ct)
    {
        var key = ProDataFilters.AssetKey(assetKey) ?? throw new ArgumentException("an asset key is required");
        var (rows, text) = await Run(new SqlQuery(AssetMetadataSql.ForAsset, new Dictionary<string, object?> { ["AssetKey"] = key }), ct).ConfigureAwait(false);
        var all = rows.Select(r => new AssetMetadataObject(ProDataQueries.S(r, "SourceSystem"), ProDataQueries.S(r, "ItemName"), ProDataQueries.S(r, "MemberAssetId"),
            ProDataQueries.T(r, "CollectionTime") ?? default, ProDataQueries.SN(r, "SerialNumber"), ProDataQueries.SN(r, "MacAddress"), ProDataQueries.SN(r, "ParentResourceId"),
            ProDataQueries.LN(r, "PropertyCount"), ProDataQueries.LN(r, "PropertiesBytes"), B(r, "Dropped"), B(r, "HandoffHeld"), ProDataQueries.S(r, "PropertiesJson"))).ToList();
        return R(AssetMetadataText.Ordered(all), text);
    }
}

/// <summary>Plain words and the rules of the section: which sources, in which order, what the level means.</summary>
public static class AssetMetadataText
{
    /// The sources in the order the asset page shows them (operator 2026-10-06: Entra, Intune, Defender, AD, Azure/ARM,
    /// Exposure Graph, VM extensions); an unknown source system comes last, by name.
    public static readonly string[] Order = ["entra-device", "entra-user", "entra-serviceprincipal", "intune-device", "mde", "ad-computer", "arm", "exposure-graph", "arm-vm-extension"];

    public static string Label(string sourceSystem) => sourceSystem switch
    {
        "entra-device" => "Entra ID (device)",
        "entra-user" => "Entra ID (user)",
        "entra-serviceprincipal" => "Entra ID (service principal)",
        "intune-device" => "Intune",
        "mde" => "Defender for Endpoint",
        "ad-computer" => "Active Directory",
        "arm" => "Azure (ARM)",
        "exposure-graph" => "Exposure Graph",
        "arm-vm-extension" => "VM extensions",
        _ => sourceSystem,
    };

    public static int Rank(string sourceSystem) { var i = Array.IndexOf(Order, sourceSystem); return i < 0 ? Order.Length : i; }

    /// The newest object of each (source system, record, item); sources in <see cref="Order"/>, then by record and item.
    public static IReadOnlyList<AssetMetadataObject> Newest(IEnumerable<AssetMetadataObject> rows) =>
        rows.GroupBy(o => (o.SourceSystem, o.MemberAssetId, o.ItemName))
            .Select(g => g.OrderByDescending(o => o.CollectionTime).First())
            .OrderBy(o => Rank(o.SourceSystem)).ThenBy(o => o.SourceSystem, StringComparer.Ordinal)
            .ThenBy(o => o.MemberAssetId, StringComparer.OrdinalIgnoreCase).ThenBy(o => o.ItemName, StringComparer.OrdinalIgnoreCase).ToList();

    /// Every kept snapshot in the page's order: sources in <see cref="Order"/>, then record and item, newest first.
    public static IReadOnlyList<AssetMetadataObject> Ordered(IEnumerable<AssetMetadataObject> rows) =>
        rows.OrderBy(o => Rank(o.SourceSystem)).ThenBy(o => o.SourceSystem, StringComparer.Ordinal)
            .ThenBy(o => o.MemberAssetId, StringComparer.OrdinalIgnoreCase).ThenBy(o => o.ItemName, StringComparer.OrdinalIgnoreCase)
            .ThenByDescending(o => o.CollectionTime).ToList();

    /// #412: every kept snapshot of each (source system, record, item), newest first, each with what changed against the
    /// snapshot before it (<see cref="MetadataDiff.Compare"/>); the oldest kept has no comparison (Changes = null).
    public static IReadOnlyList<AssetMetadataHistory> History(IEnumerable<AssetMetadataObject> rows) =>
        rows.GroupBy(o => (o.SourceSystem, o.MemberAssetId, o.ItemName))
            .Select(g =>
            {
                var snaps = g.OrderByDescending(o => o.CollectionTime).ToList();
                var list = snaps.Select((o, i) => new AssetMetadataSnapshot(o, i + 1 < snaps.Count ? MetadataDiff.Compare(snaps[i + 1].PropertiesJson, o.PropertiesJson) : null)).ToList();
                return new AssetMetadataHistory(g.Key.SourceSystem, g.Key.MemberAssetId, g.Key.ItemName, list);
            })
            .OrderBy(h => Rank(h.SourceSystem)).ThenBy(h => h.SourceSystem, StringComparer.Ordinal)
            .ThenBy(h => h.MemberAssetId, StringComparer.OrdinalIgnoreCase).ThenBy(h => h.ItemName, StringComparer.OrdinalIgnoreCase).ToList();

    /// A cfg.Setting ValueJson ("\"full\"") as its text ("full"); null when not set.
    public static string? SettingText(string? valueJson)
    {
        if (string.IsNullOrWhiteSpace(valueJson)) return null;
        try
        {
            using var d = JsonDocument.Parse(valueJson);
            return d.RootElement.ValueKind == JsonValueKind.String ? d.RootElement.GetString()?.Trim() : d.RootElement.GetRawText().Trim();
        }
        catch (JsonException) { return valueJson.Trim().Trim('"'); }
    }

    /// SI_AssetProperties_RetentionDays the way the data sync reads it: a whole number, at least 1; else 3.
    public static int RetentionDays(string? valueJson) =>
        int.TryParse(SettingText(valueJson), NumberStyles.Integer, CultureInfo.InvariantCulture, out var n) ? Math.Max(1, n) : 3;

    /// Is the full level on? 'full' in the Pro database = on, any other value there = off. Not set in the Pro database:
    /// the configuration file decides, which the web app cannot read -- so the stored metadata answers (the data sync
    /// stores it only while the install runs full).
    public static bool IsFull(AssetMetadataState s, bool hasStoredMetadata) =>
        s.ModeSetting is { } m ? string.Equals(m, "full", StringComparison.OrdinalIgnoreCase) : hasStoredMetadata || s.LastSnapshot is not null;
}

// ---- the object as a person reads it: property paths, lists kept as lists --------------------------------------------

/// One value of a property. Kind: text | number | bool | null | empty (an empty object) | list (an array of values, or
/// a mixed array) | table (an array of objects: one row per element, one column per property path inside it).
public sealed record MetaValue(string Kind, string? Text = null, IReadOnlyList<MetaValue>? Items = null, IReadOnlyList<string>? Columns = null,
    IReadOnlyList<IReadOnlyList<MetaValue?>>? Rows = null)
{
    public int Count => Kind == "list" ? Items?.Count ?? 0 : Kind == "table" ? Rows?.Count ?? 0 : 0;
}

/// One property of an object: its dotted path into the source object (properties.storageProfile.osDisk.osType) and its value.
public sealed record MetaRow(string Path, MetaValue Value);

/// <summary>
/// PURE. A source object as rows of (property path, value). Objects are walked into dotted paths; an ARRAY ENDS a path
/// and stays one value -- a list of values, or a table with one row per element -- never numbered columns
/// (dataDisks[0].lun, dataDisks[1].lun ...). Bounded: at most <c>maxRows</c> rows and <c>maxDepth</c> levels; a deeper
/// branch is shown as its JSON text, so nothing is silently left out.
/// </summary>
public static class MetadataTree
{
    public const int MaxRows = 2000;
    public const int MaxDepth = 12;
    public const int MaxTextLength = 2000;

    public static IReadOnlyList<MetaRow> Flatten(string? json, int maxRows = MaxRows)
    {
        var rows = new List<MetaRow>();
        if (string.IsNullOrWhiteSpace(json)) return rows;
        try
        {
            using var doc = JsonDocument.Parse(json);
            Walk(doc.RootElement, "", rows, maxRows, 0);
        }
        catch (JsonException) { rows.Add(new MetaRow("(unreadable)", Text(json))); }
        return rows;
    }

    private static MetaValue Text(string s) => new("text", s.Length > MaxTextLength ? s[..MaxTextLength] + "…" : s);

    private static void Walk(JsonElement e, string path, List<MetaRow> rows, int maxRows, int depth)
    {
        if (rows.Count >= maxRows) return;
        if (e.ValueKind == JsonValueKind.Object)
        {
            if (depth >= MaxDepth) { rows.Add(new MetaRow(path, Text(e.GetRawText()))); return; }
            var any = false;
            foreach (var p in e.EnumerateObject())
            {
                any = true;
                Walk(p.Value, path.Length == 0 ? p.Name : path + "." + p.Name, rows, maxRows, depth + 1);
                if (rows.Count >= maxRows) return;
            }
            if (!any && path.Length > 0) rows.Add(new MetaRow(path, new MetaValue("empty")));
            return;
        }
        rows.Add(new MetaRow(path.Length == 0 ? "(value)" : path, Value(e, depth)));
    }

    /// One value: a scalar as text, an array as a list or a table.
    public static MetaValue Value(JsonElement e, int depth = 0) => e.ValueKind switch
    {
        JsonValueKind.String => Text(e.GetString() ?? ""),
        JsonValueKind.Number => new MetaValue("number", e.GetRawText()),
        JsonValueKind.True => new MetaValue("bool", "true"),
        JsonValueKind.False => new MetaValue("bool", "false"),
        JsonValueKind.Null or JsonValueKind.Undefined => new MetaValue("null"),
        JsonValueKind.Array => Array(e, depth),
        JsonValueKind.Object => Object(e, depth),
        _ => Text(e.GetRawText()),
    };

    private static MetaValue Array(JsonElement a, int depth)
    {
        var items = a.EnumerateArray().ToList();
        if (depth >= MaxDepth) return Text(a.GetRawText());
        if (items.Count > 0 && items.All(i => i.ValueKind == JsonValueKind.Object))
        {
            // a table: one row per element, its columns the property paths inside the elements (first seen first)
            var columns = new List<string>();
            var perRow = new List<Dictionary<string, MetaValue>>();
            foreach (var it in items)
            {
                var cells = new Dictionary<string, MetaValue>(StringComparer.Ordinal);
                var sub = new List<MetaRow>();
                Walk(it, "", sub, MaxRows, depth + 1);
                foreach (var r in sub) { if (!cells.ContainsKey(r.Path)) cells[r.Path] = r.Value; if (!columns.Contains(r.Path)) columns.Add(r.Path); }
                perRow.Add(cells);
            }
            var rows = perRow.Select(c => (IReadOnlyList<MetaValue?>)columns.Select(col => c.TryGetValue(col, out var v) ? v : null).ToList()).ToList();
            return new MetaValue("table", Columns: columns, Rows: rows);
        }
        return new MetaValue("list", Items: items.Select(i => Value(i, depth + 1)).ToList());
    }

    /// An object inside a mixed array: its compact text.
    private static MetaValue Object(JsonElement o, int depth) => Text(o.GetRawText());

    /// The plain text of a value -- what the page's search and sort read, and what an export would write.
    public static string Plain(MetaValue v) => v.Kind switch
    {
        "null" => "",
        "empty" => "(empty)",
        "list" => string.Join(", ", (v.Items ?? []).Select(Plain)),
        "table" => v.Count.ToString(CultureInfo.InvariantCulture) + " item(s)",
        _ => v.Text ?? "",
    };
}

// ---- #412 history: what changed between two consecutive snapshots of a source object ----------------------------------

/// <summary>
/// PURE. The changes from an older snapshot of a source object to the next one, as property paths -- the same paths the
/// page shows (<see cref="MetadataTree"/>: objects are walked, an ARRAY ENDS a path). A path only in the newer object is
/// "added", only in the older "removed", in both with another value "changed". Arrays are compared sensibly: as a SET of
/// their items (each item compared whole, an object item by its content with its properties in any order), so a source
/// listing the same items in another order is no change, and a change names the items added and removed. Bounded:
/// at most <see cref="MaxChanges"/> changes, each text at most <see cref="MaxText"/> characters.
/// </summary>
public static class MetadataDiff
{
    public const int MaxChanges = 500;
    public const int MaxText = 300;

    private sealed record Leaf(bool IsArray, string Canon, IReadOnlyList<(string Canon, string Text)> Items, string Text);

    public static IReadOnlyList<MetadataChange> Compare(string? olderJson, string? newerJson)
    {
        var a = Leaves(olderJson);
        var b = Leaves(newerJson);
        var changes = new List<MetadataChange>();
        foreach (var (path, nv) in b.List)
        {
            if (changes.Count >= MaxChanges) break;
            if (!a.Map.TryGetValue(path, out var ov)) { changes.Add(new(path, "added", null, nv.Text)); continue; }
            if (ov.IsArray && nv.IsArray)
            {
                var (added, removed) = SetDiff(ov.Items, nv.Items);
                if (added.Count == 0 && removed.Count == 0) continue;
                changes.Add(new(path, "changed",
                    removed.Count > 0 ? Cut($"{removed.Count} item(s) removed: " + string.Join(", ", removed)) : "(no item removed)",
                    added.Count > 0 ? Cut($"{added.Count} item(s) added: " + string.Join(", ", added)) : "(no item added)"));
                continue;
            }
            if (ov.Canon != nv.Canon) changes.Add(new(path, "changed", ov.Text, nv.Text));
        }
        foreach (var (path, ov) in a.List)
        {
            if (changes.Count >= MaxChanges) break;
            if (!b.Map.ContainsKey(path)) changes.Add(new(path, "removed", ov.Text, null));
        }
        return changes;
    }

    private static (List<string> Added, List<string> Removed) SetDiff(IReadOnlyList<(string Canon, string Text)> older, IReadOnlyList<(string Canon, string Text)> newer)
    {
        var left = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var (c, _) in older) left[c] = left.TryGetValue(c, out var n) ? n + 1 : 1;
        var added = new List<string>();
        foreach (var (c, t) in newer)
        {
            if (left.TryGetValue(c, out var n) && n > 0) { left[c] = n - 1; continue; }
            added.Add(t);
        }
        var removed = new List<string>();
        var stillOld = new Dictionary<string, int>(left, StringComparer.Ordinal);
        foreach (var (c, t) in older)
        {
            if (stillOld.TryGetValue(c, out var n) && n > 0) { stillOld[c] = n - 1; removed.Add(t); }
        }
        return (added, removed);
    }

    private sealed class LeafSet
    {
        public List<(string Path, Leaf Leaf)> List { get; } = new();
        public Dictionary<string, Leaf> Map { get; } = new(StringComparer.Ordinal);
        public void Add(string path, Leaf leaf) { if (Map.TryAdd(path, leaf)) List.Add((path, leaf)); }
    }

    private static LeafSet Leaves(string? json)
    {
        var set = new LeafSet();
        if (string.IsNullOrWhiteSpace(json)) return set;
        try
        {
            using var doc = JsonDocument.Parse(json);
            Walk(doc.RootElement, "", set, 0);
        }
        catch (JsonException) { set.Add("(unreadable)", new Leaf(false, json, [], Cut(json))); }
        return set;
    }

    private static void Walk(JsonElement e, string path, LeafSet set, int depth)
    {
        if (set.List.Count >= MetadataTree.MaxRows) return;
        if (e.ValueKind == JsonValueKind.Object && depth < MetadataTree.MaxDepth)
        {
            var any = false;
            foreach (var p in e.EnumerateObject())
            {
                any = true;
                Walk(p.Value, path.Length == 0 ? p.Name : path + "." + p.Name, set, depth + 1);
            }
            if (!any && path.Length > 0) set.Add(path, new Leaf(false, "{}", [], "(empty)"));
            return;
        }
        var key = path.Length == 0 ? "(value)" : path;
        if (e.ValueKind == JsonValueKind.Array)
        {
            var items = e.EnumerateArray().Select(i => (Canon(i), Display(i))).ToList();
            set.Add(key, new Leaf(true, Canon(e), items, Cut(items.Count == 0 ? "(empty list)" : string.Join(", ", items.Select(i => i.Item2)))));
            return;
        }
        set.Add(key, new Leaf(false, Canon(e), [], Cut(Display(e))));
    }

    /// The value as a person reads it: a string without quotes, (not set) for null, an object or array as compact JSON.
    private static string Display(JsonElement e) => e.ValueKind switch
    {
        JsonValueKind.String => e.GetString() ?? "",
        JsonValueKind.Null or JsonValueKind.Undefined => "(not set)",
        JsonValueKind.Object or JsonValueKind.Array => Canon(e),
        _ => e.GetRawText(),
    };

    /// A canonical text of a value: an object's properties sorted by name, so the same content always compares equal.
    public static string Canon(JsonElement e)
    {
        switch (e.ValueKind)
        {
            case JsonValueKind.Object:
                return "{" + string.Join(",", e.EnumerateObject().OrderBy(p => p.Name, StringComparer.Ordinal)
                    .Select(p => JsonSerializer.Serialize(p.Name) + ":" + Canon(p.Value))) + "}";
            case JsonValueKind.Array:
                return "[" + string.Join(",", e.EnumerateArray().Select(Canon)) + "]";
            default:
                return e.GetRawText();
        }
    }

    private static string Cut(string s) => s.Length > MaxText ? s[..MaxText] + "…" : s;
}
