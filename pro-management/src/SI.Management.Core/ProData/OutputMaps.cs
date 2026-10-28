using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace SI.Management.Core.ProData;

/// One listed data-out connector (config/data-out.locked.json, embedded copy held to the original by a test).
public sealed record DataOutEntry(string Output, string Connector, string Label, string Kind, string? File, string? Sheet, string? Step,
    IReadOnlyList<string> Editions, bool Default, string? WrittenBy, bool FixedColumns, string? Reason, string? TableSetting)
{
    /// Where the output goes, in plain words.
    public string Destination => Kind switch
    {
        "excel" => $"Excel: {File}, sheet {Sheet}",
        "servicenow-importset" => "ServiceNow Import Set (the table the setting " + TableSetting + " names)",
        "fixed" => "written by the " + WrittenBy + " connector",
        _ => Kind,
    };
}

/// One column of an output map: the key (target), what it reads (from), the closed output operation (op) and the name the
/// output gives it (as -- the customer's rename; the target when empty). <paramref name="Position"/> (owner 2026-10-19, the
/// column builder's order): the column's place among the columns sent, 1 = first -- set only on a column the customer
/// moved (<see cref="OutputMapRules.Arrange{T}"/>); null = its place in the map.
public sealed record OutputColumn(string Target, string From, string? Op, string? As, int? Position = null)
{
    public string Name => string.IsNullOrWhiteSpace(As) ? Target : As.Trim();
}

/// <summary>
/// THE RULES OF AN OUTPUT COLUMN CHANGE (V3-DATA-MODEL 2.12, REQUIREMENTS #467) -- the C# twin of the engine's checks
/// (engine\pro-settings\SI-DataModelTemplateRows.ps1 Test-SIDataModelProItem + engine\data-model\SI-DataModelTemplates.ps1
/// Test-SIDataModel, the outputs part). An output map is one cfg.Template row per column, kind 'datamodel', key
/// 'outputs/&lt;id&gt;:&lt;target&gt;'; a customer change is a cfg.ItemOverride row of the same key: 'override' (the column with
/// another source, operation or name), 'disable' (the column removed), or an override without a template (a column of
/// their own). The engine merges them per column at run start; the conformance view flags UpgradeAvailable when the shipped
/// column changed under an override.
/// </summary>
public static partial class OutputMapRules
{
    public const string Kind = "datamodel";
    public const int MaxKey = 128;
    public const int MaxName = 128;

    /// The closed output operation set (engine\data-model\SI-DataModelTemplates.ps1 Get-SIOutputMapOps; a test compares).
    public static readonly string[] Ops = { "enum", "first", "join", "join_ids", "render", "format_date", "round", "mask", "domain_part", "if_class", "lower", "upper" };

    /// The system tokens a column may read instead of a field. #914: $action, $batch_id, $cleared, $reason, $replaces are the
    /// data-out contract's envelope (u_action, u_si_batch_id, u_si_cleared, u_si_reason, u_si_replaces), filled when the row is sent.
    public static readonly string[] Tokens = { "$run_id", "$run_time", "$changed_at", "$row_hash", "$action", "$batch_id", "$cleared", "$reason", "$replaces" };

    [GeneratedRegex(@"^[a-z][a-z0-9\-]{0,60}$", RegexOptions.CultureInvariant)]
    public static partial Regex OutputId();

    [GeneratedRegex(@"^(finding|summary|record)\.[A-Za-z_][A-Za-z0-9_\.]{0,120}$", RegexOptions.CultureInvariant)]
    private static partial Regex PathPattern();

    /// The data-model key of one column.
    public static string Key(string outputId, string target) => "outputs/" + outputId + ":" + target;

    /// (output id, target) of a column key, or null when the key is not an output column.
    public static (string OutputId, string Target)? SplitKey(string? key)
    {
        if (string.IsNullOrEmpty(key) || !key.StartsWith("outputs/", StringComparison.Ordinal)) return null;
        var i = key.IndexOf(':');
        if (i < 0) return null;
        var id = key[8..i];
        var target = key[(i + 1)..];
        if (!OutputId().IsMatch(id) || target.Length == 0) return null;
        return (id, target);
    }

    private static Stream Resource(string name) =>
        typeof(OutputMapRules).Assembly.GetManifestResourceStream("DataModel/" + name)
        ?? throw new InvalidOperationException($"the embedded data model file {name} is missing from the build");

    private static readonly Lazy<IReadOnlyList<DataOutEntry>> CatalogLazy = new(() =>
    {
        using var s = Resource("data-out.locked.json");
        return LoadCatalog(JsonDocument.Parse(s));
    });

    private static readonly Lazy<IReadOnlySet<string>> FieldsLazy = new(() =>
    {
        using var s = Resource("field-catalog.locked.json");
        using var d = JsonDocument.Parse(s);
        var set = new HashSet<string>(StringComparer.Ordinal);
        if (d.RootElement.TryGetProperty("fields", out var fs) && fs.ValueKind == JsonValueKind.Array)
            foreach (var f in fs.EnumerateArray())
                if (f.TryGetProperty("name", out var n) && n.ValueKind == JsonValueKind.String && n.GetString() is { Length: > 0 } name) set.Add(name);
        return set;
    });

    /// The listed data-out connectors.
    public static IReadOnlyList<DataOutEntry> Catalog => CatalogLazy.Value;

    /// Every SI field of the catalog (what a column may read).
    public static IReadOnlySet<string> Fields => FieldsLazy.Value;

    public static DataOutEntry? Entry(string? outputId) => Catalog.FirstOrDefault(e => e.Output == outputId);

    public static IReadOnlyList<DataOutEntry> LoadCatalog(JsonDocument doc)
    {
        static string? S(JsonElement e, string n) => e.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
        static bool B(JsonElement e, string n) => e.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.True;
        var list = new List<DataOutEntry>();
        if (doc.RootElement.TryGetProperty("outputs", out var outs) && outs.ValueKind == JsonValueKind.Array)
            foreach (var o in outs.EnumerateArray())
            {
                var eds = o.TryGetProperty("editions", out var ed) && ed.ValueKind == JsonValueKind.Array
                    ? ed.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString()!).ToList() : new List<string>();
                list.Add(new DataOutEntry(S(o, "output") ?? "", S(o, "connector") ?? "", S(o, "label") ?? "", S(o, "kind") ?? "", S(o, "file"), S(o, "sheet"), S(o, "step"),
                    eds, B(o, "default"), S(o, "writtenBy"), B(o, "fixedColumns"), S(o, "reason"), S(o, "tableSetting")));
            }
        return list;
    }

    /// One column from its JSON body (a template row or an override), or null when it is not a column.
    public static OutputColumn? ParseColumn(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try
        {
            using var d = JsonDocument.Parse(json.TrimStart((char)0xFEFF));
            var o = d.RootElement;
            if (o.ValueKind != JsonValueKind.Object) return null;
            static string? S(JsonElement e, string n) => e.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
            var target = S(o, "target");
            if (string.IsNullOrEmpty(target)) return null;
            int? pos = o.TryGetProperty("position", out var pv) && pv.ValueKind == JsonValueKind.Number && pv.TryGetInt32(out var pi) ? pi : null;
            return new OutputColumn(target, S(o, "from") ?? "", S(o, "op"), S(o, "as"), pos);
        }
        catch (JsonException) { return null; }
    }

    /// The override body the engine reads: { "target", "from", "op"?, "as"?, "position"? } (nothing else).
    public static string Body(OutputColumn c)
    {
        var o = new JsonObject { ["target"] = c.Target, ["from"] = c.From };
        if (!string.IsNullOrWhiteSpace(c.Op)) o["op"] = c.Op.Trim();
        if (!string.IsNullOrWhiteSpace(c.As)) o["as"] = c.As.Trim();
        if (c.Position is { } p) o["position"] = p;
        return o.ToJsonString();
    }

    /// The highest place a column can be moved to.
    public const int MaxPosition = 500;

    /// <summary>
    /// THE ORDER of the columns an output sends (the engine's twin: engine\data-model\SI-OutputMapper.ps1,
    /// Get-SIOutputColumnsInOrder): the map's order, then every column with a <see cref="OutputColumn.Position"/> taken out
    /// and put back at that place (lowest place first; a place past the end is the end; equal places keep the map's order).
    /// </summary>
    public static IReadOnlyList<T> Arrange<T>(IReadOnlyList<T> items, Func<T, int?> position)
    {
        var placed = items.Select((x, i) => (Item: x, Index: i, Pos: position(x))).Where(x => x.Pos is not null).OrderBy(x => x.Pos).ThenBy(x => x.Index).ToList();
        var list = items.Where(x => position(x) is null).ToList();
        foreach (var p in placed) list.Insert(Math.Clamp(p.Pos!.Value - 1, 0, list.Count), p.Item);
        return list;
    }

    /// <summary>
    /// The places the column builder stores for an order the customer chose (<paramref name="wanted"/>, the targets in
    /// order) over the map's own order (<paramref name="mapOrder"/>): the columns that keep their relative order in the
    /// LONGEST run of the map's order carry no place, every other column the place it is wanted at -- so moving one column
    /// changes one column, and <see cref="Arrange{T}"/> gives back exactly <paramref name="wanted"/>.
    /// </summary>
    public static IReadOnlyDictionary<string, int?> Places(IReadOnlyList<string> mapOrder, IReadOnlyList<string> wanted)
    {
        var rank = mapOrder.Select((t, i) => (t, i)).ToDictionary(x => x.t, x => x.i, StringComparer.Ordinal);
        // a column the map does not have yet (one being added) comes after the map's own, by its key -- where the engine puts
        // the customer's own columns
        var added = wanted.Where(t => !rank.ContainsKey(t)).OrderBy(t => t, StringComparer.Ordinal).ToList();
        var seq = wanted.Select(t => rank.TryGetValue(t, out var r) ? r : mapOrder.Count + added.IndexOf(t)).ToList();
        // the longest increasing run (patience sorting, O(n log n)), its members kept in place
        var tails = new List<int>(); var tailAt = new List<int>(); var prev = new int[seq.Count];
        for (var i = 0; i < seq.Count; i++)
        {
            if (seq[i] == int.MaxValue) { prev[i] = -2; continue; }
            int lo = 0, hi = tails.Count;
            while (lo < hi) { var mid = (lo + hi) / 2; if (tails[mid] < seq[i]) lo = mid + 1; else hi = mid; }
            prev[i] = lo > 0 ? tailAt[lo - 1] : -1;
            if (lo == tails.Count) { tails.Add(seq[i]); tailAt.Add(i); } else { tails[lo] = seq[i]; tailAt[lo] = i; }
        }
        var keep = new HashSet<int>();
        for (var k = tailAt.Count > 0 ? tailAt[^1] : -1; k >= 0; k = prev[k]) keep.Add(k);
        var places = new Dictionary<string, int?>(StringComparer.Ordinal);
        for (var i = 0; i < wanted.Count; i++) places[wanted[i]] = keep.Contains(i) ? null : i + 1;
        return places;
    }

    /// May the customer change this output's columns? (null = yes, else the plain reason why not)
    public static string? Locked(string outputId)
    {
        var e = Entry(outputId);
        if (e is null) return $"'{outputId}' is not a listed output";
        if (e.FixedColumns) return $"The columns of the {e.Label} are fixed: {e.Reason}";
        return null;
    }

    /// <summary>
    /// The reasons an output column override is refused (empty = accepted). <paramref name="shipped"/>: the shipped column
    /// of the same key (null = the customer's own column). <paramref name="otherNames"/>: the names of the other columns of
    /// the map in force (a name is unique per output).
    /// </summary>
    public static IReadOnlyList<string> Validate(string key, string? body, OutputColumn? shipped, IEnumerable<string>? otherNames = null, IReadOnlySet<string>? fields = null)
    {
        fields ??= Fields;
        var why = new List<string>();
        var k = SplitKey(key);
        if (k is null || key.Length > MaxKey || key.Any(char.IsControl)) return new[] { $"'{key}' is not an output column (outputs/<output>:<column>, at most {MaxKey} characters)" };
        if (Locked(k.Value.OutputId) is { } locked) return new[] { locked };
        if (string.IsNullOrWhiteSpace(body)) return new[] { "the column is empty" };
        JsonDocument doc;
        try { doc = JsonDocument.Parse(body.TrimStart((char)0xFEFF)); }
        catch (JsonException ex) { return new[] { "the column is not valid JSON: " + ex.Message }; }
        using (doc)
        {
            var o = doc.RootElement;
            if (o.ValueKind != JsonValueKind.Object) return new[] { "a column must be a JSON object" };
            foreach (var p in o.EnumerateObject())
                if (p.Name is not ("target" or "from" or "op" or "as" or "position")) why.Add($"'{p.Name}' is not part of a column (target, from, op, as, position)");
            if (o.TryGetProperty("position", out var posv) && !(posv.ValueKind == JsonValueKind.Number && posv.TryGetInt32(out var posi) && posi is >= 1 and <= MaxPosition))
                why.Add($"the place of a column is a whole number from 1 to {MaxPosition}");
            var c = ParseColumn(body);
            if (c is null) { why.Add("the column has no target"); return why; }
            if (!string.Equals(c.Target, k.Value.Target, StringComparison.Ordinal)) why.Add($"the target must be '{k.Value.Target}' -- the key names the column");
            if (c.Target.Length > MaxName || c.Target.Any(char.IsControl)) why.Add($"the column key must be one line of at most {MaxName} characters");
            var from = c.From.Trim();
            var okFrom = Tokens.Contains(from) || (from.StartsWith("$const:", StringComparison.Ordinal) && from.Length <= 207 && !from.Any(char.IsControl))
                         || PathPattern().IsMatch(from) || fields.Contains(from);
            if (from.Length == 0) why.Add("the column reads nothing: choose an SI field");
            else if (!okFrom) why.Add($"'{from}' is no SI field, system value or path");
            if (!string.IsNullOrWhiteSpace(c.Op))
            {
                var op = c.Op.Trim();
                var name = op.Split(':')[0];
                if (!Ops.Contains(name)) why.Add($"'{name}' is not an output operation ({string.Join(", ", Ops)})");
                // a value map is checked by the engine against the shipped value maps: here only the shipped column's own
                // translation is kept, never a new one (an unknown value map would stop the run)
                else if (name == "enum" && !string.Equals(op, shipped?.Op, StringComparison.Ordinal)) why.Add("a value translation (enum) can only be the one the shipped column uses");
                if (op.Any(char.IsControl) || op.Length > 120) why.Add("the operation must be one line of at most 120 characters");
            }
            if (!string.IsNullOrWhiteSpace(c.As) && (c.As.Trim().Length > MaxName || c.As.Any(char.IsControl))) why.Add($"the name must be one line of at most {MaxName} characters");
            if (otherNames is not null && otherNames.Any(n => string.Equals(n, c.Name, StringComparison.OrdinalIgnoreCase))) why.Add($"another column of this output is already named '{c.Name}'");
        }
        return why;
    }
}
