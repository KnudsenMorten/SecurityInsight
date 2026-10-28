using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace SI.Management.Web.Changes;

/// <summary>
/// #772 -- ONE editor over the ONE classification mechanism for a dimension a customer maps himself: the ServiceNow sub-CI
/// (owner 2026-10-19: a customer's ServiceNow team links the findings "under 3 sub-cis per ci - OS findings, SQL findings, Other
/// findings" / "it must be configurable") and the OS family ("so i can filter on Windows vs. Linux"). Pure, no I/O.
/// <para>A mapping is NOT a second mechanism: it reads and writes the same 'datamodel' cfg.ItemOverride rows the
/// classification wizard does -- the dimension 'dimensions:&lt;id&gt;' (the BUCKETS: its values, and its 'default' = the fallback
/// bucket) and the 'classification:&lt;row id&gt;' rows that set the target field -- and the engine evaluates them as every other
/// classification row (engine/data-model/SI-Classification.ps1). The editor's own conventions on those rows:</para>
/// <list type="bullet">
/// <item>BASE rows (the sub-CI's component mapping): one per base value, id <c>&lt;BasePrefix&gt;&lt;value&gt;</c>, field = the base
///   field, equals that value, priority <see cref="BasePriority"/>. A base value without a row goes to the fallback.</item>
/// <item>RULES (ordered, first match wins): every other row on the target, priority <see cref="RuleTop"/> - 10 x its place, so
///   they come before the base rows. A shipped rule (the OS family's) is changed by an override and removed by a disable; a
///   customer rule (id <c>&lt;RulePrefix&gt;n</c>) is added and removed.</item>
/// </list>
/// Nothing rewrites history: a staged change is written on Review &amp; commit in the signed-in name with its reason (the
/// change log), and the next run classifies with it. <see cref="Evaluate"/> is the preview's twin of the engine for THESE rows
/// (equals / in / prefix / pattern, case-insensitive, any value of a list) -- a fixture holds the two equal.
/// </summary>
public static partial class DimensionMapping
{
    public const int BasePriority = 100;
    public const int RuleTop = 9000;
    public const int RuleStep = 10;
    public const int MaxBuckets = 30;
    public const int MaxRules = 400;
    public const int MaxRuleValues = 50;

    /// What one mapping edits.
    public sealed record Spec(string Id, string Title, string TargetField, string DimensionId, string DimensionName, string? BaseField, string? BaseDimension,
        IReadOnlyList<string> BaseDefault, IReadOnlyList<string> BucketDefault, string FallbackDefault, IReadOnlyList<(string Field, string Label)> RuleFields,
        string RulePrefix, string BasePrefix, string Lede, bool Assets)
    {
        public string DimensionKey => ClassificationItemValidator.DimensionsTemplate + ":" + DimensionId;
    }

    public static readonly Spec ServiceNowSubCi = new("servicenow-subci", "ServiceNow sub-CI mapping", "si_servicenow_subci", "servicenow_subci", "ServiceNow sub-CI",
        "si_component", "component", ClassificationMapping.ComponentDefault, ["OS", "SQL", "Other"], "Other",
        [("si_affected_vendor", "Vendor"), ("si_affected_product", "Affected software / product"), ("si_report_name", "Report"), ("si_category", "Category"), ("si_finding_key", "Configuration id")],
        "servicenow-subci-rule-", "servicenow-subci-component-",
        "ServiceNow links each finding under one sub-CI of its CI. Every finding gets exactly one bucket: your ordered rules first (first match wins), then its component, else the fallback bucket.",
        Assets: false);

    public static readonly Spec OsFamily = new("os-family", "OS family mapping", "si_os_family", "os_family", "OS family",
        null, null, Array.Empty<string>(), ["Windows", "Linux", "macOS", "iOS", "Android", "Network OS", "Other", "Unknown"], "Unknown",
        [("si_os_platform", "OS platform"), ("si_os_name", "OS name"), ("si_device_category", "Device category"), ("si_asset_type", "Asset type")],
        "os-family-rule-", "",
        "Every asset (and every finding on it) gets exactly one OS family: the first rule that matches its OS platform, OS name or device category, else the fallback (Unknown -- no source says which OS it runs).",
        Assets: true);

    public static readonly IReadOnlyList<Spec> All = [ServiceNowSubCi, OsFamily];
    public static Spec? Find(string? id) => All.FirstOrDefault(s => string.Equals(s.Id, id, StringComparison.OrdinalIgnoreCase));

    public static readonly IReadOnlyList<(string Match, string Label)> Matches = [("in", "is one of"), ("prefix", "starts with"), ("pattern", "matches the pattern")];

    /// One rule as the editor shows it.
    public sealed record Rule(string Id, string Field, string Match, IReadOnlyList<string> Values, string Bucket, int Priority, bool Shipped, bool Off);

    /// A whole mapping: the buckets (in order), the fallback bucket, base value -> bucket (missing = fallback), the rules in order.
    public sealed record Mapping(IReadOnlyList<string> Buckets, string Fallback, IReadOnlyDictionary<string, string> Base, IReadOnlyList<Rule> Rules);

    /// One staged change of a mapping.
    public sealed record Change(string Key, string State, string? Body, string What);

    [GeneratedRegex(@"^[A-Za-z0-9][A-Za-z0-9 ._/&+\-]{0,63}$", RegexOptions.CultureInvariant)]
    private static partial Regex Bucket();

    /// A pattern / value: plain characters and the wildcards * and ? -- no quote, backslash, bracket or bar (as the wizard).
    [GeneratedRegex(@"^[A-Za-z0-9 ._@/:+#\-*?()]+$", RegexOptions.CultureInvariant)]
    private static partial Regex Plain();

    private static string S(JsonElement o, string p) => o.ValueKind == JsonValueKind.Object && o.TryGetProperty(p, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";

    private static JsonElement? Body(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try { using var d = JsonDocument.Parse(json); return d.RootElement.Clone(); } catch (JsonException) { return null; }
    }

    private static List<string> Strings(JsonElement o, string p)
    {
        var l = new List<string>();
        if (o.ValueKind != JsonValueKind.Object || !o.TryGetProperty(p, out var v)) return l;
        if (v.ValueKind == JsonValueKind.Array) l.AddRange(v.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString() ?? "").Where(x => x.Length > 0));
        else if (v.ValueKind == JsonValueKind.String && (v.GetString() ?? "").Length > 0) l.Add(v.GetString()!);
        return l;
    }

    // ------------------------------------------------------------------------------------------------ read

    /// The base values (the sub-CI: the component dimension's values in force).
    public static IReadOnlyList<string> BaseValues(Spec spec, IReadOnlyList<DataModelRow> rows)
    {
        if (spec.BaseDimension is null) return Array.Empty<string>();
        var d = rows.FirstOrDefault(r => r.ItemKey == ClassificationItemValidator.DimensionsTemplate + ":" + spec.BaseDimension);
        var vals = d is not null && Body(d.Effective ?? d.TemplateBody) is { } b ? Strings(b, "values") : new List<string>();
        return vals.Count > 0 ? vals : spec.BaseDefault;
    }

    /// The mapping in force, from the Pro data model rows (the shipped one when the rows are not published yet).
    public static Mapping Read(Spec spec, IReadOnlyList<DataModelRow> rows)
    {
        var dim = rows.FirstOrDefault(r => r.ItemKey == spec.DimensionKey);
        var buckets = new List<string>(spec.BucketDefault);
        var fallback = spec.FallbackDefault;
        if (dim is not null && Body(dim.Effective ?? dim.TemplateBody) is { } db)
        {
            var v = Strings(db, "values");
            if (v.Count > 0) buckets = v;
            var def = S(db, "default");
            fallback = buckets.FirstOrDefault(b => string.Equals(b, def, StringComparison.OrdinalIgnoreCase))
                       ?? buckets.FirstOrDefault(b => string.Equals(b, spec.FallbackDefault, StringComparison.OrdinalIgnoreCase)) ?? buckets.LastOrDefault() ?? spec.FallbackDefault;
        }
        var baseMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var basePrio = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var rules = new List<Rule>();
        foreach (var r in ClassificationMapping.Of(rows).Where(x => x.Target == spec.TargetField))
        {
            if (r.Off) continue;
            if (IsBase(spec, r))
            {
                foreach (var v in r.Values)
                    if (!basePrio.TryGetValue(v, out var p) || r.Priority > p) { baseMap[v] = r.Set; basePrio[v] = r.Priority; }
                continue;
            }
            rules.Add(new Rule(r.Id, r.Field, r.Match is "equals" ? "in" : r.Match, r.Values, r.Set, r.Priority, !r.Own, false));
        }
        // first match wins: the highest priority first (the engine's order; file / id order breaks a tie)
        rules = rules.OrderByDescending(x => x.Priority).ThenBy(x => x.Id, StringComparer.Ordinal).ToList();
        return new Mapping(buckets, fallback, baseMap, rules);
    }

    private static bool IsBase(Spec spec, ClassificationMapping.Row r) =>
        spec.BaseField is not null && r.Field == spec.BaseField && r.Match is "equals" or "in" && r.Priority <= BasePriority;

    // ------------------------------------------------------------------------------------------------ the posted form

    /// The form as posted: the bucket names by slot (an empty one is removed), the fallback slot, per base value the bucket
    /// slot ("" = the fallback), the rules (field, match, values ';'-separated, bucket slot) in order (an empty one removed).
    public sealed record Posted(IReadOnlyList<string?> Buckets, string? Fallback, IReadOnlyDictionary<string, string?> Base,
        IReadOnlyList<(string? Field, string? Match, string? Values, string? Bucket)> Rules);

    /// The posted form -> a mapping (or the reasons it is refused). Buckets are referred to by SLOT, so renaming a bucket keeps
    /// every base value and rule that pointed at it.
    public static (Mapping? Mapping, IReadOnlyList<string> Problems) Parse(Spec spec, Posted p, IReadOnlyList<string> baseValues)
    {
        var why = new List<string>();
        var bySlot = new Dictionary<string, string>(StringComparer.Ordinal);
        var buckets = new List<string>();
        for (var i = 0; i < p.Buckets.Count; i++)
        {
            var b = (p.Buckets[i] ?? "").Trim();
            if (b.Length == 0) continue;
            if (!Bucket().IsMatch(b)) { why.Add($"bucket '{b}': letters, digits, space and . _ / & + - only, at most 64 characters"); continue; }
            if (buckets.Contains(b, StringComparer.OrdinalIgnoreCase)) { why.Add($"bucket '{b}' is listed twice"); continue; }
            buckets.Add(b); bySlot[i.ToString(System.Globalization.CultureInfo.InvariantCulture)] = b;
        }
        if (buckets.Count == 0) why.Add("name at least one bucket");
        if (buckets.Count > MaxBuckets) why.Add($"at most {MaxBuckets} buckets");
        string? fallback = p.Fallback is not null && bySlot.TryGetValue(p.Fallback, out var fb) ? fb : null;
        if (fallback is null) why.Add("mark one bucket as the fallback -- a finding no rule places gets it, never blank");
        var baseMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var v in baseValues)
        {
            if (!p.Base.TryGetValue(v, out var slot) || string.IsNullOrEmpty(slot)) continue;
            if (bySlot.TryGetValue(slot, out var b)) { if (!string.Equals(b, fallback, StringComparison.Ordinal)) baseMap[v] = b; }
            else why.Add($"'{v}' points at a bucket that is removed -- pick another");
        }
        var rules = new List<Rule>();
        foreach (var (field, match, values, bucket) in p.Rules)
        {
            var vals = (values ?? "").Split(';').Select(x => x.Trim()).Where(x => x.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            if (string.IsNullOrWhiteSpace(field) && vals.Count == 0) continue;   // an empty row = removed
            var f = spec.RuleFields.FirstOrDefault(x => x.Field == field);
            if (f.Field is null) { why.Add("a rule: pick the field from the list"); continue; }
            if (!Matches.Any(m => m.Match == match)) { why.Add($"a rule on {f.Label}: pick how it matches from the list"); continue; }
            if (vals.Count == 0) { why.Add($"a rule on {f.Label}: type the value(s) to match"); continue; }
            if (vals.Count > MaxRuleValues) { why.Add($"a rule on {f.Label}: at most {MaxRuleValues} values"); continue; }
            var bad = vals.FirstOrDefault(x => x.Length > 200 || !Plain().IsMatch(x) || (match == "in" && x.IndexOfAny(['*', '?']) >= 0));
            if (bad is not null) { why.Add($"a rule on {f.Label}: '{bad}' is not a plain value -- letters, digits, space, . _ @ / : + # - ( ) and, for a pattern, * and ?"); continue; }
            if (match != "in" && vals.Any(x => x.All(c => c is '*' or '?' or ' ')) && !(spec.Assets && vals.Count == 1 && vals[0] is "*" or "?*"))
            { why.Add($"a rule on {f.Label}: a pattern needs at least one letter or digit"); continue; }
            if (bucket is null || !bySlot.TryGetValue(bucket, out var rb)) { why.Add($"a rule on {f.Label}: pick its bucket"); continue; }
            rules.Add(new Rule("", f.Field, match!, vals, rb, 0, false, false));
        }
        if (rules.Count > MaxRules) why.Add($"at most {MaxRules} rules");
        return why.Count > 0 || fallback is null ? (null, why) : (new Mapping(buckets, fallback, baseMap, rules), Array.Empty<string>());
    }

    // ------------------------------------------------------------------------------------------------ the changes

    private static string Slug(string v) => Regex.Replace(v.ToLowerInvariant(), "[^a-z0-9]+", "-").Trim('-');

    /// The data-model changes that turn the mapping in force into <paramref name="want"/> -- only what differs. Each is one
    /// cfg.ItemOverride change (validated again when it is staged and on commit).
    public static IReadOnlyList<Change> Plan(Spec spec, IReadOnlyList<DataModelRow> rows, Mapping want, IReadOnlyList<string> baseValues)
    {
        var changes = new List<Change>();
        var have = Read(spec, rows);
        // 1. the buckets and the fallback: the dimension item
        if (!have.Buckets.SequenceEqual(want.Buckets, StringComparer.Ordinal) || !string.Equals(have.Fallback, want.Fallback, StringComparison.Ordinal))
        {
            var dim = rows.FirstOrDefault(r => r.ItemKey == spec.DimensionKey);
            JsonObject o;
            try { o = (JsonNode.Parse(dim?.Effective ?? dim?.TemplateBody ?? "{}") as JsonObject) ?? new JsonObject(); } catch (JsonException) { o = new JsonObject(); }
            o["id"] = spec.DimensionId;
            o["name"] ??= spec.DimensionName;
            var arr = new JsonArray(); foreach (var b in want.Buckets) arr.Add(b);
            o["values"] = arr;
            o["default"] = want.Fallback;
            var shipped = dim?.TemplateBody is { } tb && Body(tb) is { } tbe && Strings(tbe, "values").SequenceEqual(want.Buckets, StringComparer.Ordinal)
                          && string.Equals(S(tbe, "default"), want.Fallback, StringComparison.Ordinal);
            changes.Add(shipped && dim is { Overridden: true }
                ? new Change(spec.DimensionKey, ItemOverrideRepository.StateInherit, null, "the buckets back to the shipped " + string.Join(", ", want.Buckets))
                : new Change(spec.DimensionKey, ItemOverrideRepository.StateOverride, o.ToJsonString(), $"buckets {string.Join(", ", want.Buckets)}; fallback {want.Fallback}"));
        }
        var cls = rows.Where(r => r.Template == ClassificationItemValidator.ClassificationTemplate && r.Item.Length > 0).ToDictionary(r => r.Item, StringComparer.Ordinal);
        // 2. the base rows (one per base value)
        if (spec.BaseField is not null)
            foreach (var v in baseValues)
            {
                var id = spec.BasePrefix + Slug(v);
                want.Base.TryGetValue(v, out var b);
                cls.TryGetValue(id, out var row);
                var bodyOf = (string set) => new JsonObject
                {
                    ["id"] = id, ["field"] = spec.BaseField, ["match"] = "equals", ["values"] = new JsonArray(v), ["target"] = spec.TargetField, ["set"] = set,
                    ["priority"] = BasePriority, ["state"] = "enabled", ["note"] = $"{spec.DimensionName}: {v} -> {set} (set on the mapping page)",
                };
                AddRow(changes, row, id, b, bodyOf, $"{v} -> {b ?? want.Fallback + " (fallback)"}");
            }
        // 3. the rules, in order: priority RuleTop - 10 x place; a removed rule goes
        var taken = new HashSet<string>(cls.Keys, StringComparer.Ordinal);
        var unused = have.Rules.ToList();
        for (var i = 0; i < want.Rules.Count; i++)
        {
            var w = want.Rules[i];
            var prio = Math.Max(BasePriority + 1, RuleTop - RuleStep * i);
            // the same rule (field, match, values) keeps its row; a new one gets the next free customer id
            var same = unused.FirstOrDefault(h => h.Field == w.Field && h.Match == w.Match && h.Values.SequenceEqual(w.Values, StringComparer.OrdinalIgnoreCase));
            string id;
            if (same is not null) { unused.Remove(same); id = same.Id; }
            else { var n = 1; do { id = spec.RulePrefix + n++; } while (taken.Contains(id)); taken.Add(id); }
            cls.TryGetValue(id, out var row);
            var label = spec.RuleFields.FirstOrDefault(f => f.Field == w.Field).Label ?? w.Field;
            var text = $"rule {i + 1}: {label} {Matches.First(m => m.Match == w.Match).Label} {string.Join(", ", w.Values)} -> {w.Bucket}";
            JsonObject Make(string set) => new()
            {
                ["id"] = id, ["field"] = w.Field, ["match"] = w.Match,
                [w.Match == "in" ? "values" : "pattern"] = new JsonArray(w.Values.Select(x => (JsonNode)JsonValue.Create(x)!).ToArray()),
                ["target"] = spec.TargetField, ["set"] = set, ["priority"] = prio, ["state"] = "enabled", ["note"] = $"{spec.DimensionName} rule (set on the mapping page)",
            };
            AddRow(changes, row, id, w.Bucket, Make, text);
        }
        foreach (var gone in unused)
        {
            if (!cls.TryGetValue(gone.Id, out var row)) continue;
            changes.Add(new Change(row.ItemKey, row.Own ? ItemOverrideRepository.StateInherit : ItemOverrideRepository.StateDisable, null, $"remove the rule {gone.Id}"));
        }
        return changes;
    }

    /// One row to the wanted value: <paramref name="set"/> null = the row should not place anything (removed / turned off).
    private static void AddRow(List<Change> changes, DataModelRow? row, string id, string? set, Func<string, JsonObject> make, string what)
    {
        var key = ClassificationItemValidator.ClassificationTemplate + ":" + id;
        if (set is null)
        {
            if (row is null || row.Effective is null) return;            // nothing there, or off already
            changes.Add(new Change(key, row.Own ? ItemOverrideRepository.StateInherit : ItemOverrideRepository.StateDisable, null, what));
            return;
        }
        var body = make(set);
        if (row is not null && !row.Own && row.TemplateBody is { } tb && Same(tb, body))
        {
            if (row.Overridden || row.Disabled) changes.Add(new Change(key, ItemOverrideRepository.StateInherit, null, what + " (as shipped)"));
            return;
        }
        if (row?.Effective is { } eff && Same(eff, body)) return;
        if (row is null || row.Own) body["origin"] = "customer";
        changes.Add(new Change(key, ItemOverrideRepository.StateOverride, body.ToJsonString(), what));
    }

    /// Two rows place the same: field, match, values / pattern, target, set, priority and state (the note does not count).
    private static bool Same(string json, JsonObject want)
    {
        if (Body(json) is not { } a) return false;
        using var bd = JsonDocument.Parse(want.ToJsonString());
        var b = bd.RootElement;
        foreach (var p in new[] { "field", "match", "target", "set" }) if (!string.Equals(S(a, p), S(b, p), StringComparison.Ordinal)) return false;
        if ((S(a, "state") is { Length: > 0 } st ? st : "enabled") != "enabled") return false;
        var av = Strings(a, "values").Concat(Strings(a, "pattern")).ToList(); var bv = Strings(b, "values").Concat(Strings(b, "pattern")).ToList();
        if (!av.SequenceEqual(bv, StringComparer.Ordinal)) return false;
        var ap = a.TryGetProperty("priority", out var x) && x.TryGetInt32(out var xi) ? xi : -1;
        var bp = b.TryGetProperty("priority", out var y) && y.TryGetInt32(out var yi) ? yi : -2;
        return ap == bp;
    }

    // ------------------------------------------------------------------------------------------------ the preview

    /// The bucket a mapping gives one finding / asset (field -> its values; a list field has several): the rules in order,
    /// then the base value, else the fallback. The engine's twin for these rows: case-insensitive; 'in' = one of the values
    /// equals; prefix / pattern = a PowerShell wildcard (prefix = the glob followed by *); any value of a list; an empty field
    /// never matches.
    public static string Evaluate(Mapping m, IReadOnlyDictionary<string, IReadOnlyList<string>> facts, string? baseField)
    {
        foreach (var r in m.Rules)
        {
            if (r.Off) continue;
            if (!facts.TryGetValue(r.Field, out var vals) || vals.Count == 0) continue;
            if (vals.Any(v => Matches1(r, v))) return r.Bucket;
        }
        if (baseField is not null && facts.TryGetValue(baseField, out var bv))
            foreach (var v in bv) if (m.Base.TryGetValue(v.Trim(), out var b)) return b;
        return m.Fallback;
    }

    private static bool Matches1(Rule r, string value)
    {
        var v = value.Trim();
        if (v.Length == 0) return false;
        if (r.Match is "in" or "equals") return r.Values.Any(x => string.Equals(x.Trim(), v, StringComparison.OrdinalIgnoreCase));
        return r.Values.Any(p =>
        {
            var g = r.Match == "prefix" && !p.EndsWith('*') ? p + "*" : p;
            return Glob(g).IsMatch(v);
        });
    }

    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, Regex> Globs = new(StringComparer.Ordinal);

    /// A PowerShell wildcard of plain characters (* any run, ? one character) as a whole-value, case-insensitive regex.
    private static Regex Glob(string g) => Globs.GetOrAdd(g, x =>
        new Regex("^" + string.Concat(x.Select(c => c switch { '*' => ".*", '?' => ".", _ => Regex.Escape(c.ToString()) })) + "$",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Singleline, TimeSpan.FromMilliseconds(200)));

    /// Counts per bucket of a list of grouped facts (each with its number of findings / assets).
    public static IReadOnlyDictionary<string, long> Count(Mapping m, IEnumerable<(IReadOnlyDictionary<string, IReadOnlyList<string>> Facts, long N)> groups, string? baseField)
    {
        var d = new Dictionary<string, long>(StringComparer.Ordinal);
        foreach (var (facts, n) in groups) { var b = Evaluate(m, facts, baseField); d[b] = (d.TryGetValue(b, out var c) ? c : 0) + n; }
        return d;
    }

    /// A ';'-joined source value (a vulnerability's products) as its values.
    public static IReadOnlyList<string> Values(string? s) =>
        string.IsNullOrWhiteSpace(s) ? Array.Empty<string>() : s.Split(';').Select(x => x.Trim()).Where(x => x.Length > 0).ToList();
}
