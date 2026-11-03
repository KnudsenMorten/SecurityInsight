using System.Text.Json.Nodes;

namespace SI.Management.Core.ProData;

/// <summary>
/// One CI rule of the ServiceNow CI output (#1055): the CI fields it names and the values that match each (OR within a
/// field). It MATCHES a CI when every field it names holds one of its values (case does not count); a CI without a value
/// for a field never matches a rule that names it.
/// </summary>
public sealed record CiRule(IReadOnlyList<ScopeFilter> Fields)
{
    public bool Matches(IReadOnlyDictionary<string, string?> ci) =>
        Fields.Count > 0 && Fields.All(f => ci.TryGetValue(f.Field, out var v) && !string.IsNullOrWhiteSpace(v) && f.Values.Contains(v.Trim(), StringComparer.OrdinalIgnoreCase));

    /// "asset type Unknown + OS family iOS, Android".
    public string Describe() => string.Join(" + ", Fields.Select(f => CiRules.Label(f.Field).ToLowerInvariant() + " " + string.Join(", ", f.Values)));
}

/// <summary>
/// THE CI RULES OF THE SERVICENOW CI OUTPUT (#1055, owner 2026-11-02: "we should NOT be syncing these assets [mobile phones]
/// into snow"; "we need to be able to filter on this in the snow connectors"): the output scope item 'cmdb-servicenow' takes
/// <c>"include": [ { "si_asset_type": [...], "si_os_family": [...], "si_class": [...] } ]</c> and
/// <c>"exclude": [ ... ]</c>. A CI is sent when no include rule is set or it matches ANY include rule, AND it matches NO
/// exclude rule. The C# twin of SI-OutputScope.ps1 ($SIOutputScopeCiRuleFields, Test-SIOutputScopeCiRules,
/// Test-SIOutputScopeCiRuleBody) -- tests\fixtures\ci-scope-rules.cases.json holds both to the same cases.
/// </summary>
public static class CiRules
{
    /// The CI fields a rule may name: its words, its closed list of values (empty = the classification catalog's values,
    /// which a customer may extend -- any plain value is accepted).
    public static readonly IReadOnlyList<(string Field, string Label, IReadOnlyList<string> Values)> Fields =
    [
        ("si_asset_type", "Asset type", Array.Empty<string>()),
        ("si_os_family", "OS family", Array.Empty<string>()),
        ("si_class", "Class", ["device", "identity", "cloud_resource", "public_ip"]),
    ];

    /// The destinations that take CI rules.
    public static readonly IReadOnlyList<string> Destinations = ["cmdb-servicenow"];
    public const int Max = 25;

    public static bool Supports(string destination) => Destinations.Contains(destination);
    public static string Label(string field) => Fields.FirstOrDefault(f => f.Field == field).Label ?? field;

    /// The rules of an 'include' / 'exclude' node (a rule naming no value is dropped; fields in the catalog's order).
    public static IReadOnlyList<CiRule> Read(JsonNode? node)
    {
        if (node is not JsonArray a) return Array.Empty<CiRule>();
        var list = new List<CiRule>();
        foreach (var x in a)
        {
            if (x is not JsonObject o) continue;
            var fs = new List<ScopeFilter>();
            foreach (var (field, n) in o.OrderBy(p => p.Key, StringComparer.Ordinal))
            {
                var vals = n switch
                {
                    JsonArray va => va.Select(v => OutputMapper.Text(v)).ToList(),
                    JsonValue => new List<string?> { OutputMapper.Text(n) },
                    _ => new List<string?>(),
                };
                var clean = vals.Where(v => !string.IsNullOrWhiteSpace(v)).Select(v => v!.Trim()).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
                if (clean.Count > 0) fs.Add(new ScopeFilter(field, clean));
            }
            if (fs.Count > 0) list.Add(new CiRule(fs));
        }
        return list;
    }

    /// The rules as stored: one object per rule, its fields in the catalog's order.
    public static JsonArray Write(IEnumerable<CiRule> rules) => new(rules.Select(r =>
    {
        var o = new JsonObject();
        foreach (var f in r.Fields.OrderBy(f => Order(f.Field)).ThenBy(f => f.Field, StringComparer.Ordinal))
            o[f.Field] = ProJson.Array(Ordered(f.Field, f.Values));
        return (JsonNode?)o;
    }).ToArray());

    private static int Order(string field) { var i = Fields.Select(f => f.Field).ToList().IndexOf(field); return i < 0 ? int.MaxValue : i; }

    /// A closed list's values in its own order; any other list as given (no repeats).
    public static IReadOnlyList<string> Ordered(string field, IReadOnlyList<string> values) =>
        Fields.FirstOrDefault(f => f.Field == field).Values is { Count: > 0 } k ? k.Where(v => values.Contains(v, StringComparer.OrdinalIgnoreCase)).ToList() : values.Distinct(StringComparer.OrdinalIgnoreCase).ToList();

    /// Test-SIOutputScopeCiRuleBody's rules for one side ('include' / 'exclude').
    public static IReadOnlyList<string> Validate(string side, IReadOnlyList<CiRule> rules)
    {
        var why = new List<string>();
        if (rules.Count > Max) why.Add($"{side}: at most {Max} rules");
        var i = 0;
        foreach (var r in rules)
        {
            i++;
            if (r.Fields.Count == 0) { why.Add($"{side} rule {i} names no field"); continue; }
            foreach (var f in r.Fields)
            {
                var known = Fields.FirstOrDefault(x => x.Field == f.Field);
                if (known.Field is null) { why.Add($"{side} rule {i}: '{f.Field}' is not a CI field a rule may name ({string.Join(", ", Fields.Select(x => x.Field))})"); continue; }
                if (f.Values.Count == 0) why.Add($"{side} rule {i}: '{f.Field}' names no value");
                foreach (var v in f.Values)
                {
                    if (v.Length > 64 || v.IndexOfAny(['\r', '\n', '\t', ';']) >= 0) why.Add($"{side} rule {i}: '{v}' is not a value of {f.Field} (one line, at most 64 characters)");
                    else if (known.Values.Count > 0 && !known.Values.Contains(v, StringComparer.OrdinalIgnoreCase)) why.Add($"{side} rule {i}: '{v}' is not a {known.Label.ToLowerInvariant()} ({string.Join(", ", known.Values)})");
                }
            }
        }
        return why;
    }

    /// Test-SIOutputScopeCiRuleBody on a STORED body as it is (before <see cref="Read"/> drops an empty rule): the reasons
    /// its 'include' / 'exclude' are refused -- the same the engine gives at run start.
    public static IReadOnlyList<string> ValidateBody(string destination, string? body)
    {
        var why = new List<string>();
        if (ProJson.Parse(body) is not JsonObject o) return why;
        foreach (var side in new[] { "include", "exclude" })
        {
            if (!o.TryGetPropertyValue(side, out var node) || node is null) continue;
            if (!Supports(destination)) { why.Add($"'{side}' is a CI rule of the ServiceNow CI output only (cmdb-servicenow), not of {destination}"); continue; }
            if (node is not JsonArray a) { why.Add($"'{side}' must be a list of rules: [ {{ \"si_asset_type\": [\"Mobile\"] }} ]"); continue; }
            if (a.Count > Max) why.Add($"{side}: at most {Max} rules");
            var i = 0;
            foreach (var r in a)
            {
                i++;
                if (r is not JsonObject ro) { why.Add($"{side} rule {i}: a rule is an object {{ \"<CI field>\": [values] }}"); continue; }
                if (ro.Count == 0) { why.Add($"{side} rule {i} names no field"); continue; }
                foreach (var (field, vn) in ro)
                {
                    if (!Fields.Any(f => f.Field == field)) { why.Add($"{side} rule {i}: '{field}' is not a CI field a rule may name ({string.Join(", ", Fields.Select(x => x.Field))})"); continue; }
                    if (vn is null or JsonObject) { why.Add($"{side} rule {i}: '{field}' must be a list of values"); continue; }
                    var vals = (vn is JsonArray va ? va.Select(x => OutputMapper.Text(x)) : (IEnumerable<string>)new[] { OutputMapper.Text(vn) }).Where(v => !string.IsNullOrWhiteSpace(v)).Select(v => v.Trim()).ToList();
                    if (vals.Count == 0) { why.Add($"{side} rule {i}: '{field}' names no value"); continue; }
                    why.AddRange(Validate(side, [new CiRule([new ScopeFilter(field, vals)])]).Select(w => w.Replace($"{side} rule 1", $"{side} rule {i}")));
                }
            }
        }
        return why;
    }

    /// A CI's values for the rules from a JSON item (its own si_asset_type, si_os_family, si_class).
    public static IReadOnlyDictionary<string, string?> ValuesOf(JsonObject item) =>
        Fields.ToDictionary(f => f.Field, f => OutputMapper.Text(OutputMapper.Get(item, f.Field)), StringComparer.Ordinal);

    /// The asset kind of a CI's class (ConvertTo-SIDataOutAssetKind).
    public static string KindOf(string? cls) => (cls ?? "").Trim().ToLowerInvariant() switch
    {
        "device" => "endpoint", "identity" => "identity", "cloud_resource" => "azure", "public_ip" => "publicip", _ => "",
    };

    /// Does a CI item pass the CI output's scope (its tier, its kind, the CI rules)? Test-SIDataOutInScope -Grain ci.
    public static bool Passes(OutputScope scope, JsonObject item)
    {
        var tierText = OutputMapper.Text(OutputMapper.Get(item, "si_tier"));
        int? tier = int.TryParse(tierText, System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out var t) ? t : null;
        return scope.PassesCi(tier, KindOf(OutputMapper.Text(OutputMapper.Get(item, "si_class"))), ValuesOf(item));
    }
}
