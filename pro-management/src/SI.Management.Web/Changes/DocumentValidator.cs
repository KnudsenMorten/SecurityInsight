using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;
using YamlDotNet.Serialization;

namespace SI.Management.Web.Changes;

/// <summary>
/// The C# twin of Test-SIProDocumentKey / Test-SIProDocument (engine\pro-settings\SI-ProSettings.ps1) and the parts of
/// Test-SIJsonChange / Test-SIRuleText they call (engine\pro-settings\SI-Settings.ps1). The run-start reader checks
/// every cfg.Document row AGAIN and FAILS the run on a refused row -- so the GUI must never write what the reader
/// would refuse. Where this port is unsure it refuses (conservative), never the other way round.
/// </summary>
public static partial class DocumentValidator
{
    public static readonly IReadOnlyList<string> Kinds = ["exclusions", "weights", "rule"];
    public static readonly IReadOnlyList<string> WeightEngines = ["endpoint", "identity", "azure", "publicip"];

    /// The detection kinds the asset-profiling engine registers ($script:SIKindRegistry in
    /// engine\asset-profiling\shared\RuleEval.ps1). A test reads that file and fails when this list drifts.
    public static readonly IReadOnlyList<string> RuleKinds =
    [
        "nameMatches", "osPlatform", "hasMdeMachineGroupTag", "egDetectedRoles", "hasEntraExtensionAttributeTag", "hasSoftwareInstalled",
        "groupMembership", "hasAzureTagDirectOrParent", "egKustoQuery", "mostFrequentUserTier", "ipInRange", "hasTag", "assetKind",
    ];

    [GeneratedRegex(@"^(endpoint|identity|azure|shared)/[A-Za-z][A-Za-z0-9_\-]{0,99}$", RegexOptions.CultureInvariant)] public static partial Regex RuleKey();
    [GeneratedRegex(@"^[A-Za-z0-9_]+$", RegexOptions.CultureInvariant)] private static partial Regex ReportKey();
    [GeneratedRegex(@"^CVE-\d{4}-\d{4,7}$", RegexOptions.CultureInvariant)] private static partial Regex Cve();
    [GeneratedRegex(@"^[A-Za-z0-9._:\-]{1,128}$", RegexOptions.CultureInvariant)] private static partial Regex ConfigId();
    [GeneratedRegex("^[^\"\\\\\\r\\n]{1,128}$", RegexOptions.CultureInvariant)] private static partial Regex Tag();
    [GeneratedRegex(@"^[A-Za-z_][A-Za-z0-9_]{0,63}$", RegexOptions.CultureInvariant)] private static partial Regex Field();
    [GeneratedRegex(@"^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$", RegexOptions.CultureInvariant)] private static partial Regex IpRange();
    [GeneratedRegex("^[^\"\\\\\\r\\n]{1,64}$", RegexOptions.CultureInvariant)] private static partial Regex MapKey();

    public static string? KeyProblem(string kind, string key)
    {
        // #251: the CMDB ownership map is a configuration document too -- kept in cfg.ItemOverride, never in cfg.Document
        if (kind == OwnershipMapValidator.Kind) return OwnershipMapValidator.KeyProblem(key);
        if (!Kinds.Contains(kind)) return $"'{kind}' is not a document kind (exclusions, weights, rule)";
        if (string.IsNullOrWhiteSpace(key) || key.Length > 128) return "the key is empty or longer than 128 characters";
        return kind switch
        {
            "exclusions" when key != "global" && !ReportKey().IsMatch(key) => $"'{key}' is not 'global' or a report name",
            "weights" when key != "solution" => "the weights document has the key 'solution'",
            "rule" when !RuleKey().IsMatch(key) => $"'{key}' is not '<engine>/<rule id>' (engine: endpoint, identity, azure or shared)",
            _ => null,
        };
    }

    /// <summary>The reasons a document is refused (empty = accepted). knownReports = the Risk Analysis report names an
    /// exclusions document may be keyed by (besides 'global').</summary>
    public static IReadOnlyList<string> Validate(string kind, string key, string? body, IReadOnlyCollection<string> knownReports)
    {
        var why = new List<string>();
        var k = KeyProblem(kind, key);
        if (k is not null) { why.Add(k); return why; }
        if (kind == OwnershipMapValidator.Kind) return OwnershipMapValidator.Validate(body);
        if (string.IsNullOrWhiteSpace(body)) { why.Add("the document is empty"); return why; }
        body = body.TrimStart('﻿');
        switch (kind)
        {
            case "exclusions":
                if (key != "global" && !knownReports.Contains(key, StringComparer.Ordinal)) { why.Add($"'{key}' is not a shipped Risk Analysis report"); break; }
                if (ParseObject(body, why) is not { } ex) break;
                foreach (var p in ex.EnumerateObject())
                {
                    if (IsNote(p.Name)) continue;
                    if (key == "global")
                    {
                        // #541: the global exclusions reach every report whose scope declares them (the Risk Analysis scope preamble)
                        switch (p.Name)
                        {
                            case "ExcludedAssetTags": List(p.Value, Tag(), "tag (no quotes, backslashes or line breaks)", why); break;
                            case "ExcludedAssets": List(p.Value, Tag(), "asset id or name (no quotes, backslashes or line breaks)", why); break;
                            case "ExcludedIpRanges": List(p.Value, IpRange(), "IPv4 address or range (a.b.c.d/nn)", why); break;
                            default: why.Add("only ExcludedAssetTags, ExcludedAssets and ExcludedIpRanges can be set globally"); break;
                        }
                        continue;
                    }
                    switch (p.Name)
                    {
                        case "ExcludedCves": List(p.Value, Cve(), "CVE id (CVE-YYYY-NNNN)", why); break;
                        case "ExcludedConfigurationIds": List(p.Value, ConfigId(), "configuration id (letters, digits, . _ : -)", why); break;
                        case "ExcludedAssetTags": List(p.Value, Tag(), "tag (no quotes, backslashes or line breaks)", why); break;
                        case "ExcludedAssets": List(p.Value, Tag(), "asset id or name (no quotes, backslashes or line breaks)", why); break;
                        case "ExcludedIpRanges": List(p.Value, IpRange(), "IPv4 address or range (a.b.c.d/nn)", why); break;
                        case "CveMinAgeDays":
                            if (!(Whole(p.Value, out var n) && n >= 0 && n <= 3650)) why.Add("CveMinAgeDays must be a whole number from 0 to 3650");
                            break;
                        default: why.Add($"'{p.Name}' is not an exclusion setting"); break;
                    }
                }
                break;
            case "weights":
                if (ParseObject(body, why) is not { } w) break;
                foreach (var p in w.EnumerateObject())
                {
                    if (IsNote(p.Name) || p.Name == "$schema") continue;
                    if (p.Name != "weightedRiskFactors") { why.Add($"'{p.Name}' is not managed as a Pro document -- only weightedRiskFactors (keep other sections in the file)"); continue; }
                    if (p.Value.ValueKind != JsonValueKind.Object) { why.Add("weightedRiskFactors must be an object keyed by engine"); continue; }
                    foreach (var e in p.Value.EnumerateObject())
                    {
                        if (IsNote(e.Name)) continue;
                        Weights(e.Name, e.Value, why);
                    }
                }
                break;
            case "rule":
                why.AddRange(RuleProblems(body, key[(key.IndexOf('/') + 1)..]));
                break;
        }
        return why;
    }

    private static bool IsNote(string n) => n.StartsWith('_') || n == "Comment";

    private static JsonElement? ParseObject(string text, List<string> why)
    {
        try
        {
            using var doc = JsonDocument.Parse(text);
            if (doc.RootElement.ValueKind != JsonValueKind.Object) { why.Add("the document must be a JSON object"); return null; }
            return doc.RootElement.Clone();
        }
        catch (JsonException ex) { why.Add("the document is not valid JSON: " + ex.Message); return null; }
    }

    private static string Text(JsonElement v) => v.ValueKind switch
    {
        JsonValueKind.String => v.GetString() ?? "",
        JsonValueKind.Null => "",
        _ => v.GetRawText(),
    };

    private static void List(JsonElement v, Regex rx, string what, List<string> why)
    {
        var items = v.ValueKind == JsonValueKind.Array ? v.EnumerateArray().ToList() : new List<JsonElement> { v };
        foreach (var x in items)
        {
            if (x.ValueKind is JsonValueKind.Object or JsonValueKind.Array) { why.Add($"'{x.GetRawText()}' is not a valid {what}"); continue; }
            var s = Text(x);
            if (!rx.IsMatch(s)) why.Add($"'{s}' is not a valid {what}");
        }
    }

    private static bool Whole(JsonElement v, out double n)
    {
        n = 0;
        var s = Text(v);
        if (v.ValueKind is JsonValueKind.Object or JsonValueKind.Array) return false;
        if (!double.TryParse(s, NumberStyles.Float, CultureInfo.InvariantCulture, out n)) return false;
        return n == Math.Floor(n);
    }

    private static void Weights(string engine, JsonElement v, List<string> why)
    {
        if (!WeightEngines.Contains(engine)) { why.Add($"'{engine}' is not an engine (endpoint, identity, azure, publicip)"); return; }
        if (v.ValueKind == JsonValueKind.Null) return;
        if (v.ValueKind != JsonValueKind.Object) { why.Add($"{engine}: the weights must be an object"); return; }
        if (v.TryGetProperty("combine", out var c) && Text(c) is { Length: > 0 } cs && cs is not ("product" or "max" or "sum-of-deltas"))
            why.Add("combine must be product, max or sum-of-deltas");
        if (v.TryGetProperty("maxMultiplier", out var mm) && mm.ValueKind != JsonValueKind.Null && !(Whole(mm, out var m) && m >= 0 && m <= 10000))
            why.Add("maxMultiplier must be a whole number from 0 to 10000 (100 = 1.0x, 500 = a 5x cap, 0 = no cap)");
        var fields = v.TryGetProperty("fields", out var f) ? (f.ValueKind == JsonValueKind.Array ? f.EnumerateArray().ToList() : new List<JsonElement> { f }) : new List<JsonElement>();
        if (fields.Count == 0) why.Add("at least one weighted field is needed");
        foreach (var fl in fields)
        {
            var name = fl.ValueKind == JsonValueKind.Object && fl.TryGetProperty("field", out var fn) ? Text(fn) : "";
            if (!Field().IsMatch(name)) { why.Add($"'{name}' is not a valid field name"); continue; }
            var map = fl.TryGetProperty("valueMap", out var vm) && vm.ValueKind == JsonValueKind.Object ? vm.EnumerateObject().ToList() : new List<JsonProperty>();
            if (map.Count == 0) why.Add($"{name}: the value map is empty");
            foreach (var kv in map)
            {
                if (!MapKey().IsMatch(kv.Name)) why.Add($"{name}: '{kv.Name}' is not a valid value");
                if (!(Whole(kv.Value, out var x) && x >= 1 && x <= 1000)) why.Add($"{name}: the multiplier for '{kv.Name}' must be a whole number from 1 to 1000 (100 = 1.0x, 150 = 1.5x)");
            }
            if (fl.TryGetProperty("default", out var d) && d.ValueKind != JsonValueKind.Null && !(Whole(d, out var dv) && dv >= 1 && dv <= 1000))
                why.Add($"{name}: the default multiplier must be a whole number from 1 to 1000 (100 = 1.0x)");
        }
    }

    /// Test-SIRuleText: it parses, keeps the key's id, uses only known kinds and appliesTo engines, tiers 0-3.
    public static IReadOnlyList<string> RuleProblems(string text, string id)
    {
        var why = new List<string>();
        object? o;
        try { o = new DeserializerBuilder().Build().Deserialize<object>(text); }
        catch (Exception ex) when (ex is YamlDotNet.Core.YamlException or InvalidOperationException) { why.Add("the rule is not valid YAML: " + ex.Message); return why; }
        if (o is not IDictionary<object, object> map) { why.Add("the rule must be a YAML mapping"); return why; }
        string? S(IDictionary<object, object> m, string k) => m.TryGetValue(k, out var v) ? v?.ToString() : null;
        if (S(map, "id") != id) why.Add($"the id must stay '{id}' -- it is what replaces the shipped rule");
        if (S(map, "mode") == "disable") return why;
        var applies = map.TryGetValue("appliesTo", out var ap) ? (ap is IEnumerable<object> l ? l.Select(x => x?.ToString() ?? "") : new[] { ap?.ToString() ?? "" }) : Array.Empty<string>();
        foreach (var a in applies.SelectMany(x => x.Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)))
            if (!new[] { "endpoint", "identity", "azure", "publicip", "any" }.Contains(a.ToLowerInvariant())) why.Add($"appliesTo '{a}' is not an engine");
        var dets = map.TryGetValue("detections", out var dv) && dv is IList<object> dl ? dl : null;
        if (dets is null || dets.Count == 0 || dets[0] is null) { why.Add("a rule needs at least one detection"); return why; }
        foreach (var d in dets)
        {
            if (d is not IDictionary<object, object> dm) { why.Add("a detection must be a mapping"); continue; }
            var did = S(dm, "id");
            var detect = dm.TryGetValue("detect", out var dt) ? dt as IDictionary<object, object> : null;
            var list = detect is null ? null : (detect.TryGetValue("any", out var any) && any is IList<object> al && al.Count > 0 ? al
                : detect.TryGetValue("all", out var all) && all is IList<object> ll && ll.Count > 0 ? ll : null);
            if (list is null) { why.Add($"detection '{did}': detect needs an 'any' or 'all' list"); continue; }
            foreach (var k in list)
            {
                var kind = k is IDictionary<object, object> km ? S(km, "kind") : null;
                if (kind is null || !RuleKinds.Contains(kind)) why.Add($"detection '{did}': '{kind}' is not a detection kind the engine knows");
            }
            if (dm.TryGetValue("set", out var set) && set is IDictionary<object, object> sm && sm.TryGetValue("Tier", out var t) && t is not null)
                if (!int.TryParse(t.ToString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var n) || n < 0 || n > 3)
                    why.Add($"detection '{did}': Tier must be 0, 1, 2 or 3");
        }
        return why;
    }
}
