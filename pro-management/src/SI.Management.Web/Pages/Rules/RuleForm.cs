using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using YamlDotNet.Core;
using YamlDotNet.RepresentationModel;

namespace SI.Management.Web.Pages.Rules;

/// <summary>
/// One value of a rule: a name and its value(s). <see cref="List"/> = a YAML list (one item per line in the form);
/// <see cref="Text"/> = written as quoted text (false = a plain value: a number, true / false, or empty). A value the
/// engine reads as text stays text, a number stays a number -- so a form round trip loads exactly as the YAML did.
/// </summary>
public sealed class RuleParam
{
    public string Name { get; set; } = "";
    public string Value { get; set; } = "";
    public bool List { get; set; }
    public bool Text { get; set; } = true;
}

public sealed class RuleCondition
{
    public string Kind { get; set; } = "";
    public List<RuleParam> Params { get; set; } = new();
}

public sealed class RuleDetection
{
    public string Id { get; set; } = "";
    /// any (one condition is enough) | all (every condition).
    public string Combine { get; set; } = "any";
    public List<RuleCondition> Conditions { get; set; } = new();
    /// The tier this detection sets: "" (none), 0..3.
    public string Tier { get; set; } = "";
    /// Everything else the detection sets (Purpose, Category, Tags, cmdbId, ...).
    public List<RuleParam> Set { get; set; } = new();
    /// Other keys of the detection (excludeAssets, ...).
    public List<RuleParam> Fields { get; set; } = new();
}

/// <summary>
/// An asset-profiling (tier / detection) rule as a form: the rule's own fields, its detections, each with its conditions
/// ("detect: any | all"), what it sets (Tier + the rest) and its other keys. Parse reads the YAML the engine reads
/// (Get-SIRuleSet); ToYaml writes the subset of YAML SecurityInsight's own reader (SI-Yaml.ps1) reads, so the
/// materialised rule loads with the same values and types. A rule the form cannot hold without losing something (a
/// nested map under a condition, a list of lists, ...) is NOT shown as a form -- it is edited as YAML.
/// </summary>
public sealed partial class RuleFormModel
{
    public string Id { get; set; } = "";
    public List<RuleParam> Fields { get; set; } = new();
    public List<RuleDetection> Detections { get; set; } = new();

    /// The detection kinds and the parameters each one reads (engine\asset-profiling\shared\RuleEval.ps1) -- offered in
    /// the form; any other parameter name is kept as written.
    public static readonly IReadOnlyDictionary<string, string[]> KindParams = new Dictionary<string, string[]>(StringComparer.Ordinal)
    {
        ["nameMatches"] = ["namePatterns"],
        ["osPlatform"] = ["osPatterns"],
        ["hasMdeMachineGroupTag"] = ["machineTagPatterns"],
        ["egDetectedRoles"] = ["egSignals"],
        ["hasEntraExtensionAttributeTag"] = ["attribute", "patterns"],
        ["hasSoftwareInstalled"] = ["tvmSoftwareNames"],
        ["groupMembership"] = ["group"],
        ["hasAzureTagDirectOrParent"] = ["tag", "value"],
        ["egKustoQuery"] = ["query"],
        ["mostFrequentUserTier"] = ["tierValues"],
        ["ipInRange"] = ["cidrs", "fields"],
        ["hasTag"] = ["tag", "value", "match", "sources"],
        ["assetKind"] = ["kinds"],
    };

    /// Friendly labels for the rule's and a detection's well-known keys.
    public static string Label(string name) => name switch
    {
        "appliesTo" => "Engines it applies to (appliesTo)",
        "mode" => "Mode",
        "purpose" => "Purpose",
        "category" => "Category",
        "description" => "Description",
        "excludeAssets" => "Assets (CIs) this detection skips (excludeAssets)",
        "excludeNames" => "Assets (CIs) this detection skips (excludeNames)",
        "Purpose" => "Purpose it sets",
        "Category" => "Category it sets",
        "Tags" => "Tags it sets",
        "cmdbId" => "CMDB service id it sets (cmdbId)",
        _ => name,
    };

    [GeneratedRegex(@"^[A-Za-z_][A-Za-z0-9_\-]{0,99}$", RegexOptions.CultureInvariant)] private static partial Regex KeyName();
    [GeneratedRegex(@"^(true|false|True|False|TRUE|FALSE|-?\d{1,18}|-?\d{1,18}\.\d{1,18})$", RegexOptions.CultureInvariant)] private static partial Regex PlainSafe();

    // ------------------------------------------------------------------------------------------------ YAML -> form

    /// The form of a rule text, or null + why the form cannot hold it (then it is edited as YAML).
    public static (RuleFormModel? Form, string? Why) Parse(string yaml)
    {
        YamlMappingNode root;
        try
        {
            var s = new YamlStream();
            s.Load(new StringReader(yaml.TrimStart('﻿')));
            if (s.Documents.Count != 1 || s.Documents[0].RootNode is not YamlMappingNode m) return (null, "the rule is not one YAML mapping");
            root = m;
        }
        catch (YamlException ex) { return (null, "the rule is not valid YAML: " + ex.Message); }
        var f = new RuleFormModel();
        foreach (var (k, v) in root.Children)
        {
            var name = (k as YamlScalarNode)?.Value ?? "";
            if (name == "id") { if (v is not YamlScalarNode idn) return (null, "id is not one value"); f.Id = idn.Value ?? ""; continue; }
            if (name == "detections")
            {
                if (v is not YamlSequenceNode ds) return (null, "detections is not a list");
                foreach (var d in ds.Children)
                {
                    var (det, why) = ParseDetection(d);
                    if (det is null) return (null, why);
                    f.Detections.Add(det);
                }
                continue;
            }
            var p = ParamOf(name, v);
            if (p is null) return (null, $"'{name}' holds a structure the form cannot show");
            f.Fields.Add(p);
        }
        return (f, null);
    }

    private static (RuleDetection? D, string? Why) ParseDetection(YamlNode node)
    {
        if (node is not YamlMappingNode m) return (null, "a detection is not a mapping");
        var d = new RuleDetection();
        var sawDetect = false;
        foreach (var (k, v) in m.Children)
        {
            var name = (k as YamlScalarNode)?.Value ?? "";
            switch (name)
            {
                case "id":
                    if (v is not YamlScalarNode idn) return (null, "a detection id is not one value");
                    d.Id = idn.Value ?? "";
                    break;
                case "detect":
                {
                    if (v is not YamlMappingNode dm || dm.Children.Count != 1) return (null, $"detection '{d.Id}': detect must hold exactly one of any / all");
                    var (ck, cv) = dm.Children.First();
                    var comb = (ck as YamlScalarNode)?.Value ?? "";
                    if (comb is not ("any" or "all")) return (null, $"detection '{d.Id}': detect holds '{comb}', not any / all");
                    if (cv is not YamlSequenceNode cs) return (null, $"detection '{d.Id}': {comb} is not a list");
                    d.Combine = comb;
                    foreach (var c in cs.Children)
                    {
                        if (c is not YamlMappingNode cm) return (null, $"detection '{d.Id}': a condition is not a mapping");
                        var cond = new RuleCondition();
                        foreach (var (pk, pv) in cm.Children)
                        {
                            var pn = (pk as YamlScalarNode)?.Value ?? "";
                            if (pn == "kind") { if (pv is not YamlScalarNode kn) return (null, "a condition kind is not one value"); cond.Kind = kn.Value ?? ""; continue; }
                            var p = ParamOf(pn, pv);
                            if (p is null) return (null, $"detection '{d.Id}', condition {cond.Kind}: '{pn}' holds a structure the form cannot show");
                            cond.Params.Add(p);
                        }
                        d.Conditions.Add(cond);
                    }
                    sawDetect = true;
                    break;
                }
                case "set":
                {
                    if (v is not YamlMappingNode sm) return (null, $"detection '{d.Id}': set is not a mapping");
                    foreach (var (sk, sv) in sm.Children)
                    {
                        var sn = (sk as YamlScalarNode)?.Value ?? "";
                        if (sn == "Tier" && sv is YamlScalarNode tn && tn.Style == ScalarStyle.Plain && Regex.IsMatch(tn.Value ?? "", "^[0-3]$")) { d.Tier = tn.Value!; continue; }
                        var p = ParamOf(sn, sv);
                        if (p is null) return (null, $"detection '{d.Id}': set.{sn} holds a structure the form cannot show");
                        d.Set.Add(p);
                    }
                    break;
                }
                default:
                {
                    var p = ParamOf(name, v);
                    if (p is null) return (null, $"detection '{d.Id}': '{name}' holds a structure the form cannot show");
                    d.Fields.Add(p);
                    break;
                }
            }
        }
        if (!sawDetect) return (null, $"detection '{d.Id}' has no detect");
        return (d, null);
    }

    /// A value the form can hold: one scalar, or a list of scalars of one kind (all text, or all plain). Null otherwise.
    private static RuleParam? ParamOf(string name, YamlNode v)
    {
        if (!KeyName().IsMatch(name)) return null;
        if (v is YamlScalarNode s)
        {
            var text = IsText(s);
            var val = s.Value ?? "";
            // a value the form cannot write back the same way: text starting with a space over several lines
            if (BadBlock(val)) return null;
            if (!text && !(val.Length == 0 || PlainSafe().IsMatch(val) || IsNullWord(val))) return null;
            return new RuleParam { Name = name, Value = IsNullWord(val) && !text ? "" : val, Text = text };
        }
        if (v is YamlSequenceNode q)
        {
            if (q.Children.Count == 0) return new RuleParam { Name = name, Value = "", List = true, Text = true };
            if (q.Children.Any(c => c is not YamlScalarNode)) return null;
            var items = q.Children.Cast<YamlScalarNode>().ToList();
            var kinds = items.Select(IsText).Distinct().ToList();
            if (kinds.Count != 1) return null;
            if (items.Any(i => (i.Value ?? "").Contains('\n') || (i.Value ?? "").Length == 0 || (i.Value ?? "") != (i.Value ?? "").Trim())) return null;
            if (!kinds[0] && items.Any(i => !PlainSafe().IsMatch(i.Value ?? ""))) return null;
            return new RuleParam { Name = name, Value = string.Join("\n", items.Select(i => i.Value)), List = true, Text = kinds[0] };
        }
        return null;
    }

    /// A text over several lines that a literal block cannot carry as it is: its first non-empty line starts with a space
    /// or a tab (the block's indentation would swallow it), it ends with an empty line, or it holds a tab-indented line.
    public static bool BadBlock(string v)
    {
        v = v.Replace("\r\n", "\n");
        if (!v.Contains('\n')) return false;
        var first = v.Split('\n').FirstOrDefault(l => l.Trim().Length > 0) ?? "";
        return first.StartsWith(' ') || first.StartsWith('\t') || v.EndsWith("\n\n", StringComparison.Ordinal) || v.Split('\n').Any(l => l.StartsWith('\t'))
               || v.Split('\n').Any(l => l.Length > 0 && l.Trim().Length == 0);
    }

    private static bool IsNullWord(string v) => v is "~" or "null" or "Null" or "NULL";

    /// Text = the engine's reader returns a string for it (quoted, a block, or a plain word that is no number / bool / null).
    private static bool IsText(YamlScalarNode s)
    {
        if (s.Style != ScalarStyle.Plain) return true;
        var v = s.Value ?? "";
        return !(v.Length == 0 || IsNullWord(v) || PlainSafe().IsMatch(v)
                 || bool.TryParse(v, out _) || decimal.TryParse(v, NumberStyles.Float, CultureInfo.InvariantCulture, out _));
    }

    // ------------------------------------------------------------------------------------------------ form -> YAML

    /// What keeps the form from being written (empty = it can be written).
    public IReadOnlyList<string> Problems()
    {
        var why = new List<string>();
        if (string.IsNullOrWhiteSpace(Id)) why.Add("the rule needs an id");
        void Check(IEnumerable<RuleParam> ps, string where)
        {
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var p in ps)
            {
                if (!KeyName().IsMatch(p.Name ?? "")) { why.Add($"{where}: '{p.Name}' is not a name (letters, digits, _ and -, starting with a letter)"); continue; }
                if (!seen.Add(p.Name!)) why.Add($"{where}: '{p.Name}' is there twice");
                var v = (p.Value ?? "").Replace("\r\n", "\n");
                if (!p.List && BadBlock(v)) why.Add($"{where}: {p.Name} -- a text over several lines may not start with a space or end with an empty line");
            }
        }
        Check(Fields, "the rule");
        foreach (var r in new[] { "id", "detections" }) if (Fields.Any(p => string.Equals(p.Name, r, StringComparison.OrdinalIgnoreCase))) why.Add($"the rule: '{r}' is not a free field");
        if (Detections.Count == 0) why.Add("a rule needs at least one detection");
        for (var i = 0; i < Detections.Count; i++)
        {
            var d = Detections[i];
            var where = $"detection {i + 1}" + (string.IsNullOrWhiteSpace(d.Id) ? "" : $" ({d.Id})");
            if (string.IsNullOrWhiteSpace(d.Id)) why.Add($"{where}: it needs an id");
            if (d.Combine is not ("any" or "all")) why.Add($"{where}: choose 'any' or 'all'");
            if (d.Conditions.Count == 0) why.Add($"{where}: it needs at least one condition");
            if (!string.IsNullOrEmpty(d.Tier) && !Regex.IsMatch(d.Tier, "^[0-3]$")) why.Add($"{where}: Tier must be 0, 1, 2 or 3");
            Check(d.Fields, where);
            Check(d.Set, where + ", what it sets");
            if (d.Set.Any(p => p.Name == "Tier")) why.Add($"{where}: set Tier with the Tier choice");
            foreach (var r in new[] { "id", "detect", "set" }) if (d.Fields.Any(p => string.Equals(p.Name, r, StringComparison.OrdinalIgnoreCase))) why.Add($"{where}: '{r}' is not a free field");
            for (var j = 0; j < d.Conditions.Count; j++)
            {
                var c = d.Conditions[j];
                if (string.IsNullOrWhiteSpace(c.Kind)) why.Add($"{where}, condition {j + 1}: choose a kind");
                Check(c.Params, $"{where}, condition {j + 1}");
                if (c.Params.Any(p => string.Equals(p.Name, "kind", StringComparison.OrdinalIgnoreCase))) why.Add($"{where}, condition {j + 1}: 'kind' is not a parameter");
            }
        }
        return why;
    }

    public string ToYaml()
    {
        var sb = new StringBuilder();
        sb.Append("id: ").Append(Q(Id.Trim())).Append('\n');
        foreach (var p in Fields) Emit(sb, 0, p);
        sb.Append("detections:\n");
        foreach (var d in Detections)
        {
            sb.Append("  - id: ").Append(Q(d.Id.Trim())).Append('\n');
            sb.Append("    detect:\n");
            sb.Append("      ").Append(d.Combine).Append(":\n");
            foreach (var c in d.Conditions)
            {
                sb.Append("        - kind: ").Append(Q(c.Kind.Trim())).Append('\n');
                foreach (var p in c.Params) Emit(sb, 10, p);
            }
            foreach (var p in d.Fields) Emit(sb, 4, p);
            if (!string.IsNullOrEmpty(d.Tier) || d.Set.Count > 0)
            {
                sb.Append("    set:\n");
                if (!string.IsNullOrEmpty(d.Tier)) sb.Append("      Tier: ").Append(d.Tier).Append('\n');
                foreach (var p in d.Set) Emit(sb, 6, p);
            }
        }
        return sb.ToString();
    }

    /// Single-quoted text ('' escapes a quote) -- one line only.
    public static string Q(string s) => "'" + s.Replace("'", "''") + "'";

    private static string Scalar(RuleParam p, string v) => !p.Text && (v.Length == 0 || PlainSafe().IsMatch(v)) ? v : Q(v);

    private static void Emit(StringBuilder sb, int indent, RuleParam p)
    {
        var pad = new string(' ', indent);
        var v = (p.Value ?? "").Replace("\r\n", "\n").Replace('\r', '\n');
        if (p.List)
        {
            var items = v.Split('\n').Select(x => x.Trim()).Where(x => x.Length > 0).ToList();
            if (items.Count == 0) { sb.Append(pad).Append(p.Name).Append(": []\n"); return; }
            sb.Append(pad).Append(p.Name).Append(":\n");
            foreach (var i in items) sb.Append(pad).Append("  - ").Append(Scalar(p, i)).Append('\n');
            return;
        }
        if (v.Contains('\n'))
        {
            var keep = v.EndsWith('\n');
            var body = keep ? v[..^1] : v;
            sb.Append(pad).Append(p.Name).Append(keep ? ": |\n" : ": |-\n");
            foreach (var line in body.Split('\n')) sb.Append(line.Length == 0 ? "" : pad + "  " + line).Append('\n');
            return;
        }
        if (!p.Text && v.Length == 0) { sb.Append(pad).Append(p.Name).Append(":\n"); return; }
        sb.Append(pad).Append(p.Name).Append(": ").Append(Scalar(p, v)).Append('\n');
    }

    // ------------------------------------------------------------------------------------------------ meaning

    /// The rule as the engine's reader sees it -- typed (SI-Yaml's plain-scalar typing), keys in order -- as canonical
    /// JSON. Two texts with the same meaning give the same string (comments and quoting do not count).
    public static string Meaning(string yaml)
    {
        var s = new YamlStream();
        s.Load(new StringReader(yaml.TrimStart('﻿')));
        using var ms = new MemoryStream();
        using (var w = new Utf8JsonWriter(ms)) Write(w, s.Documents.Count == 0 ? null : s.Documents[0].RootNode);
        return Encoding.UTF8.GetString(ms.ToArray());
    }

    private static void Write(Utf8JsonWriter w, YamlNode? n)
    {
        switch (n)
        {
            case null: w.WriteNullValue(); break;
            case YamlMappingNode m:
                w.WriteStartObject();
                foreach (var (mk, mv) in m.Children.OrderBy(c => ((YamlScalarNode)c.Key).Value, StringComparer.Ordinal)) { w.WritePropertyName(((YamlScalarNode)mk).Value ?? ""); Write(w, mv); }
                w.WriteEndObject();
                break;
            case YamlSequenceNode q:
                w.WriteStartArray();
                foreach (var c in q.Children) Write(w, c);
                w.WriteEndArray();
                break;
            case YamlScalarNode s:
                var v = s.Value ?? "";
                if (IsText(s)) { w.WriteStringValue(v); break; }
                if (v.Length == 0 || IsNullWord(v)) w.WriteNullValue();
                else if (bool.TryParse(v, out var b)) w.WriteBooleanValue(b);
                else w.WriteStringValue("#" + decimal.Parse(v, NumberStyles.Float, CultureInfo.InvariantCulture).ToString(CultureInfo.InvariantCulture));
                break;
        }
    }

    /// A new rule's starting form.
    public static RuleFormModel New(string id, string engine) => new()
    {
        Id = id,
        Fields =
        {
            new RuleParam { Name = "appliesTo", Value = engine == "shared" ? "any" : engine },
            new RuleParam { Name = "purpose", Value = "" },
            new RuleParam { Name = "category", Value = "" },
        },
        Detections =
        {
            new RuleDetection
            {
                Id = id + "-1", Combine = "any", Tier = "2",
                Conditions = { new RuleCondition { Kind = "nameMatches", Params = { new RuleParam { Name = "namePatterns", List = true, Value = "" } } } },
                Set = { new RuleParam { Name = "Purpose", Value = "" } },
            },
        },
    };
}
