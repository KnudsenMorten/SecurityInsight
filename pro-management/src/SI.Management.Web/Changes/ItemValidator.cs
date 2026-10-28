using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;
using YamlDotNet.Core;
using YamlDotNet.Core.Events;
using YamlDotNet.Serialization;

namespace SI.Management.Web.Changes;

/// <summary>
/// The C# twin of Test-SIProItem (engine\pro-settings\SI-ProConfig.ps1) for the item kinds the profiling and tagging
/// editors write: 'rule' (a tier / detection rule, YAML -- Test-SIRuleText), 'assettagging' (an MDE tag rule or the
/// AutoExclude gates, JSON) and 'schemaoverlay' (a profile-table overlay per engine, JSON). The run-start reader
/// (Merge-SIProItems) validates every override AGAIN and STOPS the run on a refused one, so the GUI must never write what
/// it would refuse. Where the PowerShell rule compares without case (-match, -eq, -notcontains, hashtable keys) this does
/// too; where the two YAML / JSON readers differ, this one refuses (conservative) -- never the other way round.
/// Both test suites read tests/fixtures/item-validation-cases.json (ItemValidatorTests, SIv3-ProfilingEditors.Tests.ps1).
/// </summary>
public static partial class ItemValidator
{
    public const string Rule = "rule";
    public const string AssetTagging = "assettagging";
    public const string SchemaOverlay = "schemaoverlay";

    /// The kinds and their key patterns, exactly as $script:SIProItemKinds (PowerShell's -match ignores case).
    public static readonly IReadOnlyDictionary<string, (string Format, Regex Key)> Kinds = new Dictionary<string, (string, Regex)>(StringComparer.Ordinal)
    {
        [Rule] = ("yaml", new Regex(@"^(endpoint|identity|azure|shared)/[A-Za-z0-9][A-Za-z0-9_\-]{0,99}$", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)),
        [AssetTagging] = ("json", new Regex(@"^(config|tag/[^\r\n/\\]{1,120})$", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)),
        [SchemaOverlay] = ("json", new Regex(@"^(endpoint|identity|azure|publicip)$", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)),
    };

    /// Get-SIProAssetTagStemKey / the engine's Get-AssetTagStemKey: '&lt;stem&gt;--tier&lt;N&gt;--SI' and '&lt;stem&gt;--excluded--SI'
    /// share the key '&lt;STEM&gt;--SI'. Null when the name does not follow the convention.
    [GeneratedRegex(@"^(?<stem>.+?)--(?:tier(?<tier>\d+)|excluded)--SI$", RegexOptions.IgnoreCase)] private static partial Regex TagName();

    public static string? StemKey(string? name)
    {
        if (string.IsNullOrWhiteSpace(name)) return null;
        var m = TagName().Match(name.Trim());
        return m.Success ? (m.Groups["stem"].Value + "--SI").ToUpperInvariant() : null;
    }

    /// The tier a tag name sets ('--tier&lt;N&gt;--SI'), or null ('--excluded--SI' / not the convention).
    public static int? TagTier(string? name)
    {
        if (string.IsNullOrWhiteSpace(name)) return null;
        var m = TagName().Match(name.Trim());
        return m.Success && m.Groups["tier"].Success && int.TryParse(m.Groups["tier"].Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var t) ? t : null;
    }

    /// The reasons an item body is not accepted (empty = accepted). ruleKinds: the detection kinds the engine registers
    /// (<see cref="DocumentValidator.RuleKinds"/>).
    public static IReadOnlyList<string> Validate(string kind, string key, string? body, string? format = null, IReadOnlyCollection<string>? ruleKinds = null)
    {
        var why = new List<string>();
        if (!Kinds.TryGetValue(kind ?? "", out var spec)) { why.Add($"'{kind}' is not a configuration kind this editor writes ({string.Join(", ", Kinds.Keys)})"); return why; }
        if (string.IsNullOrEmpty(key) || !spec.Key.IsMatch(key)) { why.Add($"'{key}' is not a valid {kind} key"); return why; }
        format = string.IsNullOrEmpty(format) ? spec.Format : format;
        if (format != spec.Format) { why.Add($"a {kind} item is {spec.Format}, not {format}"); return why; }
        if (string.IsNullOrWhiteSpace(body)) { why.Add("the body is empty"); return why; }
        JsonElement? o = null;
        if (format == "json")
        {
            try
            {
                using var doc = JsonDocument.Parse(body);
                var dup = DuplicateKey(doc.RootElement);
                if (dup is not null) { why.Add($"the body is not valid JSON: the name '{dup}' appears twice in one object (names are compared without case)"); return why; }
                o = doc.RootElement.Clone();
            }
            catch (JsonException ex) { why.Add("the body is not valid JSON: " + ex.Message); return why; }
        }
        var isObj = o is { ValueKind: JsonValueKind.Object };
        switch (kind)
        {
            case Rule:
                why.AddRange(RuleTextProblems(body.TrimStart('﻿'), key[(key.IndexOf('/') + 1)..], ruleKinds ?? DocumentValidator.RuleKinds));
                break;
            case AssetTagging:
            {
                if (!isObj) { why.Add("an asset-tagging item must be a JSON object"); break; }
                if (string.Equals(key, "config", StringComparison.OrdinalIgnoreCase)) break;   // the gates the rules name, free-form
                var name = Prop(o!.Value, "AssetTagName") is { } n ? AsText(n) : "";
                var stem = StemKey(name);
                if (stem is null) { why.Add("AssetTagName must be '<stem>--tier<N>--SI' or '<stem>--excluded--SI'"); break; }
                if (!string.Equals("tag/" + stem, key, StringComparison.Ordinal)) why.Add($"the key must be 'tag/{stem}' -- it is the tag's merge key");
                break;
            }
            case SchemaOverlay:
            {
                if (!isObj) { why.Add("a schema overlay must be a JSON object"); break; }
                if (Prop(o!.Value, "fields") is { } f && f.ValueKind is not (JsonValueKind.Array or JsonValueKind.Null)) why.Add("fields must be a list");
                break;
            }
        }
        return why;
    }

    /// A property by name without case (PowerShell's PSObject.Properties[...]).
    public static JsonElement? Prop(JsonElement o, string name)
    {
        if (o.ValueKind != JsonValueKind.Object) return null;
        foreach (var p in o.EnumerateObject()) if (string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase)) return p.Value;
        return null;
    }

    /// [string] of a JSON value as PowerShell writes it.
    private static string AsText(JsonElement v) => v.ValueKind switch
    {
        JsonValueKind.String => v.GetString() ?? "",
        JsonValueKind.Null => "",
        JsonValueKind.True => "True",
        JsonValueKind.False => "False",
        _ => v.GetRawText(),
    };

    /// PowerShell's ConvertFrom-Json refuses two names that differ only in case in one object.
    private static string? DuplicateKey(JsonElement e)
    {
        if (e.ValueKind == JsonValueKind.Object)
        {
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var p in e.EnumerateObject())
            {
                if (!seen.Add(p.Name)) return p.Name;
                if (DuplicateKey(p.Value) is { } d) return d;
            }
        }
        else if (e.ValueKind == JsonValueKind.Array)
            foreach (var x in e.EnumerateArray()) if (DuplicateKey(x) is { } d) return d;
        return null;
    }

    // ------------------------------------------------------------------ rules: Test-SIRuleText

    /// <summary>
    /// Test-SIRuleText (engine\pro-settings\SI-Settings.ps1): the text parses, carries the expected id, and uses only known
    /// kinds and tiers 0-3 (a 'mode: disable' rule needs nothing else). Map keys and the comparisons ignore case, as the
    /// PowerShell hashtable and -eq / -notin / -notcontains do. YAML that SecurityInsight's own reader (SI-Yaml.ps1)
    /// refuses -- anchors, aliases, tags, flow mappings, several documents, keys that differ only in case -- is refused here.
    /// </summary>
    public static IReadOnlyList<string> RuleTextProblems(string text, string id, IReadOnlyCollection<string> kinds)
    {
        var why = new List<string>();
        var unsupported = UnsupportedYaml(text);
        if (unsupported is not null) { why.Add("the rule is not valid YAML: " + unsupported); return why; }
        object? o;
        try { o = new DeserializerBuilder().Build().Deserialize<object>(text); }
        catch (Exception ex) when (ex is YamlException or InvalidOperationException) { why.Add("the rule is not valid YAML: " + ex.Message); return why; }
        if (o is not IDictionary<object, object> map) { why.Add("the rule must be a YAML mapping"); return why; }
        if (!string.Equals(S(map, "id") ?? "", id, StringComparison.OrdinalIgnoreCase)) why.Add($"the id must stay '{id}' -- it is what replaces the shipped rule");
        if (string.Equals(S(map, "mode"), "disable", StringComparison.OrdinalIgnoreCase)) return why;
        var applies = Get(map, "appliesTo") switch
        {
            null => Array.Empty<string>(),
            IEnumerable<object> l when Get(map, "appliesTo") is not string => l.Select(x => x?.ToString() ?? ""),
            var x => new[] { x.ToString() ?? "" },
        };
        foreach (var a in applies.SelectMany(x => Regex.Split(x, @"[,;]\s*")).Where(x => x.Length > 0))
            if (!new[] { "endpoint", "identity", "azure", "publicip", "any" }.Contains(a.ToLowerInvariant(), StringComparer.OrdinalIgnoreCase)) why.Add($"appliesTo '{a}' is not an engine");
        var dets = Get(map, "detections") switch { IList<object> l => l, null => null, var x => new List<object> { x } };
        if (dets is null || dets.Count == 0 || dets[0] is null) { why.Add("a rule needs at least one detection"); return why; }
        foreach (var d in dets)
        {
            var dm = d as IDictionary<object, object>;
            var did = dm is null ? "" : S(dm, "id") ?? "";
            var detect = dm is null ? null : Get(dm, "detect") as IDictionary<object, object>;
            var list = detect is null ? null : (Truthy(Get(detect, "any")) ? AsList(Get(detect, "any")) : Truthy(Get(detect, "all")) ? AsList(Get(detect, "all")) : null);
            if (list is null || list.Count == 0) { why.Add($"detection '{did}': detect needs an 'any' or 'all' list"); }
            foreach (var k in list ?? new List<object?>())
            {
                var kind = k is IDictionary<object, object> km ? S(km, "kind") ?? "" : "";
                if (!kinds.Contains(kind, StringComparer.OrdinalIgnoreCase)) why.Add($"detection '{did}': '{kind}' is not a detection kind the engine knows");
            }
            if (dm is not null && Get(dm, "set") is IDictionary<object, object> sm && Get(sm, "Tier") is { } t)
                if (t is not string ts || !int.TryParse(ts, NumberStyles.Integer, CultureInfo.InvariantCulture, out var n) || n < 0 || n > 3)
                    why.Add($"detection '{did}': Tier must be 0, 1, 2 or 3");
        }
        return why;
    }

    private static bool Truthy(object? v) => v switch { null => false, string s => s.Length > 0, IList<object> l => l.Count > 0, IDictionary<object, object> => true, _ => true };
    private static IList<object?> AsList(object? v) => v switch { IList<object> l => l.Cast<object?>().ToList(), null => new List<object?>(), var x => new List<object?> { x } };

    /// A map value by key without case (the PowerShell hashtable).
    public static object? Get(IDictionary<object, object> m, string key)
    {
        foreach (var kv in m) if (string.Equals(kv.Key?.ToString(), key, StringComparison.OrdinalIgnoreCase)) return kv.Value;
        return null;
    }

    private static string? S(IDictionary<object, object> m, string key) => Get(m, key) switch { null => null, string s => s, var x => x.ToString() };

    /// What SecurityInsight's own YAML reader refuses (SI-Yaml.ps1) and YamlDotNet would accept.
    public static string? UnsupportedYaml(string text)
    {
        try
        {
            var parser = new Parser(new StringReader(text));
            var docs = 0;
            // per open collection: its keys so far (null = a sequence) and whether the next node is a key
            var stack = new Stack<(HashSet<string>? Keys, bool[] ExpectKey)>();
            void ValueSeen() { if (stack.Count > 0 && stack.Peek().Keys is not null) stack.Peek().ExpectKey[0] = !stack.Peek().ExpectKey[0]; }
            while (parser.MoveNext())
            {
                switch (parser.Current)
                {
                    case DocumentStart: if (++docs > 1) return "more than one document"; break;
                    case AnchorAlias: return "an alias (*name)";
                    case MappingStart ms when ms.Style == MappingStyle.Flow: return "a flow mapping ({ ... })";
                    case NodeEvent ne when !ne.Anchor.IsEmpty: return "an anchor (&name)";
                    case NodeEvent ne when !ne.Tag.IsEmpty && !ne.Tag.IsNonSpecific: return "a tag (!name)";
                    case Scalar sc:
                        if (stack.Count > 0 && stack.Peek() is { Keys: { } keys, ExpectKey: var ek } && ek[0])
                        {
                            if (sc.Style is ScalarStyle.SingleQuoted or ScalarStyle.DoubleQuoted) return "a quoted key";
                            if (!keys.Add(sc.Value)) return $"the key '{sc.Value}' appears twice";
                        }
                        ValueSeen();
                        break;
                    case MappingStart:
                        ValueSeen();
                        stack.Push((new HashSet<string>(StringComparer.Ordinal), new[] { true }));
                        break;
                    case SequenceStart:
                        ValueSeen();
                        stack.Push((null, new[] { false }));
                        break;
                    case MappingEnd or SequenceEnd:
                        if (stack.Count > 0) stack.Pop();
                        break;
                }
            }
        }
        catch (YamlException ex) { return ex.Message; }
        if (text.Split('\n').Any(l => l.TrimEnd('\r').Length > 0 && l.TrimStart(' ').StartsWith('\t'))) return "a line indented with a tab";
        return null;
    }
}
