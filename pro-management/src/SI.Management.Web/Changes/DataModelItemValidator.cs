using System.Text.Json;
using System.Text.RegularExpressions;

namespace SI.Management.Web.Changes;

/// <summary>
/// #527 (4): the C# twin of Test-SIDataModelProItem + Test-SIRiskFactorItem (engine\pro-settings\SI-DataModelTemplateRows.ps1,
/// engine\data-model\SI-RiskFactorCatalog.ps1) for the 'datamodel' cfg.ItemOverride rows the Risk factors page writes:
/// a factor ('risk-factors:&lt;id&gt;') or a provider mapping ('mappings/&lt;provider&gt;:&lt;field|recordTypes|resourceTypes&gt;').
/// Pro manages the data model in SQL only -- the shipped JSON is published into cfg.Template, a customer change is an
/// override row, and the run exports the effective model and validates it again (Test-SIDataModel).
/// The factor rules (owner 2026-10-10): exactly one scope (asset | finding), never si_tier, SI fields only, no raw source
/// path in a condition -- a renamed source field is a MAPPING override, never a factor change.
/// </summary>
public static partial class DataModelItemValidator
{
    public const string Kind = "datamodel";
    public const int KeyMax = 128;

    [GeneratedRegex(@"^[a-z][a-z0-9\-]{0,40}(/[a-z0-9][a-z0-9_\-]{0,60})?(:[^\r\n]{1,126})?$", RegexOptions.CultureInvariant)]
    public static partial Regex KeyPattern();

    [GeneratedRegex(@"^si_[a-z0-9_]+$", RegexOptions.CultureInvariant)]
    private static partial Regex SiField();

    [GeneratedRegex(@"^[A-Za-z][A-Za-z0-9]{0,63}$", RegexOptions.CultureInvariant)]
    private static partial Regex ShortName();

    [GeneratedRegex(@"^(node|identity|ci|machine|deviceInfo|resource|derived|user|sp|app|registration|signIn|computer|device|host|exposure|roles|azureRoles|record|properties|rawData)(\[\*\])?(\.[A-Za-z0-9_$@-]+(\[\*\])?)+$", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex RawPath();

    /// The templates the GUI writes items of: the Risk factors page (factors, provider mappings, lists, the same
    /// recommendation across providers, a report's scope) and the Rule packs page (a pack's header). Every other template
    /// of the Pro data model (the field catalog, value maps, trust, ...) is not written from the GUI.
    public const string GuiTemplatesText = "risk-factors, mappings/<provider>, lists, recommendation-equivalence, report-scope, rules/<pack>, dimensions, classification";
    public static bool GuiWrites(string key)
    {
        var name = Split(key ?? "").Name;
        return name is "risk-factors" or "lists" or "recommendation-equivalence" or ReportFactorMatrix.Template
            or ClassificationItemValidator.DimensionsTemplate or ClassificationItemValidator.ClassificationTemplate   // #561 / #562 the classification wizard
            || name.StartsWith("mappings/", StringComparison.Ordinal) || name.StartsWith("rules/", StringComparison.Ordinal);
    }

    /// The template name of a key ('risk-factors', 'mappings/mde') and its item part ('' = the template's header).
    public static (string Name, string Item) Split(string key)
    {
        var i = key.IndexOf(':');
        return i < 0 ? (key, "") : (key[..i], key[(i + 1)..]);
    }

    /// The reasons a write is refused (empty = accepted). Sends nothing.
    public static IReadOnlyList<string> Validate(string key, string state, string? body)
    {
        if (string.IsNullOrEmpty(key) || key.Length > KeyMax || !KeyPattern().IsMatch(key)) return new[] { $"'{key}' is not a data-model key ('<template>' or '<template>:<item key>')" };
        if (!GuiWrites(key)) return new[] { $"'{key}' is not an item of a data-model template the GUI writes ({GuiTemplatesText})" };
        if (state is not (ItemOverrideRepository.StateOverride or ItemOverrideRepository.StateInherit or ItemOverrideRepository.StateDisable)) return new[] { $"'{state}' is not a state (override, disable, inherit)" };
        // #462: a rule pack's header is never switched off as an item (its rules would lose their template) -- a pack is
        // turned off by its header's 'enabled'
        var (hName, hItem) = Split(key);
        if (state == ItemOverrideRepository.StateDisable && hItem.Length == 0 && hName.StartsWith("rules/", StringComparison.Ordinal))
            return new[] { "a rule pack is turned off with its header's 'enabled': false, not by switching the header off" };
        if (state != ItemOverrideRepository.StateOverride) return Array.Empty<string>();
        var text = (body ?? "").TrimStart((char)0xFEFF);
        if (string.IsNullOrWhiteSpace(text)) return new[] { "the body is empty" };
        JsonDocument doc;
        try { doc = JsonDocument.Parse(text); }
        catch (JsonException ex) { return new[] { "the body is not valid JSON: " + ex.Message }; }
        using (doc)
        {
            var o = doc.RootElement;
            if (o.ValueKind != JsonValueKind.Object) return new[] { "a data-model item must be a JSON object" };
            var (name, item) = Split(key);
            if (name.StartsWith("rules/", StringComparison.Ordinal) && item.Length == 0) return RulePackHeader(o);
            if (item.Length == 0) return Array.Empty<string>();
            if (name == "risk-factors") return Factor(item, o);
            if (name == "recommendation-equivalence") return EquivalenceGroup(item, o);
            if (name.StartsWith("mappings/", StringComparison.Ordinal)) return Mapping(item, o);
            if (name == "lists") return List(item, o);
            if (name == ReportFactorMatrix.Template) return ReportFactorMatrix.Validate(item, o);   // #541 (6): one report's scope and factor exceptions
            if (name == ClassificationItemValidator.DimensionsTemplate) return ClassificationItemValidator.Dimension(item, o);         // #561 / #562 one dimension
            if (name == ClassificationItemValidator.ClassificationTemplate) return ClassificationItemValidator.Rule(item, o);        // #561 / #562 one classification row
            return Array.Empty<string>();
        }
    }

    /// #462 a CI rule pack's header (the twin of Get-SIRulePackHeader's input): kind 'ci-rule-pack', a stage the engine
    /// knows (production / live or testing), 'enabled' true or false, a whole-number priority, a known source.
    public static IReadOnlyList<string> RulePackHeader(JsonElement h)
    {
        var why = new List<string>();
        var kind = h.TryGetProperty("kind", out var k) && k.ValueKind == JsonValueKind.String ? k.GetString() : null;
        if (kind != "ci-rule-pack") why.Add("a rule pack's header has kind 'ci-rule-pack'");
        if (h.TryGetProperty("stage", out var s) && !(s.ValueKind == JsonValueKind.String && s.GetString() is "production" or "live" or "testing"))
            why.Add("a rule pack's stage is 'production' (live) or 'testing'");
        if (h.TryGetProperty("enabled", out var e) && e.ValueKind is not (JsonValueKind.True or JsonValueKind.False)) why.Add("'enabled' is true or false");
        if (h.TryGetProperty("priority", out var p) && !(p.ValueKind == JsonValueKind.Number && p.TryGetInt32(out _))) why.Add("'priority' is a whole number");
        if (h.TryGetProperty("source", out var src) && !(src.ValueKind == JsonValueKind.String && src.GetString() is "shipped" or "invardia" or "customer"))
            why.Add("'source' is shipped, invardia or customer");
        return why;
    }

    /// #464 one group of the recommendation equivalence (the twin of Test-SIRecommendationEquivalenceGroup): its id is the
    /// key, a canonical id and title, and two or more members from two or more providers, each naming an id or a title.
    public static IReadOnlyList<string> EquivalenceGroup(string item, JsonElement g)
    {
        var why = new List<string>();
        string Str(JsonElement o, string p) => o.ValueKind == JsonValueKind.Object && o.TryGetProperty(p, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";
        if (Str(g, "id") != item) why.Add($"id must be '{item}' -- the key names the group");
        if (Str(g, "stage") is { Length: > 0 } st0 && st0 is not ("production" or "testing" or "not_used")) why.Add("stage is production, testing or not_used");
        // #693 the match: key (default -- the same recommendation across providers) | link (an operator's link on one owner) |
        // fold (a meaning rule over generic SI fields). The full rule checks are the engine's (Test-SIRecommendationEquivalenceGroup).
        var match = Str(g, "match").Trim().ToLowerInvariant();
        if (match.Length == 0) match = "key";
        if (match is not ("key" or "link" or "fold")) { why.Add("match is key, link or fold"); return why; }
        if (match == "fold")
        {
            foreach (var side in new[] { "evidence", "canonical", "on" })
                if (!(g.TryGetProperty(side, out var a) && a.ValueKind == JsonValueKind.Array && a.GetArrayLength() > 0)) why.Add($"a fold rule needs at least one '{side}' entry");
            foreach (var side in new[] { "evidence", "canonical" })
                if (g.TryGetProperty(side, out var a) && a.ValueKind == JsonValueKind.Array)
                    foreach (var c in a.EnumerateArray())
                        if (!Str(c, "field").StartsWith("si_", StringComparison.Ordinal)) why.Add($"a {side} condition reads a generic SI field (si_...), never a provider column");
            return why;
        }
        if (match == "link")
        {
            if (Str(g, "owner").Trim().Length == 0) why.Add("owner is required -- the CI the findings are on");
            if (Str(g, "linkedBy").Trim().Length == 0 || Str(g, "reason").Trim().Length == 0) why.Add("a link records who made it (linkedBy) and why (reason)");
            var lm = g.TryGetProperty("members", out var lmm) && lmm.ValueKind == JsonValueKind.Array ? lmm.EnumerateArray().Select(x => Str(x, "id").Trim()).ToList() : new List<string>();
            if (lm.Count < 2 || lm.Any(x => x.Length == 0)) why.Add("at least two members, each naming its finding key (id)");
            if (!lm.Contains(Str(g, "canonicalId").Trim(), StringComparer.OrdinalIgnoreCase)) why.Add("canonicalId is one of the members -- the finding that stays");
            return why;
        }
        if (Str(g, "canonicalId").Trim().Length == 0) why.Add("canonicalId is required -- the finding key the group is known by");
        if (Str(g, "canonicalTitle").Trim().Length == 0) why.Add("canonicalTitle is required");
        var members = g.TryGetProperty("members", out var m) && m.ValueKind == JsonValueKind.Array ? m.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.Object).ToList() : new List<JsonElement>();
        if (members.Count < 2) why.Add("at least two members -- one recommendation from two or more providers");
        if (members.Any(x => Str(x, "provider").Length == 0)) why.Add("every member names its provider");
        if (members.Any(x => Str(x, "id").Trim().Length == 0 && Str(x, "title").Trim().Length == 0)) why.Add("every member names the provider's id or its exact title");
        if (members.Count >= 2 && members.Select(x => Str(x, "provider")).Distinct(StringComparer.Ordinal).Count() < 2) why.Add("the members come from one provider -- it needs two");
        return why;
    }

    /// A risk factor: its id is the key, one scope, and its condition reads SI fields only, never si_tier.
    public static IReadOnlyList<string> Factor(string item, JsonElement f)
    {
        var why = new List<string>();
        var id = f.TryGetProperty("id", out var i) && i.ValueKind == JsonValueKind.String ? i.GetString() : null;
        if (!string.Equals(id, item, StringComparison.Ordinal)) why.Add($"id must be '{item}' -- the key names the factor");
        var scope = f.TryGetProperty("appliesTo", out var s) && s.ValueKind == JsonValueKind.String ? s.GetString() : null;
        if (scope is not ("asset" or "finding")) why.Add("must have exactly one scope -- appliesTo 'asset' (the asset's exposure, hygiene, importance) or 'finding' (extra about the recommendation / vulnerability)");
        // the risk factor model (owner 2026-10-10): impact is a whole number 1 (very low) .. 5 (very high); class built-in |
        // optional; state enabled | disabled; a built-in factor is always on. Each read only when the body carries it, so
        // a catalog without the fields yet stays valid. (Against the SHIPPED class: RiskFactorModel.ShippedProblems.)
        if (f.TryGetProperty("impact", out var imp) && RiskFactorModel.ImpactOf(f) is null)
            why.Add($"impact '{imp.GetRawText()}' -- the impact is a whole number from {RiskFactorModel.ImpactMin} (very low) to {RiskFactorModel.ImpactMax} (very high)");
        var cls = f.TryGetProperty("class", out var cl) ? (cl.ValueKind == JsonValueKind.String ? cl.GetString() : cl.GetRawText()) : null;
        if (cls is not null && cls is not (RiskFactorModel.Builtin or RiskFactorModel.Optional)) why.Add($"class '{cls}' -- a factor is 'builtin' or 'optional'");
        var fstate = f.TryGetProperty("state", out var fs) ? (fs.ValueKind == JsonValueKind.String ? fs.GetString() : fs.GetRawText()) : null;
        if (fstate is not null && fstate is not (RiskFactorModel.Enabled or RiskFactorModel.Disabled)) why.Add($"state '{fstate}' -- a factor is 'enabled' or 'disabled'");
        if (cls == RiskFactorModel.Builtin && fstate == RiskFactorModel.Disabled) why.Add("a built-in factor is always on -- it cannot be disabled (change its impact instead)");
        if (f.TryGetProperty("shortName", out var sn) && !(sn.ValueKind == JsonValueKind.String && ShortName().IsMatch(sn.GetString() ?? "")))
            why.Add("shortName is one word of letters and digits (the report / Excel / PDF name, e.g. EnabledNoSignInStale)");
        // the criteria block the wizard edits (#541 (7)): kind, SI field, source, list / threshold range
        why.AddRange(FactorCriteria.Problems(f));
        var by = f.TryGetProperty("evaluatedBy", out var e) && e.ValueKind == JsonValueKind.String ? e.GetString() : null;
        if (by == "report") return why;
        if (f.TryGetProperty("when", out var w)) Walk(w, why);
        return why;
    }

    private static void Walk(JsonElement c, List<string> why)
    {
        if (c.ValueKind != JsonValueKind.Object) return;
        foreach (var g in new[] { "all", "any" })
        {
            if (c.TryGetProperty(g, out var arr) && arr.ValueKind == JsonValueKind.Array)
            {
                foreach (var x in arr.EnumerateArray()) Walk(x, why);
                return;
            }
        }
        var field = c.TryGetProperty("field", out var fl) && fl.ValueKind == JsonValueKind.String ? fl.GetString() ?? "" : "";
        if (field == "si_tier") why.Add("reads si_tier -- a risk factor never restates tier (tier counts through the risk index and the tier multiplier)");
        else if (!SiField().IsMatch(field)) why.Add($"reads '{field}' -- a factor reads SI fields (si_*) only; a source field belongs in its provider mapping");
        if (c.TryGetProperty("value", out var v))
        {
            var vals = v.ValueKind == JsonValueKind.Array ? v.EnumerateArray().ToList() : new List<JsonElement> { v };
            foreach (var x in vals)
                if (x.ValueKind == JsonValueKind.String && RawPath().IsMatch(x.GetString() ?? "")) why.Add($"value '{x.GetString()}' is a raw source path -- it belongs in a provider mapping");
        }
    }

    /// A provider mapping: an SI field filled from one or more source paths -- the ONE place a raw source path lives.
    public static IReadOnlyList<string> Mapping(string item, JsonElement m)
    {
        var why = new List<string>();
        var field = m.TryGetProperty("field", out var f) && f.ValueKind == JsonValueKind.String ? f.GetString() ?? "" : "";
        if (field.Length == 0) why.Add("a mapping names the SI field it fills ('field')");
        else if (!item.StartsWith(field + "|", StringComparison.Ordinal) && !item.StartsWith(field + "~", StringComparison.Ordinal) && item != field)
            why.Add($"the key must start with '{field}|' -- the key names the mapped field");
        if (!(m.TryGetProperty("sources", out var src) && src.ValueKind == JsonValueKind.Array && src.GetArrayLength() > 0 && src.EnumerateArray().All(x => x.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(x.GetString()))))
            why.Add("a mapping lists its source paths ('sources': one or more)");
        return why;
    }

    /// A value that is a raw source path (belongs in a provider mapping, never in a factor, list or dimension rule).
    internal static bool IsRawPath(string s) => RawPath().IsMatch(s);

    internal static readonly string[] Ops = { "eq", "ne", "in", "not_in", "is_true", "is_false", "is_empty", "not_empty", "gt", "gte", "lt", "lte", "like", "contains", "contains_any", "matches", "older_than_days", "newer_than_days", "in_ranges", "in_list" };

    /// A list (what the wizard's list criteria change): its id is the key; a conditions list holds named entries whose
    /// conditions read SI fields with a known operation and plain values (a 'matches' pattern must compile); a values list
    /// plain values; a ranges list addresses / CIDRs. Nothing that could make a failing query.
    public static IReadOnlyList<string> List(string item, JsonElement l)
    {
        var why = new List<string>();
        var id = l.TryGetProperty("id", out var i) && i.ValueKind == JsonValueKind.String ? i.GetString() : null;
        if (!string.Equals(id, item, StringComparison.Ordinal)) why.Add($"id must be '{item}' -- the key names the list");
        var type = l.TryGetProperty("type", out var t) && t.ValueKind == JsonValueKind.String ? t.GetString() : null;
        switch (type)
        {
            case "conditions":
                if (!(l.TryGetProperty("entries", out var es) && es.ValueKind == JsonValueKind.Array)) { why.Add("a conditions list has 'entries'"); break; }
                if (es.GetArrayLength() > FactorCriteria.MaxEntries) why.Add($"at most {FactorCriteria.MaxEntries} entries");
                foreach (var e in es.EnumerateArray())
                {
                    var name = e.TryGetProperty("name", out var n) && n.ValueKind == JsonValueKind.String ? n.GetString() ?? "" : "";
                    if (name.Length is 0 or > 300 || name.Any(char.IsControl)) why.Add("every entry has a plain name (1-300 characters)");
                    if (!e.TryGetProperty("when", out var w)) { why.Add($"entry '{name}' has no condition"); continue; }
                    foreach (var leaf in FactorCriteria.Leaves(w))
                    {
                        if (!SiField().IsMatch(leaf.Field) || leaf.Field == "si_tier") why.Add($"entry '{name}' reads '{leaf.Field}' -- SI fields only, never si_tier");
                        if (!Ops.Contains(leaf.Op, StringComparer.Ordinal)) why.Add($"entry '{name}': '{leaf.Op}' is not an operation");
                        foreach (var v in leaf.Value.ValueKind == JsonValueKind.Array ? leaf.Value.EnumerateArray().ToList() : new List<JsonElement> { leaf.Value })
                        {
                            if (v.ValueKind != JsonValueKind.String) continue;
                            var s = v.GetString() ?? "";
                            if (s.Length > FactorCriteria.MaxValueLength || s.Any(char.IsControl)) why.Add($"entry '{name}': a value is too long or not plain text");
                            else if (RawPath().IsMatch(s)) why.Add($"entry '{name}': value '{s}' is a raw source path");
                            if (leaf.Op == "matches") { try { _ = new Regex(s, RegexOptions.None, TimeSpan.FromSeconds(1)); } catch (ArgumentException) { why.Add($"entry '{name}': '{s}' is not a valid pattern"); } }
                        }
                    }
                }
                break;
            case "values":
            case "ranges":
                if (!(l.TryGetProperty("values", out var vs) && vs.ValueKind == JsonValueKind.Array)) { why.Add($"a {type} list has 'values'"); break; }
                foreach (var v in vs.EnumerateArray())
                {
                    var s = v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : v.ValueKind == JsonValueKind.Number ? v.GetRawText() : null;
                    // the break glass extension attribute: every value is an attribute=value entry held to the engine's
                    // rule (ConvertTo-SIBreakGlassAttributeRule) -- its own length (a directory extension name plus a value
                    // of up to 256 characters), so the plain-value length below does not apply
                    if (item == BreakGlassAttribute.ListId)
                    {
                        if (type != "values") break;
                        if (BreakGlassAttribute.Problem(s) is { } notAnEntry) why.Add(notAnEntry);
                        continue;
                    }
                    if (s is null || s.Length > FactorCriteria.MaxValueLength || s.Any(char.IsControl)) { why.Add("every value is a plain string or number"); continue; }
                    if (type == "ranges" && !IsRange(s)) why.Add($"'{s}' is not an address or CIDR range");
                    else if (item == BreakGlassPatterns.ListId && BreakGlassPatterns.Problem(s) is { } bad) why.Add(bad);
                }
                break;
            default:
                why.Add("type must be conditions, values or ranges");
                break;
        }
        // the break glass extension attribute: a values list (Test-SIBreakGlassAttributeList), a bounded number of entries
        if (item == BreakGlassAttribute.ListId)
        {
            if (type != "values") why.Add("the break glass attribute list is a values list of attribute=value entries");
            else if (l.TryGetProperty("values", out var bg) && bg.ValueKind == JsonValueKind.Array && bg.GetArrayLength() > BreakGlassAttribute.MaxEntries) why.Add($"at most {BreakGlassAttribute.MaxEntries} entries");
        }
        // the risk rating bands: three whole NUMBERS above 0, highest first (Test-SIRiskRatingBands)
        if (item == SI.Management.Core.ProData.RiskRatingBands.ListId) why.AddRange(SI.Management.Core.ProData.RiskRatingBands.Problems(l));
        return why;
    }

    private static bool IsRange(string s)
    {
        var parts = s.Split('/');
        if (parts.Length > 2 || !System.Net.IPAddress.TryParse(parts[0], out var a)) return false;
        if (parts.Length == 1) return true;
        var max = a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? 128 : 32;
        return int.TryParse(parts[1], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var bits) && bits >= 0 && bits <= max;
    }}
