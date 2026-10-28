using System.Text.Json;
using System.Text.Json.Nodes;
using SI.Management.Web.Data;

namespace SI.Management.Web.Changes;

/// One rule of a pack as the Rule packs page shows it: what it sets, its own stage and priority.
public sealed record RulePackRule(string Id, string Name, string Stage, int? Priority, string Sets, IReadOnlyList<string> AppliesTo);

/// <summary>
/// One CI rule pack: its header in force (the customer's override when there is one, else the shipped header) and its
/// rules. Stage 'production' is shown as live. An Invardia pack arrives switched off and, once staged, as testing.
/// </summary>
public sealed record RulePackView(string Key, string Pack, string Name, string Description, string Stage, bool Enabled, int Priority, string Source,
    bool Overridden, string? HeaderBody, IReadOnlyList<RulePackRule> Rules)
{
    public bool Live => Enabled && Stage == "production";
    public bool Testing => Enabled && Stage == "testing";
    /// "live" | "testing" | "off".
    public string StateText => !Enabled ? "off" : Stage == "production" ? "live" : "testing";
    public bool FromInvardia => Source == "invardia";
    /// The lowest / highest rule priority (a rule without one takes the pack's).
    public string PriorityText
    {
        get
        {
            var ps = Rules.Select(r => r.Priority ?? Priority).Distinct().OrderBy(p => p).ToList();
            return ps.Count switch { 0 => Priority.ToString(System.Globalization.CultureInfo.InvariantCulture), 1 => ps[0].ToString(System.Globalization.CultureInfo.InvariantCulture), _ => $"{ps[0]}-{ps[^1]}" };
        }
    }
}

/// What a rule (of a testing pack) WOULD set on one CI: the CI's si_rule_proposals entry.
public sealed record RuleProposal(string CiId, string? CiName, string Rule, string Field, string? Current, string? Proposed, string? Reason);

/// <summary>
/// #462 the Rule packs page's reads: the CI rule packs of the Pro data model IN SQL -- the 'datamodel' cfg.Template rows
/// 'rules/&lt;pack&gt;' (the header) and 'rules/&lt;pack&gt;:&lt;rule id&gt;' (one per rule), published from data-model/rules by
/// the release (engine\pro-settings\SI-DataModelTemplateRows.ps1), with the customer's cfg.ItemOverride rows. A pack is
/// turned on / off, staged or promoted by overriding its HEADER (ChangeService.NewDataModelItemAsync -> Review &amp; commit);
/// nothing here writes. And what a testing pack WOULD set: the CIs' si_rule_proposals (sidata.Ci.DocJson).
/// </summary>
public sealed class RulePackStore
{
    public const string MissingSchemaMessage = "This database has no rule packs yet (cfg.Template / cfg.ItemOverride with the data-model rows) -- they arrive with the next update of the Pro settings schema and templates.";
    /// The most CIs read for proposals, and the most proposals shown per pack.
    public const int MaxCis = 2000, MaxProposals = 500;

    public const string ListSql = """
IF OBJECT_ID(N'cfg.Template') IS NOT NULL AND OBJECT_ID(N'cfg.ItemOverride') IS NOT NULL
SELECT x.ItemKey, x.TemplateBody, x.TemplateVersion, x.State, x.OverrideBody FROM (
    SELECT t.ItemKey, t.BodyJson AS TemplateBody, t.[Version] AS TemplateVersion, o.State, o.BodyJson AS OverrideBody, t.SortOrder AS Ord
    FROM cfg.Template t
    LEFT JOIN cfg.ItemOverride o ON o.Kind = t.Kind AND o.ItemKey = t.ItemKey
    WHERE t.Kind = N'datamodel' AND t.RetiredAt IS NULL AND t.ItemKey LIKE N'rules/%'
    UNION ALL
    SELECT o.ItemKey, NULL, NULL, o.State, o.BodyJson, 2147483647
    FROM cfg.ItemOverride o
    WHERE o.Kind = N'datamodel' AND o.ItemKey LIKE N'rules/%'
      AND NOT EXISTS (SELECT 1 FROM cfg.Template t WHERE t.Kind = o.Kind AND t.ItemKey = o.ItemKey AND t.RetiredAt IS NULL)
) x
ORDER BY x.Ord, x.ItemKey;
""";

    /// The CIs that carry proposals (a testing rule's would-set), newest build.
    public const string ProposalsSql = """
IF OBJECT_ID(N'sidata.Ci') IS NOT NULL
SELECT TOP (@Max) c.CiId, c.Name, c.DocJson FROM sidata.Ci AS c
WHERE c.DocJson LIKE N'%si_rule_proposals%'
ORDER BY c.CiId;
""";

    private readonly ISqlExecutor _sql;
    public RulePackStore(ISqlExecutor sql) => _sql = sql;

    /// Every pack row; null when the schema is not there yet.
    public async Task<IReadOnlyList<DataModelRow>?> RowsAsync(CancellationToken ct)
    {
        var rows = await _sql.QueryAsync(ListSql, new Dictionary<string, object?>(), ct);
        if (rows.Count == 0) return null;
        return rows.Select(r => new DataModelRow(r.Str("ItemKey") ?? "", r.Str("TemplateBody"), r.Str("TemplateVersion"), r.Str("State"), r.Str("OverrideBody"))).ToList();
    }

    private static string S(JsonElement o, string p) => o.ValueKind == JsonValueKind.Object && o.TryGetProperty(p, out var v) ? v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : v.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined ? "" : v.ToString() : "";

    /// PURE. The packs of a row list: one per header row ('rules/&lt;pack&gt;'), its rules from the item rows in force.
    public static IReadOnlyList<RulePackView> Packs(IEnumerable<DataModelRow> rows)
    {
        var list = rows.ToList();
        var packs = new List<RulePackView>();
        foreach (var h in list.Where(r => r.Template.StartsWith("rules/", StringComparison.Ordinal) && r.Item.Length == 0))
        {
            var body = h.Overridden ? h.OverrideBody : h.TemplateBody ?? h.OverrideBody;
            var head = Header(h.Template, body);
            var rules = list.Where(r => r.Template == h.Template && r.Item.Length > 0 && r.Effective is not null).Select(r => Rule(r.Item, r.Effective!)).ToList();
            packs.Add(head with { Overridden = h.Overridden, HeaderBody = body, Rules = rules });
        }
        return packs;
    }

    /// PURE. A header body -> the pack's header (the same defaults as Get-SIRulePackHeader: an Invardia pack is off and testing
    /// until an Admin stages it; an unknown stage never decides).
    public static RulePackView Header(string key, string? body)
    {
        string pack = key["rules/".Length..], name = pack, desc = "", stage = "", source = "shipped"; bool? enabled = null; var prio = 100;
        try
        {
            using var d = JsonDocument.Parse(string.IsNullOrWhiteSpace(body) ? "{}" : body);
            var o = d.RootElement;
            if (S(o, "pack") is { Length: > 0 } p) pack = p;
            name = S(o, "name") is { Length: > 0 } n ? n : pack;
            desc = S(o, "description"); stage = S(o, "stage").Trim().ToLowerInvariant();
            if (S(o, "source") is { Length: > 0 } src) source = src.Trim().ToLowerInvariant();
            if (o.ValueKind == JsonValueKind.Object && o.TryGetProperty("enabled", out var en)) enabled = en.ValueKind switch { JsonValueKind.True => true, JsonValueKind.False => false, JsonValueKind.String => en.GetString() is "true" or "True" or "1", _ => null };
            if (int.TryParse(S(o, "priority"), System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out var pr)) prio = pr;
        }
        catch (JsonException) { }
        if (source is not ("shipped" or "invardia" or "customer")) source = "shipped";
        if (stage == "live") stage = "production";
        if (stage.Length == 0) stage = source == "invardia" ? "testing" : "production";
        if (stage is not ("production" or "testing")) stage = "testing";
        enabled ??= source != "invardia";
        return new RulePackView(key, pack, name, desc, stage, enabled.Value, prio, source, false, body, Array.Empty<RulePackRule>());
    }

    /// PURE. One rule body -> its id, name, stage, priority and what it sets ("si_tier = 0; si_tags = AD-Tier0").
    public static RulePackRule Rule(string item, string body)
    {
        try
        {
            using var d = JsonDocument.Parse(body);
            var o = d.RootElement;
            var sets = new List<string>();
            if (o.TryGetProperty("set", out var set) && set.ValueKind == JsonValueKind.Object)
                foreach (var p in set.EnumerateObject())
                    sets.Add(p.Name + " = " + (p.Value.ValueKind == JsonValueKind.Array ? string.Join(", ", p.Value.EnumerateArray().Select(x => x.ValueKind == JsonValueKind.String ? x.GetString() : x.ToString())) : p.Value.ValueKind == JsonValueKind.String ? p.Value.GetString() : p.Value.ToString()));
            int? prio = int.TryParse(S(o, "priority"), System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out var pr) ? pr : null;
            var classes = o.TryGetProperty("applies_to", out var at) && at.ValueKind == JsonValueKind.Array ? at.EnumerateArray().Select(x => x.ToString()).ToList() : new List<string>();
            var stage = S(o, "stage"); if (stage.Length == 0) stage = "production";
            return new RulePackRule(S(o, "id") is { Length: > 0 } id ? id : item, S(o, "name"), stage, prio, string.Join("; ", sets), classes);
        }
        catch (JsonException) { return new RulePackRule(item, "", "", null, "", Array.Empty<string>()); }
    }

    /// PURE. The header body an Admin stages: the header in force with stage / enabled changed (every other key kept, the
    /// rules array left null as the header row carries it). stage: "production" | "testing" | null = unchanged.
    public static string HeaderWith(RulePackView pack, string? stage, bool? enabled)
    {
        JsonObject o;
        try { o = (JsonNode.Parse(string.IsNullOrWhiteSpace(pack.HeaderBody) ? "{}" : pack.HeaderBody) as JsonObject) ?? new JsonObject(); }
        catch (JsonException) { o = new JsonObject(); }
        o["kind"] = "ci-rule-pack";
        o["pack"] ??= pack.Pack;
        if (stage is not null) o["stage"] = stage;
        if (enabled is not null) o["enabled"] = enabled.Value;
        if (!o.ContainsKey("rules")) o["rules"] = null;
        return o.ToJsonString();
    }

    /// The proposals of the given rules (a pack's) on the CIs, at most MaxProposals.
    public async Task<IReadOnlyList<RuleProposal>> ProposalsAsync(IReadOnlyCollection<string> ruleIds, CancellationToken ct)
    {
        if (ruleIds.Count == 0) return Array.Empty<RuleProposal>();
        var rows = await _sql.QueryAsync(ProposalsSql, new Dictionary<string, object?> { ["Max"] = MaxCis }, ct);
        var ids = new HashSet<string>(ruleIds, StringComparer.OrdinalIgnoreCase);
        var list = new List<RuleProposal>();
        foreach (var r in rows)
        {
            foreach (var p in Proposals(r.Str("CiId") ?? "", r.Str("Name"), r.Str("DocJson"))) if (ids.Contains(p.Rule)) list.Add(p);
            if (list.Count >= MaxProposals) break;
        }
        return list.Take(MaxProposals).ToList();
    }

    /// PURE. A CI document's si_rule_proposals (a list, or the JSON text the sync kept).
    public static IEnumerable<RuleProposal> Proposals(string ciId, string? ciName, string? docJson)
    {
        if (string.IsNullOrWhiteSpace(docJson)) yield break;
        JsonElement arr;
        try
        {
            using var d = JsonDocument.Parse(docJson);
            if (d.RootElement.ValueKind != JsonValueKind.Object || !d.RootElement.TryGetProperty("si_rule_proposals", out var v)) yield break;
            if (v.ValueKind == JsonValueKind.String && v.GetString() is { } s && s.TrimStart().StartsWith('['))
            {
                using var inner = JsonDocument.Parse(s);
                arr = inner.RootElement.Clone();
            }
            else arr = v.Clone();
        }
        catch (JsonException) { yield break; }
        if (arr.ValueKind == JsonValueKind.Object) { yield return One(ciId, ciName, arr); yield break; }
        if (arr.ValueKind != JsonValueKind.Array) yield break;
        foreach (var p in arr.EnumerateArray()) if (p.ValueKind == JsonValueKind.Object) yield return One(ciId, ciName, p);
    }

    private static RuleProposal One(string ciId, string? ciName, JsonElement p) =>
        new(ciId, ciName, S(p, "rule"), S(p, "field"), S(p, "current") is { Length: > 0 } c ? c : null, S(p, "proposed") is { Length: > 0 } pr ? pr : null, S(p, "reason") is { Length: > 0 } re ? re : null);
}
