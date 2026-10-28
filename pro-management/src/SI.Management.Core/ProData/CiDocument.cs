using System.Globalization;
using System.Text.Json;

namespace SI.Management.Core.ProData;

// =====================================================================================================================
// THE CI DOCUMENT (sidata.Ci.DocJson / sidata.CiRecord.DocJson, written by the data sync from SI_CI_CL / SI_Record_CL):
// every resolved si_* field plus the traces the CI page explains -- how the tier was decided (si_tier_claims), where each
// field came from (si_field_sources), how the CMDB criticality became a factor (si_criticality_source), the risk factors
// (si_risk_factors) and the coverage gaps (si_coverage_gaps). Parsing is lenient: a missing, empty or malformed part is
// an empty list, never an error, and a value the sync kept as JSON text is read as the JSON it holds.
// =====================================================================================================================

/// One tier claim: a rule that matched the CI, what tier it claims, whether it was allowed to decide (and why not), and
/// whether it won. <see cref="Evidence"/>: the fields the rule's condition read.
public sealed record CiTierClaim(string Rule, string? Name, string? Stage, string? Mechanism, int? Tier, bool Admissible, string? Reason, bool Winner, IReadOnlyList<string> Evidence)
{
    /// #579 the claim in one short line (the purpose it sets, else the rule name's first line); null on an older document.
    public string? Label { get; init; }
    /// #579 rule | tag | default (who decides with this claim); null on an older document.
    public string? Kind { get; init; }
    /// #579 the values that matched, in words ("Defender tag PAWDevices--tier0--SI", "installed software ...").
    public IReadOnlyList<string> Matched { get; init; } = [];
    /// The key of the rule that made the claim ("&lt;engine&gt;/&lt;rule id&gt;" -- what a rule change names); null for a claim
    /// no such rule made (a tag, a pin, a rule pack) and on an older document.
    public string? RuleKey { get; init; }
    /// Whether the document says anything about the rule's key (false = written before claims carried one).
    public bool RuleKeyRecorded { get; init; }
}

/// Where one resolved field came from: the provider and record that supplied it, when that record observed it, and
/// whether it was stale (no fresh source -- the newest value was kept).
/// #459: Conflicts = the other FRESH providers that hold a different value ("provider: value"), never deciding.
public sealed record CiFieldSource(string Field, string? Provider, string? Record, string? ObservedAt, bool Stale, IReadOnlyList<string>? Conflicts = null);

/// How the CMDB criticality became the criticality factor.
public sealed record CiCriticality(string? Cmdb, string? Field, string? Value, string? Mapping, double? Factor, string? DataSensitivity, double? DataSensitivityFactor);

/// One risk factor on the CI (risk factor model v2: an ENABLED factor counts its impact 1-5 on its side; a disabled factor
/// is not evaluated, so it is never on a CI). A CI document written before the model (an entry with stage testing) counts
/// with impact 0. Stage is the old field, kept for those documents.
public sealed record CiRiskFactor(string Id, string? Name, string? Axis, double Impact, string? Stage, string? Coverage)
{
    /// The report / Excel / PDF name (shortName), else the id.
    public string? ShortName { get; init; }
    /// asset | vulnerability (the side of the score it adds to); null on an old document.
    public string? Side { get; init; }
    /// enabled | disabled; null on an old document.
    public string? State { get; init; }
    public bool Counts => Impact != 0;
}

/// One CI-level coverage gap (a check the CI fails, e.g. not onboarded).
public sealed record CiCoverageGap(string Id, string? Name);

/// One field of a document as text (a list joined, an object as its JSON).
public sealed record CiFieldValue(string Field, string Text);

/// The parsed document.
public sealed record CiDocument(IReadOnlyList<CiTierClaim> Claims, IReadOnlyList<CiFieldSource> Sources, CiCriticality? Criticality,
    IReadOnlyList<CiRiskFactor> Factors, IReadOnlyList<CiCoverageGap> Gaps, IReadOnlyList<CiFieldValue> Fields)
{
    public static readonly CiDocument Empty = new([], [], null, [], [], []);
    public bool HasWinner => Claims.Any(c => c.Winner);
    /// #579 the tier in one plain sentence (si_tier_explanation): who decided it and what else claimed; null on an older document.
    public string? Explanation { get; init; }
    /// #406 since when the CI is in its lifecycle state (si_lifecycle_since, UTC); null on an older document.
    public DateTime? LifecycleSince { get; init; }
    /// #406 why the CI is in its lifecycle state (si_lifecycle_reason): the evidence in words.
    public string? LifecycleReason { get; init; }
    /// #406 a not seen / retired CI: days since any source last saw it when it was built (si_not_seen_days).
    public int? NotSeenDays { get; init; }
    /// #856 a CI without a name (a device Defender only discovered): its best identifier, shown MARKED as a fallback -- never
    /// the CI's name; null when the document has a name.
    public CiNameFallback? NameFallback { get; init; }
}

public static class CiDoc
{
    /// The fields the CI page shows in a section of their own (not again under "every field").
    public static readonly IReadOnlySet<string> Traces = new HashSet<string>(StringComparer.Ordinal)
    {
        "si_tier_claims", "si_tier_explanation", "si_field_sources", "si_criticality_source", "si_risk_factors", "si_coverage_gaps", "si_linked_objects",
    };

    public static CiDocument Parse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return CiDocument.Empty;
        JsonDocument doc;
        try { doc = JsonDocument.Parse(json); }
        catch (JsonException) { return CiDocument.Empty; }
        using (doc)
        {
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object) return CiDocument.Empty;
            return new CiDocument(Claims(Get(root, "si_tier_claims")), Sources(Get(root, "si_field_sources")), Criticality(Get(root, "si_criticality_source")),
                Factors(Get(root, "si_risk_factors")), Gaps(Get(root, "si_coverage_gaps")), Fields(root))
            {
                Explanation = S(root, "si_tier_explanation"),
                LifecycleSince = UtcOrNull(S(root, "si_lifecycle_since")),
                LifecycleReason = S(root, "si_lifecycle_reason"),
                NotSeenDays = D(root, "si_not_seen_days") is { } nd ? (int)nd : null,
                NameFallback = CiDisplayName.FromDocument(root, S(root, "si_ci_id")),
            };
        }
    }

    /// An ISO time (UTC) or null.
    internal static DateTime? UtcOrNull(string? s) =>
        s is { Length: > 0 } && DateTime.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var d) ? d : null;

    /// A property, with a value the sync kept as JSON text read as that JSON (a clone: it outlives the document).
    private static JsonElement? Get(JsonElement o, string name)
    {
        if (!o.TryGetProperty(name, out var v)) return null;
        if (v.ValueKind == JsonValueKind.String && v.GetString() is { } s && (s.TrimStart().StartsWith('[') || s.TrimStart().StartsWith('{')))
        {
            try { using var d = JsonDocument.Parse(s); return d.RootElement.Clone(); }
            catch (JsonException) { return v.Clone(); }
        }
        return v.Clone();
    }

    /// An array's objects (a single object counts as one; anything else none).
    private static IEnumerable<JsonElement> Objects(JsonElement? e) => e switch
    {
        { ValueKind: JsonValueKind.Array } a => a.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.Object),
        { ValueKind: JsonValueKind.Object } o => new[] { o },
        _ => Array.Empty<JsonElement>(),
    };

    internal static string? S(JsonElement o, string name) => o.TryGetProperty(name, out var v) ? v.ValueKind switch
    {
        JsonValueKind.String => v.GetString() is { Length: > 0 } s ? s : null,
        JsonValueKind.Number or JsonValueKind.True or JsonValueKind.False => v.GetRawText(),
        _ => null,
    } : null;

    /// #459: a conflict's value as one short text (a list joined, anything else its JSON), at most 200 characters.
    private static string ValueText(JsonElement c)
    {
        if (!c.TryGetProperty("value", out var v)) return "";
        var s = v.ValueKind switch
        {
            JsonValueKind.String => v.GetString() ?? "",
            JsonValueKind.Array => string.Join(", ", v.EnumerateArray().Select(x => x.ValueKind == JsonValueKind.String ? x.GetString() ?? "" : x.GetRawText())),
            JsonValueKind.Null or JsonValueKind.Undefined => "",
            _ => v.GetRawText(),
        };
        return s.Length > 200 ? s[..200] + "..." : s;
    }

    internal static double? D(JsonElement o, string name) => o.TryGetProperty(name, out var v) ? v.ValueKind switch
    {
        JsonValueKind.Number when v.TryGetDouble(out var d) => d,
        JsonValueKind.String when double.TryParse(v.GetString(), NumberStyles.Float, CultureInfo.InvariantCulture, out var d) => d,
        _ => null,
    } : null;

    internal static bool B(JsonElement o, string name) => o.TryGetProperty(name, out var v) && v.ValueKind switch
    {
        JsonValueKind.True => true,
        JsonValueKind.String => v.GetString() is "true" or "True" or "1",
        JsonValueKind.Number => v.TryGetInt32(out var i) && i != 0,
        _ => false,
    };

    public static IReadOnlyList<CiTierClaim> Claims(JsonElement? e) => Objects(e).Select(c => new CiTierClaim(
        S(c, "rule") ?? "", S(c, "name"), S(c, "stage"), S(c, "mechanism"),
        D(c, "tier") is { } t && t >= 0 && t <= 255 ? (int)t : null,
        // a claim that does not say is not admissible: it never decided anything
        B(c, "admissible"), S(c, "reason"), B(c, "winner"), List(c.TryGetProperty("evidence", out var ev) ? ev : null))
    {
        Label = S(c, "label"), Kind = S(c, "kind"), Matched = List(Prop(c, "matched")),
        RuleKey = S(c, "rule_key")?.Trim() is { Length: > 0 } key ? key : null, RuleKeyRecorded = c.TryGetProperty("rule_key", out _),
    }).ToList();

    private static JsonElement? Prop(JsonElement o, string name) => o.TryGetProperty(name, out var v) ? v : null;

    public static IReadOnlyList<CiFieldSource> Sources(JsonElement? e)
    {
        if (e is not { ValueKind: JsonValueKind.Object } o) return [];
        return o.EnumerateObject().Where(p => p.Value.ValueKind == JsonValueKind.Object)
            .Select(p => new CiFieldSource(p.Name, S(p.Value, "provider"), S(p.Value, "record"), S(p.Value, "observed_at"), B(p.Value, "stale"),
                Objects(p.Value.TryGetProperty("conflicts", out var cf) ? cf : null).Select(c => $"{S(c, "provider")}: {ValueText(c)}").ToList()))
            .OrderBy(s => s.Field, StringComparer.Ordinal).ToList();
    }

    public static CiCriticality? Criticality(JsonElement? e) => e is { ValueKind: JsonValueKind.Object } o
        ? new CiCriticality(S(o, "cmdb"), S(o, "field"), S(o, "value"), S(o, "mapping"), D(o, "factor"), S(o, "data_sensitivity"), D(o, "data_sensitivity_factor"))
        : null;

    public static IReadOnlyList<CiRiskFactor> Factors(JsonElement? e) => Objects(e).Select(f =>
    {
        var stage = S(f, "stage");
        var state = S(f, "state");
        // model v2: an entry counts when its state is enabled (the engine writes only enabled factors); a document from
        // before it (no state) keeps the old rule -- a testing factor was shown, never counted: impact 0
        var counts = state is not null ? state == "enabled" : stage is null or "production";
        var impact = counts ? D(f, "impact") ?? 0 : 0;
        return new CiRiskFactor(S(f, "id") ?? "", S(f, "name"), S(f, "axis"), impact, stage, S(f, "coverage"))
        {
            ShortName = S(f, "shortName"), Side = S(f, "side"), State = state,
        };
    }).Where(f => f.Id.Length > 0).ToList();

    public static IReadOnlyList<CiCoverageGap> Gaps(JsonElement? e) => Objects(e).Select(g => new CiCoverageGap(S(g, "id") ?? "", S(g, "name"))).Where(g => g.Id.Length > 0).ToList();

    /// Every field of a document as text, by name (the traces left out -- they have sections of their own).
    public static IReadOnlyList<CiFieldValue> Fields(JsonElement root) =>
        root.EnumerateObject().Where(p => !Traces.Contains(p.Name)).Select(p => new CiFieldValue(p.Name, Text(p.Value)))
            .Where(f => f.Text.Length > 0).OrderBy(f => f.Field, StringComparer.Ordinal).ToList();

    /// Every field of any document (a provider record's SI fields) as text.
    public static IReadOnlyList<CiFieldValue> AllFields(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return [];
        try
        {
            using var d = JsonDocument.Parse(json);
            return d.RootElement.ValueKind != JsonValueKind.Object ? []
                : d.RootElement.EnumerateObject().Select(p => new CiFieldValue(p.Name, Text(p.Value))).Where(f => f.Text.Length > 0)
                    .OrderBy(f => f.Field, StringComparer.Ordinal).ToList();
        }
        catch (JsonException) { return []; }
    }

    /// A JSON value as text a person reads: a string as itself, a list of strings joined with "; ", a list of objects by
    /// their provider:id, id or name, anything else as compact JSON. Numbers stay invariant here; the page formats them.
    public static string Text(JsonElement v) => v.ValueKind switch
    {
        JsonValueKind.String => Unwrap(v.GetString() ?? ""),
        JsonValueKind.Number => v.GetRawText(),
        JsonValueKind.True => "true",
        JsonValueKind.False => "false",
        JsonValueKind.Array => string.Join("; ", v.EnumerateArray().Select(Item).Where(s => s.Length > 0)),
        JsonValueKind.Object => v.GetRawText(),
        _ => "",
    };

    /// A cell the grid read as JSON text (a list or an object column) as text a person reads; plain text as it is.
    public static string Text(string? jsonOrText) => string.IsNullOrEmpty(jsonOrText) ? "" : Unwrap(jsonOrText);

    private static string Unwrap(string s)
    {
        var t = s.TrimStart();
        if (!(t.StartsWith('[') || t.StartsWith('{'))) return s;
        try { using var d = JsonDocument.Parse(s); return d.RootElement.ValueKind == JsonValueKind.String ? s : Text(d.RootElement); }
        catch (JsonException) { return s; }
    }

    private static string Item(JsonElement e)
    {
        if (e.ValueKind != JsonValueKind.Object) return Text(e);
        var id = S(e, "id");
        var provider = S(e, "provider");
        if (provider is not null && id is not null) return provider + ":" + id;
        return id ?? S(e, "name") ?? S(e, "value") ?? e.GetRawText();
    }

    private static IReadOnlyList<string> List(JsonElement? e) => e switch
    {
        { ValueKind: JsonValueKind.Array } a => a.EnumerateArray().Select(x => Text(x)).Where(s => s.Length > 0).ToArray(),
        { ValueKind: JsonValueKind.String } s when s.GetString() is { Length: > 0 } one => new[] { one },
        _ => Array.Empty<string>(),
    };
}
