using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace SI.Management.Web.Changes;

/// <summary>
/// The risk factor model on the Risk factors page -- pure, no I/O. Every factor carries a short name, a description,
/// what it is about (asset | finding), a group, a class (built-in | optional), an impact 1-5 (very low .. very high) and a
/// state (enabled | disabled). The customer fine-tunes the impact of any factor and switches OPTIONAL factors on or off;
/// a built-in factor is always on. Each change is a normal data-model item (the factor's cfg.ItemOverride body), staged
/// on Review &amp; commit and validated again there (<see cref="DataModelItemValidator.Factor"/>) and by the engine.
///
/// The score: asset side = the risk-index base + the SUM of the asset factors' impacts (no cap); vulnerability side =
/// the risk-index base + the SUM of the vulnerability factors' impacts (no cap); risk score = asset side x vulnerability
/// side. The owner's example: (5 + 5) x (5 + 4) = 90.
/// </summary>
public static class RiskFactorModel
{
    public const string Builtin = "builtin";
    public const string Optional = "optional";
    public const string Enabled = "enabled";
    public const string Disabled = "disabled";
    public const int ImpactMin = 1;
    public const int ImpactMax = 5;

    /// The words for each impact level, lowest first.
    public static readonly IReadOnlyList<(int Level, string Label)> ImpactLevels = new[]
    {
        (1, "Very low"), (2, "Low"), (3, "Medium"), (4, "High"), (5, "Very high"),
    };

    /// "Very low" .. "Very high"; a missing or off-scale impact shows as "not set".
    public static string ImpactLabel(int? level) => level is >= ImpactMin and <= ImpactMax ? ImpactLevels[level.Value - 1].Label : "not set";

    /// A factor id as a report name: internet_exposed -> InternetExposed (used when the catalog has no shortName yet).
    public static string ShortNameOf(string id)
    {
        if (string.IsNullOrEmpty(id)) return "";
        var sb = new StringBuilder(id.Length);
        foreach (var part in id.Split(new[] { '_', '-', ' ' }, StringSplitOptions.RemoveEmptyEntries))
            sb.Append(char.ToUpperInvariant(part[0])).Append(part.AsSpan(1));
        return sb.ToString();
    }

    /// The impact of a factor body as a whole number 1-5, or null (missing, not whole, or outside the scale).
    public static int? ImpactOf(JsonElement factor)
    {
        if (factor.ValueKind != JsonValueKind.Object || !factor.TryGetProperty("impact", out var i)) return null;
        if (i.ValueKind == JsonValueKind.Number && i.TryGetDouble(out var d) && d == Math.Floor(d) && d >= ImpactMin && d <= ImpactMax) return (int)d;
        return null;
    }

    /// The class the SHIPPED item gives a factor: the template's 'class' ('optional' or built-in). A template without the
    /// field counts as built-in -- the safe reading until the catalog carries it. The customer's own factor (no template)
    /// is optional unless its body says built-in.
    public static string ShippedClass(DataModelRow r)
    {
        var source = r.TemplateBody ?? r.OverrideBody;
        var cls = ClassOf(source);
        if (r.TemplateBody is null) return cls == Builtin ? Builtin : Optional;
        return cls == Optional ? Optional : Builtin;
    }

    private static string? ClassOf(string? body)
    {
        if (string.IsNullOrWhiteSpace(body)) return null;
        try
        {
            using var d = JsonDocument.Parse(body);
            return d.RootElement.ValueKind == JsonValueKind.Object && d.RootElement.TryGetProperty("class", out var c) && c.ValueKind == JsonValueKind.String ? c.GetString() : null;
        }
        catch (JsonException) { return null; }
    }

    /// The reasons a change of a factor is refused against what SecurityInsight ships (empty = accepted): a built-in
    /// factor cannot be switched off -- neither as an item ('disable') nor by its state -- and stays built-in.
    /// The static checks of the body itself are <see cref="DataModelItemValidator.Factor"/>'s.
    public static IReadOnlyList<string> ShippedProblems(DataModelRow? shipped, string state, string? body)
    {
        if (shipped is null || shipped.Template != "risk-factors" || ShippedClass(shipped) != Builtin) return Array.Empty<string>();
        if (state == ItemOverrideRepository.StateDisable) return new[] { "a built-in factor is always on -- it cannot be switched off (change its impact instead)" };
        if (state != ItemOverrideRepository.StateOverride || string.IsNullOrWhiteSpace(body)) return Array.Empty<string>();
        var why = new List<string>();
        try
        {
            using var d = JsonDocument.Parse(body);
            var o = d.RootElement;
            if (o.ValueKind != JsonValueKind.Object) return why;
            if (o.TryGetProperty("state", out var s) && s.ValueKind == JsonValueKind.String && s.GetString() == Disabled)
                why.Add("a built-in factor is always on -- it cannot be switched off (change its impact instead)");
            if (o.TryGetProperty("class", out var c) && !(c.ValueKind == JsonValueKind.String && c.GetString() == Builtin))
                why.Add("a built-in factor stays built-in -- its class cannot be changed");
        }
        catch (JsonException) { }
        return why;
    }

    /// IMPACT: the factor body with its impact set to a whole number 1-5. Refused outside the scale.
    public static (string? Body, IReadOnlyList<string> Problems) WithImpact(string? factorJson, string? posted)
    {
        if (!int.TryParse(posted, NumberStyles.Integer, CultureInfo.InvariantCulture, out var n) || n < ImpactMin || n > ImpactMax)
            return (null, new[] { $"the impact is a whole number from {ImpactMin} (very low) to {ImpactMax} (very high)" });
        if (Parse(factorJson) is not { } o) return (null, new[] { "the factor is not a JSON object" });
        o["impact"] = n;
        return (o.ToJsonString(), Array.Empty<string>());
    }

    /// STATE: the factor body with its state set to enabled / disabled. Refused for a built-in factor (always on).
    public static (string? Body, IReadOnlyList<string> Problems) WithState(DataModelRow row, string? factorJson, string? posted)
    {
        if (posted is not (Enabled or Disabled)) return (null, new[] { "the state is enabled or disabled" });
        if (ShippedClass(row) == Builtin && posted == Disabled) return (null, new[] { "a built-in factor is always on -- it cannot be switched off (change its impact instead)" });
        if (Parse(factorJson) is not { } o) return (null, new[] { "the factor is not a JSON object" });
        o["state"] = posted;
        return (o.ToJsonString(), Array.Empty<string>());
    }

    private static JsonObject? Parse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try { return JsonNode.Parse(json) as JsonObject; }
        catch (JsonException) { return null; }
    }

    // ------------------------------------------------------------------------------------------------ filter + sort

    public static readonly string[] SortKeys = { "short", "about", "group", "class", "impact", "state" };

    /// The factor list filtered by what it is about ('Asset' / 'Vulnerability') and group, sorted by a column. Each filter
    /// may hold several values, '|'-joined (owner 2026-10-19: every filter multi-select): any of them matches.
    public static IReadOnlyList<RiskFactorView> Arrange(IEnumerable<RiskFactorView> factors, string? about, string? group, string? sort, bool descending)
    {
        var q = factors;
        var abouts = SI.Management.Core.ProData.ProDataFilters.Values(about);
        var groups = SI.Management.Core.ProData.ProDataFilters.Values(group);
        if (abouts.Count > 0) q = q.Where(f => abouts.Contains(f.About, StringComparer.OrdinalIgnoreCase));
        if (groups.Count > 0) q = q.Where(f => groups.Contains(f.Group, StringComparer.OrdinalIgnoreCase));
        Func<RiskFactorView, IComparable> key = sort switch
        {
            "about" => f => f.About,
            "group" => f => f.Group,
            "class" => f => f.IsBuiltin ? 0 : 1,
            "impact" => f => f.ImpactLevel ?? 0,
            "state" => f => f.IsEnabled ? 0 : 1,
            _ => f => f.ShortName,
        };
        var ordered = descending ? q.OrderByDescending(key).ThenBy(f => f.ShortName, StringComparer.OrdinalIgnoreCase) : q.OrderBy(key).ThenBy(f => f.ShortName, StringComparer.OrdinalIgnoreCase);
        return ordered.ToList();
    }

    /// The groups the filter offers (every group a factor names, sorted).
    public static IReadOnlyList<string> Groups(IEnumerable<RiskFactorView> factors) =>
        factors.Select(f => f.Group).Where(g => g.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(g => g, StringComparer.OrdinalIgnoreCase).ToList();

    // ------------------------------------------------------------------------------------------------ score preview

    /// The base values the preview offers (the risk index gives each finding x asset class x tier its base).
    public const int BaseMin = 0;
    public const int BaseMax = 10;

    /// One score preview. AssetRow / VulnerabilityRow = the risk index row (1-based, first-match order) that gave the base,
    /// 0 when no row fits (base 0), null when the base was picked by hand.
    public sealed record ScorePreview(double AssetBase, IReadOnlyList<RiskFactorView> AssetFactors, double VulnerabilityBase, IReadOnlyList<RiskFactorView> VulnerabilityFactors)
    {
        public int? AssetRow { get; init; }
        public int? VulnerabilityRow { get; init; }
        public int AssetImpacts => AssetFactors.Sum(f => f.ImpactLevel ?? 0);
        public int VulnerabilityImpacts => VulnerabilityFactors.Sum(f => f.ImpactLevel ?? 0);
        public double AssetSide => AssetBase + AssetImpacts;
        public double VulnerabilitySide => VulnerabilityBase + VulnerabilityImpacts;
        /// RiskIndexScoring.Total -- the engine's formula (RA-RiskScore.ps1).
        public double Score => SI.Management.Core.ProData.RiskIndexScoring.Total(AssetBase, AssetImpacts, VulnerabilityBase, VulnerabilityImpacts);
        /// The risk rating bands in force (risk_rating_bands); null = the built-in 50 / 30 / 15.
        public SI.Management.Core.ProData.RiskRatingBands? Bands { get; init; }
        public string Rating => SI.Management.Core.ProData.RiskIndexScoring.Rating(Score, Bands);
        /// "(5 + 5) x (5 + 4) = 90"
        public string Formula => $"({N(AssetBase)} + {AssetImpacts}) x ({N(VulnerabilityBase)} + {VulnerabilityImpacts}) = {N(Score)}";
        private static string N(double d) => d.ToString("0.##", CultureInfo.InvariantCulture);
    }

    /// The preview of a score: the picked bases (clamped to the offered range) and the picked ENABLED factors, each on its
    /// own side (an asset factor adds to the asset side, a vulnerability factor to the vulnerability side; an unknown id or
    /// a switched-off factor adds nothing). Read-only: nothing is staged.
    public static ScorePreview Preview(IEnumerable<RiskFactorView> factors, double? assetBase, double? vulnerabilityBase, IEnumerable<string>? picked)
    {
        var set = (picked ?? Array.Empty<string>()).ToHashSet(StringComparer.Ordinal);
        var chosen = factors.Where(f => set.Contains(f.Id) && f.IsEnabled).ToList();
        double Clamp(double? v) => Math.Clamp(v ?? 5, BaseMin, BaseMax);
        return new ScorePreview(Clamp(assetBase), chosen.Where(f => f.Scope == "asset").ToList(), Clamp(vulnerabilityBase), chosen.Where(f => f.Scope == "finding").ToList());
    }

    /// The preview with the bases the SHIPPED / committed risk index gives a sample finding -- first match, per base, exactly
    /// as Risk Analysis looks them up (RiskIndexScoring, the twin of RA-RiskIndexSi.ps1).
    public static ScorePreview PreviewFromIndex(IEnumerable<RiskFactorView> factors, IReadOnlyList<SI.Management.Core.ProData.RiskIndexRow> orderedIndex,
        SI.Management.Core.ProData.RiskIndexFinding sample, IEnumerable<string>? picked)
    {
        var rules = SI.Management.Core.ProData.RiskIndexScoring.BuildRules(orderedIndex);
        var (a, v) = SI.Management.Core.ProData.RiskIndexScoring.Score(rules, sample);
        var p = Preview(factors, a.Score, v.Score, picked);
        return p with { AssetBase = a.Score, VulnerabilityBase = v.Score, AssetRow = a.Row, VulnerabilityRow = v.Row };
    }

    /// The values a sample-finding dropdown offers for one index matcher column: every distinct value the index in force
    /// names in it (sorted) -- a closed set, so a preview never matches on typed text.
    public static IReadOnlyList<string> IndexValues(IEnumerable<SI.Management.Core.ProData.RiskIndexRow> index, string column) =>
        index.Select(r => r.Get(column).Trim()).Where(s => s.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(s => s, StringComparer.OrdinalIgnoreCase).ToList();
}
