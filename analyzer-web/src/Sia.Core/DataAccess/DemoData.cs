using System.Text.Json;
using System.Text.Json.Serialization;
using Sia.Core.Model;

namespace Sia.Core.DataAccess;

/// <summary>
/// Loads the synthetic demo snapshot (analyzer/seed/demo-snapshot.json — the same seed the
/// PowerShell POC shipped) into <see cref="RiskRow"/>s. Demo/preview/offline only; the hosted
/// app reads the live Log Analytics workspace. No real customer/tenant/asset data.
/// </summary>
public static class DemoData
{
    private static readonly JsonSerializerOptions Options = new() { PropertyNameCaseInsensitive = true };

    public static IReadOnlyList<RiskRow> Load(string seedPath)
    {
        if (string.IsNullOrWhiteSpace(seedPath) || !File.Exists(seedPath))
            throw new FileNotFoundException("Demo seed snapshot not found.", seedPath ?? "(null)");

        var doc = JsonSerializer.Deserialize<SeedDoc>(File.ReadAllText(seedPath), Options)
                  ?? throw new InvalidOperationException("Demo seed JSON did not parse.");

        // Mirror the live mapper's RiskFactor_*_Detailed-over-numeric preference so the demo
        // path renders the same plain-language drivers the real RA-Summary schema produces.
        // The bare RiskFactor_* columns are numeric factors in the real schema; we accept
        // either a string (legacy seed) or a number (current seed) and surface the _Detailed
        // text when present, falling back to a non-zero numeric factor as a string.
        static string PreferDetailed(string? detailed, string? bare)
        {
            if (!string.IsNullOrWhiteSpace(detailed)) return detailed!;
            return string.IsNullOrWhiteSpace(bare) || bare == "0" ? "" : bare!;
        }

        return (doc.Rows ?? new List<SeedRow>()).Select(r => new RiskRow
        {
            SecurityDomain         = r.SecurityDomain ?? "",
            ConfigurationName      = r.ConfigurationName ?? "",
            ConfigurationId        = r.ConfigurationId ?? "",
            CriticalityTier        = r.CriticalityTier,
            CriticalityTierLevel   = r.CriticalityTierLevel ?? "",
            SecuritySeverity       = r.SecuritySeverity ?? "",
            RiskScoreTotal         = r.RiskScoreTotal,
            RiskScoreTotalWeighted = r.RiskScoreTotalWeighted,
            RiskFactorConsequence  = PreferDetailed(r.RiskFactorConsequenceDetailed, AsText(r.RiskFactorConsequence)),
            RiskFactorProbability  = PreferDetailed(r.RiskFactorProbabilityDetailed, AsText(r.RiskFactorProbability)),
            CollectionTime         = r.CollectionTime
        }).ToList();
    }

    /// <summary>Flatten a JSON number-or-string cell to its text form (numbers without
    /// a trailing ".0").</summary>
    private static string AsText(JsonElement? e)
    {
        if (e is null) return "";
        var v = e.Value;
        return v.ValueKind switch
        {
            JsonValueKind.String => v.GetString() ?? "",
            JsonValueKind.Number => v.TryGetInt64(out var l) ? l.ToString(System.Globalization.CultureInfo.InvariantCulture)
                                                             : v.GetDouble().ToString(System.Globalization.CultureInfo.InvariantCulture),
            JsonValueKind.Null or JsonValueKind.Undefined => "",
            _ => v.ToString(),
        };
    }

    private sealed class SeedDoc
    {
        [JsonPropertyName("rows")] public List<SeedRow>? Rows { get; set; }
    }

    private sealed class SeedRow
    {
        public string? SecurityDomain { get; set; }
        public string? ConfigurationName { get; set; }
        public string? ConfigurationId { get; set; }
        public int CriticalityTier { get; set; }
        public string? CriticalityTierLevel { get; set; }
        public string? SecuritySeverity { get; set; }
        public double RiskScoreTotal { get; set; }
        [JsonPropertyName("RiskScoreTotal_Weighted")] public double RiskScoreTotalWeighted { get; set; }
        // Bare RiskFactor_* is NUMERIC in the real schema; a legacy seed used a string here.
        // Read as JsonElement so either form parses, then AsText() flattens it.
        [JsonPropertyName("RiskFactor_Consequence")] public JsonElement? RiskFactorConsequence { get; set; }
        [JsonPropertyName("RiskFactor_Probability")] public JsonElement? RiskFactorProbability { get; set; }
        // Real-schema plain-language driver columns (preferred over the bare factor when present).
        [JsonPropertyName("RiskFactor_Consequence_Detailed")] public string? RiskFactorConsequenceDetailed { get; set; }
        [JsonPropertyName("RiskFactor_Probability_Detailed")] public string? RiskFactorProbabilityDetailed { get; set; }
        public DateTimeOffset CollectionTime { get; set; }
    }
}
