using System.Text.Json;

namespace SI.Management.Web.Changes;

/// <summary>
/// The "Risk factors" legend -- the appendix of a printed / PDF report and the sheet of every Excel export: one row per
/// factor (short name, description, asset / vulnerability, impact; class, group, state, id). Risk Analysis writes it next
/// to each workbook as <c>&lt;name&gt;.riskfactors.json</c> (Invoke-RiskAnalysis.ps1, Get-RARiskFactorLegendRows);
/// <see cref="FromJson"/> reads that file. The web app has no access to the engine's output folder, so its pages build the
/// same rows from the factor catalog in force (<see cref="FromFactors"/>, the same order: asset factors first, then
/// vulnerability factors, by group and short name).
/// </summary>
public static class RiskFactorLegend
{
    public sealed record Row(string ShortName, string Description, string AppliesTo, int Impact, string Class, string Group, string State, string Id);

    /// The engine's group order (Get-RARiskFactorLegendRows).
    public static readonly string[] GroupOrder = { "Exposure", "Device health", "Identity", "Privilege", "Apps", "Importance", "Exploitability", "Impact", "Severity", "Lifecycle" };

    private static IReadOnlyList<Row> Sort(IEnumerable<Row> rows) => rows
        .OrderBy(r => r.AppliesTo == "Asset" ? 0 : 1)
        .ThenBy(r => Array.IndexOf(GroupOrder, r.Group) is var i && i >= 0 ? i : 99)
        .ThenBy(r => r.ShortName, StringComparer.OrdinalIgnoreCase).ToList();

    /// The legend of the catalog in force (the customer's impacts and states included).
    public static IReadOnlyList<Row> FromFactors(IEnumerable<RiskFactorView> factors) => Sort(factors.Select(f => new Row(
        f.ShortName, string.IsNullOrEmpty(f.Name) ? f.Description : f.Name, f.Scope == "finding" ? "Vulnerability" : "Asset", f.ImpactLevel ?? 0,
        f.IsBuiltin ? "Built-in" : "Optional", f.Group, f.IsEnabled ? "Enabled" : "Disabled", f.Id)));

    /// A <c>&lt;name&gt;.riskfactors.json</c> written by Risk Analysis (an array of rows, or one row; missing fields blank).
    /// Unreadable text -> no rows.
    public static IReadOnlyList<Row> FromJson(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return Array.Empty<Row>();
        try
        {
            using var d = JsonDocument.Parse(json.TrimStart('﻿'));
            var items = d.RootElement.ValueKind == JsonValueKind.Array ? d.RootElement.EnumerateArray().ToList()
                : d.RootElement.ValueKind == JsonValueKind.Object ? new List<JsonElement> { d.RootElement } : new List<JsonElement>();
            static string S(JsonElement o, string p) => o.TryGetProperty(p, out var v) ? v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : v.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined ? "" : v.GetRawText() : "";
            static int I(JsonElement o, string p) => o.TryGetProperty(p, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetInt32(out var n) ? n : int.TryParse(S(o, p), out var m) ? m : 0;
            return Sort(items.Where(x => x.ValueKind == JsonValueKind.Object && S(x, "ShortName").Length > 0)
                .Select(x => new Row(S(x, "ShortName"), S(x, "Description"), S(x, "AppliesTo") == "Vulnerability" ? "Vulnerability" : "Asset", I(x, "Impact"),
                    S(x, "Class"), S(x, "Group"), S(x, "State"), S(x, "Id"))));
        }
        catch (JsonException) { return Array.Empty<Row>(); }
    }
}
