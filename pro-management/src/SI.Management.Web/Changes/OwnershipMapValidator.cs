using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace SI.Management.Web.Changes;

/// <summary>
/// THE CMDB OWNERSHIP MAP as configuration (#251): per asset type, which import connector already owns it in the
/// customer's CMDB (match-only vs create). ONE document per install -- cfg.ItemOverride Kind 'cmdbownership', ItemKey
/// 'map', State 'override', Format 'json', no base -- holding the cmdbSourceOwnership object (the shape of
/// config\cmdb-source-ownership.locked.json). Setup seeds it from that shipped file; the customer owns it; a template
/// release never changes it.
/// This is the C# twin of Test-SIProItem's 'cmdbownership' rules (engine\pro-settings\SI-ProConfig.ps1). The run-start
/// reader checks the document AGAIN and stops the run on a refused one, so the GUI must never write what it would
/// refuse. Both read tests/fixtures/ownership-map-cases.json.
/// </summary>
public static partial class OwnershipMapValidator
{
    public const string Kind = "cmdbownership";
    public const string Key = "map";

    [GeneratedRegex(@"^[a-z0-9][a-z0-9_\-\.]{0,99}$", RegexOptions.CultureInvariant)] private static partial Regex AssetType();

    public static bool Is(string? kind, string? key) => kind == Kind && key == Key;

    public static string? KeyProblem(string key) => key == Key ? null : $"the CMDB ownership map has the key '{Key}'";

    private static bool IsNote(string n) => n.StartsWith('_') || n == "Comment";

    private static string Text(JsonElement v) => v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : v.GetRawText();

    /// A whole number 0..3650, written as a JSON number or as text ([int]::TryParse in PowerShell).
    private static bool Days(JsonElement v)
    {
        if (v.ValueKind is not (JsonValueKind.Number or JsonValueKind.String)) return false;
        return int.TryParse(Text(v).Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var n) && n is >= 0 and <= 3650;
    }

    private static bool Bool(JsonElement v) => v.ValueKind is JsonValueKind.True or JsonValueKind.False;

    private static bool NonEmptyText(JsonElement v) => v.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(v.GetString());

    /// The reasons the map is refused (empty = accepted).
    public static IReadOnlyList<string> Validate(string? body)
    {
        var why = new List<string>();
        if (string.IsNullOrWhiteSpace(body)) { why.Add("the document is empty"); return why; }
        JsonDocument doc;
        try { doc = JsonDocument.Parse(body.TrimStart('﻿')); }
        catch (JsonException ex) { why.Add("the document is not valid JSON: " + ex.Message); return why; }
        using (doc)
        {
            var o = doc.RootElement;
            if (o.ValueKind != JsonValueKind.Object) { why.Add("the ownership map must be a JSON object"); return why; }
            foreach (var p in o.EnumerateObject())
            {
                if (IsNote(p.Name)) continue;
                var v = p.Value;
                switch (p.Name)
                {
                    case "notACiResourceTypes":
                        if (v.ValueKind != JsonValueKind.Array || v.EnumerateArray().Any(x => !NonEmptyText(x))) why.Add("notACiResourceTypes must be a list of resource types");
                        break;
                    case "defaultSiMayCreate":
                        if (!Bool(v)) why.Add("defaultSiMayCreate must be true or false");
                        break;
                    case "defaultExpectedWithinDays":
                        if (!Days(v)) why.Add("defaultExpectedWithinDays must be a whole number from 0 to 3650");
                        break;
                    case "defaultCiClass":
                        if (!NonEmptyText(v)) why.Add("defaultCiClass must be a CI class name");
                        break;
                    case "assetTypes":
                        if (v.ValueKind != JsonValueKind.Array) { why.Add("assetTypes must be a list"); break; }
                        AssetTypes(v, why);
                        break;
                    default:
                        why.Add($"'{p.Name}' is not an ownership setting");
                        break;
                }
            }
        }
        return why;
    }

    private static void AssetTypes(JsonElement list, List<string> why)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var n = 0;
        foreach (var e in list.EnumerateArray())
        {
            n++;
            var at = $"assetTypes[{n}]";
            if (e.ValueKind != JsonValueKind.Object) { why.Add($"{at} must be an object"); continue; }
            if (!e.TryGetProperty("siAssetType", out _)) why.Add($"{at} has no siAssetType");
            foreach (var p in e.EnumerateObject())
            {
                if (IsNote(p.Name)) continue;
                var v = p.Value;
                switch (p.Name)
                {
                    case "siAssetType":
                        var t = v.ValueKind == JsonValueKind.String ? (v.GetString() ?? "").Trim().ToLowerInvariant() : "";
                        if (!AssetType().IsMatch(t)) { why.Add($"{at}: '{Text(v)}' is not an asset type (lower-case letters, digits, _ - .)"); break; }
                        if (!seen.Add(t)) why.Add($"assetTypes: '{t}' is listed twice");
                        break;
                    case "siMayCreate":
                        if (!Bool(v)) why.Add($"{at}: siMayCreate must be true or false");
                        break;
                    case "expectedWithinDays":
                        if (!Days(v)) why.Add($"{at}: expectedWithinDays must be a whole number from 0 to 3650");
                        break;
                    case "ciClass":
                        if (!NonEmptyText(v)) why.Add($"{at}: ciClass must be a CI class name");
                        break;
                    case "ownedBy":
                        if (v.ValueKind is not (JsonValueKind.String or JsonValueKind.Null)) why.Add($"{at}: ownedBy must be text or null");
                        break;
                    default:
                        why.Add($"{at}: '{p.Name}' is not an asset type setting");
                        break;
                }
            }
        }
    }

    /// A starting text when no map exists yet (setup normally seeds the shipped one): the safe defaults, nothing created.
    public const string Starter = "{\n  \"_note\": \"which import connector owns each asset type in your CMDB -- an asset type not listed here is never created\",\n  \"defaultSiMayCreate\": false,\n  \"defaultExpectedWithinDays\": 7,\n  \"assetTypes\": []\n}";
}
