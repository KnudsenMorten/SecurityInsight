using System.Text.Json;

namespace SI.Management.Core.ProData;

/// One band of the Protection Score: its words ("Good"), its colour family ("good" -- the CSS class suffix) and the colour a
/// mail uses on white (Ink).
public sealed record ProtectionBand(string Name, double Min, string Tone, string Ink);

/// <summary>
/// THE Protection Score's bands (owner 2026-10-20: "protection score ... should indicate a different color based on the agreed
/// ranges ... we also had other words to go with this like Moderate etc."): read from the embedded copy of
/// data-model\protection-score-bands.locked.json -- the ONE definition the engine reads too (Get-SIProtectionBand); a test keeps the
/// two files equal. 0-100, higher is better; a band is the first, from the top, whose Min the score reaches.
/// </summary>
public static class ProtectionBands
{
    public const string ResourceName = "protection-score-bands.locked.json";
    public static readonly ProtectionBand Unknown = new("Unknown", double.NaN, "unknown", "#546e7a");

    private static readonly Lazy<IReadOnlyList<ProtectionBand>> _all = new(Load);

    /// The bands, highest first.
    public static IReadOnlyList<ProtectionBand> All => _all.Value;

    /// The band of a score (null = Unknown).
    public static ProtectionBand Of(double? score)
    {
        if (score is not { } s || double.IsNaN(s)) return Unknown;
        foreach (var b in All) if (s >= b.Min) return b;
        return Unknown;
    }

    private static IReadOnlyList<ProtectionBand> Load()
    {
        using var stream = typeof(ProtectionBands).Assembly.GetManifestResourceStream("DataModel/" + ResourceName)
            ?? throw new InvalidOperationException("the embedded " + ResourceName + " is missing");
        using var doc = JsonDocument.Parse(stream);
        return doc.RootElement.GetProperty("bands").EnumerateArray()
            .Select(b => new ProtectionBand(b.GetProperty("name").GetString() ?? "", b.GetProperty("min").GetDouble(), b.GetProperty("tone").GetString() ?? "unknown",
                b.TryGetProperty("ink", out var ink) ? ink.GetString() ?? "#333333" : "#333333"))
            .OrderByDescending(b => b.Min).ToList();
    }
}
