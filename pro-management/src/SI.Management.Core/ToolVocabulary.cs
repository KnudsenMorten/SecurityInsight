using SI.Management.Core.ProData;

namespace SI.Management.Core;

/// <summary>
/// The words a chat model (or an MCP client) may use for a filter value, and how each is read before a query runs.
/// A model guesses: "Critical" for a severity SecurityInsight calls "Very High", "Tier 0" for the tier "0", "devices"
/// for the domain "Endpoint". Reading order for one value:
///   1. a value present in the data, ignoring case;
///   2. the same, ignoring spaces, '-' and '_';
///   3. a synonym whose meaning is present in the data (or, if the data is not known, the canonical value);
///   4. the canonical list;
///   5. (report names only) the one present value that contains the text.
/// Every reading that changes the text is recorded ("severity 'Critical' read as 'Very High'") and returned with the
/// tool result. A value that cannot be read is passed on as typed; the tool then reports the values present when it
/// matches nothing, so "nothing matched my guess" is never mistaken for "there is nothing".
/// </summary>
public static class ToolVocabulary
{
    /// SecurityInsight's severities, most severe first (Risk Analysis SecuritySeverityScope).
    public static readonly IReadOnlyList<string> Severities = ["Very High", "High", "Medium-High", "Medium", "Low"];
    /// The Risk Analysis security domains.
    public static readonly IReadOnlyList<string> Domains = ["Endpoint", "Identity", "Azure", "PublicIP"];

    public static readonly IReadOnlyList<(string Value, string[] Words)> SeverityWords =
    [
        ("Very High", ["very high", "critical", "crit", "severe", "highest", "urgent", "p1"]),
        ("High", ["high", "important", "p2"]),
        ("Medium-High", ["medium-high", "medium high", "med-high", "elevated"]),
        ("Medium", ["medium", "med", "moderate", "p3"]),
        ("Low", ["low", "minor", "p4"]),
        // only when the data carries an informational value: SecurityInsight's own scope has none
        ("Informational", ["informational", "info", "information", "none"]),
    ];

    public static readonly IReadOnlyList<(string Value, string[] Words)> DomainWords =
    [
        ("Endpoint", ["endpoint", "endpoints", "device", "devices", "machine", "machines", "server", "servers", "workstation", "workstations", "computer", "computers", "host", "hosts"]),
        ("Identity", ["identity", "identities", "user", "users", "account", "accounts", "entra", "entra id", "aad", "azure ad", "active directory", "ad"]),
        ("Azure", ["azure", "cloud", "subscription", "subscriptions", "resource", "resources", "arm"]),
        ("PublicIP", ["publicip", "public ip", "public ips", "internet", "internet facing", "external", "exposure", "ip", "ips", "shodan"]),
    ];

    public static readonly IReadOnlyList<(string Value, string[] Words)> AssetKindWords =
        DomainWords.Select(d => (d.Value.ToLowerInvariant(), d.Words)).ToList();

    public static readonly IReadOnlyList<(string Value, string[] Words)> TierWords =
    [
        ("0", ["0", "tier 0", "tier0", "t0", "critical"]),
        ("1", ["1", "tier 1", "tier1", "t1", "high"]),
        ("2", ["2", "tier 2", "tier2", "t2", "medium"]),
        ("3", ["3", "tier 3", "tier3", "t3", "low"]),
        (ProDataFilters.Unclassified, ["unclassified", "none", "unknown", "untiered", "no tier"]),
    ];

    public static readonly IReadOnlyList<(string Value, string[] Words)> SortWords =
    [
        (FindingSorts.Importance, ["importance", "important", "priority", "default", "tier"]),
        (FindingSorts.Risk, ["risk", "risk score", "riskscore", "score", "highest risk", "top", "weighted risk score"]),
        (FindingSorts.Severity, ["severity", "sev"]),
        (FindingSorts.Asset, ["asset", "asset name", "name", "host"]),
        (FindingSorts.Report, ["report", "report name"]),
    ];

    public static readonly IReadOnlyList<(string Value, string[] Words)> DimensionWords =
    [
        (TrendDimensions.None, ["none", "all", "total", "overall"]),
        (TrendDimensions.Tier, ["tier", "asset tier", "tiers"]),
        (TrendDimensions.Severity, ["severity", "severities", "sev"]),
        (TrendDimensions.Domain, ["domain", "security domain", "domains"]),
        (TrendDimensions.Report, ["report", "report name", "reports"]),
    ];

    public static readonly IReadOnlyList<(string Value, string[] Words)> GrainWords =
    [
        (Grains.Day, ["day", "daily", "days"]),
        (Grains.Week, ["week", "weekly", "weeks"]),
        (Grains.Month, ["month", "monthly", "months"]),
    ];

    /// Lower case without spaces, '-' and '_': "Very-High", "very high" and "VeryHigh" are one key.
    public static string Key(string s)
    {
        var chars = s.Where(ch => !char.IsWhiteSpace(ch) && ch != '-' && ch != '_').Select(char.ToLowerInvariant).ToArray();
        return new string(chars);
    }

    /// Reads one filter value. present = the values in the data (null when unknown); canonical = the fixed list.
    /// Returns the value to query with (null when raw is empty) and adds a note when the text was changed.
    public static string? Resolve(string argument, string? raw, IReadOnlyList<string>? present, IReadOnlyList<string> canonical,
        IReadOnlyList<(string Value, string[] Words)> words, ICollection<string> notes, bool containsMatch = false)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;
        var typed = raw.Trim();
        var hit = Find(typed, present, canonical, words, containsMatch);
        if (hit is null) return typed;
        if (!string.Equals(hit, typed, StringComparison.Ordinal)) notes.Add($"{argument} '{typed}' read as '{hit}'");
        return hit;
    }

    private static string? Find(string typed, IReadOnlyList<string>? present, IReadOnlyList<string> canonical,
        IReadOnlyList<(string Value, string[] Words)> words, bool containsMatch)
    {
        var p = present ?? Array.Empty<string>();
        var exact = p.FirstOrDefault(v => v.Equals(typed, StringComparison.OrdinalIgnoreCase));
        if (exact is not null) return exact;
        var key = Key(typed);
        if (key.Length == 0) return null;
        var loose = p.FirstOrDefault(v => Key(v) == key);
        if (loose is not null) return loose;

        // a synonym: the meaning it stands for, then whichever spelling of that meaning the data uses
        var group = words.FirstOrDefault(g => Key(g.Value) == key || g.Words.Any(w => Key(w) == key));
        if (group.Value is not null)
        {
            var keys = group.Words.Select(Key).Append(Key(group.Value)).ToHashSet(StringComparer.Ordinal);
            var inData = p.FirstOrDefault(v => keys.Contains(Key(v)));
            if (inData is not null) return inData;
            var canon = canonical.FirstOrDefault(v => Key(v) == Key(group.Value));
            if (canon is not null) return canon;
        }

        var c = canonical.FirstOrDefault(v => Key(v) == key);
        if (c is not null) return c;

        if (containsMatch && key.Length >= 3)
        {
            var contains = p.Where(v => Key(v).Contains(key, StringComparison.Ordinal)).ToList();
            if (contains.Count == 1) return contains[0];
        }
        return null;
    }

    /// For a fixed list (sort, dimension, grain): the value, or the fallback with a note saying the text was not one.
    public static string Pick(string argument, string? raw, IReadOnlyList<string> allowed, IReadOnlyList<(string Value, string[] Words)> words,
        string fallback, ICollection<string> notes)
    {
        if (string.IsNullOrWhiteSpace(raw)) return fallback;
        var hit = Resolve(argument, raw, null, allowed, words, notes);
        if (hit is not null && allowed.Contains(hit, StringComparer.Ordinal)) return hit;
        notes.Add($"{argument} '{raw.Trim()}' is not one of {string.Join(", ", allowed)}; used '{fallback}'");
        return fallback;
    }

    /// For a fixed list whose wrong value must not be guessed (tier, asset kind): the value, or ArgumentException
    /// naming the values that exist.
    public static string? Strict(string argument, string? raw, IReadOnlyList<string> allowed, IReadOnlyList<(string Value, string[] Words)> words, ICollection<string> notes)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;
        var local = new List<string>();
        var hit = Resolve(argument, raw, null, allowed, words, local);
        if (hit is null || !allowed.Contains(hit, StringComparer.Ordinal))
            throw new ArgumentException($"{argument} '{raw.Trim()}' does not exist; the values are: {string.Join(", ", allowed)}");
        foreach (var n in local) notes.Add(n);
        return hit;
    }

    /// "a, b, c" bounded so a long report list cannot flood a tool result.
    public static string List(IReadOnlyList<string>? values, int max = 40)
    {
        if (values is null || values.Count == 0) return "(none)";
        var shown = string.Join(", ", values.Take(max));
        return values.Count > max ? $"{shown} ... and {values.Count - max} more" : shown;
    }

    /// Severity order for listing values (most severe first), anything unknown after.
    public static IReadOnlyList<string> OrderSeverities(IEnumerable<string> values) =>
        values.OrderBy(SeverityRank).ThenBy(v => v, StringComparer.OrdinalIgnoreCase).ToList();

    /// The shared rank (<see cref="SeverityOrder"/>, #246); a synonym ("severe", "p1") ranks as the value it means.
    private static int SeverityRank(string v)
    {
        var r = SeverityOrder.Rank(v);
        if (r != SeverityOrder.Other) return r;
        var k = Key(v);
        for (var i = 0; i < SeverityWords.Count; i++)
            if (Key(SeverityWords[i].Value) == k || SeverityWords[i].Words.Any(w => Key(w) == k)) return SeverityOrder.Rank(SeverityWords[i].Value);
        return SeverityOrder.Other;
    }
}
