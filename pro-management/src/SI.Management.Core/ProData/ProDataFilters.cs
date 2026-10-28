using System.Text.RegularExpressions;

namespace SI.Management.Core.ProData;

/// <summary>
/// The ONLY way a caller's filter value reaches a SQL parameter. Values are bounded (length, character set, range) and
/// refused with ArgumentException when they do not fit -- never trimmed into something different. They still travel
/// as parameters: this is the second line, the fixed templates are the first.
/// </summary>
public static partial class ProDataFilters
{
    public const int MaxTake = 500;
    public const int MaxExport = 50_000;
    public const int MaxTextLength = 200;
    public const int MaxDays = 730;
    public const string Unclassified = "Unclassified";
    public static readonly IReadOnlyList<string> Tiers = ["0", "1", "2", "3", Unclassified];
    public static readonly IReadOnlyList<string> AssetKinds = ["endpoint", "identity", "azure", "publicip"];

    // Report names, domains, severities: letters, digits and the punctuation real values carry.
    [GeneratedRegex(@"^[\p{L}\p{N}][\p{L}\p{N} ._:/()+#\-]{0,199}$", RegexOptions.CultureInvariant)]
    private static partial Regex LabelPattern();

    // A collection or finding id: a number, a GUID, or a short token.
    [GeneratedRegex(@"^[A-Za-z0-9\-_.:]{1,64}$", RegexOptions.CultureInvariant)]
    private static partial Regex IdPattern();

    // An asset key: SI_CorrelationId / SI_AssetId shapes (ids, ARM paths, UPNs, FQDNs).
    [GeneratedRegex(@"^[\p{L}\p{N}][\p{L}\p{N} ._:/@()+#\-]{0,399}$", RegexOptions.CultureInvariant)]
    private static partial Regex AssetKeyPattern();

    /// Free search text: anything printable except control characters; matched literally (LIKE wildcards escaped).
    public static string? Text(string? v)
    {
        if (string.IsNullOrWhiteSpace(v)) return null;
        var t = v.Trim();
        if (t.Length > MaxTextLength) throw new ArgumentException($"the search text is longer than {MaxTextLength} characters");
        if (t.Any(char.IsControl)) throw new ArgumentException("the search text contains a control character");
        return t;
    }

    public static string? Label(string? v, string what)
    {
        if (string.IsNullOrWhiteSpace(v)) return null;
        var t = v.Trim();
        if (!LabelPattern().IsMatch(t)) throw new ArgumentException($"'{what}' may contain only letters, digits, spaces and . _ : / ( ) + # - (max 200)");
        return t;
    }

    public static string? Id(string? v, string what)
    {
        if (string.IsNullOrWhiteSpace(v)) return null;
        var t = v.Trim();
        if (!IdPattern().IsMatch(t)) throw new ArgumentException($"'{what}' is not a valid id");
        return t;
    }

    public static string? AssetKey(string? v)
    {
        if (string.IsNullOrWhiteSpace(v)) return null;
        var t = v.Trim();
        if (!AssetKeyPattern().IsMatch(t)) throw new ArgumentException("the asset key is not valid");
        return t;
    }

    public static string? Tier(string? v)
    {
        if (string.IsNullOrWhiteSpace(v)) return null;
        var t = v.Trim();
        if (t.StartsWith("Tier", StringComparison.OrdinalIgnoreCase)) t = t[4..].Trim();
        var hit = Tiers.FirstOrDefault(x => x.Equals(t, StringComparison.OrdinalIgnoreCase));
        return hit ?? throw new ArgumentException("tier must be 0, 1, 2, 3 or Unclassified");
    }

    /// One known tier source as the board's chips name it ('rule', 'api-permission', ...): letters, digits and '-' only.
    public static string? TierSource(string? v)
    {
        if (string.IsNullOrWhiteSpace(v)) return null;
        var t = v.Trim();
        if (!TierSourcePattern().IsMatch(t) || !TierSources.IsKnown(t)) throw new ArgumentException("the tier source is not valid");
        return t;
    }

    [GeneratedRegex(@"^[A-Za-z0-9][A-Za-z0-9\-]{0,63}$", RegexOptions.CultureInvariant)]
    private static partial Regex TierSourcePattern();

    public static string? Kind(string? v)
    {
        if (string.IsNullOrWhiteSpace(v)) return null;
        var hit = AssetKinds.FirstOrDefault(x => x.Equals(v.Trim(), StringComparison.OrdinalIgnoreCase));
        return hit ?? throw new ArgumentException("asset kind must be endpoint, identity, azure or publicip");
    }

    public static string Pick(string? v, IReadOnlyList<string> allowed, string fallback)
        => allowed.FirstOrDefault(a => a.Equals(v?.Trim(), StringComparison.OrdinalIgnoreCase)) ?? fallback;

    public static int Days(int days) => days is >= 1 and <= MaxDays ? days : throw new ArgumentException($"days must be between 1 and {MaxDays}");

    /// What separates several values of one filter (owner 2026-10-19: "all filters support multi select ... device + azure").
    /// No validated value may hold it (<see cref="Label"/>, <see cref="Tier"/> and <see cref="Kind"/> refuse a '|').
    public const char ValueSeparator = '|';

    /// <summary>
    /// A filter of one or more values ('|'-separated -- a page joins the values its multi-select sends): each value
    /// validated by <paramref name="one"/>, duplicates dropped, joined back in the order given; null = no filter. At most
    /// <see cref="GridSql.MaxValues"/> values.
    /// </summary>
    public static string? Many(string? v, Func<string?, string?> one)
    {
        if (string.IsNullOrWhiteSpace(v)) return null;
        var parts = v.Split(ValueSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(one).Where(x => x is not null).Select(x => x!).Distinct(StringComparer.Ordinal).ToList();
        if (parts.Count > GridSql.MaxValues) throw new ArgumentException($"at most {GridSql.MaxValues} values per filter");
        return parts.Count == 0 ? null : string.Join(ValueSeparator, parts);
    }

    /// The values of a normalised many-valued filter (none = no filter).
    public static IReadOnlyList<string> Values(string? joined) =>
        string.IsNullOrEmpty(joined) ? Array.Empty<string>() : joined.Split(ValueSeparator, StringSplitOptions.RemoveEmptyEntries);

    /// A normalised many-valued filter as the JSON array parameter its IN-list reads (OPENJSON); null = no filter.
    public static string? Json(string? joined) => string.IsNullOrEmpty(joined) ? null : System.Text.Json.JsonSerializer.Serialize(Values(joined));

    /// The whole filter, validated. Paging is clamped (a page size is not an injection vector, just a cost). Tier,
    /// severity, domain, report and asset kind may each hold several values (<see cref="Many"/>).
    public static FindingFilter Normalize(FindingFilter f) => f with
    {
        CollectionId = Id(f.CollectionId, "collection"),
        Tier = Many(f.Tier, Tier),
        Severity = Many(f.Severity, v => Label(v, "severity")),
        Domain = Many(f.Domain, v => Label(v, "domain")),
        Report = Many(f.Report, v => Label(v, "report")),
        AssetKind = Many(f.AssetKind, Kind),
        Text = Text(f.Text),
        AssetKey = AssetKey(f.AssetKey),
        Sort = Pick(f.Sort, FindingSorts.All, FindingSorts.Importance),
        Skip = Math.Clamp(f.Skip, 0, 10_000_000),
        Take = Math.Clamp(f.Take, 1, MaxTake),
    };

    public static TrendRequest Normalize(TrendRequest r) => r with
    {
        Days = Days(r.Days),
        Dimension = Pick(r.Dimension, TrendDimensions.All, TrendDimensions.Tier),
        Measure = Pick(r.Measure, TrendMeasures.All, TrendMeasures.Findings),
        Tier = Many(r.Tier, Tier),
        Severity = Many(r.Severity, v => Label(v, "severity")),
        Domain = Many(r.Domain, v => Label(v, "domain")),
        Report = Many(r.Report, v => Label(v, "report")),
    };

    public static TierBoardRequest Normalize(TierBoardRequest r) => r with
    {
        Tier = Tier(r.Tier) ?? "0",
        AssetKind = Kind(r.AssetKind),
        Text = Text(r.Text),
        Source = TierSource(r.Source),
        Skip = Math.Max(r.Skip, 0),   // #881 no ceiling of our own: past 1,000,000 the board showed that page again, silently
        Take = Math.Clamp(r.Take, 1, 200),
    };

    /// A user's text as a LIKE pattern matched literally: LIKE's own wildcards are bracket-escaped, then wrapped in %.
    public static string? Like(string? text) => text is null ? null : "%" + text.Replace("[", "[[]").Replace("%", "[%]").Replace("_", "[_]") + "%";
}
