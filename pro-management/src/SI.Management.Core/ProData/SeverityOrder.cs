namespace SI.Management.Core.ProData;

/// <summary>
/// THE ONE severity order of the web app: Very High (and Critical, the same step under another name), High,
/// Medium-High, Medium, Low, Informational, anything else, none. Every list, filter, chart series, export and SQL ORDER BY uses this rank,
/// never the alphabet (which reads High, Low, Medium, Very High). C# uses <see cref="Rank"/> / <see cref="Comparer"/>;
/// SQL uses <see cref="SqlRank"/> over a column, so both sides rank the same values the same way.
/// </summary>
public static class SeverityOrder
{
    /// Rank of the top severity step (Very High / Critical).
    public const int Top = 0;
    /// The steps counted as "top severities" in the measures (Very High / Critical and High).
    public const int TopSeverityMaxRank = 1;
    /// A severity text no step names (still listed, after the named ones).
    public const int Other = 6;
    /// No severity at all (empty, "(none)").
    public const int None = 7;

    /// The labels in rank order, as the reports write them (for option lists and help text).
    public static readonly IReadOnlyList<string> Labels = ["Very High", "High", "Medium-High", "Medium", "Low", "Informational"];

    /// The rank of one severity text: lower = more severe. Case, spaces, '-' and '_' do not matter.
    public static int Rank(string? severity)
    {
        if (string.IsNullOrWhiteSpace(severity)) return None;
        var k = Key(severity);
        return k switch
        {
            "veryhigh" or "critical" => 0,
            "high" => 1,
            "mediumhigh" => 2,
            "medium" or "moderate" => 3,
            "low" => 4,
            "informational" or "info" or "information" => 5,
            "none" or "(none)" => None,
            _ => Other,
        };
    }

    /// The SI word a stored severity is SHOWN as (owner 2026-10-15: severity uses the five SI words -- a source's or a
    /// connector's "critical" is "Very High"; only the risk rating says Critical): "critical" / "very-high" -> "Very High",
    /// "medium_high" -> "Medium-High", "moderate" -> "Medium", "info" -> "Informational"; anything else as it is.
    public static string Label(string? severity)
    {
        var r = Rank(severity);
        return r < Labels.Count ? Labels[r] : (severity ?? "").Trim();
    }

    /// True for the top severities the measures count (Very High / Critical and High).
    public static bool IsTop(string? severity) => Rank(severity) <= TopSeverityMaxRank;

    private static string Key(string s)
    {
        Span<char> buf = stackalloc char[Math.Min(s.Length, 64)];
        var n = 0;
        foreach (var c in s)
        {
            if (n == buf.Length) break;
            if (c is ' ' or '-' or '_') continue;
            buf[n++] = char.ToLowerInvariant(c);
        }
        return new string(buf[..n]);
    }

    /// Most severe first; equal ranks by name (ordinal, ignoring case) so the order is stable.
    public static readonly IComparer<string?> Comparer = Comparer<string?>.Create((a, b) =>
    {
        var r = Rank(a).CompareTo(Rank(b));
        return r != 0 ? r : StringComparer.OrdinalIgnoreCase.Compare(a ?? "", b ?? "");
    });

    /// Least severe first (the other direction of a severity column sort).
    public static readonly IComparer<string?> Ascending = Comparer<string?>.Create((a, b) => Comparer.Compare(b, a));

    /// Sorts severity texts most severe first.
    public static IOrderedEnumerable<T> BySeverity<T>(this IEnumerable<T> items, Func<T, string?> severity) => items.OrderBy(severity, Comparer);

    /// The same rank as a SQL expression over one column (an nvarchar severity). Used in ORDER BY and in sums of the
    /// top severities; the mapping is the C# <see cref="Rank"/> one.
    public static string SqlRank(string column)
    {
        var k = $"LOWER(REPLACE(REPLACE(REPLACE(LTRIM(RTRIM(COALESCE({column}, N''))), N' ', N''), N'-', N''), N'_', N''))";
        return $"CASE {k} WHEN N'veryhigh' THEN 0 WHEN N'critical' THEN 0 WHEN N'high' THEN 1 WHEN N'mediumhigh' THEN 2 WHEN N'medium' THEN 3 WHEN N'moderate' THEN 3 " +
               $"WHEN N'low' THEN 4 WHEN N'informational' THEN 5 WHEN N'info' THEN 5 WHEN N'information' THEN 5 " +
               $"WHEN N'' THEN {None} WHEN N'none' THEN {None} WHEN N'(none)' THEN {None} ELSE {Other} END";
    }
}
