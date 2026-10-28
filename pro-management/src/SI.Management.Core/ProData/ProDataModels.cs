namespace SI.Management.Core.ProData;

/// <summary>
/// A statement plus its parameters. The text is ALWAYS one of the fixed templates in <see cref="ProDataSql"/> (a sort
/// fragment is picked from a whitelist, never taken from a caller); every caller value travels as a parameter.
/// </summary>
public sealed record SqlQuery(string Text, IReadOnlyDictionary<string, object?> Parameters);

/// One collection of Risk Analysis results loaded into SQL (sidata.Collection).
public sealed record CollectionInfo(string CollectionId, DateTime CollectionTime, string Kind, long? Rows, string? RunId);

/// The filters of the findings browser. Every value is optional; null = no filter. Validated by
/// <see cref="ProDataFilters.Normalize"/> before it reaches a query.
public sealed record FindingFilter
{
    public string? CollectionId { get; init; }
    public string? Tier { get; init; }
    public string? Severity { get; init; }
    public string? Domain { get; init; }
    public string? Report { get; init; }
    public string? AssetKind { get; init; }
    public string? Text { get; init; }
    public string? AssetKey { get; init; }
    /// What the signed-in user may see (#253, built from their scopes); null = no restriction.
    public VisibilityPredicate? Visibility { get; init; }
    /// #855: the CI lifecycle states the view counts (sidata.Finding.CiLifecycle); null = the default, ACTIVE CIs only.
    public LifecycleFilter? Lifecycle { get; init; }
    public string Sort { get; init; } = FindingSorts.Importance;
    public int Skip { get; init; }
    public int Take { get; init; } = 50;
}

public static class FindingSorts
{
    /// Most important first: asset tier (0 = most critical, unclassified last), then risk score high -> low.
    public const string Importance = "importance";
    public const string Risk = "risk";
    /// Most severe first (Very High, High, Medium, Low, Informational, none) -- by RANK, never alphabetically.
    public const string Severity = "severity";
    /// The other direction of the severity sort: least severe first, still by rank.
    public const string SeverityAscending = "severity-asc";
    public const string Asset = "asset";
    public const string Report = "report";
    public static readonly IReadOnlyList<string> All = [Importance, Risk, Severity, SeverityAscending, Asset, Report];
}

public sealed record FindingRow(string FindingId, string CollectionId, DateTime? CollectionTime, string AssetKey, string AssetName, string AssetKind,
    string ReportName, string SecurityDomain, string ConfigurationId, string Cve, string Title, string Severity, string Tier, double RiskScore)
{
    /// #264: the exemption mark the finding carried in its collection (read only where the database has it).
    public bool IsExempted { get; init; }
    /// Its end date at run time (null with <see cref="IsExempted"/> = no end date).
    public DateTime? ExemptedUntil { get; init; }
    /// #283: the finding's Category exactly as the Risk Analysis report carries it (level 2 under SecurityDomain, e.g.
    /// Identity / Authentication) -- read from its Risk Analysis row where the reader has it, else null.
    public string? Category { get; init; }
    /// #431: every kind the finding's CI is made of (';'-list, most descriptive first; <see cref="AssetKind"/> is the first).
    /// What the asset-kind filter and its counts match -- empty where the reader does not carry it.
    public string AssetKinds { get; init; } = "";

    /// #431: the kinds this finding counts under in the asset-kind filter -- every part of its CI, else its one AssetKind.
    public IReadOnlyList<string> KindsForFilter()
    {
        var all = (AssetKinds ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return all.Length > 0 ? all.Distinct(StringComparer.OrdinalIgnoreCase).ToList()
            : string.IsNullOrWhiteSpace(AssetKind) ? Array.Empty<string>() : [AssetKind];
    }
}

public sealed record FindingPage(IReadOnlyList<FindingRow> Rows, long Total, int Skip, int Take)
{
    /// #812: the default view (no CI, kind or text filter, the default order) reads the order and the totals the data sync
    /// stored for the collection; false = they are not written yet -- the page says the list is being prepared (it never
    /// counts and sorts every finding itself). <see cref="Schema"/> false = the database lacks the tables (the update adds them).
    public bool Prepared { get; init; } = true;
    public bool Schema { get; init; } = true;
}

public sealed record PivotCell(string Tier, string Severity, string Domain, long Findings, long Assets);

public sealed record FindingDetail(FindingRow Finding, string? DetailJson, string? AssetPropertiesJson, IReadOnlyList<(string Type, string Value)> Identifiers);

/// The trend analytics request over sidata.FindingDaily: one series per value of the chosen dimension.
public sealed record TrendRequest
{
    public int Days { get; init; } = 90;
    /// none | tier | severity | domain | report
    public string Dimension { get; init; } = TrendDimensions.Tier;
    public string Measure { get; init; } = TrendMeasures.Findings;
    public string? Tier { get; init; }
    public string? Severity { get; init; }
    public string? Domain { get; init; }
    public string? Report { get; init; }
    /// #855: the CI lifecycle states the trend counts (sidata.FindingDaily / AssetDaily.CiLifecycle); null = ACTIVE only.
    public LifecycleFilter? Lifecycle { get; init; }
}

public static class TrendDimensions
{
    public const string None = "none";
    public const string Tier = "tier";
    public const string Severity = "severity";
    public const string Domain = "domain";
    public const string Report = "report";
    public static readonly IReadOnlyList<string> All = [None, Tier, Severity, Domain, Report];
}

/// <summary>
/// What a trend draws. A finding's risk score is only meaningful per finding, so the score measures are the AVERAGE
/// risk score per finding and the HIGHEST one -- never the plain sum, which only grows with the number of findings
/// (12,461 findings "totalling" 105,548 says nothing anyone can act on).
/// </summary>
public static class TrendMeasures
{
    public const string Findings = "findings";
    public const string Assets = "assets";
    /// Average risk score per finding. ("score" is kept as the key so links made before the change still work.)
    public const string Score = "score";
    /// The highest risk score of any one finding.
    public const string MaxScore = "maxscore";
    /// Findings at the top severities (Very High / Critical and High).
    public const string TopSeverity = "topseverity";
    public static readonly IReadOnlyList<string> All = [Findings, Assets, Score, MaxScore, TopSeverity];
}

/// <summary>
/// One trend point of one group. ScoreTotal is carried only so groups can be COMBINED correctly (an average of several
/// groups is their summed score over their summed findings); it is never shown as a measure.
/// </summary>
/// <para>#295: <see cref="Assets"/> is the number of DISTINCT assets with findings in this group on this day (null = not
/// computed yet for that day). It is never a sum of smaller groups' counts -- an asset with findings in several groups
/// counts once in each group it is in, and once in their union.</para>
public sealed record TrendCell(DateOnly Day, string Dimension, long Findings, long? Assets, double ScoreTotal, string? CollectionId = null,
    double? ScoreMax = null, long TopSeverityFindings = 0)
{
    /// Average risk score per finding (null when there is no finding).
    public double? ScoreAverage => Findings > 0 ? ScoreTotal / Findings : null;
}

/// How several trend cells combine into one value of a measure (a day's "Other" series, a total line).
public static class TrendMath
{
    public static double? Combine(IEnumerable<TrendCell> cells, string measure)
    {
        var list = cells as IReadOnlyCollection<TrendCell> ?? cells.ToList();
        if (list.Count == 0) return null;
        return measure switch
        {
            // #295: distinct counts do not add up -- one group's count stands; several groups (a day's "Other") have no
            // honest combined count from these cells (an asset can be in several), so it is unknown, never their sum
            TrendMeasures.Assets => list.Select(c => c.Dimension).Distinct(StringComparer.Ordinal).Count() == 1 && list.Select(c => c.Day).Distinct().Count() == 1
                ? list.Max(c => c.Assets) : null,
            TrendMeasures.Score => list.Sum(c => c.Findings) is var n and > 0 ? list.Sum(c => c.ScoreTotal) / n : null,
            TrendMeasures.MaxScore => list.Max(c => c.ScoreMax),
            TrendMeasures.TopSeverity => list.Sum(c => c.TopSeverityFindings),
            _ => list.Sum(c => c.Findings),
        };
    }

    public static string Label(string? measure) => measure switch
    {
        TrendMeasures.Assets => "Assets with findings",
        TrendMeasures.Score => "Average risk score per finding",
        TrendMeasures.MaxScore => "Highest risk score",
        TrendMeasures.TopSeverity => "Very High + High findings",
        _ => "Findings",
    };
}

public sealed record LifecycleDay(DateOnly Day, long Opened, long Closed, long Reopened, long? OpenAtEndOfDay)
{
    /// #855 W9: the closes by reason -- fixed (Remediated), asset retired (AssetRetired), any other reason. Null = the day was
    /// worked out before the split existed (only the total is known).
    public long? ClosedFixed { get; init; }
    public long? ClosedRetired { get; init; }
    public long? ClosedOther { get; init; }
}

/// One bucket of the closure dashboard (a day, a week starting Monday, or a month).
public sealed record LifecycleBucket(DateOnly Start, string Label, long Opened, long Closed, long Reopened, long? OpenAtEnd)
{
    /// #855 W9: the closes by reason (null when a day of the bucket predates the split).
    public long? ClosedFixed { get; init; }
    public long? ClosedRetired { get; init; }
    public long? ClosedOther { get; init; }
}

public static class Grains
{
    public const string Day = "day";
    public const string Week = "week";
    public const string Month = "month";
    public static readonly IReadOnlyList<string> All = [Day, Week, Month];
}

public sealed record OpenVulnCell(string Severity, string Tier, long Items);

/// The open vulnerabilities by severity and tier as a page shows them: Known = false when they could not be counted in time
/// (not counted by the data sync yet, and the page's own count ran out of time) -- the page says so and shows no numbers.
/// CountedAt = when the data sync counted them (null = counted for this request).
public sealed record OpenVulnCounts(IReadOnlyList<OpenVulnCell> Cells, bool Known, DateTime? CountedAt = null);

public sealed record TimeToFixRow(string Severity, long Fixed, double? MedianDays, double? P90Days);

/// The wall board's headline numbers. VeryHigh counts the top severity step (Very High, also written Critical).
/// The risk score is shown per finding (average) and at its highest, never summed.
public sealed record WallboardKpis(DateTime? CollectionTime, long Findings, long Tier0Findings, long VeryHigh, long High, double? AverageRiskScore, double? HighestRiskScore);

public sealed record TierCount(string Tier, long Assets);
/// The Unclassified findings of the newest collection, as the tier board explains them: how many, on how many assets
/// (the assets of the board's Unclassified lane that have findings), and how many have no asset at all (those cannot be on
/// the board -- the finding names no asset id). "Unclassified" is one definition everywhere: the tier is not 0..3
/// (<see cref="ProDataSql.TierExpr"/>), and a finding's tier is its asset's tier (the data load fills it from the asset).
public sealed record UnclassifiedFindings(long Findings, long Assets, long WithoutAsset);
/// Assets of one tier set by one source. <see cref="Source"/> is empty for the assets whose source was not recorded:
/// those are counted as "set by an unknown source", never shown as a source chip of their own (see <see cref="TierSources"/>).
public sealed record TierSource(string Tier, string Source, long Assets)
{
    public bool Known => TierSources.IsKnown(Source);
}

/// <summary>
/// Which tier sources the board shows as chips (and filters by). A profiler writes SI_TierSetBy as the source(s) whose
/// claim equals the tier ('rule', 'logon', 'entra-role+azure-role', 'default', ...). An empty value (nothing recorded)
/// and 'unattributed' (claims exist but none equals the tier) say nothing about who set the tier, so they are counted
/// as an unknown source and never get a chip.
/// </summary>
public static class TierSources
{
    public const string Unattributed = "unattributed";

    public static bool IsKnown(string? source) =>
        !string.IsNullOrWhiteSpace(source) && !source.Trim().Equals(Unattributed, StringComparison.OrdinalIgnoreCase)
        && !source.Trim().StartsWith('(');

    /// The known sources of one SI_TierSetBy value ('software+logon' -> software, logon); none when unknown.
    public static string[] Split(string? setBy) =>
        string.IsNullOrWhiteSpace(setBy) ? Array.Empty<string>()
        : setBy.Split('+', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Where(IsKnown).ToArray();
}

/// One asset card on the tier board.
public sealed record TierAsset(string AssetKey, string AssetName, string AssetKind, string Tier, DateTime? LastSeen, string? TierSetBy, string? TierReason, string? TierClaimsJson);

public sealed record TierBoardRequest
{
    public string Tier { get; init; } = "0";
    public string? AssetKind { get; init; }
    public string? Text { get; init; }
    /// Only the assets this one known source set (a chip on the board), e.g. 'api-permission'; null = every asset.
    public string? Source { get; init; }
    public int Skip { get; init; }
    public int Take { get; init; } = 60;
}

/// #292: a Tier-0 asset on the wall board -- its Very High and High VULNERABILITIES (findings with a CVE) in the newest
/// collection, and its total risk score.
public sealed record Tier0Asset(string AssetKey, string AssetName, string AssetKind, long VeryHigh, long High, double RiskTotal);
