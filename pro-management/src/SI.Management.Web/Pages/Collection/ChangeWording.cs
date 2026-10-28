namespace SI.Management.Web.Pages.Collection;

/// <summary>
/// What a person reads for the change between two collections ("What changed", its export, the lifecycle counts). The
/// codes stay what the database, the URLs (f.Change=new|gone|changed) and saved links carry; only the words change.
/// <para>ABSENCE IS NOT REMEDIATION: a finding missing from the newer collection is "No longer reported", never fixed,
/// closed or gone. The more precise words are used only where the same read proves them
/// (<see cref="SI.Management.Core.ProData.CollectionViewSql.FindingChanges"/>' ChangeReason).</para>
/// </summary>
public static class ChangeWording
{
    public const string New = "new", Gone = "gone", Changed = "changed", Unchanged = "unchanged";
    /// The reasons the comparison can prove for a finding missing from the newer collection.
    public const string Absent = "absent", ExemptedReason = "exempted";

    /// The cell of a side the row does not have (the before of a new row, the after of a row no longer reported).
    public const string NoValue = "—";

    public const string NoLongerReported = "No longer reported";
    public const string NotFound = "Not found in the newest run";
    public const string Exempted = "Exempted";

    public const string NoLongerReportedTip =
        "Not in the newest run. This does not prove it was fixed: the asset may be gone, out of scope, or not collected this time.";
    public const string NotFoundTip =
        "The asset is in the newest run, but this finding was not reported on it. This does not prove it was fixed: it may be out of scope or not collected this time.";
    public const string ExemptedTip =
        "The newest run still reports it, but it is exempted, and this view leaves exempted findings out.";
    public const string AssetNoLongerReportedTip =
        "No finding on this asset in the newest run. This does not prove they were fixed: the asset may be gone, out of scope, or not collected this time.";

    /// The words of a change kind (and, for a finding no longer reported, of what the comparison proved about it).
    public static string Label(string? code, string? reason = null) => code switch
    {
        New => "New",
        Gone => reason switch { Absent => NotFound, ExemptedReason => Exempted, _ => NoLongerReported },
        Changed => "Changed",
        Unchanged => "Unchanged",
        null => "",
        _ => code,
    };

    /// The explanation shown on hover (null = none).
    public static string? Tooltip(string? code, string? reason = null, bool asset = false) => code switch
    {
        New => asset ? "Not in the earlier run; in the newest one." : "Not in the earlier run; reported in the newest one.",
        Gone => asset ? AssetNoLongerReportedTip : reason switch { Absent => NotFoundTip, ExemptedReason => ExemptedTip, _ => NoLongerReportedTip },
        Changed => asset ? "In both runs, with a different number of findings, total risk or tier." : "In both runs, with a different severity, risk score, tier or rating.",
        _ => null,
    };

    /// True when the column is the side this row does not have: a "before" column of a new row, an "after" column of a
    /// row no longer reported. Its cell reads <see cref="NoValue"/>, never "Unclassified" or blank.
    public static bool MissingSide(string column, string? code) =>
        (code == New && column.EndsWith("Before", StringComparison.Ordinal)) || (code == Gone && column.EndsWith("After", StringComparison.Ordinal));

    /// The hover text of a risk change that is the whole risk of one side (a new row, or one no longer reported).
    public static string? RiskChangeTooltip(string? code, bool asset = false) => code switch
    {
        Gone => asset
            ? "The whole risk counts as the change because the asset has no finding in the newest run -- not because they were fixed."
            : "The whole risk counts as the change because the finding is not in the newest run -- not because it was fixed.",
        New => asset
            ? "The whole risk counts as the change because the asset had no finding in the earlier run."
            : "The whole risk counts as the change because the finding was not in the earlier run.",
        _ => null,
    };

    /// The text of the Change filter's chip: "any" for every kind of change (the view's default), else the kinds' words.
    public static string Chip(IReadOnlyList<string> values)
    {
        var set = values.ToHashSet(StringComparer.Ordinal);
        if (set.SetEquals(new[] { New, Gone, Changed })) return "any";
        if (set.SetEquals(new[] { New, Gone, Changed, Unchanged })) return "any, or unchanged";
        return string.Join(" or ", values.Select(v => Label(v)));
    }
}
