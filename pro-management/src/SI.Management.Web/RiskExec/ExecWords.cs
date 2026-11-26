using SI.Management.Web.Pages;

namespace SI.Management.Web.RiskExec;

/// One headline tile in plain words: its label, the short line under the value ("what is this number"), and the tooltip that
/// says exactly what is counted (from the code that counts it).
public sealed record KpiText(string Key, string Label, string Sub, string Tip);

/// <summary>
/// #1382 (owner 2026-11-25, on the Executive overview / wall board tiles of 3.1.50: "improve the text, which are missing people dont
/// understand. the formula is also missing", "new what ?", "very high what ?" -- and: "this is for executives, they dont understand
/// and ask questions to understand"): THE WORDS of the executive tiles, in one place, so the wall board, the Executive overview and
/// report, the Risk Analysis page and the management mail say the same. Plain words for a reader who is not technical; each line
/// answers "what is this number and is it good or bad?"; the (i) beside a score holds the detail (<see cref="ProtectionScoreInfo"/>).
/// Every sentence is checked against the code that computes the number. PURE.
/// </summary>
public static class ExecWords
{
    /// The Protection Score's calculation in one or two plain sentences, with the install's values (null = the values are not
    /// known: the words name no number).
    public static string Formula(ProtectionModel? m)
    {
        if (m is null)
            return "Each asset starts at 100 and loses points for every problem still to fix – the more serious, the more points. The most critical assets (Tier 0) count most.";
        var total = m.Shares.Sum();
        string Share(int i) => Fmt.Num(total > 0 ? m.Shares[i] / total * 100 : 0, 0) + " %";
        var minor = m.MinorCap == 0 || (m.Medium == 0 && m.Low == 0) ? ", smaller ones do not count" : " and at most " + Fmt.Int(m.MinorCap) + " for all smaller ones together";
        return "Each asset starts at 100 and loses " + Fmt.Int(m.VeryHigh) + " points for every very high problem still to fix, " + Fmt.Int(m.High) + " for every high one" + minor + ". "
            + "The most critical assets count most: Tier 0 " + Share(0) + ", Tier 1 " + Share(1) + ", Tier 2 " + Share(2) + ", Tier 3 " + Share(3) + " of the score.";
    }

    /// The normal patch window in words: "30 days" when every asset type has the same, else per asset type; null = the settings
    /// could not be read (no number is made up).
    public static string? PatchWindow(AcceptedLifecycle life) =>
        !life.Readable || life.Grace.Count == 0 ? null
        : life.Grace.Select(g => g.Days).Distinct().Count() == 1 ? Days(life.Grace[0].Days)
        : string.Join(", ", life.Grace.Select(g => g.Type + " " + Days(g.Days)));

    private static string Days(int d) => Fmt.Int(d) + (d == 1 ? " day" : " days");

    /// The line under "Protection Score, within Accepted Lifecycle": the formula, then the one difference to Actual Risks.
    public static string LifecycleLine(AcceptedLifecycle life, ProtectionModel? m) =>
        Formula(m) + " Missing updates still inside our normal patch window" + (PatchWindow(life) is { } w ? " (" + w + ")" : "") + " do not count yet.";

    /// The line under "Protection Score, Actual Risks".
    public static string ActualLine(ProtectionModel? m) =>
        Formula(m) + " Every open problem counts at once – also an update released yesterday.";

    /// Said after a tile's line, beside the (i).
    public const string InfoHint = "The (i) shows the full calculation.";

    /// The version from which the Protection Score is calculated the new way (#1361: the tier-share score of the assets' health).
    public const string NewScoreSince = "3.1.46";

    /// The note of a score change between two runs calculated in different ways.
    public const string NotComparable = "not comparable: the score is calculated in a new way since version " + NewScoreSince;

    /// The unit of a score change.
    public const string ScoreUnit = " points";

    // ---- the tile of the open findings with no date (#860) -------------------------------------------------------------

    public const string NoDateLabel = "Open issues with no start date";
    public const string NoDateSub = "We cannot tell how old they are, so they always count against the score.";
    public const string NoDateTip = "Open findings the Protection Score counts that have no update release date, no first-seen date from the source and were not seen by SecurityInsight before. "
        + "Without a date they can never be inside the patch window, so they always count – in both views.";

    // ---- the wall board's headline row (Pages/Wallboard.cshtml; the counts: ProDataSql.KpisText, the close-loop days) --------

    public static readonly KpiText OpenFindings = new("findings", "Open security issues", "All findings of the latest scan, every severity.",
        "Every finding of the latest complete scan (vulnerabilities, misconfigurations, exposures; all severities) on the assets the board counts (active assets by default). One finding = one issue on one asset.");
    public static readonly KpiText Tier0Findings = new("tier0", "Open issues on Tier 0 assets", "On the most critical assets – fewer is better.",
        "Findings of the latest scan on Tier 0 assets: the assets that control identity or the whole estate (for example domain controllers, PKI, admin workstations).");
    public static readonly KpiText VeryHigh = new("very_high", "Very High issues", "The most serious level – fix these first.",
        "Findings of the latest scan with severity Very High (Critical in some sources): the top of the five levels Very High, High, Medium, Low, Informational.");
    public static readonly KpiText High = new("high", "High issues", "The second most serious level.",
        "Findings of the latest scan with severity High.");
    public static readonly KpiText AverageRisk = new("avg_risk", "Average risk score per finding", "How serious a typical issue is – lower is better.",
        "The risk scores of all findings of the latest scan divided by their number. A risk score combines severity, the asset's tier and risk factors; it has no upper limit. It does not grow just because more assets were scanned.");
    public static readonly KpiText HighestRisk = new("max_risk", "Highest risk score (one finding)", "The single most serious issue – lower is better.",
        "The risk score of the single worst finding of the latest scan.");
    public static readonly KpiText OpenVulns = new("open_vulns", "Open vulnerabilities", "Known software vulnerabilities (CVEs) per device, tracked until fixed.",
        "The open items of the vulnerability tracking at the end of the latest day: one per known vulnerability (CVE) per asset, open until SecurityInsight sees it gone or the asset is retired. A device missing one update can have many.");
    public static readonly KpiText NewVulns = new("new_vulns", "New vulnerabilities, last 7 days", "Weaknesses that appeared in the last 7 days.",
        "Vulnerability items opened in the last 7 days: a known vulnerability (CVE) seen on an asset for the first time.");
    public static readonly KpiText FixedVulns = new("fixed_vulns", "Fixed vulnerabilities, last 7 days", "Weaknesses that went away in the last 7 days – more is better.",
        "Vulnerability items closed as fixed in the last 7 days: the weakness was gone from an asset that was still scanned. Items closed because their asset was retired are not counted.");
    /// The days before the close-loop split its closes by reason: only the total is known.
    public static readonly KpiText ClosedVulns = new("closed_vulns", "Closed vulnerabilities, last 7 days", "Fixed, or the device was retired.",
        "Vulnerability items closed in the last 7 days: fixed, or their asset was retired. The split by reason comes with the next days of the vulnerability tracking.");
}
