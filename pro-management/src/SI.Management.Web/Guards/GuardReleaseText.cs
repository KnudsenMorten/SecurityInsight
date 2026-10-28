using System.Globalization;
using System.Text.RegularExpressions;

namespace SI.Management.Web.Guards;

/// <summary>
/// One held set in ONE PLAIN SENTENCE, in customer words, from its own stored numbers (operator 2026-10-09: "this is way too
/// complex and honestly hard to explain to people" / "unreadable"): no ids, no hashes, no run states, no "(s)" -- real
/// singular and plural. Times are written as "yyyy-MM-dd HH:mm UTC" inside a data-utc element, so the browser shows them
/// in the viewer's own time.
///   vulnerability closes  "66 vulnerabilities on 1 device would be marked as fixed in your vulnerability list (SQL). Held
///                          because that is unusually many at once."
///   a held collection     "The Risk Analysis of 2026-10-08 21:15 UTC (12,546 findings) wasn't loaded because its run
///                          failed. Release to load it anyway; what it missed stays unknown."
///   a CMDB hand-off batch "300 configuration items would disappear from the ServiceNow hand-off (25 % of 1,200). ..."
///   asset metadata        "The asset data from entra-user changed by 25 % (1,200 before, 900 now). ..."
/// The technical side (ids, the run's own words, the plan hash) is the row's Details. PURE.
/// </summary>
public static partial class GuardReleaseText
{
    private static CultureInfo C(CultureInfo? c) => c ?? SI.Management.Core.ProData.ScoreFormat.Culture;
    private static string N(double v, CultureInfo c) => Math.Abs(v % 1) < 1e-9 ? v.ToString("N0", c) : v.ToString("#,0.#", c);

    /// "1 device" / "66 devices" -- real singular and plural, never "(s)".
    public static string Count(double n, string one, string many, CultureInfo? culture = null) => N(n, C(culture)) + " " + (Math.Abs(n - 1) < 1e-9 ? one : many);

    /// A fact of the held set's summary as a number, or null when it is not stored.
    private static double? Num(GuardRelease r, string name) =>
        double.TryParse(r.Fact(name), NumberStyles.Float, CultureInfo.InvariantCulture, out var d) ? d : null;

    /// The UTC text the browser formatter rewrites to local time (the element carries data-utc).
    public static string When(DateTime? t) => t is { } x ? DateTime.SpecifyKind(x, DateTimeKind.Utc).ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture) + " UTC" : "";

    public static bool IsHandoff(GuardRelease r) => string.Equals(r.Kind, "sql-cmdb", StringComparison.OrdinalIgnoreCase);
    public static bool IsAssetProperties(GuardRelease r) => string.Equals(r.Kind, "asset-properties", StringComparison.OrdinalIgnoreCase);

    /// Where a vulnerability connector writes, in words: never the connector's id.
    public static string Target(string? kind) => (kind ?? "").ToLowerInvariant() switch
    {
        "servicenow" => "ServiceNow",
        "rest" => "your vulnerability system (REST)",
        _ => "your vulnerability list (SQL)",
    };

    /// The source of a held asset-metadata collection ('asset-properties/&lt;profiler&gt;/&lt;source&gt;' or its summary).
    private static string Source(GuardRelease r) =>
        r.Fact("Source") is { Length: > 0 } s ? s : (r.Connector ?? "").Split('/', StringSplitOptions.RemoveEmptyEntries).LastOrDefault() ?? r.Connector;

    [GeneratedRegex(@"(\d+) (?:of \d+ )?reports? (?:failed|produced no|returned nothing)", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex FailedReports();

    /// Why a collection is held, in words (from the run's own message).
    public static string Cause(GuardRelease r)
    {
        var all = (r.HoldReason ?? "") + " " + (r.RunDetail ?? "");
        if (FailedReports().Match(all) is { Success: true } m && int.TryParse(m.Groups[1].Value, out var k)) return Count(k, "report", "reports", CultureInfo.InvariantCulture) + " failed";
        if (all.Contains("still running", StringComparison.OrdinalIgnoreCase)) return "its run had not finished";
        if (all.Contains("no run-health", StringComparison.OrdinalIgnoreCase) || all.Contains("no record", StringComparison.OrdinalIgnoreCase)) return "its run left no record";
        if (all.Contains("success-partial", StringComparison.OrdinalIgnoreCase)) return "its run was incomplete";
        return "its run failed";
    }

    /// THE sentence of one held set: what would happen, and why it is held.
    public static string Sentence(GuardRelease r, CultureInfo? culture = null)
    {
        var c = C(culture);
        if (r.IsCollection)
            return $"The Risk Analysis of {(When(r.CollectionTime) is { Length: > 0 } w ? w : "an earlier run")} ({Count(r.CollectionRows, "finding", "findings", c)}) wasn't loaded because {Cause(r)}. Release to load it anyway; what it missed stays unknown.";
        if (IsHandoff(r))
            return Num(r, "Disappeared") is { } gone
                ? $"{Count(gone, "configuration item", "configuration items", c)} would disappear from the ServiceNow hand-off{(Num(r, "ChangePercent") is { } pct && Num(r, "PreviousCis") is { } prev ? $" ({N(Math.Abs(pct), c)} % of {N(prev, c)})" : "")}. Held because that is an unusually large change."
                : $"This run's CMDB hand-off ({Count(r.HeldCount, "configuration item", "configuration items", c)}) changed unusually much. Held so a broken collection doesn't reach ServiceNow.";
        if (IsAssetProperties(r))
            return $"The asset data from {Source(r)} changed by {(Num(r, "ChangePercent") is { } p ? N(Math.Abs(p), c) + " %" : "an unusual amount")}{(Num(r, "PreviousRows") is { } before ? $" ({N(before, c)} before, {N(r.HeldCount, c)} now)" : "")}. Held so a broken collection doesn't reach your CMDB.";
        return $"{Count(r.HeldCount, "vulnerability", "vulnerabilities", c)}{(r.Assets > 0 ? " on " + Count(r.Assets, "device", "devices", c) : "")} would be marked as fixed in {Target(r.Kind)}. Held because that is unusually many at once.";
    }

    /// What a release does, for the confirm dialog and the Details.
    public static string IfRelease(GuardRelease r, CultureInfo? culture = null)
    {
        var c = C(culture);
        if (r.IsCollection)
            return $"The Risk Analysis of {(When(r.CollectionTime) is { Length: > 0 } w ? w : "an earlier run")} ({Count(r.CollectionRows, "finding", "findings", c)}) is loaded with the next data sync and marked partial wherever it is shown. What it missed stays unknown, not resolved.";
        if (IsHandoff(r))
            return $"ServiceNow imports this run's hand-off of {Count(r.HeldCount, "configuration item", "configuration items", c)} with its next import.";
        if (IsAssetProperties(r))
            return $"The new asset data from {Source(r)} ({Count(r.HeldCount, "object", "objects", c)}) goes to your CMDB and vulnerability system with the next run.";
        return $"{Count(r.HeldCount, "vulnerability", "vulnerabilities", c)} {(r.HeldCount == 1 ? "is" : "are")} marked as fixed in {Target(r.Kind)} with the next run -- only those that are still gone then.";
    }

    /// What stays as it is when nobody releases it.
    public static string IfLeft(GuardRelease r) =>
        r.IsCollection ? "Nothing is lost: the next complete Risk Analysis is loaded as normal."
        : IsHandoff(r) ? "Nothing is lost: ServiceNow keeps importing the previous hand-off until a run is back within the limit."
        : IsAssetProperties(r) ? "Nothing is lost: the previous asset data of this source is used until a run is back within the limit."
        : "Nothing is lost: the vulnerabilities stay open in your list exactly as they were.";
}
