using System.Globalization;

namespace SI.Management.Core.ProData;

// #855 THE LIFECYCLE A VIEW COUNTS (owner 2026-10-21: "we need to be able to trust all data" / "sweep the code for every views
// use the correct filters" / "default filter is active, so it should be active only"). ONE type every reader of CIs, their
// findings or an aggregate built from them takes: which CI lifecycle states the view counts. The default is ACTIVE -- a request
// that names none gets it, and the page says so (the ViewScope line); a person chooses Not seen, Retired or All. The stored
// value is sidata.Ci.Lifecycle (active | not_seen | retired), carried as sidata.Finding.CiLifecycle and as a key / column of the
// derived tables (sql\si-data-schema.sql "THE CI LIFECYCLE ON EVERY FINDING"). A NULL there -- a finding no CI carries, or a
// row stored before the lifecycle was stamped -- counts as ACTIVE (its asset is not known to be gone). What "active", "not
// seen" and "retired" mean comes from the settings in force (CiLifecycleRules), never from a day count of the view's own (#859).

/// <summary>The CI lifecycle states a view counts: one or more of active / not_seen / retired, or every state (All).</summary>
public sealed record LifecycleFilter
{
    /// The address parameter every view reads its lifecycle choice from (the CI list's own name).
    public const string Parameter = "lifecycle";

    /// The stored states, in the order the views offer them.
    public static readonly IReadOnlyList<string> Known = new[] { "active", "not_seen", "retired" };

    /// The states counted, in the stored order; null = every state (All).
    public IReadOnlyList<string>? States { get; }

    /// True when the request named no lifecycle and the view's default (active) is in force -- the page says so.
    public bool IsDefault { get; }

    private LifecycleFilter(IReadOnlyList<string>? states, bool isDefault) { States = states; IsDefault = isDefault; }

    /// THE DEFAULT of every view: active CIs only.
    public static LifecycleFilter Active { get; } = new(new[] { "active" }, true);

    /// Every lifecycle state (the person cleared the default: lifecycle=all).
    public static LifecycleFilter All { get; } = new(null, false);

    /// The named states (unknown names are left out; none left = the default).
    public static LifecycleFilter Of(params string[] states) => From(states, defaulted: false);

    public bool IsAll => States is null;
    public bool IsActiveOnly => States is { Count: 1 } s && s[0] == "active";

    /// <summary>
    /// PURE. The filter of a request's lifecycle values (the parameter may repeat, or carry several values '|' / ','
    /// separated -- the CI list's multi-filter): none, or only unknown values = the default (active); "all" = every state;
    /// all three states named = every state.
    /// </summary>
    public static LifecycleFilter Parse(IEnumerable<string?>? values)
    {
        var raw = (values ?? Array.Empty<string?>())
            .SelectMany(v => (v ?? "").Split(new[] { '|', ',' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            .Select(Normalise).Where(v => v.Length > 0).ToList();
        if (raw.Contains(CiLifecycleDefinitions.ClearedFilter)) return All;
        return From(raw, defaulted: true);
    }

    private static LifecycleFilter From(IEnumerable<string> names, bool defaulted)
    {
        var set = Known.Where(s => names.Select(Normalise).Contains(s)).ToList();
        if (set.Count == 0) return Active;
        if (set.Count == Known.Count) return All;
        return new LifecycleFilter(set, false);
    }

    /// "Not seen" / "not-seen" / "not_seen" -> "not_seen"; "All" -> "all".
    private static string Normalise(string? v) => (v ?? "").Trim().ToLowerInvariant().Replace('-', '_').Replace(' ', '_');

    /// <summary>
    /// PURE. The SQL predicate on a lifecycle column (e.g. "f.CiLifecycle"): written from the FIXED state names only, never
    /// from the request's text. A NULL value counts as active. All = "1 = 1".
    /// </summary>
    public string Sql(string column)
    {
        if (States is null) return "1 = 1";
        var inList = States.Count == 1 ? column + " = N'" + States[0] + "'" : column + " IN (" + string.Join(", ", States.Select(s => "N'" + s + "'")) + ")";
        return States.Contains("active") ? "(" + inList + " OR " + column + " IS NULL)" : inList;
    }

    /// <summary>PURE. The same test on a value in memory (null / "" = active).</summary>
    public bool Includes(string? lifecycle)
    {
        if (States is null) return true;
        var v = string.IsNullOrWhiteSpace(lifecycle) ? "active" : Normalise(lifecycle);
        return States.Contains(v);
    }

    /// A stable key for result caches ("active", "not_seen,retired", "all").
    public string Key => States is null ? "all" : string.Join(",", States);

    /// The address value that asks for exactly this filter (null = the default: no parameter).
    public string? QueryValue => IsDefault ? null : States is null ? CiLifecycleDefinitions.ClearedFilter : string.Join("|", States);

    /// <summary>
    /// PURE. What the view counts, in plain words with the numbers in force -- the ViewScope line's lifecycle part. <paramref name="what"/>
    /// names the view's things ("CIs", "findings", "devices").
    /// </summary>
    public string Words(CiLifecycleRules rules, string what = "CIs")
    {
        var seen = CiLifecycleRules.Days(rules.SeenWithinDays);
        if (States is null)
            return string.Create(CultureInfo.InvariantCulture, $"{what} of every lifecycle (active, not seen and retired; active = seen by a source within the last {seen})");
        var names = string.Join(" or ", States.Select(s => CiLifecycleDefinitions.Label(s).ToLowerInvariant()));
        if (IsDefault)
            return string.Create(CultureInfo.InvariantCulture, $"{what} of active CIs only (the default): seen by a source within the last {seen}. Choose Not seen, Retired or All to see the others");
        return string.Create(CultureInfo.InvariantCulture, $"{what} of {names} CIs only (active = seen by a source within the last {seen}; not seen = not seen for longer, in its grace period of {rules.GraceText}; retired = past it)");
    }

    /// <summary>
    /// PURE. The words of a view that is BUILT over active CIs only (the facets, the Summary groupings, the remediations: their
    /// stored rows carry no lifecycle) -- it offers no choice and says where the others are.
    /// </summary>
    public static string ActiveOnlyWords(CiLifecycleRules rules, string what = "findings") =>
        string.Create(CultureInfo.InvariantCulture,
            $"{what} of active CIs only: seen by a source within the last {CiLifecycleRules.Days(rules.SeenWithinDays)} (this view is built over active CIs; the CI list and the findings browser show not seen and retired CIs)");
}
