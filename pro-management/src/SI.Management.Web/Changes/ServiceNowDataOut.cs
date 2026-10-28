namespace SI.Management.Web.Changes;

/// <summary>
/// #903 (owner 2026-10-26: "if active they should be part of the data out for both cmdb and vulnerability"): ONE ServiceNow
/// connector feeds BOTH ServiceNow data-out outputs (servicenow-ci and servicenow-vulnerable-item). It has the direction
/// 'data-out' (kind servicenow only), is always apply (data out has no test mode), Enabled = it sends, and AT MOST ONE is
/// switched on -- never a silent choice: two switched on is refused when staged (<see cref="Conflict"/>), at the review
/// (<see cref="FinalConflict"/>) and in the SQL write itself (ConnectorRepository.WriteSql), and the engine sends to neither
/// (SI-SnowVerify.ps1 Select-SISnowDataOutConnector). The vulnerability close-loop never runs it.
/// </summary>
public static class ServiceNowDataOut
{
    public const string Direction = "data-out";

    /// The two outputs a data-out connector feeds -- "Switch on" stages them on with it (SI_DataOut_Outputs).
    public static readonly IReadOnlyList<string> Outputs = ["servicenow-ci", "servicenow-vulnerable-item"];

    public static bool Is(string? kind, string? direction) =>
        string.Equals((kind ?? "").Trim(), "servicenow", StringComparison.OrdinalIgnoreCase) && string.Equals((direction ?? "").Trim(), Direction, StringComparison.OrdinalIgnoreCase);

    public static bool Is(ConnectorRow r) => Is(r.Kind, r.Direction);

    /// The data-out connectors switched on, by name.
    public static IReadOnlyList<string> On(IEnumerable<ConnectorRow> rows) =>
        rows.Where(r => Is(r) && r.Enabled).Select(r => r.Name).OrderBy(n => n, StringComparer.Ordinal).ToList();

    /// The plain words for two (or more) switched on.
    public static string TwoOnText(IReadOnlyList<string> on) =>
        $"{on.Count} ServiceNow data-out connectors are switched on ({string.Join(", ", on)}). Nothing is sent to ServiceNow until one is switched off -- SecurityInsight never chooses one for you.";

    /// PURE. Null = fine; else why the write may not be staged: it switches a data-out connector ON while another one is on.
    /// A write that keeps an already switched-on connector on is not refused (the state does not get worse; two on is shown).
    public static string? Conflict(ConnectorWrite w, IReadOnlyList<ConnectorRow> rows)
    {
        if (w.Action != "Set" || !w.Enabled || !Is(w.Kind, w.Direction)) return null;
        var cur = rows.FirstOrDefault(r => r.Name == w.Name);
        if (cur is not null && Is(cur) && cur.Enabled) return null;
        var others = rows.Where(r => r.Name != w.Name && Is(r) && r.Enabled).Select(r => r.Name).OrderBy(n => n, StringComparer.Ordinal).ToList();
        return others.Count == 0 ? null
            : $"{string.Join(", ", others)} {(others.Count == 1 ? "is" : "are")} already switched on as the ServiceNow data-out connector -- only one can send. Switch {(others.Count == 1 ? "it" : "them")} off in the same change set (stage that first), or here first.";
    }

    /// PURE. The data-out connectors switched on once every one of <paramref name="writes"/> is written over <paramref name="rows"/>.
    public static IReadOnlyList<string> OnAfter(IReadOnlyList<ConnectorRow> rows, IEnumerable<ConnectorWrite> writes)
    {
        var state = rows.ToDictionary(r => r.Name, r => Is(r) && r.Enabled, StringComparer.Ordinal);
        foreach (var w in writes)
            state[w.Name] = w.Action == "Set" && w.Enabled && Is(w.Kind, w.Direction);
        return state.Where(p => p.Value).Select(p => p.Key).OrderBy(n => n, StringComparer.Ordinal).ToList();
    }

    /// PURE. Null = fine; else why <paramref name="w"/> cannot be committed with the other pending changes: after all of them,
    /// two data-out connectors would be on, and this change is one that switches one on.
    public static string? FinalConflict(ConnectorWrite w, IReadOnlyList<ConnectorRow> rows, IEnumerable<ConnectorWrite> pending)
    {
        if (w.Action != "Set" || !w.Enabled || !Is(w.Kind, w.Direction)) return null;
        var on = OnAfter(rows, pending);
        return on.Count > 1 ? $"after these changes {string.Join(" and ", on)} would both be switched on as the ServiceNow data-out connector -- only one can send; stage switching the other one off too" : null;
    }

    /// The order a commit writes connector changes in: those that switch a data-out connector OFF first, so "Test off, Prod on"
    /// in one commit never meets the one-on rule half way.
    public static int CommitOrder(ConnectorWrite w) => w.Action == "Set" && w.Enabled && Is(w.Kind, w.Direction) ? 1 : 0;
}
