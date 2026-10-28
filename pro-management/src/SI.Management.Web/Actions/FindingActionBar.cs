using System.Globalization;
using SI.Management.Web.Exemptions;

namespace SI.Management.Web.Actions;

/// <summary>
/// What the shared action bar (<c>Pages/Shared/_FindingActions.cshtml</c>, #272) needs to know about the grid it sits on:
/// where the selection comes from (<see cref="SelectionSources"/>), the collection, the strip's element id, how many
/// findings the filter matches and whether it narrows the collection (the #264 guard of "all matching"), and what the
/// page's own selection form does NOT already carry. The bar is rendered INSIDE the page's selection form, so the selected
/// keys and the filter travel with that form; the bar adds only the rest.
/// </summary>
public sealed record FindingActionBar
{
    public required string Source { get; init; }
    public string? CollectionId { get; init; }
    /// The element id of the strip that shows when rows are selected (the grid's data-strip points at it).
    public required string StripId { get; init; }
    /// How many findings the current filter matches (the "all N matching" count).
    public long Total { get; init; }
    public bool Narrowed { get; init; }
    public int BulkMax { get; init; } = ExemptionSettings.Values.Defaults.BulkMax;
    /// The selection form is a GET form (the collection grids): the bar adds the antiforgery token its POST buttons need.
    public bool InGetForm { get; init; }
    /// The grid's "show only these" (a GET of the same page with the selection).
    public bool ShowOnlySelected { get; init; }
    /// The department of a department page (the task form offers its people).
    public int? DepartmentId { get; init; }
    /// Hidden fields the selection form does not carry yet (e.g. the Unassigned queue's marker).
    public IReadOnlyList<(string Key, string Value)> Hidden { get; init; } = Array.Empty<(string, string)>();

    /// #286: the grid the rows are on (its spec name -- posted as "grid") and, for an aggregated grid, its row-to-finding
    /// mapping: the bar then acts on the findings each selected row stands for, and the dialog says "N rows = M findings".
    public string? Grid { get; init; }
    public FindingRowMap? Map { get; init; }
    /// "All matching" is offered (an aggregated grid offers it only where the server can rebuild the page's rows).
    public bool AllMatching => Map is null || Map.AllMatching;

    /// #264: may "apply to all N matching" be offered at all (a narrowing filter, at most SIWeb_Exemption_BulkMax)?
    public ExemptionBulkGuard.Verdict Guard => ExemptionBulkGuard.Check(Narrowed, Total, BulkMax);

    public static string IdOf(string s) => System.Text.RegularExpressions.Regex.Replace(s, "[^A-Za-z0-9_-]", "-");
    public static string Count(long n) => n.ToString("N0", CultureInfo.CurrentCulture);
}
