namespace SI.Management.Web.Pages;

/// <summary>
/// THE date filter of "+ Add filter" (owner 2026-10-19: "date ranges with quick picks 7/30/90 days"): the quick picks are
/// links (the last 7, 30 or 90 days -- one click, no form), and a from..to box for a range of days
/// (yyyy-MM-dd..yyyy-MM-dd, either end may be left out). The server's rule is <see cref="SI.Management.Core.ProData.GridSql.Dates"/>.
/// </summary>
/// <param name="Id">The element id.</param>
/// <param name="Name">The address parameter ("f.LastSeen").</param>
/// <param name="Label">What the column is.</param>
/// <param name="Form">The filter form the box belongs to.</param>
/// <param name="Current">The filter as asked now ("30d", "2026-10-01..2026-10-19"), or null.</param>
/// <param name="Href">The view's address with this filter set to a value (null removes it).</param>
public sealed record DateFilter(string Id, string Name, string Label, string Form, string? Current, Func<string?, string> Href)
{
    /// The quick picks: (value, words).
    public IReadOnlyList<(string Value, string Words)> Picks =>
        SI.Management.Core.ProData.GridSql.DayPicks.Select(d => (d.ToString(System.Globalization.CultureInfo.InvariantCulture) + "d", "Last " + d + " days")).ToList();

}
