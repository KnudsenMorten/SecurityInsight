namespace SI.Management.Web.Pages;

/// One choice of a <see cref="MultiFilter"/>: the value sent, the words shown and, when known, how many items it holds.
public sealed record FilterChoice(string Value, string Label, long? Count = null);

/// <summary>
/// THE filter of every view (owner 2026-10-19: "all filters support multi select ... all views and filters must support
/// that"; Pages/Shared/_MultiFilter.cshtml): a disclosure with one checkbox per value and its count, "All" = nothing
/// ticked; values of ONE filter are OR-ed, different filters AND-ed (the server's rule). Every ticked value is one more
/// address parameter of the same name -- so a selection is in the URL (a link shares it), in a saved layout (the
/// remembered address state) and in every export (the export links carry the address). The counts are the choice's own
/// (<see cref="FilterChoice.Count"/>, exact only when nothing else narrows the view) or read when the filter is first
/// opened from <see cref="CountsUrl"/> (js/app/value-counts.js: counted under the view's OTHER filters). A guard test
/// (MultiFilterTests) fails a view that still renders a single-choice filter dropdown.
/// </summary>
public sealed record MultiFilter
{
    /// The element id (also the stem of the ids inside).
    public required string Id { get; init; }
    /// The address parameter every ticked value is sent as.
    public required string Name { get; init; }
    /// What the filter is ("Domain", "Severity").
    public required string Label { get; init; }
    public IReadOnlyList<FilterChoice> Choices { get; init; } = Array.Empty<FilterChoice>();
    /// The values ticked now (a chosen value the choices do not list is still shown, so it can be unticked).
    public IReadOnlyList<string> Chosen { get; init; } = Array.Empty<string>();
    /// Where the counts are read when the filter is first opened (null = the choices' own counts, or none).
    public string? CountsUrl { get; init; }
    /// One sentence shown with the choices (e.g. that the counts can overlap).
    public string? Note { get; init; }
    /// The form the checkboxes belong to (a filter in a table's header row sits outside its form).
    public string? Form { get; init; }
    /// In a grid's column-filter row: no visible label (the column header says it), the summary alone.
    public bool Compact { get; init; }
    /// The choices are not known when the page is drawn (a filter "+ Add filter" offers): they are the values the counts read
    /// returns when the filter is first opened (js/app/value-counts.js), each with its count.
    public bool Fill { get; init; }
    /// A filter with a NAMED default (the CI list's lifecycle: active): the value "All" is sent as, so ticking All clears the
    /// default instead of bringing it back (null = "All" sends nothing, the usual filter).
    public string? AllValue { get; init; }
    /// The text of the Apply button (a page whose filters submit together says "Apply").
    public string Apply { get; init; } = "Apply";
    /// The button only CLOSES the list, it submits nothing: the filter is one field of a larger form that is saved by its
    /// own button (the connector / workbook scope: the ticks are kept and staged with a reason -- a submitting "Done" sent
    /// the stage form without its reason and the ticks were lost, owner 2026-10-20).
    public bool ApplyCloses { get; init; }

    /// The most choices one filter lists (a filter of more values has a search box on its page).
    public const int MaxChoices = 200;

    /// The choices listed: the offered ones, then any chosen value they do not hold.
    public IReadOnlyList<FilterChoice> Listed =>
        Choices.Concat(Chosen.Where(c => !Choices.Any(x => string.Equals(x.Value, c, StringComparison.Ordinal))).Select(c => new FilterChoice(c, c)))
            .Take(MaxChoices).ToList();

    public bool IsChosen(string value) => Chosen.Contains(value, StringComparer.Ordinal);

    /// What the closed filter says: "All", the one value chosen, or "2 chosen".
    public string Summary => Chosen.Count switch
    {
        0 => "All",
        1 => Listed.FirstOrDefault(c => string.Equals(c.Value, Chosen[0], StringComparison.Ordinal))?.Label ?? Chosen[0],
        _ => Fmt.Int(Chosen.Count) + " chosen",
    };

    /// The values of one address parameter (it may repeat, or arrive '|'-joined from a link of another page).
    public static IReadOnlyList<string> ValuesOf(Microsoft.AspNetCore.Http.IQueryCollection query, string name) =>
        query[name].Where(v => !string.IsNullOrWhiteSpace(v))
            .SelectMany(v => v!.Split(SI.Management.Core.ProData.ProDataFilters.ValueSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            .Distinct(StringComparer.Ordinal).ToList();

    /// An id as the value a choice is sent as (an address value, never shown as a number).
    public static string Key(int id) => id.ToString(System.Globalization.CultureInfo.InvariantCulture);

    /// Choices from plain values (their own words).
    public static IReadOnlyList<FilterChoice> Plain(IEnumerable<string> values, Func<string, string>? label = null, Func<string, long?>? count = null) =>
        values.Where(v => !string.IsNullOrEmpty(v)).Distinct(StringComparer.Ordinal).Select(v => new FilterChoice(v, label?.Invoke(v) ?? v, count?.Invoke(v))).ToList();
}
