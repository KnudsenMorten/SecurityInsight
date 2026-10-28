namespace SI.Management.Core.ProData;

/// <summary>
/// THE DEFAULT FILTERS OF A FINDING VIEW that its own columns do not carry (owner 2026-10-19: "is there a filter so i can
/// filter on device type ... we need more filters of the most common fields"): the finding's category, subcategory
/// (Domain &gt; Category &gt; Subcategory) and component -- the PREPARED columns of sidata.Finding (view-stored-columns.json,
/// filled per collection by the data sync), never a value worked out of a JSON document. Added to a grid over finding rows
/// (its source reads sidata.Finding AS f, its key is FindingId) as HIDDEN value-filter columns: "+ Add filter" offers them
/// with the counts of the view, the address carries them like any filter, and a column a view already has is not added
/// twice. Only on a database that has the finding context columns (<see cref="DataColumnSchema.FindingContext"/>); a
/// collection the data sync has not prepared for this list yet has no values in them, so its filter lists nothing.
/// </summary>
public static class FindingFilterColumns
{
    /// (column key, words, the sidata.Finding column).
    public static readonly IReadOnlyList<(string Key, string Label, string Column)> Columns =
    [
        ("FindingCategory", "Category", "Category"),
        ("FindingSubcategory", "Subcategory", "Subcategory"),
        ("FindingComponent", "Component (finding)", "Component"),
    ];

    /// The spec with the filter columns (hidden) after the domain -- or unchanged when it is no grid over finding rows.
    public static GridSpec With(GridSpec spec)
    {
        const string from = "\nFROM sidata.Finding AS f";
        var i = spec.Source.IndexOf(from, StringComparison.Ordinal);
        if (i < 0 || spec.KeyColumn != "FindingId") return spec;
        var add = Columns.Where(c => spec.Column(c.Key) is null).ToList();
        if (add.Count == 0) return spec;
        var source = spec.Source[..i] + string.Concat(add.Select(c => ",\n       f." + c.Column + " AS " + c.Key)) + spec.Source[i..];
        var cols = spec.Columns.ToList();
        var at = cols.FindIndex(c => c.Key == "SecurityDomain");
        at = at < 0 ? cols.Count : at + 1;
        cols.InsertRange(at, add.Select(c => new GridColumn(c.Key, c.Label, Filter: GridFilter.Values, Hidden: true)));
        return GridSql.Check(spec with { Source = source, Columns = cols });
    }
}
