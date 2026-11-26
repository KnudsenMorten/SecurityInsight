namespace SI.Management.Web.Columns;

/// <summary>
/// A list column's cell on screen (<c>GridColumn.Lines</c>; owner 2026-11-24: "detected paths is cut off and it mentions
/// multiple paths"): the items of the value -- one per line, or ';' separated -- each IN FULL, in their order, duplicates
/// once. Up to <see cref="ShownOpen"/> items are shown as they are; a longer list folds into "N paths" that opens. Nothing is
/// ever cut: a path, a person's folder name included, is the evidence an Admin needs (owner 2026-11-17).
/// </summary>
public static class CellLines
{
    /// How many items are shown without folding.
    public const int ShownOpen = 3;

    private static readonly char[] Separators = ['\n', '\r', ';'];

    /// The items of a list cell's text (none for an empty value).
    public static IReadOnlyList<string> Split(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return [];
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var items = new List<string>();
        foreach (var part in text.Split(Separators, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            if (seen.Add(part)) items.Add(part);
        return items;
    }
}
