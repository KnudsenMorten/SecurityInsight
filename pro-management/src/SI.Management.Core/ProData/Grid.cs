using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace SI.Management.Core.ProData;

/// How a grid column is shown and compared.
public enum GridType { Text, Number, Date, Tier, Flag }

/// How a grid column can be filtered.
///   Contains -- free text, matched literally anywhere in the value
///   Values   -- one or more exact values (multi-select)
///   Tokens   -- one or more values of a ';'-separated list column (MITRE tactics, compliance tags)
///   Range    -- a number range "lo..hi" ("7" = at least 7, "..5" = at most 5)
///   Dates    -- a date range (owner 2026-10-19): "7d" / "30d" / "90d" = the last 7 / 30 / 90 days, or
///               "yyyy-MM-dd..yyyy-MM-dd" (either end may be left out; the end day is included), UTC days
public enum GridFilter { None, Contains, Values, Tokens, Range, Dates }

/// One column of a grid: its key (also the URL name and the SQL alias), its label, how it filters, whether free-text
/// search covers it. <paramref name="SortSql"/> overrides what "sort by this column" orders on (e.g. severity by rank).
/// <paramref name="AnyOf"/> (#431, a <see cref="GridFilter.Values"/> column only): the ';'-list the source carries under
/// that alias, which this column's filter and value counts read instead of the shown value -- a row matches a chosen value
/// when ANY item of the list is it, and counts once under each item (so the counts can overlap). The asset kind: the
/// column SHOWS the most descriptive kind, the filter matches every kind the CI is made of.
/// <paramref name="FilterNote"/>: one sentence the filter shows next to its choices (e.g. that the counts can overlap).
/// <paramref name="LateSql"/> (a grid with <see cref="GridSpec.Late"/> only): the column is costly to read (the CI document),
/// and this expression over the spec's late join computes it for the rows of the page alone -- unless the request filters,
/// sorts or searches on it.
public sealed record GridColumn(string Key, string Label, GridType Type = GridType.Text, GridFilter Filter = GridFilter.None,
    bool Search = false, bool Sortable = true, string? SortSql = null, bool Hidden = false, string? AnyOf = null, string? FilterNote = null,
    string? LateSql = null)
{
    /// #431: the asset-kind column of a grid whose source selects <see cref="ProDataSql.AssetKindsExpr"/> AS AssetKinds.
    public static GridColumn AssetKind(string label = "Kind") =>
        new("AssetKind", label, Filter: GridFilter.Values, AnyOf: "AssetKinds", FilterNote: ProDataSql.KindOverlapNote);
}

/// <summary>
/// A grid: a FIXED source statement (<see cref="Source"/>, a SELECT whose aliases are the column keys, with optional
/// leading CTEs in <see cref="Ctes"/>) and the columns over it. <see cref="GridSql"/> wraps it with paging, sort,
/// per-column filters, free-text search and the row selection -- all parameters, never caller text.
/// <see cref="Immutable"/>: the source reads only the rows of ONE complete collection, so an answer never changes and
/// may be cached long; otherwise (close-loop, connector, exemption state) it is cached briefly.
/// </summary>
public sealed record GridSpec(string Name, string Ctes, string Source, IReadOnlyList<GridColumn> Columns, string DefaultSort, bool DefaultDesc,
    string KeyColumn, IReadOnlyList<string> SourceParameters, bool Immutable, GridLate? Late = null, GridKeyset? Keyset = null, string? KeySortSql = null)
{
    public GridColumn? Column(string? key) => Columns.FirstOrDefault(c => string.Equals(c.Key, key, StringComparison.OrdinalIgnoreCase));
}

/// <summary>
/// #812 (a large customer, 1,117,524 findings per collection): the INDEX-ORDERED page of a grid over one collection's finding
/// rows. The generic page counts every matching row (COUNT_BIG(*) OVER ()) and sorts them all before it can return 50; for
/// the view a page opens with -- no filter, no search, no selection, a sort the index orders -- the page's keys are read
/// straight off an index instead (<see cref="Keys"/>, ordered by <see cref="Sorts"/>, OFFSET/FETCH), the source is computed
/// for those keys only (<see cref="Narrow"/> rewrites the source's "this collection" condition), and the total is the STORED
/// count (<see cref="Total"/>). A request that filters, searches or selects keeps the generic page.
/// <see cref="Counts"/>: the stored counts per value (sidata.FindingFacet) a column's filter dropdown shows when no other
/// filter, search or selection narrows the view; null = that column is counted live.
/// <see cref="Applies"/>: false when the source's own parameters narrow it (e.g. one CI's findings) -- the generic page then.
/// </summary>
public sealed record GridKeyset(string Keys, IReadOnlyDictionary<string, string> Sorts, Func<string, string> Narrow, string Total,
    Func<IReadOnlyDictionary<string, object?>, bool> Applies, Func<string, string?>? Counts = null);

/// <summary>
/// The LATE projection of a grid (owner 2026-10-11, "takes 10 sec to open a view"): the page is chosen -- filtered, sorted,
/// counted, paged -- over a NARROW source that leaves out the costly columns (<see cref="GridColumn.LateSql"/>), and those are
/// computed afterwards for the page's rows only, through <see cref="Join"/> (which reaches the row again by the key column,
/// as g.[key]). <see cref="NarrowSource"/>(keys) = the source without the late columns but those named (the ones this request
/// filters, sorts or searches on). The full <see cref="GridSpec.Source"/> stays the reference shape (value counts read it).
/// </summary>
public sealed record GridLate(Func<IReadOnlyCollection<string>, string> NarrowSource, string Join);

/// What one grid view asks for: sort, page, search, per-column filters, selected rows. Everything here comes from
/// the URL and is validated by <see cref="GridSql.Normalize"/> before it reaches a parameter.
public sealed record GridRequest
{
    public string? Sort { get; init; }
    public bool? Desc { get; init; }
    public int Page { get; init; } = 1;
    public int Size { get; init; } = 50;
    public string? Search { get; init; }
    /// column key -> the raw filter text (Values / Tokens: values separated by '|'; Range: "lo..hi")
    public IReadOnlyDictionary<string, string> Filters { get; init; } = new Dictionary<string, string>();
    public IReadOnlyList<string> Selected { get; init; } = Array.Empty<string>();
}

/// A normalised filter of one column.
/// <paramref name="From"/> / <paramref name="Before"/> (a <see cref="GridFilter.Dates"/> filter): the first moment
/// included and the first moment no longer included (UTC); <paramref name="Text"/> keeps what was asked ("30d").
public sealed record GridFilterValue(string Key, GridFilter Kind, IReadOnlyList<string> Values, double? Low, double? High, string? Text,
    DateTime? From = null, DateTime? Before = null);

/// The validated request: only known columns, whitelisted sort, bounded paging.
public sealed record GridState(string Sort, bool Desc, int Page, int Size, string? Search, IReadOnlyList<GridFilterValue> Filters, IReadOnlyList<string> Selected)
{
    public int Skip => (Page - 1) * Size;

    /// A stable text of everything that shapes the answer (the cache key's "query shape").
    public string Shape()
    {
        var sb = new StringBuilder();
        sb.Append(Sort).Append('|').Append(Desc ? 'd' : 'a').Append('|').Append(Page).Append('|').Append(Size).Append("|q=").Append(Search);
        foreach (var f in Filters.OrderBy(x => x.Key, StringComparer.Ordinal))
            sb.Append("|f.").Append(f.Key).Append('=').Append(string.Join("\u001f", f.Values)).Append('~').Append(f.Low?.ToString("R", CultureInfo.InvariantCulture))
              .Append("..").Append(f.High?.ToString("R", CultureInfo.InvariantCulture)).Append('~').Append(f.Text)
              .Append('~').Append(f.From?.ToString("o", CultureInfo.InvariantCulture)).Append("..").Append(f.Before?.ToString("o", CultureInfo.InvariantCulture));
        if (Selected.Count > 0) sb.Append("|sel=").Append(string.Join("\u001f", Selected.OrderBy(s => s, StringComparer.Ordinal)));
        return sb.ToString();
    }
}

/// One page of a grid: rows as column key -> value, and the total for the pager.
public sealed record GridPage(IReadOnlyList<IReadOnlyDictionary<string, object?>> Rows, long Total, GridState State);

/// <summary>The one statement builder every collection view uses.</summary>
public static partial class GridSql
{
    /// The rows per page the statement builder accepts (owner 2026-10-19: "per-page up to 500"; <see cref="MaxSelected"/>
    /// covers a whole page). A page's own reads may ask for 25 (the search, the executive top 5); a VIEWER chooses from
    /// <see cref="PageChoices"/> only.
    public static readonly int[] Sizes = [25, 50, 100, 200, 250, 500];

    /// <summary>
    /// THE rows-per-page choice of every grid (#857, owner 2026-10-21: "where is the ability to control number per page 50
    /// is not enough"): the shared grid toolbar offers exactly these, each page reads its "size" address parameter through
    /// <see cref="PageSize(string?)"/> -- anything else is <see cref="DefaultPageSize"/> -- and pages in SQL (OFFSET / FETCH
    /// or keyset), so a 500-row page reads 500 rows. Exports keep their own rules.
    /// </summary>
    public static readonly int[] PageChoices = [50, 100, 250, 500];
    public const int DefaultPageSize = 50;

    /// A viewer's rows per page: one of <see cref="PageChoices"/>, anything else the default.
    public static int PageSize(int asked) => PageChoices.Contains(asked) ? asked : DefaultPageSize;

    /// A "size" address parameter as rows per page (invariant digits only; anything else the default).
    public static int PageSize(string? raw) =>
        int.TryParse(raw, NumberStyles.None, CultureInfo.InvariantCulture, out var s) ? PageSize(s) : DefaultPageSize;

    public const int MaxValues = 50;
    public const int MaxSelected = 500;

    [GeneratedRegex("^[A-Za-z][A-Za-z0-9]{0,40}$", RegexOptions.CultureInvariant)]
    private static partial Regex KeyPattern();

    public static bool IsKey(string k) => KeyPattern().IsMatch(k);

    /// A spec is checked once: column keys are plain identifiers (they become SQL aliases), the key column and the
    /// default sort exist, and the source is read-only.
    public static GridSpec Check(GridSpec s)
    {
        foreach (var c in s.Columns) if (!IsKey(c.Key)) throw new InvalidOperationException($"grid {s.Name}: '{c.Key}' is not a plain column key");
        foreach (var c in s.Columns.Where(c => c.AnyOf is not null))
        {
            if (!IsKey(c.AnyOf!) || c.Filter != GridFilter.Values) throw new InvalidOperationException($"grid {s.Name}: '{c.Key}' AnyOf must name a plain list alias on a Values column");
            // the list is read as g.[AnyOf]: the source must select it under that alias
            if (!System.Text.RegularExpressions.Regex.IsMatch(s.Source, @"\bAS\s+\[?" + c.AnyOf + @"\b")) throw new InvalidOperationException($"grid {s.Name}: the source selects no '{c.AnyOf}' for '{c.Key}'");
        }
        if (s.Column(s.KeyColumn) is null) throw new InvalidOperationException($"grid {s.Name}: key column {s.KeyColumn} is not a column");
        if (s.Column(s.DefaultSort) is not { Sortable: true }) throw new InvalidOperationException($"grid {s.Name}: default sort {s.DefaultSort} is not sortable");
        if (s.Columns.Select(c => c.Key.ToLowerInvariant()).Distinct().Count() != s.Columns.Count) throw new InvalidOperationException($"grid {s.Name}: duplicate column");
        return s;
    }

    /// Validates a request against a spec. A filter on an unknown column, or a column that does not filter, is ignored
    /// (a stale link still opens); a value that does not fit is refused with ArgumentException.
    public static GridState Normalize(GridSpec spec, GridRequest r)
    {
        var sortCol = spec.Column(r.Sort) is { Sortable: true } sc ? sc.Key : spec.DefaultSort;
        var desc = r.Desc ?? (sortCol == spec.DefaultSort ? spec.DefaultDesc : spec.Column(sortCol)!.Type is GridType.Number or GridType.Date);
        var size = Sizes.Contains(r.Size) ? r.Size : 50;
        // #881 no page ceiling of our own (page 100,001 of a 50 M-row grid showed page 100,000 again, silently): only what the
        // row offset can hold (int.MaxValue rows)
        var page = Math.Clamp(r.Page, 1, int.MaxValue / size);
        var filters = new List<GridFilterValue>();
        foreach (var (k, raw) in r.Filters)
        {
            if (spec.Column(k) is not { } col || col.Filter == GridFilter.None || string.IsNullOrWhiteSpace(raw)) continue;
            switch (col.Filter)
            {
                case GridFilter.Contains:
                    filters.Add(new(col.Key, col.Filter, Array.Empty<string>(), null, null, ProDataFilters.Text(raw)));
                    break;
                case GridFilter.Values:
                case GridFilter.Tokens:
                    var vals = raw.Split('|', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                        .Select(v => ProDataFilters.Text(v)!).Distinct(StringComparer.Ordinal).ToList();
                    if (vals.Count > MaxValues) throw new ArgumentException($"at most {MaxValues} values per column filter");
                    if (vals.Count > 0) filters.Add(new(col.Key, col.Filter, vals, null, null, null));
                    break;
                case GridFilter.Range:
                    var (lo, hi) = Range(raw);
                    if (lo is not null || hi is not null) filters.Add(new(col.Key, col.Filter, Array.Empty<string>(), lo, hi, null));
                    break;
                case GridFilter.Dates:
                    var (from, before) = Dates(raw, DateTime.UtcNow);
                    if (from is not null || before is not null) filters.Add(new(col.Key, col.Filter, Array.Empty<string>(), null, null, raw.Trim(), from, before));
                    break;
            }
        }
        var sel = r.Selected.Where(s => !string.IsNullOrWhiteSpace(s)).Select(s => ProDataFilters.Text(s)!).Distinct(StringComparer.Ordinal).ToList();
        if (sel.Count > MaxSelected) throw new ArgumentException($"at most {MaxSelected} rows can be selected");
        return new GridState(sortCol, desc, page, size, ProDataFilters.Text(r.Search), filters, sel);
    }

    /// "7" = at least 7; "..5" = at most 5; "4..6.9" = between. Invariant numbers only.
    public static (double? Low, double? High) Range(string raw)
    {
        var t = raw.Trim();
        static double? N(string s) => s.Length == 0 ? null
            : double.TryParse(s, NumberStyles.Float, CultureInfo.InvariantCulture, out var d) && double.IsFinite(d) ? d
            : throw new ArgumentException($"'{s}' is not a number");
        var i = t.IndexOf("..", StringComparison.Ordinal);
        return i < 0 ? (N(t), null) : (N(t[..i].Trim()), N(t[(i + 2)..].Trim()));
    }

    /// The quick picks of a date filter: the last N days.
    public static readonly int[] DayPicks = [7, 30, 90];

    /// <summary>
    /// A date range (UTC days): "30d" = from the start of the day 30 days ago (today's date minus 30) with no end;
    /// "2026-10-01..2026-10-19" = from the start of the first day to the start of the day after the last; an end may be
    /// left out ("2026-10-01.." / "..2026-10-19"). At most 3,650 days back. A value that is no date range is refused.
    /// </summary>
    public static (DateTime? From, DateTime? Before) Dates(string raw, DateTime nowUtc)
    {
        var t = raw.Trim();
        var m = Regex.Match(t, "^([0-9]{1,4})d$", RegexOptions.CultureInvariant);
        if (m.Success)
        {
            var days = int.Parse(m.Groups[1].Value, CultureInfo.InvariantCulture);
            if (days is < 1 or > 3650) throw new ArgumentException($"'{t}': 1 to 3,650 days");
            return (DateTime.SpecifyKind(nowUtc.Date.AddDays(-days), DateTimeKind.Utc), null);
        }
        static DateTime? D(string s) => s.Length == 0 ? null
            : DateTime.TryParseExact(s, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var d)
                ? DateTime.SpecifyKind(d, DateTimeKind.Utc)
                : throw new ArgumentException($"'{s}' is not a date (yyyy-MM-dd)");
        var i = t.IndexOf("..", StringComparison.Ordinal);
        var (a, b) = i < 0 ? (D(t), D(t)) : (D(t[..i].Trim()), D(t[(i + 2)..].Trim()));
        if (a is not null && b is not null && b < a) throw new ArgumentException($"'{t}': the end is before the start");
        return (a, b?.AddDays(1));
    }

    private static string P(string key) => "F_" + key;
    private static string Col(string key) => "g.[" + key + "]";

    /// The WHERE of a grid: every filterable column ALWAYS has its predicate (NULL parameter = no filter), so the
    /// statement text depends only on the spec and the sort -- never on which filters a caller set.
    private static string Where(GridSpec s)
    {
        var parts = new List<string> { "1 = 1" };
        foreach (var c in s.Columns)
        {
            switch (c.Filter)
            {
                case GridFilter.Contains: parts.Add($"(@{P(c.Key)} IS NULL OR {Col(c.Key)} LIKE @{P(c.Key)})"); break;
                // #431: an AnyOf column matches when any item of its ';'-list is a chosen value (exact, not LIKE: no escaping needed)
                case GridFilter.Values when c.AnyOf is not null:
                    parts.Add($"(@{P(c.Key)} IS NULL OR EXISTS (SELECT 1 FROM STRING_SPLIT({Col(c.AnyOf)}, N';') AS av JOIN OPENJSON(@{P(c.Key)}) AS fv ON fv.[value] = LTRIM(RTRIM(av.[value]))))");
                    break;
                case GridFilter.Values: parts.Add($"(@{P(c.Key)} IS NULL OR {Col(c.Key)} IN (SELECT fv.[value] FROM OPENJSON(@{P(c.Key)}) AS fv))"); break;
                // a ';'-list holds the token when ';' + list + ';' matches one of the prepared '%;token;%' patterns
                case GridFilter.Tokens: parts.Add($"(@{P(c.Key)} IS NULL OR EXISTS (SELECT 1 FROM OPENJSON(@{P(c.Key)}) AS fv WHERE N';' + REPLACE({Col(c.Key)}, N'; ', N';') + N';' LIKE fv.[value]))"); break;
                case GridFilter.Range: parts.Add($"(@{P(c.Key)}Lo IS NULL OR {Col(c.Key)} >= @{P(c.Key)}Lo) AND (@{P(c.Key)}Hi IS NULL OR {Col(c.Key)} <= @{P(c.Key)}Hi)"); break;
                case GridFilter.Dates: parts.Add($"(@{P(c.Key)}From IS NULL OR {Col(c.Key)} >= @{P(c.Key)}From) AND (@{P(c.Key)}Before IS NULL OR {Col(c.Key)} < @{P(c.Key)}Before)"); break;
            }
        }
        var search = s.Columns.Where(c => c.Search).Select(c => $"{Col(c.Key)} LIKE @Q").ToList();
        if (search.Count > 0) parts.Add($"(@Q IS NULL OR {string.Join(" OR ", search)})");
        parts.Add($"(@Sel IS NULL OR {Col(s.KeyColumn)} IN (SELECT sv.[value] FROM OPENJSON(@Sel) AS sv))");
        return string.Join("\n  AND ", parts);
    }

    private static string OrderBy(GridSpec s, GridState st)
    {
        var col = s.Column(st.Sort)!;
        var expr = col.SortSql ?? Col(col.Key);
        var dir = st.Desc ? "DESC" : "ASC";
        // NULLs last in both directions, then the key so paging is stable (#812: a key the spec orders numerically)
        return $"CASE WHEN {expr} IS NULL THEN 1 ELSE 0 END, {expr} {dir}, {s.KeySortSql ?? Col(s.KeyColumn)}";
    }

    /// <summary>
    /// #812: whether a request is the view a grid opens with, which <see cref="GridSpec.Keyset"/> pages off an index: no filter,
    /// no search, no selection, a DESC sort the index orders (NULLs come last by themselves), the source not narrowed.
    /// </summary>
    public static bool UsesKeyset(GridSpec s, GridState st, IReadOnlyDictionary<string, object?> sourceParams) =>
        s.Keyset is { } k && st.Filters.Count == 0 && st.Search is null && st.Selected.Count == 0 && st.Desc
        && k.Sorts.ContainsKey(st.Sort) && k.Applies(sourceParams);

    /// The index-ordered page (<see cref="GridSpec.Keyset"/>): the page's keys off the index, the source for those keys only,
    /// the stored total. Same columns, same order and same rows as the generic page of the same request.
    private static SqlQuery KeysetPage(GridSpec s, GridState st, IReadOnlyDictionary<string, object?> sourceParams, bool export, int max)
    {
        var k = s.Keyset!;
        var cols = string.Join(", ", s.Columns.Select(c => Col(c.Key)));
        var ctes = s.Ctes.Trim().Length == 0 ? "" : s.Ctes.Trim() + ",\n";
        var text = $"""
WITH pk AS (
    SELECT {k.Keys}
    ORDER BY {k.Sorts[st.Sort]}
    OFFSET @Skip ROWS FETCH NEXT @Take ROWS ONLY
), {ctes}g AS (
{k.Narrow(s.Source)}
)
SELECT {cols},
       {k.Total} AS TotalRows
FROM g
WHERE {Where(s)}
ORDER BY {OrderBy(s, st)}
OPTION (RECOMPILE);
""";
        var p = Params(s, st, sourceParams);
        p["Skip"] = export ? 0 : st.Skip;
        p["Take"] = export ? Math.Clamp(max, 1, ProDataFilters.MaxExport) : st.Size;
        return new SqlQuery(text, p);
    }

    private static string With(GridSpec s) => s.Ctes.Trim().Length == 0 ? $"WITH g AS (\n{s.Source}\n)" : $"WITH {s.Ctes.Trim()},\ng AS (\n{s.Source}\n)";

    /// One page (or, with <paramref name="export"/>, every row up to <paramref name="max"/>) of the grid.
    public static SqlQuery Page(GridSpec s, GridState st, IReadOnlyDictionary<string, object?> sourceParams, bool export = false, int max = ProDataFilters.MaxExport)
    {
        if (UsesKeyset(s, st, sourceParams)) return KeysetPage(s, st, sourceParams, export, max);
        if (LatePage(s, st, sourceParams, export, max) is { } late) return late;
        var cols = string.Join(", ", s.Columns.Select(c => Col(c.Key)));
        var text = $"""
{With(s)}
SELECT {cols},
       COUNT_BIG(*) OVER () AS TotalRows
FROM g
WHERE {Where(s)}
ORDER BY {OrderBy(s, st)}
OFFSET @Skip ROWS FETCH NEXT @Take ROWS ONLY
OPTION (RECOMPILE);
""";
        var p = Params(s, st, sourceParams);
        p["Skip"] = export ? 0 : st.Skip;
        p["Take"] = export ? Math.Clamp(max, 1, ProDataFilters.MaxExport) : st.Size;
        return new SqlQuery(text, p);
    }

    /// <summary>
    /// The page of a grid with a <see cref="GridSpec.Late"/> projection: chosen over the narrow source (the late columns
    /// this request filters, sorts or searches on included -- they must be read for every row then), the other late
    /// columns computed for the page's rows only. Null when the spec has none, or the request needs every late column.
    /// </summary>
    private static SqlQuery? LatePage(GridSpec s, GridState st, IReadOnlyDictionary<string, object?> sourceParams, bool export, int max)
    {
        if (s.Late is not { } late || s.Ctes.Trim().Length > 0) return null;
        var lateCols = s.Columns.Where(c => c.LateSql is not null).ToList();
        if (lateCols.Count == 0) return null;
        bool Needed(GridColumn c) => string.Equals(st.Sort, c.Key, StringComparison.OrdinalIgnoreCase)
            || st.Filters.Any(f => string.Equals(f.Key, c.Key, StringComparison.OrdinalIgnoreCase))
            || (c.Search && st.Search is not null);
        var needed = lateCols.Where(Needed).Select(c => c.Key).ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (needed.Count == lateCols.Count) return null;
        var inner = s.Columns.Where(c => c.LateSql is null || needed.Contains(c.Key)).ToList();
        var n = s with { Source = late.NarrowSource(needed), Columns = inner, Late = null };
        var outer = string.Join(", ", s.Columns.Select(c => c.LateSql is not null && !needed.Contains(c.Key) ? c.LateSql + " AS [" + c.Key + "]" : Col(c.Key)));
        var text = $"""
WITH gp AS (
{n.Source}
)
SELECT {outer},
       g.TotalRows
FROM (
SELECT {string.Join(", ", inner.Select(c => Col(c.Key)))},
       COUNT_BIG(*) OVER () AS TotalRows
FROM gp AS g
WHERE {Where(n)}
ORDER BY {OrderBy(n, st)}
OFFSET @Skip ROWS FETCH NEXT @Take ROWS ONLY
) AS g
{late.Join}
ORDER BY {OrderBy(n, st)}
OPTION (RECOMPILE);
""";
        var p = Params(n, st, sourceParams);
        p["Skip"] = export ? 0 : st.Skip;
        p["Take"] = export ? Math.Clamp(max, 1, ProDataFilters.MaxExport) : st.Size;
        return new SqlQuery(text, p);
    }

    /// <summary>
    /// #287: how many rows each value of ONE value-filter column has, under every OTHER active filter, the search and the
    /// selection (the column's own filter is left out -- so a count is exactly what ticking that value alone gives). A
    /// token column (';'-lists: MITRE, compliance) counts each token. At most <see cref="MaxCountedValues"/> values.
    /// </summary>
    public static SqlQuery ValueCounts(GridSpec s, GridState st, IReadOnlyDictionary<string, object?> sourceParams, string column)
    {
        var col = s.Column(column);
        if (col is not { Filter: GridFilter.Values or GridFilter.Tokens }) throw new ArgumentException($"'{column}' has no value filter");
        var others = st with { Filters = st.Filters.Where(f => f.Key != col.Key).ToList() };
        // #812: nothing else narrows the view -- the counts the data sync stored per collection (sidata.FindingFacet)
        if (s.Keyset is { Counts: { } stored } ks && others.Filters.Count == 0 && st.Search is null && st.Selected.Count == 0 && ks.Applies(sourceParams)
            && stored(col.Key) is { } countsSql)
            return new SqlQuery(countsSql, s.SourceParameters.Where(n => n == "CollectionId").ToDictionary(n => n, n => sourceParams[n]));
        // a grid with a LATE projection counts over its narrow source: the costly late columns are read only when the counted
        // column, another active filter or the search needs them (the one-row-per-CVE grid: the close-loop is left out)
        if (s.Late is { } late && s.Ctes.Trim().Length == 0 && s.Columns.Any(c => c.LateSql is not null))
        {
            var lateCols = s.Columns.Where(c => c.LateSql is not null).ToList();
            var needed = lateCols.Where(c => string.Equals(c.Key, col.Key, StringComparison.OrdinalIgnoreCase)
                    || others.Filters.Any(f => string.Equals(f.Key, c.Key, StringComparison.OrdinalIgnoreCase))
                    || (c.Search && st.Search is not null))
                .Select(c => c.Key).ToHashSet(StringComparer.OrdinalIgnoreCase);
            if (needed.Count < lateCols.Count)
                s = s with { Source = late.NarrowSource(needed), Columns = s.Columns.Where(c => c.LateSql is null || needed.Contains(c.Key)).ToList(), Late = null };
        }
        // #431: an AnyOf column counts a row once under EACH distinct item of its list (counts can overlap; the grid total
        // still counts the row once)
        var values = col.Filter == GridFilter.Tokens
            ? $"CROSS APPLY (SELECT LTRIM(RTRIM(t.[value])) AS V FROM STRING_SPLIT(REPLACE({Col(col.Key)}, N'; ', N';'), N';') AS t) AS v"
            : col.AnyOf is not null
            ? $"CROSS APPLY (SELECT DISTINCT CONVERT(nvarchar(400), LTRIM(RTRIM(t.[value]))) AS V FROM STRING_SPLIT({Col(col.AnyOf)}, N';') AS t) AS v"
            : $"CROSS APPLY (SELECT CONVERT(nvarchar(400), {Col(col.Key)}) AS V) AS v";
        var text = $"""
{With(s)}
SELECT TOP ({MaxCountedValues}) v.V AS V, COUNT_BIG(*) AS N
FROM g
{values}
WHERE {Where(s)}
  AND v.V IS NOT NULL AND v.V <> N''
GROUP BY v.V
ORDER BY COUNT_BIG(*) DESC, v.V
OPTION (RECOMPILE);
""";
        return new SqlQuery(text, Params(s, others, sourceParams));
    }

    /// The most values one count read returns.
    public const int MaxCountedValues = 500;

    /// Every parameter of a grid statement: the source's own (exactly those the spec declares), one per filter, the
    /// search, the selection.
    public static Dictionary<string, object?> Params(GridSpec s, GridState st, IReadOnlyDictionary<string, object?> sourceParams)
    {
        var p = new Dictionary<string, object?>(StringComparer.Ordinal);
        foreach (var name in s.SourceParameters)
            p[name] = sourceParams.TryGetValue(name, out var v) ? v : throw new ArgumentException($"grid {s.Name} needs @{name}");
        foreach (var c in s.Columns)
        {
            var f = st.Filters.FirstOrDefault(x => x.Key == c.Key);
            switch (c.Filter)
            {
                case GridFilter.Contains: p[P(c.Key)] = ProDataFilters.Like(f?.Text); break;
                case GridFilter.Values: p[P(c.Key)] = f is null ? null : JsonSerializer.Serialize(f.Values); break;
                case GridFilter.Tokens: p[P(c.Key)] = f is null ? null : JsonSerializer.Serialize(f.Values.Select(v => "%;" + Escape(v) + ";%")); break;
                case GridFilter.Range: p[P(c.Key) + "Lo"] = f?.Low; p[P(c.Key) + "Hi"] = f?.High; break;
                case GridFilter.Dates: p[P(c.Key) + "From"] = f?.From; p[P(c.Key) + "Before"] = f?.Before; break;
            }
        }
        if (s.Columns.Any(c => c.Search)) p["Q"] = ProDataFilters.Like(st.Search);
        p["Sel"] = st.Selected.Count == 0 ? null : JsonSerializer.Serialize(st.Selected);
        return p;
    }

    /// LIKE's own wildcards matched literally.
    public static string Escape(string v) => v.Replace("[", "[[]").Replace("%", "[%]").Replace("_", "[_]");
}
